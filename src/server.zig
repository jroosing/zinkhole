//! Network front end: UDP and TCP listeners served by a fixed pool of worker
//! threads. A UDP worker answers what needs no upstream server and hands
//! cache misses to the forwarding stage (forwarder.zig, ADR-0005), so it
//! never waits for one; when every forwarding slot is busy, it answers
//! SERVFAIL. TCP connections are handed to a fixed pool of connection
//! slots, so a few slow or idle clients cannot hold up the others. Memory is
//! fixed at startup: each worker, TCP slot and forwarding slot owns one
//! query and one response buffer, and answering a query allocates nothing
//! (only cache insertions do).

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;

const dns = @import("dns.zig");
const ip = @import("ip.zig");
const tcp = @import("tcp.zig");
const Resolver = @import("resolver.zig").Resolver;
const forwarder_mod = @import("forwarder.zig");
const Forwarder = forwarder_mod.Forwarder;
const SlotPool = @import("slot_pool.zig").SlotPool;

const log = std.log.scoped(.server);

/// Larger queries are dropped; real queries are well under 512 bytes.
const max_query_len = forwarder_mod.max_query_len;
/// TCP connections served at once, over all listeners, unless set.
const default_tcp_connections = 16;
/// An idle TCP connection is closed after this long (RFC 7766 suggests seconds).
const tcp_idle_timeout_ms = 5_000;
/// Queries answered per TCP connection before it is closed.
const tcp_max_queries = 100;

pub const Server = struct {
    io: Io,
    gpa: Allocator,
    resolver: *Resolver,
    udp_sockets: std.ArrayList(net.Socket) = .empty,
    tcp_listeners: std.ArrayList(net.Server) = .empty,
    /// UDP workers.
    workers: []Worker = &.{},
    /// TCP connections, each served by a task of its own; valid once
    /// `tcp_ready`.
    tcp: SlotPool(TcpSlot) = undefined,
    tcp_ready: bool = false,
    group: Io.Group = .init,
    /// Valid once `start` has started it.
    forwarder: Forwarder = undefined,
    forwarding: bool = false,
    /// Set once workers hold pointers into the socket lists.
    pointers_locked: bool = false,

    const Worker = struct {
        server: *Server,
        query: [max_query_len]u8,
        response: [dns.max_message_len]u8,
    };

    const TcpSlot = struct {
        /// The connection to serve; this slot closes it.
        stream: net.Stream,
        query: [max_query_len]u8,
        response: [dns.max_message_len]u8,
    };

    /// Opens a UDP socket and a TCP listener on every address.
    pub fn listen(server: *Server, addresses: []const net.IpAddress) !void {
        for (addresses) |address| {
            // If IPv4 is served on the same port, the IPv6 socket must be
            // IPv6-only to avoid a conflict; otherwise allow dual-stack.
            const ip6_only = if (address == .ip6) hasIp4OnPort(addresses, address.getPort()) else null;
            const udp = address.bind(server.io, .{ .mode = .dgram, .protocol = .udp, .ip6_only = ip6_only }) catch |err| {
                // Containers and LXCs often run without IPv6; serve IPv4 then.
                if (address == .ip6 and (err == error.AddressFamilyUnsupported or err == error.AddressUnavailable)) {
                    log.warn("IPv6 is not available ({t}), skipping {f}", .{ err, address });
                    continue;
                }
                log.err("cannot listen on {f} (udp): {t}", .{ address, err });
                return err;
            };
            // Once in the list, `deinit` closes it.
            server.udp_sockets.append(server.gpa, udp) catch |err| {
                udp.close(server.io);
                return err;
            };

            // Quick restarts, but no other socket on the port; IPv6-only next
            // to an IPv4 listener on the same port, as for UDP.
            var listener = tcp.listen(address, ip6_only orelse false) catch |err| {
                log.err("cannot listen on {f} (tcp): {t}", .{ address, err });
                return err;
            };
            server.tcp_listeners.append(server.gpa, listener) catch |err| {
                listener.deinit(server.io);
                return err;
            };
            log.info("listening on {f} (udp and tcp)", .{udp.address});
        }
        if (server.udp_sockets.items.len == 0) return error.NoListenAddress;
    }

    pub const Options = struct {
        /// Per UDP socket.
        udp_workers: u16,
        /// Upstream queries in flight at once (`upstream.max_in_flight`).
        forward_slots: u16,
        /// TCP connections served at once, over all listeners; further
        /// connections are closed on arrival.
        tcp_connections: u16 = default_tcp_connections,
    };

    /// Starts the forwarding slots, `udp_workers` per UDP socket, the TCP
    /// connection slots and one accepting task per TCP listener. `server`
    /// must not move afterwards.
    pub fn start(server: *Server, options: Options) !void {
        std.debug.assert(options.tcp_connections > 0);
        try server.forwarder.init(server.io, server.gpa, server.resolver, options.forward_slots);
        server.forwarding = true;
        const udp_workers = options.udp_workers;
        server.workers = try server.gpa.alloc(Worker, server.udp_sockets.items.len * udp_workers);
        for (server.workers) |*worker| worker.server = server;
        try server.tcp.init(server.io, server.gpa, options.tcp_connections);
        server.tcp_ready = true;

        // Workers keep pointers into the socket lists: from here on, any
        // operation that could move them panics instead of leaving workers
        // with dangling pointers.
        server.udp_sockets.lockPointers();
        server.tcp_listeners.lockPointers();
        server.pointers_locked = true;

        var next: usize = 0;
        for (server.udp_sockets.items) |*socket| {
            for (0..udp_workers) |_| {
                try server.group.concurrent(server.io, udpWorker, .{ &server.workers[next], socket });
                next += 1;
            }
        }
        for (server.tcp_listeners.items) |*listener| try server.group.concurrent(server.io, acceptTcp, .{ server, listener });
        for (0..options.tcp_connections) |_| try server.group.concurrent(server.io, tcpWorker, .{server});
    }

    /// Stops all workers and forwarding slots, then closes the sockets.
    pub fn deinit(server: *Server) void {
        server.group.cancel(server.io);
        if (server.tcp_ready) {
            // Connections accepted but never served.
            while (server.tcp.unserved(server.io)) |slot| {
                slot.stream.close(server.io);
                server.tcp.release(server.io, slot);
            }
            server.tcp.deinit(server.gpa);
        }
        // Slots answer on the UDP sockets: they stop before those close.
        if (server.forwarding) server.forwarder.deinit();
        if (server.pointers_locked) {
            server.udp_sockets.unlockPointers();
            server.tcp_listeners.unlockPointers();
        }
        for (server.udp_sockets.items) |socket| socket.close(server.io);
        for (server.tcp_listeners.items) |*listener| listener.deinit(server.io);
        server.udp_sockets.deinit(server.gpa);
        server.tcp_listeners.deinit(server.gpa);
        server.gpa.free(server.workers);
        server.* = undefined;
    }

    fn udpWorker(worker: *Worker, socket: *const net.Socket) Io.Cancelable!void {
        const io = worker.server.io;
        while (true) {
            const message = socket.receive(io, &worker.query) catch |err| switch (err) {
                error.Canceled => |e| return e,
                else => {
                    log.debug("udp receive: {t}", .{err});
                    try io.sleep(.fromMilliseconds(10), .awake); // never spin on a broken socket
                    continue;
                },
            };
            if (message.flags.trunc) continue; // larger than any real query

            const resolver = worker.server.resolver;
            const arrived = resolver.arrival();
            const response = switch (resolver.answerLocally(message.data, &worker.response, message.from, .udp, arrived)) {
                .drop => continue,
                .response => |response| response,
                .upstream => if (worker.server.forwarder.submit(socket, message.from, message.data, arrived))
                    continue
                else
                    resolver.failUpstream(message.data, &worker.response, message.from, .udp, arrived) orelse continue,
            };
            socket.send(io, &message.from, response) catch |err| switch (err) {
                error.Canceled => |e| return e,
                else => log.debug("udp send to {f}: {t}", .{ message.from, err }),
            };
        }
    }

    /// Hands each connection to a free TCP slot, or closes it when every
    /// slot is busy.
    fn acceptTcp(server: *Server, listener: *net.Server) Io.Cancelable!void {
        const io = server.io;
        while (true) {
            const stream = listener.accept(io) catch |err| switch (err) {
                error.Canceled => |e| return e,
                else => {
                    log.debug("tcp accept: {t}", .{err});
                    try io.sleep(.fromMilliseconds(100), .awake);
                    continue;
                },
            };
            // Checked per connection, not just per query: a client that may
            // not query must not get to hold a TCP slot.
            if (!ip.isAllowed(server.resolver.allow_clients, stream.socket.address)) {
                stream.close(io);
                continue;
            }
            const slot = server.tcp.take(io) orelse {
                log.debug("tcp {f}: every connection slot is busy, closing", .{stream.socket.address});
                stream.close(io);
                continue;
            };
            slot.stream = stream;
            server.tcp.submit(io, slot);
        }
    }

    fn tcpWorker(server: *Server) Io.Cancelable!void {
        const io = server.io;
        while (true) {
            const slot = try server.tcp.next(io);
            defer server.tcp.release(io, slot);
            defer slot.stream.close(io);
            server.serveConnection(slot) catch |err| {
                if (err == error.Canceled) return error.Canceled;
                log.debug("tcp {f}: {t}", .{ slot.stream.socket.address, err });
            };
        }
    }

    fn serveConnection(server: *Server, slot: *TcpSlot) !void {
        const io = server.io;
        const socket = slot.stream.socket.handle;
        for (0..tcp_max_queries) |_| {
            const query = tcp.readMessage(io, socket, &slot.query, tcp.deadlineIn(io, tcp_idle_timeout_ms)) catch |err| switch (err) {
                error.EndOfStream => return, // the client closed the connection
                else => |e| return e,
            };
            const response = try server.resolver.handle(query, &slot.response, slot.stream.socket.address, .tcp) orelse return;
            try tcp.writeMessage(io, socket, response, tcp.deadlineIn(io, tcp_idle_timeout_ms));
        }
    }
};

fn hasIp4OnPort(addresses: []const net.IpAddress, port: u16) bool {
    for (addresses) |address| {
        if (address == .ip4 and address.getPort() == port) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;
const config_mod = @import("config.zig");
const Policy = @import("policy.zig").Policy;
const Cache = @import("cache.zig").Cache;
const upstream_mod = @import("upstream.zig");
const Upstream = upstream_mod.Upstream;
const Watchdog = @import("test_watchdog.zig").Watchdog;

/// A server on loopback with one local record and, unless given, no
/// upstream servers.
const TestServer = struct {
    config: config_mod.Config,
    policy: Policy,
    cache: Cache,
    upstream: Upstream,
    resolver: Resolver,
    server: Server,

    fn init(t: *TestServer, allow_clients: []const ip.Cidr) !void {
        return t.initWith(allow_clients, &.{});
    }

    fn initWith(t: *TestServer, allow_clients: []const ip.Cidr, upstream_servers: []const upstream_mod.ServerAddress) !void {
        const io = testing.io;
        const gpa = testing.allocator;
        var diag: config_mod.Diagnostic = .{};
        t.config = try config_mod.parse(gpa, "upstream:\n  servers: [9.9.9.9]\nlocal:\n  records:\n    nas.lan: 10.0.0.10\n", &diag);
        errdefer t.config.deinit();
        t.policy = try .init(io, gpa, &t.config);
        errdefer t.policy.deinit();
        t.cache = try .init(gpa, .{ .capacity = 4, .min_ttl = 0, .max_ttl = 60, .seed = 1 });
        errdefer t.cache.deinit();
        try t.upstream.init(io, gpa, upstream_servers, 2000);
        errdefer t.upstream.deinit();
        t.resolver = .{
            .io = io,
            .policy = &t.policy,
            .cache = &t.cache,
            .upstream = &t.upstream,
            .allow_clients = allow_clients,
            .log_queries = .init(false),
        };
        t.server = .{ .io = io, .gpa = gpa, .resolver = &t.resolver };
        errdefer t.server.deinit();
        try t.server.listen(&.{.{ .ip4 = .loopback(0) }});
        try t.server.start(.{ .udp_workers = 1, .forward_slots = 4 });
    }

    fn deinit(t: *TestServer) void {
        t.server.deinit();
        t.upstream.deinit();
        t.cache.deinit();
        t.policy.deinit();
        t.config.deinit();
    }

    fn connect(t: *TestServer) !net.Stream {
        return t.server.tcp_listeners.items[0].socket.address.connect(testing.io, .{ .mode = .stream, .protocol = .tcp });
    }
};

test "allowed clients are answered over TCP" {
    var t: TestServer = undefined;
    try t.init(&.{ip.Cidr.parse("127.0.0.0/8").?});
    defer t.deinit();
    const stream = try t.connect();
    defer stream.close(testing.io);

    var query_buf: [512]u8 = undefined;
    const query = dns.testQuery(&query_buf, 7, "nas.lan", .a, null);
    try tcp.writeMessage(testing.io, stream.socket.handle, query, tcp.deadlineIn(testing.io, 1000));
    var response_buf: [512]u8 = undefined;
    const response = try tcp.readMessage(testing.io, stream.socket.handle, &response_buf, tcp.deadlineIn(testing.io, 1000));
    try testing.expectEqual(1, dns.readU16(response, 6));
}

test "TCP connections from clients outside the allowed networks are closed at once" {
    var t: TestServer = undefined;
    try t.init(&.{ip.Cidr.parse("10.0.0.0/8").?});
    defer t.deinit();
    const stream = try t.connect();
    defer stream.close(testing.io);

    // An allowed client would get 5 s to send its query; this one gets none.
    var buf: [2]u8 = undefined;
    try testing.expectError(error.EndOfStream, tcp.readMessage(testing.io, stream.socket.handle, &buf, tcp.deadlineIn(testing.io, 1000)));
}

/// Sends a query for nas.lan on `stream` and returns the answer count.
fn askOverTcp(stream: net.Stream, ms: u32) !u16 {
    var query_buf: [512]u8 = undefined;
    const query = dns.testQuery(&query_buf, 7, "nas.lan", .a, null);
    try tcp.writeMessage(testing.io, stream.socket.handle, query, tcp.deadlineIn(testing.io, ms));
    var response_buf: [512]u8 = undefined;
    const response = try tcp.readMessage(testing.io, stream.socket.handle, &response_buf, tcp.deadlineIn(testing.io, ms));
    return dns.readU16(response, 6);
}

test "idle TCP connections do not hold up other TCP clients" {
    var t: TestServer = undefined;
    try t.init(&.{ip.Cidr.parse("127.0.0.0/8").?});
    defer t.deinit();
    const idle = [_]net.Stream{ try t.connect(), try t.connect() };
    defer for (idle) |stream| stream.close(testing.io);
    try testing.io.sleep(.fromMilliseconds(50), .awake); // both accepted

    const stream = try t.connect();
    defer stream.close(testing.io);
    try testing.expectEqual(1, try askOverTcp(stream, 250));
}

test "TCP connections beyond the slots are closed at once, and freed slots serve again" {
    var t: TestServer = undefined;
    try t.init(&.{ip.Cidr.parse("127.0.0.0/8").?});
    defer t.deinit();
    var server: Server = .{ .io = testing.io, .gpa = testing.allocator, .resolver = &t.resolver };
    defer server.deinit();
    try server.listen(&.{.{ .ip4 = .loopback(0) }});
    try server.start(.{ .udp_workers = 1, .forward_slots = 1, .tcp_connections = 2 });
    const address = server.tcp_listeners.items[0].socket.address;
    const connect: net.IpAddress.ConnectOptions = .{ .mode = .stream, .protocol = .tcp };

    const first = try address.connect(testing.io, connect);
    const second = try address.connect(testing.io, connect);
    defer second.close(testing.io);
    try testing.io.sleep(.fromMilliseconds(50), .awake); // both hold a slot

    const third = try address.connect(testing.io, connect);
    defer third.close(testing.io);
    var buf: [2]u8 = undefined;
    try testing.expectError(error.EndOfStream, tcp.readMessage(testing.io, third.socket.handle, &buf, tcp.deadlineIn(testing.io, 1000)));

    first.close(testing.io);
    try testing.io.sleep(.fromMilliseconds(50), .awake); // its slot is free again
    const fourth = try address.connect(testing.io, connect);
    defer fourth.close(testing.io);
    try testing.expectEqual(1, try askOverTcp(fourth, 1000));
}

/// A TCP port that is free right now.
fn freePort() !u16 {
    const any: net.IpAddress = .{ .ip4 = .unspecified(0) };
    var probe = try any.listen(testing.io, .{});
    defer probe.deinit(testing.io);
    return probe.socket.address.getPort();
}

test "IPv4 and IPv6 listeners share a port, as in the default config" {
    var t: TestServer = undefined;
    try t.init(&.{ip.Cidr.parse("127.0.0.0/8").?});
    defer t.deinit();
    const port = try freePort();
    var server: Server = .{ .io = testing.io, .gpa = testing.allocator, .resolver = &t.resolver };
    defer server.deinit();
    server.listen(&.{ .{ .ip4 = .unspecified(port) }, .{ .ip6 = .unspecified(port) } }) catch |err| switch (err) {
        // IPv6 is off here (some CI containers): `listen` then serves IPv4
        // only, and there is no shared port to test.
        error.NoListenAddress => return error.SkipZigTest,
        else => |e| return e,
    };
    if (server.tcp_listeners.items.len != 2) return error.SkipZigTest;
}

test "no other socket can take over the DNS port" {
    var t: TestServer = undefined;
    try t.init(&.{ip.Cidr.parse("127.0.0.0/8").?});
    defer t.deinit();
    // Not even one that asks for SO_REUSEPORT, as std's reuse_address does.
    const address = t.server.tcp_listeners.items[0].socket.address;
    if (address.listen(testing.io, .{ .reuse_address = true })) |intruder| {
        var listener = intruder;
        listener.deinit(testing.io);
        return error.TestUnexpectedResult;
    } else |err| try testing.expectEqual(error.AddressInUse, err);
}

/// A UDP client on loopback for `t`.
const TestClient = struct {
    socket: net.Socket,
    server: net.IpAddress,

    fn open(t: *const TestServer) !TestClient {
        const loopback: net.IpAddress = .{ .ip4 = .loopback(0) };
        return .{ .socket = try loopback.bind(testing.io, .{ .mode = .dgram, .protocol = .udp }), .server = t.server.udp_sockets.items[0].address };
    }

    fn close(c: *TestClient) void {
        c.socket.close(testing.io);
    }

    fn send(c: *TestClient, id: u16, name: []const u8) !void {
        var buf: [512]u8 = undefined;
        try c.socket.send(testing.io, &c.server, dns.testQuery(&buf, id, name, .a, null));
    }

    /// The ID of the next answer, if one comes within `ms`.
    fn receiveId(c: *TestClient, ms: u32) !u16 {
        return (try c.receive(ms)).id;
    }

    /// The ID and rcode of the next answer, if one comes within `ms`.
    fn receive(c: *TestClient, ms: u32) !struct { id: u16, rcode: dns.Rcode } {
        var buf: [512]u8 = undefined;
        const message = try c.socket.receiveTimeout(testing.io, &buf, tcp.deadlineIn(testing.io, ms));
        return .{ .id = dns.readId(message.data), .rcode = dns.readFlags(message.data).rcode };
    }
};

test "local answers are not held up by queries waiting on an upstream server" {
    var slow: upstream_mod.Stub = undefined;
    try slow.start(.answer);
    defer slow.stop();
    slow.udp_delay_ms = 500;
    var t: TestServer = undefined;
    try t.initWith(&.{ip.Cidr.parse("127.0.0.0/8").?}, &.{.{ .address = slow.address() }});
    defer t.deinit();
    var client: TestClient = try .open(&t);
    defer client.close();

    for ([_][]const u8{ "one.example.com", "two.example.com", "three.example.com" }, 1..) |name, id| try client.send(@intCast(id), name);
    try client.send(10, "nas.lan");

    // Only one worker: the local answer comes first, long before the others.
    try testing.expectEqual(10, try client.receiveId(250));
    var answered: [3]bool = @splat(false);
    for (0..3) |_| answered[(try client.receiveId(1500)) - 1] = true;
    try testing.expectEqual([3]bool{ true, true, true }, answered);
}

test "uncached queries are forwarded in parallel, never more than the slots at once" {
    // A full pool is logged as a warning; keep the test output quiet.
    const log_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = log_level;
    var slow: upstream_mod.Stub = undefined;
    try slow.start(.answer);
    defer slow.stop();
    slow.udp_delay_ms = 300;
    var t: TestServer = undefined;
    try t.initWith(&.{ip.Cidr.parse("127.0.0.0/8").?}, &.{.{ .address = slow.address() }});
    defer t.deinit();
    var client: TestClient = try .open(&t);
    defer client.close();

    const started = Io.Clock.Timestamp.now(testing.io, .awake);
    var name_buf: [32]u8 = undefined;
    for (1..9) |id| try client.send(@intCast(id), try std.fmt.bufPrint(&name_buf, "name{d}.example.com", .{id}));
    var answered: [8]bool = @splat(false);
    var servfails: usize = 0;
    var last_answer_ms: i64 = 0;
    for (0..8) |_| {
        const answer = try client.receive(2000);
        answered[answer.id - 1] = true;
        if (answer.rcode == .servfail) servfails += 1 else last_answer_ms = started.untilNow(testing.io).raw.toMilliseconds();
    }

    try testing.expectEqual([8]bool{ true, true, true, true, true, true, true, true }, answered);
    // 4 slots: the other 4 fail at once.
    try testing.expectEqual(4, servfails);
    // The 4 forwarded ones are answered together, after one round of 300 ms.
    // One at a time would take 1.2 s.
    try testing.expect(last_answer_ms >= 280 and last_answer_ms < 900);
    try testing.expectEqual(4, t.resolver.stats.get(.forwarded));
    try testing.expectEqual(4, t.resolver.stats.get(.failed));
}

test "stopping the server does not wait for queries at an upstream server" {
    // A full pool is logged as a warning; keep the test output quiet.
    const log_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = log_level;
    var watchdog: Watchdog = try .start(10);
    defer watchdog.stop();
    var silent: upstream_mod.Stub = undefined;
    try silent.start(.silent);
    defer silent.stop();
    var t: TestServer = undefined;
    try t.initWith(&.{ip.Cidr.parse("127.0.0.0/8").?}, &.{.{ .address = silent.address() }});
    var client: TestClient = try .open(&t);
    defer client.close();

    // 4 slots wait for an answer that never comes (2 s timeout); the other 2
    // queries fail at once.
    var name_buf: [32]u8 = undefined;
    for (1..7) |id| try client.send(@intCast(id), try std.fmt.bufPrint(&name_buf, "name{d}.example.com", .{id}));
    try testing.io.sleep(.fromMilliseconds(200), .awake);

    const started = Io.Clock.Timestamp.now(testing.io, .awake);
    t.deinit();
    try testing.expect(started.untilNow(testing.io).raw.toMilliseconds() < 1000);
}

test "when every slot waits on an upstream server, more misses fail at once and local answers stay instant" {
    // A full pool is logged as a warning; keep the test output quiet.
    const log_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = log_level;
    var silent: upstream_mod.Stub = undefined;
    try silent.start(.silent);
    defer silent.stop();
    var t: TestServer = undefined;
    try t.initWith(&.{ip.Cidr.parse("127.0.0.0/8").?}, &.{.{ .address = silent.address() }});
    defer t.deinit();
    var client: TestClient = try .open(&t);
    defer client.close();

    // The 4 slots wait 2 s for an answer that never comes.
    var name_buf: [32]u8 = undefined;
    for (1..7) |id| try client.send(@intCast(id), try std.fmt.bufPrint(&name_buf, "name{d}.example.com", .{id}));
    try client.send(10, "nas.lan");

    var seen: [3]u16 = undefined;
    for (&seen) |*id| {
        const answer = try client.receive(250);
        id.* = answer.id;
        try testing.expectEqual(if (answer.id == 10) dns.Rcode.noerror else .servfail, answer.rcode);
    }
    std.mem.sort(u16, &seen, {}, std.sort.asc(u16));
    try testing.expectEqual([3]u16{ 5, 6, 10 }, seen);
    try testing.expectEqual(2, t.resolver.stats.get(.failed));
}
