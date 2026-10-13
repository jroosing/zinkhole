//! Network front end: UDP and TCP listeners served by a fixed pool of worker
//! threads. Memory is fixed at startup: each worker owns one query and one
//! response buffer, and answering a query allocates nothing (only cache
//! insertions do).

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;

const dns = @import("dns.zig");
const ip = @import("ip.zig");
const tcp = @import("tcp.zig");
const Resolver = @import("resolver.zig").Resolver;

const log = std.log.scoped(.server);

/// Larger queries are dropped; real queries are well under 512 bytes.
const max_query_len = 4096;
/// TCP is only used for truncated answers, so few workers suffice.
const tcp_workers_per_listener = 2;
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
    workers: []Worker = &.{},
    group: Io.Group = .init,
    /// Set once workers hold pointers into the socket lists.
    pointers_locked: bool = false,

    const Worker = struct {
        server: *Server,
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

    /// Starts the workers: `udp_workers` per UDP socket plus a few per TCP listener.
    pub fn start(server: *Server, udp_workers: u16) !void {
        const udp_count = server.udp_sockets.items.len * udp_workers;
        const tcp_count = server.tcp_listeners.items.len * tcp_workers_per_listener;
        server.workers = try server.gpa.alloc(Worker, udp_count + tcp_count);
        for (server.workers) |*worker| worker.server = server;

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
        for (server.tcp_listeners.items) |*listener| {
            for (0..tcp_workers_per_listener) |_| {
                try server.group.concurrent(server.io, tcpWorker, .{ &server.workers[next], listener });
                next += 1;
            }
        }
    }

    /// Stops all workers and closes the sockets.
    pub fn deinit(server: *Server) void {
        server.group.cancel(server.io);
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

            const response = try worker.server.resolver.handle(message.data, &worker.response, message.from, .udp) orelse continue;
            socket.send(io, &message.from, response) catch |err| switch (err) {
                error.Canceled => |e| return e,
                else => log.debug("udp send to {f}: {t}", .{ message.from, err }),
            };
        }
    }

    fn tcpWorker(worker: *Worker, listener: *net.Server) Io.Cancelable!void {
        const io = worker.server.io;
        while (true) {
            const stream = listener.accept(io) catch |err| switch (err) {
                error.Canceled => |e| return e,
                else => {
                    log.debug("tcp accept: {t}", .{err});
                    try io.sleep(.fromMilliseconds(100), .awake);
                    continue;
                },
            };
            defer stream.close(io);
            // Checked per connection, not just per query: a client that may
            // not query must not get to hold one of the few TCP workers.
            if (!ip.isAllowed(worker.server.resolver.allow_clients, stream.socket.address)) continue;
            serveConnection(worker, stream) catch |err| {
                if (err == error.Canceled) return error.Canceled;
                log.debug("tcp {f}: {t}", .{ stream.socket.address, err });
            };
        }
    }

    fn serveConnection(worker: *Worker, stream: net.Stream) !void {
        const io = worker.server.io;
        const socket = stream.socket.handle;
        for (0..tcp_max_queries) |_| {
            const query = tcp.readMessage(io, socket, &worker.query, tcp.deadlineIn(io, tcp_idle_timeout_ms)) catch |err| switch (err) {
                error.EndOfStream => return, // the client closed the connection
                else => |e| return e,
            };
            const response = try worker.server.resolver.handle(query, &worker.response, stream.socket.address, .tcp) orelse return;
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
const Upstream = @import("upstream.zig").Upstream;

/// A server on loopback with one local record and no upstream servers.
const TestServer = struct {
    config: config_mod.Config,
    policy: Policy,
    cache: Cache,
    upstream: Upstream,
    resolver: Resolver,
    server: Server,

    fn init(t: *TestServer, allow_clients: []const ip.Cidr) !void {
        const io = testing.io;
        const gpa = testing.allocator;
        var diag: config_mod.Diagnostic = .{};
        t.config = try config_mod.parse(gpa, "upstream:\n  servers: [9.9.9.9]\nlocal:\n  records:\n    nas.lan: 10.0.0.10\n", &diag);
        errdefer t.config.deinit();
        t.policy = try .init(io, gpa, &t.config);
        errdefer t.policy.deinit();
        t.cache = try .init(gpa, .{ .capacity = 4, .min_ttl = 0, .max_ttl = 60, .seed = 1 });
        errdefer t.cache.deinit();
        try t.upstream.init(io, gpa, &.{}, 100);
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
        try t.server.start(1);
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
    try server.listen(&.{ .{ .ip4 = .unspecified(port) }, .{ .ip6 = .unspecified(port) } });
    try testing.expectEqual(2, server.tcp_listeners.items.len);
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
