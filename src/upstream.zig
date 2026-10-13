//! Forwarding to upstream DNS servers. Each `Server` is either plain DNS
//! (UDP first, TCP when the answer is truncated) or DNS over TLS (see
//! dot.zig) behind the same `exchange`. `Upstream` tries the servers in
//! order, starting with the one that answered last, so a dead server costs
//! one timeout instead of one per query.
//!
//! Spoofing defenses: every exchange uses a random query ID, and only answers
//! with the same ID and the same question are accepted. Plain DNS also uses a
//! fresh socket (random source port) and accepts answers only from the
//! server's address.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;

const dns = @import("dns.zig");
const dot = @import("dot.zig");
const tcp = @import("tcp.zig");
const metrics_mod = @import("metrics.zig");
const Metrics = metrics_mod.Metrics;

const log = std.log.scoped(.upstream);

pub const plain_port = 53;
pub const tls_port = 853;

/// Where and how to reach an upstream server, as configured.
pub const ServerAddress = struct {
    address: net.IpAddress,
    /// The name its TLS certificate must carry (e.g. dns.quad9.net) for DNS
    /// over TLS; null for plain DNS.
    tls_name: ?[]const u8 = null,

    pub fn format(server: ServerAddress, w: *Io.Writer) Io.Writer.Error!void {
        if (server.tls_name) |name| {
            try w.print("tls://{f}#{s}", .{ server.address, name });
        } else {
            try w.print("{f}", .{server.address});
        }
    }
};

/// An upstream server: sends it a query and returns its answer.
pub const Server = union(enum) {
    plain: Plain,
    tls: dot.Tls,

    /// Sends `query` and returns the server's answer to exactly that query,
    /// in `out`. The server sees a random query ID; the answer carries the
    /// original one. `query.bytes` is restored before returning. Everything,
    /// including a TCP fallback or a TLS reconnect, happens before `deadline`.
    pub fn exchange(server: *Server, io: Io, query: dns.UpstreamQuery, out: []u8, deadline: Io.Timeout) ![]u8 {
        const original_id = dns.readId(query.bytes);
        defer dns.setId(query.bytes, original_id);
        var random: [2]u8 = undefined;
        io.random(&random);
        dns.setId(query.bytes, std.mem.readInt(u16, &random, .big));

        const response = switch (server.*) {
            .plain => |*plain| try plain.exchange(io, query, out, deadline),
            .tls => |*tls| try tls.exchange(io, query, out, deadline),
        };
        dns.setId(response, original_id);
        return response;
    }

    pub fn format(server: Server, w: *Io.Writer) Io.Writer.Error!void {
        switch (server) {
            .plain => |plain| try w.print("{f}", .{plain.address}),
            .tls => |tls| try w.print("tls://{f}#{s}", .{ tls.address, tls.name }),
        }
    }
};

/// Plain DNS: UDP, and TCP when the answer is truncated.
pub const Plain = struct {
    address: net.IpAddress,

    fn exchange(plain: *const Plain, io: Io, query: dns.UpstreamQuery, out: []u8, deadline: Io.Timeout) ![]u8 {
        return try plain.exchangeUdp(io, query, out, deadline) orelse
            try plain.exchangeTcp(io, query, out, deadline);
    }

    /// Returns null when the answer is truncated and must be fetched over TCP.
    fn exchangeUdp(plain: *const Plain, io: Io, query: dns.UpstreamQuery, out: []u8, deadline: Io.Timeout) !?[]u8 {
        const server = &plain.address;
        const any_address: net.IpAddress = switch (server.*) {
            .ip4 => .{ .ip4 = .unspecified(0) },
            .ip6 => .{ .ip6 = .unspecified(0) },
        };
        const socket = try any_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
        defer socket.close(io);
        try socket.send(io, server, query.bytes);

        while (true) {
            const message = try socket.receiveTimeout(io, out, deadline);
            // Ignore anything that is not the answer to this query.
            if (!message.from.eql(server)) continue;
            if (!query.isAnswer(message.data)) continue;
            if (message.flags.trunc or dns.readFlags(message.data).tc) return null;
            return message.data;
        }
    }

    fn exchangeTcp(plain: *const Plain, io: Io, query: dns.UpstreamQuery, out: []u8, deadline: Io.Timeout) ![]u8 {
        const stream = try tcp.connect(io, &plain.address, deadline);
        defer stream.close(io);
        try tcp.writeMessage(io, stream.socket.handle, query.bytes, deadline);
        const response = try tcp.readMessage(io, stream.socket.handle, out, deadline);
        if (!query.isAnswer(response)) return error.InvalidResponse;
        return response;
    }
};

pub const Upstream = struct {
    /// Owns `servers` and the TLS names.
    arena: std.heap.ArenaAllocator,
    servers: []Server,
    timeout_ms: u32,
    /// Index of the server that answered most recently.
    preferred: std.atomic.Value(usize) = .init(0),
    /// CA certificates; loaded only when a server uses DNS over TLS.
    trust: dot.Trust,
    /// Counts every attempt per server, if set.
    metrics: ?*Metrics = null,

    pub const Error = error{AllServersFailed} || Io.Cancelable;

    /// Copies `addresses`. `upstream` must not move afterwards: TLS servers
    /// point into it.
    pub fn init(upstream: *Upstream, io: Io, gpa: Allocator, addresses: []const ServerAddress, timeout_ms: u32) !void {
        upstream.* = .{ .arena = .init(gpa), .servers = &.{}, .timeout_ms = timeout_ms, .trust = .{ .gpa = gpa } };
        errdefer upstream.arena.deinit();
        const arena = upstream.arena.allocator();

        const servers = try arena.alloc(Server, addresses.len);
        var tls_count: usize = 0;
        for (addresses, servers) |address, *server| {
            if (address.tls_name) |name| {
                server.* = .{ .tls = .init(address.address, try arena.dupe(u8, name), &upstream.trust) };
                tls_count += 1;
            } else {
                server.* = .{ .plain = .{ .address = address.address } };
            }
        }
        upstream.servers = servers;
        if (tls_count == 0) return;

        upstream.trust.load(io) catch |err| {
            log.err("cannot load the system's CA certificates, needed for tls:// servers: {t}", .{err});
            upstream.trust.deinit();
            return error.CertificateBundleLoadFailure;
        };
        log.info("DNS over TLS: loaded {d} CA certificates", .{upstream.trust.bundle.map.count()});
        if (tls_count < addresses.len) {
            log.warn("plain DNS servers are configured next to tls:// servers; queries go unencrypted whenever they are used", .{});
        }
    }

    pub fn deinit(upstream: *Upstream) void {
        for (upstream.servers) |*server| switch (server.*) {
            .plain => {},
            .tls => |*tls| tls.deinit(),
        };
        upstream.trust.deinit();
        upstream.arena.deinit();
        upstream.* = undefined;
    }

    /// Forwards the client's query `msg` and writes the answer to `out`.
    /// Rewrites `msg` in place (see `dns.rewriteForUpstream`); its ID and
    /// question section stay intact. Each server gets `timeout_ms` for all of
    /// its exchange.
    pub fn forward(upstream: *Upstream, io: Io, msg: []u8, q: *const dns.Query, out: []u8) Error![]u8 {
        const query = dns.rewriteForUpstream(msg, q);
        const first = upstream.preferred.load(.monotonic);
        for (0..upstream.servers.len) |attempt| {
            const index = (first + attempt) % upstream.servers.len;
            const server = &upstream.servers[index];
            const started = Io.Clock.Timestamp.now(io, .awake);
            const response = server.exchange(io, query, out, tcp.deadlineIn(io, upstream.timeout_ms)) catch |err| {
                if (err == error.Canceled) return error.Canceled;
                log.debug("{f}: {t}", .{ server.*, err });
                upstream.count(io, index, .failure);
                continue;
            };
            // A server that refuses us is misconfigured or rate limiting: try the next one.
            if (dns.readFlags(response).rcode == .refused) {
                log.debug("{f}: refused", .{server.*});
                upstream.count(io, index, .failure);
                continue;
            }
            const micros = @max(0, started.untilNow(io).raw.toMicroseconds());
            upstream.count(io, index, .{ .answer = std.math.lossyCast(u32, @divTrunc(micros, 100)) });
            if (index != first) upstream.preferred.store(index, .monotonic);
            return response;
        }
        return error.AllServersFailed;
    }

    fn count(upstream: *Upstream, io: Io, server: usize, attempt: metrics_mod.Attempt) void {
        const metrics = upstream.metrics orelse return;
        metrics.countAttempt(server, attempt, Io.Clock.real.now(io).toSeconds());
    }
};

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

/// A DNS server on loopback (UDP and TCP on one ephemeral port) that answers
/// as scripted, for testing exchanges without a network.
const Stub = struct {
    udp: net.Socket,
    tcp: net.Server,
    behavior: Behavior,
    group: Io.Group = .init,
    /// Queries received so far; `last_buf` holds the latest.
    received: std.atomic.Value(u32) = .init(0),
    last_buf: [512]u8 = undefined,
    last_len: usize = 0,
    /// Waits before answering, for testing deadlines.
    udp_delay_ms: u32 = 0,
    tcp_delay_ms: u32 = 0,

    const Behavior = enum {
        answer,
        silent,
        refuse,
        /// Sends a wrong-ID and a wrong-question answer (for 6.6.6.6) before
        /// the real one.
        spoof_first,
        /// Answers UDP queries with TC set and no records; TCP in full.
        truncate,
    };

    fn start(stub: *Stub, behavior: Behavior) !void {
        const io = testing.io;
        const loopback: net.IpAddress = .{ .ip4 = .loopback(0) };
        stub.* = .{ .behavior = behavior, .udp = try loopback.bind(io, .{ .mode = .dgram, .protocol = .udp }), .tcp = undefined };
        errdefer stub.udp.close(io);
        stub.tcp = try stub.udp.address.listen(io, .{ .reuse_address = true });
        errdefer stub.tcp.deinit(io);
        try stub.group.concurrent(io, serveUdp, .{stub});
        try stub.group.concurrent(io, serveTcp, .{stub});
    }

    fn stop(stub: *Stub) void {
        const io = testing.io;
        stub.group.cancel(io);
        stub.tcp.deinit(io);
        stub.udp.close(io);
    }

    fn address(stub: *const Stub) net.IpAddress {
        return stub.udp.address;
    }

    fn lastQuery(stub: *const Stub) []const u8 {
        return stub.last_buf[0..stub.last_len];
    }

    fn serveUdp(stub: *Stub) Io.Cancelable!void {
        const io = testing.io;
        var buf: [512]u8 = undefined;
        var out: [512]u8 = undefined;
        while (true) {
            const message = stub.udp.receive(io, &buf) catch |err| switch (err) {
                error.Canceled => |e| return e,
                else => continue,
            };
            const response = stub.respond(message.data, &out, .udp) orelse continue;
            if (stub.udp_delay_ms > 0) try io.sleep(.fromMilliseconds(stub.udp_delay_ms), .awake);
            if (stub.behavior == .spoof_first) {
                var spoofed_buf: [512]u8 = undefined;
                const spoofed = spoofed_buf[0..response.len];
                @memcpy(spoofed, response);
                @memcpy(spoofed[spoofed.len - 4 ..], &[_]u8{ 6, 6, 6, 6 }); // the A record's address
                dns.setId(spoofed, dns.readId(response) +% 1);
                stub.udp.send(io, &message.from, spoofed) catch {};
                dns.setId(spoofed, dns.readId(response));
                spoofed[dns.header_len + 1] ^= 0x01; // a different name
                stub.udp.send(io, &message.from, spoofed) catch {};
            }
            stub.udp.send(io, &message.from, response) catch {};
        }
    }

    fn serveTcp(stub: *Stub) Io.Cancelable!void {
        const io = testing.io;
        var buf: [512]u8 = undefined;
        var out: [512]u8 = undefined;
        while (true) {
            const stream = stub.tcp.accept(io) catch |err| switch (err) {
                error.Canceled => |e| return e,
                else => continue,
            };
            defer stream.close(io);
            const query = tcp.readMessage(io, stream.socket.handle, &buf, .none) catch |err| {
                if (err == error.Canceled) return error.Canceled;
                continue;
            };
            const response = stub.respond(query, &out, .tcp) orelse continue;
            if (stub.tcp_delay_ms > 0) try io.sleep(.fromMilliseconds(stub.tcp_delay_ms), .awake);
            tcp.writeMessage(io, stream.socket.handle, response, .none) catch {};
        }
    }

    /// Records `query` and builds the scripted response; null for none.
    fn respond(stub: *Stub, query: []const u8, out: []u8, transport: enum { udp, tcp }) ?[]u8 {
        @memcpy(stub.last_buf[0..query.len], query);
        stub.last_len = query.len;
        _ = stub.received.fetchAdd(1, .release);
        var name_buf: [dns.max_name_len]u8 = undefined;
        const q = dns.parseQuery(query, &name_buf) catch return null;
        const options: dns.ResponseOptions = switch (stub.behavior) {
            .silent => return null,
            .refuse => .{ .rcode = .refused },
            .truncate => if (transport == .udp) .{ .truncated = true } else answer,
            .answer, .spoof_first => answer,
        };
        return dns.writeResponse(out, query, &q, options) catch null;
    }

    const answer: dns.ResponseOptions = .{ .answers = &.{.{ .a = .{ 1, 2, 3, 4 } }}, .ttl = 60 };
};

/// A client query, sent through `Server.exchange` or `Upstream.forward`.
const TestQuery = struct {
    buf: [512]u8 = undefined,
    name_buf: [dns.max_name_len]u8 = undefined,
    q: dns.Query = undefined,
    msg: []u8 = &.{},

    /// The query for `name`, rewritten for upstream as `forward` does.
    fn init(t: *TestQuery, id: u16, name: []const u8) !dns.UpstreamQuery {
        try t.client(id, name, null);
        return dns.rewriteForUpstream(t.msg, &t.q);
    }

    fn client(t: *TestQuery, id: u16, name: []const u8, edns_size: ?u16) !void {
        t.msg = dns.testQuery(&t.buf, id, name, .a, edns_size);
        t.q = try dns.parseQuery(t.msg, &t.name_buf);
    }

    /// Forwards a client query for example.com.
    fn forward(t: *TestQuery, upstream: *Upstream, id: u16, out: []u8) ![]u8 {
        try t.client(id, "example.com", null);
        return upstream.forward(testing.io, t.msg, &t.q, out);
    }

    /// The question as sent, for checking answers.
    fn sent(t: *const TestQuery) dns.UpstreamQuery {
        return .{ .bytes = t.msg, .question_end = t.q.question_end };
    }
};

/// The stub's real answer: one A record for 1.2.3.4, with the client's ID.
fn expectAnswer(query: dns.UpstreamQuery, response: []const u8, id: u16) !void {
    try testing.expectEqual(id, dns.readId(response));
    try testing.expectEqual(.noerror, dns.readFlags(response).rcode);
    try testing.expect(query.isAnswer(response));
    var records: dns.RecordIterator = .init(response, query.question_end);
    const record = (try records.next()).?;
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, response[record.rdata_offset..][0..record.rdata_len]);
}

test "a plain server answers with the original ID, but never sees it" {
    var stub: Stub = undefined;
    try stub.start(.answer);
    defer stub.stop();
    var server: Server = .{ .plain = .{ .address = stub.address() } };

    var ids_seen: [3]u16 = undefined;
    for (&ids_seen) |*seen| {
        var t: TestQuery = .{};
        const query = try t.init(0xABCD, "example.com");
        var out: [512]u8 = undefined;
        const response = try server.exchange(testing.io, query, &out, tcp.deadlineIn(testing.io, 1000));
        try expectAnswer(query, response, 0xABCD);
        seen.* = dns.readId(stub.lastQuery());
    }
    // A random ID per exchange (three times 0xABCD has odds of 2^-48).
    try testing.expect(!(ids_seen[0] == 0xABCD and ids_seen[1] == 0xABCD and ids_seen[2] == 0xABCD));
}

test "answers with a wrong ID or question are ignored" {
    var stub: Stub = undefined;
    try stub.start(.spoof_first);
    defer stub.stop();
    var server: Server = .{ .plain = .{ .address = stub.address() } };

    var t: TestQuery = .{};
    const query = try t.init(0x1111, "example.com");
    var out: [512]u8 = undefined;
    const response = try server.exchange(testing.io, query, &out, tcp.deadlineIn(testing.io, 1000));
    try expectAnswer(query, response, 0x1111);
}

test "a truncated answer is fetched again over TCP" {
    var stub: Stub = undefined;
    try stub.start(.truncate);
    defer stub.stop();
    var server: Server = .{ .plain = .{ .address = stub.address() } };

    var t: TestQuery = .{};
    const query = try t.init(0x2222, "example.com");
    var out: [512]u8 = undefined;
    const response = try server.exchange(testing.io, query, &out, tcp.deadlineIn(testing.io, 1000));
    try expectAnswer(query, response, 0x2222);
    try testing.expectEqual(2, stub.received.load(.acquire)); // UDP, then TCP
}

test "the TCP fallback gets no time beyond the deadline" {
    var stub: Stub = undefined;
    try stub.start(.truncate);
    defer stub.stop();
    // Each answer alone fits in the deadline; both together do not.
    stub.udp_delay_ms = 150;
    stub.tcp_delay_ms = 150;
    var server: Server = .{ .plain = .{ .address = stub.address() } };

    var t: TestQuery = .{};
    const query = try t.init(0x3333, "example.com");
    var out: [512]u8 = undefined;
    try testing.expectError(error.Timeout, server.exchange(testing.io, query, &out, tcp.deadlineIn(testing.io, 200)));
}

test "a silent server times out at the deadline" {
    var stub: Stub = undefined;
    try stub.start(.silent);
    defer stub.stop();
    var server: Server = .{ .plain = .{ .address = stub.address() } };

    var t: TestQuery = .{};
    const query = try t.init(0x4444, "example.com");
    var out: [512]u8 = undefined;
    try testing.expectError(error.Timeout, server.exchange(testing.io, query, &out, tcp.deadlineIn(testing.io, 100)));
}

test "when a server fails, the next answers and is asked first from then on" {
    var silent: Stub = undefined;
    try silent.start(.silent);
    defer silent.stop();
    var good: Stub = undefined;
    try good.start(.answer);
    defer good.stop();

    var upstream: Upstream = undefined;
    try upstream.init(testing.io, testing.allocator, &.{ .{ .address = silent.address() }, .{ .address = good.address() } }, 100);
    defer upstream.deinit();

    var out: [512]u8 = undefined;
    var t: TestQuery = .{};
    const response_5555 = try t.forward(&upstream, 0x5555, &out);
    try expectAnswer(t.sent(), response_5555, 0x5555);
    try testing.expectEqual(1, silent.received.load(.acquire));

    const response_6666 = try t.forward(&upstream, 0x6666, &out);
    try expectAnswer(t.sent(), response_6666, 0x6666);
    try testing.expectEqual(1, silent.received.load(.acquire));
    try testing.expectEqual(2, good.received.load(.acquire));
}

test "a refusing server is skipped" {
    var refusing: Stub = undefined;
    try refusing.start(.refuse);
    defer refusing.stop();
    var good: Stub = undefined;
    try good.start(.answer);
    defer good.stop();

    var upstream: Upstream = undefined;
    try upstream.init(testing.io, testing.allocator, &.{ .{ .address = refusing.address() }, .{ .address = good.address() } }, 500);
    defer upstream.deinit();

    var out: [512]u8 = undefined;
    var t: TestQuery = .{};
    const response = try t.forward(&upstream, 0x7777, &out);
    try expectAnswer(t.sent(), response, 0x7777);
    try testing.expectEqual(1, refusing.received.load(.acquire));
}

test "when every server fails, forwarding fails" {
    var silent: Stub = undefined;
    try silent.start(.silent);
    defer silent.stop();
    var refusing: Stub = undefined;
    try refusing.start(.refuse);
    defer refusing.stop();

    var upstream: Upstream = undefined;
    try upstream.init(testing.io, testing.allocator, &.{ .{ .address = silent.address() }, .{ .address = refusing.address() } }, 100);
    defer upstream.deinit();

    var out: [512]u8 = undefined;
    var t: TestQuery = .{};
    try testing.expectError(error.AllServersFailed, t.forward(&upstream, 0x8888, &out));
}

test "each attempt counts against its server: answers with their time, failures and refusals" {
    var silent: Stub = undefined;
    try silent.start(.silent);
    defer silent.stop();
    var refusing: Stub = undefined;
    try refusing.start(.refuse);
    defer refusing.stop();
    var slow: Stub = undefined;
    try slow.start(.answer);
    defer slow.stop();
    slow.udp_delay_ms = 20;

    const servers = [_]ServerAddress{ .{ .address = silent.address() }, .{ .address = refusing.address() }, .{ .address = slow.address() } };
    var metrics: Metrics = try .init(testing.io, testing.allocator, .{ .zone = .{}, .started = 0, .upstream = &servers });
    defer metrics.deinit();
    var upstream: Upstream = undefined;
    try upstream.init(testing.io, testing.allocator, &servers, 100);
    defer upstream.deinit();
    upstream.metrics = &metrics;

    var out: [512]u8 = undefined;
    var t: TestQuery = .{};
    _ = try t.forward(&upstream, 0x7878, &out);
    _ = try t.forward(&upstream, 0x7879, &out); // the slow server is asked first now

    const now = Io.Clock.real.now(testing.io).toSeconds();
    const failed = metrics.attempts(0, .today, now);
    try testing.expectEqual(1, failed.failures);
    try testing.expectEqual(0, failed.answers);
    try testing.expectEqual(null, failed.averageMs());
    try testing.expectEqual(1, metrics.attempts(1, .today, now).failures);
    const answered = metrics.attempts(2, .last_24h, now);
    try testing.expectEqual(2, answered.answers);
    try testing.expectEqual(0, answered.failures);
    try testing.expect(answered.averageMs().? >= 20);
}

test "client EDNS options never reach the upstream server" {
    var stub: Stub = undefined;
    try stub.start(.answer);
    defer stub.stop();
    var upstream: Upstream = undefined;
    try upstream.init(testing.io, testing.allocator, &.{.{ .address = stub.address() }}, 500);
    defer upstream.deinit();

    // A client query whose OPT record carries a cookie option.
    var t: TestQuery = .{};
    try t.client(0x9999, "example.com", 4096);
    const opt_end = t.msg.len;
    std.mem.writeInt(u16, t.buf[opt_end - 2 ..][0..2], 12, .big); // OPT rdata length
    @memcpy(t.buf[opt_end..][0..12], &[_]u8{ 0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8 });
    const msg = t.buf[0 .. opt_end + 12];
    t.q = try dns.parseQuery(msg, &t.name_buf);

    var out: [512]u8 = undefined;
    _ = try upstream.forward(testing.io, msg, &t.q, &out);

    const sent = stub.lastQuery();
    var name_buf: [dns.max_name_len]u8 = undefined;
    const received = try dns.parseQuery(sent, &name_buf);
    var records: dns.RecordIterator = .init(sent, received.question_end);
    const opt = (try records.next()).?;
    try testing.expectEqual(.opt, opt.type);
    try testing.expectEqual(0, opt.rdata_len);
}

test "DNS over TLS to a public server (zig build test -Dnetwork)" {
    if (!@import("build_options").network_tests) return error.SkipZigTest;
    const quad9: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 9, 9, 9, 9 }, .port = tls_port } };

    var upstream: Upstream = undefined;
    try upstream.init(testing.io, testing.allocator, &.{.{ .address = quad9, .tls_name = "dns.quad9.net" }}, 5000);
    defer upstream.deinit();
    var out: [512]u8 = undefined;
    // The second query reuses the first one's connection.
    for ([_]u16{ 0xA001, 0xA002 }) |id| {
        var t: TestQuery = .{};
        const response = try t.forward(&upstream, id, &out);
        try testing.expectEqual(id, dns.readId(response));
        try testing.expectEqual(.noerror, dns.readFlags(response).rcode);
        try testing.expect(t.sent().isAnswer(response));
    }

    // A certificate for another name is rejected.
    var impostor: Upstream = undefined;
    try impostor.init(testing.io, testing.allocator, &.{.{ .address = quad9, .tls_name = "dns.example.com" }}, 5000);
    defer impostor.deinit();
    var t: TestQuery = .{};
    try testing.expectError(error.AllServersFailed, t.forward(&impostor, 0xA003, &out));
}
