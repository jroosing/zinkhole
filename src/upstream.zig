//! Forwarding to upstream DNS servers, either plain DNS (UDP first, TCP when
//! the answer is truncated) or DNS over TLS (see dot.zig). Servers are tried
//! in order, starting with the one that answered last, so a dead server costs
//! one timeout instead of one per query.
//!
//! Spoofing defenses for plain DNS: every exchange uses a fresh socket
//! (random source port) and a random query ID, and only answers from the
//! server's address with the same ID and the same question are accepted.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;

const dns = @import("dns.zig");
const dot = @import("dot.zig");
const tcp = @import("tcp.zig");

const log = std.log.scoped(.upstream);

pub const plain_port = 53;
pub const tls_port = 853;

/// An upstream server as configured.
pub const Server = struct {
    address: net.IpAddress,
    /// The name its TLS certificate must carry (e.g. dns.quad9.net) for DNS
    /// over TLS; null for plain DNS.
    tls_name: ?[]const u8 = null,

    pub fn format(server: Server, w: *Io.Writer) Io.Writer.Error!void {
        if (server.tls_name) |name| {
            try w.print("tls://{f}#{s}", .{ server.address, name });
        } else {
            try w.print("{f}", .{server.address});
        }
    }
};

pub const Upstream = struct {
    /// Owns `endpoints` and the server names.
    arena: std.heap.ArenaAllocator,
    endpoints: []Endpoint,
    timeout_ms: u32,
    /// Index of the server that answered most recently.
    preferred: std.atomic.Value(usize) = .init(0),
    /// CA certificates; loaded only when a server uses DNS over TLS.
    trust: dot.Trust,

    const Endpoint = struct {
        server: Server,
        /// Open connections, for DNS over TLS.
        pool: dot.Pool = .{},
    };

    pub const Error = error{AllServersFailed} || Io.Cancelable;

    /// Copies `servers`. `upstream` must not move afterwards: TLS
    /// connections point into it.
    pub fn init(upstream: *Upstream, io: Io, gpa: Allocator, servers: []const Server, timeout_ms: u32) !void {
        upstream.* = .{ .arena = .init(gpa), .endpoints = &.{}, .timeout_ms = timeout_ms, .trust = .{ .gpa = gpa } };
        errdefer upstream.arena.deinit();
        const arena = upstream.arena.allocator();

        const endpoints = try arena.alloc(Endpoint, servers.len);
        var tls_count: usize = 0;
        for (servers, endpoints) |server, *endpoint| {
            const tls_name = if (server.tls_name) |name| try arena.dupe(u8, name) else null;
            if (tls_name != null) tls_count += 1;
            endpoint.* = .{ .server = .{ .address = server.address, .tls_name = tls_name } };
        }
        upstream.endpoints = endpoints;
        if (tls_count == 0) return;

        upstream.trust.load(io) catch |err| {
            log.err("cannot load the system's CA certificates, needed for tls:// servers: {t}", .{err});
            upstream.trust.deinit();
            return error.CertificateBundleLoadFailure;
        };
        log.info("DNS over TLS: loaded {d} CA certificates", .{upstream.trust.bundle.map.count()});
        if (tls_count < servers.len) {
            log.warn("plain DNS servers are configured next to tls:// servers; queries go unencrypted whenever they are used", .{});
        }
    }

    pub fn deinit(upstream: *Upstream) void {
        for (upstream.endpoints) |*endpoint| endpoint.pool.deinit();
        upstream.trust.deinit();
        upstream.arena.deinit();
        upstream.* = undefined;
    }

    /// Forwards the client's query `msg` and writes the answer to `out` with
    /// the client's ID restored. Rewrites `msg` in place (see
    /// `dns.rewriteForUpstream`); its question section stays intact.
    pub fn forward(upstream: *Upstream, io: Io, msg: []u8, q: *const dns.Query, out: []u8) Error![]u8 {
        const query = dns.rewriteForUpstream(msg, q);
        const first = upstream.preferred.load(.monotonic);
        for (0..upstream.endpoints.len) |attempt| {
            const index = (first + attempt) % upstream.endpoints.len;
            const endpoint = &upstream.endpoints[index];
            const response = upstream.exchange(io, endpoint, query, q.question_end, out) catch |err| {
                if (err == error.Canceled) return error.Canceled;
                log.debug("{f}: {t}", .{ endpoint.server, err });
                continue;
            };
            if (index != first) upstream.preferred.store(index, .monotonic);
            dns.setId(response, q.id);
            return response;
        }
        return error.AllServersFailed;
    }

    fn exchange(upstream: *Upstream, io: Io, endpoint: *Endpoint, query: []u8, question_end: usize, out: []u8) ![]u8 {
        var id: [2]u8 = undefined;
        io.random(&id);
        dns.setId(query, std.mem.readInt(u16, &id, .big));

        const address = &endpoint.server.address;
        const deadline = tcp.deadlineIn(io, upstream.timeout_ms);
        const response = if (endpoint.server.tls_name) |name|
            try dot.exchange(io, &upstream.trust, &endpoint.pool, address, name, query, question_end, out, deadline)
        else
            try exchangeUdp(io, address, query, question_end, out, deadline) orelse
                try exchangeTcp(io, address, query, question_end, out, tcp.deadlineIn(io, upstream.timeout_ms));
        // A server that refuses us is misconfigured or rate limiting: try the next one.
        if (dns.readFlags(response).rcode == .refused) return error.Refused;
        return response;
    }
};

/// Returns null when the answer is truncated and must be fetched over TCP.
fn exchangeUdp(io: Io, server: *const net.IpAddress, query: []const u8, question_end: usize, out: []u8, deadline: Io.Timeout) !?[]u8 {
    const any_address: net.IpAddress = switch (server.*) {
        .ip4 => .{ .ip4 = .unspecified(0) },
        .ip6 => .{ .ip6 = .unspecified(0) },
    };
    const socket = try any_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    try socket.send(io, server, query);

    while (true) {
        const message = try socket.receiveTimeout(io, out, deadline);
        // Ignore anything that is not the answer to this query.
        if (!message.from.eql(server)) continue;
        if (!dns.isResponseTo(message.data, query, question_end)) continue;
        if (message.flags.trunc or dns.readFlags(message.data).tc) return null;
        return message.data;
    }
}

fn exchangeTcp(io: Io, server: *const net.IpAddress, query: []const u8, question_end: usize, out: []u8, deadline: Io.Timeout) ![]u8 {
    const stream = try tcp.connect(io, server, deadline);
    defer stream.close(io);
    try tcp.writeMessage(io, stream.socket.handle, query, deadline);
    const response = try tcp.readMessage(io, stream.socket.handle, out, deadline);
    if (!dns.isResponseTo(response, query, question_end)) return error.InvalidResponse;
    return response;
}
