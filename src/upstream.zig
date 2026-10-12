//! Forwarding to upstream DNS servers: UDP first, TCP when the answer is
//! truncated. Servers are tried in order, starting with the one that answered
//! last, so a dead server costs one timeout instead of one per query.
//!
//! Spoofing defenses: every exchange uses a fresh socket (random source port)
//! and a random query ID, and only answers from the server's address with the
//! same ID and the same question are accepted.

const std = @import("std");
const Io = std.Io;
const net = Io.net;

const dns = @import("dns.zig");
const tcp = @import("tcp.zig");

const log = std.log.scoped(.upstream);

pub const Upstream = struct {
    servers: []const net.IpAddress,
    timeout_ms: u32,
    /// Index of the server that answered most recently.
    preferred: std.atomic.Value(usize) = .init(0),

    pub const Error = error{AllServersFailed} || Io.Cancelable;

    /// Forwards the client's query `msg` and writes the answer to `out` with
    /// the client's ID restored. Rewrites `msg` in place (see
    /// `dns.rewriteForUpstream`); its question section stays intact.
    pub fn forward(upstream: *Upstream, io: Io, msg: []u8, q: *const dns.Query, out: []u8) Error![]u8 {
        const query = dns.rewriteForUpstream(msg, q);
        const first = upstream.preferred.load(.monotonic);
        for (0..upstream.servers.len) |attempt| {
            const index = (first + attempt) % upstream.servers.len;
            const server = &upstream.servers[index];
            const response = upstream.exchange(io, server, query, q.question_end, out) catch |err| {
                if (err == error.Canceled) return error.Canceled;
                log.debug("{f}: {t}", .{ server.*, err });
                continue;
            };
            if (index != first) upstream.preferred.store(index, .monotonic);
            dns.setId(response, q.id);
            return response;
        }
        return error.AllServersFailed;
    }

    fn exchange(upstream: *Upstream, io: Io, server: *const net.IpAddress, query: []u8, question_end: usize, out: []u8) ![]u8 {
        var id: [2]u8 = undefined;
        io.random(&id);
        dns.setId(query, std.mem.readInt(u16, &id, .big));

        const response = try exchangeUdp(io, server, query, question_end, out, tcp.deadlineIn(io, upstream.timeout_ms)) orelse
            try exchangeTcp(io, server, query, question_end, out, tcp.deadlineIn(io, upstream.timeout_ms));
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
    const stream = try connectTcp(io, server, deadline);
    defer stream.close(io);
    try tcp.writeMessage(io, stream.socket.handle, query, deadline);
    const response = try tcp.readMessage(io, stream.socket.handle, out, deadline);
    if (!dns.isResponseTo(response, query, question_end)) return error.InvalidResponse;
    return response;
}

/// `IpAddress.connect` with a deadline. Zig 0.17's threaded `Io` cannot time
/// out a connect yet (it panics with "TODO"), so the connect runs as a
/// concurrent task that is canceled when the deadline passes.
fn connectTcp(io: Io, server: *const net.IpAddress, deadline: Io.Timeout) !net.Stream {
    var done: Io.Event = .unset;
    var task = try io.concurrent(connectAndSignal, .{ io, server, &done });
    waitUntil(io, &done, deadline) catch |err| {
        // `cancel` waits for the task to finish, so `done` outlives it.
        if (task.cancel(io)) |stream| stream.close(io) else |_| {}
        return err;
    };
    return task.await(io);
}

fn connectAndSignal(io: Io, server: *const net.IpAddress, done: *Io.Event) net.IpAddress.ConnectError!net.Stream {
    defer done.set(io);
    return server.connect(io, .{ .mode = .stream, .protocol = .tcp });
}

/// Waits for `event`, retrying spurious wakeups until `deadline` has passed.
fn waitUntil(io: Io, event: *Io.Event, deadline: Io.Timeout) Io.Event.WaitTimeoutError!void {
    while (true) {
        event.waitTimeout(io, deadline) catch |err| switch (err) {
            error.Timeout => {
                const remaining = deadline.toDurationFromNow(io).?;
                if (remaining.raw.toMilliseconds() > 0) continue;
                return error.Timeout;
            },
            error.Canceled => |e| return e,
        };
        return;
    }
}
