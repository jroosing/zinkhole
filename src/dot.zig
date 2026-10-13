//! DNS over TLS (RFC 7858) to upstream servers.
//!
//! A TLS handshake costs several round trips, so connections are kept open
//! and reused: each server has a small pool of idle connections. A connection
//! carries one query at a time and is discarded after any error, so a pooled
//! connection never has a stray answer waiting in it.
//!
//! The server's certificate is verified against the system's CA certificates
//! and the configured TLS name (e.g. dns.quad9.net). The server is reached by
//! IP address, so no name has to be resolved to find it.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;
const TlsClient = std.crypto.tls.Client;

const dns = @import("dns.zig");
const tcp = @import("tcp.zig");

const log = std.log.scoped(.upstream);

/// Idle connections kept open per server.
const max_idle_connections = 4;
/// Idle connections older than this are closed instead of reused. Servers
/// close idle connections themselves; measured: Cloudflare after 10 s, Quad9
/// after about 11 s, Google after more than 40 s.
const max_idle_seconds = 8;

/// The CA certificates that server certificates are checked against.
/// Loaded once at startup; must not move after `init` (connections point
/// into it).
pub const Trust = struct {
    gpa: Allocator,
    bundle: std.crypto.Certificate.Bundle = .empty,
    lock: Io.RwLock = .init,

    pub fn load(trust: *Trust, io: Io) !void {
        try trust.bundle.rescan(trust.gpa, io, Io.Clock.real.now(io));
        if (trust.bundle.map.count() == 0) return error.NoCaCertificates;
    }

    pub fn deinit(trust: *Trust) void {
        trust.bundle.deinit(trust.gpa);
    }
};

/// An upstream server reached over DNS over TLS.
pub const Tls = struct {
    address: net.IpAddress,
    /// The name the server's certificate must carry.
    name: []const u8,
    trust: *Trust,
    pool: Pool = .{},

    /// `name` and `trust` must outlive the adapter.
    pub fn init(address: net.IpAddress, name: []const u8, trust: *Trust) Tls {
        return .{ .address = address, .name = name, .trust = trust };
    }

    pub fn deinit(tls: *Tls) void {
        tls.pool.deinit();
    }

    /// Sends `query` and reads the answer into `out`, reusing a pooled
    /// connection when possible.
    pub fn exchange(tls: *Tls, io: Io, query: dns.UpstreamQuery, out: []u8, deadline: Io.Timeout) ![]u8 {
        if (tls.pool.take(io, nowSeconds(io))) |connection| {
            if (connection.exchange(query, out, deadline)) |response| {
                tls.pool.put(io, connection, nowSeconds(io));
                return response;
            } else |err| {
                connection.destroy();
                if (err == error.Canceled) return error.Canceled;
                // Most likely the server closed the idle connection; DNS queries
                // are safe to repeat, so try once more on a new connection.
                log.debug("tls://{f}: reused connection failed ({t}), reconnecting", .{ tls.address, err });
            }
        }

        const connection = try Connection.open(io, tls.trust, &tls.address, tls.name, deadline);
        errdefer connection.destroy();
        const response = try connection.exchange(query, out, deadline);
        tls.pool.put(io, connection, nowSeconds(io));
        return response;
    }
};

/// Idle connections to one server, most recently used last.
const Pool = struct {
    mutex: Io.Mutex = .init,
    idle: [max_idle_connections]*Connection = undefined,
    len: usize = 0,

    /// Takes the most recently used idle connection, closing stale ones.
    fn take(pool: *Pool, io: Io, now: i64) ?*Connection {
        pool.mutex.lockUncancelable(io);
        defer pool.mutex.unlock(io);
        while (pool.len > 0) {
            pool.len -= 1;
            const connection = pool.idle[pool.len];
            if (now - connection.last_used <= max_idle_seconds) return connection;
            // The newest one is stale, so all older ones are too.
            connection.destroy();
        }
        return null;
    }

    /// Returns a healthy connection to the pool, or closes it if the pool is full.
    fn put(pool: *Pool, io: Io, connection: *Connection, now: i64) void {
        connection.last_used = now;
        const kept = kept: {
            pool.mutex.lockUncancelable(io);
            defer pool.mutex.unlock(io);
            if (pool.len == pool.idle.len) break :kept false;
            pool.idle[pool.len] = connection;
            pool.len += 1;
            break :kept true;
        };
        if (!kept) connection.destroy();
    }

    pub fn deinit(pool: *Pool) void {
        for (pool.idle[0..pool.len]) |connection| connection.destroy();
        pool.len = 0;
    }
};

/// One TLS connection with its buffers, in a single allocation that must not
/// move (the TLS client points into it).
const Connection = struct {
    gpa: Allocator,
    io: Io,
    stream: net.Stream,
    socket_reader: tcp.DeadlineReader,
    socket_writer: tcp.DeadlineWriter,
    tls: TlsClient,
    /// Boot-clock seconds.
    last_used: i64 = 0,

    /// Encrypted bytes from and to the server; TLS needs room for a full record.
    encrypted_in: [TlsClient.min_buffer_len]u8,
    encrypted_out: [TlsClient.min_buffer_len]u8,
    /// Decrypted bytes: a full record plus anything not yet consumed.
    plain_in: [TlsClient.min_buffer_len + 1024]u8,
    plain_out: [1024]u8,

    fn open(io: Io, trust: *Trust, address: *const net.IpAddress, tls_name: []const u8, deadline: Io.Timeout) !*Connection {
        const gpa = trust.gpa;
        const connection = try gpa.create(Connection);
        errdefer gpa.destroy(connection);
        const stream = try tcp.connect(io, address, deadline);
        errdefer stream.close(io);

        connection.* = .{
            .gpa = gpa,
            .io = io,
            .stream = stream,
            .socket_reader = .init(io, stream.socket.handle, &connection.encrypted_in, deadline),
            .socket_writer = .init(io, stream.socket.handle, &connection.encrypted_out, deadline),
            .tls = undefined, // the handshake below fills it in
            .encrypted_in = undefined,
            .encrypted_out = undefined,
            .plain_in = undefined,
            .plain_out = undefined,
        };

        var entropy: [TlsClient.Options.entropy_len]u8 = undefined;
        io.random(&entropy);
        connection.tls = TlsClient.init(&connection.socket_reader.interface, &connection.socket_writer.interface, .{
            .host = .{ .explicit = tls_name },
            .ca = .{ .bundle = .{ .gpa = gpa, .io = io, .lock = &trust.lock, .bundle = &trust.bundle } },
            .read_buffer = &connection.plain_in,
            .write_buffer = &connection.plain_out,
            .entropy = &entropy,
            .realtime_now = Io.Clock.real.now(io),
        }) catch |err| switch (err) {
            error.ReadFailed => return connection.socket_reader.err orelse error.ReadFailed,
            error.WriteFailed => return connection.socket_writer.err orelse error.WriteFailed,
            else => |e| return e,
        };
        return connection;
    }

    /// Closes the socket without a TLS close_notify: DNS messages carry their
    /// own length, so the server cannot mistake this for a truncated answer.
    fn destroy(connection: *Connection) void {
        connection.stream.close(connection.io);
        connection.gpa.destroy(connection);
    }

    fn exchange(connection: *Connection, query: dns.UpstreamQuery, out: []u8, deadline: Io.Timeout) ![]u8 {
        connection.socket_reader.deadline = deadline;
        connection.socket_writer.deadline = deadline;

        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, @intCast(query.bytes.len), .big);
        const writer = &connection.tls.writer;
        writer.writeAll(&prefix) catch return connection.writeError();
        writer.writeAll(query.bytes) catch return connection.writeError();
        writer.flush() catch return connection.writeError(); // encrypts
        connection.socket_writer.interface.flush() catch return connection.writeError(); // sends

        const reader = &connection.tls.reader;
        const len = reader.takeInt(u16, .big) catch |err| return connection.readError(err);
        if (len > out.len) return error.MessageTooLarge;
        reader.readSliceAll(out[0..len]) catch |err| return connection.readError(err);

        const response = out[0..len];
        if (!query.isAnswer(response)) return error.InvalidResponse;
        return response;
    }

    fn writeError(connection: *Connection) (tcp.SocketError || error{WriteFailed}) {
        return connection.socket_writer.err orelse error.WriteFailed;
    }

    fn readError(connection: *Connection, err: Io.Reader.Error) (tcp.SocketError || TlsClient.ReadError || Io.Reader.Error) {
        if (err == error.EndOfStream) return error.EndOfStream;
        if (connection.socket_reader.err) |socket_err| return socket_err;
        if (connection.tls.read_err) |tls_err| return tls_err;
        return error.ReadFailed;
    }
};

fn nowSeconds(io: Io) i64 {
    return Io.Clock.boot.now(io).toSeconds();
}
