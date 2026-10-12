//! Network front end: UDP and TCP listeners served by a fixed pool of worker
//! threads. Memory is fixed at startup: each worker owns one query and one
//! response buffer, and answering a query allocates nothing (only cache
//! insertions do).

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;

const dns = @import("dns.zig");
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
                if (address == .ip6 and err == error.AddressFamilyUnsupported) {
                    log.warn("IPv6 is not available, skipping {f}", .{address});
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

            // SO_REUSEADDR/SO_REUSEPORT: lets an IPv6 dual-stack listener and
            // an IPv4 listener share the port, and allows quick restarts.
            var listener = address.listen(server.io, .{ .reuse_address = true }) catch |err| {
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
