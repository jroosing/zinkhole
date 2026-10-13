//! A small HTTP service for the sync origin and the metrics endpoint: one
//! listener per address, each answering one request at a time, and only to
//! allowed clients. Every request must be complete, answers included, within
//! a deadline, and a canceled service never waits for a slow client.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;

const ip = @import("ip.zig");
const tcp = @import("tcp.zig");

const log = std.log.scoped(.http);

/// A request, and its answer, must be done within this.
const request_timeout_ms = 5_000;
/// The request line and headers must fit in this. Behind a reverse proxy,
/// browsers send every cookie of the parent domain along.
const max_head_len = 16 * 1024;

/// Answers one request on `server`, from `client`.
pub const Handler = struct {
    context: *anyopaque,
    answer: *const fn (context: *anyopaque, server: *std.http.Server, client: net.IpAddress) anyerror!void,
};

pub const HttpService = struct {
    io: Io,
    gpa: Allocator,
    allow_clients: []const ip.Cidr,
    handler: Handler,
    listeners: std.ArrayList(net.Server) = .empty,
    group: Io.Group = .init,
    /// Set once the serve tasks hold pointers into `listeners`.
    pointers_locked: bool = false,

    /// Listens on `addresses` and starts serving. `service` must not move
    /// afterwards; `allow_clients` must outlive it.
    pub fn init(service: *HttpService, io: Io, gpa: Allocator, addresses: []const net.IpAddress, allow_clients: []const ip.Cidr, handler: Handler) !void {
        service.* = .{ .io = io, .gpa = gpa, .allow_clients = allow_clients, .handler = handler };
        errdefer service.deinit();
        for (addresses) |listen_address| {
            // IPv6-only next to an IPv4 listener on the same port.
            const ip6_only = listen_address == .ip6 and for (addresses) |other| {
                if (other == .ip4 and other.getPort() == listen_address.getPort()) break true;
            } else false;
            var listener = try tcp.listen(listen_address, ip6_only);
            service.listeners.append(gpa, listener) catch |err| {
                listener.deinit(io);
                return err;
            };
        }
        // Tasks keep pointers into the list from here on.
        service.listeners.lockPointers();
        service.pointers_locked = true;
        for (service.listeners.items) |*listener| try service.group.concurrent(io, serve, .{ service, listener });
    }

    /// Stops serving, also in the middle of a request.
    pub fn deinit(service: *HttpService) void {
        service.group.cancel(service.io);
        if (service.pointers_locked) service.listeners.unlockPointers();
        for (service.listeners.items) |*listener| listener.deinit(service.io);
        service.listeners.deinit(service.gpa);
        service.* = undefined;
    }

    /// The first listen address, with its port resolved.
    pub fn address(service: *const HttpService) net.IpAddress {
        return service.listeners.items[0].socket.address;
    }

    fn serve(service: *HttpService, listener: *net.Server) Io.Cancelable!void {
        const io = service.io;
        while (true) {
            const stream = listener.accept(io) catch |err| switch (err) {
                error.Canceled => |e| return e,
                else => {
                    log.debug("accept: {t}", .{err});
                    try io.sleep(.fromMilliseconds(100), .awake);
                    continue;
                },
            };
            defer stream.close(io);
            // Before reading anything: a client that may not ask must not get
            // to hold the only serve task for a request's deadline.
            if (!ip.isAllowed(service.allow_clients, stream.socket.address)) continue;
            service.handle(stream) catch |err| {
                if (err == error.Canceled) return error.Canceled;
                log.debug("request from {f}: {t}", .{ stream.socket.address, err });
            };
        }
    }

    fn handle(service: *HttpService, stream: net.Stream) !void {
        const io = service.io;
        const deadline = tcp.deadlineIn(io, request_timeout_ms);
        var in_buf: [max_head_len]u8 = undefined;
        var out_buf: [4096]u8 = undefined;
        var reader: tcp.DeadlineReader = .init(io, stream.socket.handle, &in_buf, deadline);
        var writer: tcp.DeadlineWriter = .init(io, stream.socket.handle, &out_buf, deadline);
        var server: std.http.Server = .init(&reader.interface, &writer.interface);
        service.handler.answer(service.handler.context, &server, stream.socket.address) catch |err| {
            // The deadline streams report every socket error as ReadFailed or
            // WriteFailed. A cancellation hidden in there must still end the
            // task: swallowed, it would leave `deinit` waiting forever.
            if (reader.err) |socket_err| if (socket_err == error.Canceled) return error.Canceled;
            if (writer.err) |socket_err| if (socket_err == error.Canceled) return error.Canceled;
            return err;
        };
    }
};
