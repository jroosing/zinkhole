//! TCP helpers with deadlines, so a slow or unresponsive peer can never
//! occupy a worker indefinitely:
//!
//!   * DNS over TCP framing (RFC 1035 4.2.2, RFC 7766): every message is
//!     preceded by its length as a big-endian u16.
//!   * `connect` with a deadline.
//!   * `listen` without SO_REUSEPORT.
//!   * `DeadlineReader`/`DeadlineWriter`: `Io.Reader`/`Io.Writer` streams over
//!     a socket whose reads and writes fail once the deadline has passed,
//!     used underneath TLS.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const posix = std.posix;

pub const SocketError = Io.Operation.NetRead.Error ||
    Io.Operation.NetWrite.Error ||
    Io.OperateTimeoutError;

pub const Error = error{ EndOfStream, MessageTooLarge } || SocketError;

/// An absolute deadline `ms` milliseconds from now, shared by several calls.
pub fn deadlineIn(io: Io, ms: u32) Io.Timeout {
    return .{ .deadline = .fromNow(io, .{ .raw = .fromMilliseconds(ms), .clock = .awake }) };
}

/// Reads one length-prefixed message into `buf`.
pub fn readMessage(io: Io, socket: net.Socket.Handle, buf: []u8, deadline: Io.Timeout) Error![]u8 {
    var prefix: [2]u8 = undefined;
    try readExact(io, socket, &prefix, deadline);
    const len = std.mem.readInt(u16, &prefix, .big);
    if (len > buf.len) return error.MessageTooLarge;
    try readExact(io, socket, buf[0..len], deadline);
    return buf[0..len];
}

/// Writes `message` with its length prefix in a single write where possible.
pub fn writeMessage(io: Io, socket: net.Socket.Handle, message: []const u8, deadline: Io.Timeout) Error!void {
    var prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &prefix, @intCast(message.len), .big);
    var written: usize = 0;
    while (written < prefix.len + message.len) {
        const header: []const u8 = if (written < prefix.len) prefix[written..] else &.{};
        const body = [_][]const u8{message[written -| prefix.len..]};
        const result = try io.operateTimeout(.{ .net_write = .{
            .socket_handle = socket,
            .header = header,
            .data = &body,
        } }, deadline);
        written += try result.net_write;
    }
}

fn readExact(io: Io, socket: net.Socket.Handle, buf: []u8, deadline: Io.Timeout) Error!void {
    var filled: usize = 0;
    while (filled < buf.len) {
        var vector = [_][]u8{buf[filled..]};
        const result = try io.operateTimeout(.{ .net_read = .{
            .socket_handle = socket,
            .data = &vector,
        } }, deadline);
        const n = (try result.net_read).data_len;
        if (n == 0) return error.EndOfStream;
        filled += n;
    }
}

/// `IpAddress.connect` with a deadline. Zig 0.17's threaded `Io` cannot time
/// out a connect yet (it panics with "TODO"), so the connect runs as a
/// concurrent task that is canceled when the deadline passes.
pub fn connect(io: Io, address: *const net.IpAddress, deadline: Io.Timeout) !net.Stream {
    var done: Io.Event = .unset;
    var task = try io.concurrent(connectAndSignal, .{ io, address, &done });
    waitUntil(io, &done, deadline) catch |err| {
        // `cancel` waits for the task to finish, so `done` outlives it.
        if (task.cancel(io)) |stream| stream.close(io) else |_| {}
        return err;
    };
    return task.await(io);
}

fn connectAndSignal(io: Io, address: *const net.IpAddress, done: *Io.Event) net.IpAddress.ConnectError!net.Stream {
    defer done.set(io);
    return address.connect(io, .{ .mode = .stream, .protocol = .tcp });
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

pub const ListenError = error{
    AddressInUse,
    AddressUnavailable,
    AddressFamilyUnsupported,
    AccessDenied,
    SystemResources,
    Unexpected,
};

/// Like `IpAddress.listen(.{ .reuse_address = true })`, but with only
/// SO_REUSEADDR (so a restart can bind again despite connections in
/// TIME_WAIT) and not SO_REUSEPORT, which would let another socket bind the
/// same port and take a share of the connections. `ip6_only` makes an IPv6
/// listener IPv6-only, so that an IPv4 listener can share its port.
pub fn listen(address: net.IpAddress, ip6_only: bool) ListenError!net.Server {
    const family: u32 = switch (address) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
    const rc = posix.system.socket(family, posix.SOCK.STREAM, posix.IPPROTO.TCP);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        .AFNOSUPPORT => return error.AddressFamilyUnsupported,
        .MFILE, .NFILE, .NOBUFS, .NOMEM => return error.SystemResources,
        else => return error.Unexpected,
    }
    const fd: posix.socket_t = @intCast(rc);
    errdefer _ = posix.system.close(fd);
    try setOption(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, 1);
    if (address == .ip6) try setOption(fd, posix.IPPROTO.IPV6, posix.IPV6.V6ONLY, @intFromBool(ip6_only));

    var storage: SocketAddress = .from(address);
    switch (posix.errno(posix.system.bind(fd, &storage.any, storage.len()))) {
        .SUCCESS => {},
        .ADDRINUSE => return error.AddressInUse,
        .ADDRNOTAVAIL => return error.AddressUnavailable,
        .ACCES, .PERM => return error.AccessDenied,
        else => return error.Unexpected,
    }
    switch (posix.errno(posix.system.listen(fd, 128))) {
        .SUCCESS => {},
        .ADDRINUSE => return error.AddressInUse,
        else => return error.Unexpected,
    }
    // The resolved port, if `address` asked for any (port 0).
    var len: posix.socklen_t = @sizeOf(SocketAddress);
    if (posix.errno(posix.system.getsockname(fd, &storage.any, &len)) != .SUCCESS) return error.Unexpected;
    return .{ .socket = .{ .handle = fd, .address = storage.toAddress() }, .options = {} };
}

fn setOption(fd: posix.socket_t, level: i32, name: u32, value: u32) error{Unexpected}!void {
    const bytes: []const u8 = @ptrCast(&value);
    if (posix.errno(posix.system.setsockopt(fd, level, name, bytes.ptr, @intCast(bytes.len))) != .SUCCESS) {
        return error.Unexpected;
    }
}

const SocketAddress = extern union {
    any: posix.sockaddr,
    in: posix.sockaddr.in,
    in6: posix.sockaddr.in6,

    fn from(address: net.IpAddress) SocketAddress {
        return switch (address) {
            .ip4 => |a| .{ .in = .{ .port = std.mem.nativeToBig(u16, a.port), .addr = @bitCast(a.bytes) } },
            .ip6 => |a| .{ .in6 = .{
                .port = std.mem.nativeToBig(u16, a.port),
                .flowinfo = a.flow,
                .addr = a.bytes,
                .scope_id = a.interface.index,
            } },
        };
    }

    fn len(sa: *const SocketAddress) posix.socklen_t {
        return if (sa.any.family == posix.AF.INET) @sizeOf(posix.sockaddr.in) else @sizeOf(posix.sockaddr.in6);
    }

    fn toAddress(sa: *const SocketAddress) net.IpAddress {
        if (sa.any.family == posix.AF.INET) {
            return .{ .ip4 = .{ .bytes = @bitCast(sa.in.addr), .port = std.mem.bigToNative(u16, sa.in.port) } };
        }
        return .{ .ip6 = .{
            .bytes = sa.in6.addr,
            .port = std.mem.bigToNative(u16, sa.in6.port),
            .flow = sa.in6.flowinfo,
            .interface = .{ .index = sa.in6.scope_id },
        } };
    }
};

/// An `Io.Reader` over a socket. Reads fail with `error.Timeout` (in `err`)
/// once `deadline` has passed; set a new deadline before each exchange.
pub const DeadlineReader = struct {
    io: Io,
    socket: net.Socket.Handle,
    deadline: Io.Timeout,
    interface: Io.Reader,
    /// Why the last read failed with `error.ReadFailed`.
    err: ?SocketError = null,

    pub fn init(io: Io, socket: net.Socket.Handle, buffer: []u8, deadline: Io.Timeout) DeadlineReader {
        return .{
            .io = io,
            .socket = socket,
            .deadline = deadline,
            .interface = .{
                .vtable = &.{ .stream = stream, .readVec = readVec },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn stream(io_r: *Io.Reader, io_w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const dest = limit.slice(try io_w.writableSliceGreedy(1));
        var data: [1][]u8 = .{dest};
        const n = try readVec(io_r, &data);
        io_w.advance(n);
        return n;
    }

    fn readVec(io_r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        const r: *DeadlineReader = @alignCast(@fieldParentPtr("interface", io_r));
        var vectors: [8][]u8 = undefined;
        const count, const data_size = try io_r.writableVector(&vectors, data);
        const result = r.io.operateTimeout(.{ .net_read = .{
            .socket_handle = r.socket,
            .data = vectors[0..count],
        } }, r.deadline) catch |err| return r.fail(err);
        const n = (result.net_read catch |err| return r.fail(err)).data_len;
        if (n == 0) return error.EndOfStream;
        // Bytes beyond `data` landed in the reader's own buffer.
        if (n > data_size) {
            io_r.end += n - data_size;
            return data_size;
        }
        return n;
    }

    fn fail(r: *DeadlineReader, err: SocketError) error{ReadFailed} {
        r.err = err;
        return error.ReadFailed;
    }
};

/// An `Io.Writer` over a socket. Writes fail with `error.Timeout` (in `err`)
/// once `deadline` has passed; set a new deadline before each exchange.
pub const DeadlineWriter = struct {
    io: Io,
    socket: net.Socket.Handle,
    deadline: Io.Timeout,
    interface: Io.Writer,
    /// Why the last write failed with `error.WriteFailed`.
    err: ?SocketError = null,

    pub fn init(io: Io, socket: net.Socket.Handle, buffer: []u8, deadline: Io.Timeout) DeadlineWriter {
        return .{
            .io = io,
            .socket = socket,
            .deadline = deadline,
            .interface = .{ .vtable = &.{ .drain = drain }, .buffer = buffer },
        };
    }

    fn drain(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const w: *DeadlineWriter = @alignCast(@fieldParentPtr("interface", io_w));
        const result = w.io.operateTimeout(.{ .net_write = .{
            .socket_handle = w.socket,
            .header = io_w.buffered(),
            .data = data,
            .splat = splat,
        } }, w.deadline) catch |err| return w.fail(err);
        const n = result.net_write catch |err| return w.fail(err);
        return io_w.consume(n);
    }

    fn fail(w: *DeadlineWriter, err: SocketError) error{WriteFailed} {
        w.err = err;
        return error.WriteFailed;
    }
};
