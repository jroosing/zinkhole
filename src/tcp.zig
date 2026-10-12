//! DNS over TCP framing (RFC 1035 4.2.2, RFC 7766): every message is preceded
//! by its length as a big-endian u16. Each read and write has a deadline, so
//! a slow or idle peer cannot occupy a worker indefinitely.

const std = @import("std");
const Io = std.Io;
const net = Io.net;

pub const Error = error{ EndOfStream, MessageTooLarge } ||
    Io.Operation.NetRead.Error ||
    Io.Operation.NetWrite.Error ||
    Io.OperateTimeoutError;

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
