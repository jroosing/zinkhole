//! Log output with a level chosen at runtime (`log.level` in the config).
//!
//! Lines go to stderr as `level(scope): message`, which journald and
//! container runtimes collect as-is (they add their own timestamps).

const std = @import("std");

var current_level: std.atomic.Value(u8) = .init(@backingInt(std.log.Level.info));

pub fn setLevel(level: std.log.Level) void {
    current_level.store(@backingInt(level), .monotonic);
}

pub fn logFn(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@backingInt(level) > current_level.load(.monotonic)) return;
    const prefix = comptime level.asText() ++ (if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ");

    var buffer: [512]u8 = undefined;
    const stderr = std.debug.lockStderr(&buffer);
    defer std.debug.unlockStderr();
    const writer = &stderr.file_writer.interface;
    writer.print(prefix ++ format ++ "\n", args) catch {};
    writer.flush() catch {};
}
