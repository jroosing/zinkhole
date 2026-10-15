//! For tests only.

const std = @import("std");

/// A corpus entry for a fuzz test that reads its input with one
/// `Smith.slice`: the length as a little-endian u32, then the bytes. A
/// plain `zig build test` runs each entry once; `--fuzz` starts from them.
pub fn input(comptime bytes: []const u8) *const [4 + bytes.len]u8 {
    return comptime &(std.mem.toBytes(std.mem.nativeToLittle(u32, bytes.len)) ++ bytes[0..bytes.len].*);
}

test "a corpus entry reads back through Smith.slice" {
    var smith: std.testing.Smith = .{ .in = input("abc") };
    var buf: [8]u8 = undefined;
    try std.testing.expectEqualStrings("abc", buf[0..smith.slice(&buf)]);
}
