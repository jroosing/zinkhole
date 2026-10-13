//! For tests only.

const std = @import("std");
const Io = std.Io;
const testing = std.testing;

/// Turns a test that hangs into one that fails: panics if still running
/// after `seconds`, unless stopped first.
pub const Watchdog = struct {
    future: Io.Future(void),

    pub fn start(seconds: i64) !Watchdog {
        return .{ .future = try testing.io.concurrent(bark, .{seconds}) };
    }

    pub fn stop(watchdog: *Watchdog) void {
        watchdog.future.cancel(testing.io);
    }

    fn bark(seconds: i64) void {
        testing.io.sleep(.fromSeconds(seconds), .awake) catch return; // stopped in time
        @panic("test timed out (watchdog)");
    }
};
