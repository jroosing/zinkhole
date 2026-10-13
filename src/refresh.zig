//! The Refresh schedule: decides when the lists are loaded. It only sees
//! time (plain seconds) and events; the supervisor runs the loads.
//!
//!   * first load at start, then one Refresh interval after each complete load
//!   * incomplete loads are retried after 60 s, doubling, capped at the interval
//!   * a load running longer than 10 minutes is canceled (incomplete)
//!   * a reload that changes the sources cancels the running load and starts
//!     a new one at once, with a fresh retry delay

const std = @import("std");

const log = std.log.scoped(.lists);

/// A load running longer than this is canceled and counts as incomplete.
const load_timeout_s = 10 * 60;
/// First retry after an incomplete load; doubles with every further one.
const min_retry_delay_s = 60;
/// The retry delay never exceeds the Refresh interval, or this without one.
const max_retry_delay_s = 24 * 3600;

pub const Schedule = struct {
    /// When the running load started (seconds); null when none is running.
    running_since: ?i64 = null,
    /// When the last complete load finished; null before the first one.
    last_complete: ?i64 = null,
    /// Incomplete loads since the last complete one, and when the latest ended.
    failures: u32 = 0,
    last_failure: i64 = 0,
    /// A reload changed the sources since the last load started.
    sources_changed: bool = false,
    /// The interval at the last tick, for logging when the next retry is due.
    interval: ?i64 = null,

    pub const Action = enum { idle, start, cancel };

    /// Called every tick. `interval` (seconds) comes from the current config;
    /// null means no Refresh.
    pub fn next(s: *Schedule, now: i64, interval: ?i64) Action {
        s.interval = interval;
        if (s.running_since) |since| {
            // A load of outdated sources is not worth finishing.
            if (s.sources_changed) {
                log.info("the sources changed, canceling the running load", .{});
                return .cancel;
            }
            if (now - since > load_timeout_s) {
                log.warn("loading lists took longer than {d} minutes, canceled", .{load_timeout_s / 60});
                return .cancel;
            }
            return .idle;
        }
        if (s.sources_changed) return .start;
        if (s.failures > 0) {
            return if (now >= s.last_failure + retryDelay(s.failures, interval)) .start else .idle;
        }
        const last = s.last_complete orelse return .start;
        const refresh = interval orelse return .idle;
        return if (now >= last + refresh) .start else .idle;
    }

    pub fn started(s: *Schedule, now: i64) void {
        s.running_since = now;
        s.sources_changed = false;
    }

    /// After a `cancel`, report the load as incomplete.
    pub fn finished(s: *Schedule, now: i64, complete: bool) void {
        // Canceled because the sources changed: not a failure of the sources.
        const superseded = s.running_since != null and s.sources_changed;
        s.running_since = null;
        // A load that could not start counts as a failed load of the current
        // sources; retrying on every tick would not help.
        if (!superseded) s.sources_changed = false;
        if (complete) {
            s.last_complete = now;
            s.failures = 0;
        } else if (!superseded) {
            s.failures +|= 1;
            s.last_failure = now;
            const delay = retryDelay(s.failures, s.interval);
            log.info("retrying the lists in {d} minutes", .{@divTrunc(delay + 59, 60)});
        }
    }

    /// A reload changed the sources: load them at once, with a fresh retry delay.
    pub fn sourcesChanged(s: *Schedule) void {
        s.sources_changed = true;
        s.failures = 0;
    }

    /// 60 s after the first incomplete load, doubling after each further one,
    /// capped at the interval in force.
    fn retryDelay(failures: u32, interval: ?i64) i64 {
        const doubled = @as(i64, min_retry_delay_s) << @intCast(@min(failures - 1, 30));
        return @min(doubled, interval orelse max_retry_delay_s);
    }
};

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

const hour = 3600;

test "the first tick starts a load" {
    var s: Schedule = .{};
    try testing.expectEqual(.start, s.next(0, hour));
}

test "a running load is left alone, and canceled after 10 minutes" {
    // The timeout is logged as a warning; keep the test output quiet.
    const log_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = log_level;

    var s: Schedule = .{};
    s.started(100);
    try testing.expectEqual(.idle, s.next(101, hour));
    try testing.expectEqual(.idle, s.next(100 + 600, hour));
    try testing.expectEqual(.cancel, s.next(100 + 601, hour));
    // The canceled load counts as incomplete.
    s.finished(100 + 601, false);
    try testing.expectEqual(.idle, s.next(100 + 601 + 59, hour));
    try testing.expectEqual(.start, s.next(100 + 601 + 60, hour));
}

test "after a complete load, the next starts one interval later" {
    var s: Schedule = .{};
    s.started(0);
    s.finished(10, true);
    try testing.expectEqual(.idle, s.next(11, hour));
    try testing.expectEqual(.idle, s.next(10 + hour - 1, hour));
    try testing.expectEqual(.start, s.next(10 + hour, hour));
}

test "without an interval, a complete load is the last one" {
    var s: Schedule = .{};
    s.started(0);
    s.finished(10, true);
    try testing.expectEqual(.idle, s.next(10 + 1000 * 24 * hour, null));
}

/// Fails a load at `now` and checks it is retried exactly `delay` later.
fn expectRetryAfter(s: *Schedule, now: i64, interval: ?i64, delay: i64) !void {
    s.started(now);
    s.finished(now, false);
    try testing.expectEqual(.idle, s.next(now + delay - 1, interval));
    try testing.expectEqual(.start, s.next(now + delay, interval));
}

test "incomplete loads are retried with a doubling delay, capped at the interval" {
    var s: Schedule = .{};
    var now: i64 = 0;
    for ([_]i64{ 60, 120, 240, 480, 960, 1920, hour, hour }) |delay| {
        try expectRetryAfter(&s, now, hour, delay);
        now += delay;
    }

    // Without an interval, the cap is a day.
    var no_refresh: Schedule = .{};
    now = 0;
    for ([_]i64{ 60, 120, 240, 480, 960, 1920, 3840, 7680, 15360, 30720, 61440, 24 * hour, 24 * hour }) |delay| {
        try expectRetryAfter(&no_refresh, now, null, delay);
        now += delay;
    }
}

test "a complete load resets the retry delay" {
    var s: Schedule = .{};
    try expectRetryAfter(&s, 0, hour, 60);
    try expectRetryAfter(&s, 60, hour, 120);
    s.started(180);
    s.finished(190, true);
    try expectRetryAfter(&s, 190 + hour, hour, 60);
}

test "a changed interval applies at once" {
    var s: Schedule = .{};
    s.started(0);
    s.finished(0, true);

    // 24 h -> 1 h, three hours after the last load: load now.
    try testing.expectEqual(.idle, s.next(3 * hour, 24 * hour));
    try testing.expectEqual(.start, s.next(3 * hour, hour));
    // Refresh turned off, then on again.
    try testing.expectEqual(.idle, s.next(3 * hour, null));
    try testing.expectEqual(.idle, s.next(24 * hour - 1, 24 * hour));
    try testing.expectEqual(.start, s.next(24 * hour, 24 * hour));
}

test "changed sources start a load at once, with a fresh retry delay" {
    var s: Schedule = .{};
    s.started(0);
    s.finished(0, true);
    s.sourcesChanged();
    try testing.expectEqual(.start, s.next(10, hour));

    // While retrying the old sources.
    var retrying: Schedule = .{};
    try expectRetryAfter(&retrying, 0, hour, 60);
    try expectRetryAfter(&retrying, 60, hour, 120);
    retrying.sourcesChanged();
    try testing.expectEqual(.start, retrying.next(181, hour));
    try expectRetryAfter(&retrying, 181, hour, 60);
}

test "changed sources cancel the running load, without counting a failure" {
    var s: Schedule = .{};
    s.started(0);
    s.sourcesChanged();
    try testing.expectEqual(.cancel, s.next(5, hour));
    s.finished(5, false);
    try testing.expectEqual(.start, s.next(5, hour));
    // The canceled load did not count: the next failure waits 60 s, not 120.
    try expectRetryAfter(&s, 6, hour, 60);
}

test "a load that could not start waits for the retry delay" {
    var s: Schedule = .{};
    s.finished(0, false);
    try testing.expectEqual(.idle, s.next(59, hour));
    try testing.expectEqual(.start, s.next(60, hour));

    // Also right after the sources changed: no new attempt on every tick.
    var changed: Schedule = .{};
    changed.started(0);
    changed.finished(0, true);
    changed.sourcesChanged();
    changed.finished(10, false);
    try testing.expectEqual(.idle, changed.next(11, hour));
    try testing.expectEqual(.start, changed.next(70, hour));
}
