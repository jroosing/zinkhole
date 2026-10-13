//! Metrics (ADR-0004): counts per local hour for the last 24 hours, and the
//! current state of the instance, served as JSON.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;

const ip = @import("ip.zig");
const localtime = @import("localtime.zig");
const tcp = @import("tcp.zig");
const HttpService = @import("http_service.zig").HttpService;
const Zone = localtime.Zone;
const Outcome = @import("resolver.zig").Outcome;
const Cache = @import("cache.zig").Cache;
const upstream_mod = @import("upstream.zig");
const ServerAddress = upstream_mod.ServerAddress;
const Upstream = upstream_mod.Upstream;

pub const Window = enum { today, last_24h };

const hour_seconds = 3600;
const day_seconds = 24 * hour_seconds;

/// Hours are numbered from the epoch, with their boundaries on the local
/// hour. Changes between standard and daylight saving time shift the offset
/// by whole hours, so every hour gets its own number: the repeated hour in
/// the autumn as well.
fn hourOf(zone: *const Zone, t: i64) usize {
    const phase = @mod(zone.offsetAt(t), hour_seconds);
    return @intCast(@max(0, @divFloor(t + phase, hour_seconds)));
}

/// UTC time of the local midnight that starts the day `t` falls in.
fn startOfDay(zone: *const Zone, t: i64) i64 {
    const local = t + zone.offsetAt(t);
    const midnight = local - @mod(local, day_seconds);
    // The offset at midnight can differ from the one now.
    return midnight - zone.offsetAt(midnight - zone.offsetAt(t));
}

/// Counts per key for each of the latest 25 hours; a day with a change
/// from daylight saving time has 25.
fn Hourly(comptime Key: type) type {
    return struct {
        const Self = @This();
        const bucket_count = 25;
        /// Marks a bucket that is being cleared for a new hour.
        const clearing = std.math.maxInt(usize);

        /// Word-sized, because 32-bit targets (e.g. ARMv7) lack 64-bit atomics.
        const Bucket = struct {
            hour: std.atomic.Value(usize) = .init(0),
            counts: std.EnumArray(Key, std.atomic.Value(usize)) = .initFill(.init(0)),
        };

        buckets: [bucket_count]Bucket = @splat(.{}),

        fn add(h: *Self, hour: usize, key: Key, amount: usize) void {
            const bucket = h.claim(hour) orelse return;
            _ = bucket.counts.getPtr(key).fetchAdd(amount, .monotonic);
        }

        /// The bucket for `hour`, cleared first if it held an older hour.
        /// Null if it holds a newer one (the clock went back a day or more).
        fn claim(h: *Self, hour: usize) ?*Bucket {
            const bucket = &h.buckets[hour % bucket_count];
            var current = bucket.hour.load(.acquire);
            while (current != hour) {
                if (current == clearing) {
                    std.atomic.spinLoopHint();
                    current = bucket.hour.load(.acquire);
                    continue;
                }
                if (current > hour) return null;
                if (bucket.hour.cmpxchgWeak(current, clearing, .acquire, .acquire)) |actual| {
                    current = actual;
                    continue;
                }
                for (&bucket.counts.values) |*count| count.store(0, .monotonic);
                bucket.hour.store(hour, .release);
                return bucket;
            }
            return bucket;
        }

        /// The counts of hours `first` to `last`, inclusive.
        fn sum(h: *const Self, first: usize, last: usize) std.EnumArray(Key, usize) {
            var sums: std.EnumArray(Key, usize) = .initFill(0);
            for (&h.buckets) |*bucket| {
                const hour = bucket.hour.load(.acquire);
                if (hour < first or hour > last) continue;
                for (&sums.values, &bucket.counts.values) |*sum_value, *count| sum_value.* += count.load(.monotonic);
            }
            return sums;
        }
    };
}

/// What one upstream server did with the queries sent to it.
pub const Attempts = struct {
    answers: usize,
    failures: usize,
    /// The time until the answers came, in tenths of a millisecond.
    answer_time: usize,

    /// Null without answers.
    pub fn averageMs(a: Attempts) ?f64 {
        if (a.answers == 0) return null;
        return @as(f64, @floatFromInt(a.answer_time)) / 10 / @as(f64, @floatFromInt(a.answers));
    }
};

const AttemptKey = enum { answers, failures, answer_time };

/// One query sent to one upstream server.
pub const Attempt = union(enum) {
    /// An answer, and how long it took in tenths of a millisecond.
    answer: u32,
    /// A timeout, an error or REFUSED.
    failure,
};

pub const Role = enum { standalone, origin, replica };

/// What changes when this process restarts, and nothing else.
pub const Options = struct {
    /// Owned by `Metrics` from `init` on.
    zone: Zone,
    role: Role = .standalone,
    /// Replica only: the origin's URL.
    origin: []const u8 = "",
    /// When this process started (Unix time).
    started: i64,
    upstream: []const ServerAddress = &.{},
};

/// How a list load went.
pub const ListLoad = struct {
    /// Each source, and whether this load got it.
    sources: []const Source,
    complete: bool,
    /// When it finished (Unix time).
    finished: i64,

    pub const Source = struct { source: []const u8, ok: bool };
};

/// What the endpoint reads at the moment of a request.
pub const Live = struct {
    /// Index of the upstream server asked first.
    preferred_upstream: usize,
    cache_entries: usize,
    cache_capacity: usize,
};

pub const Metrics = struct {
    io: Io,
    gpa: Allocator,
    zone: Zone,
    role: Role,
    started: i64,
    /// Holds `upstream_names`.
    arena: std.heap.ArenaAllocator,
    /// As configured, such as `tls://9.9.9.9:853#dns.quad9.net`.
    upstream_names: []const []const u8,
    /// Replica only; in `arena`.
    origin: []const u8,
    query_counts: Hourly(Outcome) = .{},
    /// One per upstream server, in config order.
    attempt_counts: []Hourly(AttemptKey),

    /// Guards the fields below: the supervisor and the origin write them,
    /// the endpoint reads them.
    mutex: Io.Mutex = .init,
    /// Holds the strings in `sources`.
    sources_arena: std.heap.ArenaAllocator,
    /// As the latest load found them.
    sources: []const ListLoad.Source = &.{},
    last_complete_load: ?i64 = null,
    /// Domains in the lists in use.
    blocked_domains: usize = 0,
    allowed_domains: usize = 0,
    next_load: ?i64 = null,
    local_records: usize = 0,
    last_sync: ?i64 = null,
    sync_failures: u32 = 0,
    fetches: [max_fetchers]Fetch = undefined,
    fetch_count: usize = 0,

    const max_fetchers = 16;
    const Fetch = struct { address: ip.Ip, at: i64 };

    pub fn init(io: Io, gpa: Allocator, options: Options) Allocator.Error!Metrics {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        errdefer arena.deinit();
        const names = try arena.allocator().alloc([]const u8, options.upstream.len);
        for (options.upstream, names) |server, *name| name.* = try std.fmt.allocPrint(arena.allocator(), "{f}", .{server});
        const origin = try arena.allocator().dupe(u8, options.origin);
        const attempt_counts = try gpa.alloc(Hourly(AttemptKey), options.upstream.len);
        @memset(attempt_counts, .{});
        return .{
            .io = io,
            .gpa = gpa,
            .zone = options.zone,
            .role = options.role,
            .started = options.started,
            .arena = arena,
            .upstream_names = names,
            .origin = origin,
            .attempt_counts = attempt_counts,
            .sources_arena = .init(gpa),
        };
    }

    pub fn deinit(m: *Metrics) void {
        m.gpa.free(m.attempt_counts);
        m.sources_arena.deinit();
        m.arena.deinit();
        m.zone.deinit(m.gpa);
        m.* = undefined;
    }

    /// The JSON document (ADR-0004) as of `now`. Indented, with the summary
    /// first and one line per hour last, so it reads well in a terminal.
    pub fn write(m: *Metrics, w: *Io.Writer, now: i64, live: Live) Io.Writer.Error!void {
        try w.print("{{\n  \"format\": 1,\n  \"version\": \"{s}\",\n  \"role\": \"{t}\",\n  \"now\": ", .{ version, m.role });
        try m.writeTime(w, now, .seconds);
        try w.writeAll(",\n  \"started\": ");
        try m.writeTime(w, m.started, .seconds);
        try w.print(",\n  \"uptime_s\": {d},\n  \"time_zone\": ", .{@max(0, now - m.started)});
        try writeString(w, m.zone.name());

        try w.writeAll(",\n  \"queries\": {\n    \"today\": ");
        try writeQueries(w, m.queries(.today, now));
        try w.writeAll(",\n    \"last_24h\": ");
        try writeQueries(w, m.queries(.last_24h, now));

        try w.writeAll("\n  },\n  \"upstream\": [");
        for (m.upstream_names, 0..) |name, server| {
            try w.writeAll(if (server == 0) "\n    { \"server\": " else ",\n    { \"server\": ");
            try writeString(w, name);
            try w.print(", \"preferred\": {},\n      \"today\": ", .{server == live.preferred_upstream});
            try writeAttempts(w, m.attempts(server, .today, now));
            try w.writeAll(",\n      \"last_24h\": ");
            try writeAttempts(w, m.attempts(server, .last_24h, now));
            try w.writeAll(" }");
        }
        try w.writeAll(if (m.upstream_names.len == 0) "]" else "\n  ]");
        try m.writeStatus(w, now, live);

        try w.writeAll(",\n  \"hourly\": [");
        const last = hourOf(&m.zone, now);
        const phase = @mod(m.zone.offsetAt(now), hour_seconds);
        for (0..24) |i| {
            const hour = (last + i) -| 23;
            try w.writeAll(if (i == 0) "\n    { \"hour\": " else ",\n    { \"hour\": ");
            try m.writeTime(w, @as(i64, @intCast(hour)) * hour_seconds - phase, .minutes);
            const counts = m.query_counts.sum(hour, hour);
            try w.print(", \"total\": {d}", .{total(counts)});
            for (hourly_order) |outcome| try w.print(", \"{t}\": {d}", .{ outcome, counts.get(outcome) });
            try w.writeAll(" }");
        }
        try w.writeAll("\n  ]\n}\n");
    }

    /// ISO 8601 in local time, with the offset.
    fn writeTime(m: *const Metrics, w: *Io.Writer, t: i64, precision: enum { seconds, minutes }) Io.Writer.Error!void {
        const offset = m.zone.offsetAt(t);
        const local = t + offset;
        const date = localtime.dateOfDay(@divFloor(local, day_seconds));
        const seconds: u32 = @intCast(@mod(local, day_seconds));
        try w.print("\"{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}", .{ @as(u64, @intCast(@max(0, date.year))), date.month, date.day, seconds / 3600, seconds / 60 % 60 });
        if (precision == .seconds) try w.print(":{d:0>2}", .{seconds % 60});
        const east = @abs(offset);
        try w.print("{c}{d:0>2}:{d:0>2}\"", .{ @as(u8, if (offset < 0) '-' else '+'), east / 3600, east / 60 % 60 });
    }

    /// A list load finished. Copies the sources, without their query
    /// strings, which can hold tokens.
    pub fn setLists(m: *Metrics, load: ListLoad) Allocator.Error!void {
        var arena: std.heap.ArenaAllocator = .init(m.gpa);
        errdefer arena.deinit();
        const sources = try arena.allocator().alloc(ListLoad.Source, load.sources.len);
        for (load.sources, sources) |from, *to| {
            const end = std.mem.indexOfAny(u8, from.source, "?#") orelse from.source.len;
            to.* = .{ .source = try arena.allocator().dupe(u8, from.source[0..end]), .ok = from.ok };
        }
        m.mutex.lockUncancelable(m.io);
        defer m.mutex.unlock(m.io);
        m.sources_arena.deinit();
        m.sources_arena = arena;
        m.sources = sources;
        if (load.complete) m.last_complete_load = load.finished;
    }

    /// The domains in the lists in use.
    pub fn setDomains(m: *Metrics, blocked: usize, allowed: usize) void {
        m.mutex.lockUncancelable(m.io);
        defer m.mutex.unlock(m.io);
        m.blocked_domains = blocked;
        m.allowed_domains = allowed;
    }

    /// When the next list load is due; null when none is (or one runs).
    pub fn setNextLoad(m: *Metrics, at: ?i64) void {
        m.mutex.lockUncancelable(m.io);
        defer m.mutex.unlock(m.io);
        m.next_load = at;
    }

    pub fn setLocalRecords(m: *Metrics, count: usize) void {
        m.mutex.lockUncancelable(m.io);
        defer m.mutex.unlock(m.io);
        m.local_records = count;
    }

    /// Origin only: `address` fetched the Policy settings. Keeps the latest
    /// `max_fetchers` addresses.
    pub fn fetchedBy(m: *Metrics, address: net.IpAddress, now: i64) void {
        const client: ip.Ip = .fromAddress(address);
        m.mutex.lockUncancelable(m.io);
        defer m.mutex.unlock(m.io);
        const fetches = m.fetches[0..m.fetch_count];
        const slot = for (fetches) |*fetch| {
            if (std.meta.eql(fetch.address, client)) break fetch;
        } else if (m.fetch_count < max_fetchers) new: {
            m.fetch_count += 1;
            break :new &m.fetches[m.fetch_count - 1];
        } else oldest: {
            var oldest = &fetches[0];
            for (fetches[1..]) |*fetch| if (fetch.at < oldest.at) {
                oldest = fetch;
            };
            break :oldest oldest;
        };
        slot.* = .{ .address = client, .at = now };
    }

    /// Replica only: a sync succeeded.
    pub fn synced(m: *Metrics, now: i64) void {
        m.mutex.lockUncancelable(m.io);
        defer m.mutex.unlock(m.io);
        m.last_sync = now;
        m.sync_failures = 0;
    }

    /// Replica only: a sync failed.
    pub fn syncFailed(m: *Metrics) void {
        m.mutex.lockUncancelable(m.io);
        defer m.mutex.unlock(m.io);
        m.sync_failures +|= 1;
    }

    /// The state the supervisor and the origin reported, under the lock.
    fn writeStatus(m: *Metrics, w: *Io.Writer, now: i64, live: Live) Io.Writer.Error!void {
        m.mutex.lockUncancelable(m.io);
        defer m.mutex.unlock(m.io);
        try w.print(",\n  \"lists\": {{\n    \"blocked_domains\": {d}, \"allowed_domains\": {d},\n    \"sources\": [", .{ m.blocked_domains, m.allowed_domains });
        for (m.sources, 0..) |source, i| {
            try w.writeAll(if (i == 0) "\n      { \"source\": " else ",\n      { \"source\": ");
            try writeString(w, source.source);
            try w.print(", \"ok\": {} }}", .{source.ok});
        }
        try w.writeAll(if (m.sources.len == 0) "],\n    \"last_complete_load\": " else "\n    ],\n    \"last_complete_load\": ");
        try m.writeOptionalTime(w, m.last_complete_load);
        try w.writeAll(",\n    \"next_load\": ");
        try m.writeOptionalTime(w, m.next_load);
        try w.print("\n  }},\n  \"cache\": {{ \"entries\": {d}, \"capacity\": {d} }},\n  \"local_records\": {d}", .{ live.cache_entries, live.cache_capacity, m.local_records });

        switch (m.role) {
            .standalone => {},
            .origin => {
                try w.writeAll(",\n  \"sync\": { \"fetched_by\": [");
                var listed: usize = 0;
                for (m.fetches[0..m.fetch_count]) |fetch| {
                    if (now - fetch.at > day_seconds) continue;
                    try w.print("{s}\n    {{ \"address\": \"{f}\", \"last_fetch\": ", .{ if (listed == 0) "" else ",", fetch.address });
                    try m.writeTime(w, fetch.at, .seconds);
                    try w.writeAll(" }");
                    listed += 1;
                }
                try w.writeAll(if (listed == 0) "] }" else "\n  ] }");
            },
            .replica => {
                try w.writeAll(",\n  \"sync\": { \"origin\": ");
                try writeString(w, m.origin);
                try w.writeAll(", \"last_sync\": ");
                try m.writeOptionalTime(w, m.last_sync);
                try w.print(", \"failures_in_a_row\": {d} }}", .{m.sync_failures});
            },
        }
    }

    fn writeOptionalTime(m: *const Metrics, w: *Io.Writer, t: ?i64) Io.Writer.Error!void {
        if (t) |value| try m.writeTime(w, value, .seconds) else try w.writeAll("null");
    }

    pub fn countAttempt(m: *Metrics, server: usize, attempt: Attempt, now: i64) void {
        const counts = &m.attempt_counts[server];
        const hour = hourOf(&m.zone, now);
        switch (attempt) {
            .answer => |time| {
                counts.add(hour, .answers, 1);
                counts.add(hour, .answer_time, time);
            },
            .failure => counts.add(hour, .failures, 1),
        }
    }

    /// What upstream server `server` (an index into the configured ones) did
    /// in `window`.
    pub fn attempts(m: *Metrics, server: usize, window: Window, now: i64) Attempts {
        const first, const last = m.hours(window, now);
        const counts = m.attempt_counts[server].sum(first, last);
        return .{ .answers = counts.get(.answers), .failures = counts.get(.failures), .answer_time = counts.get(.answer_time) };
    }

    pub fn countQuery(m: *Metrics, outcome: Outcome, now: i64) void {
        m.query_counts.add(hourOf(&m.zone, now), outcome, 1);
    }

    /// The queries per Outcome in `window`, as of `now`.
    pub fn queries(m: *Metrics, window: Window, now: i64) std.EnumArray(Outcome, usize) {
        const first, const last = m.hours(window, now);
        return m.query_counts.sum(first, last);
    }

    /// The first and last hour of `window`.
    fn hours(m: *const Metrics, window: Window, now: i64) struct { usize, usize } {
        const last = hourOf(&m.zone, now);
        return switch (window) {
            .today => .{ hourOf(&m.zone, startOfDay(&m.zone, now)), last },
            .last_24h => .{ last -| 23, last },
        };
    }
};

/// Serves the document at `GET /metrics`: one listener per address, each
/// answering one request at a time.
pub const Endpoint = struct {
    /// What the document is made from.
    pub const Sources = struct {
        metrics: *Metrics,
        upstream: *const Upstream,
        cache: *Cache,
    };

    io: Io,
    gpa: Allocator,
    sources: Sources,
    service: HttpService,

    const path = "/metrics";

    /// Listens on `addresses` and starts serving. `endpoint` must not move
    /// afterwards.
    pub fn init(endpoint: *Endpoint, io: Io, gpa: Allocator, addresses: []const net.IpAddress, allow_clients: []const ip.Cidr, sources: Sources) !void {
        endpoint.* = .{ .io = io, .gpa = gpa, .sources = sources, .service = undefined };
        try endpoint.service.init(io, gpa, addresses, allow_clients, .{ .context = endpoint, .answer = answerRequest });
    }

    pub fn deinit(endpoint: *Endpoint) void {
        endpoint.service.deinit();
        endpoint.* = undefined;
    }

    /// The first listen address, with its port resolved.
    pub fn address(endpoint: *const Endpoint) net.IpAddress {
        return endpoint.service.address();
    }

    fn answerRequest(context: *anyopaque, server: *std.http.Server, _: net.IpAddress) anyerror!void {
        const endpoint: *Endpoint = @ptrCast(@alignCast(context));
        try endpoint.answer(server);
    }

    fn answer(endpoint: *Endpoint, server: *std.http.Server) !void {
        var request = try server.receiveHead();
        const target = request.head.target;
        if (!std.mem.eql(u8, target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len], path)) {
            return request.respond("", .{ .status = .not_found, .keep_alive = false });
        }
        if (request.head.method != .GET and request.head.method != .HEAD) {
            return request.respond("", .{ .status = .method_not_allowed, .keep_alive = false, .extra_headers = &.{.{ .name = "allow", .value = "GET" }} });
        }
        const sources = endpoint.sources;
        // Into memory first: the document is written under a lock the
        // supervisor also takes, which a slow client must not hold.
        var body: Io.Writer.Allocating = .init(endpoint.gpa);
        defer body.deinit();
        sources.metrics.write(&body.writer, Io.Clock.real.now(endpoint.io).toSeconds(), .{
            .preferred_upstream = sources.upstream.preferred.load(.monotonic),
            .cache_entries = sources.cache.count(endpoint.io),
            .cache_capacity = sources.cache.capacity,
        }) catch return error.OutOfMemory;
        try request.respond(body.written(), .{
            .keep_alive = false,
            .extra_headers = &.{
                .{ .name = "content-type", .value = "application/json" },
                .{ .name = "cache-control", .value = "no-store" },
            },
        });
    }
};

const version = @import("build_options").version;

/// The Outcomes in the document's order: what people look for first.
const hourly_order = [_]Outcome{ .blocked, .cached, .local, .private, .forwarded, .failed, .refused, .invalid };

fn total(counts: std.EnumArray(Outcome, usize)) usize {
    var sum: usize = 0;
    for (counts.values) |count| sum += count;
    return sum;
}

fn writeQueries(w: *Io.Writer, counts: std.EnumArray(Outcome, usize)) Io.Writer.Error!void {
    const all = total(counts);
    try w.print("{{\n      \"total\": {d}, \"blocked\": {d}, \"blocked_pct\": ", .{ all, counts.get(.blocked) });
    try writePercent(w, counts.get(.blocked), all);
    // Of the queries that needed an upstream answer, the share the cache had.
    try w.print(",\n      \"cached\": {d}, \"cache_hit_pct\": ", .{counts.get(.cached)});
    try writePercent(w, counts.get(.cached), counts.get(.cached) + counts.get(.forwarded) + counts.get(.failed));
    try w.print(",\n      \"local\": {d}, \"private\": {d}, \"forwarded\": {d},\n      \"failed\": {d}, \"refused\": {d}, \"invalid\": {d}\n    }}", .{
        counts.get(.local), counts.get(.private), counts.get(.forwarded), counts.get(.failed), counts.get(.refused), counts.get(.invalid),
    });
}

fn writeAttempts(w: *Io.Writer, a: Attempts) Io.Writer.Error!void {
    try w.print("{{ \"answers\": {d}, \"failures\": {d}, \"avg_ms\": ", .{ a.answers, a.failures });
    if (a.averageMs()) |ms| try w.print("{d:.1}", .{ms}) else try w.writeAll("null");
    try w.writeAll(" }");
}

/// One decimal, or null when there is nothing to divide by.
fn writePercent(w: *Io.Writer, part: usize, whole: usize) Io.Writer.Error!void {
    if (whole == 0) return w.writeAll("null");
    try w.print("{d:.1}", .{@as(f64, @floatFromInt(part)) * 100 / @as(f64, @floatFromInt(whole))});
}

/// A JSON string. Bytes outside ASCII become \u00XX: not their meaning, but
/// always valid JSON (sources are URLs and paths, nearly always ASCII).
fn writeString(w: *Io.Writer, s: []const u8) Io.Writer.Error!void {
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '"', '\\' => try w.print("\\{c}", .{c}),
        0...0x1f, 0x7f...0xff => try w.print("\\u{x:0>4}", .{c}),
        else => try w.writeByte(c),
    };
    try w.writeByte('"');
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

/// 2026-07-15 00:00 in Amsterdam (22:00 UTC the day before).
const amsterdam_midnight = 1784066400;

const amsterdam_rule = "CET-1CEST,M3.5.0,M10.5.0/3";

fn testMetrics() !Metrics {
    return .init(testing.io, testing.allocator, .{ .zone = try .fromRule(amsterdam_rule), .started = 0 });
}

test "today counts the queries since local midnight" {
    var m = try testMetrics();
    defer m.deinit();
    m.countQuery(.blocked, amsterdam_midnight - 1);
    m.countQuery(.blocked, amsterdam_midnight);
    m.countQuery(.forwarded, amsterdam_midnight + 13 * hour_seconds);
    const now = amsterdam_midnight + 14 * hour_seconds;

    const today = m.queries(.today, now);
    try testing.expectEqual(1, today.get(.blocked));
    try testing.expectEqual(1, today.get(.forwarded));
    try testing.expectEqual(2, m.queries(.last_24h, now).get(.blocked));
}

test "the last 24 hours drop the oldest hour every hour, and are empty after a quiet day" {
    var m = try testMetrics();
    defer m.deinit();
    const start = amsterdam_midnight + 30 * 60;
    // The current hour and the 23 before it.
    m.countQuery(.cached, start);
    try testing.expectEqual(1, m.queries(.last_24h, start + 23 * hour_seconds).get(.cached));
    try testing.expectEqual(0, m.queries(.last_24h, start + 24 * hour_seconds).get(.cached));

    // One query an hour for two days.
    for (1..49) |i| {
        const t = start + @as(i64, @intCast(i)) * hour_seconds;
        m.countQuery(.forwarded, t);
        try testing.expectEqual(@min(i, 24), m.queries(.last_24h, t).get(.forwarded));
    }

    const later = start + 100 * hour_seconds;
    try testing.expectEqual(0, m.queries(.last_24h, later).get(.forwarded));
    try testing.expectEqual(0, m.queries(.today, later).get(.forwarded));
    m.countQuery(.forwarded, later);
    try testing.expectEqual(1, m.queries(.last_24h, later).get(.forwarded));
}

test "today starts at local midnight on days with 25 and 23 hours" {
    const days = [_]struct { i64, i64 }{
        .{ 1792879200, 1792969200 }, // 2026-10-25, back to standard time
        .{ 1774738800, 1774821600 }, // 2026-03-29, to daylight saving time
    };
    for (days) |day| {
        const midnight, const next_midnight = day;
        var m = try testMetrics();
        defer m.deinit();
        m.countQuery(.blocked, midnight - 60);
        m.countQuery(.blocked, midnight + 60);
        m.countQuery(.blocked, next_midnight - 60);
        try testing.expectEqual(2, m.queries(.today, next_midnight - 1).get(.blocked));
        try testing.expectEqual(0, m.queries(.today, next_midnight).get(.blocked));
    }
}

/// `m.write` as parsed JSON.
fn testDocument(m: *Metrics, now: i64, live: Live) !std.json.Parsed(std.json.Value) {
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try m.write(&out.writer, now, live);
    return std.json.parseFromSlice(std.json.Value, testing.allocator, out.written(), .{});
}

fn field(value: std.json.Value, path: []const []const u8) !std.json.Value {
    var current = value;
    for (path) |key| current = current.object.get(key) orelse {
        std.debug.print("no '{s}' in the document\n", .{key});
        return error.TestUnexpectedResult;
    };
    return current;
}

test "the document holds today, the last 24 hours, each hour and each upstream server" {
    const servers = [_]ServerAddress{
        .{ .address = .{ .ip4 = .{ .bytes = .{ 9, 9, 9, 9 }, .port = 853 } }, .tls_name = "dns.quad9.net" },
        .{ .address = .{ .ip4 = .{ .bytes = .{ 1, 0, 0, 1 }, .port = 53 } } },
    };
    const zone = localtime.load(testing.io, testing.allocator, amsterdam_rule, Io.Dir.cwd());
    var m: Metrics = try .init(testing.io, testing.allocator, .{ .zone = zone, .started = amsterdam_midnight - hour_seconds, .upstream = &servers });
    defer m.deinit();
    const now = amsterdam_midnight + 14 * hour_seconds + 5 * 60; // 14:05
    const one_pm = amsterdam_midnight + 13 * hour_seconds;
    m.countQuery(.blocked, amsterdam_midnight - 30 * 60);
    for ([_]Outcome{ .blocked, .blocked, .blocked, .forwarded, .cached, .cached }) |outcome| m.countQuery(outcome, one_pm);
    m.countAttempt(0, .{ .answer = 184 }, now);
    m.countAttempt(0, .failure, now);

    const parsed = try testDocument(&m, now, .{ .preferred_upstream = 0, .cache_entries = 5, .cache_capacity = 4096 });
    defer parsed.deinit();
    const doc = parsed.value;
    try testing.expectEqual(1, (try field(doc, &.{"format"})).integer);
    try testing.expectEqualStrings("standalone", (try field(doc, &.{"role"})).string);
    try testing.expectEqualStrings("2026-07-15T14:05:00+02:00", (try field(doc, &.{"now"})).string);
    try testing.expectEqualStrings("2026-07-14T23:00:00+02:00", (try field(doc, &.{"started"})).string);
    try testing.expectEqual(15 * hour_seconds + 5 * 60, (try field(doc, &.{"uptime_s"})).integer);
    try testing.expectEqualStrings(amsterdam_rule, (try field(doc, &.{"time_zone"})).string);

    const today = (try field(doc, &.{ "queries", "today" }));
    try testing.expectEqual(6, (try field(today, &.{"total"})).integer);
    try testing.expectEqual(3, (try field(today, &.{"blocked"})).integer);
    try testing.expectEqual(50.0, (try field(today, &.{"blocked_pct"})).float);
    try testing.expectEqual(66.7, (try field(today, &.{"cache_hit_pct"})).float); // 2 of 3 not answered locally
    try testing.expectEqual(4, (try field(doc, &.{ "queries", "last_24h", "blocked" })).integer);

    const hourly = (try field(doc, &.{"hourly"})).array.items;
    try testing.expectEqual(24, hourly.len);
    try testing.expectEqualStrings("2026-07-14T15:00+02:00", (try field(hourly[0], &.{"hour"})).string);
    try testing.expectEqualStrings("2026-07-15T13:00+02:00", (try field(hourly[22], &.{"hour"})).string);
    try testing.expectEqual(3, (try field(hourly[22], &.{"blocked"})).integer);
    try testing.expectEqual(1, (try field(hourly[8], &.{"blocked"})).integer); // 23:00 yesterday
    try testing.expectEqual(0, (try field(hourly[23], &.{"total"})).integer);

    const upstream = (try field(doc, &.{"upstream"})).array.items;
    try testing.expectEqual(2, upstream.len);
    try testing.expectEqualStrings("tls://9.9.9.9:853#dns.quad9.net", (try field(upstream[0], &.{"server"})).string);
    try testing.expect((try field(upstream[0], &.{"preferred"})).bool);
    try testing.expectEqual(1, (try field(upstream[0], &.{ "today", "answers" })).integer);
    try testing.expectEqual(1, (try field(upstream[0], &.{ "last_24h", "failures" })).integer);
    try testing.expectEqual(18.4, (try field(upstream[0], &.{ "today", "avg_ms" })).float);
    try testing.expect(!(try field(upstream[1], &.{"preferred"})).bool);
    try testing.expectEqual(.null, std.meta.activeTag((try field(upstream[1], &.{ "today", "avg_ms" }))));

    try testing.expectEqual(0, (try field(doc, &.{ "lists", "sources" })).array.items.len);
    try testing.expectEqual(.null, std.meta.activeTag(try field(doc, &.{ "lists", "last_complete_load" })));
    try testing.expectEqual(5, (try field(doc, &.{ "cache", "entries" })).integer);
    try testing.expectEqual(4096, (try field(doc, &.{ "cache", "capacity" })).integer);
    try testing.expectEqual(null, doc.object.get("sync"));
}

const test_live: Live = .{ .preferred_upstream = 0, .cache_entries = 0, .cache_capacity = 0 };

test "lists, local records and the origin's fetches are as last reported" {
    var m: Metrics = try .init(testing.io, testing.allocator, .{ .zone = .{}, .role = .origin, .started = 0 });
    defer m.deinit();
    const day = 24 * hour_seconds;
    const now = 100 * day;
    const loaded = [_]ListLoad.Source{
        .{ .source = "https://lists.example/pro.txt?token=secret", .ok = true },
        .{ .source = "/etc/zinkhole/allow.txt", .ok = true },
    };
    try m.setLists(.{ .sources = &loaded, .complete = true, .finished = now - hour_seconds });
    // A later load that missed a source keeps the time of the complete one.
    try m.setLists(.{ .sources = &.{ loaded[0], .{ .source = loaded[1].source, .ok = false } }, .complete = false, .finished = now });
    m.setDomains(194332, 3);
    m.setNextLoad(now + hour_seconds);
    m.setLocalRecords(4);
    // 17 replicas: the one fetching longest ago makes room; then one stops.
    for (1..18) |i| m.fetchedBy(.{ .ip4 = .{ .bytes = .{ 10, 0, 0, @intCast(i) }, .port = 40000 } }, now - day + @as(i64, @intCast(i)));
    m.fetchedBy(.{ .ip4 = .{ .bytes = .{ 10, 0, 0, 3 }, .port = 40001 } }, now);

    const parsed = try testDocument(&m, now + 3, test_live);
    defer parsed.deinit();
    const doc = parsed.value;
    try testing.expectEqual(194332, (try field(doc, &.{ "lists", "blocked_domains" })).integer);
    try testing.expectEqual(3, (try field(doc, &.{ "lists", "allowed_domains" })).integer);
    const sources = (try field(doc, &.{ "lists", "sources" })).array.items;
    try testing.expectEqualStrings("https://lists.example/pro.txt", (try field(sources[0], &.{"source"})).string);
    try testing.expect((try field(sources[0], &.{"ok"})).bool);
    try testing.expect(!(try field(sources[1], &.{"ok"})).bool);
    try testing.expectEqualStrings("1970-04-10T23:00:00+00:00", (try field(doc, &.{ "lists", "last_complete_load" })).string);
    try testing.expectEqualStrings("1970-04-11T01:00:00+00:00", (try field(doc, &.{ "lists", "next_load" })).string);
    try testing.expectEqual(4, (try field(doc, &.{"local_records"})).integer);

    // 10.0.0.1 made room, and 10.0.0.2 last fetched more than a day ago.
    const fetched = (try field(doc, &.{ "sync", "fetched_by" })).array.items;
    try testing.expectEqual(15, fetched.len);
    for (fetched) |entry| {
        const address = (try field(entry, &.{"address"})).string;
        try testing.expect(!std.mem.eql(u8, address, "10.0.0.1") and !std.mem.eql(u8, address, "10.0.0.2"));
        if (std.mem.eql(u8, address, "10.0.0.3")) {
            try testing.expectEqualStrings("1970-04-11T00:00:00+00:00", (try field(entry, &.{"last_fetch"})).string);
        }
    }
}

test "a replica shows its origin, its last sync and the failures since" {
    var m: Metrics = try .init(testing.io, testing.allocator, .{ .zone = .{}, .role = .replica, .origin = "http://10.10.50.85:5380", .started = 0 });
    defer m.deinit();
    {
        const parsed = try testDocument(&m, 1000, test_live);
        defer parsed.deinit();
        try testing.expectEqualStrings("http://10.10.50.85:5380", (try field(parsed.value, &.{ "sync", "origin" })).string);
        try testing.expectEqual(.null, std.meta.activeTag(try field(parsed.value, &.{ "sync", "last_sync" })));
    }
    m.synced(500);
    m.syncFailed();
    m.syncFailed();
    const parsed = try testDocument(&m, 1000, test_live);
    defer parsed.deinit();
    try testing.expectEqualStrings("1970-01-01T00:08:20+00:00", (try field(parsed.value, &.{ "sync", "last_sync" })).string);
    try testing.expectEqual(2, (try field(parsed.value, &.{ "sync", "failures_in_a_row" })).integer);
}

const TestResponse = struct {
    status: std.http.Status,
    content_type_buf: [64]u8 = undefined,
    content_type_len: usize = 0,
    body: []u8 = &.{},

    fn contentType(r: *const TestResponse) []const u8 {
        return r.content_type_buf[0..r.content_type_len];
    }
};

fn testRequest(method: std.http.Method, url: []const u8) !TestResponse {
    var client: std.http.Client = .{ .allocator = testing.allocator, .io = testing.io };
    defer client.deinit();
    var request = try client.request(method, try std.Uri.parse(url), .{ .keep_alive = false });
    defer request.deinit();
    if (method == .POST) try request.sendBodyComplete(@constCast("x")) else try request.sendBodiless();
    var redirect_buf: [1024]u8 = undefined;
    var response = try request.receiveHead(&redirect_buf);
    var result: TestResponse = .{ .status = response.head.status };
    const content_type = response.head.content_type orelse "";
    result.content_type_len = content_type.len;
    @memcpy(result.content_type_buf[0..content_type.len], content_type);
    var transfer_buf: [1024]u8 = undefined;
    result.body = try response.reader(&transfer_buf).allocRemaining(testing.allocator, .limited(1 << 20));
    return result;
}

const loopback_clients = [_]ip.Cidr{ip.Cidr.parse("127.0.0.0/8").?};

/// An endpoint on an ephemeral loopback port, with what it reads from.
const TestEndpoint = struct {
    metrics: Metrics,
    upstream: Upstream,
    cache: Cache,
    endpoint: Endpoint,

    fn start(t: *TestEndpoint, allow_clients: []const ip.Cidr) !void {
        t.metrics = try .init(testing.io, testing.allocator, .{ .zone = .{}, .started = 0 });
        errdefer t.metrics.deinit();
        try t.upstream.init(testing.io, testing.allocator, &.{}, 100);
        errdefer t.upstream.deinit();
        t.cache = try .init(testing.allocator, .{ .capacity = 64, .min_ttl = 0, .max_ttl = 3600, .seed = 1 });
        errdefer t.cache.deinit();
        try t.endpoint.init(testing.io, testing.allocator, &.{.{ .ip4 = .loopback(0) }}, allow_clients, .{ .metrics = &t.metrics, .upstream = &t.upstream, .cache = &t.cache });
    }

    fn stop(t: *TestEndpoint) void {
        t.endpoint.deinit();
        t.cache.deinit();
        t.upstream.deinit();
        t.metrics.deinit();
    }

    fn url(t: *const TestEndpoint, buf: []u8, path: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "http://{f}{s}", .{ t.endpoint.address(), path });
    }
};

test "GET /metrics serves the document; other paths and methods get 404 and 405" {
    var t: TestEndpoint = undefined;
    try t.start(&loopback_clients);
    defer t.stop();
    var url_buf: [64]u8 = undefined;

    const ok = try testRequest(.GET, try t.url(&url_buf, "/metrics"));
    defer testing.allocator.free(ok.body);
    try testing.expectEqual(.ok, ok.status);
    try testing.expectEqualStrings("application/json", ok.contentType());
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, ok.body, .{});
    defer parsed.deinit();
    try testing.expectEqual(64, (try field(parsed.value, &.{ "cache", "capacity" })).integer);

    const other = try testRequest(.GET, try t.url(&url_buf, "/sync"));
    defer testing.allocator.free(other.body);
    try testing.expectEqual(.not_found, other.status);
    const post = try testRequest(.POST, try t.url(&url_buf, "/metrics"));
    defer testing.allocator.free(post.body);
    try testing.expectEqual(.method_not_allowed, post.status);
}

test "requests with large headers, such as cookies passed on by a reverse proxy, are answered" {
    var t: TestEndpoint = undefined;
    try t.start(&loopback_clients);
    defer t.stop();
    var client: std.http.Client = .{ .allocator = testing.allocator, .io = testing.io };
    defer client.deinit();
    const cookie: [12 * 1024]u8 = @splat('a');
    var url_buf: [64]u8 = undefined;
    var request = try client.request(.GET, try std.Uri.parse(try t.url(&url_buf, "/metrics")), .{
        .keep_alive = false,
        .extra_headers = &.{.{ .name = "cookie", .value = &cookie }},
    });
    defer request.deinit();
    try request.sendBodiless();
    var redirect_buf: [1024]u8 = undefined;
    const response = try request.receiveHead(&redirect_buf);
    try testing.expectEqual(.ok, response.head.status);
}

test "metrics connections from clients outside the allowed networks are closed before reading" {
    var t: TestEndpoint = undefined;
    try t.start(&.{ip.Cidr.parse("192.168.0.0/16").?});
    defer t.stop();
    const stream = try t.endpoint.address().connect(testing.io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(testing.io);
    var buf: [16]u8 = undefined;
    var reader: tcp.DeadlineReader = .init(testing.io, stream.socket.handle, &buf, tcp.deadlineIn(testing.io, 1000));
    try testing.expectError(error.EndOfStream, reader.interface.takeByte());
}
