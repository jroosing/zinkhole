//! Local time (ADR-0004): the offset from UTC at a given moment, from the
//! `TZ` variable or `/etc/localtime`.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const epoch = std.time.epoch;

const log = std.log.scoped(.time);

pub const Zone = struct {
    /// From a zone file: every change of offset, in time order.
    transitions: []const Transition = &.{},
    /// Before the first transition.
    initial_offset: i32 = 0,
    /// After the last transition; null keeps the last transition's offset.
    rule: ?Rule = .{},
    name_buf: [64]u8 = undefined,
    name_len: usize = 0,

    const Transition = struct { at: i64, offset: i32 };

    /// Seconds east of UTC at Unix time `t`.
    pub fn offsetAt(zone: *const Zone, t: i64) i32 {
        const transitions = zone.transitions;
        if (transitions.len == 0 or t >= transitions[transitions.len - 1].at) {
            if (zone.rule) |rule| return rule.offsetAt(t);
            return if (transitions.len == 0) zone.initial_offset else transitions[transitions.len - 1].offset;
        }
        // The first transition after `t`; the one before it applies.
        var low: usize = 0;
        var high = transitions.len;
        while (low < high) {
            const mid = (low + high) / 2;
            if (transitions[mid].at <= t) low = mid + 1 else high = mid;
        }
        return if (low == 0) zone.initial_offset else transitions[low - 1].offset;
    }

    /// A POSIX TZ rule, such as `CET-1CEST,M3.5.0,M10.5.0/3`.
    pub fn fromRule(text: []const u8) error{InvalidRule}!Zone {
        return .{ .rule = try .parse(text) };
    }

    /// A zone file (TZif), such as `/etc/localtime`.
    pub fn fromTzif(gpa: Allocator, bytes: []const u8) error{ InvalidZoneFile, OutOfMemory }!Zone {
        var reader: std.Io.Reader = .fixed(bytes);
        var tz = std.tz.Tz.parse(gpa, &reader) catch |err| switch (err) {
            error.OutOfMemory => |e| return e,
            else => return error.InvalidZoneFile,
        };
        defer tz.deinit();
        const transitions = try gpa.alloc(Transition, tz.transitions.len);
        for (tz.transitions, transitions) |from, *to| to.* = .{ .at = from.ts, .offset = from.timetype.offset };
        return .{
            .transitions = transitions,
            .initial_offset = tz.timetypes[0].offset,
            // A rule this code cannot read keeps the last offset.
            .rule = if (tz.footer) |footer| Rule.parse(footer) catch null else null,
        };
    }

    pub fn deinit(zone: *Zone, gpa: Allocator) void {
        gpa.free(zone.transitions);
        zone.* = undefined;
    }

    /// What `load` found: a zone name, a rule, or "UTC".
    pub fn name(zone: *const Zone) []const u8 {
        return zone.name_buf[0..zone.name_len];
    }

    fn named(zone: Zone, text: []const u8) Zone {
        var result = zone;
        result.name_len = @min(text.len, result.name_buf.len);
        @memcpy(result.name_buf[0..result.name_len], text[0..result.name_len]);
        return result;
    }
};

const zoneinfo_dir = "usr/share/zoneinfo/";

/// The local time zone, from `tz` (the `TZ` variable: a zone name or a
/// rule), else `/etc/localtime`, else UTC. Paths are relative to `root`.
pub fn load(io: Io, gpa: Allocator, tz: ?[]const u8, root: Io.Dir) Zone {
    if (tz) |value| {
        const text = if (std.mem.startsWith(u8, value, ":")) value[1..] else value;
        if (isZoneName(text)) {
            var path_buf: [zoneinfo_dir.len + 256]u8 = undefined;
            const path = std.fmt.bufPrint(&path_buf, zoneinfo_dir ++ "{s}", .{text}) catch unreachable;
            if (readZone(io, gpa, root, path)) |zone| return zone.named(text);
        }
        if (Zone.fromRule(text)) |zone| return zone.named(text) else |_| {}
        log.warn("TZ={s} is neither a time zone name nor a rule; ignoring it", .{value});
    }
    if (readZone(io, gpa, root, "etc/localtime")) |zone| {
        var buf: [256]u8 = undefined;
        return zone.named(localtimeName(io, root, &buf));
    }
    log.warn("no time zone found (set TZ or provide /etc/localtime); metrics use UTC", .{});
    return Zone.named(.{}, "UTC");
}

/// A name such as `Europe/Amsterdam` or `Etc/GMT+5`, which cannot climb out
/// of the zoneinfo directory.
fn isZoneName(text: []const u8) bool {
    if (text.len == 0 or text.len > 255 or text[0] == '/') return false;
    for (text) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '/' and c != '_' and c != '-' and c != '+') return false;
    }
    return true;
}

fn readZone(io: Io, gpa: Allocator, root: Io.Dir, path: []const u8) ?Zone {
    const bytes = root.readFileAlloc(io, path, gpa, .limited(1024 * 1024)) catch return null;
    defer gpa.free(bytes);
    return Zone.fromTzif(gpa, bytes) catch |err| {
        log.warn("/{s}: {t}", .{ path, err });
        return null;
    };
}

/// The zone `/etc/localtime` links to, else the one in `/etc/timezone`.
fn localtimeName(io: Io, root: Io.Dir, buf: []u8) []const u8 {
    if (root.readLink(io, "etc/localtime", buf)) |len| {
        const target = buf[0..len];
        const marker = "zoneinfo/";
        if (std.mem.indexOf(u8, target, marker)) |at| return target[at + marker.len ..];
    } else |_| {}
    if (root.readFile(io, "etc/timezone", buf)) |content| {
        const trimmed = std.mem.trim(u8, content, " \t\r\n");
        if (trimmed.len > 0) return trimmed;
    } else |_| {}
    return "/etc/localtime";
}

const day_seconds = 24 * 3600;

/// A POSIX TZ rule: standard time, and optionally daylight saving time with
/// the yearly dates it starts and ends.
const Rule = struct {
    /// Seconds east of UTC (POSIX writes them west of UTC).
    std_offset: i32 = 0,
    dst: ?Dst = null,

    const Dst = struct {
        offset: i32,
        start: Change,
        end: Change,
    };

    /// When daylight saving time starts or ends: a day of the year, and the
    /// time of day in the local time in effect until then.
    const Change = struct {
        /// Mm.w.d: weekday `d` (0 is Sunday) of week `w` (5 is the last) of month `m`.
        month: u4,
        week: u3,
        weekday: u3,
        time: i32 = 2 * 3600,

        /// Seconds from the epoch to the change in `year`, in local time.
        fn at(change: Change, year: i64) i64 {
            const first = daysFromCivil(year, change.month, 1);
            const first_weekday: u3 = @intCast(@mod(first + 4, 7)); // 1970-01-01 was a Thursday
            var day = @mod(@as(i64, change.weekday) - first_weekday, 7) + @as(i64, change.week - 1) * 7;
            const month_len = epoch.getDaysInMonth(@intCast(year), @fromBackingInt(@intCast(change.month)));
            while (day >= month_len) day -= 7;
            return (first + day) * day_seconds + change.time;
        }
    };

    fn offsetAt(rule: Rule, t: i64) i32 {
        const dst = rule.dst orelse return rule.std_offset;
        const year = dateOfDay(@divFloor(t + rule.std_offset, day_seconds)).year;
        const start = dst.start.at(year) - rule.std_offset;
        const end = dst.end.at(year) - dst.offset;
        // In the southern hemisphere, daylight saving time spans the new year.
        const in_dst = if (start < end) start <= t and t < end else !(end <= t and t < start);
        return if (in_dst) dst.offset else rule.std_offset;
    }

    fn parse(text: []const u8) error{InvalidRule}!Rule {
        var p: Parser = .{ .text = text };
        try p.name();
        var rule: Rule = .{ .std_offset = -try p.offset() };
        if (p.done()) return rule;
        try p.name();
        const dst_offset = if (p.peek() == ',') rule.std_offset + 3600 else -try p.offset();
        try p.expect(',');
        const start = try p.change();
        try p.expect(',');
        const end = try p.change();
        if (!p.done()) return error.InvalidRule;
        rule.dst = .{ .offset = dst_offset, .start = start, .end = end };
        return rule;
    }
};

const Parser = struct {
    text: []const u8,
    pos: usize = 0,

    fn done(p: *const Parser) bool {
        return p.pos == p.text.len;
    }

    fn peek(p: *const Parser) ?u8 {
        return if (p.done()) null else p.text[p.pos];
    }

    fn expect(p: *Parser, c: u8) error{InvalidRule}!void {
        if (p.peek() != c) return error.InvalidRule;
        p.pos += 1;
    }

    /// A zone abbreviation: at least three letters (`CET`), or quoted
    /// letters, digits and signs (`<+0530>`).
    fn name(p: *Parser) error{InvalidRule}!void {
        if (p.peek() == '<') {
            const close = std.mem.indexOfScalarPos(u8, p.text, p.pos, '>') orelse return error.InvalidRule;
            for (p.text[p.pos + 1 .. close]) |c| {
                if (!std.ascii.isAlphanumeric(c) and c != '+' and c != '-') return error.InvalidRule;
            }
            if (close - p.pos - 1 < 3) return error.InvalidRule;
            p.pos = close + 1;
            return;
        }
        const start = p.pos;
        while (p.peek()) |c| : (p.pos += 1) if (!std.ascii.isAlphabetic(c)) break;
        if (p.pos - start < 3) return error.InvalidRule;
    }

    /// `[+|-]hh[:mm[:ss]]` in seconds, with the sign as written.
    fn offset(p: *Parser) error{InvalidRule}!i32 {
        const negative = p.peek() == '-';
        if (negative or p.peek() == '+') p.pos += 1;
        var seconds: i32 = try p.number(167) * 3600;
        if (p.peek() == ':') {
            p.pos += 1;
            seconds += try p.number(59) * 60;
            if (p.peek() == ':') {
                p.pos += 1;
                seconds += try p.number(59);
            }
        }
        return if (negative) -seconds else seconds;
    }

    /// `Mm.w.d[/time]`.
    fn change(p: *Parser) error{InvalidRule}!Rule.Change {
        try p.expect('M');
        const month = try p.number(12);
        try p.expect('.');
        const week = try p.number(5);
        try p.expect('.');
        const weekday = try p.number(6);
        if (month == 0 or week == 0) return error.InvalidRule;
        var result: Rule.Change = .{ .month = @intCast(month), .week = @intCast(week), .weekday = @intCast(weekday) };
        if (p.peek() == '/') {
            p.pos += 1;
            result.time = try p.offset();
        }
        return result;
    }

    fn number(p: *Parser, max: i32) error{InvalidRule}!i32 {
        const start = p.pos;
        var value: i32 = 0;
        while (p.peek()) |c| : (p.pos += 1) {
            if (!std.ascii.isDigit(c)) break;
            value = value * 10 + (c - '0');
            if (value > max) return error.InvalidRule;
        }
        if (p.pos == start) return error.InvalidRule;
        return value;
    }
};

/// Days from 1970-01-01 to the given date (proleptic Gregorian calendar).
fn daysFromCivil(year: i64, month: u4, day: u5) i64 {
    const y = if (month <= 2) year - 1 else year;
    const era = @divFloor(y, 400);
    const year_of_era = y - era * 400;
    const m: i64 = month;
    const day_of_year = @divFloor(153 * (if (m > 2) m - 3 else m + 9) + 2, 5) + day - 1;
    const day_of_era = year_of_era * 365 + @divFloor(year_of_era, 4) - @divFloor(year_of_era, 100) + day_of_year;
    return era * 146097 + day_of_era - 719468;
}

pub const Date = struct { year: i64, month: u4, day: u5 };

/// The date of day `days` since 1970-01-01.
pub fn dateOfDay(days: i64) Date {
    const z = days + 719468;
    const era = @divFloor(z, 146097);
    const day_of_era = z - era * 146097;
    const year_of_era = @divFloor(day_of_era - @divFloor(day_of_era, 1460) + @divFloor(day_of_era, 36524) - @divFloor(day_of_era, 146096), 365);
    const day_of_year = day_of_era - (365 * year_of_era + @divFloor(year_of_era, 4) - @divFloor(year_of_era, 100));
    const march_based_month = @divFloor(5 * day_of_year + 2, 153);
    // Years start in March here: January and February belong to the next.
    return .{
        .year = year_of_era + era * 400 + @intFromBool(march_based_month >= 10),
        .month = @intCast(if (march_based_month < 10) march_based_month + 3 else march_based_month - 9),
        .day = @intCast(day_of_year - @divFloor(153 * march_based_month + 2, 5) + 1),
    };
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

test "the Amsterdam rule switches between +1 and +2 at the 2026 clock changes" {
    const zone = try Zone.fromRule("CET-1CEST,M3.5.0,M10.5.0/3");
    const spring = 1774746000; // 2026-03-29 01:00 UTC
    const autumn = 1792890000; // 2026-10-25 01:00 UTC
    try testing.expectEqual(3600, zone.offsetAt(spring - 1));
    try testing.expectEqual(7200, zone.offsetAt(spring));
    try testing.expectEqual(7200, zone.offsetAt(autumn - 1));
    try testing.expectEqual(3600, zone.offsetAt(autumn));
}

test "in the southern hemisphere, daylight saving time spans the new year" {
    const zone = try Zone.fromRule("AEST-10AEDT,M10.1.0,M4.1.0/3"); // Australia/Sydney
    const new_year = 1767225600; // 2026-01-01 00:00 UTC
    const autumn = 1775318400; // 2026-04-04 16:00 UTC, 03:00 daylight time
    const spring = 1791043200; // 2026-10-03 16:00 UTC, 02:00 standard time
    try testing.expectEqual(11 * 3600, zone.offsetAt(new_year));
    try testing.expectEqual(11 * 3600, zone.offsetAt(autumn - 1));
    try testing.expectEqual(10 * 3600, zone.offsetAt(autumn));
    try testing.expectEqual(10 * 3600, zone.offsetAt(spring - 1));
    try testing.expectEqual(11 * 3600, zone.offsetAt(spring));
    try testing.expectEqual(11 * 3600, zone.offsetAt(new_year + 365 * day_seconds - 1));
}

test "rules with nth weekdays, half-hour offsets, quoted names and negative change times" {
    const new_york = try Zone.fromRule("EST5EDT,M3.2.0,M11.1.0");
    const us_spring = 1772953200; // 2026-03-08 07:00 UTC, the second Sunday
    const us_autumn = 1793512800; // 2026-11-01 06:00 UTC, the first Sunday
    try testing.expectEqual(-5 * 3600, new_york.offsetAt(us_spring - 1));
    try testing.expectEqual(-4 * 3600, new_york.offsetAt(us_spring));
    try testing.expectEqual(-4 * 3600, new_york.offsetAt(us_autumn - 1));
    try testing.expectEqual(-5 * 3600, new_york.offsetAt(us_autumn));

    const kolkata = try Zone.fromRule("IST-5:30");
    try testing.expectEqual(5 * 3600 + 1800, kolkata.offsetAt(us_spring));
    const sao_paulo = try Zone.fromRule("<-03>3");
    try testing.expectEqual(-3 * 3600, sao_paulo.offsetAt(us_spring));

    // Changes at -1:00 and 0:00 local time: 01:00 UTC, like the EU.
    const nuuk = try Zone.fromRule("<-02>2<-01>,M3.5.0/-1,M10.5.0/0");
    const eu_spring = 1774746000; // 2026-03-29 01:00 UTC
    const eu_autumn = 1792890000; // 2026-10-25 01:00 UTC
    try testing.expectEqual(-2 * 3600, nuuk.offsetAt(eu_spring - 1));
    try testing.expectEqual(-1 * 3600, nuuk.offsetAt(eu_spring));
    try testing.expectEqual(-1 * 3600, nuuk.offsetAt(eu_autumn - 1));
    try testing.expectEqual(-2 * 3600, nuuk.offsetAt(eu_autumn));

    for ([_][]const u8{ "", "CET", "C-1", "CET-1CEST", "CET-1CEST,M3.5.0", "CET-1CEST,M13.5.0,M10.5.0", "<+03-3", "CET-1 " }) |bad| {
        try testing.expectError(error.InvalidRule, Zone.fromRule(bad));
    }
}

/// A version 2 TZif file: an empty version 1 block, then `transitions`
/// (Unix time, index into `offsets`), `offsets` and `footer`.
fn testTzif(buf: []u8, transitions: []const struct { i64, u8 }, offsets: []const i32, footer: []const u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    const reserved: [15]u8 = @splat(0);
    const no_counts: [24]u8 = @splat(0);
    try w.writeAll("TZif2" ++ reserved ++ no_counts);
    try w.writeAll("TZif2" ++ reserved);
    for ([_]usize{ 0, 0, 0, transitions.len, offsets.len, 2 }) |n| try w.writeInt(u32, @intCast(n), .big);
    for (transitions) |transition| try w.writeInt(i64, transition[0], .big);
    for (transitions) |transition| try w.writeByte(transition[1]);
    for (offsets) |offset| {
        try w.writeInt(i32, offset, .big);
        try w.writeAll(&.{ 0, 0 }); // not DST; designation "X"
    }
    try w.print("X\x00\n{s}\n", .{footer});
    return w.buffered();
}

test "a zone file's transitions apply until the last one, its rule after that" {
    const eu_spring = 1774746000; // 2026-03-29 01:00 UTC
    const eu_autumn = 1792890000; // 2026-10-25 01:00 UTC
    const july_2026 = eu_spring + 100 * day_seconds;
    const july_2027 = july_2026 + 365 * day_seconds;
    var buf: [256]u8 = undefined;

    // +3 in the summer of 2026 tells the transitions apart from the rule.
    const fat = try testTzif(&buf, &.{ .{ eu_spring, 1 }, .{ eu_autumn, 0 } }, &.{ 3600, 3 * 3600 }, "CET-1CEST,M3.5.0,M10.5.0/3");
    var zone: Zone = try .fromTzif(testing.allocator, fat);
    defer zone.deinit(testing.allocator);
    try testing.expectEqual(3600, zone.offsetAt(eu_spring - 1));
    try testing.expectEqual(3 * 3600, zone.offsetAt(july_2026));
    try testing.expectEqual(3600, zone.offsetAt(eu_autumn));
    try testing.expectEqual(2 * 3600, zone.offsetAt(july_2027));

    // Slim files, as Alpine ships them, stop listing transitions long ago.
    const slim = try testTzif(&buf, &.{}, &.{3600}, "CET-1CEST,M3.5.0,M10.5.0/3");
    var slim_zone: Zone = try .fromTzif(testing.allocator, slim);
    defer slim_zone.deinit(testing.allocator);
    try testing.expectEqual(2 * 3600, slim_zone.offsetAt(july_2027));
    try testing.expectEqual(3600, slim_zone.offsetAt(eu_autumn));

    // Without a rule the last offset stays.
    const no_rule = try testTzif(&buf, &.{.{ eu_spring, 1 }}, &.{ 3600, 7200 }, "");
    var no_rule_zone: Zone = try .fromTzif(testing.allocator, no_rule);
    defer no_rule_zone.deinit(testing.allocator);
    try testing.expectEqual(3600, no_rule_zone.offsetAt(eu_spring - 1));
    try testing.expectEqual(7200, no_rule_zone.offsetAt(july_2027));

    try testing.expectError(error.InvalidZoneFile, Zone.fromTzif(testing.allocator, "TZif2 but cut short"));
}

test "the zone comes from TZ (a name or a rule), else /etc/localtime, else UTC" {
    // Each fallback is logged as a warning; keep the test output quiet.
    const log_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = log_level;
    const io = testing.io;
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const july = 1774746000 + 100 * day_seconds; // 2026

    var utc = load(io, gpa, null, tmp.dir);
    defer utc.deinit(gpa);
    try testing.expectEqualStrings("UTC", utc.name());
    try testing.expectEqual(0, utc.offsetAt(july));

    var buf: [256]u8 = undefined;
    const amsterdam = try testTzif(&buf, &.{}, &.{3600}, "CET-1CEST,M3.5.0,M10.5.0/3");
    try tmp.dir.createDirPath(io, "usr/share/zoneinfo/Europe");
    try tmp.dir.writeFile(io, .{ .sub_path = "usr/share/zoneinfo/Europe/Amsterdam", .data = amsterdam });
    try tmp.dir.createDirPath(io, "etc");
    try tmp.dir.symLink(io, "../usr/share/zoneinfo/Europe/Amsterdam", "etc/localtime", .{});

    const cases = [_]struct { ?[]const u8, []const u8, i32 }{
        .{ "Europe/Amsterdam", "Europe/Amsterdam", 7200 },
        .{ ":Europe/Amsterdam", "Europe/Amsterdam", 7200 },
        .{ "EST5EDT,M3.2.0,M11.1.0", "EST5EDT,M3.2.0,M11.1.0", -4 * 3600 },
        // Not TZ: /etc/localtime, named after the zone its link points to.
        .{ null, "Europe/Amsterdam", 7200 },
        .{ "Mars/Olympus", "Europe/Amsterdam", 7200 },
        .{ "../../etc/localtime", "Europe/Amsterdam", 7200 },
    };
    for (cases) |case| {
        var zone = load(io, gpa, case[0], tmp.dir);
        defer zone.deinit(gpa);
        try testing.expectEqualStrings(case[1], zone.name());
        try testing.expectEqual(case[2], zone.offsetAt(july));
    }

    // A copy instead of a link (Proxmox does that) is named by /etc/timezone.
    try tmp.dir.deleteFile(io, "etc/localtime");
    try tmp.dir.writeFile(io, .{ .sub_path = "etc/localtime", .data = amsterdam });
    try tmp.dir.writeFile(io, .{ .sub_path = "etc/timezone", .data = "Europe/Amsterdam\n" });
    var copied = load(io, gpa, null, tmp.dir);
    defer copied.deinit(gpa);
    try testing.expectEqualStrings("Europe/Amsterdam", copied.name());
    try testing.expectEqual(7200, copied.offsetAt(july));
}
