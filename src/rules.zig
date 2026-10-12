//! Everything that decides how a name is answered, in two parts:
//!
//!   Rules  built from the config file alone: local records, inline
//!          block/allow rules and response settings. Cheap to build, so a
//!          reload (SIGHUP) applies them instantly.
//!   Lists  built from downloaded or local list files. Loaded in the
//!          background at start, on every refresh, and when a reload
//!          changes the configured sources.
//!
//! Both are immutable once built; the resolver swaps in new ones atomically.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const Config = @import("config.zig").Config;
const DomainSet = @import("domain_set.zig").DomainSet;
const LocalZone = @import("local.zig").LocalZone;
const blocklist = @import("blocklist.zig");

const log = std.log.scoped(.lists);

/// A single list may not exceed this much (decompressed) data.
const max_list_bytes = 64 * 1024 * 1024;

pub const Rules = struct {
    gpa: Allocator,
    local: LocalZone,
    /// Inline rules from the config file.
    block: DomainSet,
    allow: DomainSet,
    block_response: Config.BlockResponse,
    block_ttl: u32,
    local_ttl: u32,
    forward_private: bool,

    pub fn create(io: Io, gpa: Allocator, config: *const Config) Allocator.Error!*Rules {
        const rules = try gpa.create(Rules);
        errdefer gpa.destroy(rules);
        rules.* = .{
            .gpa = gpa,
            .local = try .init(gpa, config.local.records, randomSeed(io)),
            .block = .init(randomSeed(io)),
            .allow = .init(randomSeed(io)),
            .block_response = config.blocking.response,
            .block_ttl = config.blocking.ttl,
            .local_ttl = config.local.ttl,
            .forward_private = config.local.private_names == .forward,
        };
        errdefer rules.deinit();

        // The config loader already checked that every inline rule parses.
        var block_sink: blocklist.Sink = .{ .gpa = gpa, .block = &rules.block, .allow = &rules.allow, .is_allowlist = false };
        for (config.blocking.block) |rule| try addInline(rule, &block_sink);
        var allow_sink: blocklist.Sink = .{ .gpa = gpa, .block = &rules.block, .allow = &rules.allow, .is_allowlist = true };
        for (config.blocking.allow) |rule| try addInline(rule, &allow_sink);
        return rules;
    }

    pub fn destroy(rules: *Rules) void {
        const gpa = rules.gpa;
        rules.deinit();
        gpa.destroy(rules);
    }

    fn deinit(rules: *Rules) void {
        rules.local.deinit();
        rules.block.deinit(rules.gpa);
        rules.allow.deinit(rules.gpa);
    }

    fn addInline(rule: []const u8, sink: *blocklist.Sink) Allocator.Error!void {
        blocklist.parseLine(rule, sink) catch |err| switch (err) {
            error.OutOfMemory => |e| return e,
            error.SetFull => unreachable, // a handful of inline rules
        };
    }
};

/// The list sources to load: URLs or file paths.
pub const Sources = struct {
    blocklists: []const []const u8,
    allowlists: []const []const u8,

    pub fn fromConfig(config: *const Config) Sources {
        return .{ .blocklists = config.blocking.lists, .allowlists = config.blocking.allowlists };
    }

    pub fn isEmpty(sources: Sources) bool {
        return sources.blocklists.len == 0 and sources.allowlists.len == 0;
    }

    pub fn eql(a: Sources, b: Sources) bool {
        return eqlStrings(a.blocklists, b.blocklists) and eqlStrings(a.allowlists, b.allowlists);
    }

    /// A copy whose strings live in `arena`.
    pub fn dupe(sources: Sources, arena: Allocator) Allocator.Error!Sources {
        return .{
            .blocklists = try dupeStrings(arena, sources.blocklists),
            .allowlists = try dupeStrings(arena, sources.allowlists),
        };
    }

    fn eqlStrings(a: []const []const u8, b: []const []const u8) bool {
        if (a.len != b.len) return false;
        for (a, b) |x, y| {
            if (!std.mem.eql(u8, x, y)) return false;
        }
        return true;
    }

    fn dupeStrings(arena: Allocator, strings: []const []const u8) Allocator.Error![]const []const u8 {
        const copy = try arena.alloc([]const u8, strings.len);
        for (strings, copy) |s, *c| c.* = try arena.dupe(u8, s);
        return copy;
    }
};

pub const Lists = struct {
    gpa: Allocator,
    block: DomainSet,
    allow: DomainSet,
    /// False if any source failed to load.
    complete: bool,

    /// Lists with no entries; `complete` is false so the first real load
    /// replaces them even if some sources fail.
    pub fn createEmpty(io: Io, gpa: Allocator) Allocator.Error!*Lists {
        const lists = try gpa.create(Lists);
        lists.* = .{ .gpa = gpa, .block = .init(randomSeed(io)), .allow = .init(randomSeed(io)), .complete = false };
        return lists;
    }

    /// Loads every source. A source that fails is logged and skipped, and
    /// leaves `complete` false.
    pub fn load(io: Io, gpa: Allocator, sources: Sources) (Allocator.Error || Io.Cancelable)!*Lists {
        const lists = try createEmpty(io, gpa);
        errdefer lists.destroy();
        lists.complete = true;
        if (sources.isEmpty()) return lists;

        const started = Io.Clock.awake.now(io);
        var client: std.http.Client = .{ .allocator = gpa, .io = io };
        defer client.deinit();
        var failed: usize = 0;
        for (sources.blocklists) |source| {
            if (!try lists.loadSource(io, &client, source, false)) failed += 1;
        }
        for (sources.allowlists) |source| {
            if (!try lists.loadSource(io, &client, source, true)) failed += 1;
        }
        lists.complete = failed == 0;
        lists.block.shrink(gpa);
        lists.allow.shrink(gpa);

        const memory = lists.block.memoryUsage() + lists.allow.memoryUsage();
        log.info("{d} blocked and {d} allowed domains from {d} sources ({d} failed), {d} KiB, {d} ms", .{
            lists.block.count(),
            lists.allow.count(),
            sources.blocklists.len + sources.allowlists.len,
            failed,
            memory / 1024,
            started.untilNow(io, .awake).toMilliseconds(),
        });
        return lists;
    }

    pub fn destroy(lists: *Lists) void {
        lists.block.deinit(lists.gpa);
        lists.allow.deinit(lists.gpa);
        lists.gpa.destroy(lists);
    }

    /// Returns false if the source could not be loaded.
    fn loadSource(lists: *Lists, io: Io, client: *std.http.Client, source: []const u8, is_allowlist: bool) (Allocator.Error || Io.Cancelable)!bool {
        var sink: blocklist.Sink = .{ .gpa = lists.gpa, .block = &lists.block, .allow = &lists.allow, .is_allowlist = is_allowlist };
        blocklist.load(io, lists.gpa, client, source, &sink, max_list_bytes) catch |err| {
            if (err == error.Canceled) return error.Canceled;
            if (err == error.OutOfMemory) return error.OutOfMemory;
            log.err("{s}: {t} (kept {d} rules read before the error)", .{ source, err, sink.stats.rules });
            return false;
        };
        log.debug("{s}: {d} rules, {d} lines skipped", .{ source, sink.stats.rules, sink.stats.skipped });
        return true;
    }
};

fn randomSeed(io: Io) u64 {
    var bytes: [8]u8 = undefined;
    io.random(&bytes);
    return std.mem.readInt(u64, &bytes, .little);
}
