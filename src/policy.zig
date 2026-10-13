//! The Policy: decides how a name is answered without asking an upstream
//! server (steps 2-4 of the query pipeline: local records, blocked names,
//! private names). It is built from two parts:
//!
//!   ConfigPolicy  built from the config file alone: local records, inline
//!                 block/allow rules and response settings. Cheap to build,
//!                 so a reload (SIGHUP) applies it instantly.
//!   Lists         built from downloaded or local list files. Loaded in the
//!                 background at start, on every refresh, and when a reload
//!                 changes the configured sources.
//!
//! Both are immutable once built; the Policy swaps in new ones under its lock.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const Config = @import("config.zig").Config;
const DomainSet = @import("domain_set.zig").DomainSet;
const dns = @import("dns.zig");
const local = @import("local.zig");
const LocalZone = local.LocalZone;
const blocklist = @import("blocklist.zig");

const log = std.log.scoped(.lists);

/// A single list may not exceed this much (decompressed) data.
const max_list_bytes = 64 * 1024 * 1024;

/// Firefox enables DNS-over-HTTPS on its own (bypassing this resolver)
/// unless this name fails to resolve.
const firefox_doh_canary = "use-application-dns.net";

pub const Policy = struct {
    io: Io,
    gpa: Allocator,
    /// Guards the pointers below: `decide` holds it shared, swaps hold it
    /// exclusively only to replace a pointer.
    lock: Io.RwLock = .init,
    config_policy: *ConfigPolicy,
    lists: *Lists,

    pub const Decision = union(enum) {
        local: Local,
        /// A reverse lookup (PTR) for a local record's address.
        reverse: Reverse,
        blocked: Blocked,
        /// A private name that no local record answers: never sent upstream.
        private,
        /// Not decided here: try the cache, then the upstream servers.
        upstream,

        pub const Local = struct {
            addresses: Addresses,
            ttl: u32,
        };

        pub const Blocked = struct {
            response: Config.BlockResponse,
            ttl: u32,
        };

        pub const Reverse = struct {
            host_buf: [dns.max_name_len]u8 = undefined,
            host_len: u8 = 0,
            ttl: u32,

            fn init(name: []const u8, ttl: u32) Reverse {
                var result: Reverse = .{ .host_len = @intCast(name.len), .ttl = ttl };
                @memcpy(result.host_buf[0..name.len], name);
                return result;
            }

            pub fn host(reverse: *const Reverse) []const u8 {
                return reverse.host_buf[0..reverse.host_len];
            }
        };

        /// A copy of a local record's addresses.
        pub const Addresses = struct {
            v4_buf: [local.max_addresses][4]u8 = undefined,
            v6_buf: [local.max_addresses][16]u8 = undefined,
            v4_len: u8 = 0,
            v6_len: u8 = 0,

            fn copy(addresses: local.Addresses) Addresses {
                var result: Addresses = .{ .v4_len = @intCast(addresses.v4.len), .v6_len = @intCast(addresses.v6.len) };
                @memcpy(result.v4_buf[0..addresses.v4.len], addresses.v4);
                @memcpy(result.v6_buf[0..addresses.v6.len], addresses.v6);
                return result;
            }

            pub fn v4(addresses: *const Addresses) []const [4]u8 {
                return addresses.v4_buf[0..addresses.v4_len];
            }

            pub fn v6(addresses: *const Addresses) []const [16]u8 {
                return addresses.v6_buf[0..addresses.v6_len];
            }
        };
    };

    /// Starts with no lists; they are loaded separately and handed in with
    /// `replaceLists`.
    pub fn init(io: Io, gpa: Allocator, config: *const Config) Allocator.Error!Policy {
        const config_policy: *ConfigPolicy = try .create(io, gpa, config);
        errdefer config_policy.destroy();
        return .{ .io = io, .gpa = gpa, .config_policy = config_policy, .lists = try .createEmpty(io, gpa) };
    }

    pub fn deinit(policy: *Policy) void {
        policy.config_policy.destroy();
        policy.lists.destroy();
        policy.* = undefined;
    }

    /// Replaces the part built from the config file (on reload).
    pub fn applyConfig(policy: *Policy, config: *const Config) Allocator.Error!void {
        const new = try ConfigPolicy.create(policy.io, policy.gpa, config);
        const old = old: {
            policy.lock.lockUncancelable(policy.io);
            defer policy.lock.unlock(policy.io);
            const old = policy.config_policy;
            policy.config_policy = new;
            break :old old;
        };
        old.destroy();
    }

    pub const Replacement = enum { replaced, kept };

    /// Takes ownership of `lists` and serves them instead of the current
    /// ones, unless they are partial, the current ones are complete, and
    /// both come from the same sources (a failed Refresh must not weaken
    /// blocking; after a source change the new lists win even if partial).
    pub fn replaceLists(policy: *Policy, lists: *Lists) Replacement {
        const old = old: {
            policy.lock.lockUncancelable(policy.io);
            defer policy.lock.unlock(policy.io);
            const current = policy.lists;
            if (!lists.complete and current.complete and lists.sources.eql(current.sources)) break :old lists;
            policy.lists = lists;
            break :old current;
        };
        old.destroy();
        return if (old == lists) .kept else .replaced;
    }

    /// `name` must be in the form `dns.Query.name` has: lowercase, without a
    /// trailing dot.
    pub fn decide(policy: *Policy, name: []const u8, qtype: dns.Type) Decision {
        if (builtin.mode == .debug) std.debug.assert(isNormalized(name));
        policy.lock.lockSharedUncancelable(policy.io);
        defer policy.lock.unlockShared(policy.io);
        const config_policy = policy.config_policy;
        if (config_policy.local.lookup(name)) |addresses| {
            return .{ .local = .{ .addresses = .copy(addresses), .ttl = config_policy.local_ttl } };
        }
        if (qtype == .ptr) {
            if (config_policy.local.reverseLookup(name)) |host| return .{ .reverse = .init(host, config_policy.local_ttl) };
        }
        if (std.mem.eql(u8, name, firefox_doh_canary)) {
            return .{ .blocked = .{ .response = .nxdomain, .ttl = config_policy.block_ttl } };
        }
        if (policy.isBlocked(name)) {
            return .{ .blocked = .{ .response = config_policy.block_response, .ttl = config_policy.block_ttl } };
        }
        if (!config_policy.forward_private and config_policy.local.isPrivate(name)) return .private;
        return .upstream;
    }

    /// Blocked unless an allow rule (inline or from a list) also matches.
    /// Caller holds the lock.
    fn isBlocked(policy: *const Policy, name: []const u8) bool {
        const blocked = policy.config_policy.block.matches(name) or policy.lists.block.matches(name);
        return blocked and !(policy.config_policy.allow.matches(name) or policy.lists.allow.matches(name));
    }

    fn isNormalized(name: []const u8) bool {
        if (std.mem.endsWith(u8, name, ".")) return false;
        for (name) |c| {
            if (std.ascii.isUpper(c)) return false;
        }
        return true;
    }
};

const ConfigPolicy = struct {
    gpa: Allocator,
    local: LocalZone,
    /// Inline rules from the config file.
    block: DomainSet,
    allow: DomainSet,
    block_response: Config.BlockResponse,
    block_ttl: u32,
    local_ttl: u32,
    forward_private: bool,

    pub fn create(io: Io, gpa: Allocator, config: *const Config) Allocator.Error!*ConfigPolicy {
        const policy = try gpa.create(ConfigPolicy);
        errdefer gpa.destroy(policy);
        policy.* = .{
            .gpa = gpa,
            .local = try .init(gpa, config.local.records, randomSeed(io)),
            .block = .init(randomSeed(io)),
            .allow = .init(randomSeed(io)),
            .block_response = config.blocking.response,
            .block_ttl = config.blocking.ttl,
            .local_ttl = config.local.ttl,
            .forward_private = config.local.private_names == .forward,
        };
        errdefer policy.deinit();

        // The config loader already checked that every inline rule parses.
        var block_sink: blocklist.Sink = .{ .gpa = gpa, .block = &policy.block, .allow = &policy.allow, .is_allowlist = false };
        for (config.blocking.block) |rule| try addInline(rule, &block_sink);
        var allow_sink: blocklist.Sink = .{ .gpa = gpa, .block = &policy.block, .allow = &policy.allow, .is_allowlist = true };
        for (config.blocking.allow) |rule| try addInline(rule, &allow_sink);
        return policy;
    }

    pub fn destroy(policy: *ConfigPolicy) void {
        const gpa = policy.gpa;
        policy.deinit();
        gpa.destroy(policy);
    }

    fn deinit(policy: *ConfigPolicy) void {
        policy.local.deinit();
        policy.block.deinit(policy.gpa);
        policy.allow.deinit(policy.gpa);
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

    pub const empty: Sources = .{ .blocklists = &.{}, .allowlists = &.{} };

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
    /// The sources these lists were loaded from; their strings live in `arena`.
    sources: Sources = .empty,
    /// Whether each source loaded: the blocklists, then the allowlists.
    loaded: []const bool = &.{},
    arena: std.heap.ArenaAllocator,

    /// Lists with no entries; `complete` is false so the first real load
    /// replaces them even if some sources fail.
    fn createEmpty(io: Io, gpa: Allocator) Allocator.Error!*Lists {
        const lists = try gpa.create(Lists);
        lists.* = .{ .gpa = gpa, .block = .init(randomSeed(io)), .allow = .init(randomSeed(io)), .complete = false, .arena = .init(gpa) };
        return lists;
    }

    /// Loads every source. A source that fails is logged and skipped, and
    /// leaves `complete` false.
    pub fn load(io: Io, gpa: Allocator, sources: Sources) (Allocator.Error || Io.Cancelable)!*Lists {
        const lists = try createEmpty(io, gpa);
        errdefer lists.destroy();
        lists.sources = try sources.dupe(lists.arena.allocator());
        lists.complete = true;
        if (sources.isEmpty()) return lists;

        const started = Io.Clock.awake.now(io);
        var client: std.http.Client = .{ .allocator = gpa, .io = io };
        defer client.deinit();
        const loaded = try lists.arena.allocator().alloc(bool, sources.blocklists.len + sources.allowlists.len);
        for (sources.blocklists, loaded[0..sources.blocklists.len]) |source, *ok| {
            ok.* = try lists.loadSource(io, &client, source, false);
        }
        for (sources.allowlists, loaded[sources.blocklists.len..]) |source, *ok| {
            ok.* = try lists.loadSource(io, &client, source, true);
        }
        lists.loaded = loaded;
        const failed = std.mem.count(bool, loaded, &.{false});
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
        lists.arena.deinit();
        lists.gpa.destroy(lists);
    }

    /// Returns false if the source could not be loaded.
    fn loadSource(lists: *Lists, io: Io, client: *std.http.Client, source: []const u8, is_allowlist: bool) (Allocator.Error || Io.Cancelable)!bool {
        var sink: blocklist.Sink = .{ .gpa = lists.gpa, .block = &lists.block, .allow = &lists.allow, .is_allowlist = is_allowlist };
        blocklist.load(io, lists.gpa, client, source, &sink, max_list_bytes) catch |err| {
            if (err == error.Canceled) return error.Canceled;
            if (err == error.OutOfMemory) return error.OutOfMemory;
            log.warn("{s}: {t} (kept {d} rules read before the error)", .{ source, err, sink.stats.rules });
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

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;
const config_mod = @import("config.zig");

/// A config parsed from `source`, with the upstream server the config requires.
fn testConfig(source: []const u8) !Config {
    var buf: [4096]u8 = undefined;
    const full = try std.fmt.bufPrint(&buf, "upstream:\n  servers: [9.9.9.9]\n{s}", .{source});
    var diag: config_mod.Diagnostic = .{};
    return config_mod.parse(testing.allocator, full, &diag) catch |err| {
        std.debug.print("line {d}: {s}\n", .{ diag.line, diag.message() });
        return err;
    };
}

fn testPolicy(source: []const u8) !Policy {
    var cfg = try testConfig(source);
    defer cfg.deinit();
    return Policy.init(testing.io, testing.allocator, &cfg);
}

test "a local record decides local, with its addresses and TTL" {
    var policy = try testPolicy(
        \\local:
        \\  ttl: 120
        \\  records:
        \\    nas.lan: [192.168.1.10, "fd00::10"]
    );
    defer policy.deinit();

    const decision = policy.decide("nas.lan", .a);
    try testing.expect(decision == .local);
    try testing.expectEqual(120, decision.local.ttl);
    try testing.expectEqualSlices([4]u8, &.{.{ 192, 168, 1, 10 }}, decision.local.addresses.v4());
    try testing.expectEqualSlices([16]u8, &.{.{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 }}, decision.local.addresses.v6());
}

fn expectLocalV4(policy: *Policy, name: []const u8, expected: [4]u8) !void {
    const decision = policy.decide(name, .a);
    try testing.expect(decision == .local);
    try testing.expectEqualSlices([4]u8, &.{expected}, decision.local.addresses.v4());
}

test "a wildcard matches every name below it, and exact records win" {
    var policy = try testPolicy(
        \\local:
        \\  records:
        \\    "*.apps.lan": 192.168.1.20
        \\    special.apps.lan: 192.168.1.30
    );
    defer policy.deinit();

    try expectLocalV4(&policy, "grafana.apps.lan", .{ 192, 168, 1, 20 });
    try expectLocalV4(&policy, "a.b.apps.lan", .{ 192, 168, 1, 20 });
    try expectLocalV4(&policy, "special.apps.lan", .{ 192, 168, 1, 30 });
    try testing.expect(policy.decide("apps.lan", .a) != .local);
    try testing.expect(policy.decide("other.lan", .a) != .local);
}

test "localhost is built in but can be overridden" {
    var builtin_policy = try testPolicy("");
    defer builtin_policy.deinit();
    try expectLocalV4(&builtin_policy, "localhost", .{ 127, 0, 0, 1 });
    try expectLocalV4(&builtin_policy, "app.localhost", .{ 127, 0, 0, 1 });

    var custom = try testPolicy(
        \\local:
        \\  records:
        \\    localhost: 127.0.0.2
    );
    defer custom.deinit();
    try expectLocalV4(&custom, "localhost", .{ 127, 0, 0, 2 });
}

test "a PTR query for a local record's address decides reverse, first name wins" {
    var policy = try testPolicy(
        \\local:
        \\  ttl: 60
        \\  records:
        \\    nas.lan: [192.168.1.10, "fd00::10"]
        \\    media.lan: 192.168.1.10
    );
    defer policy.deinit();

    const v4 = policy.decide("10.1.168.192.in-addr.arpa", .ptr);
    try testing.expect(v4 == .reverse);
    try testing.expectEqualStrings("nas.lan", v4.reverse.host());
    try testing.expectEqual(60, v4.reverse.ttl);

    const v6 = policy.decide("0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa", .ptr);
    try testing.expectEqualStrings("nas.lan", v6.reverse.host());

    // Only PTR queries get a reverse answer.
    try testing.expect(policy.decide("10.1.168.192.in-addr.arpa", .a) != .reverse);
    try testing.expect(policy.decide("11.1.168.192.in-addr.arpa", .ptr) != .reverse);
}

test "a block rule decides blocked, with the block response and TTL" {
    var policy = try testPolicy(
        \\blocking:
        \\  ttl: 30
        \\  block: [ads.example.com]
    );
    defer policy.deinit();

    const decision = policy.decide("ads.example.com", .a);
    try testing.expect(decision == .blocked);
    try testing.expectEqual(.zero, decision.blocked.response);
    try testing.expectEqual(30, decision.blocked.ttl);
    // A listed domain blocks its subdomains too, for every record type.
    try testing.expect(policy.decide("x.ads.example.com", .https) == .blocked);
    try testing.expect(policy.decide("example.com", .a) == .upstream);

    var nxdomain = try testPolicy(
        \\blocking:
        \\  response: nxdomain
        \\  block: [ads.example.com]
    );
    defer nxdomain.deinit();
    try testing.expectEqual(.nxdomain, nxdomain.decide("ads.example.com", .a).blocked.response);
}

test "an allow rule wins over a block rule" {
    var policy = try testPolicy(
        \\blocking:
        \\  block: [example.com]
        \\  allow: [cdn.example.com]
    );
    defer policy.deinit();

    try testing.expect(policy.decide("cdn.example.com", .a) == .upstream);
    try testing.expect(policy.decide("img.cdn.example.com", .a) == .upstream);
    try testing.expect(policy.decide("ads.example.com", .a) == .blocked);
}

test "the Firefox canary is blocked with NXDOMAIN, whatever the block response" {
    var policy = try testPolicy("");
    defer policy.deinit();

    const decision = policy.decide("use-application-dns.net", .a);
    try testing.expect(decision == .blocked);
    try testing.expectEqual(.nxdomain, decision.blocked.response);
}

test "private names decide private, unless they are forwarded" {
    var policy = try testPolicy("");
    defer policy.deinit();

    for ([_][]const u8{
        "printer",
        "nas.lan",
        "router.home.arpa",
        "1.1.168.192.in-addr.arpa",
        "1.0.20.172.in-addr.arpa",
        "1.0.100.100.in-addr.arpa",
    }) |name| {
        try testing.expect(policy.decide(name, .a) == .private);
    }
    for ([_][]const u8{
        "1.0.32.172.in-addr.arpa",
        "8.8.8.8.in-addr.arpa",
        "example.com",
        "planet.com",
        "",
    }) |name| {
        try testing.expect(policy.decide(name, .a) == .upstream);
    }

    var forward = try testPolicy(
        \\local:
        \\  private_names: forward
    );
    defer forward.deinit();
    try testing.expect(forward.decide("printer", .a) == .upstream);
}

test "a local record wins over a block rule, and a block rule over a private name" {
    var policy = try testPolicy(
        \\blocking:
        \\  block: [tracker.example.com, "*.lan"]
        \\local:
        \\  records:
        \\    tracker.example.com: 192.168.1.50
    );
    defer policy.deinit();

    try testing.expect(policy.decide("tracker.example.com", .a) == .local);
    try testing.expect(policy.decide("printer.lan", .a) == .blocked);
}

test "applyConfig replaces local records and inline rules" {
    var policy = try testPolicy(
        \\local:
        \\  records:
        \\    nas.lan: 192.168.1.10
    );
    defer policy.deinit();

    var reloaded = try testConfig(
        \\blocking:
        \\  block: [ads.example.com]
        \\local:
        \\  records:
        \\    nas.lan: 192.168.1.11
    );
    defer reloaded.deinit();
    try policy.applyConfig(&reloaded);

    try expectLocalV4(&policy, "nas.lan", .{ 192, 168, 1, 11 });
    try testing.expect(policy.decide("ads.example.com", .a) == .blocked);
}

/// Lists loaded through `Lists.load` from a blocklist and an allowlist file.
fn testLists(blocklist_text: []const u8, allowlist_text: []const u8) !*Lists {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "block.txt", .data = blocklist_text });
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "allow.txt", .data = allowlist_text });
    var block_buf: [64]u8 = undefined;
    var allow_buf: [64]u8 = undefined;
    const block_path = try std.fmt.bufPrint(&block_buf, ".zig-cache/tmp/{s}/block.txt", .{tmp.sub_path});
    const allow_path = try std.fmt.bufPrint(&allow_buf, ".zig-cache/tmp/{s}/allow.txt", .{tmp.sub_path});
    return Lists.load(testing.io, testing.allocator, .{ .blocklists = &.{block_path}, .allowlists = &.{allow_path} });
}

test "rules from lists block and allow like inline rules" {
    var policy = try testPolicy(
        \\blocking:
        \\  block: [inline-blocked.example]
        \\  allow: [list-blocked.example]
    );
    defer policy.deinit();

    try testing.expectEqual(.replaced, policy.replaceLists(try testLists(
        \\0.0.0.0 ads.example
        \\||list-blocked.example^
    , "inline-blocked.example\n")));

    try testing.expect(policy.decide("ads.example", .a) == .blocked);
    // Allow rules win, wherever each rule comes from.
    try testing.expect(policy.decide("list-blocked.example", .a) == .upstream);
    try testing.expect(policy.decide("inline-blocked.example", .a) == .upstream);
}

test "partial lists replace complete ones only when the sources changed" {
    const io = testing.io;
    // Failed sources are logged as warnings; keep the test output quiet.
    const log_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = log_level;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "a.txt", .data = "a.example\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "b.txt", .data = "b.example\n" });
    var a_buf: [64]u8 = undefined;
    var b_buf: [64]u8 = undefined;
    var c_buf: [64]u8 = undefined;
    const a = try std.fmt.bufPrint(&a_buf, ".zig-cache/tmp/{s}/a.txt", .{tmp.sub_path});
    const b = try std.fmt.bufPrint(&b_buf, ".zig-cache/tmp/{s}/b.txt", .{tmp.sub_path});
    const c = try std.fmt.bufPrint(&c_buf, ".zig-cache/tmp/{s}/c.txt", .{tmp.sub_path}); // never written

    var policy = try testPolicy("");
    defer policy.deinit();
    const ab: Sources = .{ .blocklists = &.{ a, b }, .allowlists = &.{} };
    try testing.expectEqual(.replaced, policy.replaceLists(try Lists.load(io, testing.allocator, ab)));

    // A Refresh in which b fails: the complete lists keep serving.
    try tmp.dir.deleteFile(io, "b.txt");
    try testing.expectEqual(.kept, policy.replaceLists(try Lists.load(io, testing.allocator, ab)));
    try testing.expect(policy.decide("b.example", .a) == .blocked);

    // A Reload removed b and added c, which fails: the new lists win anyway.
    const ac: Sources = .{ .blocklists = &.{ a, c }, .allowlists = &.{} };
    try testing.expectEqual(.replaced, policy.replaceLists(try Lists.load(io, testing.allocator, ac)));
    try testing.expect(policy.decide("b.example", .a) == .upstream);
    try testing.expect(policy.decide("a.example", .a) == .blocked);
}

test "a load records which sources it got" {
    const io = testing.io;
    // The failed source is logged as a warning; keep the test output quiet.
    const log_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = log_level;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "a.txt", .data = "a.example\n" });
    var a_buf: [64]u8 = undefined;
    var missing_buf: [64]u8 = undefined;
    const a = try std.fmt.bufPrint(&a_buf, ".zig-cache/tmp/{s}/a.txt", .{tmp.sub_path});
    const missing = try std.fmt.bufPrint(&missing_buf, ".zig-cache/tmp/{s}/missing.txt", .{tmp.sub_path});

    const lists = try Lists.load(io, testing.allocator, .{ .blocklists = &.{ a, missing }, .allowlists = &.{a} });
    defer lists.destroy();
    try testing.expectEqualSlices(bool, &.{ true, false, true }, lists.loaded);
}
