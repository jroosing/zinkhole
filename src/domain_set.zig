//! A compact set of domain names with subdomain matching, used for block- and
//! allowlists. Lists can hold millions of names, so the layout is tuned for
//! memory and lookup speed:
//!
//!   bytes: [len][name][len][name]...   every name stored once, back to back
//!   map:   offset into `bytes` -> Match flags (4-byte keys, no pointers)
//!
//! A lookup hashes the queried name and compares it against `bytes` in place,
//! so lookups never allocate. Each name costs its length plus about 10 bytes.
//!
//! The set is built once (single writer) and then only read, so concurrent
//! lookups from many threads need no locking.

const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const DomainSet = struct {
    bytes: std.ArrayList(u8) = .empty,
    map: Map = .empty,
    /// Random per-set hash seed, so list contents cannot be crafted to collide.
    seed: u64,

    /// Which names an entry covers.
    pub const Match = packed struct(u8) {
        /// The listed name itself.
        exact: bool = false,
        /// Every name below the listed one.
        subdomains: bool = false,
        _padding: u6 = 0,

        pub const domain_and_subdomains: Match = .{ .exact = true, .subdomains = true };
        pub const subdomains_only: Match = .{ .subdomains = true };
    };

    const Map = std.HashMapUnmanaged(u32, Match, OffsetContext, std.hash_map.default_max_load_percentage);

    pub fn init(seed: u64) DomainSet {
        return .{ .seed = seed };
    }

    pub fn deinit(set: *DomainSet, gpa: Allocator) void {
        set.map.deinit(gpa);
        set.bytes.deinit(gpa);
        set.* = undefined;
    }

    pub fn count(set: *const DomainSet) u32 {
        return set.map.count();
    }

    /// Adds a normalized name (lowercase, no trailing dot). Adding a name
    /// twice merges the match flags.
    pub fn add(set: *DomainSet, gpa: Allocator, name: []const u8, match: Match) error{ OutOfMemory, SetFull }!void {
        assert(name.len > 0 and name.len <= std.math.maxInt(u8));
        // Offsets are 32-bit.
        if (set.bytes.items.len + 1 + name.len > std.math.maxInt(u32)) return error.SetFull;
        // Reserve first, so nothing can fail after the map entry exists.
        try set.bytes.ensureUnusedCapacity(gpa, 1 + name.len);
        // The hash contexts read `bytes` while the map rehashes, so it must
        // not move until the entry is complete.
        set.bytes.lockPointers();
        defer set.bytes.unlockPointers();

        const gop = try set.map.getOrPutContextAdapted(gpa, name, set.adapter(), set.context());
        if (gop.found_existing) {
            gop.value_ptr.* = .{
                .exact = gop.value_ptr.exact or match.exact,
                .subdomains = gop.value_ptr.subdomains or match.subdomains,
            };
            return;
        }
        gop.key_ptr.* = @intCast(set.bytes.items.len);
        gop.value_ptr.* = match;
        set.bytes.appendAssumeCapacity(@intCast(name.len));
        set.bytes.appendSliceAssumeCapacity(name);
    }

    /// Returns the flags stored for exactly `name`.
    pub fn get(set: *const DomainSet, name: []const u8) ?Match {
        return set.map.getAdapted(name, set.adapter());
    }

    /// True if `name` is covered by an entry for itself or for one of its
    /// parent domains.
    pub fn matches(set: *const DomainSet, name: []const u8) bool {
        if (name.len == 0 or set.map.count() == 0) return false;
        if (set.get(name)) |match| {
            if (match.exact) return true;
        }
        var parent = name;
        while (std.mem.findScalar(u8, parent, '.')) |dot| {
            parent = parent[dot + 1 ..];
            if (set.get(parent)) |match| {
                if (match.subdomains) return true;
            }
        }
        return false;
    }

    /// Releases spare capacity once the set is complete.
    pub fn shrink(set: *DomainSet, gpa: Allocator) void {
        set.bytes.shrinkAndFree(gpa, set.bytes.items.len);
    }

    /// Bytes of memory held by the set.
    pub fn memoryUsage(set: *const DomainSet) usize {
        const slot_size = @sizeOf(u32) + @sizeOf(Match) + 1; // key, value, metadata
        return set.bytes.capacity + @as(usize, set.map.capacity()) * slot_size;
    }

    fn context(set: *const DomainSet) OffsetContext {
        return .{ .bytes = set.bytes.items, .seed = set.seed };
    }

    fn adapter(set: *const DomainSet) NameAdapter {
        return .{ .bytes = set.bytes.items, .seed = set.seed };
    }

    fn nameAt(bytes: []const u8, offset: u32) []const u8 {
        const len = bytes[offset];
        return bytes[offset + 1 ..][0..len];
    }

    /// Hashes stored entries (keys are offsets into `bytes`).
    const OffsetContext = struct {
        bytes: []const u8,
        seed: u64,

        pub fn hash(ctx: OffsetContext, offset: u32) u64 {
            return std.hash.Wyhash.hash(ctx.seed, nameAt(ctx.bytes, offset));
        }

        pub fn eql(_: OffsetContext, a: u32, b: u32) bool {
            return a == b;
        }
    };

    /// Looks up entries by name without storing the name first.
    const NameAdapter = struct {
        bytes: []const u8,
        seed: u64,

        pub fn hash(ctx: NameAdapter, name: []const u8) u64 {
            return std.hash.Wyhash.hash(ctx.seed, name);
        }

        pub fn eql(ctx: NameAdapter, name: []const u8, offset: u32) bool {
            return std.mem.eql(u8, name, nameAt(ctx.bytes, offset));
        }
    };
};

const testing = std.testing;

test "exact and subdomain matching" {
    var set: DomainSet = .init(0x1234);
    defer set.deinit(testing.allocator);

    try set.add(testing.allocator, "ads.example.com", .domain_and_subdomains);
    try set.add(testing.allocator, "tracker.net", .subdomains_only);

    try testing.expect(set.matches("ads.example.com"));
    try testing.expect(set.matches("x.y.ads.example.com"));
    try testing.expect(!set.matches("example.com"));
    try testing.expect(!set.matches("bads.example.com"));

    try testing.expect(!set.matches("tracker.net"));
    try testing.expect(set.matches("a.tracker.net"));
    try testing.expect(!set.matches(""));

    // Adding the same name again merges the flags.
    try set.add(testing.allocator, "tracker.net", .{ .exact = true });
    try testing.expect(set.matches("tracker.net"));
    try testing.expectEqual(2, set.count());
}

test "many names survive rehashing" {
    var set: DomainSet = .init(42);
    defer set.deinit(testing.allocator);

    var buf: [32]u8 = undefined;
    for (0..20_000) |i| {
        try set.add(testing.allocator, try std.fmt.bufPrint(&buf, "host{d}.example.org", .{i}), .domain_and_subdomains);
    }
    set.shrink(testing.allocator);
    try testing.expectEqual(20_000, set.count());
    for (0..20_000) |i| {
        try testing.expect(set.matches(try std.fmt.bufPrint(&buf, "www.host{d}.example.org", .{i})));
    }
    try testing.expect(!set.matches("host20000.example.org"));
    try testing.expect(set.memoryUsage() > 0);
}
