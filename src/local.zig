//! Local DNS: hostnames for the LAN ("nas.lan -> 192.168.1.10"), reverse
//! (PTR) lookups for them, and the private and special-use names that must
//! never be forwarded to public upstream servers.

const std = @import("std");
const Allocator = std.mem.Allocator;

const dns = @import("dns.zig");
const DomainSet = @import("domain_set.zig").DomainSet;
const Ip = @import("ip.zig").Ip;

/// Most addresses a single hostname may have.
pub const max_addresses = 16;

/// A configured hostname.
pub const Record = struct {
    /// Normalized name. For a wildcard (`*.apps.lan`) this is the part after `*.`.
    name: []const u8,
    /// Matches every name below `name`, but not `name` itself.
    wildcard: bool,
    /// At most `max_addresses`.
    addresses: []const Ip,
};

pub const Addresses = struct {
    v4: []const [4]u8,
    v6: []const [16]u8,
};

pub const LocalZone = struct {
    /// Owns every name and address below.
    arena: std.heap.ArenaAllocator,
    exact: std.StringHashMapUnmanaged(Addresses) = .empty,
    /// Keyed by the name after `*.`.
    wildcards: std.StringHashMapUnmanaged(Addresses) = .empty,
    /// Address (in IPv6 form) -> first name configured for it, for PTR queries.
    reverse: std.AutoHashMapUnmanaged([16]u8, []const u8) = .empty,
    /// Private and special-use zones; see `private_zones`.
    private: DomainSet,

    pub fn init(gpa: Allocator, records: []const Record, seed: u64) Allocator.Error!LocalZone {
        var zone: LocalZone = .{ .arena = .init(gpa), .private = .init(seed) };
        errdefer zone.deinit();
        const arena = zone.arena.allocator();

        for (records) |record| {
            const name = try arena.dupe(u8, record.name);
            const addresses = try splitFamilies(arena, record.addresses);
            const map = if (record.wildcard) &zone.wildcards else &zone.exact;
            try map.put(arena, name, addresses);
            if (record.wildcard) continue;
            for (record.addresses) |ip| {
                const gop = try zone.reverse.getOrPut(arena, ip.toV6());
                if (!gop.found_existing) gop.value_ptr.* = name;
            }
        }

        // RFC 6761: localhost and its subdomains are loopback, unless configured otherwise.
        const loopback: Addresses = .{ .v4 = &.{.{ 127, 0, 0, 1 }}, .v6 = &.{loopback_v6} };
        if (!zone.exact.contains("localhost")) try zone.exact.put(arena, "localhost", loopback);
        if (!zone.wildcards.contains("localhost")) try zone.wildcards.put(arena, "localhost", loopback);
        for ([_]Ip{ .{ .v4 = .{ 127, 0, 0, 1 } }, .{ .v6 = loopback_v6 } }) |ip| {
            const gop = try zone.reverse.getOrPut(arena, ip.toV6());
            if (!gop.found_existing) gop.value_ptr.* = "localhost";
        }

        for (private_zones) |private_zone| {
            zone.private.add(arena, private_zone, .domain_and_subdomains) catch |err| switch (err) {
                error.OutOfMemory => |e| return e,
                error.SetFull => unreachable, // a few hundred bytes
            };
        }
        return zone;
    }

    pub fn deinit(zone: *LocalZone) void {
        zone.arena.deinit();
        zone.* = undefined;
    }

    /// Addresses for `name`: an exact record, else the most specific wildcard.
    pub fn lookup(zone: *const LocalZone, name: []const u8) ?Addresses {
        if (zone.exact.get(name)) |addresses| return addresses;
        var parent = name;
        while (std.mem.findScalar(u8, parent, '.')) |dot| {
            parent = parent[dot + 1 ..];
            if (zone.wildcards.get(parent)) |addresses| return addresses;
        }
        return null;
    }

    /// The hostname for a reverse lookup name like "10.1.168.192.in-addr.arpa".
    pub fn reverseLookup(zone: *const LocalZone, name: []const u8) ?[]const u8 {
        const ip = parseReverseName(name) orelse return null;
        return zone.reverse.get(ip.toV6());
    }

    /// True for single-label names and names in private or special-use zones.
    pub fn isPrivate(zone: *const LocalZone, name: []const u8) bool {
        if (name.len == 0) return false; // the root
        return std.mem.findScalar(u8, name, '.') == null or zone.private.matches(name);
    }
};

const loopback_v6: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

/// Zones that never resolve on the public internet. Queries for them that the
/// local records do not answer get NXDOMAIN instead of leaking upstream.
pub const private_zones = [_][]const u8{
    // Special-use and private-use names (RFC 6761, RFC 6762 appendix G,
    // RFC 7686, RFC 8375, ICANN's .internal).
    "local",                "lan",             "home",             "internal",
    "intranet",             "private",         "corp",             "localdomain",
    "home.arpa",            "test",            "invalid",          "onion",
    // Reverse zones for private and special-purpose ranges (RFC 6303).
    "0.in-addr.arpa",       "10.in-addr.arpa", "127.in-addr.arpa", "254.169.in-addr.arpa",
    "168.192.in-addr.arpa",
    "d.f.ip6.arpa", "c.f.ip6.arpa", // fc00::/7
    "8.e.f.ip6.arpa", "9.e.f.ip6.arpa", "a.e.f.ip6.arpa", "b.e.f.ip6.arpa", // fe80::/10
    "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", // ::
    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", // ::1
} ++ reverseZones(172, 16, 31) ++ // 172.16.0.0/12
    reverseZones(100, 64, 127); // 100.64.0.0/10 (carrier-grade NAT, Tailscale)

fn reverseZones(comptime first_octet: u8, comptime from: u8, comptime to: u8) [to - from + 1][]const u8 {
    @setEvalBranchQuota(100_000);
    var zones: [to - from + 1][]const u8 = undefined;
    for (&zones, from..) |*zone, second_octet| {
        zone.* = std.fmt.comptimePrint("{d}.{d}.in-addr.arpa", .{ second_octet, first_octet });
    }
    return zones;
}

fn splitFamilies(arena: Allocator, addresses: []const Ip) Allocator.Error!Addresses {
    var v4: std.ArrayList([4]u8) = .empty;
    var v6: std.ArrayList([16]u8) = .empty;
    for (addresses) |ip| switch (ip) {
        .v4 => |b| try v4.append(arena, b),
        .v6 => |b| try v6.append(arena, b),
    };
    return .{ .v4 = v4.items, .v6 = v6.items };
}

/// Parses "4.3.2.1.in-addr.arpa" or a complete 32-nibble ip6.arpa name.
pub fn parseReverseName(name: []const u8) ?Ip {
    const v4_suffix = ".in-addr.arpa";
    const v6_suffix = ".ip6.arpa";
    if (std.mem.endsWith(u8, name, v4_suffix)) {
        var bytes: [4]u8 = undefined;
        var labels = std.mem.splitScalar(u8, name[0 .. name.len - v4_suffix.len], '.');
        for (0..4) |i| {
            bytes[3 - i] = parseOctet(labels.next() orelse return null) orelse return null;
        }
        if (labels.next() != null) return null;
        return .{ .v4 = bytes };
    }
    if (std.mem.endsWith(u8, name, v6_suffix)) {
        const nibbles = name[0 .. name.len - v6_suffix.len];
        if (nibbles.len != 32 * 2 - 1) return null;
        var bytes: [16]u8 = @splat(0);
        for (0..32) |i| {
            if (i != 31 and nibbles[i * 2 + 1] != '.') return null;
            const value = std.fmt.charToDigit(nibbles[i * 2], 16) catch return null;
            // The first label is the lowest nibble of the address.
            const position = 31 - i;
            bytes[position / 2] |= if (position % 2 == 0) value << 4 else value;
        }
        return .{ .v6 = bytes };
    }
    return null;
}

/// A decimal 0-255 without sign, separators or leading zeros.
fn parseOctet(text: []const u8) ?u8 {
    if (text.len == 0 or text.len > 3) return null;
    if (text.len > 1 and text[0] == '0') return null;
    var value: u16 = 0;
    for (text) |c| {
        if (c < '0' or c > '9') return null;
        value = value * 10 + (c - '0');
    }
    return std.math.cast(u8, value);
}

const testing = std.testing;

fn testZone(records: []const Record) !LocalZone {
    return LocalZone.init(testing.allocator, records, 99);
}

test "exact, wildcard and reverse lookups" {
    var zone = try testZone(&.{
        .{ .name = "nas.lan", .wildcard = false, .addresses = &.{ Ip.parse("192.168.1.10").?, Ip.parse("fd00::10").? } },
        .{ .name = "media.lan", .wildcard = false, .addresses = &.{Ip.parse("192.168.1.10").?} },
        .{ .name = "apps.lan", .wildcard = true, .addresses = &.{Ip.parse("192.168.1.20").?} },
        .{ .name = "special.apps.lan", .wildcard = false, .addresses = &.{Ip.parse("192.168.1.30").?} },
    });
    defer zone.deinit();

    const nas = zone.lookup("nas.lan").?;
    try testing.expectEqual(1, nas.v4.len);
    try testing.expectEqual(1, nas.v6.len);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 1, 10 }, &nas.v4[0]);

    try testing.expectEqualSlices(u8, &.{ 192, 168, 1, 20 }, &zone.lookup("grafana.apps.lan").?.v4[0]);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 1, 20 }, &zone.lookup("a.b.apps.lan").?.v4[0]);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 1, 30 }, &zone.lookup("special.apps.lan").?.v4[0]);
    try testing.expectEqual(null, zone.lookup("apps.lan"));
    try testing.expectEqual(null, zone.lookup("other.lan"));

    // The first name configured for an address wins.
    try testing.expectEqualStrings("nas.lan", zone.reverseLookup("10.1.168.192.in-addr.arpa").?);
    try testing.expectEqualStrings("nas.lan", zone.reverseLookup("0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa").?);
    try testing.expectEqual(null, zone.reverseLookup("11.1.168.192.in-addr.arpa"));
}

test "localhost is built in but can be overridden" {
    var zone = try testZone(&.{});
    defer zone.deinit();
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &zone.lookup("localhost").?.v4[0]);
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &zone.lookup("app.localhost").?.v4[0]);
    try testing.expectEqualStrings("localhost", zone.reverseLookup("1.0.0.127.in-addr.arpa").?);

    var custom = try testZone(&.{.{ .name = "localhost", .wildcard = false, .addresses = &.{Ip.parse("127.0.0.2").?} }});
    defer custom.deinit();
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 2 }, &custom.lookup("localhost").?.v4[0]);
}

test "private names" {
    var zone = try testZone(&.{});
    defer zone.deinit();
    try testing.expect(zone.isPrivate("printer"));
    try testing.expect(zone.isPrivate("nas.lan"));
    try testing.expect(zone.isPrivate("router.home.arpa"));
    try testing.expect(zone.isPrivate("1.1.168.192.in-addr.arpa"));
    try testing.expect(zone.isPrivate("1.0.20.172.in-addr.arpa"));
    try testing.expect(zone.isPrivate("1.0.100.100.in-addr.arpa"));
    try testing.expect(!zone.isPrivate("1.0.32.172.in-addr.arpa"));
    try testing.expect(!zone.isPrivate("8.8.8.8.in-addr.arpa"));
    try testing.expect(!zone.isPrivate("example.com"));
    try testing.expect(!zone.isPrivate("planet.com"));
    try testing.expect(!zone.isPrivate(""));
}

test "parseReverseName" {
    try testing.expectEqual(Ip{ .v4 = .{ 192, 168, 1, 10 } }, parseReverseName("10.1.168.192.in-addr.arpa").?);
    try testing.expectEqual(null, parseReverseName("1.168.192.in-addr.arpa"));
    try testing.expectEqual(null, parseReverseName("010.1.168.192.in-addr.arpa"));
    try testing.expectEqual(null, parseReverseName("256.1.168.192.in-addr.arpa"));
    try testing.expectEqual(null, parseReverseName("1.10.1.168.192.in-addr.arpa"));

    const v6 = parseReverseName("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa").?;
    try testing.expectEqual(Ip.parse("2001:db8::1").?, v6);
    try testing.expectEqual(null, parseReverseName("8.b.d.0.1.0.0.2.ip6.arpa"));
}
