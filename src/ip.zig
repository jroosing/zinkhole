//! IP address helpers: parsing config values, client access control (CIDR)
//! and printing addresses without a port.

const std = @import("std");
const net = std.Io.net;

/// A bare IP address (no port).
pub const Ip = union(enum) {
    v4: [4]u8,
    v6: [16]u8,

    /// Parses a literal IPv4 or IPv6 address.
    pub fn parse(text: []const u8) ?Ip {
        const address = net.IpAddress.parse(text, 0) catch return null;
        return fromAddress(address);
    }

    /// The address of a socket peer. IPv4-mapped IPv6 addresses (seen on
    /// dual-stack sockets) become plain IPv4.
    pub fn fromAddress(address: net.IpAddress) Ip {
        return switch (net.IpAddress.fromIp6(net.Ip6Address.fromAny(address))) {
            .ip4 => |a| .{ .v4 = a.bytes },
            .ip6 => |a| .{ .v6 = a.bytes },
        };
    }

    /// IPv6 form of the address; IPv4 becomes IPv4-mapped (::ffff:a.b.c.d),
    /// so CIDR matching needs only one code path.
    pub fn toV6(ip: Ip) [16]u8 {
        return switch (ip) {
            .v4 => |b| .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff } ++ b,
            .v6 => |b| b,
        };
    }

    pub fn format(ip: Ip, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (ip) {
            .v4 => |b| try w.print("{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] }),
            .v6 => |b| try w.print("{f}", .{net.Ip6Address.Unresolved{ .bytes = b, .interface_name = null }}),
        }
    }
};

/// A network in CIDR notation, e.g. 192.168.0.0/16 or fd00::/8.
pub const Cidr = struct {
    /// Network address in IPv6 form (IPv4 networks are IPv4-mapped).
    bytes: [16]u8,
    /// Prefix length in bits within `bytes` (IPv4 prefixes are offset by 96).
    prefix_len: u8,

    /// Parses "address/prefix" or a single address (a /32 or /128 network).
    pub fn parse(text: []const u8) ?Cidr {
        const slash = std.mem.findScalar(u8, text, '/');
        const ip = Ip.parse(if (slash) |i| text[0..i] else text) orelse return null;
        const max: u8, const offset: u8 = switch (ip) {
            .v4 => .{ 32, 96 },
            .v6 => .{ 128, 0 },
        };
        const prefix_len = if (slash) |i|
            std.fmt.parseInt(u8, text[i + 1 ..], 10) catch return null
        else
            max;
        if (prefix_len > max) return null;
        return .{ .bytes = ip.toV6(), .prefix_len = offset + prefix_len };
    }

    pub fn contains(cidr: Cidr, ip: Ip) bool {
        const bytes = ip.toV6();
        const full = cidr.prefix_len / 8;
        if (!std.mem.eql(u8, cidr.bytes[0..full], bytes[0..full])) return false;
        const rest_bits: u3 = @intCast(cidr.prefix_len % 8);
        if (rest_bits == 0) return true;
        const mask = @as(u8, 0xff) << @intCast(8 - @as(u4, rest_bits));
        return (cidr.bytes[full] & mask) == (bytes[full] & mask);
    }
};

pub fn isAllowed(networks: []const Cidr, address: net.IpAddress) bool {
    const ip = Ip.fromAddress(address);
    for (networks) |network| {
        if (network.contains(ip)) return true;
    }
    return false;
}

/// Parses "1.2.3.4", "1.2.3.4:53", "[2001:db8::1]:53", "[2001:db8::1]" or a
/// bare "2001:db8::1". A missing port means `default_port`.
pub fn parseSocketAddress(text: []const u8, default_port: u16) ?net.IpAddress {
    var address = net.IpAddress.parseLiteral(text) catch
        net.IpAddress.parse(text, default_port) catch return null;
    if (address.getPort() == 0) address.setPort(default_port);
    return address;
}

const testing = std.testing;

test "Cidr.contains" {
    const lan = Cidr.parse("192.168.0.0/16").?;
    try testing.expect(lan.contains(Ip.parse("192.168.1.20").?));
    try testing.expect(!lan.contains(Ip.parse("192.169.0.1").?));
    try testing.expect(!lan.contains(Ip.parse("fd00::1").?));

    const odd = Cidr.parse("172.16.0.0/12").?;
    try testing.expect(odd.contains(Ip.parse("172.31.255.255").?));
    try testing.expect(!odd.contains(Ip.parse("172.32.0.0").?));

    const ula = Cidr.parse("fc00::/7").?;
    try testing.expect(ula.contains(Ip.parse("fd12:3456::1").?));
    try testing.expect(!ula.contains(Ip.parse("fe80::1").?));

    const host = Cidr.parse("10.0.0.1").?;
    try testing.expect(host.contains(Ip.parse("10.0.0.1").?));
    try testing.expect(!host.contains(Ip.parse("10.0.0.2").?));

    const any = Cidr.parse("0.0.0.0/0").?;
    try testing.expect(any.contains(Ip.parse("8.8.8.8").?));
    try testing.expect(!any.contains(Ip.parse("2001:db8::1").?));

    try testing.expectEqual(null, Cidr.parse("10.0.0.0/33"));
    try testing.expectEqual(null, Cidr.parse("fd00::/129"));
    try testing.expectEqual(null, Cidr.parse("nonsense/8"));
}

test "IPv4-mapped peers match IPv4 networks" {
    const lan = [_]Cidr{Cidr.parse("192.168.0.0/16").?};
    const mapped: net.IpAddress = .{ .ip6 = net.Ip6Address.fromIp4(.{ .bytes = .{ 192, 168, 1, 2 }, .port = 5000 }) };
    try testing.expect(isAllowed(&lan, mapped));
    try testing.expect(!isAllowed(&lan, .{ .ip4 = .{ .bytes = .{ 8, 8, 8, 8 }, .port = 53 } }));
}

test "parseSocketAddress" {
    const v4 = parseSocketAddress("9.9.9.9", 53).?;
    try testing.expectEqual(53, v4.getPort());
    try testing.expectEqual(5353, parseSocketAddress("127.0.0.1:5353", 53).?.getPort());
    const v6 = parseSocketAddress("[2620:fe::fe]:853", 53).?;
    try testing.expectEqual(853, v6.getPort());
    try testing.expect(v6 == .ip6);
    try testing.expectEqual(53, parseSocketAddress("2620:fe::fe", 53).?.getPort());
    try testing.expectEqual(53, parseSocketAddress("[::]", 53).?.getPort());
    try testing.expectEqual(null, parseSocketAddress("dns.example.com", 53));
    try testing.expectEqual(null, parseSocketAddress("1.2.3.4:99999", 53));
}

test "format" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("10.0.0.1", try std.fmt.bufPrint(&buf, "{f}", .{Ip.parse("10.0.0.1").?}));
    try testing.expectEqualStrings("fd00::1", try std.fmt.bufPrint(&buf, "{f}", .{Ip.parse("fd00:0::1").?}));
}
