//! Decides how each query is answered. The pipeline, in order:
//!
//!   1. client not allowed                  -> REFUSED
//!   2. local record, or PTR for one        -> local answer
//!   3. blocked (allow rules win)           -> 0.0.0.0 / :: or NXDOMAIN
//!   4. private or special-use name         -> NXDOMAIN
//!   5. cached answer                       -> cached answer
//!   6. upstream servers                    -> forwarded answer (then cached)
//!
//! Steps 2-4 are the `Policy`'s decision; this module turns it into a response.

const std = @import("std");
const Io = std.Io;
const net = Io.net;

const dns = @import("dns.zig");
const ip = @import("ip.zig");
const local = @import("local.zig");
const Cache = @import("cache.zig").Cache;
const Upstream = @import("upstream.zig").Upstream;
const Policy = @import("policy.zig").Policy;

const log = std.log.scoped(.query);

pub const Transport = enum { udp, tcp };

pub const Outcome = enum { local, blocked, private, cached, forwarded, failed, refused, invalid };

pub const Resolver = struct {
    io: Io,
    policy: *Policy,
    cache: *Cache,
    upstream: *Upstream,
    allow_clients: []const ip.Cidr,
    log_queries: std.atomic.Value(bool),
    stats: Stats = .{},

    /// Answers one query. Returns the response (a slice of `out`), or null if
    /// the message is not a query and must be dropped.
    pub fn handle(r: *Resolver, msg: []u8, out: []u8, client: net.IpAddress, transport: Transport) Io.Cancelable!?[]u8 {
        var name_buf: [dns.max_name_len]u8 = undefined;
        const q = dns.parseQuery(msg, &name_buf) catch |err| {
            r.stats.count(.invalid);
            return switch (err) {
                error.NotQuery => null,
                error.NotImplemented => dns.writeHeaderOnly(out, msg, .notimp),
                error.FormatError => dns.writeHeaderOnly(out, msg, .formerr),
                error.Refused => dns.writeHeaderOnly(out, msg, .refused),
            };
        };

        const log_query = r.log_queries.load(.monotonic);
        const started = if (log_query) Io.Clock.Timestamp.now(r.io, .awake) else undefined;

        const outcome, var response = try r.resolve(msg, out, &q, client);
        if (transport == .udp and response.len > q.maxUdpSize()) {
            // Too large for this client over UDP: send just the header with
            // TC set, and the client retries over TCP.
            response = r.respond(out, msg, &q, .{ .rcode = dns.readFlags(response).rcode, .truncated = true });
        }

        r.stats.count(outcome);
        if (log_query) {
            const micros: u64 = @intCast(@max(0, started.untilNow(r.io).raw.toMicroseconds()));
            log.info("{f} {s} {f} {t} {d}.{d}ms", .{
                ip.Ip.fromAddress(client),
                if (q.name.len == 0) "." else q.name,
                q.qtype,
                outcome,
                micros / 1000,
                micros % 1000 / 100,
            });
        }
        return response;
    }

    fn resolve(r: *Resolver, msg: []u8, out: []u8, q: *const dns.Query, client: net.IpAddress) Io.Cancelable!struct { Outcome, []u8 } {
        if (!ip.isAllowed(r.allow_clients, client)) {
            return .{ .refused, r.respond(out, msg, q, .{ .rcode = .refused }) };
        }
        if (q.qclass != dns.class_in or q.qtype == .axfr or q.qtype == .ixfr) {
            return .{ .refused, r.respond(out, msg, q, .{ .rcode = .refused }) };
        }

        const decision = r.policy.decide(q.name, q.qtype);
        switch (decision) {
            .local => |*answer| {
                const addresses: local.Addresses = .{ .v4 = answer.addresses.v4(), .v6 = answer.addresses.v6() };
                return .{ .local, r.addressAnswer(out, msg, q, addresses, answer.ttl, true) };
            },
            .reverse => |*answer| {
                return .{ .local, r.respond(out, msg, q, .{ .answers = &.{.{ .ptr = answer.host() }}, .ttl = answer.ttl, .authoritative = true }) };
            },
            .blocked => |blocked| {
                const response = switch (blocked.response) {
                    .nxdomain => r.respond(out, msg, q, .{ .rcode = .nxdomain }),
                    .zero => r.addressAnswer(out, msg, q, .{ .v4 = &.{@splat(0)}, .v6 = &.{@splat(0)} }, blocked.ttl, false),
                };
                return .{ .blocked, response };
            },
            .private => return .{ .private, r.respond(out, msg, q, .{ .rcode = .nxdomain }) },
            .upstream => {},
        }

        if (r.cache.lookup(r.io, msg, q, out)) |response| return .{ .cached, response };

        const response = r.upstream.forward(r.io, msg, q, out) catch |err| switch (err) {
            error.Canceled => |e| return e,
            error.AllServersFailed => return .{ .failed, r.respond(out, msg, q, .{ .rcode = .servfail }) },
        };
        r.cache.store(r.io, q, response);
        return .{ .forwarded, response };
    }

    /// A/AAAA records of `addresses` that match the question type; other
    /// types get an empty answer (NODATA).
    fn addressAnswer(r: *Resolver, out: []u8, msg: []const u8, q: *const dns.Query, addresses: local.Addresses, ttl: u32, authoritative: bool) []u8 {
        var answers: [local.max_addresses]dns.Answer = undefined;
        var count: usize = 0;
        if (q.qtype == .a or q.qtype == .any) {
            for (addresses.v4) |address| {
                answers[count] = .{ .a = address };
                count += 1;
            }
        }
        if (q.qtype == .aaaa or q.qtype == .any) {
            for (addresses.v6) |address| {
                answers[count] = .{ .aaaa = address };
                count += 1;
            }
        }
        return r.respond(out, msg, q, .{ .answers = answers[0..count], .ttl = ttl, .authoritative = authoritative });
    }

    fn respond(_: *Resolver, out: []u8, msg: []const u8, q: *const dns.Query, options: dns.ResponseOptions) []u8 {
        return dns.writeResponse(out, msg, q, options) catch
            // Cannot happen with a full-size buffer; fail safe anyway.
            dns.writeHeaderOnly(out, msg, .servfail).?;
    }
};

pub const Stats = struct {
    /// Word-sized, because 32-bit targets (e.g. ARMv7) lack 64-bit atomics.
    counters: std.EnumArray(Outcome, std.atomic.Value(usize)) = .initFill(.init(0)),

    fn count(stats: *Stats, outcome: Outcome) void {
        _ = stats.counters.getPtr(outcome).fetchAdd(1, .monotonic);
    }

    pub fn get(stats: *Stats, outcome: Outcome) usize {
        return stats.counters.getPtr(outcome).load(.monotonic);
    }

    pub fn write(stats: *Stats, w: *std.Io.Writer) std.Io.Writer.Error!void {
        var total: usize = 0;
        for (std.enums.values(Outcome)) |outcome| total +%= stats.get(outcome);
        try w.print("{d} queries", .{total});
        for (std.enums.values(Outcome)) |outcome| try w.print(", {t} {d}", .{ outcome, stats.get(outcome) });
    }
};

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;
const config_mod = @import("config.zig");

/// A resolver with a Policy built from config text, a real cache and no
/// upstream servers, so nothing leaves the process.
const TestResolver = struct {
    config: config_mod.Config,
    policy: Policy,
    cache: Cache,
    upstream: Upstream,
    resolver: Resolver,
    query_buf: [512]u8 = undefined,
    out: [dns.max_message_len]u8 = undefined,
    /// Where the last response's records start.
    question_end: usize = 0,

    fn init(t: *TestResolver, source: []const u8) !void {
        var buf: [4096]u8 = undefined;
        const full = try std.fmt.bufPrint(&buf, "upstream:\n  servers: [9.9.9.9]\n{s}", .{source});
        var diag: config_mod.Diagnostic = .{};
        t.config = try config_mod.parse(testing.allocator, full, &diag);
        errdefer t.config.deinit();
        t.policy = try .init(testing.io, testing.allocator, &t.config);
        errdefer t.policy.deinit();
        t.cache = try .init(testing.allocator, .{ .capacity = 16, .min_ttl = 0, .max_ttl = 3600, .seed = 1 });
        errdefer t.cache.deinit();
        try t.upstream.init(testing.io, testing.allocator, &.{}, 100);
        t.resolver = .{
            .io = testing.io,
            .policy = &t.policy,
            .cache = &t.cache,
            .upstream = &t.upstream,
            .allow_clients = t.config.server.allow_clients,
            .log_queries = .init(false),
        };
    }

    fn deinit(t: *TestResolver) void {
        t.upstream.deinit();
        t.cache.deinit();
        t.policy.deinit();
        t.config.deinit();
    }

    /// Asks over UDP from 127.0.0.1, without EDNS.
    fn ask(t: *TestResolver, name: []const u8, qtype: dns.Type) ![]u8 {
        return t.askFrom("127.0.0.1", name, qtype, .udp);
    }

    fn askFrom(t: *TestResolver, client: []const u8, name: []const u8, qtype: dns.Type, transport: Transport) ![]u8 {
        const query = dns.testQuery(&t.query_buf, 0x1234, name, qtype, null);
        t.question_end = query.len;
        const address = ip.parseSocketAddress(client, 5353).?;
        return (try t.resolver.handle(query, &t.out, address, transport)).?;
    }

    /// The answer section's records, as (type, ttl, rdata).
    fn answers(t: *const TestResolver, response: []const u8, buf: []TestAnswer) ![]TestAnswer {
        var records: dns.RecordIterator = .init(response, t.question_end);
        var count: usize = 0;
        while (try records.next()) |record| {
            if (record.section != .answer) continue;
            buf[count] = .{ .type = record.type, .ttl = record.ttl, .data = response[record.rdata_offset..][0..record.rdata_len] };
            count += 1;
        }
        return buf[0..count];
    }
};

const TestAnswer = struct { type: dns.Type, ttl: u32, data: []const u8 };

test "a blocked name gets zero addresses for A and AAAA, an empty answer otherwise" {
    var t: TestResolver = undefined;
    try t.init(
        \\blocking:
        \\  ttl: 30
        \\  block: [ads.example.com]
    );
    defer t.deinit();
    var buf: [4]TestAnswer = undefined;

    const a = try t.ask("ads.example.com", .a);
    try testing.expectEqual(.noerror, dns.readFlags(a).rcode);
    try testing.expect(!dns.readFlags(a).aa);
    const a_answers = try t.answers(a, &buf);
    try testing.expectEqual(1, a_answers.len);
    try testing.expectEqual(30, a_answers[0].ttl);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, a_answers[0].data);

    const aaaa = try t.ask("ads.example.com", .aaaa);
    try testing.expectEqualSlices(u8, &@as([16]u8, @splat(0)), (try t.answers(aaaa, &buf))[0].data);

    // No way around the block through other record types.
    const https = try t.ask("ads.example.com", .https);
    try testing.expectEqual(.noerror, dns.readFlags(https).rcode);
    try testing.expectEqual(0, (try t.answers(https, &buf)).len);
}

test "local records are answered authoritatively, PTR queries with the hostname" {
    var t: TestResolver = undefined;
    try t.init(
        \\local:
        \\  records:
        \\    nas.lan: 192.168.1.10
    );
    defer t.deinit();
    var buf: [4]TestAnswer = undefined;

    const a = try t.ask("nas.lan", .a);
    try testing.expect(dns.readFlags(a).aa);
    const a_answers = try t.answers(a, &buf);
    try testing.expectEqual(1, a_answers.len);
    try testing.expectEqual(300, a_answers[0].ttl);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 1, 10 }, a_answers[0].data);

    // The name exists, but has no record of this type.
    const mx = try t.ask("nas.lan", .mx);
    try testing.expectEqual(.noerror, dns.readFlags(mx).rcode);
    try testing.expectEqual(0, (try t.answers(mx, &buf)).len);

    const ptr = try t.ask("10.1.168.192.in-addr.arpa", .ptr);
    try testing.expect(dns.readFlags(ptr).aa);
    try testing.expectEqualSlices(u8, "\x03nas\x03lan\x00", (try t.answers(ptr, &buf))[0].data);
}

test "private names, the Firefox canary and nxdomain blocking answer NXDOMAIN" {
    var t: TestResolver = undefined;
    try t.init(
        \\blocking:
        \\  response: nxdomain
        \\  block: [ads.example.com]
    );
    defer t.deinit();

    for ([_][]const u8{ "printer", "nas.lan", "use-application-dns.net", "ads.example.com" }) |name| {
        const response = try t.ask(name, .a);
        try testing.expectEqual(.nxdomain, dns.readFlags(response).rcode);
        try testing.expectEqual(0, dns.readU16(response, 6)); // no answers
    }
}

test "clients outside the allowed networks and zone transfers are refused" {
    var t: TestResolver = undefined;
    try t.init(
        \\local:
        \\  records:
        \\    nas.lan: 192.168.1.10
    );
    defer t.deinit();

    const outsider = try t.askFrom("203.0.113.7", "nas.lan", .a, .udp);
    try testing.expectEqual(.refused, dns.readFlags(outsider).rcode);
    try testing.expectEqual(0, dns.readU16(outsider, 6));

    const axfr = try t.askFrom("127.0.0.1", "lan", .axfr, .tcp);
    try testing.expectEqual(.refused, dns.readFlags(axfr).rcode);
}

fn label(comptime c: u8) [60]u8 {
    return @splat(c);
}

test "an answer too large for UDP is truncated, and complete over TCP" {
    // A long name with 16 IPv6 addresses: about 660 bytes, over the 512 a
    // client without EDNS accepts.
    const name = label('a') ++ "." ++ label('b') ++ "." ++ label('c') ++ ".lan";
    var t: TestResolver = undefined;
    try t.init("local:\n  records:\n    " ++ name ++ ": [" ++
        "\"fd00::1\", \"fd00::2\", \"fd00::3\", \"fd00::4\", \"fd00::5\", \"fd00::6\", \"fd00::7\", \"fd00::8\", " ++
        "\"fd00::9\", \"fd00::a\", \"fd00::b\", \"fd00::c\", \"fd00::d\", \"fd00::e\", \"fd00::f\", \"fd00::10\"]");
    defer t.deinit();

    const udp = try t.askFrom("127.0.0.1", name, .aaaa, .udp);
    try testing.expect(dns.readFlags(udp).tc);
    try testing.expectEqual(0, dns.readU16(udp, 6));
    try testing.expect(udp.len <= dns.min_udp_payload);

    const tcp = try t.askFrom("127.0.0.1", name, .aaaa, .tcp);
    try testing.expect(!dns.readFlags(tcp).tc);
    try testing.expectEqual(16, dns.readU16(tcp, 6));
}

test "a name left to the upstream servers fails with SERVFAIL when none answers" {
    var t: TestResolver = undefined;
    try t.init("");
    defer t.deinit();

    const response = try t.ask("example.com", .a);
    try testing.expectEqual(.servfail, dns.readFlags(response).rcode);
    try testing.expectEqual(1, t.resolver.stats.get(.failed));
}
