//! Decides how each query is answered. The pipeline, in order:
//!
//!   1. client not allowed                  -> REFUSED
//!   2. local record, or PTR for one        -> local answer
//!   3. blocked (allow rules win)           -> 0.0.0.0 / :: or NXDOMAIN
//!   4. forwarded zone                      -> as 6-7, with the zone's server
//!   5. private or special-use name         -> NXDOMAIN
//!   6. cached answer                       -> cached answer
//!   7. upstream servers                    -> forwarded answer (then cached),
//!                                             or a stale cached one if none answers
//!
//! Steps 2-5 are the `Policy`'s decision; this module turns it into a response.

const std = @import("std");
const Io = std.Io;
const net = Io.net;

const dns = @import("dns.zig");
const ip = @import("ip.zig");
const local = @import("local.zig");
const Cache = @import("cache.zig").Cache;
const Upstream = @import("upstream.zig").Upstream;
const Policy = @import("policy.zig").Policy;
const Metrics = @import("metrics.zig").Metrics;

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
    /// Counts each Outcome per hour, if set.
    metrics: ?*Metrics = null,

    /// What `answerLocally` did with a query.
    pub const Answer = union(enum) {
        /// Not a query: send nothing.
        drop,
        /// The response, a slice of `out`.
        response: []u8,
        /// A cache miss: `forward` answers the same message.
        upstream,
    };

    /// Answers one query, from start to finish. Returns the response (a slice
    /// of `out`), or null if the message is not a query and must be dropped.
    pub fn handle(r: *Resolver, msg: []u8, out: []u8, client: net.IpAddress, transport: Transport) Io.Cancelable!?[]u8 {
        const arrived = r.arrival();
        return switch (r.answerLocally(msg, out, client, transport, arrived)) {
            .drop => null,
            .response => |response| response,
            .upstream => try r.forward(msg, out, client, transport, arrived),
        };
    }

    /// When a query arrived, for the query log; null while it is off.
    pub fn arrival(r: *Resolver) ?Io.Clock.Timestamp {
        return if (r.log_queries.load(.monotonic)) Io.Clock.Timestamp.now(r.io, .awake) else null;
    }

    /// Answers everything that needs no upstream server, which is all but
    /// cache misses. Never waits for the network.
    pub fn answerLocally(r: *Resolver, msg: []u8, out: []u8, client: net.IpAddress, transport: Transport, arrived: ?Io.Clock.Timestamp) Answer {
        var name_buf: [dns.max_name_len]u8 = undefined;
        const q = dns.parseQuery(msg, &name_buf) catch |err| {
            r.countOutcome(.invalid);
            const response = switch (err) {
                error.NotQuery => null,
                error.NotImplemented => dns.writeHeaderOnly(out, msg, .notimp),
                error.FormatError => dns.writeHeaderOnly(out, msg, .formerr),
                error.Refused => dns.writeHeaderOnly(out, msg, .refused),
            };
            return if (response) |bytes| .{ .response = bytes } else .drop;
        };
        const outcome, const response = r.resolveLocally(msg, out, &q, client) orelse return .upstream;
        return .{ .response = r.finish(msg, out, &q, client, transport, outcome, response, arrived) };
    }

    /// Answers `msg`, for which `answerLocally` returned `.upstream`, from
    /// the upstream servers. Rewrites `msg` (see `Upstream.forward`). Null
    /// only if `msg` is no longer the query `answerLocally` saw.
    pub fn forward(r: *Resolver, msg: []u8, out: []u8, client: net.IpAddress, transport: Transport, arrived: ?Io.Clock.Timestamp) Io.Cancelable!?[]u8 {
        var name_buf: [dns.max_name_len]u8 = undefined;
        // `answerLocally` parsed the same bytes, so this cannot fail; if it
        // does anyway, the query is dropped rather than trusted.
        const q = dns.parseQuery(msg, &name_buf) catch return null;
        const outcome, const response = try r.resolveUpstream(msg, out, &q);
        return r.finish(msg, out, &q, client, transport, outcome, response, arrived);
    }

    /// Answers SERVFAIL for `msg`, for which `answerLocally` returned
    /// `.upstream`, when there is no room to ask an upstream server. Null
    /// only if `msg` is no longer the query `answerLocally` saw.
    pub fn failUpstream(r: *Resolver, msg: []u8, out: []u8, client: net.IpAddress, transport: Transport, arrived: ?Io.Clock.Timestamp) ?[]u8 {
        var name_buf: [dns.max_name_len]u8 = undefined;
        const q = dns.parseQuery(msg, &name_buf) catch return null;
        return r.finish(msg, out, &q, client, transport, .failed, r.respond(out, msg, &q, .{ .rcode = .servfail }), arrived);
    }

    /// Truncates for UDP clients, counts the Outcome and logs the query.
    fn finish(r: *Resolver, msg: []const u8, out: []u8, q: *const dns.Query, client: net.IpAddress, transport: Transport, outcome: Outcome, answer: []u8, arrived: ?Io.Clock.Timestamp) []u8 {
        var response = answer;
        if (transport == .udp and response.len > q.maxUdpSize()) {
            // Too large for this client over UDP: send just the header with
            // TC set, and the client retries over TCP.
            response = r.respond(out, msg, q, .{ .rcode = dns.readFlags(response).rcode, .truncated = true });
        }

        r.countOutcome(outcome);
        if (arrived) |started| {
            const micros: u64 = @intCast(@max(0, started.untilNow(r.io).raw.toMicroseconds()));
            log.info("{f} {f} {f} {t} {d}.{d}ms", .{
                ip.Ip.fromAddress(client),
                dns.printable(q.name),
                q.qtype,
                outcome,
                micros / 1000,
                micros % 1000 / 100,
            });
        }
        return response;
    }

    fn countOutcome(r: *Resolver, outcome: Outcome) void {
        r.stats.count(outcome);
        if (r.metrics) |metrics| metrics.countQuery(outcome, Io.Clock.real.now(r.io).toSeconds());
    }

    /// Null when only an upstream server can answer.
    fn resolveLocally(r: *Resolver, msg: []const u8, out: []u8, q: *const dns.Query, client: net.IpAddress) ?struct { Outcome, []u8 } {
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
            .blocked => |blocked| return .{ .blocked, r.blockedAnswer(out, msg, q, blocked) },
            .private => |private| return .{ .private, r.respond(out, msg, q, .{ .rcode = .nxdomain, .negative_ttl = private.ttl }) },
            .upstream, .forward => {},
        }

        if (r.cache.lookup(r.io, msg, q, out)) |response| return r.aliasChecked(out, msg, q, .cached, response);
        return null;
    }

    fn resolveUpstream(r: *Resolver, msg: []u8, out: []u8, q: *const dns.Query) Io.Cancelable!struct { Outcome, []u8 } {
        // Decided again rather than handed along: the server of a forwarded
        // zone, as the current Policy says.
        const sent = switch (r.policy.decide(q.name, q.qtype)) {
            .forward => |zone| r.upstream.forwardTo(r.io, zone.server, msg, q, out),
            else => r.upstream.forward(r.io, msg, q, out),
        };
        const response = sent catch |err| switch (err) {
            error.Canceled => |e| return e,
            error.AllServersFailed => {
                // `forward` kept the ID and question that `lookupStale` reads.
                if (r.cache.lookupStale(r.io, msg, q, out)) |stale| return r.aliasChecked(out, msg, q, .cached, stale);
                return .{ .failed, r.respond(out, msg, q, .{ .rcode = .servfail }) };
            },
        };
        // Cached as it came: the aliases are checked again on every hit, so
        // a reload that changes the rules applies at once.
        r.cache.store(r.io, q, response);
        return r.aliasChecked(out, msg, q, .forwarded, response);
    }

    /// `response` (in `out`), unless one of its CNAME records makes the
    /// queried name an alias of a blocked name: then the block response.
    fn aliasChecked(r: *Resolver, out: []u8, msg: []const u8, q: *const dns.Query, outcome: Outcome, response: []u8) struct { Outcome, []u8 } {
        var records: dns.RecordIterator = .init(response, q.question_end);
        while (records.next() catch null) |record| {
            if (record.section != .answer or record.type != .cname) continue;
            var target_buf: [dns.max_name_len]u8 = undefined;
            const target = dns.readName(response, record.rdata_offset, &target_buf) catch continue;
            // `target` is a copy, so the block response may overwrite `out`.
            if (r.policy.blockAlias(q.name, target)) |blocked| return .{ .blocked, r.blockedAnswer(out, msg, q, blocked) };
        }
        return .{ outcome, response };
    }

    fn blockedAnswer(r: *Resolver, out: []u8, msg: []const u8, q: *const dns.Query, blocked: Policy.Decision.Blocked) []u8 {
        return switch (blocked.response) {
            .nxdomain => r.respond(out, msg, q, .{ .rcode = .nxdomain, .negative_ttl = blocked.ttl }),
            .zero => r.addressAnswer(out, msg, q, .{ .v4 = &.{@splat(0)}, .v6 = &.{@splat(0)} }, blocked.ttl, false),
        };
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
        return r.respond(out, msg, q, .{ .answers = answers[0..count], .ttl = ttl, .authoritative = authoritative, .negative_ttl = ttl });
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

    const Options = struct {
        serve_stale_s: u32 = 0,
        upstream: []const @import("upstream.zig").ServerAddress = &.{},
    };

    fn init(t: *TestResolver, source: []const u8) !void {
        return t.initWith(source, .{});
    }

    fn initWith(t: *TestResolver, source: []const u8, options: Options) !void {
        var buf: [4096]u8 = undefined;
        const full = try std.fmt.bufPrint(&buf, "upstream:\n  servers: [9.9.9.9]\n{s}", .{source});
        var diag: config_mod.Diagnostic = .{};
        t.config = try config_mod.parse(testing.allocator, full, &diag);
        errdefer t.config.deinit();
        t.policy = try .init(testing.io, testing.allocator, &t.config);
        errdefer t.policy.deinit();
        t.cache = try .init(testing.allocator, .{ .capacity = 16, .min_ttl = 0, .max_ttl = 3600, .seed = 1, .serve_stale_s = options.serve_stale_s });
        errdefer t.cache.deinit();
        try t.upstream.init(testing.io, testing.allocator, options.upstream, 500);
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
        return t.records(response, .answer, buf);
    }

    /// The records of one section, as (type, ttl, rdata).
    fn records(t: *const TestResolver, response: []const u8, section: dns.Section, buf: []TestAnswer) ![]TestAnswer {
        var records_it: dns.RecordIterator = .init(response, t.question_end);
        var count: usize = 0;
        while (try records_it.next()) |record| {
            if (record.section != section) continue;
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

/// The SOA in the authority section of `response`, which must be the only
/// record there: its TTL and its MINIMUM field (the negative TTL).
fn expectSoa(t: *const TestResolver, response: []const u8, ttl: u32) !void {
    var buf: [4]TestAnswer = undefined;
    const authority = try t.records(response, .authority, &buf);
    try testing.expectEqual(1, authority.len);
    try testing.expectEqual(.soa, authority[0].type);
    try testing.expectEqual(ttl, authority[0].ttl);
    const data = authority[0].data;
    try testing.expectEqual(ttl, std.mem.readInt(u32, data[data.len - 4 ..][0..4], .big));
}

test "negative answers carry an SOA, so clients can cache them for the TTL" {
    var t: TestResolver = undefined;
    try t.init(
        \\blocking:
        \\  ttl: 30
        \\  block: [ads.example.com]
        \\local:
        \\  ttl: 120
        \\  records:
        \\    nas.lan: 192.168.1.10
    );
    defer t.deinit();
    var buf: [4]TestAnswer = undefined;

    // An empty answer for a blocked name, and for a local name.
    try expectSoa(&t, try t.ask("ads.example.com", .https), 30);
    try expectSoa(&t, try t.ask("nas.lan", .aaaa), 120);
    // NXDOMAIN for a private name.
    const private = try t.ask("printer", .a);
    try testing.expectEqual(.nxdomain, dns.readFlags(private).rcode);
    try expectSoa(&t, private, 120);

    // Answers with records need none.
    try testing.expectEqual(0, (try t.records(try t.ask("nas.lan", .a), .authority, &buf)).len);
    try testing.expectEqual(0, (try t.records(try t.ask("ads.example.com", .a), .authority, &buf)).len);
}

test "an NXDOMAIN block carries an SOA with the block TTL" {
    var t: TestResolver = undefined;
    try t.init(
        \\blocking:
        \\  ttl: 45
        \\  response: nxdomain
        \\  block: [ads.example.com]
    );
    defer t.deinit();
    const response = try t.ask("ads.example.com", .a);
    try testing.expectEqual(.nxdomain, dns.readFlags(response).rcode);
    try expectSoa(&t, response, 45);
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

test "with metrics, every query's Outcome is counted in the current hour" {
    var t: TestResolver = undefined;
    try t.init("blocking:\n  block: [ads.example.com]\n");
    defer t.deinit();
    var metrics: Metrics = try .init(testing.io, testing.allocator, .{ .zone = .{}, .started = 0 });
    defer metrics.deinit();
    t.resolver.metrics = &metrics;

    _ = try t.ask("ads.example.com", .a);
    _ = try t.ask("printer", .a);
    var malformed = [_]u8{ 0x12, 0x34, 0x01, 0x00, 0, 1 };
    _ = try t.resolver.handle(&malformed, &t.out, ip.parseSocketAddress("127.0.0.1", 5353).?, .udp);

    const today = metrics.queries(.today, Io.Clock.real.now(testing.io).toSeconds());
    try testing.expectEqual(1, today.get(.blocked));
    try testing.expectEqual(1, today.get(.private));
    try testing.expectEqual(1, today.get(.invalid));
}

/// Caches an upstream-style answer for `name`: one A record with `ttl`.
fn cacheAnswer(t: *TestResolver, name: []const u8, ttl: u32) !void {
    var query_buf: [512]u8 = undefined;
    var name_buf: [dns.max_name_len]u8 = undefined;
    const query = dns.testQuery(&query_buf, 1, name, .a, null);
    const q = try dns.parseQuery(query, &name_buf);
    var response_buf: [512]u8 = undefined;
    t.cache.store(testing.io, &q, try dns.writeResponse(&response_buf, query, &q, .{ .answers = &.{.{ .a = .{ 1, 2, 3, 4 } }}, .ttl = ttl }));
}

test "when no upstream server answers, an expired cached answer is served with TTL 30" {
    var t: TestResolver = undefined;
    try t.initWith("", .{ .serve_stale_s = 3600 });
    defer t.deinit();
    try cacheAnswer(&t, "example.com", 1);
    try testing.io.sleep(.fromMilliseconds(1100), .awake); // expired

    const response = try t.ask("example.com", .a);
    try testing.expectEqual(.noerror, dns.readFlags(response).rcode);
    var buf: [4]TestAnswer = undefined;
    const answers = try t.answers(response, &buf);
    try testing.expectEqual(1, answers.len);
    try testing.expectEqual(30, answers[0].ttl);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, answers[0].data);
    try testing.expectEqual(1, t.resolver.stats.get(.cached));
    try testing.expectEqual(0, t.resolver.stats.get(.failed));
}

test "with serving stale answers off, an expired cached answer is not served" {
    var t: TestResolver = undefined;
    try t.initWith("", .{});
    defer t.deinit();
    try cacheAnswer(&t, "example.com", 1);
    try testing.io.sleep(.fromMilliseconds(1100), .awake);

    try testing.expectEqual(.servfail, dns.readFlags(try t.ask("example.com", .a)).rcode);
}

test "a name in a forwarded zone is answered by the zone's server, then from the cache" {
    var router: @import("upstream.zig").Stub = undefined;
    try router.start(.answer);
    defer router.stop();
    var source_buf: [128]u8 = undefined;
    const source = try std.fmt.bufPrint(&source_buf, "local:\n  forward:\n    lan: \"{f}\"\n", .{router.address()});
    var t: TestResolver = undefined;
    try t.init(source); // and no upstream servers
    defer t.deinit();

    const response = try t.ask("printer.lan", .a);
    try testing.expectEqual(.noerror, dns.readFlags(response).rcode);
    var buf: [4]TestAnswer = undefined;
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, (try t.answers(response, &buf))[0].data);
    try testing.expectEqual(1, t.resolver.stats.get(.forwarded));
    try testing.expectEqual(1, router.received.load(.acquire));

    _ = try t.ask("printer.lan", .a);
    try testing.expectEqual(1, t.resolver.stats.get(.cached));
    try testing.expectEqual(1, router.received.load(.acquire));
}

test "an answer whose CNAME points at a blocked name is blocked, also from the cache" {
    var upstream: @import("upstream.zig").Stub = undefined;
    try upstream.start(.alias);
    defer upstream.stop();
    var t: TestResolver = undefined;
    try t.initWith(
        \\blocking:
        \\  ttl: 30
        \\  block: [example.net]
    , .{ .upstream = &.{.{ .address = upstream.address() }} });
    defer t.deinit();
    var buf: [4]TestAnswer = undefined;

    for (0..2) |_| {
        const response = try t.ask("metrics.shop.example", .a);
        const answers = try t.answers(response, &buf);
        try testing.expectEqual(1, answers.len);
        try testing.expectEqual(30, answers[0].ttl);
        try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, answers[0].data);
    }
    try testing.expectEqual(2, t.resolver.stats.get(.blocked));
    try testing.expectEqual(1, upstream.received.load(.acquire)); // the second from the cache
}

test "an allow rule for the queried name wins over a blocked CNAME" {
    var upstream: @import("upstream.zig").Stub = undefined;
    try upstream.start(.alias);
    defer upstream.stop();
    var t: TestResolver = undefined;
    try t.initWith(
        \\blocking:
        \\  block: [example.net]
        \\  allow: [metrics.shop.example]
    , .{ .upstream = &.{.{ .address = upstream.address() }} });
    defer t.deinit();

    const response = try t.ask("metrics.shop.example", .a);
    var buf: [4]TestAnswer = undefined;
    try testing.expectEqual(2, (try t.answers(response, &buf)).len);
    try testing.expectEqual(1, t.resolver.stats.get(.forwarded));
}

test "a name left to the upstream servers fails with SERVFAIL when none answers" {
    var t: TestResolver = undefined;
    try t.init("");
    defer t.deinit();

    const response = try t.ask("example.com", .a);
    try testing.expectEqual(.servfail, dns.readFlags(response).rcode);
    try testing.expectEqual(1, t.resolver.stats.get(.failed));
}
