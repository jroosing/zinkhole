//! Decides how each query is answered. The pipeline, in order:
//!
//!   1. client not allowed                  -> REFUSED
//!   2. local record, or PTR for one        -> local answer
//!   3. blocked (allow rules win)           -> 0.0.0.0 / :: or NXDOMAIN
//!   4. private or special-use name         -> NXDOMAIN
//!   5. cached answer                       -> cached answer
//!   6. upstream servers                    -> forwarded answer (then cached)
//!
//! Steps 2-4 read the current `ConfigPolicy` and `Lists` under a shared lock. A
//! reload or refresh takes the exclusive lock only to swap a pointer.

const std = @import("std");
const Io = std.Io;
const net = Io.net;

const dns = @import("dns.zig");
const ip = @import("ip.zig");
const local = @import("local.zig");
const Cache = @import("cache.zig").Cache;
const Upstream = @import("upstream.zig").Upstream;
const ConfigPolicy = @import("rules.zig").ConfigPolicy;
const Lists = @import("rules.zig").Lists;

const log = std.log.scoped(.query);

pub const Transport = enum { udp, tcp };

pub const Outcome = enum { local, blocked, private, cached, forwarded, failed, refused, invalid };

/// Firefox enables DNS-over-HTTPS on its own (bypassing this resolver)
/// unless this name fails to resolve.
const firefox_doh_canary = "use-application-dns.net";

pub const Resolver = struct {
    io: Io,
    lock: Io.RwLock = .init,
    policy: *ConfigPolicy,
    lists: *Lists,
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

        policy: {
            r.lock.lockSharedUncancelable(r.io);
            defer r.lock.unlockShared(r.io);
            const policy = r.policy;

            if (policy.local.lookup(q.name)) |addresses| {
                return .{ .local, r.addressAnswer(out, msg, q, addresses, policy.local_ttl, true) };
            }
            if (q.qtype == .ptr) {
                if (policy.local.reverseLookup(q.name)) |host| {
                    return .{ .local, r.respond(out, msg, q, .{ .answers = &.{.{ .ptr = host }}, .ttl = policy.local_ttl, .authoritative = true }) };
                }
            }
            if (std.mem.eql(u8, q.name, firefox_doh_canary)) {
                return .{ .blocked, r.respond(out, msg, q, .{ .rcode = .nxdomain }) };
            }
            if (r.isBlocked(q.name)) {
                const response = switch (policy.block_response) {
                    .nxdomain => r.respond(out, msg, q, .{ .rcode = .nxdomain }),
                    .zero => r.addressAnswer(out, msg, q, .{ .v4 = &.{@splat(0)}, .v6 = &.{@splat(0)} }, policy.block_ttl, false),
                };
                return .{ .blocked, response };
            }
            if (!policy.forward_private and policy.local.isPrivate(q.name)) {
                return .{ .private, r.respond(out, msg, q, .{ .rcode = .nxdomain }) };
            }
            break :policy;
        }

        if (r.cache.lookup(r.io, msg, q, out)) |response| return .{ .cached, response };

        const response = r.upstream.forward(r.io, msg, q, out) catch |err| switch (err) {
            error.Canceled => |e| return e,
            error.AllServersFailed => return .{ .failed, r.respond(out, msg, q, .{ .rcode = .servfail }) },
        };
        r.cache.store(r.io, q, response);
        return .{ .forwarded, response };
    }

    /// Blocked unless an allow rule (inline or from a list) also matches.
    /// Caller holds the lock.
    fn isBlocked(r: *const Resolver, name: []const u8) bool {
        const blocked = r.policy.block.matches(name) or r.lists.block.matches(name);
        return blocked and !(r.policy.allow.matches(name) or r.lists.allow.matches(name));
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

    pub fn swapPolicy(r: *Resolver, policy: *ConfigPolicy) *ConfigPolicy {
        r.lock.lockUncancelable(r.io);
        defer r.lock.unlock(r.io);
        const old = r.policy;
        r.policy = policy;
        return old;
    }

    pub fn swapLists(r: *Resolver, lists: *Lists) *Lists {
        r.lock.lockUncancelable(r.io);
        defer r.lock.unlock(r.io);
        const old = r.lists;
        r.lists = lists;
        return old;
    }

    pub fn listsComplete(r: *Resolver) bool {
        r.lock.lockSharedUncancelable(r.io);
        defer r.lock.unlockShared(r.io);
        return r.lists.complete;
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
