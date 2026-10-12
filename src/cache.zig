//! A bounded cache of upstream responses with LRU eviction and TTL expiry.
//!
//! An entry stores the raw response bytes under a key made from the question
//! (name, type) and the client's DNSSEC flags. On a hit the bytes are copied
//! out and adjusted for the new client: its message ID, its spelling of the
//! name, and record TTLs lowered by the time spent in the cache.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const dns = @import("dns.zig");

pub const Cache = struct {
    gpa: Allocator,
    mutex: Io.Mutex = .init,
    map: Map = .empty,
    /// Most recently used entry first.
    lru: std.DoublyLinkedList = .{},
    /// Random per-cache hash seed, so query names cannot be crafted to collide.
    seed: u64,
    /// Maximum number of entries; 0 disables the cache.
    capacity: u32,
    min_ttl: u32,
    max_ttl: u32,

    /// Larger responses are not cached.
    pub const max_response_len = 4096;
    const max_key_len = 3 + dns.max_name_len;

    const Map = std.array_hash_map.Custom([]const u8, *Entry, KeyContext, true);

    const Entry = struct {
        node: std.DoublyLinkedList.Node = .{},
        /// The key followed by the response, in one allocation.
        data: []u8,
        key_len: usize,
        /// Boot-clock seconds.
        stored_at: i64,
        expires_at: i64,

        fn key(entry: *const Entry) []const u8 {
            return entry.data[0..entry.key_len];
        }

        fn response(entry: *const Entry) []const u8 {
            return entry.data[entry.key_len..];
        }
    };

    pub const Options = struct {
        capacity: u32,
        min_ttl: u32,
        max_ttl: u32,
        seed: u64,
    };

    pub fn init(gpa: Allocator, options: Options) Allocator.Error!Cache {
        var cache: Cache = .{
            .gpa = gpa,
            .seed = options.seed,
            .capacity = options.capacity,
            .min_ttl = options.min_ttl,
            .max_ttl = options.max_ttl,
        };
        // Allocate the table once, so inserting never allocates under the lock.
        try cache.map.ensureTotalCapacityContext(gpa, options.capacity, cache.context());
        return cache;
    }

    pub fn deinit(cache: *Cache) void {
        for (cache.map.values()) |entry| cache.destroy(entry);
        cache.map.deinit(cache.gpa);
        cache.* = undefined;
    }

    pub fn count(cache: *Cache, io: Io) usize {
        cache.mutex.lockUncancelable(io);
        defer cache.mutex.unlock(io);
        return cache.map.count();
    }

    /// Copies a cached answer for `q` into `out`, adjusted for this client.
    pub fn lookup(cache: *Cache, io: Io, query: []const u8, q: *const dns.Query, out: []u8) ?[]u8 {
        if (cache.capacity == 0) return null;
        var key_buf: [max_key_len]u8 = undefined;
        const key = makeKey(&key_buf, q);
        const now = nowSeconds(io);

        const response, const age = found: {
            cache.mutex.lockUncancelable(io);
            defer cache.mutex.unlock(io);
            const entry = cache.map.getContext(key, cache.context()) orelse return null;
            if (now >= entry.expires_at) {
                cache.remove(entry);
                return null;
            }
            const cached = entry.response();
            if (cached.len > out.len) return null;
            cache.lru.remove(&entry.node);
            cache.lru.prepend(&entry.node);
            @memcpy(out[0..cached.len], cached);
            break :found .{ out[0..cached.len], now - entry.stored_at };
        };

        dns.setId(response, q.id);
        var flags = dns.readFlags(response);
        flags.rd = q.flags.rd;
        dns.writeFlags(response, flags);
        // Same name (ignoring case), type and class, so the lengths match.
        @memcpy(response[dns.header_len..q.question_end], query[dns.header_len..q.question_end]);
        dns.ageTtls(response, std.math.cast(u32, age) orelse return null) catch return null;
        return response;
    }

    /// Stores a copy of an upstream `response` to `q`, if it is cacheable:
    /// NOERROR or NXDOMAIN, not truncated, and with at least one record that
    /// carries a non-zero TTL (after clamping to `min_ttl`/`max_ttl`).
    pub fn store(cache: *Cache, io: Io, q: *const dns.Query, response: []const u8) void {
        if (cache.capacity == 0 or response.len > max_response_len) return;
        const flags = dns.readFlags(response);
        if (flags.tc or (flags.rcode != .noerror and flags.rcode != .nxdomain)) return;

        var key_buf: [max_key_len]u8 = undefined;
        const key = makeKey(&key_buf, q);
        const data = cache.gpa.alloc(u8, key.len + response.len) catch return;
        @memcpy(data[0..key.len], key);
        const copy = data[key.len..];
        @memcpy(copy, response);

        dns.clampTtls(copy, cache.min_ttl, cache.max_ttl) catch return cache.gpa.free(data);
        const ttl = (dns.minTtl(copy) catch null) orelse return cache.gpa.free(data);
        if (ttl == 0) return cache.gpa.free(data);

        const entry = cache.gpa.create(Entry) catch return cache.gpa.free(data);
        const now = nowSeconds(io);
        entry.* = .{ .data = data, .key_len = key.len, .stored_at = now, .expires_at = now + ttl };

        cache.mutex.lockUncancelable(io);
        defer cache.mutex.unlock(io);
        if (cache.map.getContext(entry.key(), cache.context())) |old| {
            cache.remove(old);
        } else if (cache.map.count() >= cache.capacity) {
            const oldest: *Entry = @alignCast(@fieldParentPtr("node", cache.lru.last.?));
            cache.remove(oldest);
        }
        cache.map.putAssumeCapacityContext(entry.key(), entry, cache.context());
        cache.lru.prepend(&entry.node);
    }

    /// Unlinks and frees an entry. Caller holds the mutex.
    fn remove(cache: *Cache, entry: *Entry) void {
        _ = cache.map.swapRemoveContext(entry.key(), cache.context());
        cache.lru.remove(&entry.node);
        cache.destroy(entry);
    }

    fn destroy(cache: *Cache, entry: *Entry) void {
        cache.gpa.free(entry.data);
        cache.gpa.destroy(entry);
    }

    fn context(cache: *const Cache) KeyContext {
        return .{ .seed = cache.seed };
    }

    const KeyContext = struct {
        seed: u64,

        pub fn hash(ctx: KeyContext, key: []const u8) u32 {
            return @truncate(std.hash.Wyhash.hash(ctx.seed, key));
        }

        pub fn eql(_: KeyContext, a: []const u8, b: []const u8, _: usize) bool {
            return std.mem.eql(u8, a, b);
        }
    };
};

/// Key layout: qtype (2 bytes), flags (1 byte), lowercase name. Responses
/// differ with EDNS (OPT record present), the DO bit and the CD bit, so
/// those are part of the key.
fn makeKey(buf: *[Cache.max_key_len]u8, q: *const dns.Query) []const u8 {
    std.mem.writeInt(u16, buf[0..2], @backingInt(q.qtype), .big);
    const dnssec_ok = if (q.edns) |edns| edns.dnssec_ok else false;
    buf[2] = @as(u8, @intFromBool(q.edns != null)) |
        @as(u8, @intFromBool(dnssec_ok)) << 1 |
        @as(u8, @intFromBool(q.flags.cd)) << 2;
    @memcpy(buf[3..][0..q.name.len], q.name);
    return buf[0 .. 3 + q.name.len];
}

fn nowSeconds(io: Io) i64 {
    return Io.Clock.boot.now(io).toSeconds();
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

const TestMessages = struct {
    query_buf: [512]u8 = undefined,
    response_buf: [512]u8 = undefined,
    name_buf: [dns.max_name_len]u8 = undefined,
    query: []u8 = &.{},
    q: dns.Query = undefined,

    /// A query for `name` and an upstream-style answer with one A record.
    fn init(m: *TestMessages, id: u16, name: []const u8, ttl: u32) ![]u8 {
        var len: usize = 0;
        const header = [_]u8{ @intCast(id >> 8), @truncate(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };
        @memcpy(m.query_buf[0..header.len], &header);
        len = header.len;
        var labels = std.mem.splitScalar(u8, name, '.');
        while (labels.next()) |label| {
            m.query_buf[len] = @intCast(label.len);
            @memcpy(m.query_buf[len + 1 ..][0..label.len], label);
            len += 1 + label.len;
        }
        @memcpy(m.query_buf[len..][0..5], &[_]u8{ 0, 0, 1, 0, 1 });
        len += 5;
        m.query = m.query_buf[0..len];
        m.q = try dns.parseQuery(m.query, &m.name_buf);
        return dns.writeResponse(&m.response_buf, m.query, &m.q, .{ .answers = &.{.{ .a = .{ 1, 2, 3, 4 } }}, .ttl = ttl });
    }
};

test "store and look up, personalized for the client" {
    var cache: Cache = try .init(testing.allocator, .{ .capacity = 4, .min_ttl = 0, .max_ttl = 3600, .seed = 7 });
    defer cache.deinit();
    const io = testing.io;

    var first: TestMessages = .{};
    const response = try first.init(1, "Example.com", 300);
    cache.store(io, &first.q, response);
    try testing.expectEqual(1, cache.count(io));

    var second: TestMessages = .{};
    _ = try second.init(2, "EXAMPLE.COM", 300);
    var out: [512]u8 = undefined;
    const hit = cache.lookup(io, second.query, &second.q, &out).?;
    try testing.expectEqual(2, dns.readId(hit));
    try testing.expectEqualSlices(u8, second.query[dns.header_len..second.q.question_end], hit[dns.header_len..second.q.question_end]);
    try testing.expect(dns.isResponseTo(hit, second.query, second.q.question_end));
    const ttl = (try dns.minTtl(hit)).?;
    try testing.expect(ttl <= 300 and ttl >= 299);

    var other: TestMessages = .{};
    _ = try other.init(3, "other.com", 300);
    try testing.expectEqual(null, cache.lookup(io, other.query, &other.q, &out));
}

test "TTLs are clamped and uncacheable responses are skipped" {
    var cache: Cache = try .init(testing.allocator, .{ .capacity = 4, .min_ttl = 60, .max_ttl = 120, .seed = 7 });
    defer cache.deinit();
    const io = testing.io;
    var out: [512]u8 = undefined;

    var m: TestMessages = .{};
    cache.store(io, &m.q, try m.init(1, "short.example", 5));
    try testing.expectEqual(60, (try dns.minTtl(cache.lookup(io, m.query, &m.q, &out).?)).?);
    cache.store(io, &m.q, try m.init(1, "long.example", 99999));
    try testing.expectEqual(120, (try dns.minTtl(cache.lookup(io, m.query, &m.q, &out).?)).?);

    const servfail = try m.init(1, "fail.example", 300);
    var flags = dns.readFlags(servfail);
    flags.rcode = .servfail;
    dns.writeFlags(servfail, flags);
    cache.store(io, &m.q, servfail);
    try testing.expectEqual(null, cache.lookup(io, m.query, &m.q, &out));
}

test "least recently used entries are evicted first" {
    var cache: Cache = try .init(testing.allocator, .{ .capacity = 2, .min_ttl = 0, .max_ttl = 3600, .seed = 7 });
    defer cache.deinit();
    const io = testing.io;
    var out: [512]u8 = undefined;

    var a: TestMessages = .{};
    var b: TestMessages = .{};
    var c: TestMessages = .{};
    cache.store(io, &a.q, try a.init(1, "a.example", 300));
    cache.store(io, &b.q, try b.init(1, "b.example", 300));
    _ = cache.lookup(io, a.query, &a.q, &out).?; // a is now the most recent
    cache.store(io, &c.q, try c.init(1, "c.example", 300));

    try testing.expectEqual(2, cache.count(io));
    try testing.expect(cache.lookup(io, a.query, &a.q, &out) != null);
    try testing.expect(cache.lookup(io, b.query, &b.q, &out) == null);
    try testing.expect(cache.lookup(io, c.query, &c.q, &out) != null);

    // Storing an existing key replaces it.
    cache.store(io, &c.q, try c.init(1, "c.example", 100));
    try testing.expectEqual(2, cache.count(io));
}

test "a disabled cache stores nothing" {
    var cache: Cache = try .init(testing.allocator, .{ .capacity = 0, .min_ttl = 0, .max_ttl = 3600, .seed = 7 });
    defer cache.deinit();
    var m: TestMessages = .{};
    var out: [512]u8 = undefined;
    cache.store(testing.io, &m.q, try m.init(1, "a.example", 300));
    try testing.expectEqual(null, cache.lookup(testing.io, m.query, &m.q, &out));
}
