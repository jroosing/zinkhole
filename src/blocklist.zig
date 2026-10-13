//! Blocklist parsing and loading.
//!
//! Each line is recognized on its own, so the common list formats (and lists
//! that mix them) need no configuration:
//!
//!   hosts file     0.0.0.0 ads.example.com tracker.example.com
//!   domain list    ads.example.com
//!   wildcards      *.example.com                (subdomains only)
//!   Adblock        ||ads.example.com^           (@@||...^ exceptions allow)
//!   dnsmasq        address=/ads.example.com/0.0.0.0, local=/x/, server=/x/
//!
//! Comments (`#`, `!`), Adblock headers and rules without DNS meaning
//! (cosmetic filters, URL paths, regular expressions, unknown `$` modifiers)
//! are skipped. A listed domain matches itself and all of its subdomains.
//!
//! Lists are streamed line by line, never loaded into memory as a whole.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const dns = @import("dns.zig");
const DomainSet = @import("domain_set.zig").DomainSet;
const Ip = @import("ip.zig").Ip;

const log = std.log.scoped(.lists);

/// Longest line considered; longer lines are skipped.
pub const max_line_len = 4096;

pub const Rule = struct {
    /// Normalized domain name.
    name: []const u8,
    match: DomainSet.Match,
    /// An Adblock exception (`@@||example.com^`): allow instead of block.
    exception: bool = false,
};

pub const Stats = struct {
    lines: usize = 0,
    rules: usize = 0,
    skipped: usize = 0,
};

/// Collects parsed rules into the block and allow sets.
pub const Sink = struct {
    gpa: Allocator,
    block: *DomainSet,
    allow: *DomainSet,
    /// In an allowlist source every rule allows, whatever its syntax.
    is_allowlist: bool,
    stats: Stats = .{},

    pub const Error = error{ OutOfMemory, SetFull };

    pub fn add(sink: *Sink, rule: Rule) Error!void {
        const target = if (sink.is_allowlist or rule.exception) sink.allow else sink.block;
        try target.add(sink.gpa, rule.name, rule.match);
        sink.stats.rules += 1;
    }

    pub fn skip(sink: *Sink) void {
        sink.stats.skipped += 1;
    }
};

/// Parses one line of a list in any supported format and passes the rules it
/// contains to `sink` (anything with `add(Rule) !void` and `skip() void`).
pub fn parseLine(raw: []const u8, sink: anytype) !void {
    const line = std.mem.trim(u8, stripComment(raw), " \t\r");
    if (line.len == 0) return;
    switch (line[0]) {
        '!', '[' => return, // Adblock comments and "[Adblock Plus 2.0]" headers
        else => {},
    }
    if (std.mem.startsWith(u8, line, "@@||")) return parseAdblock(line[4..], true, sink);
    if (std.mem.startsWith(u8, line, "||")) return parseAdblock(line[2..], false, sink);
    if (std.mem.startsWith(u8, line, "address=/") or
        std.mem.startsWith(u8, line, "local=/") or
        std.mem.startsWith(u8, line, "server=/"))
    {
        return parseDnsmasq(line, sink);
    }

    var fields = std.mem.tokenizeAny(u8, line, " \t");
    const first = fields.next() orelse return;
    if (Ip.parse(first) != null) {
        // hosts file: "<address> <name> [<name>...]"
        while (fields.next()) |host| try addHostsEntry(host, sink);
        return;
    }
    if (fields.next() != null) return sink.skip(); // not a format we know
    try addDomain(first, sink);
}

/// Removes a `#` comment. Only a `#` at the start or after whitespace starts a
/// comment, so cosmetic filters like `example.com##.ad` stay intact (and are
/// then rejected as invalid names rather than blocking example.com).
fn stripComment(line: []const u8) []const u8 {
    for (line, 0..) |c, i| {
        if (c == '#' and (i == 0 or line[i - 1] == ' ' or line[i - 1] == '\t')) return line[0..i];
    }
    return line;
}

/// Adblock rule body after `||`: `example.com^`, optionally followed by `|`
/// and `$important`. Other modifiers change the meaning, so those rules are
/// skipped rather than guessed at.
fn parseAdblock(body: []const u8, exception: bool, sink: anytype) !void {
    const end = std.mem.findAny(u8, body, "^|$/") orelse body.len;
    var tail = body[end..];
    if (std.mem.startsWith(u8, tail, "^")) tail = tail[1..];
    if (std.mem.startsWith(u8, tail, "|")) tail = tail[1..];
    if (tail.len != 0 and !std.mem.eql(u8, tail, "$important")) return sink.skip();

    var domain = body[0..end];
    var match: DomainSet.Match = .domain_and_subdomains;
    if (std.mem.startsWith(u8, domain, "*.")) {
        domain = domain[2..];
        match = .subdomains_only;
    }
    var buf: [dns.max_name_len]u8 = undefined;
    const name = dns.normalizeName(domain, &buf) orelse return sink.skip();
    try sink.add(.{ .name = name, .match = match, .exception = exception });
}

/// dnsmasq rules: `address=/a.com/b.com/<target>` blocks when the target is a
/// sinkhole address or empty; `local=/a.com/` and `server=/a.com/` (no
/// upstream server) mean "answer locally", which also blocks. Rules that
/// redirect or forward elsewhere are skipped.
fn parseDnsmasq(line: []const u8, sink: anytype) !void {
    const eq = std.mem.findScalar(u8, line, '=').?;
    const spec = line[eq + 1 ..]; // "/a.com/b.com/<target>"
    const last_slash = std.mem.findScalarLast(u8, spec, '/').?;
    if (last_slash == 0) return sink.skip();

    const target = spec[last_slash + 1 ..];
    const blocks = if (std.mem.eql(u8, line[0..eq], "address")) isSinkhole(target) else target.len == 0;
    if (!blocks) return sink.skip();

    var domains = std.mem.tokenizeScalar(u8, spec[1..last_slash], '/');
    while (domains.next()) |domain| {
        var buf: [dns.max_name_len]u8 = undefined;
        const name = dns.normalizeName(domain, &buf) orelse {
            sink.skip();
            continue;
        };
        try sink.add(.{ .name = name, .match = .domain_and_subdomains });
    }
}

fn isSinkhole(target: []const u8) bool {
    const sinkholes = [_][]const u8{ "", "#", "0.0.0.0", "::", "127.0.0.1", "::1" };
    for (sinkholes) |s| {
        if (std.mem.eql(u8, target, s)) return true;
    }
    return false;
}

/// A name from a hosts file line. Hosts files also map local names
/// ("127.0.0.1 localhost"); single-label names, address-like names and the
/// usual local aliases are never blocked.
fn addHostsEntry(host: []const u8, sink: anytype) !void {
    var buf: [dns.max_name_len]u8 = undefined;
    const name = dns.normalizeName(host, &buf) orelse return sink.skip();
    if (std.mem.findScalar(u8, name, '.') == null or
        Ip.parse(name) != null or
        std.mem.eql(u8, name, "localhost.localdomain"))
    {
        return sink.skip();
    }
    try sink.add(.{ .name = name, .match = .domain_and_subdomains });
}

/// A plain domain, or `*.domain` for subdomains only.
fn addDomain(token: []const u8, sink: anytype) !void {
    var buf: [dns.max_name_len]u8 = undefined;
    if (std.mem.startsWith(u8, token, "*.")) {
        const name = dns.normalizeName(token[2..], &buf) orelse return sink.skip();
        return sink.add(.{ .name = name, .match = .subdomains_only });
    }
    const name = dns.normalizeName(token, &buf) orelse return sink.skip();
    try sink.add(.{ .name = name, .match = .domain_and_subdomains });
}

// ---------------------------------------------------------------------------
// Loading list sources

pub fn isUrl(source: []const u8) bool {
    return std.mem.startsWith(u8, source, "https://") or std.mem.startsWith(u8, source, "http://");
}

/// Streams one list (an http(s) URL or a file path) into `sink`. At most
/// `max_bytes` of (decompressed) data are accepted.
pub fn load(io: Io, gpa: Allocator, client: *std.http.Client, source: []const u8, sink: *Sink, max_bytes: u64) !void {
    if (isUrl(source)) return loadUrl(gpa, client, source, sink, max_bytes);
    return loadFile(io, source, sink, max_bytes);
}

fn loadFile(io: Io, path: []const u8, sink: *Sink, max_bytes: u64) !void {
    const file = try Io.Dir.cwd().openFile(io, path, .{ .allow_directory = false });
    defer file.close(io);
    var buffer: [16 * 1024]u8 = undefined;
    var file_reader = file.reader(io, &buffer);
    consume(&file_reader.interface, sink, max_bytes) catch |err| switch (err) {
        error.ReadFailed => return file_reader.err orelse error.ReadFailed,
        else => |e| return e,
    };
}

fn loadUrl(gpa: Allocator, client: *std.http.Client, url: []const u8, sink: *Sink, max_bytes: u64) !void {
    const uri = std.Uri.parse(url) catch return error.InvalidUrl;
    var request = try client.request(.GET, uri, .{
        .keep_alive = false,
        .headers = .{ .user_agent = .{ .override = "zinkhole" } },
    });
    defer request.deinit();
    try request.sendBodiless();

    var redirect_buffer: [8 * 1024]u8 = undefined;
    var response = try request.receiveHead(&redirect_buffer);
    // `request.uri` is where the redirects (if any) ended up.
    try refuseDowngrade(url, request.uri);
    if (response.head.status != .ok) {
        log.warn("{s}: HTTP status {d}", .{ url, @backingInt(response.head.status) });
        return error.HttpError;
    }

    // Only gzip and deflate are offered by the client; refuse anything else.
    const window: []u8 = switch (response.head.content_encoding) {
        .identity => &.{},
        .gzip, .deflate => try gpa.alloc(u8, std.compress.flate.max_window_len),
        else => return error.UnsupportedEncoding,
    };
    defer gpa.free(window);

    var transfer_buffer: [16 * 1024]u8 = undefined;
    var decompress: std.http.Decompress = undefined;
    const body = response.readerDecompressing(&transfer_buffer, &decompress, window);
    consume(body, sink, max_bytes) catch |err| switch (err) {
        error.ReadFailed => return response.bodyErr() orelse error.ReadFailed,
        else => |e| return e,
    };
}

/// A list configured as https:// must not arrive over plain http after a
/// redirect: on the way, anyone could rewrite its rules.
fn refuseDowngrade(source: []const u8, final: std.Uri) error{InsecureRedirect}!void {
    const was_https = std.mem.startsWith(u8, source, "https://");
    if (was_https and !std.ascii.eqlIgnoreCase(final.scheme, "https")) return error.InsecureRedirect;
}

/// Feeds everything `reader` produces to the line parser.
fn consume(reader: *Io.Reader, sink: anytype, max_bytes: u64) !void {
    var splitter: LineSplitter = .{};
    var total: u64 = 0;
    while (true) {
        const chunk = reader.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => break,
            error.ReadFailed => return error.ReadFailed,
        };
        total += chunk.len;
        if (total > max_bytes) return error.ListTooLarge;
        try splitter.feed(chunk, sink);
        reader.toss(chunk.len);
    }
    try splitter.finish(sink);
}

/// Splits a stream of chunks into lines. Complete lines inside a chunk are
/// parsed in place; only lines that straddle chunks are copied.
const LineSplitter = struct {
    partial: [max_line_len]u8 = undefined,
    partial_len: usize = 0,
    /// The current line exceeded `max_line_len` and is being skipped.
    overflow: bool = false,
    first_line: bool = true,

    fn feed(ls: *LineSplitter, data: []const u8, sink: anytype) !void {
        var rest = data;
        while (std.mem.findScalar(u8, rest, '\n')) |nl| {
            if (ls.partial_len == 0 and !ls.overflow) {
                try ls.line(rest[0..nl], sink);
            } else {
                ls.append(rest[0..nl]);
                try ls.line(ls.partial[0..ls.partial_len], sink);
            }
            ls.partial_len = 0;
            ls.overflow = false;
            rest = rest[nl + 1 ..];
        }
        ls.append(rest);
    }

    fn finish(ls: *LineSplitter, sink: anytype) !void {
        if (ls.partial_len > 0 or ls.overflow) try ls.line(ls.partial[0..ls.partial_len], sink);
    }

    fn append(ls: *LineSplitter, bytes: []const u8) void {
        if (ls.overflow) return;
        if (ls.partial.len - ls.partial_len < bytes.len) {
            ls.overflow = true;
            return;
        }
        @memcpy(ls.partial[ls.partial_len..][0..bytes.len], bytes);
        ls.partial_len += bytes.len;
    }

    fn line(ls: *LineSplitter, text: []const u8, sink: anytype) !void {
        sink.stats.lines += 1;
        defer ls.first_line = false;
        if (ls.overflow or text.len > max_line_len) return sink.skip();
        const without_bom = if (ls.first_line and std.mem.startsWith(u8, text, "\xEF\xBB\xBF")) text[3..] else text;
        try parseLine(without_bom, sink);
    }
};

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

const TestSink = struct {
    rules: std.ArrayList([]const u8) = .empty,
    stats: Stats = .{},

    fn add(sink: *TestSink, rule: Rule) !void {
        const prefix = if (rule.exception) "allow " else if (rule.match.exact) "" else "*.";
        try sink.rules.append(testing.allocator, try std.fmt.allocPrint(testing.allocator, "{s}{s}", .{ prefix, rule.name }));
    }

    fn skip(sink: *TestSink) void {
        sink.stats.skipped += 1;
    }

    fn deinit(sink: *TestSink) void {
        for (sink.rules.items) |r| testing.allocator.free(r);
        sink.rules.deinit(testing.allocator);
    }
};

fn expectRules(input: []const u8, expected: []const []const u8) !void {
    var sink: TestSink = .{};
    defer sink.deinit();
    var lines = std.mem.splitScalar(u8, input, '\n');
    while (lines.next()) |line| try parseLine(line, &sink);
    try testing.expectEqual(expected.len, sink.rules.items.len);
    for (expected, sink.rules.items) |want, got| try testing.expectEqualStrings(want, got);
}

test "hosts files" {
    try expectRules(
        \\# StevenBlack-style header
        \\127.0.0.1 localhost
        \\127.0.0.1 localhost.localdomain
        \\255.255.255.255 broadcasthost
        \\::1 localhost ip6-localhost
        \\fe80::1%lo0 localhost
        \\0.0.0.0 0.0.0.0
        \\0.0.0.0 Ads.Example.com # inline comment
        \\:: v6.example.com
    ++ "\n0.0.0.0\ttab.example.com\tsecond.example.com", &.{ "ads.example.com", "v6.example.com", "tab.example.com", "second.example.com" });
}

test "domain lists and wildcards" {
    try expectRules(
        \\ads.example.com
        \\  spaced.example.com
        \\*.wild.example.com
        \\trailing.dot.com.
        \\not a domain
        \\bad_chars!.com
        \\example.com##.cosmetic-filter
    , &.{ "ads.example.com", "spaced.example.com", "*.wild.example.com", "trailing.dot.com" });
}

test "adblock syntax" {
    try expectRules(
        \\[Adblock Plus 2.0]
        \\! Title: test list
        \\||ads.example.com^
        \\||plain.example.com
        \\||important.example.com^$important
        \\||terminated.example.com^|
        \\@@||allowed.example.com^
        \\||*.sub.example.com^
        \\||third.example.com^$third-party
        \\||path.example.com/ads.js
        \\||glob*.example.com^
        \\/regex[0-9]+\.com/
        \\|https://example.com/banner
    , &.{
        "ads.example.com",        "plain.example.com",         "important.example.com",
        "terminated.example.com", "allow allowed.example.com", "*.sub.example.com",
    });
}

test "dnsmasq syntax" {
    try expectRules(
        \\address=/ads.example.com/0.0.0.0
        \\address=/a.example.com/b.example.com/
        \\address=/nx.example.com/#
        \\local=/local.example.com/
        \\server=/blocked.example.com/
        \\server=/forwarded.example.com/192.168.1.1
        \\address=/redirect.example.com/192.168.1.5
        \\address=/#/
    , &.{ "ads.example.com", "a.example.com", "b.example.com", "nx.example.com", "local.example.com", "blocked.example.com" });
}

test "streaming splits lines across chunks and skips overlong lines" {
    var sink: TestSink = .{};
    defer sink.deinit();
    var splitter: LineSplitter = .{};
    try splitter.feed("\xEF\xBB\xBFfirst.example.com\nsec", &sink);
    try splitter.feed("ond.example.com\r\n", &sink);
    const long: [max_line_len + 10]u8 = @splat('a');
    try splitter.feed(&long, &sink);
    try splitter.feed("\nthird.example.com", &sink);
    try splitter.finish(&sink);

    try testing.expectEqual(3, sink.rules.items.len);
    try testing.expectEqualStrings("first.example.com", sink.rules.items[0]);
    try testing.expectEqualStrings("second.example.com", sink.rules.items[1]);
    try testing.expectEqualStrings("third.example.com", sink.rules.items[2]);
    try testing.expectEqual(4, sink.stats.lines);
    try testing.expectEqual(1, sink.stats.skipped);
}

test "consume enforces the size limit" {
    var sink: TestSink = .{};
    defer sink.deinit();
    var reader: Io.Reader = .fixed("a.example.com\nb.example.com\n");
    try testing.expectError(error.ListTooLarge, consume(&reader, &sink, 10));
}

test "sink routes exceptions and allowlists" {
    var block: DomainSet = .init(1);
    defer block.deinit(testing.allocator);
    var allow: DomainSet = .init(2);
    defer allow.deinit(testing.allocator);

    var blocklist: Sink = .{ .gpa = testing.allocator, .block = &block, .allow = &allow, .is_allowlist = false };
    try parseLine("||ads.example.com^", &blocklist);
    try parseLine("@@||good.ads.example.com^", &blocklist);
    var allowlist: Sink = .{ .gpa = testing.allocator, .block = &block, .allow = &allow, .is_allowlist = true };
    try parseLine("0.0.0.0 fine.example.com", &allowlist);

    try testing.expect(block.matches("x.ads.example.com"));
    try testing.expect(allow.matches("good.ads.example.com"));
    try testing.expect(allow.matches("fine.example.com"));
    try testing.expectEqual(1, block.count());
    try testing.expectEqual(2, allow.count());
}

test "random lines never break the parser" {
    var prng: std.Random.DefaultPrng = .init(7);
    const random = prng.random();
    const alphabet = "ab.-_*|^$@/=#! \t0:1";
    var block: DomainSet = .init(1);
    defer block.deinit(testing.allocator);
    var allow: DomainSet = .init(2);
    defer allow.deinit(testing.allocator);
    var sink: Sink = .{ .gpa = testing.allocator, .block = &block, .allow = &allow, .is_allowlist = false };
    var buf: [300]u8 = undefined;
    for (0..50_000) |_| {
        const len = random.uintLessThan(usize, buf.len);
        for (buf[0..len]) |*c| c.* = alphabet[random.uintLessThan(usize, alphabet.len)];
        try parseLine(buf[0..len], &sink);
    }
    try testing.expect(sink.stats.rules + sink.stats.skipped > 0);
}

test "a list fetched over https is never accepted from a redirect to http" {
    const https = "https://lists.example/ads.txt";
    try testing.expectError(error.InsecureRedirect, refuseDowngrade(https, try std.Uri.parse("http://lists.example/ads.txt")));
    try refuseDowngrade(https, try std.Uri.parse("https://cdn.example/ads.txt"));
    // A configured http:// list is already warned about; upgrades are fine.
    try refuseDowngrade("http://lists.example/ads.txt", try std.Uri.parse("http://cdn.example/ads.txt"));
    try refuseDowngrade("http://lists.example/ads.txt", try std.Uri.parse("https://lists.example/ads.txt"));
}
