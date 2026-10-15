//! DNS wire format (RFC 1035, RFC 6891): only what a forwarding blocker needs.
//!
//! Everything works on caller-provided byte slices and never allocates. Every
//! length field read from a message is bounds-checked before use; malformed
//! input produces an error, never an out-of-bounds access.

const std = @import("std");
const assert = std.debug.assert;

pub const header_len = 12;
/// Longest domain name in text form (no trailing dot).
pub const max_name_len = 253;
/// Largest DNS message; TCP framing uses a 16-bit length.
pub const max_message_len = 65535;
/// UDP payload limit for clients that do not use EDNS(0).
pub const min_udp_payload = 512;
/// EDNS(0) UDP payload size advertised by this server and used upstream.
/// 1232 avoids IP fragmentation (DNS Flag Day 2020).
pub const edns_payload_size = 1232;

pub const class_in: u16 = 1;

pub const Type = enum(u16) {
    a = 1,
    ns = 2,
    cname = 5,
    soa = 6,
    ptr = 12,
    mx = 15,
    txt = 16,
    aaaa = 28,
    srv = 33,
    opt = 41,
    ds = 43,
    rrsig = 46,
    dnskey = 48,
    svcb = 64,
    https = 65,
    ixfr = 251,
    axfr = 252,
    any = 255,
    _,

    /// Prints the mnemonic, or `TYPE<n>` (RFC 3597) for unnamed types.
    pub fn format(t: Type, w: *std.Io.Writer) std.Io.Writer.Error!void {
        inline for (@typeInfo(Type).@"enum".field_names) |name| {
            if (t == @field(Type, name)) {
                const upper = comptime upper: {
                    var buf: [name.len]u8 = undefined;
                    _ = std.ascii.upperString(&buf, name);
                    break :upper buf;
                };
                return w.writeAll(&upper);
            }
        }
        return w.print("TYPE{d}", .{@backingInt(t)});
    }
};

pub const Rcode = enum(u4) {
    noerror = 0,
    formerr = 1,
    servfail = 2,
    nxdomain = 3,
    notimp = 4,
    refused = 5,
    _,
};

/// The 16-bit flags word of the header. Fields are listed from the least
/// significant bit, matching the wire layout once read as a big-endian u16;
/// convert with `@backingInt` / `@fromBackingInt`.
pub const Flags = packed struct(u16) {
    rcode: Rcode,
    cd: bool,
    ad: bool,
    z: bool,
    ra: bool,
    rd: bool,
    tc: bool,
    aa: bool,
    opcode: u4,
    qr: bool,
};

/// EDNS(0) information from a query's OPT record.
pub const Edns = struct {
    udp_size: u16,
    dnssec_ok: bool,
    /// Offset of the OPT record's CLASS field, which holds the UDP size.
    udp_size_offset: usize,
};

/// A parsed query. Only single-question queries are accepted, which is what
/// every real client sends.
pub const Query = struct {
    id: u16,
    flags: Flags,
    /// Question name in lowercase dotted form without trailing dot; empty for
    /// the root. Points into the buffer passed to `parseQuery`.
    name: []const u8,
    qtype: Type,
    qclass: u16,
    /// Offset just past the question section.
    question_end: usize,
    edns: ?Edns,

    /// Largest response this client accepts over UDP.
    pub fn maxUdpSize(q: *const Query) usize {
        const edns = q.edns orelse return min_udp_payload;
        return @max(min_udp_payload, edns.udp_size);
    }
};

pub const QueryError = error{
    /// Too short or a response (QR set): drop silently.
    NotQuery,
    /// An opcode other than QUERY.
    NotImplemented,
    /// Malformed message.
    FormatError,
    /// A label contains a '.', which has no unambiguous text form.
    Refused,
};

pub fn parseQuery(msg: []const u8, name_buf: *[max_name_len]u8) QueryError!Query {
    if (msg.len < header_len) return error.NotQuery;
    const flags = readFlags(msg);
    if (flags.qr) return error.NotQuery;
    if (flags.opcode != 0) return error.NotImplemented;
    if (readU16(msg, 4) != 1) return error.FormatError;

    const name_len, var pos = try readQuestionName(msg, header_len, name_buf);
    if (msg.len - pos < 4) return error.FormatError;
    const qtype: Type = @fromBackingInt(readU16(msg, pos));
    const qclass = readU16(msg, pos + 2);
    pos += 4;

    // Queries normally carry no answer or authority records; skip them anyway
    // and look for the OPT record in the additional section.
    var edns: ?Edns = null;
    var records: RecordIterator = .init(msg, pos);
    while (records.next() catch return error.FormatError) |record| {
        if (record.type != .opt) continue;
        if (record.section != .additional or edns != null) return error.FormatError;
        edns = .{
            .udp_size = record.class,
            .dnssec_ok = record.ttl & 0x8000 != 0,
            .udp_size_offset = record.class_offset,
        };
    }

    return .{
        .id = readU16(msg, 0),
        .flags = flags,
        .name = name_buf[0..name_len],
        .qtype = qtype,
        .qclass = qclass,
        .question_end = pos,
        .edns = edns,
    };
}

/// Reads the uncompressed question name at `start` into `out` as lowercase
/// dotted text. Returns the text length and the offset just past the name.
fn readQuestionName(msg: []const u8, start: usize, out: *[max_name_len]u8) QueryError!struct { usize, usize } {
    var pos = start;
    var text_len: usize = 0;
    // Wire bytes consumed so far, excluding the terminating zero. The whole
    // name including that zero may not exceed 255 bytes (RFC 1035 3.1).
    var wire_len: usize = 0;
    while (true) {
        if (pos >= msg.len) return error.FormatError;
        const label_len = msg[pos];
        pos += 1;
        if (label_len == 0) break;
        // Compression pointers (0xC0) and extended label types are invalid in
        // a question: there is nothing earlier in the message to point to.
        if (label_len > 63) return error.FormatError;
        if (msg.len - pos < label_len) return error.FormatError;
        wire_len += 1 + label_len;
        if (wire_len > 254) return error.FormatError;

        if (text_len != 0) {
            out[text_len] = '.';
            text_len += 1;
        }
        for (msg[pos..][0..label_len]) |c| {
            if (c == '.') return error.Refused;
            out[text_len] = std.ascii.toLower(c);
            text_len += 1;
        }
        pos += label_len;
    }
    return .{ text_len, pos };
}

pub const Section = enum { answer, authority, additional };

pub const Record = struct {
    type: Type,
    class: u16,
    ttl: u32,
    section: Section,
    class_offset: usize,
    ttl_offset: usize,
    rdata_offset: usize,
    rdata_len: u16,
};

pub const MalformedError = error{Malformed};

/// Iterates the resource records that follow the question section.
pub const RecordIterator = struct {
    msg: []const u8,
    pos: usize,
    /// Records left in the answer, authority and additional sections.
    remaining: [3]u16,
    section: usize = 0,

    pub fn init(msg: []const u8, question_end: usize) RecordIterator {
        return .{
            .msg = msg,
            .pos = question_end,
            .remaining = .{ readU16(msg, 6), readU16(msg, 8), readU16(msg, 10) },
        };
    }

    pub fn next(it: *RecordIterator) MalformedError!?Record {
        while (it.section < 3 and it.remaining[it.section] == 0) it.section += 1;
        if (it.section == 3) return null;
        it.remaining[it.section] -= 1;

        const fields = try skipName(it.msg, it.pos);
        if (it.msg.len - fields < 10) return error.Malformed;
        const rdata_len = readU16(it.msg, fields + 8);
        const rdata = fields + 10;
        if (it.msg.len - rdata < rdata_len) return error.Malformed;
        it.pos = rdata + rdata_len;

        return .{
            .type = @fromBackingInt(readU16(it.msg, fields)),
            .class = readU16(it.msg, fields + 2),
            .ttl = readU32(it.msg, fields + 4),
            .section = @fromBackingInt(@intCast(it.section)),
            .class_offset = fields + 2,
            .ttl_offset = fields + 4,
            .rdata_offset = rdata,
            .rdata_len = rdata_len,
        };
    }
};

/// Returns the offset just past a possibly compressed name starting at `pos`.
fn skipName(msg: []const u8, start: usize) MalformedError!usize {
    var pos = start;
    while (true) {
        if (pos >= msg.len) return error.Malformed;
        const len = msg[pos];
        switch (len >> 6) {
            0b00 => {
                if (len == 0) return pos + 1;
                pos += 1 + len;
            },
            // A compression pointer always ends the name.
            0b11 => {
                if (msg.len - pos < 2) return error.Malformed;
                return pos + 2;
            },
            else => return error.Malformed,
        }
    }
}

/// Reads the possibly compressed name at `start` into `out` as lowercase
/// dotted text. Each compression pointer must point before everything read
/// so far, so pointers only ever move backwards and cannot loop.
pub fn readName(msg: []const u8, start: usize, out: *[max_name_len]u8) MalformedError![]const u8 {
    var pos = start;
    var text_len: usize = 0;
    // As in `readQuestionName`: at most 255 bytes including the root.
    var wire_len: usize = 0;
    var earliest = start;
    while (true) {
        if (pos >= msg.len) return error.Malformed;
        const len = msg[pos];
        switch (len >> 6) {
            0b00 => {
                if (len == 0) return out[0..text_len];
                if (msg.len - pos - 1 < len) return error.Malformed;
                wire_len += 1 + len;
                if (wire_len > 254) return error.Malformed;
                if (text_len != 0) {
                    out[text_len] = '.';
                    text_len += 1;
                }
                for (msg[pos + 1 ..][0..len]) |c| {
                    out[text_len] = std.ascii.toLower(c);
                    text_len += 1;
                }
                pos += 1 + len;
            },
            0b11 => {
                if (msg.len - pos < 2) return error.Malformed;
                const target = readU16(msg, pos) & 0x3FFF;
                if (target >= earliest) return error.Malformed;
                earliest = target;
                pos = target;
            },
            else => return error.Malformed,
        }
    }
}

/// Offset just past the question section of a single-question message.
fn questionEnd(msg: []const u8) MalformedError!usize {
    if (msg.len < header_len or readU16(msg, 4) != 1) return error.Malformed;
    const end = try skipName(msg, header_len);
    if (msg.len - end < 4) return error.Malformed;
    return end + 4;
}

// ---------------------------------------------------------------------------
// Inspecting and patching responses

/// True if `response` answers `query`: same ID, QR set, opcode QUERY and the
/// same single question. Anything else (spoofed or stray packets) is ignored.
pub fn isResponseTo(response: []const u8, query: []const u8, question_end: usize) bool {
    if (response.len < question_end) return false;
    if (readU16(response, 0) != readU16(query, 0)) return false;
    const flags = readFlags(response);
    if (!flags.qr or flags.opcode != 0) return false;
    if (readU16(response, 4) != 1) return false;
    // Names compare case-insensitively (label length bytes are < 64 and thus
    // unaffected); type and class must match exactly.
    const name_end = question_end - 4;
    if (!std.ascii.eqlIgnoreCase(response[header_len..name_end], query[header_len..name_end])) return false;
    return std.mem.eql(u8, response[name_end..question_end], query[name_end..question_end]);
}

/// Smallest TTL over all records except OPT, or null if there are none. An
/// SOA in the authority section (a negative answer) also counts with its
/// MINIMUM field, which caps how long the answer may be cached (RFC 2308).
pub fn minTtl(msg: []const u8) MalformedError!?u32 {
    var min: ?u32 = null;
    var records: RecordIterator = .init(msg, try questionEnd(msg));
    while (try records.next()) |record| {
        if (record.type == .opt) continue;
        min = @min(min orelse record.ttl, record.ttl);
        // MINIMUM is the last field, after two names of at least one byte.
        if (record.type == .soa and record.section == .authority and record.rdata_len >= 22) {
            min = @min(min.?, readU32(msg, record.rdata_offset + record.rdata_len - 4));
        }
    }
    return min;
}

/// Clamps the TTL of every record except OPT into `[lo, hi]`, and the
/// MINIMUM of an SOA in the authority section, which is a negative answer's
/// TTL too (see `minTtl`).
pub fn clampTtls(msg: []u8, lo: u32, hi: u32) MalformedError!void {
    assert(lo <= hi);
    var records: RecordIterator = .init(msg, try questionEnd(msg));
    while (try records.next()) |record| {
        if (record.type == .opt) continue;
        writeU32(msg, record.ttl_offset, std.math.clamp(record.ttl, lo, hi));
        if (record.type == .soa and record.section == .authority and record.rdata_len >= 22) {
            const minimum = record.rdata_offset + record.rdata_len - 4;
            writeU32(msg, minimum, std.math.clamp(readU32(msg, minimum), lo, hi));
        }
    }
}

/// Lowers the TTL of every record except OPT by `elapsed` seconds.
pub fn ageTtls(msg: []u8, elapsed: u32) MalformedError!void {
    var records: RecordIterator = .init(msg, try questionEnd(msg));
    while (try records.next()) |record| {
        if (record.type == .opt) continue;
        writeU32(msg, record.ttl_offset, record.ttl -| elapsed);
    }
}

/// A query in the form sent to upstream servers (see `rewriteForUpstream`).
pub const UpstreamQuery = struct {
    bytes: []u8,
    /// Offset just past the question section.
    question_end: usize,

    /// True if `response` answers this query (see `isResponseTo`).
    pub fn isAnswer(query: UpstreamQuery, response: []const u8) bool {
        return isResponseTo(response, query.bytes, query.question_end);
    }
};

/// Rewrites a parsed query in place into the form sent upstream: header and
/// question stay, other records are dropped, and the client's OPT record is
/// replaced by a fresh one with no options and our UDP payload size. Client
/// cookies, client subnet and other EDNS options never reach upstream
/// servers, and the answers are safe to share between clients via the cache.
pub fn rewriteForUpstream(msg: []u8, q: *const Query) UpstreamQuery {
    var flags = q.flags; // keeps RD, CD and AD
    flags.aa = false;
    flags.tc = false;
    flags.ra = false;
    flags.z = false;
    flags.rcode = .noerror;
    writeFlags(msg, flags);
    writeU16(msg, 6, 0);
    writeU16(msg, 8, 0);
    writeU16(msg, 10, 0);
    var b: Builder = .{ .buf = msg, .len = q.question_end };
    if (q.edns) |edns| {
        // The client's OPT record took at least as much space, so this fits.
        if (b.opt(edns.dnssec_ok)) writeU16(msg, 10, 1) else |_| {}
    }
    return .{ .bytes = msg[0..b.len], .question_end = q.question_end };
}

pub fn readId(msg: []const u8) u16 {
    return readU16(msg, 0);
}

pub fn setId(msg: []u8, id: u16) void {
    writeU16(msg, 0, id);
}

pub fn readFlags(msg: []const u8) Flags {
    return @fromBackingInt(readU16(msg, 2));
}

pub fn writeFlags(msg: []u8, flags: Flags) void {
    writeU16(msg, 2, @backingInt(flags));
}

// ---------------------------------------------------------------------------
// Building responses

pub const Answer = union(enum) {
    a: [4]u8,
    aaaa: [16]u8,
    /// Target name in dotted form, for PTR records.
    ptr: []const u8,
    /// Target name in dotted form, for CNAME records.
    cname: []const u8,
};

pub const ResponseOptions = struct {
    rcode: Rcode = .noerror,
    authoritative: bool = false,
    truncated: bool = false,
    answers: []const Answer = &.{},
    ttl: u32 = 0,
    /// For an NXDOMAIN or an empty answer: adds an SOA record, so clients
    /// cache the negative answer for this long (RFC 2308).
    negative_ttl: ?u32 = null,
};

/// The made-up zone of the SOA in negative answers (`.invalid`, RFC 6761).
const soa_mname = "zinkhole.invalid";
const soa_rname = "hostmaster.zinkhole.invalid";

pub const BuildError = error{NoSpaceLeft};

/// Builds a response to `q`: the client's question echoed back verbatim, the
/// given answers (owner names compressed to point at the question) and an OPT
/// record if the client sent one.
pub fn writeResponse(out: []u8, query: []const u8, q: *const Query, options: ResponseOptions) BuildError![]u8 {
    var b: Builder = .{ .buf = out };
    var flags = q.flags; // keeps opcode, RD and CD from the query
    flags.qr = true;
    flags.aa = options.authoritative;
    flags.tc = options.truncated;
    flags.ra = true;
    flags.z = false;
    flags.ad = false;
    flags.rcode = options.rcode;

    try b.int(u16, q.id);
    try b.int(u16, @backingInt(flags));
    const negative = options.rcode == .nxdomain or (options.rcode == .noerror and options.answers.len == 0);
    const soa_ttl: ?u32 = if (negative) options.negative_ttl else null;
    try b.int(u16, 1);
    try b.int(u16, @intCast(options.answers.len));
    try b.int(u16, if (soa_ttl != null) 1 else 0);
    try b.int(u16, if (q.edns != null) 1 else 0);
    try b.bytes(query[header_len..q.question_end]);

    for (options.answers) |answer| {
        try b.int(u16, 0xC000 | header_len); // pointer to the question name
        switch (answer) {
            .a => |ip| {
                try b.recordHeader(.a, options.ttl, ip.len);
                try b.bytes(&ip);
            },
            .aaaa => |ip| {
                try b.recordHeader(.aaaa, options.ttl, ip.len);
                try b.bytes(&ip);
            },
            .ptr, .cname => |name| {
                try b.recordHeader(if (answer == .ptr) .ptr else .cname, options.ttl, encodedNameLen(name));
                try b.name(name);
            },
        }
    }

    if (soa_ttl) |ttl| {
        // Owned by the question name, so it covers exactly this answer.
        try b.int(u16, 0xC000 | header_len);
        try b.recordHeader(.soa, ttl, encodedNameLen(soa_mname) + encodedNameLen(soa_rname) + 20);
        try b.name(soa_mname);
        try b.name(soa_rname);
        try b.int(u32, 1); // serial
        try b.int(u32, 3600); // refresh
        try b.int(u32, 600); // retry
        try b.int(u32, 86400); // expire
        try b.int(u32, ttl); // minimum: the negative TTL
    }

    if (q.edns) |edns| try b.opt(edns.dnssec_ok);
    return out[0..b.len];
}

/// A bare error response echoing only the header, for queries whose question
/// could not be parsed. Returns null if `query` is shorter than a header.
pub fn writeHeaderOnly(out: []u8, query: []const u8, rcode: Rcode) ?[]u8 {
    if (query.len < header_len or out.len < header_len) return null;
    var flags = readFlags(query);
    flags.qr = true;
    flags.aa = false;
    flags.tc = false;
    flags.ra = true;
    flags.z = false;
    flags.ad = false;
    flags.rcode = rcode;
    writeU16(out, 0, readU16(query, 0));
    writeFlags(out, flags);
    @memset(out[4..header_len], 0);
    return out[0..header_len];
}

/// Wire length of a dotted name: one length byte per label plus the root byte.
fn encodedNameLen(name: []const u8) u16 {
    if (name.len == 0) return 1;
    return @intCast(name.len + 2);
}

const Builder = struct {
    buf: []u8,
    len: usize = 0,

    fn bytes(b: *Builder, data: []const u8) BuildError!void {
        if (b.buf.len - b.len < data.len) return error.NoSpaceLeft;
        @memcpy(b.buf[b.len..][0..data.len], data);
        b.len += data.len;
    }

    fn int(b: *Builder, comptime T: type, value: T) BuildError!void {
        var encoded: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &encoded, value, .big);
        try b.bytes(&encoded);
    }

    /// An OPT record (RFC 6891) without options.
    fn opt(b: *Builder, dnssec_ok: bool) BuildError!void {
        try b.int(u8, 0); // root owner name
        try b.int(u16, @backingInt(Type.opt));
        try b.int(u16, edns_payload_size);
        try b.int(u32, if (dnssec_ok) 0x8000 else 0); // extended rcode, version, DO bit
        try b.int(u16, 0);
    }

    fn recordHeader(b: *Builder, record_type: Type, ttl: u32, rdata_len: usize) BuildError!void {
        try b.int(u16, @backingInt(record_type));
        try b.int(u16, class_in);
        try b.int(u32, ttl);
        try b.int(u16, @intCast(rdata_len));
    }

    /// Writes a dotted name as uncompressed labels. The name must already be
    /// valid (labels of 1 to 63 bytes).
    fn name(b: *Builder, dotted: []const u8) BuildError!void {
        if (dotted.len > 0) {
            var labels = std.mem.splitScalar(u8, dotted, '.');
            while (labels.next()) |label| {
                assert(label.len > 0 and label.len <= 63);
                try b.int(u8, @intCast(label.len));
                try b.bytes(label);
            }
        }
        try b.int(u8, 0);
    }
};

// ---------------------------------------------------------------------------
// Domain names in text form

/// Validates a hostname from a config file or blocklist and writes it to `out`
/// in canonical form: lowercase, without a trailing dot. Accepts letters,
/// digits, '-' and '_' in labels of 1 to 63 characters. Returns null if the
/// name is invalid.
pub fn normalizeName(text: []const u8, out: *[max_name_len]u8) ?[]const u8 {
    const name = if (std.mem.endsWith(u8, text, ".")) text[0 .. text.len - 1] else text;
    if (name.len == 0 or name.len > max_name_len) return null;
    var label_len: usize = 0;
    for (name, 0..) |c, i| {
        switch (c) {
            'a'...'z', '0'...'9', '-', '_' => out[i] = c,
            'A'...'Z' => out[i] = c | 0x20,
            '.' => {
                if (label_len == 0) return null;
                label_len = 0;
                out[i] = c;
                continue;
            },
            else => return null,
        }
        label_len += 1;
        if (label_len > 63) return null;
    }
    if (label_len == 0) return null;
    return out[0..name.len];
}

/// True if `name` equals `zone` or is below it ("a.b.lan" is under "lan").
pub fn isAtOrBelow(name: []const u8, zone: []const u8) bool {
    if (!std.mem.endsWith(u8, name, zone)) return false;
    return name.len == zone.len or name[name.len - zone.len - 1] == '.';
}

/// A name as it appears in logs: "." for the root, and every byte outside
/// printable ASCII (or a backslash) as \xNN. Query names come from the
/// network and may hold any byte but '.', including line breaks and
/// terminal escapes.
pub fn printable(name: []const u8) Printable {
    return .{ .name = name };
}

pub const Printable = struct {
    name: []const u8,

    pub fn format(p: Printable, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (p.name.len == 0) return w.writeByte('.');
        for (p.name) |c| {
            if (c >= 0x20 and c < 0x7f and c != '\\') {
                try w.writeByte(c);
            } else {
                try w.print("\\x{x:0>2}", .{c});
            }
        }
    }
};

pub fn readU16(msg: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, msg[offset..][0..2], .big);
}

fn readU32(msg: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, msg[offset..][0..4], .big);
}

fn writeU16(msg: []u8, offset: usize, value: u16) void {
    std.mem.writeInt(u16, msg[offset..][0..2], value, .big);
}

fn writeU32(msg: []u8, offset: usize, value: u32) void {
    std.mem.writeInt(u32, msg[offset..][0..4], value, .big);
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;
const fuzz = @import("test_fuzz.zig");

fn repeat(comptime c: u8, comptime n: usize) [n]u8 {
    return @splat(c);
}

/// Builds a query for tests: header, one question, optional OPT record.
pub fn testQuery(buf: []u8, id: u16, name: []const u8, qtype: Type, edns_size: ?u16) []u8 {
    var b: Builder = .{ .buf = buf };
    b.int(u16, id) catch unreachable;
    b.int(u16, 0x0100) catch unreachable; // RD
    b.int(u16, 1) catch unreachable;
    b.int(u16, 0) catch unreachable;
    b.int(u16, 0) catch unreachable;
    b.int(u16, if (edns_size != null) 1 else 0) catch unreachable;
    b.name(name) catch unreachable;
    b.int(u16, @backingInt(qtype)) catch unreachable;
    b.int(u16, class_in) catch unreachable;
    if (edns_size) |size| {
        b.int(u8, 0) catch unreachable;
        b.int(u16, @backingInt(Type.opt)) catch unreachable;
        b.int(u16, size) catch unreachable;
        b.int(u32, 0x8000) catch unreachable;
        b.int(u16, 0) catch unreachable;
    }
    return buf[0..b.len];
}

test "parse a query with EDNS" {
    var buf: [512]u8 = undefined;
    var name_buf: [max_name_len]u8 = undefined;
    const msg = testQuery(&buf, 0xBEEF, "WWW.Example.COM", .aaaa, 4096);
    const q = try parseQuery(msg, &name_buf);
    try testing.expectEqual(0xBEEF, q.id);
    try testing.expectEqualStrings("www.example.com", q.name);
    try testing.expectEqual(Type.aaaa, q.qtype);
    try testing.expectEqual(class_in, q.qclass);
    try testing.expect(q.flags.rd);
    try testing.expectEqual(4096, q.edns.?.udp_size);
    try testing.expect(q.edns.?.dnssec_ok);
    try testing.expectEqual(4096, q.maxUdpSize());
}

test "parse the root name and reject malformed queries" {
    var buf: [512]u8 = undefined;
    var name_buf: [max_name_len]u8 = undefined;

    const root = try parseQuery(testQuery(&buf, 1, "", .ns, null), &name_buf);
    try testing.expectEqualStrings("", root.name);
    try testing.expectEqual(min_udp_payload, root.maxUdpSize());

    const msg = testQuery(&buf, 1, "example.com", .a, null);
    try testing.expectError(error.NotQuery, parseQuery(msg[0..11], &name_buf));
    for (header_len..msg.len) |len| {
        try testing.expectError(error.FormatError, parseQuery(msg[0..len], &name_buf));
    }

    msg[2] |= 0x80; // QR: a response, not a query
    try testing.expectError(error.NotQuery, parseQuery(msg, &name_buf));
    msg[2] = 0x28; // opcode UPDATE
    try testing.expectError(error.NotImplemented, parseQuery(msg, &name_buf));
    msg[2] = 0x01;

    msg[header_len] = 0xC0; // compression pointer in the question
    try testing.expectError(error.FormatError, parseQuery(msg, &name_buf));
}

test "names longer than 255 wire bytes are rejected" {
    var buf: [600]u8 = undefined;
    var name_buf: [max_name_len]u8 = undefined;
    const label = repeat('a', 63);
    // 3*64 + 62 + 1 = 255 wire bytes: the longest legal name (253 characters).
    const longest = label ++ "." ++ label ++ "." ++ label ++ "." ++ repeat('a', 61);
    const q = try parseQuery(testQuery(&buf, 1, longest, .a, null), &name_buf);
    try testing.expectEqual(253, q.name.len);
    const too_long = label ++ "." ++ label ++ "." ++ label ++ "." ++ repeat('a', 62);
    try testing.expectError(error.FormatError, parseQuery(testQuery(&buf, 1, too_long, .a, null), &name_buf));
}

test "labels containing dots are refused" {
    var buf: [512]u8 = undefined;
    var name_buf: [max_name_len]u8 = undefined;
    const msg = testQuery(&buf, 1, "ads.com", .a, null);
    msg[header_len + 4] = '.'; // turn the "com" length byte into a dot: one label "ads.com"
    msg[header_len] = 7;
    try testing.expectError(error.Refused, parseQuery(msg, &name_buf));
}

test "build a response and walk its records" {
    var query_buf: [512]u8 = undefined;
    var name_buf: [max_name_len]u8 = undefined;
    var out: [512]u8 = undefined;
    const msg = testQuery(&query_buf, 7, "Nas.Lan", .a, 1232);
    const q = try parseQuery(msg, &name_buf);

    const answers = [_]Answer{ .{ .a = .{ 192, 168, 1, 10 } }, .{ .a = .{ 192, 168, 1, 11 } } };
    const response = try writeResponse(&out, msg, &q, .{ .answers = &answers, .ttl = 300, .authoritative = true });
    try testing.expect(isResponseTo(response, msg, q.question_end));

    const flags = readFlags(response);
    try testing.expect(flags.qr and flags.aa and flags.rd and flags.ra);
    try testing.expectEqual(Rcode.noerror, flags.rcode);
    // The client's spelling of the name is echoed back.
    try testing.expectEqualSlices(u8, msg[header_len..q.question_end], response[header_len..q.question_end]);

    var records: RecordIterator = .init(response, q.question_end);
    const first = (try records.next()).?;
    try testing.expectEqual(Type.a, first.type);
    try testing.expectEqual(300, first.ttl);
    try testing.expectEqualSlices(u8, &.{ 192, 168, 1, 10 }, response[first.rdata_offset..][0..first.rdata_len]);
    _ = (try records.next()).?;
    const opt = (try records.next()).?;
    try testing.expectEqual(Type.opt, opt.type);
    try testing.expectEqual(Section.additional, opt.section);
    try testing.expectEqual(edns_payload_size, opt.class);
    try testing.expectEqual(null, try records.next());

    try testing.expectEqual(300, try minTtl(response));
    try ageTtls(response, 100);
    try testing.expectEqual(200, try minTtl(response));
    try clampTtls(response, 250, 3600);
    try testing.expectEqual(250, try minTtl(response));

    // A response that does not fit fails cleanly.
    try testing.expectError(error.NoSpaceLeft, writeResponse(out[0..40], msg, &q, .{ .answers = &answers }));
}

test "PTR answers encode the target name" {
    var query_buf: [512]u8 = undefined;
    var name_buf: [max_name_len]u8 = undefined;
    var out: [512]u8 = undefined;
    const msg = testQuery(&query_buf, 9, "10.1.168.192.in-addr.arpa", .ptr, null);
    const q = try parseQuery(msg, &name_buf);
    const response = try writeResponse(&out, msg, &q, .{ .answers = &.{.{ .ptr = "nas.lan" }}, .ttl = 60 });
    var records: RecordIterator = .init(response, q.question_end);
    const ptr = (try records.next()).?;
    try testing.expectEqualSlices(u8, "\x03nas\x03lan\x00", response[ptr.rdata_offset..][0..ptr.rdata_len]);
}

test "isResponseTo rejects mismatches" {
    var query_buf: [512]u8 = undefined;
    var name_buf: [max_name_len]u8 = undefined;
    var out: [512]u8 = undefined;
    const msg = testQuery(&query_buf, 42, "example.com", .a, null);
    const q = try parseQuery(msg, &name_buf);
    const response = try writeResponse(&out, msg, &q, .{});
    try testing.expect(isResponseTo(response, msg, q.question_end));

    setId(response, 43);
    try testing.expect(!isResponseTo(response, msg, q.question_end));
    setId(response, 42);
    response[q.question_end - 3] = @backingInt(Type.aaaa); // different qtype
    try testing.expect(!isResponseTo(response, msg, q.question_end));
}

test "rewriteForUpstream drops EDNS options and extra records" {
    var buf: [512]u8 = undefined;
    var name_buf: [max_name_len]u8 = undefined;
    const original = testQuery(&buf, 3, "example.com", .a, 4096);
    // Append an 8-byte EDNS option (a client cookie) to the OPT record.
    const opt_rdlen_offset = original.len - 2;
    writeU16(&buf, opt_rdlen_offset, 12);
    @memcpy(buf[original.len..][0..12], &[_]u8{ 0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8 });
    const msg = buf[0 .. original.len + 12];

    const q = try parseQuery(msg, &name_buf);
    const rewritten = rewriteForUpstream(msg, &q).bytes;
    try testing.expectEqual(q.question_end + 11, rewritten.len);
    const again = try parseQuery(rewritten, &name_buf);
    try testing.expectEqual(edns_payload_size, again.edns.?.udp_size);
    try testing.expect(again.edns.?.dnssec_ok);
    var records: RecordIterator = .init(rewritten, again.question_end);
    try testing.expectEqual(0, (try records.next()).?.rdata_len);

    // Without EDNS nothing follows the question.
    const plain = testQuery(&buf, 4, "example.com", .a, null);
    const plain_q = try parseQuery(plain, &name_buf);
    try testing.expectEqual(plain_q.question_end, rewriteForUpstream(plain, &plain_q).bytes.len);
}

test "header-only error responses" {
    var query_buf: [512]u8 = undefined;
    var out: [512]u8 = undefined;
    const msg = testQuery(&query_buf, 5, "example.com", .a, null);
    const response = writeHeaderOnly(&out, msg, .formerr).?;
    try testing.expectEqual(header_len, response.len);
    try testing.expectEqual(5, readId(response));
    try testing.expectEqual(Rcode.formerr, readFlags(response).rcode);
    try testing.expectEqual(null, writeHeaderOnly(&out, msg[0..5], .formerr));
}

test "malformed records are detected" {
    var query_buf: [512]u8 = undefined;
    var name_buf: [max_name_len]u8 = undefined;
    var out: [512]u8 = undefined;
    const msg = testQuery(&query_buf, 1, "example.com", .a, null);
    const q = try parseQuery(msg, &name_buf);
    const response = try writeResponse(&out, msg, &q, .{ .answers = &.{.{ .a = .{ 1, 2, 3, 4 } }}, .ttl = 5 });
    for (q.question_end..response.len) |len| {
        try testing.expectError(error.Malformed, minTtl(response[0..len]));
    }
}

test "normalizeName" {
    var buf: [max_name_len]u8 = undefined;
    try testing.expectEqualStrings("example.com", normalizeName("Example.COM.", &buf).?);
    try testing.expectEqualStrings("_dmarc.x-y.org", normalizeName("_dmarc.x-y.org", &buf).?);
    try testing.expectEqual(null, normalizeName("", &buf));
    try testing.expectEqual(null, normalizeName(".", &buf));
    try testing.expectEqual(null, normalizeName("a..b", &buf));
    try testing.expectEqual(null, normalizeName(".a.b", &buf));
    try testing.expectEqual(null, normalizeName("exa mple.com", &buf));
    try testing.expectEqual(null, normalizeName("*.example.com", &buf));
    try testing.expectEqual(null, normalizeName(repeat('a', 64) ++ ".com", &buf));
}

test "isAtOrBelow" {
    try testing.expect(isAtOrBelow("lan", "lan"));
    try testing.expect(isAtOrBelow("nas.lan", "lan"));
    try testing.expect(!isAtOrBelow("plan", "lan"));
    try testing.expect(!isAtOrBelow("lan", "nas.lan"));
}

test "Type formatting" {
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("AAAA", try std.fmt.bufPrint(&buf, "{f}", .{Type.aaaa}));
    try testing.expectEqualStrings("TYPE999", try std.fmt.bufPrint(&buf, "{f}", .{@as(Type, @fromBackingInt(999))}));
}

test "fuzz: no message breaks the parsers, and a parsed query gets a response to it" {
    try testing.fuzz({}, fuzzMessage, .{ .corpus = &.{
        fuzz.input(fuzz_query),
        fuzz.input(fuzz_response),
    } });
}

/// www.example.com A, with an OPT record (DO set).
const fuzz_query = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01" ++
    "\x03www\x07example\x03com\x00\x00\x01\x00\x01" ++
    "\x00\x00\x29\x04\xd0\x00\x00\x80\x00\x00\x00";
/// Its answer: www.example.com CNAME cdn.example.com (compressed), and an
/// A record for that.
const fuzz_response = "\x12\x34\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" ++
    "\x03www\x07example\x03com\x00\x00\x01\x00\x01" ++
    "\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x06\x03cdn\xc0\x10" ++
    "\xc0\x2d\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04";

fn fuzzMessage(_: void, smith: *testing.Smith) !void {
    var buf: [600]u8 = undefined;
    const msg = buf[0..smith.slice(&buf)];
    var out: [2048]u8 = undefined;

    _ = minTtl(msg) catch {};
    ageTtls(msg, 5) catch {};
    clampTtls(msg, 1, 100) catch {};
    _ = writeHeaderOnly(&out, msg, .formerr);
    if (questionEnd(msg)) |question_end| {
        // Every name in the message reads as a valid name, or fails cleanly.
        var name_buf: [max_name_len]u8 = undefined;
        try expectValidName(readName(msg, header_len, &name_buf));
        var records: RecordIterator = .init(msg, question_end);
        while (records.next() catch null) |record| {
            if (record.type == .cname or record.type == .ptr or record.type == .ns) {
                try expectValidName(readName(msg, record.rdata_offset, &name_buf));
            }
        }
    } else |_| {}

    var parsed_name: [max_name_len]u8 = undefined;
    const q = parseQuery(msg, &parsed_name) catch return;
    try expectValidName(q.name);
    const answers = [_]Answer{ .{ .a = .{ 1, 2, 3, 4 } }, .{ .cname = "a.b" }, .{ .ptr = "c" } };
    for ([_]ResponseOptions{
        .{ .answers = &answers, .ttl = 1 },
        .{ .rcode = .nxdomain, .negative_ttl = 30 },
    }) |options| {
        const response = try writeResponse(&out, msg, &q, options);
        try testing.expect(isResponseTo(response, msg, q.question_end));
        _ = try minTtl(response);
    }
    // What goes upstream is still the same query.
    const upstream = rewriteForUpstream(msg, &q);
    var upstream_name: [max_name_len]u8 = undefined;
    const sent = try parseQuery(upstream.bytes, &upstream_name);
    try testing.expectEqualStrings(q.name, sent.name);
}

/// Lowercase text of at most `max_name_len` bytes (labels may hold any
/// other byte), or `error.Malformed`.
fn expectValidName(result: MalformedError![]const u8) !void {
    const name = result catch return;
    try testing.expect(name.len <= max_name_len);
    for (name) |c| try testing.expect(!std.ascii.isUpper(c));
}
test "a negative answer's TTL is the smaller of its SOA's TTL and MINIMUM (RFC 2308)" {
    var name_buf: [max_name_len]u8 = undefined;
    var query_buf: [512]u8 = undefined;
    const query = testQuery(&query_buf, 1, "gone.example.com", .a, null);
    const q = try parseQuery(query, &name_buf);
    var response_buf: [512]u8 = undefined;
    const response = try writeResponse(&response_buf, query, &q, .{ .rcode = .nxdomain, .negative_ttl = 3600 });
    try testing.expectEqual(3600, (try minTtl(response)).?);

    // The SOA's MINIMUM is the last field of the message (there is no OPT).
    writeU32(response, response.len - 4, 60);
    try testing.expectEqual(60, (try minTtl(response)).?);
}

test "compressed names are read in full, and pointers that do not point back are rejected" {
    // At 12: "example.com"; at 25: "www" + a pointer to 12; at 31: "CDN" + a
    // pointer to 25.
    const msg = @as([header_len]u8, @splat(0)) ++
        "\x07example\x03com\x00".* ++
        "\x03www\xc0\x0c".* ++
        "\x03CDN\xc0\x19".*;
    var buf: [max_name_len]u8 = undefined;
    try testing.expectEqualStrings("example.com", try readName(&msg, 12, &buf));
    try testing.expectEqualStrings("www.example.com", try readName(&msg, 25, &buf));
    try testing.expectEqualStrings("cdn.www.example.com", try readName(&msg, 31, &buf));

    // A pointer to itself, and a pointer forwards.
    const loop = @as([header_len]u8, @splat(0)) ++ "\x03www\xc0\x0c".*;
    try testing.expectError(error.Malformed, readName(&loop, 12, &buf));
    const forwards = @as([header_len]u8, @splat(0)) ++ "\xc0\x0e\x03www\x00".*;
    try testing.expectError(error.Malformed, readName(&forwards, 12, &buf));
    // Cut off in the middle of a label.
    try testing.expectError(error.Malformed, readName(msg[0..20], 12, &buf));
}

test "names are printed safely for logs" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("www.example.com", try std.fmt.bufPrint(&buf, "{f}", .{printable("www.example.com")}));
    try testing.expectEqualStrings(".", try std.fmt.bufPrint(&buf, "{f}", .{printable("")}));
    // Line breaks, terminal escapes, NUL and backslashes cannot forge or
    // garble log lines.
    try testing.expectEqualStrings("a\\x0ainfo(main)", try std.fmt.bufPrint(&buf, "{f}", .{printable("a\ninfo(main)")}));
    try testing.expectEqualStrings("\\x1b[31mred\\x00\\x5c", try std.fmt.bufPrint(&buf, "{f}", .{printable("\x1b[31mred\x00\\")}));
}
