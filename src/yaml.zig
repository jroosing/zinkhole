//! A strict YAML subset parser, sized for configuration files.
//!
//! Supported:
//!   * block mappings (`key: value`) and block sequences (`- item`)
//!   * single-line flow sequences (`[a, b, "c"]`)
//!   * plain, 'single-quoted' and "double-quoted" scalars
//!   * comments, blank lines and a leading `---`
//!
//! Anything else is rejected with a line number instead of being silently
//! misread: tabs in indentation, anchors/aliases/tags, block scalars (`|`,
//! `>`), flow mappings, multiple documents, duplicate keys and mappings
//! nested inside sequences. Not supporting aliases also rules out "billion
//! laughs" expansion.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Node = struct {
    line: u32,
    value: Value,

    pub const Value = union(enum) {
        /// A key with nothing after it (`key:`).
        empty,
        scalar: []const u8,
        sequence: []const Node,
        mapping: []const Pair,
    };
};

pub const Pair = struct {
    key: []const u8,
    /// Line of the key, for error messages.
    line: u32,
    value: Node,
};

/// Where and why parsing failed.
pub const Diagnostic = struct {
    line: u32 = 0,
    message: []const u8 = "",
};

pub const Error = error{ InvalidYaml, OutOfMemory };

const max_depth = 32;

/// Parses `source` into a tree allocated in `arena`; free the arena to free the tree.
pub fn parse(arena: Allocator, source: []const u8, diag: *Diagnostic) Error!Node {
    var parser: Parser = .{ .arena = arena, .diag = diag, .lines = &.{} };
    parser.lines = try parser.splitLines(source);
    if (parser.lines.len == 0) return .{ .line = 1, .value = .empty };

    const root = try parser.parseBlock(parser.lines[0].indent, 0);
    if (parser.index < parser.lines.len) {
        return parser.fail(parser.lines[parser.index].number, "unexpected indentation");
    }
    return root;
}

/// One meaningful source line: indentation removed, trailing whitespace
/// trimmed. Comment-only and blank lines are dropped while splitting; trailing
/// comments are removed by the scalar parsers, which know about quoting.
const Line = struct {
    number: u32,
    indent: u32,
    text: []const u8,
};

const Parser = struct {
    arena: Allocator,
    diag: *Diagnostic,
    lines: []const Line,
    index: usize = 0,

    fn fail(p: *Parser, line: u32, message: []const u8) Error {
        p.diag.* = .{ .line = line, .message = message };
        return error.InvalidYaml;
    }

    fn splitLines(p: *Parser, source: []const u8) Error![]const Line {
        var lines: std.ArrayList(Line) = .empty;
        var it = std.mem.splitScalar(u8, source, '\n');
        var number: u32 = 0;
        var seen_content = false;
        while (it.next()) |raw| {
            number += 1;
            var line = std.mem.trimEnd(u8, raw, " \t\r");
            if (number == 1 and std.mem.startsWith(u8, line, "\xEF\xBB\xBF")) line = line[3..];

            var indent: u32 = 0;
            while (indent < line.len and line[indent] == ' ') indent += 1;
            const text = line[indent..];
            if (text.len == 0 or text[0] == '#') continue;
            if (text[0] == '\t') return p.fail(number, "tabs are not allowed for indentation, use spaces");

            if (isDocumentStart(text)) {
                if (seen_content) return p.fail(number, "multiple documents are not supported");
                continue;
            }
            if (std.mem.eql(u8, text, "...")) return p.fail(number, "document end markers are not supported");
            if (text[0] == '%') return p.fail(number, "YAML directives are not supported");

            seen_content = true;
            try lines.append(p.arena, .{ .number = number, .indent = indent, .text = text });
        }
        return lines.items;
    }

    /// Parses the block (mapping or sequence) whose first line is the current
    /// line, indented by exactly `indent` spaces.
    fn parseBlock(p: *Parser, indent: u32, depth: u32) Error!Node {
        const line = p.lines[p.index];
        if (depth >= max_depth) return p.fail(line.number, "nesting is too deep");
        if (isSequenceItem(line.text)) return p.parseSequence(indent, depth);
        return p.parseMapping(indent, depth);
    }

    fn parseMapping(p: *Parser, indent: u32, depth: u32) Error!Node {
        const first_line = p.lines[p.index].number;
        var pairs: std.ArrayList(Pair) = .empty;
        while (p.index < p.lines.len) {
            const line = p.lines[p.index];
            if (line.indent < indent) break;
            if (line.indent > indent) return p.fail(line.number, "unexpected indentation");
            if (isSequenceItem(line.text)) return p.fail(line.number, "expected 'key: value', found a list item");

            const key, const rest = try p.splitKey(line);
            for (pairs.items) |existing| {
                if (std.mem.eql(u8, existing.key, key)) return p.fail(line.number, "duplicate key");
            }
            p.index += 1;

            const value: Node = if (!isBlankOrComment(rest))
                try p.parseInlineValue(rest, line.number)
            else if (p.index < p.lines.len and p.lines[p.index].indent > indent)
                try p.parseBlock(p.lines[p.index].indent, depth + 1)
            else if (p.index < p.lines.len and p.lines[p.index].indent == indent and isSequenceItem(p.lines[p.index].text))
                // A list may sit at the same indentation as its key.
                try p.parseSequence(indent, depth + 1)
            else
                .{ .line = line.number, .value = .empty };

            try pairs.append(p.arena, .{ .key = key, .line = line.number, .value = value });
        }
        return .{ .line = first_line, .value = .{ .mapping = pairs.items } };
    }

    fn parseSequence(p: *Parser, indent: u32, depth: u32) Error!Node {
        const first_line = p.lines[p.index].number;
        var items: std.ArrayList(Node) = .empty;
        while (p.index < p.lines.len) {
            const line = p.lines[p.index];
            if (line.indent < indent) break;
            if (line.indent > indent) return p.fail(line.number, "unexpected indentation");
            // Not a list item: the list ended (it sat at the same indentation as its key).
            if (!isSequenceItem(line.text)) break;
            p.index += 1;

            const rest = std.mem.trimStart(u8, line.text[1..], " \t");
            const item: Node = if (!isBlankOrComment(rest))
                try p.parseInlineValue(rest, line.number)
            else if (p.index < p.lines.len and p.lines[p.index].indent > indent)
                try p.parseBlock(p.lines[p.index].indent, depth + 1)
            else
                .{ .line = line.number, .value = .empty };

            if (item.value == .mapping) return p.fail(line.number, "mappings inside lists are not supported");
            try items.append(p.arena, item);
        }
        return .{ .line = first_line, .value = .{ .sequence = items.items } };
    }

    /// Splits `key: rest` and decodes the key.
    fn splitKey(p: *Parser, line: Line) Error!struct { []const u8, []const u8 } {
        const text = line.text;
        if (text[0] == '"' or text[0] == '\'') {
            const key, const after = try p.parseQuoted(text, line.number);
            const rest = std.mem.trimStart(u8, after, " \t");
            if (rest.len == 0 or rest[0] != ':') return p.fail(line.number, "expected ':' after quoted key");
            if (rest.len > 1 and !isSpace(rest[1])) return p.fail(line.number, "expected a space after ':'");
            return .{ key, std.mem.trimStart(u8, rest[1..], " \t") };
        }

        var i: usize = 0;
        while (i < text.len) : (i += 1) {
            switch (text[i]) {
                '#' => if (i > 0 and isSpace(text[i - 1])) break,
                ':' => if (i + 1 == text.len or isSpace(text[i + 1])) {
                    const key = std.mem.trimEnd(u8, text[0..i], " \t");
                    if (key.len == 0) return p.fail(line.number, "empty key");
                    try p.checkPlainStart(key, line.number);
                    return .{ key, std.mem.trimStart(u8, text[i + 1 ..], " \t") };
                },
                else => {},
            }
        }
        return p.fail(line.number, "expected 'key: value'");
    }

    /// Parses a value that follows `key: ` or `- ` on the same line.
    fn parseInlineValue(p: *Parser, text: []const u8, line: u32) Error!Node {
        switch (text[0]) {
            '[' => return p.parseFlowSequence(text, line),
            '{' => return p.fail(line, "flow mappings ({...}) are not supported"),
            '"', '\'' => {
                const value, const rest = try p.parseQuoted(text, line);
                try p.expectEnd(rest, line);
                return .{ .line = line, .value = .{ .scalar = value } };
            },
            else => {
                const value = try p.parsePlain(text, .block, line);
                return .{ .line = line, .value = .{ .scalar = value } };
            },
        }
    }

    /// Parses `[a, "b", c]` on a single line. Only scalars may appear inside.
    fn parseFlowSequence(p: *Parser, text: []const u8, line: u32) Error!Node {
        var items: std.ArrayList(Node) = .empty;
        var rest = std.mem.trimStart(u8, text[1..], " \t");
        if (rest.len > 0 and rest[0] == ']') {
            try p.expectEnd(rest[1..], line);
            return .{ .line = line, .value = .{ .sequence = &.{} } };
        }
        while (true) {
            if (rest.len == 0) return p.fail(line, "unterminated '[' (flow lists must fit on one line)");
            const value: []const u8 = switch (rest[0]) {
                '"', '\'' => quoted: {
                    const value, rest = try p.parseQuoted(rest, line);
                    break :quoted value;
                },
                '[', '{' => return p.fail(line, "nested flow collections are not supported"),
                ',', ']' => return p.fail(line, "empty item in flow list"),
                else => plain: {
                    const end = std.mem.findAny(u8, rest, ",]") orelse return p.fail(line, "unterminated '['");
                    const value = try p.parsePlain(rest[0..end], .flow, line);
                    rest = rest[end..];
                    break :plain value;
                },
            };
            try items.append(p.arena, .{ .line = line, .value = .{ .scalar = value } });

            rest = std.mem.trimStart(u8, rest, " \t");
            if (rest.len == 0) return p.fail(line, "unterminated '['");
            switch (rest[0]) {
                ',' => rest = std.mem.trimStart(u8, rest[1..], " \t"),
                ']' => {
                    try p.expectEnd(rest[1..], line);
                    return .{ .line = line, .value = .{ .sequence = items.items } };
                },
                else => return p.fail(line, "expected ',' or ']' in flow list"),
            }
        }
    }

    const Context = enum { block, flow };

    /// Parses an unquoted scalar. In block context it runs to the end of the
    /// line or to a ` #` comment; in flow context the caller passes the text
    /// up to the next `,` or `]`.
    fn parsePlain(p: *Parser, text: []const u8, context: Context, line: u32) Error![]const u8 {
        var end = text.len;
        if (std.mem.find(u8, text, " #")) |i| end = i;
        if (std.mem.find(u8, text, "\t#")) |i| end = @min(end, i);
        const value = std.mem.trim(u8, text[0..end], " \t");
        if (context == .flow and end != text.len) return p.fail(line, "comments are not allowed inside flow lists");
        if (value.len == 0) return p.fail(line, "empty value");
        try p.checkPlainStart(value, line);
        if (context == .block) {
            if (std.mem.find(u8, value, ": ") != null or std.mem.find(u8, value, ":\t") != null or value[value.len - 1] == ':') {
                return p.fail(line, "unexpected ':' in value (quote the value if this is intended)");
            }
        }
        return value;
    }

    /// Rejects plain scalars starting with YAML indicator characters, which
    /// other YAML parsers would interpret as aliases, tags, block scalars...
    fn checkPlainStart(p: *Parser, value: []const u8, line: u32) Error!void {
        switch (value[0]) {
            '&', '*', '!', '|', '>', '%', '@', '`', '{', '}', '[', ']', ',' => {
                return p.fail(line, "value starts with a YAML indicator character; wrap it in quotes");
            },
            else => {},
        }
    }

    /// Parses a quoted scalar at the start of `text`. Returns the decoded
    /// value and the text after the closing quote.
    fn parseQuoted(p: *Parser, text: []const u8, line: u32) Error!struct { []const u8, []const u8 } {
        const quote = text[0];
        var out: std.ArrayList(u8) = .empty;
        var i: usize = 1;
        while (i < text.len) : (i += 1) {
            const c = text[i];
            if (quote == '\'') {
                if (c != '\'') {
                    try out.append(p.arena, c);
                } else if (i + 1 < text.len and text[i + 1] == '\'') {
                    try out.append(p.arena, '\'');
                    i += 1;
                } else {
                    return .{ out.items, text[i + 1 ..] };
                }
                continue;
            }
            switch (c) {
                '"' => return .{ out.items, text[i + 1 ..] },
                '\\' => {
                    i += 1;
                    if (i == text.len) break;
                    i += try p.appendEscape(&out, text[i..], line);
                },
                else => try out.append(p.arena, c),
            }
        }
        return p.fail(line, "unterminated quoted string (quoted values must fit on one line)");
    }

    /// Decodes the escape sequence at the start of `seq` (after the
    /// backslash). Returns how many bytes beyond the first one were consumed.
    fn appendEscape(p: *Parser, out: *std.ArrayList(u8), seq: []const u8, line: u32) Error!usize {
        const simple: ?u8 = switch (seq[0]) {
            '\\' => '\\',
            '"' => '"',
            '/' => '/',
            '0' => 0,
            't' => '\t',
            'n' => '\n',
            'r' => '\r',
            else => null,
        };
        if (simple) |c| {
            try out.append(p.arena, c);
            return 0;
        }
        const digits: usize = switch (seq[0]) {
            'x' => 2,
            'u' => 4,
            else => return p.fail(line, "unsupported escape sequence in double-quoted string"),
        };
        if (seq.len < 1 + digits) return p.fail(line, "truncated escape sequence");
        const code = std.fmt.parseInt(u21, seq[1..][0..digits], 16) catch
            return p.fail(line, "invalid hex digits in escape sequence");
        var utf8: [4]u8 = undefined;
        const len = std.unicode.utf8Encode(code, &utf8) catch
            return p.fail(line, "escape sequence is not a valid code point");
        try out.appendSlice(p.arena, utf8[0..len]);
        return digits;
    }

    /// After a complete value only whitespace or a comment may follow.
    fn expectEnd(p: *Parser, rest: []const u8, line: u32) Error!void {
        const trimmed = std.mem.trimStart(u8, rest, " \t");
        if (trimmed.len == 0) return;
        if (trimmed[0] == '#' and trimmed.len < rest.len) return;
        return p.fail(line, "unexpected text after value");
    }
};

fn isSpace(c: u8) bool {
    return c == ' ' or c == '\t';
}

fn isSequenceItem(text: []const u8) bool {
    return text[0] == '-' and (text.len == 1 or isSpace(text[1]));
}

fn isBlankOrComment(text: []const u8) bool {
    return text.len == 0 or text[0] == '#';
}

fn isDocumentStart(text: []const u8) bool {
    if (!std.mem.startsWith(u8, text, "---")) return false;
    const rest = std.mem.trimStart(u8, text[3..], " \t");
    return rest.len == 0 or rest[0] == '#';
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

fn parseForTest(arena: *std.heap.ArenaAllocator, source: []const u8) !Node {
    var diag: Diagnostic = .{};
    return parse(arena.allocator(), source, &diag);
}

fn expectParseError(source: []const u8, line: u32) !void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var diag: Diagnostic = .{};
    try testing.expectError(error.InvalidYaml, parse(arena.allocator(), source, &diag));
    try testing.expectEqual(line, diag.line);
}

test "mappings, sequences and scalars" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const root = try parseForTest(&arena,
        \\# comment
        \\---
        \\server:
        \\  listen:
        \\    - 0.0.0.0:53
        \\    - "[::]:53"   # quoted because of the brackets
        \\  workers: 4
        \\upstream:
        \\  servers: [9.9.9.9, '1.1.1.1:53']
        \\local:
        \\  records:
        \\    nas.lan: 192.168.1.10
        \\    "*.apps.lan": fd00::1
        \\    it's: plain # trailing comment
        \\list:
        \\- a
        \\- b
        \\empty:
    );
    const top = root.value.mapping;
    try testing.expectEqual(5, top.len);

    const server = top[0].value.value.mapping;
    try testing.expectEqualStrings("listen", server[0].key);
    const listen = server[0].value.value.sequence;
    try testing.expectEqualStrings("0.0.0.0:53", listen[0].value.scalar);
    try testing.expectEqualStrings("[::]:53", listen[1].value.scalar);
    try testing.expectEqual(6, listen[1].line);
    try testing.expectEqualStrings("4", server[1].value.value.scalar);

    const servers = top[1].value.value.mapping[0].value.value.sequence;
    try testing.expectEqualStrings("9.9.9.9", servers[0].value.scalar);
    try testing.expectEqualStrings("1.1.1.1:53", servers[1].value.scalar);

    const records = top[2].value.value.mapping[0].value.value.mapping;
    try testing.expectEqualStrings("*.apps.lan", records[1].key);
    try testing.expectEqualStrings("fd00::1", records[1].value.value.scalar);
    try testing.expectEqualStrings("it's", records[2].key);
    try testing.expectEqualStrings("plain", records[2].value.value.scalar);

    const list = top[3].value.value.sequence;
    try testing.expectEqual(2, list.len);
    try testing.expectEqualStrings("b", list[1].value.scalar);
    try testing.expect(top[4].value.value == .empty);
}

test "quoted scalars and escapes" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const root = try parseForTest(&arena,
        \\a: 'it''s # not a comment'
        \\b: "tab\there \u00e9 \"q\""
        \\c: []
    );
    const m = root.value.mapping;
    try testing.expectEqualStrings("it's # not a comment", m[0].value.value.scalar);
    try testing.expectEqualStrings("tab\there \xc3\xa9 \"q\"", m[1].value.value.scalar);
    try testing.expectEqual(0, m[2].value.value.sequence.len);
}

test "empty document" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const root = try parseForTest(&arena, "# only a comment\n\n");
    try testing.expect(root.value == .empty);
}

test "rejects unsupported or ambiguous YAML" {
    try expectParseError("a: 1\na: 2", 2); // duplicate key
    try expectParseError("a:\n\tb: 1", 2); // tab indentation
    try expectParseError("a: &anchor 1", 1);
    try expectParseError("a: *alias", 1);
    try expectParseError("a: !tag x", 1);
    try expectParseError("a: |\n  text", 1);
    try expectParseError("a: {b: 1}", 1);
    try expectParseError("a: [::]:53", 1); // unquoted bracket value
    try expectParseError("a: [1, [2]]", 1);
    try expectParseError("a:\n  - b: 1", 2); // mapping inside a list
    try expectParseError("a: b: c", 1);
    try expectParseError("a: 'unterminated", 1);
    try expectParseError("a: 1\n  b: 2", 2); // bad indentation
    try expectParseError("a: 1\n---\nb: 2", 2);
    try expectParseError("just a scalar", 1);
    try expectParseError("a: \"bad \\q escape\"", 1);
}

test "nesting depth is limited" {
    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(testing.allocator);
    for (0..max_depth + 1) |depth| {
        try source.appendNTimes(testing.allocator, ' ', depth);
        try source.appendSlice(testing.allocator, "k:\n");
    }
    try expectParseError(source.items, max_depth + 1);
}

test "random input never breaks the parser" {
    var prng: std.Random.DefaultPrng = .init(42);
    const random = prng.random();
    const alphabet = "ab1: -#'\"[],{}&*!|>\t\n\n  \\x";
    var buf: [200]u8 = undefined;
    for (0..20_000) |_| {
        const len = random.uintLessThan(usize, buf.len);
        for (buf[0..len]) |*c| c.* = alphabet[random.uintLessThan(usize, alphabet.len)];
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        var diag: Diagnostic = .{};
        _ = parse(arena.allocator(), buf[0..len], &diag) catch {};
    }
}
