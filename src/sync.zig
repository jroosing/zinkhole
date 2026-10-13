//! Sync (ADR-0002): replicas pull the Policy settings from an origin.

const std = @import("std");
const Io = std.Io;
const net = Io.net;

const ip = @import("ip.zig");
const tcp = @import("tcp.zig");

const log = std.log.scoped(.sync);

/// The synced text is a config file's sections, so the config limit applies.
const max_text_len = 1024 * 1024;
/// A request to the origin, and an origin's whole answer, must fit in this.
const request_timeout_ms = 5_000;
const path = "/sync";

/// Identifies one version of the synced text (SHA-256); sent as the ETag.
pub const Fingerprint = [32]u8;

fn fingerprintOf(text: []const u8) Fingerprint {
    var fingerprint: Fingerprint = undefined;
    std.crypto.hash.sha2.Sha256.hash(text, &fingerprint, .{});
    return fingerprint;
}

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// Proves an answer comes from an origin with the secret, for this request.
pub const Signature = [HmacSha256.mac_length]u8;
/// A replica's random challenge, in hex: an answer signed over it cannot be
/// replayed to a later request.
pub const Nonce = [32]u8;

const nonce_header = "x-zinkhole-nonce";
const signature_header = "x-zinkhole-signature";

fn sign(secret: []const u8, nonce: *const Nonce, status: std.http.Status, fingerprint: Fingerprint, body: []const u8) Signature {
    var hmac: HmacSha256 = .init(secret);
    var status_buf: [3]u8 = undefined;
    hmac.update("zinkhole-sync-1\n");
    hmac.update(nonce);
    hmac.update("\n");
    hmac.update(std.fmt.bufPrint(&status_buf, "{d}", .{@backingInt(status)}) catch unreachable);
    hmac.update("\n");
    hmac.update(&std.fmt.bytesToHex(fingerprint, .lower));
    hmac.update("\n");
    hmac.update(body);
    var signature: Signature = undefined;
    hmac.final(&signature);
    return signature;
}

/// The quoted hex form HTTP uses for ETag and If-None-Match.
fn etag(fingerprint: Fingerprint) [66]u8 {
    return ("\"" ++ std.fmt.bytesToHex(fingerprint, .lower) ++ "\"").*;
}

/// Serves the Policy settings to replicas: one listener per address, each
/// answering one request at a time.
pub const Origin = struct {
    io: Io,
    gpa: std.mem.Allocator,
    secret: []u8,
    allow_clients: []const ip.Cidr,
    listeners: std.ArrayList(net.Server) = .empty,
    group: Io.Group = .init,
    /// Set once the serve tasks hold pointers into `listeners`.
    pointers_locked: bool = false,
    /// Guards `text`, which `publish` replaces.
    mutex: Io.Mutex = .init,
    text: []u8 = &.{},
    fingerprint: Fingerprint,

    /// Listens on `addresses` and starts serving (nothing until `publish`).
    /// `origin` must not move afterwards.
    pub fn init(origin: *Origin, io: Io, gpa: std.mem.Allocator, addresses: []const net.IpAddress, secret: []const u8, allow_clients: []const ip.Cidr) !void {
        origin.* = .{
            .io = io,
            .gpa = gpa,
            .secret = try gpa.dupe(u8, secret),
            .allow_clients = allow_clients,
            .fingerprint = fingerprintOf(""),
        };
        errdefer origin.deinit();
        for (addresses) |listen_address| {
            // IPv6-only next to an IPv4 listener on the same port.
            const ip6_only = listen_address == .ip6 and for (addresses) |other| {
                if (other == .ip4 and other.getPort() == listen_address.getPort()) break true;
            } else false;
            var listener = try tcp.listen(listen_address, ip6_only);
            origin.listeners.append(gpa, listener) catch |err| {
                listener.deinit(io);
                return err;
            };
        }
        // Tasks keep pointers into the list from here on.
        origin.listeners.lockPointers();
        origin.pointers_locked = true;
        for (origin.listeners.items) |*listener| try origin.group.concurrent(io, serve, .{ origin, listener });
    }

    pub fn deinit(origin: *Origin) void {
        origin.group.cancel(origin.io);
        if (origin.pointers_locked) origin.listeners.unlockPointers();
        for (origin.listeners.items) |*listener| listener.deinit(origin.io);
        origin.listeners.deinit(origin.gpa);
        origin.gpa.free(origin.text);
        origin.gpa.free(origin.secret);
        origin.* = undefined;
    }

    /// The first listen address, with its port resolved.
    pub fn address(origin: *const Origin) net.IpAddress {
        return origin.listeners.items[0].socket.address;
    }

    /// Serves `text` (the config's `policy_text`) from now on.
    pub fn publish(origin: *Origin, text: []const u8) std.mem.Allocator.Error!void {
        const copy = try origin.gpa.dupe(u8, text);
        origin.mutex.lockUncancelable(origin.io);
        defer origin.mutex.unlock(origin.io);
        origin.gpa.free(origin.text);
        origin.text = copy;
        origin.fingerprint = fingerprintOf(copy);
    }

    fn serve(origin: *Origin, listener: *net.Server) Io.Cancelable!void {
        const io = origin.io;
        while (true) {
            const stream = listener.accept(io) catch |err| switch (err) {
                error.Canceled => |e| return e,
                else => {
                    log.debug("accept: {t}", .{err});
                    try io.sleep(.fromMilliseconds(100), .awake);
                    continue;
                },
            };
            defer stream.close(io);
            // Before reading anything: a client that may not sync must not
            // get to hold the only serve task for a request's deadline.
            if (!ip.isAllowed(origin.allow_clients, stream.socket.address)) continue;
            origin.handle(stream) catch |err| {
                if (err == error.Canceled) return error.Canceled;
                log.debug("request from {f}: {t}", .{ stream.socket.address, err });
            };
        }
    }

    fn handle(origin: *Origin, stream: net.Stream) !void {
        const io = origin.io;
        const deadline = tcp.deadlineIn(io, request_timeout_ms);
        var in_buf: [4096]u8 = undefined;
        var out_buf: [4096]u8 = undefined;
        var reader: tcp.DeadlineReader = .init(io, stream.socket.handle, &in_buf, deadline);
        var writer: tcp.DeadlineWriter = .init(io, stream.socket.handle, &out_buf, deadline);
        var server: std.http.Server = .init(&reader.interface, &writer.interface);
        origin.answer(&server) catch |err| {
            // The deadline streams report every socket error as ReadFailed or
            // WriteFailed. A cancellation hidden in there must still end the
            // task: swallowed, it would leave `deinit` waiting forever.
            if (reader.err) |socket_err| if (socket_err == error.Canceled) return error.Canceled;
            if (writer.err) |socket_err| if (socket_err == error.Canceled) return error.Canceled;
            return err;
        };
    }

    fn answer(origin: *Origin, server: *std.http.Server) !void {
        const io = origin.io;
        var request = try server.receiveHead();
        if (request.head.method != .GET or !std.mem.eql(u8, request.head.target, path)) {
            return request.respond("", .{ .status = .not_found, .keep_alive = false });
        }

        var if_none_match: ?[]const u8 = null;
        var nonce: ?*const Nonce = null;
        var headers = request.iterateHeaders();
        while (headers.next()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "if-none-match")) if_none_match = header.value;
            if (std.ascii.eqlIgnoreCase(header.name, nonce_header) and header.value.len == @sizeOf(Nonce)) {
                nonce = header.value[0..@sizeOf(Nonce)];
            }
        }
        const challenge = nonce orelse return request.respond("", .{ .status = .bad_request, .keep_alive = false });

        // A copy, so a slow client never holds the lock `publish` needs.
        const text, const fingerprint = snapshot: {
            origin.mutex.lockUncancelable(io);
            defer origin.mutex.unlock(io);
            break :snapshot .{ try origin.gpa.dupe(u8, origin.text), origin.fingerprint };
        };
        defer origin.gpa.free(text);
        const tag = etag(fingerprint);
        const unchanged = if (if_none_match) |value| std.mem.eql(u8, value, &tag) else false;
        const status: std.http.Status = if (unchanged) .not_modified else .ok;
        const body = if (unchanged) "" else text;
        const signature = std.fmt.bytesToHex(sign(origin.secret, challenge, status, fingerprint, body), .lower);
        try request.respond(body, .{
            .status = status,
            .keep_alive = false,
            .extra_headers = &.{
                .{ .name = "etag", .value = &tag },
                .{ .name = signature_header, .value = &signature },
            },
        });
    }
};

/// What a replica got from its origin.
pub const Fetched = union(enum) {
    unchanged,
    changed: Synced,

    pub fn deinit(fetched: *Fetched, gpa: std.mem.Allocator) void {
        switch (fetched.*) {
            .unchanged => {},
            .changed => |synced| gpa.free(synced.text),
        }
        fetched.* = undefined;
    }
};

/// Policy settings as received from the origin, with the proof that it sent
/// them.
pub const Synced = struct {
    text: []u8,
    fingerprint: Fingerprint,
    nonce: Nonce,
    signature: Signature,
};

/// Asks the origin at `url` (e.g. http://192.168.1.5:5380) for its Policy
/// settings; `have` is the fingerprint of the ones the replica has. A
/// replica keeps one `client` for all syncs, so an https:// origin does not
/// cost a rescan of the system's CA certificates on every sync.
pub fn fetch(client: *std.http.Client, url: []const u8, secret: []const u8, have: ?Fingerprint) !Fetched {
    const io = client.io;
    const gpa = client.allocator;
    var nonce_bytes: [@sizeOf(Nonce) / 2]u8 = undefined;
    io.random(&nonce_bytes);
    const nonce: Nonce = std.fmt.bytesToHex(nonce_bytes, .lower);

    var url_buf: [512]u8 = undefined;
    const full_url = std.fmt.bufPrint(&url_buf, "{s}{s}", .{ std.mem.trimEnd(u8, url, "/"), path }) catch return error.InvalidUrl;
    const uri = std.Uri.parse(full_url) catch return error.InvalidUrl;

    const have_tag = if (have) |fingerprint| etag(fingerprint) else undefined;
    const headers = [_]std.http.Header{
        .{ .name = nonce_header, .value = &nonce },
        .{ .name = "if-none-match", .value = &have_tag },
    };
    var request = try client.request(.GET, uri, .{
        .keep_alive = false,
        .redirect_behavior = .not_allowed,
        .headers = .{ .user_agent = .{ .override = "zinkhole" } },
        .extra_headers = if (have != null) &headers else headers[0..1],
    });
    defer request.deinit();
    try request.sendBodiless();
    var redirect_buf: [1024]u8 = undefined;
    var response = try request.receiveHead(&redirect_buf);
    const status = response.head.status;
    if (status != .ok and status != .not_modified) return error.UnexpectedStatus;

    // Header strings are only valid until the body is read.
    var fingerprint: ?Fingerprint = null;
    var signature: ?Signature = null;
    var it = response.head.iterateHeaders();
    while (it.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "etag")) fingerprint = parseEtag(header.value);
        if (std.ascii.eqlIgnoreCase(header.name, signature_header)) signature = parseHex(Signature, header.value);
    }
    const claimed = fingerprint orelse return error.BadSignature;
    const proof = signature orelse return error.BadSignature;

    if (status == .not_modified) {
        const expected = sign(secret, &nonce, status, claimed, "");
        if (!std.crypto.timing_safe.eql(Signature, expected, proof)) return error.BadSignature;
        // Signed, but about another version than the replica's: not unchanged.
        if (have == null or !std.mem.eql(u8, &have.?, &claimed)) return error.BadSignature;
        return .unchanged;
    }

    var transfer_buf: [4096]u8 = undefined;
    const body = response.reader(&transfer_buf).allocRemaining(gpa, .limited(max_text_len)) catch |err| switch (err) {
        error.ReadFailed => return response.bodyErr() orelse error.ReadFailed,
        else => |e| return e,
    };
    errdefer gpa.free(body);
    const expected = sign(secret, &nonce, status, claimed, body);
    if (!std.crypto.timing_safe.eql(Signature, expected, proof)) return error.BadSignature;
    if (!std.mem.eql(u8, &claimed, &fingerprintOf(body))) return error.BadSignature;
    return .{ .changed = .{ .text = body, .fingerprint = claimed, .nonce = nonce, .signature = proof } };
}

/// `"<64 hex digits>"`, as `etag` writes it.
fn parseEtag(value: []const u8) ?Fingerprint {
    if (value.len != 66 or value[0] != '"' or value[65] != '"') return null;
    return parseHex(Fingerprint, value[1..65]);
}

fn parseHex(comptime T: type, hex: []const u8) ?T {
    var bytes: T = undefined;
    if (hex.len != bytes.len * 2) return null;
    _ = std.fmt.hexToBytes(&bytes, hex) catch return null;
    return bytes;
}

/// A replica's copy of its last synced settings, in its state directory.
pub const state_file = "synced.yaml";
const state_header = "# zinkhole sync ";

/// Writes `synced` to the state file: the proof as a comment line, then the
/// text, so the file stays valid YAML and can be appended to a config to
/// promote the replica. Written to a temporary file, flushed to disk, and
/// renamed, so neither a crash nor a power loss leaves half a file.
pub fn saveState(io: Io, dir: Io.Dir, synced: Synced) !void {
    const tmp_name = state_file ++ ".tmp";
    {
        var file = try dir.createFile(io, tmp_name, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, state_header);
        try file.writeStreamingAll(io, &synced.nonce);
        try file.writeStreamingAll(io, " ");
        try file.writeStreamingAll(io, &std.fmt.bytesToHex(synced.signature, .lower));
        try file.writeStreamingAll(io, "\n");
        try file.writeStreamingAll(io, synced.text);
        // Without this, the rename can reach the disk before the data does.
        try file.sync(io);
    }
    try dir.rename(tmp_name, dir, state_file, io);
    // Make the rename itself durable (best effort: not every file system
    // lets a directory be synced).
    var dir_file = dir.openFile(io, ".", .{ .allow_directory = true }) catch return;
    defer dir_file.close(io);
    dir_file.sync(io) catch {};
}

/// Reads the state file; null if there is none. A file whose signature does
/// not match its text (or the secret) is rejected.
pub fn loadState(io: Io, gpa: std.mem.Allocator, dir: Io.Dir, secret: []const u8) !?Synced {
    const saved = dir.readFileAlloc(io, state_file, gpa, .limited(max_text_len + 256)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => |e| return e,
    };
    defer gpa.free(saved);
    const newline = std.mem.findScalar(u8, saved, '\n') orelse return error.BadSignature;
    const header = saved[0..newline];
    const proof_len = state_header.len + @sizeOf(Nonce) + 1 + @sizeOf(Signature) * 2;
    if (header.len != proof_len or !std.mem.startsWith(u8, header, state_header)) return error.BadSignature;
    const nonce: Nonce = header[state_header.len..][0..@sizeOf(Nonce)].*;
    const signature = parseHex(Signature, header[state_header.len + @sizeOf(Nonce) + 1 ..]) orelse return error.BadSignature;

    const text = saved[newline + 1 ..];
    const fingerprint = fingerprintOf(text);
    if (!std.crypto.timing_safe.eql(Signature, sign(secret, &nonce, .ok, fingerprint, text), signature)) {
        return error.BadSignature;
    }
    return .{ .text = try gpa.dupe(u8, text), .fingerprint = fingerprint, .nonce = nonce, .signature = signature };
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

const test_secret = "0123456789abcdef0123456789abcdef";

/// Turns a test that hangs into one that fails: panics if still running
/// after `seconds`, unless stopped first.
const Watchdog = struct {
    future: Io.Future(void),

    fn start(seconds: i64) !Watchdog {
        return .{ .future = try testing.io.concurrent(bark, .{seconds}) };
    }

    fn stop(watchdog: *Watchdog) void {
        watchdog.future.cancel(testing.io);
    }

    fn bark(seconds: i64) void {
        testing.io.sleep(.fromSeconds(seconds), .awake) catch return; // stopped in time
        @panic("test timed out (watchdog)");
    }
};
const loopback_clients = [_]ip.Cidr{ip.Cidr.parse("127.0.0.0/8").?};

/// `fetch` with a client of its own.
fn testFetch(url: []const u8, secret: []const u8, have: ?Fingerprint) !Fetched {
    var client: std.http.Client = .{ .allocator = testing.allocator, .io = testing.io };
    defer client.deinit();
    return fetch(&client, url, secret, have);
}

/// An origin serving on an ephemeral loopback port.
fn testOrigin(origin: *Origin, allow_clients: []const ip.Cidr) !void {
    try origin.init(testing.io, testing.allocator, &.{.{ .ip4 = .loopback(0) }}, test_secret, allow_clients);
}

fn originUrl(origin: *const Origin, buf: []u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "http://{f}", .{origin.address()});
}

test "a replica fetches the Policy settings the origin publishes" {
    var origin: Origin = undefined;
    try testOrigin(&origin, &loopback_clients);
    defer origin.deinit();
    const text = "local:\n  records:\n    nas.lan: 10.0.0.10\n";
    try origin.publish(text);

    var url_buf: [64]u8 = undefined;
    var fetched = try testFetch(try originUrl(&origin, &url_buf), test_secret, null);
    defer fetched.deinit(testing.allocator);
    try testing.expect(fetched == .changed);
    try testing.expectEqualStrings(text, fetched.changed.text);
}

test "unchanged settings are reported as unchanged, until the origin publishes" {
    var origin: Origin = undefined;
    try testOrigin(&origin, &loopback_clients);
    defer origin.deinit();
    try origin.publish("local:\n  ttl: 60\n");
    var url_buf: [64]u8 = undefined;
    const url = try originUrl(&origin, &url_buf);

    var first = try testFetch(url, test_secret, null);
    defer first.deinit(testing.allocator);
    const have = first.changed.fingerprint;

    var again = try testFetch(url, test_secret, have);
    defer again.deinit(testing.allocator);
    try testing.expect(again == .unchanged);

    try origin.publish("local:\n  ttl: 120\n");
    var changed = try testFetch(url, test_secret, have);
    defer changed.deinit(testing.allocator);
    try testing.expectEqualStrings("local:\n  ttl: 120\n", changed.changed.text);
    try testing.expect(!std.mem.eql(u8, &have, &changed.changed.fingerprint));
}

/// Sits between a replica and its origin, and can tamper with or replay the
/// origin's answers, as an attacker on the LAN could.
const Proxy = struct {
    listener: net.Server,
    origin: net.IpAddress,
    mode: Mode,
    group: Io.Group = .init,
    /// The first answer, for `replay`.
    recorded: ?[]u8 = null,

    const Mode = enum { tamper, replay };

    fn start(proxy: *Proxy, origin: net.IpAddress, mode: Mode) !void {
        const loopback: net.IpAddress = .{ .ip4 = .loopback(0) };
        proxy.* = .{ .listener = try loopback.listen(testing.io, .{ .reuse_address = true }), .origin = origin, .mode = mode };
        try proxy.group.concurrent(testing.io, run, .{proxy});
    }

    fn stop(proxy: *Proxy) void {
        proxy.group.cancel(testing.io);
        proxy.listener.deinit(testing.io);
        if (proxy.recorded) |bytes| testing.allocator.free(bytes);
    }

    fn url(proxy: *const Proxy, buf: []u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "http://{f}", .{proxy.listener.socket.address});
    }

    fn run(proxy: *Proxy) Io.Cancelable!void {
        while (true) {
            const client = proxy.listener.accept(testing.io) catch |err| switch (err) {
                error.Canceled => |e| return e,
                else => continue,
            };
            defer client.close(testing.io);
            proxy.relay(client) catch |err| if (err == error.Canceled) return error.Canceled;
        }
    }

    fn relay(proxy: *Proxy, client: net.Stream) !void {
        const io = testing.io;
        var request_buf: [4096]u8 = undefined;
        var client_reader = client.reader(io, &request_buf);
        var request: std.ArrayList(u8) = .empty;
        defer request.deinit(testing.allocator);
        while (true) { // a GET has no body: the head ends with an empty line
            const line = try client_reader.interface.takeDelimiterInclusive('\n');
            try request.appendSlice(testing.allocator, line);
            if (std.mem.eql(u8, line, "\r\n")) break;
        }

        const origin = try proxy.origin.connect(io, .{ .mode = .stream, .protocol = .tcp });
        defer origin.close(io);
        var origin_write_buf: [256]u8 = undefined;
        var origin_writer = origin.writer(io, &origin_write_buf);
        try origin_writer.interface.writeAll(request.items);
        try origin_writer.interface.flush();
        var origin_read_buf: [4096]u8 = undefined;
        var origin_reader = origin.reader(io, &origin_read_buf);
        const answer = try origin_reader.interface.allocRemaining(testing.allocator, .unlimited);
        defer testing.allocator.free(answer);

        const forwarded: []const u8 = switch (proxy.mode) {
            .tamper => tamper: {
                answer[answer.len - 1] ^= 0x01; // the last byte of the body
                break :tamper answer;
            },
            .replay => replay: {
                if (proxy.recorded == null) proxy.recorded = try testing.allocator.dupe(u8, answer);
                break :replay proxy.recorded.?;
            },
        };
        var client_write_buf: [256]u8 = undefined;
        var client_writer = client.writer(io, &client_write_buf);
        try client_writer.interface.writeAll(forwarded);
        try client_writer.interface.flush();
    }
};

test "answers signed with another secret are rejected" {
    var origin: Origin = undefined;
    try testOrigin(&origin, &loopback_clients);
    defer origin.deinit();
    try origin.publish("local:\n  ttl: 60\n");
    var url_buf: [64]u8 = undefined;
    const other_secret = "fedcba9876543210fedcba9876543210";
    try testing.expectError(error.BadSignature, testFetch(try originUrl(&origin, &url_buf), other_secret, null));
}

test "answers changed on the way are rejected" {
    var origin: Origin = undefined;
    try testOrigin(&origin, &loopback_clients);
    defer origin.deinit();
    try origin.publish("local:\n  ttl: 60\n");
    var proxy: Proxy = undefined;
    try proxy.start(origin.address(), .tamper);
    defer proxy.stop();
    var url_buf: [64]u8 = undefined;
    try testing.expectError(error.BadSignature, testFetch(try proxy.url(&url_buf), test_secret, null));
}

test "replayed answers are rejected, including 'unchanged'" {
    var origin: Origin = undefined;
    try testOrigin(&origin, &loopback_clients);
    defer origin.deinit();
    try origin.publish("local:\n  ttl: 60\n");
    var url_buf: [64]u8 = undefined;

    // A recorded full answer, replayed to a later request.
    var replay: Proxy = undefined;
    try replay.start(origin.address(), .replay);
    defer replay.stop();
    const url = try replay.url(&url_buf);
    var first = try testFetch(url, test_secret, null);
    defer first.deinit(testing.allocator);
    try testing.expectError(error.BadSignature, testFetch(url, test_secret, null));

    // A recorded "unchanged", replayed after the settings changed.
    var replay_unchanged: Proxy = undefined;
    try replay_unchanged.start(origin.address(), .replay);
    defer replay_unchanged.stop();
    var url2_buf: [64]u8 = undefined;
    const url2 = try replay_unchanged.url(&url2_buf);
    var unchanged = try testFetch(url2, test_secret, first.changed.fingerprint);
    defer unchanged.deinit(testing.allocator);
    try testing.expect(unchanged == .unchanged);
    try origin.publish("local:\n  ttl: 120\n");
    try testing.expectError(error.BadSignature, testFetch(url2, test_secret, first.changed.fingerprint));
}

/// The status the origin answers a bare request with.
fn statusOf(method: std.http.Method, url: []const u8) !std.http.Status {
    var client: std.http.Client = .{ .allocator = testing.allocator, .io = testing.io };
    defer client.deinit();
    var request = try client.request(method, try std.Uri.parse(url), .{
        .keep_alive = false,
        .extra_headers = &.{.{ .name = nonce_header, .value = &@as(Nonce, @splat('0')) }},
    });
    defer request.deinit();
    if (method == .POST) try request.sendBodyComplete(@constCast("x")) else try request.sendBodiless();
    var redirect_buf: [1024]u8 = undefined;
    return (try request.receiveHead(&redirect_buf)).head.status;
}

test "only allowed clients get answers, and only at GET /sync" {
    var origin: Origin = undefined;
    try testOrigin(&origin, &loopback_clients);
    defer origin.deinit();
    try origin.publish("local:\n  ttl: 60\n");
    var url_buf: [64]u8 = undefined;
    const base = try originUrl(&origin, &url_buf);
    var path_buf: [96]u8 = undefined;

    try testing.expectEqual(.ok, try statusOf(.GET, try std.fmt.bufPrint(&path_buf, "{s}/sync", .{base})));
    try testing.expectEqual(.not_found, try statusOf(.GET, try std.fmt.bufPrint(&path_buf, "{s}/config", .{base})));
    try testing.expectEqual(.not_found, try statusOf(.POST, try std.fmt.bufPrint(&path_buf, "{s}/sync", .{base})));

    var lan_only: Origin = undefined;
    try testOrigin(&lan_only, &.{ip.Cidr.parse("192.168.0.0/16").?});
    defer lan_only.deinit();
    try lan_only.publish("local:\n  ttl: 60\n");
    var lan_buf: [64]u8 = undefined;
    if (testFetch(try originUrl(&lan_only, &lan_buf), test_secret, null)) |fetched| {
        var unexpected = fetched;
        unexpected.deinit(testing.allocator);
        return error.TestUnexpectedResult;
    } else |_| {}
}

test "the state file keeps the last synced settings, and rejects tampering" {
    var origin: Origin = undefined;
    try testOrigin(&origin, &loopback_clients);
    defer origin.deinit();
    const text = "local:\n  records:\n    nas.lan: 10.0.0.10\n";
    try origin.publish(text);
    var url_buf: [64]u8 = undefined;
    var fetched = try testFetch(try originUrl(&origin, &url_buf), test_secret, null);
    defer fetched.deinit(testing.allocator);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try testing.expectEqual(null, try loadState(testing.io, testing.allocator, tmp.dir, test_secret));

    try saveState(testing.io, tmp.dir, fetched.changed);
    const loaded = (try loadState(testing.io, testing.allocator, tmp.dir, test_secret)).?;
    defer testing.allocator.free(loaded.text);
    try testing.expectEqualStrings(text, loaded.text);
    try testing.expectEqual(fetched.changed.fingerprint, loaded.fingerprint);

    // The file is valid YAML: the proof is a comment above the settings.
    const saved = try tmp.dir.readFileAlloc(testing.io, state_file, testing.allocator, .limited(4096));
    defer testing.allocator.free(saved);
    try testing.expect(std.mem.startsWith(u8, saved, "# "));
    try testing.expect(std.mem.endsWith(u8, saved, text));

    const tampered = try std.mem.replaceOwned(u8, testing.allocator, saved, "10.0.0.10", "10.6.6.6");
    defer testing.allocator.free(tampered);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = state_file, .data = tampered });
    try testing.expectError(error.BadSignature, loadState(testing.io, testing.allocator, tmp.dir, test_secret));
}

test "an origin that cannot listen on an address fails cleanly" {
    var origin: Origin = undefined;
    // 192.0.2.1 (a documentation address) is not on this host.
    const addresses = [_]net.IpAddress{ .{ .ip4 = .loopback(0) }, .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 5380 } } };
    if (origin.init(testing.io, testing.allocator, &addresses, test_secret, &loopback_clients)) |_| {
        origin.deinit();
        return error.TestUnexpectedResult;
    } else |_| {}
}

test "connections from clients outside the allowed networks are closed before reading" {
    var watchdog: Watchdog = try .start(10);
    defer watchdog.stop();
    var origin: Origin = undefined;
    try testOrigin(&origin, &.{ip.Cidr.parse("192.168.0.0/16").?});
    defer origin.deinit();
    const stream = try origin.address().connect(testing.io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(testing.io);

    // Sending nothing must not keep the origin's only serve task busy.
    var buf: [16]u8 = undefined;
    var reader: tcp.DeadlineReader = .init(testing.io, stream.socket.handle, &buf, tcp.deadlineIn(testing.io, 1000));
    try testing.expectError(error.EndOfStream, reader.interface.takeByte());
}

test "shutting down while a request is half-received does not hang" {
    var watchdog: Watchdog = try .start(10);
    defer watchdog.stop();
    var origin: Origin = undefined;
    try testOrigin(&origin, &loopback_clients);
    const stream = try origin.address().connect(testing.io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(testing.io);
    // Half a request head: the origin's serve task is now waiting for more.
    var write_buf: [64]u8 = undefined;
    var writer = stream.writer(testing.io, &write_buf);
    try writer.interface.writeAll("GET /sync HTTP/1.1\r\n");
    try writer.interface.flush();
    try testing.io.sleep(.fromMilliseconds(100), .awake);

    origin.deinit(); // must cancel the serve task, not wait forever
}

test "no other socket can take over the sync port" {
    var origin: Origin = undefined;
    try testOrigin(&origin, &loopback_clients);
    defer origin.deinit();
    if (origin.address().listen(testing.io, .{ .reuse_address = true })) |intruder| {
        var listener = intruder;
        listener.deinit(testing.io);
        return error.TestUnexpectedResult;
    } else |err| try testing.expectEqual(error.AddressInUse, err);
}
