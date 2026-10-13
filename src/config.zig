//! Configuration: loads the YAML file into typed, validated settings.
//!
//! Unknown keys are errors (a typo must not silently disable a setting), and
//! every error names the line it was found on.

const std = @import("std");
const Io = std.Io;
const net = std.Io.net;
const Allocator = std.mem.Allocator;

const yaml = @import("yaml.zig");
const dns = @import("dns.zig");
const ip = @import("ip.zig");
const local = @import("local.zig");
const blocklist = @import("blocklist.zig");
const upstream_mod = @import("upstream.zig");

const log = std.log.scoped(.config);

const max_file_size = 1024 * 1024;

pub const Config = struct {
    /// Owns all strings and slices below.
    arena: std.heap.ArenaAllocator,
    server: Server = .{},
    upstream: Upstream = .{},
    cache: Cache = .{},
    blocking: Blocking = .{},
    local: Local = .{},
    log: Log = .{},
    sync: Sync = .none,
    /// Null when metrics are not served.
    metrics: ?Metrics = null,
    /// The `blocking:` and `local:` sections exactly as written (comments
    /// included): what an origin serves to its replicas.
    policy_text: []const u8 = "",
    /// The file's text, which a replica combines with each sync.
    source: []const u8 = "",

    pub const Server = struct {
        listen: []const net.IpAddress = &default_listen,
        /// Only clients in these networks may query.
        allow_clients: []const ip.Cidr = &default_allow_clients,
        /// UDP worker threads per listen address.
        workers: u16 = 4,
    };

    pub const Upstream = struct {
        servers: []const upstream_mod.ServerAddress = &.{},
        timeout_ms: u32 = 2000,
        /// Upstream queries in flight at once (the forwarding slots, ADR-0005).
        max_in_flight: u16 = 64,
    };

    pub const Cache = struct {
        /// Maximum number of cached responses; 0 disables the cache.
        size: u32 = 4096,
        min_ttl: u32 = 0,
        max_ttl: u32 = 86400,
    };

    pub const BlockResponse = enum {
        /// 0.0.0.0 for A, :: for AAAA, an empty answer for other types.
        zero,
        nxdomain,
    };

    pub const Blocking = struct {
        response: BlockResponse = .zero,
        ttl: u32 = 300,
        /// Download the lists again this often; 0 means only at start, and when a
        /// reload changes the lists.
        refresh_hours: u32 = 24,
        /// Blocklist URLs or file paths.
        lists: []const []const u8 = &.{},
        /// Allowlist URLs or file paths; allow rules beat block rules.
        allowlists: []const []const u8 = &.{},
        /// Inline rules, in any list syntax.
        block: []const []const u8 = &.{},
        allow: []const []const u8 = &.{},
    };

    pub const PrivateNames = enum {
        /// Answer NXDOMAIN when no local record matches.
        nxdomain,
        /// Send them upstream (e.g. to a router that knows DHCP hostnames).
        forward,
    };

    pub const Local = struct {
        ttl: u32 = 300,
        private_names: PrivateNames = .nxdomain,
        records: []const local.Record = &.{},
    };

    pub const Log = struct {
        level: std.log.Level = .info,
        /// Log every query with client, name, type and outcome.
        queries: bool = false,
    };

    /// Whether this instance serves its Policy settings to replicas, takes
    /// them from an origin, or neither.
    pub const Sync = union(enum) {
        none,
        origin: Origin,
        replica: Replica,

        pub const Origin = struct {
            /// HTTP listen addresses for replicas.
            serve: []const net.IpAddress,
            secret: []const u8,
        };

        pub const Replica = struct {
            /// The origin's URL, e.g. http://192.168.1.5:5380.
            origin: []const u8,
            secret: []const u8,
            /// Seconds between syncs.
            interval: u32,
            /// Where the replica keeps its last synced settings.
            state_dir: []const u8,
        };
    };

    pub const Metrics = struct {
        /// HTTP listen addresses for `GET /metrics`.
        listen: []const net.IpAddress,
    };

    pub const min_secret_len = 32;

    pub fn deinit(config: *Config) void {
        config.arena.deinit();
        config.* = undefined;
    }
};

const default_listen = [_]net.IpAddress{
    .{ .ip4 = .unspecified(53) },
    .{ .ip6 = .unspecified(53) },
};

/// Loopback, private (RFC 1918, RFC 4193), link-local and CGNAT networks.
const default_allow_clients = [_]ip.Cidr{
    ip.Cidr.parse("127.0.0.0/8").?,
    ip.Cidr.parse("10.0.0.0/8").?,
    ip.Cidr.parse("172.16.0.0/12").?,
    ip.Cidr.parse("192.168.0.0/16").?,
    ip.Cidr.parse("169.254.0.0/16").?,
    ip.Cidr.parse("100.64.0.0/10").?,
    ip.Cidr.parse("::1/128").?,
    ip.Cidr.parse("fc00::/7").?,
    ip.Cidr.parse("fe80::/10").?,
};

/// Describes why loading failed.
pub const Diagnostic = struct {
    /// 0 when the problem is not tied to a line.
    line: u32 = 0,
    /// The line is in the settings synced from the origin, not in the file.
    from_origin: bool = false,
    buf: [256]u8 = undefined,
    len: usize = 0,

    pub fn message(diag: *const Diagnostic) []const u8 {
        return diag.buf[0..diag.len];
    }

    fn fail(diag: *Diagnostic, line: u32, comptime format: []const u8, args: anytype) error{InvalidConfig} {
        diag.line = line;
        // A message too long for the buffer is cut off.
        const text: []const u8 = std.fmt.bufPrint(&diag.buf, format, args) catch &diag.buf;
        diag.len = text.len;
        return error.InvalidConfig;
    }
};

pub const Error = error{ InvalidConfig, OutOfMemory };

pub fn load(io: Io, gpa: Allocator, path: []const u8, diag: *Diagnostic) Error!Config {
    const source = Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_file_size)) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        error.StreamTooLong => return diag.fail(0, "file is larger than 1 MiB", .{}),
        else => return diag.fail(0, "cannot read file: {t}", .{err}),
    };
    defer gpa.free(source);
    return parse(gpa, source, diag);
}

pub fn parse(gpa: Allocator, source: []const u8, diag: *Diagnostic) Error!Config {
    var tree_arena: std.heap.ArenaAllocator = .init(gpa);
    defer tree_arena.deinit();
    var yaml_diag: yaml.Diagnostic = .{};
    const root = yaml.parse(tree_arena.allocator(), source, &yaml_diag) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        error.InvalidYaml => return diag.fail(yaml_diag.line, "{s}", .{yaml_diag.message}),
    };

    var config: Config = .{ .arena = .init(gpa) };
    errdefer config.deinit();
    var decoder: Decoder = .{ .arena = config.arena.allocator(), .scratch = tree_arena.allocator(), .diag = diag };
    try decoder.decodeRoot(root, &config);
    config.policy_text = try policyText(config.arena.allocator(), source, root);
    config.source = try config.arena.allocator().dupe(u8, source);
    return config;
}

/// A replica's config: its own file's `source` plus the Policy settings
/// `synced` from its origin (the origin's `policy_text`).
pub fn parseReplica(gpa: Allocator, source: []const u8, synced: []const u8, diag: *Diagnostic) Error!Config {
    var config = try parse(gpa, source, diag);
    errdefer config.deinit();
    diag.from_origin = true;
    var tree_arena: std.heap.ArenaAllocator = .init(gpa);
    defer tree_arena.deinit();
    var yaml_diag: yaml.Diagnostic = .{};
    const root = yaml.parse(tree_arena.allocator(), synced, &yaml_diag) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        error.InvalidYaml => return diag.fail(yaml_diag.line, "{s}", .{yaml_diag.message}),
    };
    var decoder: Decoder = .{ .arena = config.arena.allocator(), .scratch = tree_arena.allocator(), .diag = diag };
    for (try decoder.mapping(root, "top level")) |pair| {
        if (is(pair, "blocking")) {
            try decoder.decodeBlocking(pair.value, &config.blocking);
        } else if (is(pair, "local")) {
            try decoder.decodeLocal(pair.value, &config.local);
        } else {
            return diag.fail(pair.line, "the origin may only send 'blocking' and 'local', not '{s}'", .{pair.key});
        }
    }
    diag.from_origin = false;
    config.policy_text = try config.arena.allocator().dupe(u8, synced);
    return config;
}

/// The text of the `blocking:` and `local:` sections, each from its key's
/// line up to the next top-level key, so comments and formatting are kept.
fn policyText(arena: Allocator, source: []const u8, root: yaml.Node) Allocator.Error![]const u8 {
    const pairs = switch (root.value) {
        .mapping => |pairs| pairs,
        else => return "",
    };
    var text: std.ArrayList(u8) = .empty;
    for (pairs, 0..) |pair, i| {
        if (!is(pair, "blocking") and !is(pair, "local")) continue;
        const start = lineStart(source, pair.line);
        const end = if (i + 1 < pairs.len) lineStart(source, pairs[i + 1].line) else source.len;
        try text.appendSlice(arena, source[start..end]);
        if (text.items[text.items.len - 1] != '\n') try text.append(arena, '\n');
    }
    return text.items;
}

/// Byte offset at which the 1-based `line` starts.
fn lineStart(source: []const u8, line: u32) usize {
    var offset: usize = 0;
    for (1..line) |_| {
        offset = (std.mem.findScalarPos(u8, source, offset, '\n') orelse return source.len) + 1;
    }
    return offset;
}

/// Turns the YAML tree into a `Config`, copying kept strings into `arena`.
const Decoder = struct {
    arena: Allocator,
    /// Freed when parsing ends; for bookkeeping that the config does not keep.
    scratch: Allocator,
    diag: *Diagnostic,

    fn fail(d: *Decoder, line: u32, comptime format: []const u8, args: anytype) error{InvalidConfig} {
        return d.diag.fail(line, format, args);
    }

    fn decodeRoot(d: *Decoder, root: yaml.Node, config: *Config) Error!void {
        // Lines of the sections a replica takes from its origin instead.
        var policy_line: ?u32 = null;
        var metrics_line: u32 = 0;
        for (try d.mapping(root, "top level")) |pair| {
            if (is(pair, "blocking") or is(pair, "local")) policy_line = policy_line orelse pair.line;
            if (is(pair, "server")) {
                try d.decodeServer(pair.value, &config.server);
            } else if (is(pair, "upstream")) {
                try d.decodeUpstream(pair.value, &config.upstream);
            } else if (is(pair, "cache")) {
                try d.decodeCache(pair.value, &config.cache);
            } else if (is(pair, "blocking")) {
                try d.decodeBlocking(pair.value, &config.blocking);
            } else if (is(pair, "local")) {
                try d.decodeLocal(pair.value, &config.local);
            } else if (is(pair, "log")) {
                try d.decodeLog(pair.value, &config.log);
            } else if (is(pair, "sync")) {
                config.sync = try d.decodeSync(pair);
            } else if (is(pair, "metrics")) {
                config.metrics = try d.decodeMetrics(pair.value);
                metrics_line = pair.line;
            } else {
                return d.fail(pair.line, "unknown section '{s}'", .{pair.key});
            }
        }
        if (config.metrics) |metrics| {
            try d.checkPortsFree(metrics_line, "metrics.listen", metrics.listen, "server.listen", config.server.listen);
            if (config.sync == .origin) try d.checkPortsFree(metrics_line, "metrics.listen", metrics.listen, "sync.serve", config.sync.origin.serve);
        }
        if (config.sync == .replica) {
            if (policy_line) |line| {
                return d.fail(line, "'blocking' and 'local' are synced from the origin; remove them from a replica's config", .{});
            }
        }
        if (config.upstream.servers.len == 0) {
            return d.fail(0, "upstream.servers: at least one upstream DNS server is required", .{});
        }
    }

    fn decodeServer(d: *Decoder, node: yaml.Node, server: *Config.Server) Error!void {
        for (try d.mapping(node, "server")) |pair| {
            if (is(pair, "listen")) {
                server.listen = try d.socketAddresses(pair);
            } else if (is(pair, "allow_clients")) {
                const items = try d.nonEmptyList(pair);
                const networks = try d.arena.alloc(ip.Cidr, items.len);
                for (items, networks) |item, *network| {
                    network.* = ip.Cidr.parse(try d.scalar(item, pair.key)) orelse
                        return d.fail(item.line, "invalid network '{s}' (expected e.g. 192.168.0.0/16)", .{item.value.scalar});
                }
                server.allow_clients = networks;
            } else if (is(pair, "workers")) {
                server.workers = try d.integer(u16, pair, 1, 64);
            } else {
                return d.unknownKey(pair, "server");
            }
        }
    }

    fn decodeUpstream(d: *Decoder, node: yaml.Node, upstream: *Config.Upstream) Error!void {
        for (try d.mapping(node, "upstream")) |pair| {
            if (is(pair, "servers")) {
                upstream.servers = try d.upstreamServers(pair);
            } else if (is(pair, "timeout_ms")) {
                upstream.timeout_ms = try d.integer(u32, pair, 100, 30_000);
            } else if (is(pair, "max_in_flight")) {
                upstream.max_in_flight = try d.integer(u16, pair, 1, 1024);
            } else {
                return d.unknownKey(pair, "upstream");
            }
        }
    }

    fn decodeCache(d: *Decoder, node: yaml.Node, cache: *Config.Cache) Error!void {
        for (try d.mapping(node, "cache")) |pair| {
            if (is(pair, "size")) {
                cache.size = try d.integer(u32, pair, 0, 1_000_000);
            } else if (is(pair, "min_ttl")) {
                cache.min_ttl = try d.integer(u32, pair, 0, 604_800);
            } else if (is(pair, "max_ttl")) {
                cache.max_ttl = try d.integer(u32, pair, 0, 604_800);
            } else {
                return d.unknownKey(pair, "cache");
            }
        }
        if (cache.min_ttl > cache.max_ttl) return d.fail(node.line, "cache: min_ttl is larger than max_ttl", .{});
    }

    fn decodeBlocking(d: *Decoder, node: yaml.Node, blocking: *Config.Blocking) Error!void {
        for (try d.mapping(node, "blocking")) |pair| {
            if (is(pair, "response")) {
                blocking.response = try d.enumeration(Config.BlockResponse, pair);
            } else if (is(pair, "ttl")) {
                blocking.ttl = try d.integer(u32, pair, 0, 86_400);
            } else if (is(pair, "refresh_hours")) {
                blocking.refresh_hours = try d.integer(u32, pair, 0, 8760);
            } else if (is(pair, "lists")) {
                blocking.lists = try d.listSources(pair);
            } else if (is(pair, "allowlists")) {
                blocking.allowlists = try d.listSources(pair);
            } else if (is(pair, "block")) {
                blocking.block = try d.inlineRules(pair);
            } else if (is(pair, "allow")) {
                blocking.allow = try d.inlineRules(pair);
            } else {
                return d.unknownKey(pair, "blocking");
            }
        }
    }

    fn decodeLocal(d: *Decoder, node: yaml.Node, local_config: *Config.Local) Error!void {
        for (try d.mapping(node, "local")) |pair| {
            if (is(pair, "ttl")) {
                local_config.ttl = try d.integer(u32, pair, 0, 86_400);
            } else if (is(pair, "private_names")) {
                local_config.private_names = try d.enumeration(Config.PrivateNames, pair);
            } else if (is(pair, "records")) {
                local_config.records = try d.records(pair.value);
            } else {
                return d.unknownKey(pair, "local");
            }
        }
    }

    fn decodeSync(d: *Decoder, section: yaml.Pair) Error!Config.Sync {
        var serve: ?[]const net.IpAddress = null;
        var origin: ?[]const u8 = null;
        var secret: ?[]const u8 = null;
        var interval: u32 = 60;
        var state_dir: []const u8 = "/var/lib/zinkhole";
        for (try d.mapping(section.value, "sync")) |pair| {
            if (is(pair, "serve")) {
                serve = try d.httpAddresses(pair, 5380);
            } else if (is(pair, "origin")) {
                const url = try d.scalar(pair.value, pair.key);
                if (!blocklist.isUrl(url)) return d.fail(pair.value.line, "sync.origin must start with http:// or https://", .{});
                _ = std.Uri.parse(url) catch return d.fail(pair.value.line, "invalid URL '{s}'", .{url});
                origin = try d.arena.dupe(u8, url);
            } else if (is(pair, "secret")) {
                const text = try d.scalar(pair.value, pair.key);
                if (text.len < Config.min_secret_len) {
                    return d.fail(pair.value.line, "sync.secret must be at least {d} characters", .{Config.min_secret_len});
                }
                secret = try d.arena.dupe(u8, text);
            } else if (is(pair, "interval")) {
                interval = try d.integer(u32, pair, 1, 86_400);
            } else if (is(pair, "state_dir")) {
                state_dir = try d.arena.dupe(u8, try d.scalar(pair.value, pair.key));
            } else {
                return d.unknownKey(pair, "sync");
            }
        }
        if ((serve == null) == (origin == null)) {
            return d.fail(section.line, "sync: set either 'serve' (origin) or 'origin' (replica)", .{});
        }
        const key = secret orelse return d.fail(section.line, "sync needs a secret, the same on origin and replicas", .{});
        if (serve) |addresses| return .{ .origin = .{ .serve = addresses, .secret = key } };
        return .{ .replica = .{ .origin = origin.?, .secret = key, .interval = interval, .state_dir = state_dir } };
    }

    fn decodeMetrics(d: *Decoder, node: yaml.Node) Error!Config.Metrics {
        var listen: ?[]const net.IpAddress = null;
        for (try d.mapping(node, "metrics")) |pair| {
            if (is(pair, "listen")) {
                listen = try d.httpAddresses(pair, 9153);
            } else {
                return d.unknownKey(pair, "metrics");
            }
        }
        return .{ .listen = listen orelse return d.fail(node.line, "metrics needs 'listen', e.g. [\"192.168.1.5:9153\"]", .{}) };
    }

    /// HTTP listen addresses, each with a port.
    fn httpAddresses(d: *Decoder, pair: yaml.Pair, comptime example_port: u16) Error![]const net.IpAddress {
        const items = try d.nonEmptyList(pair);
        const addresses = try d.arena.alloc(net.IpAddress, items.len);
        for (items, addresses) |item, *address| {
            const text = try d.scalar(item, pair.key);
            address.* = ip.parseSocketAddress(text, 0) orelse
                return d.fail(item.line, "'{s}' is not an IP address with a port", .{text});
            if (address.getPort() == 0) return d.fail(item.line, "'{s}' needs a port, e.g. 192.168.1.5:{d}", .{ text, example_port });
        }
        return addresses;
    }

    /// TCP listeners of `name` and `other_name` must not take the same
    /// address and port; an unspecified address takes the port on all.
    fn checkPortsFree(d: *Decoder, line: u32, comptime name: []const u8, addresses: []const net.IpAddress, comptime other_name: []const u8, others: []const net.IpAddress) Error!void {
        for (addresses) |address| for (others) |other| {
            if (address.getPort() != other.getPort()) continue;
            if (address.eql(&other) or isUnspecified(address) or isUnspecified(other)) {
                return d.fail(line, name ++ ": port {d} is already in use by " ++ other_name, .{address.getPort()});
            }
        };
    }

    fn decodeLog(d: *Decoder, node: yaml.Node, log_config: *Config.Log) Error!void {
        for (try d.mapping(node, "log")) |pair| {
            if (is(pair, "level")) {
                const value = try d.scalar(pair.value, pair.key);
                const levels = [_]struct { []const u8, std.log.Level }{
                    .{ "error", .err }, .{ "warn", .warn }, .{ "info", .info }, .{ "debug", .debug },
                };
                for (levels) |entry| {
                    if (std.mem.eql(u8, value, entry[0])) {
                        log_config.level = entry[1];
                        break;
                    }
                } else return d.fail(pair.value.line, "log.level must be error, warn, info or debug", .{});
            } else if (is(pair, "queries")) {
                log_config.queries = try d.boolean(pair);
            } else {
                return d.unknownKey(pair, "log");
            }
        }
    }

    /// `name: address` or `name: [address, ...]`; `*.name` for wildcards.
    fn records(d: *Decoder, node: yaml.Node) Error![]const local.Record {
        const pairs = try d.mapping(node, "local.records");
        const result = try d.arena.alloc(local.Record, pairs.len);
        // Names seen so far: a hash set, as there can be tens of thousands.
        var exact_names: std.StringHashMapUnmanaged(void) = .empty;
        var wildcard_names: std.StringHashMapUnmanaged(void) = .empty;
        for (pairs, result) |pair, *record| {
            const wildcard = std.mem.startsWith(u8, pair.key, "*.");
            var name_buf: [dns.max_name_len]u8 = undefined;
            const normalized = dns.normalizeName(if (wildcard) pair.key[2..] else pair.key, &name_buf) orelse
                return d.fail(pair.line, "invalid hostname '{s}'", .{pair.key});
            const name = try d.arena.dupe(u8, normalized);
            const seen = if (wildcard) &wildcard_names else &exact_names;
            if ((try seen.getOrPut(d.scratch, name)).found_existing) {
                return d.fail(pair.line, "hostname '{s}' is defined twice", .{pair.key});
            }

            const values: []const yaml.Node = switch (pair.value.value) {
                .scalar => (&pair.value)[0..1],
                .sequence => |items| items,
                else => &.{},
            };
            if (values.len == 0) return d.fail(pair.line, "'{s}' needs at least one IP address", .{pair.key});
            if (values.len > local.max_addresses) {
                return d.fail(pair.line, "'{s}' has more than {d} addresses", .{ pair.key, local.max_addresses });
            }
            const addresses = try d.arena.alloc(ip.Ip, values.len);
            for (values, addresses) |value, *address| {
                const text = try d.scalar(value, pair.key);
                address.* = ip.Ip.parse(text) orelse
                    return d.fail(value.line, "'{s}' is not an IP address", .{text});
            }
            record.* = .{ .name = name, .wildcard = wildcard, .addresses = addresses };
        }
        return result;
    }

    fn socketAddresses(d: *Decoder, pair: yaml.Pair) Error![]const net.IpAddress {
        const items = try d.nonEmptyList(pair);
        const addresses = try d.arena.alloc(net.IpAddress, items.len);
        for (items, addresses) |item, *address| {
            const text = try d.scalar(item, pair.key);
            address.* = ip.parseSocketAddress(text, 53) orelse
                return d.fail(item.line, "'{s}' is not an IP address with optional port", .{text});
        }
        return addresses;
    }

    /// Plain DNS: `ip`, `ip:port`, `[ipv6]:port`. DNS over TLS:
    /// `tls://ip[:port]#name`, where `name` is what the server's certificate
    /// must carry (the format Unbound uses, minus the hostname lookup).
    fn upstreamServers(d: *Decoder, pair: yaml.Pair) Error![]const upstream_mod.ServerAddress {
        const items = try d.nonEmptyList(pair);
        const servers = try d.arena.alloc(upstream_mod.ServerAddress, items.len);
        for (items, servers) |item, *server| {
            const text = try d.scalar(item, pair.key);
            const tls_prefix = "tls://";
            if (!std.mem.startsWith(u8, text, tls_prefix)) {
                server.* = .{ .address = ip.parseSocketAddress(text, upstream_mod.plain_port) orelse
                    return d.fail(item.line, "'{s}' is not an IP address with optional port", .{text}) };
                continue;
            }
            const rest = text[tls_prefix.len..];
            const hash = std.mem.findScalar(u8, rest, '#') orelse
                return d.fail(item.line, "'{s}' needs the server's TLS name after '#', e.g. tls://9.9.9.9#dns.quad9.net", .{text});
            const address = ip.parseSocketAddress(rest[0..hash], upstream_mod.tls_port) orelse
                return d.fail(item.line, "'{s}' is not an IP address with optional port", .{rest[0..hash]});
            var name_buf: [dns.max_name_len]u8 = undefined;
            const name = dns.normalizeName(rest[hash + 1 ..], &name_buf) orelse
                return d.fail(item.line, "'{s}' is not a valid TLS name", .{rest[hash + 1 ..]});
            if (ip.Ip.parse(name) != null) {
                return d.fail(item.line, "the TLS name must be a hostname (e.g. dns.quad9.net), not an IP address", .{});
            }
            server.* = .{ .address = address, .tls_name = try d.arena.dupe(u8, name) };
        }
        return servers;
    }

    /// Blocklist sources: http(s) URLs or file paths.
    fn listSources(d: *Decoder, pair: yaml.Pair) Error![]const []const u8 {
        const sources = try d.stringList(pair);
        for (sources, (try d.list(pair))) |source, item| {
            if (blocklist.isUrl(source)) {
                _ = std.Uri.parse(source) catch return d.fail(item.line, "invalid URL '{s}'", .{source});
                if (std.mem.startsWith(u8, source, "http://")) {
                    log.warn("line {d}: {s} is fetched without TLS; prefer https://", .{ item.line, source });
                }
            }
        }
        return sources;
    }

    /// Inline rules must each be valid, so typos fail loudly instead of
    /// being skipped like unsupported lines in a downloaded list.
    fn inlineRules(d: *Decoder, pair: yaml.Pair) Error![]const []const u8 {
        const rules = try d.stringList(pair);
        for (rules, (try d.list(pair))) |rule, item| {
            var counter: RuleCounter = .{};
            blocklist.parseLine(rule, &counter) catch unreachable;
            if (counter.rules == 0) return d.fail(item.line, "'{s}' is not a valid domain or rule", .{rule});
        }
        return rules;
    }

    // Value helpers ---------------------------------------------------------

    fn mapping(d: *Decoder, node: yaml.Node, what: []const u8) Error![]const yaml.Pair {
        return switch (node.value) {
            .empty => &.{},
            .mapping => |pairs| pairs,
            else => d.fail(node.line, "{s}: expected 'key: value' entries", .{what}),
        };
    }

    fn list(d: *Decoder, pair: yaml.Pair) Error![]const yaml.Node {
        return switch (pair.value.value) {
            .empty => &.{},
            .sequence => |items| items,
            else => d.fail(pair.value.line, "{s}: expected a list", .{pair.key}),
        };
    }

    fn nonEmptyList(d: *Decoder, pair: yaml.Pair) Error![]const yaml.Node {
        const items = try d.list(pair);
        if (items.len == 0) return d.fail(pair.line, "{s}: the list is empty", .{pair.key});
        return items;
    }

    fn stringList(d: *Decoder, pair: yaml.Pair) Error![]const []const u8 {
        const items = try d.list(pair);
        const strings = try d.arena.alloc([]const u8, items.len);
        for (items, strings) |item, *string| {
            string.* = try d.arena.dupe(u8, try d.scalar(item, pair.key));
        }
        return strings;
    }

    fn scalar(d: *Decoder, node: yaml.Node, key: []const u8) Error![]const u8 {
        return switch (node.value) {
            .scalar => |value| value,
            else => d.fail(node.line, "{s}: expected a single value", .{key}),
        };
    }

    fn integer(d: *Decoder, comptime T: type, pair: yaml.Pair, min: T, max: T) Error!T {
        const text = try d.scalar(pair.value, pair.key);
        const value = std.fmt.parseInt(T, text, 10) catch
            return d.fail(pair.value.line, "{s}: '{s}' is not a whole number", .{ pair.key, text });
        if (value < min or value > max) {
            return d.fail(pair.value.line, "{s}: must be between {d} and {d}", .{ pair.key, min, max });
        }
        return value;
    }

    fn boolean(d: *Decoder, pair: yaml.Pair) Error!bool {
        const text = try d.scalar(pair.value, pair.key);
        if (std.mem.eql(u8, text, "true")) return true;
        if (std.mem.eql(u8, text, "false")) return false;
        return d.fail(pair.value.line, "{s}: expected true or false", .{pair.key});
    }

    fn enumeration(d: *Decoder, comptime E: type, pair: yaml.Pair) Error!E {
        const text = try d.scalar(pair.value, pair.key);
        return std.meta.stringToEnum(E, text) orelse {
            const names = comptime names: {
                var joined: []const u8 = "";
                for (std.meta.fieldNames(E), 0..) |name, i| joined = joined ++ (if (i == 0) "" else ", ") ++ name;
                break :names joined;
            };
            return d.fail(pair.value.line, "{s}: expected one of: {s}", .{ pair.key, names });
        };
    }

    fn unknownKey(d: *Decoder, pair: yaml.Pair, section: []const u8) error{InvalidConfig} {
        return d.fail(pair.line, "unknown key '{s}' in section '{s}'", .{ pair.key, section });
    }
};

fn isUnspecified(address: net.IpAddress) bool {
    return switch (address) {
        .ip4 => |a| std.mem.allEqual(u8, &a.bytes, 0),
        .ip6 => |a| std.mem.allEqual(u8, &a.bytes, 0),
    };
}

fn is(pair: yaml.Pair, key: []const u8) bool {
    return std.mem.eql(u8, pair.key, key);
}

/// Counts what `blocklist.parseLine` finds, to validate inline rules.
const RuleCounter = struct {
    rules: usize = 0,
    stats: blocklist.Stats = .{},

    pub fn add(counter: *RuleCounter, _: blocklist.Rule) error{}!void {
        counter.rules += 1;
    }

    pub fn skip(_: *RuleCounter) void {}
};

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

fn expectConfigError(source: []const u8, line: u32, message_part: []const u8) !void {
    var diag: Diagnostic = .{};
    try testing.expectError(error.InvalidConfig, parse(testing.allocator, source, &diag));
    try testing.expectEqual(line, diag.line);
    if (std.mem.find(u8, diag.message(), message_part) == null) {
        std.debug.print("unexpected message: {s}\n", .{diag.message()});
        return error.TestUnexpectedResult;
    }
}

test "full configuration" {
    var diag: Diagnostic = .{};
    var config = try parse(testing.allocator,
        \\server:
        \\  listen: ["127.0.0.1:5353", "[::1]:5353"]
        \\  allow_clients: [192.168.0.0/16, "fd00::/8"]
        \\  workers: 2
        \\upstream:
        \\  servers:
        \\    - 9.9.9.9
        \\    - "[2620:fe::fe]:53"
        \\    - tls://149.112.112.112#DNS.Quad9.net
        \\    - "tls://[2620:fe::9]:8853#dns.quad9.net"
        \\  timeout_ms: 1500
        \\cache:
        \\  size: 100
        \\  min_ttl: 10
        \\blocking:
        \\  response: nxdomain
        \\  refresh_hours: 12
        \\  lists:
        \\    - https://example.com/hosts.txt
        \\    - /etc/zinkhole/local.txt
        \\  block: ["ads.example.com", "||tracker.example^", "*.wild.example"]
        \\  allow: [ok.example.com]
        \\local:
        \\  ttl: 60
        \\  private_names: forward
        \\  records:
        \\    NAS.lan: 192.168.1.10
        \\    router.lan: [192.168.1.1, "fd00::1"]
        \\    "*.apps.lan": 192.168.1.20
        \\log:
        \\  level: debug
        \\  queries: true
    , &diag);
    defer config.deinit();

    try testing.expectEqual(2, config.server.listen.len);
    try testing.expectEqual(5353, config.server.listen[1].getPort());
    try testing.expectEqual(2, config.server.allow_clients.len);
    try testing.expectEqual(2, config.server.workers);
    const servers = config.upstream.servers;
    try testing.expectEqual(4, servers.len);
    try testing.expectEqual(null, servers[0].tls_name);
    try testing.expectEqual(53, servers[0].address.getPort());
    try testing.expectEqualStrings("dns.quad9.net", servers[2].tls_name.?);
    try testing.expectEqual(853, servers[2].address.getPort());
    try testing.expectEqual(8853, servers[3].address.getPort());
    try testing.expect(servers[3].address == .ip6);
    try testing.expectEqual(1500, config.upstream.timeout_ms);
    try testing.expectEqual(100, config.cache.size);
    try testing.expectEqual(10, config.cache.min_ttl);
    try testing.expectEqual(Config.BlockResponse.nxdomain, config.blocking.response);
    try testing.expectEqual(2, config.blocking.lists.len);
    try testing.expectEqual(3, config.blocking.block.len);
    try testing.expectEqual(Config.PrivateNames.forward, config.local.private_names);

    const records = config.local.records;
    try testing.expectEqual(3, records.len);
    try testing.expectEqualStrings("nas.lan", records[0].name);
    try testing.expectEqual(2, records[1].addresses.len);
    try testing.expect(records[2].wildcard);
    try testing.expectEqualStrings("apps.lan", records[2].name);

    try testing.expectEqual(std.log.Level.debug, config.log.level);
    try testing.expect(config.log.queries);
}

test "defaults" {
    var diag: Diagnostic = .{};
    var config = try parse(testing.allocator, "upstream:\n  servers: [1.1.1.1]\n", &diag);
    defer config.deinit();
    try testing.expectEqual(2, config.server.listen.len);
    try testing.expectEqual(4, config.server.workers);
    try testing.expectEqual(4096, config.cache.size);
    try testing.expectEqual(Config.BlockResponse.zero, config.blocking.response);
    try testing.expect(ip.isAllowed(config.server.allow_clients, .{ .ip4 = .{ .bytes = .{ 192, 168, 1, 1 }, .port = 1 } }));
    try testing.expect(!ip.isAllowed(config.server.allow_clients, .{ .ip4 = .{ .bytes = .{ 8, 8, 8, 8 }, .port = 1 } }));
}

test "configuration errors name the line" {
    try expectConfigError("", 0, "upstream");
    try expectConfigError("upstream:\n  servers: [1.1.1.1]\n  timeout: 5", 3, "unknown key 'timeout'");
    try expectConfigError("upstrem:\n  servers: [1.1.1.1]", 1, "unknown section");
    try expectConfigError("upstream:\n  servers: [dns.google]", 2, "not an IP address");
    try expectConfigError("upstream:\n  servers: []", 2, "empty");
    try expectConfigError("upstream:\n  servers: [tls://9.9.9.9]", 2, "needs the server's TLS name");
    try expectConfigError("upstream:\n  servers: [tls://dns.quad9.net#dns.quad9.net]", 2, "not an IP address");
    try expectConfigError("upstream:\n  servers: [tls://9.9.9.9#9.9.9.9]", 2, "must be a hostname");
    try expectConfigError("upstream:\n  servers: [tls://9.9.9.9#bad_name!]", 2, "not a valid TLS name");
    try expectConfigError("upstream:\n  servers: [1.1.1.1]\nserver:\n  workers: 0", 4, "between 1 and 64");
    try expectConfigError("upstream:\n  servers: [1.1.1.1]\nblocking:\n  response: refuse", 4, "zero, nxdomain");
    try expectConfigError("upstream:\n  servers: [1.1.1.1]\nblocking:\n  block:\n    - not a domain", 5, "not a valid domain");
    try expectConfigError("upstream:\n  servers: [1.1.1.1]\nlocal:\n  records:\n    nas.lan: 999.1.1.1", 5, "not an IP address");
    try expectConfigError("upstream:\n  servers: [1.1.1.1]\nlocal:\n  records:\n    nas.lan: 10.0.0.1\n    NAS.LAN: 10.0.0.2", 6, "defined twice");
    try expectConfigError("upstream:\n  servers: [1.1.1.1]\nlocal:\n  records:\n    bad_host!: 10.0.0.1", 5, "invalid hostname");
    try expectConfigError("upstream:\n  servers: [1.1.1.1]\nlog:\n  queries: yes", 4, "true or false");
    try expectConfigError("upstream:\n  servers: [1.1.1.1]\ncache:\n  min_ttl: 10\n  max_ttl: 5", 4, "min_ttl");
    try expectConfigError("upstream:\n  servers: [1.1.1.1]\nserver:\n  allow_clients: [192.168.0.0/40]", 4, "invalid network");
    try expectConfigError("upstream: [1.1.1.1]", 1, "expected 'key: value'");
    try expectConfigError("a: b: c", 1, "unexpected ':'");
}

const test_secret = "0123456789abcdef0123456789abcdef";

test "the sync section makes an instance an origin or a replica" {
    var diag: Diagnostic = .{};
    const base = "upstream:\n  servers: [1.1.1.1]\n";

    var origin = try parse(testing.allocator, base ++
        \\sync:
        \\  serve: ["192.168.1.5:5380"]
        \\  secret: 
    ++ test_secret, &diag);
    defer origin.deinit();
    try testing.expect(origin.sync == .origin);
    try testing.expectEqual(5380, origin.sync.origin.serve[0].getPort());
    try testing.expectEqualStrings(test_secret, origin.sync.origin.secret);

    var replica = try parse(testing.allocator, base ++
        \\sync:
        \\  origin: http://192.168.1.5:5380
        \\  interval: 30
        \\  secret: 
    ++ test_secret, &diag);
    defer replica.deinit();
    try testing.expect(replica.sync == .replica);
    try testing.expectEqualStrings("http://192.168.1.5:5380", replica.sync.replica.origin);
    try testing.expectEqual(30, replica.sync.replica.interval);

    var standalone = try parse(testing.allocator, base, &diag);
    defer standalone.deinit();
    try testing.expect(standalone.sync == .none);
}

test "sync configuration errors" {
    const base = "upstream:\n  servers: [1.1.1.1]\n";
    try expectConfigError(base ++ "sync:\n  serve: [\"10.0.0.1:5380\"]\n  origin: http://10.0.0.2:5380\n  secret: " ++ test_secret, 3, "either 'serve' (origin) or 'origin' (replica)");
    try expectConfigError(base ++ "sync:\n  serve: [\"10.0.0.1:5380\"]\n  secret: short", 5, "at least 32 characters");
    try expectConfigError(base ++ "sync:\n  serve: [\"10.0.0.1:5380\"]", 3, "needs a secret");
    try expectConfigError(base ++ "sync:\n  serve: [10.0.0.1]\n  secret: " ++ test_secret, 4, "needs a port");
    try expectConfigError(base ++ "sync:\n  origin: ftp://10.0.0.1\n  secret: " ++ test_secret, 4, "http:// or https://");
    try expectConfigError(base ++ "sync:\n  secret: " ++ test_secret, 3, "either 'serve' (origin) or 'origin' (replica)");
    try expectConfigError(base ++ "blocking:\n  block: [ads.example]\nsync:\n  origin: http://10.0.0.1:5380\n  secret: " ++ test_secret, 3, "synced from the origin");
}

test "upstream.max_in_flight limits the upstream queries at once" {
    var diag: Diagnostic = .{};
    var config = try parse(testing.allocator, "upstream:\n  servers: [1.1.1.1]\n  max_in_flight: 16\n", &diag);
    defer config.deinit();
    try testing.expectEqual(16, config.upstream.max_in_flight);

    var defaults = try parse(testing.allocator, "upstream:\n  servers: [1.1.1.1]\n", &diag);
    defer defaults.deinit();
    try testing.expectEqual(64, defaults.upstream.max_in_flight);

    try expectConfigError("upstream:\n  servers: [1.1.1.1]\n  max_in_flight: 0", 3, "between 1 and 1024");
    try expectConfigError("upstream:\n  servers: [1.1.1.1]\n  max_in_flight: 5000", 3, "between 1 and 1024");
}

test "the metrics section says where metrics are served" {
    var diag: Diagnostic = .{};
    const base = "upstream:\n  servers: [1.1.1.1]\n";
    var config = try parse(testing.allocator, base ++ "metrics:\n  listen: [\"10.10.50.85:9153\", \"[::1]:9153\"]\n", &diag);
    defer config.deinit();
    try testing.expectEqual(2, config.metrics.?.listen.len);
    try testing.expectEqual(9153, config.metrics.?.listen[1].getPort());

    var without = try parse(testing.allocator, base, &diag);
    defer without.deinit();
    try testing.expectEqual(null, without.metrics);

    // Not synced: a replica has its own.
    var replica = try parse(testing.allocator, base ++ "sync:\n  origin: http://10.0.0.1:5380\n  secret: " ++ test_secret ++ "\nmetrics:\n  listen: [\"10.0.0.2:9153\"]\n", &diag);
    defer replica.deinit();
    try testing.expect(replica.metrics != null);
}

test "metrics configuration errors" {
    const base = "upstream:\n  servers: [1.1.1.1]\n";
    try expectConfigError(base ++ "metrics:\n  listen: [10.0.0.1]", 4, "needs a port");
    try expectConfigError(base ++ "metrics:\n  listen: []", 4, "empty");
    try expectConfigError(base ++ "metrics:\n  port: 9153", 4, "unknown key 'port'");
    // The DNS server listens on 0.0.0.0:53 and [::]:53 by default.
    try expectConfigError(base ++ "metrics:\n  listen: [\"10.0.0.1:53\"]", 3, "port 53 is already in use by server.listen");
    try expectConfigError(base ++ "metrics:\n  listen: [\"10.0.0.1:5380\"]\nsync:\n  serve: [\"0.0.0.0:5380\"]\n  secret: " ++ test_secret, 3, "port 5380 is already in use by sync.serve");
    // Different addresses may share a port.
    var diag: Diagnostic = .{};
    var config = try parse(testing.allocator, base ++ "server:\n  listen: [\"10.0.0.1:53\"]\nmetrics:\n  listen: [\"10.0.0.2:53\"]\n", &diag);
    config.deinit();
}

test "the Policy settings text is the blocking and local sections, as written" {
    var diag: Diagnostic = .{};
    var config = try parse(testing.allocator,
        \\upstream:
        \\  servers: [1.1.1.1]
        \\blocking:
        \\  # ads
        \\  block: [ads.example]
        \\sync:
        \\  serve: ["10.0.0.1:5380"]
        \\  secret: 
    ++ test_secret ++ "\n" ++
        \\local:
        \\  records:
        \\    nas.lan: 10.0.0.10
    , &diag);
    defer config.deinit();
    try testing.expectEqualStrings(
        \\blocking:
        \\  # ads
        \\  block: [ads.example]
        \\local:
        \\  records:
        \\    nas.lan: 10.0.0.10
        \\
    , config.policy_text);
}

const test_replica = "upstream:\n  servers: [1.1.1.1]\nsync:\n  origin: http://10.0.0.1:5380\n  secret: " ++ test_secret ++ "\n";

test "a replica takes its Policy settings from the synced text" {
    const synced = "blocking:\n  block: [ads.example]\nlocal:\n  records:\n    nas.lan: 10.0.0.10\n";
    var diag: Diagnostic = .{};
    var config = try parseReplica(testing.allocator, test_replica, synced, &diag);
    defer config.deinit();
    try testing.expect(config.sync == .replica);
    try testing.expectEqual(1, config.blocking.block.len);
    try testing.expectEqualStrings("nas.lan", config.local.records[0].name);
    try testing.expectEqualStrings(synced, config.policy_text);
}

test "synced text other than Policy settings is rejected, naming the origin" {
    var diag: Diagnostic = .{};
    try testing.expectError(error.InvalidConfig, parseReplica(testing.allocator, test_replica, "server:\n  workers: 2\n", &diag));
    try testing.expect(diag.from_origin);
    try testing.expectEqual(1, diag.line);

    diag = .{};
    try testing.expectError(error.InvalidConfig, parseReplica(testing.allocator, test_replica, "local:\n  records:\n    nas.lan: 999.1.1.1\n", &diag));
    try testing.expect(diag.from_origin);
    try testing.expectEqual(3, diag.line);
}

test "a replica keeps its state in /var/lib/zinkhole unless told otherwise" {
    var diag: Diagnostic = .{};
    var config = try parse(testing.allocator, test_replica, &diag);
    defer config.deinit();
    try testing.expectEqualStrings("/var/lib/zinkhole", config.sync.replica.state_dir);
    try testing.expectEqualStrings(test_replica, config.source);

    var custom = try parse(testing.allocator, test_replica ++ "  state_dir: /tmp/zh\n", &diag);
    defer custom.deinit();
    try testing.expectEqualStrings("/tmp/zh", custom.sync.replica.state_dir);
}

test "a config with many local records parses quickly" {
    // About 900 KB: close to the 1 MiB limit, as a large synced config can be.
    const count = 40_000;
    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(testing.allocator);
    try source.appendSlice(testing.allocator, "upstream:\n  servers: [1.1.1.1]\nlocal:\n  records:\n");
    for (0..count) |i| try source.print(testing.allocator, "    host{d}.lan: 10.0.0.1\n", .{i});

    const started = Io.Clock.awake.now(testing.io);
    var diag: Diagnostic = .{};
    var config = try parse(testing.allocator, source.items, &diag);
    defer config.deinit();
    const elapsed = started.untilNow(testing.io, .awake).toMilliseconds();
    try testing.expectEqual(count, config.local.records.len);
    // Duplicate checks must not compare every entry with every other one.
    if (elapsed > 2000) {
        std.debug.print("parsing took {d} ms\n", .{elapsed});
        return error.TestTooSlow;
    }
}
