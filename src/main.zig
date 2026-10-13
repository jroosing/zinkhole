//! zinkhole: a minimal DNS blocker and local DNS server for home networks.
//!
//! Threads: worker threads answer queries (server.zig). The main thread loads
//! the config, starts the server, then supervises: it reacts to signals and
//! starts list downloads, which run as one background task at a time.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const config = @import("config.zig");
const Config = config.Config;
const dns = @import("dns.zig");
const ip = @import("ip.zig");
const tcp = @import("tcp.zig");
const log_output = @import("log.zig");
const Policy = @import("policy.zig").Policy;
const Lists = @import("policy.zig").Lists;
const Sources = @import("policy.zig").Sources;
const Schedule = @import("refresh.zig").Schedule;
const Cache = @import("cache.zig").Cache;
const Resolver = @import("resolver.zig").Resolver;
const Server = @import("server.zig").Server;
const Upstream = @import("upstream.zig").Upstream;

const log = std.log.scoped(.main);

pub const std_options: std.Options = .{
    // All levels are compiled in; `log.level` in the config filters at runtime.
    .log_level = .debug,
    .logFn = log_output.logFn,
    // Never write TLS session keys to $SSLKEYLOGFILE, not even in debug builds.
    .http_enable_ssl_key_log_file = false,
};

const version = "0.1.0";
const default_config_path = "/etc/zinkhole/config.yaml";

/// Answering queries needs little stack; TLS handshakes during list
/// downloads need the most (measured: 256 KiB overflows in debug builds,
/// 512 KiB suffices). Only touched pages consume memory.
const thread_stack_size = 1024 * 1024;

const usage =
    \\Usage: zinkhole [options]
    \\
    \\A minimal DNS blocker and local DNS server.
    \\
    \\Options:
    \\  -c, --config <path>  configuration file (default: /etc/zinkhole/config.yaml)
    \\  -t, --test           check the configuration, load all lists, then exit
    \\  --healthcheck [addr] ask a running server (default 127.0.0.1:53) for
    \\                       "localhost"; exit 0 if it answers (for containers)
    \\  -h, --help           show this help
    \\  -V, --version        show the version
    \\
    \\Signals:
    \\  SIGHUP   reload the configuration file
    \\  SIGUSR1  log query statistics
    \\
;

pub fn main(init: std.process.Init.Minimal) !u8 {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer if (builtin.mode == .debug) {
        _ = debug_allocator.deinit();
    };
    const gpa = if (builtin.mode == .debug) debug_allocator.allocator() else std.heap.smp_allocator;

    // Blocking I/O on a fixed set of threads. All code takes an `Io`, so the
    // evented implementations (io_uring, Grand Central Dispatch) could be
    // swapped in here once they leave experimental status.
    var threaded: Io.Threaded = .init(gpa, .{
        .stack_size = thread_stack_size,
        .argv0 = .init(init.args),
        .environ = init.environ,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var config_path: []const u8 = default_config_path;
    var test_only = false;
    var args = init.args.iterate();
    _ = args.skip(); // program name
    while (args.next()) |arg| {
        if (eql(arg, "-c") or eql(arg, "--config")) {
            config_path = args.next() orelse {
                printTo(io, .stderr(), "error: {s} needs a path\n", .{arg});
                return 2;
            };
        } else if (eql(arg, "-t") or eql(arg, "--test")) {
            test_only = true;
        } else if (eql(arg, "--healthcheck")) {
            return healthcheck(io, args.next() orelse "127.0.0.1:53");
        } else if (eql(arg, "-h") or eql(arg, "--help")) {
            printTo(io, .stdout(), usage, .{});
            return 0;
        } else if (eql(arg, "-V") or eql(arg, "--version")) {
            printTo(io, .stdout(), "zinkhole {s}\n", .{version});
            return 0;
        } else {
            printTo(io, .stderr(), "error: unknown option '{s}'\n\n" ++ usage, .{arg});
            return 2;
        }
    }

    var diag: config.Diagnostic = .{};
    var cfg = config.load(io, gpa, config_path, &diag) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        error.InvalidConfig => {
            if (diag.line == 0) {
                printTo(io, .stderr(), "{s}: {s}\n", .{ config_path, diag.message() });
            } else {
                printTo(io, .stderr(), "{s}:{d}: {s}\n", .{ config_path, diag.line, diag.message() });
            }
            return 1;
        },
    };
    log_output.setLevel(cfg.log.level);

    defer cfg.deinit();
    if (test_only) return check(io, gpa, &cfg);
    run(io, gpa, config_path, &cfg) catch |err| {
        log.err("{t}", .{err});
        return 1;
    };
    return 0;
}

/// `--healthcheck`: queries the server at `target` for "localhost", which is
/// answered from the built-in local record, so the check does not depend on
/// upstream servers. Lets images without a shell (FROM scratch) define a
/// container healthcheck.
fn healthcheck(io: Io, target: []const u8) u8 {
    const server = ip.parseSocketAddress(target, 53) orelse {
        printTo(io, .stderr(), "unhealthy: '{s}' is not an IP address with optional port\n", .{target});
        return 1;
    };
    // ID 0x6863, recursion desired, one question: localhost A IN.
    const query = [_]u8{ 0x68, 0x63, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 } ++
        "\x09localhost\x00".* ++ [_]u8{ 0, 1, 0, 1 };

    const any_address: Io.net.IpAddress = switch (server) {
        .ip4 => .{ .ip4 = .unspecified(0) },
        .ip6 => .{ .ip6 = .unspecified(0) },
    };
    const socket = any_address.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch |err| {
        printTo(io, .stderr(), "unhealthy: {t}\n", .{err});
        return 1;
    };
    defer socket.close(io);
    socket.send(io, &server, &query) catch |err| {
        printTo(io, .stderr(), "unhealthy: {t}\n", .{err});
        return 1;
    };
    var buffer: [512]u8 = undefined;
    const deadline = tcp.deadlineIn(io, 2000);
    while (true) {
        const message = socket.receiveTimeout(io, &buffer, deadline) catch |err| {
            printTo(io, .stderr(), "unhealthy: no answer from {f} ({t})\n", .{ server, err });
            return 1;
        };
        if (!message.from.eql(&server) or !dns.isResponseTo(message.data, &query, query.len)) continue;
        const rcode = dns.readFlags(message.data).rcode;
        if (rcode == .noerror) return 0;
        printTo(io, .stderr(), "unhealthy: {f} answered {t} (is it in server.allow_clients?)\n", .{ server, rcode });
        return 1;
    }
}

/// `--test`: validates the config and loads every list once.
fn check(io: Io, gpa: Allocator, cfg: *const Config) !u8 {
    var policy: Policy = try .init(io, gpa, cfg);
    defer policy.deinit();
    const lists = Lists.load(io, gpa, .fromConfig(cfg)) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        error.Canceled => unreachable, // nothing cancels the main thread
    };
    defer lists.destroy();
    printTo(io, .stdout(), "configuration OK: {d} local records, {d} inline rules, {d} blocked and {d} allowed domains from lists\n", .{
        cfg.local.records.len,
        cfg.blocking.block.len + cfg.blocking.allow.len,
        lists.block.count(),
        lists.allow.count(),
    });
    if (!lists.complete) {
        printTo(io, .stderr(), "some lists failed to load (see the errors above)\n", .{});
        return 1;
    }
    return 0;
}

/// Serves until SIGTERM/SIGINT. A reload replaces `cfg` in place.
fn run(io: Io, gpa: Allocator, config_path: []const u8, cfg: *Config) !void {
    // Long-lived copies of the settings that only apply at startup, so a
    // reload can free the config they came from.
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var upstream: Upstream = undefined;
    try upstream.init(io, gpa, cfg.upstream.servers, cfg.upstream.timeout_ms);
    defer upstream.deinit();
    var cache: Cache = try .init(gpa, .{
        .capacity = cfg.cache.size,
        .min_ttl = cfg.cache.min_ttl,
        .max_ttl = cfg.cache.max_ttl,
        .seed = randomSeed(io),
    });
    defer cache.deinit();

    // Serve right away with local records and inline rules; lists load in
    // the background. This also lets this host resolve the list servers'
    // names through us while starting.
    const allow_clients = try arena.dupe(ip.Cidr, cfg.server.allow_clients);
    var policy: Policy = try .init(io, gpa, cfg);
    defer policy.deinit();
    var resolver: Resolver = .{
        .io = io,
        .policy = &policy,
        .cache = &cache,
        .upstream = &upstream,
        .allow_clients = allow_clients,
        .log_queries = .init(cfg.log.queries),
    };

    var server: Server = .{ .io = io, .gpa = gpa, .resolver = &resolver };
    defer server.deinit();
    try server.listen(cfg.server.listen);
    try server.start(cfg.server.workers);

    var app: App = .{
        .io = io,
        .gpa = gpa,
        .config_path = config_path,
        .config = cfg,
        .policy = &policy,
        .resolver = &resolver,
        .task_arena = .init(gpa),
    };
    defer app.deinit();

    signals.install();
    log.info("zinkhole {s} ready ({d} upstream servers, {d} local records)", .{
        version, upstream.endpoints.len, cfg.local.records.len,
    });
    app.supervise();
}

/// State of the supervising main thread. It runs the list loads; the
/// Refresh schedule decides when.
const App = struct {
    io: Io,
    gpa: Allocator,
    config_path: []const u8,
    /// The configuration as last loaded; a reload replaces it in place.
    config: *Config,
    policy: *Policy,
    resolver: *Resolver,
    schedule: Schedule = .{},

    /// The running list load, if any. It returns the lists (null when it ran
    /// out of memory); the supervisor decides whether they are used.
    task: ?Io.Future(Io.Cancelable!?*Lists) = null,
    task_done: std.atomic.Value(bool) = .init(false),
    /// Holds the running task's copy of the list sources.
    task_arena: std.heap.ArenaAllocator,

    fn deinit(app: *App) void {
        app.task_arena.deinit();
    }

    fn supervise(app: *App) void {
        while (!signals.shutdown.load(.acquire)) {
            app.io.sleep(.fromSeconds(1), .awake) catch {};
            if (signals.reload.swap(false, .acq_rel)) app.reload();
            if (signals.stats.swap(false, .acq_rel)) app.logStats();
            app.scheduleLists();
        }
        log.info("shutting down", .{});
        if (app.task) |*task| {
            discardLoad(task.cancel(app.io));
            app.task = null;
        }
    }

    fn scheduleLists(app: *App) void {
        const now = nowSeconds(app.io);
        if (app.task) |*task| {
            if (app.task_done.load(.acquire)) {
                const lists = task.await(app.io) catch null; // only `cancel` cancels it
                app.task = null;
                app.finishLoad(now, lists);
            }
        }
        const refresh_hours = app.config.blocking.refresh_hours;
        const interval: ?i64 = if (refresh_hours == 0) null else @as(i64, refresh_hours) * 3600;
        switch (app.schedule.next(now, interval)) {
            .idle => {},
            .start => app.startTask(now),
            .cancel => app.cancelTask(now),
        }
    }

    fn startTask(app: *App, now: i64) void {
        _ = app.task_arena.reset(.retain_capacity);
        const sources = Sources.fromConfig(app.config).dupe(app.task_arena.allocator()) catch {
            log.err("out of memory, cannot load lists", .{});
            return app.schedule.finished(now, false);
        };
        app.task_done.store(false, .release);
        app.task = app.io.concurrent(loadLists, .{ app, sources }) catch |err| {
            log.err("cannot start loading lists: {t}", .{err});
            return app.schedule.finished(now, false);
        };
        app.schedule.started(now);
    }

    /// Lists the canceled task may already have loaded are not used.
    fn cancelTask(app: *App, now: i64) void {
        if (app.task) |*task| {
            discardLoad(task.cancel(app.io));
            app.task = null;
        }
        app.schedule.finished(now, false);
    }

    fn finishLoad(app: *App, now: i64, loaded: ?*Lists) void {
        const lists = loaded orelse return app.schedule.finished(now, false);
        const complete = lists.complete;
        if (app.policy.replaceLists(lists) == .kept) {
            log.warn("some lists failed to load, keeping the previous lists", .{});
        }
        app.schedule.finished(now, complete);
    }

    /// Runs as a background task: loads the lists, nothing else.
    fn loadLists(app: *App, sources: Sources) Io.Cancelable!?*Lists {
        defer app.task_done.store(true, .release);
        return Lists.load(app.io, app.gpa, sources) catch |err| switch (err) {
            error.Canceled => |e| return e,
            error.OutOfMemory => {
                log.err("out of memory while loading lists, keeping the previous lists", .{});
                return null;
            },
        };
    }

    fn discardLoad(result: Io.Cancelable!?*Lists) void {
        const loaded = result catch return;
        if (loaded) |lists| lists.destroy();
    }

    fn reload(app: *App) void {
        var diag: config.Diagnostic = .{};
        var new_config = config.load(app.io, app.gpa, app.config_path, &diag) catch |err| {
            switch (err) {
                error.InvalidConfig => log.err("reload failed, keeping the current configuration: {s}:{d}: {s}", .{
                    app.config_path, diag.line, diag.message(),
                }),
                error.OutOfMemory => log.err("reload failed: out of memory", .{}),
            }
            return;
        };
        app.policy.applyConfig(&new_config) catch {
            log.err("reload failed: out of memory", .{});
            new_config.deinit();
            return;
        };
        log_output.setLevel(new_config.log.level);
        app.resolver.log_queries.store(new_config.log.queries, .monotonic);

        if (!Sources.fromConfig(&new_config).eql(.fromConfig(app.config))) app.schedule.sourcesChanged();
        app.config.deinit();
        app.config.* = new_config;
        log.info("configuration reloaded (server, upstream and cache settings apply after a restart)", .{});
    }

    fn logStats(app: *App) void {
        var buffer: [512]u8 = undefined;
        var writer: Io.Writer = .fixed(&buffer);
        app.resolver.stats.write(&writer) catch {};
        log.info("{s}; {d} cached responses", .{ writer.buffered(), app.resolver.cache.count(app.io) });
    }
};

/// Signal handlers only set flags; the main loop acts on them.
const signals = struct {
    var reload: std.atomic.Value(bool) = .init(false);
    var stats: std.atomic.Value(bool) = .init(false);
    var shutdown: std.atomic.Value(bool) = .init(false);

    fn install() void {
        const action: std.posix.Sigaction = .{
            .handler = .{ .handler = handle },
            .mask = std.posix.sigemptyset(),
            .flags = std.posix.SA.RESTART,
        };
        for ([_]std.posix.SIG{ .HUP, .USR1, .INT, .TERM }) |sig| std.posix.sigaction(sig, &action, null);
    }

    fn handle(sig: std.posix.SIG) callconv(.c) void {
        switch (sig) {
            .HUP => reload.store(true, .release),
            .USR1 => stats.store(true, .release),
            else => shutdown.store(true, .release),
        }
    }
};

fn printTo(io: Io, file: Io.File, comptime format: []const u8, args: anytype) void {
    var buffer: [1024]u8 = undefined;
    var writer = file.writer(io, &buffer);
    writer.interface.print(format, args) catch {};
    writer.interface.flush() catch {};
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn nowSeconds(io: Io) i64 {
    return Io.Clock.boot.now(io).toSeconds();
}

fn randomSeed(io: Io) u64 {
    var bytes: [8]u8 = undefined;
    io.random(&bytes);
    return std.mem.readInt(u64, &bytes, .little);
}

test {
    _ = @import("yaml.zig");
    _ = @import("dns.zig");
    _ = @import("domain_set.zig");
    _ = @import("ip.zig");
    _ = @import("blocklist.zig");
    _ = @import("local.zig");
    _ = @import("cache.zig");
    _ = @import("config.zig");
    _ = @import("policy.zig");
    _ = @import("refresh.zig");
    _ = @import("resolver.zig");
    _ = @import("upstream.zig");
    _ = @import("dot.zig");
    _ = @import("tcp.zig");
}
