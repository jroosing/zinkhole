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
const sync = @import("sync.zig");
const Cache = @import("cache.zig").Cache;
const Resolver = @import("resolver.zig").Resolver;
const Server = @import("server.zig").Server;
const Upstream = @import("upstream.zig").Upstream;
const localtime = @import("localtime.zig");
const metrics_mod = @import("metrics.zig");
const Metrics = metrics_mod.Metrics;

const log = std.log.scoped(.main);
const testing = std.testing;

pub const std_options: std.Options = .{
    // All levels are compiled in; `log.level` in the config filters at runtime.
    .log_level = .debug,
    .logFn = log_output.logFn,
    // Never write TLS session keys to $SSLKEYLOGFILE, not even in debug builds.
    .http_enable_ssl_key_log_file = false,
    // No alternate signal stack per thread. It only lets a stack overflow
    // print a stack trace instead of just ending the process (the guard page
    // still stops it, and the service manager restarts it), and it costs
    // 256 KiB of resident memory per thread: about 18 MB with the
    // forwarding slots (ADR-0005).
    .signal_stack_size = null,
};

/// From build.zig.zon (see build.zig).
const version = @import("build_options").version;
const default_config_path = "/etc/zinkhole/config.yaml";

/// Answering queries needs little stack; TLS handshakes during list
/// downloads need the most (measured: 256 KiB overflows in debug builds,
/// 512 KiB suffices). Only touched pages consume memory.
const thread_stack_size = 1024 * 1024;
/// A sync with the origin taking longer than this is canceled (and failed).
const sync_timeout_s = 10;
/// Failed syncs in a row before a warning (single failures are routine).
const sync_failures_before_warning = 3;

const usage =
    \\Usage: zinkhole [options]
    \\
    \\A minimal DNS blocker and local DNS server.
    \\
    \\Options:
    \\  -c, --config <path>  configuration file (default: /etc/zinkhole/config.yaml)
    \\  -t, --test           check the configuration, load all lists, then exit
    \\  --check              only validate the configuration (no network), then exit
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
    var check_only = false;
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
        } else if (eql(arg, "--check")) {
            check_only = true;
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

    if (check_only) return checkConfig(io, gpa, config_path, .stdout(), .stderr());

    var cfg = try loadConfig(io, gpa, config_path, .stderr()) orelse return 1;
    log_output.setLevel(cfg.log.level);

    defer cfg.deinit();
    if (test_only) return check(io, gpa, &cfg);
    run(io, gpa, config_path, &cfg, init.environ.getPosix("TZ")) catch |err| {
        log.err("{t}", .{err});
        return 1;
    };
    return 0;
}

/// Loads the config file; null (after saying why on `err_out`) if it is invalid.
fn loadConfig(io: Io, gpa: Allocator, config_path: []const u8, err_out: Io.File) Allocator.Error!?Config {
    var diag: config.Diagnostic = .{};
    return config.load(io, gpa, config_path, &diag) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        error.InvalidConfig => {
            if (diag.line == 0) {
                printTo(io, err_out, "{s}: {s}\n", .{ config_path, diag.message() });
            } else {
                printTo(io, err_out, "{s}:{d}: {s}\n", .{ config_path, diag.line, diag.message() });
            }
            return null;
        },
    };
}

/// `--check`: only validates the config file, with no network access and no
/// lists, so it is quick and cannot fail because a list server is down. It
/// answers "would this binary accept this config?", e.g. before an update.
fn checkConfig(io: Io, gpa: Allocator, config_path: []const u8, out: Io.File, err_out: Io.File) !u8 {
    var cfg = try loadConfig(io, gpa, config_path, err_out) orelse return 1;
    defer cfg.deinit();
    printTo(io, out, "configuration OK\n", .{});
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
    const lists = Lists.load(io, gpa, .fromConfig(cfg), .{}) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        error.Canceled => unreachable, // nothing cancels the main thread
    };
    defer lists.destroy();
    if (cfg.sync == .replica) {
        printTo(io, .stdout(), "replica: local records and blocking come from {s}\n", .{cfg.sync.replica.origin});
    }
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

/// Serves until SIGTERM/SIGINT. A reload replaces `cfg` in place. `tz` is
/// the TZ variable, for the metrics' local time.
fn run(io: Io, gpa: Allocator, config_path: []const u8, cfg: *Config, tz: ?[]const u8) !void {
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
        .serve_stale_s = cfg.cache.serve_stale_hours * 3600,
    });
    defer cache.deinit();

    // The sync settings only change on restart; a long-lived copy outlives
    // the configs that reloads and syncs replace.
    const replica: ?Config.Sync.Replica = switch (cfg.sync) {
        .replica => |settings| .{
            .origin = try arena.dupe(u8, settings.origin),
            .secret = try arena.dupe(u8, settings.secret),
            .interval = settings.interval,
            .state_dir = try arena.dupe(u8, settings.state_dir),
        },
        else => null,
    };
    // A replica starts from the settings it last synced, if it has any.
    var synced: ?sync.Synced = if (replica) |settings| startReplica(io, gpa, cfg, settings) else null;
    defer if (synced) |s| gpa.free(s.text);

    // Serve right away with local records and inline rules; lists load in
    // the background. This also lets this host resolve the list servers'
    // names through us while starting.
    const allow_clients = try arena.dupe(ip.Cidr, cfg.server.allow_clients);
    var policy: Policy = try .init(io, gpa, cfg);
    defer policy.deinit();

    // Before anything is counted; everything that counts stops first.
    var metrics: Metrics = undefined;
    const measuring = cfg.metrics != null;
    if (measuring) metrics = try startMetrics(io, gpa, cfg, tz);
    defer if (measuring) metrics.deinit();
    const metrics_ptr: ?*Metrics = if (measuring) &metrics else null;
    upstream.metrics = metrics_ptr;
    if (metrics_ptr) |m| m.setLocalRecords(cfg.local.records.len);

    var resolver: Resolver = .{
        .io = io,
        .policy = &policy,
        .cache = &cache,
        .upstream = &upstream,
        .allow_clients = allow_clients,
        .log_queries = .init(cfg.log.queries),
        .metrics = metrics_ptr,
    };

    var server: Server = .{ .io = io, .gpa = gpa, .resolver = &resolver };
    defer server.deinit();
    try server.listen(cfg.server.listen);
    try server.start(.{ .udp_workers = cfg.server.workers, .forward_slots = cfg.upstream.max_in_flight });

    var origin: sync.Origin = undefined;
    const serving = cfg.sync == .origin;
    if (serving) try origin.init(io, gpa, cfg.sync.origin.serve, cfg.sync.origin.secret, allow_clients, metrics_ptr);
    // Right after init: its tasks point into `origin` and must stop before
    // this frame ends, whatever fails next.
    defer if (serving) origin.deinit();
    if (serving) {
        try origin.publish(cfg.policy_text);
        for (origin.service.listeners.items) |listener| log.info("serving the Policy settings to replicas on {f}", .{listener.socket.address});
    }

    var endpoint: metrics_mod.Endpoint = undefined;
    if (measuring) try endpoint.init(io, gpa, cfg.metrics.?.listen, allow_clients, .{ .metrics = &metrics, .upstream = &upstream, .cache = &cache });
    // Right after init, like the origin.
    defer if (measuring) endpoint.deinit();
    if (measuring) {
        for (endpoint.service.listeners.items) |listener| log.info("serving metrics on http://{f}/metrics", .{listener.socket.address});
    }

    var app: App = .{
        .io = io,
        .gpa = gpa,
        .config_path = config_path,
        .config = cfg,
        .policy = &policy,
        .resolver = &resolver,
        .metrics = metrics_ptr,
        .task_arena = .init(gpa),
        .origin = if (serving) &origin else null,
        .replica = replica,
        .synced = &synced,
    };
    defer app.deinit();

    signals.install();
    log.info("zinkhole {s} ready ({d} upstream servers, {d} local records)", .{
        version, upstream.servers.len, cfg.local.records.len,
    });
    app.supervise();
}

/// The metrics, in the local time zone.
fn startMetrics(io: Io, gpa: Allocator, cfg: *const Config, tz: ?[]const u8) !Metrics {
    var root = try Io.Dir.cwd().openDir(io, "/", .{});
    defer root.close(io);
    var zone = localtime.load(io, gpa, tz, root);
    errdefer zone.deinit(gpa);
    log.info("metrics use the time zone {s}", .{zone.name()});
    return .init(io, gpa, .{
        .zone = zone,
        .role = switch (cfg.sync) {
            .none => .standalone,
            .origin => .origin,
            .replica => .replica,
        },
        .origin = if (cfg.sync == .replica) cfg.sync.replica.origin else "",
        .started = realSeconds(io),
        .upstream = cfg.upstream.servers,
    });
}

/// Loads a replica's state file and, if it holds valid settings, makes them
/// part of `cfg`. Returns them (owned), or null to start without any.
fn startReplica(io: Io, gpa: Allocator, cfg: *Config, replica: Config.Sync.Replica) ?sync.Synced {
    var dir = Io.Dir.cwd().openDir(io, replica.state_dir, .{}) catch |err| {
        log.warn("cannot open the state directory {s} ({t}); synced settings will not survive a restart", .{ replica.state_dir, err });
        return null;
    };
    defer dir.close(io);
    const synced = sync.loadState(io, gpa, dir, replica.secret) catch |err| {
        log.err("ignoring {s}/{s}: {t}", .{ replica.state_dir, sync.state_file, err });
        return null;
    } orelse {
        log.warn("no synced settings yet: no local records or blocking until the first sync from {s}", .{replica.origin});
        return null;
    };
    var diag: config.Diagnostic = .{};
    const combined = config.parseReplica(gpa, cfg.source, synced.text, &diag) catch |err| {
        log.err("ignoring {s}/{s}: {t} (line {d}: {s})", .{ replica.state_dir, sync.state_file, err, diag.line, diag.message() });
        gpa.free(synced.text);
        return null;
    };
    cfg.deinit();
    cfg.* = combined;
    log.info("starting with the settings last synced from {s}", .{replica.origin});
    return synced;
}

/// State of the supervising main thread. It runs the list loads (the
/// Refresh schedule decides when) and, on a replica, the syncs.
const App = struct {
    io: Io,
    gpa: Allocator,
    config_path: []const u8,
    /// The configuration as last loaded; a reload replaces it in place.
    config: *Config,
    policy: *Policy,
    resolver: *Resolver,
    schedule: Schedule = .{},
    /// Told what the supervisor sees, if metrics are served.
    metrics: ?*Metrics,

    /// Origin only: serves the Policy settings to replicas.
    origin: ?*sync.Origin,
    /// Replica only: where to sync from (a copy that lives as long as `App`).
    replica: ?Config.Sync.Replica,
    /// Replica only: the settings last synced from the origin (owned).
    synced: *?sync.Synced,
    sync_task: ?Io.Future(Io.Cancelable!?sync.Fetched) = null,
    sync_done: std.atomic.Value(bool) = .init(false),
    /// Why the last sync task failed; written by the task before `sync_done`.
    sync_error: anyerror = error.Unknown,
    sync_started: i64 = 0,
    /// When to sync next (boot-clock seconds); 0 means now.
    next_sync: i64 = 0,
    sync_failures: u32 = 0,

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
            app.scheduleSync();
            app.reportNextLoad();
        }
        log.info("shutting down", .{});
        if (app.task) |*task| {
            discardLoad(task.cancel(app.io));
            app.task = null;
        }
        if (app.sync_task) |*task| {
            app.discardSync(task.cancel(app.io));
            app.sync_task = null;
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
        switch (app.schedule.next(now, app.refreshInterval())) {
            .idle => {},
            .start => app.startTask(now),
            .cancel => app.cancelTask(now),
        }
    }

    fn refreshInterval(app: *const App) ?i64 {
        const refresh_hours = app.config.blocking.refresh_hours;
        return if (refresh_hours == 0) null else @as(i64, refresh_hours) * 3600;
    }

    /// The schedule counts in boot-clock seconds; the metrics show real time.
    fn reportNextLoad(app: *App) void {
        const metrics = app.metrics orelse return;
        const next = app.schedule.nextLoad(app.refreshInterval()) orelse return metrics.setNextLoad(null);
        // In nanoseconds, so whole seconds do not flicker between ticks.
        const real_minus_boot: i64 = @intCast(@divFloor(Io.Clock.real.now(app.io).toNanoseconds() - Io.Clock.boot.now(app.io).toNanoseconds(), std.time.ns_per_s));
        metrics.setNextLoad(next + real_minus_boot);
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
        // Before `replaceLists`, which destroys lists it does not keep.
        app.reportLoad(lists);
        if (app.policy.replaceLists(lists) == .kept) {
            log.warn("some lists failed to load, keeping the previous lists", .{});
        }
        // Only the supervisor replaces the lists, so reading them is safe here.
        if (app.metrics) |metrics| metrics.setDomains(app.policy.lists.block.count(), app.policy.lists.allow.count());
        app.schedule.finished(now, complete);
    }

    fn reportLoad(app: *App, lists: *const Lists) void {
        const metrics = app.metrics orelse return;
        const all = lists.sources.blocklists.len + lists.sources.allowlists.len;
        const sources = app.gpa.alloc(metrics_mod.ListLoad.Source, all) catch return;
        defer app.gpa.free(sources);
        for (lists.sources.blocklists, sources[0..lists.sources.blocklists.len]) |source, *to| to.source = source;
        for (lists.sources.allowlists, sources[lists.sources.blocklists.len..]) |source, *to| to.source = source;
        for (lists.loaded, sources) |ok, *to| to.ok = ok;
        metrics.setLists(.{ .sources = sources, .complete = lists.complete, .finished = realSeconds(app.io) }) catch {};
    }

    /// Runs as a background task: loads the lists, nothing else.
    fn loadLists(app: *App, sources: Sources) Io.Cancelable!?*Lists {
        defer app.task_done.store(true, .release);
        return Lists.load(app.io, app.gpa, sources, .{}) catch |err| switch (err) {
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

    fn scheduleSync(app: *App) void {
        const replica = app.replica orelse return;
        const now = nowSeconds(app.io);
        if (app.sync_task) |*task| {
            if (app.sync_done.load(.acquire)) {
                const fetched = task.await(app.io) catch null; // only `cancel` cancels it
                app.sync_task = null;
                app.finishSync(now, fetched);
            } else if (now - app.sync_started > sync_timeout_s) {
                app.discardSync(task.cancel(app.io));
                app.sync_task = null;
                app.sync_error = error.Timeout;
                app.finishSync(now, null);
            }
            return;
        }
        if (now < app.next_sync) return;
        const have = if (app.synced.*) |synced| synced.fingerprint else null;
        app.sync_done.store(false, .release);
        app.sync_task = app.io.concurrent(fetchSettings, .{ app, replica.origin, replica.secret, have }) catch |err| {
            app.sync_error = err;
            return app.finishSync(now, null);
        };
        app.sync_started = now;
    }

    /// Runs as a background task: one sync request to the origin.
    fn fetchSettings(app: *App, url: []const u8, secret: []const u8, have: ?sync.Fingerprint) Io.Cancelable!?sync.Fetched {
        defer app.sync_done.store(true, .release);
        // A client per sync: one canceled halfway leaves nothing behind.
        var client: std.http.Client = .{ .allocator = app.gpa, .io = app.io };
        defer client.deinit();
        return sync.fetch(&client, url, secret, have) catch |err| {
            const any: anyerror = err;
            if (any == error.Canceled) return error.Canceled;
            app.sync_error = err;
            return null;
        };
    }

    fn discardSync(app: *App, result: Io.Cancelable!?sync.Fetched) void {
        var fetched = (result catch return) orelse return;
        fetched.deinit(app.gpa);
    }

    /// `fetched` is null when the sync failed (see `sync_error`).
    fn finishSync(app: *App, now: i64, fetched: ?sync.Fetched) void {
        const replica = app.replica.?;
        app.next_sync = now + replica.interval;
        const result = fetched orelse {
            if (app.metrics) |metrics| metrics.syncFailed();
            app.sync_failures +|= 1;
            if (app.sync_failures == sync_failures_before_warning) {
                log.warn("cannot sync from {s} ({t}); keeping the current settings", .{ replica.origin, app.sync_error });
            } else {
                log.debug("sync from {s}: {t}", .{ replica.origin, app.sync_error });
            }
            return;
        };
        if (app.sync_failures >= sync_failures_before_warning) log.info("syncing from {s} again", .{replica.origin});
        app.sync_failures = 0;
        if (app.metrics) |metrics| metrics.synced(realSeconds(app.io));
        switch (result) {
            .unchanged => {},
            .changed => |synced| app.applySynced(synced),
        }
    }

    /// Applies settings from the origin like a reload; takes ownership.
    fn applySynced(app: *App, synced: sync.Synced) void {
        const replica = app.replica.?;
        var diag: config.Diagnostic = .{};
        var new_config = config.parseReplica(app.gpa, app.config.source, synced.text, &diag) catch |err| {
            app.gpa.free(synced.text);
            switch (err) {
                error.InvalidConfig => log.err("the settings from {s} are invalid here, keeping the current ones: line {d} of its blocking/local sections: {s}", .{
                    replica.origin, diag.line, diag.message(),
                }),
                error.OutOfMemory => log.err("sync failed: out of memory", .{}),
            }
            return;
        };
        app.policy.applyConfig(&new_config) catch {
            log.err("sync failed: out of memory", .{});
            app.gpa.free(synced.text);
            new_config.deinit();
            return;
        };
        if (!Sources.fromConfig(&new_config).eql(.fromConfig(app.config))) app.schedule.sourcesChanged();
        if (app.metrics) |metrics| metrics.setLocalRecords(new_config.local.records.len);
        app.config.deinit();
        app.config.* = new_config;
        if (app.synced.*) |old| app.gpa.free(old.text);
        app.synced.* = synced;
        log.info("applied the settings synced from {s}", .{replica.origin});

        var dir = Io.Dir.cwd().openDir(app.io, replica.state_dir, .{}) catch |err| {
            return log.warn("cannot save the synced settings in {s}: {t}", .{ replica.state_dir, err });
        };
        defer dir.close(app.io);
        sync.saveState(app.io, dir, synced) catch |err| log.warn("cannot save the synced settings in {s}: {t}", .{ replica.state_dir, err });
    }

    fn reload(app: *App) void {
        var diag: config.Diagnostic = .{};
        var new_config = app.loadConfig(&diag) catch |err| {
            switch (err) {
                error.InvalidConfig => log.err("reload failed, keeping the current configuration: {s}:{d}: {s}", .{
                    if (diag.from_origin) "settings synced from the origin" else app.config_path, diag.line, diag.message(),
                }),
                error.OutOfMemory => log.err("reload failed: out of memory", .{}),
            }
            return;
        };
        if (std.meta.activeTag(new_config.sync) != std.meta.activeTag(app.config.sync)) {
            log.err("reload failed: changing the sync role (origin, replica or neither) needs a restart", .{});
            new_config.deinit();
            return;
        }
        app.policy.applyConfig(&new_config) catch {
            log.err("reload failed: out of memory", .{});
            new_config.deinit();
            return;
        };
        if (app.origin) |origin| origin.publish(new_config.policy_text) catch log.err("cannot publish the new settings: out of memory", .{});
        // A replica syncs right away, as a manual "sync now".
        if (new_config.sync == .replica) app.next_sync = 0;
        log_output.setLevel(new_config.log.level);
        app.resolver.log_queries.store(new_config.log.queries, .monotonic);

        if (!Sources.fromConfig(&new_config).eql(.fromConfig(app.config))) app.schedule.sourcesChanged();
        if (app.metrics) |metrics| metrics.setLocalRecords(new_config.local.records.len);
        app.config.deinit();
        app.config.* = new_config;
        log.info("configuration reloaded (server, upstream and cache settings apply after a restart)", .{});
    }

    /// The config file, plus the last synced settings on a replica.
    fn loadConfig(app: *App, diag: *config.Diagnostic) config.Error!Config {
        var own = try config.load(app.io, app.gpa, app.config_path, diag);
        const synced = app.synced.* orelse return own;
        if (own.sync != .replica) return own;
        defer own.deinit();
        return config.parseReplica(app.gpa, own.source, synced.text, diag);
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
    // Streaming, not positional: each call makes a new writer, and a
    // positional one would start at offset 0 when stdout is a regular file.
    var writer = file.writerStreaming(io, &buffer);
    writer.interface.print(format, args) catch {};
    writer.interface.flush() catch {};
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn nowSeconds(io: Io) i64 {
    return Io.Clock.boot.now(io).toSeconds();
}

/// Unix time, for what people read.
fn realSeconds(io: Io) i64 {
    return Io.Clock.real.now(io).toSeconds();
}

fn randomSeed(io: Io) u64 {
    var bytes: [8]u8 = undefined;
    io.random(&bytes);
    return std.mem.readInt(u64, &bytes, .little);
}

/// What `--check` returned and printed for a config file with this `text`.
/// (Output goes to files, not the test runner's own stdout.)
const CheckResult = struct {
    code: u8,
    out: [256]u8 = undefined,
    out_len: usize = 0,
    err: [256]u8 = undefined,
    err_len: usize = 0,

    fn stdout(r: *const CheckResult) []const u8 {
        return r.out[0..r.out_len];
    }

    fn stderr(r: *const CheckResult) []const u8 {
        return r.err[0..r.err_len];
    }
};

fn checkText(text: []const u8) !CheckResult {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "config.yaml", .data = text });
    var out_file = try tmp.dir.createFile(testing.io, "out.txt", .{ .read = true });
    defer out_file.close(testing.io);
    var err_file = try tmp.dir.createFile(testing.io, "err.txt", .{ .read = true });
    defer err_file.close(testing.io);
    var path_buf: [96]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/config.yaml", .{tmp.sub_path});

    var result: CheckResult = .{ .code = try checkConfig(testing.io, testing.allocator, path, out_file, err_file) };
    result.out_len = try out_file.readPositionalAll(testing.io, &result.out, 0);
    result.err_len = try err_file.readPositionalAll(testing.io, &result.err, 0);
    return result;
}

test "--check accepts a valid config and rejects an invalid one" {
    const valid = try checkText("upstream:\n  servers: [1.1.1.1]\n");
    try testing.expectEqual(0, valid.code);
    try testing.expectEqualStrings("configuration OK\n", valid.stdout());

    const bad_address = try checkText("upstream:\n  servers: [not-an-address]\n");
    try testing.expectEqual(1, bad_address.code);
    try testing.expect(std.mem.find(u8, bad_address.stderr(), ":2: ") != null);

    const no_upstream = try checkText("local:\n  ttl: 60\n");
    try testing.expectEqual(1, no_upstream.code);
    try testing.expectEqualStrings("", no_upstream.stdout());
}

test "--check does not load lists, so an unreachable source is fine" {
    // The config parser warns about the http:// source; keep the output quiet.
    const log_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = log_level;
    // 192.0.2.1 is a documentation address: loading it would take until a timeout.
    const started = Io.Clock.awake.now(testing.io);
    const result = try checkText("upstream:\n  servers: [1.1.1.1]\nblocking:\n  lists: [http://192.0.2.1/hosts.txt, /no/such/file.txt]\n");
    try testing.expectEqual(0, result.code);
    try testing.expect(started.untilNow(testing.io, .awake).toMilliseconds() < 1000);
}

test "the version is MAJOR.MINOR.PATCH, taken from build.zig.zon" {
    var parts = std.mem.splitScalar(u8, @import("build_options").version, '.');
    var count: usize = 0;
    while (parts.next()) |part| : (count += 1) {
        _ = try std.fmt.parseInt(u32, part, 10);
    }
    try testing.expectEqual(3, count);
    try testing.expectEqualStrings(@import("build_options").version, version);
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
    _ = @import("sync.zig");
    _ = @import("resolver.zig");
    _ = @import("upstream.zig");
    _ = @import("dot.zig");
    _ = @import("tcp.zig");
    _ = @import("server.zig");
    _ = @import("localtime.zig");
    _ = @import("metrics.zig");
    _ = @import("http_service.zig");
    _ = @import("forwarder.zig");
    _ = @import("test_fuzz.zig");
    _ = @import("slot_pool.zig");
}
