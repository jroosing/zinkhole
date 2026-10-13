const std = @import("std");

/// The single source of the version: `zinkhole --version` and the release
/// tag (checked by CI) both come from here.
const manifest = @import("build.zig.zon");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // `zig build --release` picks ReleaseSafe: optimized, but bounds and
    // overflow checks stay on. That is the right trade-off for a daemon that
    // parses untrusted network input.
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .safe });

    // Debug info only takes disk space (it is never loaded into memory), but
    // it makes panic messages useful, so it is kept unless asked otherwise.
    const strip = b.option(bool, "strip", "Omit debug info from the binary") orelse false;
    const network = b.option(bool, "network", "Also run the tests that need the internet") orelse false;
    // For checking the threads (workers, forwarding slots, list loads) for
    // data races: `zig build test -Dsanitize-thread`.
    const sanitize_thread = b.option(bool, "sanitize-thread", "Build with ThreadSanitizer") orelse false;
    const options = b.addOptions();
    options.addOption(bool, "network_tests", network);
    options.addOption([]const u8, "version", manifest.version);

    const root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = strip,
        .sanitize_thread = sanitize_thread,
    });
    root_module.addOptions("build_options", options);

    const exe = b.addExecutable(.{
        .name = "zinkhole",
        .root_module = root_module,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    const run_step = b.step("run", "Run zinkhole");
    run_step.dependOn(&run_cmd.step);

    const test_filters = b.option([]const []const u8, "test-filter", "Only run tests whose name contains this") orelse &.{};
    const tests = b.addTest(.{ .root_module = root_module, .filters = test_filters });
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);
}
