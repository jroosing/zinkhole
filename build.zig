const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // `zig build --release` picks ReleaseSafe: optimized, but bounds and
    // overflow checks stay on. That is the right trade-off for a daemon that
    // parses untrusted network input.
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .safe });

    // Debug info only takes disk space (it is never loaded into memory), but
    // it makes panic messages useful, so it is kept unless asked otherwise.
    const strip = b.option(bool, "strip", "Omit debug info from the binary") orelse false;

    const root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = strip,
    });

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

    const tests = b.addTest(.{ .root_module = root_module });
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);
}
