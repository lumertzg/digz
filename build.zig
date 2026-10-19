const std = @import("std");
const Ldns = @import("build/ldns.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const fmt = b.addFmt(.{
        .paths = &.{
            b.path("src"),
            b.path("build"),
            b.path("build.zig"),
            b.path("build.zig.zon"),
            b.path(".ziglint.zon"),
        },
        .check = true,
    });
    b.step("fmt", "Check code formatting").dependOn(&fmt.step);

    const ldns_c = Ldns.create(b, target, optimize);
    const ldns = b.createModule(.{
        .root_source_file = b.path("src/ldns/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "ldns_c", .module = ldns_c }},
    });
    const zlap = b.dependency("zlap", .{ .target = target, .optimize = optimize });
    const imports = [_]std.Build.Module.Import{
        .{ .name = "ldns", .module = ldns },
        .{ .name = "zlap", .module = zlap.module("zlap") },
    };
    const exe = b.addExecutable(.{
        .name = "digz",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &imports,
        }),
    });
    b.installArtifact(exe);

    const test_options = b.addOptions();
    test_options.addOptionPath("binary", exe.getEmittedBin());
    const app_tests = b.createModule(.{
        .root_source_file = b.path("src/App.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &imports,
    });
    app_tests.addImport("ldns_c", ldns_c);
    app_tests.addOptions("test_options", test_options);

    const test_step = b.step("test", "Run tests");
    for ([_]*std.Build.Module{ ldns, app_tests }) |module| {
        const tests = b.addTest(.{ .root_module = module });
        test_step.dependOn(&b.addRunArtifact(tests).step);
    }

    const run = b.addRunArtifact(exe);
    run.addPassthruArgs();
    b.step("run", "Run digz").dependOn(&run.step);
}
