const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    // Add custom option to specify main file
    const main_file_option = b.option([]const u8, "main-file", "Path to the Zig file containing the main function") orelse "src/main.zig";

    // Add custom option for percentage of UDP DNS packets to ignore
    const ignore_dns_option = b.option(u32, "ignore-dns", "Percentage of UDP DNS packets to ignore (0-100)") orelse 0;

    // Add custom option to specify log mode
    const log_mode_option = b.option([]const u8, "log-mode", "Log mode (no-io, io-prints, io-logging)") orelse "no-io";

    // Validate log mode option
    if (!std.mem.eql(u8, log_mode_option, "no-io") and
        !std.mem.eql(u8, log_mode_option, "io-prints") and
        !std.mem.eql(u8, log_mode_option, "io-logging"))
    {
        std.debug.print("Invalid log mode. Use 'no-io', 'io-prints', or 'io-logging'.\n", .{});
        return;
    }

    // We will also create a module for our other entry point
    const exe_mod = b.createModule(.{
        .root_source_file = b.path(main_file_option),
        .target = target,
        .optimize = optimize,
    });

    // Add a compile-time constant for log mode
    const options = b.addOptions();
    options.addOption(u32, "ignore_dns", ignore_dns_option);
    options.addOption([]const u8, "log_mode", log_mode_option);

    // Add options module to executable module
    exe_mod.addImport("build_options", options.createModule());

    // This creates another `std.Build.Step.Compile`, but this one builds an executable
    // rather than a static library.
    const exe = b.addExecutable(.{
        .name = "zig_router",
        .root_module = exe_mod,
    });

    // Link against libc and libnetfilter_queue
    exe.linkSystemLibrary("libnetfilter_queue"); // Link against libnetfilter_queue
    exe.linkLibC(); // Link against libc

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(exe);

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(exe);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
