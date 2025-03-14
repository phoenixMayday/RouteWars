const std = @import("std");

// import log mode build option
const log_mode = @import("build_options").log_mode;

const IOMode = enum {
    NoIO,
    IOPrints,
    IOLogging,
};

const current_mode: IOMode = blk: {
    if (std.mem.eql(u8, log_mode, "no-io")) {
        break :blk IOMode.NoIO;
    } else if (std.mem.eql(u8, log_mode, "io-prints")) {
        break :blk IOMode.IOPrints;
    } else if (std.mem.eql(u8, log_mode, "io-logging")) {
        break :blk IOMode.IOLogging;
    } else {
        @compileError("Invalid log mode. Use 'no-io', 'io-prints', or 'io-logging'.");
    }
};

pub fn log(comptime fmt: []const u8, args: anytype) void {
    switch (current_mode) {
        .NoIO => {
            // no I/O operations
        },
        .IOPrints => {
            // print to stdout
            std.debug.print(fmt, args);
        },
        .IOLogging => {
            // log to a file
            const file = std.fs.cwd().createFile("log.txt", .{ .truncate = false }) catch |err| {
                std.debug.print("Failed to open log file: {}\n", .{err});
                return;
            };
            defer file.close();

            // go to end of the file
            file.seekFromEnd(0) catch |err| {
                std.debug.print("Failed to seek to end of log file: {}\n", .{err});
                return;
            };

            file.writer().print(fmt, args) catch |err| {
                std.debug.print("Failed to write to log file: {}\n", .{err});
            };
        },
    }
}
