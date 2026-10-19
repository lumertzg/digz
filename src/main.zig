const std = @import("std");
const zlap = @import("zlap");
const App = @import("App.zig");
const Args = @import("Args.zig");

pub fn main(init: std.process.Init) u8 {
    const app: App = .{
        .arena = init.arena.allocator(),
        .io = init.io,
        .environ = init.environ_map,
    };

    app.run(zlap.parse(Args, init)) catch |err| {
        if (err == error.Reported) return 1;

        return switch (app.fail("{t}", .{err})) {
            error.Reported => 1,
        };
    };

    return 0;
}
