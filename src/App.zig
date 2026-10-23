//! Runs a query and renders its response using borrowed process dependencies.
const Self = @This();

const std = @import("std");
const zlap = @import("zlap");
const ldns = @import("ldns");
const Args = @import("Args.zig");
const Renderer = @import("Renderer.zig");
const JsonRenderer = @import("JsonRenderer.zig");
const Trace = @import("Trace.zig");
const DnsServer = @import("fixtures/DnsServer.zig");
const test_options = @import("test_options");

/// Process-lifetime storage, released by the caller.
arena: std.mem.Allocator,
io: std.Io,
environ: *const std.process.Environ.Map,

pub fn run(self: Self, args: Args) !void {
    if (args.completions) |shell| {
        var buffer: [4096]u8 = undefined;
        var stdout = std.Io.File.stdout().writerStreaming(self.io, &buffer);
        switch (shell) {
            inline else => |value| {
                try stdout.interface.writeAll(zlap.completionScript(Args, value));
            },
        }
        try stdout.interface.flush();
        return;
    }

    if (args.json_schema) {
        var buffer: [4096]u8 = undefined;
        var stdout = std.Io.File.stdout().writerStreaming(self.io, &buffer);
        try JsonRenderer.writeSchema(&stdout.interface);
        try stdout.interface.flush();
        return;
    }

    var query = try self.createQuery(args);
    defer query.deinit();

    const options: ldns.Resolver.Options = .{
        .server = if (args.server) |value| try self.arena.dupeSentinel(u8, value, 0) else null,
        .source = if (args.source) |value| try self.arena.dupeSentinel(u8, value, 0) else null,
        .family = if (args.ipv4) .ipv4 else if (args.ipv6) .ipv6 else .any,
        .port = args.port,
        .tcp = args.tcp,
        .timeout_ms = args.timeout_ms,
        .tries = args.tries,
    };
    if (args.trace) return self.runTrace(args, &query, options);

    const endpoint = try self.endpointText(args);
    var resolver = ldns.Resolver.init(options) catch |err| {
        if (err == error.InvalidServer) {
            return self.fail("--server {q} is not an IP address or hostname", .{args.server.?});
        }

        return self.fail("could not initialize {q}: {t}", .{ endpoint, err });
    };
    defer resolver.deinit();

    const start = std.Io.Timestamp.now(self.io, .awake);
    var response = resolver.send(&query) catch |err| {
        return self.fail("query to {q} failed: {t}", .{ endpoint, err });
    };
    defer response.deinit();

    const elapsed = start.durationTo(std.Io.Timestamp.now(self.io, .awake)).toMilliseconds();
    self.writeResponse(args, .{
        .packet = &response,
        .elapsed_ms = elapsed,
        .port = args.port,
        .tcp = args.tcp,
    }) catch |err| {
        return self.fail("could not write response: {t}", .{err});
    };
}

fn runTrace(self: Self, args: Args, query: *ldns.Packet, options: ldns.Resolver.Options) !void {
    var trace = try Trace.init(self.arena, query, options);
    defer trace.deinit();

    var hops: std.ArrayList(JsonRenderer.Response) = .empty;
    var trace_error: ?anyerror = null;
    const trace_start = std.Io.Timestamp.now(self.io, .awake);
    while (true) {
        const start = std.Io.Timestamp.now(self.io, .awake);
        const response = trace.next() catch |err| {
            if (args.json) {
                trace_error = err;
                break;
            }
            return self.fail("trace failed: {t}", .{err});
        } orelse break;
        const now = std.Io.Timestamp.now(self.io, .awake);

        if (args.json) {
            const snapshot = JsonRenderer.response(
                self.arena,
                response,
                start.durationTo(now).toMilliseconds(),
                args.port,
                args.tcp,
            ) catch |err| {
                trace_error = err;
                break;
            };
            hops.append(self.arena, snapshot) catch |err| {
                trace_error = err;
                break;
            };
            continue;
        }

        self.writeResponse(args, .{
            .packet = response,
            .elapsed_ms = start.durationTo(now).toMilliseconds(),
            .port = args.port,
            .tcp = args.tcp,
            .trace = .{
                .hop = trace.hops,
                .elapsed_ms = trace_start.durationTo(now).toMilliseconds(),
            },
        }) catch |err| {
            return self.fail("could not write response: {t}", .{err});
        };
    }

    if (args.json) {
        try self.writeJson(JsonRenderer.Trace{
            .hops = hops.items,
            .complete = trace_error == null,
            .@"error" = if (trace_error) |err| @errorName(err) else null,
            .elapsed_ms = trace_start.durationTo(
                std.Io.Timestamp.now(self.io, .awake),
            ).toMilliseconds(),
        });
        if (trace_error) |err| return self.fail("trace failed: {t}", .{err});
    }
}

fn createQuery(self: Self, args: Args) !ldns.Packet {
    const arena = self.arena;
    const type_text = try arena.dupeSentinel(u8, args.rr_type, 0);
    const rr_type = ldns.Type.fromText(type_text) catch {
        return self.fail("--type {q} is not a valid DNS type", .{args.rr_type});
    };

    // Transfers need a multi-message operation, not the ordinary query path.
    switch (rr_type) {
        .axfr, .ixfr => return self.fail("AXFR and IXFR transfers are not supported", .{}),
        else => {},
    }

    if (args.port == 0) return self.fail("--port must be between 1 and 65535", .{});
    if (args.timeout_ms == 0 or args.timeout_ms > std.math.maxInt(c_int)) {
        return self.fail("--timeout-ms must be between 1 and 2147483647", .{});
    }

    if (args.tries == 0) return self.fail("--tries must be between 1 and 255", .{});
    if (args.source) |source| {
        const address = std.Io.net.IpAddress.parse(source, 0) catch {
            return self.fail("--source {q} is not an IP address", .{source});
        };
        if ((args.ipv4 and address == .ip6) or (args.ipv6 and address == .ip4)) {
            return self.fail("--source {q} conflicts with --ipv4/--ipv6", .{source});
        }
    }
    if (args.edns_size) |size| {
        if (size < 512) return self.fail("--edns-size must be between 512 and 65535", .{});
    }

    const class_text = try arena.dupeSentinel(u8, args.class, 0);
    const class = ldns.Class.fromText(class_text) catch {
        return self.fail("--class {q} is not a valid DNS class", .{args.class});
    };
    const options: ldns.Packet.QueryOptions = .{
        .class = class,
        .recursion_desired = !args.no_recursion and !args.trace,
        .dnssec = args.dnssec,
        .checking_disabled = args.checking_disabled,
        .authenticated_data = args.authenticated_data,
        .edns_udp_size = args.edns_size,
        .subnet = if (args.subnet) |text| ldns.Packet.ClientSubnet.parse(text) catch {
            return self.fail("--subnet {q} must be an IPv4/IPv6 CIDR network", .{text});
        } else null,
    };

    if (args.reverse) |address| {
        const address_text = try arena.dupeSentinel(u8, address, 0);
        return ldns.Packet.reverse(address_text, options) catch |err| {
            return self.fail("reverse query for {q} failed: {t}", .{ address, err });
        };
    }

    const name = args.name orelse "example.com.";
    const name_text = try arena.dupeSentinel(u8, name, 0);
    return ldns.Packet.query(name_text, rr_type, options) catch |err| {
        return self.fail("query for {q} failed: {t}", .{ name, err });
    };
}

fn endpointText(self: Self, args: Args) error{OutOfMemory}![]const u8 {
    const arena = self.arena;
    const server = args.server orelse {
        return arena.print("nameservers from /etc/resolv.conf (port {d})", .{args.port});
    };

    if (std.mem.findScalar(u8, server, ':') != null) {
        return arena.print("[{s}]:{d}", .{ server, args.port });
    }

    return arena.print("{s}:{d}", .{ server, args.port });
}

fn writeResponse(self: Self, args: Args, result: Renderer.Result) !void {
    if (args.json) {
        return self.writeJson(try JsonRenderer.response(
            self.arena,
            result.packet,
            result.elapsed_ms,
            result.port,
            result.tcp,
        ));
    }

    const stdout_file = std.Io.File.stdout();
    const tty = stdout_file.isTty(self.io) catch false;
    const term = self.environ.get("TERM") orelse "";
    const decorated = tty and !std.mem.eql(u8, term, "dumb");

    var buffer: [4096]u8 = undefined;
    var stdout = stdout_file.writerStreaming(self.io, &buffer);
    const renderer: Renderer = .{
        .arena = self.arena,
        .writer = &stdout.interface,
        .options = .{
            .details = args.details,
            .short = args.short,
            .color = decorated and !self.environ.contains("NO_COLOR"),
            .borders = decorated,
            .width = if (tty) terminalWidth(stdout_file) else null,
        },
    };

    try renderer.write(result);
    try stdout.interface.flush();
}

fn writeJson(self: Self, value: anytype) !void {
    var buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(self.io, &buffer);
    const renderer: JsonRenderer = .{ .writer = &stdout.interface };
    try renderer.write(value);
    try stdout.interface.flush();
}

fn terminalWidth(file: std.Io.File) usize {
    var size: std.posix.winsize = undefined;
    if (std.c.ioctl(file.handle, @intCast(std.c.T.IOCGWINSZ), &size) == 0 and size.col != 0) {
        return size.col;
    }

    return 80;
}

/// Returns to the entry point so callers unwind owned resources before exiting.
pub fn fail(self: Self, comptime fmt: []const u8, args: anytype) error{Reported} {
    var buffer: [1024]u8 = undefined;
    var stderr = std.Io.File.stderr().writerStreaming(self.io, &buffer);

    stderr.interface.print("digz: " ++ fmt ++ "\n", args) catch return error.Reported;
    stderr.interface.flush() catch return error.Reported;

    return error.Reported;
}

test {
    std.testing.refAllDecls(Trace);
    std.testing.refAllDecls(JsonRenderer);
}

test "a later invalid record preserves JSON trace history and reports InvalidResponse" {
    var storage = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer storage.deinit();
    const arena = storage.allocator();
    var server = try DnsServer.init("127.0.0.1", 0, &.{
        .{
            .flags = 0x8000,
            .authority = &.{"test. 60 IN NS ns.test."},
            .additional = &.{"ns.test. 60 IN A 127.0.0.1"},
        },
        .{ .raw_answer = "\xc0\x0c\x01\x01\x00\x01\x00\x00\x00\x3c\x00\x08" ++
            "\x00\x01\xffvalue" },
    });
    defer server.deinit();
    try server.start();
    const result = try std.process.run(arena, std.testing.io, .{
        .argv = &.{
            test_options.binary,
            "example.test",
            "--trace",
            "--json",
            "--server",
            "127.0.0.1",
            "--port",
            try arena.print("{d}", .{server.port()}),
            "--tries",
            "1",
            "--timeout-ms",
            "200",
        },
        .timeout = .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } },
    });

    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, result.term);
    try std.testing.expect(std.mem.containsAtLeast(u8, result.stderr, 1, "InvalidResponse"));
    const parsed = try std.json.parseFromSlice(std.json.Value, arena, result.stdout, .{});
    const document = parsed.value.object;
    try std.testing.expect(!document.get("complete").?.bool);
    try std.testing.expectEqualStrings("InvalidResponse", document.get("error").?.string);
    const hops = document.get("hops").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), hops.len);
    const authority = hops[0].object.get("authority").?.array.items;
    try std.testing.expectEqualStrings("ns.test.", authority[0].object.get("data").?.string);
}
