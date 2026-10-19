//! Local UDP DNS server fixture for trace and CLI regression tests.
const Self = @This();

const std = @import("std");
const c = @import("ldns_c");
const assert = std.debug.assert;

socket: std.Io.net.Socket,
replies: []const Reply,
thread: ?std.Thread = null,
stopping: std.atomic.Value(bool) = .init(false),
failure: ?anyerror = null,

pub const Reply = struct {
    flags: u16 = 0x8400,
    answer: []const [:0]const u8 = &.{},
    authority: []const [:0]const u8 = &.{},
    additional: []const [:0]const u8 = &.{},
    /// One wire-format answer for records rejected by ldns's text parser.
    raw_answer: ?[]const u8 = null,
};

pub fn init(address: []const u8, listen_port: u16, replies: []const Reply) !Self {
    assert(replies.len > 0);

    const ip = try std.Io.net.IpAddress.parse(address, listen_port);
    return .{
        .socket = try ip.bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp }),
        .replies = replies,
    };
}

/// Start only after the fixture has reached its final address in memory.
pub fn start(self: *Self) !void {
    self.thread = try std.Thread.spawn(.{}, serve, .{self});
}

pub fn deinit(self: *Self) void {
    self.stopping.store(true, .release);
    if (self.thread) |thread| thread.join();
    self.socket.close(std.testing.io);
    if (self.failure) |err| std.debug.panic("DNS fixture failed: {t}", .{err});
    self.* = undefined;
}

pub fn port(self: *const Self) u16 {
    return self.socket.address.getPort();
}

fn serve(self: *Self) void {
    self.run() catch |err| {
        self.failure = err;
    };
}

fn run(self: *Self) !void {
    var index: usize = 0;
    var buffer: [4096]u8 = undefined;
    while (!self.stopping.load(.acquire)) {
        const message = self.socket.receiveTimeout(std.testing.io, &buffer, .{
            .duration = .{ .raw = .fromMilliseconds(20), .clock = .awake },
        }) catch |err| switch (err) {
            error.Timeout => continue,
            else => return err,
        };
        var storage = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer storage.deinit();

        const reply = self.replies[@min(index, self.replies.len - 1)];
        const data = try encode(storage.allocator(), message.data, reply);
        try self.socket.send(std.testing.io, &message.from, data);
        index += 1;
    }
}

fn encode(arena: std.mem.Allocator, query: []const u8, reply: Reply) ![]const u8 {
    var header: [12]u8 = @splat(0);
    @memcpy(header[0..2], query[0..2]);
    std.mem.writeInt(u16, header[2..4], reply.flags, .big);
    std.mem.writeInt(u16, header[4..6], 1, .big);
    std.mem.writeInt(u16, header[6..8], @intCast(
        reply.answer.len + @intFromBool(reply.raw_answer != null),
    ), .big);
    std.mem.writeInt(u16, header[8..10], @intCast(reply.authority.len), .big);
    std.mem.writeInt(u16, header[10..12], @intCast(reply.additional.len), .big);

    var end: usize = 12;
    while (query[end] != 0) end += 1 + @as(usize, query[end]);
    end += 5;

    var result: std.ArrayList(u8) = .empty;
    try result.appendSlice(arena, &header);
    try result.appendSlice(arena, query[12..end]);
    const sections = [_][]const [:0]const u8{ reply.answer, reply.authority, reply.additional };
    for (sections, 0..) |section, i| {
        for (section) |text| {
            var record: [*c]c.ldns_rr = null;
            if (c.ldns_rr_new_frm_str(&record, text.ptr, 0, null, null) != c.LDNS_STATUS_OK) {
                return error.InvalidFixtureRecord;
            }
            defer c.ldns_rr_free(record);

            var wire: [*c]u8 = null;
            var length: usize = 0;
            if (c.ldns_rr2wire(&wire, record, c.LDNS_SECTION_ANSWER, &length) != c.LDNS_STATUS_OK) {
                return error.InvalidFixtureRecord;
            }
            defer c.free(wire);

            try result.appendSlice(arena, wire[0..length]);
        }
        if (i == 0) {
            if (reply.raw_answer) |wire| try result.appendSlice(arena, wire);
        }
    }

    return result.items;
}
