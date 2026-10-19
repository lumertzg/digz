//! A read-only borrowed record. Text methods return caller-owned allocations.
const Self = @This();

const std = @import("std");
const c = @import("ldns_c");
const types = @import("types.zig");
const Name = @import("Name.zig");
const assert = std.debug.assert;

handle: *const c.ldns_rr,

/// Borrows a packet's record list. The packet must outlive this view and its records.
pub const Records = struct {
    handle: ?*const c.ldns_rr_list,

    pub fn len(self: Records) usize {
        return if (self.handle) |handle| c.ldns_rr_list_rr_count(handle) else 0;
    }

    pub fn at(self: Records, index: usize) Self {
        assert(index < self.len());

        return .{ .handle = c.ldns_rr_list_rr(self.handle.?, index).? };
    }
};

pub fn rrType(self: Self) types.Type {
    return @fromBackingInt(@intCast(c.ldns_rr_get_type(self.handle)));
}

pub fn class(self: Self) types.Class {
    return @fromBackingInt(@intCast(c.ldns_rr_get_class(self.handle)));
}

pub fn ttl(self: Self) u32 {
    return c.ldns_rr_ttl(self.handle);
}

pub fn owner(self: Self) Name {
    return .{ .handle = c.ldns_rr_owner(self.handle).? };
}

/// Borrows an NS record's target name, or null for other or incomplete records.
pub fn nameserver(self: Self) ?Name {
    if (self.rrType() != .ns) return null;

    const name = c.ldns_rr_rdf(self.handle, 0) orelse return null;
    return .{ .handle = name };
}

pub fn ownerText(self: Self, allocator: std.mem.Allocator) error{OutOfMemory}![]u8 {
    return self.owner().toText(allocator);
}

pub const TextError = error{ OutOfMemory, InvalidResponse };

pub fn dataText(self: Self, allocator: std.mem.Allocator) TextError![]u8 {
    const count = c.ldns_rr_rd_count(self.handle);
    if (count == 0) return allocator.dupe(u8, "");

    const buffer = c.ldns_buffer_new(64) orelse return error.OutOfMemory;
    defer c.ldns_buffer_free(buffer);

    for (0..count) |index| {
        if (index != 0 and c.ldns_buffer_printf(buffer, " ") < 0) {
            return error.OutOfMemory;
        }

        // The string-returning API discards conversion errors, including invalid RDATA.
        switch (c.ldns_rdf2buffer_str(buffer, c.ldns_rr_rdf(self.handle, index))) {
            c.LDNS_STATUS_OK => {},
            c.LDNS_STATUS_MEM_ERR => return error.OutOfMemory,
            else => return error.InvalidResponse,
        }
    }

    return types.copyText(allocator, c.ldns_buffer_export2str(buffer));
}

test "RDATA conversion distinguishes malformed records from allocation failure" {
    const wire = "\x00\x01\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++
        "\x00\x01\x01\x00\x01\x00\x00\x00\x3c\x00\x08\x00\x01\xffvalue";
    var packet: [*c]c.ldns_pkt = null;
    try std.testing.expect(c.ldns_wire2pkt(&packet, wire.ptr, wire.len) == c.LDNS_STATUS_OK);
    defer c.ldns_pkt_free(packet);
    const invalid: Self = .{ .handle = c.ldns_rr_list_rr(c.ldns_pkt_answer(packet), 0).? };
    try std.testing.expectError(error.InvalidResponse, invalid.dataText(std.testing.allocator));

    const long_txt = "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ++
        "fedcba9876543210fedcba9876543210\"";
    const cases = [_]struct { record: [:0]const u8, expected: []const u8 }{
        .{
            .record = "example.test. 60 IN MX 10 mail.example.test.",
            .expected = "10 mail.example.test.",
        },
        .{ .record = "example.test. 60 IN TXT " ++ long_txt, .expected = long_txt },
    };
    for (cases) |case| {
        var handle: [*c]c.ldns_rr = null;
        try std.testing.expect(c.ldns_rr_new_frm_str(
            &handle,
            case.record,
            0,
            null,
            null,
        ) == c.LDNS_STATUS_OK);
        defer c.ldns_rr_free(handle);
        const valid: Self = .{ .handle = handle.? };
        const text = try valid.dataText(std.testing.allocator);
        defer std.testing.allocator.free(text);
        try std.testing.expectEqualStrings(case.expected, text);
        try std.testing.expectError(
            error.OutOfMemory,
            valid.dataText(std.testing.failing_allocator),
        );
    }
}
