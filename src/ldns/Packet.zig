//! Owns an ldns packet. Copies alias the same allocation and must not be freed separately.
const Self = @This();

const std = @import("std");
const c = @import("ldns_c");
const types = @import("types.zig");
const Status = @import("status.zig").Status;
const Records = @import("Record.zig").Records;
const ExtendedErrors = @import("ExtendedErrors.zig");
const assert = std.debug.assert;

handle: *c.ldns_pkt,

pub const Flags = struct {
    qr: bool,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    ad: bool,
    cd: bool,
};

pub const Header = struct {
    id: u16,
    opcode: types.Opcode,
    rcode: types.Rcode,
    flags: Flags,
};

pub const QueryOptions = struct {
    class: types.Class = .in,
    recursion_desired: bool = true,
    checking_disabled: bool = false,
    authenticated_data: bool = false,
    /// Requests DNSSEC records (DO), not local signature validation.
    dnssec: bool = false,
    /// Null omits EDNS unless DNSSEC or ECS is requested. Fallback may add it.
    edns_udp_size: ?u16 = null,
    /// Explicit client network disclosure, independent of the transport address.
    subnet: ?ClientSubnet = null,
};

pub const ClientSubnet = struct {
    address: std.Io.net.IpAddress,
    prefix_length: u8,

    /// Requires CIDR notation. Host bits are masked when building the query.
    pub fn parse(text: []const u8) error{InvalidSubnet}!ClientSubnet {
        const slash = std.mem.findScalar(u8, text, '/') orelse return error.InvalidSubnet;
        const address = std.Io.net.IpAddress.parse(text[0..slash], 0) catch {
            return error.InvalidSubnet;
        };
        const prefix_text = text[slash + 1 ..];
        if (prefix_text.len == 0) return error.InvalidSubnet;
        for (prefix_text) |digit| {
            if (digit < '0' or digit > '9') return error.InvalidSubnet;
        }

        const prefix = std.fmt.parseUnsigned(u8, prefix_text, 10) catch {
            return error.InvalidSubnet;
        };
        if (prefix > @as(u8, if (address == .ip4) 32 else 128)) return error.InvalidSubnet;

        return .{ .address = address, .prefix_length = prefix };
    }
};

pub const Edns = struct {
    version: u8,
    udp_size: u16,
    flags: u16,
    dnssec_ok: bool,
};

pub const QueryError = error{ OutOfMemory, InvalidQuery, InvalidSubnet, UnexpectedLdnsStatus };
pub const ReverseError = QueryError || error{InvalidAddress};

/// Creates a PTR query for an IPv4 or IPv6 literal. The address is borrowed for this call.
pub fn reverse(address: [:0]const u8, options: QueryOptions) ReverseError!Self {
    if (std.mem.findScalar(u8, address, 0) != null) return error.InvalidAddress;

    var parsed: [*c]c.ldns_rdf = null;
    const status = if (std.mem.findScalar(u8, address, ':') != null)
        c.ldns_str2rdf_aaaa(&parsed, address.ptr)
    else
        c.ldns_str2rdf_a(&parsed, address.ptr);
    switch (status) {
        c.LDNS_STATUS_OK => {},
        c.LDNS_STATUS_MEM_ERR => return error.OutOfMemory,
        else => return error.InvalidAddress,
    }
    assert(parsed != null);
    defer c.ldns_rdf_deep_free(parsed);

    const reversed = c.ldns_rdf_address_reverse(parsed) orelse return error.OutOfMemory;
    defer c.ldns_rdf_deep_free(reversed);

    const text = c.ldns_rdf2str(reversed);
    if (text == null) return error.OutOfMemory;
    defer c.free(text);

    return query(std.mem.span(text), .ptr, options);
}

/// The name is borrowed only for this call. Zero type/class codes and embedded NULs
/// are rejected because ldns would silently substitute defaults or truncate the name.
/// InvalidQuery also covers ldns's generic name-parsing failure status.
pub fn query(name: [:0]const u8, rr_type: types.Type, options: QueryOptions) QueryError!Self {
    if (@backingInt(rr_type) == 0 or @backingInt(options.class) == 0 or
        std.mem.findScalar(u8, name, 0) != null)
    {
        return error.InvalidQuery;
    }
    if (options.edns_udp_size) |udp_size| {
        if (udp_size < 512) return error.InvalidQuery;
    }

    var handle: [*c]c.ldns_pkt = null;
    const status: Status = @fromBackingInt(@intCast(c.ldns_pkt_query_new_frm_str(
        &handle,
        name.ptr,
        @backingInt(rr_type),
        @backingInt(options.class),
        if (options.recursion_desired) c.LDNS_RD else 0,
    )));
    switch (status) {
        .ok => {},
        .out_of_memory => return error.OutOfMemory,
        .err => return error.InvalidQuery,
        else => return error.UnexpectedLdnsStatus,
    }
    assert(handle != null);
    errdefer c.ldns_pkt_free(handle);

    c.ldns_pkt_set_cd(handle, @intFromBool(options.checking_disabled));
    c.ldns_pkt_set_ad(handle, @intFromBool(options.authenticated_data));
    c.ldns_pkt_set_edns_udp_size(handle, options.edns_udp_size orelse
        @as(u16, if (options.dnssec or options.subnet != null) 1232 else 0));
    c.ldns_pkt_set_edns_do(handle, @intFromBool(options.dnssec));
    if (options.subnet) |subnet| try setClientSubnet(handle, subnet);

    return .{ .handle = handle };
}

fn setClientSubnet(handle: *c.ldns_pkt, subnet: ClientSubnet) QueryError!void {
    if (subnet.prefix_length > @as(u8, if (subnet.address == .ip4) 32 else 128)) {
        return error.InvalidSubnet;
    }

    // RFC 7871: scope is zero in queries. Only significant address bytes go on wire.
    var data: [20]u8 = @splat(0);
    switch (subnet.address) {
        .ip4 => |address| {
            data[1] = 1;
            @memcpy(data[4..8], &address.bytes);
        },
        .ip6 => |address| {
            data[1] = 2;
            @memcpy(data[4..20], &address.bytes);
        },
    }
    data[2] = subnet.prefix_length;
    const length = 4 + (@as(usize, subnet.prefix_length) + 7) / 8;
    const remainder: u3 = @intCast(subnet.prefix_length % 8);
    if (remainder != 0) {
        const host_bits: u3 = @intCast(8 - @as(u4, remainder));
        data[length - 1] &= @as(u8, 0xff) << host_bits;
    }

    const option = c.ldns_edns_new_from_data(c.LDNS_EDNS_CLIENT_SUBNET, length, &data) orelse {
        return error.OutOfMemory;
    };
    errdefer c.ldns_edns_deep_free(option);

    const list = c.ldns_edns_option_list_new() orelse return error.OutOfMemory;
    errdefer c.ldns_edns_option_list_deep_free(list);

    if (c.ldns_edns_option_list_push(list, option) == 0) return error.OutOfMemory;
    c.ldns_pkt_set_edns_option_list(handle, list);
}

/// Invalidates this owner and every alias of its packet.
pub fn deinit(self: *Self) void {
    c.ldns_pkt_free(self.handle);
    self.* = undefined;
}

/// Returns text owned by the caller. Release it with allocator.free.
pub fn toText(self: *const Self, allocator: std.mem.Allocator) error{OutOfMemory}![]u8 {
    return types.copyText(allocator, c.ldns_pkt2str(self.handle));
}

pub fn header(self: *const Self) Header {
    const rcode: u16 = @intCast(c.ldns_pkt_get_rcode(self.handle));
    const extended: u16 = c.ldns_pkt_edns_extended_rcode(self.handle);

    return .{
        .id = c.ldns_pkt_id(self.handle),
        .opcode = @fromBackingInt(@intCast(c.ldns_pkt_get_opcode(self.handle))),
        .rcode = @fromBackingInt(rcode | (extended << 4)),
        .flags = .{
            .qr = c.ldns_pkt_qr(self.handle) != 0,
            .aa = c.ldns_pkt_aa(self.handle) != 0,
            .tc = c.ldns_pkt_tc(self.handle) != 0,
            .rd = c.ldns_pkt_rd(self.handle) != 0,
            .ra = c.ldns_pkt_ra(self.handle) != 0,
            .ad = c.ldns_pkt_ad(self.handle) != 0,
            .cd = c.ldns_pkt_cd(self.handle) != 0,
        },
    };
}

/// OPT metadata is separate from the additional record view in ldns.
pub fn edns(self: *const Self) ?Edns {
    if (c.ldns_pkt_edns(self.handle) == 0) return null;

    return .{
        .version = c.ldns_pkt_edns_version(self.handle),
        .udp_size = c.ldns_pkt_edns_udp_size(self.handle),
        .flags = c.ldns_pkt_edns_z(self.handle),
        .dnssec_ok = c.ldns_pkt_edns_do(self.handle) != 0,
    };
}

/// Reads received OPT data without ldns's allocating, lazy option-list parser.
pub fn extendedErrors(self: *const Self) ExtendedErrors {
    const data = c.ldns_pkt_edns_data(self.handle);
    if (data == null) return .{ .remaining = &.{} };

    return .{ .remaining = c.ldns_rdf_data(data)[0..c.ldns_rdf_size(data)] };
}

pub fn records(self: *const Self, section: types.Section) Records {
    return .{ .handle = switch (section) {
        .question => c.ldns_pkt_question(self.handle),
        .answer => c.ldns_pkt_answer(self.handle),
        .authority => c.ldns_pkt_authority(self.handle),
        .additional => c.ldns_pkt_additional(self.handle),
    } };
}

pub fn size(self: *const Self) usize {
    return c.ldns_pkt_size(self.handle);
}

/// The replying nameserver address, or null for packets without transport metadata.
/// The returned text is owned by the caller, not borrowed from the packet.
pub fn serverText(self: *const Self, allocator: std.mem.Allocator) error{OutOfMemory}!?[]u8 {
    const address = c.ldns_pkt_answerfrom(self.handle);
    if (address == null) return null;

    const text = try types.copyText(allocator, c.ldns_rdf2str(address));
    return text;
}

test "ECS queries serialize masked prefixes with exact wire lengths" {
    const cases = [_]struct { cidr: []const u8, opt_data: []const u8 }{
        .{ .cidr = "203.0.113.237/0", .opt_data = "\x00\x08\x00\x08\x00\x04\x00\x01\x00\x00" },
        .{ .cidr = "2001:db8::1/0", .opt_data = "\x00\x08\x00\x08\x00\x04\x00\x02\x00\x00" },
        .{
            .cidr = "192.0.2.255/25",
            .opt_data = "\x00\x0c\x00\x08\x00\x08\x00\x01\x19\x00\xc0\x00\x02\x80",
        },
        .{
            .cidr = "203.0.113.237/32",
            .opt_data = "\x00\x0c\x00\x08\x00\x08\x00\x01\x20\x00\xcb\x00\x71\xed",
        },
        .{
            .cidr = "2001:db8:abff::1/41",
            .opt_data = "\x00\x0e\x00\x08\x00\x0a\x00\x02\x29\x00\x20\x01\x0d\xb8\xab\x80",
        },
        .{
            .cidr = "2001:db8:abcd:9876:5432:fedc:ba98:7654/128",
            .opt_data = "\x00\x18\x00\x08\x00\x14\x00\x02\x80\x00" ++
                "\x20\x01\x0d\xb8\xab\xcd\x98\x76\x54\x32\xfe\xdc\xba\x98\x76\x54",
        },
    };

    for (cases) |case| {
        var packet = try query("example.com", .a, .{ .subnet = try ClientSubnet.parse(case.cidr) });
        defer packet.deinit();

        var wire: [*c]u8 = null;
        var length: usize = 0;
        const status = c.ldns_pkt2wire(&wire, packet.handle, &length);
        try std.testing.expect(status == c.LDNS_STATUS_OK);
        defer c.free(wire);

        // A fixed question ends at byte 29. Compare the complete OPT record, not C internals.
        try std.testing.expectEqualSlices(u8, "\x00\x01", wire[10..12]);
        try std.testing.expectEqualSlices(u8, "\x00\x00\x29\x04\xd0\x00\x00\x00\x00", wire[29..38]);
        try std.testing.expectEqualSlices(u8, case.opt_data, wire[38..length]);
    }
}

test "invalid subnet input and directly constructed prefixes are rejected" {
    const invalid = [_][]const u8{
        "192.0.2.1", "192.0.2.1/", "192.0.2.1/33", "::1/129", "::1/-1",
        "::1/1_2",   "::1/64/2",   "::1/+64",      "foo/24",  "fe80::1%lo/64",
    };

    for (invalid) |text| {
        try std.testing.expectError(error.InvalidSubnet, ClientSubnet.parse(text));
    }

    for ([_][]const u8{ "192.0.2.1", "2001:db8::1" }, [_]u8{ 33, 129 }) |text, prefix| {
        const address = try std.Io.net.IpAddress.parse(text, 0);
        try std.testing.expectError(error.InvalidSubnet, query("example.com", .a, .{
            .subnet = .{ .address = address, .prefix_length = prefix },
        }));
    }
}

test "ECS enables EDNS without overriding explicit size or query flags" {
    var plain = try query("example.com", .a, .{});
    defer plain.deinit();
    try std.testing.expectEqual(null, plain.edns());

    var packet = try reverse("198.51.100.77", .{
        .subnet = try ClientSubnet.parse("2001:db8:abff::1/41"),
        .edns_udp_size = 512,
        .dnssec = true,
        .recursion_desired = false,
        .checking_disabled = true,
        .authenticated_data = true,
    });
    defer packet.deinit();

    const metadata = packet.edns().?;
    try std.testing.expectEqual(@as(u16, 512), metadata.udp_size);
    try std.testing.expect(metadata.dnssec_ok);
    try std.testing.expect(!packet.header().flags.rd);
    try std.testing.expect(packet.header().flags.cd and packet.header().flags.ad);
    try std.testing.expectEqual(types.Type.ptr, packet.records(.question).at(0).rrType());
}
