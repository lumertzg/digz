//! DNS codes and C presentation-string ownership.
const std = @import("std");
const c = @import("ldns_c");

/// DNS type codes, including unnamed and future values.
pub const Type = enum(u16) {
    a = c.LDNS_RR_TYPE_A,
    ns = c.LDNS_RR_TYPE_NS,
    cname = c.LDNS_RR_TYPE_CNAME,
    soa = c.LDNS_RR_TYPE_SOA,
    ptr = c.LDNS_RR_TYPE_PTR,
    mx = c.LDNS_RR_TYPE_MX,
    txt = c.LDNS_RR_TYPE_TXT,
    aaaa = c.LDNS_RR_TYPE_AAAA,
    srv = c.LDNS_RR_TYPE_SRV,
    ixfr = c.LDNS_RR_TYPE_IXFR,
    axfr = c.LDNS_RR_TYPE_AXFR,
    any = c.LDNS_RR_TYPE_ANY,
    _,

    /// Accepts ldns mnemonics case-insensitively, decimal codes, and TYPE<number>.
    pub fn fromText(text: [:0]const u8) error{InvalidType}!Type {
        const code = parseCode(text, "TYPE", c.ldns_get_rr_type_by_name) catch
            return error.InvalidType;

        return @fromBackingInt(code);
    }

    pub fn toText(self: Type, allocator: std.mem.Allocator) error{OutOfMemory}![]u8 {
        return copyText(allocator, c.ldns_rr_type2str(@backingInt(self)));
    }
};

/// DNS class codes, including unnamed and future values.
pub const Class = enum(u16) {
    in = c.LDNS_RR_CLASS_IN,
    ch = c.LDNS_RR_CLASS_CH,
    hs = c.LDNS_RR_CLASS_HS,
    none = c.LDNS_RR_CLASS_NONE,
    any = c.LDNS_RR_CLASS_ANY,
    _,

    /// Accepts ldns mnemonics case-insensitively, decimal codes, and CLASS<number>.
    pub fn fromText(text: [:0]const u8) error{InvalidClass}!Class {
        const code = parseCode(text, "CLASS", c.ldns_get_rr_class_by_name) catch
            return error.InvalidClass;

        return @fromBackingInt(code);
    }

    pub fn toText(self: Class, allocator: std.mem.Allocator) error{OutOfMemory}![]u8 {
        return copyText(allocator, c.ldns_rr_class2str(@backingInt(self)));
    }
};

/// DNS response codes, separate from library and transport errors.
pub const Rcode = enum(u16) {
    noerror = c.LDNS_RCODE_NOERROR,
    formerr = c.LDNS_RCODE_FORMERR,
    servfail = c.LDNS_RCODE_SERVFAIL,
    nxdomain = c.LDNS_RCODE_NXDOMAIN,
    notimpl = c.LDNS_RCODE_NOTIMPL,
    refused = c.LDNS_RCODE_REFUSED,
    _,

    pub fn toText(self: Rcode, allocator: std.mem.Allocator) error{OutOfMemory}![]u8 {
        return copyText(allocator, c.ldns_pkt_rcode2str(@backingInt(self)));
    }
};

pub const Opcode = enum(u8) {
    query = c.LDNS_PACKET_QUERY,
    iquery = c.LDNS_PACKET_IQUERY,
    status = c.LDNS_PACKET_STATUS,
    notify = c.LDNS_PACKET_NOTIFY,
    update = c.LDNS_PACKET_UPDATE,
    _,

    pub fn toText(self: Opcode, allocator: std.mem.Allocator) error{OutOfMemory}![]u8 {
        return copyText(allocator, c.ldns_pkt_opcode2str(@backingInt(self)));
    }
};

pub const Section = enum { question, answer, authority, additional };

pub fn copyText(allocator: std.mem.Allocator, text: [*c]u8) error{OutOfMemory}![]u8 {
    if (text == null) return error.OutOfMemory;
    defer c.free(text);

    return allocator.dupe(u8, std.mem.span(text));
}

fn parseCode(
    text: [:0]const u8,
    comptime prefix: []const u8,
    comptime lookup: anytype,
) error{InvalidValue}!u16 {
    if (text.len == 0 or std.mem.findScalar(u8, text, 0) != null) return error.InvalidValue;

    const prefixed = std.ascii.startsWithIgnoreCase(text, prefix);
    const number = if (prefixed) text[prefix.len..] else text;
    if (prefixed or std.ascii.isDigit(text[0])) {
        if (number.len == 0) return error.InvalidValue;

        // ldns uses atoi for numeric codes, which accepts partial input and ignores overflow.
        for (number) |byte| {
            if (!std.ascii.isDigit(byte)) return error.InvalidValue;
        }

        const code = std.fmt.parseInt(u16, number, 10) catch return error.InvalidValue;
        if (code == 0) return error.InvalidValue;

        return code;
    }

    const code = lookup(text.ptr);
    if (code == 0) return error.InvalidValue;

    return @intCast(code);
}
