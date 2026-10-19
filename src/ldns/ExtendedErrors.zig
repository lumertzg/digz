//! Borrows received EDNS wire data. The packet must outlive this iterator and its text.
const Self = @This();

const std = @import("std");
const c = @import("ldns_c");

remaining: []const u8,

/// Supplemental resolver diagnostics. Text borrows the packet and is not NUL-terminated.
pub const ExtendedError = struct {
    code: u16,
    text: []const u8,

    pub fn description(self: ExtendedError) []const u8 {
        return switch (self.code) {
            c.LDNS_EDE_OTHER => "Other Error",
            c.LDNS_EDE_UNSUPPORTED_DNSKEY_ALG => "Unsupported DNSKEY Algorithm",
            c.LDNS_EDE_UNSUPPORTED_DS_DIGEST => "Unsupported DS Digest Type",
            c.LDNS_EDE_STALE_ANSWER => "Stale Answer",
            c.LDNS_EDE_FORGED_ANSWER => "Forged Answer",
            c.LDNS_EDE_DNSSEC_INDETERMINATE => "DNSSEC Indeterminate",
            c.LDNS_EDE_DNSSEC_BOGUS => "DNSSEC Bogus",
            c.LDNS_EDE_SIGNATURE_EXPIRED => "Signature Expired",
            c.LDNS_EDE_SIGNATURE_NOT_YET_VALID => "Signature Not Yet Valid",
            c.LDNS_EDE_DNSKEY_MISSING => "DNSKEY Missing",
            c.LDNS_EDE_RRSIGS_MISSING => "RRSIGs Missing",
            c.LDNS_EDE_NO_ZONE_KEY_BIT_SET => "No Zone Key Bit Set",
            c.LDNS_EDE_NSEC_MISSING => "NSEC Missing",
            c.LDNS_EDE_CACHED_ERROR => "Cached Error",
            c.LDNS_EDE_NOT_READY => "Not Ready",
            c.LDNS_EDE_BLOCKED => "Blocked",
            c.LDNS_EDE_CENSORED => "Censored",
            c.LDNS_EDE_FILTERED => "Filtered",
            c.LDNS_EDE_PROHIBITED => "Prohibited",
            c.LDNS_EDE_STALE_NXDOMAIN_ANSWER => "Stale NXDOMAIN Answer",
            c.LDNS_EDE_NOT_AUTHORITATIVE => "Not Authoritative",
            c.LDNS_EDE_NOT_SUPPORTED => "Not Supported",
            c.LDNS_EDE_NO_REACHABLE_AUTHORITY => "No Reachable Authority",
            c.LDNS_EDE_NETWORK_ERROR => "Network Error",
            c.LDNS_EDE_INVALID_DATA => "Invalid Data",
            c.LDNS_EDE_SIGNATURE_EXPIRED_BEFORE_VALID => "Signature Expired Before Valid",
            c.LDNS_EDE_TOO_EARLY => "Too Early",
            c.LDNS_EDE_UNSUPPORTED_NSEC3_ITERATIONS_VALUE => "Unsupported NSEC3 Iterations Value",
            c.LDNS_EDE_UNABLE_TO_CONFORM_TO_POLICY => "Unable to Conform to Policy",
            c.LDNS_EDE_SYNTHESIZED => "Synthesized",
            c.LDNS_EDE_INVALID_QUERY_TYPE => "Invalid Query Type",
            else => "Unknown",
        };
    }
};

/// Skips unrelated options. A malformed option ends iteration with an error.
pub fn next(self: *Self) error{InvalidResponse}!?ExtendedError {
    errdefer self.remaining = &.{};

    while (self.remaining.len != 0) {
        const bytes = self.remaining;
        if (bytes.len < 4) return error.InvalidResponse;

        const option = std.mem.readInt(u16, bytes[0..2], .big);
        const length = std.mem.readInt(u16, bytes[2..4], .big);
        if (length > bytes.len - 4) return error.InvalidResponse;

        const data = bytes[4..][0..length];
        self.remaining = bytes[4 + @as(usize, length) ..];
        if (option != c.LDNS_EDNS_EDE) continue;
        if (data.len < 2) return error.InvalidResponse;

        return .{
            .code = std.mem.readInt(u16, data[0..2], .big),
            .text = data[2..],
        };
    }

    return null;
}

test "EDE iteration skips other options and preserves unknown errors" {
    var errors: Self = .{ .remaining = "\x00\x0a\x00\x02\xaa\xbb" ++
        "\x00\x0f\x00\x08\x00\x0fpolicy" ++
        "\x00\x0f\x00\x02\xfe\x01" };

    const blocked = (try errors.next()).?;
    try std.testing.expectEqual(@as(u16, 15), blocked.code);
    try std.testing.expectEqualStrings("policy", blocked.text);

    const unknown = (try errors.next()).?;
    try std.testing.expectEqual(@as(u16, 0xfe01), unknown.code);
    try std.testing.expectEqualStrings("", unknown.text);
    try std.testing.expectEqualStrings("Unknown", unknown.description());
    try std.testing.expectEqual(null, try errors.next());
}

test "malformed EDNS options fail once and end iteration" {
    const malformed = [_][]const u8{
        "\x00\x0f\x00",
        "\x00\x0f\x00\x04\x00\x01",
        "\x00\x0f\x00\x01\x00",
        "\x00\x0a\x00\x04\x00\x01",
    };

    for (malformed) |bytes| {
        var errors: Self = .{ .remaining = bytes };
        try std.testing.expectError(error.InvalidResponse, errors.next());
        try std.testing.expectEqual(null, try errors.next());
    }
}
