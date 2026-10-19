//! Library errors, separate from DNS response codes.
const std = @import("std");
const c = @import("ldns_c");

/// Library statuses, not DNS response codes. Unnamed statuses retain their numeric value.
pub const Status = enum(c.ldns_status) {
    ok = c.LDNS_STATUS_OK,
    out_of_memory = c.LDNS_STATUS_MEM_ERR,
    err = c.LDNS_STATUS_ERR,
    _,

    pub const Error = error{
        OutOfMemory,
        NetworkError,
        SocketError,
        NoNameservers,
        ResponseIdMismatch,
        ResponseQuestionMismatch,
        InvalidResponse,
        UnexpectedLdnsStatus,
    };

    /// Converts transport and response-parsing statuses to Zig errors.
    /// NetworkError includes timeouts because ldns does not distinguish them.
    pub fn check(self: Status) Error!void {
        return switch (@backingInt(self)) {
            c.LDNS_STATUS_OK => {},
            c.LDNS_STATUS_MEM_ERR => error.OutOfMemory,
            c.LDNS_STATUS_NETWORK_ERR => error.NetworkError,
            c.LDNS_STATUS_SOCKET_ERROR => error.SocketError,
            c.LDNS_STATUS_RES_NO_NS => error.NoNameservers,
            c.LDNS_STATUS_ID_DID_NOT_MATCH => error.ResponseIdMismatch,
            c.LDNS_STATUS_QUERY_DID_NOT_MATCH => error.ResponseQuestionMismatch,
            c.LDNS_STATUS_QDCOUNT_MUST_BE_ONE,
            c.LDNS_STATUS_WIRE_INCOMPLETE_HEADER,
            c.LDNS_STATUS_WIRE_INCOMPLETE_QUESTION,
            c.LDNS_STATUS_WIRE_INCOMPLETE_ANSWER,
            c.LDNS_STATUS_WIRE_INCOMPLETE_AUTHORITY,
            c.LDNS_STATUS_WIRE_INCOMPLETE_ADDITIONAL,
            c.LDNS_STATUS_WIRE_RDATA_ERR,
            c.LDNS_STATUS_PACKET_OVERFLOW,
            c.LDNS_STATUS_INVALID_POINTER,
            c.LDNS_STATUS_LABEL_OVERFLOW,
            c.LDNS_STATUS_DOMAINNAME_OVERFLOW,
            c.LDNS_STATUS_DOMAINNAME_UNDERFLOW,
            c.LDNS_STATUS_RDATA_OVERFLOW,
            => error.InvalidResponse,
            else => error.UnexpectedLdnsStatus,
        };
    }

    /// Returns borrowed static text, with a fallback for unrecognized statuses.
    pub fn message(self: Status) []const u8 {
        const text = c.ldns_get_errorstr_by_id(@backingInt(self));
        if (text == null) return "Unknown ldns status";

        return std.mem.span(text);
    }
};
