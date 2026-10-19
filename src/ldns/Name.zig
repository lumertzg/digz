//! A borrowed DNS name. Its record or packet must outlive this view.
const Self = @This();

const std = @import("std");
const c = @import("ldns_c");
const types = @import("types.zig");

handle: *const c.ldns_rdf,

pub fn eql(self: Self, other: Self) bool {
    return c.ldns_dname_compare(self.handle, other.handle) == 0;
}

/// Includes equality. Comparisons use DNS labels, not presentation-string suffixes.
pub fn isWithin(self: Self, parent: Self) bool {
    return self.eql(parent) or c.ldns_dname_is_subdomain(self.handle, parent.handle) != 0;
}

pub fn labels(self: Self) usize {
    return c.ldns_dname_label_count(self.handle);
}

pub fn toText(self: Self, allocator: std.mem.Allocator) error{OutOfMemory}![]u8 {
    return types.copyText(allocator, c.ldns_rdf2str(self.handle));
}
