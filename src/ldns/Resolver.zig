//! Owns resolver configuration and transport state. Copies alias the same allocation.
//! Calls block in ldns and must not run concurrently on the same resolver or query.
const Self = @This();

const std = @import("std");
const c = @import("ldns_c");
const Packet = @import("Packet.zig");
const Status = @import("status.zig").Status;
const assert = std.debug.assert;

handle: *c.ldns_resolver,
source: ?*c.ldns_rdf = null,

pub const Family = enum(u8) {
    any = c.LDNS_RESOLV_INETANY,
    ipv4 = c.LDNS_RESOLV_INET,
    ipv6 = c.LDNS_RESOLV_INET6,
};

pub const Options = struct {
    /// An IP literal or hostname, or null to load nameservers from /etc/resolv.conf.
    /// Hostnames are bootstrapped separately using hosts and the configured resolver.
    server: ?[:0]const u8 = null,
    port: u16 = 53,
    tcp: bool = false,
    family: Family = .any,
    /// Local IP literal. Its family is used when no transport family is selected.
    source: ?[:0]const u8 = null,
    /// Per-attempt socket timeout, not an overall deadline. Range: 1–2147483647 ms.
    timeout_ms: u32 = 5000,
    /// Total attempts per nameserver and transport stage, including the first.
    tries: u8 = 3,
};

pub const InitError = error{
    OutOfMemory,
    InvalidServer,
    InvalidSource,
    InvalidOptions,
    ResolverConfigFailed,
    NoNameservers,
    ServerLookupFailed,
};

pub fn init(options: Options) InitError!Self {
    if (options.port == 0 or options.timeout_ms == 0 or options.tries == 0) {
        return error.InvalidOptions;
    }

    // ldns converts milliseconds to a signed int for poll. Negative means no deadline.
    if (options.timeout_ms > std.math.maxInt(c_int)) return error.InvalidOptions;

    var handle: [*c]c.ldns_resolver = null;
    if (options.server != null) {
        handle = c.ldns_resolver_new() orelse return error.OutOfMemory;
    } else {
        switch (c.ldns_resolver_new_frm_file(&handle, null)) {
            c.LDNS_STATUS_OK => {},
            c.LDNS_STATUS_MEM_ERR => return error.OutOfMemory,
            else => return error.ResolverConfigFailed,
        }
    }
    assert(handle != null);
    errdefer c.ldns_resolver_deep_free(handle);

    var source: ?*c.ldns_rdf = null;
    errdefer if (source) |address| c.ldns_rdf_deep_free(address);

    var family = options.family;
    if (options.source) |text| {
        source = parseAddress(text) catch |err| switch (err) {
            error.InvalidAddress => return error.InvalidSource,
            error.OutOfMemory => return error.OutOfMemory,
        };
        const source_family: Family = if (c.ldns_rdf_get_type(source.?) == c.LDNS_RDF_TYPE_A)
            .ipv4
        else
            .ipv6;
        if (family != .any and family != source_family) return error.InvalidOptions;
        family = source_family;

        // ldns borrows the source RDF and does not release it in resolver_deep_free.
        c.ldns_resolver_set_source(handle, source.?);
    }
    c.ldns_resolver_set_ip6(handle, @backingInt(family));

    if (options.server) |server| {
        try addServer(handle, server, options);
    }

    if (c.ldns_resolver_nameserver_count(handle) == 0) return error.NoNameservers;

    c.ldns_resolver_set_port(handle, options.port);
    c.ldns_resolver_set_usevc(handle, @intFromBool(options.tcp));
    c.ldns_resolver_set_retry(handle, options.tries);
    c.ldns_resolver_set_timeout(handle, .{
        .tv_sec = @intCast(options.timeout_ms / 1000),
        .tv_usec = @intCast((options.timeout_ms % 1000) * 1000),
    });

    return .{ .handle = handle, .source = source };
}

pub fn deinit(self: *Self) void {
    c.ldns_resolver_deep_free(self.handle);
    if (self.source) |address| c.ldns_rdf_deep_free(address);
    self.* = undefined;
}

/// Borrows the query and returns an independently owned response packet.
/// Replaces the query ID and may add EDNS during UDP-to-TCP fallback.
pub fn send(self: *Self, query: *Packet) Status.Error!Packet {
    c.ldns_pkt_set_random_id(query.handle);

    var answer: [*c]c.ldns_pkt = null;
    const status: Status = @fromBackingInt(@intCast(c.ldns_resolver_send_pkt(
        &answer,
        self.handle,
        query.handle,
    )));
    errdefer c.ldns_pkt_free(answer);
    try status.check();
    assert(answer != null);

    // ldns validates the ID and question, but not these response header fields.
    if (c.ldns_pkt_qr(answer) == 0 or
        c.ldns_pkt_get_opcode(answer) != c.ldns_pkt_get_opcode(query.handle))
    {
        return error.InvalidResponse;
    }

    return .{ .handle = answer };
}

fn addServer(handle: *c.ldns_resolver, server: [:0]const u8, options: Options) InitError!void {
    if (std.mem.findScalar(u8, server, 0) != null) return error.InvalidServer;

    const address = parseAddress(server) catch |err| switch (err) {
        error.InvalidAddress => return addHostname(handle, server, options),
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer c.ldns_rdf_deep_free(address);

    try pushAddress(handle, address);
}

fn parseAddress(text: [:0]const u8) error{ InvalidAddress, OutOfMemory }!*c.ldns_rdf {
    if (std.mem.findScalar(u8, text, 0) != null) return error.InvalidAddress;

    var address: [*c]c.ldns_rdf = null;
    const status = if (std.mem.findScalar(u8, text, ':') != null)
        c.ldns_str2rdf_aaaa(&address, text.ptr)
    else
        c.ldns_str2rdf_a(&address, text.ptr);
    switch (status) {
        c.LDNS_STATUS_OK => {},
        c.LDNS_STATUS_MEM_ERR => return error.OutOfMemory,
        else => return error.InvalidAddress,
    }
    assert(address != null);

    return address;
}

fn addHostname(handle: *c.ldns_resolver, server: [:0]const u8, options: Options) InitError!void {
    _ = std.Io.net.HostName.init(server) catch return error.InvalidServer;

    // The query's server and port must never be used to resolve their own hostname.
    var bootstrap = try init(.{
        .tcp = options.tcp,
        .family = options.family,
        .source = options.source,
        .timeout_ms = options.timeout_ms,
        .tries = options.tries,
    });
    defer bootstrap.deinit();

    // The ldns hostname helper resets the family to ANY. Remove other-family
    // nameservers so bootstrap transport cannot escape the requested family.
    const family = c.ldns_resolver_ip6(bootstrap.handle);
    if (family != c.LDNS_RESOLV_INETANY) {
        const filtered = c.ldns_resolver_clone(bootstrap.handle) orelse return error.OutOfMemory;
        errdefer c.ldns_resolver_deep_free(filtered);

        while (c.ldns_resolver_pop_nameserver(filtered)) |address| {
            c.ldns_rdf_deep_free(address);
        }

        const address_type = if (family == c.LDNS_RESOLV_INET)
            c.LDNS_RDF_TYPE_A
        else
            c.LDNS_RDF_TYPE_AAAA;
        const nameservers = c.ldns_resolver_nameservers(bootstrap.handle);
        for (0..c.ldns_resolver_nameserver_count(bootstrap.handle)) |index| {
            if (c.ldns_rdf_get_type(nameservers[index]) == address_type) {
                try pushAddress(filtered, nameservers[index]);
            }
        }

        c.ldns_resolver_deep_free(bootstrap.handle);
        bootstrap.handle = filtered;
    }

    const name = c.ldns_dname_new_frm_str(server.ptr) orelse return error.OutOfMemory;
    defer c.ldns_rdf_deep_free(name);

    const addresses = c.ldns_get_rr_list_addr_by_name(
        bootstrap.handle,
        name,
        c.LDNS_RR_CLASS_IN,
        c.LDNS_RD,
    ) orelse return error.ServerLookupFailed;
    defer c.ldns_rr_list_deep_free(addresses);

    for (0..c.ldns_rr_list_rr_count(addresses)) |index| {
        const record = c.ldns_rr_list_rr(addresses, index);
        try pushAddress(handle, c.ldns_rr_rdf(record, 0));
    }
}

fn pushAddress(handle: *c.ldns_resolver, address: *const c.ldns_rdf) error{OutOfMemory}!void {
    const index = c.ldns_resolver_nameserver_count(handle);
    if (c.ldns_resolver_push_nameserver(handle, address) != c.LDNS_STATUS_OK) {
        return error.OutOfMemory;
    }

    // ldns reports success even if its internal RDF clone allocation failed.
    if (c.ldns_resolver_nameservers(handle)[index] == null) return error.OutOfMemory;
}
