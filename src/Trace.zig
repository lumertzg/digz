//! Walks delegations with non-recursive queries. Owns hop responses and borrows the process arena.
const Self = @This();

const std = @import("std");
const ldns = @import("ldns");
const DnsServer = @import("fixtures/DnsServer.zig");
const assert = std.debug.assert;

arena: std.mem.Allocator,
query: *ldns.Packet,
options: ldns.Resolver.Options,
servers: []const [:0]const u8,
response: ?ldns.Packet = null,
depth: usize = 0,
hops: usize = 0,
attempts: usize = 0,
finished: bool = false,

/// The arena and query must outlive the trace. The starting server overrides root hints.
pub fn init(
    arena: std.mem.Allocator,
    query: *ldns.Packet,
    options: ldns.Resolver.Options,
) error{ OutOfMemory, InvalidSource, InvalidOptions }!Self {
    assert(query.records(.question).len() == 1);
    assert(!query.header().flags.rd);

    var resolved_options = options;
    if (options.source) |source| {
        const address = std.Io.net.IpAddress.parse(source, 0) catch return error.InvalidSource;
        const family: ldns.Resolver.Family = if (address == .ip4) .ipv4 else .ipv6;
        if (options.family != .any and options.family != family) return error.InvalidOptions;
        resolved_options.family = family;
    }

    var servers: []const [:0]const u8 = &roots;
    if (options.server) |server| {
        const values = try arena.alloc([:0]const u8, 1);
        values[0] = try arena.dupeSentinel(u8, server, 0);
        servers = values;
    }

    return .{ .arena = arena, .query = query, .options = resolved_options, .servers = servers };
}

pub fn deinit(self: *Self) void {
    if (self.response) |*packet| packet.deinit();
    self.* = undefined;
}

/// The returned packet is borrowed until the next call or deinit.
/// Authoritative answers (including CNAMEs) and DNS error responses end the walk.
pub fn next(self: *Self) !?*const ldns.Packet {
    if (self.finished) return null;

    if (self.response) |*packet| {
        const header = packet.header();
        if (header.flags.aa or header.rcode != .noerror) {
            self.finished = true;
            return null;
        }

        self.servers = try self.referralServers(packet);
    }

    if (self.hops == 32) return error.TraceLimitExceeded;

    const packet = try self.send();
    if (self.response) |*previous| previous.deinit();
    self.response = packet;
    self.hops += 1;

    return &self.response.?;
}

fn send(self: *Self) !ldns.Packet {
    var last_error: anyerror = error.NoNameservers;
    var failure: ?ldns.Packet = null;
    defer if (failure) |*packet| packet.deinit();

    for (self.servers) |server| {
        if (std.Io.net.IpAddress.parse(server, 0)) |address| {
            if (!self.supportsFamily(if (address == .ip4) .ipv4 else .ipv6)) continue;
        } else |_| {}

        // Share one budget across all referrals, rather than multiplying retries at every cut.
        if (self.attempts == 32) {
            if (failure != null) break;
            return error.TraceLimitExceeded;
        }
        self.attempts += 1;

        var options = self.options;
        options.server = server;

        var resolver = ldns.Resolver.init(options) catch |err| {
            if (err == error.OutOfMemory) return err;
            last_error = err;
            continue;
        };
        defer resolver.deinit();

        var packet = resolver.send(self.query) catch |err| {
            if (err == error.OutOfMemory) return err;
            last_error = err;
            continue;
        };
        const rcode = packet.header().rcode;
        if (rcode == .servfail or rcode == .refused) {
            if (failure) |*previous| previous.deinit();
            failure = packet;
            continue;
        }

        if (rcode == .noerror and !packet.header().flags.aa) {
            _ = self.referralZone(&packet) catch |err| {
                packet.deinit();
                last_error = err;
                continue;
            };
        }

        return packet;
    }

    if (failure) |packet| {
        failure = null;
        return packet;
    }

    return last_error;
}

fn supportsFamily(self: *const Self, family: ldns.Resolver.Family) bool {
    return self.options.family == .any or self.options.family == family;
}

fn referralZone(self: *const Self, packet: *const ldns.Packet) error{
    NonAuthoritativeAnswer,
    InvalidReferral,
}!ldns.Name {
    if (packet.records(.answer).len() != 0) return error.NonAuthoritativeAnswer;

    const question = self.query.records(.question).at(0);
    const target = question.owner();
    const authority = packet.records(.authority);
    var cut: ?ldns.Name = null;

    for (0..authority.len()) |index| {
        const record = authority.at(index);
        if (record.rrType() != .ns or record.class() != question.class()) continue;

        const owner = record.owner();
        if (!target.isWithin(owner) or owner.labels() <= self.depth) continue;
        if (cut == null or owner.labels() > cut.?.labels()) cut = owner;
    }

    return cut orelse error.InvalidReferral;
}

fn referralServers(self: *Self, packet: *const ldns.Packet) ![]const [:0]const u8 {
    const zone = try self.referralZone(packet);
    const question = self.query.records(.question).at(0);
    const authority = packet.records(.authority);
    const arena = self.arena;
    const additional = packet.records(.additional);
    var servers: std.ArrayList([:0]const u8) = .empty;

    for (0..authority.len()) |index| {
        const record = authority.at(index);
        if (record.class() != question.class() or !record.owner().eql(zone)) continue;

        const name = record.nameserver() orelse continue;
        var has_glue = false;

        // Additional addresses are trusted only for named servers inside this delegation.
        if (name.isWithin(zone)) {
            for (0..additional.len()) |address_index| {
                const address = additional.at(address_index);
                if (address.class() != .in or !address.owner().eql(name)) continue;
                if (address.rrType() != .a and address.rrType() != .aaaa) continue;
                if (!self.supportsFamily(if (address.rrType() == .a) .ipv4 else .ipv6)) continue;

                const text = try address.dataText(arena);
                try appendServer(arena, &servers, text);
                has_glue = true;
            }
        }

        // Missing and out-of-bailiwick glue use independent hostname bootstrap, not the target.
        if (!has_glue) try appendServer(arena, &servers, try name.toText(arena));
    }

    if (servers.items.len == 0) return error.NoNameservers;
    self.depth = zone.labels();

    return servers.items;
}

fn appendServer(
    arena: std.mem.Allocator,
    servers: *std.ArrayList([:0]const u8),
    text: []const u8,
) error{OutOfMemory}!void {
    for (servers.items) |server| {
        if (std.ascii.eqlIgnoreCase(server, text)) return;
    }

    if (servers.items.len < 64) {
        try servers.append(arena, try arena.dupeSentinel(u8, text, 0));
    }
}

// Bootstrap addresses from ldns's root hints. Each hop still uses the requested port/transport.
const roots = [_][:0]const u8{
    "198.41.0.4",      "170.247.170.2",       "192.33.4.12",        "199.7.91.13",
    "192.203.230.10",  "192.5.5.241",         "192.112.36.4",       "198.97.190.53",
    "192.36.148.17",   "192.58.128.30",       "193.0.14.129",       "199.7.83.42",
    "202.12.27.33",    "2001:503:ba3e::2:30", "2801:1b8:10::b",     "2001:500:2::c",
    "2001:500:2d::d",  "2001:500:a8::e",      "2001:500:2f::f",     "2001:500:12::d0d",
    "2001:500:1::53",  "2001:7fe::53",        "2001:503:c27::2:30", "2001:7fd::1",
    "2001:500:9f::42", "2001:dc3::35",
};

test "opposite-family-only glue falls back to nameserver hostname lookup" {
    for ([_]ldns.Resolver.Family{ .ipv4, .any }) |family| {
        var storage = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer storage.deinit();
        const arena = storage.allocator();
        var server = try DnsServer.init("127.0.0.1", 0, &.{
            .{
                .flags = 0x8000,
                .authority = &.{"localhost. 60 IN NS localhost."},
                .additional = &.{"localhost. 60 IN AAAA ::1"},
            },
            .{ .answer = &.{"example.localhost. 60 IN A 192.0.2.37"} },
        });
        defer server.deinit();
        try server.start();
        var query = try ldns.Packet.query("example.localhost", .a, .{ .recursion_desired = false });
        defer query.deinit();
        var trace = try init(arena, &query, .{
            .server = "127.0.0.1",
            .port = server.port(),
            .family = family,
            .source = if (family == .any) "127.0.0.1" else null,
            .tries = 1,
            .timeout_ms = 200,
        });
        defer trace.deinit();

        _ = (try trace.next()).?;
        const answers = (try trace.next()).?.records(.answer);
        try std.testing.expectEqual(@as(usize, 1), answers.len());
        const answer = answers.at(0);
        try std.testing.expectEqualStrings("192.0.2.37", try answer.dataText(arena));
        try std.testing.expectEqual(null, try trace.next());
    }
}

test "unusable address families do not consume the trace budget or candidate capacity" {
    var storage = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer storage.deinit();
    const arena = storage.allocator();
    var glue: [65][:0]const u8 = undefined;
    for (glue[0..64], 1..) |*record, index| {
        record.* = try arena.printSentinel("ns.test. 60 IN AAAA 2001:db8::{x}", .{index}, 0);
    }
    glue[64] = "ns.test. 60 IN A 127.0.0.1";

    var server = try DnsServer.init("127.0.0.1", 0, &.{
        .{ .flags = 0x8000, .authority = &.{"test. 60 IN NS ns.test."}, .additional = &glue },
        .{ .answer = &.{"example.test. 60 IN A 192.0.2.81"} },
    });
    defer server.deinit();
    try server.start();
    var query = try ldns.Packet.query("example.test", .a, .{ .recursion_desired = false });
    defer query.deinit();
    var trace = try init(arena, &query, .{
        .server = "127.0.0.1",
        .port = server.port(),
        .family = .ipv4,
        .tries = 1,
        .timeout_ms = 200,
    });
    defer trace.deinit();

    _ = (try trace.next()).?;
    const answers = (try trace.next()).?.records(.answer);
    try std.testing.expectEqual(@as(usize, 1), answers.len());
    const answer = answers.at(0);
    try std.testing.expectEqualStrings("192.0.2.81", try answer.dataText(arena));
    try std.testing.expectEqual(null, try trace.next());
}

test "unusable NOERROR replies and SERVFAIL try a healthy sibling" {
    const failures = [_]DnsServer.Reply{
        .{ .flags = 0x8000 },
        .{ .flags = 0x8000, .answer = &.{"example.test. 60 IN A 192.0.2.99"} },
        .{ .flags = 0x8000, .authority = &.{"test. 60 IN NS ns1.test."} },
        .{ .flags = 0x8002 },
    };

    for (failures) |failure| {
        var storage = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer storage.deinit();
        const arena = storage.allocator();
        var first = try DnsServer.init("127.0.0.1", 0, &.{
            .{
                .flags = 0x8000,
                .authority = &.{ "test. 60 IN NS ns1.test.", "test. 60 IN NS ns2.test." },
                .additional = &.{ "ns1.test. 60 IN A 127.0.0.1", "ns2.test. 60 IN AAAA ::1" },
            },
            failure,
        });
        defer first.deinit();
        var second = try DnsServer.init("::1", first.port(), &.{
            .{ .answer = &.{"example.test. 60 IN A 192.0.2.42"} },
        });
        defer second.deinit();
        try first.start();
        try second.start();
        var query = try ldns.Packet.query("example.test", .a, .{ .recursion_desired = false });
        defer query.deinit();
        var trace = try init(arena, &query, .{
            .server = "127.0.0.1",
            .port = first.port(),
            .tries = 1,
            .timeout_ms = 200,
        });
        defer trace.deinit();

        _ = (try trace.next()).?;
        const answers = (try trace.next()).?.records(.answer);
        try std.testing.expectEqual(@as(usize, 1), answers.len());
        const answer = answers.at(0);
        try std.testing.expectEqualStrings("192.0.2.42", try answer.dataText(arena));
        try std.testing.expectEqual(null, try trace.next());
    }
}
