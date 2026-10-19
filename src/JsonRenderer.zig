//! Machine-readable DNS responses. Snapshots own arena-backed text, not packet pointers.
const Self = @This();

const std = @import("std");
const ldns = @import("ldns");
const assert = std.debug.assert;

writer: *std.Io.Writer,

pub const Question = struct {
    name: []const u8,
    type: []const u8,
    type_code: u16,
    class: []const u8,
    class_code: u16,
};

pub const Record = struct {
    name: []const u8,
    ttl: u32,
    type: []const u8,
    type_code: u16,
    class: []const u8,
    class_code: u16,
    /// DNS presentation text, including quoting and escaping for TXT and unknown types.
    data: []const u8,
};

pub const Response = struct {
    schema_version: u8 = 1,
    question: []const Question,
    header: struct {
        id: u16,
        opcode: []const u8,
        opcode_code: u8,
        rcode: []const u8,
        rcode_code: u16,
        flags: ldns.Packet.Flags,
    },
    answer: []const Record,
    authority: []const Record,
    additional: []const Record,
    edns: ?struct {
        version: u8,
        udp_size: u16,
        flags: u16,
        dnssec_ok: bool,
        extended_errors: []const ExtendedError,
        options_malformed: bool,
    },
    server: ?struct { address: []const u8, port: u16 },
    /// Configured policy, not the transport of the successful fallback attempt.
    transport_policy: enum { tcp, udp_with_tcp_fallback },
    elapsed_ms: i64,
};

pub const ExtendedError = struct {
    code: u16,
    description: []const u8,
    text: []const u8,
};

pub const Trace = struct {
    schema_version: u8 = 1,
    hops: []const Response,
    /// The walk terminated normally, including termination on a DNS error response.
    complete: bool,
    @"error": ?[]const u8,
    elapsed_ms: i64,
};

pub fn write(self: Self, value: anytype) std.Io.Writer.Error!void {
    try std.json.Stringify.value(value, .{ .whitespace = .indent_2 }, self.writer);
    try self.writer.writeByte('\n');
}

pub fn writeSchema(writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try writer.writeAll(@embedFile("json-schema.json"));
}

/// Copies every borrowed field before the trace advances and releases its packet.
pub fn response(
    arena: std.mem.Allocator,
    packet: *const ldns.Packet,
    elapsed_ms: i64,
    port: u16,
    tcp: bool,
) ldns.Record.TextError!Response {
    assert(elapsed_ms >= 0);
    assert(port != 0);

    const header = packet.header();
    const questions = packet.records(.question);
    const question = try arena.alloc(Question, questions.len());
    for (question, 0..) |*item, index| {
        const record = questions.at(index);
        item.* = .{
            .name = try record.ownerText(arena),
            .type = try record.rrType().toText(arena),
            .type_code = @backingInt(record.rrType()),
            .class = try record.class().toText(arena),
            .class_code = @backingInt(record.class()),
        };
    }

    var result: Response = .{
        .question = question,
        .header = .{
            .id = header.id,
            .opcode = try header.opcode.toText(arena),
            .opcode_code = @backingInt(header.opcode),
            .rcode = try header.rcode.toText(arena),
            .rcode_code = @backingInt(header.rcode),
            .flags = header.flags,
        },
        .answer = try records(arena, packet.records(.answer)),
        .authority = try records(arena, packet.records(.authority)),
        .additional = try records(arena, packet.records(.additional)),
        .edns = null,
        .server = if (try packet.serverText(arena)) |address| .{
            .address = address,
            .port = port,
        } else null,
        .transport_policy = if (tcp) .tcp else .udp_with_tcp_fallback,
        .elapsed_ms = elapsed_ms,
    };
    if (packet.edns()) |edns| {
        var errors: std.ArrayList(ExtendedError) = .empty;
        var iterator = packet.extendedErrors();
        var malformed = false;
        while (true) {
            const extended = (iterator.next() catch {
                malformed = true;
                break;
            }) orelse break;
            try errors.append(arena, .{
                .code = extended.code,
                .description = extended.description(),
                .text = try utf8Text(arena, extended.text),
            });
        }
        result.edns = .{
            .version = edns.version,
            .udp_size = edns.udp_size,
            .flags = edns.flags,
            .dnssec_ok = edns.dnssec_ok,
            .extended_errors = try errors.toOwnedSlice(arena),
            .options_malformed = malformed,
        };
    }

    return result;
}

fn records(arena: std.mem.Allocator, source: ldns.Records) ldns.Record.TextError![]const Record {
    const result = try arena.alloc(Record, source.len());
    for (result, 0..) |*item, index| {
        const record = source.at(index);
        item.* = .{
            .name = try record.ownerText(arena),
            .ttl = record.ttl(),
            .type = try record.rrType().toText(arena),
            .type_code = @backingInt(record.rrType()),
            .class = try record.class().toText(arena),
            .class_code = @backingInt(record.class()),
            .data = try record.dataText(arena),
        };
    }

    return result;
}

// EDE text comes from the network. Keep its JSON type stable even for invalid UTF-8.
fn utf8Text(arena: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]const u8 {
    var result: std.ArrayList(u8) = .empty;
    var index: usize = 0;
    while (index < text.len) {
        const length = std.unicode.utf8ByteSequenceLength(text[index]) catch 0;
        if (length != 0 and length <= text.len - index) {
            const sequence = text[index..][0..length];
            if (std.unicode.utf8ValidateSlice(sequence)) {
                try result.appendSlice(arena, sequence);
                index += length;
                continue;
            }
        }
        try result.appendSlice(arena, "\xef\xbf\xbd");
        index += 1;
    }

    return result.toOwnedSlice(arena);
}

test "JSON snapshot outlives its packet and preserves unknown DNS codes" {
    var storage = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer storage.deinit();
    const arena = storage.allocator();

    const snapshot = blk: {
        var packet = try ldns.Packet.query("MiXeD.example", @fromBackingInt(65400), .{
            .class = @fromBackingInt(65001),
            .dnssec = true,
            .checking_disabled = true,
        });
        defer packet.deinit();

        break :blk try response(arena, &packet, 17, 5353, false);
    };

    var output = std.Io.Writer.Allocating.init(arena);
    const renderer: Self = .{ .writer = &output.writer };
    try renderer.write(snapshot);

    const parsed = try std.json.parseFromSlice(std.json.Value, arena, output.written(), .{});
    const object = parsed.value.object;
    const question = object.get("question").?.array.items[0].object;
    try std.testing.expectEqualStrings("MiXeD.example.", question.get("name").?.string);
    try std.testing.expectEqualStrings("TYPE65400", question.get("type").?.string);
    try std.testing.expectEqual(@as(i64, 65400), question.get("type_code").?.integer);
    try std.testing.expectEqualStrings("CLASS65001", question.get("class").?.string);
    try std.testing.expectEqual(@as(i64, 65001), question.get("class_code").?.integer);
    try std.testing.expectEqual(@as(i64, 17), object.get("elapsed_ms").?.integer);
    try std.testing.expectEqualStrings(
        "udp_with_tcp_fallback",
        object.get("transport_policy").?.string,
    );
    try std.testing.expect(object.get("server").? == .null);
    try std.testing.expectEqual(@as(usize, 0), object.get("answer").?.array.items.len);
    try std.testing.expectEqual(@as(usize, 0), object.get("authority").?.array.items.len);
    try std.testing.expectEqual(@as(usize, 0), object.get("additional").?.array.items.len);
    try std.testing.expect(object.get("edns").?.object.get("dnssec_ok").?.bool);
    try std.testing.expectEqual(
        @as(i64, 1232),
        object.get("edns").?.object.get("udp_size").?.integer,
    );
}
