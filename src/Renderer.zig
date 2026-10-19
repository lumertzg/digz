//! Append-only DNS views. Packet ownership stays with the caller.
const Self = @This();

const std = @import("std");
const ldns = @import("ldns");
const assert = std.debug.assert;

arena: std.mem.Allocator,
writer: *std.Io.Writer,
options: Options = .{},

pub const Result = struct {
    packet: *const ldns.Packet,
    elapsed_ms: i64,
    port: u16,
    /// Configured mode. ldns does not expose which fallback attempt succeeded.
    tcp: bool,
    trace: ?struct {
        hop: usize,
        elapsed_ms: i64,
    } = null,
};

pub const Options = struct {
    details: bool = false,
    short: bool = false,
    color: bool = false,
    borders: bool = false,
    /// Null means unbounded output, as when writing to a file.
    width: ?usize = null,
};

pub const Error = ldns.Record.TextError || std.Io.Writer.Error;

/// Allocations live in the caller's arena. Leaves flushing to the caller.
pub fn write(self: Self, result: Result) Error!void {
    assert(result.elapsed_ms >= 0);
    assert(self.options.width == null or self.options.width.? > 0);
    assert(!(self.options.short and self.options.details));

    if (result.trace) |trace| {
        assert(trace.hop > 0);
        assert(trace.elapsed_ms >= result.elapsed_ms);
        assert(!self.options.short);
        if (!self.options.details) return self.renderTrace(result);
    }

    try self.render(result);
}

const Column = enum { name, ttl, class, rr_type, data };

const Row = struct {
    name: []const u8,
    ttl: []const u8,
    class: []const u8,
    rr_type: []const u8,
    data: []const u8,

    fn cell(self: Row, column: Column) []const u8 {
        return switch (column) {
            .name => self.name,
            .ttl => self.ttl,
            .class => self.class,
            .rr_type => self.rr_type,
            .data => self.data,
        };
    }
};

const labels: Row = .{
    .name = "NAME",
    .ttl = "TTL",
    .class = "CLASS",
    .rr_type = "TYPE",
    .data = "DATA",
};
const Style = enum { title, heading, accent, muted, positive, negative };

fn render(self: Self, value: Result) Error!void {
    const arena = self.arena;

    if (self.options.short) {
        const answers = value.packet.records(.answer);
        for (0..answers.len()) |index| {
            const text = try answers.at(index).dataText(arena);
            try self.writer.writeAll(try escape(arena, text));
            try self.writer.writeByte('\n');
        }
        return;
    }

    const header = value.packet.header();
    const status = try header.rcode.toText(arena);
    const answers = value.packet.records(.answer).len();
    const status_style: Style = if (header.rcode == .noerror) .positive else .negative;

    if (self.options.details) {
        try self.styledLine("HEADER", .heading);
        try self.field("ID", try arena.print("{d}", .{header.id}));
        try self.field("Opcode", try header.opcode.toText(arena));
        try self.style(status_style);
        try self.field("Status", status);
        try self.reset();

        var flags = std.Io.Writer.Allocating.init(arena);
        defer flags.deinit();

        inline for (@typeInfo(ldns.Packet.Flags).@"struct".field_names) |name| {
            if (@field(header.flags, name)) {
                if (flags.written().len != 0) try flags.writer.writeByte(' ');
                try flags.writer.writeAll(name);
            }
        }
        try self.field("Flags", flags.written());

        if (value.packet.edns()) |edns| {
            try self.writer.writeByte('\n');
            try self.styledLine("EDNS", .heading);
            try self.field("Version", try arena.print("{d}", .{edns.version}));
            try self.field("UDP size", try arena.print("{d} bytes", .{edns.udp_size}));
            try self.field("Flags", try arena.print("{s} (0x{x:0>4})", .{
                if (edns.dnssec_ok) "do" else "no DO", edns.flags,
            }));

            var errors = value.packet.extendedErrors();
            while (true) {
                const extended = (errors.next() catch {
                    try self.field("EDE", "Malformed EDNS option");
                    break;
                }) orelse break;
                const text = try escape(arena, extended.text);
                try self.field("EDE", try arena.print("{d} ({s}){s}{s}", .{
                    extended.code, extended.description(), if (text.len == 0) "" else ": ", text,
                }));
            }
        }

        for (std.enums.values(ldns.Section)) |which| {
            try self.writer.writeByte('\n');
            try self.section(value.packet.records(which), which);
        }
    } else {
        const questions = value.packet.records(.question);
        if (questions.len() != 0) {
            const question = questions.at(0);
            const name = try escape(arena, try question.ownerText(arena));
            const rr_type = try question.rrType().toText(arena);
            const class = try question.class().toText(arena);
            try self.line(try arena.print("{s}  {s}{s}{s}", .{
                name,
                rr_type,
                if (question.class() == .in) "" else "  ",
                if (question.class() == .in) "" else class,
            }), 0, .title);
        }
        try self.styledLine(try arena.print("{s}  {d} answer{s}  {d} ms", .{
            status, answers, if (answers == 1) "" else "s", value.elapsed_ms,
        }), status_style);
        try self.writer.writeByte('\n');

        if (answers == 0) {
            const message = if (header.rcode == .nxdomain)
                "Name does not exist."
            else
                "No answer records.";
            try self.line(message, 0, null);
        } else {
            try self.section(value.packet.records(.answer), .answer);
        }
    }
    try self.writer.writeByte('\n');
    try self.metadata(value);
    if (value.trace != null) try self.writer.writeByte('\n');
}

fn renderTrace(self: Self, value: Result) Error!void {
    const arena = self.arena;
    const trace = value.trace.?;
    const header = value.packet.header();
    const answers = value.packet.records(.answer);
    const status = try header.rcode.toText(arena);
    const status_style: Style = if (header.rcode == .noerror) .positive else .negative;

    if (trace.hop == 1) {
        const questions = value.packet.records(.question);
        if (questions.len() != 0) {
            const question = questions.at(0);
            const name = try escape(arena, try question.ownerText(arena));
            try self.styledLine(try arena.print("{s}  {s}  {s}", .{
                name, try question.rrType().toText(arena), try question.class().toText(arena),
            }), .title);
        }
        try self.line(if (value.tcp) "TCP" else "UDP (TCP fallback enabled)", 0, .muted);
        try self.writer.writeByte('\n');
    } else if (self.options.borders and
        (self.options.width == null or self.options.width.? > 3))
    {
        try self.style(.muted);
        try self.writer.writeAll("│\n↓\n");
        try self.reset();
    } else {
        try self.writer.writeByte('\n');
    }

    const address = try escape(arena, try value.packet.serverText(arena) orelse "unknown");
    const endpoint = if (std.mem.findScalar(u8, address, ':') != null)
        try arena.print("[{s}]:{d}", .{ address, value.port })
    else
        try arena.print("{s}:{d}", .{ address, value.port });
    try self.traceLine(try arena.print("HOP {d}  {s}  {d} ms", .{
        trace.hop, endpoint, value.elapsed_ms,
    }), .title, true);

    const kind = if (header.rcode != .noerror)
        "DNS error"
    else if (header.flags.aa)
        "authoritative"
    else if (answers.len() != 0)
        "non-authoritative answer"
    else
        "referral";
    try self.traceLine(try arena.print("{s}  {s}", .{ status, kind }), status_style, false);

    const records = if (answers.len() != 0) answers else value.packet.records(.authority);
    if (header.rcode == .nxdomain) try self.traceLine("Name does not exist.", null, false);
    if (records.len() == 0) try self.traceLine("No answer records.", null, false);
    for (0..records.len()) |index| {
        const record = records.at(index);
        const name = try escape(arena, try record.ownerText(arena));
        const data = try escape(arena, try record.dataText(arena));
        const class = if (record.class() == .in) "" else try arena.print("{s}  ", .{
            try record.class().toText(arena),
        });
        try self.traceLine(try arena.print("{s}  {s}{s}  {s}", .{
            name, class, try record.rrType().toText(arena), data,
        }), null, false);
    }

    // Match the walk's terminal condition, not merely the presence of answer records.
    if (header.flags.aa or header.rcode != .noerror) {
        try self.writer.writeByte('\n');
        try self.styledLine(try arena.print("{s}  {d} answer{s}  {d} hop{s}  {d} ms", .{
            status,    answers.len(),                   if (answers.len() == 1) "" else "s",
            trace.hop, if (trace.hop == 1) "" else "s", trace.elapsed_ms,
        }), status_style);
    }
}

fn traceLine(self: Self, text: []const u8, color: ?Style, node: bool) Error!void {
    const decorated = self.options.borders and
        (self.options.width == null or self.options.width.? > 3);
    const indent: usize = if (decorated) 3 else if (node) 0 else 2;
    const spaces = if (self.options.width) |width| @min(indent, width - 1) else indent;
    const available = if (self.options.width) |width| width - spaces else @max(text.len, 1);
    const colored = if (color == .positive or color == .negative)
        std.mem.findScalar(u8, text, ' ') orelse text.len
    else
        text.len;
    var rest = text;
    var first = node;

    while (rest.len != 0) {
        if (decorated) {
            try self.style(if (first) .heading else .muted);
            try self.writer.writeAll(if (first) "●  " else "│  ");
            try self.reset();
        } else {
            try self.writer.splatByteAll(' ', spaces);
        }
        var count = @min(rest.len, available);
        if (rest.len > available) {
            if (std.mem.findScalarLast(u8, rest[0..count], ' ')) |space| count = space + 1;
        }

        try self.styledText(rest[0..count], color, colored -| (text.len - rest.len));
        try self.writer.writeByte('\n');
        rest = rest[count..];
        first = false;
    }
}

fn metadata(self: Self, value: Result) Error!void {
    const arena = self.arena;
    const address = try value.packet.serverText(arena) orelse "unknown";
    const server = try escape(arena, address);
    const endpoint = if (std.mem.findScalar(u8, server, ':') != null)
        try arena.print("[{s}]:{d}", .{ server, value.port })
    else
        try arena.print("{s}:{d}", .{ server, value.port });

    if (self.options.details) try self.styledLine("QUERY", .heading);
    try self.style(.muted);
    try self.field("Server", endpoint);
    try self.field("Transport", if (value.tcp) "TCP" else "UDP (TCP fallback enabled)");
    if (self.options.details) {
        try self.field("Elapsed", try arena.print("{d} ms", .{value.elapsed_ms}));
        try self.field("Size", try arena.print("{d} bytes", .{value.packet.size()}));
    }
    try self.reset();
}

fn section(self: Self, records: ldns.Records, which: ldns.Section) Error!void {
    const arena = self.arena;

    if (self.options.details) {
        const title = switch (which) {
            .question => "QUESTION",
            .answer => "ANSWER",
            .authority => "AUTHORITY",
            .additional => "ADDITIONAL",
        };
        try self.styledLine(try arena.print("{s}  {d} record{s}", .{
            title, records.len(), if (records.len() == 1) "" else "s",
        }), .heading);
    }
    if (records.len() == 0) return;

    const rows = try arena.alloc(Row, records.len());
    var show_class = self.options.details;

    for (rows, 0..) |*row, index| {
        const record = records.at(index);
        show_class = show_class or record.class() != .in;
        row.* = .{
            .name = try escape(arena, try record.ownerText(arena)),
            .ttl = try arena.print("{d}", .{record.ttl()}),
            .class = try record.class().toText(arena),
            .rr_type = try record.rrType().toText(arena),
            .data = if (which == .question)
                ""
            else
                try escape(arena, try record.dataText(arena)),
        };
    }

    const columns: []const Column = if (which == .question)
        &.{ .name, .class, .rr_type }
    else if (show_class)
        &.{ .name, .ttl, .class, .rr_type, .data }
    else
        &.{ .name, .ttl, .rr_type, .data };
    try self.table(rows, columns);
}

fn table(self: Self, rows: []const Row, columns: []const Column) Error!void {
    var widths: [5]usize = @splat(0);
    const spacing = if (self.options.borders) 3 * columns.len + 1 else 2 * (columns.len - 1);
    var total: usize = spacing;

    for (columns, 0..) |column, index| {
        widths[index] = labels.cell(column).len;
        for (rows) |row| widths[index] = @max(widths[index], row.cell(column).len);
        total += widths[index];
    }

    if (self.options.width) |width| {
        const last = columns.len - 1;
        if (total > width and columns[last] == .data) {
            const fixed = total - widths[last];
            if (width >= fixed + labels.data.len) {
                widths[last] = width - fixed;
                total = width;
            }
        }
        if (total > width) {
            for (rows, 0..) |row, index| {
                if (index != 0) try self.writer.writeByte('\n');
                const title = try self.arena.print("Record {d}", .{index + 1});
                try self.styledLine(title, .muted);
                for (columns) |column| try self.field(labels.cell(column), row.cell(column));
            }
            return;
        }
    }

    const sizes = widths[0..columns.len];
    if (self.options.borders) try self.border(sizes, "┌", "┬", "┐");
    try self.tableRow(labels, columns, sizes, true);
    if (self.options.borders) try self.border(sizes, "├", "┼", "┤");
    for (rows) |row| try self.tableRow(row, columns, sizes, false);
    if (self.options.borders) try self.border(sizes, "└", "┴", "┘");
}

fn tableRow(
    self: Self,
    row: Row,
    columns: []const Column,
    widths: []const usize,
    header: bool,
) Error!void {
    const last = columns.len - 1;
    var offset: usize = 0;
    while (true) {
        var end = @min(offset + widths[last], row.data.len);
        if (columns[last] == .data and end < row.data.len) {
            if (std.mem.findScalarLast(u8, row.data[offset..end], ' ')) |space| {
                end = offset + space + 1;
            }
        }

        if (self.options.borders) {
            try self.style(.muted);
            try self.writer.writeAll("│ ");
            try self.reset();
        }

        for (columns, widths, 0..) |column, width, index| {
            const text = if (column == .data)
                row.data[offset..end]
            else if (offset == 0)
                row.cell(column)
            else
                "";
            const padding = width - text.len;
            if (column == .ttl) try self.writer.splatByteAll(' ', padding);

            if (header) {
                try self.style(.heading);
            } else switch (column) {
                .name, .ttl, .class => try self.style(.muted),
                .rr_type => try self.style(.accent),
                .data => {},
            }
            try self.writer.writeAll(text);
            try self.reset();

            if (column != .ttl and (self.options.borders or index + 1 != columns.len)) {
                try self.writer.splatByteAll(' ', padding);
            }
            try self.style(.muted);
            if (index + 1 != columns.len) {
                try self.writer.writeAll(if (self.options.borders) " │ " else "  ");
            }
            try self.reset();
        }
        if (self.options.borders) {
            try self.style(.muted);
            try self.writer.writeAll(" │");
            try self.reset();
        }
        try self.writer.writeByte('\n');

        offset = end;
        if (columns[last] != .data or offset >= row.data.len) break;
    }
}

fn border(
    self: Self,
    widths: []const usize,
    left: []const u8,
    middle: []const u8,
    right: []const u8,
) Error!void {
    try self.style(.muted);
    try self.writer.writeAll(left);

    for (widths, 0..) |width, index| {
        for (0..width + 2) |_| try self.writer.writeAll("─");
        try self.writer.writeAll(if (index + 1 == widths.len) right else middle);
    }
    try self.reset();
    try self.writer.writeByte('\n');
}

fn field(self: Self, label: []const u8, value: []const u8) Error!void {
    try self.line(try self.arena.print("{s}: {s}", .{ label, value }), 2, null);
}

// All variable text is ASCII-escaped before layout, so bytes equal terminal cells.
fn line(self: Self, text: []const u8, indent: usize, color: ?Style) Error!void {
    const spaces = if (self.options.width) |width| @min(indent, width - 1) else indent;
    const available = if (self.options.width) |width| width - spaces else @max(text.len, 1);
    const colored = if (color == .positive or color == .negative)
        std.mem.findScalar(u8, text, ' ') orelse text.len
    else
        text.len;
    var rest = text;

    while (rest.len != 0) {
        const count = @min(rest.len, available);
        try self.writer.splatByteAll(' ', spaces);
        try self.styledText(rest[0..count], color, colored -| (text.len - rest.len));
        try self.writer.writeByte('\n');
        rest = rest[count..];
    }
}

fn styledLine(self: Self, text: []const u8, color: Style) Error!void {
    try self.line(text, 0, color);
}

fn styledText(self: Self, text: []const u8, color: ?Style, colored: usize) Error!void {
    const value = color orelse return self.writer.writeAll(text);
    const end = @min(text.len, colored);
    try self.style(value);
    try self.writer.writeAll(text[0..end]);
    if (end < text.len) {
        try self.reset();
        try self.style(.muted);
        try self.writer.writeAll(text[end..]);
    }
    try self.reset();
}

fn style(self: Self, color: Style) Error!void {
    if (!self.options.color) return;

    try self.writer.writeAll(switch (color) {
        .title => "\x1b[1m",
        .heading => "\x1b[1;36m",
        .accent => "\x1b[36m",
        .muted => "\x1b[90m",
        .positive => "\x1b[1;32m",
        .negative => "\x1b[1;33m",
    });
}

fn reset(self: Self) Error!void {
    if (self.options.color) try self.writer.writeAll("\x1b[0m");
}

/// Borrows printable input, otherwise returns arena-backed escaped text.
fn escape(arena: std.mem.Allocator, text: []const u8) error{OutOfMemory}![]const u8 {
    const start = for (text, 0..) |byte, index| {
        if (byte < 0x20 or byte > 0x7e) break index;
    } else return text;

    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(arena);
    try bytes.appendSlice(arena, text[0..start]);

    const hex = "0123456789abcdef";
    for (text[start..]) |byte| {
        if (byte >= 0x20 and byte <= 0x7e) {
            try bytes.append(arena, byte);
        } else {
            try bytes.appendSlice(arena, &.{ '\\', 'x', hex[byte >> 4], hex[byte & 15] });
        }
    }

    return bytes.toOwnedSlice(arena);
}
