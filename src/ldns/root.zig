//! Typed ldns values, owning packets, and blocking resolver transport.
const std = @import("std");
const types = @import("types.zig");

pub const Type = types.Type;
pub const Class = types.Class;
pub const Rcode = types.Rcode;
pub const Opcode = types.Opcode;
pub const Section = types.Section;
pub const Status = @import("status.zig").Status;
pub const Name = @import("Name.zig");
pub const Packet = @import("Packet.zig");
pub const Resolver = @import("Resolver.zig");
pub const Record = @import("Record.zig");
pub const Records = Record.Records;
pub const ExtendedErrors = @import("ExtendedErrors.zig");
pub const ExtendedError = ExtendedErrors.ExtendedError;

test {
    std.testing.refAllDecls(@This());
}
