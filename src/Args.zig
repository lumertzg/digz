//! Command-line options and help metadata.
const Self = @This();

const zlap = @import("zlap");

name: ?[]const u8 = null,
reverse: ?[]const u8 = null,
rr_type: []const u8 = "a",
class: []const u8 = "in",
no_recursion: bool = false,
dnssec: bool = false,
checking_disabled: bool = false,
authenticated_data: bool = false,
edns_size: ?u16 = null,
subnet: ?[]const u8 = null,
server: ?[]const u8 = null,
port: u16 = 53,
tcp: bool = false,
ipv4: bool = false,
ipv6: bool = false,
source: ?[]const u8 = null,
timeout_ms: u32 = 5000,
tries: u8 = 3,
trace: bool = false,
details: bool = false,
short: bool = false,
json: bool = false,
json_schema: bool = false,

pub const meta: zlap.Meta(Self) = .{
    .bin = "digz",
    .version = "0.0.1",
    .about = "Query a DNS server and print its response.",
    .fields = .{
        .name = .{
            .positional = true,
            .value_name = "NAME",
            .help = "Optional domain name (default: example.com.).",
        },
        .reverse = .{
            .value_name = "IP",
            .help = "Query PTR records for an IPv4 or IPv6 address instead of a name.",
            .conflicts = &.{ .name, .rr_type },
        },
        .rr_type = .{
            .long = "type",
            .short = 't',
            .value_name = "TYPE",
            .help = "Record type name, decimal code, or TYPE<number> (default: A).",
        },
        .class = .{
            .short = 'c',
            .value_name = "CLASS",
            .help = "Query class name, decimal code, or CLASS<number> (default: IN).",
        },
        .no_recursion = .{
            .help = "Disable the recursion-desired flag.",
        },
        .dnssec = .{
            .help = "Request DNSSEC records (DO), with EDNS size 1232. Does not validate.",
        },
        .checking_disabled = .{
            .help = "Ask the server to disable DNSSEC checking (CD).",
        },
        .authenticated_data = .{
            .help = "Signal support for the server's authenticated-data flag (AD).",
        },
        .edns_size = .{
            .value_name = "BYTES",
            .help = "Enable EDNS version 0 with a UDP payload size of 512–65535 bytes.",
        },
        .subnet = .{
            .value_name = "CIDR",
            .help = "Send EDNS Client Subnet (IPv4/IPv6). Discloses the network to nameservers.",
        },
        .server = .{
            .short = 's',
            .value_name = "HOST",
            .help = "Nameserver IP or hostname. With --trace, selects the starting server.",
        },
        .port = .{
            .short = 'p',
            .help = "Nameserver port (default: 53).",
        },
        .tcp = .{
            .help = "Use TCP instead of UDP. UDP automatically falls back when truncated.",
        },
        .ipv4 = .{
            .short = '4',
            .help = "Use only IPv4 DNS transport, including nameserver hostname lookup.",
            .conflicts = &.{.ipv6},
        },
        .ipv6 = .{
            .short = '6',
            .help = "Use only IPv6 DNS transport, including nameserver hostname lookup.",
            .conflicts = &.{.ipv4},
        },
        .source = .{
            .value_name = "IP",
            .help = "Bind queries to a local IP address. Implies its transport family.",
        },
        .timeout_ms = .{
            .help = "Per-attempt socket timeout in ms (1–2147483647, default: 5000).",
        },
        .tries = .{
            .value_name = "COUNT",
            .help = "Total attempts per server and transport stage (1–255, default: 3).",
        },
        .trace = .{
            .help = "Follow delegations from the root to an authoritative response, without RD.",
            .conflicts = &.{.short},
        },
        .details = .{
            .help = "Show the header, question, and all response sections.",
        },
        .short = .{
            .help = "Print only answer data, one record per line, without wrapping.",
            .conflicts = &.{.details},
        },
        .json = .{
            .help = "Print all response sections as JSON. Trace produces one document.",
            .conflicts = &.{ .short, .details },
        },
        .json_schema = .{
            .help = "Print the JSON output schema without making a query.",
            .conflicts = &.{ .json, .short, .details, .trace },
        },
    },
};
