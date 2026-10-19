//! Native build of ldns 1.9.2 for 64-bit Linux and macOS with system OpenSSL 3.
const std = @import("std");

pub fn create(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Optimize,
    prefix: ?[]const u8,
) *std.Build.Module {
    validateTarget(target.result);

    const bindings = b.addTranslateC(.{
        .root_source_file = b.path("src/ldns.h"),
        .target = target,
        .optimize = optimize,
    });
    bindings.defineCMacro("OPENSSL_API_COMPAT", "10100");
    for ([_][]const u8{ "ssl", "crypto" }) |name| {
        bindings.linkSystemLibrary(name, openssl_options);
    }

    if (prefix) |path| {
        const installation: std.Build.LazyPath = .{ .cwd_relative = path };
        bindings.addIncludePath(installation.path(b, "include"));
        const module = bindings.createModule();
        module.addObjectFile(installation.path(b, "lib/libldns.a"));

        return module;
    }

    const upstream = b.dependency("ldns", .{});
    const common = b.addConfigHeader(.{
        .style = .{ .autoconf_at = upstream.path("ldns/common.h.in") },
        .include_path = "ldns/common.h",
    }, .{
        .ldns_build_config_have_ssl = 1,
        .ldns_build_config_have_inttypes_h = 1,
        .ldns_build_config_have_attr_format = 1,
        .ldns_build_config_have_attr_unused = 1,
        .ldns_build_config_have_socklen_t = 1,
        .ldns_build_config_use_dane = 1,
        .ldns_build_config_have_b32_pton = 0,
        .ldns_build_config_have_b32_ntop = 0,
        .ldns_build_config_use_dsa = 1,
        .ldns_build_config_use_ed25519 = 1,
        .ldns_build_config_use_ed448 = 1,
        .ignore = "@ignore@",
        .end = "@end@",
    });
    const util = b.addConfigHeader(.{
        .style = .{ .autoconf_at = upstream.path("ldns/util.h.in") },
        .include_path = "ldns/util.h",
    }, .{
        .include_inttypes_h = "#include <inttypes.h>",
        .include_systypes_h = "#include <sys/types.h>",
        .include_unistd_h = "#include <unistd.h>",
        .PACKAGE_VERSION = "1.9.2",
        .LDNS_VERSION_MAJOR = 1,
        .LDNS_VERSION_MINOR = 9,
        .LDNS_VERSION_MICRO = 2,
        .unused = "@unused@",
    });
    const net = b.addConfigHeader(.{
        .style = .{ .autoconf_at = upstream.path("ldns/net.h.in") },
        .include_path = "ldns/net.h",
    }, .{ .include_sys_socket_h = "#include <sys/socket.h>" });

    const library = b.addLibrary(.{
        .name = "ldns",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    const includes = [_]std.Build.LazyPath{
        upstream.path(""),
        b.path("build/include"),
        common.getOutputDir(),
        util.getOutputDir(),
        net.getOutputDir(),
    };
    for (includes) |include| {
        library.root_module.addIncludePath(include);
        bindings.addIncludePath(include);
    }
    library.root_module.addCSourceFiles(.{
        .root = upstream.path(""),
        .files = &sources,
        .flags = &.{
            "-std=c99",
            "-fno-strict-aliasing",
            "-DOPENSSL_API_COMPAT=10100",
            "-D_GNU_SOURCE",
            "-D_DARWIN_C_SOURCE",
        },
    });
    for ([_][]const u8{ "ssl", "crypto" }) |name| {
        library.root_module.linkSystemLibrary(name, openssl_options);
    }

    const module = bindings.createModule();
    module.linkLibrary(library);
    b.step("deps", "Build static ldns with system OpenSSL").dependOn(&library.step);

    return module;
}

fn validateTarget(target: std.Target) void {
    const supported_abi = switch (target.os.tag) {
        .linux => target.abi == .gnu or target.abi == .musl,
        .macos => target.abi == .none,
        else => false,
    };
    const supported_arch = target.cpu.arch == .x86_64 or target.cpu.arch == .aarch64;
    if (!supported_abi or !supported_arch) {
        @panic("digz supports 64-bit x86_64/aarch64 Linux (glibc or musl) and macOS only");
    }
}

const openssl_options: std.Build.Module.LinkSystemLibraryOptions = .{
    .use_pkg_config = .force,
    .preferred_link_mode = .dynamic,
    .search_strategy = .mode_first,
};

const sources = [_][]const u8{
    "buffer.c",
    "dane.c",
    "dname.c",
    "dnssec.c",
    "dnssec_sign.c",
    "dnssec_verify.c",
    "dnssec_zone.c",
    "duration.c",
    "error.c",
    "higher.c",
    "host2str.c",
    "host2wire.c",
    "keys.c",
    "net.c",
    "packet.c",
    "parse.c",
    "radix.c",
    "rbtree.c",
    "rdata.c",
    "resolver.c",
    "rr.c",
    "rr_functions.c",
    "sha1.c",
    "sha2.c",
    "str2host.c",
    "tsig.c",
    "update.c",
    "util.c",
    "wire2host.c",
    "zone.c",
    "edns.c",
    "compat/b64_ntop.c",
    "compat/b64_pton.c",
    "compat/strlcpy.c",
};
