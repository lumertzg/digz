#ifndef DIGZ_LDNS_CONFIG_H
#define DIGZ_LDNS_CONFIG_H

/* POSIX configuration for x86_64/aarch64 Linux and macOS without OpenSSL. */

#define HAVE_ARPA_INET_H 1
#define HAVE_ASCTIME_R 1
#define HAVE_ATTR_FORMAT 1
#define HAVE_ATTR_UNUSED 1
#define HAVE_BZERO 1
#define HAVE_CALLOC 1
#define HAVE_CTIME_R 1
#define HAVE_DECL_INET_NTOP 1
#define HAVE_DECL_INET_PTON 1
#define HAVE_ENDPROTOENT 1
#define HAVE_ENDSERVENT 1
#define HAVE_FCNTL 1
#define HAVE_FORK 1
#define HAVE_FORK_AVAILABLE 1
#define HAVE_GETADDRINFO 1
#define HAVE_GETOPT_H 1
#define HAVE_GMTIME_R 1
#define HAVE_INET_ATON 1
#define HAVE_INET_NTOP 1
#define HAVE_INET_PTON 1
#define HAVE_INTTYPES_H 1
#define HAVE_ISASCII 1
#define HAVE_ISBLANK 1
#define HAVE_LOCALTIME_R 1
#define HAVE_MEMMOVE 1
#define HAVE_MEMSET 1
#define HAVE_NETDB_H 1
#define HAVE_NETINET_IN_H 1
#define HAVE_POLL 1
#define HAVE_RANDOM 1
#define HAVE_SLEEP 1
#define HAVE_SNPRINTF 1
#define HAVE_STDARG_H 1
#define HAVE_STDBOOL_H 1
#define HAVE_STDINT_H 1
#define HAVE_STDIO_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRINGS_H 1
#define HAVE_STRING_H 1
#define HAVE_STRTOUL 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_TIMEGM 1
#define HAVE_TIME_H 1
#define HAVE_UNISTD_H 1
#define HAVE__BOOL 1
#define PACKAGE_VERSION "1.9.2"
#define RRTYPE_AMTRELAY 1
#define RRTYPE_DSYNC 1
#define RRTYPE_OPENPGPKEY 1
#define RRTYPE_RESINFO 1
#define RRTYPE_SVCB_HTTPS 1
#define SIZEOF_TIME_T 8
#define STDC_HEADERS 1

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __APPLE__
#include <sys/random.h>
/* ldns defines these unconditionally in str2host.c. */
#undef htonll
#undef ntohll
#endif

_Static_assert(sizeof(void *) == 8, "ldns configuration requires 64-bit pointers");
_Static_assert(sizeof(time_t) == SIZEOF_TIME_T, "ldns configuration requires 64-bit time_t");
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "ldns configuration requires little-endian targets"
#endif

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif
#ifndef BIG_ENDIAN
#define BIG_ENDIAN 4321
#endif
#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif

#define FD_SET_T
#define SOCK_INVALID -1
#define close_socket(s) do { if ((s) != SOCK_INVALID) { close(s); (s) = -1; } } while (0)

/* Cover ldns's internal bootstrap queries too. Never fall back to predictable IDs. */
static inline long digz_random(void) {
    uint32_t value;
    if (getentropy(&value, sizeof(value)) != 0) abort();
    return value & 0x7fffffff;
}
#define random digz_random

int ldns_b64_ntop(const uint8_t *src, size_t size, char *dst, size_t capacity);
int ldns_b64_pton(const char *src, uint8_t *dst, size_t capacity);
static inline size_t ldns_b64_ntop_calculate_size(size_t size) {
    return ((size + 2) / 3) * 4 + 1;
}
static inline size_t ldns_b64_pton_calculate_size(size_t size) {
    return ((size + 3) / 4) * 3 + 1;
}
int ldns_dname_compare_v(const void *a, const void *b);

#ifdef __APPLE__
#define HAVE_STRLCPY 1
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t capacity);
#endif

#endif
