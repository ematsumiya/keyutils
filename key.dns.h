/*
 * Common DNS resolving code for keyutils
 *
 * Copyright (c) 2022, SUSE LLC
 * Author: Enzo Matsumiya <ematsumiya@suse.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#ifndef _KEY_DNS_H
#define _KEY_DNS_H 

#define _GNU_SOURCE
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <limits.h>
#include <resolv.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/uio.h> // struct iovec

#include "keyutils.h"

extern int verbose;
extern int debug_mode;
extern key_serial_t key;
extern long key_expiry;

#define DEFAULT_KEY_TTL 5

#define MAX_VLS		15	/* Max Volume Location Servers Per-Cell (AFSDB) */
#define MAX_PAYLOAD	256	/* Max number of payload vectors (iovecs) */

#define MAX_ADDRS	MAX_PAYLOAD	/* Max number of IP addresses for a hostname */
#define MAX_ADDR_LEN	(INET6_ADDRSTRLEN + 8 + 1)
#define MAX_TARGETS	128

#define IS_IP4(af)	((af) == AF_INET)
#define IS_IP6(af)	((af) == AF_INET6)
#define IS_IP_ANY(af)	((af) == AF_UNSPEC)

/* For DNS/libresolv-specific messages */
void nsError(const char *hostname);
void nsError_ex(const char *hostname);
int get_err(int optval);
/* For keyutils-specific messages */
extern __attribute__((format(printf, 3, 4)))
void _log(FILE *f, int level, const char *fmt, ...);

/*
 * Just print an error to stderr or the syslog
 */
#define error(fmt, ...) \
	do { \
		_log(stderr, LOG_ERR, "E: " fmt, ##__VA_ARGS__); \
	} while (0)

/*
 * Print an error to stderr or the syslog, negate the key being created, and
 * exit with a generic -1 error code.
 *
 * On error, negatively instantiate the key ourselves so that we can
 * make sure the kernel doesn't hang it off of a searchable keyring
 * and interfere with the next attempt to instantiate the key.
 */
#define error_ex(fmt, ...) \
	do { \
		_log(stderr, LOG_ERR, fmt, ##__VA_ARGS__); \
		if (!debug_mode) \
			keyctl_negate(key, 1, KEY_REQKEY_DEFL_DEFAULT); \
		exit(-1); \
	} while (0)

#define error_oom() error_ex("%s: out of memory", __func__)

/*
 * Print a warning to stderr or the syslog
 */
#define warn(fmt, ...) \
	do { \
		_log(stderr, LOG_WARNING, "W: " fmt, ##__VA_ARGS__); \
	} while (0)

/*
 * Print status information
 */
#define info(fmt, ...) \
	do { \
		if (verbose >= 1) \
			_log(stdout, LOG_INFO, "I: " fmt, ##__VA_ARGS__); \
	} while (0)

/*
 * Print debugging information
 */
#define debug(fmt, ...) \
	do { \
		if (verbose >= 2) \
			_log(stdout, LOG_DEBUG, "D: " fmt, ##__VA_ARGS__); \
	} while (0)

/*
 * Print nameserver warning
 */
#define nsWarn(fmt, ...) \
	do { \
		if (isatty(2)) \
			_log(stderr, LOG_WARNING, "NS: W: " fmt, ##__VA_ARGS__); \
		else \
			_log(stderr, LOG_WARNING, fmt, ##__VA_ARGS__); \
	} while (0)

#define STRNDUP_CHECK(dst, src, len) \
	do { \
		(dst) = strndup(src, len); \
		if (!(dst)) \
			error_oom(); \
	} while (0)

#define CALLOC_CHECK(dst, count, size) \
	do { \
		(dst) = calloc(count, size); \
		if (!(dst)) \
			error_oom(); \
	} while (0)

static inline const char *str_type(ns_type type)
{
	if (type == ns_t_invalid)
		return "invalid";

	if (type == ns_t_any)
		return "A/AAAA";

	/* p_type is deprecated in glibc >2.34 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	return p_type(type);
#pragma GCC diagnostic pop
}

/* data to be sent through keyctl */
struct payload {
	struct iovec data[MAX_PAYLOAD];
	int index;
};

typedef struct payload payload_t;

/* Structure to easily pass around host information */
struct hostinfo {
	char *hostname;
	ns_type type;
	char *addrs[MAX_ADDRS];
	int naddrs;
	char port[10];
	int af;
	long ttl;
	ns_msg *handle;
	bool single_addr;
};

typedef struct hostinfo hostinfo_t;

static inline void dump_host(hostinfo_t *host)
{
	int i = 0;

	if (!host)
		return;

	debug("Host info:");
	debug("  hostname: %s", host->hostname);
	debug("  type: %s", (host->type == ns_t_a || host->type == ns_t_aaaa) ?
			    "A/AAAA" : str_type(host->type));
	for (i = 0; i < host->naddrs; i++)
		debug("  addr[%d]: %s", i, host->addrs[i]);
	if (host->port[0] != '\0')
		debug("  port: %s", host->port+1);
	/* skip af; it's used only internally for resolving and could contain
	 * incoherent information */
	debug("  ttl: %ld", host->ttl);
}

static inline void free_hostinfo(hostinfo_t *host)
{
	int i;

	if (!host)
		return;

	if (host->hostname) {
		free(host->hostname);
		host->hostname = NULL;
	}
	for (i = 0; i < host->naddrs; i++) {
		if (host->addrs[i]) {
			free(host->addrs[i]);
			host->addrs[i] = NULL;
		}
	}
	if (host->handle) {
		free(host->handle);
		host->handle = NULL;
	}
}

static inline void free_host(hostinfo_t *host)
{
	if (!host)
		return;

	free_hostinfo(host);
	free(host);
	host = NULL;
}

extern void parse_opts(hostinfo_t *host, char *options);
void dump_payload(payload_t *payload);

/* Main function for DNS module */
int dns_resolver(hostinfo_t *host, payload_t *payload);

/* AFS-specific DNS query function */
void afs_lookup_VL_servers(const char *cell, char *options, long config_ttl);

#endif /* _KEY_DNS_H */
