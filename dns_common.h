/*
 * Common DNS resolving code for keyutils
 *
 * Copyright (c) 2021, SUSE LLC
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
#ifndef DNS_COMMON_H
#define DNS_COMMON_H 

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <limits.h>
#include <sys/uio.h> // struct iovec

#define MAX_VLS		15	/* Max Volume Location Servers Per-Cell (AFSDB) */
#define MAX_PAYLOAD	256	/* Max number of payload vectors (iovecs) */
#define ONE_ADDR_ONLY	100	/* Mask to indicate that only the first address
				   from the DNS record must be returned */

#define HAS_INET(m) 	(((m) & AF_INET) == AF_INET)
#define HAS_INET6(m) 	(((m) & AF_INET6) == AF_INET6)

extern __attribute__((format(printf, 1, 2), noreturn))
void error(const char *fmt, ...);
extern __attribute__((format(printf, 1, 2)))
void _error(const char *fmt, ...);
extern __attribute__((format(printf, 1, 2)))
void warning(const char *fmt, ...);
extern __attribute__((format(printf, 1, 2)))
void info(const char *fmt, ...);
extern __attribute__((noreturn))
void nsError(int err, const char *domain);
extern void _nsError(int err, const char *domain);
extern __attribute__((format(printf, 1, 2)))
void debug(const char *fmt, ...);

extern unsigned int key_expiry;

/*
 * Workaround for deprecated glibc DNS funcitons.
 * This should be harmless, as it's only used for p_type() macro.
 * Any other deprecated function shoulld still be caught with -Wdeprecated-declaration
 */
static inline const char *print_ns_type(int type)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	return p_type(type);
#pragma GCC diagnostic pop
}

struct host_info {
	char *hostname;
	char port[8];
	int mask;
	unsigned int *ttl;
};

struct payload {
	struct iovec data[MAX_PAYLOAD];
	int index;
};

typedef struct payload payload_t;

int dns_resolver(struct host_info *hi, ns_type type, payload_t *payload);

#endif /* DNS_COMMON_H */
