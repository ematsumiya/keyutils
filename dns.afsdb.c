/*
 * DNS Resolver Module User-space Helper for AFSDB records
 *
 * Copyright (C) Wang Lei (wang840925@gmail.com) 2010
 * Authors: Wang Lei (wang840925@gmail.com)
 *
 * Copyright (C) David Howells (dhowells@redhat.com) 2018
 *
 * This is a userspace tool for querying AFSDB RR records in the DNS on behalf
 * of the kernel, and converting the VL server addresses to IPv4 format so that
 * they can be used by the kAFS filesystem.
 *
 * As some function like res_init() should use the static library, which is a
 * bug of libresolv, that is the reason for cifs.upcall to reimplement.
 *
 * To use this program, you must tell /sbin/request-key how to invoke it.  You
 * need to have the keyutils package installed and something like the following
 * lines added to your /etc/request-key.conf file:
 *
 * 	#OP    TYPE         DESCRIPTION CALLOUT INFO PROGRAM ARG1 ARG2 ARG3 ...
 * 	====== ============ =========== ============ ==========================
 * 	create dns_resolver afsdb:*     *            /sbin/key.dns_resolver %k
 *
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
#include "key.dns.h"

/*
 * Look up an AFSDB record to get the VL server addresses.
 */
static int dns_query_AFSDB(struct host_info *host, payload_t *payload)
{
	return dns_resolver(host, ns_t_afsdb, payload);
}

/*
 * Look up an SRV record to get the VL server addresses [RFC 5864].
 */
static int dns_query_VL_SRV(struct host_info *host, payload_t *payload)
{
	return dns_resolver(host, ns_t_srv, payload);
}

/*
 * Instantiate the key.
 */
static __attribute__((noreturn))
void afs_instantiate(payload_t *payload)
{
	int ret;

	/* set the key's expiry time from the minimum TTL encountered */
	if (!debug_mode) {
		ret = keyctl_set_timeout(key, key_expiry);
		if (ret == -1)
			error("%s: keyctl_set_timeout: %m", __func__);
	}

	/* must include a NUL char at the end of the payload */
	payload->data[payload->index].iov_base = "";
	payload->data[payload->index++].iov_len = 1;
	dump_payload(payload);

	/* load the key with data key */
	if (!debug_mode) {
		ret = keyctl_instantiate_iov(key, payload->data, payload->index, 0);
		if (ret == -1)
			error("%s: keyctl_instantiate: %m", __func__);
	}

	exit(0);
}

/*
 * Look up VL servers for AFS.
 */
void afs_look_up_VL_servers(char *cell, char *options, payload_t *payload)
{
	struct host_info host = { 0 };

	host.hostname = cell;

	/*
	 * Is the IP address family limited?
	 *
	 * FIXME: shouldn't ONE_ADDR_ONLY be handled here?
	 */
	if (strcmp(options, "ipv4") == 0)
		host.mask |= AF_INET;
	else if (strcmp(options, "ipv6") == 0)
		host.mask |= AF_INET6;

	if (dns_query_VL_SRV(&host, payload) != 0)
		dns_query_AFSDB(&host, payload);

	/* handle a lack of results */
	if (payload->index == 0)
		nsError(NO_DATA, cell);

	afs_instantiate(payload);
}
