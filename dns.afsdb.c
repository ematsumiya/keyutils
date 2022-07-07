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
 * Instantiate the key.
 */
static int afs_instantiate(payload_t *payload, unsigned int ttl)
{
	int ret = 0;

	/* set the key's expiry time from the minimum TTL encountered */
	ret = keyctl_set_timeout(key, ttl);
	if (ret) {
		error("%s: keyctl_set_timeout: %m", __func__);
		return ret;
	}

	/* instantiate the key */
	ret = keyctl_instantiate_iov(key, payload->data, payload->index, 0);
	if (ret)
		error("%s: keyctl_instantiate: %m", __func__);

	return ret;
}

/*
 * Lookup VL servers for AFS.
 */
__attribute__((noreturn))
void afs_lookup_VL_servers(const char *cell, char *options, long config_ttl)
{
	payload_t *payload = NULL;
	struct hostinfo host = { 0 };
	char *vlsrv_name = NULL;
	unsigned int ttl;
	int ret = 0;

	if (!cell)
		error_ex("%s: missing hostname", __func__);

	CALLOC_CHECK(vlsrv_name, 1, MAXDNAME);
	snprintf(vlsrv_name, MAXDNAME, "_afs3-vlserver._udp.%s", cell);
	STRNDUP_CHECK(host.hostname, vlsrv_name, strlen(vlsrv_name));
	CALLOC_CHECK(payload, 1, sizeof(payload_t));

	free(vlsrv_name);

	host.af = AF_UNSPEC;
	host.single_addr = true;

	parse_opts(&host, options);

	/*
	 * Look up an SRV record to get the VL server addresses [RFC 5864].
	 */
	host.type = ns_t_srv;
	ret = dns_resolver(&host, payload);
	if (ret) {
		free(host.hostname);
		STRNDUP_CHECK(host.hostname, cell, strlen(cell));

		/*
		 * Look up an AFSDB record to get the VL server addresses.
		 */
		host.type = ns_t_afsdb;
		ret = dns_resolver(&host, payload);
	}

	if (ret || payload->index == 0) {
		ret = get_err(0);
		goto out_free;
	}

	dump_payload(payload);

	/*
	 * If TTL was set through the config file (@config_ttl),
	 * it takes precedence over the one from the DNS record (stored
	 * in host.ttl).
	 */
	if (config_ttl > 0)
		ttl = (unsigned int)config_ttl;
	else if (host.ttl > 0)
		ttl = (unsigned int)host.ttl;
	else
		/* Fallback to default value if dns_resolver() couldn't
		 * get TTL for some reason */
		ttl = DEFAULT_KEY_TTL;

	info("Key timeout will be %u seconds", ttl);

	if (!debug_mode)
		ret = afs_instantiate(payload, ttl);
out_free:
	free_hostinfo(&host);
	free(payload);

	exit(ret);
}
