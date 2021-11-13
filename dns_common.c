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
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <arpa/nameser.h>

#include "dns_common.h"

static char *get_ip_str(int type, char *s, const void *data)
{
	switch (type) {
	case ns_t_a:
		inet_ntop(AF_INET, data, s, INET_ADDRSTRLEN);
		break;
	case ns_t_aaaa:
		inet_ntop(AF_INET6, data, s, INET6_ADDRSTRLEN);
		break;
	default:
		error("%s: invalid type '%d'", __func__, type);
	}

	return s;
}

/* "valid" for our cases */
static bool is_ns_type_valid(ns_type type)
{
	switch(type) {
	case ns_t_a:
	case ns_t_aaaa:
	case ns_t_afsdb:
	case ns_t_srv:
		return true;
	default:
		return false;
	}
}

/*
 * Append an address to the payload segment list
 */
static void append_address_to_payload(char *addr, payload_t *payload)
{
	size_t len = strlen(addr);
	int i;

	if (!payload) {
		error("payload buffer is NULL, can't append addr '%s'", addr);
		return;
	}

	debug("append '%s'", addr);

	if (payload->index + 2 > MAX_PAYLOAD - 1) {
		info("payload buffer is full, can't append addr '%s'", addr);
		return;
	}

	/* do not append duplicate entry */
	for (i = 0; i < payload->index; i++)
		if (payload->data[i].iov_len == len &&
		    memcmp(payload->data[i].iov_base, addr, len) == 0)
			return;

	if (payload->index != 0) {
		payload->data[payload->index  ].iov_base = ",";
		payload->data[payload->index++].iov_len = 1;
	}
	payload->data[payload->index  ].iov_base = (void *) strndup(addr, len);
	payload->data[payload->index++].iov_len = len;
}

/**
 * Parses query response (types A/AAAA) and appends the IP address to @payload.
 *
 * Returns the smallest TTL from all IPs found.
 */
static unsigned int hosts_to_addrs(struct host_info *host, ns_msg *handle,
				   payload_t *payload)
{
	unsigned int ttl = UINT_MAX;
	int rrnum, rrmax, rrcount;
	ns_rr rr;
	int type;
	const unsigned char *rdata;
	int iplen = INET6_ADDRSTRLEN + 8 + 1; /* IPv4/v6 + port + NUL */
	char ipbuf[iplen];

	rrcount = ns_msg_count(*handle, ns_s_an);
	rrmax = rrcount;

	debug("RR count is %d", rrcount);

	/* Look at all the resource records in this section. */
	for (rrnum = 0; rrnum < rrmax ; rrnum++) {
		/* Expand the resource record number rrnum into rr. */
		if (ns_parserr(handle, ns_s_an, rrnum, &rr)) {
			_error("ns_parserr failed : %m");
			continue;
		}

		rdata = ns_rr_rdata(rr);
		ttl = MIN(ns_rr_ttl(rr), ttl);
		type = ns_rr_type(rr);

		get_ip_str(type, ipbuf, rdata);

		if (type == ns_t_srv)
			strcat(host->ip, host->port);

		append_address_to_payload(host->ip, payload);

		info("Type '%s' RR, server name: %s, IP: %*.*s, ttl: %d",
				print_ns_type(type),
				host->hostname,
				iplen, iplen,
				host->ip, ttl);
	}

	return ttl;
}

/**
 * Get maximum number of hostname targets some AFSDB/SRV record might have.
 */
static int get_n_targets(ns_msg *handle)
{
	int count = ns_msg_count(*handle, ns_s_an);
	int max = count;

	debug("RR count is %d", max);

	if (max > MAX_VLS) {
		debug("Processing only '%d' records.", MAX_VLS);
		max = MAX_VLS;
	}

	return max;
}

/**
 * Get host targets/cells for AFSDB and SRV records.
 *
 * Stores hosts information into @hosts. Must be freed by caller.
 * @ntgts is the maximum number of targets we have available to process. Should
 * be return value of get_n_targets().
 *
 * Returns the number of hosts processed.
 */
static int get_targets(ns_msg *handle, ns_type type, int ntgts,
		       struct host_info **hosts)
{
	int n = 0;			/* list index */
	int hostlen = sizeof(struct host_info);
	int rrn;
	ns_rr rr;
	int subtype = 0;		/* for ns_t_afsdb */
	int i;
	const unsigned char *rdata;
	unsigned short prio, weight, port; /* for ns_t_srv */

	/* Look at all the resource records in this section. */
	for (rrn = 0; rrn < ntgts; rrn++) {
		/* Expand the resource record number rrnum into rr. */
		if (ns_parserr(handle, ns_s_an, rrn, &rr)) {
			_error("ns_parserr failed : %m");
			continue;
		}

		rdata = ns_rr_rdata(rr);
		hosts[n] = calloc(1, hostlen);
		if (!hosts[n])
			goto out_oom;

		/* increment rdata after reading each field, based on type */
		switch (type) {
		case ns_t_mx: // FIXME
		case ns_t_afsdb:
			subtype = ns_get16(rdata); rdata += NS_INT16SZ;
			info("rdata: subtype %d", subtype);
			break;
		case ns_t_srv:
			prio = ns_get16(rdata); rdata += NS_INT16SZ;
			weight = ns_get16(rdata); rdata += NS_INT16SZ;
			port = ns_get16(rdata); rdata += NS_INT16SZ;

			sprintf(hosts[n]->port, "+%hu", port);

			info("rdata: prio %u weight %u port %u",
			     prio, weight, port);
			break;
		default:
			_error("Invalid type '%d'", type);
			goto next;
		}

		hosts[n]->hostname = calloc(1, MAXDNAME);

		/* Expand the name server's domain name. */
		if (ns_name_uncompress(ns_msg_base(*handle),
				       ns_msg_end(*handle),
				       rdata,
				       hosts[n]->hostname,
				       MAXDNAME) < 0) {
			_error("ns_name_uncompress() failed: %m\n"
			       "trying next result...");
			goto next;
		}

		/* discard if duplicate */
		for (i = 0; i < n; i++)
			if (strcasecmp(hosts[i]->hostname,
				       hosts[n]->hostname) == 0)
				goto next;

		n++;
		continue;

next:
		free(hosts[n]->hostname);
		free(hosts[n]);
	}

	/* failed to parse all records? */
	if (n == 0)
		error("Failed to parse all records");

	return n;

out_oom:
	if (n != 0) {
		for (i = 0; i < n; i++) {
			if (hosts[i]->hostname)
				free(hosts[i]->hostname);
			free(hosts[i]);
		}
	}

	free(hosts);
	error("Out of memory"); /* exits */
}

/*
 * Dump the payload when debugging
 */
void dump_payload(payload_t *payload)
{
	size_t plen, n;
	char *buf, *p;
	int i;

	plen = 0;
	for (i = 0; i < payload->index; i++) {
		n = payload->data[i].iov_len;
		debug("seg[%d]: %zu", i, n);
		plen += n;
	}
	if (plen == 0) {
		info("The key instantiation data is empty");
		return;
	}

	debug("total: %zu", plen);
	buf = malloc(plen + 1);
	if (!buf)
		return;

	p = buf;
	for (i = 0; i < payload->index; i++) {
		n = payload->data[i].iov_len;
		memcpy(p, payload->data[i].iov_base, n);
		p += n;
	}

	info("The key instantiation data is '%s'", buf);
	free(buf);
}

/* returns a handle for RR processing */
static ns_msg *dns_query(char *hostname, ns_type type)
{
	res_state sp = calloc(1, sizeof(*sp)); /* res_state is a pointer to
						  struct __res_state */
	ns_msg	*handle = NULL;		/* handle for response message */
	int	len;			/* response buffer length */
	union {
		HEADER hdr;
		u_char buf[NS_PACKETSZ];
	} response; /* response buffers */

	if (res_ninit(sp) < 0)
		error("Can't initialize sp");

	/* query the dns for a @type resource record */
	len = res_nquery(sp,
			 hostname,
			 ns_c_in,
			 type,
			 response.buf,
			 sizeof(response));

	if (len < 0 || len > NS_MAXMSG) {
		_nsError(h_errno, hostname);
		goto out;
	}

	handle = malloc(sizeof(ns_msg));
	if (!handle)
		error("Out of memory");

	if (ns_initparse(response.buf, len, handle) < 0)
		error("ns_initparse: %m");

out:
	res_nclose(sp);

	return handle;
}

/**
 * Perform address resolution on a hostname and add the resulting addresses as
 * strings to the list of payload segments.
 *
 * @host: host information to query for
 * @type: DNS query type
 * @payload: payload buffer to append results to. Must be initialized in caller.
 */
int dns_resolver(struct host_info *host, ns_type type, payload_t *payload)
{
	struct host_info **hosts;
	ns_msg **handles; /* A/AAAA-only handles */
	int ntgts = 0, i;
	ns_type newtype = type;
	unsigned int ttl;

	if (!is_ns_type_valid(type)) {
		debug("unused ns_type '%s' (%d) in keyutils",
		      print_ns_type(type), type);
		//return -1;
	}

	debug("Get RR (type '%s') for hostname '%s'",
	      print_ns_type(type), host->hostname);

	/* get targets for AFSDB/SRV record types */
	if (type == ns_t_afsdb || type == ns_t_srv) {
		int maxtgts;
		ns_msg *tmp;

		/*
		 * caller for AFSDB/SRV sets either AF_INET *or* AF_INET6,
		 * but not both, nor UNSPEC, like A/AAAA queries can do
		 */
		if (HAS_INET(host->mask))
			newtype = ns_t_a;
		else if (HAS_INET6(host->mask))
			newtype = ns_t_aaaa;

		tmp = dns_query(host->hostname, type);
		if (!tmp)
			error("Can't query '%s' with type '%s'", host->hostname,
			      print_ns_type(type));

		maxtgts = get_n_targets(tmp);
		hosts = calloc(maxtgts, sizeof(*host));
		if (!hosts) {
			free(tmp);
			error("Out of memory");
		}
		ntgts = get_targets(tmp, type, maxtgts, hosts);
		free(tmp);
	} else if (type == ns_t_a || type == ns_t_aaaa) {
		ntgts = 1;
		hosts = calloc(1, sizeof(*host));
		hosts[0] = host;
	}

	handles = calloc(ntgts, sizeof(ns_msg));
	if (!handles) {
		_error("Out of memoy");
		goto out_free;
	}
	
	/*
	 * run through @hosts and query each target hostnames to get
	 * and save their IPs
	 */
	for (i = 0; i < ntgts; i++) {
		int ret;
		handles[i] = dns_query(hosts[i]->hostname, newtype);

		if (!handles[i]) {
			_error("Can't query '%s' with type '%s'",
			      host->hostname,
			      print_ns_type(newtype));
			goto out_free;
		}

		hosts[i]->mask = host->mask;
		ret = hosts_to_addrs(hosts[i], handles[i], payload);

		ttl = MIN(ttl, ret);
	}

	/* caller has requested DNS TTL to be used */
	if (host->ttl) {
		info("DNS resolve for '%s' RR results: %u, ttl: %d",
		     print_ns_type(newtype),
		     payload->index,
		     ttl);
		*host->ttl = ttl;
	} else {
		info("DNS resolve for '%s' RR results: %u, ttl: N/A",
		     print_ns_type(newtype),
		     payload->index);
	}

out_free:
	if (ntgts != 0) {
		for(i = 0; i < ntgts; i++) {
			if (hosts[i]) {
				if (hosts[i]->hostname)
					free(hosts[i]->hostname);
				free(hosts[i]);
			}
			if (handles[i])
				free(handles[i]);
		}
		if (hosts)
			free(hosts);
		if (handles)
			free(handles);
	}

	return 0;
}
