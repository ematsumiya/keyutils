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

/* Convert a struct sockaddr address to a string, IPv4 and IPv6 */
static char *get_ip_str(const struct sockaddr *sa, char *s)
{
	int af = sa->sa_family;
	size_t len = (af == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN);

	switch (af) {
	case AF_INET:
		inet_ntop(af, &(((struct sockaddr_in *)sa)->sin_addr), s, len);
		break;
	case AF_INET6:
		inet_ntop(af, &(((struct sockaddr_in6 *)sa)->sin6_addr), s, len);
		break;
	default:
		error("%s: inet_ntop: %m", __func__);
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

//static int dns_resolver_gai(struct host_info *, payload_t *);

/**
 * Converts hosts queried by dns_query() to IP addresses.
 *
 * Saves DNS record TTL to @hi->ttl (allocated by caller)
 */
static void hosts_to_addrs(struct host_info *hi, ns_msg handle, ns_sect section,
			   ns_type type, payload_t *payload)
{
	char **server_list;		/* list of name servers	*/
	int n = 0;			/* number of name servers in list */
	int rrnum, rrmax, rrcount;
	ns_rr rr;
	int subtype = 0;		/* only used for ns_t_afsdb */
	int i, ret;
	const unsigned char *rdata;
	unsigned short prio, weight, port; /* used only for ns_t_srv */
	unsigned int ttl = UINT_MAX, rr_ttl;
	char ipbuf[INET6_ADDRSTRLEN + 8 + 1];

	rrcount = ns_msg_count(handle, section);
	rrmax = rrcount;

	if (type == ns_t_afsdb && rrcount > MAX_LVS) {
		debug("RR count '%d' is greater than MAX_LVS (%d)."
		      "Processing '%d' records for AFSDB.",
		      rrcount, MAX_LVS, MAX_LVS);
		rrmax = MAX_LVS;
	} else {
		debug("RR count is %d", rrcount);
	}

	server_list = calloc(rrmax, MAXDNAME);

	/* Look at all the resource records in this section. */
	for (rrnum = 0; rrnum < rrmax ; rrnum++) {
		/* Expand the resource record number rrnum into rr. */
		if (ns_parserr(&handle, section, rrnum, &rr)) {
			_error("ns_parserr failed : %m");
			continue;
		}

		if (ns_rr_type(rr) != type)
			continue;

		rdata = ns_rr_rdata(rr);
		server_list[n] = NULL;

		rr_ttl = ns_rr_ttl(rr);
		if (ttl > rr_ttl)
			ttl = rr_ttl;

		if (type == ns_t_afsdb) {
			subtype = ns_get16(rdata);
			info("rdata: subtype %d", subtype);
		} else if (type == ns_t_srv) {
			prio = ns_get16(rdata);
			weight = ns_get16(rdata);
			port = ns_get16(rdata);

			sprintf(hi->port, "+%hu", port);

			info("rdata: prio %u  weight %u port %u", prio, weight, port);
		}

		server_list[n] = malloc(MAXDNAME);
		if (!server_list[n]) {
			error("Out of memory");
			goto out_free;
		}

		/* Expand the name server's domain name */
		if (ns_name_uncompress(ns_msg_base(handle),
				       ns_msg_end(handle),
				       rdata,
				       server_list[n],
				       MAXDNAME) < 0) {
			perror("ns_name_uncompress() failed");
			_error("trying next result...");
			goto next;
		}

		/* Check the domain name we've just unpacked and add it to
		 * the list of servers if it is not a duplicate.
		 * If it is a duplicate, just ignore it.
		 */
		for (i = 0; i < n; i++)
			if (strcasecmp(server_list[i], server_list[n]) == 0)
				goto next;

		/* Turn the hostname into IP addresses */
		get_ip_str(rdata, ipbuf);

		if (type == ns_t_srv)
			strcat(ipbuf, hi->port);

		append_address_to_payload(ipbuf, payload);

		info("Type '%s' RR, server name: %s, IP: %*.*s, ttl: %d",
				print_ns_type(type),
				hi->hostname,
				(int)strlen(ipbuf),
				(int)strlen(ipbuf),
				ipbuf, ttl);

		/* prepare for the next record */
		n++;
		//continue;

next:
		free(server_list[n]);
	}

	if (hi->ttl) {
		*hi->ttl = ttl;
		info("ttl: %d", ttl);
	} else {
		debug("not saving TTL");
	}

out_free:
	free(server_list);
}

/**
 * Perform DNS query.
 *
 * @hi: host information to query for
 * @type: DNS record type (ns_type) to query for
 * @payload: payload buffer to append results to. Must be initialized in caller.
 */
static int dns_query(struct host_info *hi, ns_type type, payload_t *payload)
{
	char *hostname = hi->hostname;
	int	response_len;		/* buffer length */
	ns_msg	handle;			/* handle for response message */
	union {
		HEADER hdr;
		u_char buf[NS_PACKETSZ];
	} response;		/* response buffers */

	if (!is_ns_type_valid(type)) {
		debug("unused ns_type '%s' (%d) in keyutils",
		      print_ns_type(type), type);
		return -1;
	}

	debug("Get RR (type '%s') for hostname '%s'",
	      print_ns_type(type), hostname);

	/* query the dns for a @type resource record */
	response_len = res_query(hostname,
				 ns_c_in,
				 type,
				 response.buf,
				 sizeof(response));

	if (response_len < 0) {
		/* negative result */
		_nsError(h_errno, hostname);
		return -1;
	}

	if (ns_initparse(response.buf, response_len, &handle) < 0)
		error("ns_initparse: %m");

	/* look up the hostnames we've obtained to get the actual addresses */
	hosts_to_addrs(hi, handle, ns_s_an, type, payload);

	if (hi->ttl)
		info("DNS query '%s' RR results: %u, ttl: %d",
		     print_ns_type(type),
		     payload->index,
		     *hi->ttl);
	else
		info("DNS query '%s' RR results: %u, ttl: N/A",
		     print_ns_type(type),
		     payload->index);
	return 0;
}

/*
 * Append an address to the payload segment list
 */
void append_address_to_payload(char *addr, payload_t *payload)
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

/* resolve name using getaddrinfo() (see below) */
static int dns_resolver_gai(struct host_info *hi, payload_t *payload)
{
	struct addrinfo hints, *addr, *ai;
	char buf[INET6_ADDRSTRLEN + 8 + 1];
	char *hostname = hi->hostname;
	int mask = hi->mask;
	int af_mask = ((mask & ONE_ADDR_ONLY) == ONE_ADDR_ONLY) ?
		       mask & ~ONE_ADDR_ONLY : mask;
	int ret;

	if (!(af_mask & AF_INET) && !(af_mask & AF_INET6)) {
		info("Invalid address family '%d'", mask);
		return -1;
	}

	memset(&hints, 0, sizeof(hints));

	debug("Resolve '%s' using:", hostname);
	if (HAS_INET(af_mask))
		debug("  IPv4");
	if (HAS_INET6(af_mask))
		debug("  IPv6");

	/* getaddrinfo() will query both IPv4 and IPv6 if ai_family is AF_UNSPEC */
	if (HAS_INET(af_mask) && HAS_INET6(af_mask))
		hints.ai_family = AF_UNSPEC;

	/* resolve name to ip */
	ret = getaddrinfo(hostname, NULL, &hints, &addr);
	if (ret) {
		info("unable to resolve hostname: %s [%s]",
		     hostname, gai_strerror(ret));
		return -1;
	}

	for (ai = addr; ai; ai = ai->ai_next) {
		debug("RR: %x,%x,%x,%x,%x,%s",
		      ai->ai_flags, ai->ai_family,
		      ai->ai_socktype, ai->ai_protocol,
		      ai->ai_addrlen, ai->ai_canonname);

		/* convert address to string */
		get_ip_str(ai->ai_addr, buf);

		if (hi->port)
			strcat(buf, hi->port);

		append_address_to_payload(buf, payload);

		if (mask & ONE_ADDR_ONLY) {
			break;
		}
	}

	freeaddrinfo(addr);
	return 0;
}

/*
 * Perform address resolution on a hostname and add the resulting address as a
 * string to the list of payload segments.
 *
 * @hi: host information to query for
 * @type: DNS query type
 * @payload: payload buffer to append results to. Must be initialized in caller.
 */
int dns_resolver(struct host_info *hi, ns_type type, payload_t *payload)
{
	if (!hi || !hi->hostname) {
		error("Invalid host information.\n");
		return -1;
	}

	return dns_query(hi, type, payload);
}
