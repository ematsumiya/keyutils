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
#include "key.dns.h"

#define clamp(x, lo, hi) (MIN(hi, MAX(x, lo)))

static const int ns_errno_map[] = {
	[0]			= ECONNREFUSED,
	[HOST_NOT_FOUND]	= ENODATA,
	[TRY_AGAIN]		= EAGAIN,
	[NO_RECOVERY]		= ECONNREFUSED,
	[NO_DATA]		= ENODATA,
};
static const int ns_errno_max = sizeof(ns_errno_map) / sizeof(ns_errno_map[0]);

/*
 * Returns -errno, @optval, -h_errno, or -1, in that order.
 *
 * Resets errno and h_errno to 0 unconditionally.
 */
int get_err(int optval)
{
	int ret = -1;

	if (errno)
		ret = -errno;
	else if (optval)
		ret = optval;
	else if (h_errno >= ns_errno_max)
		ret = -ECONNREFUSED;
	else if (h_errno)
		ret = -(ns_errno_map[h_errno]);

	errno = h_errno = 0;
	return ret;
}

const char *get_strerr(int optval)
{
	int opt = optval < 0 ? -optval : optval;

	/* begin with h_errno here because it can be more descriptive for us */
	if (h_errno)
		return hstrerror(h_errno);
	else if (errno)
		return strerror(errno);
	else if (opt)
		return strerror(opt);

	return "Unknown error";
}

void _log(FILE *f, int level, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	if (isatty(2)) {
		vfprintf(f, fmt, va);
		fputc('\n', f);
	} else {
		vsyslog(level, fmt, va);
	}
	va_end(va);
}

/*
 * Print nameserver error
 *
 * Error code is always h_errno (netdb.h) for these.
 */
void nsError(const char *hostname)
{
	if (isatty(2))
		error("NS: %s: %s.", hostname, hstrerror(h_errno));
	else
		error("%s: %s", hostname, hstrerror(h_errno));
}

/*
 * Print nameserver error and exit
 */
void nsError_ex(const char *hostname)
{
	unsigned timeout;
	int ret, err;

	nsError(hostname);

	if (!debug_mode) {
		if (h_errno >= ns_errno_max)
			err = ECONNREFUSED;
		else
			err = ns_errno_map[h_errno];

		switch (h_errno) {
		case TRY_AGAIN:
			timeout = 1;
			break;
		case 0:
		case NO_RECOVERY:
			timeout = 10;
			break;
		default:
			timeout = 1 * 60;
			break;
		}

		error("Reject the key with error %d", err);

		ret = keyctl_reject(key, timeout, err, KEY_REQKEY_DEFL_DEFAULT);
		if (ret == -1)
			error_ex("keyctl_reject: %m");
	}

	exit(h_errno);
}

/*
 * Dump the payload when debugging
 */
void dump_payload(payload_t *payload)
{
	size_t plen, n;
	unsigned char *buf, *p;
	int i;

	plen = 0;
	for (i = 0; i < payload->index; i++) {
		n = payload->data[i].iov_len;
		debug("seg[%d] size %zu", i, n);
		plen += n;
	}
	if (plen == 0) {
		info("Key instantiation data is empty");
		return;
	}

	debug("payload len: %zu", plen);

	CALLOC_CHECK(buf, 1, plen + 1);

	p = buf;
	for (i = 0; i < payload->index; i++) {
		n = payload->data[i].iov_len;
		memcpy(p, payload->data[i].iov_base, n);
		p += n;
	}

	info("The key instantiation data is '%s'", buf);
	free(buf);
}

static char *get_addr_str(int af, char *s, const void *data)
{
	switch (af) {
	case AF_INET:
		inet_ntop(AF_INET, data, s, INET_ADDRSTRLEN);
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, data, s, INET6_ADDRSTRLEN);
		break;
	default:
		error("Invalid address family '%d'", af);
		s = NULL;
	}

	return s;
}

/*
 * "valid" for our cases
 * ns_t_any is used to represent an "A/AAAA" query, i.e. both IPv4 and IPv6
 * addresses must be queried
 */
static bool is_type_valid(ns_type type)
{
	switch(type) {
	case ns_t_a:
	case ns_t_aaaa:
	case ns_t_any:
	case ns_t_afsdb:
	case ns_t_srv:
		return true;
	default:
		return false;
	}
}

static inline bool is_type_resolvable(ns_type type)
{
	return (type == ns_t_a || type == ns_t_aaaa);
}

static bool can_resolve_host(hostinfo_t *host)
{
	bool afok = false, typeok = false;

	if (!host)
		return false;

	switch (host->af) {
	case AF_INET:
	case AF_INET6:
	case AF_UNSPEC:
		afok = true;
		break;
	default:
		afok = false;
		break;
	}

	switch(host->type) {
	case ns_t_a:
	case ns_t_aaaa:
	case ns_t_any:
		typeok = true;
		break;
	default:
		typeok = false;
	}

	return (afok && typeok);
}

static inline int ns2af(ns_type type)
{
	if (type == ns_t_a)
		return AF_INET;
	if (type == ns_t_aaaa)
		return AF_INET6;

	return AF_UNSPEC;
}

static inline void add_to_payload(payload_t *payload, void *data, size_t len)
{
	payload->data[payload->index].iov_base = data;
	payload->data[payload->index].iov_len = len;
	payload->index++;
}

/*
 * Append an address to the payload segment list
 */
static void append_addr(char *addr, payload_t *payload)
{
	size_t len;
	int i;

	if (!addr) {
		error("no address to append to payload");
		return;
	}

	if (!payload) {
		error("payload buffer is NULL, can't append addr '%s'", addr);
		return;
	}

	len = strlen(addr);

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

	if (payload->index != 0)
		add_to_payload(payload, ",", 1);

	add_to_payload(payload, (void *)strndup(addr, len), len);
}

/*
 * Returns the smallest TTL from all targets.
 */
static long append_addrs(hostinfo_t **targets, int ntgts, payload_t *payload)
{
	int i;
	long ttl = LONG_MAX;

	for (i = 0; i < ntgts; i++) {
		hostinfo_t *t = targets[i];
		int n;

		for (n = 0; n < t->naddrs; n++) {
			if (t->port[0] != '\0')
				strcat(t->addrs[n], t->port);
			append_addr(t->addrs[n], payload);
		}

		dump_host(t);
		ttl = MIN(ttl, t->ttl);
	}

	/* must include a NUL char at the end of the payload */
	add_to_payload(payload, "", 1);

	return ttl;
}

static inline bool is_host_dup(hostinfo_t *h1, hostinfo_t *h2)
{
	int len;

	if (!h1 || !h2)
		return false;

	if (!h1->hostname || !h2->hostname)
		return false;

	len = MAX(strlen(h1->hostname), strlen(h2->hostname));
	if (strncasecmp(h1->hostname, h2->hostname, len) != 0)
		return false;

	debug("dup host '%s'", h1->hostname);
	return true;
}

/*
 * Get maximum number of targets a record might have
 */
static int get_rr_count(ns_msg *handle)
{
	return ns_msg_count(*handle, ns_s_an);
}

static int get_rr_name(hostinfo_t *host, const unsigned char *rdata)
{
	int ret = 0;

	CALLOC_CHECK(host->hostname, 1, MAXDNAME);

	/* Expand the name server's domain name */
	ret = ns_name_uncompress(ns_msg_base(*(host->handle)),
				 ns_msg_end(*(host->handle)),
				 rdata, host->hostname, MAXDNAME);
	if (ret < 0) {
		warn("ns_name_uncompress() failed: %m");
		ret = get_err(-ENODATA);
		return ret;
	}

	return 0;
}

/*
 * Parses a resource record
 */
static int parse_rr(hostinfo_t *host, ns_rr rr)
{
	const unsigned char *rdata;
	unsigned short prio, weight, port; /* for ns_t_srv */
	int subtype = 0; /* for ns_t_afsdb */
	ns_type rrtype;
	int ret = 0;

	if (!host)
		return -EINVAL;

	rrtype = ns_rr_type(rr);
	rdata = ns_rr_rdata(rr);

	/* increment rdata after reading each field, based on type */
	switch (rrtype) {
	case ns_t_afsdb:
		NS_GET16(subtype, rdata);
		debug("rdata: subtype=%d", subtype);
		break;
	case ns_t_srv:
		NS_GET16(prio, rdata);
		NS_GET16(weight, rdata);
		NS_GET16(port, rdata);

		snprintf(host->port, 10, "+%hu", port); // '+' + 8 + NUL

		debug("rdata: prio=%u, weight=%u, port=%u",
		      prio, weight, port);
		break;
	case ns_t_a:
	case ns_t_aaaa:
		if (host->naddrs == MAX_ADDRS) {
			warn("Can't add more IP addresses (max '%d' reached)",
			     MAX_ADDRS);
			break;
		}

		CALLOC_CHECK(host->addrs[host->naddrs], 1, MAX_ADDR_LEN);
		get_addr_str(ns2af(rrtype), host->addrs[host->naddrs], rdata);

		debug("rdata: addr=%s", host->addrs[host->naddrs]);

		host->naddrs++;
		break;
	default:
		debug("invalid type '%s' (%d)", str_type(rrtype), rrtype);
		return -EINVAL;
	}

	debug("rdata: type='%s' (%d), ttl=%d", str_type(rrtype), rrtype,
	      ns_rr_ttl(rr));

	host->type = rrtype;
	host->ttl = ns_rr_ttl(rr);

	if (!is_type_resolvable(rrtype))
		ret = get_rr_name(host, rdata);

	debug("rdata: hostname='%s'", host->hostname);

	return ret;
}

/*
 * Get host targets/cells for AFSDB and SRV records
 *
 * @host: host with queried handle
 * @targets: array to store targets' information. Must be initialized and
 *	     freed by caller.
 * @maxn: Maximum number of targets we have available to process. It gets updated
 *        when done parsing to the actual number of targets available.
 *
 * Non-unique info is copied from @host to each target. Targets with duplicate
 * hostnames are discarded.
 *
 * Returns 0 on success, or -error otherwise.
 */
static int get_targets(hostinfo_t *host, hostinfo_t **targets, int *maxn)
{
	int n = 0; /* list index */
	int i, ret;
	ns_rr rr;

	debug("Resource record count is %d", *maxn);

	for (i = 0; i < *maxn; i++) {
		hostinfo_t *target = NULL;

		if (ns_parserr(host->handle, ns_s_an, i, &rr)) {
			error("ns_parserr failed: %m");
			continue;
		}

		CALLOC_CHECK(targets[n], 1, sizeof(hostinfo_t));
		target = targets[n];

		target->handle = host->handle; /* temp */
		ret = parse_rr(target, rr);
		if (ret)
			goto out;

		/* discard if duplicate */
		for (i = 0; i < n; i++)
			if (is_host_dup(targets[i], target))
				goto next;

		target->handle = NULL;
		target->af = host->af;
		target->single_addr = host->single_addr;

		n++;
		continue;
next:
		free_host(target);
		target = NULL;
	}

	ret = 0;

	if (n == 0) {
		error("Failed to parse all records");
		ret = -ENODATA;
	}

	*maxn = n;
out:
	return ret;
}

/*
 * "resolves" a host as in: parses a host containing A/AAAA resource
 * records, i.e. assumes @host::handle is allocated and is valid.
 */
static int resolve_host(hostinfo_t *host, int n)
{
	int i, ret = 0, err = 0;
	ns_rr rr;

	if (!host->handle)
		return -ENODATA;

	for (i = 0; i < n; i++) {
		ns_type type;

		if (ns_parserr(host->handle, ns_s_an, i, &rr)) {
			error("ns_parserr failed: %m");
			continue;
		}

		type = ns_rr_type(rr);
		/* ignore resource records that doesn't contain IP addresses */
		if (!is_type_resolvable(type)) {
			debug("skipping unresolvable type '%s' (%d)",
			      str_type(type), type);
			err++;
			continue;
		}

		ret = parse_rr(host, rr);
		if (ret) {
			warn("Failed to parse host '%s': %s", host->hostname,
			     get_strerr(ret));
			err++;
			/* continue */
		}
	}

	if (err >= n)
		ret = -ENODATA;

	return ret;
}

/*
 * Makes the actual query
 *
 * @host: host info to query for
 *
 * Returns 0 on success and sets host->handle for resource record processing. 
 * Returns -error otherwise.
 *
 * Caller is responsible for freeing the allocated handle in both cases.
 */
static int dns_query(hostinfo_t *host)
{
	res_state sp;
	int ret, len;

	if (!host)
		return -EINVAL;

	if (!is_type_valid(host->type))
		return -EINVAL;

	union {
		HEADER hdr;
		u_char buf[NS_PACKETSZ];
	} answer; /* answer buffers */

	CALLOC_CHECK(sp, 1, sizeof(*sp));

	if (res_ninit(sp) < 0) {
		error("Can't initialize sp");
		return -ENODEV;
	}

	h_errno = 0;
	/* query the dns for a @type resource record */
	len = res_nquery(sp, host->hostname, ns_c_in, host->type, answer.buf,
			 sizeof(answer));

	if (len < 0 || len > NS_MAXMSG) {
		ret = get_err(-ENODATA);
		goto out;
	}

	CALLOC_CHECK(host->handle, 1, sizeof(ns_msg));

	ret = 0;

	if (ns_initparse(answer.buf, len, host->handle) < 0) {
		error("ns_initparse: %m");
		ret = get_err(-ENODATA);
	}
out:
	/* frees sp */
	res_nclose(sp);
	return ret;
}

/*
 * Queries the host and returns the number of targets (resource records)
 * for it. Returns -error in case of errors.
 */
static int query_host(hostinfo_t *host)
{
	int n, ret;

	ret = dns_query(host);
	if (ret) {
		if (host->handle) {
			free(host->handle);
			host->handle = NULL;
		}
		return ret;
	}

	n = get_rr_count(host->handle);
	if (n == 0)
		return -ENODATA;

	if (!is_type_resolvable(host->type) && n > MAX_VLS) {
		info("Processing only '%d' records.", MAX_VLS);
		return MAX_VLS;
	}

	if (n > 1 && is_type_resolvable(host->type) && host->single_addr)
		return 1;

	return n;
}

static int __resolve_targets(hostinfo_t **targets, int ntgts, ns_type type)
{
	int n = 0;
	int i, ret, err = 0;

	if (!is_type_resolvable(type))
		return -EINVAL;

	for (i = 0; i < ntgts; i++) {
		targets[i]->type = type;
		targets[i]->af = ns2af(type);

		n = query_host(targets[i]);
		if (!n) {
			debug("can't query '%s', error %d", targets[i]->hostname, n);
			err++;
			continue;
		}

		ret = resolve_host(targets[i], n);
		if (ret) {
			debug("failed to parse '%s' resource records for target '%s': %s",
			      str_type(type), targets[i]->hostname, get_strerr(ret));
			err++;
		}
	}

	if (err >= ntgts)
		ret = -ENODATA;

	return ret;
}

static int resolve_targets4(hostinfo_t **targets, int ntgts)
{
	return __resolve_targets(targets, ntgts, ns_t_a);
}

static int resolve_targets6(hostinfo_t **targets, int ntgts)
{
	return __resolve_targets(targets, ntgts, ns_t_aaaa);
}

/*
 * This function resolves the targets in @targets, based on @af address family
 * (requested by the "ipv4" or "ipv6" options).
 *
 * On success, each target will have at least one IP address in its addrs list,
 * ready to be appended to the payload. Returns 0.
 * On errors:
 * - if @af is AF_INET or AF_INET6, returns -ENODATA
 * - if @af is AF_UNSPEC, returns -AF_INET if only ipv4 failed, -AF_INET6 if
 *   only ipv6 failed, and -ENODATA if both failed
 */
static int resolve_targets(hostinfo_t **targets, int ntgts, int af)
{
	int ret4 = 0, ret6 = 0, ret = 0;

	if (IS_IP4(af) || IS_IP_ANY(af))
		ret4 = resolve_targets4(targets, ntgts);
	if (ret4) {
		warn("Failed to resolve IPv4 targets: %s", get_strerr(ret4));
		ret = IS_IP_ANY(af) ? -AF_INET : -ENODATA;
	}

	if (IS_IP6(af) || IS_IP_ANY(af))
		ret6 = resolve_targets6(targets, ntgts);
	if (ret6) {
		warn("Failed to resolve IPv6 targets: %s", get_strerr(ret6));
		ret = IS_IP_ANY(af) ? -AF_INET6 : -ENODATA;
	}

	if (ret4 && ret6)
		ret = -ENODATA;

	return ret;
}

/*
 * Perform address resolution for a hostname and add the resulting addresses as
 * strings to the list of payload segments
 *
 * @host: host information to query for
 * @payload: payload buffer to append results to. Initialized and freed by caller.
 *
 * Returns 0 on success, -error otherwise.
 */
int dns_resolver(hostinfo_t *host, payload_t *payload)
{
	hostinfo_t *targets[MAX_TARGETS];
	int ntgts = 0, i;
	int ret = 0;
	long ttl;

	if (!host || !host->hostname || !payload)
		return -EINVAL;

	if (!is_type_valid(host->type)) {
		warn("Invalid query type '%s' (%d)", str_type(host->type),
		     host->type);
		return -EINVAL;
	}

	debug("Querying hostname %s with query type '%s' (%d)",
	      host->hostname, str_type(host->type), host->type);

	for (i = 0; i < MAX_TARGETS; i++)
		targets[i] = NULL;

	host->handle = NULL;
	host->naddrs = 0;

	if (can_resolve_host(host)) {
		targets[0] = host;
		ntgts = 1;

		goto resolve;
	}

	/* else, can't straight resolve, must query+fetch targets first */
	ntgts = query_host(host);
	if (ntgts < 1) {
		ret = ntgts;
		error("Failed to query host '%s': %s", host->hostname,
		      get_strerr(ret));
		goto out;
	}

	ret = get_targets(host, targets, &ntgts);
	if (ret || ntgts == 0) {
		error("Failed to get targets for '%s': %s", host->hostname,
		      get_strerr(ret));
		goto out;
	}

resolve:
	ret = resolve_targets(targets, ntgts, host->af);
	if (ret == -ENODATA) {
		error("Failed to resolve targets for '%s': %s", host->hostname,
		      get_strerr(ret));
		goto out;
	} /* else, we got at least *some* data */

	/* append resolved addresses to payload */
	ttl = append_addrs(targets, ntgts, payload);

	host->ttl = clamp(ttl, -1, LONG_MAX);

	/* success if reached here */
	ret = errno = h_errno = 0;
out:
	i = 0;
	while (targets[i] && targets[i] != host)
		free_host(targets[i++]);

	return ret;
}
