/*
 * DNS Resolver Module User-space Helper for AFSDB records
 *
 * Copyright (C) Wang Lei (wang840925@gmail.com) 2010
 * Authors: Wang Lei (wang840925@gmail.com)
 *          David Howells (dhowells@redhat.com)
 *
 * This is a userspace tool for querying AFSDB RR records in the DNS on behalf
 * of the kernel, and converting the VL server addresses to IPv4 format so that
 * they can be used by the kAFS filesystem.
 *
 * Compile with:
 *
 * 	cc -o key.dns_resolver key.dns_resolver.c -lresolv -lkeyutils
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

static const char *DNS_PARSE_VERSION = "1.0";
static const char prog[] = "key.dns_resolver";
static const char key_type[] = "dns_resolver";
static const char a_query_type[] = "a";
static const char aaaa_query_type[] = "aaaa";
static const char afsdb_query_type[] = "afsdb";
static const char *config_file = "/etc/keyutils/key.dns_resolver.conf";
static bool config_specified = false;
key_serial_t key;
static int verbose;
int debug_mode;
#define DEFAULT_KEY_TTL 5
unsigned int key_expiry = DEFAULT_KEY_TTL;

/*
 * Print an error to stderr or the syslog, negate the key being created and
 * exit
 */
void error(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	if (isatty(2)) {
		vfprintf(stderr, fmt, va);
		fputc('\n', stderr);
	} else {
		vsyslog(LOG_ERR, fmt, va);
	}
	va_end(va);

	/*
	 * on error, negatively instantiate the key ourselves so that we can
	 * make sure the kernel doesn't hang it off of a searchable keyring
	 * and interfere with the next attempt to instantiate the key.
	 */
	if (!debug_mode)
		keyctl_negate(key, 1, KEY_REQKEY_DEFL_DEFAULT);

	exit(1);
}

#define error(FMT, ...) error("Error: " FMT, ##__VA_ARGS__);

/*
 * Just print an error to stderr or the syslog
 */
void _error(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	if (isatty(2)) {
		vfprintf(stderr, fmt, va);
		fputc('\n', stderr);
	} else {
		vsyslog(LOG_ERR, fmt, va);
	}
	va_end(va);
}

/*
 * Print a warning to stderr or the syslog
 */
void warning(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	if (isatty(2)) {
		vfprintf(stderr, fmt, va);
		fputc('\n', stderr);
	} else {
		vsyslog(LOG_WARNING, fmt, va);
	}
	va_end(va);
}

/*
 * Print status information
 */
void info(const char *fmt, ...)
{
	va_list va;

	if (verbose < 1)
		return;

	va_start(va, fmt);
	if (isatty(1)) {
		fputs("I: ", stdout);
		vfprintf(stdout, fmt, va);
		fputc('\n', stdout);
	} else {
		vsyslog(LOG_INFO, fmt, va);
	}
	va_end(va);
}

/*
 * Print a nameserver error and exit
 */
static const int ns_errno_map[] = {
	[0]			= ECONNREFUSED,
	[HOST_NOT_FOUND]	= ENODATA,
	[TRY_AGAIN]		= EAGAIN,
	[NO_RECOVERY]		= ECONNREFUSED,
	[NO_DATA]		= ENODATA,
};

void _nsError(int err, const char *domain)
{
	if (isatty(2))
		fprintf(stderr, "NS:%s: %s.\n", domain, hstrerror(err));
	else
		syslog(LOG_INFO, "%s: %s", domain, hstrerror(err));

	if (err >= sizeof(ns_errno_map) / sizeof(ns_errno_map[0]))
		err = ECONNREFUSED;
	else
		err = ns_errno_map[err];

	info("Reject the key with error %d", err);
}

void nsError(int err, const char *domain)
{
	unsigned timeout;
	int ret;

	_nsError(err, domain);

	switch (err) {
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

	if (!debug_mode) {
		ret = keyctl_reject(key, timeout, err, KEY_REQKEY_DEFL_DEFAULT);
		if (ret == -1)
			error("%s: keyctl_reject: %m", __func__);
	}
	exit(0);
}

/*
 * Print debugging information
 */
void debug(const char *fmt, ...)
{
	va_list va;

	if (verbose < 2)
		return;

	va_start(va, fmt);
	if (isatty(1)) {
		fputs("D: ", stdout);
		vfprintf(stdout, fmt, va);
		fputc('\n', stdout);
	} else {
		vsyslog(LOG_DEBUG, fmt, va);
	}
	va_end(va);
}

/*
 * Look up a A and/or AAAA records to get host addresses
 *
 * The callout_info is parsed for request options.  For instance, "ipv4" to
 * request only IPv4 addresses, "ipv6" to request only IPv6 addresses and
 * "list" to get multiple addresses.
 * The "ttl" option may be used so the proper DNS record TTL will be saved to host_info->ttl.
 */
static __attribute__((noreturn))
int dns_query_a_or_aaaa(char *hostname, char *options, payload_t *payload)
{
	struct host_info hi;
	int ret, af_mask;

	memset(&hi, 0, sizeof(struct host_info));

	debug("Get A/AAAA RR for hostname:'%s', options:'%s'",
	      hostname, options);

	hi.hostname = hostname;

	if (!options[0]) {
		/* legacy mode */
		hi.mask = AF_INET | ONE_ADDR_ONLY;
	} else {
		char *k, *val;

		hi.mask |= ONE_ADDR_ONLY;

		do {
			k = options;
			options = strchr(options, ' ');
			if (!options)
				options = k + strlen(k);
			else
				*options++ = '\0';
			if (!*k)
				continue;
			if (strchr(k, ','))
				error("Option name '%s' contains a comma", k);

			val = strchr(k, '=');
			if (val)
				*val++ = '\0';

			debug("Opt %s", k);

			if (strcmp(k, "ipv4") == 0)
				hi.mask |= AF_INET;
			else if (strcmp(k, "ipv6") == 0)
				hi.mask |= AF_INET6;
			else if (strcmp(k, "list") == 0)
				hi.mask &= ~ONE_ADDR_ONLY;
			else if (strcmp(k, "ttl") == 0) {
				hi.ttl = malloc(sizeof(unsigned int));
			}
		} while (*options);
	}

	if (!HAS_INET(hi.mask) && !HAS_INET6(hi.mask))
		hi.mask |= AF_INET | AF_INET6;

	af_mask = hi.mask & ~ONE_ADDR_ONLY;

	/* Turn the hostname into IP addresses */
	if (HAS_INET(af_mask))
		ret = dns_resolver(&hi, ns_t_a, payload);
	if (ret)
		nsError(NO_DATA, hostname);

	if (HAS_INET6(af_mask))
		ret = dns_resolver(&hi, ns_t_aaaa, payload);
	if (ret)
		nsError(NO_DATA, hostname);

	/* handle a lack of results */
	if (payload->index == 0)
		nsError(NO_DATA, hostname);

	/* must include a NUL char at the end of the payload */
	payload->data[payload->index].iov_base = "";
	payload->data[payload->index++].iov_len = 1;
	dump_payload(payload);

	/* load the key with data key */
	if (!debug_mode) {
		/*
		 * if "ttl" option was set, it takes precedence over
		 * key.dns_resolver.conf's default_ttl value
		 */
		if (hi.ttl)
			ret = keyctl_set_timeout(key, *hi.ttl);
		else
			ret = keyctl_set_timeout(key, key_expiry);

		if (ret == -1)
			error("%s: keyctl_set_timeout: %m", __func__);

		ret = keyctl_instantiate_iov(key, payload->data, payload->index, 0);
		if (ret == -1)
			error("%s: keyctl_instantiate: %m", __func__);
	}

	exit(0);
}

/*
 * Read the config file.
 */
static void read_config(void)
{
	FILE *f;
	char buf[4096], *b, *p, *k, *v;
	unsigned int line = 0, u;
	int n;

	info("READ CONFIG %s", config_file);

	f = fopen(config_file, "r");
	if (!f) {
		if (errno == ENOENT && !config_specified) {
			debug("%s: %m", config_file);
			return;
		}
		error("%s: %m", config_file);
	}

	while (fgets(buf, sizeof(buf) - 1, f)) {
		line++;

		/* Trim off leading and trailing spaces and discard whole-line
		 * comments.
		 */
		b = buf;
		while (isspace(*b))
			b++;
		if (!*b || *b == '#')
			continue;
		p = strchr(b, '\n');
		if (!p)
			error("%s:%u: line missing newline or too long", config_file, line);
		while (p > buf && isspace(p[-1]))
			p--;
		*p = 0;

		/* Split into key[=value] pairs and trim spaces. */
		k = b;
		v = NULL;
		b = strchr(b, '=');
		if (b) {
			char quote = 0;
			bool esc = false;

			if (b == k)
				error("%s:%u: Unspecified key",
				      config_file, line);

			/* NUL-terminate the key. */
			for (p = b - 1; isspace(*p); p--)
				;
			p[1] = 0;

			/* Strip leading spaces */
			b++;
			while (isspace(*b))
				b++;
			if (!*b)
				goto missing_value;

			if (*b == '"' || *b == '\'') {
				quote = *b;
				b++;
			}
			v = p = b;
			while (*b) {
				if (esc) {
					switch (*b) {
					case ' ':
					case '\t':
					case '"':
					case '\'':
					case '\\':
						break;
					default:
						goto invalid_escape_char;
					}
					esc = false;
					*p++ = *b++;
					continue;
				}
				if (*b == '\\') {
					esc = true;
					b++;
					continue;
				}
				if (*b == quote) {
					b++;
					if (*b)
						goto post_quote_data;
					quote = 0;
					break;
				}
				if (!quote && *b == '#')
					break; /* Terminal comment */
				*p++ = *b++;
			}

			if (esc)
				error("%s:%u: Incomplete escape", config_file, line);
			if (quote)
				error("%s:%u: Unclosed quotes", config_file, line);
			*p = 0;
		}

		if (strcmp(k, "default_ttl") == 0) {
			if (!v)
				goto missing_value;
			if (sscanf(v, "%u%n", &u, &n) != 1)
				goto bad_value;
			if (v[n])
				goto extra_data;
			if (u < 1 || u > INT_MAX)
				goto out_of_range;
			key_expiry = u;
		} else {
			warning("%s:%u: Unknown option '%s'", config_file, line, k);
		}
	}

	if (ferror(f) || fclose(f) == EOF)
		error("%s: %m", config_file);
	return;

missing_value:
	error("%s:%u: %s: Missing value", config_file, line, k);
invalid_escape_char:
	error("%s:%u: %s: Invalid char in escape", config_file, line, k);
post_quote_data:
	error("%s:%u: %s: Data after closing quote", config_file, line, k);
bad_value:
	error("%s:%u: %s: Bad value", config_file, line, k);
extra_data:
	error("%s:%u: %s: Extra data supplied", config_file, line, k);
out_of_range:
	error("%s:%u: %s: Value out of range", config_file, line, k);
}

/*
 * Dump the configuration after parsing the config file.
 */
static __attribute__((noreturn))
void config_dumper(void)
{
	printf("default_ttl = %u\n", key_expiry);
	exit(0);
}

/*
 * Print usage details,
 */
static __attribute__((noreturn))
void usage(void)
{
	if (isatty(2)) {
		fprintf(stderr,
			"Usage: %s [-vv] [-c config] key_serial\n",
			prog);
		fprintf(stderr,
			"Usage: %s -D [-vv] [-c config] <desc> <calloutinfo>\n",
			prog);
	} else {
		info("Usage: %s [-vv] [-c config] key_serial", prog);
	}
	exit(2);
}

static const struct option long_options[] = {
	{ "config",		0, NULL, 'c' },
	{ "debug",		0, NULL, 'D' },
	{ "dump-config",	0, NULL, 2   },
	{ "verbose",		0, NULL, 'v' },
	{ "version",		0, NULL, 'V' },
	{ NULL,			0, NULL, 0 }
};

/*
 *
 */
int main(int argc, char *argv[])
{
	int ktlen, qtlen, ret;
	char *keyend, *p;
	char *callout_info = NULL;
	char *buf = NULL, *name;
	bool dump_config = false;
	payload_t *payload = NULL;

	openlog(prog, 0, LOG_DAEMON);

	while ((ret = getopt_long(argc, argv, "c:vDV", long_options, NULL)) != -1) {
		switch (ret) {
		case 'c':
			config_file = optarg;
			config_specified = true;
			continue;
		case 2:
			dump_config = true;
			continue;
		case 'D':
			debug_mode = 1;
			continue;
		case 'V':
			printf("version: %s from %s (%s)\n",
			       DNS_PARSE_VERSION,
			       keyutils_version_string,
			       keyutils_build_string);
			exit(0);
		case 'v':
			verbose++;
			continue;
		default:
			if (!isatty(2))
				syslog(LOG_ERR, "unknown option: %c", ret);
			usage();
		}
	}

	argc -= optind;
	argv += optind;
	read_config();
	if (dump_config)
		config_dumper();

	if (!debug_mode) {
		if (argc != 1)
			usage();

		/* get the key ID */
		if (!**argv)
			error("Invalid blank key ID");
		key = strtol(*argv, &p, 10);
		if (*p)
			error("Invalid key ID format");

		/* get the key description (of the form "x;x;x;x;<query_type>:<name>") */
		ret = keyctl_describe_alloc(key, &buf);
		if (ret == -1)
			error("keyctl_describe_alloc failed: %m");

		/* get the callout_info (which can supply options) */
		ret = keyctl_read_alloc(KEY_SPEC_REQKEY_AUTH_KEY, (void **)&callout_info);
		if (ret == -1)
			error("Invalid key callout_info read: %m");
	} else {
		if (argc != 2)
			usage();

		ret = asprintf(&buf, "%s;-1;-1;0;%s", key_type, argv[0]);
		if (ret < 0)
			error("Error %m");
		callout_info = argv[1];
	}

	ret = 1;
	info("Key description: '%s'", buf);
	info("Callout info: '%s'", callout_info);

	p = strchr(buf, ';');
	if (!p)
		error("Badly formatted key description '%s'", buf);
	ktlen = p - buf;

	/* make sure it's the type we are expecting */
	if (ktlen != sizeof(key_type) - 1 ||
	    memcmp(buf, key_type, ktlen) != 0)
		error("Key type is not supported: '%*.*s'", ktlen, ktlen, buf);

	keyend = buf + ktlen + 1;

	/* the actual key description follows the last semicolon */
	keyend = rindex(keyend, ';');
	if (!keyend)
		error("Invalid key description: %s", buf);
	keyend++;

	payload = malloc(sizeof(payload_t));

	name = index(keyend, ':');
	if (!name)
		dns_query_a_or_aaaa(keyend, callout_info, payload);

	qtlen = name - keyend;
	name++;

	info("Query type: '%*.*s'", qtlen, qtlen, keyend);

	if ((qtlen == sizeof(a_query_type) - 1 &&
	     memcmp(keyend, a_query_type, sizeof(a_query_type) - 1) == 0) ||
	    (qtlen == sizeof(aaaa_query_type) - 1 &&
	     memcmp(keyend, aaaa_query_type, sizeof(aaaa_query_type) - 1) == 0)
	    ) {
		info("Do DNS query of A/AAAA type for:'%s' mask:'%s'",
		     name, callout_info);
		dns_query_a_or_aaaa(name, callout_info, payload);
	}

	if (qtlen == sizeof(afsdb_query_type) - 1 &&
	    memcmp(keyend, afsdb_query_type, sizeof(afsdb_query_type) - 1) == 0
	    ) {
		info("Do AFS VL server query for:'%s' mask:'%s'",
		     name, callout_info);
		afs_look_up_VL_servers(name, callout_info, payload);
	}

	error("Query type: \"%*.*s\" is not supported", qtlen, qtlen, keyend);
}
