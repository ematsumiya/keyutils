/*
 * TLS handshake module userspace helper for kernel modules
 *
 * Copyright (C) 2021 SUSE LLC
 * Author: Enzo Matsumiya <ematsumiya@suse.de>
 *
 * This is a userspace tool for performing TLSv1.3 handshake (with GNUTLS) with
 * a server and then handing back down the handshake parameters to the kernel,
 * so kTLS can be used in an existing TCP socket with SOL_TLS level and TCP
 * ESTABLISHED state.
 *
 * Compile with:
 *
 * 	cc -o key.tls_handshake key.tls_handshake.c -lgnutls
 *
 * To use this program, you must tell /sbin/request-key how to invoke it.  You
 * need to have the keyutils package installed and something like the following
 * lines added to your /etc/request-key.conf file:
 *
 * 	#OP    TYPE         DESCRIPTION CALLOUT INFO PROGRAM ARG1 ARG2 ARG3 ...
 * 	====== ============ =========== ============ ==========================
 * 	create tls_handshake nvme:*     *            /sbin/key.tls_handshake %k
 *
 * For now, only 'nvme' key type is supported. NFS, SMB-over-QUIC, kSMBD, and
 * others are possible future users of this program.
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
#include <keyutils.h>
#include <ctype.h>

#include "key.dns.h"
#include "dns_common.h" // for payload_t
#include "tls_handshake/tls_common.h"

static const char TLS_HANDSHAKE_VERSION[] = "0.1";
static const char prog[] = "key.tls_handshake";
static const char key_type[] = "tls_handshake";
static const char nvme_upcall_type[] = "nvme";
static const char *config_file = "/etc/keyutils/key.tls_handshake.conf";
static bool config_specified = false;
static key_serial_t tls_key;
static int verbose;
static int is_debug;
#define DEFAULT_SERVER_TIMEOUT 10 /* How long should the server wait for ClientHello */
unsigned int server_timeout = DEFAULT_SERVER_TIMEOUT;

/*
 * Read the config file.
 */
static void read_config(void)
{
	FILE *f;
	char buf[4096], *b, *p, *k, *v;
	unsigned int line = 0, u;
	int n;

	f = fopen(config_file, "r");
	if (!f) {
		if (errno == ENOENT && !config_specified) {
			fprintf(stderr, "%s: %m\n", config_file);
			return;
		}
		fprintf(stderr, "%s: %m\n", config_file);
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
		if (!p) {
			fprintf(stderr, "%s:%u: line missing newline or too long\n", config_file, line);
			exit(1);
		}

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

			if (b == k) {
				fprintf(stderr, "%s:%u: Unspecified key\n", config_file, line);
				exit(1);
			}

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

			if (esc) {
				fprintf(stderr, "%s:%u: Incomplete escape\n", config_file, line);
				exit(1);
			}
			if (quote) {
				fprintf(stderr, "%s:%u: Unclosed quotes\n", config_file, line);
				exit(1);
			}
			
			*p = 0;
		}

		if (strcmp(k, "default_server_timeout") == 0) {
			if (!v)
				goto missing_value;
			if (sscanf(v, "%u%n", &u, &n) != 1)
				goto bad_value;
			if (v[n])
				goto extra_data;
			if (u < 1 || u > INT_MAX)
				goto out_of_range;
			server_timeout = u;
		} else {
			fprintf(stderr, "%s:%u: Unknown option '%s'\n", config_file, line, k);
		}
	}

	if (ferror(f) || fclose(f) == EOF)
		fprintf(stderr, "%s: %m\n", config_file);

	return;

missing_value:
	fprintf(stderr, "%s:%u: %s: Missing value\n", config_file, line, k);
	exit(1);
invalid_escape_char:
	fprintf(stderr, "%s:%u: %s: Invalid char in escape\n", config_file, line, k);
	exit(1);
post_quote_data:
	fprintf(stderr, "%s:%u: %s: Data after closing quote\n", config_file, line, k);
	exit(1);
bad_value:
	fprintf(stderr, "%s:%u: %s: Bad value\n", config_file, line, k);
	exit(1);
extra_data:
	fprintf(stderr, "%s:%u: %s: Extra data supplied\n", config_file, line, k);
	exit(1);
out_of_range:
	fprintf(stderr, "%s:%u: %s: Value out of range\n", config_file, line, k);
	exit(1);
}

/*
 * Dump the configuration after parsing the config file.
 */
static __attribute__((noreturn))
void config_dumper(void)
{
	printf("default_server_timeout = %u\n", server_timeout);
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
		fprintf(stdout, "Usage: %s [-vv] [-c config] key_serial\n", prog);
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

int main(int argc, char *argv[])
{
	int ktlen, qtlen, ret;
	char *keyend, *p;
	char *callout_info = NULL;
	char *buf = NULL, *upcaller;
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
			is_debug = 1;
			continue;
		case 'V':
			printf("version: %s\n", TLS_HANDSHAKE_VERSION);
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

	if (!is_debug) {
		if (argc != 1)
			usage();

		/* get the key ID */
		if (!**argv) {
			fprintf(stderr, "Invalid blank key ID\n");
			exit(1);
		}

		tls_key = strtol(*argv, &p, 10);

		if (*p) {
			fprintf(stderr, "Invalid key ID format\n");
			exit(1);
		}

		/* get the key description (of the form "<type>;<peer>;x;x;x") */
		ret = keyctl_describe_alloc(tls_key, &buf);
		if (ret == -1) {
			fprintf(stderr, "keyctl_describe_alloc failed: %m\n");
			exit(1);
		}

		/* get the callout_info (which can supply options) */
		ret = keyctl_read_alloc(KEY_SPEC_REQKEY_AUTH_KEY, (void **)&callout_info);
		if (ret == -1) {
			fprintf(stderr, "Invalid key callout_info read: %m\n");
			exit(1);
		}
	} else {
		if (argc != 2)
			usage();

		ret = asprintf(&buf, "%s;-1;-1;0;%s", key_type, argv[0]);
		if (ret < 0) {
			fprintf(stderr, "Error %m\n");
			exit(1);
		}

		callout_info = argv[1];
	}

	ret = 1;
	fprintf(stdout, "Key description: '%s'\n", buf);
	fprintf(stdout, "Callout info: '%s'\n", callout_info);

	p = strchr(buf, ';');
	if (!p) {
		fprintf(stderr, "Badly formatted key description '%s'\n", buf);
	}

	ktlen = p - buf;

	/* make sure it's the type we are expecting */
	if (ktlen != sizeof(key_type) - 1 ||
	    memcmp(buf, key_type, ktlen) != 0) {
		fprintf(stderr, "Key type is not supported: '%*.*s'\n", ktlen, ktlen, buf);
		exit(1);
	}

	keyend = buf + ktlen + 1;

	/* the actual key description follows the last semicolon */
	keyend = rindex(keyend, ';');
	if (!keyend) {
		fprintf(stderr, "Invalid key description: %s\n", buf);
		exit(1);
	}

	keyend++;
	payload = malloc(sizeof(payload_t));

	upcaller = index(keyend, ';');
	if (!upcaller)
		return do_tls_handshake(keyend, callout_info, payload);

	qtlen = upcaller - keyend;
	upcaller++;

	fprintf(stdout, "Upcalling from: '%*.*s'\n", qtlen, qtlen, keyend);

	if ((qtlen == sizeof(nvme_upcall_type) - 1 && !memcmp(keyend, nvme_upcall_type, sizeof(nvme_upcall_type) - 1))) {
		fprintf(stdout, "Starting TLS handshake for: '%s' callout_info '%s'\n", upcaller, callout_info);
		return do_tls_handshake(upcaller, callout_info, payload);
	}

	fprintf(stderr, "Query type: \"%*.*s\" is not supported\n", qtlen, qtlen, keyend);
	exit(1);
}
