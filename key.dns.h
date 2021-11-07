/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public Licence as published by
 * the Free Software Foundation; either version 2 of the Licence, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public Licence for more details.
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
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

#include "dns_common.h"

/*
 * key.dns_resolver.c
 */
extern key_serial_t key;
extern int debug_mode;
extern unsigned mask;

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

extern void append_address_to_payload(char *addr, payload_t *payload);
extern void dump_payload(payload_t *payload);

/*
 * dns.afsdb.c
 */
extern __attribute__((noreturn))
void afs_look_up_VL_servers(char *cell, char *options, payload_t *payload);
