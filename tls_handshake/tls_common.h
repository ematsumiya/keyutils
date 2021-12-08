#ifndef TLS_COMMON_H
#define TLS_COMMON_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>

#include "dns_common.h" // for payload_t FIXME

#define GNUTLS_MIN_VERS "3.4.6"

#define MAX_BUF 1024
#define DEFAULT_PORT 4421

#define DEFAULT_SERVER_TIMEOUT 10 /* How long should the server wait for ClientHello */

#define CAFILE "/etc/ssl/ca-bundle.pem"

/*
#define DEFAULT_NVME_CLIENT_CERT "/etc/nvme/client.crt"
#define DEFAULT_NVME_CLIENT_KEY "/etc/nvme/client.key"
#define DEFAULT_NVME_SERVER_CERT "/etc/nvme/server.crt"
#define DEFAULT_NVME_SERVER_KEY "/etc/nvme/server.crt"
*/
#define DEFAULT_NVME_CLIENT_CERT "tls_handshake/client.crt"
#define DEFAULT_NVME_CLIENT_KEY "tls_handshake/client.key"
#define DEFAULT_NVME_SERVER_CERT "tls_handshake/server.crt"
#define DEFAULT_NVME_SERVER_KEY "tls_handshake/server.key"

bool check_gnutls_version(void);
const char *bin2hex(const void *bin, size_t bin_size);
void print_x509_certificate_info(gnutls_session_t session);
int print_info(gnutls_session_t session);

void append_data_to_payload(uint8_t *data, size_t len, payload_t *payload);

int do_tls_handshake(char *upcall_type, char *options, payload_t *payload);

#endif /* TLS_COMMON_H */
