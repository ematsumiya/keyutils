#include <arpa/inet.h>

#include "tls_common.h"

extern int tls_client_start(const char *server, int port, payload_t *payload);
extern int tls_server_start(char *expected_client, int port, int timeout, payload_t *payload);

static bool is_ip_valid(char *ip)
{
	struct sockaddr_in sa;
	struct sockaddr_in6 sa6;
	int result;

	/* try ipv4 first */
	result = inet_pton(AF_INET, ip, &(sa.sin_addr));

	if (result != 1) {
		result = inet_pton(AF_INET6, ip, &(sa6.sin6_addr));
	} else {
		return true;
	}

	return result == 1;
}

bool check_gnutls_version(void)
{
	if (!gnutls_check_version(GNUTLS_MIN_VERS)) {
		fprintf(stderr, "GnuTLS " GNUTLS_MIN_VERS " or later is required to run this program\n");
		return false;
	}
	return true;
}

const char *bin2hex(const void *bin, size_t bin_size)
{
        static char printable[110];
        const unsigned char *_bin = bin;
        char *print;
        size_t i;

        if (bin_size > 50)
                bin_size = 50;

        print = printable;
        for (i = 0; i < bin_size; i++) {
                sprintf(print, "%.2x ", _bin[i]);
                print += 2;
        }

        return printable;
}

/* This function will print information about this session's peer
 * certificate.
 */
void print_x509_certificate_info(gnutls_session_t session)
{
        char serial[40];
        char dn[256];
        size_t size;
        unsigned int algo, bits;
        time_t expiration_time, activation_time;
        const gnutls_datum_t *cert_list;
        unsigned int cert_list_size = 0;
        gnutls_x509_crt_t cert;
        gnutls_datum_t cinfo;

        /* This function only works for X.509 certificates.
         */
        if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
                return;

        cert_list = gnutls_certificate_get_peers(session, &cert_list_size);

        printf("Peer provided %d certificates.\n", cert_list_size);

        if (cert_list_size > 0) {
                int ret;

                /* we only print information about the first certificate.
                 */
                gnutls_x509_crt_init(&cert);

                gnutls_x509_crt_import(cert, &cert_list[0],
                                       GNUTLS_X509_FMT_DER);

                printf("Certificate info:\n");

                /* This is the preferred way of printing short information about
                   a certificate. */

                ret =
                    gnutls_x509_crt_print(cert, GNUTLS_CRT_PRINT_ONELINE,
                                          &cinfo);
                if (ret == 0) {
                        printf("\t%s\n", cinfo.data);
                        gnutls_free(cinfo.data);
                }

                /* If you want to extract fields manually for some other reason,
                   below are popular example calls. */

                expiration_time =
                    gnutls_x509_crt_get_expiration_time(cert);
                activation_time =
                    gnutls_x509_crt_get_activation_time(cert);

                printf("\tCertificate is valid since: %s",
                       ctime(&activation_time));
                printf("\tCertificate expires: %s",
                       ctime(&expiration_time));

                /* Print the serial number of the certificate.
                 */
                size = sizeof(serial);
                gnutls_x509_crt_get_serial(cert, serial, &size);

                printf("\tCertificate serial number: %s\n",
                       bin2hex(serial, size));

                /* Extract some of the public key algorithm's parameters
                 */
                algo = gnutls_x509_crt_get_pk_algorithm(cert, &bits);

                printf("Certificate public key: %s",
                       gnutls_pk_algorithm_get_name(algo));

                /* Print the version of the X.509
                 * certificate.
                 */
                printf("\tCertificate version: #%d\n",
                       gnutls_x509_crt_get_version(cert));

                size = sizeof(dn);
                gnutls_x509_crt_get_dn(cert, dn, &size);
                printf("\tDN: %s\n", dn);

                size = sizeof(dn);
                gnutls_x509_crt_get_issuer_dn(cert, dn, &size);
                printf("\tIssuer's DN: %s\n", dn);

                gnutls_x509_crt_deinit(cert);

        }
}

int print_info(gnutls_session_t session)
{
        gnutls_credentials_type_t cred;
        gnutls_kx_algorithm_t kx;
        int dhe, ecdh, group;
        char *desc;

        /* get a description of the session connection, protocol,
         * cipher/key exchange */
        desc = gnutls_session_get_desc(session);
        if (desc != NULL) {
                printf("- Session: %s\n", desc);
        }

        dhe = ecdh = 0;

        kx = gnutls_kx_get(session);

        /* Check the authentication type used and switch
         * to the appropriate.
         */
        cred = gnutls_auth_get_type(session);
        switch (cred) {
#ifdef ENABLE_SRP
        case GNUTLS_CRD_SRP:
                printf("- SRP session with username %s\n",
                       gnutls_srp_server_get_username(session));
                break;
#endif

        case GNUTLS_CRD_PSK:
                /* This returns NULL in server side.
                 */
                if (gnutls_psk_client_get_hint(session) != NULL)
                        printf("- PSK authentication. PSK hint '%s'\n",
                               gnutls_psk_client_get_hint(session));
                /* This returns NULL in client side.
                 */
                if (gnutls_psk_server_get_username(session) != NULL)
                        printf("- PSK authentication. Connected as '%s'\n",
                               gnutls_psk_server_get_username(session));

                if (kx == GNUTLS_KX_ECDHE_PSK)
                        ecdh = 1;
                else if (kx == GNUTLS_KX_DHE_PSK)
                        dhe = 1;
                break;

        case GNUTLS_CRD_ANON:  /* anonymous authentication */

                printf("- Anonymous authentication.\n");
                if (kx == GNUTLS_KX_ANON_ECDH)
                        ecdh = 1;
                else if (kx == GNUTLS_KX_ANON_DH)
                        dhe = 1;
                break;

        case GNUTLS_CRD_CERTIFICATE:   /* certificate authentication */

                /* Check if we have been using ephemeral Diffie-Hellman.
                 */
                if (kx == GNUTLS_KX_DHE_RSA || kx == GNUTLS_KX_DHE_DSS)
                        dhe = 1;
                else if (kx == GNUTLS_KX_ECDHE_RSA
                         || kx == GNUTLS_KX_ECDHE_ECDSA)
                        ecdh = 1;

                /* if the certificate list is available, then
                 * print some information about it.
                 */
                print_x509_certificate_info(session);
                break;
	default:
		break;
        }                       /* switch */

        /* read the negotiated group - if any */
        group = gnutls_group_get(session);
        if (group != 0) {
                printf("- Negotiated group %s\n",
                       gnutls_group_get_name(group));
        } else {
                if (ecdh != 0)
                        printf("- Ephemeral ECDH using curve %s\n",
	                       gnutls_ecc_curve_get_name(gnutls_ecc_curve_get
                                                         (session)));
                else if (dhe != 0)
                        printf("- Ephemeral DH using prime of %d bits\n",
                               gnutls_dh_get_prime_bits(session));
        }

        return 0;
}

void append_data_to_payload(uint8_t *data, size_t len, payload_t *payload)
{
	int i;

	if (!payload) {
		fprintf(stderr, "payload buffer is NULL, can't append data at '0x%p'\n", data);
		return;
	}

	if (payload->index + 2 > MAX_PAYLOAD - 1) {
		fprintf(stderr, "payload buffer is full, can't append data\n");
		return;
	}

	/* do not append duplicate entry */
	for (i = 0; i < payload->index; i++)
		if (payload->data[i].iov_len == len &&
		    memcmp(payload->data[i].iov_base, data, len) == 0)
			return;

	if (payload->index != 0) {
		payload->data[payload->index  ].iov_base = ",";
		payload->data[payload->index++].iov_len = 1;
	}

	payload->data[payload->index].iov_base = malloc(len);
	if (!payload->data[payload->index].iov_base) {
		fprintf(stderr, "out of memory\n");
		return;
	}

	memcpy(payload->data[payload->index].iov_base, data, len);
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
		fprintf(stderr, "%s: seg[%d]: %zu\n", __func__, i, n);
		plen += n;
	}
	if (plen == 0) {
		fprintf(stderr, "%s: The key instantiation data is empty\n", __func__);
		return;
	}

	fprintf(stderr, "%s: total: %zu\n", __func__, plen);
	buf = malloc(plen + 1);
	if (!buf)
		return;

	p = buf;
	for (i = 0; i < payload->index; i++) {
		n = payload->data[i].iov_len;
		memcpy(p, payload->data[i].iov_base, n);
		p += n;
	}

	fprintf(stderr, "%s: The key instantiation data is at '0x%p'\n", __func__, buf);
	free(buf);
}

int do_tls_handshake(char *desc, char *options, payload_t *payload)
{
	int optcount = 0;
	bool is_client;
	char *peer_ip;
	int port;
	int daemon_timeout = DEFAULT_SERVER_TIMEOUT;
	int ret;

	if (!desc || !options || !payload)
		return -1;

	/*
	 * Parse options
	 *
	 * For client (host):
	 * - server IP
	 * - server port
	 * - host NQN (?)
	 *
	 * Callout info format:
	 * '"client";"server_ip";"server_port";"extra"'
	 *
	 * For server (target):
	 * - expected client IP
	 * - listen port
	 * - daemon timeout
	 * - TODO???
	 *
	 * Callout info format:
	 * '"server";"expected_client_ip";"port";"timeout";"extra"'
	 */
	if (!strcmp(desc, "nvme")) {
		char *token = strtok(options, ";");
		while (token) {
			switch (optcount) {
			/* peer end */
			case 0:
				fprintf(stderr, "parsing peer: %s\n", token);
				if (!strcmp(token, "client"))
					is_client = true;
				else if (!strcmp(token, "server"))
					is_client = false;
				else
					goto err_invalid;
				break;
			/* peer IP */
			case 1:
				fprintf(stderr, "parsing IP: %s\n", token);
				if (is_ip_valid(token))
					peer_ip = strdup(token);
				else
					goto err_invalid;
				break;
			/* port */
			case 2:
				fprintf(stderr, "parsing port: %s\n", token);
				port = strtol(token, NULL, 10);
				if (port == 0)
					port = DEFAULT_PORT;

				break;
			/* timeout */
			case 3:
				if (!is_client) {
					fprintf(stderr, "parsing timeout: %s\n", token);
					daemon_timeout = strtol(token, NULL, 10);
					if (daemon_timeout < DEFAULT_SERVER_TIMEOUT)
						daemon_timeout = DEFAULT_SERVER_TIMEOUT;
				}
				break;
			default:
				goto err_invalid;
				break;
			}

			token = strtok(NULL, ";");
			optcount++;
		}
	}

	if (is_client)
		ret = tls_client_start(peer_ip, port, payload);
	else
		ret = tls_server_start(peer_ip, port, daemon_timeout, payload);

	if (ret != 0)
		fprintf(stderr, "TLS %s failed with error %d\n", is_client ? "client" : "server", ret);

	return ret;

err_invalid:
	fprintf(stderr, "Error parsing options for %s\n", __func__);
	return -1;
}
