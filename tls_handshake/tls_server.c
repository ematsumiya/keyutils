#include <errno.h>
#include "tls_common.h"

#define CRLFILE "crl.pem"

/* The OCSP status file contains up to date information about revocation
 * of the server's certificate. That can be periodically be updated
 * using:
 * $ ocsptool --ask --load-cert your_cert.pem --load-issuer your_issuer.pem
 *            --load-signer your_issuer.pem --outfile ocsp-status.der
 */
#define OCSP_STATUS_FILE "ocsp-status.der"

int tls_server_start(char *expected_client, int port, int timeout)
{
	int listenfd;
	int sockfd, ret;
	gnutls_certificate_credentials_t x509_cred;
	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	struct timeval tv;
	socklen_t client_len;
	char ipbuf[INET6_ADDRSTRLEN];
	gnutls_session_t session;
	int optval = 1;

	gnutls_global_init();

	gnutls_certificate_allocate_credentials(&x509_cred);
	gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE, GNUTLS_X509_FMT_PEM);
	//gnutls_certificate_set_x509_crl_file(x509_cred, CRLFILE, GNUTLS_X509_FMT_PEM);
	gnutls_certificate_set_x509_key_file(x509_cred, DEFAULT_NVME_SERVER_CERT, DEFAULT_NVME_SERVER_KEY, GNUTLS_X509_FMT_PEM);
	gnutls_certificate_set_ocsp_status_request_file(x509_cred, OCSP_STATUS_FILE, 0);
	gnutls_certificate_set_known_dh_params(x509_cred, GNUTLS_SEC_PARAM_MEDIUM);

	listenfd = socket(AF_INET, SOCK_STREAM, 0);

	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(port); /* server port number */

	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	setsockopt(listenfd, SOL_SOCKET, SO_RCVTIMEO, (void *)&tv, sizeof(tv));
	setsockopt(listenfd, SOL_SOCKET, SO_SNDTIMEO, (void *)&tv, sizeof(tv));
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (void *)&optval, sizeof(int));
	
	bind(listenfd, (struct sockaddr *)&sa_serv, sizeof(sa_serv));
	listen(listenfd, 1024);

	client_len = sizeof(sa_cli);
	for (;;) {
		gnutls_init(&session, GNUTLS_SERVER);
		gnutls_set_default_priority(session);
		gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);

		/* We don't request any certificate from the client.
		 * If we did we would need to verify it. One way of
		 * doing that is shown in the "Verifying a certificate"
		 * example.
		 */
		gnutls_certificate_server_set_request(session, GNUTLS_CERT_IGNORE);
		gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

		sockfd = accept(listenfd, (struct sockaddr *)&sa_cli, &client_len);

		/* reached timeout without any connections => terminate */
		if (sockfd == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			fprintf(stderr, "Timeout reached (%ds) waiting for client\n", timeout);
			close(sockfd);
			ret = -EAGAIN;
			goto err_timeout;
		}

		if (inet_ntop(AF_INET, &sa_cli.sin_addr, ipbuf, sizeof(ipbuf))) {
			if (strncmp(ipbuf, expected_client, strlen(expected_client))) {
				if (strcmp(ipbuf, "0.0.0.0"))
					fprintf(stderr, "Not expecting any connections from '%s'\n", ipbuf);
				close(sockfd);
				gnutls_deinit(session);
				continue;
			}
		}

		gnutls_transport_set_int(session, sockfd);

		do {
			ret = gnutls_handshake(session);
		} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

		if (ret < 0) {
			close(sockfd);
			gnutls_deinit(session);
			fprintf(stderr, "Handshake failed: %s (%d)\n", gnutls_strerror(ret), ret);
			if (ret == GNUTLS_E_TIMEDOUT) {
				ret = -EAGAIN;
				goto err_timeout;
			}
			continue;
		}

		print_info(session);

		do {
			ret = gnutls_bye(session, GNUTLS_SHUT_WR);
		} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

		close(sockfd);
		gnutls_deinit(session);
		ret = 0;
		/* we have served our purpose, end cleanly */
		break;
	}
err_timeout:
	close(listenfd);
	gnutls_certificate_free_credentials(x509_cred);
	gnutls_global_deinit();

	return ret;
}
