#include "tls_common.h"
#include "dns_common.h"

/*
 * Connects to the peer and returns a socket descriptor.
 */
static int tcp_connect(const char *server, int port)
{
	int err, sockfd;
	int flag = 1, curstate = 0;
	struct sockaddr_in sa;

	if (!server || port == 0) {
		fprintf(stderr, "Invalid server or port\n");
		exit(1);
	}

	/* sets some fd options such as nonblock */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&curstate, sizeof(curstate));

	memset(&sa, '\0', sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);

	inet_pton(AF_INET, server, &sa.sin_addr);

	err = connect(sockfd, (struct sockaddr *)&sa, sizeof(sa));
	if ((err < 0) && (errno != EINPROGRESS)) {
		fprintf(stderr, "Connect error\n");
		exit(1);
	}

	/* lower the send buffers to force EAGAIN */
	setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
	fcntl(sockfd, F_SETFL, O_NONBLOCK);

	return sockfd;
}

static void tcp_close(int sockfd)
{
	shutdown(sockfd, SHUT_RDWR);	/* no more receptions */
	close(sockfd);
}

int tls_client_start(const char *server, int port, payload_t *payload)
{
	int ret, sockfd;
	gnutls_certificate_credentials_t xcred;
	gnutls_session_t session;

	gnutls_global_init();
	gnutls_certificate_allocate_credentials(&xcred);
	gnutls_certificate_set_x509_system_trust(xcred);

	gnutls_certificate_set_x509_key_file(xcred, DEFAULT_NVME_CLIENT_CERT, DEFAULT_NVME_CLIENT_KEY, GNUTLS_X509_FMT_PEM);

	/* Initialize TLS session */
	gnutls_init(&session, GNUTLS_CLIENT);
	gnutls_set_default_priority(session);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	sockfd = tcp_connect(server, port);

	gnutls_transport_set_int(session, sockfd);
	gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

	do {
		ret = gnutls_handshake(session);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

	if (ret < 0) {
		if (ret == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR)
			fprintf(stderr, "Handshake failed: can't verify certificate\n");
		else
			fprintf(stderr, "Handshake failed: %s (%d)\n", gnutls_strerror(ret), ret);

		goto end;
	} else {
		/* copy crypto info to payload, which will be sent back to kernel */
		gnutls_datum_t cipher_key;
		gnutls_datum_t mac_key;
		gnutls_datum_t iv;
		unsigned char seqn[8];

		gnutls_record_get_state(session, 1, &mac_key, &iv, &cipher_key, seqn);

		/* mac_key might be empty */
		if (mac_key.size != 0)
			append_data_to_payload(mac_key.data, mac_key.size, payload);

		append_data_to_payload(cipher_key.data, cipher_key.size, payload);
		append_data_to_payload(iv.data, iv.size, payload);
		append_data_to_payload(seqn, 8, payload);
	}

	print_info(session);

	gnutls_bye(session, GNUTLS_SHUT_RDWR);

end:
	tcp_close(sockfd);

	gnutls_deinit(session);
	gnutls_certificate_free_credentials(xcred);
	gnutls_global_deinit();

	return 0;
}
