#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/quic.h>

/*
 * Usage: ./msg_client [KEYS_DIR]   (default: ../keys)
 *
 * NOTE: quic_client_handshake(sockfd, psk_file, hostname, alpns) takes a
 * *PSK file* as its 2nd argument (or NULL for certificate mode, which only
 * uses the system trust store). To verify the server against our own
 * ca-cert.pem we drive the handshake with GnuTLS directly and then hand the
 * session to quic_handshake().
 */
static int client_handshake(int sockfd, const char *ca_file, const char *host)
{
	gnutls_certificate_credentials_t cred;
	gnutls_session_t session;
	int ret;

	ret = gnutls_certificate_allocate_credentials(&cred);
	if (ret)
		return ret;
	ret = gnutls_certificate_set_x509_trust_file(cred, ca_file, GNUTLS_X509_FMT_PEM);
	if (ret <= 0) {
		printf("[client] failed to load CA %s: %s\n", ca_file, gnutls_strerror(ret));
		ret = -1;
		goto err_cred;
	}

	ret = gnutls_init(&session, GNUTLS_CLIENT);
	if (ret)
		goto err_cred;
	ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
	if (ret)
		goto err_session;
	ret = gnutls_priority_set_direct(session, QUIC_PRIORITY, NULL);
	if (ret)
		goto err_session;

	/* SNI + verify the server cert chain and its name against the CA. */
	ret = gnutls_server_name_set(session, GNUTLS_NAME_DNS, host, strlen(host));
	if (ret)
		goto err_session;
	gnutls_session_set_verify_cert(session, host, 0);

	gnutls_transport_set_int(session, sockfd);
	ret = quic_handshake(session);

err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_certificate_free_credentials(cred);
	return ret;
}

int main(int argc, char *argv[])
{
	const char *keys = argc > 1 ? argv[1] : "../keys";
	const char *msgs[] = {"Hello from client!", "QUIC is working!", "Bye!"};
	struct sockaddr_in addr = {
		.sin_family      = AF_INET,
		.sin_port        = htons(4433),
		.sin_addr.s_addr = inet_addr("127.0.0.1")
	};
	unsigned int flags;
	char ca[256], buf[256];
	int sockfd, i, n;
	int64_t sid;

	snprintf(ca, sizeof(ca), "%s/ca-cert.pem", keys);

	/* 1. Create QUIC socket */
	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (sockfd < 0) {
		perror("[client] socket (is the quic module loaded?)");
		return 1;
	}

	/* 2. Connect (only sets the peer address; no packets sent yet) */
	if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr))) {
		perror("[client] connect");
		return 1;
	}

	/* 3. TLS handshake. "server.test" is the SAN in keys/server-cert.pem. */
	if (client_handshake(sockfd, ca, "server.test")) {
		printf("[client] handshake failed\n");
		return 1;
	}
	printf("[client] connected!\n");

	/* 4. Send messages on one bidirectional stream (stream 0).
	 *    First send opens it (STREAM_NEW), last send closes our side (FIN).
	 */
	sid = 0;
	for (i = 0; i < 3; i++) {
		flags = 0;
		if (i == 0)
			flags |= MSG_QUIC_STREAM_NEW;
		if (i == 2)
			flags |= MSG_QUIC_STREAM_FIN;
		if (quic_sendmsg(sockfd, msgs[i], strlen(msgs[i]), sid, flags) < 0) {
			perror("[client] send");
			return 1;
		}
		printf("[client] sent: %s\n", msgs[i]);
		sleep(1);
	}

	/* 5. Wait for the server's reply so we don't close before data is
	 *    delivered (close() sends CONNECTION_CLOSE immediately).
	 */
	flags = 0;
	n = quic_recvmsg(sockfd, buf, sizeof(buf) - 1, &sid, &flags);
	if (n > 0) {
		buf[n] = '\0';
		printf("[client] got reply: %s\n", buf);
	}

	close(sockfd);
	return 0;
}
