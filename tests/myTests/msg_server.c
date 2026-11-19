#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/quic.h>   /* libquic API */

/* Usage: ./msg_server [KEYS_DIR]   (default: ../keys) */
int main(int argc, char *argv[])
{
	const char *keys = argc > 1 ? argv[1] : "../keys";
	struct sockaddr_in addr = {
		.sin_family      = AF_INET,
		.sin_port        = htons(4433),
		.sin_addr.s_addr = INADDR_ANY
	};
	char pkey[256], cert[256], buf[256];
	const char *reply = "server got all messages";
	int listenfd, conn, n;
	unsigned int flags;
	int64_t sid;

	snprintf(pkey, sizeof(pkey), "%s/server-key.pem", keys);
	snprintf(cert, sizeof(cert), "%s/server-cert.pem", keys);
	if (access(pkey, R_OK) || access(cert, R_OK)) {
		printf("[server] cannot read %s or %s\n", pkey, cert);
		return 1;
	}

	/* 1. Create QUIC socket (UDP under the hood, handled by kernel module) */
	listenfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (listenfd < 0) {
		perror("[server] socket (is the quic module loaded?)");
		return 1;
	}
	if (bind(listenfd, (struct sockaddr *)&addr, sizeof(addr))) {
		perror("[server] bind");
		return 1;
	}
	if (listen(listenfd, 1)) {
		perror("[server] listen");
		return 1;
	}

	printf("[server] waiting for connection on port 4433...\n");

	/* 2. Accept a QUIC connection */
	conn = accept(listenfd, NULL, NULL);
	if (conn < 0) {
		perror("[server] accept");
		return 1;
	}

	/* 3. TLS handshake (certificate mode: private key + certificate) */
	if (quic_server_handshake(conn, pkey, cert, NULL)) {
		printf("[server] handshake failed\n");
		return 1;
	}
	printf("[server] client connected!\n");

	/* 4. Receive messages until the client finishes the stream (FIN) */
	for (;;) {
		flags = 0;
		n = quic_recvmsg(conn, buf, sizeof(buf) - 1, &sid, &flags);
		if (n < 0) {
			perror("[server] recv");
			break;
		}
		buf[n] = '\0';
		if (n)
			printf("[server] got (stream %lld): %s\n", (long long)sid, buf);
		if (flags & MSG_QUIC_STREAM_FIN) {
			/* Reply on the same bidi stream and finish it. */
			quic_sendmsg(conn, reply, strlen(reply), sid, MSG_QUIC_STREAM_FIN);
			break;
		}
	}

	sleep(1); /* let the reply get out before CONNECTION_CLOSE */
	close(conn);
	close(listenfd);
	return 0;
}
