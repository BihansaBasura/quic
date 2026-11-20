#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/quic.h>   /* libquic API */

int main() {
    int listenfd, conn;
    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(4433),
        .sin_addr.s_addr = INADDR_ANY
    };
    char buf[256];

    /* 1. Create QUIC socket (UDP under the hood, handled by kernel module) */
    listenfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);

    bind(listenfd, (struct sockaddr *)&addr, sizeof(addr));
    listen(listenfd, 1);

    printf("[server] waiting for connection on port 4433...\n");

    /* 2. Accept a QUIC connection */
    conn = accept(listenfd, NULL, NULL);

    /* 3. TLS handshake using libquic */
    if (quic_server_handshake(conn, "../keys/server-key.pem", "../keys/server-cert.pem", NULL)) {
        printf("[server] handshake failed\n");
        return 1;
    }
    printf("[server] client connected!\n");

    /* 4. Receive messages in a loop */
    int n;
    while ((n = recv(conn, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[n] = '\0';
        printf("[server] got: %s\n", buf);
    }

    close(conn);
    close(listenfd);
    return 0;
}