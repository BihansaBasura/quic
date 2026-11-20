#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/quic.h>

int main() {
    int sockfd;
    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(4433),
        .sin_addr.s_addr = inet_addr("127.0.0.1")
    };

    /* 1. Create QUIC socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);

    /* 2. Connect to server */
    connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));

    /* 3. TLS handshake (NULL = certificate mode, not PSK) */
    if (quic_client_handshake(sockfd, NULL, "server.test", NULL)) {
        printf("[client] handshake failed\n");
        return 1;
    }
    printf("[client] connected!\n");

    /* 4. Send messages */
    const char *msgs[] = {"Hello from client!", "QUIC is working!", "Bye!"};
    for (int i = 0; i < 3; i++) {
        /* the first message must open a new QUIC stream */
        send(sockfd, msgs[i], strlen(msgs[i]), i == 0 ? MSG_QUIC_STREAM_NEW : 0);
        printf("[client] sent: %s\n", msgs[i]);
        sleep(1);
    }

    close(sockfd);
    return 0;
}