#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#error "Este test es para Windows (Winsock)"
#endif

int main(int argc, char **argv) {
    WSADATA wsa;
    int res = WSAStartup(MAKEWORD(2,2), &wsa);
    if (res != 0) {
        printf("WSAStartup failed: %d\n", res);
        return 1;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    struct sockaddr_in serv;
    serv.sin_family = AF_INET;
    serv.sin_port = htons(80);
    if (inet_pton(AF_INET, "127.0.0.1", &serv.sin_addr) != 1) {
        serv.sin_addr.s_addr = inet_addr("127.0.0.1");
    }

    printf("Intentando conectar a 127.0.0.1:80...\n");
    res = connect(sock, (struct sockaddr*)&serv, sizeof(serv));
    if (res == SOCKET_ERROR) {
        printf("connect() failed: %d\n", WSAGetLastError());
    } else {
        printf("connect() succeeded\n");
        const char *msg = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
        send(sock, msg, (int)strlen(msg), 0);
        char buf[512];
        int n = recv(sock, buf, sizeof(buf)-1, 0);
        if (n > 0) {
            buf[n] = '\0';
            printf("Received (%d bytes):\n%.*s\n", n, n, buf);
        } else {
            printf("No data received or recv failed: %d\n", WSAGetLastError());
        }
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}
