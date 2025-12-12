#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#error "Este test es para Windows (Winsock)"
#endif

/*
    Pequeño test de Winsock en C para Windows.
    Crea un socket TCP, se conecta a localhost:80, envía una petición HTTP simple y recibe la respuesta.
    A modo de prueba para intruducirme con Winsock en C.
*/

int main(int argc, char **argv) {
	// Inicialización de Winsock:
	// WSAStartup solicita al sistema que cargue y prepare la biblioteca Winsock
	// MAKEWORD(2,2) pide la versión 2.2 de la API
    WSADATA wsa;
    int res = WSAStartup(MAKEWORD(2,2), &wsa);
    if (res != 0) {
        printf("WSAStartup failed: %d\n", res);
        return 1;
    }

	// Creación de un socket TCP (IPv4):
	// AF_INET = IPv4, SOCK_STREAM = TCP, IPPROTO_TCP = protocolo TCP
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

	// Preparación de la estructura de dirección del servidor:
	// sockaddr_in contiene familia, puerto y dirección IPv4
    struct sockaddr_in serv; // Estructura IPv4 para la dirección del servidor
    serv.sin_family = AF_INET;
    // htons convierte el puerto al orden de bytes de red
    serv.sin_port = htons(80);
	// inet_pton intenta convertir la cadena "127.0.0.1" a binario (recomendado)
    if (inet_pton(AF_INET, "127.0.0.1", &serv.sin_addr) != 1) {
        serv.sin_addr.s_addr = inet_addr("127.0.0.1"); // Si falla, se usa inet_addr como alternativa (antigua)
    }

    printf("Intentando conectar a 127.0.0.1:80...\n");
	// Establece la conexión TCP con el servidor especificado en 'serv'
    // Se castea a (struct sockaddr*) porque connect() usa esa estructura genérica IPv4/IPv6
    res = connect(sock, (struct sockaddr*)&serv, sizeof(serv));
    if (res == SOCKET_ERROR) {
        // Si falla, WSAGetLastError devuelve el código de error de Winsock
        printf("connect() failed: %d\n", WSAGetLastError());
    } else {
        printf("connect() succeeded\n");
		// Envía una petición HTTP simple (GET). send devuelve bytes enviados
        const char *msg = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
        send(sock, msg, (int)strlen(msg), 0);
		// Recibe la respuesta del servidor en un buffer y la imprime
        char buf[512];
        int n = recv(sock, buf, sizeof(buf)-1, 0);
        if (n > 0) {
            buf[n] = '\0';
            printf("Received (%d bytes):\n%.*s\n", n, n, buf);
        } else {
            // recv puede devolver 0 (conexión cerrada) o SOCKET_ERROR en fallo
            printf("No data received or recv failed: %d\n", WSAGetLastError());
        }
    }

	// Cierra el socket y libera recursos de Winsock
    closesocket(sock);
    WSACleanup();
    return 0;
}
