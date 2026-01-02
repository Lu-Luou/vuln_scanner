#include "network.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <sys/select.h>


static int set_nonblocking(socket_t s) {
#ifdef _WIN32
	u_long mode = 1;
	return ioctlsocket(s, FIONBIO, &mode);
#else
	int flags = fcntl(s, F_GETFL, 0);
	if (flags < 0) return -1;
	return fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif
}

int net_init(const AppConfig *cfg) {
	int verbose = (cfg) ? cfg->verbose : 0;
#ifdef _WIN32
	if (verbose >= 2) {
		printf("[net] Inicializando WinSock...\n");
	}
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		if (verbose >= 1) {
			fprintf(stderr, "[net] WSAStartup fallo (%d)\n", WSAGetLastError());
		}
		return -1;
	}
	if (verbose >= 2) {
		printf("[net] WinSock OK\n");
	}
#else
	(void)verbose; // evitar warning
#endif
	return 0;
}

void net_cleanup(void) {
#ifdef _WIN32
	WSACleanup();
#endif
}

/*
 * Nota:
 *   - Emplea sockets no bloqueantes para poder imponer un timeout efectivo usando select.
 *   - Cierra cada socket que crea para evitar fugas de descriptor.
 *   - El significado de NET_PORT_FILTERED lo uso cuando la espera expira (select retorna 0),
 *     lo que suele indicar que un firewall/proxy o algo está descartando paquetes en lugar de responder.
 */
static NetPortState connect_with_timeout(const char *host, uint16_t port, int timeout_ms) {
	char port_str[8];

	// Inicializo struct addrinfo para solicitar direcciones de
    // tipo stream/TCP (AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP).
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	socket_t s = INVALID_SOCKET;
	int ret;
	// Convierto el puerto a string en port_str.
	snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	ret = getaddrinfo(host, port_str, &hints, &res); // Resuelvo el host
	if (ret != 0 || !res) {
		return NET_PORT_ERROR;
	}

	NetPortState state = NET_PORT_ERROR;
	// Iteración sobre cada dirección devuelta
	for (struct addrinfo *p = res; p; p = p->ai_next) {
		s = (socket_t)socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (s == INVALID_SOCKET) {
			continue;
		}
		if (set_nonblocking(s) != 0) {
			CLOSESOCK(s);
			continue;
		}

		ret = connect(s, p->ai_addr, (int)p->ai_addrlen);
		if (ret == 0) {
			state = NET_PORT_OPEN; // Conexión exitosa inmediata
			CLOSESOCK(s);
			break;
		}

#ifdef _WIN32
		int wsaerr = WSAGetLastError();
		if (wsaerr != WSAEWOULDBLOCK && wsaerr != WSAEINPROGRESS) {
			CLOSESOCK(s); // conexión fallida o que no progresa
			continue;
		}
#else
		if (errno != EINPROGRESS) {
			CLOSESOCK(s);
			continue;
		}
#endif
		// Odio que mezclen tipos y estructuras, que les cuesta ponerle un tipado a los structs
		fd_set wfds; // escritura
		struct timeval tv; // timeout
		FD_ZERO(&wfds);
		FD_SET(s, &wfds);
		tv.tv_sec = timeout_ms / 1000;
		tv.tv_usec = (timeout_ms % 1000) * 1000;

		ret = select((int)(s + 1), NULL, &wfds, NULL, &tv); // espero a que sea escribible
		if (ret > 0 && FD_ISSET(s, &wfds)) {
			int err = 0;
			socklen_t len = sizeof(err);
			if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &len) == 0 && err == 0) {
				state = NET_PORT_OPEN;
			} else {
				state = NET_PORT_CLOSED;
			}
		} else if (ret == 0) {
			state = NET_PORT_FILTERED; // timeout
		} else {
			state = NET_PORT_ERROR;
		}

		CLOSESOCK(s);
		if (state == NET_PORT_OPEN) break;
	}

	freeaddrinfo(res);
	return state;
}

NetPortState net_scan_tcp_connect(const char *host, uint16_t port, int timeout_ms) {
	return connect_with_timeout(host, port, timeout_ms);
}

int net_grab_banner(const char *host, uint16_t port, char *banner, int banner_len, int timeout_ms) {
	if (!banner || banner_len <= 1) {
		return -1;
	}

	char port_str[8];
	struct addrinfo hints; 
	struct addrinfo *res = NULL;
	socket_t s = INVALID_SOCKET;
	int ret;

	snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	ret = getaddrinfo(host, port_str, &hints, &res);
	if (ret != 0 || !res) {
		return -1;
	}

	int read_len = -1;
	for (struct addrinfo *p = res; p; p = p->ai_next) {
		s = (socket_t)socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (s == INVALID_SOCKET) continue;
		if (connect(s, p->ai_addr, (int)p->ai_addrlen) != 0) {
#ifdef _WIN32
			if (WSAGetLastError() != WSAEWOULDBLOCK && WSAGetLastError() != WSAEINPROGRESS) {
				CLOSESOCK(s);
				continue;
			}
#else
			if (errno != EINPROGRESS) {
				CLOSESOCK(s);
				continue;
			}
#endif
		}

		// Esperar por datos
		fd_set rfds;
		struct timeval tv;
		FD_ZERO(&rfds);
		FD_SET(s, &rfds);
		tv.tv_sec = timeout_ms / 1000;
		tv.tv_usec = (timeout_ms % 1000) * 1000;

		ret = select((int)(s + 1), &rfds, NULL, NULL, &tv);
		if (ret > 0 && FD_ISSET(s, &rfds)) {
			read_len = recv(s, banner, banner_len - 1, 0);
			if (read_len > 0) {
				banner[read_len] = '\0';
			}
		}
		CLOSESOCK(s);
		if (read_len > 0) break;
	}

	freeaddrinfo(res);
	return read_len;
}

static NetPortState connect_udp(const char *host, uint16_t port, int timeout_ms) {
	char port_str[8];
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	socket_t s = INVALID_SOCKET;
	int ret;

	snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	ret = getaddrinfo(host, port_str, &hints, &res);
	if (ret != 0 || !res) {
		return NET_PORT_ERROR;
	}

	NetPortState state = NET_PORT_FILTERED;
	for (struct addrinfo *p = res; p; p = p->ai_next) {
		s = (socket_t)socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (s == INVALID_SOCKET) continue;

		/* Conectar el socket UDP: con "connect" el kernel asocia peer
		   y algunos sistemas propagan ICMP 'port unreachable' como
		   errores en recv(), lo que ayuda a distinguir 'closed' de 'filtered'.*/
		if (connect(s, p->ai_addr, (int)p->ai_addrlen) == SOCKET_ERROR) {
			CLOSESOCK(s);
			continue;
		}

		const char payload[1] = {0};
		ret = send(s, payload, 1, 0);
		if (ret == SOCKET_ERROR) {
			CLOSESOCK(s);
			continue;
		}

		fd_set rfds;
		struct timeval tv;
		FD_ZERO(&rfds);
		FD_SET(s, &rfds);
		tv.tv_sec = timeout_ms / 1000;
		tv.tv_usec = (timeout_ms % 1000) * 1000;

		ret = select((int)(s + 1), &rfds, NULL, NULL, &tv);
		if (ret > 0 && FD_ISSET(s, &rfds)) {
			char buf[256];
			int r = recv(s, buf, (int)sizeof(buf), 0);
			if (r > 0) {
				state = NET_PORT_OPEN; // recibimos datos
			} else if (r == 0) {
				state = NET_PORT_FILTERED; // EOF improbable en UDP
			} else {
#ifdef _WIN32
				int werr = WSAGetLastError();
				if (werr == WSAECONNRESET) {
					state = NET_PORT_CLOSED; // ICMP port unreachable
				} else {
					state = NET_PORT_ERROR;
				}
#else
				if (errno == ECONNREFUSED) {
					state = NET_PORT_CLOSED; // ICMP port unreachable
				} else {
					state = NET_PORT_ERROR;
				}
#endif
			}
		} else if (ret == 0) {
			state = NET_PORT_FILTERED; // sin respuesta dentro del timeout
		} else {
			state = NET_PORT_ERROR; // select devolvió error
		}

		CLOSESOCK(s);
		break; // usar la primer address que funciona
	}

	freeaddrinfo(res);
	return state;
}

NetPortState net_scan_udp(const char *host, uint16_t port, int timeout_ms) {
    return connect_udp(host, port, timeout_ms);
}

NetPortState net_scan_tcp_syn(const char *host, uint16_t port, int timeout_ms) {
	(void)host; // warnings
	(void)port;
	(void)timeout_ms;
	return NET_PORT_ERROR; // todavia no implementado
}
