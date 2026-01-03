#include "network.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <sys/select.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>


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
#if defined(_WIN32)
		if (ret > 0 && FD_ISSET(s, &rfds)) {
			char buf[256];
			int r = recv(s, buf, (int)sizeof(buf), 0);
			if (r > 0) {
				state = NET_PORT_OPEN; // recibimos datos
			} else if (r == 0) {
				state = NET_PORT_FILTERED; // EOF improbable en UDP
			} else {
#else
		if (ret > 0 && FD_ISSET(s, &rfds)) {
			char buf[256];
			ssize_t r = recv(s, buf, sizeof(buf), 0);
			if (r > 0) {
				state = NET_PORT_OPEN; // recibimos datos
			} else if (r == 0) {
				state = NET_PORT_FILTERED; // EOF improbable en UDP
			} else {
#endif
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
#ifdef _WIN32
	(void)host; (void)port; (void)timeout_ms;
	return NET_PORT_ERROR; // no implementado en Windows
#else
	struct addrinfo hints, *res = NULL;
	char port_str[8];
	snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; // IPv4 only for SYN scan
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
		if (res) freeaddrinfo(res);
		return NET_PORT_ERROR;
	}

	struct sockaddr_in *dst = (struct sockaddr_in *)res->ai_addr; // Parseo destino

	// Empieza el crafteo del socket RAW porque me encanta sufrir en bajo nivel
	// Obtener IP origen local en base a ruta hacia destino, no tcp real
	int tmp = socket(AF_INET, SOCK_DGRAM, 0);
	if (tmp < 0) { 
		freeaddrinfo(res);
		return NET_PORT_ERROR;
	}
	struct sockaddr_in tmpaddr;
	memset(&tmpaddr, 0, sizeof(tmpaddr));
	tmpaddr.sin_family = AF_INET;
	tmpaddr.sin_addr.s_addr = dst->sin_addr.s_addr;
	tmpaddr.sin_port = htons(53);
	connect(tmp, (struct sockaddr *)&tmpaddr, sizeof(tmpaddr));
	struct sockaddr_in local;
	socklen_t llen = sizeof(local);
	memset(&local,0,sizeof(local));
	if (getsockname(tmp, (struct sockaddr *)&local, &llen) < 0) {
		close(tmp);
		freeaddrinfo(res);
		return NET_PORT_ERROR;
	}
	close(tmp);

	// Crear sockets RAW
	int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (send_sock < 0 || recv_sock < 0) {
		if (send_sock >= 0) close(send_sock);
		if (recv_sock >= 0) close(recv_sock);
		freeaddrinfo(res);
		return NET_PORT_ERROR;
	}

	int one = 1;
	if (setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
		close(send_sock);
		close(recv_sock);
		freeaddrinfo(res);
		return NET_PORT_ERROR;
	}

	// Construir paquete IP/TCP
	unsigned char packet[4096];
	memset(packet, 0, sizeof(packet));
	struct iphdr *iph = (struct iphdr *)packet;
	struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
	iph->id = htons(rand() & 0xFFFF);
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->saddr = local.sin_addr.s_addr;
	iph->daddr = dst->sin_addr.s_addr;

	// Elegir puertos y secuencia en host-order para validación posterior
	uint16_t src_port = (uint16_t)(1025 + (rand() % (65535 - 1025)));
	uint32_t seq_host = ((uint32_t)rand() << 16) ^ (uint32_t)rand();
	tcph->source = htons(src_port);
	tcph->dest = htons(port);
	tcph->seq = htonl(seq_host);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr) / 4;
	tcph->syn = 1;
	tcph->window = htons(65535);

	// IP checksum
	unsigned long sum = 0;
	unsigned short *iphs = (unsigned short *)iph;
	for (int i = 0; i < (int)(iph->ihl * 2); ++i) 
		sum += iphs[i];
	while (sum >> 16) 
		sum = (sum & 0xFFFF) + (sum >> 16);
	iph->check = (unsigned short)(~sum);

	// TCP checksum (pseudo-header)
	struct {
		uint32_t src_addr;
		uint32_t dst_addr;
		uint8_t zero;
		uint8_t proto;
		uint16_t tcp_len;
	} pseudo;
	pseudo.src_addr = iph->saddr;
	pseudo.dst_addr = iph->daddr;
	pseudo.zero = 0;
	pseudo.proto = IPPROTO_TCP;
	pseudo.tcp_len = htons(sizeof(struct tcphdr));

	unsigned char chkbuf[sizeof(pseudo) + sizeof(struct tcphdr)];
	memcpy(chkbuf, &pseudo, sizeof(pseudo));
	memcpy(chkbuf + sizeof(pseudo), tcph, sizeof(struct tcphdr));

	unsigned long csum = 0;
	unsigned short *w = (unsigned short *)chkbuf;
	int wn = (sizeof(chkbuf) + 1) / 2;
	for (int i = 0; i < wn; ++i)
		csum += w[i];
	while (csum >> 16)
		csum = (csum & 0xFFFF) + (csum >> 16);
	tcph->check = (unsigned short)(~csum);


	// Envia el paquete ya construido
	struct sockaddr_in to = *dst;
	ssize_t sent = sendto(send_sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
						  (struct sockaddr *)&to, sizeof(to));
	if (sent <= 0) {
		close(send_sock); close(recv_sock); freeaddrinfo(res); return NET_PORT_ERROR;
	}

	/* Esperar potenciales múltiples respuestas dentro del timeout
	   Para evitar races entre hilos y manejar respuestas reordenadas, no
	   asumimos que la primera recv pertenece a este SYN: validamos
	   que el ACK contiene seq+1 (en host order). Si no coincide, seguimos
	   leyendo hasta agotar el timeout. */
	NetPortState state = NET_PORT_FILTERED;
	struct timeval start_tv, now_tv;
	gettimeofday(&start_tv, NULL);

	while (1) {
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(recv_sock, &rfds);
		gettimeofday(&now_tv, NULL);
		long elapsed_ms = (now_tv.tv_sec - start_tv.tv_sec) * 1000 +
						  (now_tv.tv_usec - start_tv.tv_usec) / 1000;
		long remaining_ms = timeout_ms - elapsed_ms;
		if (remaining_ms <= 0) {
			state = NET_PORT_FILTERED;
			break;
		}
		struct timeval tv;
		tv.tv_sec = remaining_ms / 1000;
		tv.tv_usec = (remaining_ms % 1000) * 1000;

		int sel = select(recv_sock + 1, &rfds, NULL, NULL, &tv);
		if (sel < 0) {
			state = NET_PORT_ERROR;
			break;
		}
		if (sel == 0) {
			state = NET_PORT_FILTERED; // timeout
			break;
		}

		if (FD_ISSET(recv_sock, &rfds)) {
			unsigned char buf[65536];
			ssize_t r = recv(recv_sock, buf, sizeof(buf), 0);
			if (r <= 0) continue; // intentar nuevamente hasta timeout

			struct iphdr *riph = (struct iphdr *)buf;
			size_t iphdr_len = (riph->ihl > 0) ? (riph->ihl * 4) : sizeof(struct iphdr);
			if ((size_t)r <= iphdr_len + sizeof(struct tcphdr)) continue;
			struct tcphdr *rtcp = (struct tcphdr *)(buf + iphdr_len);

			// Verificar dirección/puertos
			if (riph->saddr != iph->daddr || riph->daddr != iph->saddr) continue;
			if (ntohs(rtcp->source) != port || ntohs(rtcp->dest) != src_port) continue;

			// Validar flags y número de ack (debe ser seq_host+1)
			uint32_t resp_ack = ntohl(rtcp->ack_seq);
			if (rtcp->syn && rtcp->ack && resp_ack == (seq_host + 1)) {
				state = NET_PORT_OPEN;

				/* Enviar un RST para evitar completar la conexión en el servidor
				   (SYN scan típicamente envía RST inmediatamente tras recibir SYN-ACK). */
				{
					unsigned char rst_pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)];
					memset(rst_pkt, 0, sizeof(rst_pkt));
					struct iphdr *riph2 = (struct iphdr *)rst_pkt;
					struct tcphdr *rtcp2 = (struct tcphdr *)(rst_pkt + sizeof(struct iphdr));

					riph2->ihl = 5;
					riph2->version = 4;
					riph2->tos = 0;
					riph2->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
					riph2->id = htons(rand() & 0xFFFF);
					riph2->frag_off = 0;
					riph2->ttl = 64;
					riph2->protocol = IPPROTO_TCP;
					riph2->saddr = iph->saddr; // origen = nuestro IP
					riph2->daddr = iph->daddr; // destino = target IP

					rtcp2->source = htons(src_port);
					rtcp2->dest = htons(port);
					rtcp2->doff = sizeof(struct tcphdr) / 4;
					rtcp2->rst = 1;

					/* Usar ack_seq = servidor_seq + 1 para que el RST sea aceptado */
					uint32_t server_seq = ntohl(rtcp->seq);
					rtcp2->ack_seq = htonl(server_seq + 1);

					/* Calcular checksums IP y TCP */
					unsigned long sum2 = 0;
					unsigned short *ip2h = (unsigned short *)riph2;
					for (int i = 0; i < (int)(riph2->ihl * 2); ++i)
						sum2 += ip2h[i];
					while (sum2 >> 16) sum2 = (sum2 & 0xFFFF) + (sum2 >> 16);
					riph2->check = (unsigned short)(~sum2);

					struct {
						uint32_t src_addr;
						uint32_t dst_addr;
						uint8_t zero;
						uint8_t proto;
						uint16_t tcp_len;
					} pseudo2;
					pseudo2.src_addr = riph2->saddr;
					pseudo2.dst_addr = riph2->daddr;
					pseudo2.zero = 0;
					pseudo2.proto = IPPROTO_TCP;
					pseudo2.tcp_len = htons(sizeof(struct tcphdr));

					unsigned char chkbuf2[sizeof(pseudo2) + sizeof(struct tcphdr)];
					memcpy(chkbuf2, &pseudo2, sizeof(pseudo2));
					memcpy(chkbuf2 + sizeof(pseudo2), rtcp2, sizeof(struct tcphdr));
					unsigned long csum2 = 0;
					unsigned short *w2 = (unsigned short *)chkbuf2;
					int wn2 = (sizeof(chkbuf2) + 1) / 2;
					for (int i = 0; i < wn2; ++i) csum2 += w2[i];
					while (csum2 >> 16) csum2 = (csum2 & 0xFFFF) + (csum2 >> 16);
					rtcp2->check = (unsigned short)(~csum2);

					sendto(send_sock, rst_pkt, sizeof(rst_pkt), 0, (struct sockaddr *)&to, sizeof(to));
				}

				break;
			} else if (rtcp->rst) {
				state = NET_PORT_CLOSED;
				break;
			} else {
				/* no es la respuesta esperada: seguir esperando */
				continue;
			}
		}
	}

	close(send_sock);
	close(recv_sock);
	freeaddrinfo(res);
	return state;
#endif
}
