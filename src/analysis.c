#include "analysis.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>


static int set_recv_timeout(int fd, int seconds) {
	struct timeval tv;
	tv.tv_sec = seconds;
	tv.tv_usec = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0)
		return -1;
	return 0;
}

/* Non-blocking connect con timeout. Returns 0, -1 si error. */
static int connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addrlen, int timeout) {
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) return -1;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;

	int rc = connect(fd, addr, addrlen);
	if (rc == 0) {
		fcntl(fd, F_SETFL, flags);
		return 0;
	}
	if (errno != EINPROGRESS) {
		fcntl(fd, F_SETFL, flags);
		return -1;
	}

	fd_set wfds;
	FD_ZERO(&wfds);
	FD_SET(fd, &wfds);
	struct timeval tv;
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	rc = select(fd + 1, NULL, &wfds, NULL, &tv);
	if (rc <= 0) { /* timeout or error */
		fcntl(fd, F_SETFL, flags);
		return -1;
	}
	int err = 0;
	socklen_t len = sizeof(err);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
		fcntl(fd, F_SETFL, flags);
		return -1;
	}
	fcntl(fd, F_SETFL, flags);
	if (err != 0) {
		errno = err;
		return -1;
	}
	return 0;
}

ssize_t banner_grab_passive(int fd, char *out, size_t out_len, int timeout_seconds) {
	if (!out || out_len == 0) return -1;
	if (set_recv_timeout(fd, timeout_seconds) < 0) return -1;
	ssize_t n = recv(fd, out, out_len - 1, 0);
	if (n > 0) out[n] = '\0';
	else if (n == 0) {
		/* remote closed */
		out[0] = '\0';
	} else {
		/* recv error or timeout */
		out[0] = '\0';
		return -1;
	}
	return n;
}

/* Auxiliar para enviar un buffer corto acorde a puertos comunes */
static void choose_probe_for_port(int port, char *probe, size_t len) {
	if (!probe) return;
	probe[0] = '\0';
	switch (port) {
		case 80: case 8080: case 8000:
			snprintf(probe, len, "HEAD / HTTP/1.0\r\nHost: example\r\n\r\n");
			break;
		case 443:
			/* TLS: no puede enviar probe en texto plano, vacío */
			probe[0] = '\0';
			break;
		case 22:
			/* SSH usualmente envía banner sin solicitar, no se necesita probe */
			probe[0] = '\0';
			break;
		case 25:
			snprintf(probe, len, "EHLO example.com\r\n");
			break;
		case 21:
			/* FTP envía banner al conectar */
			probe[0] = '\0';
			break;
		case 110: case 995: case 143: case 993:
			probe[0] = '\0';
			break;
		default:
			/* Probe genérica que puede provocar una respuesta */
			snprintf(probe, len, "\r\n");
			break;
	}
}

ssize_t banner_grab_active(const char *ip, int port, char *out, size_t out_len, int timeout_seconds) {
	if (!ip || !out || out_len == 0) return -1;
	int fd = -1;
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	if (inet_pton(AF_INET, ip, &sa.sin_addr) <= 0) return -1;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;

	if (connect_with_timeout(fd, (struct sockaddr*)&sa, sizeof(sa), timeout_seconds) < 0) {
		close(fd);
		return -1;
	}

	/* Primero intentar leer cualquier banner inmediato sin mandar nada */
	if (set_recv_timeout(fd, 1) == 0) {
		ssize_t n = recv(fd, out, out_len - 1, 0);
		if (n > 0) {
			out[n] = '\0';
			close(fd);
			return n;
		}
	}

	/* Enviar un probe activo para ese puerto */
	char probe[256];
	choose_probe_for_port(port, probe, sizeof(probe));
	if (probe[0] != '\0') {
		ssize_t s = send(fd, probe, strlen(probe), 0);
		(void)s;
	}

	if (set_recv_timeout(fd, timeout_seconds) < 0) {
		close(fd);
		return -1;
	}
	ssize_t n = recv(fd, out, out_len - 1, 0);
	if (n > 0) out[n] = '\0';
	else if (n <= 0) out[0] = '\0';
	close(fd);
	return n;
}

void identify_service_from_banner(const char *banner, char *service, size_t svc_len, char *proto, size_t proto_len) {
	if (!service || svc_len == 0) return;
	if (!proto || proto_len == 0) return;
	service[0] = '\0';
	proto[0] = '\0';
	if (!banner || banner[0] == '\0') {
		strncpy(service, "unknown", svc_len);
		strncpy(proto, "tcp", proto_len);
		return;
	}
	const char *b = banner;
	if (strstr(b, "HTTP/") || strstr(b, "Server:") || strstr(b, "GET ") || strstr(b, "HEAD ")) {
		strncpy(service, "http", svc_len);
		strncpy(proto, "tcp", proto_len);
		return;
	}
	if (strstr(b, "SSH-")) {
		strncpy(service, "ssh", svc_len);
		strncpy(proto, "tcp", proto_len);
		return;
	}
	if (strstr(b, "220") && (strstr(b, "SMTP") || strstr(b, "ESMTP"))) {
		strncpy(service, "smtp", svc_len);
		strncpy(proto, "tcp", proto_len);
		return;
	}
	if (strstr(b, "FTP") || strstr(b, "220 ")) {
		strncpy(service, "ftp", svc_len);
		strncpy(proto, "tcp", proto_len);
		return;
	}
	if (strstr(b, "POP3") || strstr(b, "+OK")) {
		strncpy(service, "pop3", svc_len);
		strncpy(proto, "tcp", proto_len);
		return;
	}
	/* fallback heuristics */
	if (strcasestr(b, "smtp")) { strncpy(service, "smtp", svc_len); strncpy(proto, "tcp", proto_len); return; }
	if (strcasestr(b, "http")) { strncpy(service, "http", svc_len); strncpy(proto, "tcp", proto_len); return; }

	strncpy(service, "unknown", svc_len);
	strncpy(proto, "tcp", proto_len);
}

int analyze_port(const char *ip, int port, struct port_analysis *res) {
	if (!ip || !res) return -1;
	memset(res, 0, sizeof(*res));
	res->port = port;

	char banner[ANALYSIS_BANNER_LEN];
	ssize_t n = banner_grab_active(ip, port, banner, sizeof(banner), 3);
	if (n < 0) {
		res->is_open = 0;
		res->banner[0] = '\0';
		strncpy(res->service, "closed/filtered", ANALYSIS_SERVICE_LEN);
		strncpy(res->proto, "tcp", ANALYSIS_PROTO_LEN);
		return 0;
	}
	res->is_open = 1;
	strncpy(res->banner, banner[0] ? banner : "", ANALYSIS_BANNER_LEN);
	identify_service_from_banner(res->banner, res->service, ANALYSIS_SERVICE_LEN, res->proto, ANALYSIS_PROTO_LEN);
	return 0;
}

