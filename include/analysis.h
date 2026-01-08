/* analysis.h - port/banner analysis helpers */
#ifndef ANALYSIS_H
#define ANALYSIS_H

#include <sys/types.h>

#define ANALYSIS_BANNER_LEN 512
#define ANALYSIS_SERVICE_LEN 64
#define ANALYSIS_PROTO_LEN 32

struct port_analysis {
	int port;
	int is_open; /* 0 closed/unreachable, 1 open */
	char banner[ANALYSIS_BANNER_LEN];
	char service[ANALYSIS_SERVICE_LEN];
	char proto[ANALYSIS_PROTO_LEN];
};

/* Prueba en analizar IP:puerto. Returns 0 on success, -1 on error. */
int analyze_port(const char *ip, int port, struct port_analysis *res);

/* Passive banner grabbing: lee un puerto de un socket TCP ya conectado.
 * Returns numero de bytes leidos o -1. */
ssize_t banner_grab_passive(int fd, char *out, size_t out_len, int timeout_seconds);

/* Active banner grabbing: conecta y opcionalmente envia probes. Returns bytes leidos o -1. */
ssize_t banner_grab_active(const char *ip, int port, char *out, size_t out_len, int timeout_seconds);

/* Identifica servicio/protocolo heurísticamente a partir de un banner. */
void identify_service_from_banner(const char *banner, char *service, size_t svc_len, char *proto, size_t proto_len);

#endif /* ANALYSIS_H */
