// Funciones de red multiplataforma para escaneo de puertos
#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>

#include "config.h"

typedef enum {
	NET_PORT_OPEN = 0,
	NET_PORT_CLOSED,
	NET_PORT_FILTERED,
	NET_PORT_ERROR
} NetPortState;

int net_init(const AppConfig *cfg);
void net_cleanup(void);

// Escaneo TCP Connect: retorna NET_PORT_OPEN si el connect() finaliza, NET_PORT_CLOSED si falla.
NetPortState net_scan_tcp_connect(const char *host, uint16_t port, int timeout_ms);

// Banner simple: conecta y lee hasta banner_len-1 bytes; retorna cantidad leida o -1 en error.
int net_grab_banner(const char *host, uint16_t port, char *banner, int banner_len, int timeout_ms);

// UDP best-effort: envia un datagrama vacio y espera respuesta.
NetPortState net_scan_udp(const char *host, uint16_t port, int timeout_ms);

// Placeholder TCP SYN (requiere raw sockets/admin). Actualmente no implementado.
NetPortState net_scan_tcp_syn(const char *host, uint16_t port, int timeout_ms);

#endif // NETWORK_H
