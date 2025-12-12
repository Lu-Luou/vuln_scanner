// Construccion de listas de puertos y rutinas de escaneo
#ifndef SCANNER_IP_H
#define SCANNER_IP_H

#include <stdint.h>
#include <stddef.h>

#include "config.h"
#include "network.h"

typedef enum {
	SCAN_TCP_CONNECT,
	SCAN_TCP_SYN,
	SCAN_UDP
} ScanMode;

typedef struct {
	uint16_t *ports;
	size_t count;
} PortList;

int scanner_build_default_ports(PortList *list);
void scanner_free_ports(PortList *list);

// Escanea una lista de puertos con el modo indicado y muestra resultados basicos.
int scanner_run(const char *host, const PortList *list, ScanMode mode, const AppConfig *cfg);

#endif // SCANNER_IP_H
