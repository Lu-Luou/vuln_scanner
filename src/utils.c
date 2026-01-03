
#include "utils.h"
#include "scannerIP.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_usage(const char *prog) {
	printf("Uso: %s [-v] [-d] [-f] <function> <host> <protocol> [port|ports_file]\n", prog);
	printf("  -v      : activa verbose nivel 2 (mostrar todos los estados). Default 1\n");
	printf("  -d      : usar lista por defecto (puertos 1-1024 + populares)\n");
	printf("  -f      : indica que el último argumento es un archivo con puertos (uno por línea)\n");
	printf("  function: 'port_state' (o 'scan')\n");
	printf("  protocol: tcp | udp | tcp_syn\n");
	printf("Ejemplo: %s -v port_state 127.0.0.1 udp 54321\n", prog);
}

int read_ports_file(const char *path, PortList *list) {
	if (!path || !list) return -1;
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	uint16_t *buf = NULL;
	size_t cap = 0, cnt = 0;
	char line[128];
	while (fgets(line, sizeof(line), f)) {
		char *s = line;
		while (*s == ' ' || *s == '\t') s++;
		if (*s == '\0' || *s == '\n' || *s == '#') continue;
		char *end = NULL;
		long v = strtol(s, &end, 10);
		if (end == s || v <= 0 || v > 65535) continue;
		if (cnt + 1 > cap) {
			size_t newcap = (cap == 0) ? 16 : cap * 2;
			uint16_t *n = (uint16_t *)realloc(buf, newcap * sizeof(uint16_t));
			if (!n) { free(buf); fclose(f); return -1; }
			buf = n; cap = newcap;
		}
		buf[cnt++] = (uint16_t)v;
	}
	fclose(f);
	if (cnt == 0) {
		free(buf);
		return -1;
	}
	list->ports = buf;
	list->count = cnt;
	return 0;
}

