// Configuracion general de la aplicacion
#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
	OS_WINDOWS,
	OS_LINUX,
	OS_UNKNOWN
} OsType;

typedef struct {
	OsType os;
	int verbose; // 0 = solo abiertos, 1 = +filtrados, 2 = todo (incluye cerrados/errores)
    int max_threads; // maximo de hilos worker (configurable en config.c)
    int timeout_ms;  // timeout por puerto en milisegundos (configurable en config.c)
} AppConfig;

extern const uint16_t popular_ports[];
extern const size_t popular_count;

void config_init(AppConfig *cfg);
void config_detect_os(AppConfig *cfg);
const char *config_os_name(OsType os);

#endif // CONFIG_H
