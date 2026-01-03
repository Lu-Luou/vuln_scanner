#include "config.h"
#include <stdint.h>

const uint16_t popular_ports[] = {2049, 2222, 3000, 3306, 3389, 4000, 5000, 5173, 5900,
	8000, 8080, 8443, 5432, 6379, 27017, 11211, 9200, 9092, 25565, 54321};
const size_t popular_count = sizeof(popular_ports) / sizeof(popular_ports[0]);

void config_init(AppConfig *cfg) {
	if (!cfg) {
		return;
	}

	/* Valores por defecto modificables */
	static const int DEFAULT_MAX_THREADS = 32;
	static const int DEFAULT_TIMEOUT_MS = 800;

	cfg->verbose = 0;
	cfg->os = OS_UNKNOWN;
	cfg->max_threads = DEFAULT_MAX_THREADS;
	cfg->timeout_ms = DEFAULT_TIMEOUT_MS;
}

void config_detect_os(AppConfig *cfg) {
	if (!cfg) {
		return;
	}

    #if defined(_WIN32) || defined(_WIN64)
        cfg->os = OS_WINDOWS;
    #elif defined(__linux__)
        cfg->os = OS_LINUX;
    #else
        cfg->os = OS_UNKNOWN;
    #endif
}

const char *config_os_name(OsType os) {
	switch (os) {
		case OS_WINDOWS:
			return "Windows";
		case OS_LINUX:
			return "Linux";
		default:
			return "Desconocido";
	}
}
