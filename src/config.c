#include "config.h"

void config_init(AppConfig *cfg) {
	if (!cfg) {
		return;
	}

	cfg->verbose = 0;
	cfg->os = OS_UNKNOWN;
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
