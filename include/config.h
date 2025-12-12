// Configuracion general de la aplicacion
#ifndef CONFIG_H
#define CONFIG_H

typedef enum {
	OS_WINDOWS,
	OS_LINUX,
	OS_UNKNOWN
} OsType;

typedef struct {
	OsType os;
	int verbose; // 0 = solo abiertos, 1 = +filtrados, 2 = todo (incluye cerrados/errores)
} AppConfig;

void config_init(AppConfig *cfg);
void config_detect_os(AppConfig *cfg);
const char *config_os_name(OsType os);

#endif // CONFIG_H
