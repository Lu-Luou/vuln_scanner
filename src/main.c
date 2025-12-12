#include <stdio.h>

#include "config.h"

// cd /c/Users/ruber/source/repos/vulnscanner/build
// cmake ..    # only to include new files
// mingw32-make
// ./vulnscanner.exe

int main() {
    AppConfig cfg;
    config_init(&cfg);
    config_detect_os(&cfg);

    printf("Escaner iniciado\n");
    printf("Sistema operativo detectado: %s\n", config_os_name(cfg.os));

    return 0;
}
