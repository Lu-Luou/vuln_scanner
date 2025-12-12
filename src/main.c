#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"
#include "scannerIP.h"
#include "utils.h"

// cd /c/Users/ruber/source/repos/vulnscanner/build
// cmake ..    # only to include new files
// mingw32-make
// ./vulnscanner.exe 127.0.0.1 tcp 1

int main(int argc, char **argv) {
    const char *host = (argc > 1) ? argv[1] : "127.0.0.1";
    const char *mode_str = (argc > 2) ? argv[2] : "tcp";
    int verbose = (argc > 3) ? atoi(argv[3]) : 1;

    ScanMode mode = SCAN_TCP_CONNECT;
    if (strcmp(mode_str, "udp") == 0) {
        mode = SCAN_UDP;
    } else if (strcmp(mode_str, "tcpsyn") == 0) {
        mode = SCAN_TCP_SYN;
    }

    AppConfig cfg;
    config_init(&cfg);
    config_detect_os(&cfg);
    cfg.verbose = verbose;

    printf("Escaner iniciado (%s)\n", config_os_name(cfg.os));
    printf("Objetivo: %s | Modo: %s | Verbose: %d\n", host, mode_str, cfg.verbose);

    PortList list;
    if (scanner_build_default_ports(&list) != 0) {
        fprintf(stderr, "No se pudo construir lista de puertos\n");
        return 1;
    }

    if (scanner_run(host, &list, mode, &cfg) != 0) {
        fprintf(stderr, "Fallo el escaneo\n");
        scanner_free_ports(&list);
        return 1;
    }

    scanner_free_ports(&list);
    return 0;
}
