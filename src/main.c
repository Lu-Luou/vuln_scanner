#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"
#include "scannerIP.h"
#include "utils.h"

// cd /c/Users/ruber/source/repos/vulnscanner/build
// cmake ..    # only to include new files
// mingw32-make

/* examples:
 * ./vulnscanner.exe -v -d port_state 127.0.0.1 udp
 * ./vulnscanner.exe port_state 127.0.0.1 udp 54321
 * ./vulnscanner.exe -f port_state 127.0.0.1 udp ports.txt
 */

int main(int argc, char **argv) {
    int verbose = 1;
    int use_file = 0;
    int use_default = 0;
    int argi = 1;

    /* parse flags */
    while (argi < argc && argv[argi][0] == '-') {
        if (strcmp(argv[argi], "-v") == 0) {
            /* -v without argument => verbose level 2 */
            verbose = 2;
            argi++;
        } else if (strcmp(argv[argi], "-d") == 0) {
            use_default = 1;
            argi++;
        } else if (strcmp(argv[argi], "-f") == 0) {
            use_file = 1;
            argi++;
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (argi >= argc) { print_usage(argv[0]); return 1; }
    const char *function = argv[argi++];
    if (argi >= argc) { print_usage(argv[0]); return 1; }
    const char *host = argv[argi++];
    if (argi >= argc) { print_usage(argv[0]); return 1; }
    const char *mode_str = argv[argi++];

    const char *port_arg = (argi < argc) ? argv[argi] : NULL;

    /* Validar modo de escaneo: aceptar "tcp" (connect), "udp", o "syn"/"tcp_syn" */
    ScanMode mode = SCAN_TCP_CONNECT;
    if (strcmp(mode_str, "udp") == 0) {
        mode = SCAN_UDP;
    } else if (strcmp(mode_str, "tcp_syn") == 0 || strcmp(mode_str, "tcpsyn") == 0 || strcmp(mode_str, "syn") == 0) {
        mode = SCAN_TCP_SYN;
    } else if (strcmp(mode_str, "tcp") == 0 || strcmp(mode_str, "connect") == 0 || strcmp(mode_str, "tcp_connect") == 0) {
        mode = SCAN_TCP_CONNECT;
    } else {
        fprintf(stderr, "Modo de escaneo desconocido: %s\n", mode_str);
        fprintf(stderr, "Modos válidos: tcp, udp, syn / tcp_syn)\n");
        return 1;
    }

    AppConfig cfg;
    config_init(&cfg);
    config_detect_os(&cfg);
    cfg.verbose = verbose;

    printf("Escaner iniciado (%s)\n", config_os_name(cfg.os));
    printf("Funcion: %s | Objetivo: %s | Modo: %s | Verbose: %d\n", function, host, mode_str, cfg.verbose);

    PortList list;
    memset(&list, 0, sizeof(list));

    if (use_default) {
        if (scanner_build_default_ports(&list) != 0) {
            fprintf(stderr, "No se pudo construir lista de puertos\n");
            return 1;
        }
    } else if (use_file) {
        if (!port_arg) { fprintf(stderr, "Falta archivo de puertos\n"); return 1; }
        if (read_ports_file(port_arg, &list) != 0) {
            fprintf(stderr, "No se pudo leer archivo de puertos: %s\n", port_arg);
            return 1;
        }
    } else if (port_arg) {
        // si se pasa un puerto simple
        long v = strtol(port_arg, NULL, 10);
        if (v > 0 && v <= 65535) {
            uint16_t *buf = (uint16_t *)malloc(sizeof(uint16_t));
            if (!buf) { fprintf(stderr, "Sin memoria\n"); return 1; }
            buf[0] = (uint16_t)v;
            list.ports = buf;
            list.count = 1;
        } else {
            // no numérico: intentar leer como archivo aunque no se haya pasado -f
            if (read_ports_file(port_arg, &list) != 0) {
                fprintf(stderr, "Argumento de puerto inválido: %s\n", port_arg);
                return 1;
            }
        }
    } else {
        if (scanner_build_default_ports(&list) != 0) {
            fprintf(stderr, "No se pudo construir lista de puertos\n");
            return 1;
        }
    }

    /* map function name -> action */
    if (strcmp(function, "port_state") == 0 || strcmp(function, "scan") == 0) {
        if (scanner_run(host, &list, mode, &cfg) != 0) {
            fprintf(stderr, "Fallo el escaneo\n");
            scanner_free_ports(&list);
            return 1;
        }
    } else {
        fprintf(stderr, "Funcion desconocida: %s\n", function);
        scanner_free_ports(&list);
        return 1;
    }

    scanner_free_ports(&list);
    return 0;
}
