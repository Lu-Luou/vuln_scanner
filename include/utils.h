#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>
#include "scannerIP.h"

// Imprime ayuda/uso del programa.
void print_usage(const char *prog);

/*  Lee un archivo de puertos (uno por línea) y rellena una PortList.
    Devuelve 0 si OK, -1 en caso de error.*/
int read_ports_file(const char *path, PortList *list);

#endif
