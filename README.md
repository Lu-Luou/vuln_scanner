# Vulnscanner simple y en C usando "GPT-5.1 Codex" y otras herramientas

## Esquema del proyecto

```txt
+-------------------------------------------------------+
|                    VULN SCANNER                       |
+First stage--------------------------------------------+
|                                                       |
|  +------------------------+       +---------------+   |
|  |   Input / CLI Parser   | ----> |  Config Core  |   |
|  +------------------------+       +---------------+   |
|            |                                 |        |
|            v                                 v        |
|  +------Threads-------+            +----------------+ |
|  |  Port Scanner      |<---------->| Network Utils  | |
|  |  - TCP Scan        |            | - Raw sockets  | |
|  |  - SYN Scan        |            | - Packet forge | |
|  |  - UDP Scan        |            | - Timeouts     | |
|  +--------------------+ I'm here   +----------------+ |
|            |                                 |        |
|            v                                 v        |
|  +------Threads-------+ Analysis.c +----------------+ |
|  |  Web Scanner       |<---------->| HTTP Client    | |
|  |  - Dir fuzzing     |            | - GET/POST     | |
|  |  - XSS tests       |            | - Headers      | |
|  |  - SQL tests       |            | - Cookies      | |
|  +--------------------+            +----------------+ |
|            |                                 |        |
|            +------------+         +-----------+       |
|                         |         |                   |
+Second stage-------------|---------|-------------------+
|                         v         v                   |
|            +---------------------------------------+  |
|            |         Vulnerability Engine          |  |
|            |  - Reglas (XSS, SQLi, ports, CMS)     |  |
|            |  - Fingerprinting (OS/CMS)            |  |
|            |  - Scoring de riesgo                  |  |
|            +---------------------------------------+  |
|                         |         |                   |
|                         v         v                   |
|            +------MAYBE-----+   +------------------+  |
|            |  Threat Intel  |   |    Reporting     |  |
|            | - Blacklists   |   | - JSON/HTML logs |  |
|            | - IOC feeds    |   | - Summary CVSS   |  |
|            +----------------+   +------------------+  |
|                         \         /                   |
|                          \       /                    |
|                          +MAYBE+                      |
|                          | TUI |                      |
|                          +-----+                      |
+-------------------------------------------------------+
```

## Funcionamiento

Esta herramienta es un escáner de puertos multihilo escrito en C que realiza comprobaciones básicas
de estado de puerto contra un host objetivo. Actualmente implementa tres modos de escaneo:

- TCP connect: intenta establecer una conexión TCP (método por defecto para `tcp`).
- UDP: envía un datagrama vacío y espera respuesta para distinguir "abierto", "cerrado" o "filtrado".
- TCP SYN: escaneo SYN usando sockets RAW (requiere Linux y privilegios de administrador / cap_net_raw).

Comportamiento clave tomado del código fuente:

- El ejecutable acepta una función (por ejemplo `port_state` o `scan`), un host, un protocolo y opcionalmente un puerto único o un fichero de puertos (uno por línea).
- Si se solicita, puede usar una lista de puertos por defecto que incluye puertos 1-1024 y un conjunto de puertos "populares" (implementado en `scanner_build_default_ports`).
- Escanea puertos en paralelo usando hasta 32 hilos (valor por defecto); el timeout por puerto es de ~800 ms por defecto. Ambos valores por defecto se definen en `src/config.c` como `DEFAULT_MAX_THREADS` y `DEFAULT_TIMEOUT_MS` — editalos ahí para cambiar el comportamiento.
- Para puertos TCP abiertos, el escáner intenta leer un banner con un timeout corto (500 ms).
- Los estados posibles por puerto son: `abierto`, `cerrado`, `filtrado` y `error`.

### Salida

Los resultados se imprimen en formato simple por puerto, por ejemplo:

- `[  22/tcp] abierto`

- `[  53/udp] filtrado`

En modo de `verbose` por defecto (`-v` no pasado) sólo se muestran puertos abiertos y errores;
con `-v` (nivel 2) se muestran todos los estados y mensajes de progreso.

## Conceptos

### Uso

Compilación en Linux/macOS:

```bash
mkdir -p build && cd build
cmake ..
make
```

O simplemente `make` si prefieres usar el `Makefile` desde la raíz del repositorio.

Compilacion en Windows con MSYS2:

```bash
cd build
cmake ..
mingw32-make
```

Ejemplos de ejecución:

- Escanear un puerto UDP concreto (modo normal):

	```bash
	./vulnscanner port_state 127.0.0.1 udp 54321
	```

- Usar `-v` para más salida de diagnóstico:

	```bash
	./vulnscanner -v port_state 127.0.0.1 tcp 22
	```

- Usar la lista por defecto de puertos (1-1024 + populares):

	```bash
	./vulnscanner -d port_state 192.168.1.1 tcp
	```

- Leer puertos desde un fichero (uno por línea):

	```bash
	./vulnscanner -f port_state 10.0.0.5 tcp ports.txt
	```

### Notas

- El modo `tcp_syn` requiere permisos para crear sockets RAW; en Linux ejecuta como `root` o añade la capacidad `cap_net_raw` al binario. Si no hay permisos, el escáner aborta con error.
- El comportamiento fino (lista de puertos, timeouts, número de hilos, etc.) puede ajustarse en el código fuente: `src/scannerIP.c` (construcción de la lista por defecto y worker threads). Para cambiar rápidamente los valores por defecto de hilos y timeout edita las constantes en `src/config.c` (`DEFAULT_MAX_THREADS`, `DEFAULT_TIMEOUT_MS`).
- En Windows el escaneo SYN no está soportado en esta implementación; en Linux está implementado con sockets RAW a mano (ver `net_scan_tcp_syn`).
