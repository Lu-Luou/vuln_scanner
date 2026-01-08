#include "scannerIP.h"
#include "analysis.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static int add_port(uint16_t port, uint8_t *seen, uint16_t *buffer, size_t *count, size_t max_count) {
	if (port == 0 || port > MAX_PORT) return 0;
	if (seen[port]) return 0;
	if (*count >= max_count) return -1;
	seen[port] = 1;
	buffer[*count] = port;
	(*count)++;
	return 0;
}

int scanner_build_default_ports(PortList *list) {
	if (!list) return -1;
	memset(list, 0, sizeof(*list));

	// Reservar un buffer razonable: 1024 + (9 * populares) + extra por realocs
	size_t max_ports = 1024 + (popular_count * 9) + 32;
	uint16_t *buffer = (uint16_t *)malloc(max_ports * sizeof(uint16_t));
	if (!buffer) return -1;

	uint8_t *seen = (uint8_t *)calloc(MAX_PORT + 1, sizeof(uint8_t));
	if (!seen) {
		free(buffer);
		return -1;
	}

	size_t count = 0;
	// Puertos 1-1024
	for (uint16_t p = 1; p <= 1024; ++p) {
		if (add_port(p, seen, buffer, &count, max_ports) != 0) break;
	}

	// Populares +/- 4
	for (size_t i = 0; i < popular_count; ++i) {
		uint16_t base = popular_ports[i];
		uint16_t start = (base > 4) ? (uint16_t)(base - 4) : 1;
		uint16_t end = (base + 4 <= MAX_PORT) ? (uint16_t)(base + 4) : MAX_PORT;
		for (uint16_t p = start; p <= end; ++p) {
			if (add_port(p, seen, buffer, &count, max_ports) != 0) break;
		}
	}

	free(seen);
	list->ports = buffer;
	list->count = count;
	return 0;
}

void scanner_free_ports(PortList *list) {
	if (!list) return;
	free(list->ports);
	list->ports = NULL;
	list->count = 0;
}

static const char *state_to_str(NetPortState s) {
	switch (s) {
		case NET_PORT_OPEN: return "abierto";
		case NET_PORT_CLOSED: return "cerrado";
		case NET_PORT_FILTERED: return "filtrado";
		default: return "error";
	}
}

static NetPortState scan_port(const char *host, uint16_t port, ScanMode mode, int timeout_ms, const AppConfig *cfg) {
	switch (mode) {
		case SCAN_TCP_CONNECT:
			return net_scan_tcp_connect(host, port, timeout_ms);
			case SCAN_TCP_SYN:
				if (cfg && cfg->os != OS_LINUX) {
					if (cfg->verbose) {
						printf("[!] TCP SYN solo soportado en Linux en esta implementación\n");
					}
					return NET_PORT_ERROR;
				}
				return net_scan_tcp_syn(host, port, timeout_ms);
		case SCAN_UDP:
			return net_scan_udp(host, port, timeout_ms);
		default:
			return NET_PORT_ERROR;
	}
}

typedef struct PrintedResult {
	uint16_t port;
	ScanMode mode;
	NetPortState state;
	int banner_len;
	char banner[128];
} PrintedResult;

static int cmp_port(const void *a, const void *b) {
	const PrintedResult *ra = (const PrintedResult *)a;
	const PrintedResult *rb = (const PrintedResult *)b;
	if (ra->port < rb->port) return -1;
	if (ra->port > rb->port) return 1;
	return 0;
}

typedef struct {
	const char *host;
	const PortList *list;
	ScanMode mode;
	const AppConfig *cfg;
	int timeout_ms;
	size_t *cursor;
	mutex_t *cursor_mtx;
	mutex_t *print_mtx;

	// resultados compartidos
	struct PrintedResult *results;
	size_t *res_count;
	mutex_t *res_mtx;

	// progreso
	size_t *processed;
	size_t *next_progress;
	mutex_t *progress_mtx;
	size_t total_ports;
} WorkerArgs; // argumentos para cada hilo laburante


/*
Compatibilidad con CreateThread: la firma DWORD WINAPI ThreadProc(LPVOID lpParameter)
es la requerida por CreateThread/WaitForMultipleObjects en la API Win32.

LPVOID es equivalente a void* (puntero genérico para pasar argumentos al hilo).

DWORD es un entero sin signo de 32 bits usado como código de salida del hilo.

WINAPI es una convención de llamada (stdcall) usada por la API Win32.
*/

/*
En POSIX se usa la firma void worker_thread(void param)
porque pthread_create espera un retorno void y un parámetro void
porque linux la rompe ;)
*/
#ifdef _WIN32
static DWORD WINAPI worker_thread(LPVOID param)
#else
static void *worker_thread(void *param)
#endif
{
	WorkerArgs *w = (WorkerArgs *)param;
	for (;;) {
		size_t idx;
		mutex_lock(w->cursor_mtx);
		idx = (*(w->cursor))++;
		mutex_unlock(w->cursor_mtx);
		if (idx >= w->list->count) {
			break;
		}

		uint16_t port = w->list->ports[idx];
		NetPortState st = scan_port(w->host, port, w->mode, w->timeout_ms, w->cfg);
		int should_store = 0;
		if (w->cfg->verbose > 1) {
			/* verbose >= 2: almacenar todos los estados */
			should_store = 1;
		} else {
			/* verbose <= 1: sólo almacenar puertos abiertos o con error */
			if (st == NET_PORT_OPEN || st == NET_PORT_ERROR) {
				should_store = 1;
			}
		}

		if (should_store) {
			PrintedResult pr;
			pr.port = port;
			pr.mode = w->mode;
			pr.state = st;
			pr.banner_len = -1;
			pr.banner[0] = '\0';
			if (st == NET_PORT_OPEN && w->mode == SCAN_TCP_CONNECT) {
				pr.banner_len = net_grab_banner(w->host, port, pr.banner, (int)sizeof(pr.banner), 500);
			}

			mutex_lock(w->res_mtx);
			size_t idx = *(w->res_count);
			w->results[idx] = pr;
			(*(w->res_count))++;
			mutex_unlock(w->res_mtx);
		}

		// progreso cada 128 puertos procesados
		mutex_lock(w->progress_mtx);
		size_t processed_now = ++(*(w->processed));
		if (processed_now >= *(w->next_progress)) {
			*(w->next_progress) += 128;
			/* Solo imprimir progreso si verbose > 1. En verbose <= 1
			   actualizamos el contador pero no mostramos nada. */
			if (w->cfg && w->cfg->verbose > 1) {
				mutex_lock(w->print_mtx);
				printf("[progreso] %zu/%zu puertos escaneados\n", processed_now, w->total_ports);
				mutex_unlock(w->print_mtx);
			}
		}
		mutex_unlock(w->progress_mtx);
	}

#ifdef _WIN32
	return 0;
#else
	return NULL;
#endif
}

int scanner_run(const char *host, const PortList *list, ScanMode mode, const AppConfig *cfg) {
	if (!host || !list || !cfg) return -1;
	if (net_init(cfg) != 0) {
		fprintf(stderr, "No se pudo inicializar red\n");
		return -1;
	}

	/* Si se solicita SCAN_TCP_SYN, validar permiso para RAW sockets */
	if (mode == SCAN_TCP_SYN) {
#ifdef __linux__
		int check = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
		if (check < 0) {
			fprintf(stderr, "No hay permiso para sockets RAW: %s\n", strerror(errno));
			fprintf(stderr, "Ejecute como root o asigne cap_net_raw a binario\n");
			net_cleanup();
			return -1;
		}
		close(check);
#else
		if (cfg->verbose) fprintf(stderr, "SYN scan solo soportado en Linux\n");
		net_cleanup();
		return -1;
#endif
	}

	int timeout_ms = (cfg && cfg->timeout_ms > 0) ? cfg->timeout_ms : 800; // timeout moderado (configurable)
	size_t cursor = 0;
	size_t processed = 0;
	size_t next_progress = 128;
	mutex_t cursor_mtx;
	mutex_t print_mtx;
	mutex_init(&cursor_mtx);
	mutex_init(&print_mtx);
	mutex_t res_mtx;
	mutex_init(&res_mtx);
	mutex_t progress_mtx;
	mutex_init(&progress_mtx);

	PrintedResult *results = (PrintedResult *)malloc(list->count * sizeof(PrintedResult));
	size_t res_count = 0;

	// elegir cantidad de hilos (max configurable en cfg->max_threads o cantidad de puertos si es menor)
	size_t max_threads = (cfg && cfg->max_threads > 0) ? (size_t)cfg->max_threads : 32;
	size_t worker_count = list->count < max_threads ? list->count : max_threads;
	if (worker_count == 0) {
		net_cleanup();
		mutex_destroy(&cursor_mtx);
		mutex_destroy(&print_mtx);
		mutex_destroy(&res_mtx);
		free(results);
		return 0;
	}

	thread_handle_t *threads = (thread_handle_t *)malloc(worker_count * sizeof(thread_handle_t));
	WorkerArgs *args = (WorkerArgs *)malloc(worker_count * sizeof(WorkerArgs));
	if (!threads || !args || !results) {
		fprintf(stderr, "Sin memoria para hilos\n");
		free(threads);
		free(args);
		free(results);
		net_cleanup();
		mutex_destroy(&cursor_mtx);
		mutex_destroy(&print_mtx);
		mutex_destroy(&res_mtx);
		mutex_destroy(&progress_mtx);
		return -1;
	} // necesito una copia de args por hilo para no pisarlos más allá de que conecte las variables con punteros

	for (size_t i = 0; i < worker_count; i++) { // ++i?
		args[i].host = host;
		args[i].list = list;
		args[i].mode = mode;
		args[i].cfg = cfg;
		args[i].timeout_ms = timeout_ms;
		args[i].cursor = &cursor;
		args[i].cursor_mtx = &cursor_mtx;
		args[i].print_mtx = &print_mtx;
		args[i].results = results;
		args[i].res_count = &res_count;
		args[i].res_mtx = &res_mtx;
		args[i].processed = &processed;
		args[i].next_progress = &next_progress;
		args[i].progress_mtx = &progress_mtx;
		args[i].total_ports = list->count;

#ifdef _WIN32
		threads[i] = CreateThread(NULL, 0, worker_thread, &args[i], 0, NULL);
#else
		pthread_create(&threads[i], NULL, worker_thread, &args[i]);
#endif
	}

#ifdef _WIN32
	WaitForMultipleObjects((DWORD)worker_count, threads, TRUE, INFINITE); // esperar a todos los hilos antes de borrarlos
	for (size_t i = 0; i < worker_count; ++i) {
		CloseHandle(threads[i]);
	}
#else
	for (size_t i = 0; i < worker_count; ++i) {
		pthread_join(threads[i], NULL); // aca me paso la verificacion porque linux la rompe ;)
	}
#endif

	// ordenar y emitir resultados para registro ordenado por puerto
	if (res_count > 1) {
		qsort(results, res_count, sizeof(PrintedResult), cmp_port);
	}

	for (size_t i = 0; i < res_count; ++i) {
		const PrintedResult *pr = &results[i];
		/* Si verbose <= 1, sólo mostrar abiertos o errores. En verbose >=2 mostrar todo. */
		if (cfg->verbose <= 1) {
			if (!(pr->state == NET_PORT_OPEN || pr->state == NET_PORT_ERROR)) {
				continue;
			}
		}
		const char *proto = (pr->mode == SCAN_UDP) ? "udp" : "tcp";
		if (pr->state == NET_PORT_OPEN && pr->mode != SCAN_UDP) {
			struct port_analysis pa;
			if (analyze_port(host, pr->port, &pa) == 0 && pa.is_open) {
				if (pa.banner[0]) {
					printf("[%5u/%s] %s | service=%s proto=%s | banner: %s\n", pr->port, proto, state_to_str(pr->state), pa.service, pa.proto, pa.banner);
				} else {
					/* No banner but service identified */
					printf("[%5u/%s] %s | service=%s proto=%s\n", pr->port, proto, state_to_str(pr->state), pa.service, pa.proto);
				}
			} else {
				/* Fallback banner */
				if (pr->banner_len > 0) {
					printf("[%5u/%s] %s | banner: %s\n", pr->port, proto, state_to_str(pr->state), pr->banner);
				} else {
					printf("[%5u/%s] %s\n", pr->port, proto, state_to_str(pr->state));
				}
			}
		} else {
			if (pr->banner_len > 0) {
				printf("[%5u/%s] %s | banner: %s\n", pr->port, proto, state_to_str(pr->state), pr->banner);
			} else {
				printf("[%5u/%s] %s\n", pr->port, proto, state_to_str(pr->state));
			}
		}
	}

	free(results);
	free(threads);
	free(args);
	mutex_destroy(&cursor_mtx);
	mutex_destroy(&print_mtx);
	mutex_destroy(&res_mtx);
	mutex_destroy(&progress_mtx);
	net_cleanup();
	return 0;
}
