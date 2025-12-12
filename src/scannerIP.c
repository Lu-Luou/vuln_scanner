#include "scannerIP.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint16_t popular_ports[] = {3306, 8080, 5432, 6379, 27017, 11211, 9200};
static const size_t popular_count = sizeof(popular_ports) / sizeof(popular_ports[0]);

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

	// Reservar un buffer razonable: 1024 + (9 * populares)
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

static NetPortState scan_port(const char *host, uint16_t port, ScanMode mode, int timeout_ms, int verbose) {
	switch (mode) {
		case SCAN_TCP_CONNECT:
			return net_scan_tcp_connect(host, port, timeout_ms);
		case SCAN_TCP_SYN:
			if (verbose) {
				printf("[!] TCP SYN no implementado (requiere raw sockets)\n");
			}
			return NET_PORT_ERROR;
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
	mutex_t *print_mtx; // not used after refactor, kept for compatibility

	// resultados compartidos
	struct PrintedResult *results;
	size_t *res_count;
	mutex_t *res_mtx;

	// progreso
	size_t *processed;
	size_t *next_progress;
	mutex_t *progress_mtx;
	size_t total_ports;
} WorkerArgs;

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
		NetPortState st = scan_port(w->host, port, w->mode, w->timeout_ms, w->cfg->verbose);
		int should_store = 0;
		if (st == NET_PORT_OPEN || st == NET_PORT_CLOSED || st == NET_PORT_ERROR) {
			should_store = 1; // siempre guardamos abiertos/cerrados/error
		} else if (w->cfg->verbose > 1 && st == NET_PORT_FILTERED) {
			should_store = 1; // filtrados solo si verbose
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
			mutex_lock(w->print_mtx);
			printf("[progreso] %zu/%zu puertos escaneados\n", processed_now, w->total_ports);
			mutex_unlock(w->print_mtx);
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

	int timeout_ms = 800; // timeout moderado
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

	// elegir cantidad de hilos (max 32 o cantidad de puertos si es menor)
	size_t worker_count = list->count < 32 ? list->count : 32;
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
	}

	for (size_t i = 0; i < worker_count; ++i) {
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
	WaitForMultipleObjects((DWORD)worker_count, threads, TRUE, INFINITE);
	for (size_t i = 0; i < worker_count; ++i) {
		CloseHandle(threads[i]);
	}
#else
	for (size_t i = 0; i < worker_count; ++i) {
		pthread_join(threads[i], NULL);
	}
#endif

	// ordenar y emitir resultados para registro ordenado por puerto
	if (res_count > 1) {
		qsort(results, res_count, sizeof(PrintedResult), cmp_port);
	}

	for (size_t i = 0; i < res_count; ++i) {
		const PrintedResult *pr = &results[i];
		if (pr->state == NET_PORT_FILTERED) {
			continue; // no imprimir filtrados en el resumen final
		}
		const char *proto = (pr->mode == SCAN_UDP) ? "udp" : "tcp";
		if (pr->banner_len > 0) {
			printf("[%5u/%s] %s | banner: %s\n", pr->port, proto, state_to_str(pr->state), pr->banner);
		} else {
			printf("[%5u/%s] %s\n", pr->port, proto, state_to_str(pr->state));
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
