// Construccion de listas de puertos y rutinas de escaneo
#ifndef SCANNER_IP_H
#define SCANNER_IP_H

#include <stdint.h>
#include <stddef.h>

#include "config.h"
#include "network.h"

// Max port constant
#define MAX_PORT 65535

// Threading and mutex aux
#ifdef _WIN32
	#include <windows.h>
	typedef HANDLE thread_handle_t;
	typedef CRITICAL_SECTION mutex_t;
	static inline void mutex_init(mutex_t *m) { InitializeCriticalSection(m); }
	static inline void mutex_lock(mutex_t *m) { EnterCriticalSection(m); }
	static inline void mutex_unlock(mutex_t *m) { LeaveCriticalSection(m); }
	static inline void mutex_destroy(mutex_t *m) { DeleteCriticalSection(m); }
#else
	#include <pthread.h>
	typedef pthread_t thread_handle_t;
	typedef pthread_mutex_t mutex_t;
	static inline void mutex_init(mutex_t *m) { pthread_mutex_init(m, NULL); }
	static inline void mutex_lock(mutex_t *m) { pthread_mutex_lock(m); }
	static inline void mutex_unlock(mutex_t *m) { pthread_mutex_unlock(m); }
	static inline void mutex_destroy(mutex_t *m) { pthread_mutex_destroy(m); }
#endif

typedef enum {
	SCAN_TCP_CONNECT,
	SCAN_TCP_SYN,
	SCAN_UDP
} ScanMode;

typedef struct {
	uint16_t *ports;
	size_t count;
} PortList;

int scanner_build_default_ports(PortList *list);
void scanner_free_ports(PortList *list);

// Escanea una lista de puertos con el modo indicado y muestra resultados basicos.
int scanner_run(const char *host, const PortList *list, ScanMode mode, const AppConfig *cfg);

#endif // SCANNER_IP_H
