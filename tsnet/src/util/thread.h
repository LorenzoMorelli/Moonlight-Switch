#ifndef TSNET_UTIL_THREAD_H
#define TSNET_UTIL_THREAD_H

#include <pthread.h>

/* Create a worker thread with an explicit large stack. The libnx pthread
 * default stack is too small for mbedtls TLS handshakes plus our on-stack
 * per-record buffers; the control/magicsock/DERP threads need the room.
 * Returns 0 on success (like pthread_create). */
int tsnet_thread_create(pthread_t *t, void *(*fn)(void *), void *arg);

#endif
