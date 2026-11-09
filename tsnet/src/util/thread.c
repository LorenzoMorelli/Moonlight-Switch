/* tsnet_thread_create — create a worker thread with an explicit large
 * stack. libnx's default pthread stack is small; mbedtls TLS handshakes and
 * our per-record buffers (h2 8 KB, Noise 4 KB, cstream 4 KB) live on the
 * stack, so the control/magicsock/DERP threads overflow the default and
 * fault on Horizon. 1 MB is generous and cheap (RAM budget is ~16 MB) and is
 * comfortably above any observed default, leaving margin for the deepest path
 * (TLS handshake + jansson netmap parse). */
#include "util/thread.h"

#define TSNET_THREAD_STACK (1024 * 1024)

int tsnet_thread_create(pthread_t *t, void *(*fn)(void *), void *arg) {
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0) return -1;
    pthread_attr_setstacksize(&attr, TSNET_THREAD_STACK);
    int rc = pthread_create(t, &attr, fn, arg);
    pthread_attr_destroy(&attr);
    return rc;
}
