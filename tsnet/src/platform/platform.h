/* Platform abstraction for libtsnet (platform_nx.c: Horizon OS via libnx).
 * Only the platform backend may touch OS-specific APIs outside the shim.
 */
#ifndef TSNET_PLATFORM_H
#define TSNET_PLATFORM_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h> /* ssize_t */

/* CA bundle used to verify TLS to the control server and DERP relays */
#define TSNET_CA_BUNDLE "romfs:/tailscale/cacert.pem"

/* Fill buf with cryptographically secure random bytes. Aborts the process
 * if no CSPRNG is available (never returns weak randomness). */
void tsnet_rand_bytes(void *buf, size_t len);

/* Wire up any platform prerequisites for libsodium *before* sodium_init().
 * On Switch libsodium's stock randombytes opens /dev/urandom, which does not
 * exist on Horizon, so sodium_init() would abort(); this registers a
 * libnx-CSPRNG-backed randombytes implementation instead. No-op on hosts that
 * have /dev/urandom. Call once, before tsnet_crypto_init()'s sodium_init(). */
void tsnet_plat_crypto_prepare(void);

/* Monotonic milliseconds since an arbitrary epoch. */
uint64_t tsnet_now_ms(void);

/* Raise the CALLING thread's scheduler priority for the latency-critical data
 * path (packet decrypt on the udp thread, delivery on the lwIP tcpip thread).
 * Without it these run at the default priority and are preempted by the
 * renderer, so arriving video packets and outbound input commands are serviced
 * late — video jitter + input lag with no packet loss. No-op off Horizon. */
void tsnet_plat_thread_boost(void);

/* Wall clock seconds since Unix epoch (for TLS cert validation, key expiry). */
int64_t tsnet_wall_time(void);

/* ---- real-stack TCP/UDP for the control plane and magicsock -----------
 * These always use the real network stack (libnx __real_*), bypassing the socket shim: tsnet's own transport must never
 * loop back into lwIP. All fds are real-stack fds.
 */

/* Resolve host and connect (TCP). Returns fd >= 0 or -1 (errno). */
int tsnet_plat_tcp_dial(const char *host, uint16_t port, int timeout_ms);
ssize_t tsnet_plat_sock_read(int fd, void *buf, size_t n);
ssize_t tsnet_plat_sock_write(int fd, const void *buf, size_t n);
int tsnet_plat_sock_close(int fd);
/* shutdown(SHUT_RDWR): unblocks a reader thread without freeing state */
int tsnet_plat_sock_shutdown(int fd);
/* 1 = readable, 0 = timeout, -1 = error */
int tsnet_plat_sock_wait_read(int fd, int timeout_ms);
/* set SO_RCVTIMEO/SO_SNDTIMEO */
int tsnet_plat_sock_set_timeout(int fd, int timeout_ms);

/* ---- real-stack UDP (magicsock transport) ------------------------------ */
struct tsnet_addr; /* shim/classify.h */

/* Open+bind a UDP socket on port (0 = kernel-chosen). Returns fd or -1. */
int tsnet_plat_udp_open(uint16_t port, uint16_t *bound_port_out);
ssize_t tsnet_plat_udp_sendto(int fd, const void *buf, size_t len,
                              const struct tsnet_addr *dst);
/* Blocking recv with timeout; returns len, 0 on timeout, -1 on error. */
ssize_t tsnet_plat_udp_recvfrom(int fd, void *buf, size_t cap,
                                struct tsnet_addr *src, int timeout_ms);
/* Resolve a hostname to an IPv4 tsnet_addr (port not set). */
int tsnet_plat_resolve4(const char *host, struct tsnet_addr *out);
/* Local IPv4 the OS would use to reach dst (UDP connect trick). */
int tsnet_plat_local_ip4(const struct tsnet_addr *dst,
                         struct tsnet_addr *out);

#endif
