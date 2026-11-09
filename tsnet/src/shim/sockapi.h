#ifndef TSNET_SHIM_SOCKAPI_H
#define TSNET_SHIM_SOCKAPI_H

/* Neutral socket-API surface between the platform shim and the lwIP
 * backend adapter.
 *
 * The platform side (shim_nx.c with newlib/libnx headers) and the lwIP side (lwip_adapter.c with
 * lwip/sockets.h) can NOT share a translation unit: their socket headers
 * define conflicting types and constants. Everything crossing the border
 * uses tsnet_addr and the TSNET_* constants below; each side translates
 * to its own representation.
 *
 * Error convention for data-path calls: like libc, >= 0 on success, -1
 * with errno set (lwIP is configured with LWIP_ERRNO_STDINCLUDE so it
 * already sets the platform errno).
 */

#include "classify.h"
#include "fdtable.h"
#include "mixedpoll.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* poll events (values match BSD/newlib for convenience; lwIP side maps) */
#define TSNET_POLLIN   0x0001
#define TSNET_POLLPRI  0x0002
#define TSNET_POLLOUT  0x0004
#define TSNET_POLLERR  0x0008
#define TSNET_POLLHUP  0x0010
#define TSNET_POLLNVAL 0x0020

/* msg flags */
#define TSNET_MSG_PEEK     0x01
#define TSNET_MSG_DONTWAIT 0x02
#define TSNET_MSG_WAITALL  0x04
#define TSNET_MSG_TRUNC    0x08

/* shutdown */
#define TSNET_SHUT_RD 0
#define TSNET_SHUT_WR 1
#define TSNET_SHUT_RDWR 2

/* socket types/domains for bk_socket (neutral) */
#define TSNET_AF_INET 4
#define TSNET_AF_INET6 6
#define TSNET_SOCK_STREAM 1
#define TSNET_SOCK_DGRAM 2

/* setsockopt/getsockopt: neutral (level, name) ids understood by the lwIP
 * adapter; the platform side maps its constants to these. Anything not
 * listed is best-effort accepted and ignored. */
enum tsnet_sockopt {
    TSNET_SO_UNSUPPORTED = 0,
    TSNET_SO_REUSEADDR,
    TSNET_SO_KEEPALIVE,
    TSNET_SO_BROADCAST,
    TSNET_SO_LINGER,
    TSNET_SO_RCVBUF,
    TSNET_SO_SNDTIMEO,
    TSNET_SO_RCVTIMEO,
    TSNET_SO_ERROR,
    TSNET_TCP_NODELAY,
    TSNET_TCP_KEEPALIVE_ON, /* SO_KEEPALIVE on IPPROTO_TCP level variants */
};

/* ---- lwIP backend adapter (implemented in lwip_adapter.c) ------------- */

/* vtable for the fd table (socket/bind/setsockopt/nonblock/close),
 * registered via tsnet_fdtable_init(). bk_socket takes the NEUTRAL
 * domain/type (TSNET_AF_*, TSNET_SOCK_*). bk_setsockopt takes a neutral
 * enum tsnet_sockopt in `optname` and ignores `level`. */
extern const tsnet_sock_backend tsnet_lwip_backend;

int tsnet_lwip_adapter_connect(int fd, const tsnet_addr *dst);
ssize_t tsnet_lwip_adapter_send(int fd, const void *buf, size_t len, int tflags);
ssize_t tsnet_lwip_adapter_sendto(int fd, const void *buf, size_t len,
                                  int tflags, const tsnet_addr *dst);
ssize_t tsnet_lwip_adapter_recv(int fd, void *buf, size_t len, int tflags);
ssize_t tsnet_lwip_adapter_recvfrom(int fd, void *buf, size_t len, int tflags,
                                    tsnet_addr *src /* nullable */);
ssize_t tsnet_lwip_adapter_read(int fd, void *buf, size_t len);
ssize_t tsnet_lwip_adapter_write(int fd, const void *buf, size_t len);
int tsnet_lwip_adapter_listen(int fd, int backlog);
/* returns new lwIP fd, fills src */
int tsnet_lwip_adapter_accept(int fd, tsnet_addr *src /* nullable */);
int tsnet_lwip_adapter_shutdown(int fd, int how /* TSNET_SHUT_* */);
int tsnet_lwip_adapter_getsockname(int fd, tsnet_addr *out);
int tsnet_lwip_adapter_getpeername(int fd, tsnet_addr *out);
/* neutral option get; only TSNET_SO_ERROR/TSNET_SO_RCVBUF supported */
int tsnet_lwip_adapter_getsockopt(int fd, int topt, void *val, uint32_t *len);
/* poll with TSNET_POLL* bits in events/revents */
int tsnet_lwip_adapter_poll(tsnet_pfd *fds, int n, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif
