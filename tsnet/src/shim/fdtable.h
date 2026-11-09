#ifndef TSNET_SHIM_FDTABLE_H
#define TSNET_SHIM_FDTABLE_H

/* Virtual fd table with lazy backend binding: the
 * backend (real stack or lwIP) is chosen on first use by destination.
 *
 * Every socket created through the shim starts as a virtual fd in state
 * UNBOUND, recording family/type/protocol, socket options, bind address and
 * nonblocking mode. The first operation that reveals the destination
 * (connect, sendto, sendmsg) classifies it and materializes the socket on
 * the lwIP backend (tailnet) or the real backend (libnx), replaying the recorded state. Operations that imply local-only use
 * (listen, recvfrom, poll on an unbound socket) materialize according to
 * the recorded bind address (tailnet address -> lwIP, anything else,
 * wildcard and multicast included -> real).
 *
 * The core is portable and backend-agnostic: backends are injected as
 * vtables (lwip_* and libnx). The (level,
 * optname) pairs and (domain,type,protocol) triples pass through in the
 * *platform* representation; each backend adapter translates to its own
 * constants.
 */

#include "classify.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TSNET_VFD_MAX 64
#define TSNET_VFD_MAX_OPTS 16
#define TSNET_VFD_OPT_VAL_MAX 24

typedef enum tsnet_backend_kind {
    TSNET_BK_UNBOUND = 0,
    TSNET_BK_LWIP = 1,
    TSNET_BK_REAL = 2,
} tsnet_backend_kind;

typedef struct tsnet_sock_backend {
    /* All return >=0 (fd) or 0 on success, negative TSNET_E_* on failure. */
    int (*bk_socket)(int domain, int type, int protocol);
    int (*bk_bind)(int fd, const tsnet_addr *a);
    int (*bk_setsockopt)(int fd, int level, int optname, const void *val,
                         uint32_t len);
    int (*bk_nonblock)(int fd, bool nb);
    int (*bk_close)(int fd);
} tsnet_sock_backend;

void tsnet_fdtable_init(const tsnet_sock_backend *real,
                        const tsnet_sock_backend *lwip);
void tsnet_fdtable_reset(void); /* closes nothing; tests only */

/* Allocate a virtual fd. Returns index >= 0 or TSNET_E_NOMEM. */
int tsnet_vfd_open(int domain, int type, int protocol);

/* Close underlying socket (if materialized) and free the slot. */
int tsnet_vfd_close(int vfd);

bool tsnet_vfd_valid(int vfd);
tsnet_backend_kind tsnet_vfd_kind(int vfd);
/* Underlying backend fd; TSNET_E_STATE if not materialized. */
int tsnet_vfd_backend_fd(int vfd);
int tsnet_vfd_domain(int vfd);
int tsnet_vfd_type(int vfd);

/* Record (UNBOUND) or forward (materialized) state changes. */
int tsnet_vfd_bind(int vfd, const tsnet_addr *a);
int tsnet_vfd_setsockopt(int vfd, int level, int optname, const void *val,
                         uint32_t len);
int tsnet_vfd_set_nonblock(int vfd, bool nb);
bool tsnet_vfd_nonblock(int vfd);
/* Recorded bind address; false if none. */
bool tsnet_vfd_bound_addr(int vfd, tsnet_addr *out);

/* Materialization triggers. Both are no-ops when already materialized.
 * require_route: classify dst (connect/sendto path).
 * require_default: listen/recv/poll path — recorded bind address decides
 * (specific tailnet address -> lwIP, everything else -> real). */
int tsnet_vfd_require_route(int vfd, const tsnet_addr *dst);
int tsnet_vfd_require_default(int vfd);

/* Adopt an already-materialized backend fd (accept() results). */
int tsnet_vfd_adopt(tsnet_backend_kind kind, int backend_fd, int domain,
                    int type, int protocol);

#ifdef __cplusplus
}
#endif

#endif
