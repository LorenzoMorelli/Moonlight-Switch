#ifndef TSNET_SHIM_MIXEDPOLL_H
#define TSNET_SHIM_MIXEDPOLL_H

/* poll() over a mixed set of real-stack and lwIP fds.
 *
 * Common cases (all real / all lwIP) delegate directly with the full
 * timeout. The mixed case alternates: lwIP poll with timeout 0, real poll
 * with the remaining timeout in slices of <= 10 ms, returning as soon as
 * either side reports events.
 *
 * The poll primitives (libnx poll and lwip_poll) are injected. Events use
 * the platform's POLL* bit values (backends translate if theirs differ).
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tsnet_pfd {
    int fd;        /* backend fd */
    short events;
    short revents;
} tsnet_pfd;

/* returns number of fds with events, 0 on timeout, negative TSNET_E_* */
typedef int (*tsnet_poll_fn)(tsnet_pfd *fds, int n, int timeout_ms);

typedef struct tsnet_mpent {
    int is_lwip;   /* 0 = real stack, 1 = lwIP */
    int fd;        /* backend fd */
    short events;
    short revents; /* out */
} tsnet_mpent;

void tsnet_mixedpoll_init(tsnet_poll_fn real_poll, tsnet_poll_fn lwip_poll);

/* timeout_ms < 0 means infinite, like poll(2). */
int tsnet_mixed_poll(tsnet_mpent *ents, int n, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif
