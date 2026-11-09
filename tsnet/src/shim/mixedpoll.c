#include "mixedpoll.h"

#include "platform/platform.h"
#include "tsnet/tsnet.h"


#define MIXED_SLICE_MS 10
#define MP_MAX 64

static tsnet_poll_fn g_real_poll, g_lwip_poll;

void tsnet_mixedpoll_init(tsnet_poll_fn real_poll, tsnet_poll_fn lwip_poll) {
    g_real_poll = real_poll;
    g_lwip_poll = lwip_poll;
}

/* Copy one side's entries into a compact tsnet_pfd array. */
static int gather(const tsnet_mpent *ents, int n, int want_lwip,
                  tsnet_pfd *out, int *idx_map) {
    int m = 0;
    for (int i = 0; i < n; i++) {
        if (ents[i].is_lwip == want_lwip) {
            out[m].fd = ents[i].fd;
            out[m].events = ents[i].events;
            out[m].revents = 0;
            idx_map[m] = i;
            m++;
        }
    }
    return m;
}

static void scatter(tsnet_mpent *ents, const tsnet_pfd *pfds,
                    const int *idx_map, int m) {
    for (int i = 0; i < m; i++) ents[idx_map[i]].revents = pfds[i].revents;
}

static int count_hits(const tsnet_mpent *ents, int n) {
    int c = 0;
    for (int i = 0; i < n; i++)
        if (ents[i].revents) c++;
    return c;
}

int tsnet_mixed_poll(tsnet_mpent *ents, int n, int timeout_ms) {
    if (!g_real_poll || !g_lwip_poll) return TSNET_E_STATE;
    if (n < 0 || n > MP_MAX) return TSNET_E_INVAL;

    tsnet_pfd rp[MP_MAX], lp[MP_MAX];
    int rmap[MP_MAX], lmap[MP_MAX];
    for (int i = 0; i < n; i++) ents[i].revents = 0;
    int nr = gather(ents, n, 0, rp, rmap);
    int nl = gather(ents, n, 1, lp, lmap);

    /* common fast paths: one side only, full timeout delegation */
    if (nl == 0) {
        int rc = g_real_poll(rp, nr, timeout_ms);
        if (rc > 0) scatter(ents, rp, rmap, nr);
        return rc;
    }
    if (nr == 0) {
        int rc = g_lwip_poll(lp, nl, timeout_ms);
        if (rc > 0) scatter(ents, lp, lmap, nl);
        return rc;
    }

    /* mixed: alternate, lwIP non-blocking + real in short slices */
    uint64_t start = tsnet_now_ms();
    for (;;) {
        int rc = g_lwip_poll(lp, nl, 0);
        if (rc < 0) return rc;
        if (rc > 0) {
            scatter(ents, lp, lmap, nl);
            /* collect any real events too, without blocking */
            int rr = g_real_poll(rp, nr, 0);
            if (rr > 0) scatter(ents, rp, rmap, nr);
            return count_hits(ents, n);
        }

        int slice = MIXED_SLICE_MS;
        if (timeout_ms >= 0) {
            uint64_t elapsed = tsnet_now_ms() - start;
            if (elapsed >= (uint64_t)timeout_ms) {
                /* time is up: one last non-blocking real probe so that
                 * poll(..., 0) still checks both sides */
                rc = g_real_poll(rp, nr, 0);
                if (rc > 0) scatter(ents, rp, rmap, nr);
                return rc > 0 ? count_hits(ents, n) : rc;
            }
            uint64_t left = (uint64_t)timeout_ms - elapsed;
            if (left < MIXED_SLICE_MS) slice = (int)left;
        }
        rc = g_real_poll(rp, nr, slice);
        if (rc < 0) return rc;
        if (rc > 0) {
            scatter(ents, rp, rmap, nr);
            int rl = g_lwip_poll(lp, nl, 0);
            if (rl > 0) scatter(ents, lp, lmap, nl);
            return count_hits(ents, n);
        }
    }
}
