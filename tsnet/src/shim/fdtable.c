#include "fdtable.h"

#include "tsnet/tsnet.h"
#include "util/log.h"

#include <pthread.h>
#include <string.h>

typedef struct vfd_entry {
    bool in_use;
    tsnet_backend_kind kind;
    int backend_fd;
    int domain, type, protocol;
    bool nonblock;
    bool has_bind;
    /* kind was chosen by require_default (no destination known), so a later
     * destination may still re-home a datagram socket (see require_route) */
    bool kind_by_default;
    /* real fd left behind by a REAL->LWIP re-home; closed with the vfd */
    int shadow_real_fd;
    tsnet_addr bind_addr;
    int n_opts;
    struct {
        int level, optname;
        uint32_t len;
        uint8_t val[TSNET_VFD_OPT_VAL_MAX];
    } opts[TSNET_VFD_MAX_OPTS];
} vfd_entry;

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static vfd_entry g_tab[TSNET_VFD_MAX];
static tsnet_sock_backend g_real, g_lwip;
static bool g_inited;

void tsnet_fdtable_init(const tsnet_sock_backend *real,
                        const tsnet_sock_backend *lwip) {
    pthread_mutex_lock(&g_mu);
    g_real = *real;
    g_lwip = *lwip;
    g_inited = true;
    pthread_mutex_unlock(&g_mu);
}

void tsnet_fdtable_reset(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_tab, 0, sizeof(g_tab));
    pthread_mutex_unlock(&g_mu);
}

static vfd_entry *get(int vfd) {
    if (vfd < 0 || vfd >= TSNET_VFD_MAX || !g_tab[vfd].in_use) return NULL;
    return &g_tab[vfd];
}

int tsnet_vfd_open(int domain, int type, int protocol) {
    pthread_mutex_lock(&g_mu);
    if (!g_inited) {
        pthread_mutex_unlock(&g_mu);
        return TSNET_E_STATE;
    }
    for (int i = 0; i < TSNET_VFD_MAX; i++) {
        if (!g_tab[i].in_use) {
            memset(&g_tab[i], 0, sizeof(g_tab[i]));
            g_tab[i].in_use = true;
            g_tab[i].kind = TSNET_BK_UNBOUND;
            g_tab[i].backend_fd = -1;
            g_tab[i].shadow_real_fd = -1;
            g_tab[i].domain = domain;
            g_tab[i].type = type;
            g_tab[i].protocol = protocol;
            pthread_mutex_unlock(&g_mu);
            return i;
        }
    }
    pthread_mutex_unlock(&g_mu);
    TSNET_LOGE("fdtable: out of virtual fds");
    return TSNET_E_NOMEM;
}

static const tsnet_sock_backend *bk_of(tsnet_backend_kind k) {
    return k == TSNET_BK_LWIP ? &g_lwip : &g_real;
}

int tsnet_vfd_close(int vfd) {
    pthread_mutex_lock(&g_mu);
    vfd_entry *e = get(vfd);
    if (!e) {
        pthread_mutex_unlock(&g_mu);
        return TSNET_E_INVAL;
    }
    int rc = TSNET_OK;
    if (e->kind != TSNET_BK_UNBOUND)
        rc = bk_of(e->kind)->bk_close(e->backend_fd);
    if (e->shadow_real_fd >= 0) g_real.bk_close(e->shadow_real_fd);
    e->in_use = false;
    pthread_mutex_unlock(&g_mu);
    return rc;
}

bool tsnet_vfd_valid(int vfd) {
    pthread_mutex_lock(&g_mu);
    bool ok = get(vfd) != NULL;
    pthread_mutex_unlock(&g_mu);
    return ok;
}

tsnet_backend_kind tsnet_vfd_kind(int vfd) {
    pthread_mutex_lock(&g_mu);
    vfd_entry *e = get(vfd);
    tsnet_backend_kind k = e ? e->kind : TSNET_BK_UNBOUND;
    pthread_mutex_unlock(&g_mu);
    return k;
}

int tsnet_vfd_backend_fd(int vfd) {
    pthread_mutex_lock(&g_mu);
    vfd_entry *e = get(vfd);
    int fd = (e && e->kind != TSNET_BK_UNBOUND) ? e->backend_fd
                                                : TSNET_E_STATE;
    pthread_mutex_unlock(&g_mu);
    return fd;
}

int tsnet_vfd_domain(int vfd) {
    pthread_mutex_lock(&g_mu);
    vfd_entry *e = get(vfd);
    int d = e ? e->domain : TSNET_E_INVAL;
    pthread_mutex_unlock(&g_mu);
    return d;
}

int tsnet_vfd_type(int vfd) {
    pthread_mutex_lock(&g_mu);
    vfd_entry *e = get(vfd);
    int t = e ? e->type : TSNET_E_INVAL;
    pthread_mutex_unlock(&g_mu);
    return t;
}

int tsnet_vfd_bind(int vfd, const tsnet_addr *a) {
    pthread_mutex_lock(&g_mu);
    vfd_entry *e = get(vfd);
    if (!e) {
        pthread_mutex_unlock(&g_mu);
        return TSNET_E_INVAL;
    }
    if (e->kind != TSNET_BK_UNBOUND) {
        const tsnet_sock_backend *bk = bk_of(e->kind);
        int fd = e->backend_fd;
        pthread_mutex_unlock(&g_mu);
        return bk->bk_bind(fd, a);
    }
    e->has_bind = true;
    e->bind_addr = *a;
    pthread_mutex_unlock(&g_mu);
    return TSNET_OK;
}

int tsnet_vfd_setsockopt(int vfd, int level, int optname, const void *val,
                         uint32_t len) {
    pthread_mutex_lock(&g_mu);
    vfd_entry *e = get(vfd);
    if (!e) {
        pthread_mutex_unlock(&g_mu);
        return TSNET_E_INVAL;
    }
    /* Record first (a datagram socket materialized by default may still be
     * re-homed, and the replay must include options set after the first
     * materialization), then apply to the current backend if any. */
    bool recorded = false;
    if (len <= TSNET_VFD_OPT_VAL_MAX) {
        /* overwrite an earlier recording of the same option */
        int slot = e->n_opts;
        for (int i = 0; i < e->n_opts; i++) {
            if (e->opts[i].level == level && e->opts[i].optname == optname) {
                slot = i;
                break;
            }
        }
        if (slot < TSNET_VFD_MAX_OPTS) {
            if (slot == e->n_opts) e->n_opts++;
            e->opts[slot].level = level;
            e->opts[slot].optname = optname;
            e->opts[slot].len = len;
            memcpy(e->opts[slot].val, val, len);
            recorded = true;
        }
    }
    if (e->kind != TSNET_BK_UNBOUND) {
        const tsnet_sock_backend *bk = bk_of(e->kind);
        int fd = e->backend_fd;
        pthread_mutex_unlock(&g_mu);
        return bk->bk_setsockopt(fd, level, optname, val, len);
    }
    int n_opts = e->n_opts;
    pthread_mutex_unlock(&g_mu);
    if (!recorded)
        TSNET_LOGW("fdtable: setsockopt(%d) not recorded (len %u / %d opts), "
                   "dropped", optname, len, n_opts);
    return TSNET_OK; /* best effort, like unsupported lwIP options */
}

int tsnet_vfd_set_nonblock(int vfd, bool nb) {
    pthread_mutex_lock(&g_mu);
    vfd_entry *e = get(vfd);
    if (!e) {
        pthread_mutex_unlock(&g_mu);
        return TSNET_E_INVAL;
    }
    e->nonblock = nb;
    if (e->kind != TSNET_BK_UNBOUND) {
        const tsnet_sock_backend *bk = bk_of(e->kind);
        int fd = e->backend_fd;
        pthread_mutex_unlock(&g_mu);
        return bk->bk_nonblock(fd, nb);
    }
    pthread_mutex_unlock(&g_mu);
    return TSNET_OK;
}

bool tsnet_vfd_nonblock(int vfd) {
    pthread_mutex_lock(&g_mu);
    vfd_entry *e = get(vfd);
    bool nb = e ? e->nonblock : false;
    pthread_mutex_unlock(&g_mu);
    return nb;
}

bool tsnet_vfd_bound_addr(int vfd, tsnet_addr *out) {
    pthread_mutex_lock(&g_mu);
    vfd_entry *e = get(vfd);
    bool ok = e && e->has_bind;
    if (ok) *out = e->bind_addr;
    pthread_mutex_unlock(&g_mu);
    return ok;
}

/* Datagram socket? type carries platform flag bits (SOCK_NONBLOCK/CLOEXEC)
 * above the low byte on every supported libc; SOCK_DGRAM is 2 everywhere. */
static bool is_dgram(const vfd_entry *e) {
    return (e->type & 0xff) == 2 || e->protocol == 17 /* IPPROTO_UDP */;
}

/* caller holds g_mu */
static int materialize_locked(vfd_entry *e, tsnet_backend_kind kind) {
    const tsnet_sock_backend *bk = bk_of(kind);
    int fd = bk->bk_socket(e->domain, e->type, e->protocol);
    if (fd < 0) {
        TSNET_LOGE("fdtable: backend socket() failed (%d)", fd);
        return fd;
    }
    for (int i = 0; i < e->n_opts; i++) {
        int rc = bk->bk_setsockopt(fd, e->opts[i].level, e->opts[i].optname,
                                   e->opts[i].val, e->opts[i].len);
        if (rc < 0)
            TSNET_LOGD("fdtable: replay setsockopt(%d,%d) -> %d (ignored)",
                       e->opts[i].level, e->opts[i].optname, rc);
    }
    if (e->has_bind) {
        int rc = bk->bk_bind(fd, &e->bind_addr);
        if (rc < 0) {
            TSNET_LOGE("fdtable: replay bind failed (%d)", rc);
            bk->bk_close(fd);
            return rc;
        }
    }
    if (e->nonblock) bk->bk_nonblock(fd, true);
    e->kind = kind;
    e->backend_fd = fd;
    return TSNET_OK;
}

int tsnet_vfd_require_route(int vfd, const tsnet_addr *dst) {
    pthread_mutex_lock(&g_mu);
    vfd_entry *e = get(vfd);
    if (!e) {
        pthread_mutex_unlock(&g_mu);
        return TSNET_E_INVAL;
    }
    tsnet_route route = tsnet_classify(dst);
    tsnet_backend_kind want =
        route == TSNET_ROUTE_TUNNEL ? TSNET_BK_LWIP : TSNET_BK_REAL;
    if (e->kind == want) {
        pthread_mutex_unlock(&g_mu);
        return TSNET_OK;
    }
    if (e->kind == TSNET_BK_UNBOUND) {
        e->kind_by_default = false;
        int rc = materialize_locked(e, want);
        pthread_mutex_unlock(&g_mu);
        return rc;
    }
    /* Materialized on the real stack by a receiver (require_default with a
     * wildcard/no bind) and the first destination is a tailnet peer: re-home
     * the datagram socket onto lwIP. moonlight-common-c does exactly this for
     * video: the receive thread blocks in recvfrom() before the ping thread's
     * first sendto(), and the server only streams to the ping's source. The
     * real fd is kept (not closed) until the vfd closes so a receiver still
     * blocked in it drains through its own timeout and then follows the
     * table to the new backend on its next call. Stream sockets and sockets
     * bound to a specific address keep their first kind. */
    if (e->kind == TSNET_BK_REAL && want == TSNET_BK_LWIP &&
        e->kind_by_default && is_dgram(e) && e->shadow_real_fd < 0) {
        int old_fd = e->backend_fd;
        int rc = materialize_locked(e, TSNET_BK_LWIP);
        if (rc == TSNET_OK) {
            e->shadow_real_fd = old_fd;
            e->kind_by_default = false;
            TSNET_LOGI("fdtable: vfd %d re-homed real->tunnel for dst "
                       "%u.%u.%u.%u:%u (real fd %d parked)",
                       vfd, dst->ip[0], dst->ip[1], dst->ip[2], dst->ip[3],
                       dst->port, old_fd);
        } else {
            TSNET_LOGW("fdtable: vfd %d re-home real->tunnel failed (%d), "
                       "staying real", vfd, rc);
        }
        pthread_mutex_unlock(&g_mu);
        return TSNET_OK;
    }
    TSNET_LOGW("fdtable: vfd %d already %s but dst classifies %s", vfd,
               e->kind == TSNET_BK_LWIP ? "tunnel" : "real",
               want == TSNET_BK_LWIP ? "tunnel" : "real");
    pthread_mutex_unlock(&g_mu);
    return TSNET_OK;
}

int tsnet_vfd_require_default(int vfd) {
    pthread_mutex_lock(&g_mu);
    vfd_entry *e = get(vfd);
    if (!e) {
        pthread_mutex_unlock(&g_mu);
        return TSNET_E_INVAL;
    }
    if (e->kind != TSNET_BK_UNBOUND) {
        pthread_mutex_unlock(&g_mu);
        return TSNET_OK;
    }
    /* Listener/receiver with no destination: a specific tailnet bind address
     * selects the tunnel; wildcard, multicast and LAN addresses (mDNS, WoL)
     * select the real stack. */
    tsnet_backend_kind want = TSNET_BK_REAL;
    if (e->has_bind && !tsnet_addr_is_wildcard(&e->bind_addr) &&
        !tsnet_addr_is_multicast_or_broadcast(&e->bind_addr)) {
        tsnet_addr a = e->bind_addr;
        if (tsnet_addr_in_tailnet_ranges(&a) || tsnet_registry_contains(&a))
            want = TSNET_BK_LWIP;
    }
    int rc = materialize_locked(e, want);
    /* only a wildcard/unbound datagram receiver may be re-homed later; a
     * socket bound to a specific (LAN) address expressed a real choice */
    if (rc == TSNET_OK)
        e->kind_by_default =
            !e->has_bind || tsnet_addr_is_wildcard(&e->bind_addr);
    pthread_mutex_unlock(&g_mu);
    return rc;
}

int tsnet_vfd_adopt(tsnet_backend_kind kind, int backend_fd, int domain,
                    int type, int protocol) {
    if (kind == TSNET_BK_UNBOUND || backend_fd < 0) return TSNET_E_INVAL;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < TSNET_VFD_MAX; i++) {
        if (!g_tab[i].in_use) {
            memset(&g_tab[i], 0, sizeof(g_tab[i]));
            g_tab[i].in_use = true;
            g_tab[i].kind = kind;
            g_tab[i].backend_fd = backend_fd;
            g_tab[i].shadow_real_fd = -1;
            g_tab[i].domain = domain;
            g_tab[i].type = type;
            g_tab[i].protocol = protocol;
            pthread_mutex_unlock(&g_mu);
            return i;
        }
    }
    pthread_mutex_unlock(&g_mu);
    return TSNET_E_NOMEM;
}
