#include "magicsock.h"

#include "crypto/tscrypto.h"
#include "derp/derp_client.h"
#include "disco/disco.h"
#include "disco/stun.h"
#include "platform/platform.h"
#include "tsnet/tsnet.h"
#include "util/log.h"
#include "util/thread.h"
#include "wg/tsnet_wgif.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define MS_MAX_DERP_CONNS 4
#define MS_DEFAULT_PORT 41641
/* path policy */
#define MS_DIRECT_TRUST_MS 15000  /* direct while a pong is fresher than this */
#define MS_PING_INTERVAL_MS 5000  /* discovery ping cadence without a path */
/* Maintenance pings must land INSIDE the trust window or the direct path
 * expires between pings and flaps direct->derp->direct; 10s keeps it
 * continuously fresh against the 15s pong trust. */
#define MS_KEEP_INTERVAL_MS 10000
#define MS_STUN_INTERVAL_MS 30000
#define MS_TRAFFIC_ACTIVE_MS 30000 /* discovery only for recently used peers */
#define MS_PERIODIC_INTERVAL_MS 1000 /* run keepalive/STUN/discover at ~1 Hz */
#define MS_DERP_BACKOFF_MIN_MS 1000  /* DERP redial backoff after a failure */
#define MS_DERP_BACKOFF_MAX_MS 30000

struct ms_peer {
    bool valid;
    uint8_t node_key[32];
    uint8_t disco_key[32];
    bool has_disco;
    int home_derp;   /* peer's DERP region from the netmap (can be stale) */
    int derp_route;  /* DERP region we last received from this peer on;
                      * preferred over home_derp, which can be stale */
    /* candidate endpoints: netmap + CallMeMaybe + observed sources */
    tsnet_addr eps[TSNET_MAX_ENDPOINTS];
    int n_eps;
    /* direct path state */
    tsnet_addr best;
    uint64_t best_pong_ms;
    uint64_t last_ping_ms;
    uint64_t last_traffic_ms;
    uint8_t txid[TSNET_DISCO_TXID_LEN]; /* current discovery round */
};

static struct {
    bool up;
    bool derp_only;
    volatile int stopping;
    uint8_t node_priv[32], node_pub[32];
    uint8_t disco_priv[32], disco_pub[32];
    char ca_file[256];

    int udp_fd;
    uint16_t udp_port;
    pthread_t udp_thread;
    bool udp_thread_up;
    pthread_t maint_thread; /* periodic maintenance, kept off the rx thread */
    bool maint_thread_up;

    pthread_mutex_t mu; /* guards peers, derpmap, endpoints, home_derp */
    struct ms_peer peers[TSNET_MAX_PEERS];
    int n_peers;
    tsnet_derpmap derpmap;
    int home_derp;

    /* DERP connections have their OWN mutex, never held together with g.mu.
     * Dials happen only on the udp thread; sends hold derp_mu for the whole
     * tsnet_derp_send (no use-after-free); the DERP reader only ever takes
     * g.mu, so a close (which joins the reader) under derp_mu cannot
     * deadlock against it. want_region[] lets send paths request a region
     * without dialing inline (no blocking dial off the udp thread — critical
     * for the lwIP tcpip thread). */
    pthread_mutex_t derp_mu;
    struct {
        tsnet_derp *conn;
        int region_id;
    } conns[MS_MAX_DERP_CONNS];
    int want_region[MS_MAX_DERP_CONNS];
    int n_want;
    /* per-region redial backoff so a persistently unreachable region (e.g.
     * ENETUNREACH on the home DERP) is not hammered every loop pass. Only
     * touched on the udp thread. */
    struct {
        int region;
        uint64_t next_ms;
        int backoff_ms;
    } derp_bo[MS_MAX_DERP_CONNS * 2];

    /* our endpoints (STUN public + local), published via control */
    uint8_t stun_txid[TSNET_STUN_TXID_LEN];
    uint64_t last_stun_ms;
    char endpoints[4][64];
    int n_endpoints;
    void (*endpoints_cb)(const char **eps, int n, void *ud);
    void *endpoints_ud;
} g;

/* ---- helpers -------------------------------------------------------------- */

static struct ms_peer *peer_by_node_locked(const uint8_t node_key[32]) {
    for (int i = 0; i < g.n_peers; i++)
        if (g.peers[i].valid &&
            memcmp(g.peers[i].node_key, node_key, 32) == 0)
            return &g.peers[i];
    return NULL;
}

static struct ms_peer *peer_by_disco_locked(const uint8_t disco_key[32]) {
    for (int i = 0; i < g.n_peers; i++)
        if (g.peers[i].valid && g.peers[i].has_disco &&
            memcmp(g.peers[i].disco_key, disco_key, 32) == 0)
            return &g.peers[i];
    return NULL;
}

static void peer_add_ep_locked(struct ms_peer *p, const tsnet_addr *a) {
    if (a->family != 4 || a->port == 0) return; /* v4 magicsock for now */
    for (int i = 0; i < p->n_eps; i++) {
        if (tsnet_addr_eq_ip(&p->eps[i], a) && p->eps[i].port == a->port)
            return;
    }
    if (p->n_eps < TSNET_MAX_ENDPOINTS) {
        p->eps[p->n_eps++] = *a;
    } else {
        /* full: drop the oldest (FIFO) so a symmetric-NAT peer's stale
         * source ports age out and a new network's endpoint gets a chance */
        memmove(&p->eps[0], &p->eps[1],
                (TSNET_MAX_ENDPOINTS - 1) * sizeof(p->eps[0]));
        p->eps[TSNET_MAX_ENDPOINTS - 1] = *a;
    }
}

static const tsnet_derp_region *find_region_locked(int id) {
    for (int i = 0; i < g.derpmap.n_regions; i++)
        if (g.derpmap.regions[i].id == id) return &g.derpmap.regions[i];
    return NULL;
}

static void derp_recv(const uint8_t src_key[32], const uint8_t *pkt,
                      size_t len, void *ud);
static void derp_state(bool con_up, void *ud);

/* Queue a region to be connected by the udp thread (caller holds neither
 * lock). Non-blocking: never dials inline. */
static void derp_request_region(int region_id) {
    if (region_id == 0) return;
    pthread_mutex_lock(&g.derp_mu);
    for (int i = 0; i < g.n_want; i++)
        if (g.want_region[i] == region_id) {
            pthread_mutex_unlock(&g.derp_mu);
            return;
        }
    if (g.n_want < MS_MAX_DERP_CONNS) g.want_region[g.n_want++] = region_id;
    pthread_mutex_unlock(&g.derp_mu);
}

/* Send via an existing DERP connection for region, holding derp_mu for the
 * whole send so the connection cannot be freed concurrently. If none exists
 * yet, request one and drop the packet (WireGuard/disco retransmit): dialing
 * inline would block the caller, which may be the lwIP tcpip thread. */
static void derp_send_to(int region, const uint8_t dst_key[32],
                         const uint8_t *pkt, size_t len) {
    if (region == 0) return;
    pthread_mutex_lock(&g.derp_mu);
    tsnet_derp *d = NULL;
    int slot = -1;
    for (int i = 0; i < MS_MAX_DERP_CONNS; i++)
        if (g.conns[i].conn && g.conns[i].region_id == region &&
            !tsnet_derp_dead(g.conns[i].conn)) {
            d = g.conns[i].conn;
            slot = i;
            break;
        }
    if (d) {
        int rc = tsnet_derp_send(d, dst_key, pkt, len);
        if (rc != TSNET_OK) {
            /* dead connection: close it here (we hold derp_mu, the reader
             * only takes g.mu, so join cannot deadlock) and re-request */
            tsnet_derp_close(d);
            g.conns[slot].conn = NULL;
            pthread_mutex_unlock(&g.derp_mu);
            TSNET_LOGI("magicsock: DERP tx via region %d failed, reconnecting",
                       region);
            derp_request_region(region);
            return;
        }
        /* DEBUG, not INFO: this fires per data packet. At video rate the
         * synchronous fflush-to-SD in the logger (util/log.c) would stall the
         * tcpip thread and collapse throughput. */
        TSNET_LOGD("magicsock: DERP tx %zu bytes via region %d to "
                   "%02x%02x%02x%02x.. (%s)",
                   len, region, dst_key[0], dst_key[1], dst_key[2], dst_key[3],
                   tsnet_disco_looks(pkt, len) ? "disco" : "wg");
    }
    pthread_mutex_unlock(&g.derp_mu);
    if (!d) {
        TSNET_LOGI("magicsock: WG/disco -> region %d dropped (no DERP conn "
                   "yet), requesting", region);
        derp_request_region(region);
    }
}

/* Per-region DERP redial backoff. udp-thread only, no lock needed. */
static bool derp_bo_blocked(int region, uint64_t now) {
    for (unsigned i = 0; i < sizeof(g.derp_bo) / sizeof(g.derp_bo[0]); i++)
        if (g.derp_bo[i].region == region)
            return now < g.derp_bo[i].next_ms;
    return false;
}

static void derp_bo_fail(int region, uint64_t now) {
    int free_slot = -1;
    for (unsigned i = 0; i < sizeof(g.derp_bo) / sizeof(g.derp_bo[0]); i++) {
        if (g.derp_bo[i].region == region) {
            int bo = g.derp_bo[i].backoff_ms * 2;
            if (bo > MS_DERP_BACKOFF_MAX_MS) bo = MS_DERP_BACKOFF_MAX_MS;
            g.derp_bo[i].backoff_ms = bo;
            g.derp_bo[i].next_ms = now + (uint64_t)bo;
            return;
        }
        if (free_slot < 0 && g.derp_bo[i].region == 0) free_slot = (int)i;
    }
    if (free_slot < 0) free_slot = 0; /* evict slot 0 if the table is full */
    g.derp_bo[free_slot].region = region;
    g.derp_bo[free_slot].backoff_ms = MS_DERP_BACKOFF_MIN_MS;
    g.derp_bo[free_slot].next_ms = now + MS_DERP_BACKOFF_MIN_MS;
}

static void derp_bo_ok(int region) {
    for (unsigned i = 0; i < sizeof(g.derp_bo) / sizeof(g.derp_bo[0]); i++)
        if (g.derp_bo[i].region == region) {
            g.derp_bo[i].region = 0;
            g.derp_bo[i].next_ms = 0;
            g.derp_bo[i].backoff_ms = 0;
            return;
        }
}

/* Establish/refresh DERP connections for the home region + any requested
 * regions. Runs ONLY on the udp thread; dials are blocking here (safe) and
 * happen under derp_mu. Also reaps connections whose reader has exited. */
static void derp_ensure_connections(void) {
    int home;
    pthread_mutex_lock(&g.mu);
    home = g.home_derp;
    pthread_mutex_unlock(&g.mu);

    /* reap connections whose reader thread has exited (server restart /
     * TCP close) so their regions get re-dialed below. Close outside
     * derp_mu. */
    for (;;) {
        tsnet_derp *dead = NULL;
        int dead_region = 0;
        pthread_mutex_lock(&g.derp_mu);
        for (int i = 0; i < MS_MAX_DERP_CONNS; i++) {
            if (g.conns[i].conn && tsnet_derp_dead(g.conns[i].conn)) {
                dead = g.conns[i].conn;
                dead_region = g.conns[i].region_id;
                g.conns[i].conn = NULL;
                break;
            }
        }
        pthread_mutex_unlock(&g.derp_mu);
        if (!dead) break;
        tsnet_derp_close(dead);
        derp_request_region(dead_region); /* reconnect on the next pass */
    }

    /* collect the set of regions we want connected: home + queued */
    int want[MS_MAX_DERP_CONNS + 1];
    int n = 0;
    if (home) want[n++] = home;
    pthread_mutex_lock(&g.derp_mu);
    for (int i = 0; i < g.n_want && n <= MS_MAX_DERP_CONNS; i++) {
        int r = g.want_region[i];
        bool dup = false;
        for (int j = 0; j < n; j++) dup |= want[j] == r;
        if (!dup) want[n++] = r;
    }
    g.n_want = 0;
    pthread_mutex_unlock(&g.derp_mu);

    for (int w = 0; w < n; w++) {
        int region = want[w];
        pthread_mutex_lock(&g.derp_mu);
        bool exists = false;
        for (int i = 0; i < MS_MAX_DERP_CONNS; i++)
            if (g.conns[i].conn && g.conns[i].region_id == region)
                exists = true;
        pthread_mutex_unlock(&g.derp_mu);
        if (exists) continue;

        /* honour per-region redial backoff: don't hammer an unreachable
         * region (e.g. ENETUNREACH on the home DERP) every pass */
        if (derp_bo_blocked(region, tsnet_now_ms())) continue;

        /* look up the region + dial WITHOUT any lock held */
        pthread_mutex_lock(&g.mu);
        const tsnet_derp_region *reg = find_region_locked(region);
        tsnet_derp_region regcopy;
        if (reg) regcopy = *reg;
        pthread_mutex_unlock(&g.mu);
        if (!reg) continue;

        tsnet_derp *d = NULL;
        /* pass the region as the callback ud so derp_recv can learn which
         * region a peer's packets actually arrive on (derp_route) */
        int rc = tsnet_derp_connect(&d, &regcopy, g.node_priv,
                                    g.ca_file[0] ? g.ca_file : NULL, derp_recv,
                                    derp_state, (void *)(intptr_t)region);
        if (rc != TSNET_OK) {
            derp_bo_fail(region, tsnet_now_ms());
            TSNET_LOGE("magicsock: DERP connect region %d failed (%s), "
                       "backing off", region, tsnet_err_str(rc));
            continue;
        }
        derp_bo_ok(region);
        if (region == home) tsnet_derp_note_preferred(d, true);

        /* install; evict the longest-idle non-home conn if full */
        pthread_mutex_lock(&g.derp_mu);
        int slot = -1;
        for (int i = 0; i < MS_MAX_DERP_CONNS && slot < 0; i++)
            if (!g.conns[i].conn) slot = i;
        tsnet_derp *evict = NULL;
        if (slot < 0) {
            uint64_t oldest = UINT64_MAX;
            for (int i = 0; i < MS_MAX_DERP_CONNS; i++) {
                if (g.conns[i].region_id == home) continue;
                uint64_t la = tsnet_derp_last_activity(g.conns[i].conn);
                if (la < oldest) { oldest = la; slot = i; }
            }
            if (slot >= 0) { evict = g.conns[slot].conn; g.conns[slot].conn = NULL; }
        }
        if (slot >= 0) {
            g.conns[slot].conn = d;
            g.conns[slot].region_id = region;
        }
        pthread_mutex_unlock(&g.derp_mu);
        if (evict) tsnet_derp_close(evict); /* outside the lock */
        if (slot < 0) tsnet_derp_close(d);  /* no room: drop */
    }
}

/* ---- disco ---------------------------------------------------------------- */

/* send one disco ping to ep (via UDP) or via DERP when ep==NULL */
static void send_disco_ping(struct ms_peer *p, const tsnet_addr *ep) {
    tsnet_disco_msg m;
    memset(&m, 0, sizeof(m));
    m.type = TSNET_DISCO_PING;
    memcpy(m.txid, p->txid, sizeof(m.txid));
    memcpy(m.node_key, g.node_pub, 32);
    uint8_t pkt[256];
    int n = tsnet_disco_seal(&m, g.disco_priv, g.disco_pub, p->disco_key, pkt,
                             sizeof(pkt));
    if (n < 0) return;
    if (ep)
        tsnet_plat_udp_sendto(g.udp_fd, pkt, (size_t)n, ep);
    else
        derp_send_to(p->home_derp ? p->home_derp : g.home_derp, p->node_key,
                     pkt, (size_t)n);
}

/* send our endpoints via DERP so the peer pings us too (hole punching) */
static void send_call_me_maybe(struct ms_peer *p) {
    tsnet_disco_msg m;
    memset(&m, 0, sizeof(m));
    m.type = TSNET_DISCO_CALL_ME_MAYBE;
    pthread_mutex_lock(&g.mu);
    for (int i = 0; i < g.n_endpoints && m.n_eps < TSNET_DISCO_MAX_EPS; i++) {
        tsnet_addr a;
        if (tsnet_parse_ipport(g.endpoints[i], &a)) m.eps[m.n_eps++] = a;
    }
    pthread_mutex_unlock(&g.mu);
    if (m.n_eps == 0) return;
    uint8_t pkt[512];
    int n = tsnet_disco_seal(&m, g.disco_priv, g.disco_pub, p->disco_key, pkt,
                             sizeof(pkt));
    if (n > 0)
        derp_send_to(p->home_derp ? p->home_derp : g.home_derp, p->node_key,
                     pkt, (size_t)n);
}

/* start/continue a discovery round for p (mu held) */
static void discover_locked(struct ms_peer *p, uint64_t now) {
    if (g.derp_only) return;
    if (!p->has_disco || p->n_eps == 0) return;
    bool have_direct = p->best_pong_ms &&
                       now - p->best_pong_ms < MS_DIRECT_TRUST_MS;
    uint64_t interval =
        have_direct ? MS_KEEP_INTERVAL_MS : MS_PING_INTERVAL_MS;
    if (now - p->last_ping_ms < interval) return;
    p->last_ping_ms = now;
    tsnet_rand_bytes(p->txid, sizeof(p->txid));

    if (have_direct) {
        /* maintenance: ping only the active path */
        struct ms_peer copy = *p;
        pthread_mutex_unlock(&g.mu);
        send_disco_ping(&copy, &copy.best);
        pthread_mutex_lock(&g.mu);
        return;
    }
    /* full round: every candidate + DERP + CallMeMaybe */
    struct ms_peer copy = *p;
    pthread_mutex_unlock(&g.mu);
    for (int i = 0; i < copy.n_eps; i++)
        send_disco_ping(&copy, &copy.eps[i]);
    send_disco_ping(&copy, NULL); /* via DERP */
    send_call_me_maybe(&copy);
    pthread_mutex_lock(&g.mu);
}

/* handle one opened disco message. from_udp!=NULL: observed UDP source */
static void handle_disco(const uint8_t sender_disco[32],
                         const tsnet_disco_msg *m,
                         const tsnet_addr *from_udp, int via_region) {
    uint64_t now = tsnet_now_ms();
    pthread_mutex_lock(&g.mu);
    struct ms_peer *p = peer_by_disco_locked(sender_disco);
    if (!p) {
        pthread_mutex_unlock(&g.mu);
        return;
    }
    switch (m->type) {
    case TSNET_DISCO_PING: {
        /* learn the source as a candidate and answer with the observed
         * source (magicsock behavior; DERP pings answered via DERP with
         * the DerpMagicIP synthetic source 127.3.3.40:region) */
        tsnet_disco_msg pong;
        memset(&pong, 0, sizeof(pong));
        pong.type = TSNET_DISCO_PONG;
        memcpy(pong.txid, m->txid, sizeof(pong.txid));
        if (from_udp) {
            peer_add_ep_locked(p, from_udp);
            pong.src = *from_udp;
        } else {
            pong.src.family = 4;
            pong.src.ip[0] = 127;
            pong.src.ip[1] = 3;
            pong.src.ip[2] = 3;
            pong.src.ip[3] = 40;
            pong.src.port = (uint16_t)via_region;
        }
        struct ms_peer copy = *p;
        pthread_mutex_unlock(&g.mu);
        uint8_t pkt[256];
        int n = tsnet_disco_seal(&pong, g.disco_priv, g.disco_pub,
                                 copy.disco_key, pkt, sizeof(pkt));
        if (n > 0) {
            if (from_udp)
                tsnet_plat_udp_sendto(g.udp_fd, pkt, (size_t)n, from_udp);
            else
                derp_send_to(via_region, copy.node_key, pkt, (size_t)n);
        }
        return;
    }
    case TSNET_DISCO_PONG:
        if (from_udp && memcmp(m->txid, p->txid, sizeof(p->txid)) == 0) {
            bool was_direct = p->best_pong_ms &&
                              now - p->best_pong_ms < MS_DIRECT_TRUST_MS;
            p->best = *from_udp;
            p->best_pong_ms = now;
            if (!was_direct)
                TSNET_LOGI("magicsock: direct path to peer established "
                           "(%u.%u.%u.%u:%u)",
                           from_udp->ip[0], from_udp->ip[1], from_udp->ip[2],
                           from_udp->ip[3], from_udp->port);
        }
        break;
    case TSNET_DISCO_CALL_ME_MAYBE:
        for (int i = 0; i < m->n_eps; i++) peer_add_ep_locked(p, &m->eps[i]);
        /* answer immediately with pings to open our side */
        p->last_ping_ms = 0;
        discover_locked(p, now);
        break;
    default:
        break;
    }
    pthread_mutex_unlock(&g.mu);
}

/* ---- STUN / endpoints ------------------------------------------------------ */

static void publish_endpoints_locked(void) {
    if (!g.endpoints_cb || g.n_endpoints == 0) return;
    const char *eps[4];
    int n = g.n_endpoints;
    for (int i = 0; i < n; i++) eps[i] = g.endpoints[i];
    void (*cb)(const char **, int, void *) = g.endpoints_cb;
    void *ud = g.endpoints_ud;
    pthread_mutex_unlock(&g.mu);
    cb(eps, n, ud);
    pthread_mutex_lock(&g.mu);
}

static int stun_target_locked(tsnet_addr *out) {
    const tsnet_derp_region *reg = find_region_locked(g.home_derp);
    if (!reg && g.derpmap.n_regions) reg = &g.derpmap.regions[0];
    if (!reg || reg->n_nodes == 0) return -1;
    const tsnet_derp_node *node = &reg->nodes[0];
    tsnet_addr a;
    memset(&a, 0, sizeof(a));
    if (node->ipv4[0]) {
        if (!tsnet_parse_ip(node->ipv4, &a)) return -1;
    } else {
        if (tsnet_plat_resolve4(node->hostname, &a) != 0) return -1;
    }
    a.port = (uint16_t)node->stun_port;
    *out = a;
    return 0;
}

static void stun_refresh(uint64_t now) {
    pthread_mutex_lock(&g.mu);
    if (now - g.last_stun_ms < MS_STUN_INTERVAL_MS) {
        pthread_mutex_unlock(&g.mu);
        return;
    }
    g.last_stun_ms = now;
    tsnet_addr target;
    if (stun_target_locked(&target) != 0) {
        pthread_mutex_unlock(&g.mu);
        return;
    }
    tsnet_rand_bytes(g.stun_txid, sizeof(g.stun_txid));
    uint8_t txid[TSNET_STUN_TXID_LEN];
    memcpy(txid, g.stun_txid, sizeof(txid));

    /* local endpoint is known synchronously */
    tsnet_addr local;
    if (tsnet_plat_local_ip4(&target, &local) == 0) {
        snprintf(g.endpoints[1], sizeof(g.endpoints[1]), "%u.%u.%u.%u:%u",
                 local.ip[0], local.ip[1], local.ip[2], local.ip[3],
                 g.udp_port);
        if (g.n_endpoints < 2) g.n_endpoints = 2;
        if (!g.endpoints[0][0])
            snprintf(g.endpoints[0], sizeof(g.endpoints[0]), "%s",
                     g.endpoints[1]);
    }
    pthread_mutex_unlock(&g.mu);

    uint8_t req[64];
    int n = tsnet_stun_request(txid, req, sizeof(req));
    if (n > 0) tsnet_plat_udp_sendto(g.udp_fd, req, (size_t)n, &target);
}

static void handle_stun(const uint8_t *pkt, size_t len) {
    uint8_t txid[TSNET_STUN_TXID_LEN];
    tsnet_addr mapped;
    if (tsnet_stun_parse_response(pkt, len, txid, &mapped) != 0) return;
    pthread_mutex_lock(&g.mu);
    if (memcmp(txid, g.stun_txid, sizeof(txid)) != 0) {
        pthread_mutex_unlock(&g.mu);
        return;
    }
    char pub[64];
    snprintf(pub, sizeof(pub), "%u.%u.%u.%u:%u", mapped.ip[0], mapped.ip[1],
             mapped.ip[2], mapped.ip[3], mapped.port);
    bool changed = strcmp(g.endpoints[0], pub) != 0;
    snprintf(g.endpoints[0], sizeof(g.endpoints[0]), "%s", pub);
    if (g.n_endpoints < 1) g.n_endpoints = 1;
    if (changed) {
        TSNET_LOGI("magicsock: public endpoint %s (STUN)", pub);
        publish_endpoints_locked();
    }
    pthread_mutex_unlock(&g.mu);
}

/* ---- UDP receive loop ------------------------------------------------------ */

static void *udp_main(void *arg) {
    (void)arg;
    tsnet_plat_thread_boost(); /* latency-critical: decrypt + hand to lwIP */
    uint8_t buf[2048];
    while (!g.stopping) {
        tsnet_addr src;
        ssize_t n = tsnet_plat_udp_recvfrom(g.udp_fd, buf, sizeof(buf), &src,
                                            1000);
        if (n > 0) {
            if (tsnet_disco_looks(buf, (size_t)n)) {
                uint8_t sender[32];
                tsnet_disco_msg m;
                if (tsnet_disco_open(buf, (size_t)n, g.disco_priv, NULL,
                                     sender, &m) == 0)
                    handle_disco(sender, &m, &src, 0);
            } else if (tsnet_stun_is(buf, (size_t)n)) {
                handle_stun(buf, (size_t)n);
            } else {
                tsnet_wgif_rx(buf, (size_t)n);
            }
        }
    }
    return NULL;
}

/* Maintenance loop — kept OFF the udp receive thread so its per-packet cadence
 * stays even. These do blocking work (a getsockname socket probe every 3 s to
 * catch a Wi-Fi/hotspot change, DERP dials, STUN) that, when run inline between
 * recvfrom() calls, stall delivery in periodic micro-bursts (stutter without
 * packet loss). All shared state is g.mu / derp_mu guarded, so
 * running it on its own thread is safe. */
static void *maint_main(void *arg) {
    (void)arg;
    uint64_t last_ip_check = 0, last_periodic = 0;
    tsnet_addr last_local;
    memset(&last_local, 0, sizeof(last_local));
    while (!g.stopping) {
        struct timespec sl = {0, 200 * 1000 * 1000}; /* 200 ms */
        nanosleep(&sl, NULL);
        if (g.stopping) break;
        uint64_t now = tsnet_now_ms();

        /* network-change detection: if the local IP toward the home
         * region changed (Wi-Fi switch / hotspot), re-STUN and re-discover
         * immediately instead of waiting for the 30 s cycle */
        if (now - last_ip_check > 3000) {
            last_ip_check = now;
            pthread_mutex_lock(&g.mu);
            tsnet_addr target;
            bool have = stun_target_locked(&target) == 0;
            pthread_mutex_unlock(&g.mu);
            tsnet_addr local;
            if (have && tsnet_plat_local_ip4(&target, &local) == 0) {
                /* tell the shim our real interface IP so a subnet-route
                 * destination on our own LAN stays on the real path */
                tsnet_shim_set_local_ip(&local);
                if (!tsnet_addr_eq_ip(&local, &last_local)) {
                    if (last_local.family) {
                        TSNET_LOGI("magicsock: local IP changed, refreshing "
                                   "endpoints and paths");
                        pthread_mutex_lock(&g.mu);
                        g.last_stun_ms = 0; /* force STUN now */
                        for (int i = 0; i < g.n_peers; i++)
                            g.peers[i].last_ping_ms = 0; /* re-discover now */
                        pthread_mutex_unlock(&g.mu);
                    }
                    last_local = local;
                }
            }
        }

        /* periodic work at ~1 Hz: keep DERP connections alive, STUN,
         * discovery. */
        if (now - last_periodic >= MS_PERIODIC_INTERVAL_MS) {
            last_periodic = now;
            derp_ensure_connections();
            stun_refresh(now);
            pthread_mutex_lock(&g.mu);
            for (int i = 0; i < g.n_peers; i++) {
                struct ms_peer *p = &g.peers[i];
                if (!p->valid) continue;
                if (now - p->last_traffic_ms < MS_TRAFFIC_ACTIVE_MS)
                    discover_locked(p, now);
            }
            pthread_mutex_unlock(&g.mu);
        }
    }
    return NULL;
}

/* ---- DERP rx --------------------------------------------------------------- */

static void derp_recv(const uint8_t src_key[32], const uint8_t *pkt,
                      size_t len, void *ud) {
    int rx_region = (int)(intptr_t)ud;
    /* DEBUG, not INFO: this runs on the DERP reader thread per inbound packet.
     * At video rate the logger's synchronous fflush/fsync-to-SD (util/log.c)
     * would starve this thread, stall TLS reads, and overflow the DERP relay's
     * per-client send queue — dropping video wholesale while sparse audio
     * survives. Keep it at DEBUG for on-demand diagnosis only. */
    TSNET_LOGD("magicsock: DERP rx %zu bytes from %02x%02x%02x%02x.. via "
               "region %d (%s)",
               len, src_key[0], src_key[1], src_key[2], src_key[3], rx_region,
               tsnet_disco_looks(pkt, len) ? "disco" : "wg");
    /* learn the peer's real DERP region for the DATA path, but ONLY from
     * WireGuard packets. disco probes arrive on several regions at once
     * (the peer pings via multiple relays); following those would flap the
     * data route. WG traffic marks the region that actually carries the
     * session — keep the send path pinned there. */
    if (rx_region && !tsnet_disco_looks(pkt, len)) {
        pthread_mutex_lock(&g.mu);
        struct ms_peer *sp = peer_by_node_locked(src_key);
        if (sp && sp->derp_route != rx_region) {
            sp->derp_route = rx_region;
            TSNET_LOGI("magicsock: peer %02x%02x%02x%02x.. derp_route -> %d",
                       src_key[0], src_key[1], src_key[2], src_key[3],
                       rx_region);
        }
        pthread_mutex_unlock(&g.mu);
    }
    if (tsnet_disco_looks(pkt, len)) {
        uint8_t sender[32];
        tsnet_disco_msg m;
        if (tsnet_disco_open(pkt, len, g.disco_priv, NULL, sender, &m) == 0) {
            /* reply on the region we received this on (authoritative), else
             * the peer's netmap home_derp */
            int region = rx_region ? rx_region : g.home_derp;
            if (!region) {
                pthread_mutex_lock(&g.mu);
                struct ms_peer *p = peer_by_node_locked(src_key);
                if (p && p->home_derp) region = p->home_derp;
                pthread_mutex_unlock(&g.mu);
            }
            handle_disco(sender, &m, NULL, region);
        }
        return;
    }
    tsnet_wgif_rx(pkt, len);
}

static void derp_state(bool con_up, void *ud) {
    (void)ud;
    if (!con_up) TSNET_LOGW("magicsock: a DERP connection dropped");
}

/* ---- API -------------------------------------------------------------------- */

int tsnet_magicsock_start(const uint8_t node_priv[32],
                          const uint8_t disco_priv[32], const char *ca_file) {
    if (g.up) return TSNET_OK;
    pthread_mutex_init(&g.mu, NULL);
    pthread_mutex_init(&g.derp_mu, NULL);
    memcpy(g.node_priv, node_priv, 32);
    memcpy(g.disco_priv, disco_priv, 32);
    tsnet_x25519_pubkey(g.node_pub, node_priv);
    tsnet_x25519_pubkey(g.disco_pub, disco_priv);
    if (ca_file) snprintf(g.ca_file, sizeof(g.ca_file), "%s", ca_file);

    g.udp_fd = tsnet_plat_udp_open(MS_DEFAULT_PORT, &g.udp_port);
    if (g.udp_fd < 0) {
        TSNET_LOGE("magicsock: UDP socket failed");
        return TSNET_E_IO;
    }
    g.stopping = 0;
    if (tsnet_thread_create(&g.udp_thread, udp_main, NULL) != 0) {
        tsnet_plat_sock_close(g.udp_fd);
        return TSNET_E_STATE;
    }
    g.udp_thread_up = true;
    if (tsnet_thread_create(&g.maint_thread, maint_main, NULL) == 0)
        g.maint_thread_up = true;
    else
        TSNET_LOGW("magicsock: maintenance thread not started");
    g.up = true;
    TSNET_LOGI("magicsock: started (udp port %u)", g.udp_port);
    return TSNET_OK;
}

void tsnet_magicsock_set_endpoints_cb(void (*cb)(const char **eps, int n,
                                                 void *ud),
                                      void *ud) {
    g.endpoints_cb = cb;
    g.endpoints_ud = ud;
}

void tsnet_magicsock_set_netmap(const tsnet_netmap *nm) {
    if (!g.up) return;
    pthread_mutex_lock(&g.mu);
    if (nm->has_derpmap) g.derpmap = nm->derpmap;

    /* merge peers, preserving live path state by node key */
    struct ms_peer next[TSNET_MAX_PEERS];
    memset(next, 0, sizeof(next));
    int n_next = 0;
    for (int i = 0; i < nm->n_peers && n_next < TSNET_MAX_PEERS; i++) {
        const tsnet_peer *np = &nm->peers[i];
        struct ms_peer *old = peer_by_node_locked(np->node_key);
        struct ms_peer *p = &next[n_next++];
        if (old) *p = *old;
        p->valid = true;
        memcpy(p->node_key, np->node_key, 32);
        memcpy(p->disco_key, np->disco_key, 32);
        p->has_disco = np->has_disco;
        p->home_derp = np->home_derp;
        for (int j = 0; j < np->n_endpoints; j++)
            peer_add_ep_locked(p, &np->endpoints[j].addr);
    }
    memcpy(g.peers, next, sizeof(next));
    g.n_peers = n_next;

    int home = nm->home_derp;
    if (home == 0 && nm->n_peers > 0) home = nm->peers[0].home_derp;
    if (home == 0 && g.derpmap.n_regions > 0) home = g.derpmap.regions[0].id;
    bool home_changed = home != g.home_derp;
    g.home_derp = home;
    /* trigger an immediate STUN round against the (new) home region */
    if (home_changed) g.last_stun_ms = 0;
    pthread_mutex_unlock(&g.mu);
    /* the udp thread establishes the home connection (no inline dial) */
    if (g.home_derp) derp_request_region(g.home_derp);
    if (home_changed)
        TSNET_LOGI("magicsock: home DERP region = %d", home);

    for (int i = 0; i < nm->n_peers; i++) {
        const tsnet_peer *np = &nm->peers[i];
        for (int r = 0; r < np->n_routes; r++)
            TSNET_LOGI("magicsock: subnet route %u.%u.%u.%u/%u via peer "
                       "%02x%02x%02x%02x..",
                       np->routes[r].net.ip[0], np->routes[r].net.ip[1],
                       np->routes[r].net.ip[2], np->routes[r].net.ip[3],
                       np->routes[r].bits, np->node_key[0], np->node_key[1],
                       np->node_key[2], np->node_key[3]);
        tsnet_wgif_set_peer(np->node_key, np->addrs, np->n_addrs, np->routes,
                            np->n_routes);
    }
}

void tsnet_magicsock_send_wg(const uint8_t peer_node_key[32],
                             const uint8_t *pkt, size_t len, void *ud) {
    (void)ud;
    if (!g.up) return;
    uint64_t now = tsnet_now_ms();
    pthread_mutex_lock(&g.mu);
    struct ms_peer *p = peer_by_node_locked(peer_node_key);
    int region = g.home_derp;
    int route = 0;      /* learned region (authoritative) */
    bool bootstrap = false; /* haven't heard from this peer yet */
    bool direct = false;
    tsnet_addr dst;
    if (p) {
        p->last_traffic_ms = now;
        /* prefer the region we actually received the peer on; fall back to the
         * netmap home_derp (which the control map can report stale) */
        if (p->derp_route) {
            region = p->derp_route;
            route = p->derp_route;
        } else if (p->home_derp) {
            region = p->home_derp;
        }
        bootstrap = p->derp_route == 0;
        if (!g.derp_only && p->best_pong_ms &&
            now - p->best_pong_ms < MS_DIRECT_TRUST_MS) {
            direct = true;
            dst = p->best;
        } else {
            discover_locked(p, now); /* may briefly drop the lock */
        }
    }
    pthread_mutex_unlock(&g.mu);

    if (direct) {
        if (tsnet_plat_udp_sendto(g.udp_fd, pkt, len, &dst) == (ssize_t)len)
            return;
        /* fall through to DERP on send error */
    }
    derp_send_to(region, peer_node_key, pkt, len);
    /* Bootstrap: until we have heard back from the peer (no learned route),
     * the netmap's home_derp may be stale, so ALSO relay via our own home
     * region. A geographically-close peer is often on the same region as us,
     * so this breaks the deadlock (we can't learn the real route without first
     * reaching the peer). Once a reply arrives, derp_route is set and this
     * stops — data never fans out to two regions. */
    (void)route;
    if (bootstrap && g.home_derp && g.home_derp != region)
        derp_send_to(g.home_derp, peer_node_key, pkt, len);
}

int tsnet_magicsock_home_derp(void) { return g.home_derp; }

int tsnet_magicsock_peer_path(const uint8_t node_key[32], char *out,
                              size_t cap) {
    uint64_t now = tsnet_now_ms();
    pthread_mutex_lock(&g.mu);
    struct ms_peer *p = peer_by_node_locked(node_key);
    int n;
    if (p && p->best_pong_ms && now - p->best_pong_ms < MS_DIRECT_TRUST_MS) {
        n = snprintf(out, cap, "direct %u.%u.%u.%u:%u", p->best.ip[0],
                     p->best.ip[1], p->best.ip[2], p->best.ip[3],
                     p->best.port);
    } else {
        n = snprintf(out, cap, "derp-%d",
                     p && p->home_derp ? p->home_derp : g.home_derp);
    }
    pthread_mutex_unlock(&g.mu);
    return n;
}

void tsnet_magicsock_set_derp_only(bool derp_only) {
    g.derp_only = derp_only;
    if (derp_only) TSNET_LOGI("magicsock: DERP-only mode (direct disabled)");
}

void tsnet_magicsock_stop(void) {
    if (!g.up) return;
    g.stopping = 1;
    if (g.maint_thread_up) {
        pthread_join(g.maint_thread, NULL);
        g.maint_thread_up = false;
    }
    if (g.udp_thread_up) {
        pthread_join(g.udp_thread, NULL);
        g.udp_thread_up = false;
    }
    tsnet_plat_sock_close(g.udp_fd);
    /* the udp thread is joined, so no one else touches g.conns now; still
     * take derp_mu for consistency, but detach each conn from the table
     * before closing it (close joins the reader — never hold derp_mu across
     * a foreign lock, and the reader only takes g.mu, so this is safe) */
    for (int i = 0; i < MS_MAX_DERP_CONNS; i++) {
        pthread_mutex_lock(&g.derp_mu);
        tsnet_derp *d = g.conns[i].conn;
        g.conns[i].conn = NULL;
        pthread_mutex_unlock(&g.derp_mu);
        if (d) tsnet_derp_close(d);
    }
    memset(g.node_priv, 0, sizeof(g.node_priv));
    memset(g.disco_priv, 0, sizeof(g.disco_priv));
    g.up = false;
}
