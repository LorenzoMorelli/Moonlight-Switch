#include "netif_ts0.h"

#include "platform/platform.h"
#include "util/log.h"

#include "lwip/ip.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip6_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcpip.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "tsnet/tsnet.h"

static struct netif g_ts0;
static bool g_ts0_up;
static tsnet_ts0_output_fn g_output;
static void *g_output_ctx;

static pthread_mutex_t g_init_mu = PTHREAD_MUTEX_INITIALIZER;
static bool g_lwip_started;
static pthread_cond_t g_init_cv = PTHREAD_COND_INITIALIZER;
static bool g_init_done;

static void tcpip_ready(void *arg) {
    (void)arg;
    pthread_mutex_lock(&g_init_mu);
    g_init_done = true;
    pthread_cond_signal(&g_init_cv);
    pthread_mutex_unlock(&g_init_mu);
}

/* runs on the tcpip thread (via tcpip_callback): boost its own priority */
static void boost_tcpip_thread(void *arg) {
    (void)arg;
    tsnet_plat_thread_boost();
}

int tsnet_lwip_start(void) {
    pthread_mutex_lock(&g_init_mu);
    if (g_lwip_started) {
        pthread_mutex_unlock(&g_init_mu);
        return TSNET_OK;
    }
    g_lwip_started = true;
    pthread_mutex_unlock(&g_init_mu);

    /* LWIP_RAND() in the unix port is rand()-based (sys_arch.c:80): give it
     * a strong seed for TCP ISNs / ephemeral ports. */
    unsigned seed;
    tsnet_rand_bytes(&seed, sizeof(seed));
    srand(seed);

    tcpip_init(tcpip_ready, NULL);

    pthread_mutex_lock(&g_init_mu);
    while (!g_init_done) pthread_cond_wait(&g_init_cv, &g_init_mu);
    pthread_mutex_unlock(&g_init_mu);
    /* Raise the tcpip thread's priority from inside it: it delivers every
     * inbound video packet and holds the lwIP core lock for outbound input, so
     * it must not sit behind the renderer (jitter + input lag). */
    tcpip_callback(boost_tcpip_thread, NULL);
    TSNET_LOGI("lwip: tcpip thread started");
    return TSNET_OK;
}

/* Hand a fully formed IP packet to the tunnel transport. Runs on the
 * tcpip thread. LWIP_NETIF_TX_SINGLE_PBUF=1 guarantees a single pbuf. */
static err_t ts0_output_common(struct pbuf *p) {
    if (!g_output) return ERR_RTE;
    if (p->len != p->tot_len) {
        /* cannot happen with LWIP_NETIF_TX_SINGLE_PBUF=1 */
        TSNET_LOGE("ts0: chained pbuf on output (len=%u tot=%u)", p->len,
                   p->tot_len);
        return ERR_IF;
    }
    const uint8_t *b = p->payload;
    if (p->len >= 20 && (b[0] >> 4) == 4) {
        int hl = (b[0] & 0xf) * 4;
        /* An inbound UDP flood to closed ports (e.g. a peer still blasting a
         * stale video stream) makes lwIP emit an ICMP dest-unreachable per
         * packet — an ICMP storm that saturates the tunnel and chokes the
         * control TCP. Rate-limit outbound ICMP dest-unreachable (type 3);
         * echo/others are untouched. */
        if (b[9] == 1 && p->len > (unsigned)hl && b[hl] == 3) {
            static uint32_t win_ms;
            static int win_n;
            uint32_t now = sys_now();
            if (now - win_ms >= 1000) {
                win_ms = now;
                win_n = 0;
            }
            if (++win_n > 8) return ERR_OK; /* drop the excess silently */
        }
    }
    g_output((const uint8_t *)p->payload, p->len, g_output_ctx);
    return ERR_OK;
}

static err_t ts0_output_v4(struct netif *nif, struct pbuf *p,
                           const ip4_addr_t *addr) {
    (void)nif;
    (void)addr;
    return ts0_output_common(p);
}

#if LWIP_IPV6
static err_t ts0_output_v6(struct netif *nif, struct pbuf *p,
                           const ip6_addr_t *addr) {
    (void)nif;
    (void)addr;
    return ts0_output_common(p);
}
#endif

static err_t ts0_init_cb(struct netif *nif) {
    nif->name[0] = 't';
    nif->name[1] = 's';
    nif->mtu = TSNET_TS0_MTU;
#if LWIP_IPV6
    nif->mtu6 = TSNET_TS0_MTU;
    nif->output_ip6 = ts0_output_v6;
#endif
    nif->output = ts0_output_v4;
    /* No link layer: pure IP point-to-multipoint interface. NETIF_FLAG_UP
     * is set by netif_set_up(). */
    nif->flags = NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

struct ts0_cfg {
    ip4_addr_t ip4, mask4;
#if LWIP_IPV6
    ip6_addr_t ip6;
    bool has_ip6;
#endif
    sys_sem_t done; /* signaled by the tcpip thread when config is applied */
};

static void ts0_up_cb(void *arg) {
    struct ts0_cfg *cfg = arg;
    if (g_ts0_up) {
        netif_remove(&g_ts0);
        memset(&g_ts0, 0, sizeof(g_ts0));
    }
    ip4_addr_t gw;
    ip4_addr_set_any(&gw);
    netif_add(&g_ts0, &cfg->ip4, &cfg->mask4, &gw, NULL, ts0_init_cb,
              tcpip_input);
#if LWIP_IPV6
    if (cfg->has_ip6) {
        s8_t idx;
        netif_add_ip6_address(&g_ts0, &cfg->ip6, &idx);
        if (idx >= 0)
            netif_ip6_addr_set_state(&g_ts0, idx, IP6_ADDR_PREFERRED);
    }
#endif
    netif_set_default(&g_ts0); /* only lwIP netif: all lwIP traffic is tailnet */
    netif_set_up(&g_ts0);
    g_ts0_up = true;
    sys_sem_signal(&cfg->done); /* config is fully applied now */
}

static bool parse_cidr4(const char *s, ip4_addr_t *ip, ip4_addr_t *mask) {
    char addr[64];
    int prefix = 32;
    const char *slash = strchr(s, '/');
    if (slash) {
        size_t n = (size_t)(slash - s);
        if (n >= sizeof(addr)) return false;
        memcpy(addr, s, n);
        addr[n] = '\0';
        prefix = atoi(slash + 1);
    } else {
        snprintf(addr, sizeof(addr), "%s", s);
    }
    if (prefix < 0 || prefix > 32) return false;
    if (!ip4addr_aton(addr, ip)) return false;
    u32_t m = prefix == 0 ? 0 : 0xffffffffu << (32 - prefix);
    ip4_addr_set_u32(mask, lwip_htonl(m));
    return true;
}

int tsnet_ts0_up(const char *ip4_cidr, const char *ip6_cidr,
                 tsnet_ts0_output_fn output, void *ctx) {
    /* on-stack cfg kept alive by the semaphore round-trip below (no static:
     * a concurrent reconfigure would race a shared one) */
    struct ts0_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    if (!ip4_cidr || !parse_cidr4(ip4_cidr, &cfg.ip4, &cfg.mask4))
        return TSNET_E_INVAL;
#if LWIP_IPV6
    if (ip6_cidr) {
        char addr[64];
        const char *slash = strchr(ip6_cidr, '/');
        size_t n = slash ? (size_t)(slash - ip6_cidr) : strlen(ip6_cidr);
        if (n >= sizeof(addr)) return TSNET_E_INVAL;
        memcpy(addr, ip6_cidr, n);
        addr[n] = '\0';
        if (!ip6addr_aton(addr, &cfg.ip6)) return TSNET_E_INVAL;
        cfg.has_ip6 = true;
    }
#else
    (void)ip6_cidr;
#endif
    g_output = output;
    g_output_ctx = ctx;

    int rc = tsnet_lwip_start();
    if (rc != TSNET_OK) return rc;

    if (sys_sem_new(&cfg.done, 0) != ERR_OK) return TSNET_E_NOMEM;
    err_t e = tcpip_callback(ts0_up_cb, &cfg);
    if (e != ERR_OK) {
        sys_sem_free(&cfg.done);
        return TSNET_E_NOMEM;
    }
    /* block until ts0_up_cb has fully applied the config on the tcpip
     * thread (the callback signals cfg.done); cfg stays valid until then */
    sys_arch_sem_wait(&cfg.done, 0);
    sys_sem_free(&cfg.done);
    TSNET_LOGI("lwip: ts0 up %s%s%s", ip4_cidr, ip6_cidr ? " " : "",
               ip6_cidr ? ip6_cidr : "");
    return TSNET_OK;
}

int tsnet_ts0_input(const uint8_t *buf, uint16_t len) {
    if (!g_ts0_up) return TSNET_E_STATE;
    struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    if (!p) return TSNET_E_NOMEM;
    pbuf_take(p, buf, len);
    if (g_ts0.input(p, &g_ts0) != ERR_OK) {
        pbuf_free(p);
        return TSNET_E_IO;
    }
    return TSNET_OK;
}

static void ts0_down_cb(void *arg) {
    (void)arg;
    if (g_ts0_up) {
        netif_remove(&g_ts0);
        g_ts0_up = false;
    }
}

int tsnet_ts0_down(void) {
    if (!g_lwip_started) return TSNET_OK;
    tcpip_callback(ts0_down_cb, NULL);
    for (int i = 0; i < 1000 && g_ts0_up; i++) {
        struct timespec ts = {0, 2 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return g_ts0_up ? TSNET_E_TIMEOUT : TSNET_OK;
}
