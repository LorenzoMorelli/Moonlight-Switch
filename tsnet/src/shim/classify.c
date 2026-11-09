#include "classify.h"

#include <pthread.h>
#include <string.h>

/* ---- address helpers -------------------------------------------------- */

bool tsnet_addr_is_multicast_or_broadcast(const tsnet_addr *a) {
    if (a->family == 4) {
        /* 224.0.0.0/4 multicast, 255.255.255.255 limited broadcast */
        if ((a->ip[0] & 0xf0) == 0xe0) return true;
        if (a->ip[0] == 255 && a->ip[1] == 255 && a->ip[2] == 255 &&
            a->ip[3] == 255)
            return true;
        return false;
    }
    if (a->family == 6) return a->ip[0] == 0xff; /* ff00::/8 */
    return false;
}

bool tsnet_addr_is_wildcard(const tsnet_addr *a) {
    int n = a->family == 4 ? 4 : 16;
    for (int i = 0; i < n; i++)
        if (a->ip[i] != 0) return false;
    return true;
}

bool tsnet_addr_in_tailnet_ranges(const tsnet_addr *a) {
    if (a->family == 4) {
        /* 100.64.0.0/10: 100.64.0.0 – 100.127.255.255 */
        return a->ip[0] == 100 && (a->ip[1] & 0xc0) == 0x40;
    }
    if (a->family == 6) {
        /* fd7a:115c:a1e0::/48 */
        static const uint8_t pfx[6] = {0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0};
        return memcmp(a->ip, pfx, sizeof(pfx)) == 0;
    }
    return false;
}

bool tsnet_addr_eq_ip(const tsnet_addr *a, const tsnet_addr *b) {
    if (a->family != b->family) return false;
    return memcmp(a->ip, b->ip, a->family == 4 ? 4 : 16) == 0;
}

bool tsnet_addr_in_prefix(const tsnet_addr *a, const tsnet_prefix *p) {
    if (a->family != p->net.family) return false;
    int nbytes = a->family == 4 ? 4 : 16;
    int bits = p->bits;
    if (bits > nbytes * 8) bits = nbytes * 8;
    int full = bits / 8, rem = bits % 8;
    if (memcmp(a->ip, p->net.ip, (size_t)full) != 0) return false;
    if (rem) {
        uint8_t mask = (uint8_t)(0xff << (8 - rem));
        if ((a->ip[full] & mask) != (p->net.ip[full] & mask)) return false;
    }
    return true;
}

/* ---- registry --------------------------------------------------------- */

#define REG_MAX_ADDRS 128
#define REG_MAX_NAMES 64
#define REG_NAME_LEN 128
#define REG_ADDRS_PER_NAME 2
#define REG_MAX_ROUTES 32

static pthread_rwlock_t g_reg_lock = PTHREAD_RWLOCK_INITIALIZER;
static tsnet_addr g_addrs[REG_MAX_ADDRS];
static int g_n_addrs;
static struct {
    char name[REG_NAME_LEN];
    tsnet_addr addrs[REG_ADDRS_PER_NAME];
    int n;
} g_names[REG_MAX_NAMES];
static int g_n_names;
static tsnet_prefix g_routes[REG_MAX_ROUTES]; /* accepted subnet routes */
static int g_n_routes;
static tsnet_addr g_local_ip; /* our real (non-tunnel) interface IP, if known */

static tsnet_route_hint g_hint = TSNET_HINT_AUTO;

void tsnet_registry_clear(void) {
    pthread_rwlock_wrlock(&g_reg_lock);
    g_n_addrs = 0;
    g_n_names = 0;
    g_n_routes = 0;
    pthread_rwlock_unlock(&g_reg_lock);
}

int tsnet_registry_add_addr(const tsnet_addr *a) {
    pthread_rwlock_wrlock(&g_reg_lock);
    for (int i = 0; i < g_n_addrs; i++) {
        if (tsnet_addr_eq_ip(&g_addrs[i], a)) {
            pthread_rwlock_unlock(&g_reg_lock);
            return 0;
        }
    }
    if (g_n_addrs >= REG_MAX_ADDRS) {
        pthread_rwlock_unlock(&g_reg_lock);
        return -1;
    }
    g_addrs[g_n_addrs] = *a;
    g_addrs[g_n_addrs].port = 0;
    g_n_addrs++;
    pthread_rwlock_unlock(&g_reg_lock);
    return 0;
}

bool tsnet_registry_contains(const tsnet_addr *a) {
    pthread_rwlock_rdlock(&g_reg_lock);
    bool found = false;
    for (int i = 0; i < g_n_addrs && !found; i++)
        found = tsnet_addr_eq_ip(&g_addrs[i], a);
    pthread_rwlock_unlock(&g_reg_lock);
    return found;
}

int tsnet_registry_add_route(const tsnet_prefix *p) {
    pthread_rwlock_wrlock(&g_reg_lock);
    for (int i = 0; i < g_n_routes; i++) {
        if (g_routes[i].bits == p->bits &&
            tsnet_addr_eq_ip(&g_routes[i].net, &p->net)) {
            pthread_rwlock_unlock(&g_reg_lock);
            return 0;
        }
    }
    if (g_n_routes >= REG_MAX_ROUTES) {
        pthread_rwlock_unlock(&g_reg_lock);
        return -1;
    }
    g_routes[g_n_routes++] = *p;
    pthread_rwlock_unlock(&g_reg_lock);
    return 0;
}

bool tsnet_registry_in_route(const tsnet_addr *a) {
    pthread_rwlock_rdlock(&g_reg_lock);
    bool tunnel = false;
    for (int i = 0; i < g_n_routes; i++) {
        if (!tsnet_addr_in_prefix(a, &g_routes[i])) continue;
        /* If we are ON this subnet locally (e.g. at home on the
         * same LAN as the subnet router), the address is directly reachable —
         * keep it on the real LAN socket. Only tunnel it when we are off-LAN. */
        if (g_local_ip.family &&
            tsnet_addr_in_prefix(&g_local_ip, &g_routes[i]))
            break;
        tunnel = true;
        break;
    }
    pthread_rwlock_unlock(&g_reg_lock);
    return tunnel;
}

void tsnet_shim_set_local_ip(const tsnet_addr *ip) {
    pthread_rwlock_wrlock(&g_reg_lock);
    if (ip)
        g_local_ip = *ip;
    else
        memset(&g_local_ip, 0, sizeof(g_local_ip));
    pthread_rwlock_unlock(&g_reg_lock);
}

/* case-insensitive compare, ignoring one trailing dot on q */
static bool name_matches(const char *q, const char *stored) {
    size_t ql = strlen(q);
    if (ql > 0 && q[ql - 1] == '.') ql--;
    size_t sl = strlen(stored);
    if (ql != sl) return false;
    for (size_t i = 0; i < ql; i++) {
        char a = q[i], b = stored[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return false;
    }
    return true;
}

int tsnet_registry_add_name(const char *name, const tsnet_addr *addrs,
                            int n_addrs) {
    if (n_addrs > REG_ADDRS_PER_NAME) n_addrs = REG_ADDRS_PER_NAME;
    pthread_rwlock_wrlock(&g_reg_lock);
    int slot = -1;
    for (int i = 0; i < g_n_names; i++) {
        if (name_matches(name, g_names[i].name)) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        if (g_n_names >= REG_MAX_NAMES ||
            strlen(name) >= REG_NAME_LEN) {
            pthread_rwlock_unlock(&g_reg_lock);
            return -1;
        }
        slot = g_n_names++;
        strcpy(g_names[slot].name, name);
    }
    memcpy(g_names[slot].addrs, addrs, (size_t)n_addrs * sizeof(*addrs));
    g_names[slot].n = n_addrs;
    pthread_rwlock_unlock(&g_reg_lock);
    return 0;
}

int tsnet_registry_resolve(const char *name, tsnet_addr *out, int max) {
    pthread_rwlock_rdlock(&g_reg_lock);
    int n = 0;
    for (int i = 0; i < g_n_names; i++) {
        if (name_matches(name, g_names[i].name)) {
            for (int j = 0; j < g_names[i].n && n < max; j++)
                out[n++] = g_names[i].addrs[j];
            break;
        }
    }
    pthread_rwlock_unlock(&g_reg_lock);
    return n;
}

/* ---- classification --------------------------------------------------- */

void tsnet_shim_set_route_hint(tsnet_route_hint h) {
    __atomic_store_n(&g_hint, h, __ATOMIC_RELAXED);
}

tsnet_route_hint tsnet_shim_get_route_hint(void) {
    return __atomic_load_n(&g_hint, __ATOMIC_RELAXED);
}

tsnet_route tsnet_classify(const tsnet_addr *dst) {
    if (dst->family != 4 && dst->family != 6) return TSNET_ROUTE_REAL;
    /* multicast/broadcast/wildcard can never cross the tunnel (mDNS, WoL,
     * SSDP must keep working on the LAN even in force-tunnel debug mode) */
    if (tsnet_addr_is_multicast_or_broadcast(dst) ||
        tsnet_addr_is_wildcard(dst))
        return TSNET_ROUTE_REAL;

    switch (tsnet_shim_get_route_hint()) {
    case TSNET_HINT_FORCE_TUNNEL: return TSNET_ROUTE_TUNNEL;
    case TSNET_HINT_FORCE_REAL: return TSNET_ROUTE_REAL;
    case TSNET_HINT_AUTO: break;
    }

    if (tsnet_addr_in_tailnet_ranges(dst)) return TSNET_ROUTE_TUNNEL;
    if (tsnet_registry_contains(dst)) return TSNET_ROUTE_TUNNEL;
    /* a LAN address reachable only via a peer's advertised subnet route
     * (e.g. 192.168.1.200 when off-LAN) goes through the tunnel too */
    if (tsnet_registry_in_route(dst)) return TSNET_ROUTE_TUNNEL;
    return TSNET_ROUTE_REAL;
}
