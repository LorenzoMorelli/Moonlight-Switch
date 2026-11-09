#include "netmap.h"

#include "tsnet/tsnet.h"
#include "util/hex.h"
#include "util/log.h"

/* lwIP address parsers (safe here: this TU has no system socket headers) */
#include "lwip/ip_addr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <jansson.h>

/* ---- small parsers ------------------------------------------------------ */

bool tsnet_parse_ip(const char *s, tsnet_addr *out) {
    memset(out, 0, sizeof(*out));
    if (strchr(s, ':')) {
        ip6_addr_t a6;
        if (!ip6addr_aton(s, &a6)) return false;
        out->family = 6;
        memcpy(out->ip, &a6.addr, 16);
        return true;
    }
    ip4_addr_t a4;
    if (!ip4addr_aton(s, &a4)) return false;
    out->family = 4;
    memcpy(out->ip, &a4.addr, 4);
    return true;
}

/* "1.2.3.4:56" or "[fd7a::1]:56" (Go netip.AddrPort JSON form) */
bool tsnet_parse_ipport(const char *s, tsnet_addr *out) {
    char host[64];
    const char *colon;
    if (s[0] == '[') {
        const char *close = strchr(s, ']');
        if (!close || close[1] != ':') return false;
        size_t n = (size_t)(close - s - 1);
        if (n >= sizeof(host)) return false;
        memcpy(host, s + 1, n);
        host[n] = '\0';
        colon = close + 1;
    } else {
        colon = strrchr(s, ':');
        if (!colon) return false;
        size_t n = (size_t)(colon - s);
        if (n >= sizeof(host)) return false;
        memcpy(host, s, n);
        host[n] = '\0';
    }
    if (!tsnet_parse_ip(host, out)) return false;
    long port = strtol(colon + 1, NULL, 10);
    if (port <= 0 || port > 65535) return false;
    out->port = (uint16_t)port;
    return true;
}

/* days since 1970-01-01 for y-m-d (proleptic Gregorian; Hinnant's
 * days_from_civil) — newlib has no timegm() */
static int64_t days_from_civil(int y, int m, int d) {
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (unsigned)((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1);
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

/* RFC 3339 "2026-09-06T17:00:00Z" (fractional seconds and offsets ok) */
int64_t tsnet_parse_rfc3339(const char *s) {
    int y, mo, d, h, mi, sec;
    if (sscanf(s, "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &sec) != 6)
        return 0;
    if (y <= 1971) return 0; /* Go zero time (0001-01-01) => "no expiry" */
    int64_t t = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + sec;
    /* apply numeric offset if present (find last '+'/'-' after 'T') */
    const char *tpos = strchr(s, 'T');
    const char *off = tpos ? strpbrk(tpos, "+-") : NULL;
    if (off) {
        int oh = 0, om = 0;
        if (sscanf(off + 1, "%d:%d", &oh, &om) >= 1) {
            int sign = *off == '-' ? -1 : 1;
            t -= sign * (oh * 3600 + om * 60);
        }
    }
    return t;
}

static void get_str(json_t *obj, const char *key, char *out, size_t cap) {
    json_t *v = json_object_get(obj, key);
    if (json_is_string(v))
        snprintf(out, cap, "%s", json_string_value(v));
    else if (cap)
        out[0] = '\0';
}

static bool get_key32(json_t *obj, const char *key, const char *prefix,
                      uint8_t out[32]) {
    json_t *v = json_object_get(obj, key);
    if (!json_is_string(v)) return false;
    return tsnet_key_parse(json_string_value(v), prefix, out);
}

/* Parse a peer's AllowedIPs into subnet routes: entries whose prefix is
 * broader than a host route (v4 </32, v6 </128) are advertised subnet routes
 * (e.g. "192.168.1.0/24"). Host routes are the peer's own addresses, already
 * parsed from Addresses. */
static int parse_allowed_routes(json_t *arr, tsnet_prefix *out, int max) {
    if (!json_is_array(arr)) return 0;
    int n = 0;
    size_t i;
    json_t *v;
    json_array_foreach(arr, i, v) {
        if (n >= max) break;
        if (!json_is_string(v)) continue;
        const char *s = json_string_value(v);
        const char *slash = strchr(s, '/');
        if (!slash) continue;
        char ip[64];
        size_t l = (size_t)(slash - s);
        if (l == 0 || l >= sizeof(ip)) continue;
        memcpy(ip, s, l);
        ip[l] = '\0';
        tsnet_addr net;
        if (!tsnet_parse_ip(ip, &net)) continue;
        int bits = atoi(slash + 1);
        int host = net.family == 4 ? 32 : 128;
        if (bits < 0 || bits > host) continue;
        if (bits == host) continue; /* host route = the peer's own address */
        out[n].net = net;
        out[n].bits = (uint8_t)bits;
        n++;
    }
    return n;
}

/* ---- node parsing -------------------------------------------------------- */

/* strip the "/32"-style suffix, keep the CIDR string too */
static int parse_addresses(json_t *arr, tsnet_addr *ips, int max_ips,
                           char cidrs[][64], int max_cidrs) {
    if (!json_is_array(arr)) return 0;
    int n = 0;
    size_t i;
    json_t *v;
    json_array_foreach(arr, i, v) {
        if (n >= max_ips) break;
        if (!json_is_string(v)) continue;
        const char *s = json_string_value(v);
        char ip[64];
        const char *slash = strchr(s, '/');
        size_t l = slash ? (size_t)(slash - s) : strlen(s);
        if (l >= sizeof(ip)) continue;
        memcpy(ip, s, l);
        ip[l] = '\0';
        if (!tsnet_parse_ip(ip, &ips[n])) continue;
        if (cidrs && n < max_cidrs) snprintf(cidrs[n], 64, "%s", s);
        n++;
    }
    return n;
}

static void strip_trailing_dot(char *s) {
    size_t l = strlen(s);
    if (l > 0 && s[l - 1] == '.') s[l - 1] = '\0';
}

/* legacy "DERP": "127.3.3.40:N" (tailcfg.go, DerpMagicIP) */
static int parse_home_derp(json_t *node) {
    json_t *v = json_object_get(node, "HomeDERP");
    if (json_is_integer(v)) return (int)json_integer_value(v);
    v = json_object_get(node, "DERP");
    if (json_is_string(v)) {
        const char *s = json_string_value(v);
        const char *colon = strrchr(s, ':');
        if (colon) return atoi(colon + 1);
    }
    return 0;
}

static void parse_peer(json_t *node, tsnet_peer *p) {
    memset(p, 0, sizeof(*p));
    json_t *v = json_object_get(node, "ID");
    if (json_is_integer(v)) p->id = json_integer_value(v);
    get_str(node, "Name", p->name, sizeof(p->name));
    strip_trailing_dot(p->name);
    get_key32(node, "Key", "nodekey:", p->node_key);
    p->has_disco = get_key32(node, "DiscoKey", "discokey:", p->disco_key);
    p->n_addrs = parse_addresses(json_object_get(node, "Addresses"), p->addrs,
                                 TSNET_MAX_PEER_ADDRS, NULL, 0);
    p->n_routes = parse_allowed_routes(json_object_get(node, "AllowedIPs"),
                                       p->routes, TSNET_MAX_PEER_ROUTES);
    p->home_derp = parse_home_derp(node);

    json_t *eps = json_object_get(node, "Endpoints");
    if (json_is_array(eps)) {
        size_t i;
        json_t *e;
        json_array_foreach(eps, i, e) {
            if (p->n_endpoints >= TSNET_MAX_ENDPOINTS) break;
            if (!json_is_string(e)) continue;
            if (tsnet_parse_ipport(json_string_value(e),
                                   &p->endpoints[p->n_endpoints].addr))
                p->n_endpoints++;
        }
    }
    v = json_object_get(node, "Online");
    p->online = json_is_boolean(v) ? json_boolean_value(v) : true;
    v = json_object_get(node, "KeyExpiry");
    if (json_is_string(v))
        p->key_expiry = tsnet_parse_rfc3339(json_string_value(v));
}

static tsnet_peer *find_peer(tsnet_netmap *nm, int64_t id) {
    for (int i = 0; i < nm->n_peers; i++)
        if (nm->peers[i].id == id) return &nm->peers[i];
    return NULL;
}

static void upsert_peer(tsnet_netmap *nm, json_t *node) {
    json_t *v = json_object_get(node, "ID");
    if (!json_is_integer(v)) return;
    tsnet_peer *p = find_peer(nm, json_integer_value(v));
    if (!p) {
        if (nm->n_peers >= TSNET_MAX_PEERS) {
            TSNET_LOGW("netmap: peer table full, dropping peer");
            return;
        }
        p = &nm->peers[nm->n_peers++];
    }
    parse_peer(node, p);
}

static void remove_peer(tsnet_netmap *nm, int64_t id) {
    for (int i = 0; i < nm->n_peers; i++) {
        if (nm->peers[i].id == id) {
            nm->peers[i] = nm->peers[nm->n_peers - 1];
            nm->n_peers--;
            return;
        }
    }
}

static void parse_self(tsnet_netmap *nm, json_t *node) {
    nm->has_self = true;
    json_t *v = json_object_get(node, "ID");
    if (json_is_integer(v)) nm->self_id = json_integer_value(v);
    get_str(node, "Name", nm->self_name, sizeof(nm->self_name));
    strip_trailing_dot(nm->self_name);
    get_key32(node, "Key", "nodekey:", nm->self_node_key);
    nm->n_self_addrs =
        parse_addresses(json_object_get(node, "Addresses"), nm->self_ips,
                        TSNET_MAX_PEER_ADDRS, nm->self_addrs,
                        TSNET_MAX_PEER_ADDRS);
    nm->home_derp = parse_home_derp(node);
    v = json_object_get(node, "KeyExpiry");
    if (json_is_string(v))
        nm->self_key_expiry = tsnet_parse_rfc3339(json_string_value(v));
}

/* ---- DERP map ------------------------------------------------------------ */

static void parse_derpmap(tsnet_netmap *nm, json_t *dm) {
    json_t *regions = json_object_get(dm, "Regions");
    if (!json_is_object(regions)) return;
    memset(&nm->derpmap, 0, sizeof(nm->derpmap));
    nm->has_derpmap = true;
    const char *key;
    json_t *reg;
    json_object_foreach(regions, key, reg) {
        if (nm->derpmap.n_regions >= TSNET_MAX_DERP_REGIONS) break;
        tsnet_derp_region *r = &nm->derpmap.regions[nm->derpmap.n_regions];
        memset(r, 0, sizeof(*r));
        json_t *v = json_object_get(reg, "RegionID");
        r->id = json_is_integer(v) ? (int)json_integer_value(v) : atoi(key);
        get_str(reg, "RegionCode", r->code, sizeof(r->code));
        json_t *nodes = json_object_get(reg, "Nodes");
        if (json_is_array(nodes)) {
            size_t i;
            json_t *nd;
            json_array_foreach(nodes, i, nd) {
                if (r->n_nodes >= TSNET_MAX_DERP_NODES) break;
                tsnet_derp_node *dn = &r->nodes[r->n_nodes];
                memset(dn, 0, sizeof(*dn));
                get_str(nd, "Name", dn->name, sizeof(dn->name));
                get_str(nd, "HostName", dn->hostname, sizeof(dn->hostname));
                get_str(nd, "CertName", dn->cert_name, sizeof(dn->cert_name));
                get_str(nd, "IPv4", dn->ipv4, sizeof(dn->ipv4));
                get_str(nd, "IPv6", dn->ipv6, sizeof(dn->ipv6));
                v = json_object_get(nd, "STUNPort");
                dn->stun_port = json_is_integer(v)
                                    ? (int)json_integer_value(v)
                                    : 0;
                if (dn->stun_port == 0) dn->stun_port = 3478;
                v = json_object_get(nd, "STUNOnly");
                dn->stun_only = json_is_true(v);
                v = json_object_get(nd, "DERPPort");
                dn->derp_port =
                    json_is_integer(v) ? (int)json_integer_value(v) : 0;
                if (dn->derp_port == 0) dn->derp_port = 443;
                v = json_object_get(nd, "CanPort80");
                dn->can_port80 = json_is_true(v);
                r->n_nodes++;
            }
        }
        nm->derpmap.n_regions++;
    }
}

/* ---- PeersChangedPatch (tailcfg.go) ----------------------------- */

static void apply_patch(tsnet_netmap *nm, json_t *patch) {
    json_t *v = json_object_get(patch, "NodeID");
    if (!json_is_integer(v)) return;
    tsnet_peer *p = find_peer(nm, json_integer_value(v));
    if (!p) return;
    v = json_object_get(patch, "DERPRegion");
    if (json_is_integer(v)) p->home_derp = (int)json_integer_value(v);
    v = json_object_get(patch, "Endpoints");
    if (json_is_array(v)) {
        p->n_endpoints = 0;
        size_t i;
        json_t *e;
        json_array_foreach(v, i, e) {
            if (p->n_endpoints >= TSNET_MAX_ENDPOINTS) break;
            if (json_is_string(e) &&
                tsnet_parse_ipport(json_string_value(e),
                                   &p->endpoints[p->n_endpoints].addr))
                p->n_endpoints++;
        }
    }
    get_key32(patch, "Key", "nodekey:", p->node_key);
    if (get_key32(patch, "DiscoKey", "discokey:", p->disco_key))
        p->has_disco = true;
    v = json_object_get(patch, "Online");
    if (json_is_boolean(v)) p->online = json_boolean_value(v);
    v = json_object_get(patch, "KeyExpiry");
    if (json_is_string(v))
        p->key_expiry = tsnet_parse_rfc3339(json_string_value(v));
}

/* ---- MapResponse --------------------------------------------------------- */

int tsnet_netmap_apply(tsnet_netmap *nm, const char *json, size_t len,
                       tsnet_map_msg *msg) {
    if (msg) memset(msg, 0, sizeof(*msg));
    json_error_t err;
    json_t *root = json_loadb(json, len, 0, &err);
    if (!root) {
        TSNET_LOGE("netmap: bad JSON at %d: %s", err.line, err.text);
        return TSNET_E_PROTO;
    }

    json_t *v = json_object_get(root, "KeepAlive");
    if (json_is_true(v) && msg) msg->keep_alive = true;

    v = json_object_get(root, "Node");
    if (json_is_object(v)) parse_self(nm, v);

    v = json_object_get(root, "DERPMap");
    if (json_is_object(v)) parse_derpmap(nm, v);

    v = json_object_get(root, "Peers");
    if (json_is_array(v)) {
        /* full peer list: replace */
        nm->n_peers = 0;
        size_t i;
        json_t *node;
        json_array_foreach(v, i, node) upsert_peer(nm, node);
    }

    v = json_object_get(root, "PeersChanged");
    if (json_is_array(v)) {
        size_t i;
        json_t *node;
        json_array_foreach(v, i, node) upsert_peer(nm, node);
    }

    v = json_object_get(root, "PeersRemoved");
    if (json_is_array(v)) {
        size_t i;
        json_t *id;
        json_array_foreach(v, i, id) {
            if (json_is_integer(id)) remove_peer(nm, json_integer_value(id));
        }
    }

    v = json_object_get(root, "PeersChangedPatch");
    if (json_is_array(v)) {
        size_t i;
        json_t *patch;
        json_array_foreach(v, i, patch) {
            if (json_is_object(patch)) apply_patch(nm, patch);
        }
    }

    v = json_object_get(root, "OnlineChange");
    if (json_is_object(v)) {
        const char *key;
        json_t *on;
        json_object_foreach(v, key, on) {
            tsnet_peer *p = find_peer(nm, strtoll(key, NULL, 10));
            if (p && json_is_boolean(on)) p->online = json_boolean_value(on);
        }
    }

    v = json_object_get(root, "Domain");
    if (json_is_string(v))
        snprintf(nm->domain, sizeof(nm->domain), "%s", json_string_value(v));

    if (msg) {
        json_t *pr = json_object_get(root, "PingRequest");
        if (json_is_object(pr)) {
            get_str(pr, "URL", msg->ping_url, sizeof(msg->ping_url));
            msg->ping_log = json_is_true(json_object_get(pr, "Log"));
        }
        get_str(root, "PopBrowserURL", msg->pop_browser_url,
                sizeof(msg->pop_browser_url));
        get_str(root, "MapSessionHandle", msg->map_session_handle,
                sizeof(msg->map_session_handle));
        v = json_object_get(root, "Seq");
        if (json_is_integer(v)) msg->seq = json_integer_value(v);
    }

    json_decref(root);
    return TSNET_OK;
}

void tsnet_netmap_sync_registry(const tsnet_netmap *nm) {
    tsnet_registry_clear();
    for (int i = 0; i < nm->n_peers; i++) {
        const tsnet_peer *p = &nm->peers[i];
        for (int j = 0; j < p->n_addrs; j++)
            tsnet_registry_add_addr(&p->addrs[j]);
        for (int j = 0; j < p->n_routes; j++)
            tsnet_registry_add_route(&p->routes[j]); /* subnet routes */
        if (p->name[0] && p->n_addrs > 0) {
            tsnet_registry_add_name(p->name, p->addrs, p->n_addrs);
            /* short name: first label of the FQDN */
            char shortn[128];
            snprintf(shortn, sizeof(shortn), "%s", p->name);
            char *dot = strchr(shortn, '.');
            if (dot) {
                *dot = '\0';
                tsnet_registry_add_name(shortn, p->addrs, p->n_addrs);
            }
        }
    }
}
