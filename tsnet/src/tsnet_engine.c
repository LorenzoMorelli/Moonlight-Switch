/* Engine: wires the control client, lwIP/ts0, WireGuard and magicsock into
 * the public tsnet_start/stop API. The control
 * client runs in a dedicated thread; the data plane lives on the lwIP
 * tcpip thread plus the DERP reader threads. */
#include "tsnet/tsnet.h"

#include "control/control.h"
#include "crypto/tscrypto.h"
#include "lwip/netif_ts0.h"
#include "magicsock/magicsock.h"
#include "platform/platform.h"
#include "shim/classify.h"
#include "util/keyfile.h"
#include "util/thread.h"
#include "util/log.h"
#include "wg/tsnet_wgif.h"

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static struct {
    bool running;
    pthread_t control_thread;
    tsnet_control *ctl;
    tsnet_events ev;
    volatile tsnet_state state;

    bool dataplane_up;
    char self_ip4[20];
    char state_dir[256];
    char ca_file[256];

    /* peer snapshot for the UI */
    pthread_mutex_t peers_mu;
    tsnet_peer_info peers[TSNET_MAX_PEERS];
    uint8_t peer_keys[TSNET_MAX_PEERS][32];
    int n_peers;
} g;

static void wg_tx(const uint8_t peer_node_key[32], const uint8_t *pkt,
                  size_t len, void *ud) {
    (void)ud;
    tsnet_magicsock_send_wg(peer_node_key, pkt, len, NULL);
}

static void on_endpoints(const char **eps, int n, void *ud) {
    (void)ud;
    if (g.ctl) tsnet_control_set_endpoints(g.ctl, eps, n);
}

static void on_ctl_state(tsnet_state st, const char *detail, void *ud) {
    (void)ud;
    g.state = st;
    if (g.ev.on_state) g.ev.on_state(st, detail, g.ev.ud);
}

static void on_ctl_authurl(const char *url, void *ud) {
    (void)ud;
    if (g.ev.on_authurl) g.ev.on_authurl(url, g.ev.ud);
}

static int bring_up_dataplane(const tsnet_netmap *nm) {
    if (nm->n_self_addrs == 0) return TSNET_E_STATE;
    const char *v4 = NULL, *v6 = NULL;
    for (int i = 0; i < nm->n_self_addrs; i++) {
        if (nm->self_ips[i].family == 4 && !v4) v4 = nm->self_addrs[i];
        if (nm->self_ips[i].family == 6 && !v6) v6 = nm->self_addrs[i];
    }
    if (!v4) return TSNET_E_STATE;

    int rc = tsnet_ts0_up(v4, v6, tsnet_wgif_ts0_output(), NULL);
    if (rc != TSNET_OK) return rc;

    uint8_t node_priv[32], disco_priv[32];
    char path[512];
    snprintf(path, sizeof(path), "%s/node.key", g.state_dir);
    if (tsnet_keyfile_load(path, node_priv) != TSNET_OK) return TSNET_E_IO;
    snprintf(path, sizeof(path), "%s/disco.key", g.state_dir);
    if (tsnet_keyfile_load(path, disco_priv) != TSNET_OK) return TSNET_E_IO;

    rc = tsnet_wgif_up(node_priv, wg_tx, NULL);
    if (rc == TSNET_OK) {
        tsnet_magicsock_set_endpoints_cb(on_endpoints, NULL);
        rc = tsnet_magicsock_start(node_priv, disco_priv,
                                   g.ca_file[0] ? g.ca_file : NULL);
    }
    memset(node_priv, 0, sizeof(node_priv));
    memset(disco_priv, 0, sizeof(disco_priv));
    if (rc != TSNET_OK) return rc;

    snprintf(g.self_ip4, sizeof(g.self_ip4), "%u.%u.%u.%u",
             nm->self_ips[0].ip[0], nm->self_ips[0].ip[1],
             nm->self_ips[0].ip[2], nm->self_ips[0].ip[3]);
    g.dataplane_up = true;
    TSNET_LOGI("engine: data plane up, self %s", g.self_ip4);
    return TSNET_OK;
}

static void on_ctl_netmap(const tsnet_netmap *nm, void *ud) {
    (void)ud;
    if (!g.dataplane_up) {
        TSNET_LOGI("engine: first netmap (%d peers), bringing up data plane",
                   nm->n_peers);
        int rc = bring_up_dataplane(nm);
        if (rc != TSNET_OK) {
            TSNET_LOGE("engine: data plane bring-up failed (%s)",
                       tsnet_err_str(rc));
            return;
        }
        /* past the crash-prone bring-up: drop back to buffered logging */
        tsnet_log_set_sync(false);
    }
    tsnet_magicsock_set_netmap(nm);
    if (g.ctl)
        tsnet_control_set_preferred_derp(g.ctl, tsnet_magicsock_home_derp());

    /* refresh the UI snapshot */
    pthread_mutex_lock(&g.peers_mu);
    g.n_peers = 0;
    for (int i = 0; i < nm->n_peers && i < TSNET_MAX_PEERS; i++) {
        const tsnet_peer *p = &nm->peers[i];
        tsnet_peer_info *o = &g.peers[g.n_peers];
        memset(o, 0, sizeof(*o));
        snprintf(o->name, sizeof(o->name), "%s", p->name);
        for (int j = 0; j < p->n_addrs; j++) {
            if (p->addrs[j].family == 4) {
                snprintf(o->ip4, sizeof(o->ip4), "%u.%u.%u.%u",
                         p->addrs[j].ip[0], p->addrs[j].ip[1],
                         p->addrs[j].ip[2], p->addrs[j].ip[3]);
                break;
            }
        }
        o->online = p->online;
        o->session_up = tsnet_wgif_peer_up(p->node_key);
        tsnet_magicsock_peer_path(p->node_key, o->path, sizeof(o->path));
        memcpy(g.peer_keys[g.n_peers], p->node_key, 32);
        /* per-peer visibility: which tailnet IP maps to which host, and
         * whether a WireGuard session is up (diagnosing "can't reach the
         * Sunshine PC" — confirms the target IP is a real peer) */
        TSNET_LOGI("engine: peer %s ip=%s key=%02x%02x%02x%02x online=%d "
                   "session=%d path=%s",
                   o->name, o->ip4[0] ? o->ip4 : "-", p->node_key[0],
                   p->node_key[1], p->node_key[2], p->node_key[3], o->online,
                   o->session_up, o->path[0] ? o->path : "-");
        g.n_peers++;
    }
    pthread_mutex_unlock(&g.peers_mu);
    if (g.ev.on_peers) g.ev.on_peers(g.ev.ud);
}

static void *control_main(void *arg) {
    (void)arg;
    tsnet_control_run(g.ctl); /* blocks until stop or fatal */
    return NULL;
}

int tsnet_start(const tsnet_config *cfg, const tsnet_events *ev) {
    /* Crash-safe bring-up trace: on-device the only post-mortem we get is
     * this log, so fsync each line and checkpoint every step until the first
     * netmap. If the app aborts, the last line names the step that failed. */
    tsnet_log_set_sync(true);
    TSNET_LOGI("engine: tsnet_start (server=%s host=%s)",
               cfg->server_url ? cfg->server_url : "(default)",
               cfg->hostname ? cfg->hostname : "(default)");
    if (g.running) return TSNET_E_STATE;
    TSNET_LOGI("engine: crypto init");
    if (tsnet_crypto_init() != 0) return TSNET_E_STATE;
    if (ev) g.ev = *ev;
    pthread_mutex_init(&g.peers_mu, NULL);
    snprintf(g.state_dir, sizeof(g.state_dir), "%s",
             cfg->state_dir ? cfg->state_dir : "./tsnet-state");
    snprintf(g.ca_file, sizeof(g.ca_file), "%s", TSNET_CA_BUNDLE);
    if (cfg->log_level) tsnet_log_set_level(cfg->log_level);

    TSNET_LOGI("engine: lwip start (ca=%s)", g.ca_file[0] ? g.ca_file : "none");
    int rc = tsnet_lwip_start();
    if (rc != TSNET_OK) {
        TSNET_LOGE("engine: lwip start failed (%s)", tsnet_err_str(rc));
        return rc;
    }

    TSNET_LOGI("engine: control create");
    tsnet_control_cbs cbs = {
        .on_state = on_ctl_state,
        .on_authurl = on_ctl_authurl,
        .on_netmap = on_ctl_netmap,
    };
    rc = tsnet_control_create(&g.ctl, cfg, &cbs);
    if (rc != TSNET_OK) {
        TSNET_LOGE("engine: control create failed (%s)", tsnet_err_str(rc));
        return rc;
    }

    TSNET_LOGI("engine: spawn control thread");
    if (tsnet_thread_create(&g.control_thread, control_main, NULL) != 0) {
        tsnet_control_destroy(g.ctl);
        g.ctl = NULL;
        return TSNET_E_STATE;
    }
    g.running = true;
    TSNET_LOGI("engine: tsnet_start returning OK");
    return TSNET_OK;
}

void tsnet_stop(void) {
    if (!g.running) return;
    tsnet_control_stop(g.ctl);
    pthread_join(g.control_thread, NULL);
    tsnet_control_destroy(g.ctl);
    g.ctl = NULL;
    tsnet_magicsock_stop();
    tsnet_ts0_down();
    tsnet_registry_clear();
    g.running = false;
    g.dataplane_up = false;
    g.state = TSNET_ST_STOPPED;
    g.self_ip4[0] = '\0';
}

tsnet_state tsnet_get_state(void) { return g.state; }

int tsnet_get_peers(tsnet_peer_info *out, int max) {
    pthread_mutex_lock(&g.peers_mu);
    int n = g.n_peers < max ? g.n_peers : max;
    for (int i = 0; i < n; i++) {
        out[i] = g.peers[i];
        /* live fields */
        out[i].session_up = tsnet_wgif_peer_up(g.peer_keys[i]);
        tsnet_magicsock_peer_path(g.peer_keys[i], out[i].path,
                                  sizeof(out[i].path));
    }
    pthread_mutex_unlock(&g.peers_mu);
    return n;
}

void tsnet_get_self_ip4(char *out, size_t cap) {
    snprintf(out, cap, "%s", g.self_ip4);
}

bool tsnet_dest_is_tunnel(const char *ipv4) {
    if (!g.running || !ipv4) return false;
    unsigned a, b, c, d;
    if (sscanf(ipv4, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    tsnet_addr dst;
    memset(&dst, 0, sizeof(dst));
    dst.family = 4;
    dst.ip[0] = (uint8_t)a;
    dst.ip[1] = (uint8_t)b;
    dst.ip[2] = (uint8_t)c;
    dst.ip[3] = (uint8_t)d;
    return tsnet_classify(&dst) == TSNET_ROUTE_TUNNEL;
}
