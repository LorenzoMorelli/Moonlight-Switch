#include "tsnet_wgif.h"

#include "lwip/netif_ts0.h"
#include "platform/platform.h"
#include "tsnet/tsnet.h"
#include "util/log.h"

/* patched copy from gen/wg (scripts/gen-wg.cmake) */
#include "wireguard.h"
#include "crypto.h"

#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "lwip/tcpip.h"
#include "lwip/timeouts.h"

#include <pthread.h>
#include <string.h>

#define WGIF_TIMER_MSECS 400 /* wireguardif.c:50 */
#define WG_HDR_LEN 16        /* struct message_transport_data header */

/* AllowedIPs bookkeeping, indexed like device.peers */
#define WGIF_MAX_ROUTES 4
struct peer_meta {
    bool valid;
    uint8_t node_key[32];
    tsnet_addr addrs[4];
    int n_addrs;
    tsnet_prefix routes[WGIF_MAX_ROUTES]; /* subnet routes via this peer */
    int n_routes;
};

static struct {
    struct wireguard_device dev;
    struct peer_meta meta[WIREGUARD_MAX_PEERS];
    tsnet_wgif_tx_fn tx;
    void *tx_ud;
    bool up;
    /* guards meta[] identity/validity against peer_up(), which runs off
     * the tcpip thread */
    pthread_mutex_t meta_mu;
} g;

/* ---- helpers (tcpip thread only, unless stated) ------------------------- */

static struct wireguard_peer *peer_by_key(const uint8_t node_key[32]) {
    for (int i = 0; i < WIREGUARD_MAX_PEERS; i++) {
        if (g.meta[i].valid &&
            memcmp(g.meta[i].node_key, node_key, 32) == 0)
            return &g.dev.peers[i];
    }
    return NULL;
}

static int peer_index_of(struct wireguard_peer *p) {
    return (int)(p - g.dev.peers);
}

/* parse src/dst IP of a raw IP packet into tsnet_addr (ip only) */
static bool packet_addr(const uint8_t *pkt, size_t len, bool dst,
                        tsnet_addr *out) {
    memset(out, 0, sizeof(*out));
    if (len < 20) return false;
    uint8_t ver = pkt[0] >> 4;
    if (ver == 4) {
        out->family = 4;
        memcpy(out->ip, pkt + (dst ? 16 : 12), 4);
        return true;
    }
    if (ver == 6 && len >= 40) {
        out->family = 6;
        memcpy(out->ip, pkt + (dst ? 24 : 8), 16);
        return true;
    }
    return false;
}

static struct wireguard_peer *peer_by_ip(const tsnet_addr *a) {
    for (int i = 0; i < WIREGUARD_MAX_PEERS; i++) {
        if (!g.meta[i].valid) continue;
        for (int j = 0; j < g.meta[i].n_addrs; j++) {
            if (tsnet_addr_eq_ip(&g.meta[i].addrs[j], a))
                return &g.dev.peers[i];
        }
    }
    /* not a peer's own address: try advertised subnet routes (a LAN host
     * reachable via a subnet-router peer, e.g. 192.168.1.200) */
    for (int i = 0; i < WIREGUARD_MAX_PEERS; i++) {
        if (!g.meta[i].valid) continue;
        for (int j = 0; j < g.meta[i].n_routes; j++)
            if (tsnet_addr_in_prefix(a, &g.meta[i].routes[j]))
                return &g.dev.peers[i];
    }
    return NULL;
}

/* Retry a handshake initiation faster than the WireGuard-spec REKEY_TIMEOUT
 * (5 s). On the first connection to a peer the initial init is often dropped
 * (the peer is still receiving our just-published disco key / disco is still
 * settling), and a 5 s wait for the retransmit exceeds Moonlight's TCP connect
 * timeout, so the session comes up only after the app has given up. A ~1 s
 * retry catches the peer-ready moment quickly; once a session exists no more
 * initiations are sent, so there is no steady-state cost. */
#define WGIF_INIT_RETRY_MS 1000
static bool wgif_can_send_initiation(struct wireguard_peer *peer) {
    return (peer->last_initiation_tx == 0) ||
           (wireguard_sys_now() - peer->last_initiation_tx >= WGIF_INIT_RETRY_MS);
}

static void wgif_start_handshake(struct wireguard_peer *peer) {
    struct message_handshake_initiation msg;
    if (!wireguard_create_handshake_initiation(&g.dev, peer, &msg)) return;
    peer->send_handshake = false;
    peer->last_initiation_tx = wireguard_sys_now();
    memcpy(peer->handshake_mac1, msg.mac1, WIREGUARD_COOKIE_LEN);
    peer->handshake_mac1_valid = true;
    g.tx(g.meta[peer_index_of(peer)].node_key, (const uint8_t *)&msg,
         sizeof(msg), g.tx_ud);
    TSNET_LOGI("wgif: handshake initiation sent to peer %d",
               peer_index_of(peer));
}

/* encrypt + send one IP packet (or keepalive when pkt==NULL) — adapted
 * from wireguardif.c:92-186 with a flat output buffer */
static int wgif_send_data(struct wireguard_peer *peer, const uint8_t *pkt,
                          size_t len) {
    struct wireguard_keypair *keypair = &peer->curr_keypair;
    if (keypair->valid && !keypair->initiator && keypair->last_rx == 0)
        keypair = &peer->prev_keypair;
    if (!keypair->valid || !(keypair->initiator || keypair->last_rx != 0)) {
        peer->active = true;
        peer->send_handshake = true;
        if (wgif_can_send_initiation(peer)) wgif_start_handshake(peer);
        return TSNET_E_STATE;
    }
    if (wireguard_expired(keypair->keypair_millis, REJECT_AFTER_TIME) ||
        keypair->sending_counter >= REJECT_AFTER_MESSAGES) {
        keypair_destroy(keypair);
        peer->send_handshake = true;
        return TSNET_E_STATE;
    }

    size_t padded = (len + 15) & ~(size_t)15;
    uint8_t buf[TSNET_WGIF_MAX_PKT];
    if (WG_HDR_LEN + padded + WIREGUARD_AUTHTAG_LEN > sizeof(buf))
        return TSNET_E_INVAL;
    struct message_transport_data *hdr = (struct message_transport_data *)buf;
    memset(buf, 0, WG_HDR_LEN + padded);
    hdr->type = MESSAGE_TRANSPORT_DATA;
    hdr->receiver = keypair->remote_index;
    U64TO8_LITTLE(hdr->counter, keypair->sending_counter);
    if (pkt && len) memcpy(hdr->enc_packet, pkt, len);
    wireguard_encrypt_packet(hdr->enc_packet, hdr->enc_packet, padded,
                             keypair);

    uint32_t now = wireguard_sys_now();
    peer->last_tx = now;
    keypair->last_tx = now;
    g.tx(g.meta[peer_index_of(peer)].node_key, buf,
         WG_HDR_LEN + padded + WIREGUARD_AUTHTAG_LEN, g.tx_ud);

    if (keypair->sending_counter >= REKEY_AFTER_MESSAGES ||
        (keypair->initiator &&
         wireguard_expired(keypair->keypair_millis, REKEY_AFTER_TIME)))
        peer->send_handshake = true;
    return TSNET_OK;
}

/* ---- ts0 output hook (tcpip thread) ------------------------------------- */

static void ts0_out(const uint8_t *buf, uint16_t len, void *ctx) {
    (void)ctx;
    tsnet_addr dst;
    if (!packet_addr(buf, len, true, &dst)) return;
    struct wireguard_peer *peer = peer_by_ip(&dst);
    if (!peer) {
        TSNET_LOGI("wgif: no peer for destination, dropping %u bytes", len);
        return;
    }
    wgif_send_data(peer, buf, len);
}

/* ---- inbound (posted to tcpip thread) ----------------------------------- */

static void wgif_process_rx(void *arg) {
    struct pbuf *p = arg;
    /* tsnet_wgif_rx allocates from PBUF_POOL; a datagram larger than one
     * pool buffer would be chained and p->len < p->tot_len, so processing
     * only the first segment would corrupt the frame. Our datagrams are
     * <= MTU+overhead < PBUF_POOL_BUFSIZE so this never chains; guard
     * anyway and drop a chained (oversized/malformed) datagram. */
    if (p->len != p->tot_len) {
        TSNET_LOGD("wgif: dropping chained rx pbuf (%u/%u)", p->len,
                   p->tot_len);
        pbuf_free(p);
        return;
    }
    uint8_t *data = p->payload;
    size_t len = p->len;
    struct wireguard_peer *peer;

    /* Handshake messages (types 1-3) are low-volume and worth an INFO line —
     * they show the peer answering us over DERP. Transport data (type 4) fires
     * per packet: at video rate the logger's synchronous fflush-to-SD would
     * starve the tcpip thread and collapse throughput, so keep it at DEBUG. */
    int mtype = wireguard_get_message_type(data, len);
    if (mtype == MESSAGE_TRANSPORT_DATA)
        TSNET_LOGD("wgif: rx wg msg type=%d len=%zu", mtype, len);
    else
        TSNET_LOGI("wgif: rx wg msg type=%d len=%zu", mtype, len);
    switch (mtype) {
    case MESSAGE_HANDSHAKE_INITIATION: {
        struct message_handshake_initiation *msg = (void *)data;
        if (!wireguard_check_mac1(&g.dev, data,
                                  sizeof(*msg) - 2 * WIREGUARD_COOKIE_LEN,
                                  msg->mac1))
            break;
        peer = wireguard_process_initiation_message(&g.dev, msg);
        if (peer) {
            struct message_handshake_response resp;
            if (wireguard_create_handshake_response(&g.dev, peer, &resp)) {
                wireguard_start_session(peer, false);
                g.tx(g.meta[peer_index_of(peer)].node_key,
                     (const uint8_t *)&resp, sizeof(resp), g.tx_ud);
                wgif_send_data(peer, NULL, 0); /* keepalive */
            }
        }
        break;
    }
    case MESSAGE_HANDSHAKE_RESPONSE: {
        struct message_handshake_response *msg = (void *)data;
        if (!wireguard_check_mac1(&g.dev, data,
                                  sizeof(*msg) - 2 * WIREGUARD_COOKIE_LEN,
                                  msg->mac1))
            break;
        peer = peer_lookup_by_handshake(&g.dev, msg->receiver);
        if (peer && wireguard_process_handshake_response(&g.dev, peer, msg)) {
            wireguard_start_session(peer, true);
            /* Clear the pending-handshake flag: during the ~tens-of-ms rekey
             * window the many in-flight data packets keep re-setting
             * send_handshake on the expiring keypair (wgif_send_data). Without
             * this it stays set after the fresh session is up, so once
             * WGIF_INIT_RETRY_MS elapses the timer fires a *second*, spurious
             * handshake ~1 s later — rekeying twice per interval and risking a
             * brief keypair mismatch (dropped packets) on the peer. */
            peer->send_handshake = false;
            TSNET_LOGI("wgif: session established with peer %d",
                       peer_index_of(peer));
            wgif_send_data(peer, NULL, 0); /* keepalive confirms session */
        }
        break;
    }
    case MESSAGE_COOKIE_REPLY: {
        struct message_cookie_reply *msg = (void *)data;
        peer = peer_lookup_by_handshake(&g.dev, msg->receiver);
        if (peer) wireguard_process_cookie_message(&g.dev, peer, msg);
        break;
    }
    case MESSAGE_TRANSPORT_DATA: {
        if (len < WG_HDR_LEN + WIREGUARD_AUTHTAG_LEN) break;
        struct message_transport_data *msg = (void *)data;
        peer = peer_lookup_by_receiver(&g.dev, msg->receiver);
        if (!peer) {
            break;
        }
        struct wireguard_keypair *keypair =
            get_peer_keypair_for_idx(peer, msg->receiver);
        if (!keypair) {
            break;
        }
        if (!keypair->receiving_valid ||
            wireguard_expired(keypair->keypair_millis, REJECT_AFTER_TIME)) {
            keypair_destroy(keypair);
            break;
        }
        uint64_t nonce = U8TO64_LITTLE(msg->counter);
        size_t ct_len = len - WG_HDR_LEN;
        uint8_t out[TSNET_WGIF_MAX_PKT];
        if (ct_len > sizeof(out)) break;
        if (!wireguard_decrypt_packet(out, msg->enc_packet, ct_len, nonce,
                                      keypair)) {
            break;
        }
        uint32_t now = wireguard_sys_now();
        keypair->last_rx = now;
        peer->last_rx = now;
        keypair_update(peer, keypair);
        if (keypair->initiator &&
            wireguard_expired(keypair->keypair_millis,
                              REJECT_AFTER_TIME - peer->keepalive_interval -
                                  REKEY_TIMEOUT))
            peer->send_handshake = true;

        size_t pt_len = ct_len - WIREGUARD_AUTHTAG_LEN;
        if (pt_len == 0) break; /* keepalive */
        if (!wireguard_check_replay(keypair, nonce)) {
            break;
        }

        /* cryptokey routing: inner source must be one of the peer's IPs */
        tsnet_addr src;
        if (!packet_addr(out, pt_len, false, &src)) break;
        int pi = peer_index_of(peer);
        bool ok = false;
        for (int j = 0; j < g.meta[pi].n_addrs && !ok; j++)
            ok = tsnet_addr_eq_ip(&g.meta[pi].addrs[j], &src);
        /* also accept sources inside the peer's advertised subnet routes, so
         * a reply from a LAN host behind a subnet router (e.g. 192.168.1.200)
         * is not dropped by cryptokey routing */
        for (int j = 0; j < g.meta[pi].n_routes && !ok; j++)
            ok = tsnet_addr_in_prefix(&src, &g.meta[pi].routes[j]);
        if (!ok) {
            TSNET_LOGD("wgif: inner source not in AllowedIPs, dropped");
            break;
        }
        /* actual IP length from header (v4: total length; v6: 40+payload) */
        size_t ip_len = pt_len;
        if ((out[0] >> 4) == 4)
            ip_len = ((size_t)out[2] << 8) | out[3];
        else if ((out[0] >> 4) == 6)
            ip_len = 40 + (((size_t)out[4] << 8) | out[5]);
        if (ip_len > pt_len) break;
        tsnet_ts0_input(out, (uint16_t)ip_len);
        break;
    }
    default:
        break;
    }
    pbuf_free(p);
}

void tsnet_wgif_rx(const uint8_t *pkt, size_t len) {
    if (!g.up || len == 0 || len > TSNET_WGIF_MAX_PKT + 64) return;
    struct pbuf *p = pbuf_alloc(PBUF_RAW, (uint16_t)len, PBUF_POOL);
    if (!p) return;
    pbuf_take(p, pkt, (uint16_t)len);
    if (tcpip_callback(wgif_process_rx, p) != ERR_OK) pbuf_free(p);
}

/* ---- periodic timer (tcpip thread, wireguardif.c:833-878) --------------- */

static void wgif_tmr(void *arg) {
    (void)arg;
    sys_timeout(WGIF_TIMER_MSECS, wgif_tmr, NULL);
    for (int i = 0; i < WIREGUARD_MAX_PEERS; i++) {
        struct wireguard_peer *peer = &g.dev.peers[i];
        if (!peer->valid) continue;
        if (peer->curr_keypair.valid &&
            wireguard_expired(peer->curr_keypair.keypair_millis,
                              REJECT_AFTER_TIME * 3)) {
            keypair_destroy(&peer->next_keypair);
            keypair_destroy(&peer->curr_keypair);
            keypair_destroy(&peer->prev_keypair);
        }
        if (peer->curr_keypair.valid &&
            (wireguard_expired(peer->curr_keypair.keypair_millis,
                               REJECT_AFTER_TIME) ||
             peer->curr_keypair.sending_counter >= REJECT_AFTER_MESSAGES))
            keypair_destroy(&peer->curr_keypair);
        /* keepalive */
        if (peer->keepalive_interval > 0 &&
            (peer->curr_keypair.valid || peer->prev_keypair.valid) &&
            wireguard_expired(peer->last_tx, peer->keepalive_interval))
            wgif_send_data(peer, NULL, 0);
        /* handshake */
        bool want_hs =
            peer->send_handshake ||
            (peer->curr_keypair.valid && !peer->curr_keypair.initiator &&
             wireguard_expired(peer->curr_keypair.keypair_millis,
                               REJECT_AFTER_TIME -
                                   peer->keepalive_interval)) ||
            (!peer->curr_keypair.valid && peer->active);
        if (want_hs && wgif_can_send_initiation(peer))
            wgif_start_handshake(peer);
    }
}

/* ---- setup (any thread; peers mutate via tcpip callbacks) ---------------- */

struct set_peer_msg {
    uint8_t node_key[32];
    tsnet_addr addrs[4];
    int n_addrs;
    tsnet_prefix routes[WGIF_MAX_ROUTES];
    int n_routes;
    int remove;
    int done;
    sys_sem_t sem;
};

static void set_peer_cb(void *arg) {
    struct set_peer_msg *m = arg;
    struct wireguard_peer *peer = peer_by_key(m->node_key);
    /* hold meta_mu around identity changes so diagnostic readers never see
     * a node_key mid-crypto_zero */
    if (m->remove) {
        if (peer) {
            int i = peer_index_of(peer);
            pthread_mutex_lock(&g.meta_mu);
            g.meta[i].valid = false;
            pthread_mutex_unlock(&g.meta_mu);
            crypto_zero(peer, sizeof(*peer));
            peer->valid = false;
        }
    } else {
        if (!peer) {
            peer = peer_alloc(&g.dev);
            if (peer && wireguard_peer_init(&g.dev, peer, m->node_key, NULL)) {
                peer->keepalive_interval = KEEPALIVE_TIMEOUT;
                int i = peer_index_of(peer);
                pthread_mutex_lock(&g.meta_mu);
                memcpy(g.meta[i].node_key, m->node_key, 32);
                g.meta[i].valid = true;
                pthread_mutex_unlock(&g.meta_mu);
            } else {
                peer = NULL;
            }
        }
        if (peer) {
            int i = peer_index_of(peer);
            m->n_addrs = m->n_addrs > 4 ? 4 : m->n_addrs;
            if (m->n_routes > WGIF_MAX_ROUTES) m->n_routes = WGIF_MAX_ROUTES;
            pthread_mutex_lock(&g.meta_mu);
            memcpy(g.meta[i].addrs, m->addrs,
                   (size_t)m->n_addrs * sizeof(tsnet_addr));
            g.meta[i].n_addrs = m->n_addrs;
            memcpy(g.meta[i].routes, m->routes,
                   (size_t)m->n_routes * sizeof(tsnet_prefix));
            g.meta[i].n_routes = m->n_routes;
            pthread_mutex_unlock(&g.meta_mu);
        }
    }
    sys_sem_signal(&m->sem);
}

static int run_peer_op(struct set_peer_msg *m) {
    if (sys_sem_new(&m->sem, 0) != ERR_OK) return TSNET_E_NOMEM;
    if (tcpip_callback(set_peer_cb, m) != ERR_OK) {
        sys_sem_free(&m->sem);
        return TSNET_E_NOMEM;
    }
    sys_arch_sem_wait(&m->sem, 0);
    sys_sem_free(&m->sem);
    return TSNET_OK;
}

int tsnet_wgif_set_peer(const uint8_t node_key[32], const tsnet_addr *addrs,
                        int n_addrs, const tsnet_prefix *routes,
                        int n_routes) {
    if (!g.up) return TSNET_E_STATE;
    struct set_peer_msg m;
    memset(&m, 0, sizeof(m));
    memcpy(m.node_key, node_key, 32);
    m.n_addrs = n_addrs > 4 ? 4 : n_addrs;
    memcpy(m.addrs, addrs, (size_t)m.n_addrs * sizeof(*addrs));
    m.n_routes = n_routes > WGIF_MAX_ROUTES ? WGIF_MAX_ROUTES : n_routes;
    if (m.n_routes > 0)
        memcpy(m.routes, routes, (size_t)m.n_routes * sizeof(*routes));
    return run_peer_op(&m);
}

int tsnet_wgif_remove_peer(const uint8_t node_key[32]) {
    if (!g.up) return TSNET_E_STATE;
    struct set_peer_msg m;
    memset(&m, 0, sizeof(m));
    memcpy(m.node_key, node_key, 32);
    m.remove = 1;
    return run_peer_op(&m);
}

bool tsnet_wgif_peer_up(const uint8_t node_key[32]) {
    /* diagnostic read off the tcpip thread: find the peer index under
     * meta_mu (stable identity), then read the keypair validity flags. The
     * keypair bools may still change under us, but a bool read is atomic
     * enough for a status indicator and cannot fault. */
    pthread_mutex_lock(&g.meta_mu);
    int idx = -1;
    for (int i = 0; i < WIREGUARD_MAX_PEERS; i++)
        if (g.meta[i].valid && memcmp(g.meta[i].node_key, node_key, 32) == 0) {
            idx = i;
            break;
        }
    pthread_mutex_unlock(&g.meta_mu);
    if (idx < 0) return false;
    struct wireguard_peer *peer = &g.dev.peers[idx];
    return peer->curr_keypair.valid || peer->prev_keypair.valid;
}

struct wgif_up_msg {
    int rc;
    sys_sem_t sem;
};

static uint8_t g_node_priv[32];

static void wgif_up_cb(void *arg) {
    struct wgif_up_msg *m = arg;
    wireguard_init();
    if (!wireguard_device_init(&g.dev, g_node_priv)) {
        m->rc = TSNET_E_STATE;
    } else {
        sys_timeout(WGIF_TIMER_MSECS, wgif_tmr, NULL);
        m->rc = TSNET_OK;
    }
    sys_sem_signal(&m->sem);
}

int tsnet_wgif_up(const uint8_t node_priv[32], tsnet_wgif_tx_fn tx, void *ud) {
    if (g.up) return TSNET_OK;
    pthread_mutex_init(&g.meta_mu, NULL);
    g.tx = tx;
    g.tx_ud = ud;
    memcpy(g_node_priv, node_priv, 32);

    struct wgif_up_msg m = {.rc = TSNET_E_IO};
    if (sys_sem_new(&m.sem, 0) != ERR_OK) return TSNET_E_NOMEM;
    if (tcpip_callback(wgif_up_cb, &m) != ERR_OK) {
        sys_sem_free(&m.sem);
        return TSNET_E_NOMEM;
    }
    sys_arch_sem_wait(&m.sem, 0);
    sys_sem_free(&m.sem);
    memset(g_node_priv, 0, sizeof(g_node_priv));
    if (m.rc != TSNET_OK) return m.rc;

    g.up = true;
    TSNET_LOGI("wgif: device up");
    return TSNET_OK;
}

/* called by netif_ts0 for every outgoing packet: exported for the engine */
tsnet_ts0_output_fn tsnet_wgif_ts0_output(void) { return ts0_out; }
