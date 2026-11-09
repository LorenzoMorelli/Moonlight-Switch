#include "disco.h"

#include "crypto/tscrypto.h"
#include "platform/platform.h"

#include <string.h>

/* disco.go */
static const uint8_t MAGIC[6] = {0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac};
#define KEY_LEN 32
#define NONCE_LEN 24
#define HDR (6 + KEY_LEN + NONCE_LEN)

bool tsnet_disco_looks(const uint8_t *pkt, size_t len) {
    /* disco.go LooksLikeDiscoWrapper */
    return len >= HDR && memcmp(pkt, MAGIC, sizeof(MAGIC)) == 0;
}

static void put_addrport(uint8_t *p, const tsnet_addr *a) {
    /* ip16 (v4-mapped for IPv4) + u16 BE port (disco.go) */
    memset(p, 0, 16);
    if (a->family == 4) {
        p[10] = 0xff;
        p[11] = 0xff;
        memcpy(p + 12, a->ip, 4);
    } else {
        memcpy(p, a->ip, 16);
    }
    p[16] = (uint8_t)(a->port >> 8);
    p[17] = (uint8_t)a->port;
}

static void get_addrport(const uint8_t *p, tsnet_addr *a) {
    memset(a, 0, sizeof(*a));
    static const uint8_t v4map[12] = {0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0xff, 0xff};
    if (memcmp(p, v4map, 12) == 0) {
        a->family = 4;
        memcpy(a->ip, p + 12, 4);
    } else {
        a->family = 6;
        memcpy(a->ip, p, 16);
    }
    a->port = (uint16_t)(p[16] << 8 | p[17]);
}

static int marshal_payload(const tsnet_disco_msg *msg, uint8_t *pt,
                           size_t cap) {
    if (cap < 2) return -1;
    pt[0] = (uint8_t)msg->type;
    pt[1] = 0; /* version v0 */
    size_t n = 2;
    switch (msg->type) {
    case TSNET_DISCO_PING: /* TxID + NodeKey (disco.go) */
        if (cap < 2 + 12 + 32) return -1;
        memcpy(pt + n, msg->txid, 12);
        n += 12;
        memcpy(pt + n, msg->node_key, 32);
        n += 32;
        break;
    case TSNET_DISCO_PONG: /* TxID + ip16+port (disco.go) */
        if (cap < 2 + 12 + 18) return -1;
        memcpy(pt + n, msg->txid, 12);
        n += 12;
        put_addrport(pt + n, &msg->src);
        n += 18;
        break;
    case TSNET_DISCO_CALL_ME_MAYBE: /* N x ip16+port (disco.go) */
        /* clamp to the array bound so a bad n_eps can't read past eps[] */
        if (msg->n_eps < 0 || msg->n_eps > TSNET_DISCO_MAX_EPS) return -1;
        if (cap < 2 + (size_t)msg->n_eps * 18) return -1;
        for (int i = 0; i < msg->n_eps; i++) {
            put_addrport(pt + n, &msg->eps[i]);
            n += 18;
        }
        break;
    default:
        return -1;
    }
    return (int)n;
}

int tsnet_disco_seal(const tsnet_disco_msg *msg,
                     const uint8_t self_disco_priv[32],
                     const uint8_t self_disco_pub[32],
                     const uint8_t peer_disco_pub[32], uint8_t *out,
                     size_t cap) {
    uint8_t pt[2 + 18 * TSNET_DISCO_MAX_EPS + 64];
    int ptlen = marshal_payload(msg, pt, sizeof(pt));
    if (ptlen < 0) return -1;
    size_t total = HDR + (size_t)ptlen + TSNET_BOX_OVERHEAD;
    if (cap < total) return -1;

    memcpy(out, MAGIC, 6);
    memcpy(out + 6, self_disco_pub, KEY_LEN);
    uint8_t *nonce = out + 6 + KEY_LEN;
    tsnet_rand_bytes(nonce, NONCE_LEN);
    if (tsnet_box_seal(out + HDR, nonce, pt, (size_t)ptlen, peer_disco_pub,
                       self_disco_priv) != 0)
        return -1;
    return (int)total;
}

int tsnet_disco_open(const uint8_t *pkt, size_t len,
                     const uint8_t self_disco_priv[32],
                     const uint8_t *peer_disco_pub, uint8_t *sender_out,
                     tsnet_disco_msg *msg) {
    if (!tsnet_disco_looks(pkt, len)) return -1;
    const uint8_t *sender = pkt + 6;
    if (peer_disco_pub && memcmp(sender, peer_disco_pub, KEY_LEN) != 0)
        return -1;
    if (sender_out) memcpy(sender_out, sender, KEY_LEN);
    const uint8_t *nonce = pkt + 6 + KEY_LEN;
    size_t ct_len = len - HDR;
    if (ct_len < TSNET_BOX_OVERHEAD + 2 || ct_len > 1024) return -1;

    uint8_t pt[1024];
    if (tsnet_box_open(pt, nonce, pkt + HDR, ct_len, sender,
                       self_disco_priv) != 0)
        return -1;
    size_t ptlen = ct_len - TSNET_BOX_OVERHEAD;

    memset(msg, 0, sizeof(*msg));
    /* pt[1] is the message version; the Go parsers ignore it for Ping/Pong
     * and treat a nonzero version as "no endpoints" for CallMeMaybe
     * (disco.go parsePing/parsePong/parseCallMeMaybe) — do NOT reject, so a
     * future version bump stays interoperable. */
    uint8_t ver = pt[1];
    msg->type = (tsnet_disco_type)pt[0];
    const uint8_t *d = pt + 2;
    size_t dn = ptlen - 2;
    switch (msg->type) {
    case TSNET_DISCO_PING:
        if (dn < 12) return -1;
        memcpy(msg->txid, d, 12);
        /* NodeKey optional (padding tolerated, disco.go) */
        if (dn >= 12 + 32) memcpy(msg->node_key, d + 12, 32);
        break;
    case TSNET_DISCO_PONG:
        if (dn < 12 + 18) return -1;
        memcpy(msg->txid, d, 12);
        get_addrport(d + 12, &msg->src);
        break;
    case TSNET_DISCO_CALL_ME_MAYBE:
        /* nonzero version or misaligned length => no endpoints (disco.go
         * parseCallMeMaybe) */
        if (ver != 0 || dn % 18 != 0) return 0;
        for (size_t off = 0;
             off + 18 <= dn && msg->n_eps < TSNET_DISCO_MAX_EPS; off += 18)
            get_addrport(d + off, &msg->eps[msg->n_eps++]);
        break;
    default:
        return -1; /* relay types 0x04+ out of scope */
    }
    return 0;
}
