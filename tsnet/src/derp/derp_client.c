#include "derp_client.h"

#include "control/cstream.h"
#include "control/httpmin.h"
#include "crypto/tscrypto.h"
#include "platform/platform.h"
#include "tsnet/tsnet.h"
#include "util/log.h"
#include "util/thread.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* derp.go frame types */
#define DERP_SERVER_KEY 0x01
#define DERP_CLIENT_INFO 0x02
#define DERP_SERVER_INFO 0x03
#define DERP_SEND_PACKET 0x04
#define DERP_RECV_PACKET 0x05
#define DERP_KEEP_ALIVE 0x06
#define DERP_NOTE_PREFERRED 0x07
#define DERP_PEER_GONE 0x08
#define DERP_PEER_PRESENT 0x09
#define DERP_PING 0x12
#define DERP_PONG 0x13
#define DERP_HEALTH 0x14
#define DERP_RESTARTING 0x15

#define DERP_PROTOCOL_VERSION 2 /* derp.go */
/* derp.go */
static const uint8_t DERP_MAGIC[8] = {0x44, 0x45, 0x52, 0x50,
                                      0xf0, 0x9f, 0x94, 0x91};

#define DERP_MAX_FRAME (1024 * 1024) /* server info bound, derp.go MaxInfoLen */
#define DERP_MAX_PACKET (64 * 1024)

struct tsnet_derp {
    tsnet_cstream *cs;
    pthread_mutex_t wmu; /* serializes frame writes */
    pthread_t reader;
    bool reader_running;
    volatile int closing;

    uint8_t node_priv[32], node_pub[32];
    uint8_t server_key[32];

    int region_id;
    volatile uint64_t last_activity_ms;
    volatile int dead; /* set by the reader thread just before it exits */

    tsnet_derp_recv_cb on_recv;
    tsnet_derp_state_cb on_state;
    void *ud;
};

void tsnet_derp_frame_header(uint8_t hdr[5], uint8_t type, uint32_t len) {
    hdr[0] = type;
    hdr[1] = (uint8_t)(len >> 24);
    hdr[2] = (uint8_t)(len >> 16);
    hdr[3] = (uint8_t)(len >> 8);
    hdr[4] = (uint8_t)len;
}

int tsnet_derp_parse_server_key(const uint8_t *payload, size_t len,
                                uint8_t key[32]) {
    if (len < sizeof(DERP_MAGIC) + 32) return -1;
    if (memcmp(payload, DERP_MAGIC, sizeof(DERP_MAGIC)) != 0) return -1;
    memcpy(key, payload + sizeof(DERP_MAGIC), 32);
    return 0;
}

static int write_frame(tsnet_derp *d, uint8_t type, const uint8_t *a,
                       size_t alen, const uint8_t *b, size_t blen) {
    uint8_t hdr[5];
    tsnet_derp_frame_header(hdr, type, (uint32_t)(alen + blen));
    pthread_mutex_lock(&d->wmu);
    int rc = tsnet_cstream_write(d->cs, hdr, sizeof(hdr));
    if (rc == 0 && alen) rc = tsnet_cstream_write(d->cs, a, alen);
    if (rc == 0 && blen) rc = tsnet_cstream_write(d->cs, b, blen);
    pthread_mutex_unlock(&d->wmu);
    return rc == 0 ? TSNET_OK : TSNET_E_IO;
}

/* read one frame header+payload into buf (cap DERP_MAX_FRAME) */
static int read_frame(tsnet_derp *d, uint8_t *type, uint8_t *buf,
                      size_t cap, size_t *len_out) {
    uint8_t hdr[5];
    if (tsnet_cstream_read_full(d->cs, hdr, sizeof(hdr)) != 0) return -1;
    *type = hdr[0];
    uint32_t len = (uint32_t)hdr[1] << 24 | (uint32_t)hdr[2] << 16 |
                   (uint32_t)hdr[3] << 8 | hdr[4];
    if (len > cap) {
        TSNET_LOGE("derp: oversized frame type=%d len=%u", *type, len);
        return -1;
    }
    if (len && tsnet_cstream_read_full(d->cs, buf, len) != 0) return -1;
    *len_out = len;
    return 0;
}

static int send_client_info(tsnet_derp *d) {
    /* {"version":2,"CanAckPings":true} — derp_client.go */
    char info[64];
    int ilen = snprintf(info, sizeof(info),
                        "{\"version\":%d,\"CanAckPings\":true}",
                        DERP_PROTOCOL_VERSION);
    /* naclbox with random nonce prepended (types/key/node.go) */
    uint8_t nonce[24];
    tsnet_rand_bytes(nonce, sizeof(nonce));
    uint8_t boxed[24 + 64 + TSNET_BOX_OVERHEAD];
    memcpy(boxed, nonce, 24);
    if (tsnet_box_seal(boxed + 24, nonce, info, (size_t)ilen, d->server_key,
                       d->node_priv) != 0)
        return TSNET_E_PROTO;
    size_t boxed_len = 24 + (size_t)ilen + TSNET_BOX_OVERHEAD;
    return write_frame(d, DERP_CLIENT_INFO, d->node_pub, 32, boxed, boxed_len);
}

static void *reader_main(void *arg) {
    tsnet_derp *d = arg;
    tsnet_plat_thread_boost(); /* carries inbound video on the DERP path */
    uint8_t *buf = malloc(DERP_MAX_FRAME);
    if (!buf) goto out;

    for (;;) {
        uint8_t type;
        size_t len;
        if (read_frame(d, &type, buf, DERP_MAX_FRAME, &len) != 0) break;
        d->last_activity_ms = tsnet_now_ms();
        switch (type) {
        case DERP_RECV_PACKET: /* v2: 32B src + payload (derp.go) */
            if (len > 32 && d->on_recv)
                d->on_recv(buf, buf + 32, len - 32, d->ud);
            break;
        case DERP_PING: /* echo back as pong (derp.go) */
            if (len == 8) write_frame(d, DERP_PONG, buf, 8, NULL, 0);
            break;
        case DERP_KEEP_ALIVE:
        case DERP_PONG:
        case DERP_HEALTH:
        case DERP_SERVER_INFO:
        case DERP_PEER_PRESENT:
            break;
        case DERP_PEER_GONE:
            TSNET_LOGD("derp: peer gone (reason=%d)",
                       len >= 33 ? buf[32] : -1);
            break;
        case DERP_RESTARTING:
            TSNET_LOGI("derp: server restarting");
            break;
        default:
            TSNET_LOGD("derp: unhandled frame type 0x%02x len=%zu", type, len);
            break;
        }
    }
out:
    free(buf);
    d->dead = 1;
    if (!d->closing && d->on_state) d->on_state(false, d->ud);
    return NULL;
}

int tsnet_derp_connect(tsnet_derp **out, const tsnet_derp_region *region,
                       const uint8_t node_priv[32], const char *ca_file,
                       tsnet_derp_recv_cb on_recv,
                       tsnet_derp_state_cb on_state, void *ud) {
    /* pick the first non-STUN-only node (derphttp picks Nodes[0]) */
    const tsnet_derp_node *node = NULL;
    for (int i = 0; i < region->n_nodes; i++) {
        if (!region->nodes[i].stun_only) {
            node = &region->nodes[i];
            break;
        }
    }
    if (!node) return TSNET_E_INVAL;

    tsnet_derp *d = calloc(1, sizeof(*d));
    if (!d) return TSNET_E_NOMEM;
    pthread_mutex_init(&d->wmu, NULL);
    d->region_id = region->id;
    d->on_recv = on_recv;
    d->on_state = on_state;
    d->ud = ud;
    memcpy(d->node_priv, node_priv, 32);
    tsnet_x25519_pubkey(d->node_pub, node_priv);

    /* TLS policy: the Go client always uses https to DERPMap nodes
     * (derphttp_client.go), so TLS is always used; CanPort80 is ignored. Verification uses CertName
     * when set, else HostName (derphttp_client.go). */
    const char *host = node->hostname;
    uint16_t port = (uint16_t)node->derp_port;
    const char *sni = node->cert_name[0] ? node->cert_name : node->hostname;
    d->cs = tsnet_cstream_dial(host, port, true, sni, ca_file, 10000);
    if (!d->cs) {
        TSNET_LOGE("derp: dial %s:%u failed", host, port);
        free(d);
        return TSNET_E_IO;
    }

    /* HTTP upgrade (derphttp_client.go) */
    char req[512];
    int n = snprintf(req, sizeof(req),
                     "GET /derp HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Upgrade: DERP\r\n"
                     "Connection: Upgrade\r\n"
                     "\r\n",
                     host);
    if (tsnet_cstream_write(d->cs, req, (size_t)n) != 0) goto fail_io;
    /* status line + headers until blank */
    char line[512];
    if (tsnet_cstream_read_line(d->cs, line, sizeof(line)) < 0) goto fail_io;
    int status = 0;
    sscanf(line, "HTTP/1.%*d %d", &status);
    if (status != 101) {
        TSNET_LOGE("derp: upgrade refused: %.100s", line);
        goto fail_proto;
    }
    for (;;) {
        int l = tsnet_cstream_read_line(d->cs, line, sizeof(line));
        if (l < 0) goto fail_io;
        if (l == 0) break;
    }

    /* ServerKey frame */
    uint8_t buf[1024];
    uint8_t type;
    size_t len;
    if (read_frame(d, &type, buf, sizeof(buf), &len) != 0) goto fail_io;
    if (type != DERP_SERVER_KEY ||
        tsnet_derp_parse_server_key(buf, len, d->server_key) != 0) {
        TSNET_LOGE("derp: invalid server greeting (type=%d)", type);
        goto fail_proto;
    }
    if (send_client_info(d) != TSNET_OK) goto fail_io;

    d->last_activity_ms = tsnet_now_ms();
    if (tsnet_thread_create(&d->reader, reader_main, d) != 0) goto fail_io;
    d->reader_running = true;

    TSNET_LOGI("derp: connected to region %d (%s:%u)", region->id, host,
               port);
    *out = d;
    return TSNET_OK;

fail_io:
    tsnet_cstream_close(d->cs);
    free(d);
    return TSNET_E_IO;
fail_proto:
    tsnet_cstream_close(d->cs);
    free(d);
    return TSNET_E_PROTO;
}

int tsnet_derp_send(tsnet_derp *d, const uint8_t dst_key[32], const void *pkt,
                    size_t len) {
    if (len > DERP_MAX_PACKET) return TSNET_E_INVAL;
    return write_frame(d, DERP_SEND_PACKET, dst_key, 32, pkt, len);
}

int tsnet_derp_note_preferred(tsnet_derp *d, bool preferred) {
    uint8_t v = preferred ? 1 : 0;
    return write_frame(d, DERP_NOTE_PREFERRED, &v, 1, NULL, 0);
}

int tsnet_derp_region_id(const tsnet_derp *d) { return d->region_id; }

uint64_t tsnet_derp_last_activity(const tsnet_derp *d) {
    return d->last_activity_ms;
}

bool tsnet_derp_dead(const tsnet_derp *d) { return d->dead != 0; }

void tsnet_derp_close(tsnet_derp *d) {
    if (!d) return;
    d->closing = 1;
    /* shutdown unblocks the reader; free the stream only after joining */
    tsnet_cstream_shutdown(d->cs);
    if (d->reader_running) pthread_join(d->reader, NULL);
    tsnet_cstream_close(d->cs);
    pthread_mutex_destroy(&d->wmu);
    memset(d->node_priv, 0, sizeof(d->node_priv));
    free(d);
}
