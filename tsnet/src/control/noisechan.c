#include "noisechan.h"

#include "httpmin.h"
#include "tsnet/tsnet.h"
#include "util/log.h"
#include "util/url.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

int tsnet_noisechan_connect(tsnet_noisechan *ch, const struct tsnet_url *url,
                            const char *ca_file,
                            const uint8_t machine_priv[32],
                            const uint8_t control_pub[32], uint16_t version,
                            int timeout_ms) {
    memset(ch, 0, sizeof(*ch));
    ch->cs = tsnet_cstream_dial(url->host, url->port, url->tls, url->host,
                                ca_file, timeout_ms);
    if (!ch->cs) return TSNET_E_IO;

    tsnet_noise_hs hs;
    uint8_t init[TSNET_NOISE_INIT_LEN];
    if (tsnet_noise_client_start(&hs, machine_priv, control_pub,
                                 version, init) != 0) {
        tsnet_cstream_close(ch->cs);
        ch->cs = NULL;
        return TSNET_E_PROTO;
    }
    /* path prefix: server URLs may carry a path ("/" means none) */
    const char *prefix = strcmp(url->path, "/") == 0 ? "" : url->path;
    int rc = tsnet_http_upgrade_ts2021(ch->cs, url->host, prefix, init);
    if (rc != 0) {
        TSNET_LOGE("noisechan: upgrade failed (%d)", rc);
        tsnet_cstream_close(ch->cs);
        ch->cs = NULL;
        return TSNET_E_PROTO;
    }

    /* response: either 51-byte Noise response or a type-3 error frame */
    uint8_t hdr[3];
    if (tsnet_cstream_read_full(ch->cs, hdr, 3) != 0) goto io_fail;
    if (hdr[0] == TSNET_NOISE_MSG_ERROR) {
        size_t elen = (size_t)hdr[1] << 8 | hdr[2];
        char emsg[256] = {0};
        if (elen < sizeof(emsg))
            tsnet_cstream_read_full(ch->cs, emsg, elen);
        TSNET_LOGE("noisechan: server refused handshake: %s", emsg);
        goto proto_fail;
    }
    uint8_t resp[TSNET_NOISE_RESP_LEN];
    memcpy(resp, hdr, 3);
    if (tsnet_cstream_read_full(ch->cs, resp + 3, sizeof(resp) - 3) != 0)
        goto io_fail;
    if (tsnet_noise_client_finish(&hs, resp, &ch->conn) != 0) {
        TSNET_LOGE("noisechan: handshake verification failed");
        goto proto_fail;
    }
    TSNET_LOGI("noisechan: secure channel up (%s:%u)", url->host, url->port);
    return TSNET_OK;

io_fail:
    tsnet_cstream_close(ch->cs);
    ch->cs = NULL;
    return TSNET_E_IO;
proto_fail:
    tsnet_cstream_close(ch->cs);
    ch->cs = NULL;
    return TSNET_E_PROTO;
}

/* read and decrypt exactly one type-4 record into ch->pt */
static int read_record(tsnet_noisechan *ch) {
    uint8_t hdr[3];
    if (tsnet_cstream_read_full(ch->cs, hdr, 3) != 0) return -1;
    if (hdr[0] != TSNET_NOISE_MSG_RECORD) {
        TSNET_LOGE("noisechan: unexpected frame type %d", hdr[0]);
        return -1;
    }
    size_t ct_len = (size_t)hdr[1] << 8 | hdr[2];
    if (ct_len < 16 || ct_len > TSNET_NOISE_MAX_CT) return -1;
    uint8_t ct[TSNET_NOISE_MAX_CT];
    if (tsnet_cstream_read_full(ch->cs, ct, ct_len) != 0) return -1;
    int n = tsnet_noise_decrypt(&ch->conn, ct, ct_len, ch->pt);
    if (n < 0) {
        TSNET_LOGE("noisechan: record decrypt failed");
        return -1;
    }
    ch->pt_off = 0;
    ch->pt_len = (size_t)n;
    return 0;
}

/* consume the optional early payload (ts2021/conn.go) */
static int check_early(tsnet_noisechan *ch) {
    if (ch->early_done) return 0;
    ch->early_done = true;

    /* peek the first 9 plaintext bytes */
    uint8_t nine[9];
    size_t have = 0;
    while (have < sizeof(nine)) {
        if (ch->pt_off >= ch->pt_len && read_record(ch) != 0) return -1;
        size_t take = ch->pt_len - ch->pt_off;
        if (take > sizeof(nine) - have) take = sizeof(nine) - have;
        memcpy(nine + have, ch->pt + ch->pt_off, take);
        ch->pt_off += take;
        have += take;
    }
    static const uint8_t magic[5] = {0xff, 0xff, 0xff, 'T', 'S'};
    if (memcmp(nine, magic, 5) != 0) {
        /* no early payload: stash the 9 bytes in a separate prefix buffer
         * that reads drain before ch->pt (no in-place memmove — the 9 bytes
         * may have spanned records, so pt still holds the tail of the last
         * record read, which must be delivered AFTER the 9 bytes) */
        memcpy(ch->hdr9, nine, 9);
        ch->hdr9_off = 0;
        ch->hdr9_len = 9;
        return 0;
    }
    uint32_t plen = (uint32_t)nine[5] << 24 | (uint32_t)nine[6] << 16 |
                    (uint32_t)nine[7] << 8 | nine[8];
    if (plen > 64 * 1024) return -1; /* sane bound; Go allows 10MB */
    char *json = malloc(plen + 1);
    if (!json) return -1;
    size_t off = 0;
    while (off < plen) {
        if (ch->pt_off >= ch->pt_len && read_record(ch) != 0) {
            free(json);
            return -1;
        }
        size_t take = ch->pt_len - ch->pt_off;
        if (take > plen - off) take = plen - off;
        memcpy(json + off, ch->pt + ch->pt_off, take);
        ch->pt_off += take;
        off += take;
    }
    json[plen] = '\0';
    json_error_t jerr;
    json_t *root = json_loads(json, 0, &jerr);
    free(json);
    if (root) {
        json_t *chal = json_object_get(root, "nodeKeyChallenge");
        if (json_is_string(chal))
            snprintf(ch->node_key_challenge, sizeof(ch->node_key_challenge),
                     "%s", json_string_value(chal));
        json_decref(root);
    }
    TSNET_LOGD("noisechan: early payload consumed (challenge=%s)",
               ch->node_key_challenge[0] ? "yes" : "no");
    return 0;
}

ssize_t tsnet_noisechan_read(tsnet_noisechan *ch, void *buf, size_t n) {
    if (!ch->cs) return -1;
    if (check_early(ch) != 0) return -1;
    /* deliver the stashed early-probe prefix first */
    if (ch->hdr9_off < ch->hdr9_len) {
        size_t take = ch->hdr9_len - ch->hdr9_off;
        if (take > n) take = n;
        memcpy(buf, ch->hdr9 + ch->hdr9_off, take);
        ch->hdr9_off += take;
        return (ssize_t)take;
    }
    /* skip empty records (valid keepalive-style type-4 frames) rather than
     * reporting a spurious EOF */
    while (ch->pt_off >= ch->pt_len) {
        if (read_record(ch) != 0) return -1;
    }
    size_t take = ch->pt_len - ch->pt_off;
    if (take > n) take = n;
    memcpy(buf, ch->pt + ch->pt_off, take);
    ch->pt_off += take;
    return (ssize_t)take;
}

int tsnet_noisechan_write(tsnet_noisechan *ch, const void *buf, size_t n) {
    if (!ch->cs) return TSNET_E_STATE;
    const uint8_t *p = buf;
    while (n > 0) {
        size_t chunk = n > TSNET_NOISE_MAX_PT ? TSNET_NOISE_MAX_PT : n;
        uint8_t frame[TSNET_NOISE_MAX_MSG];
        int fl = tsnet_noise_encrypt(&ch->conn, p, chunk, frame);
        if (fl < 0) return TSNET_E_PROTO;
        if (tsnet_cstream_write(ch->cs, frame, (size_t)fl) != 0)
            return TSNET_E_IO;
        p += chunk;
        n -= chunk;
    }
    return TSNET_OK;
}

void tsnet_noisechan_close(tsnet_noisechan *ch) {
    if (ch->cs) {
        tsnet_cstream_close(ch->cs);
        ch->cs = NULL;
    }
}
