#include "h2.h"

#include "tsnet/tsnet.h"
#include "util/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nghttp2/nghttp2.h>

struct tsnet_h2 {
    nghttp2_session *sess;
    tsnet_noisechan *ch;
    char authority[256];

    /* current request state (one request in flight at a time) */
    int32_t stream_id;
    int status;
    int stream_closed;
    uint32_t close_error;
    tsnet_h2_data_cb on_data;
    void *ud;
    int cb_abort;

    /* request body */
    const uint8_t *body;
    size_t body_len, body_off;
};

static ssize_t send_cb(nghttp2_session *sess, const uint8_t *data,
                       size_t length, int flags, void *user_data) {
    (void)sess;
    (void)flags;
    tsnet_h2 *h2 = user_data;
    if (tsnet_noisechan_write(h2->ch, data, length) != TSNET_OK)
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    return (ssize_t)length;
}

static int on_header_cb(nghttp2_session *sess, const nghttp2_frame *frame,
                        const uint8_t *name, size_t namelen,
                        const uint8_t *value, size_t valuelen, uint8_t flags,
                        void *user_data) {
    (void)sess;
    (void)flags;
    tsnet_h2 *h2 = user_data;
    if (frame->hd.stream_id == h2->stream_id && namelen == 7 &&
        memcmp(name, ":status", 7) == 0 && valuelen >= 3) {
        h2->status = (value[0] - '0') * 100 + (value[1] - '0') * 10 +
                     (value[2] - '0');
    }
    return 0;
}

static int on_data_chunk_cb(nghttp2_session *sess, uint8_t flags,
                            int32_t stream_id, const uint8_t *data,
                            size_t len, void *user_data) {
    (void)sess;
    (void)flags;
    tsnet_h2 *h2 = user_data;
    if (stream_id == h2->stream_id && h2->on_data && !h2->cb_abort) {
        if (h2->on_data(data, len, h2->ud) != 0) h2->cb_abort = 1;
    }
    return 0;
}

static int on_stream_close_cb(nghttp2_session *sess, int32_t stream_id,
                              uint32_t error_code, void *user_data) {
    (void)sess;
    tsnet_h2 *h2 = user_data;
    if (stream_id == h2->stream_id) {
        h2->stream_closed = 1;
        h2->close_error = error_code;
    }
    return 0;
}

static ssize_t body_read_cb(nghttp2_session *sess, int32_t stream_id,
                            uint8_t *buf, size_t length, uint32_t *data_flags,
                            nghttp2_data_source *source, void *user_data) {
    (void)sess;
    (void)stream_id;
    (void)source;
    tsnet_h2 *h2 = user_data;
    size_t left = h2->body_len - h2->body_off;
    size_t n = left < length ? left : length;
    memcpy(buf, h2->body + h2->body_off, n);
    h2->body_off += n;
    if (h2->body_off == h2->body_len) *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return (ssize_t)n;
}

int tsnet_h2_open(tsnet_h2 **out, tsnet_noisechan *ch, const char *authority) {
    tsnet_h2 *h2 = calloc(1, sizeof(*h2));
    if (!h2) return TSNET_E_NOMEM;
    h2->ch = ch;
    snprintf(h2->authority, sizeof(h2->authority), "%s", authority);

    nghttp2_session_callbacks *cbs;
    if (nghttp2_session_callbacks_new(&cbs) != 0) { /* OOM */
        free(h2);
        return TSNET_E_NOMEM;
    }
    nghttp2_session_callbacks_set_send_callback(cbs, send_cb);
    nghttp2_session_callbacks_set_on_header_callback(cbs, on_header_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        cbs, on_data_chunk_cb);
    nghttp2_session_callbacks_set_on_stream_close_callback(
        cbs, on_stream_close_cb);
    int rc = nghttp2_session_client_new(&h2->sess, cbs, h2);
    nghttp2_session_callbacks_del(cbs);
    if (rc != 0) {
        free(h2);
        return TSNET_E_NOMEM;
    }
    nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 4},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 4 * 1024 * 1024},
    };
    nghttp2_submit_settings(h2->sess, NGHTTP2_FLAG_NONE, settings, 2);
    /* also grow the connection-level window for large netmaps */
    nghttp2_session_set_local_window_size(h2->sess, NGHTTP2_FLAG_NONE, 0,
                                          4 * 1024 * 1024);
    *out = h2;
    return TSNET_OK;
}

#define NV(NAME, VALUE, VLEN)                                              \
    {                                                                      \
        (uint8_t *)(NAME), (uint8_t *)(VALUE), sizeof(NAME) - 1, (VLEN),   \
            NGHTTP2_NV_FLAG_NONE                                           \
    }

int tsnet_h2_post(tsnet_h2 *h2, const char *path, const char *lb_key,
                  const void *body, size_t body_len, tsnet_h2_data_cb on_data,
                  void *ud) {
    h2->status = 0;
    h2->stream_closed = 0;
    h2->close_error = 0;
    h2->on_data = on_data;
    h2->ud = ud;
    h2->cb_abort = 0;
    h2->body = body;
    h2->body_len = body_len;
    h2->body_off = 0;

    /* headers per control/ts2021/client.go */
    nghttp2_nv nva[8];
    int n = 0;
    nva[n++] = (nghttp2_nv)NV(":method", "POST", 4);
    nva[n++] = (nghttp2_nv)NV(":scheme", "https", 5);
    nva[n++] = (nghttp2_nv)NV(":authority", h2->authority,
                              strlen(h2->authority));
    nva[n++] = (nghttp2_nv)NV(":path", path, strlen(path));
    nva[n++] = (nghttp2_nv)NV("content-type", "application/json", 16);
    if (lb_key)
        nva[n++] = (nghttp2_nv)NV("ts-lb", lb_key, strlen(lb_key));

    nghttp2_data_provider prd = {.source = {.ptr = NULL},
                                 .read_callback = body_read_cb};
    int32_t sid = nghttp2_submit_request(h2->sess, NULL, nva, (size_t)n,
                                         body_len ? &prd : NULL, NULL);
    if (sid < 0) {
        TSNET_LOGE("h2: submit_request: %s", nghttp2_strerror(sid));
        return TSNET_E_PROTO;
    }
    h2->stream_id = sid;

    uint8_t buf[8192];
    while (!h2->stream_closed) {
        /* a data callback that asked to abort (malformed/oversized map
         * message) must tear the stream down, else the loop blocks forever
         * waiting for a close that never comes */
        if (h2->cb_abort) {
            nghttp2_submit_rst_stream(h2->sess, NGHTTP2_FLAG_NONE,
                                      h2->stream_id, NGHTTP2_CANCEL);
            nghttp2_session_send(h2->sess);
            return TSNET_E_CLOSED;
        }
        int rc = nghttp2_session_send(h2->sess);
        if (rc != 0) {
            TSNET_LOGE("h2: send: %s", nghttp2_strerror(rc));
            return TSNET_E_IO;
        }
        if (h2->stream_closed) break;
        ssize_t r = tsnet_noisechan_read(h2->ch, buf, sizeof(buf));
        if (r <= 0) {
            /* DEBUG, not ERROR: a read of 0/-1 is the normal end of a map
             * long-poll — most often a *deliberate* self-shutdown from
             * kick_map() (endpoints / preferred-DERP changed) that forces the
             * stream to reopen with fresh values. The control loop logs the
             * real outcome (reconnect reason / HTTP status) at INFO/WARN. */
            TSNET_LOGD("h2: channel read ended (r=%zd)", r);
            return TSNET_E_IO;
        }
        ssize_t consumed = nghttp2_session_mem_recv(h2->sess, buf, (size_t)r);
        if (consumed < 0) {
            TSNET_LOGE("h2: mem_recv: %s",
                       nghttp2_strerror((int)consumed));
            return TSNET_E_PROTO;
        }
    }
    /* flush anything pending (window updates, rst) */
    nghttp2_session_send(h2->sess);

    if (h2->cb_abort) return TSNET_E_CLOSED;
    if (h2->close_error != NGHTTP2_NO_ERROR) {
        TSNET_LOGE("h2: stream closed with error %u", h2->close_error);
        return TSNET_E_PROTO;
    }
    return h2->status > 0 ? h2->status : TSNET_E_PROTO;
}

void tsnet_h2_close(tsnet_h2 *h2) {
    if (!h2) return;
    if (h2->sess) nghttp2_session_del(h2->sess);
    free(h2);
}
