#include "control.h"

#include "crypto/tscrypto.h"
#include "h2.h"
#include "httpmin.h"
#include "netmap.h"
#include "noisechan.h"
#include "platform/platform.h"
#include "tsnet_capver.h"
#include "util/hex.h"
#include "util/keyfile.h"
#include "util/log.h"
#include "util/thread.h"
#include "util/url.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <jansson.h>

#define DIAL_TIMEOUT_MS 15000
/* server keepalives arrive every ~60 s with KeepAlive=true; Go uses a 120 s
 * watchdog (direct.go watchdogTimeout) */
#define MAP_READ_TIMEOUT_MS 130000

struct tsnet_control {
    tsnet_config cfg;
    char server_url[256];
    char state_dir[256];
    char hostname[64];
    char auth_key[256]; /* reusable/tagged keys can exceed 128 chars */
    char ca_file[256];

    tsnet_control_cbs cbs;

    uint8_t machine_priv[32];
    uint8_t node_priv[32], node_pub[32];
    uint8_t disco_priv[32], disco_pub[32];
    uint8_t control_pub[32];
    bool have_control_key;

    tsnet_url url;

    tsnet_noisechan chan;
    tsnet_h2 *h2;
    bool chan_up;
    /* guards chan/chan_up between the control thread (setup/teardown) and
     * tsnet_control_stop(), which shuts the socket down from another thread */
    pthread_mutex_t chan_lock;

    tsnet_netmap netmap;
    char map_session_handle[128];
    int64_t map_seq;

    char endpoints[TSNET_MAX_ENDPOINTS][64];
    int n_endpoints;
    int preferred_derp;
    /* Endpoint / PreferredDERP publish worker. These values must reach the
     * server via a NON-streaming MapRequest (the long-poll is read-only for
     * capver>=68). Instead of tearing the map stream down and reconnecting on
     * every change (churny: re-registers, re-fetches the netmap), a dedicated
     * worker publishes the current state on a short-lived side connection
     * while the map stream keeps running untouched. ep_lock guards the mutable
     * fields above, have_control_key/control_pub, and the worker signalling. */
    pthread_mutex_t ep_lock;
    pthread_cond_t pub_cv;
    pthread_t pub_thread;
    bool pub_thread_up;
    bool pub_req;  /* a change is waiting to be published */
    bool pub_stop; /* tell the worker to exit */

    volatile int stop;
    tsnet_state state;

    /* map stream reassembly (u32 LE length-prefixed, direct.go) */
    uint8_t *mapbuf;
    size_t mapbuf_len, mapbuf_cap;
    int map_msgs_seen;
    int map_error;
};

static void set_state(tsnet_control *c, tsnet_state st, const char *detail) {
    c->state = st;
    TSNET_LOGI("control: state -> %d (%s)", st, detail ? detail : "");
    if (c->cbs.on_state) c->cbs.on_state(st, detail ? detail : "", c->cbs.ud);
}

/* ---- keys ----------------------------------------------------------------- */

static int load_or_create_key(const char *dir, const char *name,
                              uint8_t priv[32]) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (tsnet_keyfile_load(path, priv) == TSNET_OK) return TSNET_OK;
    uint8_t pub[32];
    tsnet_x25519_keygen(priv, pub);
    int rc = tsnet_keyfile_store(path, priv);
    if (rc == TSNET_OK) TSNET_LOGI("control: generated new %s", name);
    return rc;
}

static int load_keys(tsnet_control *c) {
    mkdir(c->state_dir, 0700);
    if (load_or_create_key(c->state_dir, "machine.key", c->machine_priv) !=
        TSNET_OK)
        return TSNET_E_IO;
    if (load_or_create_key(c->state_dir, "node.key", c->node_priv) != TSNET_OK)
        return TSNET_E_IO;
    if (load_or_create_key(c->state_dir, "disco.key", c->disco_priv) !=
        TSNET_OK)
        return TSNET_E_IO;
    tsnet_x25519_pubkey(c->node_pub, c->node_priv);
    tsnet_x25519_pubkey(c->disco_pub, c->disco_priv);
    return TSNET_OK;
}

/* ---- bootstrap: GET /key?v=<capver> --------------------------------------- */

static int fetch_control_key(tsnet_control *c) {
    tsnet_cstream *s =
        tsnet_cstream_dial(c->url.host, c->url.port, c->url.tls, c->url.host,
                           c->ca_file[0] ? c->ca_file : NULL, DIAL_TIMEOUT_MS);
    if (!s) return TSNET_E_IO;
    char path[300];
    const char *prefix = strcmp(c->url.path, "/") == 0 ? "" : c->url.path;
    snprintf(path, sizeof(path), "%s/key?v=%d", prefix,
             TSNET_CAPABILITY_VERSION);
    char body[4096];
    int status = tsnet_http_get(s, c->url.host, path, body, sizeof(body));
    tsnet_cstream_close(s);
    if (status != 200) {
        TSNET_LOGE("control: GET /key -> %d", status);
        return TSNET_E_PROTO;
    }
    json_error_t jerr;
    json_t *root = json_loads(body, 0, &jerr);
    if (!root) return TSNET_E_PROTO;
    json_t *pk = json_object_get(root, "publicKey");
    bool ok = json_is_string(pk) &&
              tsnet_key_parse(json_string_value(pk), "mkey:", c->control_pub);
    json_decref(root);
    if (!ok) {
        TSNET_LOGE("control: /key response missing publicKey");
        return TSNET_E_PROTO;
    }
    /* publish under ep_lock so the publish worker observes a fully-written
     * control_pub (set just above) together with have_control_key */
    pthread_mutex_lock(&c->ep_lock);
    c->have_control_key = true;
    pthread_mutex_unlock(&c->ep_lock);
    TSNET_LOGI("control: got control Noise key");
    return TSNET_OK;
}

/* ---- JSON builders --------------------------------------------------------- */

static json_t *build_hostinfo(tsnet_control *c) {
    json_t *hi = json_object();
    pthread_mutex_lock(&c->ep_lock);
    int derp = c->preferred_derp;
    pthread_mutex_unlock(&c->ep_lock);
    if (derp > 0) {
        json_t *ni = json_object();
        json_object_set_new(ni, "PreferredDERP", json_integer(derp));
        json_object_set_new(ni, "WorkingUDP", json_true());
        json_object_set_new(hi, "NetInfo", ni);
    }
    json_object_set_new(hi, "Hostname", json_string(c->hostname));
    json_object_set_new(hi, "OS", json_string("linux"));
    json_object_set_new(hi, "OSVersion", json_string("HorizonOS"));
    json_object_set_new(hi, "DeviceModel", json_string("Nintendo Switch"));
    json_object_set_new(hi, "IPNVersion",
                        json_string("moonlight-tsnet " TSNET_VERSION));
    json_object_set_new(hi, "BackendLogID", json_string(""));
    return hi;
}

static void key_str(const uint8_t pub[32], const char *prefix, char *out) {
    tsnet_key_format(pub, prefix, out);
}

/* ---- register --------------------------------------------------------------- */

struct body_acc {
    char buf[64 * 1024];
    size_t len;
};

static int acc_cb(const uint8_t *data, size_t len, void *ud) {
    struct body_acc *a = ud;
    if (a->len + len >= sizeof(a->buf)) return 1;
    memcpy(a->buf + a->len, data, len);
    a->len += len;
    a->buf[a->len] = '\0';
    return 0;
}

/* one register exchange; fills authurl (if login pending) and flags */
static int do_register_once(tsnet_control *c, const char *followup,
                            char *authurl, size_t authurl_cap,
                            bool *authorized) {
    json_t *req = json_object();
    json_object_set_new(req, "Version",
                        json_integer(TSNET_CAPABILITY_VERSION));
    char nk[75];
    key_str(c->node_pub, "nodekey:", nk);
    json_object_set_new(req, "NodeKey", json_string(nk));
    static const uint8_t zero32[32] = {0};
    char ok[75];
    key_str(zero32, "nodekey:", ok);
    json_object_set_new(req, "OldNodeKey", json_string(ok));
    if (c->auth_key[0] && !followup) {
        json_t *auth = json_object();
        json_object_set_new(auth, "AuthKey", json_string(c->auth_key));
        json_object_set_new(req, "Auth", auth);
    }
    if (followup)
        json_object_set_new(req, "Followup", json_string(followup));
    json_object_set_new(req, "Expiry", json_string("0001-01-01T00:00:00Z"));
    json_object_set_new(req, "Hostinfo", build_hostinfo(c));

    char *body = json_dumps(req, JSON_COMPACT);
    json_decref(req);
    if (!body) return TSNET_E_NOMEM;

    struct body_acc acc = {.len = 0};
    char nkey[75];
    key_str(c->node_pub, "nodekey:", nkey);
    const char *prefix = strcmp(c->url.path, "/") == 0 ? "" : c->url.path;
    char path[300];
    snprintf(path, sizeof(path), "%s/machine/register", prefix);
    int status = tsnet_h2_post(c->h2, path, nkey, body, strlen(body), acc_cb,
                               &acc);
    free(body);
    if (status < 0) return status;
    if (status != 200) {
        TSNET_LOGE("control: register -> HTTP %d: %.200s", status, acc.buf);
        return TSNET_E_PROTO;
    }

    json_error_t jerr;
    json_t *resp = json_loads(acc.buf, 0, &jerr);
    if (!resp) {
        TSNET_LOGE("control: register response not JSON");
        return TSNET_E_PROTO;
    }
    json_t *v = json_object_get(resp, "Error");
    if (json_is_string(v) && json_string_value(v)[0]) {
        TSNET_LOGE("control: register error: %s", json_string_value(v));
        json_decref(resp);
        return TSNET_E_AUTH;
    }
    *authorized = json_is_true(json_object_get(resp, "MachineAuthorized"));
    v = json_object_get(resp, "AuthURL");
    if (json_is_string(v))
        snprintf(authurl, authurl_cap, "%s", json_string_value(v));
    else
        authurl[0] = '\0';
    bool expired = json_is_true(json_object_get(resp, "NodeKeyExpired"));
    json_decref(resp);
    if (expired) return TSNET_E_AUTH;
    return TSNET_OK;
}

static int do_register(tsnet_control *c) {
    set_state(c, TSNET_ST_AUTHENTICATING, "registering");
    char authurl[256];
    bool authorized = false;
    int rc = do_register_once(c, NULL, authurl, sizeof(authurl), &authorized);
    if (rc != TSNET_OK) return rc;

    if (authurl[0] && !authorized) {
        /* The server returns an AuthURL even when an auth key was supplied;
         * with a key the followup authorizes automatically, so DON'T prompt
         * the user for a browser login in that case. Only pop the URL for
         * genuinely interactive (keyless) logins. */
        if (c->auth_key[0]) {
            set_state(c, TSNET_ST_AUTHENTICATING, "authorizing with key");
        } else {
            TSNET_LOGI("control: login URL: %s", authurl);
            if (c->cbs.on_authurl) c->cbs.on_authurl(authurl, c->cbs.ud);
            /* Followup blocks until the URL is visited (tailcfg.go) */
            set_state(c, TSNET_ST_AUTHENTICATING, "waiting for browser login");
        }
        rc = do_register_once(c, authurl, authurl, sizeof(authurl),
                              &authorized);
        if (rc != TSNET_OK) return rc;
    }
    /* successful registration: the auth key must not be persisted (it never
     * is) nor kept in memory longer than needed */
    memset(c->auth_key, 0, sizeof(c->auth_key));
    TSNET_LOGI("control: registered (authorized=%d)", authorized);
    return TSNET_OK;
}

/* ---- map stream ------------------------------------------------------------- */

static void handle_ping_request(tsnet_control *c, const tsnet_map_msg *msg) {
    /* default ping type: HEAD to the URL over TLS (direct.go) */
    tsnet_url u;
    if (!tsnet_url_parse(msg->ping_url, &u)) return;
    tsnet_cstream *s =
        tsnet_cstream_dial(u.host, u.port, u.tls, u.host,
                           c->ca_file[0] ? c->ca_file : NULL, 5000);
    if (!s) return;
    char req[512];
    int n = snprintf(req, sizeof(req),
                     "HEAD %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
                     u.path, u.host);
    tsnet_cstream_write(s, req, (size_t)n);
    char line[128];
    tsnet_cstream_read_line(s, line, sizeof(line));
    tsnet_cstream_close(s);
    TSNET_LOGD("control: answered PingRequest %s", msg->ping_url);
}

static int process_map_message(tsnet_control *c, const uint8_t *msg,
                               size_t len) {
    tsnet_map_msg mm;
    int rc = tsnet_netmap_apply(&c->netmap, (const char *)msg, len, &mm);
    if (rc != TSNET_OK) return rc;
    c->map_msgs_seen++;

    if (mm.map_session_handle[0])
        snprintf(c->map_session_handle, sizeof(c->map_session_handle), "%s",
                 mm.map_session_handle);
    if (mm.seq) c->map_seq = mm.seq;

    if (mm.keep_alive) {
        TSNET_LOGD("control: keepalive");
        return TSNET_OK;
    }
    if (mm.ping_url[0]) handle_ping_request(c, &mm);
    if (mm.pop_browser_url[0] && c->cbs.on_authurl)
        c->cbs.on_authurl(mm.pop_browser_url, c->cbs.ud);

    tsnet_netmap_sync_registry(&c->netmap);
    if (c->state != TSNET_ST_RUNNING)
        set_state(c, TSNET_ST_RUNNING, "netmap received");
    TSNET_LOGI("control: netmap: self=%s addrs=%d peers=%d derp_regions=%d",
               c->netmap.self_name, c->netmap.n_self_addrs, c->netmap.n_peers,
               c->netmap.derpmap.n_regions);
    if (c->cbs.on_netmap) c->cbs.on_netmap(&c->netmap, c->cbs.ud);
    return TSNET_OK;
}

static int map_data_cb(const uint8_t *data, size_t len, void *ud) {
    tsnet_control *c = ud;
    if (c->stop) return 1;
    if (c->mapbuf_len + len > c->mapbuf_cap) {
        size_t ncap = c->mapbuf_cap ? c->mapbuf_cap : 64 * 1024;
        while (ncap < c->mapbuf_len + len) ncap *= 2;
        if (ncap > 32 * 1024 * 1024) return 1;
        uint8_t *nb = realloc(c->mapbuf, ncap);
        if (!nb) return 1;
        c->mapbuf = nb;
        c->mapbuf_cap = ncap;
    }
    memcpy(c->mapbuf + c->mapbuf_len, data, len);
    c->mapbuf_len += len;

    /* u32 LE length-prefixed messages (direct.go) */
    for (;;) {
        if (c->mapbuf_len < 4) break;
        uint32_t sz = (uint32_t)c->mapbuf[0] | (uint32_t)c->mapbuf[1] << 8 |
                      (uint32_t)c->mapbuf[2] << 16 |
                      (uint32_t)c->mapbuf[3] << 24;
        if (sz > 16 * 1024 * 1024) return 1;
        if (c->mapbuf_len < 4 + (size_t)sz) break;
        if (process_map_message(c, c->mapbuf + 4, sz) != TSNET_OK) {
            c->map_error = 1;
            return 1;
        }
        memmove(c->mapbuf, c->mapbuf + 4 + sz, c->mapbuf_len - 4 - sz);
        c->mapbuf_len -= 4 + sz;
    }
    return 0;
}

/* Publish our node info (DiscoKey, Endpoints, Hostinfo/NetInfo) to the control
 * with a NON-streaming request. Critical: a streaming MapRequest (Stream=true,
 * capver>=68) is treated as read-only by real Tailscale — it IGNORES Hostinfo,
 * Endpoints and DiscoKey (tailcfg.go MapRequest docs). So the only way our
 * disco key/endpoints actually reach the control (and thus peers, who
 * otherwise exclude us from magicsock) is this OmitPeers+Stream=false update,
 * which the server accepts without disturbing the long-poll (tailcfg.go).
 * headscale is lenient and accepted them from the stream; real Tailscale does
 * not — this is why the tunnel worked in CI but no peer could reach us. */
/* Build the non-streaming publish request body (OmitPeers, Stream=false) with
 * the current DiscoKey, Hostinfo/NetInfo (PreferredDERP) and Endpoints,
 * snapshotting the endpoint list under ep_lock. Returns a malloc'd string (or
 * NULL) and the endpoint count via *n_out. */
static char *build_publish_body(tsnet_control *c, int *n_out) {
    json_t *req = json_object();
    json_object_set_new(req, "Version",
                        json_integer(TSNET_CAPABILITY_VERSION));
    json_object_set_new(req, "OmitPeers", json_true());
    json_object_set_new(req, "Stream", json_false());
    json_object_set_new(req, "Compress", json_string(""));
    char nk[75], dk[75 + 16];
    key_str(c->node_pub, "nodekey:", nk);
    json_object_set_new(req, "NodeKey", json_string(nk));
    tsnet_key_format(c->disco_pub, "discokey:", dk);
    json_object_set_new(req, "DiscoKey", json_string(dk));
    json_object_set_new(req, "Hostinfo", build_hostinfo(c));
    pthread_mutex_lock(&c->ep_lock);
    int n = c->n_endpoints;
    if (n > 0) {
        json_t *eps = json_array();
        for (int i = 0; i < n; i++)
            json_array_append_new(eps, json_string(c->endpoints[i]));
        json_object_set_new(req, "Endpoints", eps);
    }
    pthread_mutex_unlock(&c->ep_lock);
    char *body = json_dumps(req, JSON_COMPACT);
    json_decref(req);
    if (n_out) *n_out = n;
    return body;
}

/* POST the publish body on a given (already-open) h2 channel. */
static int publish_on(tsnet_control *c, tsnet_h2 *h2, int *n_out) {
    char *body = build_publish_body(c, n_out);
    if (!body) return TSNET_E_NOMEM;
    char nk[75];
    key_str(c->node_pub, "nodekey:", nk);
    const char *prefix = strcmp(c->url.path, "/") == 0 ? "" : c->url.path;
    char path[300];
    snprintf(path, sizeof(path), "%s/machine/map", prefix);
    struct body_acc acc = {.len = 0};
    int status = tsnet_h2_post(h2, path, nk, body, strlen(body), acc_cb, &acc);
    free(body);
    return status;
}

/* Startup publish on the main channel, before the (read-only) long-poll. */
static int do_publish(tsnet_control *c) {
    /* Clear pub_req BEFORE snapshotting the body: a change that races in during
     * the POST then either lands in this snapshot or re-sets pub_req so the
     * worker republishes it — never lost. (The worker clears before its
     * snapshot for the same reason.) */
    pthread_mutex_lock(&c->ep_lock);
    c->pub_req = false;
    pthread_mutex_unlock(&c->ep_lock);
    int n = 0;
    int status = publish_on(c, c->h2, &n);
    TSNET_LOGI("control: published node info (disco + %d endpoints) -> HTTP %d",
               n, status);
    if (status < 0) return status;
    if (status != 200) return TSNET_E_PROTO;
    return TSNET_OK;
}

/* Dial timeout for the publish side connection. Shorter than the map dial so a
 * shutdown that lands mid-dial waits at most this long for the worker to join. */
#define PUBLISH_DIAL_TIMEOUT_MS 8000

/* Publish the current endpoints/PreferredDERP on a fresh, short-lived side
 * connection, leaving the map long-poll untouched. Best effort: on any failure
 * the last-published values remain in effect and the next change retries. */
static void publish_oneshot(tsnet_control *c) {
    pthread_mutex_lock(&c->ep_lock);
    bool ready = c->have_control_key && !c->pub_stop;
    uint8_t control_pub[32];
    if (ready) memcpy(control_pub, c->control_pub, sizeof(control_pub));
    pthread_mutex_unlock(&c->ep_lock);
    if (!ready) return; /* not bootstrapped yet, or shutting down */

    tsnet_noisechan chan;
    memset(&chan, 0, sizeof(chan));
    int rc = tsnet_noisechan_connect(
        &chan, &c->url, c->ca_file[0] ? c->ca_file : NULL, c->machine_priv,
        control_pub, (uint16_t)TSNET_CAPABILITY_VERSION,
        PUBLISH_DIAL_TIMEOUT_MS);
    if (rc != TSNET_OK) {
        TSNET_LOGD("control: publish side-connection failed (%s); will retry "
                   "on next change",
                   tsnet_err_str(rc));
        return;
    }
    tsnet_h2 *h2 = NULL;
    rc = tsnet_h2_open(&h2, &chan, c->url.host);
    if (rc != TSNET_OK) {
        tsnet_noisechan_close(&chan);
        return;
    }
    int n = 0;
    int status = publish_on(c, h2, &n);
    tsnet_h2_close(h2);
    tsnet_noisechan_close(&chan);
    TSNET_LOGI("control: republished (disco + %d endpoints) -> HTTP %d "
               "(side connection, map stream untouched)",
               n, status);
}

/* Worker thread: publishes endpoint/PreferredDERP updates out-of-band so the
 * map long-poll never has to be torn down. */
static void *publish_main(void *arg) {
    tsnet_control *c = arg;
    for (;;) {
        pthread_mutex_lock(&c->ep_lock);
        while (!c->pub_req && !c->pub_stop)
            pthread_cond_wait(&c->pub_cv, &c->ep_lock);
        if (c->pub_stop) {
            pthread_mutex_unlock(&c->ep_lock);
            break;
        }
        c->pub_req = false;
        pthread_mutex_unlock(&c->ep_lock);
        publish_oneshot(c);
    }
    return NULL;
}

static int do_map(tsnet_control *c) {
    json_t *req = json_object();
    json_object_set_new(req, "Version",
                        json_integer(TSNET_CAPABILITY_VERSION));
    /* Compress "" = plain JSON messages (zstd
     * fallback via libzstd only if a server refuses this) */
    json_object_set_new(req, "Compress", json_string(""));
    json_object_set_new(req, "KeepAlive", json_true());
    json_object_set_new(req, "Stream", json_true());
    char nk[75], dk[75 + 16];
    key_str(c->node_pub, "nodekey:", nk);
    json_object_set_new(req, "NodeKey", json_string(nk));
    tsnet_key_format(c->disco_pub, "discokey:", dk);
    json_object_set_new(req, "DiscoKey", json_string(dk));
    json_object_set_new(req, "Hostinfo", build_hostinfo(c));
    /* The streaming MapRequest is read-only for capver>=68: the server ignores
     * Endpoints/DiscoKey/Hostinfo here. Endpoint and PreferredDERP updates go
     * out-of-band via the publish worker (do_publish / publish_oneshot), so we
     * deliberately omit the endpoint list from the long-poll. */

    char *body = json_dumps(req, JSON_COMPACT);
    json_decref(req);
    if (!body) return TSNET_E_NOMEM;

    c->mapbuf_len = 0;
    c->map_msgs_seen = 0;
    c->map_error = 0;
    const char *prefix = strcmp(c->url.path, "/") == 0 ? "" : c->url.path;
    char path[300];
    snprintf(path, sizeof(path), "%s/machine/map", prefix);
    TSNET_LOGI("control: opening map stream");
    tsnet_cstream_set_timeout(c->chan.cs, MAP_READ_TIMEOUT_MS);
    int status = tsnet_h2_post(c->h2, path, nk, body, strlen(body),
                               map_data_cb, c);
    free(body);
    if (c->map_error) return TSNET_E_PROTO;
    if (status == TSNET_E_CLOSED && c->stop) return TSNET_OK;
    if (status < 0) return status;
    if (status != 200) {
        TSNET_LOGE("control: map -> HTTP %d", status);
        return TSNET_E_PROTO;
    }
    /* a clean end of a streaming map is unusual; treat as reconnect */
    return TSNET_E_CLOSED;
}

/* ---- channel lifecycle -------------------------------------------------------- */

static void teardown_channel(tsnet_control *c) {
    if (c->h2) {
        tsnet_h2_close(c->h2);
        c->h2 = NULL;
    }
    /* clear chan_up under the lock so a concurrent stop() cannot call
     * tsnet_cstream_shutdown() on a channel we are about to free */
    pthread_mutex_lock(&c->chan_lock);
    bool was_up = c->chan_up;
    c->chan_up = false;
    pthread_mutex_unlock(&c->chan_lock);
    if (was_up) tsnet_noisechan_close(&c->chan);
}

static int setup_channel(tsnet_control *c) {
    int rc = tsnet_noisechan_connect(&c->chan, &c->url,
                                     c->ca_file[0] ? c->ca_file : NULL,
                                     c->machine_priv, c->control_pub,
                                     (uint16_t)TSNET_CAPABILITY_VERSION,
                                     DIAL_TIMEOUT_MS);
    if (rc != TSNET_OK) return rc;
    pthread_mutex_lock(&c->chan_lock);
    c->chan_up = true;
    pthread_mutex_unlock(&c->chan_lock);
    rc = tsnet_h2_open(&c->h2, &c->chan, c->url.host);
    if (rc != TSNET_OK) {
        teardown_channel(c);
        return rc;
    }
    return TSNET_OK;
}

/* ---- public API ----------------------------------------------------------------- */

int tsnet_control_create(tsnet_control **out, const tsnet_config *cfg,
                         const tsnet_control_cbs *cbs) {
    if (tsnet_crypto_init() != 0) return TSNET_E_STATE;
    tsnet_control *c = calloc(1, sizeof(*c));
    if (!c) return TSNET_E_NOMEM;
    snprintf(c->server_url, sizeof(c->server_url), "%s",
             cfg->server_url ? cfg->server_url
                             : "https://controlplane.tailscale.com");
    snprintf(c->state_dir, sizeof(c->state_dir), "%s",
             cfg->state_dir ? cfg->state_dir : "./tsnet-state");
    snprintf(c->hostname, sizeof(c->hostname), "%s",
             cfg->hostname ? cfg->hostname : "moonlight-switch");
    if (cfg->auth_key)
        snprintf(c->auth_key, sizeof(c->auth_key), "%s", cfg->auth_key);
    if (cbs) c->cbs = *cbs;
    pthread_mutex_init(&c->chan_lock, NULL);
    pthread_mutex_init(&c->ep_lock, NULL);
    pthread_cond_init(&c->pub_cv, NULL);

    snprintf(c->ca_file, sizeof(c->ca_file), "%s", TSNET_CA_BUNDLE);

    if (!tsnet_url_parse(c->server_url, &c->url)) {
        free(c);
        return TSNET_E_INVAL;
    }
    int rc = load_keys(c);
    if (rc != TSNET_OK) {
        free(c);
        return rc;
    }
    /* start the endpoint-publish worker (idles on pub_cv until a change); it
     * needs the large stack for its side-connection TLS handshake */
    if (tsnet_thread_create(&c->pub_thread, publish_main, c) == 0)
        c->pub_thread_up = true;
    else
        TSNET_LOGW("control: publish worker not started; mid-session endpoint "
                   "updates will not be published");
    *out = c;
    return TSNET_OK;
}

int tsnet_control_run(tsnet_control *c) {
    int backoff_ms = 1000;
    while (!c->stop) {
        set_state(c, TSNET_ST_STARTING, "connecting to control");
        int rc = c->have_control_key ? TSNET_OK : fetch_control_key(c);
        if (rc == TSNET_OK) {
            rc = setup_channel(c);
            /* a handshake failure may mean the server rotated its Noise key
             * (cached from a previous /key): drop the cache so the next
             * attempt re-fetches it */
            if (rc != TSNET_OK) c->have_control_key = false;
        }
        if (rc == TSNET_OK) rc = do_register(c);
        /* publish disco key + endpoints + NetInfo with a non-streaming request
         * BEFORE the (read-only) long-poll, so real Tailscale actually stores
         * them and peers can reach us (see do_publish) */
        if (rc == TSNET_OK) rc = do_publish(c);
        if (rc == TSNET_OK) rc = do_map(c); /* blocks while the stream lives */
        teardown_channel(c);
        if (c->stop) break;
        /* reset the backoff only after a *productive* session (at least one
         * map message), so a stream that fails immediately still backs off
         * exponentially instead of hammering at ~1 s */
        if (c->map_msgs_seen > 0) backoff_ms = 1000;
        if (rc == TSNET_E_AUTH) {
            /* Auth was rejected. If we were using an auth key, it is
             * invalid/expired/already-used: clear it and stop rather than
             * looping forever on a key that cannot succeed. The user can
             * retry with a fresh key (or a keyless login). */
            if (c->auth_key[0]) {
                memset(c->auth_key, 0, sizeof(c->auth_key));
                set_state(c, TSNET_ST_NEEDS_LOGIN, "invalid auth key");
            } else {
                set_state(c, TSNET_ST_NEEDS_LOGIN, "authentication required");
            }
            return rc;
        }
        set_state(c, TSNET_ST_STARTING, "reconnecting");
        TSNET_LOGW("control: connection lost (%s), retry in %d ms",
                   tsnet_err_str(rc), backoff_ms);
        for (int slept = 0; slept < backoff_ms && !c->stop; slept += 100) {
            struct timespec ts = {0, 100 * 1000 * 1000};
            nanosleep(&ts, NULL);
        }
        backoff_ms = backoff_ms * 2 > 30000 ? 30000 : backoff_ms * 2;
    }
    set_state(c, TSNET_ST_STOPPED, "stopped");
    return TSNET_OK;
}

/* Unblock the control thread's current stream read from another thread by
 * shutting the socket down, under chan_lock so teardown_channel cannot free
 * the channel out from under us, which would be a use-after-free. */
static void shutdown_channel_locked(tsnet_control *c) {
    pthread_mutex_lock(&c->chan_lock);
    if (c->chan_up && c->chan.cs) tsnet_cstream_shutdown(c->chan.cs);
    pthread_mutex_unlock(&c->chan_lock);
}

void tsnet_control_stop(tsnet_control *c) {
    c->stop = 1;
    /* wake the publish worker so it stops idling / doesn't start a new dial */
    pthread_mutex_lock(&c->ep_lock);
    c->pub_stop = true;
    pthread_cond_signal(&c->pub_cv);
    pthread_mutex_unlock(&c->ep_lock);
    shutdown_channel_locked(c);
}

const tsnet_netmap *tsnet_control_netmap(tsnet_control *c) {
    return &c->netmap;
}

/* Wake the publish worker to send the current endpoints/PreferredDERP to the
 * server out-of-band, without disturbing the map long-poll. */
static void request_publish(tsnet_control *c) {
    pthread_mutex_lock(&c->ep_lock);
    c->pub_req = true;
    pthread_cond_signal(&c->pub_cv);
    pthread_mutex_unlock(&c->ep_lock);
}

int tsnet_control_set_endpoints(tsnet_control *c, const char **eps, int n) {
    if (n > TSNET_MAX_ENDPOINTS) n = TSNET_MAX_ENDPOINTS;
    pthread_mutex_lock(&c->ep_lock);
    bool changed = n != c->n_endpoints;
    for (int i = 0; i < n && !changed; i++)
        changed = strcmp(c->endpoints[i], eps[i]) != 0;
    if (changed) {
        for (int i = 0; i < n; i++)
            snprintf(c->endpoints[i], sizeof(c->endpoints[i]), "%s", eps[i]);
        c->n_endpoints = n;
    }
    pthread_mutex_unlock(&c->ep_lock);
    if (!changed) return TSNET_OK;
    TSNET_LOGI("control: endpoints updated (%d)", n);
    request_publish(c);
    return TSNET_OK;
}

int tsnet_control_set_preferred_derp(tsnet_control *c, int region) {
    pthread_mutex_lock(&c->ep_lock);
    bool changed = region > 0 && region != c->preferred_derp;
    if (changed) c->preferred_derp = region;
    pthread_mutex_unlock(&c->ep_lock);
    if (!changed) return TSNET_OK;
    TSNET_LOGI("control: preferred DERP -> %d", region);
    request_publish(c);
    return TSNET_OK;
}

void tsnet_control_destroy(tsnet_control *c) {
    if (!c) return;
    /* stop and join the publish worker before tearing anything down */
    if (c->pub_thread_up) {
        pthread_mutex_lock(&c->ep_lock);
        c->pub_stop = true;
        pthread_cond_signal(&c->pub_cv);
        pthread_mutex_unlock(&c->ep_lock);
        pthread_join(c->pub_thread, NULL);
        c->pub_thread_up = false;
    }
    teardown_channel(c);
    pthread_cond_destroy(&c->pub_cv);
    pthread_mutex_destroy(&c->ep_lock);
    pthread_mutex_destroy(&c->chan_lock);
    free(c->mapbuf);
    memset(c->machine_priv, 0, sizeof(c->machine_priv));
    memset(c->node_priv, 0, sizeof(c->node_priv));
    memset(c->disco_priv, 0, sizeof(c->disco_priv));
    free(c);
}
