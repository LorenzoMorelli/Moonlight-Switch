#include "cstream.h"

#include "platform/platform.h"
#include "util/log.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h> /* MBEDTLS_ERR_NET_* codes only */
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

struct tsnet_cstream {
    int fd;
    bool tls;
    /* read buffer (also holds HTTP over-read leftovers) */
    uint8_t rbuf[4096];
    size_t roff, rlen;

    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt ca;
    mbedtls_ctr_drbg_context drbg;
};

static int bio_send(void *ctx, const unsigned char *buf, size_t len) {
    tsnet_cstream *s = ctx;
    ssize_t n = tsnet_plat_sock_write(s->fd, buf, len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return (int)n;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len) {
    tsnet_cstream *s = ctx;
    ssize_t n = tsnet_plat_sock_read(s->fd, buf, len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return MBEDTLS_ERR_SSL_WANT_READ;
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    return (int)n;
}

static int rng_cb(void *ctx, unsigned char *buf, size_t len) {
    (void)ctx;
    tsnet_rand_bytes(buf, len);
    return 0;
}

/* ctr_drbg entropy source. We deliberately do NOT use mbedtls_entropy_func:
 * the switch-mbedtls hardware poll draws from the csrng *service*
 * (csrngGetRandomBytes), which is not in libnx's default init set, so on
 * Horizon the seed would fail or seed weakly. tsnet_rand_bytes() is libnx's
 * userspace CSPRNG (randomGet), always available and used for the handshake
 * f_rng too — so seed the DRBG from the same source. */
static int entropy_cb(void *ctx, unsigned char *buf, size_t len) {
    (void)ctx;
    tsnet_rand_bytes(buf, len);
    return 0;
}

static void log_mbedtls_err(const char *what, int rc) {
    char err[128];
    mbedtls_strerror(rc, err, sizeof(err));
    TSNET_LOGE("cstream: %s failed: -0x%04x %s", what, (unsigned)-rc, err);
}

tsnet_cstream *tsnet_cstream_dial(const char *host, uint16_t port, bool tls,
                                  const char *sni, const char *ca_file,
                                  int timeout_ms) {
    tsnet_cstream *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    TSNET_LOGI("cstream: dial %s:%u tls=%d", host, port, tls);
    s->fd = tsnet_plat_tcp_dial(host, port, timeout_ms);
    if (s->fd < 0) {
        TSNET_LOGE("cstream: tcp dial %s:%u failed errno=%d", host, port,
                   errno);
        free(s);
        return NULL;
    }
    if (!tls) return s;

    s->tls = true;
    mbedtls_ssl_init(&s->ssl);
    mbedtls_ssl_config_init(&s->conf);
    mbedtls_x509_crt_init(&s->ca);
    mbedtls_ctr_drbg_init(&s->drbg);

    int rc = mbedtls_ctr_drbg_seed(&s->drbg, entropy_cb, NULL, NULL, 0);
    if (rc != 0) {
        log_mbedtls_err("ctr_drbg_seed", rc);
        goto fail;
    }
    rc = mbedtls_ssl_config_defaults(&s->conf, MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc != 0) {
        log_mbedtls_err("ssl_config_defaults", rc);
        goto fail;
    }
    mbedtls_ssl_conf_rng(&s->conf, rng_cb, NULL);

    if (!ca_file) {
        TSNET_LOGE("cstream: no CA bundle configured");
        goto fail;
    }
    rc = mbedtls_x509_crt_parse_file(&s->ca, ca_file);
    if (rc < 0) {
        log_mbedtls_err("x509_crt_parse_file", rc);
        goto fail;
    }
    mbedtls_ssl_conf_ca_chain(&s->conf, &s->ca, NULL);
    mbedtls_ssl_conf_authmode(&s->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    rc = mbedtls_ssl_setup(&s->ssl, &s->conf);
    if (rc != 0) {
        log_mbedtls_err("ssl_setup", rc);
        goto fail;
    }
    if (sni) mbedtls_ssl_set_hostname(&s->ssl, sni);
    mbedtls_ssl_set_bio(&s->ssl, s, bio_send, bio_recv, NULL);

    TSNET_LOGI("cstream: TLS handshake start (%s)", host);
    while ((rc = mbedtls_ssl_handshake(&s->ssl)) != 0) {
        if (rc != MBEDTLS_ERR_SSL_WANT_READ &&
            rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
            log_mbedtls_err("ssl_handshake", rc);
            uint32_t flags = mbedtls_ssl_get_verify_result(&s->ssl);
            if (flags) {
                char vbuf[256];
                mbedtls_x509_crt_verify_info(vbuf, sizeof(vbuf), "  ", flags);
                TSNET_LOGE("cstream: cert verify: %s", vbuf);
            }
            goto fail;
        }
    }
    TSNET_LOGD("cstream: TLS up to %s:%u (%s)", host, port,
               mbedtls_ssl_get_version(&s->ssl));
    return s;

fail:
    tsnet_cstream_close(s);
    return NULL;
}

static ssize_t raw_read(tsnet_cstream *s, void *buf, size_t n) {
    if (s->tls) {
        int rc;
        do {
            rc = mbedtls_ssl_read(&s->ssl, buf, n);
        } while (rc == MBEDTLS_ERR_SSL_WANT_READ ||
                 rc == MBEDTLS_ERR_SSL_WANT_WRITE);
        if (rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return 0;
        return rc;
    }
    return tsnet_plat_sock_read(s->fd, buf, n);
}

ssize_t tsnet_cstream_read(tsnet_cstream *s, void *buf, size_t n) {
    if (s->rlen > s->roff) {
        size_t take = s->rlen - s->roff;
        if (take > n) take = n;
        memcpy(buf, s->rbuf + s->roff, take);
        s->roff += take;
        return (ssize_t)take;
    }
    return raw_read(s, buf, n);
}

int tsnet_cstream_read_full(tsnet_cstream *s, void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = tsnet_cstream_read(s, (uint8_t *)buf + off, n - off);
        if (r <= 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

int tsnet_cstream_write(tsnet_cstream *s, const void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w;
        if (s->tls) {
            int rc;
            do {
                rc = mbedtls_ssl_write(&s->ssl, (const uint8_t *)buf + off,
                                       n - off);
            } while (rc == MBEDTLS_ERR_SSL_WANT_READ ||
                     rc == MBEDTLS_ERR_SSL_WANT_WRITE);
            w = rc;
        } else {
            w = tsnet_plat_sock_write(s->fd, (const uint8_t *)buf + off,
                                      n - off);
        }
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

int tsnet_cstream_read_line(tsnet_cstream *s, char *buf, size_t cap) {
    size_t len = 0;
    while (len + 1 < cap) {
        char c;
        /* fill the buffer if empty, then consume byte-wise from it */
        if (s->roff >= s->rlen) {
            ssize_t r = raw_read(s, s->rbuf, sizeof(s->rbuf));
            if (r <= 0) return -1;
            s->roff = 0;
            s->rlen = (size_t)r;
        }
        c = (char)s->rbuf[s->roff++];
        if (c == '\n') {
            if (len > 0 && buf[len - 1] == '\r') len--;
            buf[len] = '\0';
            return (int)len;
        }
        buf[len++] = c;
    }
    return -1; /* line too long */
}

int tsnet_cstream_set_timeout(tsnet_cstream *s, int timeout_ms) {
    return tsnet_plat_sock_set_timeout(s->fd, timeout_ms);
}

void tsnet_cstream_shutdown(tsnet_cstream *s) {
    if (s && s->fd >= 0) tsnet_plat_sock_shutdown(s->fd);
}

void tsnet_cstream_close(tsnet_cstream *s) {
    if (!s) return;
    if (s->tls) {
        mbedtls_ssl_close_notify(&s->ssl);
        mbedtls_ssl_free(&s->ssl);
        mbedtls_ssl_config_free(&s->conf);
        mbedtls_x509_crt_free(&s->ca);
        mbedtls_ctr_drbg_free(&s->drbg);
    }
    if (s->fd >= 0) tsnet_plat_sock_close(s->fd);
    free(s);
}
