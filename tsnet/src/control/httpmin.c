#include "httpmin.h"

#include "util/b64.h"
#include "util/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int str_ieq(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
        a++;
        b++;
    }
    return *a == *b;
}

/* Parse status line + headers. Returns status code or -1. Fills
 * content_length (-1 if absent) and upgrade_hdr (may be ""). */
static int read_response_head(tsnet_cstream *s, long *content_length,
                              char *upgrade_hdr, size_t upgrade_cap) {
    char line[1024];
    if (tsnet_cstream_read_line(s, line, sizeof(line)) < 0) return -1;
    int status = 0;
    if (sscanf(line, "HTTP/1.%*d %d", &status) != 1 || status < 100) {
        TSNET_LOGE("http: bad status line: %.80s", line);
        return -1;
    }
    *content_length = -1;
    if (upgrade_cap) upgrade_hdr[0] = '\0';
    for (;;) {
        int n = tsnet_cstream_read_line(s, line, sizeof(line));
        if (n < 0) return -1;
        if (n == 0) break; /* end of headers */
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        char *val = colon + 1;
        while (*val == ' ' || *val == '\t') val++;
        if (str_ieq(line, "content-length")) {
            *content_length = strtol(val, NULL, 10);
        } else if (str_ieq(line, "upgrade") && upgrade_cap) {
            snprintf(upgrade_hdr, upgrade_cap, "%s", val);
        }
    }
    return status;
}

int tsnet_http_get(tsnet_cstream *s, const char *host, const char *path,
                   char *body, size_t body_cap) {
    char req[768];
    int n = snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Connection: close\r\n"
                     "User-Agent: moonlight-tsnet\r\n"
                     "\r\n",
                     path, host);
    if (n < 0 || (size_t)n >= sizeof(req)) return -1;
    if (tsnet_cstream_write(s, req, (size_t)n) < 0) return -1;

    long clen;
    int status = read_response_head(s, &clen, NULL, 0);
    if (status < 0) return -1;

    size_t got = 0;
    if (clen >= 0) {
        if ((size_t)clen >= body_cap) return -1;
        if (tsnet_cstream_read_full(s, body, (size_t)clen) < 0) return -1;
        got = (size_t)clen;
    } else {
        /* read until EOF (Connection: close) */
        for (;;) {
            ssize_t r = tsnet_cstream_read(s, body + got, body_cap - 1 - got);
            if (r <= 0) break;
            got += (size_t)r;
            if (got >= body_cap - 1) break;
        }
    }
    body[got] = '\0';
    return status;
}

int tsnet_http_upgrade_ts2021(tsnet_cstream *s, const char *host,
                              const char *path_prefix,
                              const uint8_t init[101]) {
    char b64[TSNET_B64_ENC_LEN(101)];
    tsnet_b64_encode(init, 101, b64);

    /* POST + headers per control/controlhttp/client.go; the upgrade
     * path is "/ts2021" (constants.go), possibly under a prefix when the
     * server URL has a path component. */
    char req[1024];
    int n = snprintf(req, sizeof(req),
                     "POST %s/ts2021 HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Upgrade: tailscale-control-protocol\r\n"
                     "Connection: upgrade\r\n"
                     "X-Tailscale-Handshake: %s\r\n"
                     "Content-Length: 0\r\n"
                     "\r\n",
                     path_prefix ? path_prefix : "", host, b64);
    if (n < 0 || (size_t)n >= sizeof(req)) return -1;
    if (tsnet_cstream_write(s, req, (size_t)n) < 0) return -1;

    long clen;
    char upgrade[64];
    int status = read_response_head(s, &clen, upgrade, sizeof(upgrade));
    if (status < 0) return -1;
    if (status != 101) {
        TSNET_LOGE("http: ts2021 upgrade refused: %d", status);
        return status;
    }
    if (strcmp(upgrade, "tailscale-control-protocol") != 0) {
        TSNET_LOGE("http: unexpected upgrade protocol %s", upgrade);
        return -1;
    }
    return 0;
}
