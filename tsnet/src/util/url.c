#include "url.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool tsnet_url_parse(const char *url, tsnet_url *out) {
    memset(out, 0, sizeof(*out));
    const char *p;
    if (strncmp(url, "https://", 8) == 0) {
        out->tls = true;
        out->port = 443;
        p = url + 8;
    } else if (strncmp(url, "http://", 7) == 0) {
        out->tls = false;
        out->port = 80;
        p = url + 7;
    } else {
        return false;
    }

    const char *host_end;
    if (*p == '[') { /* IPv6 literal */
        const char *close = strchr(p, ']');
        if (!close) return false;
        size_t n = (size_t)(close - p - 1);
        if (n == 0 || n >= sizeof(out->host)) return false;
        memcpy(out->host, p + 1, n);
        out->host[n] = '\0';
        host_end = close + 1;
        /* after ']' only ':' (port) or '/' (path) or end are valid */
        if (*host_end && *host_end != ':' && *host_end != '/') return false;
    } else {
        host_end = p;
        while (*host_end && *host_end != ':' && *host_end != '/') host_end++;
        size_t n = (size_t)(host_end - p);
        if (n == 0 || n >= sizeof(out->host)) return false;
        memcpy(out->host, p, n);
        out->host[n] = '\0';
    }

    if (*host_end == ':') {
        char *end;
        long port = strtol(host_end + 1, &end, 10);
        if (port <= 0 || port > 65535 || (*end && *end != '/')) return false;
        out->port = (uint16_t)port;
        host_end = end;
    }
    const char *path = *host_end ? host_end : "/";
    if (strlen(path) >= sizeof(out->path)) return false; /* no silent trunc */
    snprintf(out->path, sizeof(out->path), "%s", path);
    return true;
}
