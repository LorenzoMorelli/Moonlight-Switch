#ifndef TSNET_UTIL_URL_H
#define TSNET_UTIL_URL_H

#include <stdbool.h>
#include <stdint.h>

/* Minimal URL splitter for control/DERP endpoints:
 * "http://host", "https://host:port", "https://[v6]:port". No userinfo,
 * query or fragment support (not needed for control URLs). */
typedef struct tsnet_url {
    bool tls;        /* https */
    char host[256];  /* hostname or literal IP (brackets stripped) */
    uint16_t port;   /* explicit or scheme default */
    char path[256];  /* "/" if absent */
} tsnet_url;

bool tsnet_url_parse(const char *url, tsnet_url *out);

#endif
