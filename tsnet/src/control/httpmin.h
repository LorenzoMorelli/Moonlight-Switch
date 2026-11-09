#ifndef TSNET_CONTROL_HTTPMIN_H
#define TSNET_CONTROL_HTTPMIN_H

/* Minimal HTTP/1.1 client for exactly two exchanges:
 *  - GET <server>/key?v=<capver>            (bootstrap, small JSON body)
 *  - POST <server>/ts2021 + Upgrade         (101 -> Noise byte stream)
 * Formats per tailscale: control/controlhttp/client.go and
 * controlclient/direct.go. Everything else speaks h2 inside Noise.
 */

#include "cstream.h"

#include <stddef.h>
#include <stdint.h>

/* GET path on an open stream. Returns HTTP status code (>0) with the body
 * copied into body (NUL-terminated, cap includes NUL), or -1 on transport/
 * parse error. Supports Content-Length and closes-on-EOF bodies. */
int tsnet_http_get(tsnet_cstream *s, const char *host, const char *path,
                   char *body, size_t body_cap);

/* POST path with Upgrade: tailscale-control-protocol and the base64
 * X-Tailscale-Handshake header (client.go). On success (101 with
 * matching Upgrade header) returns 0 and the stream is the Noise channel
 * (over-read bytes preserved in the stream buffer). Returns HTTP status on
 * non-101, -1 on error. */
int tsnet_http_upgrade_ts2021(tsnet_cstream *s, const char *host,
                              const char *path_prefix,
                              const uint8_t init[101]);

#endif
