#ifndef TSNET_UTIL_B64_H
#define TSNET_UTIL_B64_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Standard base64 (RFC 4648, with padding), as Go encoding/base64.StdEncoding
 * used for the X-Tailscale-Handshake header
 * (tailscale: control/controlhttp/client.go). */

/* Bytes needed for encoding n bytes, including NUL. */
#define TSNET_B64_ENC_LEN(n) (((n) + 2) / 3 * 4 + 1)

/* Encode; out must hold TSNET_B64_ENC_LEN(n). Returns strlen of result. */
size_t tsnet_b64_encode(const uint8_t *in, size_t n, char *out);

/* Decode; out must hold at least strlen(b64)/4*3 bytes. On success stores
 * decoded length in *out_len. Rejects invalid characters/padding. */
bool tsnet_b64_decode(const char *b64, uint8_t *out, size_t *out_len);

#endif
