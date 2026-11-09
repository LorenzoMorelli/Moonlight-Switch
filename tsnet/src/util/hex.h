#ifndef TSNET_UTIL_HEX_H
#define TSNET_UTIL_HEX_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Encode n bytes as lowercase hex. out must hold 2*n+1 bytes (NUL added). */
void tsnet_hex_encode(const uint8_t *in, size_t n, char *out);

/* Decode hex (upper or lower). Returns true on success; out must hold
 * strlen(hex)/2 bytes. Fails on odd length or non-hex characters. */
bool tsnet_hex_decode(const char *hex, uint8_t *out, size_t out_len);

/* Parse a Tailscale textual key "<prefix><64 hex>" (e.g. "mkey:ab12...",
 * "nodekey:...", "discokey:...", "privkey:...") into 32 raw bytes.
 * prefix must include the colon. Returns true on success. */
bool tsnet_key_parse(const char *text, const char *prefix, uint8_t out[32]);

/* Format 32 raw bytes as "<prefix><64 hex>". out must hold
 * strlen(prefix)+65 bytes. */
void tsnet_key_format(const uint8_t key[32], const char *prefix, char *out);

#endif
