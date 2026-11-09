#include "hex.h"

#include <string.h>

static const char hexdigits[] = "0123456789abcdef";

void tsnet_hex_encode(const uint8_t *in, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hexdigits[in[i] >> 4];
        out[2 * i + 1] = hexdigits[in[i] & 0xf];
    }
    out[2 * n] = '\0';
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool tsnet_hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    size_t n = strlen(hex);
    if (n % 2 != 0 || n / 2 != out_len) return false;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

bool tsnet_key_parse(const char *text, const char *prefix, uint8_t out[32]) {
    size_t plen = strlen(prefix);
    if (strncmp(text, prefix, plen) != 0) return false;
    return tsnet_hex_decode(text + plen, out, 32);
}

void tsnet_key_format(const uint8_t key[32], const char *prefix, char *out) {
    size_t plen = strlen(prefix);
    memcpy(out, prefix, plen);
    tsnet_hex_encode(key, 32, out + plen);
}
