#include "b64.h"

#include <string.h>

static const char enc_tab[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t tsnet_b64_encode(const uint8_t *in, size_t n, char *out) {
    size_t o = 0;
    size_t i = 0;
    for (; i + 3 <= n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8 | in[i + 2];
        out[o++] = enc_tab[(v >> 18) & 0x3f];
        out[o++] = enc_tab[(v >> 12) & 0x3f];
        out[o++] = enc_tab[(v >> 6) & 0x3f];
        out[o++] = enc_tab[v & 0x3f];
    }
    size_t rem = n - i;
    if (rem == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = enc_tab[(v >> 18) & 0x3f];
        out[o++] = enc_tab[(v >> 12) & 0x3f];
        out[o++] = '=';
        out[o++] = '=';
    } else if (rem == 2) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8;
        out[o++] = enc_tab[(v >> 18) & 0x3f];
        out[o++] = enc_tab[(v >> 12) & 0x3f];
        out[o++] = enc_tab[(v >> 6) & 0x3f];
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

static int dec_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

bool tsnet_b64_decode(const char *b64, uint8_t *out, size_t *out_len) {
    size_t n = strlen(b64);
    if (n % 4 != 0) return false;
    size_t o = 0;
    for (size_t i = 0; i < n; i += 4) {
        int pad = 0;
        int v[4];
        for (int j = 0; j < 4; j++) {
            char c = b64[i + j];
            if (c == '=') {
                /* padding only allowed in the last two positions of the
                 * final group, and nothing may follow it */
                if (i + 4 != n || j < 2) return false;
                if (j == 2 && b64[i + 3] != '=') return false;
                pad++;
                v[j] = 0;
            } else {
                if (pad) return false;
                v[j] = dec_val(c);
                if (v[j] < 0) return false;
            }
        }
        uint32_t x = (uint32_t)v[0] << 18 | (uint32_t)v[1] << 12 |
                     (uint32_t)v[2] << 6 | (uint32_t)v[3];
        out[o++] = (uint8_t)(x >> 16);
        if (pad < 2) out[o++] = (uint8_t)(x >> 8);
        if (pad < 1) out[o++] = (uint8_t)x;
    }
    *out_len = o;
    return true;
}
