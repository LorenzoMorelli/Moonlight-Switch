/* libsodium-backed AEADs and platform hooks for the wireguard-lwip core
 * (see crypto_sodium.h / scripts/gen-wg.cmake). */
#include "platform/platform.h"

#include <sodium.h>
#include <stdbool.h>
#include <pthread.h>
#include <string.h>

/* WireGuard AEAD nonce: 4 zero bytes + 64-bit little-endian counter
 * (RFC 7539 layout, WireGuard whitepaper §5.4) */
static void make_nonce(uint8_t out[12], uint64_t counter) {
    memset(out, 0, 4);
    for (int i = 0; i < 8; i++) out[4 + i] = (uint8_t)(counter >> (8 * i));
}

void tsnet_wg_aead_encrypt(uint8_t *dst, const uint8_t *src, size_t src_len,
                           const uint8_t *ad, size_t ad_len, uint64_t nonce,
                           const uint8_t *key) {
    uint8_t npub[12];
    make_nonce(npub, nonce);
    unsigned long long clen;
    crypto_aead_chacha20poly1305_ietf_encrypt(dst, &clen, src, src_len, ad,
                                              ad_len, NULL, npub, key);
}

bool tsnet_wg_aead_decrypt(uint8_t *dst, const uint8_t *src, size_t src_len,
                           const uint8_t *ad, size_t ad_len, uint64_t nonce,
                           const uint8_t *key) {
    uint8_t npub[12];
    make_nonce(npub, nonce);
    /* callers pass dst=NULL for empty-plaintext tags */
    uint8_t dummy[1];
    unsigned long long mlen;
    return crypto_aead_chacha20poly1305_ietf_decrypt(
               dst ? dst : dummy, &mlen, NULL, src, src_len, ad, ad_len, npub,
               key) == 0;
}

void tsnet_wg_xaead_encrypt(uint8_t *dst, const uint8_t *src, size_t src_len,
                            const uint8_t *ad, size_t ad_len,
                            const uint8_t *nonce24, const uint8_t *key) {
    unsigned long long clen;
    crypto_aead_xchacha20poly1305_ietf_encrypt(dst, &clen, src, src_len, ad,
                                               ad_len, NULL, nonce24, key);
}

bool tsnet_wg_xaead_decrypt(uint8_t *dst, const uint8_t *src, size_t src_len,
                            const uint8_t *ad, size_t ad_len,
                            const uint8_t *nonce24, const uint8_t *key) {
    uint8_t dummy[1];
    unsigned long long mlen;
    return crypto_aead_xchacha20poly1305_ietf_decrypt(
               dst ? dst : dummy, &mlen, NULL, src, src_len, ad, ad_len,
               nonce24, key) == 0;
}

/* ---- wireguard-platform.h hooks ---------------------------------------- */

uint32_t wireguard_sys_now(void) { return (uint32_t)tsnet_now_ms(); }

void wireguard_random_bytes(void *bytes, size_t size) {
    tsnet_rand_bytes(bytes, size);
}

/* tai64n: 8-byte big-endian seconds (with 2^62 offset) + 4-byte BE nanos.
 * WireGuard uses this only as a monotonically increasing anti-replay
 * counter in handshake initiations, so it must NEVER go backwards. Deriving
 * seconds and sub-second parts from two different clocks (wall + monotonic
 * mod 1000) could regress and make the peer reject the handshake; instead
 * derive both from one monotonic source and enforce monotonicity. */
void wireguard_tai64n_now(uint8_t *output) {
    static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
    static uint64_t last;
    uint64_t base = 0x400000000000000aULL + (uint64_t)tsnet_wall_time();
    uint64_t ms = tsnet_now_ms();
    /* pack seconds + nanoseconds into one 96-bit-ish comparable value via a
     * 64-bit seconds field plus a 32-bit nanos field, but keep them
     * consistent: seconds from wall clock, nanos from the monotonic ms */
    uint64_t secs = base;
    uint32_t nanos = (uint32_t)((ms % 1000) * 1000000);
    pthread_mutex_lock(&mu);
    /* enforce strictly non-decreasing (secs,nanos) across calls */
    uint64_t packed = secs * 1000 + (nanos / 1000000);
    if (packed <= last) {
        packed = last + 1;
        secs = packed / 1000;
        nanos = (uint32_t)((packed % 1000) * 1000000);
    }
    last = packed;
    pthread_mutex_unlock(&mu);
    for (int i = 0; i < 8; i++) output[i] = (uint8_t)(secs >> (8 * (7 - i)));
    for (int i = 0; i < 4; i++)
        output[8 + i] = (uint8_t)(nanos >> (8 * (3 - i)));
}

bool wireguard_is_under_load(void) { return false; }
