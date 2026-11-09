#include "tscrypto.h"

#include <sodium.h>
#include <string.h>

#include "blake2s.h" /* wireguard-lwip reference implementation */
#include "platform/platform.h"

int tsnet_crypto_init(void) {
    /* Must precede sodium_init(): on Switch it swaps libsodium's /dev/urandom
     * randombytes for the libnx CSPRNG, otherwise sodium_init() aborts. */
    tsnet_plat_crypto_prepare();
    return sodium_init() < 0 ? -1 : 0;
}

void tsnet_blake2s(uint8_t out[32], const void *in, size_t len) {
    blake2s(out, 32, NULL, 0, in, len);
}

void tsnet_blake2s2(uint8_t out[32], const void *a, size_t alen,
                    const void *b, size_t blen) {
    blake2s_ctx ctx;
    blake2s_init(&ctx, 32, NULL, 0);
    blake2s_update(&ctx, a, alen);
    blake2s_update(&ctx, b, blen);
    blake2s_final(&ctx, out);
}

void tsnet_hmac_blake2s(uint8_t out[32], const uint8_t *key, size_t keylen,
                        const void *msg, size_t msglen) {
    /* RFC 2104 with B=64 (BLAKE2s block size) */
    uint8_t k[BLAKE2S_BLOCK_SIZE];
    memset(k, 0, sizeof(k));
    if (keylen > sizeof(k)) {
        tsnet_blake2s(k, key, keylen);
    } else {
        memcpy(k, key, keylen);
    }
    uint8_t pad[BLAKE2S_BLOCK_SIZE];
    for (int i = 0; i < BLAKE2S_BLOCK_SIZE; i++) pad[i] = k[i] ^ 0x36;
    blake2s_ctx ctx;
    blake2s_init(&ctx, 32, NULL, 0);
    blake2s_update(&ctx, pad, sizeof(pad));
    blake2s_update(&ctx, msg, msglen);
    uint8_t inner[32];
    blake2s_final(&ctx, inner);
    for (int i = 0; i < BLAKE2S_BLOCK_SIZE; i++) pad[i] = k[i] ^ 0x5c;
    blake2s_init(&ctx, 32, NULL, 0);
    blake2s_update(&ctx, pad, sizeof(pad));
    blake2s_update(&ctx, inner, sizeof(inner));
    blake2s_final(&ctx, out);
}

void tsnet_hkdf_blake2s(const uint8_t *ikm, size_t ikm_len,
                        const uint8_t *salt, size_t salt_len,
                        uint8_t out[][32], int n_out) {
    /* RFC 5869: PRK = HMAC(salt, IKM); T(i) = HMAC(PRK, T(i-1)||i) */
    uint8_t prk[32];
    tsnet_hmac_blake2s(prk, salt, salt_len, ikm, ikm_len);
    uint8_t t[33];
    size_t tlen = 0;
    for (int i = 0; i < n_out; i++) {
        t[tlen] = (uint8_t)(i + 1);
        tsnet_hmac_blake2s(out[i], prk, sizeof(prk), t, tlen + 1);
        memcpy(t, out[i], 32);
        tlen = 32;
    }
}

int tsnet_x25519(uint8_t shared[32], const uint8_t priv[32],
                 const uint8_t pub[32]) {
    /* crypto_scalarmult returns -1 iff the result is all zeros, matching
     * Go curve25519.X25519's error on a low-order point */
    return crypto_scalarmult(shared, priv, pub);
}

void tsnet_x25519_pubkey(uint8_t pub[32], const uint8_t priv[32]) {
    crypto_scalarmult_base(pub, priv);
}

void tsnet_x25519_keygen(uint8_t priv[32], uint8_t pub[32]) {
    randombytes_buf(priv, 32);
    /* clamp as Go types/key does (curve25519 convention) */
    priv[0] &= 248;
    priv[31] = (uint8_t)((priv[31] & 127) | 64);
    crypto_scalarmult_base(pub, priv);
}

void tsnet_chapoly_seal(uint8_t *ct, const uint8_t key[32],
                        const uint8_t nonce[12], const void *pt, size_t pt_len,
                        const void *ad, size_t ad_len) {
    unsigned long long clen;
    crypto_aead_chacha20poly1305_ietf_encrypt(ct, &clen, pt, pt_len, ad,
                                              ad_len, NULL, nonce, key);
}

int tsnet_chapoly_open(uint8_t *pt, const uint8_t key[32],
                       const uint8_t nonce[12], const void *ct, size_t ct_len,
                       const void *ad, size_t ad_len) {
    unsigned long long plen;
    return crypto_aead_chacha20poly1305_ietf_decrypt(pt, &plen, NULL, ct,
                                                     ct_len, ad, ad_len,
                                                     nonce, key);
}

int tsnet_box_seal(uint8_t *ct, const uint8_t nonce[24], const void *pt,
                   size_t pt_len, const uint8_t peer_pub[32],
                   const uint8_t self_priv[32]) {
    return crypto_box_easy(ct, pt, pt_len, nonce, peer_pub, self_priv);
}

int tsnet_box_open(uint8_t *pt, const uint8_t nonce[24], const void *ct,
                   size_t ct_len, const uint8_t peer_pub[32],
                   const uint8_t self_priv[32]) {
    return crypto_box_open_easy(pt, ct, ct_len, nonce, peer_pub, self_priv);
}
