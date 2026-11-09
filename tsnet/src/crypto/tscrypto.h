#ifndef TSNET_CRYPTO_H
#define TSNET_CRYPTO_H

/* Crypto primitives for tsnet:
 *  - X25519, ChaCha20-Poly1305 IETF, XChaCha20-Poly1305, NaCl box, random:
 *    libsodium (host: system package; Switch: switch-libsodium portlib)
 *  - BLAKE2s (libsodium only has BLAKE2b): bundled reference code from
 *    wireguard-lwip (src/crypto/refc/blake2s.c)
 *  - HKDF over BLAKE2s (RFC 5869): implemented here, as used by the Noise
 *    handshake (tailscale: control/controlbase/handshake.go).
 */

#include <stddef.h>
#include <stdint.h>

#define TSNET_KEY_LEN 32
#define TSNET_CHAPOLY_TAG_LEN 16
#define TSNET_CHAPOLY_NONCE_LEN 12
#define TSNET_XCHAPOLY_NONCE_LEN 24
#define TSNET_BOX_NONCE_LEN 24
#define TSNET_BOX_OVERHEAD 16

/* Must be called before any other function; idempotent, thread-safe.
 * Returns 0 on success. */
int tsnet_crypto_init(void);

void tsnet_blake2s(uint8_t out[32], const void *in, size_t len);
/* out = BLAKE2s(a || b) — the Noise MixHash pattern */
void tsnet_blake2s2(uint8_t out[32], const void *a, size_t alen,
                    const void *b, size_t blen);

void tsnet_hmac_blake2s(uint8_t out[32], const uint8_t *key, size_t keylen,
                        const void *msg, size_t msglen);

/* HKDF-BLAKE2s: extract with salt, expand to n_out*32 bytes (n_out <= 3). */
void tsnet_hkdf_blake2s(const uint8_t *ikm, size_t ikm_len,
                        const uint8_t *salt, size_t salt_len,
                        uint8_t out[][32], int n_out);

/* X25519: shared = scalarmult(priv, pub). Returns -1 on low-order/all-zero
 * result (mirrors Go curve25519.X25519 semantics). */
int tsnet_x25519(uint8_t shared[32], const uint8_t priv[32],
                 const uint8_t pub[32]);
void tsnet_x25519_pubkey(uint8_t pub[32], const uint8_t priv[32]);
/* Generate a private key (clamped random, as Go key.NewMachine). */
void tsnet_x25519_keygen(uint8_t priv[32], uint8_t pub[32]);

/* ChaCha20-Poly1305 IETF (12-byte nonce). ct must hold pt_len+16. */
void tsnet_chapoly_seal(uint8_t *ct, const uint8_t key[32],
                        const uint8_t nonce[12], const void *pt, size_t pt_len,
                        const void *ad, size_t ad_len);
/* Returns 0 on success, -1 on auth failure. pt must hold ct_len-16. */
int tsnet_chapoly_open(uint8_t *pt, const uint8_t key[32],
                       const uint8_t nonce[12], const void *ct, size_t ct_len,
                       const void *ad, size_t ad_len);

/* NaCl crypto_box (X25519+XSalsa20-Poly1305), for DERP ClientInfo and disco
 * payloads. ct must hold pt_len+16; nonce 24 bytes. */
int tsnet_box_seal(uint8_t *ct, const uint8_t nonce[24], const void *pt,
                   size_t pt_len, const uint8_t peer_pub[32],
                   const uint8_t self_priv[32]);
int tsnet_box_open(uint8_t *pt, const uint8_t nonce[24], const void *ct,
                   size_t ct_len, const uint8_t peer_pub[32],
                   const uint8_t self_priv[32]);

#endif
