#include "noise.h"

#include "crypto/tscrypto.h"

#include <stdio.h>
#include <string.h>

/* handshake.go */
static const char protocol_name[] = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
/* handshake.go */
static const char prologue_prefix[] = "Tailscale Control Protocol v";

/* all-zero 12-byte nonce used for every handshake AEAD (handshake.go) */
static const uint8_t zero_nonce[12] = {0};

static void mix_hash(tsnet_noise_hs *hs, const void *data, size_t len) {
    /* handshake.go: h = BLAKE2s(h || data) */
    tsnet_blake2s2(hs->h, hs->h, sizeof(hs->h), data, len);
}

/* handshake.go: ck, k = HKDF-BLAKE2s(ikm=DH, salt=ck); returns k */
static int mix_dh(tsnet_noise_hs *hs, uint8_t k_out[32],
                  const uint8_t priv[32], const uint8_t pub[32]) {
    uint8_t shared[32];
    if (tsnet_x25519(shared, priv, pub) != 0) return -1;
    uint8_t out[2][32];
    tsnet_hkdf_blake2s(shared, sizeof(shared), hs->ck, sizeof(hs->ck), out, 2);
    memcpy(hs->ck, out[0], 32);
    memcpy(k_out, out[1], 32);
    return 0;
}

/* handshake.go: ct = Seal(k, nonce=0, pt, ad=h); h = H(h||ct) */
static void encrypt_and_hash(tsnet_noise_hs *hs, const uint8_t k[32],
                             uint8_t *ct, const void *pt, size_t pt_len) {
    tsnet_chapoly_seal(ct, k, zero_nonce, pt, pt_len, hs->h, sizeof(hs->h));
    mix_hash(hs, ct, pt_len + TSNET_CHAPOLY_TAG_LEN);
}

static int decrypt_and_hash(tsnet_noise_hs *hs, const uint8_t k[32],
                            uint8_t *pt, const void *ct, size_t ct_len) {
    if (tsnet_chapoly_open(pt, k, zero_nonce, ct, ct_len, hs->h,
                           sizeof(hs->h)) != 0)
        return -1;
    mix_hash(hs, ct, ct_len);
    return 0;
}

static void hs_initialize(tsnet_noise_hs *hs, uint16_t version,
                          const uint8_t control_pub[32]) {
    memset(hs, 0, sizeof(*hs));
    /* handshake.go */
    tsnet_blake2s(hs->h, protocol_name, sizeof(protocol_name) - 1);
    memcpy(hs->ck, hs->h, 32);
    /* prologue (handshake.go) */
    char prologue[sizeof(prologue_prefix) + 5];
    int n = snprintf(prologue, sizeof(prologue), "%s%u", prologue_prefix,
                     (unsigned)version);
    mix_hash(hs, prologue, (size_t)n);
    /* <- s (handshake.go) */
    mix_hash(hs, control_pub, 32);
}

int tsnet_noise_client_start_ex(tsnet_noise_hs *hs,
                                const uint8_t machine_priv[32],
                                const uint8_t control_pub[32],
                                const uint8_t e_priv[32],
                                uint16_t version,
                                uint8_t init_out[TSNET_NOISE_INIT_LEN]) {
    hs_initialize(hs, version, control_pub);
    memcpy(hs->machine_priv, machine_priv, 32);
    memcpy(hs->control_pub, control_pub, 32);
    memcpy(hs->e_priv, e_priv, 32);

    /* header (messages.go) */
    memset(init_out, 0, TSNET_NOISE_INIT_LEN);
    init_out[0] = (uint8_t)(version >> 8);
    init_out[1] = (uint8_t)(version & 0xff);
    init_out[2] = TSNET_NOISE_MSG_INITIATION;
    init_out[3] = 0;
    init_out[4] = 96;

    uint8_t *ephemeral_pub = init_out + 5;
    uint8_t *machine_pub_ct = init_out + 5 + 32;
    uint8_t *tag = init_out + 5 + 32 + 48;

    /* -> e, es, s, ss (handshake.go) */
    tsnet_x25519_pubkey(ephemeral_pub, hs->e_priv);
    mix_hash(hs, ephemeral_pub, 32);
    uint8_t k[32];
    if (mix_dh(hs, k, hs->e_priv, control_pub) != 0) return -1; /* es */
    uint8_t machine_pub[32];
    tsnet_x25519_pubkey(machine_pub, machine_priv);
    encrypt_and_hash(hs, k, machine_pub_ct, machine_pub, 32);
    if (mix_dh(hs, k, machine_priv, control_pub) != 0) return -1; /* ss */
    encrypt_and_hash(hs, k, tag, NULL, 0);
    return 0;
}

int tsnet_noise_client_start(tsnet_noise_hs *hs,
                             const uint8_t machine_priv[32],
                             const uint8_t control_pub[32],
                             uint16_t version,
                             uint8_t init_out[TSNET_NOISE_INIT_LEN]) {
    uint8_t e_priv[32], e_pub[32];
    tsnet_x25519_keygen(e_priv, e_pub);
    return tsnet_noise_client_start_ex(hs, machine_priv, control_pub, e_priv,
                                       version, init_out);
}

/* handshake.go: k1, k2 = HKDF(ikm=nil, salt=ck) */
static void split(tsnet_noise_hs *hs, uint8_t k1[32], uint8_t k2[32]) {
    uint8_t out[2][32];
    tsnet_hkdf_blake2s(NULL, 0, hs->ck, 32, out, 2);
    memcpy(k1, out[0], 32);
    memcpy(k2, out[1], 32);
    hs->finished = 1;
}

int tsnet_noise_client_finish(tsnet_noise_hs *hs,
                              const uint8_t resp[TSNET_NOISE_RESP_LEN],
                              tsnet_noise_conn *conn) {
    if (hs->finished) return -1;
    /* messages.go */
    if (resp[0] != TSNET_NOISE_MSG_RESPONSE) return -1;
    if (((size_t)resp[1] << 8 | resp[2]) != 48) return -1;
    const uint8_t *control_ephemeral = resp + 3;
    const uint8_t *tag = resp + 3 + 32;

    /* <- e, ee, se (handshake.go) */
    mix_hash(hs, control_ephemeral, 32);
    uint8_t k[32];
    if (mix_dh(hs, k, hs->e_priv, control_ephemeral) != 0) return -1; /* ee */
    if (mix_dh(hs, k, hs->machine_priv, control_ephemeral) != 0)
        return -1; /* se */
    if (decrypt_and_hash(hs, k, NULL, tag, 16) != 0) return -1;

    memset(conn, 0, sizeof(*conn));
    /* client: tx=c1, rx=c2 (handshake.go) */
    split(hs, conn->tx_key, conn->rx_key);
    memcpy(conn->handshake_hash, hs->h, 32);
    memcpy(conn->peer_pub, hs->control_pub, 32);
    return 0;
}

int tsnet_noise_server_respond(const uint8_t control_priv[32],
                               const uint8_t init[TSNET_NOISE_INIT_LEN],
                               const uint8_t *e_priv,
                               uint8_t resp_out[TSNET_NOISE_RESP_LEN],
                               tsnet_noise_conn *conn) {
    /* handshake.go, test-only server role */
    uint16_t client_version = (uint16_t)(init[0] << 8 | init[1]);
    if (init[2] != TSNET_NOISE_MSG_INITIATION) return -1;
    if (((size_t)init[3] << 8 | init[4]) != 96) return -1;

    uint8_t control_pub[32];
    tsnet_x25519_pubkey(control_pub, control_priv);
    tsnet_noise_hs hs;
    hs_initialize(&hs, client_version, control_pub);

    const uint8_t *machine_ephemeral = init + 5;
    const uint8_t *machine_pub_ct = init + 5 + 32;
    const uint8_t *tag = init + 5 + 32 + 48;

    mix_hash(&hs, machine_ephemeral, 32);
    uint8_t k[32];
    if (mix_dh(&hs, k, control_priv, machine_ephemeral) != 0) return -1;
    uint8_t machine_pub[32];
    if (decrypt_and_hash(&hs, k, machine_pub, machine_pub_ct, 48) != 0)
        return -1;
    if (mix_dh(&hs, k, control_priv, machine_pub) != 0) return -1;
    if (decrypt_and_hash(&hs, k, NULL, tag, 16) != 0) return -1;

    /* <- e, ee, se */
    uint8_t eph_priv[32], eph_pub[32];
    if (e_priv) {
        memcpy(eph_priv, e_priv, 32);
        tsnet_x25519_pubkey(eph_pub, eph_priv);
    } else {
        tsnet_x25519_keygen(eph_priv, eph_pub);
    }
    memset(resp_out, 0, TSNET_NOISE_RESP_LEN);
    resp_out[0] = TSNET_NOISE_MSG_RESPONSE;
    resp_out[1] = 0;
    resp_out[2] = 48;
    memcpy(resp_out + 3, eph_pub, 32);
    mix_hash(&hs, eph_pub, 32);
    if (mix_dh(&hs, k, eph_priv, machine_ephemeral) != 0) return -1; /* ee */
    if (mix_dh(&hs, k, eph_priv, machine_pub) != 0) return -1;       /* se */
    encrypt_and_hash(&hs, k, resp_out + 3 + 32, NULL, 0);

    memset(conn, 0, sizeof(*conn));
    /* server: tx=c2, rx=c1 (handshake.go) */
    uint8_t k1[32], k2[32];
    split(&hs, k1, k2);
    memcpy(conn->tx_key, k2, 32);
    memcpy(conn->rx_key, k1, 32);
    memcpy(conn->handshake_hash, hs.h, 32);
    memcpy(conn->peer_pub, machine_pub, 32);
    return 0;
}

/* conn.go: 12-byte nonce = 4 zero bytes || 8-byte BE counter */
static void make_nonce(uint8_t nonce[12], uint64_t n) {
    memset(nonce, 0, 4);
    for (int i = 0; i < 8; i++) nonce[4 + i] = (uint8_t)(n >> (8 * (7 - i)));
}

int tsnet_noise_encrypt(tsnet_noise_conn *c, const void *pt, size_t pt_len,
                        uint8_t *frame_out) {
    if (pt_len > TSNET_NOISE_MAX_PT) return -1;
    if (c->tx_n == UINT64_MAX) return -1; /* conn.go */
    size_t ct_len = pt_len + TSNET_CHAPOLY_TAG_LEN;
    frame_out[0] = TSNET_NOISE_MSG_RECORD;
    frame_out[1] = (uint8_t)(ct_len >> 8);
    frame_out[2] = (uint8_t)(ct_len & 0xff);
    uint8_t nonce[12];
    make_nonce(nonce, c->tx_n++);
    tsnet_chapoly_seal(frame_out + 3, c->tx_key, nonce, pt, pt_len, NULL, 0);
    return (int)(TSNET_NOISE_HDR_LEN + ct_len);
}

int tsnet_noise_decrypt(tsnet_noise_conn *c, const void *ct, size_t ct_len,
                        uint8_t *pt_out) {
    if (ct_len < TSNET_CHAPOLY_TAG_LEN || ct_len > TSNET_NOISE_MAX_CT)
        return -1;
    if (c->rx_n == UINT64_MAX) return -1;
    uint8_t nonce[12];
    make_nonce(nonce, c->rx_n);
    if (tsnet_chapoly_open(pt_out, c->rx_key, nonce, ct, ct_len, NULL, 0) != 0)
        return -1;
    c->rx_n++;
    return (int)(ct_len - TSNET_CHAPOLY_TAG_LEN);
}
