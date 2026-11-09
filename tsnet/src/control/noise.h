#ifndef TSNET_CONTROL_NOISE_H
#define TSNET_CONTROL_NOISE_H

/* Noise_IK_25519_ChaChaPoly_BLAKE2s for the ts2021 control protocol.
 *
 * Faithful C port of tailscale: control/controlbase/
 * {handshake.go, messages.go, conn.go} — every constant below is copied
 * from there (file:line in comments). Only the client role is used in
 * production; the server role exists for tests.
 *
 * Wire format:
 *  - initiation (client->server), 101 bytes total (messages.go):
 *      2B protocol version (BE) | 1B type=1 | 2B payload len (BE, =96) |
 *      32B ephemeral pub | 48B machine pub (encrypted) | 16B tag
 *  - response (server->client), 51 bytes (messages.go):
 *      1B type=2 | 2B payload len (BE, =48) | 32B ephemeral pub | 16B tag
 *  - error: 1B type=3 | 2B len | len bytes of message (unauthenticated)
 *  - transport record (conn.go):
 *      1B type=4 | 2B ciphertext len (BE) | ciphertext (pt+16 tag)
 *    nonce: 4 zero bytes then 8-byte BE counter from 0 (conn.go);
 *    max message 4096 => max plaintext 4077 (conn.go).
 *  - prologue: "Tailscale Control Protocol v" + decimal version
 *    (handshake.go); protocol name handshake.go.
 */

#include <stddef.h>
#include <stdint.h>

/* The "protocol version" carried in the initiation header and mixed into
 * the prologue is the CLIENT CAPABILITY VERSION, not a fixed 1: the Go
 * client passes uint16(tailcfg.CurrentCapabilityVersion)
 * (control/ts2021/client.go); Headscale rejects small values. */
#define TSNET_NOISE_INIT_LEN 101
#define TSNET_NOISE_RESP_LEN 51
#define TSNET_NOISE_HDR_LEN 3
#define TSNET_NOISE_MAX_MSG 4096
#define TSNET_NOISE_MAX_CT (TSNET_NOISE_MAX_MSG - TSNET_NOISE_HDR_LEN)
#define TSNET_NOISE_MAX_PT (TSNET_NOISE_MAX_CT - 16)

#define TSNET_NOISE_MSG_INITIATION 1
#define TSNET_NOISE_MSG_RESPONSE 2
#define TSNET_NOISE_MSG_ERROR 3
#define TSNET_NOISE_MSG_RECORD 4

typedef struct tsnet_noise_hs {
    uint8_t h[32];  /* handshake hash */
    uint8_t ck[32]; /* chaining key */
    uint8_t machine_priv[32];
    uint8_t e_priv[32];
    uint8_t control_pub[32];
    int finished;
} tsnet_noise_hs;

typedef struct tsnet_noise_conn {
    uint8_t tx_key[32], rx_key[32];
    uint64_t tx_n, rx_n; /* record counters; 2^64-1 = exhausted */
    uint8_t handshake_hash[32];
    uint8_t peer_pub[32]; /* server: client machine key */
} tsnet_noise_conn;

/* Build the initiation message. Returns 0 or -1 (bad control key). */
int tsnet_noise_client_start(tsnet_noise_hs *hs,
                             const uint8_t machine_priv[32],
                             const uint8_t control_pub[32],
                             uint16_t version,
                             uint8_t init_out[TSNET_NOISE_INIT_LEN]);

/* Test hook: as above with a caller-supplied ephemeral private key. */
int tsnet_noise_client_start_ex(tsnet_noise_hs *hs,
                                const uint8_t machine_priv[32],
                                const uint8_t control_pub[32],
                                const uint8_t e_priv[32],
                                uint16_t version,
                                uint8_t init_out[TSNET_NOISE_INIT_LEN]);

/* Process the 51-byte response and derive transport keys. Returns 0, or
 * -1 on crypto failure / bad message. */
int tsnet_noise_client_finish(tsnet_noise_hs *hs,
                              const uint8_t resp[TSNET_NOISE_RESP_LEN],
                              tsnet_noise_conn *conn);

/* Server role (tests): consume an initiation, emit the response.
 * ephemeral may be NULL for random. */
int tsnet_noise_server_respond(const uint8_t control_priv[32],
                               const uint8_t init[TSNET_NOISE_INIT_LEN],
                               const uint8_t *e_priv /* nullable */,
                               uint8_t resp_out[TSNET_NOISE_RESP_LEN],
                               tsnet_noise_conn *conn);

/* Encrypt one transport record: writes 3-byte header + ciphertext into
 * frame_out (must hold TSNET_NOISE_HDR_LEN + pt_len + 16). Returns frame
 * length, or -1 if pt_len > max or nonces exhausted. */
int tsnet_noise_encrypt(tsnet_noise_conn *c, const void *pt, size_t pt_len,
                        uint8_t *frame_out);

/* Decrypt one record payload (frame minus the 3-byte header, whose type
 * must be 4). pt_out must hold ct_len-16. Returns plaintext length or -1. */
int tsnet_noise_decrypt(tsnet_noise_conn *c, const void *ct, size_t ct_len,
                        uint8_t *pt_out);

#endif
