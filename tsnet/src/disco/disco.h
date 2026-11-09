#ifndef TSNET_DISCO_DISCO_H
#define TSNET_DISCO_DISCO_H

/* disco — NAT traversal messages (tailscale: disco/disco.go).
 *
 * Wire: magic "TS💬" (6B: 54 53 f0 9f 92 ac) + sender disco pub (32B) +
 * nonce (24B) + naclbox(payload) sealed with the DISCO keypair.
 * Payload: type (1B) + version (1B = 0) + data:
 *   0x01 Ping:        TxID[12] + sender NodeKey[32] (disco.go)
 *   0x02 Pong:        TxID[12] + src ip16 + port u16 BE (disco.go,
 *                     IPv4 as v4-mapped v6)
 *   0x03 CallMeMaybe: N x (ip16 + port u16 BE) (disco.go)
 * Types 0x04-0x09 (UDP relay) are not implemented.
 */

#include "shim/classify.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TSNET_DISCO_MAGIC_LEN 6
#define TSNET_DISCO_TXID_LEN 12
#define TSNET_DISCO_MAX_EPS 16
/* magic + key + nonce + box(2 + payload) */
#define TSNET_DISCO_OVERHEAD (6 + 32 + 24 + 16 + 2)

typedef enum tsnet_disco_type {
    TSNET_DISCO_PING = 0x01,
    TSNET_DISCO_PONG = 0x02,
    TSNET_DISCO_CALL_ME_MAYBE = 0x03,
} tsnet_disco_type;

typedef struct tsnet_disco_msg {
    tsnet_disco_type type;
    uint8_t txid[TSNET_DISCO_TXID_LEN]; /* ping/pong */
    uint8_t node_key[32];               /* ping (zero if absent) */
    tsnet_addr src;                     /* pong: observed src ip:port */
    tsnet_addr eps[TSNET_DISCO_MAX_EPS]; /* call-me-maybe */
    int n_eps;
} tsnet_disco_msg;

/* True if pkt starts with the disco magic and is long enough. */
bool tsnet_disco_looks(const uint8_t *pkt, size_t len);

/* Seal msg from our disco identity to the peer's disco key. out must hold
 * payload + TSNET_DISCO_OVERHEAD (paylod <= ~300B). Returns length or -1. */
int tsnet_disco_seal(const tsnet_disco_msg *msg,
                     const uint8_t self_disco_priv[32],
                     const uint8_t self_disco_pub[32],
                     const uint8_t peer_disco_pub[32], uint8_t *out,
                     size_t cap);

/* Open a disco packet: verifies the box against the sender key embedded in
 * the packet (must match peer_disco_pub when non-NULL) and parses the
 * payload. sender_out (nullable) receives the embedded sender disco key. */
int tsnet_disco_open(const uint8_t *pkt, size_t len,
                     const uint8_t self_disco_priv[32],
                     const uint8_t *peer_disco_pub /* nullable */,
                     uint8_t *sender_out /* nullable, 32B */,
                     tsnet_disco_msg *msg);

#endif
