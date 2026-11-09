#ifndef TSNET_DISCO_STUN_H
#define TSNET_DISCO_STUN_H

/* Minimal STUN (RFC 5389) binding client, exactly what magicsock needs
 * (tailscale: net/stun/stun.go): binding request with SOFTWARE
 * "tailnode" + FINGERPRINT; response parse of (XOR-)MAPPED-ADDRESS. The
 * STUN servers are the DERP nodes (DERPNode.STUNPort, default 3478). */

#include "shim/classify.h"

#include <stddef.h>
#include <stdint.h>

/* 20 header + 12 SOFTWARE attr ("tailnode") + 8 FINGERPRINT attr = 40
 * (stun.go Request()); callers should pass a >= 40-byte buffer */
#define TSNET_STUN_REQ_LEN 40
#define TSNET_STUN_TXID_LEN 12

/* Build a binding request into out (must hold 40 bytes); returns length. */
int tsnet_stun_request(const uint8_t txid[TSNET_STUN_TXID_LEN], uint8_t *out,
                       size_t cap);

/* True if the buffer looks like a STUN packet (magic cookie at [4:8],
 * stun.go Is()). Used by magicsock demux. */
int tsnet_stun_is(const uint8_t *b, size_t len);

/* Parse a binding success response: fills txid and the mapped addr:port.
 * Returns 0 on success. */
int tsnet_stun_parse_response(const uint8_t *b, size_t len,
                              uint8_t txid[TSNET_STUN_TXID_LEN],
                              tsnet_addr *mapped);

#endif
