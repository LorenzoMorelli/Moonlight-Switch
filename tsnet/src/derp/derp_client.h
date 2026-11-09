#ifndef TSNET_DERP_CLIENT_H
#define TSNET_DERP_CLIENT_H

/* DERP client (tailscale: derp/derp.go, derp_client.go,
 * derphttp/derphttp_client.go).
 *
 * Wire protocol (derp.go):
 *  - HTTP(S) GET /derp with "Upgrade: DERP" -> 101 (derphttp_client.go)
 *  - frames: type(1B) + length(4B BE) (derp.go)
 *  - server:  0x01 ServerKey = magic "DERP🔑" (8B) + 32B server key
 *  - client:  0x02 ClientInfo = 32B node pub + naclbox(ClientInfo JSON)
 *             where naclbox = 24B nonce + box (types/key/node.go)
 *             ClientInfo JSON: {"version":2,"CanAckPings":true}
 *             (derp_client.go, ProtocolVersion derp.go)
 *  - server:  0x03 ServerInfo (naclbox JSON) — parsed, currently unused
 *  - client:  0x04 SendPacket = 32B dst node key + payload
 *  - server:  0x05 RecvPacket = 32B src node key + payload (v2)
 *  -          0x06 KeepAlive, 0x07 NotePreferred(1B), 0x08 PeerGone(32B+1),
 *             0x09 PeerPresent, 0x12 Ping(8B) -> 0x13 Pong(8B),
 *             0x14 Health, 0x15 Restarting
 *
 * The client owns a reader thread; recv_cb runs on it. Sends are
 * serialized with a mutex (short TCP/TLS writes with SO_SNDTIMEO).
 */

#include "control/netmap.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct tsnet_derp tsnet_derp;

/* src_key = sender node key; runs on the DERP reader thread */
typedef void (*tsnet_derp_recv_cb)(const uint8_t src_key[32],
                                   const uint8_t *pkt, size_t len, void *ud);
/* connection state change (up=false on read error/close) */
typedef void (*tsnet_derp_state_cb)(bool up, void *ud);

/* Connect to the region's first usable node. node_priv is the WireGuard
 * node private key (DERP identity, derp.go). ca_file for TLS regions.
 * Blocking (dial + upgrade + key exchange), then spawns the reader. */
int tsnet_derp_connect(tsnet_derp **out, const tsnet_derp_region *region,
                       const uint8_t node_priv[32], const char *ca_file,
                       tsnet_derp_recv_cb on_recv,
                       tsnet_derp_state_cb on_state, void *ud);

/* Send one packet (WireGuard or disco) to dst via the relay. Thread-safe. */
int tsnet_derp_send(tsnet_derp *d, const uint8_t dst_key[32], const void *pkt,
                    size_t len);

/* Tell the server this is (not) our home relay (frame 0x07). */
int tsnet_derp_note_preferred(tsnet_derp *d, bool preferred);

int tsnet_derp_region_id(const tsnet_derp *d);
/* ms of the last activity (frame received) — for idle-closing */
uint64_t tsnet_derp_last_activity(const tsnet_derp *d);
/* true once the reader thread has exited (connection is dead and must be
 * closed + reconnected). Safe to call from any thread. */
bool tsnet_derp_dead(const tsnet_derp *d);

void tsnet_derp_close(tsnet_derp *d);

/* --- pure frame helpers, unit-testable without I/O --------------------- */
/* build a frame header into hdr[5] */
void tsnet_derp_frame_header(uint8_t hdr[5], uint8_t type, uint32_t len);
/* parse ServerKey payload; returns 0 and fills key on success */
int tsnet_derp_parse_server_key(const uint8_t *payload, size_t len,
                                uint8_t key[32]);

#endif
