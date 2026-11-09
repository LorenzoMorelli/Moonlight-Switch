#ifndef TSNET_MAGICSOCK_H
#define TSNET_MAGICSOCK_H

/* magicsock: per-peer path selection between DERP relays and direct UDP.
 * Keeps the home DERP region connected, dials peers' regions on demand, and
 * upgrades to a direct path (STUN + disco) when pongs prove it works. */

#include "control/netmap.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Start with the node identity (DERP auth) and disco key. ca_file is
 * used for DERP TLS. */
int tsnet_magicsock_start(const uint8_t node_priv[32],
                          const uint8_t disco_priv[32], const char *ca_file);

/* Apply a netmap update: DERP map + peers (home derp, keys). Thread-safe. */
void tsnet_magicsock_set_netmap(const tsnet_netmap *nm);

/* Register the sink for our discovered endpoints ("ip:port" strings from
 * STUN + local interface); the engine forwards them to the control client
 * (MapRequest.Endpoints). Called before start. */
void tsnet_magicsock_set_endpoints_cb(void (*cb)(const char **eps, int n,
                                                 void *ud),
                                      void *ud);

/* Send one WireGuard datagram to the peer (called by tsnet_wgif on the
 * tcpip thread; must not block beyond the socket send timeout). */
void tsnet_magicsock_send_wg(const uint8_t peer_node_key[32],
                             const uint8_t *pkt, size_t len, void *ud);

/* Our home DERP region id (0 = not yet established). */
int tsnet_magicsock_home_derp(void);

/* Debug knob (UI "Prefer DERP"): disable the direct path
 * and pin all traffic to the relay. */
void tsnet_magicsock_set_derp_only(bool derp_only);

/* Diagnostics for the UI/CLI: current path to a peer ("derp-N"/"direct"). */
int tsnet_magicsock_peer_path(const uint8_t node_key[32], char *out,
                              size_t cap);

void tsnet_magicsock_stop(void);

#endif
