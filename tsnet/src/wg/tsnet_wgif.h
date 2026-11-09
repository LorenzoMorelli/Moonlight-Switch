#ifndef TSNET_WGIF_H
#define TSNET_WGIF_H

/* WireGuard <-> ts0 glue: replaces wireguardif.c. Same
 * protocol core (wireguard.c), but encrypted packets go to a transport
 * callback (magicsock) instead of an lwIP udp_pcb, and inbound packets
 * arrive via tsnet_wgif_rx() from any thread (processed on the tcpip
 * thread, which owns all WireGuard state).
 *
 * Peers are addressed by their WireGuard node key; AllowedIPs come from
 * the netmap (one v4 + one v6 per node) and are checked here, not via
 * the lwIP ip_addr machinery.
 */

#include "shim/classify.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TSNET_WGIF_MAX_PKT 1520 /* MTU 1280 + WG framing, rounded up */

/* Send an encrypted WireGuard packet to the peer (runs on tcpip thread;
 * must not block for long). */
typedef void (*tsnet_wgif_tx_fn)(const uint8_t peer_node_key[32],
                                 const uint8_t *pkt, size_t len, void *ud);

/* Bring up the WireGuard device on ts0 (call after tsnet_ts0_up).
 * node_priv is the tailscale node private key. */
int tsnet_wgif_up(const uint8_t node_priv[32], tsnet_wgif_tx_fn tx, void *ud);

/* Add or refresh a peer (netmap change). addrs = the peer's tailnet IPs
 * (/32 & /128); routes = advertised subnet routes reachable via this peer
 * (e.g. 192.168.1.0/24). Lazy: no handshake is started here. */
int tsnet_wgif_set_peer(const uint8_t node_key[32], const tsnet_addr *addrs,
                        int n_addrs, const tsnet_prefix *routes, int n_routes);
int tsnet_wgif_remove_peer(const uint8_t node_key[32]);

/* Feed one received WireGuard datagram (from magicsock, any thread). */
void tsnet_wgif_rx(const uint8_t *pkt, size_t len);

/* True if a session (valid keypair) exists with the peer. */
bool tsnet_wgif_peer_up(const uint8_t node_key[32]);

/* The ts0 output hook to pass to tsnet_ts0_up() (typed in netif_ts0.h). */
typedef void (*tsnet_wgif_ts0_out_fn)(const uint8_t *, uint16_t, void *);
tsnet_wgif_ts0_out_fn tsnet_wgif_ts0_output(void);

#endif
