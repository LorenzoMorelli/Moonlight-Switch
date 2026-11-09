#ifndef TSNET_SHIM_CLASSIFY_H
#define TSNET_SHIM_CLASSIFY_H

/* Destination classification for the socket shim: tailnet
 * destinations go to lwIP, everything else to the real stack.
 * Portable: works on abstract addresses, no system sockaddr here. */

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tsnet_addr {
    uint8_t family; /* 4 or 6 */
    uint8_t ip[16]; /* ip[0..3] for v4, network byte order */
    uint16_t port;  /* host byte order */
} tsnet_addr;

/* A CIDR prefix: network address + significant bits. Used for Tailscale
 * subnet routes (e.g. a peer advertising 192.168.1.0/24). */
typedef struct tsnet_prefix {
    tsnet_addr net; /* network address (host bits zero); port ignored */
    uint8_t bits;   /* prefix length */
} tsnet_prefix;

typedef enum tsnet_route {
    TSNET_ROUTE_REAL = 0,
    TSNET_ROUTE_TUNNEL = 1,
} tsnet_route;

typedef enum tsnet_route_hint {
    TSNET_HINT_AUTO = 0,
    TSNET_HINT_FORCE_TUNNEL,
    TSNET_HINT_FORCE_REAL,
} tsnet_route_hint;

/* Classify a destination address:
 *  - multicast / broadcast / wildcard          -> REAL (always)
 *  - hint FORCE_TUNNEL / FORCE_REAL            -> as forced
 *  - 100.64.0.0/10 (CGNAT range, tailnet v4)   -> TUNNEL
 *  - fd7a:115c:a1e0::/48 (tailnet v6 ULA)      -> TUNNEL
 *  - address registered from the netmap peers  -> TUNNEL
 *  - everything else                           -> REAL
 */
tsnet_route tsnet_classify(const tsnet_addr *dst);

void tsnet_shim_set_route_hint(tsnet_route_hint h);
tsnet_route_hint tsnet_shim_get_route_hint(void);

/* Netmap-fed registry of tailnet addresses (self + peer Addresses that are
 * outside the standard ranges) and MagicDNS names. Updated by the control
 * plane, read by the shim on every classification: rwlock inside. */
void tsnet_registry_clear(void);
int tsnet_registry_add_addr(const tsnet_addr *a); /* ip only, port ignored */
bool tsnet_registry_contains(const tsnet_addr *a);

/* Subnet routes advertised by a peer (accepted routes): an address inside one
 * classifies as TUNNEL so LAN-behind-tailnet hosts (e.g. 192.168.1.0/24 via a
 * subnet router) are reachable through the tunnel when off-LAN. */
int tsnet_registry_add_route(const tsnet_prefix *p);
bool tsnet_registry_in_route(const tsnet_addr *a);

/* Tell the classifier our current REAL (non-tunnel) interface address, so a
 * subnet-route destination on our own LAN stays on the real path. NULL clears
 * it (then subnet-route destinations always tunnel). */
void tsnet_shim_set_local_ip(const tsnet_addr *ip);

/* Names: short hostname ("pc") or FQDN ("pc.tail1234.ts.net"). A trailing
 * dot in queries is ignored. Lookup fills up to *n_addrs addresses. */
int tsnet_registry_add_name(const char *name, const tsnet_addr *addrs,
                            int n_addrs);
int tsnet_registry_resolve(const char *name, tsnet_addr *out, int max);

/* Address helpers. */
bool tsnet_addr_is_multicast_or_broadcast(const tsnet_addr *a);
bool tsnet_addr_is_wildcard(const tsnet_addr *a);
bool tsnet_addr_in_tailnet_ranges(const tsnet_addr *a);
bool tsnet_addr_eq_ip(const tsnet_addr *a, const tsnet_addr *b);
bool tsnet_addr_in_prefix(const tsnet_addr *a, const tsnet_prefix *p);

#ifdef __cplusplus
}
#endif

#endif
