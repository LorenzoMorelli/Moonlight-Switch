#ifndef TSNET_CONTROL_NETMAP_H
#define TSNET_CONTROL_NETMAP_H

/* Network map state: self node, peers, DERP map — parsed from MapResponse
 * JSON (tailscale: tailcfg/tailcfg.go, tailcfg/derpmap.go).
 * Sized statically: WIREGUARD_MAX_PEERS=32 (matches the WireGuard peer table). */

#include "shim/classify.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TSNET_MAX_PEERS 32
#define TSNET_MAX_PEER_ADDRS 2
#define TSNET_MAX_PEER_ROUTES 4 /* advertised subnet routes per peer */
#define TSNET_MAX_ENDPOINTS 8
#define TSNET_MAX_DERP_REGIONS 24
#define TSNET_MAX_DERP_NODES 4

typedef struct tsnet_endpoint {
    tsnet_addr addr; /* ip + port */
} tsnet_endpoint;

typedef struct tsnet_peer {
    int64_t id;                 /* Node.ID */
    char name[128];             /* Node.Name (FQDN, trailing dot stripped) */
    uint8_t node_key[32];       /* Node.Key */
    uint8_t disco_key[32];      /* Node.DiscoKey */
    bool has_disco;
    tsnet_addr addrs[TSNET_MAX_PEER_ADDRS]; /* Node.Addresses (ip only) */
    int n_addrs;
    tsnet_prefix routes[TSNET_MAX_PEER_ROUTES]; /* AllowedIPs subnet routes */
    int n_routes;
    tsnet_endpoint endpoints[TSNET_MAX_ENDPOINTS]; /* Node.Endpoints */
    int n_endpoints;
    int home_derp;              /* Node.HomeDERP, or legacy "DERP":"127.3.3.40:N" */
    bool online;                /* Node.Online (true if absent) */
    int64_t key_expiry;         /* unix seconds, 0 = no expiry */
} tsnet_peer;

typedef struct tsnet_derp_node {
    char name[32];
    char hostname[128];  /* HostName */
    char cert_name[128]; /* CertName, "" = HostName */
    char ipv4[48], ipv6[48];
    int stun_port;  /* 0 -> 3478 */
    bool stun_only;
    int derp_port;  /* 0 -> 443 */
    bool can_port80;
} tsnet_derp_node;

typedef struct tsnet_derp_region {
    int id;
    char code[32];
    tsnet_derp_node nodes[TSNET_MAX_DERP_NODES];
    int n_nodes;
} tsnet_derp_region;

typedef struct tsnet_derpmap {
    tsnet_derp_region regions[TSNET_MAX_DERP_REGIONS];
    int n_regions;
} tsnet_derpmap;

typedef struct tsnet_netmap {
    bool has_self;
    int64_t self_id;
    char self_name[128];
    uint8_t self_node_key[32];
    char self_addrs[TSNET_MAX_PEER_ADDRS][64]; /* CIDR strings for ts0 */
    tsnet_addr self_ips[TSNET_MAX_PEER_ADDRS];
    int n_self_addrs;
    int home_derp;
    int64_t self_key_expiry;

    char domain[128];

    tsnet_peer peers[TSNET_MAX_PEERS];
    int n_peers;

    tsnet_derpmap derpmap;
    bool has_derpmap;
} tsnet_netmap;

/* Parsed control messages the caller reacts to. */
typedef struct tsnet_map_msg {
    bool keep_alive;      /* KeepAlive-only message */
    char ping_url[256];   /* PingRequest.URL ("" if none) */
    bool ping_log;
    char pop_browser_url[256];
    char map_session_handle[128];
    int64_t seq;
} tsnet_map_msg;

/* Apply one MapResponse JSON document to nm. Returns TSNET_OK or
 * TSNET_E_PROTO on malformed JSON. msg (nullable) receives the
 * side-channel fields. */
int tsnet_netmap_apply(tsnet_netmap *nm, const char *json, size_t len,
                       tsnet_map_msg *msg);

/* Push peer addresses and MagicDNS names into the shim registry
 * (tsnet_registry_*), replacing previous entries. */
void tsnet_netmap_sync_registry(const tsnet_netmap *nm);

/* Helpers shared with other modules */
bool tsnet_parse_ipport(const char *s, tsnet_addr *out); /* "ip:port"/"[v6]:port" */
bool tsnet_parse_ip(const char *s, tsnet_addr *out);
int64_t tsnet_parse_rfc3339(const char *s); /* -> unix secs, 0 on error/zero time */

#endif
