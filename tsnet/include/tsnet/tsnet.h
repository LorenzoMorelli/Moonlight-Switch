/* tsnet — embedded Tailscale client for Moonlight-Switch.
 *
 * Public API (C11). All functions are thread-safe unless noted.
 */
#ifndef TSNET_H
#define TSNET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TSNET_VERSION "0.1.0"

/* ---- errors ---------------------------------------------------------- */

typedef enum tsnet_err {
    TSNET_OK = 0,
    TSNET_E_INVAL = -1,      /* invalid argument */
    TSNET_E_NOMEM = -2,      /* allocation failure */
    TSNET_E_IO = -3,         /* filesystem / socket error (see errno) */
    TSNET_E_PROTO = -4,      /* protocol violation from remote */
    TSNET_E_TLS = -5,        /* TLS handshake / cert verification failure */
    TSNET_E_AUTH = -6,       /* registration rejected / key expired */
    TSNET_E_STATE = -7,      /* called in the wrong state */
    TSNET_E_TIMEOUT = -8,
    TSNET_E_CLOSED = -9,     /* connection closed by peer */
} tsnet_err;

const char *tsnet_err_str(tsnet_err e);

/* ---- logging --------------------------------------------------------- */

typedef enum tsnet_log_level {
    TSNET_LOG_ERROR = 0,
    TSNET_LOG_WARN = 1,
    TSNET_LOG_INFO = 2,
    TSNET_LOG_DEBUG = 3,
    TSNET_LOG_TRACE = 4,
} tsnet_log_level;

/* Configure logging (also usable before tsnet_start). */
void tsnet_log_set_level(tsnet_log_level lvl);
/* Log to <path> with rotation to <path>.1 past max_size; NULL disables. */
int tsnet_log_set_file(const char *path, size_t max_size);

/* ---- lifecycle ------------------------------------------------------- */

typedef enum tsnet_state {
    TSNET_ST_STOPPED = 0,
    TSNET_ST_STARTING,       /* loading keys, dialing control */
    TSNET_ST_NEEDS_LOGIN,    /* no node key: waiting for auth key / AuthURL */
    TSNET_ST_AUTHENTICATING, /* register in flight / waiting for Followup */
    TSNET_ST_RUNNING,        /* map stream up, netif configured */
    TSNET_ST_ERROR,          /* fatal error, see tsnet_last_error() */
} tsnet_state;

typedef struct tsnet_config {
    const char *server_url;  /* control server, default https://controlplane.tailscale.com */
    const char *state_dir;   /* directory for keys + state.json + tsnet.log */
    const char *hostname;    /* node hostname (default "moonlight-switch") */
    const char *auth_key;    /* optional; never persisted after successful register */
    uint16_t udp_port;       /* magicsock port, 0 = default 41641 with random fallback */
    tsnet_log_level log_level;
} tsnet_config;

/* ---- engine: full client (control + data plane), own thread ---------- */

typedef struct tsnet_events {
    void (*on_state)(tsnet_state st, const char *detail, void *ud);
    void (*on_authurl)(const char *url, void *ud); /* interactive login */
    /* netmap changed: peer list for UI. Runs on the control thread. */
    void (*on_peers)(void *ud);
    void *ud;
} tsnet_events;

/* Start everything (lwIP, WireGuard, magicsock, control thread).
 * Returns immediately; state changes arrive via events. */
int tsnet_start(const tsnet_config *cfg, const tsnet_events *ev);

/* Graceful stop (closes control + DERP, tears down peers). Blocking. */
void tsnet_stop(void);

/* Stop, then join the network stack thread, which tsnet_stop() keeps for a
 * later restart. Call once at process exit: no thread may outlive the
 * program when it returns to the homebrew loader. */
void tsnet_shutdown(void);

tsnet_state tsnet_get_state(void);

/* Snapshot of peers for UI/CLI. Returns count written. */
typedef struct tsnet_peer_info {
    char name[128];
    char ip4[20];       /* "" if none */
    bool online;
    bool session_up;    /* WireGuard handshake completed */
    char path[24];      /* "derp-N" or "direct" */
} tsnet_peer_info;
int tsnet_get_peers(tsnet_peer_info *out, int max);

/* Own tailnet IPv4 as a string ("" if not connected). */
void tsnet_get_self_ip4(char *out, size_t cap);

/* True if a connection to this IPv4 literal would be routed through the tunnel
 * (a tailnet address, or a LAN host behind an accepted subnet route while
 * off-LAN). Lets the app pick a tunnel-safe video packet size. False for a
 * malformed/empty string or a directly-reachable address. */
bool tsnet_dest_is_tunnel(const char *ipv4);

#ifdef __cplusplus
}
#endif

#endif /* TSNET_H */
