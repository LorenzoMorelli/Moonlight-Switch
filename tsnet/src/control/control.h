#ifndef TSNET_CONTROL_CONTROL_H
#define TSNET_CONTROL_CONTROL_H

/* Control-plane orchestrator: key management, /key bootstrap,
 * ts2021 channel, /machine/register (auth key or interactive AuthURL +
 * Followup), /machine/map streaming with reconnect. Runs synchronously in
 * the caller's thread (the CLI/main app spawns a dedicated control thread).
 */

#include "netmap.h"
#include "tsnet/tsnet.h"

typedef struct tsnet_control tsnet_control;

typedef struct tsnet_control_cbs {
    /* state transitions, with a human-readable detail (may be "") */
    void (*on_state)(tsnet_state st, const char *detail, void *ud);
    /* interactive login: show this URL to the user */
    void (*on_authurl)(const char *url, void *ud);
    /* the netmap changed (already applied + registry synced) */
    void (*on_netmap)(const tsnet_netmap *nm, void *ud);
    void *ud;
} tsnet_control_cbs;

int tsnet_control_create(tsnet_control **out, const tsnet_config *cfg,
                         const tsnet_control_cbs *cbs);

/* Blocking: bootstrap, register, then map stream with reconnect+backoff.
 * Returns when tsnet_control_stop() was called (TSNET_OK) or on a fatal,
 * non-retryable error. */
int tsnet_control_run(tsnet_control *c);

/* Async stop request (returns immediately; run() exits at the next
 * reconnect boundary or read timeout). */
void tsnet_control_stop(tsnet_control *c);

/* Current netmap (owned by control; read from the control thread's
 * callbacks or after run() returns). */
const tsnet_netmap *tsnet_control_netmap(tsnet_control *c);

/* Endpoints advertised in MapRequest.Endpoints ("ip:port" strings),
 * updated by magicsock; when they change, the map stream reconnects so the
 * server learns them (lite updates arrive with a later refactor). */
int tsnet_control_set_endpoints(tsnet_control *c, const char **eps, int n);

/* Hostinfo.NetInfo.PreferredDERP for the next map request; a change
 * triggers a map reconnect (the server assigns HomeDERP from this). */
int tsnet_control_set_preferred_derp(tsnet_control *c, int region);

void tsnet_control_destroy(tsnet_control *c);

#endif
