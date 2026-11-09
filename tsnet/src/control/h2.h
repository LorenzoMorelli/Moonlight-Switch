#ifndef TSNET_CONTROL_H2_H
#define TSNET_CONTROL_H2_H

/* HTTP/2 client (nghttp2) over the Noise channel. Requests
 * mirror control/ts2021/client.go: POST https://<host><path>, JSON
 * body, optional Ts-Lb header with the node key. Single-threaded, blocking:
 * the control thread owns the session; register runs first, then the long-
 * lived map stream on the same session. */

#include "noisechan.h"

#include <stddef.h>
#include <stdint.h>

typedef struct tsnet_h2 tsnet_h2;

/* data callback for streaming responses; return 0 to continue, nonzero to
 * cancel the stream (propagated as error) */
typedef int (*tsnet_h2_data_cb)(const uint8_t *data, size_t len, void *ud);

int tsnet_h2_open(tsnet_h2 **out, tsnet_noisechan *ch, const char *authority);

/* POST path with a JSON body. on_data receives response DATA chunks as
 * they arrive. Blocks until the stream closes (or the read timeout set on
 * the underlying stream fires). Returns the HTTP :status, or a negative
 * TSNET error. lb_key ("nodekey:<hex>") adds the Ts-Lb header, NULL skips. */
int tsnet_h2_post(tsnet_h2 *h2, const char *path, const char *lb_key,
                  const void *body, size_t body_len, tsnet_h2_data_cb on_data,
                  void *ud);

void tsnet_h2_close(tsnet_h2 *h2);

#endif
