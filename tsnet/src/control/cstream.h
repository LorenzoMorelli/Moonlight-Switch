#ifndef TSNET_CONTROL_CSTREAM_H
#define TSNET_CONTROL_CSTREAM_H

/* Buffered byte stream to the control server and DERP relays: plain TCP for
 * http:// control URLs, mbedtls TLS 1.2 for https:// with certificate
 * verification always on.
 *
 * The read side is buffered: HTTP header parsing may over-read into the
 * Noise byte stream, so leftovers stay in the buffer for the next read.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct tsnet_cstream tsnet_cstream;

/* Dial host:port; if tls, run the TLS handshake verifying the certificate
 * chain against the PEM bundle at ca_file (NULL = platform default bundle
 * path). sni is the hostname for SNI/verification. Returns NULL on error. */
tsnet_cstream *tsnet_cstream_dial(const char *host, uint16_t port, bool tls,
                                  const char *sni, const char *ca_file,
                                  int timeout_ms);

/* Read up to n bytes (>=1 on success, 0 on clean EOF, -1 error). */
ssize_t tsnet_cstream_read(tsnet_cstream *s, void *buf, size_t n);
/* Read exactly n bytes or fail. */
int tsnet_cstream_read_full(tsnet_cstream *s, void *buf, size_t n);
/* Write all n bytes or fail. */
int tsnet_cstream_write(tsnet_cstream *s, const void *buf, size_t n);
/* Read one CRLF- (or LF-) terminated line into buf (NUL-terminated,
 * terminator stripped). Returns line length or -1. */
int tsnet_cstream_read_line(tsnet_cstream *s, char *buf, size_t cap);

/* Change the read/write timeout on the underlying socket (e.g. long map
 * stream reads vs short dial timeouts). */
int tsnet_cstream_set_timeout(tsnet_cstream *s, int timeout_ms);

/* Shut down the underlying socket (unblocks reads in other threads)
 * without freeing; follow with tsnet_cstream_close(). */
void tsnet_cstream_shutdown(tsnet_cstream *s);

void tsnet_cstream_close(tsnet_cstream *s);

#endif
