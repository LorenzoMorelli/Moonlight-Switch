#ifndef TSNET_CONTROL_NOISECHAN_H
#define TSNET_CONTROL_NOISECHAN_H

/* The ts2021 secure channel: TLS/TCP stream + HTTP upgrade + Noise IK,
 * exposing a plain byte stream for nghttp2, with the optional 9-byte early
 * payload (\xff\xff\xffTS + u32 BE length + tailcfg.EarlyNoise JSON)
 * consumed transparently on first read (control/ts2021/conn.go). */

#include "cstream.h"
#include "noise.h"

#include <stdbool.h>

struct tsnet_url; /* util/url.h */

typedef struct tsnet_noisechan {
    tsnet_cstream *cs;
    tsnet_noise_conn conn;
    /* decrypted-but-undelivered plaintext of the current record */
    uint8_t pt[TSNET_NOISE_MAX_PT];
    size_t pt_off, pt_len;
    /* early-payload probe leftover, delivered before pt (io.MultiReader
     * style — avoids an in-place memmove that could overflow pt) */
    uint8_t hdr9[9];
    size_t hdr9_off, hdr9_len;
    bool early_done;
    char node_key_challenge[128]; /* EarlyNoise.nodeKeyChallenge, "" if none */
} tsnet_noisechan;

/* Full connect: dial (TLS if url->tls), GET-free upgrade with the embedded
 * handshake header, complete Noise IK. control_pub is the server key from
 * /key. Returns TSNET_OK or an error. */
int tsnet_noisechan_connect(tsnet_noisechan *ch, const struct tsnet_url *url,
                            const char *ca_file,
                            const uint8_t machine_priv[32],
                            const uint8_t control_pub[32], uint16_t version,
                            int timeout_ms);

/* Byte-stream reads for nghttp2 (>=1 bytes, 0 EOF, -1 error). */
ssize_t tsnet_noisechan_read(tsnet_noisechan *ch, void *buf, size_t n);
/* Write, splitting into <=4077-byte records. */
int tsnet_noisechan_write(tsnet_noisechan *ch, const void *buf, size_t n);

void tsnet_noisechan_close(tsnet_noisechan *ch);

#endif
