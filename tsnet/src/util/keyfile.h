#ifndef TSNET_UTIL_KEYFILE_H
#define TSNET_UTIL_KEYFILE_H

#include <stddef.h>
#include <stdint.h>

/* Load/store 32-byte raw key files (machine.key, node.key, disco.key).
 * Writes are atomic: tmp file + fsync + rename. Returns TSNET_OK or
 * TSNET_E_IO / TSNET_E_INVAL (wrong size on load). */

int tsnet_keyfile_load(const char *path, uint8_t out[32]);
int tsnet_keyfile_store(const char *path, const uint8_t key[32]);

/* Best-effort secure delete (overwrite with zeros, then remove). */
int tsnet_keyfile_remove(const char *path);

#endif
