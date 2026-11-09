#include "keyfile.h"

#include "tsnet/tsnet.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <unistd.h>
#endif

int tsnet_keyfile_load(const char *path, uint8_t out[32]) {
    FILE *f = fopen(path, "rb");
    if (!f) return TSNET_E_IO;
    uint8_t buf[33];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    if (n != 32) return TSNET_E_INVAL;
    memcpy(out, buf, 32);
    return TSNET_OK;
}

static int write_file_sync(const char *path, const uint8_t *data, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) return TSNET_E_IO;
    if (fwrite(data, 1, n, f) != n || fflush(f) != 0) {
        fclose(f);
        remove(path);
        return TSNET_E_IO;
    }
#ifndef _WIN32
    fsync(fileno(f)); /* best effort; sdmc devoptab supports it via newlib */
#endif
    if (fclose(f) != 0) {
        remove(path);
        return TSNET_E_IO;
    }
    return TSNET_OK;
}

int tsnet_keyfile_store(const char *path, const uint8_t key[32]) {
    char tmp[512];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
        return TSNET_E_INVAL;
    int rc = write_file_sync(tmp, key, 32);
    if (rc != TSNET_OK) return rc;
    /* Try an atomic rename first (keeps the old key if the new write is
     * fine). Only if that fails (newlib rename() won't overwrite on some
     * devoptabs) fall back to remove+rename — but re-check: if the rename
     * then fails too, the tmp still holds the new key, so recovery is
     * possible and we never remove the original without a tmp in hand. */
    if (rename(tmp, path) == 0) return TSNET_OK;
    if (remove(path) != 0) {
        /* original could not be removed and rename failed: keep both */
        remove(tmp);
        return TSNET_E_IO;
    }
    if (rename(tmp, path) != 0) {
        remove(tmp);
        return TSNET_E_IO;
    }
    return TSNET_OK;
}

int tsnet_keyfile_remove(const char *path) {
    uint8_t zeros[32] = {0};
    FILE *f = fopen(path, "r+b");
    if (f) {
        fwrite(zeros, 1, sizeof(zeros), f);
        fflush(f);
#ifndef _WIN32
        fsync(fileno(f));
#endif
        fclose(f);
    } else if (errno == ENOENT) {
        return TSNET_OK;
    }
    return remove(path) == 0 ? TSNET_OK : TSNET_E_IO;
}
