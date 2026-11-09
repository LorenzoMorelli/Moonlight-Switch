#include "log.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static tsnet_log_level g_level = TSNET_LOG_INFO;
static bool g_stderr = true;
static bool g_sync = false; /* fsync every line: crash-safe on-device log */
static FILE *g_file = NULL;
static char g_path[512];
static size_t g_max_size = 2 * 1024 * 1024;
static size_t g_written = 0;

void tsnet_log_set_level(tsnet_log_level lvl) { g_level = lvl; }
tsnet_log_level tsnet_log_get_level(void) { return g_level; }
void tsnet_log_set_stderr(bool enable) { g_stderr = enable; }
void tsnet_log_set_sync(bool enable) { g_sync = enable; }

int tsnet_log_set_file(const char *path, size_t max_size) {
    pthread_mutex_lock(&g_mu);
    if (g_file) {
        fclose(g_file);
        g_file = NULL;
    }
    int rc = 0;
    if (path) {
        snprintf(g_path, sizeof(g_path), "%s", path);
        g_max_size = max_size ? max_size : 2 * 1024 * 1024;
        g_file = fopen(g_path, "a");
        if (g_file) {
            long pos = ftell(g_file);
            g_written = pos > 0 ? (size_t)pos : 0;
        } else {
            rc = TSNET_E_IO;
        }
    }
    pthread_mutex_unlock(&g_mu);
    return rc;
}

/* callers hold g_mu */
static void rotate_locked(void) {
    fclose(g_file);
    g_file = NULL;
    char old[sizeof(g_path) + 2];
    snprintf(old, sizeof(old), "%s.1", g_path);
    remove(old);
    rename(g_path, old);
    g_file = fopen(g_path, "w");
    g_written = 0;
}

void tsnet_logf(tsnet_log_level lvl, const char *fmt, ...) {
    if (lvl > g_level) return;

    static const char lc[] = {'E', 'W', 'I', 'D', 'T'};
    /* leave room for the trailing "\n\0" appended below */
    char line[1024];
    const size_t body_cap = sizeof(line) - 2;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    int off = snprintf(line, body_cap, "%02d:%02d:%02d.%03ld %c ",
                       tm.tm_hour, tm.tm_min, tm.tm_sec,
                       ts.tv_nsec / 1000000, lc[lvl]);
    if (off < 0) return;
    if ((size_t)off > body_cap) off = (int)body_cap; /* snprintf truncation */

    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line + off, body_cap - (size_t)off, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    /* clamp to what actually fit in body_cap (vsnprintf returns the would-be
     * length); len then has >= 2 bytes spare for '\n' and '\0' */
    size_t body = (size_t)off + (size_t)n;
    if (body > body_cap) body = body_cap;
    size_t len = body;
    line[len] = '\n';
    line[len + 1] = '\0';
    len++;

    pthread_mutex_lock(&g_mu);
    if (g_stderr) fputs(line, stderr);
    if (g_file) {
        fwrite(line, 1, len, g_file);
        fflush(g_file);
        /* fflush only reaches newlib/libnx buffers; a hard abort (svcBreak)
         * does not commit the sdmc FAT cache, so without fsync the on-device
         * log is empty after a crash. fsync forces the commit line-by-line. */
        if (g_sync) fsync(fileno(g_file));
        g_written += len;
        if (g_written >= g_max_size) rotate_locked();
    }
    pthread_mutex_unlock(&g_mu);
}
