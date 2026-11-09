#ifndef TSNET_UTIL_LOG_H
#define TSNET_UTIL_LOG_H

#include "tsnet/tsnet.h"

#include <stdarg.h>

/* Leveled logger. Thread-safe. Writes to stderr by default; optionally also
 * to a rotating file (2 x max_size). Levels per tsnet_log_level. */

void tsnet_log_set_level(tsnet_log_level lvl);
tsnet_log_level tsnet_log_get_level(void);

/* Enable logging to <path>; rotates to <path>.1 when max_size is exceeded.
 * Pass NULL to disable file logging. Returns 0 or TSNET_E_IO. */
int tsnet_log_set_file(const char *path, size_t max_size);

/* Mirror log lines to stderr (default true on host, false on NX). */
void tsnet_log_set_stderr(bool enable);

/* fsync every line to disk (crash-safe on-device log). Off by default;
 * enable during bring-up so a hard abort still leaves the last step on sdmc. */
void tsnet_log_set_sync(bool enable);

void tsnet_logf(tsnet_log_level lvl, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;

#define TSNET_LOGE(...) tsnet_logf(TSNET_LOG_ERROR, __VA_ARGS__)
#define TSNET_LOGW(...) tsnet_logf(TSNET_LOG_WARN, __VA_ARGS__)
#define TSNET_LOGI(...) tsnet_logf(TSNET_LOG_INFO, __VA_ARGS__)
#define TSNET_LOGD(...) tsnet_logf(TSNET_LOG_DEBUG, __VA_ARGS__)
#define TSNET_LOGT(...) tsnet_logf(TSNET_LOG_TRACE, __VA_ARGS__)

#endif
