#include "tsnet/tsnet.h"

const char *tsnet_err_str(tsnet_err e) {
    switch (e) {
    case TSNET_OK: return "ok";
    case TSNET_E_INVAL: return "invalid argument";
    case TSNET_E_NOMEM: return "out of memory";
    case TSNET_E_IO: return "I/O error";
    case TSNET_E_PROTO: return "protocol error";
    case TSNET_E_TLS: return "TLS error";
    case TSNET_E_AUTH: return "authentication error";
    case TSNET_E_STATE: return "invalid state";
    case TSNET_E_TIMEOUT: return "timeout";
    case TSNET_E_CLOSED: return "connection closed";
    }
    return "unknown error";
}
