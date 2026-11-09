/* lwIP side of the shim border (see sockapi.h). This TU includes ONLY lwIP
 * socket headers — never the platform's <sys/socket.h>. */
#include "sockapi.h"

#include "tsnet/tsnet.h"
#include "util/log.h"

#include "lwip/netif.h"
#include "lwip/sockets.h"

#include <errno.h>
#include <string.h>

/* ---- address conversion ------------------------------------------------ */

static socklen_t to_lwip_sa(const tsnet_addr *a, struct sockaddr_storage *ss) {
    memset(ss, 0, sizeof(*ss));
    if (a->family == 4) {
        struct sockaddr_in *sin = (struct sockaddr_in *)ss;
        sin->sin_len = sizeof(*sin);
        sin->sin_family = AF_INET;
        sin->sin_port = lwip_htons(a->port);
        memcpy(&sin->sin_addr, a->ip, 4);
        return sizeof(*sin);
    }
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
    sin6->sin6_len = sizeof(*sin6);
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = lwip_htons(a->port);
    memcpy(&sin6->sin6_addr, a->ip, 16);
    return sizeof(*sin6);
}

static void from_lwip_sa(const struct sockaddr *sa, tsnet_addr *out) {
    memset(out, 0, sizeof(*out));
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
        out->family = 4;
        memcpy(out->ip, &sin->sin_addr, 4);
        out->port = lwip_ntohs(sin->sin_port);
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
        out->family = 6;
        memcpy(out->ip, &sin6->sin6_addr, 16);
        out->port = lwip_ntohs(sin6->sin6_port);
    }
}

static int to_lwip_msgflags(int tflags) {
    int f = 0;
    if (tflags & TSNET_MSG_PEEK) f |= MSG_PEEK;
    if (tflags & TSNET_MSG_DONTWAIT) f |= MSG_DONTWAIT;
    if (tflags & TSNET_MSG_WAITALL) f |= MSG_WAITALL;
    return f;
}

/* ---- fd table vtable --------------------------------------------------- */

static int bk_socket(int domain, int type, int protocol) {
    (void)protocol;
    int d = domain == TSNET_AF_INET6 ? AF_INET6 : AF_INET;
    int t = type == TSNET_SOCK_STREAM ? SOCK_STREAM : SOCK_DGRAM;
    int fd = lwip_socket(d, t, 0);
    if (fd < 0) {
        TSNET_LOGE("lwip_adapter: socket(%d,%d) failed errno=%d", d, t, errno);
        return TSNET_E_IO;
    }
    return fd;
}

static int bk_bind(int fd, const tsnet_addr *a) {
    struct sockaddr_storage ss;
    socklen_t len = to_lwip_sa(a, &ss);
    /* Binding to a real-stack local address (e.g. the Wi-Fi IP) or the
     * wildcard both map to the wildcard on the tunnel side: keep the port,
     * drop the address. Specific tailnet addresses are kept. */
    if (!tsnet_addr_in_tailnet_ranges(a) && !tsnet_addr_is_wildcard(a)) {
        tsnet_addr any = *a;
        memset(any.ip, 0, sizeof(any.ip));
        len = to_lwip_sa(&any, &ss);
    }
    if (lwip_bind(fd, (struct sockaddr *)&ss, len) < 0) return TSNET_E_IO;
    return TSNET_OK;
}

static int bk_setsockopt(int fd, int level, int optname, const void *val,
                         uint32_t len) {
    (void)level;
    int lvl, name;
    switch (optname) {
    case TSNET_SO_REUSEADDR: lvl = SOL_SOCKET; name = SO_REUSEADDR; break;
    case TSNET_SO_KEEPALIVE: lvl = SOL_SOCKET; name = SO_KEEPALIVE; break;
    case TSNET_SO_BROADCAST: lvl = SOL_SOCKET; name = SO_BROADCAST; break;
    case TSNET_SO_LINGER:    lvl = SOL_SOCKET; name = SO_LINGER; break;
    case TSNET_SO_RCVBUF:    lvl = SOL_SOCKET; name = SO_RCVBUF; break;
    case TSNET_SO_SNDTIMEO:  lvl = SOL_SOCKET; name = SO_SNDTIMEO; break;
    case TSNET_SO_RCVTIMEO:  lvl = SOL_SOCKET; name = SO_RCVTIMEO; break;
    case TSNET_TCP_NODELAY:  lvl = IPPROTO_TCP; name = TCP_NODELAY; break;
    case TSNET_TCP_KEEPALIVE_ON: lvl = SOL_SOCKET; name = SO_KEEPALIVE; break;
    default:
        /* unsupported on the tunnel: best-effort success */
        TSNET_LOGD("lwip_adapter: unsupported sockopt %d ignored", optname);
        return TSNET_OK;
    }
    if (lwip_setsockopt(fd, lvl, name, val, len) < 0) {
        TSNET_LOGD("lwip_adapter: setsockopt(%d) errno=%d (ignored)", optname,
                   errno);
    }
    return TSNET_OK;
}

static int bk_nonblock(int fd, bool nb) {
    int flags = lwip_fcntl(fd, F_GETFL, 0);
    if (flags < 0) flags = 0;
    if (nb)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;
    return lwip_fcntl(fd, F_SETFL, flags) < 0 ? TSNET_E_IO : TSNET_OK;
}

static int bk_close(int fd) {
    return lwip_close(fd) < 0 ? TSNET_E_IO : TSNET_OK;
}

const tsnet_sock_backend tsnet_lwip_backend = {
    bk_socket, bk_bind, bk_setsockopt, bk_nonblock, bk_close,
};

/* ---- data path --------------------------------------------------------- */

int tsnet_lwip_adapter_connect(int fd, const tsnet_addr *dst) {
    struct sockaddr_storage ss;
    socklen_t len = to_lwip_sa(dst, &ss);
    int rc = lwip_connect(fd, (struct sockaddr *)&ss, len);
    TSNET_LOGI("lwip: connect fd=%d -> %u.%u.%u.%u:%u rc=%d errno=%d", fd,
               dst->ip[0], dst->ip[1], dst->ip[2], dst->ip[3], dst->port, rc,
               errno);
    return rc;
}

ssize_t tsnet_lwip_adapter_send(int fd, const void *buf, size_t len,
                                int tflags) {
    return lwip_send(fd, buf, len, to_lwip_msgflags(tflags));
}

ssize_t tsnet_lwip_adapter_sendto(int fd, const void *buf, size_t len,
                                  int tflags, const tsnet_addr *dst) {
    struct sockaddr_storage ss;
    socklen_t sl = to_lwip_sa(dst, &ss);
    return lwip_sendto(fd, buf, len, to_lwip_msgflags(tflags),
                       (struct sockaddr *)&ss, sl);
}

ssize_t tsnet_lwip_adapter_recv(int fd, void *buf, size_t len, int tflags) {
    return lwip_recv(fd, buf, len, to_lwip_msgflags(tflags));
}

ssize_t tsnet_lwip_adapter_recvfrom(int fd, void *buf, size_t len, int tflags,
                                    tsnet_addr *src) {
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    ssize_t n = lwip_recvfrom(fd, buf, len, to_lwip_msgflags(tflags),
                              src ? (struct sockaddr *)&ss : NULL,
                              src ? &sl : NULL);
    if (n >= 0 && src) from_lwip_sa((struct sockaddr *)&ss, src);
    return n;
}

ssize_t tsnet_lwip_adapter_read(int fd, void *buf, size_t len) {
    return lwip_read(fd, buf, len);
}

ssize_t tsnet_lwip_adapter_write(int fd, const void *buf, size_t len) {
    return lwip_write(fd, buf, len);
}

int tsnet_lwip_adapter_listen(int fd, int backlog) {
    return lwip_listen(fd, backlog);
}

int tsnet_lwip_adapter_accept(int fd, tsnet_addr *src) {
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    int nfd = lwip_accept(fd, src ? (struct sockaddr *)&ss : NULL,
                          src ? &sl : NULL);
    if (nfd >= 0 && src) from_lwip_sa((struct sockaddr *)&ss, src);
    return nfd;
}

int tsnet_lwip_adapter_shutdown(int fd, int how) {
    int h = how == TSNET_SHUT_RD ? SHUT_RD
            : how == TSNET_SHUT_WR ? SHUT_WR
                                   : SHUT_RDWR;
    return lwip_shutdown(fd, h);
}

int tsnet_lwip_adapter_getsockname(int fd, tsnet_addr *out) {
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    if (lwip_getsockname(fd, (struct sockaddr *)&ss, &sl) < 0) return -1;
    from_lwip_sa((struct sockaddr *)&ss, out);
    /* BSD/Linux report the routed source address for a connected socket;
     * lwIP's udp_connect() (extern/lwip/src/core/udp.c) only records the
     * remote side, so local_ip stays ANY. moonlight-common-c relies on the
     * BSD behaviour (getLocalAddressByUdpConnect -> bindUdpSocket binds the
     * video/audio/ENet sockets to that address), and a 0.0.0.0 bind would
     * send those sockets to the real stack. ts0 is the only (default) lwIP
     * netif, so the routed source is its IPv4 address. */
    if (out->family == 4 && out->ip[0] == 0 && out->ip[1] == 0 &&
        out->ip[2] == 0 && out->ip[3] == 0) {
        struct sockaddr_storage peer;
        socklen_t pl = sizeof(peer);
        if (lwip_getpeername(fd, (struct sockaddr *)&peer, &pl) == 0 &&
            netif_default != NULL) {
            const ip4_addr_t *src = netif_ip4_addr(netif_default);
            if (src && !ip4_addr_isany(src)) memcpy(out->ip, src, 4);
        }
    }
    return 0;
}

int tsnet_lwip_adapter_getpeername(int fd, tsnet_addr *out) {
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    if (lwip_getpeername(fd, (struct sockaddr *)&ss, &sl) < 0) return -1;
    from_lwip_sa((struct sockaddr *)&ss, out);
    return 0;
}

int tsnet_lwip_adapter_getsockopt(int fd, int topt, void *val, uint32_t *len) {
    socklen_t sl = *len;
    int rc;
    switch (topt) {
    case TSNET_SO_ERROR:
        rc = lwip_getsockopt(fd, SOL_SOCKET, SO_ERROR, val, &sl);
        break;
    case TSNET_SO_RCVBUF:
        rc = lwip_getsockopt(fd, SOL_SOCKET, SO_RCVBUF, val, &sl);
        break;
    default:
        /* best effort: report zeroed value */
        memset(val, 0, *len);
        return 0;
    }
    if (rc == 0) *len = sl;
    return rc;
}

int tsnet_lwip_adapter_poll(tsnet_pfd *fds, int n, int timeout_ms) {
    struct pollfd pfds[64];
    if (n > 64) return -1;
    for (int i = 0; i < n; i++) {
        pfds[i].fd = fds[i].fd;
        pfds[i].events = 0;
        pfds[i].revents = 0;
        if (fds[i].events & TSNET_POLLIN) pfds[i].events |= POLLIN;
        if (fds[i].events & TSNET_POLLOUT) pfds[i].events |= POLLOUT;
        if (fds[i].events & TSNET_POLLPRI) pfds[i].events |= POLLPRI;
    }
    int rc = lwip_poll(pfds, (nfds_t)n, timeout_ms);
    for (int i = 0; i < n; i++) {
        short r = 0;
        if (pfds[i].revents & POLLIN) r |= TSNET_POLLIN;
        if (pfds[i].revents & POLLOUT) r |= TSNET_POLLOUT;
        if (pfds[i].revents & POLLERR) r |= TSNET_POLLERR;
        if (pfds[i].revents & POLLHUP) r |= TSNET_POLLHUP;
        if (pfds[i].revents & POLLNVAL) r |= TSNET_POLLNVAL;
        fds[i].revents = r;
    }
    return rc;
}
