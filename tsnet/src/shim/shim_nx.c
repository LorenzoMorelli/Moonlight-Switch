/* Horizon OS (libnx) socket shim: devoptab "tsnet" + -Wl,--wrap= dispatch.
 * NX-only translation unit: includes newlib/libnx headers,
 * never lwIP ones (the lwIP side lives behind sockapi.h / lwip_adapter.c).
 *
 * Every socket() created through the shim returns a newlib fd registered on
 * our "tsnet" devoptab (so read/write/close work natively, and libnx's own
 * "soc" checks never see it, cf. libnx socket.c:_socketGetFd rejecting
 * foreign devoptabs). The fd's fileStruct holds the virtual-fd index into
 * the portable lazy-binding table (fdtable.c). Wrapped calls on fds that do
 * not belong to "tsnet" fall through to __real_* (libnx).
 */

#include "sockapi.h"

#include "tsnet/tsnet.h"
#include "util/log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/iosupport.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---- __real_ prototypes (provided by the linker) ----------------------- */

int __real_socket(int domain, int type, int protocol);
int __real_bind(int fd, const struct sockaddr *addr, socklen_t len);
int __real_connect(int fd, const struct sockaddr *addr, socklen_t len);
int __real_listen(int fd, int backlog);
int __real_accept(int fd, struct sockaddr *addr, socklen_t *len);
ssize_t __real_send(int fd, const void *buf, size_t len, int flags);
ssize_t __real_sendto(int fd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dst, socklen_t dlen);
ssize_t __real_sendmsg(int fd, const struct msghdr *msg, int flags);
ssize_t __real_recv(int fd, void *buf, size_t len, int flags);
ssize_t __real_recvfrom(int fd, void *buf, size_t len, int flags,
                        struct sockaddr *src, socklen_t *slen);
ssize_t __real_recvmsg(int fd, struct msghdr *msg, int flags);
int __real_setsockopt(int fd, int level, int optname, const void *val,
                      socklen_t len);
int __real_getsockopt(int fd, int level, int optname, void *val,
                      socklen_t *len);
int __real_getsockname(int fd, struct sockaddr *addr, socklen_t *len);
int __real_getpeername(int fd, struct sockaddr *addr, socklen_t *len);
int __real_shutdown(int fd, int how);
int __real_ioctl(int fd, int request, ...);
int __real_fcntl(int fd, int cmd, ...);
int __real_select(int nfds, fd_set *rfds, fd_set *wfds, fd_set *efds,
                  struct timeval *timeout);
int __real_poll(struct pollfd *fds, nfds_t nfds, int timeout);
int __real_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints, struct addrinfo **res);
void __real_freeaddrinfo(struct addrinfo *ai);
struct hostent *__real_gethostbyname(const char *name);

/* ---- devoptab ----------------------------------------------------------- */

static bool g_active; /* wraps pass through to __real_* until init */
static int g_dev = -1;

static int dt_close(struct _reent *r, void *fdptr);
static ssize_t dt_write(struct _reent *r, void *fdptr, const char *buf,
                        size_t n);
static ssize_t dt_read(struct _reent *r, void *fdptr, char *buf, size_t n);

static devoptab_t g_tsnet_devoptab = {
    .name = "tsnet",
    .structSize = sizeof(int), /* vfd index */
    .close_r = dt_close,
    .write_r = dt_write,
    .read_r = dt_read,
};

/* vfd index for one of our fds, or -1 */
static int vfd_of(int fd) {
    if (!g_active) return -1;
    __handle *h = __get_handle(fd);
    if (!h) return -1;
    if (devoptab_list[h->device] != &g_tsnet_devoptab) return -1;
    return *(int *)h->fileStruct;
}

/* allocate a newlib fd on our devoptab holding vfd */
static int fd_for_vfd(int vfd) {
    int fd = __alloc_handle(g_dev);
    if (fd == -1) {
        errno = ENFILE;
        return -1;
    }
    *(int *)__get_handle(fd)->fileStruct = vfd;
    return fd;
}

static int tsnet_err_to_errno(int e) {
    switch (e) {
    case TSNET_E_NOMEM: return ENFILE;
    case TSNET_E_INVAL: return EINVAL;
    case TSNET_E_STATE: return EBADF;
    default: return errno ? errno : EIO;
    }
}

/* ---- sockaddr conversion (newlib BSD layout) ---------------------------- */

static bool to_tsnet_addr(const struct sockaddr *sa, socklen_t len,
                          tsnet_addr *out) {
    memset(out, 0, sizeof(*out));
    if (!sa) return false;
    if (sa->sa_family == AF_INET && len >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
        out->family = 4;
        memcpy(out->ip, &sin->sin_addr, 4);
        out->port = ntohs(sin->sin_port);
        return true;
    }
    if (sa->sa_family == AF_INET6 && len >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
        out->family = 6;
        memcpy(out->ip, &sin6->sin6_addr, 16);
        out->port = ntohs(sin6->sin6_port);
        return true;
    }
    return false;
}

static socklen_t from_tsnet_addr(const tsnet_addr *a, struct sockaddr *sa,
                                 socklen_t cap) {
    if (a->family == 4) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(a->port);
        memcpy(&sin.sin_addr, a->ip, 4);
        socklen_t n = cap < sizeof(sin) ? cap : sizeof(sin);
        memcpy(sa, &sin, n);
        return sizeof(sin);
    }
    struct sockaddr_in6 sin6;
    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(a->port);
    memcpy(&sin6.sin6_addr, a->ip, 16);
    socklen_t n = cap < sizeof(sin6) ? cap : sizeof(sin6);
    memcpy(sa, &sin6, n);
    return sizeof(sin6);
}

/* ---- option / flag translation to the neutral surface ------------------- */

static int platform_opt_to_neutral(int level, int optname) {
    if (level == SOL_SOCKET) {
        switch (optname) {
        case SO_REUSEADDR: return TSNET_SO_REUSEADDR;
        case SO_KEEPALIVE: return TSNET_SO_KEEPALIVE;
        case SO_BROADCAST: return TSNET_SO_BROADCAST;
        case SO_LINGER: return TSNET_SO_LINGER;
        case SO_RCVBUF: return TSNET_SO_RCVBUF;
        case SO_SNDTIMEO: return TSNET_SO_SNDTIMEO;
        case SO_RCVTIMEO: return TSNET_SO_RCVTIMEO;
        case SO_ERROR: return TSNET_SO_ERROR;
        default: return TSNET_SO_UNSUPPORTED;
        }
    }
    if (level == IPPROTO_TCP && optname == TCP_NODELAY)
        return TSNET_TCP_NODELAY;
    return TSNET_SO_UNSUPPORTED;
}

static int platform_msgflags_to_neutral(int flags) {
    int f = 0;
    if (flags & MSG_PEEK) f |= TSNET_MSG_PEEK;
    if (flags & MSG_DONTWAIT) f |= TSNET_MSG_DONTWAIT;
    if (flags & MSG_WAITALL) f |= TSNET_MSG_WAITALL;
    return f;
}

static short platform_pollev_to_neutral(short ev) {
    short t = 0;
    if (ev & POLLIN) t |= TSNET_POLLIN;
    if (ev & POLLPRI) t |= TSNET_POLLPRI;
    if (ev & POLLOUT) t |= TSNET_POLLOUT;
    return t;
}

static short neutral_pollev_to_platform(short t) {
    short ev = 0;
    if (t & TSNET_POLLIN) ev |= POLLIN;
    if (t & TSNET_POLLPRI) ev |= POLLPRI;
    if (t & TSNET_POLLOUT) ev |= POLLOUT;
    if (t & TSNET_POLLERR) ev |= POLLERR;
    if (t & TSNET_POLLHUP) ev |= POLLHUP;
    if (t & TSNET_POLLNVAL) ev |= POLLNVAL;
    return ev;
}

/* ---- backend vtables ----------------------------------------------------
 * The fd table stores domain/type/protocol and (level,optname) exactly as
 * the app passed them (newlib values). The real backend forwards verbatim;
 * the lwIP wrapper translates to the neutral surface. */

static int realbk_socket(int domain, int type, int protocol) {
    int fd = __real_socket(domain, type, protocol);
    return fd < 0 ? TSNET_E_IO : fd;
}

static int realbk_bind(int fd, const tsnet_addr *a) {
    struct sockaddr_storage ss;
    socklen_t len = from_tsnet_addr(a, (struct sockaddr *)&ss, sizeof(ss));
    return __real_bind(fd, (struct sockaddr *)&ss, len) < 0 ? TSNET_E_IO
                                                            : TSNET_OK;
}

static int realbk_setsockopt(int fd, int level, int optname, const void *val,
                             uint32_t len) {
    return __real_setsockopt(fd, level, optname, val, (socklen_t)len) < 0
               ? TSNET_E_IO
               : TSNET_OK;
}

static int realbk_nonblock(int fd, bool nb) {
    int flags = __real_fcntl(fd, F_GETFL, 0);
    if (flags < 0) flags = 0;
    if (nb)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;
    return __real_fcntl(fd, F_SETFL, flags) < 0 ? TSNET_E_IO : TSNET_OK;
}

static int realbk_close(int fd) {
    return close(fd) < 0 ? TSNET_E_IO : TSNET_OK; /* newlib "soc" fd */
}

static const tsnet_sock_backend g_real_bk = {
    realbk_socket, realbk_bind, realbk_setsockopt, realbk_nonblock,
    realbk_close,
};

static int lwbk_socket(int domain, int type, int protocol) {
    int d = domain == AF_INET6 ? TSNET_AF_INET6 : TSNET_AF_INET;
    /* type carries SOCK_CLOEXEC/SOCK_NONBLOCK in its high bits (libcurl and
     * moonlight-common-c create sockets as SOCK_STREAM|SOCK_NONBLOCK); mask
     * them off before classifying, or a TCP socket is misread as UDP and the
     * app's HTTP request goes out as a stray datagram. */
    int base = type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK);
    int t = base == SOCK_STREAM ? TSNET_SOCK_STREAM : TSNET_SOCK_DGRAM;
    return tsnet_lwip_backend.bk_socket(d, t, protocol);
}

static int lwbk_setsockopt(int fd, int level, int optname, const void *val,
                           uint32_t len) {
    int topt = platform_opt_to_neutral(level, optname);
    return tsnet_lwip_backend.bk_setsockopt(fd, 0, topt, val, len);
}

static tsnet_sock_backend g_lwip_bk_platform;

/* ---- mixed poll plumbing ------------------------------------------------ */

static int mp_real_poll(tsnet_pfd *fds, int n, int timeout_ms) {
    struct pollfd pfds[64];
    if (n > 64) return TSNET_E_INVAL;
    for (int i = 0; i < n; i++) {
        pfds[i].fd = fds[i].fd;
        pfds[i].events = neutral_pollev_to_platform(fds[i].events);
        pfds[i].revents = 0;
    }
    int rc = __real_poll(pfds, (nfds_t)n, timeout_ms);
    for (int i = 0; i < n; i++)
        fds[i].revents = platform_pollev_to_neutral(pfds[i].revents) |
                         ((pfds[i].revents & POLLERR) ? TSNET_POLLERR : 0) |
                         ((pfds[i].revents & POLLHUP) ? TSNET_POLLHUP : 0) |
                         ((pfds[i].revents & POLLNVAL) ? TSNET_POLLNVAL : 0);
    return rc;
}

/* ---- init ---------------------------------------------------------------- */

int tsnet_shim_nx_init(void) {
    if (g_active) return TSNET_OK;
    g_dev = AddDevice(&g_tsnet_devoptab);
    if (g_dev < 0) {
        TSNET_LOGE("shim: AddDevice(tsnet) failed");
        return TSNET_E_STATE;
    }
    g_lwip_bk_platform = tsnet_lwip_backend;
    g_lwip_bk_platform.bk_socket = lwbk_socket;
    g_lwip_bk_platform.bk_setsockopt = lwbk_setsockopt;
    tsnet_fdtable_init(&g_real_bk, &g_lwip_bk_platform);
    tsnet_mixedpoll_init(mp_real_poll, tsnet_lwip_adapter_poll);
    g_active = true;
    TSNET_LOGI("shim: active (devoptab tsnet, dev=%d)", g_dev);
    return TSNET_OK;
}

/* ---- devoptab handlers --------------------------------------------------- */

static int ensure_default(int vfd) {
    int rc = tsnet_vfd_require_default(vfd);
    if (rc != TSNET_OK) return rc;
    return TSNET_OK;
}

static int dt_close(struct _reent *r, void *fdptr) {
    int vfd = *(int *)fdptr;
    int rc = tsnet_vfd_close(vfd);
    if (rc != TSNET_OK) {
        r->_errno = tsnet_err_to_errno(rc);
        return -1;
    }
    return 0;
}

static ssize_t dt_write(struct _reent *r, void *fdptr, const char *buf,
                        size_t n) {
    int vfd = *(int *)fdptr;
    int rc = ensure_default(vfd);
    if (rc != TSNET_OK) {
        r->_errno = tsnet_err_to_errno(rc);
        return -1;
    }
    int bfd = tsnet_vfd_backend_fd(vfd);
    ssize_t ret;
    if (tsnet_vfd_kind(vfd) == TSNET_BK_LWIP)
        ret = tsnet_lwip_adapter_write(bfd, buf, n);
    else
        ret = write(bfd, buf, n);
    if (ret < 0) r->_errno = errno;
    return ret;
}

static ssize_t dt_read(struct _reent *r, void *fdptr, char *buf, size_t n) {
    int vfd = *(int *)fdptr;
    int rc = ensure_default(vfd);
    if (rc != TSNET_OK) {
        r->_errno = tsnet_err_to_errno(rc);
        return -1;
    }
    int bfd = tsnet_vfd_backend_fd(vfd);
    ssize_t ret;
    if (tsnet_vfd_kind(vfd) == TSNET_BK_LWIP)
        ret = tsnet_lwip_adapter_read(bfd, buf, n);
    else
        ret = read(bfd, buf, n);
    if (ret < 0) r->_errno = errno;
    return ret;
}

/* ---- wrapped socket calls ------------------------------------------------ */

int __wrap_socket(int domain, int type, int protocol) {
    if (!g_active || (domain != AF_INET && domain != AF_INET6))
        return __real_socket(domain, type, protocol);
    int vfd = tsnet_vfd_open(domain, type, protocol);
    if (vfd < 0) {
        TSNET_LOGW("shim: vfd table full, falling back to real socket");
        return __real_socket(domain, type, protocol);
    }
    /* carry a socket()-time SOCK_NONBLOCK onto the (lazily bound) backend;
     * the lwIP backend is created blocking, so without this a non-blocking
     * app socket would block on connect */
    if (type & SOCK_NONBLOCK) tsnet_vfd_set_nonblock(vfd, true);
    int fd = fd_for_vfd(vfd);
    if (fd < 0) {
        tsnet_vfd_close(vfd);
        return -1;
    }
    return fd;
}

int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t len) {
    int vfd = vfd_of(fd);
    if (vfd < 0) return __real_bind(fd, addr, len);
    tsnet_addr a;
    if (!to_tsnet_addr(addr, len, &a)) {
        errno = EINVAL;
        return -1;
    }
    int rc = tsnet_vfd_bind(vfd, &a);
    if (rc != TSNET_OK) {
        errno = tsnet_err_to_errno(rc);
        return -1;
    }
    return 0;
}

int __wrap_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    int vfd = vfd_of(fd);
    if (vfd < 0) return __real_connect(fd, addr, len);
    tsnet_addr dst;
    if (!to_tsnet_addr(addr, len, &dst)) {
        errno = EINVAL;
        return -1;
    }
    int rc = tsnet_vfd_require_route(vfd, &dst);
    if (rc != TSNET_OK) {
        errno = tsnet_err_to_errno(rc);
        return -1;
    }
    int bfd = tsnet_vfd_backend_fd(vfd);
    bool tunnel = tsnet_vfd_kind(vfd) == TSNET_BK_LWIP;
    /* one line per outbound connection so "can't reach the host" is
     * diagnosable: shows the target and whether it went through the tunnel
     * (tailnet) or a real LAN/Internet socket */
    if (dst.family == 4)
        TSNET_LOGI("shim: connect %u.%u.%u.%u:%u -> %s", dst.ip[0], dst.ip[1],
                   dst.ip[2], dst.ip[3], dst.port, tunnel ? "tunnel" : "real");
    else
        TSNET_LOGI("shim: connect [v6]:%u -> %s", dst.port,
                   tunnel ? "tunnel" : "real");
    if (tunnel) return tsnet_lwip_adapter_connect(bfd, &dst);
    return __real_connect(bfd, addr, len);
}

int __wrap_listen(int fd, int backlog) {
    int vfd = vfd_of(fd);
    if (vfd < 0) return __real_listen(fd, backlog);
    int rc = tsnet_vfd_require_default(vfd);
    if (rc != TSNET_OK) {
        errno = tsnet_err_to_errno(rc);
        return -1;
    }
    int bfd = tsnet_vfd_backend_fd(vfd);
    if (tsnet_vfd_kind(vfd) == TSNET_BK_LWIP)
        return tsnet_lwip_adapter_listen(bfd, backlog);
    return __real_listen(bfd, backlog);
}

int __wrap_accept(int fd, struct sockaddr *addr, socklen_t *len) {
    int vfd = vfd_of(fd);
    if (vfd < 0) return __real_accept(fd, addr, len);
    int bfd = tsnet_vfd_backend_fd(vfd);
    if (bfd < 0) {
        errno = EINVAL;
        return -1;
    }
    if (tsnet_vfd_kind(vfd) == TSNET_BK_LWIP) {
        tsnet_addr src;
        int nfd = tsnet_lwip_adapter_accept(bfd, &src);
        if (nfd < 0) return -1;
        int nvfd = tsnet_vfd_adopt(TSNET_BK_LWIP, nfd, tsnet_vfd_domain(vfd),
                                   tsnet_vfd_type(vfd), 0);
        if (nvfd < 0) {
            tsnet_lwip_backend.bk_close(nfd);
            errno = ENFILE;
            return -1;
        }
        int newfd = fd_for_vfd(nvfd);
        if (newfd < 0) {
            tsnet_vfd_close(nvfd);
            return -1;
        }
        if (addr && len) *len = from_tsnet_addr(&src, addr, *len);
        return newfd;
    }
    /* real listener: the accepted fd is a normal "soc" fd; return as-is */
    return __real_accept(bfd, addr, len);
}

static ssize_t send_common(int fd, const void *buf, size_t n, int flags,
                           const struct sockaddr *dst, socklen_t dlen) {
    int vfd = vfd_of(fd);
    if (vfd < 0)
        return dst ? __real_sendto(fd, buf, n, flags, dst, dlen)
                   : __real_send(fd, buf, n, flags);
    tsnet_addr d;
    bool have_dst = dst && to_tsnet_addr(dst, dlen, &d);
    int rc = have_dst ? tsnet_vfd_require_route(vfd, &d)
                      : tsnet_vfd_require_default(vfd);
    if (rc != TSNET_OK) {
        errno = tsnet_err_to_errno(rc);
        return -1;
    }
    int bfd = tsnet_vfd_backend_fd(vfd);
    if (tsnet_vfd_kind(vfd) == TSNET_BK_LWIP) {
        int tf = platform_msgflags_to_neutral(flags);
        return have_dst ? tsnet_lwip_adapter_sendto(bfd, buf, n, tf, &d)
                        : tsnet_lwip_adapter_send(bfd, buf, n, tf);
    }
    return dst ? __real_sendto(bfd, buf, n, flags, dst, dlen)
               : __real_send(bfd, buf, n, flags);
}

ssize_t __wrap_send(int fd, const void *buf, size_t n, int flags) {
    return send_common(fd, buf, n, flags, NULL, 0);
}

ssize_t __wrap_sendto(int fd, const void *buf, size_t n, int flags,
                      const struct sockaddr *dst, socklen_t dlen) {
    return send_common(fd, buf, n, flags, dst, dlen);
}

static ssize_t recv_common(int fd, void *buf, size_t n, int flags,
                           struct sockaddr *src, socklen_t *slen) {
    int vfd = vfd_of(fd);
    if (vfd < 0)
        return src ? __real_recvfrom(fd, buf, n, flags, src, slen)
                   : __real_recv(fd, buf, n, flags);
    int rc = tsnet_vfd_require_default(vfd);
    if (rc != TSNET_OK) {
        errno = tsnet_err_to_errno(rc);
        return -1;
    }
    int bfd = tsnet_vfd_backend_fd(vfd);
    if (tsnet_vfd_kind(vfd) == TSNET_BK_LWIP) {
        int tf = platform_msgflags_to_neutral(flags);
        tsnet_addr a;
        ssize_t ret = tsnet_lwip_adapter_recvfrom(bfd, buf, n, tf,
                                                  src ? &a : NULL);
        if (ret >= 0 && src && slen) *slen = from_tsnet_addr(&a, src, *slen);
        return ret;
    }
    return src ? __real_recvfrom(bfd, buf, n, flags, src, slen)
               : __real_recv(bfd, buf, n, flags);
}

ssize_t __wrap_recv(int fd, void *buf, size_t n, int flags) {
    return recv_common(fd, buf, n, flags, NULL, NULL);
}

ssize_t __wrap_recvfrom(int fd, void *buf, size_t n, int flags,
                        struct sockaddr *src, socklen_t *slen) {
    return recv_common(fd, buf, n, flags, src, slen);
}

ssize_t __wrap_sendmsg(int fd, const struct msghdr *msg, int flags) {
    int vfd = vfd_of(fd);
    if (vfd < 0) return __real_sendmsg(fd, msg, flags);
    /* linearize: tunnel packets are <= MTU 1280, buffer covers control TCP */
    uint8_t tmp[2048];
    size_t total = 0;
    for (size_t i = 0; i < (size_t)msg->msg_iovlen; i++) {
        size_t l = msg->msg_iov[i].iov_len;
        if (total + l > sizeof(tmp)) {
            errno = EMSGSIZE;
            return -1;
        }
        memcpy(tmp + total, msg->msg_iov[i].iov_base, l);
        total += l;
    }
    return send_common(fd, tmp, total, flags,
                       (const struct sockaddr *)msg->msg_name,
                       (socklen_t)msg->msg_namelen);
}

ssize_t __wrap_recvmsg(int fd, struct msghdr *msg, int flags) {
    int vfd = vfd_of(fd);
    if (vfd < 0) return __real_recvmsg(fd, msg, flags);
    uint8_t tmp[2048];
    socklen_t slen = (socklen_t)msg->msg_namelen;
    ssize_t n = recv_common(fd, tmp, sizeof(tmp), flags,
                            (struct sockaddr *)msg->msg_name,
                            msg->msg_name ? &slen : NULL);
    if (n < 0) return n;
    msg->msg_namelen = slen;
    msg->msg_controllen = 0;
    msg->msg_flags = 0;
    size_t off = 0;
    for (size_t i = 0; i < (size_t)msg->msg_iovlen && off < (size_t)n; i++) {
        size_t l = msg->msg_iov[i].iov_len;
        if (l > (size_t)n - off) l = (size_t)n - off;
        memcpy(msg->msg_iov[i].iov_base, tmp + off, l);
        off += l;
    }
    return (ssize_t)off;
}

int __wrap_setsockopt(int fd, int level, int optname, const void *val,
                      socklen_t len) {
    int vfd = vfd_of(fd);
    if (vfd < 0) return __real_setsockopt(fd, level, optname, val, len);
    int rc = tsnet_vfd_setsockopt(vfd, level, optname, val, (uint32_t)len);
    if (rc != TSNET_OK) {
        errno = tsnet_err_to_errno(rc);
        return -1;
    }
    return 0;
}

int __wrap_getsockopt(int fd, int level, int optname, void *val,
                      socklen_t *len) {
    int vfd = vfd_of(fd);
    if (vfd < 0) return __real_getsockopt(fd, level, optname, val, len);
    switch (tsnet_vfd_kind(vfd)) {
    case TSNET_BK_UNBOUND:
        /* nothing failed yet; SO_ERROR = 0, other options zeroed */
        memset(val, 0, *len);
        return 0;
    case TSNET_BK_LWIP: {
        uint32_t l = (uint32_t)*len;
        int topt = platform_opt_to_neutral(level, optname);
        int rc = tsnet_lwip_adapter_getsockopt(tsnet_vfd_backend_fd(vfd),
                                               topt, val, &l);
        if (rc == 0) *len = (socklen_t)l;
        return rc;
    }
    case TSNET_BK_REAL:
    default:
        return __real_getsockopt(tsnet_vfd_backend_fd(vfd), level, optname,
                                 val, len);
    }
}

int __wrap_getsockname(int fd, struct sockaddr *addr, socklen_t *len) {
    int vfd = vfd_of(fd);
    if (vfd < 0) return __real_getsockname(fd, addr, len);
    switch (tsnet_vfd_kind(vfd)) {
    case TSNET_BK_UNBOUND: {
        tsnet_addr a;
        if (!tsnet_vfd_bound_addr(vfd, &a)) {
            memset(&a, 0, sizeof(a));
            a.family = tsnet_vfd_domain(vfd) == AF_INET6 ? 6 : 4;
        }
        *len = from_tsnet_addr(&a, addr, *len);
        return 0;
    }
    case TSNET_BK_LWIP: {
        tsnet_addr a;
        if (tsnet_lwip_adapter_getsockname(tsnet_vfd_backend_fd(vfd), &a) < 0)
            return -1;
        *len = from_tsnet_addr(&a, addr, *len);
        return 0;
    }
    case TSNET_BK_REAL:
    default:
        return __real_getsockname(tsnet_vfd_backend_fd(vfd), addr, len);
    }
}

int __wrap_getpeername(int fd, struct sockaddr *addr, socklen_t *len) {
    int vfd = vfd_of(fd);
    if (vfd < 0) return __real_getpeername(fd, addr, len);
    switch (tsnet_vfd_kind(vfd)) {
    case TSNET_BK_UNBOUND:
        errno = ENOTCONN;
        return -1;
    case TSNET_BK_LWIP: {
        tsnet_addr a;
        if (tsnet_lwip_adapter_getpeername(tsnet_vfd_backend_fd(vfd), &a) < 0)
            return -1;
        *len = from_tsnet_addr(&a, addr, *len);
        return 0;
    }
    case TSNET_BK_REAL:
    default:
        return __real_getpeername(tsnet_vfd_backend_fd(vfd), addr, len);
    }
}

int __wrap_shutdown(int fd, int how) {
    int vfd = vfd_of(fd);
    if (vfd < 0) return __real_shutdown(fd, how);
    if (tsnet_vfd_kind(vfd) == TSNET_BK_UNBOUND) {
        errno = ENOTCONN;
        return -1;
    }
    int bfd = tsnet_vfd_backend_fd(vfd);
    if (tsnet_vfd_kind(vfd) == TSNET_BK_LWIP) {
        int h = how == SHUT_RD ? TSNET_SHUT_RD
                : how == SHUT_WR ? TSNET_SHUT_WR
                                 : TSNET_SHUT_RDWR;
        return tsnet_lwip_adapter_shutdown(bfd, h);
    }
    return __real_shutdown(bfd, how);
}

int __wrap_ioctl(int fd, int request, ...) {
    va_list ap;
    va_start(ap, request);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    int vfd = vfd_of(fd);
    if (vfd < 0) return __real_ioctl(fd, request, arg);
    if (request == FIONBIO) {
        int nb = arg ? *(int *)arg : 0;
        int rc = tsnet_vfd_set_nonblock(vfd, nb != 0);
        if (rc != TSNET_OK) {
            errno = tsnet_err_to_errno(rc);
            return -1;
        }
        return 0;
    }
    if (tsnet_vfd_kind(vfd) == TSNET_BK_REAL)
        return __real_ioctl(tsnet_vfd_backend_fd(vfd), request, arg);
    /* other ioctls on tunnel sockets: best effort */
    TSNET_LOGD("shim: ioctl 0x%x on tunnel fd ignored", (unsigned)request);
    return 0;
}

int __wrap_fcntl(int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    int arg = va_arg(ap, int);
    va_end(ap);
    int vfd = vfd_of(fd);
    if (vfd < 0) return __real_fcntl(fd, cmd, arg);
    if (cmd == F_GETFL)
        return tsnet_vfd_nonblock(vfd) ? O_NONBLOCK : 0;
    if (cmd == F_SETFL) {
        int rc = tsnet_vfd_set_nonblock(vfd, (arg & O_NONBLOCK) != 0);
        if (rc != TSNET_OK) {
            errno = tsnet_err_to_errno(rc);
            return -1;
        }
        return 0;
    }
    errno = EINVAL;
    return -1;
}

/* ---- poll / select ------------------------------------------------------- */

int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    if (!g_active) return __real_poll(fds, nfds, timeout);
    if (nfds > 64) {
        errno = EINVAL;
        return -1;
    }
    bool any_ours = false;
    for (nfds_t i = 0; i < nfds; i++) {
        if (vfd_of(fds[i].fd) >= 0) {
            any_ours = true;
            break;
        }
    }
    if (!any_ours) return __real_poll(fds, nfds, timeout);

    tsnet_mpent ents[64];
    for (nfds_t i = 0; i < nfds; i++) {
        int vfd = vfd_of(fds[i].fd);
        if (vfd >= 0) {
            int rc = tsnet_vfd_require_default(vfd);
            if (rc != TSNET_OK) {
                errno = tsnet_err_to_errno(rc);
                return -1;
            }
            ents[i].is_lwip = tsnet_vfd_kind(vfd) == TSNET_BK_LWIP;
            ents[i].fd = tsnet_vfd_backend_fd(vfd);
        } else {
            ents[i].is_lwip = 0;
            ents[i].fd = fds[i].fd;
        }
        ents[i].events = platform_pollev_to_neutral(fds[i].events);
        ents[i].revents = 0;
    }
    int rc = tsnet_mixed_poll(ents, (int)nfds, timeout);
    if (rc < 0) {
        errno = tsnet_err_to_errno(rc);
        return -1;
    }
    for (nfds_t i = 0; i < nfds; i++)
        fds[i].revents = neutral_pollev_to_platform(ents[i].revents);
    return rc;
}

int __wrap_select(int nfds, fd_set *rfds, fd_set *wfds, fd_set *efds,
                  struct timeval *timeout) {
    if (!g_active) return __real_select(nfds, rfds, wfds, efds, timeout);
    bool any_ours = false;
    for (int i = 0; i < nfds; i++) {
        if (((rfds && FD_ISSET(i, rfds)) || (wfds && FD_ISSET(i, wfds)) ||
             (efds && FD_ISSET(i, efds))) &&
            vfd_of(i) >= 0) {
            any_ours = true;
            break;
        }
    }
    if (!any_ours) return __real_select(nfds, rfds, wfds, efds, timeout);

    /* convert to poll (mirrors libnx's own select-over-poll) */
    struct pollfd pfds[64];
    int n = 0;
    for (int i = 0; i < nfds && n < 64; i++) {
        short ev = 0;
        if (rfds && FD_ISSET(i, rfds)) ev |= POLLIN;
        if (wfds && FD_ISSET(i, wfds)) ev |= POLLOUT;
        if (efds && FD_ISSET(i, efds)) ev |= POLLPRI;
        if (!ev) continue;
        pfds[n].fd = i;
        pfds[n].events = ev;
        pfds[n].revents = 0;
        n++;
    }
    int tmo = -1;
    if (timeout)
        tmo = (int)(timeout->tv_sec * 1000 + timeout->tv_usec / 1000);
    int rc = __wrap_poll(pfds, (nfds_t)n, tmo);
    if (rc < 0) return rc;
    if (rfds) FD_ZERO(rfds);
    if (wfds) FD_ZERO(wfds);
    if (efds) FD_ZERO(efds);
    int count = 0;
    for (int i = 0; i < n; i++) {
        if (pfds[i].revents & (POLLIN | POLLERR | POLLHUP)) {
            if (rfds) {
                FD_SET(pfds[i].fd, rfds);
                count++;
            }
        }
        if (pfds[i].revents & POLLOUT) {
            if (wfds) {
                FD_SET(pfds[i].fd, wfds);
                count++;
            }
        }
        if (pfds[i].revents & POLLPRI) {
            if (efds) {
                FD_SET(pfds[i].fd, efds);
                count++;
            }
        }
    }
    return count;
}

/* ---- name resolution ------------------------------------------------------
 * Names present in the netmap resolve locally (MagicDNS); everything else
 * goes to the real resolver. Our addrinfo results are tracked so that
 * __wrap_freeaddrinfo releases the right allocator. */

/* Our MagicDNS addrinfo chains are tagged so __wrap_freeaddrinfo can tell
 * them apart from the real resolver's (they use a single-calloc-per-node
 * layout with an embedded sockaddr that the platform freeaddrinfo must not
 * touch). A per-chain tag in the first node's ai_flags avoids a fixed-size
 * tracking table entirely — no "table full -> untracked chain" hazard. */
#define GAI_OURS_MAGIC 0x7473 /* 'ts' — set in head->ai_flags */

int __wrap_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints, struct addrinfo **res) {
    if (g_active && node) {
        tsnet_addr addrs[2];
        int n = tsnet_registry_resolve(node, addrs, 2);
        if (n > 0) {
            uint16_t port = 0;
            if (service) port = (uint16_t)strtoul(service, NULL, 10);
            int socktype = hints ? hints->ai_socktype : 0;
            struct addrinfo *head = NULL, **tail = &head;
            for (int i = 0; i < n; i++) {
                if (hints && hints->ai_family == AF_INET &&
                    addrs[i].family != 4)
                    continue;
                if (hints && hints->ai_family == AF_INET6 &&
                    addrs[i].family != 6)
                    continue;
                struct addrinfo *ai =
                    calloc(1, sizeof(*ai) + sizeof(struct sockaddr_in6));
                if (!ai) break;
                ai->ai_family = addrs[i].family == 4 ? AF_INET : AF_INET6;
                ai->ai_socktype = socktype ? socktype : SOCK_STREAM;
                ai->ai_addr = (struct sockaddr *)(ai + 1);
                tsnet_addr a = addrs[i];
                a.port = port;
                ai->ai_addrlen = from_tsnet_addr(
                    &a, ai->ai_addr, sizeof(struct sockaddr_in6));
                *tail = ai;
                tail = &ai->ai_next;
            }
            if (head) {
                head->ai_flags = GAI_OURS_MAGIC; /* tag the chain as ours */
                *res = head;
                return 0;
            }
        }
    }
    return __real_getaddrinfo(node, service, hints, res);
}

void __wrap_freeaddrinfo(struct addrinfo *ai) {
    if (!ai) return;
    if (ai->ai_flags == GAI_OURS_MAGIC) {
        /* our single-calloc-per-node chain: free each node directly */
        while (ai) {
            struct addrinfo *next = ai->ai_next;
            free(ai);
            ai = next;
        }
        return;
    }
    __real_freeaddrinfo(ai);
}

struct hostent *__wrap_gethostbyname(const char *name) {
    if (g_active && name) {
        tsnet_addr addrs[2];
        int n = tsnet_registry_resolve(name, addrs, 2);
        for (int i = 0; i < n; i++) {
            if (addrs[i].family != 4) continue;
            static __thread struct hostent he;
            static __thread char hname[128];
            static __thread struct in_addr haddr;
            static __thread char *addr_list[2];
            strncpy(hname, name, sizeof(hname) - 1);
            hname[sizeof(hname) - 1] = '\0';
            memcpy(&haddr, addrs[i].ip, 4);
            addr_list[0] = (char *)&haddr;
            addr_list[1] = NULL;
            he.h_name = hname;
            he.h_aliases = NULL;
            he.h_addrtype = AF_INET;
            he.h_length = 4;
            he.h_addr_list = addr_list;
            return &he;
        }
    }
    return __real_gethostbyname(name);
}
