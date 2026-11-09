#include "platform.h"

#include "shim/classify.h"

#include <switch.h>

#include <sodium.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

void tsnet_rand_bytes(void *buf, size_t len) {
    /* libnx CSPRNG (services/csrng via runtime), never fails */
    randomGet(buf, len);
}

/* libsodium randombytes implementation backed by libnx's CSPRNG. The stock
 * sysrandom implementation opens /dev/urandom, which does not exist on
 * Horizon, so sodium_init() aborts; registering this before sodium_init()
 * makes libsodium draw entropy from randomGet() instead. Stateless: no stir/
 * close needed, and uniform() falls back to random() inside libsodium. */
static const char *nx_rb_name(void) { return "libnx_csprng"; }

static uint32_t nx_rb_random(void) {
    uint32_t v;
    randomGet(&v, sizeof(v));
    return v;
}

static void nx_rb_buf(void *const buf, const size_t size) {
    randomGet(buf, size);
}

static const randombytes_implementation nx_rb_impl = {
    .implementation_name = nx_rb_name,
    .random = nx_rb_random,
    .stir = NULL,
    .uniform = NULL,
    .buf = nx_rb_buf,
    .close = NULL,
};

void tsnet_plat_crypto_prepare(void) {
    randombytes_set_implementation((randombytes_implementation *)&nx_rb_impl);
}

uint64_t tsnet_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

void tsnet_plat_thread_boost(void) {
    /* Horizon: lower value = higher priority. The app main/UI (render) thread
     * runs at 0x20 (main.cpp); put the tunnel data path a few steps above so a
     * newly-arrived packet — or an outbound input command waiting on the lwIP
     * core lock the tcpip thread holds during rx — is serviced promptly rather
     * than behind the renderer. These threads block on recv/mbox, so a high
     * priority cannot starve anything. */
    svcSetThreadPriority(CUR_THREAD_HANDLE, 0x1C);
}

int64_t tsnet_wall_time(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec;
}

/* ---- real-stack sockets -------------------------------------------------
 * tsnet's own transport (control TLS, DERP, magicsock UDP) MUST use the real
 * libnx BSD stack, never lwIP: these call the __real_* symbols directly so
 * the -Wl,--wrap shim never reclassifies them into the tunnel.
 */
extern int __real_socket(int domain, int type, int protocol);
extern int __real_connect(int fd, const struct sockaddr *addr, socklen_t len);
extern int __real_bind(int fd, const struct sockaddr *addr, socklen_t len);
extern int __real_setsockopt(int fd, int level, int optname, const void *val,
                             socklen_t len);
extern int __real_getsockopt(int fd, int level, int optname, void *val,
                             socklen_t *len);
extern int __real_getsockname(int fd, struct sockaddr *addr, socklen_t *len);
extern int __real_fcntl(int fd, int cmd, ...);
extern ssize_t __real_sendto(int fd, const void *buf, size_t len, int flags,
                             const struct sockaddr *dst, socklen_t dlen);
extern ssize_t __real_recvfrom(int fd, void *buf, size_t len, int flags,
                               struct sockaddr *src, socklen_t *slen);
extern int __real_poll(struct pollfd *fds, nfds_t nfds, int timeout);
extern int __real_getaddrinfo(const char *node, const char *service,
                              const struct addrinfo *hints,
                              struct addrinfo **res);
extern void __real_freeaddrinfo(struct addrinfo *res);
/* read/write/close on a real fd are plain newlib (the shim only wraps the
 * socket-family symbols, and real fds live on the "soc" devoptab) */

static void addr_to_sa4(const tsnet_addr *a, struct sockaddr_in *sa) {
    memset(sa, 0, sizeof(*sa));
    sa->sin_family = AF_INET;
    sa->sin_port = htons(a->port);
    memcpy(&sa->sin_addr, a->ip, 4);
}

/* non-blocking connect + poll(POLLOUT): SO_SNDTIMEO does not bound
 * connect() on the FreeBSD-derived HOS bsd stack */
static int connect_timeout(int fd, const struct sockaddr *addr,
                           socklen_t alen, int timeout_ms) {
    int flags = __real_fcntl(fd, F_GETFL, 0);
    if (flags < 0) flags = 0;
    __real_fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int rc = __real_connect(fd, addr, alen);
    if (rc == 0) {
        __real_fcntl(fd, F_SETFL, flags);
        return 0;
    }
    if (errno != EINPROGRESS) return -1;
    struct pollfd pfd = {.fd = fd, .events = POLLOUT, .revents = 0};
    if (__real_poll(&pfd, 1, timeout_ms) != 1) return -1;
    int soerr = 0;
    socklen_t sl = sizeof(soerr);
    if (__real_getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) < 0 ||
        soerr != 0)
        return -1;
    __real_fcntl(fd, F_SETFL, flags);
    return 0;
}

int tsnet_plat_tcp_dial(const char *host, uint16_t port, int timeout_ms) {
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; /* libnx bsd: IPv4 */
    hints.ai_socktype = SOCK_STREAM;
    if (__real_getaddrinfo(host, portstr, &hints, &res) != 0 || !res)
        return -1;
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = __real_socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect_timeout(fd, ai->ai_addr, ai->ai_addrlen, timeout_ms) == 0) {
            tsnet_plat_sock_set_timeout(fd, timeout_ms);
            break;
        }
        close(fd);
        fd = -1;
    }
    __real_freeaddrinfo(res);
    return fd;
}

ssize_t tsnet_plat_sock_read(int fd, void *buf, size_t n) {
    return read(fd, buf, n);
}
ssize_t tsnet_plat_sock_write(int fd, const void *buf, size_t n) {
    return write(fd, buf, n);
}
int tsnet_plat_sock_close(int fd) { return close(fd); }
int tsnet_plat_sock_shutdown(int fd) { return shutdown(fd, SHUT_RDWR); }

int tsnet_plat_sock_wait_read(int fd, int timeout_ms) {
    struct pollfd pfd = {.fd = fd, .events = POLLIN, .revents = 0};
    int rc = __real_poll(&pfd, 1, timeout_ms);
    return rc < 0 ? -1 : rc;
}

int tsnet_plat_sock_set_timeout(int fd, int timeout_ms) {
    struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    if (__real_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        return -1;
    return __real_setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

int tsnet_plat_udp_open(uint16_t port, uint16_t *bound_port_out) {
    int fd = __real_socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (__real_bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        sa.sin_port = 0;
        if (__real_bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            close(fd);
            return -1;
        }
    }
    /* Large receive buffer: this socket carries all inbound tunnel traffic,
     * including ~10 Mbit/s bursty video on a direct path. The default libnx
     * per-socket UDP buffer (udp_rx_buf_size, 42 KB) overruns on bursts and
     * drops packets below our reader. Best effort — capped by the subsystem's
     * udp_rx_buf_size (raised at app startup when Tailscale is enabled). */
    int rcvbuf = 1 * 1024 * 1024;
    __real_setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    if (bound_port_out) {
        socklen_t sl = sizeof(sa);
        __real_getsockname(fd, (struct sockaddr *)&sa, &sl);
        *bound_port_out = ntohs(sa.sin_port);
    }
    return fd;
}

ssize_t tsnet_plat_udp_sendto(int fd, const void *buf, size_t len,
                              const struct tsnet_addr *dst) {
    if (dst->family != 4) return -1;
    struct sockaddr_in sa;
    addr_to_sa4(dst, &sa);
    return __real_sendto(fd, buf, len, 0, (struct sockaddr *)&sa, sizeof(sa));
}

ssize_t tsnet_plat_udp_recvfrom(int fd, void *buf, size_t cap,
                                struct tsnet_addr *src, int timeout_ms) {
    struct pollfd pfd = {.fd = fd, .events = POLLIN, .revents = 0};
    int pr = __real_poll(&pfd, 1, timeout_ms);
    if (pr <= 0) return pr < 0 ? -1 : 0; /* error / timeout */
    if (!(pfd.revents & POLLIN)) {
        /* POLLERR/POLLHUP: the socket is in an error state (e.g. the network
         * went away on a Wi-Fi change). poll() returns it IMMEDIATELY, so
         * returning here would spin the caller's receive loop at 100% CPU and
         * freeze the console. Pace it by sleeping the poll timeout so the
         * thread idles until the socket recovers or is rebuilt. */
        if (timeout_ms > 0) {
            struct timespec tv = {timeout_ms / 1000,
                                  (long)(timeout_ms % 1000) * 1000000L};
            nanosleep(&tv, NULL);
        }
        return 0;
    }
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    ssize_t n = __real_recvfrom(fd, buf, cap, 0, (struct sockaddr *)&sa, &sl);
    if (n >= 0 && src) {
        memset(src, 0, sizeof(*src));
        src->family = 4;
        memcpy(src->ip, &sa.sin_addr, 4);
        src->port = ntohs(sa.sin_port);
    }
    return n;
}

int tsnet_plat_resolve4(const char *host, struct tsnet_addr *out) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (__real_getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return -1;
    memset(out, 0, sizeof(*out));
    out->family = 4;
    memcpy(out->ip, &((struct sockaddr_in *)res->ai_addr)->sin_addr, 4);
    __real_freeaddrinfo(res);
    return 0;
}

int tsnet_plat_local_ip4(const struct tsnet_addr *dst,
                         struct tsnet_addr *out) {
    int fd = __real_socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in sa;
    addr_to_sa4(dst, &sa);
    if (sa.sin_port == 0) sa.sin_port = htons(443);
    if (__real_connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    socklen_t sl = sizeof(sa);
    __real_getsockname(fd, (struct sockaddr *)&sa, &sl);
    close(fd);
    memset(out, 0, sizeof(*out));
    out->family = 4;
    memcpy(out->ip, &sa.sin_addr, 4);
    return 0;
}
