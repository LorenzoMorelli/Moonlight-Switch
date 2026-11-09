/* lwIP configuration for tsnet.
 *
 * Sized for game streaming: tens of Mbit/s of UDP plus a few TCP control
 * connections through a 1280-byte-MTU WireGuard tunnel. Uses the pthread
 * sys_arch from extern/lwip/contrib/ports/unix/port/sys_arch.c.
 */
#ifndef TSNET_LWIPOPTS_H
#define TSNET_LWIPOPTS_H

/* newlib (devkitA64) provides ssize_t in <sys/types.h> but no SSIZE_MAX in
 * <limits.h>; without it lwip/arch.h would retypedef ssize_t as int. */
#include <limits.h>
#include <sys/types.h>
#ifndef SSIZE_MAX
#define SSIZE_MAX LONG_MAX
#endif

/* ---- system / threading --------------------------------------------- */
#define NO_SYS                      0
#define SYS_LIGHTWEIGHT_PROT        1
#define LWIP_TCPIP_CORE_LOCKING     1
#define LWIP_COMPAT_SOCKETS         0  /* never #define socket -> lwip_socket */
#define LWIP_POSIX_SOCKETS_IO_NAMES 0
#define LWIP_SOCKET_SELECT          1
#define LWIP_SOCKET_POLL            1

#define TCPIP_THREAD_NAME           "tsnet:tcpip"
#define TCPIP_THREAD_STACKSIZE      (64 * 1024)
#define TCPIP_THREAD_PRIO           1
#define TCPIP_MBOX_SIZE             256
#define DEFAULT_THREAD_STACKSIZE    (32 * 1024)
#define DEFAULT_THREAD_PRIO         1

/* ---- protocols ------------------------------------------------------- */
#define LWIP_IPV4                   1
#define LWIP_IPV6                   1
#define LWIP_ND6_NUM_NEIGHBORS      16
#define IPV6_FRAG_COPYHEADER        1  /* required on 64-bit (pointers > 4B) */
#define LWIP_ARP                    0  /* ts0 is a point-to-multipoint IP netif */
#define LWIP_ETHERNET               0
#define LWIP_RAW                    1  /* ICMP ping through the tunnel */
#define LWIP_ICMP                   1
#define LWIP_ICMP6                  1
#define LWIP_DHCP                   0
#define LWIP_AUTOIP                 0
#define LWIP_DNS                    0  /* MagicDNS names resolved from netmap */
#define LWIP_IGMP                   0
#define LWIP_MULTICAST_PING         0
#define LWIP_BROADCAST_PING         0

#define LWIP_NETIF_LOOPBACK         1  /* traffic to own address loops back */
#define LWIP_HAVE_LOOPIF            0
#define LWIP_LOOPBACK_MAX_PBUFS     32
#define LWIP_NETIF_TX_SINGLE_PBUF   1

/* ---- memory ---------------------------------------------------------- */
#define MEM_LIBC_MALLOC             0
#define MEMP_MEM_MALLOC             0
#define MEM_ALIGNMENT               8
#define MEM_SIZE                    (4 * 1024 * 1024)
#define PBUF_POOL_SIZE              512
#define PBUF_POOL_BUFSIZE           1536  /* >= 1280 MTU + headers/align */

#define MEMP_NUM_PBUF               64
#define MEMP_NUM_UDP_PCB            32
#define MEMP_NUM_TCP_PCB            32
#define MEMP_NUM_TCP_PCB_LISTEN     8
#define MEMP_NUM_TCP_SEG            512
#define MEMP_NUM_RAW_PCB            8
#define MEMP_NUM_NETCONN            64
#define MEMP_NUM_NETBUF             64
#define MEMP_NUM_SYS_TIMEOUT        32
#define MEMP_NUM_TCPIP_MSG_API      64
#define MEMP_NUM_TCPIP_MSG_INPKT    128
#define MEMP_NUM_SELECT_CB          32

/* ---- TCP ------------------------------------------------------------- */
/* Tunnel MTU is 1280 (Tailscale default). IPv6 header (40) + TCP (20) => 1220
 * fits both families. */
#define TCP_MSS                     1220
#define LWIP_WND_SCALE              1
#define TCP_RCV_SCALE               4
#define TCP_WND                     (256 * 1024)
#define TCP_SND_BUF                 (128 * 1024)
#define TCP_SND_QUEUELEN            ((4 * TCP_SND_BUF) / TCP_MSS)
/* default (TCP_SND_BUF/2) would trip the u16 sanity check in init.c */
#define TCP_SNDLOWAT                (32 * 1024)
#define TCP_QUEUE_OOSEQ             1
#define LWIP_TCP_SACK_OUT           1
#define LWIP_TCP_KEEPALIVE          1
#define TCP_LISTEN_BACKLOG          1

/* ---- UDP / mboxes ---------------------------------------------------- */
#define LWIP_UDP                    1
#define DEFAULT_UDP_RECVMBOX_SIZE   256
#define DEFAULT_TCP_RECVMBOX_SIZE   128
#define DEFAULT_RAW_RECVMBOX_SIZE   32
#define DEFAULT_ACCEPTMBOX_SIZE     8

/* ---- socket options -------------------------------------------------- */
#define LWIP_SO_RCVTIMEO            1
#define LWIP_SO_SNDTIMEO            1
#define LWIP_SO_RCVBUF              1
#define LWIP_SO_LINGER              1
#define SO_REUSE                    1
#define LWIP_TCP_NODELAY            1  /* moonlight control sockets set it */

/* ---- misc ------------------------------------------------------------ */
#define LWIP_STATS                  0
#define LWIP_NETIF_HOSTNAME         0
#define LWIP_NETIF_STATUS_CALLBACK  1
#define LWIP_NETIF_API              0
#define LWIP_TIMEVAL_PRIVATE        0

#define LWIP_DEBUG                  0

#endif /* TSNET_LWIPOPTS_H */
