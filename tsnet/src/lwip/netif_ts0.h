#ifndef TSNET_NETIF_TS0_H
#define TSNET_NETIF_TS0_H

/* The "ts0" lwIP network interface: carries the node's tailnet addresses
 * (from Node.Addresses in the netmap), MTU 1280. Outgoing IP packets are
 * handed to a transport callback (tsnet_wgif encrypts them and magicsock
 * sends them); packets addressed to ts0 itself loop back inside lwIP
 * (LWIP_NETIF_LOOPBACK).
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TSNET_TS0_MTU 1280

/* Outgoing-packet callback. buf/len is a full IPv4/IPv6 packet.
 * Runs on the tcpip thread: must not block. */
typedef void (*tsnet_ts0_output_fn)(const uint8_t *buf, uint16_t len,
                                    void *ctx);

/* Start the lwIP stack (tcpip thread). Idempotent, thread-safe. */
int tsnet_lwip_start(void);

/* Stop and join the tcpip thread. lwIP cannot be restarted afterwards: call
 * only at process exit, after tsnet_stop(). */
void tsnet_lwip_shutdown(void);

/* Bring up ts0 with an IPv4 address "a.b.c.d/prefix" and optionally an
 * IPv6 address "hex:.../prefix" (NULL to skip). output may be NULL while
 * there is no data plane yet (packets to non-local destinations are
 * dropped with ERR_RTE). Replaces the previous configuration if called
 * again. */
int tsnet_ts0_up(const char *ip4_cidr, const char *ip6_cidr,
                 tsnet_ts0_output_fn output, void *ctx);

/* Inject an incoming IP packet (decrypted tunnel payload) into ts0. */
int tsnet_ts0_input(const uint8_t *buf, uint16_t len);

int tsnet_ts0_down(void);

#ifdef __cplusplus
}
#endif

#endif
