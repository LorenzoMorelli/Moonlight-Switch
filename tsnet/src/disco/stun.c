#include "stun.h"

#include <string.h>

/* stun.go */
static const uint8_t MAGIC_COOKIE[4] = {0x21, 0x12, 0xa4, 0x42};
static const char SOFTWARE[] = "tailnode"; /* 8 bytes, no padding */
#define ATTR_MAPPED 0x0001
#define ATTR_XOR_MAPPED 0x0020
#define ATTR_XOR_MAPPED_ALT 0x8020
#define ATTR_SOFTWARE 0x8022
#define ATTR_FINGERPRINT 0x8028
#define STUN_HEADER_LEN 20

/* CRC-32 (IEEE 802.3, reflected 0xEDB88320) as used by Go crc32.ChecksumIEEE */
static uint32_t crc32_ieee(const uint8_t *p, size_t n) {
    static uint32_t table[256];
    static int init;
    if (!init) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        init = 1;
    }
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) c = table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

static void put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

int tsnet_stun_request(const uint8_t txid[TSNET_STUN_TXID_LEN], uint8_t *out,
                       size_t cap) {
    /* stun.go: header + SOFTWARE("tailnode") + FINGERPRINT */
    const size_t len_attr_sw = 4 + sizeof(SOFTWARE) - 1; /* 12 */
    const size_t len_fp = 8;
    const size_t total = STUN_HEADER_LEN + len_attr_sw + len_fp; /* 40 */
    if (cap < total) return -1;
    uint8_t *b = out;
    b[0] = 0x00;
    b[1] = 0x01; /* binding request */
    put16(b + 2, (uint16_t)(len_attr_sw + len_fp));
    memcpy(b + 4, MAGIC_COOKIE, 4);
    memcpy(b + 8, txid, 12);
    put16(b + 20, ATTR_SOFTWARE);
    put16(b + 22, sizeof(SOFTWARE) - 1);
    memcpy(b + 24, SOFTWARE, sizeof(SOFTWARE) - 1);
    /* fingerprint = crc32(everything so far) ^ 0x5354554e (stun.go) */
    uint32_t fp = crc32_ieee(b, total - len_fp) ^ 0x5354554e;
    put16(b + 32, ATTR_FINGERPRINT);
    put16(b + 34, 4);
    b[36] = (uint8_t)(fp >> 24);
    b[37] = (uint8_t)(fp >> 16);
    b[38] = (uint8_t)(fp >> 8);
    b[39] = (uint8_t)fp;
    return (int)total;
}

int tsnet_stun_is(const uint8_t *b, size_t len) {
    /* stun.go Is(): len >= 20, top two bits of byte 0 clear, and the magic
     * cookie at [4:8]. The top-two-bits check keeps a WireGuard/disco packet
     * whose first byte has bit 7 set from being misclassified as STUN. */
    return len >= STUN_HEADER_LEN && (b[0] & 0xc0) == 0 &&
           memcmp(b + 4, MAGIC_COOKIE, 4) == 0;
}

int tsnet_stun_parse_response(const uint8_t *b, size_t len,
                              uint8_t txid[TSNET_STUN_TXID_LEN],
                              tsnet_addr *mapped) {
    /* stun.go */
    if (!tsnet_stun_is(b, len)) return -1;
    memcpy(txid, b + 8, 12);
    if (b[0] != 0x01 || b[1] != 0x01) return -1; /* not binding success */
    size_t attrs_len = (size_t)(b[2] << 8 | b[3]);
    if (attrs_len > len - STUN_HEADER_LEN) return -1;

    const uint8_t *a = b + STUN_HEADER_LEN;
    size_t rem = attrs_len;
    int have = 0, have_fallback = 0;
    tsnet_addr fallback;
    memset(&fallback, 0, sizeof(fallback));
    while (rem >= 4) {
        uint16_t type = (uint16_t)(a[0] << 8 | a[1]);
        size_t alen = (size_t)(a[2] << 8 | a[3]);
        size_t padded = (alen + 3) & ~(size_t)3;
        a += 4;
        rem -= 4;
        if (padded > rem) return -1;
        if ((type == ATTR_XOR_MAPPED || type == ATTR_XOR_MAPPED_ALT ||
             type == ATTR_MAPPED) &&
            alen >= 8) {
            uint8_t fam = a[1];
            int xored = type != ATTR_MAPPED;
            tsnet_addr out;
            memset(&out, 0, sizeof(out));
            uint16_t port = (uint16_t)(a[2] << 8 | a[3]);
            if (xored) port ^= 0x2112;
            out.port = port;
            if (fam == 1 && alen == 8) {
                out.family = 4;
                for (int i = 0; i < 4; i++)
                    out.ip[i] =
                        xored ? (uint8_t)(a[4 + i] ^ MAGIC_COOKIE[i]) : a[4 + i];
            } else if (fam == 2 && alen == 20) {
                out.family = 6;
                for (int i = 0; i < 16; i++) {
                    uint8_t x = a[4 + i];
                    if (xored)
                        x ^= i < 4 ? MAGIC_COOKIE[i] : txid[i - 4];
                    out.ip[i] = x;
                }
                /* dual-stack servers answer with a v4-mapped v6: unmap
                 * (Go netip .Unmap() semantics) */
                static const uint8_t v4map[12] = {0, 0, 0, 0, 0, 0,
                                                  0, 0, 0, 0, 0xff, 0xff};
                if (memcmp(out.ip, v4map, 12) == 0) {
                    uint8_t v4[4];
                    memcpy(v4, out.ip + 12, 4);
                    memset(out.ip, 0, 16);
                    memcpy(out.ip, v4, 4);
                    out.family = 4;
                }
            } else {
                out.family = 0;
            }
            if (out.family) {
                if (xored) {
                    *mapped = out;
                    have = 1;
                } else if (!have_fallback) {
                    fallback = out;
                    have_fallback = 1;
                }
            }
        }
        a += padded;
        rem -= padded;
    }
    if (have) return 0;
    if (have_fallback) {
        *mapped = fallback;
        return 0;
    }
    return -1;
}
