# Prepares a patched copy of the wireguard-lwip protocol core in the build
# tree, leaving the submodule pristine:
#  - wireguard-platform.h: WIREGUARD_MAX_PEERS 1 -> 32, MAX_SRC_IPS 2 -> 8
#    (the header hardcodes them with no #ifndef guard)
#  - crypto.h is replaced with the libsodium mapping (src/wg/crypto_sodium.h)
#  - wireguard.{c,h}: anti-replay window widened to 2048 bits
# Usage: cmake -DWG_SRC=<extern/wireguard-lwip/src> -DTSNET_WG=<tsnet/src/wg>
#              -DOUT=<gen/wg> -P gen-wg.cmake

foreach (v WG_SRC TSNET_WG OUT)
    if (NOT DEFINED ${v})
        message(FATAL_ERROR "gen-wg: missing -D${v}")
    endif ()
endforeach ()

file(MAKE_DIRECTORY "${OUT}")

file(READ "${WG_SRC}/wireguard-platform.h" plat)
string(REPLACE "#define WIREGUARD_MAX_PEERS 1"
               "#define WIREGUARD_MAX_PEERS 32" plat "${plat}")
string(REPLACE "#define WIREGUARD_MAX_SRC_IPS 2"
               "#define WIREGUARD_MAX_SRC_IPS 8" plat "${plat}")
file(WRITE "${OUT}/wireguard-platform.h" "${plat}")

# Anti-replay window: upstream's 32-bit RFC 2401 bitmap is too small for
# reordered game-stream traffic, especially when a session migrates between
# DERP and a direct path. Widen it to a 2048-bit sliding window: replay_bitmap
# becomes uint64_t[32] and the scalar bit ops become multi-word ones.
# sizeof()*CHAR_BIT keeps ReplayWindowSize (=2048) and every "diff < window"
# guard correct; diff stays < 2048 so it fits uint32_t.
file(READ "${WG_SRC}/wireguard.h" wgh)
string(REPLACE "uint32_t replay_bitmap;"
               "uint64_t replay_bitmap[32]; /* tsnet: 2048-bit anti-replay window */"
               wgh "${wgh}")
file(WRITE "${OUT}/wireguard.h" "${wgh}")

file(READ "${WG_SRC}/wireguard.c" wgc)
# new-larger counter: shift the whole window left by diff bits (word/bit split;
# iterate high->low so each write reads only not-yet-written lower words)
string(REPLACE "keypair->replay_bitmap <<= diff;"
               "{ size_t _ws = diff / 64, _bs = diff % 64, _n = sizeof(keypair->replay_bitmap) / sizeof(keypair->replay_bitmap[0]); for (size_t _i = _n; _i-- > 0; ) { uint64_t _v = 0; if (_i >= _ws) { _v = keypair->replay_bitmap[_i - _ws] << _bs; if (_bs && _i > _ws) _v |= keypair->replay_bitmap[_i - _ws - 1] >> (64 - _bs); } keypair->replay_bitmap[_i] = _v; } }"
               wgc "${wgc}")
string(REPLACE "keypair->replay_bitmap |= 1;"
               "keypair->replay_bitmap[0] |= 1;"
               wgc "${wgc}")
# counter jumped past the whole window: clear it, then mark bit 0
string(REPLACE "keypair->replay_bitmap = 1;"
               "{ memset(keypair->replay_bitmap, 0, sizeof(keypair->replay_bitmap)); keypair->replay_bitmap[0] = 1; }"
               wgc "${wgc}")
# in-window duplicate test / mark: index the right word and bit
string(REPLACE "keypair->replay_bitmap & ((uint32_t)1 << diff)"
               "(keypair->replay_bitmap[diff / 64] & ((uint64_t)1 << (diff % 64)))"
               wgc "${wgc}")
string(REPLACE "keypair->replay_bitmap |= ((uint32_t)1 << diff);"
               "keypair->replay_bitmap[diff / 64] |= ((uint64_t)1 << (diff % 64));"
               wgc "${wgc}")
# session key init: an array can't be assigned 0
string(REPLACE "new_keypair.replay_bitmap = 0;"
               "memset(new_keypair.replay_bitmap, 0, sizeof(new_keypair.replay_bitmap));"
               wgc "${wgc}")
file(WRITE "${OUT}/wireguard.c" "${wgc}")

configure_file("${WG_SRC}/crypto.c" "${OUT}/crypto.c" COPYONLY)
configure_file("${TSNET_WG}/crypto_sodium.h" "${OUT}/crypto.h" COPYONLY)

message(STATUS "gen-wg: patched wireguard core in ${OUT}")
