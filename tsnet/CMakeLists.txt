# libtsnet — embedded Tailscale client (C11), built for Nintendo Switch by
# the root CMakeLists via add_subdirectory().

set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../extern/lwip)
set(WG_LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../extern/wireguard-lwip)
set(TSNET_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen)

# ---- capability version ---------------------------------------------------
# The tailcfg.CurrentCapabilityVersion this client implements
# (tailscale: tailcfg/tailcfg.go). Can be refreshed from a Tailscale checkout
# with -DTSNET_TAILCFG=<path/to/tailcfg.go>.
set(TSNET_CAPABILITY_VERSION 145)
execute_process(COMMAND ${CMAKE_COMMAND}
    -DTAILCFG=${TSNET_TAILCFG}
    -DCAPVER=${TSNET_CAPABILITY_VERSION}
    -DOUT=${TSNET_GEN_DIR}/tsnet_capver.h
    -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/gen-capver.cmake
    COMMAND_ERROR_IS_FATAL ANY)

# ---- WireGuard core (patched copy, cmake/gen-wg.cmake) ---------------------
execute_process(COMMAND ${CMAKE_COMMAND}
    -DWG_SRC=${WG_LWIP_DIR}/src
    -DTSNET_WG=${CMAKE_CURRENT_SOURCE_DIR}/src/wg
    -DOUT=${TSNET_GEN_DIR}/wg
    -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/gen-wg.cmake
    COMMAND_ERROR_IS_FATAL ANY)

# ---- lwIP (extern/lwip) ---------------------------------------------------
# Core + socket API with our lwipopts.h; threading via the pthread-based unix
# port sys_arch, which also works on Horizon (newlib/libnx provide pthread).
include(${LWIP_DIR}/src/Filelists.cmake)
set(TSNET_LWIP_SRC
    ${lwipcore_SRCS}
    ${lwipcore4_SRCS}
    ${lwipcore6_SRCS}
    ${lwipapi_SRCS}
    ${LWIP_DIR}/contrib/ports/unix/port/sys_arch.c
)
# lwIP sources are not -Werror clean. SSIZE_MAX: newlib's limits.h lacks it
# and lwip/debug.h pulls arch.h in before lwipopts.h can supply it.
set_source_files_properties(${TSNET_LWIP_SRC}
    PROPERTIES COMPILE_OPTIONS "-w"
    COMPILE_DEFINITIONS "SSIZE_MAX=__LONG_MAX__")
set_source_files_properties(
    ${TSNET_GEN_DIR}/wg/wireguard.c
    ${TSNET_GEN_DIR}/wg/crypto.c
    ${WG_LWIP_DIR}/src/crypto/refc/blake2s.c
    PROPERTIES COMPILE_OPTIONS "-w")

add_library(tsnet STATIC
    ${TSNET_LWIP_SRC}
    src/lwip/netif_ts0.c
    src/util/hex.c
    src/util/b64.c
    src/util/err.c
    src/util/log.c
    src/util/keyfile.c
    src/util/thread.c
    src/util/url.c
    src/shim/classify.c
    src/shim/fdtable.c
    src/shim/mixedpoll.c
    src/shim/lwip_adapter.c
    src/shim/shim_nx.c
    src/crypto/tscrypto.c
    ${WG_LWIP_DIR}/src/crypto/refc/blake2s.c
    src/control/noise.c
    src/control/cstream.c
    src/control/httpmin.c
    src/control/noisechan.c
    src/control/h2.c
    src/control/netmap.c
    src/control/control.c
    ${TSNET_GEN_DIR}/wg/wireguard.c
    ${TSNET_GEN_DIR}/wg/crypto.c
    src/wg/wg_sodium.c
    src/wg/tsnet_wgif.c
    src/derp/derp_client.c
    src/disco/disco.c
    src/disco/stun.c
    src/magicsock/magicsock.c
    src/tsnet_engine.c
    src/platform/platform_nx.c
)

target_include_directories(tsnet
    PUBLIC include
    PUBLIC ${TSNET_GEN_DIR}                             # tsnet_capver.h
    PUBLIC src/lwip                                     # lwipopts.h
    PUBLIC ${LWIP_DIR}/src/include
    PUBLIC ${LWIP_DIR}/contrib/ports/unix/port/include  # arch/{cc,sys_arch}.h
    PUBLIC $ENV{DEVKITPRO}/portlibs/switch/include
    PRIVATE src
    PRIVATE ${TSNET_GEN_DIR}/wg
    PRIVATE ${WG_LWIP_DIR}/src/crypto/refc
)
target_compile_features(tsnet PUBLIC c_std_11)
target_compile_options(tsnet PRIVATE -Wall -Wextra -Werror)

# nghttp2 has no devkitPro portlib: build the vendored copy (lib only).
set(ENABLE_LIB_ONLY ON CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_DOC OFF CACHE BOOL "" FORCE)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../extern/nghttp2 nghttp2
                 EXCLUDE_FROM_ALL)

# libsodium, mbedtls and jansson come from the devkitPro portlibs
find_package(Threads REQUIRED)
target_link_directories(tsnet PUBLIC $ENV{DEVKITPRO}/portlibs/switch/lib)
target_link_libraries(tsnet PUBLIC
    nghttp2_static sodium mbedtls mbedx509 mbedcrypto jansson Threads::Threads)

# Linker flags for the socket interception; the app adds these to its link
# options so every socket call goes through the shim.
set(TSNET_WRAP_LDFLAGS "")
foreach (sym socket bind connect listen accept
             send sendto sendmsg recv recvfrom recvmsg
             setsockopt getsockopt getsockname getpeername
             shutdown ioctl fcntl select poll
             getaddrinfo freeaddrinfo gethostbyname)
    list(APPEND TSNET_WRAP_LDFLAGS "-Wl,--wrap=${sym}")
endforeach ()
set(TSNET_WRAP_LDFLAGS ${TSNET_WRAP_LDFLAGS} PARENT_SCOPE)
