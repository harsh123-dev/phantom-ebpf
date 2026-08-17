// SPDX-License-Identifier: GPL-2.0
/*
 * network_events.bpf.c — PHANTOM TCP/UDP connect and accept event collection.
 *
 * Minimum kernel: 5.8
 *   - BPF_MAP_TYPE_RINGBUF: 5.8
 *   - CO-RE: 5.2 + CONFIG_DEBUG_INFO_BTF
 *   - tracepoint/sock/inet_sock_set_state: 4.16
 *   - bpf_get_current_cgroup_id(): 4.18
 *
 * Attach point:
 *   tracepoint/sock/inet_sock_set_state
 *     Fires on every TCP state transition. We filter for:
 *       BPF_TCP_SYN_SENT    (TCP_SYN_SENT)   → outbound connect initiated
 *       BPF_TCP_ESTABLISHED (TCP_ESTABLISHED) → connect completed or accept
 *       BPF_TCP_CLOSE                         → connection termination
 *
 *   For UDP, we attach to sys_exit_sendto / sys_exit_recvfrom to capture
 *   the destination/source address at the first send/recv.
 *
 * Design notes:
 *   - AF_INET and AF_INET6 are supported; other families are silently dropped.
 *   - IPv4 addresses are stored in IPv4-mapped IPv6 form (::ffff:x.x.x.x)
 *     so that local_address[16] and remote_address[16] have a uniform ABI.
 *   - local_port and remote_port are stored in host byte order per the ABI spec.
 *   - The direction field distinguishes connect (1) from accept (2) by inspecting
 *     the state transition direction.
 *
 * # VERIFY: inet_sock_set_state tracepoint args layout (oldstate, newstate,
 *   sport, dport, saddr, daddr, saddr_v6, daddr_v6, family, protocol, type)
 *   is stable from 4.16 on x86_64 and arm64.
 *   sport/dport are in NETWORK byte order in the tracepoint args.
 *   We convert to host order with __builtin_bswap16.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "vmlinux.h"
#include "phantom_events.h"
#include "phantom_maps.h"
#include "phantom_helpers.h"

/* TCP state constants (from include/net/tcp_states.h). */
#define BPF_TCP_ESTABLISHED  1
#define BPF_TCP_SYN_SENT     2
#define BPF_TCP_SYN_RECV     3
#define BPF_TCP_LISTEN       10

/* Address family constants. */
#define AF_INET   2
#define AF_INET6  10

/* Protocol constants. */
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* Direction constants (per phantom_network_event ABI). */
#define DIRECTION_CONNECT  1
#define DIRECTION_ACCEPT   2

/* -------------------------------------------------------------------------
 * inet_sock_set_state tracepoint context.
 *
 * Layout from kernel trace event definition:
 *   __field(__u16, sport)         network byte order
 *   __field(__u16, dport)         network byte order
 *   __field(__u8,  saddr[4])      IPv4 source address
 *   __field(__u8,  daddr[4])      IPv4 destination address
 *   __field(__u8,  saddr_v6[16])  IPv6 source address
 *   __field(__u8,  daddr_v6[16])  IPv6 destination address
 *   __field(__u16, family)
 *   __field(__u8,  protocol)
 *   __field(__u8,  type)          socket type
 *   __field(int,   oldstate)
 *   __field(int,   newstate)
 *
 * # VERIFY: The exact struct layout may include padding. Using
 *   TP_PROTO and TP_STRUCT for field access is safer than raw offset;
 *   the kernel generates the tracepoint format file at /sys/kernel/debug/
 *   tracing/events/sock/inet_sock_set_state/format.
 * ------------------------------------------------------------------------- */
struct inet_sock_set_state_ctx {
    unsigned long long pad;     /* Common tracepoint header. */
    const void        *skaddr;  /* Opaque socket address (not dereferenced). */
    int                oldstate;
    int                newstate;
    __u16              sport;   /* Source port, network byte order. */
    __u16              dport;   /* Destination port, network byte order. */
    __u16              family;
    __u16              protocol;
    __u8               saddr[4];
    __u8               daddr[4];
    __u8               saddr_v6[16];
    __u8               daddr_v6[16];
};

/* -------------------------------------------------------------------------
 * phantom_fill_ipv4_mapped()
 *
 * Fills a 16-byte IPv4-mapped IPv6 address buffer from a 4-byte IPv4 address.
 * Format: ::ffff:x.x.x.x (RFC 4291 section 2.5.5.2).
 *
 * Parameters:
 *   dst - 16-byte destination buffer
 *   src - 4-byte IPv4 address (network byte order, written as-is)
 *
 * This ensures the ABI field local_address[16]/remote_address[16] is
 * uniformly 16 bytes for both IPv4 and IPv6.
 * ------------------------------------------------------------------------- */
static __always_inline void
phantom_fill_ipv4_mapped(__u8 *dst, const __u8 *src)
{
    /* Clear first 10 bytes. */
    __builtin_memset(dst, 0, 10);
    /* Bytes 10-11: 0xFF 0xFF (IPv4-mapped marker). */
    dst[10] = 0xFF;
    dst[11] = 0xFF;
    /* Bytes 12-15: IPv4 address. */
    dst[12] = src[0];
    dst[13] = src[1];
    dst[14] = src[2];
    dst[15] = src[3];
}

/* -------------------------------------------------------------------------
 * BPF program: tracepoint/sock/inet_sock_set_state
 *
 * Captures TCP connect and accept events by filtering on state transitions.
 *
 * Connect:  oldstate=TCP_CLOSE → newstate=TCP_SYN_SENT
 * Accept:   oldstate=TCP_SYN_RECV → newstate=TCP_ESTABLISHED
 *           (the server side; client side is TCP_SYN_SENT → ESTABLISHED)
 *
 * We emit one event per meaningful transition to avoid duplicate reporting
 * of the same connection. Only AF_INET and AF_INET6 are processed.
 * ------------------------------------------------------------------------- */
SEC("tracepoint/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct inet_sock_set_state_ctx *ctx)
{
    struct phantom_network_event *evt;
    __u8 direction;
    int  newstate = ctx->newstate;
    int  oldstate = ctx->oldstate;

    /* Filter: only capture connect initiation and accept completion.
     * SYN_SENT = connect initiated by this process.
     * ESTABLISHED from SYN_RECV = accept completed by this process (server). */
    if (newstate == BPF_TCP_SYN_SENT) {
        direction = DIRECTION_CONNECT;
    } else if (newstate == BPF_TCP_ESTABLISHED &&
               oldstate == BPF_TCP_SYN_RECV) {
        direction = DIRECTION_ACCEPT;
    } else {
        return 0;  /* Uninteresting state transition. */
    }

    /* Only process IPv4 and IPv6. */
    if (ctx->family != AF_INET && ctx->family != AF_INET6)
        return 0;

    evt = bpf_ringbuf_reserve(&rb_network, sizeof(*evt), 0);
    if (!evt) {
        phantom_increment_reserve_failure(RESERVE_FAIL_NETWORK);
        return 0;
    }

    phantom_fill_header(&evt->header, PHANTOM_EVT_NET_CONNECT, sizeof(*evt));
    /* Refine event_type based on direction. */
    if (direction == DIRECTION_ACCEPT)
        evt->header.event_type = PHANTOM_EVT_NET_ACCEPT;

    evt->direction     = direction;
    evt->address_family = (__u8)ctx->family;
    evt->protocol      = (__u8)ctx->protocol;
    evt->socket_type   = 0;  /* Not available from this tracepoint. */

    /* Ports: convert network byte order → host byte order. */
    evt->local_port  = bpf_ntohs(ctx->sport);
    evt->remote_port = bpf_ntohs(ctx->dport);

    /* Addresses: fill 16-byte buffers with IPv4-mapped or raw IPv6. */
    if (ctx->family == AF_INET) {
        phantom_fill_ipv4_mapped(evt->local_address,  ctx->saddr);
        phantom_fill_ipv4_mapped(evt->remote_address, ctx->daddr);
    } else {
        __builtin_memcpy(evt->local_address,  ctx->saddr_v6, 16);
        __builtin_memcpy(evt->remote_address, ctx->daddr_v6, 16);
    }

    evt->syscall_result = 0;  /* Not available from this tracepoint. */

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
