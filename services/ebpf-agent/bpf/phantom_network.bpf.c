/*
 * phantom_network.bpf.c — CO-RE eBPF program for network connect/accept event capture.
 *
 * Attaches to connect(2) and accept(2) family tracepoints/kprobes.
 * Emits phantom_network_event records with AF_INET/AF_INET6 only;
 * other address families are silently dropped.
 *
 * VERIFY: IPv4-mapped-IPv6 address handling in the 16-byte fixed-width
 * field must be confirmed for AF_INET sockets.
 */
