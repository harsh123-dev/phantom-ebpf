/*
 * phantom_exec.bpf.c — CO-RE eBPF program for exec event capture.
 *
 * Attaches to the appropriate tracepoint/kprobe for exec syscall
 * family and emits phantom_exec_event records to the ring buffer.
 *
 * VERIFY: attach point and available context fields must be validated
 * against the supported kernel matrix (>= 5.8) and BTF availability.
 * Do not capture full argv; compute argv_digest in user space only.
 */

/* BPF skeleton headers and CO-RE helpers included at build time. */
