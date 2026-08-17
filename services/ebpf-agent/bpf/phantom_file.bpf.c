/*
 * phantom_file.bpf.c — CO-RE eBPF program for file_open and file_write event capture.
 *
 * Attaches to appropriate tracepoints/kprobes for open and write
 * syscall families and emits phantom_file_open_event and
 * phantom_file_write_event records to the ring buffer.
 *
 * VERIFY: canonicalized path availability via CO-RE-safe helpers must
 * be confirmed for the target kernel version matrix.
 */
