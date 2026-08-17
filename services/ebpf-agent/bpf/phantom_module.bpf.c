/*
 * phantom_module.bpf.c — CO-RE eBPF program for kernel module load event capture.
 *
 * Monitors finit_module(2), init_module(2), and delete_module(2).
 * Emits phantom_module_load_event records.
 * module_digest is resolved in user space only; never fabricated in BPF.
 *
 * VERIFY: module_name availability through CO-RE-safe helpers must be
 * confirmed; emit empty string rather than fabricating a name.
 */
