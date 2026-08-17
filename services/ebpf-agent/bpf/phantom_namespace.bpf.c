/*
 * phantom_namespace.bpf.c — CO-RE eBPF program for namespace change event capture.
 *
 * Monitors setns(2), unshare(2), and clone(2) with CLONE_NEW* flags.
 * Emits phantom_namespace_event records with before/after inode identity.
 *
 * VERIFY: namespace inode availability through CO-RE-safe nsproxy reads
 * must be confirmed against the target kernel BTF.
 */
