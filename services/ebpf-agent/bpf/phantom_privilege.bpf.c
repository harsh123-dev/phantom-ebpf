/*
 * phantom_privilege.bpf.c — CO-RE eBPF program for privilege transition event capture.
 *
 * Monitors set*id / capability / credential change operations and
 * emits phantom_privilege_event records.
 *
 * VERIFY: capability_effective_before/after availability depends on
 * commit_creds context; verify against target kernel BTF.
 */
