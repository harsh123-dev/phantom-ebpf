/*
 * phantom_helpers.h — CO-RE helper functions shared across all PHANTOM BPF programs.
 *
 * Minimum kernel: 5.8 (BPF_CORE_READ, bpf_get_current_cgroup_id, ringbuf).
 *
 * # VERIFY: bpf_probe_read_kernel_str is available on 5.8+.
 *           On older kernels (pre-5.5) bpf_probe_read_str must be used.
 *           The CO-RE libbpf shim handles this transparently when the
 *           BPF object is compiled with clang 12+ and libbpf 0.4+.
 *
 * # VERIFY: task_struct.start_time field name — some vendor kernels rename
 *           this to start_boottime. BPF_CORE_READ_OR_ZERO is used to
 *           return 0 rather than a garbage value when the CO-RE relocation
 *           fails to find the field in the running kernel's BTF.
 */

#ifndef PHANTOM_HELPERS_H
#define PHANTOM_HELPERS_H

/* vmlinux.h must be generated via `bpftool btf dump file /sys/kernel/btf/vmlinux
 * format c` and placed in include/. It provides all kernel struct definitions
 * without depending on kernel headers.
 *
 * # VERIFY: vmlinux.h must be regenerated for each target kernel/arch
 *           combination in the CI matrix.
 */
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "phantom_events.h"

/* -------------------------------------------------------------------------
 * phantom_fill_header()
 *
 * Fills a phantom_event_header from the current BPF execution context.
 * Called at the top of every event-collection function.
 *
 * Parameters:
 *   hdr       - pointer to the header to fill (in ring-buffer memory)
 *   evt_type  - one of enum phantom_event_type
 *   total_sz  - sizeof() of the enclosing event struct
 *
 * Design rationale:
 *   pid_start_time_ns: disambiguates PID reuse. We read task->start_time
 *   (nanoseconds since boot) via BPF_CORE_READ. If the field is absent in
 *   a vendor kernel's BTF, BPF_CORE_READ returns 0, which is safe (user
 *   space treats 0 as "not available").
 *
 *   cgroup_id: bpf_get_current_cgroup_id() returns the cgroup v2 ID of
 *   the calling task. The agent uses this as the primary join key to
 *   Kubernetes pod metadata. If cgroup v2 is not mounted, the ID is 0
 *   (treated as unresolvable by the attributor).
 *
 *   event_id_hi / event_id_lo: monotonic counter + cpu form a locally
 *   unique 128-bit ID. Full UUID assignment happens in user space.
 * ------------------------------------------------------------------------- */
static __always_inline void
phantom_fill_header(struct phantom_event_header *hdr,
                    __u16 evt_type,
                    __u32 total_sz)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 pid_tgid           = bpf_get_current_pid_tgid();
    __u64 uid_gid            = bpf_get_current_uid_gid();

    hdr->abi_version        = PHANTOM_ABI_VERSION;
    hdr->event_type         = evt_type;
    hdr->total_size         = total_sz;

    /* event_id: combine monotonic clock + cpu as a locally-unique seed.
     * User space replaces this with a proper UUID before submission. */
    hdr->event_id_hi        = bpf_ktime_get_ns();
    hdr->event_id_lo        = (__u64)bpf_get_smp_processor_id();

    hdr->kernel_timestamp_ns = bpf_ktime_get_ns();
    hdr->cgroup_id          = bpf_get_current_cgroup_id();

    /* # VERIFY: start_time may be named start_boottime on some kernels.
     * BPF_CORE_READ handles field-level relocation transparently when BTF
     * is available; returns 0 if the field cannot be resolved. */
    hdr->pid_start_time_ns  = BPF_CORE_READ(task, start_time);

    hdr->pid                = (__u32)(pid_tgid & 0xFFFFFFFF);
    hdr->tgid               = (__u32)(pid_tgid >> 32);
    hdr->ppid               = (__u32)BPF_CORE_READ(task, real_parent, tgid);
    hdr->uid                = (__u32)(uid_gid & 0xFFFFFFFF);
    hdr->gid                = (__u32)(uid_gid >> 32);
    hdr->cpu                = bpf_get_smp_processor_id();

    bpf_get_current_comm(hdr->comm, sizeof(hdr->comm));
}

/* -------------------------------------------------------------------------
 * phantom_increment_reserve_failure()
 *
 * Atomically increments the per-CPU ring-buffer reserve failure counter
 * for the given category index.
 *
 * Parameters:
 *   map_idx - one of RESERVE_FAIL_* constants from phantom_maps.h
 *
 * Called when bpf_ringbuf_reserve() returns NULL. The counts are read
 * by user space (via phantom_read_reserve_failures()) and reported in
 * phantom_loss_event.ring_buffer_reserve_failures.
 * ------------------------------------------------------------------------- */
#include "phantom_maps.h"

static __always_inline void
phantom_increment_reserve_failure(__u32 map_idx)
{
    __u64 *counter = bpf_map_lookup_elem(&reserve_failures, &map_idx);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

#endif /* PHANTOM_HELPERS_H */
