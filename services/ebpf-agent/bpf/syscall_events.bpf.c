// SPDX-License-Identifier: GPL-2.0
/*
 * syscall_events.bpf.c — PHANTOM process-exec syscall event collection.
 *
 * Minimum kernel: 5.8
 *   - BPF_MAP_TYPE_RINGBUF: 5.8
 *   - CO-RE (BPF_CORE_READ): 5.2 + CONFIG_DEBUG_INFO_BTF
 *   - tracepoint/sched/sched_process_exec: 2.6.28
 *   - bpf_get_current_cgroup_id(): 4.18
 *
 * Attach point:
 *   sched_process_exec — fires after a successful exec has installed the new
 *                        mm. Unlike sys_exit_execve, it is a scheduler event
 *                        tied to the task that actually changed executable.
 *
 * Design notes:
 *   - The full argv vector is NOT captured (privacy/verifier/size risk).
 *     argc is stored so the behavioral model knows invocation arity.
 *     argv_digest is zeroed by eBPF; user space fills it from /proc/<pid>/cmdline.
 *   - executable_path is read via bpf_probe_read_kernel_str into ring-buffer
 *     memory, NOT onto the BPF stack (stack limit 512 B; PATH_MAX = 4096).
 *   - Only successful executable changes are reported. This event describes
 *     the current task after exec; it does not by itself authenticate the
 *     userspace file bytes or prove an SBOM component mapping.
 */

/* vmlinux.h provides kernel struct definitions for CO-RE.
 * Generated with: bpftool btf dump file /sys/kernel/btf/vmlinux format c
 * # VERIFY: Must be regenerated for each target kernel/arch in CI matrix. */
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "phantom_events.h"
#include "phantom_maps.h"
#include "phantom_helpers.h"

/* -------------------------------------------------------------------------
 * Tracepoint context for sched_process_exec is kernel-version specific and
 * not needed here; the current task is the task whose exec just completed.
 * # VERIFY: mm->exe_file is read at sched_process_exec after successful exec.
 * ------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------
 * phantom_collect_exec()
 *
 * Core event collection logic, called from sched_process_exec.
 *
 * Reserves a phantom_exec_event in the ring buffer, fills it from the
 * current task context, and reads the executable path via CO-RE.
 *
 * The dentry name here is only a basename, not a stable file identity. It
 * must not be used alone for SBOM component binding.
 * ------------------------------------------------------------------------- */
static __always_inline int
phantom_collect_exec(void)
{
    struct phantom_exec_event *evt;
    struct task_struct *task;
    struct mm_struct *mm;

    /* Reserve ring-buffer space BEFORE any expensive reads.
     * If reserve fails we count it and bail; the loss metric is updated. */
    evt = bpf_ringbuf_reserve(&rb_exec, sizeof(*evt), 0);
    if (!evt) {
        phantom_increment_reserve_failure(RESERVE_FAIL_EXEC);
        return 0;
    }

    /* Fill the common header. */
    phantom_fill_header(&evt->header, PHANTOM_EVT_EXEC, sizeof(*evt));

    /* parent_tgid: read from real_parent for process-relation contract check. */
    task = (struct task_struct *)bpf_get_current_task();
    evt->parent_tgid = (__u32)BPF_CORE_READ(task, real_parent, tgid);

    /* argc: not available at sys_exit; set to 0. User space fills from
     * /proc/<pid>/cmdline if needed for behavioral modeling. */
    evt->argc       = 0;
    evt->exec_flags = 0;

    /* executable_path: read the current executable's dentry basename via CO-RE.
     * Written directly into ring-buffer memory — NOT the BPF stack —
     * because PHANTOM_PATH_MAX = 4096 exceeds the 512-byte stack limit.
     *
     * # VERIFY: This read chain has several potential null pointers.
     *   Each BPF_CORE_READ step returns 0/NULL on failure; we guard with
     *   an explicit null check before bpf_probe_read_kernel_str. */
    mm = BPF_CORE_READ(task, mm);
    if (mm) {
        struct file *exe_file = BPF_CORE_READ(mm, exe_file);
        if (exe_file) {
            struct dentry *dentry = BPF_CORE_READ(exe_file, f_path.dentry);
            if (dentry) {
                /* d_name.name is a kernel-space pointer; safe to read. */
                const unsigned char *dname = BPF_CORE_READ(dentry, d_name.name);
                if (dname) {
                    bpf_probe_read_kernel_str(evt->executable_path,
                                              sizeof(evt->executable_path),
                                              dname);
                } else {
                    evt->executable_path[0] = '\0';
                }
            } else {
                evt->executable_path[0] = '\0';
            }
        } else {
            evt->executable_path[0] = '\0';
        }
    } else {
        evt->executable_path[0] = '\0';
    }

    /* argv_digest: SHA-256 of bounded argv representation.
     * Cannot be computed in BPF (no crypto helper).
     * Zeroed here; user space must fill from /proc/<pid>/cmdline. */
    evt->argv_digest[0] = '\0';

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* Successful process exec only. Failed exec attempts are not reported as a
 * change in runtime executable state. The task's current mm is authoritative
 * at this tracepoint, while userspace still must validate workload identity. */
SEC("tracepoint/sched/sched_process_exec")
int handle_sched_process_exec(void *ctx)
{
    (void)ctx;
    return phantom_collect_exec();
}

char LICENSE[] SEC("license") = "GPL";
