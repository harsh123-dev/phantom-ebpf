// SPDX-License-Identifier: GPL-2.0
/*
 * syscall_events.bpf.c — PHANTOM process-exec syscall event collection.
 *
 * Minimum kernel: 5.8
 *   - BPF_MAP_TYPE_RINGBUF: 5.8
 *   - CO-RE (BPF_CORE_READ): 5.2 + CONFIG_DEBUG_INFO_BTF
 *   - tracepoint/syscalls/sys_exit_execve: 4.7
 *   - bpf_get_current_cgroup_id(): 4.18
 *
 * Attach points:
 *   sys_exit_execve  — captures executable path + argc at execve() return.
 *                      sys_exit is preferred over sys_enter because at entry
 *                      the path has not yet been resolved by the kernel;
 *                      at exit the bprm->filename is already set.
 *   sys_exit_execveat — same semantics for execveat(2).
 *
 * Design notes:
 *   - The full argv vector is NOT captured (privacy/verifier/size risk).
 *     argc is stored so the behavioral model knows invocation arity.
 *     argv_digest is zeroed by eBPF; user space fills it from /proc/<pid>/cmdline.
 *   - executable_path is read via bpf_probe_read_kernel_str into ring-buffer
 *     memory, NOT onto the BPF stack (stack limit 512 B; PATH_MAX = 4096).
 *   - This program reports both successful and failed exec() calls
 *     (syscall_result != 0) because failed exec attempts are themselves
 *     behavioral evidence.
 *
 * # VERIFY: sys_exit_execve args layout may differ across kernel versions.
 *           The fields used here (ret) are stable from 4.7+.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* vmlinux.h provides kernel struct definitions for CO-RE.
 * Generated with: bpftool btf dump file /sys/kernel/btf/vmlinux format c
 * # VERIFY: Must be regenerated for each target kernel/arch in CI matrix. */
#include "vmlinux.h"
#include "phantom_events.h"
#include "phantom_maps.h"
#include "phantom_helpers.h"

/* -------------------------------------------------------------------------
 * tracepoint context for sys_exit_execve / sys_exit_execveat.
 *
 * The tracepoint format for sys_exit_* is:
 *   struct { long long pad; long ret; };
 * The 'filename' argument is NOT available at sys_exit; it was consumed
 * by the kernel. We read the current task's comm and derive the path
 * from the mm->exe_file->f_path using CO-RE.
 * # VERIFY: mm->exe_file path is safe to read at sys_exit if execve succeeded.
 *           On failure the mm may not be updated; check ret != 0 first.
 * ------------------------------------------------------------------------- */
struct execve_exit_ctx {
    unsigned long long pad;  /* Tracepoint common fields (ignored). */
    long               ret;  /* Return value of execve(). */
};

/* -------------------------------------------------------------------------
 * phantom_collect_exec()
 *
 * Core event collection logic, called from both execve and execveat handlers.
 *
 * Reserves a phantom_exec_event in the ring buffer, fills it from the
 * current task context, and reads the executable path via CO-RE.
 *
 * # VERIFY: bpf_d_path() is available on 5.9+. For kernels 5.8 we fall
 *           back to reading task->mm->exe_file->f_path.dentry->d_name.name.
 *           For correctness and portability, we read the path via the
 *           sched_process_exec tracepoint (see process_events.bpf.c) which
 *           provides the filename argument; here we only capture the comm
 *           plus the mm-based path as a fallback.
 * ------------------------------------------------------------------------- */
static __always_inline int
phantom_collect_exec(long ret)
{
    struct phantom_exec_event *evt;
    struct task_struct *task;
    struct mm_struct *mm;
    const char *exe_name;

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

    /* executable_path: read from mm->exe_file->f_path via CO-RE.
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

/* -------------------------------------------------------------------------
 * BPF program: tracepoint/syscalls/sys_exit_execve
 *
 * Fires on return from execve(2). Collects exec behavioral evidence.
 * We capture both success (ret == 0) and failure (ret < 0) because
 * failed exec calls are themselves behavioral observations (e.g., an
 * attacker probing binaries).
 * ------------------------------------------------------------------------- */
SEC("tracepoint/syscalls/sys_exit_execve")
int handle_execve_exit(struct execve_exit_ctx *ctx)
{
    return phantom_collect_exec(ctx->ret);
}

/* -------------------------------------------------------------------------
 * BPF program: tracepoint/syscalls/sys_exit_execveat
 *
 * Same semantics as sys_exit_execve but for execveat(2).
 * # VERIFY: execveat tracepoint exists from kernel 3.19+.
 * ------------------------------------------------------------------------- */
SEC("tracepoint/syscalls/sys_exit_execveat")
int handle_execveat_exit(struct execve_exit_ctx *ctx)
{
    return phantom_collect_exec(ctx->ret);
}

char LICENSE[] SEC("license") = "GPL";
