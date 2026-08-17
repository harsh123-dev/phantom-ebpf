// SPDX-License-Identifier: GPL-2.0
/*
 * file_events.bpf.c — PHANTOM file open and write event collection.
 *
 * Minimum kernel: 5.8
 *   - BPF_MAP_TYPE_RINGBUF: 5.8
 *   - CO-RE (BPF_CORE_READ): 5.2 + CONFIG_DEBUG_INFO_BTF
 *   - tracepoint/syscalls/sys_exit_openat: 4.7
 *   - tracepoint/syscalls/sys_exit_write: 4.7
 *   - bpf_get_current_cgroup_id(): 4.18
 *
 * Attach points:
 *   sys_exit_openat   — captures file open after kernel resolves path.
 *                       sys_exit used (not sys_enter) because the fd result
 *                       and the resolved path are available only on exit.
 *   sys_exit_openat2  — same semantics for openat2(2) (kernel 5.6+).
 *   sys_exit_write    — captures write descriptor + size evidence.
 *
 * Design notes:
 *   - File content is NEVER captured (security/privacy policy).
 *   - The path is read from the dentry associated with the returned fd.
 *     This requires reading task->files->fdt->fd[n]->f_path via CO-RE.
 *   - File inode and device are read for stable target correlation even
 *     when the pathname changes (e.g., tmpfs rename).
 *   - On write: we only capture fd, requested_bytes, and result_bytes.
 *     The path is looked up from the fd if available. On failure we
 *     leave path empty; this is recorded as missing evidence, not error.
 *
 * # VERIFY: Reading fdtable from BPF via CO-RE is safe on 5.8+ when BTF
 *           includes struct files_struct, fdtable, and file definitions.
 *           Verify that CONFIG_DEBUG_INFO_BTF=y is set in the kernel build.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "vmlinux.h"
#include "phantom_events.h"
#include "phantom_maps.h"
#include "phantom_helpers.h"

/* -------------------------------------------------------------------------
 * Tracepoint context structures.
 *
 * sys_exit_openat args: (long long pad, long fd)
 * sys_exit_write  args: (long long pad, long ret)
 *
 * For sys_enter_openat we would get the filename pointer, but it may be
 * in user-space memory requiring bpf_probe_read_user_str. Instead we
 * attach at sys_exit and read the path from the resolved fd entry.
 * ------------------------------------------------------------------------- */
struct openat_exit_ctx {
    unsigned long long pad;
    long               fd;   /* Returned fd; negative on failure. */
};

struct write_exit_ctx {
    unsigned long long pad;
    long               ret;  /* Bytes written; negative on failure. */
};

/*
 * We need the write() syscall's input args (fd, buf, count). Since we attach
 * at sys_exit we cannot get them from ctx. We use a per-CPU array to stash
 * the fd and count from sys_enter_write and look them up at sys_exit.
 *
 * # VERIFY: Per-CPU stash is safe on multi-core only when enter and exit
 *   of the SAME syscall run on the same CPU. This is guaranteed by the kernel
 *   (a thread cannot migrate across a syscall). The per-CPU key is the CPU id.
 */
struct write_args {
    __u32 fd;
    __u32 requested_bytes;
};

struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct write_args);
} write_args_stash SEC(".maps");

/* -------------------------------------------------------------------------
 * phantom_read_path_from_fd()
 *
 * Reads the path from a file descriptor into dest using CO-RE.
 * Follows task->files->fdt->fd[fd_num]->f_path.dentry->d_name.name.
 *
 * Parameters:
 *   task    - current task pointer
 *   fd_num  - the file descriptor number
 *   dest    - destination buffer in ring-buffer memory
 *   dest_sz - size of dest (should be PHANTOM_PATH_MAX)
 *
 * Returns 0 on success, -1 if any step in the chain fails.
 *
 * # VERIFY: The fdtable pointer chase is safe in the BPF verifier because
 *   each intermediate pointer is checked for NULL before dereferencing via
 *   BPF_CORE_READ (which returns 0 on CO-RE relocation failure) or an
 *   explicit NULL check before bpf_probe_read_kernel_str.
 * ------------------------------------------------------------------------- */
static __always_inline int
phantom_read_path_from_fd(struct task_struct *task,
                          int fd_num,
                          char *dest,
                          __u32 dest_sz)
{
    struct files_struct *files;
    struct fdtable      *fdt;
    struct file         **fd_array;
    struct file         *f;
    struct dentry       *dentry;
    const unsigned char *dname;

    if (fd_num < 0) {
        dest[0] = '\0';
        return -1;
    }

    /* Walk the fd-table chain via CO-RE. Each step may return NULL if
     * the field is not present in the running kernel's BTF. */
    files    = BPF_CORE_READ(task, files);
    if (!files) { dest[0] = '\0'; return -1; }

    fdt      = BPF_CORE_READ(files, fdt);
    if (!fdt)  { dest[0] = '\0'; return -1; }

    fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array) { dest[0] = '\0'; return -1; }

    /* Read the file pointer at index fd_num. The cast to unsigned is safe
     * because we already checked fd_num >= 0. */
    bpf_probe_read_kernel(&f, sizeof(f), fd_array + (__u32)fd_num);
    if (!f) { dest[0] = '\0'; return -1; }

    dentry = BPF_CORE_READ(f, f_path.dentry);
    if (!dentry) { dest[0] = '\0'; return -1; }

    dname = BPF_CORE_READ(dentry, d_name.name);
    if (!dname) { dest[0] = '\0'; return -1; }

    bpf_probe_read_kernel_str(dest, dest_sz, dname);
    return 0;
}

/* -------------------------------------------------------------------------
 * BPF program: tracepoint/syscalls/sys_exit_openat
 *
 * Fires on return from openat(2). If the fd is non-negative (success),
 * reads the path from the fd table and emits a phantom_file_open_event.
 * We also emit on failure (fd < 0) to record the open attempt.
 *
 * open_flags and mode are NOT available at sys_exit. They are captured
 * from the sys_enter context via a per-CPU stash (see comment on write_args).
 * For simplicity in this version, flags/mode are set to 0; a future
 * enhancement can use the stash pattern to capture them from sys_enter.
 * ------------------------------------------------------------------------- */
SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct openat_exit_ctx *ctx)
{
    struct phantom_file_open_event *evt;
    struct task_struct *task;

    evt = bpf_ringbuf_reserve(&rb_file_open, sizeof(*evt), 0);
    if (!evt) {
        phantom_increment_reserve_failure(RESERVE_FAIL_FILE_OPEN);
        return 0;
    }

    phantom_fill_header(&evt->header, PHANTOM_EVT_FILE_OPEN, sizeof(*evt));

    evt->fd             = (__s32)ctx->fd;
    evt->open_flags     = 0;   /* Filled by user space from /proc or stash. */
    evt->mode           = 0;   /* Filled by user space. */
    evt->syscall_result = (__u32)ctx->fd;  /* fd < 0 encodes error. */

    task = (struct task_struct *)bpf_get_current_task();
    phantom_read_path_from_fd(task, (int)ctx->fd,
                               evt->path, sizeof(evt->path));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* -------------------------------------------------------------------------
 * BPF program: tracepoint/syscalls/sys_exit_openat2
 *
 * Same semantics for openat2(2) (kernel 5.6+).
 * # VERIFY: sys_exit_openat2 tracepoint exists from kernel 5.6 only.
 *           On 5.8+ this is safe. Disable via feature-detection in loader
 *           if running on an older kernel.
 * ------------------------------------------------------------------------- */
SEC("tracepoint/syscalls/sys_exit_openat2")
int handle_openat2_exit(struct openat_exit_ctx *ctx)
{
    return handle_openat_exit(ctx);
}

/* -------------------------------------------------------------------------
 * BPF program: tracepoint/syscalls/sys_enter_write
 *
 * Stashes the fd and count from sys_enter so they are available at
 * sys_exit. This is required because sys_exit_write only exposes ret.
 * ------------------------------------------------------------------------- */
struct write_enter_ctx {
    unsigned long long pad;
    unsigned int       fd;
    const char        *buf;   /* NOT read — file content is excluded. */
    size_t             count;
};

SEC("tracepoint/syscalls/sys_enter_write")
int handle_write_enter(struct write_enter_ctx *ctx)
{
    __u32 zero = 0;
    struct write_args *stash = bpf_map_lookup_elem(&write_args_stash, &zero);
    if (stash) {
        stash->fd              = ctx->fd;
        stash->requested_bytes = (__u32)ctx->count;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * BPF program: tracepoint/syscalls/sys_exit_write
 *
 * Fires on return from write(2). Retrieves stashed fd/count and reads
 * the file's inode + device for stable correlation.
 *
 * File content is NEVER read (security/privacy policy; spec C.1).
 * ------------------------------------------------------------------------- */
SEC("tracepoint/syscalls/sys_exit_write")
int handle_write_exit(struct write_exit_ctx *ctx)
{
    struct phantom_file_write_event *evt;
    struct task_struct *task;
    struct file *f;
    struct inode *inode;
    __u32 zero = 0;
    struct write_args *stash;
    __u32 fd_num = 0;

    stash = bpf_map_lookup_elem(&write_args_stash, &zero);
    if (stash)
        fd_num = stash->fd;

    evt = bpf_ringbuf_reserve(&rb_file_write, sizeof(*evt), 0);
    if (!evt) {
        phantom_increment_reserve_failure(RESERVE_FAIL_FILE_WRITE);
        return 0;
    }

    phantom_fill_header(&evt->header, PHANTOM_EVT_FILE_WRITE, sizeof(*evt));

    evt->fd             = (__s32)fd_num;
    evt->requested_bytes = stash ? stash->requested_bytes : 0;
    evt->result_bytes   = (__s64)ctx->ret;

    /* Read inode and device from the file struct via CO-RE. */
    task = (struct task_struct *)bpf_get_current_task();

    struct files_struct *files = BPF_CORE_READ(task, files);
    struct fdtable *fdt = files ? BPF_CORE_READ(files, fdt) : NULL;
    struct file **fd_array = fdt ? BPF_CORE_READ(fdt, fd) : NULL;

    if (fd_array) {
        bpf_probe_read_kernel(&f, sizeof(f), fd_array + fd_num);
        if (f) {
            inode = BPF_CORE_READ(f, f_inode);
            if (inode) {
                evt->file_inode        = BPF_CORE_READ(inode, i_ino);
                evt->file_device_major = BPF_CORE_READ(inode, i_rdev) >> 20;
                evt->file_device_minor = BPF_CORE_READ(inode, i_rdev) & 0xFFFFF;
            }
            /* Read path via dentry d_name. */
            struct dentry *dentry = BPF_CORE_READ(f, f_path.dentry);
            if (dentry) {
                const unsigned char *dname = BPF_CORE_READ(dentry, d_name.name);
                if (dname)
                    bpf_probe_read_kernel_str(evt->path,
                                              sizeof(evt->path), dname);
                else
                    evt->path[0] = '\0';
            } else {
                evt->path[0] = '\0';
            }
        } else {
            evt->file_inode = 0;
            evt->file_device_major = 0;
            evt->file_device_minor = 0;
            evt->path[0] = '\0';
        }
    } else {
        evt->file_inode = 0;
        evt->file_device_major = 0;
        evt->file_device_minor = 0;
        evt->path[0] = '\0';
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
