// SPDX-License-Identifier: GPL-2.0
/*
 * process_events.bpf.c — PHANTOM privilege, namespace, and module-load events.
 *
 * Minimum kernel: 5.8
 *   - BPF_MAP_TYPE_RINGBUF: 5.8
 *   - CO-RE: 5.2 + CONFIG_DEBUG_INFO_BTF
 *   - tracepoint/syscalls/sys_exit_setuid: 4.7
 *   - tracepoint/syscalls/sys_exit_setresuid: 4.7
 *   - tracepoint/syscalls/sys_exit_setns: 4.7
 *   - tracepoint/syscalls/sys_exit_unshare: 4.7
 *   - tracepoint/syscalls/sys_exit_finit_module: 4.7
 *   - tracepoint/syscalls/sys_exit_init_module: 4.7
 *   - tracepoint/syscalls/sys_exit_delete_module: 4.7
 *
 * Design notes:
 *   - Privilege events: we capture UID/GID transitions and capability sets.
 *     The pre-transition values are read from the current task cred at
 *     sys_enter; the post-transition values are read at sys_exit.
 *   - Namespace events: namespace inodes are read from the current task's
 *     nsproxy structure via CO-RE.
 *   - Module events: module_name is read from the finit_module tracepoint
 *     args (kernel string pointer). module_digest is always zeroed in BPF
 *     per the ABI spec; user space may fill it.
 *
 * # VERIFY: task_struct.cred.uid.val / .euid.val: the kuid_t struct has a
 *   .val field; CO-RE resolves this correctly on 5.8+.
 *
 * # VERIFY: task_struct.nsproxy.uts_ns / .mnt_ns / .net_ns etc. are CO-RE
 *   readable on 5.8+. The inode of a namespace is in the ns_common struct
 *   embedded in each namespace struct.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "phantom_events.h"
#include "phantom_maps.h"
#include "phantom_helpers.h"

/* Namespace-type constants matching CLONE_NEW* values from linux/sched.h. */
#define PHANTOM_NS_UTS    0x04000000
#define PHANTOM_NS_IPC    0x08000000
#define PHANTOM_NS_USER   0x10000000
#define PHANTOM_NS_PID    0x20000000
#define PHANTOM_NS_NET    0x40000000
#define PHANTOM_NS_MNT    0x00020000
#define PHANTOM_NS_CGROUP 0x02000000

/* Transition-kind constants for phantom_privilege_event.transition_kind. */
#define TRANSITION_SETUID     1
#define TRANSITION_SETGID     2
#define TRANSITION_SETRESUID  3
#define TRANSITION_SETRESGID  4
#define TRANSITION_CAPSET     5

/* Operation constants for phantom_module_load_event.operation. */
#define MODULE_OP_FINIT   1
#define MODULE_OP_INIT    2
#define MODULE_OP_DELETE  3

/* =========================================================================
 * PRIVILEGE EVENTS
 * ========================================================================= */

/* -------------------------------------------------------------------------
 * Per-CPU stash for pre-transition credential state.
 * Recorded at sys_enter_set*id so we have before/after values at sys_exit.
 * ------------------------------------------------------------------------- */
struct priv_enter_args {
    __u32 prev_uid;
    __u32 prev_gid;
    __u64 cap_before;
};

struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct priv_enter_args);
} priv_args_stash SEC(".maps");

/*
 * Tracepoint context for sys_exit_setuid / sys_exit_setresuid.
 * Only the return value (0=success, -errno=failure) is in the exit context.
 */
struct setid_exit_ctx {
    unsigned long long pad;
    long               ret;
};

/* -------------------------------------------------------------------------
 * phantom_stash_current_cred()
 *
 * Saves the current task's effective UID, GID, and effective capability set
 * into the per-CPU stash. Called from sys_enter handlers.
 * ------------------------------------------------------------------------- */
static __always_inline void phantom_stash_current_cred(void)
{
    __u32 zero = 0;
    struct priv_enter_args *stash = bpf_map_lookup_elem(&priv_args_stash, &zero);
    if (!stash) return;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred  *cred = BPF_CORE_READ(task, cred);
    if (!cred) return;

    stash->prev_uid = BPF_CORE_READ(cred, euid.val);
    stash->prev_gid = BPF_CORE_READ(cred, egid.val);

    /* # VERIFY: kernel_cap_t has .val[2] on 64-bit kernels. We use the
     * first u64 word of the effective capability set as an approximation.
     * CO-RE will resolve this correctly if the BTF includes kernel_cap_t. */
    kernel_cap_t eff = BPF_CORE_READ(cred, cap_effective);
    stash->cap_before = eff.val[0];
}

/* sys_enter_setuid context. */
struct setuid_enter_ctx {
    unsigned long long pad;
    __u64              uid;
};

SEC("tracepoint/syscalls/sys_enter_setuid")
int handle_setuid_enter(struct setuid_enter_ctx *ctx)
{
    phantom_stash_current_cred();
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int handle_setresuid_enter(struct setuid_enter_ctx *ctx)
{
    phantom_stash_current_cred();
    return 0;
}

/* -------------------------------------------------------------------------
 * phantom_emit_privilege_event()
 *
 * Reads the post-transition credential state and emits a privilege event.
 * Uses the pre-transition values from the per-CPU stash.
 *
 * Parameters:
 *   ret             - syscall return value
 *   transition_kind - one of TRANSITION_* constants
 * ------------------------------------------------------------------------- */
static __always_inline int
phantom_emit_privilege_event(long ret, __u32 transition_kind)
{
    struct phantom_privilege_event *evt;
    struct task_struct *task;
    const struct cred  *cred;
    __u32 zero = 0;
    struct priv_enter_args *stash;

    evt = bpf_ringbuf_reserve(&rb_privilege, sizeof(*evt), 0);
    if (!evt) {
        phantom_increment_reserve_failure(RESERVE_FAIL_PRIVILEGE);
        return 0;
    }

    phantom_fill_header(&evt->header, PHANTOM_EVT_PRIVILEGE, sizeof(*evt));

    stash = bpf_map_lookup_elem(&priv_args_stash, &zero);
    evt->previous_uid = stash ? stash->prev_uid : 0;
    evt->previous_gid = stash ? stash->prev_gid : 0;
    evt->capability_effective_before = stash ? stash->cap_before : 0;

    task = (struct task_struct *)bpf_get_current_task();
    cred = BPF_CORE_READ(task, cred);
    if (cred) {
        evt->new_uid = BPF_CORE_READ(cred, euid.val);
        evt->new_gid = BPF_CORE_READ(cred, egid.val);
        kernel_cap_t eff = BPF_CORE_READ(cred, cap_effective);
        evt->capability_effective_after = eff.val[0];
    } else {
        evt->new_uid = 0;
        evt->new_gid = 0;
        evt->capability_effective_after = 0;
    }

    evt->transition_kind = transition_kind;
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setuid")
int handle_setuid_exit(struct setid_exit_ctx *ctx)
{
    return phantom_emit_privilege_event(ctx->ret, TRANSITION_SETUID);
}

SEC("tracepoint/syscalls/sys_exit_setresuid")
int handle_setresuid_exit(struct setid_exit_ctx *ctx)
{
    return phantom_emit_privilege_event(ctx->ret, TRANSITION_SETRESUID);
}

SEC("tracepoint/syscalls/sys_exit_setgid")
int handle_setgid_exit(struct setid_exit_ctx *ctx)
{
    return phantom_emit_privilege_event(ctx->ret, TRANSITION_SETGID);
}

/* =========================================================================
 * NAMESPACE EVENTS
 * ========================================================================= */

struct setns_exit_ctx {
    unsigned long long pad;
    long               ret;
};

/* Per-CPU stash for namespace-type argument (from sys_enter). */
struct ns_enter_args {
    __u32 ns_type;
};

struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct ns_enter_args);
} ns_args_stash SEC(".maps");

struct setns_enter_ctx {
    unsigned long long pad;
    __s32              fd;
    __s32              nstype;
};

SEC("tracepoint/syscalls/sys_enter_setns")
int handle_setns_enter(struct setns_enter_ctx *ctx)
{
    __u32 zero = 0;
    struct ns_enter_args *stash = bpf_map_lookup_elem(&ns_args_stash, &zero);
    if (stash)
        stash->ns_type = (__u32)ctx->nstype;
    return 0;
}

/* -------------------------------------------------------------------------
 * phantom_emit_namespace_event()
 *
 * Reads the current process's namespace inodes for before/after comparison.
 *
 * # VERIFY: Reading nsproxy->uts_ns->ns.inum (ns_common.inum) via CO-RE
 *   is available on 5.8+ when CONFIG_DEBUG_INFO_BTF=y. The ns_common struct
 *   is embedded at offset 0 in each ns struct (uts_namespace, mnt_namespace,
 *   etc.). We only capture one namespace inode as representative evidence
 *   for the behavioral contract; complete namespace state is in user space.
 * ------------------------------------------------------------------------- */
static __always_inline int
phantom_emit_namespace_event(long ret, __u32 operation)
{
    struct phantom_namespace_event *evt;
    struct task_struct *task;
    struct nsproxy *ns;
    __u32 zero = 0;
    struct ns_enter_args *stash;

    evt = bpf_ringbuf_reserve(&rb_namespace, sizeof(*evt), 0);
    if (!evt) {
        phantom_increment_reserve_failure(RESERVE_FAIL_NAMESPACE);
        return 0;
    }

    phantom_fill_header(&evt->header, PHANTOM_EVT_NAMESPACE, sizeof(*evt));

    stash = bpf_map_lookup_elem(&ns_args_stash, &zero);
    evt->namespace_type = stash ? stash->ns_type : 0;
    evt->operation      = operation;
    evt->syscall_result = (__s32)ret;

    /* Read net namespace inode as representative "before" evidence. */
    task = (struct task_struct *)bpf_get_current_task();
    ns   = BPF_CORE_READ(task, nsproxy);
    if (ns) {
        struct net *net_ns = BPF_CORE_READ(ns, net_ns);
        if (net_ns) {
            /* net->ns.inum is the namespace inode. */
            evt->previous_namespace_inode = BPF_CORE_READ(net_ns, ns.inum);
        } else {
            evt->previous_namespace_inode = 0;
        }
    } else {
        evt->previous_namespace_inode = 0;
    }

    /* target_namespace_inode: not directly available at sys_exit without
     * reading the new nsproxy (which may not be installed yet). Set to 0;
     * user space correlates from subsequent events. */
    evt->target_namespace_inode = 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

#define NS_OP_SETNS   1
#define NS_OP_UNSHARE 2

SEC("tracepoint/syscalls/sys_exit_setns")
int handle_setns_exit(struct setns_exit_ctx *ctx)
{
    return phantom_emit_namespace_event(ctx->ret, NS_OP_SETNS);
}

struct unshare_exit_ctx {
    unsigned long long pad;
    long               ret;
};

SEC("tracepoint/syscalls/sys_exit_unshare")
int handle_unshare_exit(struct unshare_exit_ctx *ctx)
{
    return phantom_emit_namespace_event(ctx->ret, NS_OP_UNSHARE);
}

/* =========================================================================
 * MODULE LOAD EVENTS
 * ========================================================================= */

struct finit_module_exit_ctx {
    unsigned long long pad;
    long               ret;
};

/* Per-CPU stash for module filename from sys_enter_finit_module. */
struct module_enter_args {
    char filename[256];
};

struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct module_enter_args);
} module_args_stash SEC(".maps");

struct finit_module_enter_ctx {
    unsigned long long pad;
    __s32              fd;
    const char        *uargs;  /* User-space pointer — read with bpf_probe_read_user_str */
    __s32              flags;
};

SEC("tracepoint/syscalls/sys_enter_finit_module")
int handle_finit_module_enter(struct finit_module_enter_ctx *ctx)
{
    __u32 zero = 0;
    struct module_enter_args *stash = bpf_map_lookup_elem(&module_args_stash, &zero);
    if (stash && ctx->uargs) {
        /* Read the user-space uargs string (module parameter string). */
        bpf_probe_read_user_str(stash->filename, sizeof(stash->filename),
                                ctx->uargs);
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * phantom_emit_module_event()
 *
 * Emits a phantom_module_load_event. module_name is filled from the stash
 * (best-effort; may be empty if the stash was not populated).
 * module_digest is ALWAYS left zeroed per ABI spec:
 *   "never fabricated in BPF; user space resolves it".
 * ------------------------------------------------------------------------- */
static __always_inline int
phantom_emit_module_event(long ret, __u32 operation)
{
    struct phantom_module_load_event *evt;
    __u32 zero = 0;
    struct module_enter_args *stash;

    evt = bpf_ringbuf_reserve(&rb_module, sizeof(*evt), 0);
    if (!evt) {
        phantom_increment_reserve_failure(RESERVE_FAIL_MODULE);
        return 0;
    }

    phantom_fill_header(&evt->header, PHANTOM_EVT_MODULE_LOAD, sizeof(*evt));
    evt->operation      = operation;
    evt->syscall_result = (__s32)ret;

    stash = bpf_map_lookup_elem(&module_args_stash, &zero);
    if (stash)
        __builtin_memcpy(evt->module_name, stash->filename,
                         sizeof(evt->module_name));
    else
        evt->module_name[0] = '\0';

    /* module_digest: zeroed per spec. Never fabricated in BPF. */
    evt->module_digest[0] = '\0';

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_finit_module")
int handle_finit_module_exit(struct finit_module_exit_ctx *ctx)
{
    return phantom_emit_module_event(ctx->ret, MODULE_OP_FINIT);
}

SEC("tracepoint/syscalls/sys_exit_init_module")
int handle_init_module_exit(struct finit_module_exit_ctx *ctx)
{
    return phantom_emit_module_event(ctx->ret, MODULE_OP_INIT);
}

SEC("tracepoint/syscalls/sys_exit_delete_module")
int handle_delete_module_exit(struct finit_module_exit_ctx *ctx)
{
    return phantom_emit_module_event(ctx->ret, MODULE_OP_DELETE);
}

char LICENSE[] SEC("license") = "GPL";
