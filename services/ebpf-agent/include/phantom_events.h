/*
 * phantom_events.h — Formal eBPF ring-buffer event ABI definitions.
 *
 * This header declares all event struct layouts shared between the
 * BPF programs (bpf/) and the user-space loader (cmd/).
 *
 * ABI rules (from handoff doc Part C):
 * - All fields fixed-width and explicitly aligned.
 * - Strings are bounded fixed arrays, NUL-terminated when shorter than capacity.
 * - phantom_event_header appears first in every event struct.
 * - Kernel timestamps use bpf_ktime_get_ns() monotonic time;
 *   user-space must correlate to wall clock.
 * - PATH_MAX is an ABI constant recorded in abi_version; do not
 *   assume it is universally identical across build environments.
 *
 * SECURITY: Full argv, file content, environment variables, DNS names,
 * and plaintext payloads are intentionally EXCLUDED to reduce verifier
 * complexity, event size, credential exposure, and privacy risk.
 */

#ifndef PHANTOM_EVENTS_H
#define PHANTOM_EVENTS_H

#include <linux/types.h>

/* ABI version embedded in every event for decoder compatibility checks. */
#define PHANTOM_ABI_VERSION  1

/* PATH_MAX for this ABI version. Recorded in abi_version.
 * VERIFY: confirm PATH_MAX is consistently 4096 on all target kernel/arch combos. */
#define PHANTOM_PATH_MAX     4096

/* ---- Event type discriminant ----------------------------------------- */

enum phantom_event_type {
	PHANTOM_EVT_EXEC        = 1,
	PHANTOM_EVT_FILE_OPEN   = 2,
	PHANTOM_EVT_FILE_WRITE  = 3,
	PHANTOM_EVT_NET_CONNECT = 4,
	PHANTOM_EVT_NET_ACCEPT  = 5,
	PHANTOM_EVT_PRIVILEGE   = 6,
	PHANTOM_EVT_NAMESPACE   = 7,
	PHANTOM_EVT_MODULE_LOAD = 8,
	PHANTOM_EVT_LOSS        = 9,
};

/* ---- Common event header --------------------------------------------- */

struct phantom_event_header {
	__u16 abi_version;         /* ABI decoder compatibility. */
	__u16 event_type;          /* Discriminant selecting payload struct. */
	__u32 total_size;          /* Defensive user-space record-size validation. */
	__u64 event_id_hi;         /* First half of agent-generated correlation UUID. */
	__u64 event_id_lo;         /* Second half of agent-generated correlation UUID. */
	__u64 kernel_timestamp_ns; /* Monotonic ordering of kernel observations. */
	__u64 cgroup_id;           /* Primary cgroup-to-container identity join key. */
	__u64 pid_start_time_ns;   /* Disambiguates PID reuse when derivable safely. */
	__u32 pid;                 /* Observed thread identifier. */
	__u32 tgid;                /* Process identifier for thread aggregation. */
	__u32 ppid;                /* Parent process correlation. */
	__u32 uid;                 /* Effective user identity evidence. */
	__u32 gid;                 /* Effective group identity evidence. */
	__u32 cpu;                 /* Per-CPU loss and ordering diagnostics. */
	char  comm[16];            /* Kernel task command for rapid triage. */
} __attribute__((packed));

/* ---- Per-event payload structs --------------------------------------- */

struct phantom_exec_event {
	struct phantom_event_header header; /* Required common provenance. */
	__u32 parent_tgid;                  /* Parent process relation validation. */
	__u32 argc;                         /* Invocation shape without full argv capture. */
	__u32 exec_flags;                   /* Exec-specific flags when attach context exposes them. */
	char  executable_path[PHANTOM_PATH_MAX]; /* Contract executable allow-list comparison. */
	char  argv_digest[65];              /* SHA-256 hex digest of bounded argv; limits secret capture. */
} __attribute__((packed));

struct phantom_file_open_event {
	struct phantom_event_header header; /* Required common provenance. */
	__s32 fd;                           /* Result descriptor; negative denotes failure. */
	__u32 open_flags;                   /* Read/write/create intent for contract semantics. */
	__u32 mode;                         /* File creation mode when applicable. */
	__u32 syscall_result;               /* Raw result for success/failure interpretation. */
	char  path[PHANTOM_PATH_MAX];       /* Canonicalized/bounded path when safely available. */
} __attribute__((packed));

struct phantom_file_write_event {
	struct phantom_event_header header; /* Required common provenance. */
	__s32 fd;                           /* Target descriptor relation. */
	__u32 requested_bytes;              /* Requested write size for behavioral rate analysis. */
	__s64 result_bytes;                 /* Actual write result, including failure. */
	__u64 file_inode;                   /* Stable target correlation when pathname changes. */
	__u32 file_device_major;            /* Filesystem/device identity. */
	__u32 file_device_minor;            /* Filesystem/device identity. */
	char  path[PHANTOM_PATH_MAX];       /* Contract path-prefix comparison and analyst evidence. */
} __attribute__((packed));

struct phantom_network_event {
	struct phantom_event_header header; /* Required common provenance. */
	__u8  direction;                    /* 1=connect, 2=accept; avoids separate ABI shape. */
	__u8  address_family;               /* AF_INET or AF_INET6 only; decoder rejects other values. */
	__u8  protocol;                     /* IPPROTO_TCP or IPPROTO_UDP evidence. */
	__u8  socket_type;                  /* SOCK_STREAM/SOCK_DGRAM context. */
	__u16 local_port;                   /* Host-order source/listening port. */
	__u16 remote_port;                  /* Host-order peer port for destination contract check. */
	__u8  local_address[16];            /* IPv4 mapped/IPv6 local endpoint, fixed ABI width. */
	__u8  remote_address[16];           /* IPv4 mapped/IPv6 remote endpoint, fixed ABI width. */
	__s32 syscall_result;               /* Connection/accept success or failure. */
} __attribute__((packed));

struct phantom_privilege_event {
	struct phantom_event_header header; /* Required common provenance. */
	__u32 previous_uid;                 /* Pre-transition effective UID. */
	__u32 new_uid;                      /* Post-transition effective UID. */
	__u32 previous_gid;                 /* Pre-transition effective GID. */
	__u32 new_gid;                      /* Post-transition effective GID. */
	__u64 capability_effective_before;  /* Capability delta analysis. */
	__u64 capability_effective_after;   /* Capability delta analysis. */
	__u32 transition_kind;              /* set*id/capability/credential operation category. */
} __attribute__((packed));

struct phantom_namespace_event {
	struct phantom_event_header header; /* Required common provenance. */
	__u32 namespace_type;               /* CLONE_NEW* category or namespace inode class. */
	__u32 operation;                    /* setns/unshare/clone operation category. */
	__u64 previous_namespace_inode;     /* Before-state identity. */
	__u64 target_namespace_inode;       /* Requested/after-state identity. */
	__s32 syscall_result;               /* Operation success/failure. */
} __attribute__((packed));

struct phantom_module_load_event {
	struct phantom_event_header header; /* Required common provenance. */
	__u32 operation;                    /* finit_module/init_module/delete_module category. */
	__s32 syscall_result;               /* Load/unload outcome. */
	char  module_name[64];              /* Module identity if safely derivable. */
	char  module_digest[65];            /* Optional user-space-resolved SHA-256; never fabricated in BPF. */
} __attribute__((packed));

struct phantom_loss_event {
	struct phantom_event_header header;    /* Required node/cgroup/CPU provenance; cgroup may be zero for global loss. */
	__u64 dropped_since_last_report;       /* Explicitly quantifies observation loss. */
	__u64 ring_buffer_reserve_failures;    /* Distinguishes reserve pressure from decoder errors. */
	__u64 user_space_submit_failures;      /* Counts agent transport failure observed in user space. */
	__u32 loss_scope;                      /* 1=CPU, 2=agent, 3=transport. */
} __attribute__((packed));

#endif /* PHANTOM_EVENTS_H */
