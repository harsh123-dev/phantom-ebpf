/*
 * phantom_maps.h — BPF map declarations shared across all PHANTOM programs.
 *
 * Minimum kernel: 5.8 (BPF_MAP_TYPE_RINGBUF introduced in 5.8)
 *
 * Design: one ring-buffer per event category so that per-category
 * perf/loss metrics can be attributed accurately. A per-CPU array
 * of counters tracks reserve failures for the loss-event ABI.
 *
 * The ring-buffer size (512 KiB default) is set at load time by the
 * user-space loader; the BPF_MAP_DEF below is a BTF-annotated
 * declaration, not a hard-wired allocation.
 *
 * CO-RE: these maps are included by every .bpf.c via the shared header.
 * The linker combines them so only one instance exists per program.
 */

#ifndef PHANTOM_MAPS_H
#define PHANTOM_MAPS_H

#ifndef __VMLINUX_H__
#include <linux/bpf.h>
#endif
#include <bpf/bpf_helpers.h>

/* ---- Per-category ring buffers --------------------------------------- */

/*
 * PHANTOM_RINGBUF_SIZE: default ring-buffer byte capacity per map.
 * Must be a power of two; loader may override at load time via
 * bpf_map__set_max_entries(). Expressed here as 512 KiB.
 */
#define PHANTOM_RINGBUF_SIZE  (512 * 1024)

/* Ring buffer: exec events (PHANTOM_EVT_EXEC). */
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, PHANTOM_RINGBUF_SIZE);
} rb_exec SEC(".maps");

/* Ring buffer: file open events (PHANTOM_EVT_FILE_OPEN). */
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, PHANTOM_RINGBUF_SIZE);
} rb_file_open SEC(".maps");

/* Ring buffer: file write events (PHANTOM_EVT_FILE_WRITE). */
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, PHANTOM_RINGBUF_SIZE);
} rb_file_write SEC(".maps");

/* Ring buffer: network connect/accept events (PHANTOM_EVT_NET_*). */
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, PHANTOM_RINGBUF_SIZE);
} rb_network SEC(".maps");

/* Ring buffer: privilege transition events (PHANTOM_EVT_PRIVILEGE). */
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, PHANTOM_RINGBUF_SIZE);
} rb_privilege SEC(".maps");

/* Ring buffer: namespace change events (PHANTOM_EVT_NAMESPACE). */
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, PHANTOM_RINGBUF_SIZE);
} rb_namespace SEC(".maps");

/* Ring buffer: module load events (PHANTOM_EVT_MODULE_LOAD). */
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, PHANTOM_RINGBUF_SIZE);
} rb_module SEC(".maps");

/* Ring buffer: loss reporting events (PHANTOM_EVT_LOSS). */
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);  /* Loss events are small; smaller buffer. */
} rb_loss SEC(".maps");

/* ---- Per-CPU reserve-failure counters -------------------------------- */

/*
 * reserve_failures: per-CPU array of u64 failure counts.
 * Index 0 = exec, 1 = file_open, 2 = file_write, 3 = network,
 * 4 = privilege, 5 = namespace, 6 = module.
 * Read by user-space to populate phantom_loss_event fields.
 * Using PERCPU_ARRAY avoids lock contention on hot paths.
 */
struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key,   __u32);
    __type(value, __u64);
} reserve_failures SEC(".maps");

/* ---- Reserve-failure index constants --------------------------------- */
#define RESERVE_FAIL_EXEC       0
#define RESERVE_FAIL_FILE_OPEN  1
#define RESERVE_FAIL_FILE_WRITE 2
#define RESERVE_FAIL_NETWORK    3
#define RESERVE_FAIL_PRIVILEGE  4
#define RESERVE_FAIL_NAMESPACE  5
#define RESERVE_FAIL_MODULE     6

#endif /* PHANTOM_MAPS_H */
