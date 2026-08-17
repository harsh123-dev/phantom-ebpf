/*
 * normalizer.c — User-space event normalization for PHANTOM eBPF agent.
 *
 * Converts raw ring-buffer structs into normalized JSON representations
 * compatible with the DriftEventIngestRequest API contract.
 * Performs cgroup-to-workload identity resolution using a maintained
 * metadata cache (kubernetes/CRI API calls).
 *
 * SECURITY: All memory-safe bounded string operations; no sprintf/strcpy.
 */

#include "../include/phantom_events.h"
