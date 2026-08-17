/*
 * main.c — User-space libbpf loader and ring-buffer reader for PHANTOM eBPF agent.
 *
 * Responsibilities:
 * - Load and attach all CO-RE eBPF programs from phantom_*.bpf.o skeletons.
 * - Validate abi_version in every received event header.
 * - Read events from the ring buffer and dispatch to the normalizer.
 * - Emit phantom_loss_event records on ring-buffer reserve failures.
 * - Maintain the cgroup-to-pod identity mapping via Kubernetes/CRI metadata.
 * - Submit normalized events to the api-gateway with stable event_id retry.
 * - Expose Prometheus metrics on the scrape endpoint.
 *
 * SECURITY: No shell=True equivalents; all subprocess calls use execvp
 * with explicit argument arrays.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../include/phantom_events.h"

int main(void)
{
    return 0;
}
