# Harmless EXEC telemetry diagnosis

This evidence records a diagnostic agent rollout in the existing k3s lab. Agent image tag `phantom/ebpf-agent:schedexec-20261025T2215Z` successfully built/imported and DaemonSet rollout reported `1/1` Ready. It replaces syscall-exit hooks with `sched_process_exec`, which should observe only successful executable changes. Agent metrics count parsed records by event type and stage. A harmless `/bin/echo PHANTOM_EXEC_PROBE_2215` via kubectl exec completed, but `phantom_agent_events_total` still showed only `namespace` and `privilege` event labels before/after; no EXEC record was parsed. Thus the hook rollout is not yet proven to deliver executable events. Startup logs confirm `handle_sched_process_exec` attached; reason for absent records remains unresolved. No hash or SBOM binding is claimed.

First build attempt failed because SSM uses `/bin/sh` and does not support `set -o pipefail`. Second failed because the DaemonSet container is named `phantom-agent`, not `ebpf-agent`; its image built/imported successfully but was not applied. The corrected third rollout succeeded. These failed outputs are retained.

`SHA256SUMS` covers other files in this directory. These are engineering diagnostics, not a research pilot.
