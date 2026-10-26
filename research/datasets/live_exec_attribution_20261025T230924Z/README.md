# Live EXEC and cgroup attribution verification

Date: 2026-10-25 UTC. Lab instance `i-06bb29d253668fa5f`, region `ap-south-1`; k3s node `ip-10-89-2-125`, kernel `6.8.0-1066-aws`.

## Observations

- Independent `bpftrace` on `sys_enter_execve` captured real `kubectl exec` executions, including `/bin/ls`, `/bin/sh`, and `/bin/true`. The captured output and `bpftool` program/link listing are in `kernel_bpftrace_and_bpftool.json`.
- The agent counters around a harmless `/bin/ls /tmp` rose from 488 to 506 at both `event_type=exec,stage=received` and `stage=queued`. `identity_missing` rose 452 to 468; `dispatched` stayed at 1. This isolated the next loss to workload identity resolution, not kernel hook, ring-buffer callback, or parser.
- The live evaluation container's cgroup-v2 scope directory had inode 10148, exactly matching the event's BPF cgroup ID observed in agent logs. The path contained runtime container ID `34da7537…95c67b798`; a live `/host/proc/<pid>/cgroup` read returned the same ID while a harmless `/bin/sleep` remained running.
- Added a cgroup-inode-to-container-scope resolver, then checked it against the current Kubernetes Pod container ID and immutable `imageID`. The current deployed DaemonSet is `phantom/ebpf-agent:cgroupattr-20261025T2306Z`, 1/1 Ready. The evaluation Pod specifies `tiangolo/uwsgi-nginx-flask:python3.11`; its live `imageID` is `sha256:149440c61b866ba5265959ea4ce2eb8864be9e4c8e0f6d5cc88546f899ecb8e7`, matching the API event image digest and the source image expected by the prepared evaluation-attestation workflow.
- After a harmless `/bin/sleep 5` in the evaluation pod, the real API list endpoint returned event `8ae9206d-e2f0-4e64-90a5-9ca2b72e77a2`: `event_type=exec`, `comm=sleep`, pod `recommendationservice-5dc98bbcb9-xq42k`, namespace `phantom-eval`, resolved container ID `containerd://34da7537…95c67b798`, image digest `sha256:149440c61b866ba5265959ea4ce2eb8864be9e4c8e0f6d5cc88546f899ecb8e7`. This is live agent-to-API persistence for a harmless smoke event.
- The same record reports `executable_path=unknown`, `binding_status=missing`, and `purl=null`. The kernel code currently stores only the executable dentry basename, which is not accepted as an absolute path; no executable hash is available. This does not establish component-level SBOM attribution.

## Scope

These are harmless smoke checks, not attack/control pilot runs. They do not prove SBOM attestation trust, independent contract ground truth, Redis/causal completion for this particular event, sink receipt collection, or attack-detection performance. No research attacks were run.

Source archive SHA-256 deployed for this agent build: `e58c8ba6686aaa23a7057e0bc02a78b48a114bde800d08f6c86f1eb84f0b4393`. The deploy archive is stored under the lab evidence bucket prefix `phantom/evidence/agent_cgroup_attribution_20261025T2306Z/`.
