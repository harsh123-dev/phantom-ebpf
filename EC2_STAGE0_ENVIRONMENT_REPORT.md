# PHANTOM Stage 0: Environment Report

**Observed:** 2026-10-25 12:18 UTC  
**Repository:** `/root/phantom-ebpf`  
**Baseline Git state:** clean, `main` at `4798396` (`origin/main`) before this session's change.

## Machine facts

| Check | Observed result |
|---|---|
| Current user / directory | `root` / `/root/phantom-ebpf` |
| Requested path | `/home/ubuntu/phantom` is absent. The located repository is the current directory; it was not moved or cloned. |
| OS / architecture | Ubuntu 22.04.5 LTS (Jammy) / x86_64 |
| Kernel | `6.5.0-1020-aws` (`#20~22.04.1-Ubuntu`, x86_64) |
| CPU / memory | 4 CPUs; 15 GiB RAM, 13 GiB available; no swap |
| Root filesystem | `/dev/root`, 78 GiB total, 73 GiB available (7% used) |
| Git | Branch `main`, initially clean, HEAD `4798396`; GitHub CLI authentication is not configured. No credential values were inspected. |
| Bubblewrap | `/usr/bin/bwrap`, version 0.6.1 |
| Docker / kubectl / k3s | Not installed; Docker and k3s systemd units report inactive. |
| Alternative container tools | `podman`, `nerdctl`, and `ctr` not found on PATH. |
| eBPF/BTF | `/sys/kernel/btf/vmlinux` is readable (5.6 MiB); kernel config has `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_DEBUG_INFO_BTF=y`. `unprivileged_bpf_disabled=2`; current shell is root with broad effective capabilities. |
| Sandbox-related check | `unprivileged_userns_clone=1`; bubblewrap version is present. No sandbox execution test was attempted. |

## Assessment

The OS, architecture, running kernel BTF, CPU, RAM, and disk are consistent with the intended lab class, but this does not establish that the machine is the authorized disposable EC2 instance or that a k3s cluster exists. AWS identity/resource APIs were not queried. The deployment prerequisites are absent, so image building, k3s image import, cluster verification, and Kubernetes deployment are unavailable here. The eBPF capability checks are promising but do not prove that the agent can load programs in a Kubernetes pod.

The expected `/home/ubuntu/phantom` checkout is missing. This report and subsequent work remain in `/root/phantom-ebpf`; no path change or clone was made.

## Addendum — execution 2026-10-25

Read-only IMDS returned instance ID `i-06963bb589c361918`, type `m7i.xlarge`, region `ap-south-1`; these facts do not prove project ownership. The current host runs `mssql-server`, with SQL Server listening on port 1433. This prevents treating the host as a confirmed dedicated lab. AWS CLI, Terraform, Docker, kubectl, and k3s remain unavailable. AWS identity/permissions were not verified. No cloud, host, or Kubernetes mutations were made. See `PHANTOM_EXECUTION_LOG.md` for the final execution gate.
