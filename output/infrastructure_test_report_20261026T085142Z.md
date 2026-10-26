# PHANTOM infrastructure and test restoration report

**Run date:** 2026-10-26 UTC  
**Repository:** `/root/phantom-ebpf`, branch `main`, commit `664441f`  
**AWS region/account:** `ap-south-1`, account `253490771520`

## Outcome

Local Python verification was restored in isolated environments and the relevant application test suites were run. The dedicated Kubernetes lab was **not** recreated: the only available EC2 host is the administration controller with an active SQL Server, and the privileged node agent must not share that host. AWS currently has no active PHANTOM-tagged lab resources. I did not install Docker/k3s, start application containers, apply Terraform, modify the SQL Server host, or execute attack scenarios.

## Environment and resources

- Hostname: `ip-172-31-67-19`; Ubuntu 22.04.5 LTS; x86_64; kernel `6.8.0-1066-aws`.
- EC2 identity: `i-06963bb589c361918`, `m7i.xlarge`, private IP `172.31.67.19`; 4 vCPU, 16 GiB EC2 RAM; attached 80 GiB gp3 root volume (unencrypted). The instance is not tagged as PHANTOM. `sqlservr` is running and listens on TCP 1433 on wildcard addresses. This host was left unchanged and is not safe for a privileged host-wide eBPF DaemonSet.
- OS reported about 15 GiB RAM, 13 GiB available, and 66–70 GiB free disk during this run.
- Existing local runtimes: no Docker/daemon, no `kubectl`, no k3s, and no Kubernetes contexts. Terraform, Git, Python 3.10/3.11, AWS CLI, and `bpftool` are available. `clang` and `llc` are absent.
- Read-only AWS inventory found no running/stopped PHANTOM lab instance, PHANTOM-tagged volume/EIP/NAT, or PHANTOM-named S3 bucket. The Terraform lab state list is empty following the earlier teardown.
- Isolated Python environments created: `.venv-causal`, `.venv-services`, `.venv-agent`, `.venv-evaluation` (ignored by Git). All four `pip check` commands passed after installing declared compatible dependencies. The causal environment includes `torch==2.3.1+cpu`; the services and agent use separate environments because their declared Pydantic/Kubernetes constraints are incompatible in one shared environment.

## Changes made

- `research/evaluation/pyproject.toml`: changed the invalid setuptools backend `setuptools.backends.legacy:build` to `setuptools.build_meta`. Editable installation and the evaluation suite then ran successfully. Other dependency changes in this file predated this execution and were preserved.
- `services/ebpf-agent/pyproject.toml`: added explicit setuptools package discovery limited to `application*`, `domain*`, and `infrastructure*`, excluding tests. This fixes setuptools treating `bpf` and `cmd` data directories as top-level Python packages. Editable install succeeded.
- No source, historical report, raw dataset, Terraform state, or existing output artifact was removed or overwritten. No commit or push was made.

## Automated tests

| Suite | Command | Result |
|---|---|---:|
| Causal engine | `.venv-causal/bin/python -m pytest services/causal-engine/tests -q` | 376 passed, 1 skipped |
| Core | `.venv-causal/bin/python -m pytest libs/phantom-core/tests -q` | 48 passed |
| SBOM service | `.venv-services/bin/python -m pytest tests -q` from `services/sbom-service` | 211 passed |
| API gateway | `.venv-services/bin/python -m pytest tests -q` from `services/api-gateway` | 63 passed |
| eBPF agent | `.venv-agent/bin/python -m pytest services/ebpf-agent/tests -q` | 174 passed |
| Report generator | `.venv-services/bin/python -m pytest tests -q` from `services/report-generator` | 36 passed |
| Evaluation | `.venv-evaluation/bin/python -m pytest research/evaluation/tests -q` | 267 passed |
| Repository E2E | `.venv-causal/bin/python -m pytest tests/e2e -q` | 386 passed, 3 failed |
| M4 adversarial artifact checks | `.venv-causal/bin/python -m pytest tests/verify_m4_adversarial.py -q` | 27 passed, 2 failed |

Across those distinct collections: **1,588 passed, 1 skipped, 5 failed**. The causal suite was run again after installing its declared CPU Torch dependency; only the final run is counted. No failed test was removed or weakened.

E2E failures are historical-fixture failures: one test expects at least 108 JSON runs under `research/datasets/raw/` but finds 69; two tests expect six oracle YAML files under `research/evaluation/oracles/`, a directory absent from this checkout. No fixtures were fabricated. The two M4 failures inspect existing output artifacts: the PHANTOM detection CSV row contains TPR `0.0000` where the old test expects `1.0000`, and the existing LaTeX table bolds `0.000`. Those historical outputs were left unchanged.

Automated tests include synthetic fixtures, in-memory or mocked collaborators, and reference calculations. They do not prove live Kubernetes processing or real attack detection.

## Static and safety verification

- Python compile check: `.venv-causal/bin/python -m compileall -q libs services research tests run_pipeline_report.py run_demo.py` — exit 0.
- YAML parse: 33 `.yaml`/`.yml` files parsed; 0 syntax errors. This was YAML syntax validation, not Kubernetes API-schema validation.
- `git diff --check` — exit 0.
- Terraform `fmt -check` — exit 0; `init -backend=false -input=false` — exit 0; `validate` — success. No Terraform plan or apply was run.
- Secret-marker scan covered 611 text files: no private-key PEM or AWS access-key ID markers found. Values were not printed.
- Scenario runner dry-run: `python -m research.evaluation.scenarios.run_all_scenarios --dry-run --output-dir /tmp/phantom-safe-dryrun-20261026T084737Z` — exit 0. Output explicitly says zero kubectl calls, zero sink contacts, and zero records written; the target directory was not created. `--execute` was not passed.
- `bpftool feature probe kernel` — exit 0; kernel reports BPF syscall, tracepoint program type, and BTF support. `/sys/kernel/btf/vmlinux` exists and this process has CAP_SYS_ADMIN, CAP_PERFMON, and CAP_BPF. No eBPF object was built or loaded; host kernel readiness is not proof that PHANTOM's agent works.
- Docker build was attempted and exited 127 (`docker: command not found`). `kubectl version --client` exited 127 (`kubectl: command not found`). No live services or manifests were deployed.

## Deployment gate and cost

The previous lab is gone. The current `m7i.xlarge` controller is shared with SQL Server and has no PHANTOM disposable-lab ownership tags. Running k3s plus a privileged eBPF agent here would share host networking and host process visibility with that service, so I did not install a cluster.

The existing lab sample uses one `t3.xlarge`, 50 GiB gp3, three SSM interface endpoints, and a NAT Gateway. Current AWS Price List API results for Mumbai: t3.xlarge **$0.1792/hour**; gp3 **$0.0912/GB-month** ($4.56/month for 50 GB); SSM interface endpoints **$0.013/endpoint-hour** ($0.039/hour for three). Known subtotal is about **$0.225/hour**, or **$1.80 for eight hours** and **$163.85 for 730 hours**, before NAT Gateway hours/data processing, public IPv4, internet transfer, taxes, and any evidence storage. AWS bills NAT Gateway hourly and per processed GB ([VPC pricing](https://aws.amazon.com/vpc/pricing/)); gp3 storage is billed by provisioned GB-month ([EBS pricing](https://aws.amazon.com/ebs/pricing/)). The full all-in amount therefore remains unverified; no paid resource was created.

A dedicated disposable lab is still required for safe deployment and live eBPF checks. Before creating it, confirm the exact Terraform plan and obtain an all-in estimate including NAT, EIP, and network transfer. The existing shared SQL Server controller must remain untouched.

## Later manual experiment session

After a dedicated disposable lab is provisioned and verified, run health checks against its explicit Kubernetes context, verify Prometheus/SBOM/oracle/evidence gates, and then have the operator invoke the scenario runner manually with a unique output directory. This execution ran dry-run planning only; it attempted **zero** experiment runs. Existing controller services and project datasets remain preserved.

## Evidence files

Raw test outputs, dry-run plan, BPF feature probe, Terraform checks, package diff, final Git status, and other command logs are stored in `output/infrastructure_test_evidence_20261026T085142Z/`.
