# Paper Evidence Matrix

| Claim / section | Current evidence | Status / permitted wording |
|---|---|---|
| Dedicated environment | AWS identity, tagged EC2, Terraform plan/apply record, k3s and BTF evidence | Dedicated disposable lab provisioned and deployed; see execution log and deployment verification. |
| eBPF capture | Agent Running, real Prometheus histogram count, persisted API event samples | Runtime events were captured and accepted by the API. |
| Workload identity | Harmless emailservice smoke event with resolved namespace, pod, and container | Workload-level attribution occurred for sample events; some events remained ambiguous. |
| SBOM/component attribution | Resolved event fields `purl`, `sbom_id`, and binding status are null | Not demonstrated. No component attribution or provenance claim is supported. |
| Causal-engine path | Redis group at `0-0`; publisher and consumer stream/schema mismatch | Causal engine processing of agent observations is not demonstrated. |
| Cluster identity | Agent event payload hard-codes `phantom-eks`; actual cluster is `phantom-k3s-lab` | Event cluster identity is inaccurate and must be fixed before another run.
| Contract drift | Generic violation payloads; no independent registered contract oracle | Contract-drift labels are unknown; no contract detection claim is supported. |
| Prometheus | Four real targets UP; SBOM scrape target removed after verified 404 | Core exporter and cAdvisor scraping works. SBOM service has no scrape endpoint. |
| Event lag | Live smoke p95 query based on BPF monotonic timestamp and agent callback monotonic timestamp | Smoke-only kernel-to-callback estimate; do not conflate with API ingestion, detection, or end-to-end latency. |
| Resource overhead | Live cAdvisor CPU/RSS smoke queries | Point-in-time smoke measurements only; no attack-vs-baseline overhead result. |
| Pilot detection performance | 18 planned, 0 attempted | No precision, recall, F1, FPR, MTTD, or confidence interval. |
| Causal effect | No valid intervention dataset and no demonstrated graph/diagnostics | No causal estimate. |
| Extended profile | Not run | Not justified before pipeline/oracle blockers are resolved. |
| Related work | NTIA official SBOM report, Kubernetes NetworkPolicy docs, Linux kernel BPF docs | Background only; not an exhaustive literature review and no novelty claim. |

All runtime evidence is separate from historical raw datasets. Smoke artifacts are at `research/datasets/smoke_batch/20261025T150659Z/`.

## Source-level follow-up (2026-10-25)

| Claim area | New evidence | Supported conclusion |
|---|---|---|
| Redis publisher/consumer | Fake-Redis tests: valid schema event processed and acknowledged; malformed schema remains pending (2 tests) | Contract shape and local adapter flow pass; live Redis/DB pipeline is not established. |
| Workload digest | Two tests for immutable `image_id` digest extraction; agent now declines to forward fabricated/unknown workload identity | Helper behavior is unit-tested; actual Kubernetes attribution is not verified. |
| SBOM component mapping | Existing standalone mapper/domain suite: 121 passing tests | Resolver behavior is tested in isolation; runtime ingestion mapping is not connected. |
| Experimental validity | Evaluation suite: 222 passing tests | Runner/config and metric accounting tests pass; no new experiment was executed. |
| Deployment / pilot | No plan/apply or live run; AWS read-only queries show no PHANTOM lab resources | No current deployment, detection metrics, or causal finding. |

Latest focused local suite count: **476 passed, 0 failed** across core, evaluation, SBOM resolver, causal-engine, gateway, and agent tests. Synthetic event-to-BDG and binding payload tests are implementation evidence only. The SBOM resolver is not connected to persisted ingestion; the independent contract oracle and durable sink evidence are not present. No empirical claim is supported by these tests.
