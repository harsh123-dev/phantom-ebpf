# Phase 1 — Source Blocker Resolution

**Status (updated 2026-10-25):** Follow-up source fixes and focused tests have now run in an isolated Python 3.11.13 environment. This report's original environment limitations below are historical. Full runtime and Kubernetes validation remains unavailable on the shared SQL Server controller.

## Changes

| Blocker | Resolution | Evidence and remaining limit |
|---|---|---|
| Causal exporter routing | Declared container/Service port 9090 for metrics and changed Prometheus target to that port; health stays on 8080. Corrected the cAdvisor path replacement. | Parsed manifest and embedded Prometheus YAML; cross-checked target port statically. Prometheus scrape health is unverified. |
| Agent event lag absent | Added `phantom_event_delivery_lag_seconds` histogram and bounded invalid-timestamp counter. The BPF timestamp is `bpf_ktime_get_ns()`; callback entry is captured with `time.monotonic_ns()`. Zero and negative deltas are excluded. Added `/metrics` on port 9101, a ClusterIP Service, scrape job, and optional NetworkPolicy ingress. | AST/YAML checks passed. Unit test added but could not run. Runtime same-clock assumption, fresh buckets, and timestamp validity require the dedicated single-node lab. |
| Event metric semantics | Histogram measures **kernel event to userspace ring-buffer callback entry**, in seconds. The runner's p95 is `histogram_quantile` over a 5-minute rate and is represented in milliseconds. It is not API ingestion latency, detection latency, or end-to-end latency. | Kernel and userspace clocks must share the node monotonic domain without a time-namespace offset. Invalid values increment a reason-labeled counter; no zero is substituted. |
| Benign no-ops | Added controls: run-tagged Deployment annotation rollout with unchanged image refs; finite 200-request burst to the internal paired service, requiring request-token access-log evidence; and pod deletion with new Ready UID verification. | A mocked local control check and Python payload compilation passed. No cluster was available, so actual service receipts and telemetry activity are not verified. `benign-update-001` is now explicitly a metadata rollout, not a dependency update. |
| Config mismatch | Added validated YAML loader. The config drives pilot/extended scenario membership, workload pairing, repetitions, timing, namespace, and output root. CLI supports `--config`; explicit values remain overrides. | Config and scenario counts checked locally (18/27 planned); runner/import tests could not run due to missing `httpx` and pytest. |
| Nullable metrics | Evaluator filters absent samples per metric, distinguishes a measured zero from missing data, rejects non-finite/negative Prometheus samples, and reports unknown overhead as `None`. | AST and source checks passed; pytest could not run. |
| Historical output/oracle protection | Batch output defaults to a unique UTC timestamp path; existing paths and descendants of `raw/` or `raw3/` are refused. Oracle, run JSON, failed-run JSON, and index files use exclusive creation. Per-batch oracles live under that batch's `oracles/`. Run IDs include microseconds and a random suffix. | Output resolution and refusal tests added, not executed because pytest is unavailable. Existing data was not modified. |
| Ground-truth honesty | Run records mark contract outcome `unknown_contract_state` until an independent contract oracle exists. The evaluator excludes those records from TP/FP/FN/TN counts. Intervention verification is recorded separately from PHANTOM alerts. | Source-level only. No independent contract-state source is currently wired, so live detection metrics will remain inconclusive until one is implemented and validated. |

## Validation actually performed

- `ast.parse` on changed Python source/test files: **PASS**.
- PyYAML parsing of the experiment config, four Kubernetes manifests, and embedded Prometheus config: **PASS**.
- Matrix, target, and output-root assertions: **PASS** (6 pilot scenarios × 3 repetitions = 18; 9 extended scenarios × 3 = 27).
- Static exporter/scrape route assertions: **PASS** (causal 9090, agent 9101).
- Mocked benign-load subprocess receipt, command argument boundary, and payload compilation: **PASS**; this is synthetic validation, not a live activity observation.
- `python3 -m unittest tests.test_event_lag -v` from `services/ebpf-agent/`: **3 passed** for valid delta, zero source timestamp, and future timestamp rejection. This pure unit test runs without the agent's external dependencies.
- `python3 -m unittest research.evaluation.tests.test_config_unittest -v` from the repository root: **2 passed** for the 18/27 configured profiles, target pairings, and existing/historical output refusal.
- `git diff --check`: **PASS**.
- Focused pytest command: **NOT RUN**; Python reported `No module named pytest`. Project dependencies and supported Python 3.11 are unavailable. No unit test pass is claimed.

## Protocol implication

The new controls exercise bounded operational activity, but the dependency-update research treatment/control pairing has changed. The paper and protocol must describe the update control as a metadata rollout. Until an independent source verifies actual contract conformance/drift, do not calculate detection confusion-matrix metrics from expected scenario IDs or absent alerts.

## Follow-up pipeline repair (2026-10-25 15:33 UTC)

- Canonical Redis contract `1.0` and stream `phantom:drift-events` now live in `phantom-core`. API publisher and causal consumer use it; k3s-lab gateway/causal Redis URLs now use DB 0. Fake-Redis tests verify publish → schema validation → causal mutation invocation → acknowledgement and malformed payload remains pending.
- The consumer validates required workload/process/runtime evidence and timezone/digest shape, preserves unbound status with zero confidence, and does not ACK on processing or DLQ write failure. This is not a live Redis/PostgreSQL result.
- Agent stops emitting fabricated generic violations, placeholder all-zero digest, constant sequence, zero pod UID, default service account, and zero image digest. It hashes the parsed event and requires exact container identity plus runtime `image_id` immutable digest before forwarding. The agent's image digest helper has two focused tests. Runtime behavior remains unverified.
- Latest follow-up totals: phantom-core **47 passed**; evaluation **222 passed**; causal Redis/integration **69 passed**; SBOM mapper/domain **125 passed**; API outbox-retry/endpoint **8 passed**; agent lag/digest **5 passed**. **476 passed, 0 failed.** Terraform fmt/init/validate, `compileall`, YAML parse, and `git diff --check` passed. The earlier 422-test total above is superseded by this count.
- Remaining blockers: resolver serialization is not wired into ingestion; there is no independent contract oracle or run-correlated durable sink receipt. Accordingly no lab plan/apply or experiment proceeded.

## Follow-up implementation update (2026-10-25)

The SBOM resolver is now wired into gateway drift-event ingestion through the SBOM service's tenant-scoped runtime-binding endpoint. Exact CycloneDX SHA-256 component hashes can support positive attribution; path-only evidence and unresolved cases abstain. Gateway tests verify the mapping handoff and explicit unknown result when the service is unavailable. SBOM endpoint and resolver fixtures cover exact binding, ambiguous evidence, missing SBOM/provenance, and digest mismatch. These results are synthetic/local; the agent currently does not provide executable hashes, and no live attribution has been observed.

The blocking ground-truth gap remains: the sink has no durable run-correlated receipt store, and no independent contract-state oracle is wired to scenario outcomes. The end-to-end readiness gate is therefore still failed; no Terraform plan, deployment, or pilot execution was started.

## Verification follow-up — 2026-10-25 18:20 UTC

The source-level integration now has a signed-observation verifier, a deployed FastAPI/SQLite sink implementation, monotonic trust-store generations and key revocation, and a tested local backup/restore helper. The previously missing test dependencies are pinned in the causal environment; gateway JWT tests use PEM test keys without changing production verification. Latest full suite counts are evaluation 253, core 48, eBPF agent 160, SBOM 185, API gateway 63, causal engine 375 passed with 1 skipped. Total across these distinct suite runs: 1,084 passed, 1 skipped, 0 failed. Causal and gateway suites were run in isolated environments. The Redis composition used fakeredis; its optional real Redis path was skipped because no `redis-server` is installed. FastAPI routes and SQLite persistence/reinitialization were exercised locally through TestClient; this is not a deployed service test.

Trust key rotation and revocation are represented by an explicit trust-store ID, generation, config hash, and cumulative revoked-key state persisted in SQLite. Tests accept a replacement key, reject a revoked key and generation rollback, and reject silent key removal. The Kubernetes trust ConfigMap remains empty. There is still no real independently operated collector or authenticated contract registry adapter; test-only keys and an `independent_of_phantom` configuration flag cannot establish real-world independence or truth. This is a hard deployment blocker.

The sink backup helper verifies and restores a local SQLite database in tests and refuses overwrite. No automated/off-node backup, separately encrypted EBS backup volume, or node-loss recovery has been configured or tested. The current local-path PVC does not protect against node loss. The agent's executable hash remains explicitly unavailable because the event contains no pinned executable bytes/file identity, and later procfs hashing can race process exit or executable replacement. Synthetic mapper fixtures do not establish live SBOM binding.

`compileall`, parsing of 15 Kubernetes/evaluation YAML files, `git diff --check`, Terraform `fmt -check`, `init -backend=false`, and `validate` passed. An initial SBOM invocation lacked `PYTHONPATH=libs/phantom-core` and produced 10 import setup errors; the correctly configured rerun passed 185 tests. No AWS resources, Terraform plan/apply, Kubernetes deployment, or scenarios were run. **Readiness remains BLOCKED** pending an actual independent oracle source and trust anchor, operational off-node recovery, and the full isolated-lab data path. Pilot remains 18 planned / 0 attempted.

## Independent observer and S3 path follow-up — 2026-10-25 18:52 UTC

Added a scenario-policy-backed observer adapter and a separately signed contract snapshot check. It verifies the scenario ID/target service, direct assertion ID, injection success, workload/image identity, evidence references, and freshness before signing. Missing inputs return unknown. The contract registry key and observer key are separate Ed25519 trust entries; the sink verifies both the registry signature over the contract bytes and the observer signature over the full run observation. Test keys are ephemeral. No production key is configured. The live runner still has no distinct read-only collector that supplies these assertions; it continues to write explicit unknown receipts. The adapter's fixture tests are not live independent ground truth.

Added a boto3 S3 backup client with online SQLite snapshot, SHA-256, S3 checksum, SSE-S3 request, conditional no-overwrite write, version ID, integrity verification, and no-overwrite restore. A test deleted its source DB and restored a receipt into a fresh DB through an in-memory S3 test double. This verifies serialization/client behavior only; AWS object durability, IAM, bucket policy, and off-node recovery remain unverified. Terraform now contains an opt-in versioned bucket and prefix-scoped instance-role policy; the default remains disabled. No AWS resource was created.

Latest suite counts: evaluation 265, core 48, agent 160, SBOM 185, gateway 63, causal 375 passed and 1 skipped (real Redis unavailable): **1,096 passed, 1 skipped, 0 failed**. Python compilation, parse of 16 YAML files, `git diff --check`, Terraform fmt/init/validate passed. A read-only plan in verified account `253490771520`/`ap-south-1` reports **13 creates, 0 changes, 0 destroys** with backups enabled and SSM administration; saved at `/tmp/phantom-evidence-backup.tfplan`. It includes the dedicated EC2 lab and opt-in S3 bucket. The plan still assigns public IPv4 and allows unrestricted outbound security-group egress; regional cost and bucket-name availability were not estimated/checked. No plan was applied.

**Gate remains closed:** there is no production trust configuration, no independent live contract/workload collector, no actual S3 backup/restore integration, no deployed network-policy test, and no live agent-to-SBOM attribution. Executable hashes remain unavailable. No attack scenarios were run; pilot remains 18 planned / 0 attempted.

## Independent oracle and receipt follow-up (2026-10-25)

Added a fail-closed deterministic contract evaluator in `research/evaluation/oracle.py` and a durable SQLite receipt store in `research/evaluation/evidence_store.py`. The evaluator rejects detector-derived sources, checks a supplied active/verified contract snapshot and workload selector, and emits confirmed violation, confirmed compliance (only with complete coverage), or unknown. The scenario runner now writes one versioned receipt per attempt in the unique batch directory; absent independent evidence is recorded as unknown. The store uses durable SQLite commits, deterministic receipt IDs, retry idempotency, conflict rejection, retrieval, and canonical-hash verification.

Tests prove oracle/store behavior and an oracle-to-file-store composition with controlled fixtures. They do not authenticate the claimed contract signature or the producer of an `independent_sink` observation. There is no live contract snapshot adapter or independent evidence collector in this checkout. The existing in-cluster TCP `phantom-sink` still only accepts/closes connections and does not produce durable run-correlated connection receipts. The composed runtime-to-oracle-to-sink pipeline is therefore not verified and AWS/pilot readiness remains blocked. Agent executable hashes also remain unavailable: the eBPF event ABI exposes executable path and argv digest, not executable-byte SHA-256; hashing via `/proc` would require a new race/overhead design.

Final relevant tests: **494 passed, 0 failed**; compileall, 15-file YAML parse, and `git diff --check` passed. No Terraform plan, deployment, AWS changes, or scenario executions were performed.

## Follow-up: authenticated oracle and persistent sink implementation (2026-10-25 17:41 UTC)

This section records the newer state; earlier sections remain historical. Source now verifies canonical schema 1.0 Ed25519 observations against an explicitly configured public-key trust file, with freshness/replay controls and identity checks. A positive oracle outcome requires a verified configured-independent source and complete, consistent contract evidence. The Kubernetes trust ConfigMap is empty because no real independent collector or public trust anchor is available. Test-only ephemeral keys prove crypto behavior but do not provide production ground truth.

The deployed `phantom-sink` manifest now invokes a FastAPI service backed by SQLite WAL storage with `synchronous=FULL`, owner-only DB/WAL file modes, durable commit before success, retry idempotence, conflict rejection, run lookup, receipt hash verification, and signed-observation re-verification. Passive TCP beacon ports persist connection receipts but cannot infer run/scenario IDs and always report unknown. The workload is one writer with Recreate strategy on a local-path RWO PVC, non-root/read-only-root security settings, ClusterIP service, and same-namespace-only ingress. This is not replicated or off-node durability. Docker is unavailable here; the new image was not built or deployed.

A composed local test uses the real gateway Redis publisher function, real causal consumer/graph, actual sink HTTP routes and file-backed SQLite; fakeredis substitutes only Redis. It verifies processing and acknowledgment, explicit insufficient SBOM evidence, signed test observer evidence, receipt retrieval after app reinitialization, and idempotent retry. It does not exercise the live eBPF agent, gateway/PostgreSQL persistence, or SBOM service. Runtime executable SHA-256 remains unavailable: the eBPF ABI contains path and argv digest but not file content or a pinned executable handle; asynchronous procfs access may race PID exit/reuse. Agent/API schema now explicitly preserves `executable_hash_status=unavailable`.

Latest tests: evaluation **240 passed**, core **48 passed**, agent **160 passed**, SBOM **185 passed**, causal Redis/composition **6 passed**, gateway outbox mapping focus **3 passed**. Broad causal suite: **362 passed, 12 failed, 1 skipped**, failures caused by absent `dowhy`. Broad gateway suite: **49 passed, 14 failed**, due to the existing JWT fixture's unsupported RSA-key object passed to `python-jose==3.3.0`. Compileall, changed YAML parse, Terraform fmt/init/validate, and `git diff --check` passed.

**Readiness remains blocked.** No AWS or Kubernetes action, Terraform plan/apply, or experiment was run. A real independent evidence collector/trust anchor, Docker image build, and live isolated-lab verification of agent → API → Redis → causal → SBOM → oracle → sink are still required. Pilot remains **18 planned / 0 attempted**.

**Test-count correction (2026-10-25 17:42 UTC):** added assertions for rejection of detector-derived unsigned records and contradictory same-event observations. The complete evaluation suite now reports **244 passed**; earlier follow-up's 240 count is superseded. Other service counts are unchanged from the immediately preceding verified run.

**Sink-policy follow-up (2026-10-25 17:43 UTC):** restricted the HTTP receipt API to the labeled evidence collector and API gateway; scenario workload labels can reach only the legacy beacon ports. Added three YAML-backed tests for the sink PVC, single-writer security profile, and ingress/egress selectors. Evaluation suite now reports **247 passed**. NetworkPolicy effectiveness still requires a live isolated cluster check.

**Causal full-suite diagnostic (2026-10-25 17:46 UTC):** the 12 causal full-suite failures are not all attributable to one package: 5 directly require missing `dowhy`; 1 expects NetworkX 3.3's `d_separated` but the test environment has NetworkX 3.6.1; 2 require missing `scipy`; 4 estimator/pipeline assertions return `invalid_graph` as a downstream consequence of this dependency mismatch. The changed causal integration tests pass. This records the environment limitation without changing tests or dependencies in the repository.

## Live deployment follow-up — 2026-10-25

The lab has now been provisioned from the isolated `k3s-lab` Terraform state. Its EC2 node has no public IP or SG ingress; administration uses SSM. Egress remains allowed over TCP 80/443 to public destinations through NAT, so host-level public egress is not blocked. The Kubernetes evaluation policy was exercised: a target workload could not open TCP to the cross-namespace Redis service, while the API gateway control connection could. No public destination was probed.

A harmless runtime smoke event was captured by eBPF, persisted by the gateway, published on the canonical Redis stream, processed by the causal consumer, and acknowledged. At the final query the consumer success counter was 12, consumer-group `entries-read=12`, `pending=0`, and `lag=0`. This is actual live integration evidence, not a pilot run.

Two deployment defects were fixed after live errors: (1) conflicting Prometheus metric registration in the causal engine; (2) absent SBOM tables because the SBOM service had no migrations. A separate `phantom_sbom` schema and startup migrations now run. A subsequent runtime mapping call returned a deliberate unbound result because the actual target image has no SBOM document indexed. No PURL/component binding is proven.

A real HTTP sink receipt survived service reinitialization on its local-path PVC and passed its payload-integrity check. It remains unknown, unsigned, and unverified for authenticity/independence. No off-node receipt backup or node-loss recovery has been exercised. The oracle trust ConfigMap is still empty, there is no live independent contract observer, and executable SHA-256 remains unavailable.

Current state: deployment is running for integration validation, but the research/pilot gate remains **CLOSED**. No attack or benign-control scenarios were executed (18 planned / 0 attempted). Full live event binding, independent ground truth, production trust configuration, off-node backup/recovery, and a more conclusive network-policy boundary test remain prerequisites.

Evidence and checksums: `research/datasets/live_smoke_20261025T193500Z/`. Local checks in this follow-up: agent **161 passed**, SBOM **185 passed**, gateway **63 passed**; compileall, eight YAML parses, Terraform formatting/validation, and `git diff --check` passed.


## Live SBOM and recovery check — 2026-10-25 19:56 UTC

The current deployed lab was used without Terraform or resource changes. A signed/pinned Syft 1.55.0 run generated a 22,823-component CycloneDX document from the exact `linux/amd64` image manifest linked to the target pod's immutable config digest. The running `/usr/local/bin/python3.11` hash matches the Syft file entry, but the event carries `executable_hash:null`; this interpreter file has no PURL or package occurrence. Runtime-to-component attribution therefore remains unbound.

SBOM indexing remains blocked: live SBOM DB count is zero; deployment bucket/region are unset; default bucket is `phantom-sbom-artifacts`; static S3 credentials are unset; the current role policy only grants `phantom/evidence/*`, while the service writes to `sboms/<id>/...`. No ingestion call was made because the service writes DB/components before artifact upload, risking a partial record.

Manual off-node recovery is now verified: an online snapshot of the live sink SQLite database was stored in the existing encrypted, versioned AWS S3 bucket using `S3EvidenceBackupClient`; restore to a fresh DB passed integrity checks and matched the two stored receipt IDs and canonical hashes. This resolves the previous “no S3 restore tested” blocker for a manual workflow only; periodic backup automation and direct workload-role access are still absent.

The post-restart smoke receipt stayed unknown, authenticity and independence unverified. Oracle ConfigMap still has no public keys, and no deployed independent observer supplies direct contract assertions. The namespace cross-namespace Redis probe returned `connect_ex=111`, but public egress was not directly probed; node TCP 80/443 egress remains allowed through NAT.

**Research gate remains CLOSED; pilot remains 18 planned / 0 attempted.** Raw evidence and checksums: `research/datasets/live_attribution_20261025T194226Z/`.

## Live SBOM-ingestion blocker resolution — 2026-10-25

The SBOM artifact-store configuration and restricted service egress are now present in the running lab. The exact-image Syft document was accepted by the real SBOM HTTP service after the service fetched and verified the pre-existing versioned object through a short-lived regional S3 presigned GET URL. The API returned SBOM ID `f6ffce2a-50c1-4284-91f4-5d515e43da9e`; Postgres has 1 SBOM row and 22,823 components. Retrieval after the final service restart returned the same image digest and a canonical document digest matching the indexed record. A deliberately incorrect artifact hash was rejected without changing database counts. The service now returns the same record on an identical retry.

Remaining live-readiness blockers are not resolved: the indexed SBOM has `pending` signature verification and cannot support a trusted runtime component binding; the observed event was `runc` with no executable hash or run/scenario identity; the production oracle store has no trusted keys, and no independent live contract observer is configured. No independent signed receipt was produced. The pilot remains **18 planned / 0 attempted / 0 valid**. Full live verification and raw outputs are recorded in `research/datasets/sbom_ingestion_20261025T202953Z/`.
# 2026-10-25 continued attempt to open pilot gates

The run summary now reports `UNKNOWN`/`FAILED` rather than TP/FP/TN/FN derived
from planned labels while signed ground truth is unknown. Focused regression
coverage passes. The eBPF agent now counts kernel event stages; a deployed
`sched_process_exec` collection change was tested with harmless `kubectl exec`
and `/bin/echo`, but the live event counter still showed no EXEC records. The
application process hash and SBOM component binding therefore remain
unavailable. SBOM signature verification returned HTTP 503 because no trusted
signer identity and issuer are configured. The oracle trust store remains
empty and no independent contract observer produces live signed observations.
These are actual blockers, not test failures. No pilot attacks were run.

New evidence: `research/datasets/exec_telemetry_20261025T2209Z/`,
`research/datasets/attribution_probe_20261025T2132Z/`, and
`research/datasets/trust_integration_20261025T2150Z/`.

The scenario runner now writes its independent direct `verify_injection()`
assertion into receipt provenance, separate from PHANTOM detections. This can
support behavior verification in later runs but does not promote the unknown
contract outcome. Regression check: **28 focused summary/oracle/observer tests
passed**.

To make the gates actionable, the operator must supply/authorize (a) a release
or signing workflow that emits a CycloneDX attestation for the exact immutable
image digest and its verified GitHub OIDC signer identity/issuer, (b) an
independently operated contract observer and signed contract-registry source,
and (c) distinct trust-store public keys/custody. Runtime collection also
needs a verified reason why `sched_process_exec` does not emit parsed EXEC
records in this host. No trust key or ground-truth value was fabricated.


### 2026-10-25 live EXEC follow-up

The missing parsed EXEC event was traced to duplicate `rb_exec` map names in separately loaded BPF objects: the loader overwrote the syscall object's producer FD with a later object's unused map. The selective object-to-map loader fix is deployed. Kernel bpftrace captured real `execve` operations; agent counters confirmed receive/queue increments. A subsequent live cgroup-v2 inode-to-container scope resolver, verified against Kubernetes container status, allowed a harmless `sleep` EXEC to be persisted by the API with resolved target pod/container/image digest. See `research/datasets/live_exec_attribution_20261025T230924Z/`. The persisted record remains `executable_path=unknown`, `binding_status=missing`, PURL null; it does not establish component attribution.

The release and evaluation SBOM attestation workflows are prepared but not pushed or triggered. No real keyless certificate has been observed, and the live SBOM service still lacks a verified configured signer policy/image reference for its indexed record. The independent observer's production trust configuration also remains absent. Do not run attacks pending those scientific-evidence gates.

Migration-runner regression test: `test_migrations.py` **1 passed**; this confirms additive migration version 003 is recorded by the runner and is not rerun on the next initialization.
