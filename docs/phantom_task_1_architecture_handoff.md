# PHANTOM Task 1: Complete System Architecture Handoff

Full title:

"PHANTOM: Causal Attribution of Runtime SBOM Drift via eBPF Behavioral Contracts in Kubernetes"

This document is the implementation blueprint for Claude Code. Every decision here is final unless explicitly revised by the project owner.

## 1. Research Framing

PHANTOM's architecture is a research artifact for proving that runtime SBOM drift can be causally attributed, not merely detected. The central design claim is:

> A signed build-time SBOM is insufficient unless paired with runtime behavioral evidence, dependency graph evolution, and causal attribution over observed process/package/network/file interactions.

The system therefore separates observation, identity resolution, contract validation, graph mutation, causal attribution, and incident scoring into distinct components so each can be evaluated independently in an IEEE/ACM paper.

## 2. Component Registry

| Component | Responsibility | Inputs | Outputs | Failure Mode | Why Separate |
|---|---|---|---|---|---|
| eBPF Sensor | Capture low-level runtime events from Kubernetes nodes. | Kernel syscall/process/file/network events. | `KernelEvent` records to ring buffer. | Event loss or verifier rejection; downstream sees incomplete behavior. | Must remain minimal, verifier-safe, and kernel-resident. |
| Ring Buffer Reader | Consume kernel events in user space. | libbpf ring buffer records. | Batched `RawRuntimeEvent`. | Reader lag causes dropped events; downstream marks confidence degraded. | Separates kernel safety from enrichment logic. |
| Event Normalizer | Canonicalize raw events. | `RawRuntimeEvent`. | `NormalizedRuntimeEvent`. | Malformed events quarantined. | Keeps later components schema-stable. |
| Kubernetes Identity Resolver | Map cgroup/process identity to pod, container, image digest. | cgroup ID, PID namespace, Kube API watch, CRI metadata. | `WorkloadIdentity`. | Missing or ambiguous identity; event stored with `identity_status=unknown`. | Identity mapping is failure-prone and deserves explicit uncertainty. |
| SBOM Resolver | Map workload image digest to CycloneDX components/PURLs. | Image digest, signed SBOM artifact, Syft output. | `SBOMComponentBinding`. | Missing SBOM blocks contract validation for that workload. | SBOM logic changes independently from runtime tracing. |
| Contract Store | Store signed behavioral contracts. | `BehavioralContract`, cosign signatures. | Verified contract material. | Invalid signature means contract unusable. | Security boundary for trusted expected behavior. |
| Contract Validator | Compare runtime behavior against contract. | Normalized events, workload identity, SBOM bindings, BC. | Drift observations `D`. | Unknown identity produces low-confidence drift. | Separates policy semantics from raw telemetry. |
| PostgreSQL Event Store | Durable storage for normalized events, drift, incidents. | Events, identities, drift records. | Queryable history. | Write failure causes Redis-backed retry; sustained failure degrades system. | Durable audit evidence required for publication and forensics. |
| Redis Stream Buffer | Short-lived queue for async pipeline stages. | Event batches, graph mutation jobs, scoring jobs. | Ordered work queues. | Queue saturation causes backpressure and event sampling. | Decouples ingestion rate from analysis rate. |
| Behavioral Dependency Graph Builder | Maintain runtime dependency graph. | Events, SBOM bindings, drift records. | BDG `G=(V,E,φ,ψ)`. | Graph stale; causal attribution operates on older snapshot. | Graph update semantics must be independently testable. |
| Structural Causal Model Builder | Convert BDG into DoWhy causal model. | BDG snapshot, temporal event windows. | SCM specification. | Invalid DAG or cycles require condensation/temporal ordering. | Causal model construction is the research contribution. |
| Causal Attribution Engine | Estimate causal effect of suspicious behavior on drift. | SCM, treatment `S`, outcome `D`, covariates. | Attribution records with confidence. | Identification failure; reports "not identifiable." | Avoids conflating ML prediction with causal claims. |
| PCEPS Scorer | Score incident priority using causal and behavioral features. | Feature vector, XGBoost model. | Priority score, severity band. | Missing features trigger imputation and confidence penalty. | Prediction layer should be replaceable without changing causal layer. |
| Incident Reporter | Produce analyst-facing incident report. | Drift, causal attribution, PCEPS score, graph evidence. | JSON report, dashboard entry. | Partial report emitted with missing sections flagged. | Separates scientific evidence from presentation. |
| API Server | Expose PHANTOM data model. | REST/WebSocket requests. | JSON responses. | API outage does not stop node collection. | Backend interface must be stable for UI and evaluation scripts. |
| React/D3 Frontend | Visualize drift, graph, attribution, and timelines. | API responses. | Analyst UI. | UI failure does not affect detection. | Presentation concern only. |
| Prometheus/Grafana | Observe PHANTOM itself. | Metrics from agents/services. | Dashboards/alerts. | Monitoring blind spot. | Meta-observability should not contaminate research metrics. |

## 3. Full Data Flow

```text
[Kubernetes Node Kernel]
   |
   | kprobe/tracepoint/LSM eBPF programs
   v
[eBPF Maps + Ring Buffer]
   |
   | libbpf user-space reader
   v
[Node Agent: Raw Event Batch]
   |
   | normalize, validate schema, attach node metadata
   v
[NormalizedRuntimeEvent]
   |
   +--> [PostgreSQL: runtime_events append]
   |
   +--> [Redis Stream: identity.resolve]
              |
              v
       [Kubernetes Identity Resolver]
              |
              | cgroup_id / pid_ns / image_digest / pod_uid
              v
       [WorkloadIdentity]
              |
              +--> [PostgreSQL: workload_identity]
              |
              v
       [SBOM Resolver]
              |
              | image_digest -> CycloneDX SBOM -> PURL binding
              v
       [SBOMComponentBinding]
              |
              +--> [PostgreSQL: sbom_bindings]
              |
              v
       [Contract Validator]
              |
              | runtime behavior compared with signed BC
              v
       [DriftObservation D]
              |
              +--> [PostgreSQL: drift_observations]
              |
              v
       [Redis Stream: graph.update]
              |
              v
       [BDG Builder]
              |
              | mutates graph nodes/edges
              v
       [Behavioral Dependency Graph G]
              |
              +--> [PostgreSQL: graph_snapshots]
              |
              v
       [SCM Builder]
              |
              | G -> causal graph + variables
              v
       [DoWhy CausalModel]
              |
              | estimate P(D | do(S))
              v
       [Causal Attribution Engine]
              |
              v
       [AttributionRecord]
              |
              +--> [PostgreSQL: attribution_records]
              |
              v
       [PCEPS Feature Builder]
              |
              v
       [XGBoost PCEPS Scorer]
              |
              v
       [Incident Report]
              |
              +--> [PostgreSQL: incidents]
              +--> [FastAPI]
              +--> [React/D3 UI]
              +--> [Prometheus metrics]
```

## 4. eBPF Subsystem Design

### Program Types

| Program Type | Used For | Why This Type | Why Not Alternative |
|---|---|---|---|
| Tracepoints | Stable syscall-level events: `execve`, `openat`, `connect`, `accept`, `unlink`, `chmod`, `setns`. | Tracepoints are more stable than kprobes across kernel versions. | kprobes expose less stable internal symbols. |
| kprobes | Select kernel functions where tracepoints lack required semantics. | Useful for targeted visibility when tracepoint payload is insufficient. | Use sparingly because kernel symbol compatibility is weaker. |
| LSM hooks | Security-relevant decisions such as file execution, socket connect, privilege-sensitive operations. | Captures intent near enforcement boundary. | Tracepoints may observe after-the-fact behavior without policy context. |
| uprobes | Optional user-space library/package behavior only when explicitly configured. | Can observe language/runtime package loaders. | Not default because overhead and symbol/version fragility are high. |

Uncertainty statement: exact hook names must be confirmed against the target kernel headers and libbpf CO-RE availability. PHANTOM must not depend on undocumented kernel structs.

### Ring Buffer vs Perf Buffer

PHANTOM uses BPF ring buffer because the canonical kernel baseline is `>= 5.8`.

| Criterion | Ring Buffer | Perf Buffer |
|---|---|---|
| Event ordering | Shared ring supports global ordering better. | Per-CPU buffers require reconstruction. |
| Memory efficiency | Single shared buffer. | Per-CPU allocation can waste memory. |
| Complexity | Simpler user-space consumption. | More bookkeeping. |
| Kernel support | Requires newer kernels. | Works on older kernels. |
| PHANTOM decision | Preferred. | Rejected unless kernel baseline changes. |

### cgroup ID to Kubernetes Pod Identity

1. eBPF records `cgroup_id`, PID/TGID, PID namespace, mount namespace, UID/GID, and command metadata.
2. Node agent maintains a cache from cgroup ID to container ID by observing cgroup filesystem paths and container runtime metadata.
3. Container ID maps to Kubernetes pod UID through CRI metadata and Kubernetes API watch.
4. Pod UID maps to namespace, pod name, service account, labels, owner references, and image digest.

Ambiguous or missing mappings produce:

```text
identity_status ∈ {resolved, ambiguous, missing, stale}
```

Downstream handling:

| Status | Behavior |
|---|---|
| `resolved` | Full validation and attribution. |
| `ambiguous` | Store event, exclude from strong causal claims, include in uncertainty notes. |
| `missing` | Store event as orphan telemetry. |
| `stale` | Re-resolve asynchronously before graph mutation. |

### Pod Identity to SBOM Component

Mapping chain:

```text
pod_uid -> container_id -> image_digest -> signed SBOM -> CycloneDX component -> PURL
```

If an event maps to a process path or executable associated with multiple PURLs, PHANTOM creates a candidate set:

```text
PURLCandidates = {(purl, evidence_type, confidence)}
```

No single component attribution is made unless confidence exceeds a configured threshold.

## 5. Behavioral Contract Formal Definition

A Behavioral Contract is:

```text
BC = (M, C, τ, σ)
```

Where:

- `M` is metadata:
  - `contract_id: UUID`
  - `image_digest: OCI digest`
  - `sbom_digest: SHA-256`
  - `workload_selector: Kubernetes label selector`
  - `created_at: timestamp`
  - `contract_version: semver`

- `C` is the allowed behavior constraint set:
  - allowed executable paths
  - allowed file path patterns
  - allowed network destinations
  - allowed syscall classes
  - allowed package/PURL runtime activations
  - allowed parent-child process relations
  - allowed privilege transitions

- `τ` is the temporal validity interval:
  - `valid_from: timestamp`
  - `valid_until: timestamp | null`
  - `training_window: [t0, t1]`

- `σ` is the signature envelope:
  - `signature_algorithm`
  - `cosign_bundle_reference`
  - `signing_identity`
  - `transparency_log_entry`
  - `signature_material_digest`

Stored in PostgreSQL as canonical JSON plus signature metadata. The unsigned contract body is hashed before verification. A contract is usable only if cosign verification succeeds against configured trust roots.

## 6. Behavioral Dependency Graph Formal Definition

The Behavioral Dependency Graph is:

```text
G = (V, E, φ, ψ)
```

Where:

- `V` is the set of entities:
  - workload
  - container
  - process
  - executable
  - SBOM component/PURL
  - file object
  - network endpoint
  - Kubernetes service account
  - drift observation

- `E` is the set of directed behavioral relations:
  - `spawned`
  - `loaded_component`
  - `opened_file`
  - `connected_to`
  - `violated_contract`
  - `runs_as`
  - `derived_from_image`

- `φ: V -> Attributes` assigns node attributes:
  - type
  - identity confidence
  - first_seen
  - last_seen
  - namespace/pod/container metadata
  - PURL or digest where applicable

- `ψ: E -> Attributes` assigns edge attributes:
  - relation type
  - timestamp interval
  - event count
  - evidence event IDs
  - confidence
  - contract status

### Update Semantics

A graph mutation occurs when:

1. A new resolved workload identity is observed.
2. A runtime event introduces a new entity or relation.
3. A contract violation creates or updates a drift node.
4. SBOM resolution binds a process/executable to a PURL.
5. A temporal window closes and edge weights are finalized.

Graph mutation pseudocode:

```text
Algorithm UpdateBDG(event e, identity w, sbom_binding b, drift d):
  normalize entity keys from e, w, b
  for each entity implied by e:
      if entity not in V:
          add entity to V with φ(entity)
      else:
          update last_seen and confidence in φ(entity)

  for each relation implied by e:
      if edge not in E:
          add edge with ψ(edge)
      else:
          increment event_count and update timestamp interval

  if d exists:
      add or update drift node
      add violated_contract edge from responsible entity candidates
```

Complexity:

- Time: `O(k log |V| + r log |E|)` with indexed graph storage, where `k` is entities and `r` is relations per event.
- Space: `O(|V| + |E|)` per graph snapshot.

Failure cases:

- High-cardinality file paths inflate graph size.
- Identity ambiguity creates low-confidence edges.
- Event loss weakens causal paths.

Mitigation:

- Path normalization.
- Confidence-weighted edges.
- Snapshot quality metadata.

## 7. Causal Attribution Pipeline

### SCM Construction from G

PHANTOM converts BDG snapshots into a causal graph by mapping:

- Runtime behavior nodes to treatment variables.
- Contract drift nodes to outcome variables.
- Workload metadata, image digest, service account, namespace, and baseline behavior to covariates.
- Temporal precedence constrains edge direction.

DoWhy `CausalModel` is conceptually constructed as:

```text
model:
  treatment = S
  outcome = D
  common_causes = workload_baseline, namespace, image_digest, service_account, prior_drift
  effect_modifiers = package_criticality, privilege_level, network_exposure
  graph = temporal_projection(G)
```

### Meaning of `P(D | do(S))`

`S` is a suspicious runtime behavior, such as:

```text
unexpected_process_spawn
unexpected_network_destination
unexpected_package_activation
privilege_transition
```

`D` is observed SBOM/behavioral contract drift.

`P(D | do(S))` asks:

> What is the probability of drift if PHANTOM intervenes and forces suspicious behavior `S` to occur, holding confounders according to the causal model?

This is not the same as `P(D | S)`, which may be confounded by workload type, namespace policy, image family, or prior compromise.

### Counterfactual Computation

For an incident:

```text
Observed world:
  S = 1, D = 1

Counterfactual world:
  S := 0
  covariates unchanged where causally valid
  estimate D'
```

Attribution confidence is derived from:

```text
causal_effect = P(D | do(S=1)) - P(D | do(S=0))
```

Output schema:

```text
AttributionRecord:
  attribution_id: UUID
  incident_id: UUID
  treatment: string
  outcome: string
  causal_effect: float in [-1, 1]
  confidence: float in [0, 1]
  estimand_type: string
  estimator: string
  refutation_results: list
  graph_snapshot_id: UUID
  evidence_event_ids: list[UUID]
  identifiability_status: identifiable | partially_identifiable | not_identifiable
  uncertainty_reason: string | null
```

Failure cases:

- Cyclic graph without temporal ordering.
- Unobserved confounding.
- Sparse treatment observations.
- Identity ambiguity.

Mitigation:

- Temporal DAG projection.
- Refutation tests.
- Confidence penalty.
- "Not identifiable" as a valid output.

## 8. PCEPS Feature Vector

PCEPS means PHANTOM Causal Exploitability Priority Score.

| Feature | Type / Range | Source | Why Predictive | Missing Handling |
|---|---|---|---|---|
| `causal_effect` | float `[-1,1]` | Causal engine | Measures estimated causal contribution. | Set `0`, add missing flag. |
| `attribution_confidence` | float `[0,1]` | Causal engine | Penalizes weak evidence. | Set `0`. |
| `contract_violation_count` | int `[0,∞)` | Validator | More violations imply stronger drift. | Set `0`. |
| `new_process_count` | int `[0,∞)` | eBPF/BDG | Unexpected process creation is common compromise evidence. | Window median. |
| `unexpected_network_count` | int `[0,∞)` | eBPF/BDG | External communication often indicates payload or exfiltration. | Set `0`. |
| `privilege_transition` | bool | eBPF/BDG | Privilege changes increase severity. | Set `false`, missing flag. |
| `sensitive_file_access_count` | int `[0,∞)` | eBPF/BDG | Reads of secrets/configs indicate impact. | Set `0`. |
| `sbom_component_criticality` | ordinal `[0,5]` | SBOM resolver | Runtime drift in critical packages has higher risk. | Unknown = `2`. |
| `image_signature_valid` | bool | Cosign verifier | Unsigned/invalid images weaken supply-chain trust. | `false`. |
| `namespace_risk_weight` | float `[0,1]` | Kubernetes metadata | Production/system namespaces are higher impact. | Default `0.5`. |
| `service_account_privilege` | ordinal `[0,5]` | RBAC analyzer | More permissions imply higher blast radius. | Unknown = `3`. |
| `event_loss_rate` | float `[0,1]` | Agent metrics | High loss lowers reliability. | Conservative `1.0`. |
| `graph_centrality_delta` | float `[0,∞)` | BDG | Sudden graph centrality changes indicate behavioral drift. | Set `0`. |
| `prior_drift_frequency` | float `[0,∞)` | PostgreSQL | Repeated drift changes incident interpretation. | Set `0`. |
| `runtime_component_novelty` | float `[0,1]` | SBOM/BDG | New package activation is direct SBOM drift signal. | Set `0.5`. |

Obvious alternative rejected: a pure CVSS/CVE-based score is insufficient because PHANTOM targets runtime drift, which may occur without a known CVE.

## 9. Security Architecture

### eBPF Verification Constraints

The kernel verifier enforces:

- Bounded loops.
- Valid memory access.
- Type-safe helper usage.
- Stack size limits.
- Map access constraints.
- Program termination.

It does not enforce:

- Semantic correctness of PHANTOM's event model.
- Absence of logical blind spots.
- Completeness of Kubernetes identity mapping.
- Trustworthiness of user-space processing.

### Pod RBAC Design

Minimum permissions:

| Component | Permissions | Justification |
|---|---|---|
| Node agent | read node-local runtime metadata; watch pods on its node | Needed for identity resolution. |
| API backend | read PHANTOM CRDs/config; read/write PHANTOM DB only | Serves UI and analysis. |
| SBOM resolver | read image metadata and SBOM references | Needed for digest-to-SBOM binding. |
| Contract validator | read contracts and workload metadata | Needed for policy evaluation. |

No component should have permission to mutate Kubernetes workloads.

### Cosign Runtime Verification Flow

1. Resolve image digest from pod status.
2. Locate SBOM attestation for digest.
3. Verify cosign signature and transparency log inclusion.
4. Verify signer identity against policy.
5. Hash canonical SBOM content.
6. Bind verified SBOM digest to workload identity.
7. Reject unsigned or unverifiable SBOMs from strong contract validation.

### Threat Model Exclusions

PHANTOM does not defend against:

- Fully compromised kernel.
- Malicious cloud administrator.
- Hardware attacks.
- eBPF-disabled or incompatible nodes.
- Perfectly behavior-preserving malicious package replacement.
- Attacks occurring entirely before PHANTOM deployment.
- Workloads intentionally granted excessive Kubernetes privileges.
- Encrypted payload semantics beyond observable endpoints/processes/files.

## 10. AWS EKS Deployment Topology

| Component | Kubernetes Form | Reason |
|---|---|---|
| eBPF node agent | DaemonSet | Must run on every monitored node. |
| Backend API | Deployment | Horizontally scalable stateless service. |
| Identity/SBOM workers | Deployment | Queue consumers; scale by Redis lag. |
| BDG/SCM/PCEPS workers | Deployment | CPU-bound analysis; independently scalable. |
| Contract refresh | CronJob | Periodic verification and cache refresh. |
| PostgreSQL | AWS RDS | Durable managed storage. |
| Redis | ElastiCache | Managed queue/cache. |
| Prometheus/Grafana | Helm-managed Deployments | Standard observability stack. |

Node group design:

- One standard application node group for workloads.
- One optional monitoring node group for PHANTOM backend workers.
- The DaemonSet still runs on all monitored workload nodes.
- Separation is justified when evaluation requires isolating PHANTOM overhead from workload performance.

Network policy:

- Node agents may egress only to backend ingestion API or Redis endpoint.
- Backend may access RDS, ElastiCache, and Kubernetes API.
- Frontend may access backend API only.
- Workers may access Redis, RDS, and approved cloud metadata endpoints.
- No PHANTOM component may initiate traffic to arbitrary workload pods.

## 11. Design Rationale

The architecture intentionally avoids a monolithic detector. A monolith would make it difficult to distinguish telemetry loss, identity failure, SBOM mismatch, contract violation, graph mutation, causal attribution failure, and scoring error. For a research paper, these must be separately measurable.

The obvious alternative is a Falco-style rule engine over runtime events. That is simpler, but it cannot support PHANTOM's core claim: causal attribution of runtime SBOM drift. PHANTOM instead produces a graph-backed causal explanation with explicit uncertainty.

## 12. Complexity Analysis

| Stage | Time Complexity | Space Complexity |
|---|---:|---:|
| Event normalization | `O(1)` per event | `O(1)` per event |
| Identity cache lookup | `O(1)` expected | `O(P+C)` pods and containers |
| SBOM component lookup | `O(log S)` indexed, `S` components | `O(S)` per image |
| Contract validation | `O(R)` rules per event class | `O(R)` |
| BDG mutation | `O(k log V + r log E)` | `O(V+E)` |
| SCM construction | `O(V+E)` per snapshot | `O(V+E)` |
| Causal estimation | estimator-dependent; at least `O(nf)` | `O(nf)` |
| PCEPS inference | `O(Td)` for XGBoost trees/features | `O(d)` |

## 13. Failure Cases and Mitigations

| Failure | Impact | Mitigation |
|---|---|---|
| Ring buffer overflow | Missing runtime evidence | Emit loss metrics; reduce confidence. |
| Identity ambiguity | Weak attribution | Candidate sets and explicit uncertainty. |
| Missing SBOM | Cannot prove SBOM drift | Report as supply-chain evidence gap. |
| Invalid cosign signature | Contract unusable | Block strong validation. |
| Graph explosion | Slow attribution | Normalize paths, window snapshots. |
| Causal non-identifiability | No valid causal claim | Return `not_identifiable`. |
| XGBoost overfitting | Poor generalization | Separate evaluation workloads and ablations. |
| Kubernetes API lag | Stale identity mapping | Cache versioning and delayed reconciliation. |

## 14. Handoff Specification

HANDOFF TO CLAUDE CODE: implement the architecture using the following file layout and interfaces. Do not change component boundaries without explicit user approval.

```text
phantom/
  ebpf/
    phantom.bpf.c
    phantom.h
    user_agent.py
  backend/
    app/main.py
    app/schemas/events.py
    app/schemas/contracts.py
    app/schemas/graph.py
    app/schemas/causal.py
    app/schemas/incidents.py
    app/services/identity_resolver.py
    app/services/sbom_resolver.py
    app/services/contract_validator.py
    app/services/bdg_builder.py
    app/services/scm_builder.py
    app/services/causal_attribution.py
    app/services/pceps.py
  infra/
    helm/
    terraform/
  frontend/
    src/
```

Required interface definitions:

```text
function normalize_event(raw: RawRuntimeEvent) -> NormalizedRuntimeEvent

function resolve_identity(event: NormalizedRuntimeEvent) -> WorkloadIdentity

function resolve_sbom(identity: WorkloadIdentity) -> SBOMComponentBinding

function validate_contract(
  event: NormalizedRuntimeEvent,
  identity: WorkloadIdentity,
  binding: SBOMComponentBinding,
  contract: BehavioralContract
) -> DriftObservation | null

function update_bdg(
  graph_snapshot_id: UUID,
  event: NormalizedRuntimeEvent,
  identity: WorkloadIdentity,
  binding: SBOMComponentBinding | null,
  drift: DriftObservation | null
) -> GraphMutationResult

function build_scm(graph_snapshot_id: UUID) -> SCMDescriptor

function estimate_attribution(
  scm: SCMDescriptor,
  treatment: SuspiciousBehavior,
  outcome: DriftObservation
) -> AttributionRecord

function build_pceps_features(
  incident: IncidentCandidate,
  attribution: AttributionRecord,
  graph_snapshot_id: UUID
) -> PCEPSFeatureVector

function score_incident(features: PCEPSFeatureVector) -> IncidentPriorityScore
```

Claude Code must implement JSON schemas for all named data types before implementing services. Each pipeline stage must persist both successful outputs and uncertainty/failure metadata.

## ASSUMPTION LOG

A1: Kernel version is at least 5.8 — required for BPF ring buffer — validate using EKS AMI kernel inventory.

A2: cgroup IDs can be mapped reliably to container identity — necessary for pod attribution — validate with controlled pod churn experiments.

A3: Kubernetes pod status exposes immutable image digests — needed for SBOM binding — validate against EKS container runtime behavior.

A4: SBOM attestations exist for monitored images — required for strong drift claims — validate in CI/CD with Syft and cosign.

A5: Behavioral contracts can be learned or authored before enforcement — needed for comparison baseline — validate using benign workload training windows.

A6: Runtime package behavior can be meaningfully mapped to PURLs — central SBOM drift assumption — validate per language ecosystem.

A7: Temporal ordering is sufficient to orient causal graph edges — required for SCM construction — validate with synthetic attack timelines.

A8: Unobserved confounding can be bounded but not eliminated — causal inference limitation — validate with DoWhy refutation tests.

A9: Event loss is measurable by the node agent — needed for confidence penalties — validate with stress tests.

A10: Network/file/process behavior is adequate evidence of meaningful SBOM drift — core research claim — validate with ablation studies.

A11: Redis ordering is sufficient within analysis windows — needed for pipeline consistency — validate with event sequence tests.

A12: PostgreSQL can sustain expected write volume — deployment assumption — validate with load testing.

A13: XGBoost scores are secondary prioritization, not causal proof — avoids overclaiming — validate with ablation against causal-only ranking.

A14: PHANTOM runs with enough privilege to attach eBPF programs — operational requirement — validate with EKS security policy review.

A15: The kernel is trusted — PHANTOM cannot observe truth below a compromised kernel — validate by stating threat-model exclusion.

✓ CODEX TASK 1 COMPLETE

HANDOFF DOC READY FOR CLAUDE CODE
