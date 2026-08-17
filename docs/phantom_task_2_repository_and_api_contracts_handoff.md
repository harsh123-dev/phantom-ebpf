# PHANTOM Task 2: Repository Structure and API Contracts Handoff

Full title: "PHANTOM: Causal Attribution of Runtime SBOM Drift via eBPF Behavioral Contracts in Kubernetes"

This document is the final implementation blueprint for CODEX TASK 2. Claude Code shall implement it exactly and shall not infer additional public APIs, services, or directories.

## 1. Research Framing

This repository structure operationalizes PHANTOM's separation of measurement, trusted artifact interpretation, graph construction, causal reasoning, and analyst presentation. That separation is a methodological control: it allows the evaluation to measure collection loss, mapping uncertainty, contract precision, graph-update latency, causal identifiability, and prioritization performance independently. The API is deliberately gateway-owned so an experiment can replay the same immutable event and graph inputs without coupling the eBPF data plane to the user interface.

## 2. Formal Definitions

Let `E_r` be the ordered set of normalized runtime events accepted by the gateway, `I` be workload identity bindings, `B` be image-digest-to-PURL SBOM bindings, `BC` be verified behavioral contracts, `G` be a versioned Behavioral Dependency Graph (BDG), `A` be causal attribution records, and `R` be incident reports. The service composition is:

`E_r x I x B x BC -> D -> G -> A -> P -> R`

where `D` is a drift observation and `P` is a PCEPS score. Every persisted entity has an immutable UUID, UTC RFC 3339 timestamp, `schema_version: Literal["v1"]`, and `tenant_id: UUID`. The tenant identifier is a logical isolation key; the initial deployment may use one tenant but must retain it for multi-namespace evaluation isolation.

## 3. Design Rationale

The monorepo is chosen because the research artifact requires atomic evolution of event schemas across eBPF, gateway, causal engine, Helm charts, and evaluation scripts. It is not a claim that a production organization must use a monorepo. Separating services remains necessary because the eBPF agent has privileged node execution, causal estimation is CPU/memory-intensive and asynchronous, and SBOM verification has distinct trust and artifact-retention concerns.

The obvious alternative, a single FastAPI process that reads eBPF events and performs graph/causal work synchronously, is worse: it mixes a privileged data plane with an internet-facing control plane, makes ingestion tail latency depend on DoWhy/XGBoost work, and prevents reliable replay experiments.

## Part A: Repository Blueprint

### A.1 Exact Monorepo Tree

```text
phantom/
|-- README.md                              # Project entry point and reproducibility overview.
|-- LICENSE                                # Project license.
|-- .gitignore                             # Repository-specific ignore rules.
|-- .env.example                           # Names only of required environment variables; no secrets.
|-- docs/                                  # Immutable Codex task handoffs and paper-facing design records.
|   |-- phantom_task_1_architecture_handoff.md
|   `-- phantom_task_2_repository_and_api_contracts_handoff.md
|-- services/                              # Independently deployable PHANTOM services.
|   |-- sbom-service/                      # SBOM ingestion, CycloneDX validation, and cosign verification.
|   |   |-- pyproject.toml                  # Python 3.11 dependency and tool declaration.
|   |   |-- Dockerfile                      # Container build definition.
|   |   |-- app/                            # Python package root.
|   |   |   |-- domain/                     # Enterprise entities and invariants; no framework imports.
|   |   |   |-- application/                # Use cases and ports.
|   |   |   |-- infrastructure/             # PostgreSQL, object store, Syft, and cosign adapters.
|   |   |   `-- interface/                  # Internal FastAPI routers and dependency wiring.
|   |   `-- tests/                          # Unit, contract, and integration tests.
|   |-- ebpf-agent/                        # Privileged libbpf node collector and event transport.
|   |   |-- Dockerfile                      # Privileged agent image definition.
|   |   |-- include/                        # Shared BPF/user-space formal event headers.
|   |   |-- bpf/                            # CO-RE eBPF program source and map declarations.
|   |   |-- cmd/                            # User-space libbpf loader and ring-buffer reader.
|   |   `-- tests/                          # ABI and event-normalization tests.
|   |-- causal-engine/                     # BDG maintenance, SCM construction, DoWhy, and PCEPS work.
|   |   |-- pyproject.toml                  # Python 3.11 dependency and tool declaration.
|   |   |-- Dockerfile                      # Worker image definition.
|   |   |-- app/                            # Python package root.
|   |   |   |-- domain/                     # BDG, SCM, attribution, and feature invariants.
|   |   |   |-- application/                # Graph-update, attribution, and scoring use cases/ports.
|   |   |   |-- infrastructure/             # asyncpg, Redis Streams, NetworkX, DoWhy, XGBoost adapters.
|   |   |   `-- interface/                  # Worker consumers and internal health routes.
|   |   `-- tests/                          # Graph, causal, and feature-contract tests.
|   |-- api-gateway/                       # Public REST/WebSocket API and authorization boundary.
|   |   |-- pyproject.toml                  # Python 3.11 dependency and tool declaration.
|   |   |-- Dockerfile                      # Gateway image definition.
|   |   |-- app/                            # Python package root.
|   |   |   |-- domain/                     # API-owned entities, role policy, and error taxonomy.
|   |   |   |-- application/                # Command/query use cases and service ports.
|   |   |   |-- infrastructure/             # asyncpg, aioredis, HTTP/RPC client, auth adapters.
|   |   |   `-- interface/                  # FastAPI routers, Pydantic schemas, WebSocket endpoint.
|   |   `-- tests/                          # OpenAPI, authorization, and endpoint contract tests.
|   |-- report-generator/                  # Immutable incident evidence assembly and report rendering.
|   |   |-- pyproject.toml                  # Python 3.11 dependency and tool declaration.
|   |   |-- Dockerfile                      # Report-worker image definition.
|   |   |-- app/                            # Python package root.
|   |   |   |-- domain/                     # Report/evidence entities and rendering invariants.
|   |   |   |-- application/                # Report CRUD and generation use cases/ports.
|   |   |   |-- infrastructure/             # PostgreSQL, object-store, and renderer adapters.
|   |   |   `-- interface/                  # Worker consumer and internal health routes.
|   |   `-- tests/                          # Evidence-completeness and output-contract tests.
|   `-- contracts/                         # Versioned language-neutral JSON Schema API/event artifacts.
|       |-- http/                           # Canonical request/response schemas mirrored by Pydantic.
|       `-- events/                         # Redis Stream and WebSocket event schemas.
|-- frontend/                              # React, TypeScript, Tailwind, and D3 analyst application.
|   |-- package.json                        # Frontend dependency and script declaration.
|   |-- Dockerfile                          # Frontend image definition.
|   |-- src/                                # React source.
|   |   |-- api/                            # Typed gateway client.
|   |   |-- components/                     # Reusable UI components.
|   |   |-- features/                       # Drift, graph, attribution, and incident feature modules.
|   |   |-- routes/                         # Routed views.
|   |   |-- state/                          # Client state and WebSocket lifecycle.
|   |   `-- types/                          # Generated/manual contract-aligned TypeScript types.
|   `-- tests/                              # Frontend unit and end-to-end tests.
|-- infra/                                  # Deployable cloud and cluster configuration.
|   |-- terraform/                          # AWS EKS, ECR, RDS, ElastiCache, IAM, VPC, and observability IaC.
|   |   |-- modules/                        # Reusable Terraform modules.
|   |   `-- environments/                   # Environment compositions and variables.
|   |-- helm/                               # Helm charts and values for PHANTOM services.
|   |   |-- phantom-platform/               # Coordinated platform chart.
|   |   `-- observability/                  # Prometheus/Grafana chart values.
|   `-- k8s/                                # Raw cluster manifests intentionally outside Helm.
|       |-- policies/                       # NetworkPolicy and Pod Security-related manifests.
|       |-- rbac/                           # Service accounts, roles, and bindings.
|       `-- crds/                           # PHANTOM CRDs only if later explicitly approved; initially empty.
|-- research/                               # Reproducible paper experiments, not production services.
|   |-- notebooks/                          # Exploratory, read-only analysis notebooks.
|   |-- evaluation/                         # Repeatable experiment drivers, metrics, and figure generation.
|   `-- datasets/                           # Dataset manifests, provenance, and non-secret fixtures.
`-- .github/                               # GitHub automation configuration.
    `-- workflows/                          # CI and release workflow definitions.
```

No directory beyond those shown may be created. A directory named `infra/k8s/crds/` is present solely to make later CRD adoption explicit; it shall remain empty unless the project owner revises this blueprint.

### A.2 Clean Architecture Mapping

| Python service | Domain | Application | Infrastructure | Interface |
|---|---|---|---|---|
| `services/sbom-service/app` | CycloneDX artifact, PURL binding, verification state, contract invariants | ingest/retrieve/verify SBOM use cases and repository/verifier ports | asyncpg, artifact storage, Syft CLI, cosign CLI/API adapters | internal routers, Pydantic DTOs, dependency injection |
| `services/causal-engine/app` | BDG, SCM, treatment/outcome, attribution, PCEPS feature/value objects | graph mutation, SCM build, attribution and scoring use cases | asyncpg, Redis Streams, NetworkX, DoWhy, PyTorch backend, XGBoost | Redis consumers, worker entry points, health probe |
| `services/api-gateway/app` | roles, tenant scope, API error taxonomy, public resource entities | commands/queries and service ports | asyncpg, aioredis, authentication/JWKS, service HTTP clients | FastAPI routes, Pydantic models, WebSocket fan-out |
| `services/report-generator/app` | incident report, evidence reference, report status, immutability rules | create/read/update/archive/generate use cases | asyncpg, object storage, render/export adapter | Redis consumer, health probe |

`services/ebpf-agent/` is intentionally excluded: it is a C/libbpf component whose trust boundary is a privileged DaemonSet, not a Python Clean Architecture service. `services/contracts/` contains schemas only and no business logic.

### A.3 GitHub Actions Workflows

| Workflow file/name | Trigger | Purpose |
|---|---|---|
| `ci-contracts.yml` / Contract Compatibility | pull request; push to `main` | Validate JSON Schema, Pydantic/OpenAPI compatibility, and event ABI versioning. |
| `ci-python.yml` / Python Services | pull request; push to `main` | Lint, type-check, test, and build each Python service. |
| `ci-ebpf.yml` / eBPF Agent | pull request; push to `main` | Compile CO-RE objects against declared kernel-header matrix and run ABI tests. |
| `ci-frontend.yml` / Frontend | pull request; push to `main` | Type-check, test, and build the React application. |
| `ci-infra.yml` / Infrastructure Validation | pull request; push to `main` | Terraform format/validate/plan and Helm template/static manifest validation. |
| `security-supply-chain.yml` / Supply Chain | pull request; push to `main`; release tag | Generate SBOMs, scan dependencies, and sign release images/artifacts with cosign. |
| `research-reproducibility.yml` / Evaluation Reproducibility | manual dispatch; release tag | Run declared evaluation pipeline and preserve figures/metrics as artifacts. |
| `release.yml` / Release | version tag | Build, sign, publish images and versioned contract artifacts. |

## Part B: Public API Contracts

### B.1 Global Contract Rules

Base path: `/api/v1`. Media type: `application/json`. All UUID values use canonical RFC 4122 strings. All timestamps are timezone-aware RFC 3339 UTC strings. All digest fields use `sha256:<64 lowercase hexadecimal characters>`. Request bodies reject unknown fields. List endpoints support `limit: int` (1..200, default 50) and opaque `cursor: str | null`; response cursors are opaque. Gateway authorization roles are:

| Role | Authority |
|---|---|
| `phantom.agent` | Node-agent/service identity; event and drift ingestion only for its tenant. |
| `phantom.sbom_writer` | Submit and trigger verification of SBOM artifacts. |
| `phantom.analyst` | Read evidence, request attribution/PCEPS, create and edit reports. |
| `phantom.viewer` | Read-only access to tenant-scoped data and streams. |
| `phantom.admin` | All tenant-scoped actions, contract lifecycle control, report deletion. |

Common `ErrorResponse`: `schema_version: Literal["v1"]`, `error_code: str`, `message: str`, `request_id: UUID`, `details: dict[str, str | int | float | bool | None]`.

### B.2 SBOM Endpoints

#### `POST /api/v1/sboms`
Purpose: ingest one CycloneDX JSON SBOM associated with an immutable container image digest.
Auth: `phantom.sbom_writer` or `phantom.admin`.
Request `SbomIngestRequest`: `schema_version: Literal["v1"]`; `image_digest: str` matching digest rule; `artifact_uri: AnyUrl` (`https` or `s3` only); `cyclonedx_document: dict[str, object]` non-empty; `declared_sbom_digest: str` matching digest rule; `source: Literal["syft","external"]`; `generated_at: datetime`; `signature_bundle_uri: AnyUrl | None` (`https` or `s3`, required when `source="external"`); `tenant_id: UUID`.
Response `SbomRecord`: `sbom_id: UUID`; `image_digest: str`; `sbom_digest: str`; `format: Literal["CycloneDX"]`; `spec_version: str`; `component_count: int >= 0`; `verification_status: Literal["pending","verified","failed"]`; `created_at: datetime`.
Errors: `400` invalid CycloneDX/digest; `401` unauthenticated; `403` unauthorized tenant/role; `409` SBOM digest already bound to a different image digest; `413` body exceeds gateway limit; `422` validation failure.

#### `GET /api/v1/sboms/{sbom_id}`
Purpose: retrieve SBOM metadata and the canonical CycloneDX document.
Auth: `phantom.viewer` or higher.
Response `SbomDetailResponse`: `record: SbomRecord`; `cyclonedx_document: dict[str, object]`; `purl_count: int >= 0`; `signature_bundle_uri: str | None`; `verified_at: datetime | None`; `verification_error: str | None`.
Errors: `401` unauthenticated; `403` wrong tenant/role; `404` unknown SBOM.

#### `POST /api/v1/sboms/{sbom_id}/verification`
Purpose: enqueue or repeat cosign/Sigstore verification for the referenced SBOM attestation.
Auth: `phantom.sbom_writer` or `phantom.admin`.
Request `SbomVerificationRequest`: `expected_identity: str` (1..512 chars); `expected_issuer: AnyUrl`; `rekor_required: bool = true`.
Response `VerificationJobResponse`: `verification_job_id: UUID`; `sbom_id: UUID`; `status: Literal["queued","running","verified","failed"]`; `submitted_at: datetime`.
Errors: `401`; `403`; `404` unknown SBOM; `409` SBOM is currently under verification; `422` validation failure.

#### `GET /api/v1/sboms/{sbom_id}/verification`
Purpose: obtain the current or final SBOM signature verification result.
Auth: `phantom.viewer` or higher.
Response `SbomVerificationResponse`: `verification_job_id: UUID`; `sbom_id: UUID`; `status: Literal["queued","running","verified","failed"]`; `signing_identity: str | None`; `issuer: str | None`; `rekor_entry_uuid: UUID | None`; `verified_at: datetime | None`; `failure_reason: str | None`.
Errors: `401`; `403`; `404` no SBOM or verification record.

### B.3 Behavioral Contract Endpoints

#### `POST /api/v1/contracts`
Purpose: register a signed behavioral contract without activating it until signature verification succeeds.
Auth: `phantom.admin`.
Request `BehavioralContractRegisterRequest`: `schema_version: Literal["v1"]`; `image_digest: str` digest rule; `sbom_id: UUID`; `workload_selector: WorkloadSelector`; `constraints: BehavioralConstraints`; `valid_from: datetime`; `valid_until: datetime | None` (must be later than `valid_from`); `contract_version: str` regex `^[0-9]+\.[0-9]+\.[0-9]+$`; `signature_bundle_uri: AnyUrl`; `expected_signing_identity: str` (1..512); `expected_issuer: AnyUrl`; `tenant_id: UUID`.
`WorkloadSelector`: `cluster_name: str` (1..253); `namespace: str` DNS-label; `service_account: str | None`; `labels: dict[str, str]` max 32 entries.
`BehavioralConstraints`: `allowed_executables: list[str]` max 1024; `allowed_file_path_prefixes: list[str]` max 1024; `allowed_network_destinations: list[NetworkDestination]` max 1024; `allowed_syscall_classes: list[SyscallClass]` min 1 max 128; `allowed_purls: list[str]` max 4096; `allowed_parent_child_pairs: list[ProcessRelation]` max 1024; `allow_privilege_transition: bool`; `max_new_processes_per_5m: int` (0..1,000,000).
`NetworkDestination`: `protocol: Literal["tcp","udp"]`; `cidr: str` valid IPv4/IPv6 CIDR; `port_min: int` 1..65535; `port_max: int` 1..65535 and `>= port_min`.
`SyscallClass`: `Literal["process","file_read","file_write","network_connect","network_accept","namespace","privilege","module"]`.
`ProcessRelation`: `parent_executable: str`; `child_executable: str`.
Response `BehavioralContractRecord`: `contract_id: UUID`; `image_digest: str`; `sbom_id: UUID`; `contract_version: str`; `verification_status: Literal["pending","verified","failed"]`; `activation_status: Literal["inactive","active","expired","revoked"]`; `created_at: datetime`.
Errors: `400` semantic contract error; `401`; `403`; `409` duplicate active contract version/image; `422` validation failure.

#### `GET /api/v1/contracts/{contract_id}`
Purpose: retrieve one contract and its cryptographic/activation status.
Auth: `phantom.viewer` or higher.
Response `BehavioralContractDetailResponse`: `record: BehavioralContractRecord`; `workload_selector: WorkloadSelector`; `constraints: BehavioralConstraints`; `valid_from: datetime`; `valid_until: datetime | None`; `signature_bundle_uri: str`; `signing_identity: str | None`; `issuer: str | None`; `rekor_entry_uuid: UUID | None`; `revocation_reason: str | None`.
Errors: `401`; `403`; `404` unknown contract.

#### `GET /api/v1/contracts`
Purpose: look up contracts by image, workload scope, or lifecycle state.
Auth: `phantom.viewer` or higher.
Query `ContractLookupQuery`: `image_digest: str | None` digest rule; `namespace: str | None` DNS-label; `activation_status: Literal["inactive","active","expired","revoked"] | None`; `limit: int`; `cursor: str | None`; at least one of image digest, namespace, or activation status is required.
Response `ContractListResponse`: `items: list[BehavioralContractRecord]`; `next_cursor: str | None`.
Errors: `401`; `403`; `422` invalid or empty filter.

### B.4 Drift Event Ingestion

#### `POST /api/v1/drift-events`
Purpose: atomically persist one normalized drift observation and enqueue its BDG mutation.
Auth: `phantom.agent` or `phantom.admin`.
Request `DriftEventIngestRequest`: `schema_version: Literal["v1"]`; `event_id: UUID`; `observed_at: datetime`; `node_name: str` DNS-label; `event_type: RuntimeEventType`; `process: ProcessIdentity`; `workload: WorkloadIdentity`; `identity_status: Literal["resolved","ambiguous","missing","stale"]`; `sbom_binding: SbomBinding | None`; `violations: list[ContractViolation]` min 1 max 64; `evidence: RuntimeEvidence`; `agent_sequence: int >= 0`; `tenant_id: UUID`.
`RuntimeEventType`: `Literal["exec","file_open","file_write","network_connect","network_accept","privilege_transition","namespace_change","module_load"]`.
`ProcessIdentity`: `pid: int > 0`; `tgid: int > 0`; `ppid: int >= 0`; `uid: int >= 0`; `gid: int >= 0`; `comm: str` 1..16; `executable_path: str` 1..4096; `start_time_ns: int >= 0`.
`WorkloadIdentity`: `cluster_name: str`; `namespace: str`; `pod_name: str`; `pod_uid: UUID`; `container_name: str`; `container_id: str` 1..256; `image_digest: str`; `cgroup_id: int >= 0`; `service_account: str | None`.
`SbomBinding`: `sbom_id: UUID`; `purl: str` 1..2048; `binding_confidence: float` 0..1; `binding_status: Literal["resolved","ambiguous","missing"]`.
`ContractViolation`: `violation_type: Literal["unexpected_executable","unexpected_file","unexpected_network","unexpected_syscall_class","unexpected_purl","unexpected_process_relation","privilege_transition","rate_limit"]`; `expected: str | None`; `observed: str`; `severity: Literal["low","medium","high","critical"]`; `confidence: float` 0..1.
`RuntimeEvidence`: `kernel_timestamp_ns: int >= 0`; `cpu: int >= 0`; `architecture: Literal["x86_64","arm64"]`; `event_loss_observed: bool`; `correlation_id: UUID | None`; `raw_event_digest: str` digest rule.
Response `DriftEventRecord`: `drift_event_id: UUID`; `event_id: UUID`; `bdg_update_id: UUID`; `ingestion_status: Literal["accepted","duplicate"]`; `received_at: datetime`.
Errors: `400` inconsistent evidence; `401`; `403`; `409` same event ID has different canonical digest; `422`; `503` durable store unavailable (agent must retry with same event ID).

### B.5 BDG Query Endpoints

#### `GET /api/v1/bdg/nodes/{node_id}`
Purpose: retrieve a node from a named, immutable BDG snapshot.
Auth: `phantom.viewer` or higher.
Query `GraphSnapshotQuery`: `snapshot_id: UUID | None` (latest consistent snapshot when absent).
Response `BdgNodeResponse`: `snapshot_id: UUID`; `node: BdgNode`.
`BdgNode`: `node_id: UUID`; `node_type: Literal["workload","container","process","purl","file","network_endpoint","contract","drift_event"]`; `label: str`; `attributes: dict[str, str | int | float | bool | None]`; `first_seen_at: datetime`; `last_seen_at: datetime`; `confidence: float` 0..1.
Errors: `401`; `403`; `404` node/snapshot unavailable.

#### `GET /api/v1/bdg/edges/{edge_id}`
Purpose: retrieve one relationship from a named BDG snapshot.
Auth: `phantom.viewer` or higher.
Query: `GraphSnapshotQuery`.
Response `BdgEdgeResponse`: `snapshot_id: UUID`; `edge: BdgEdge`.
`BdgEdge`: `edge_id: UUID`; `source_node_id: UUID`; `target_node_id: UUID`; `edge_type: Literal["runs","executes","loads","reads","writes","connects_to","belongs_to","violates","derived_from"]`; `attributes: dict[str, str | int | float | bool | None]`; `first_seen_at: datetime`; `last_seen_at: datetime`; `observation_count: int >= 1`; `confidence: float` 0..1.
Errors: `401`; `403`; `404` edge/snapshot unavailable.

#### `POST /api/v1/bdg/subgraphs:query`
Purpose: return a bounded evidence subgraph for visualization, analysis, or report generation.
Auth: `phantom.viewer` or higher.
Request `SubgraphQueryRequest`: `snapshot_id: UUID | None`; `root_node_ids: list[UUID]` min 1 max 50; `max_hops: int` 0..6; `node_types: list[BdgNodeType] | None`; `edge_types: list[BdgEdgeType] | None`; `observed_after: datetime | None`; `observed_before: datetime | None` (must be after `observed_after`); `max_nodes: int` 1..5000.
Response `SubgraphResponse`: `snapshot_id: UUID`; `nodes: list[BdgNode]`; `edges: list[BdgEdge]`; `truncated: bool`; `query_hash: str` digest rule.
Errors: `401`; `403`; `404` requested snapshot absent; `413` expanded graph exceeds `max_nodes`; `422` invalid bounds.

### B.6 Causal Attribution Endpoints

#### `POST /api/v1/attributions`
Purpose: submit an asynchronous causal-effect estimation over one immutable BDG snapshot.
Auth: `phantom.analyst` or `phantom.admin`.
Request `AttributionRequest`: `schema_version: Literal["v1"]`; `snapshot_id: UUID`; `drift_event_id: UUID`; `treatment: TreatmentSpec`; `outcome: OutcomeSpec`; `covariates: list[CovariateSpec]` min 1 max 128; `estimator: Literal["backdoor.linear_regression","backdoor.propensity_score_matching","backdoor.generalized_linear_model"]`; `counterfactual_treatment_value: Literal[0,1]`; `tenant_id: UUID`.
`TreatmentSpec`: `variable: str` regex `^[A-Za-z][A-Za-z0-9_]{0,127}$`; `observed_value: Literal[0,1]`; `source_node_ids: list[UUID]` min 1 max 100.
`OutcomeSpec`: `variable: Literal["runtime_sbom_drift"]`; `observed_value: Literal[0,1]`; `target_node_ids: list[UUID]` min 1 max 100.
`CovariateSpec`: `variable: str` regex as above; `source: Literal["workload","container","process","purl","network","cluster","temporal"]`; `observed_value: float | int | str | bool | None`.
Response `AttributionJobResponse`: `attribution_id: UUID`; `status: Literal["queued","running","completed","not_identifiable","failed"]`; `snapshot_id: UUID`; `submitted_at: datetime`.
Errors: `400` treatment/outcome not representable in snapshot; `401`; `403`; `404` snapshot/drift missing; `409` identical active request; `422`; `503` causal worker unavailable.

#### `GET /api/v1/attributions/{attribution_id}`
Purpose: poll an attribution job and retrieve its final causal evidence.
Auth: `phantom.viewer` or higher.
Response `AttributionResultResponse`: `attribution_id: UUID`; `status: Literal["queued","running","completed","not_identifiable","failed"]`; `snapshot_id: UUID`; `drift_event_id: UUID`; `estimand: str | None`; `identified: bool`; `identification_method: str | None`; `average_treatment_effect: float | None`; `effect_ci_lower: float | None`; `effect_ci_upper: float | None`; `counterfactual_drift_probability: float | None` range 0..1; `attribution_confidence: AttributionConfidence | None`; `refutation_results: list[RefutationResult]`; `failure_reason: str | None`; `completed_at: datetime | None`.
`AttributionConfidence`: `score: float` 0..1; `data_coverage: float` 0..1; `identity_resolution_confidence: float` 0..1; `contract_verification_confidence: float` 0..1; `graph_temporal_consistency: float` 0..1; `refutation_stability: float` 0..1; `loss_penalty: float` 0..1; `explanation: list[str]` max 16.
`RefutationResult`: `method: Literal["random_common_cause","placebo_treatment_refuter","data_subset_refuter"]`; `passed: bool`; `effect_estimate: float | None`; `notes: str` max 2048.
Errors: `401`; `403`; `404` unknown attribution.

### B.7 PCEPS Endpoint

#### `POST /api/v1/pceps:scores`
Purpose: calculate a deterministic, versioned PCEPS priority score from a completed attribution and its linked evidence.
Auth: `phantom.analyst` or `phantom.admin`.
Request `PcepsScoreRequest`: `schema_version: Literal["v1"]`; `drift_event_id: UUID`; `attribution_id: UUID`; `model_version: str` 1..128; `allow_imputation: bool = true`; `tenant_id: UUID`.
Response `PcepsScoreResponse`: `score_id: UUID`; `drift_event_id: UUID`; `attribution_id: UUID`; `model_version: str`; `score: float` 0..100; `severity: Literal["informational","low","medium","high","critical"]`; `feature_completeness: float` 0..1; `imputed_features: list[str]`; `scored_at: datetime`.
Errors: `400` attribution not complete/identifiable; `401`; `403`; `404` evidence/model missing; `409` same evidence/model already scored; `422` imputation disallowed but needed.

### B.8 Incident Report Endpoints

#### `POST /api/v1/incidents`
Purpose: create a draft incident report referencing immutable drift, graph, attribution, and score evidence.
Auth: `phantom.analyst` or `phantom.admin`.
Request `IncidentCreateRequest`: `schema_version: Literal["v1"]`; `title: str` 1..240; `summary: str` 1..8000; `drift_event_ids: list[UUID]` min 1 max 1000; `attribution_ids: list[UUID]` max 1000; `score_ids: list[UUID]` max 1000; `snapshot_id: UUID`; `classification: Literal["untriaged","benign","suspicious","confirmed"]`; `tags: list[str]` max 32, each 1..64; `tenant_id: UUID`.
Response `IncidentReport`: `incident_id: UUID`; `revision: int >= 1`; `status: Literal["draft","open","resolved","archived"]`; `title: str`; `summary: str`; `classification: str`; `evidence_hash: str` digest rule; `created_by: str`; `created_at: datetime`; `updated_at: datetime`.
Errors: `400` evidence inconsistent or cross-tenant; `401`; `403`; `404` referenced evidence absent; `422` validation failure.

#### `GET /api/v1/incidents/{incident_id}`
Purpose: retrieve the current report revision and referenced evidence identifiers.
Auth: `phantom.viewer` or higher.
Response `IncidentDetailResponse`: `report: IncidentReport`; `drift_event_ids: list[UUID]`; `attribution_ids: list[UUID]`; `score_ids: list[UUID]`; `snapshot_id: UUID`; `tags: list[str]`; `resolution_notes: str | None`; `archived_at: datetime | None`.
Errors: `401`; `403`; `404` unknown incident.

#### `GET /api/v1/incidents`
Purpose: list tenant-scoped reports with bounded filtering.
Auth: `phantom.viewer` or higher.
Query `IncidentListQuery`: `status: Literal["draft","open","resolved","archived"] | None`; `classification: Literal["untriaged","benign","suspicious","confirmed"] | None`; `created_after: datetime | None`; `created_before: datetime | None`; `limit: int`; `cursor: str | None`.
Response `IncidentListResponse`: `items: list[IncidentReport]`; `next_cursor: str | None`.
Errors: `401`; `403`; `422` invalid time window.

#### `PATCH /api/v1/incidents/{incident_id}`
Purpose: create a new report revision with analyst-approved changes.
Auth: `phantom.analyst` or `phantom.admin`.
Request `IncidentUpdateRequest`: `expected_revision: int >= 1`; `title: str | None` 1..240; `summary: str | None` 1..8000; `classification: Literal["untriaged","benign","suspicious","confirmed"] | None`; `status: Literal["draft","open","resolved","archived"] | None`; `tags: list[str] | None` max 32; `resolution_notes: str | None` max 8000; at least one mutable field required.
Response `IncidentReport`.
Errors: `401`; `403`; `404`; `409` revision conflict; `422` validation failure.

#### `DELETE /api/v1/incidents/{incident_id}`
Purpose: archive an incident without deleting forensic evidence.
Auth: `phantom.admin`.
Response `IncidentArchiveResponse`: `incident_id: UUID`; `status: Literal["archived"]`; `archived_at: datetime`; `revision: int >= 1`.
Errors: `401`; `403`; `404`; `409` already archived.

### B.9 WebSocket and Probe Endpoints

#### `GET /api/v1/streams/drift` (WebSocket upgrade)
Purpose: deliver authenticated, tenant-scoped live drift notifications after durable acceptance.
Auth: bearer token during handshake; `phantom.viewer` or higher.
Client subscription `DriftStreamSubscribe`: `schema_version: Literal["v1"]`; `type: Literal["subscribe"]`; `namespace_filters: list[str]` max 64; `minimum_severity: Literal["low","medium","high","critical"]`; `resume_after_event_id: UUID | None`.
Server message `LiveDriftEvent`: `schema_version: Literal["v1"]`; `type: Literal["drift_event"]`; `stream_event_id: UUID`; `published_at: datetime`; `drift_event_id: UUID`; `event_type: RuntimeEventType`; `severity: Literal["low","medium","high","critical"]`; `namespace: str | None`; `pod_name: str | None`; `image_digest: str | None`; `identity_status: Literal["resolved","ambiguous","missing","stale"]`; `violation_types: list[str]`; `attribution_id: UUID | None`; `pceps_score: float | None` 0..100.
Errors/close codes: `4401` missing/invalid authentication; `4403` unauthorized tenant/role; `4408` invalid subscription payload; `1013` service overload, client must reconnect using resume ID.

#### `GET /healthz`
Purpose: liveness probe showing process event loop availability only.
Auth: none, cluster-internal only.
Response `HealthResponse`: `status: Literal["ok"]`; `service: str`; `timestamp: datetime`.
Errors: `503` process cannot serve requests.

#### `GET /readyz`
Purpose: readiness probe confirming all mandatory dependencies required by that service.
Auth: none, cluster-internal only.
Response `ReadinessResponse`: `status: Literal["ready","not_ready"]`; `service: str`; `checks: dict[str, Literal["pass","fail","not_applicable"]>`; `timestamp: datetime`.
Errors: `503` one or more mandatory dependencies fail.

## Part C: eBPF Ring-Buffer Event ABI

### C.1 ABI Rules

All fields are fixed-width and explicitly aligned. Strings are bounded fixed arrays and must be NUL-terminated when shorter than capacity. `event_header` appears first in every event. Kernel timestamps use `bpf_ktime_get_ns()` monotonic time and must be converted/correlated in user space; they are not wall-clock time. Event structs contain only data obtainable through verifier-safe helpers and CO-RE-compatible reads validated against target kernel BTF. Exact helper availability and attach-point context must be verified against the supported kernel matrix; this specification does not assume undocumented kernel fields.

```c
/* PSEUDOCODE ONLY: formal ABI, not compilable C. */
enum phantom_event_type : u16 {
  PHANTOM_EVT_EXEC = 1,
  PHANTOM_EVT_FILE_OPEN = 2,
  PHANTOM_EVT_FILE_WRITE = 3,
  PHANTOM_EVT_NET_CONNECT = 4,
  PHANTOM_EVT_NET_ACCEPT = 5,
  PHANTOM_EVT_PRIVILEGE = 6,
  PHANTOM_EVT_NAMESPACE = 7,
  PHANTOM_EVT_MODULE_LOAD = 8,
  PHANTOM_EVT_LOSS = 9
};

struct phantom_event_header {
  u16 abi_version;          /* ABI decoder compatibility. */
  u16 event_type;           /* Discriminant selecting payload struct. */
  u32 total_size;           /* Defensive user-space record-size validation. */
  u64 event_id_hi;          /* First half of agent-generated correlation UUID. */
  u64 event_id_lo;          /* Second half of agent-generated correlation UUID. */
  u64 kernel_timestamp_ns;  /* Monotonic ordering of kernel observations. */
  u64 cgroup_id;            /* Primary cgroup-to-container identity join key. */
  u64 pid_start_time_ns;    /* Disambiguates PID reuse when derivable safely. */
  u32 pid;                  /* Observed thread identifier. */
  u32 tgid;                 /* Process identifier for thread aggregation. */
  u32 ppid;                 /* Parent process correlation. */
  u32 uid;                  /* Effective user identity evidence. */
  u32 gid;                  /* Effective group identity evidence. */
  u32 cpu;                  /* Per-CPU loss and ordering diagnostics. */
  char comm[16];            /* Kernel task command for rapid triage. */
};

struct phantom_exec_event {
  struct phantom_event_header header; /* Required common provenance. */
  u32 parent_tgid;                   /* Parent process relation validation. */
  u32 argc;                          /* Invocation shape without full argv capture. */
  u32 exec_flags;                    /* Exec-specific flags when attach context exposes them. */
  char executable_path[PATH_MAX];    /* Contract executable allow-list comparison. */
  char argv_digest[65];              /* SHA-256 digest of bounded argv representation; limits secret capture. */
};

struct phantom_file_open_event {
  struct phantom_event_header header; /* Required common provenance. */
  s32 fd;                            /* Result descriptor; negative denotes failure. */
  u32 open_flags;                    /* Read/write/create intent for contract semantics. */
  u32 mode;                          /* File creation mode when applicable. */
  u32 syscall_result;                /* Raw result for success/failure interpretation. */
  char path[PATH_MAX];               /* Canonicalized/bounded path when safely available. */
};

struct phantom_file_write_event {
  struct phantom_event_header header; /* Required common provenance. */
  s32 fd;                            /* Target descriptor relation. */
  u32 requested_bytes;               /* Requested write size for behavioral rate analysis. */
  s64 result_bytes;                  /* Actual write result, including failure. */
  u64 file_inode;                    /* Stable target correlation when pathname changes. */
  u32 file_device_major;             /* Filesystem/device identity. */
  u32 file_device_minor;             /* Filesystem/device identity. */
  char path[PATH_MAX];               /* Contract path-prefix comparison and analyst evidence. */
};

struct phantom_network_event {
  struct phantom_event_header header; /* Required common provenance. */
  u8 direction;                      /* 1=connect, 2=accept; avoids separate ABI shape. */
  u8 address_family;                 /* AF_INET or AF_INET6 only; decoder rejects other values. */
  u8 protocol;                       /* IPPROTO_TCP or IPPROTO_UDP evidence. */
  u8 socket_type;                    /* SOCK_STREAM/SOCK_DGRAM context. */
  u16 local_port;                    /* Host-order source/listening port. */
  u16 remote_port;                   /* Host-order peer port for destination contract check. */
  u8 local_address[16];              /* IPv4 mapped/IPv6 local endpoint, fixed ABI width. */
  u8 remote_address[16];             /* IPv4 mapped/IPv6 remote endpoint, fixed ABI width. */
  s32 syscall_result;                /* Connection/accept success or failure. */
};

struct phantom_privilege_event {
  struct phantom_event_header header; /* Required common provenance. */
  u32 previous_uid;                  /* Pre-transition effective UID. */
  u32 new_uid;                       /* Post-transition effective UID. */
  u32 previous_gid;                  /* Pre-transition effective GID. */
  u32 new_gid;                       /* Post-transition effective GID. */
  u64 capability_effective_before;   /* Capability delta analysis. */
  u64 capability_effective_after;    /* Capability delta analysis. */
  u32 transition_kind;               /* set*id/capability/credential operation category. */
};

struct phantom_namespace_event {
  struct phantom_event_header header; /* Required common provenance. */
  u32 namespace_type;                /* CLONE_NEW* category or namespace inode class. */
  u32 operation;                     /* setns/unshare/clone operation category. */
  u64 previous_namespace_inode;      /* Before-state identity. */
  u64 target_namespace_inode;        /* Requested/after-state identity. */
  s32 syscall_result;                /* Operation success/failure. */
};

struct phantom_module_load_event {
  struct phantom_event_header header; /* Required common provenance. */
  u32 operation;                     /* finit_module/init_module/delete_module category. */
  s32 syscall_result;                /* Load/unload outcome. */
  char module_name[64];              /* Module identity if safely derivable. */
  char module_digest[65];            /* Optional user-space-resolved SHA-256, never fabricated in BPF. */
};

struct phantom_loss_event {
  struct phantom_event_header header; /* Required node/cgroup/CPU provenance; cgroup may be zero for global loss. */
  u64 dropped_since_last_report;     /* Explicitly quantifies observation loss. */
  u64 ring_buffer_reserve_failures;  /* Distinguishes reserve pressure from decoder errors. */
  u64 user_space_submit_failures;    /* Counts agent transport failure observed in user space. */
  u32 loss_scope;                    /* 1=CPU, 2=agent, 3=transport. */
};
```

`PATH_MAX` is an ABI constant selected at build time and recorded in `abi_version`; the agent shall not assume it is universally identical across all target build environments. Full argv, file content, environment variables, DNS names, and plaintext payloads are intentionally excluded to reduce verifier complexity, event size, credential exposure, and privacy risk.

## Part D: Prometheus Metrics Specification

| Name | Type | Labels | What it measures | Paper relevance |
|---|---|---|---|---|
| `phantom_ebpf_events_captured_total` | Counter | `node,event_type,program` | Events successfully emitted by eBPF. | Collection throughput denominator. |
| `phantom_ebpf_ringbuf_reserve_failures_total` | Counter | `node,cpu,event_type` | Ring-buffer reserve failures. | Direct measurement of kernel-side observation loss. |
| `phantom_agent_events_submitted_total` | Counter | `node,event_type,result` | Agent submission attempts classified accepted/retry/failed. | Separates capture from transport reliability. |
| `phantom_agent_event_queue_depth` | Gauge | `node` | Pending user-space events awaiting gateway submission. | Backpressure confounder. |
| `phantom_agent_event_lag_seconds` | Histogram | `node,event_type` | Kernel timestamp to gateway acceptance latency. | Timeliness of behavioral attribution. |
| `phantom_identity_resolution_total` | Counter | `status,source` | Resolved/ambiguous/missing/stale cgroup identities. | Quantifies identity uncertainty. |
| `phantom_sbom_verification_total` | Counter | `result,source` | Cosign verification outcomes. | Measures trusted-SBOM coverage. |
| `phantom_sbom_component_bindings_total` | Counter | `status` | PURL resolution outcomes. | Measures SBOM-to-runtime mapping completeness. |
| `phantom_contract_validation_total` | Counter | `result,violation_type,identity_status` | Allowed behavior and violations evaluated. | Contract precision/recall analysis input. |
| `phantom_contract_active_total` | Gauge | `namespace,verification_status` | Active contracts by scope and verification state. | Experimental policy coverage. |
| `phantom_drift_events_total` | Counter | `event_type,severity,identity_status` | Persisted drift observations. | Primary detection outcome count. |
| `phantom_bdg_nodes` | Gauge | `snapshot_id,node_type` | Nodes in a graph snapshot. | Graph scale characterization. |
| `phantom_bdg_edges` | Gauge | `snapshot_id,edge_type` | Edges in a graph snapshot. | Graph density/complexity characterization. |
| `phantom_bdg_update_duration_seconds` | Histogram | `mutation_trigger,result` | End-to-end graph mutation time. | Online feasibility evidence. |
| `phantom_bdg_snapshot_age_seconds` | Gauge | `tenant` | Age of latest queryable consistent snapshot. | Staleness bound for causal claims. |
| `phantom_causal_jobs_total` | Counter | `status,estimator` | Attribution job outcomes. | Identifiability and operational success rate. |
| `phantom_causal_estimation_duration_seconds` | Histogram | `estimator,status` | Causal estimate wall-clock time. | Causal-analysis scalability. |
| `phantom_causal_attribution_confidence` | Histogram | `confidence_band` | Distribution of final confidence scores. | Calibration and uncertainty reporting. |
| `phantom_causal_refutations_total` | Counter | `method,result` | DoWhy refutation pass/fail outcomes. | Robustness of causal claims. |
| `phantom_pceps_scoring_total` | Counter | `severity,imputation_used` | Successful score generation. | Prioritization coverage. |
| `phantom_pceps_feature_completeness` | Histogram | `model_version` | Fraction of non-imputed features per score. | ML validity under telemetry gaps. |
| `phantom_incident_reports_total` | Counter | `status,classification` | Report lifecycle transitions. | Analyst-facing incident yield. |
| `phantom_api_requests_total` | Counter | `route,method,status_code` | Gateway request outcomes. | API availability/control-plane confounder. |
| `phantom_api_request_duration_seconds` | Histogram | `route,method,status_code` | Gateway response latency. | UI/query feasibility evidence. |
| `phantom_redis_stream_lag` | Gauge | `stream,consumer_group` | Unacknowledged stream entries. | Pipeline backlog and replay risk. |
| `phantom_postgres_operation_duration_seconds` | Histogram | `operation,result` | Database operation latency. | Storage bottleneck characterization. |

Metrics labels must never include pod UID, container ID, executable path, PURL, raw IP address, incident ID, or other unbounded/high-cardinality identifiers. Such data belongs in PostgreSQL evidence, not Prometheus.

## 4. Pseudocode: Gateway Drift Ingestion Contract

Motivation: Durable event acceptance must precede asynchronous graph and causal work, preserving replayability and preventing a transient worker failure from losing forensic evidence.

```text
ALGORITHM AcceptDriftEvent(request, authenticated_principal):
  REQUIRE principal.role IN {phantom.agent, phantom.admin}
  VALIDATE request against DriftEventIngestRequest
  REQUIRE request.tenant_id == principal.tenant_id
  COMPUTE canonical_digest over request excluding transport-only fields
  BEGIN durable transaction
    IF event_id exists with a different canonical_digest THEN
      RETURN conflict
    IF event_id exists with same canonical_digest THEN
      RETURN duplicate acceptance record
    INSERT immutable normalized event and immutable drift observation
    INSERT graph mutation outbox record keyed by drift_event_id
  COMMIT durable transaction
  PUBLISH outbox record to Redis Stream with at-least-once delivery
  RETURN accepted record
```

Time complexity: `O(v + c)`, where `v` is bounded Pydantic/CycloneDX-related request validation cost and `c` is the number of violations (at most 64). Database uniqueness lookup is expected `O(log N)` with an index. Space complexity: `O(v + c)` for the accepted record; queue payload is `O(1)` references, not a duplicate full event.

Failure cases and mitigations: transaction failure returns `503` for agent retry with stable `event_id`; Redis publication failure leaves the outbox record for worker retry; duplicate delivery is idempotent by `drift_event_id`; incorrect agent clock does not reorder kernel evidence because `kernel_timestamp_ns` is retained; malformed or identity-ambiguous evidence is retained with its uncertainty state rather than silently discarded.

The obvious alternative, publishing to Redis before durable storage, is worse because a consumer acknowledgement could occur before evidence is durable, destroying auditability and undermining experimental replay.

## 5. Failure Cases and Mitigations

| Failure | Effect | Required mitigation |
|---|---|---|
| eBPF verifier rejects a program | Specific event class absent. | Fail DaemonSet readiness; publish explicit capability status; do not claim coverage for absent class. |
| Ring-buffer pressure | Unobserved behavior and biased graph. | Emit loss events/metrics; attach loss penalty to attribution confidence; retain per-CPU diagnostics. |
| Cgroup-to-pod mapping ambiguous | Potentially wrong workload/SBOM association. | Persist `identity_status=ambiguous`; prohibit high-confidence component attribution; preserve candidates only internally. |
| No signed SBOM/contract | Expected-behavior baseline unavailable. | Store event, mark contract state unavailable, do not assert SBOM drift from that evidence alone. |
| Contract signature verification fails | Untrusted policy could suppress true behavior. | Keep contract inactive; report verification reason; never apply it as allow-list. |
| Redis duplicate/reordered delivery | Repeated/stale graph mutation. | Idempotency key and event-time ordering window; immutable snapshot versions. |
| Causal DAG has cycle or lacks adjustment set | Effect not identifiable. | Return `not_identifiable`, not a numeric effect; record diagnostic/reason. |
| PCEPS feature absent | Potential score distortion. | Explicit imputation only when allowed; expose missing names and completeness; confidence never increases through imputation. |
| Gateway unavailable | Agent cannot submit events. | Bounded local queue and stable-event-ID retry; explicit loss accounting after saturation. |

## 6. Assumptions for IEEE/ACM Review

1. Kernel >= 5.8 and BTF/CO-RE capabilities required by selected programs exist on study nodes. Validate with the declared kernel compile/attach matrix.
2. A cgroup ID plus agent-maintained Kubernetes/CRI metadata resolves the responsible workload frequently enough for meaningful analysis. Validate with ground-truth pod/container instrumentation and report status distribution.
3. Image digests reported by Kubernetes are immutable and can be linked to the verified SBOM. Validate with ECR manifest and pod-status cross-checks.
4. CycloneDX PURLs offer sufficiently precise component identity for the evaluated images. Validate against manually curated image/component truth sets.
5. Behavioral contracts represent expected runtime behavior rather than merely historical normality. Validate with holdout benign workload executions and policy review.
6. Runtime ordering plus specified covariates makes selected causal effects identifiable. Validate through DoWhy identification/refutation outputs and controlled interventions.
7. Unmeasured confounding is bounded but not eliminated. State this explicitly in paper limitations and conduct sensitivity/refutation analyses.
8. The Redis outbox/consumer model provides at-least-once delivery; it does not provide global exactly-once processing. Validate idempotency under replay/fault injection.
9. Prometheus metrics do not materially interfere with the collection workload. Validate overhead with observability enabled/disabled.
10. XGBoost is used only for priority ranking; it is not evidence of causation. Validate/report causal and predictive results separately.

## 7. HANDOFF TO CLAUDE CODE

Implement this exact repository structure.
Do not create directories not listed here.
Do not create files not implied by this structure.
The API contracts in Part B are the exact Pydantic models to implement.

Implementation constraints:

1. Create every listed service with the exact Clean Architecture directories. Keep framework imports out of each `domain/` directory.
2. Make `services/contracts/http/` and `services/contracts/events/` the canonical versioned JSON Schema artifacts. Gateway Pydantic models must reject unknown request fields and mirror them exactly.
3. Expose only the gateway's `/api/v1` endpoints publicly. `sbom-service`, `causal-engine`, and `report-generator` internal interfaces must not be internet-facing.
4. Implement drift ingestion using a PostgreSQL transactional outbox and idempotency by `event_id`; do not acknowledge an event as accepted before durable commit.
5. Implement all eBPF ABI definitions in `services/ebpf-agent/include/`, and retain `abi_version` compatibility checks in `services/ebpf-agent/cmd/`. Do not capture payloads, environment variables, or full argv.
6. Make every causally relevant query use an immutable `snapshot_id`; return `not_identifiable` rather than inventing a causal effect.
7. Implement Prometheus metrics with exactly the metric names, types, and bounded labels specified above.
8. Preserve all uncertainty states (`identity_status`, binding status, verification state, loss) through database records, graph attributes, API responses, attribution confidence, reports, and WebSocket events.

✓ CODEX TASK 2 COMPLETE
HANDOFF DOC READY FOR CLAUDE CODE
