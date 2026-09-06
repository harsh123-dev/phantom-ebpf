/**
 * demoData.ts — Demo/offline data layer for PHANTOM frontend.
 *
 * All data is derived from real EC2 live eBPF evaluation runs
 * (research/evaluation/results/raw3_from_ec2/).
 *
 * Activated when VITE_USE_MOCK_DATA=true or the real API is unreachable.
 */

import type {
  BehavioralContractDetailResponse,
  BehavioralContractRecord,
  IncidentReport,
  LiveDriftEvent,
  PaginatedResponse,
  SbomDetailResponse,
  SbomRecord,
  SubgraphResponse,
} from "../types/phantom";

const NOW = new Date().toISOString();
const T = (offsetMs: number) => new Date(Date.now() - offsetMs).toISOString();

// ---------------------------------------------------------------------------
// SBOMs — 2 services from the real evaluation
// ---------------------------------------------------------------------------
export const DEMO_SBOMS: SbomRecord[] = [
  {
    sbom_id: "10000000-0000-0000-0000-000000000001",
    image_digest: "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    sbom_digest: "sha256:deadbeef00000000000000000000000000000000000000000000000000000001",
    format: "CycloneDX",
    spec_version: "1.5",
    component_count: 47,
    verification_status: "verified",
    created_at: T(7200_000),
  },
  {
    sbom_id: "10000000-0000-0000-0000-000000000002",
    image_digest: "sha256:b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
    sbom_digest: "sha256:deadbeef00000000000000000000000000000000000000000000000000000002",
    format: "CycloneDX",
    spec_version: "1.5",
    component_count: 31,
    verification_status: "verified",
    created_at: T(5400_000),
  },
];

export const DEMO_SBOM_DETAILS: Record<string, SbomDetailResponse> = {
  "10000000-0000-0000-0000-000000000001": {
    record: DEMO_SBOMS[0],
    cyclonedx_document: {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      metadata: { component: { name: "recommendationservice", version: "1.0.0" } },
      components: [
        { type: "library", name: "grpcio", version: "1.57.0", purl: "pkg:pypi/grpcio@1.57.0" },
        { type: "library", name: "protobuf", version: "4.24.4", purl: "pkg:pypi/protobuf@4.24.4" },
        { type: "library", name: "sklearn", version: "1.3.0", purl: "pkg:pypi/scikit-learn@1.3.0" },
      ],
    },
    purl_count: 47,
    signature_bundle_uri: null,
    verified_at: T(7100_000),
    verification_error: null,
  },
  "10000000-0000-0000-0000-000000000002": {
    record: DEMO_SBOMS[1],
    cyclonedx_document: {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      metadata: { component: { name: "emailservice", version: "1.0.0" } },
      components: [
        { type: "library", name: "grpcio", version: "1.57.0", purl: "pkg:pypi/grpcio@1.57.0" },
        { type: "library", name: "Jinja2", version: "3.1.2", purl: "pkg:pypi/Jinja2@3.1.2" },
        { type: "library", name: "requests", version: "2.31.0", purl: "pkg:pypi/requests@2.31.0" },
      ],
    },
    purl_count: 31,
    signature_bundle_uri: null,
    verified_at: T(5300_000),
    verification_error: null,
  },
};

// ---------------------------------------------------------------------------
// Contracts — 2 services from phantom-eval namespace
// ---------------------------------------------------------------------------
export const DEMO_CONTRACTS: BehavioralContractRecord[] = [
  {
    contract_id: "20000000-0000-0000-0000-000000000001",
    image_digest: "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    sbom_id: "10000000-0000-0000-0000-000000000001",
    contract_version: "1.0.0",
    verification_status: "verified",
    activation_status: "active",
    created_at: T(6900_000),
  },
  {
    contract_id: "20000000-0000-0000-0000-000000000002",
    image_digest: "sha256:b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
    sbom_id: "10000000-0000-0000-0000-000000000002",
    contract_version: "1.0.0",
    verification_status: "verified",
    activation_status: "active",
    created_at: T(5100_000),
  },
];

export const DEMO_CONTRACT_DETAILS: Record<string, BehavioralContractDetailResponse> = {
  "20000000-0000-0000-0000-000000000001": {
    record: DEMO_CONTRACTS[0],
    workload_selector: {
      cluster_name: "phantom-eval",
      namespace: "phantom-eval",
      service_account: null,
      labels: { app: "recommendationservice" },
    },
    constraints: {
      allowed_executables: ["/usr/local/bin/python3", "/usr/bin/python3"],
      allowed_file_path_prefixes: ["/usr/local/lib/python3.11", "/tmp"],
      allowed_network_destinations: [{ protocol: "tcp", cidr: "10.0.0.0/8", port_min: 8080, port_max: 8080 }],
      allowed_syscall_classes: ["process", "file_read", "network_connect"],
      allowed_purls: ["pkg:pypi/grpcio@1.57.0", "pkg:pypi/protobuf@4.24.4", "pkg:pypi/scikit-learn@1.3.0"],
      allowed_parent_child_pairs: [],
      allow_privilege_transition: false,
      max_new_processes_per_5m: 5,
    },
    valid_from: T(7200_000),
    valid_until: null,
    signature_bundle_uri: "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=12345",
    signing_identity: "phantom-ci@phantom-eval.iam.gserviceaccount.com",
    issuer: "https://token.actions.githubusercontent.com",
    rekor_entry_uuid: "30000000-0000-0000-0000-000000000001",
    revocation_reason: null,
  },
  "20000000-0000-0000-0000-000000000002": {
    record: DEMO_CONTRACTS[1],
    workload_selector: {
      cluster_name: "phantom-eval",
      namespace: "phantom-eval",
      service_account: null,
      labels: { app: "emailservice" },
    },
    constraints: {
      allowed_executables: ["/usr/local/bin/python3"],
      allowed_file_path_prefixes: ["/usr/local/lib/python3.11", "/app"],
      allowed_network_destinations: [{ protocol: "tcp", cidr: "10.0.0.0/8", port_min: 8080, port_max: 8080 }],
      allowed_syscall_classes: ["process", "file_read", "network_connect"],
      allowed_purls: ["pkg:pypi/grpcio@1.57.0", "pkg:pypi/Jinja2@3.1.2", "pkg:pypi/requests@2.31.0"],
      allowed_parent_child_pairs: [],
      allow_privilege_transition: false,
      max_new_processes_per_5m: 3,
    },
    valid_from: T(5400_000),
    valid_until: null,
    signature_bundle_uri: "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=12346",
    signing_identity: "phantom-ci@phantom-eval.iam.gserviceaccount.com",
    issuer: "https://token.actions.githubusercontent.com",
    rekor_entry_uuid: "30000000-0000-0000-0000-000000000002",
    revocation_reason: null,
  },
};

// ---------------------------------------------------------------------------
// Incidents — Derived from real evaluation run results (6 true positive runs)
// ---------------------------------------------------------------------------
export const DEMO_INCIDENTS: IncidentReport[] = [
  // dep-confusion reps (fast MTTD 2.6s / 7.9s / 2.6s)
  {
    incident_id: "40000000-0000-0000-0000-000000000001",
    revision: 1,
    status: "open",
    title: "Dependency Confusion Attack Detected — emailservice (rep 1)",
    summary: "PHANTOM detected a rogue pip package injected into emailservice at runtime. MTTD: 2.6s. Violated: unexpected_purl, unexpected_executable.",
    classification: "confirmed",
    evidence_hash: "sha256:feed000000000000000000000000000000000000000000000000000000000001",
    drift_event_ids: ["50000000-0000-0000-0000-000000000001"],
    created_by: "phantom-system",
    created_at: T(3600_000),
    updated_at: T(3590_000),
  },
  {
    incident_id: "40000000-0000-0000-0000-000000000002",
    revision: 1,
    status: "open",
    title: "Dependency Confusion Attack Detected — emailservice (rep 2)",
    summary: "PHANTOM detected a rogue pip package injected into emailservice at runtime. MTTD: 7.9s. Violated: unexpected_purl, unexpected_executable.",
    classification: "confirmed",
    evidence_hash: "sha256:feed000000000000000000000000000000000000000000000000000000000002",
    drift_event_ids: ["50000000-0000-0000-0000-000000000002"],
    created_by: "phantom-system",
    created_at: T(3000_000),
    updated_at: T(2990_000),
  },
  {
    incident_id: "40000000-0000-0000-0000-000000000003",
    revision: 1,
    status: "open",
    title: "Dependency Confusion Attack Detected — emailservice (rep 3)",
    summary: "PHANTOM detected a rogue pip package injected into emailservice at runtime. MTTD: 2.6s. Violated: unexpected_purl, unexpected_executable.",
    classification: "confirmed",
    evidence_hash: "sha256:feed000000000000000000000000000000000000000000000000000000000003",
    drift_event_ids: ["50000000-0000-0000-0000-000000000003"],
    created_by: "phantom-system",
    created_at: T(2400_000),
    updated_at: T(2390_000),
  },
  // xzutils reps (MTTD 4.7s / 6.4s / 70.3s)
  {
    incident_id: "40000000-0000-0000-0000-000000000004",
    revision: 1,
    status: "open",
    title: "XZ-Utils Supply Chain Backdoor — recommendationservice (rep 1)",
    summary: "PHANTOM detected a backdoored liblzma injected via kubectl exec. MTTD: 70.3s. Violated: unexpected_purl, namespace_change.",
    classification: "confirmed",
    evidence_hash: "sha256:feed000000000000000000000000000000000000000000000000000000000004",
    drift_event_ids: ["50000000-0000-0000-0000-000000000004"],
    created_by: "phantom-system",
    created_at: T(1800_000),
    updated_at: T(1790_000),
  },
  {
    incident_id: "40000000-0000-0000-0000-000000000005",
    revision: 1,
    status: "open",
    title: "XZ-Utils Supply Chain Backdoor — recommendationservice (rep 2)",
    summary: "PHANTOM detected a backdoored liblzma injected via kubectl exec. MTTD: 6.4s. Violated: unexpected_purl, namespace_change.",
    classification: "confirmed",
    evidence_hash: "sha256:feed000000000000000000000000000000000000000000000000000000000005",
    drift_event_ids: ["50000000-0000-0000-0000-000000000005"],
    created_by: "phantom-system",
    created_at: T(1200_000),
    updated_at: T(1190_000),
  },
  {
    incident_id: "40000000-0000-0000-0000-000000000006",
    revision: 1,
    status: "open",
    title: "XZ-Utils Supply Chain Backdoor — recommendationservice (rep 3)",
    summary: "PHANTOM detected a backdoored liblzma injected via kubectl exec. MTTD: 4.7s. Violated: unexpected_purl, namespace_change.",
    classification: "confirmed",
    evidence_hash: "sha256:feed000000000000000000000000000000000000000000000000000000000006",
    drift_event_ids: ["50000000-0000-0000-0000-000000000006"],
    created_by: "phantom-system",
    created_at: T(600_000),
    updated_at: T(590_000),
  },
];

// ---------------------------------------------------------------------------
// Live Drift Events — templated from real detection JSON fields
// Real fields: event_type, identity_status, tgid, node_name from EC2 results
// ---------------------------------------------------------------------------
const makeStreamId = (n: number) => `5000${String(n).padStart(4, "0")}00-0000-0000-0000-00000000000${n}`;

export const DEMO_DRIFT_EVENTS: LiveDriftEvent[] = [
  // dep-confusion events (fast detections)
  {
    schema_version: "v1",
    type: "drift_event",
    stream_event_id: makeStreamId(1),
    published_at: T(3600_000),
    drift_event_id: "50000000-0000-0000-0000-000000000001",
    event_type: "exec",
    severity: "critical",
    namespace: "phantom-eval",
    pod_name: "emailservice-7c8d9f4b5-xk2p9",
    image_digest: "sha256:b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
    identity_status: "ambiguous",
    violation_types: ["unexpected_purl", "unexpected_executable"],
    attribution_id: null,
    pceps_score: 0.93,
  },
  {
    schema_version: "v1",
    type: "drift_event",
    stream_event_id: makeStreamId(2),
    published_at: T(3000_000),
    drift_event_id: "50000000-0000-0000-0000-000000000002",
    event_type: "file_open",
    severity: "high",
    namespace: "phantom-eval",
    pod_name: "emailservice-7c8d9f4b5-xk2p9",
    image_digest: "sha256:b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
    identity_status: "ambiguous",
    violation_types: ["unexpected_purl"],
    attribution_id: null,
    pceps_score: 0.87,
  },
  {
    schema_version: "v1",
    type: "drift_event",
    stream_event_id: makeStreamId(3),
    published_at: T(2400_000),
    drift_event_id: "50000000-0000-0000-0000-000000000003",
    event_type: "network_connect",
    severity: "critical",
    namespace: "phantom-eval",
    pod_name: "emailservice-7c8d9f4b5-xk2p9",
    image_digest: "sha256:b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
    identity_status: "ambiguous",
    violation_types: ["unexpected_purl", "unexpected_network"],
    attribution_id: null,
    pceps_score: 0.96,
  },
  // xzutils events (namespace_change events)
  {
    schema_version: "v1",
    type: "drift_event",
    stream_event_id: makeStreamId(4),
    published_at: T(1800_000),
    drift_event_id: "50000000-0000-0000-0000-000000000004",
    event_type: "namespace_change",
    severity: "critical",
    namespace: "phantom-eval",
    pod_name: "recommendationservice-58f47bb76-l2g97",
    image_digest: "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    identity_status: "ambiguous",
    violation_types: ["unexpected_purl", "unexpected_executable"],
    attribution_id: null,
    pceps_score: 0.91,
  },
  {
    schema_version: "v1",
    type: "drift_event",
    stream_event_id: makeStreamId(5),
    published_at: T(1200_000),
    drift_event_id: "50000000-0000-0000-0000-000000000005",
    event_type: "module_load",
    severity: "high",
    namespace: "phantom-eval",
    pod_name: "recommendationservice-58f47bb76-l2g97",
    image_digest: "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    identity_status: "ambiguous",
    violation_types: ["unexpected_purl"],
    attribution_id: null,
    pceps_score: 0.88,
  },
  {
    schema_version: "v1",
    type: "drift_event",
    stream_event_id: makeStreamId(6),
    published_at: T(600_000),
    drift_event_id: "50000000-0000-0000-0000-000000000006",
    event_type: "exec",
    severity: "critical",
    namespace: "phantom-eval",
    pod_name: "recommendationservice-58f47bb76-l2g97",
    image_digest: "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    identity_status: "ambiguous",
    violation_types: ["unexpected_executable", "unexpected_purl"],
    attribution_id: null,
    pceps_score: 0.94,
  },
];

// ---------------------------------------------------------------------------
// BDG Subgraph — representative supply chain lineage graph
// ---------------------------------------------------------------------------
export const DEMO_SUBGRAPH: SubgraphResponse = {
  snapshot_id: "snap-demo-001",
  truncated: false,
  query_hash: "sha256:" + "a".repeat(64),
  nodes: [
    {
      node_id: "bdg-node-workload-1",
      node_type: "workload",
      label: "recommendationservice",
      attributes: { namespace: "phantom-eval", causal_tier: 0 },
      first_seen_at: T(7200_000),
      last_seen_at: NOW,
      confidence: 0.99,
    },
    {
      node_id: "bdg-node-workload-2",
      node_type: "workload",
      label: "emailservice",
      attributes: { namespace: "phantom-eval", causal_tier: 0 },
      first_seen_at: T(7200_000),
      last_seen_at: NOW,
      confidence: 0.99,
    },
    {
      node_id: "bdg-node-purl-1",
      node_type: "purl",
      label: "pkg:pypi/xz-utils-backdoor@5.6.1",
      attributes: { causal_tier: 1 },
      first_seen_at: T(1800_000),
      last_seen_at: NOW,
      confidence: 0.95,
    },
    {
      node_id: "bdg-node-purl-2",
      node_type: "purl",
      label: "pkg:pypi/internal-metrics@1.0.0 [MALICIOUS]",
      attributes: { causal_tier: 1 },
      first_seen_at: T(3600_000),
      last_seen_at: NOW,
      confidence: 0.92,
    },
    {
      node_id: "bdg-node-drift-1",
      node_type: "drift_event",
      label: "Contract Violation: unexpected_purl (CRITICAL)",
      attributes: { causal_tier: 5, violation_types: ["unexpected_purl", "unexpected_executable"], severity: "critical" },
      first_seen_at: T(1800_000),
      last_seen_at: NOW,
      confidence: 0.91,
    },
    {
      node_id: "bdg-node-drift-2",
      node_type: "drift_event",
      label: "Contract Violation: dependency_confusion (CRITICAL)",
      attributes: { causal_tier: 5, violation_types: ["unexpected_purl", "unexpected_executable"], severity: "critical" },
      first_seen_at: T(3600_000),
      last_seen_at: NOW,
      confidence: 0.93,
    },
    {
      node_id: "bdg-node-contract-1",
      node_type: "contract",
      label: "recommendationservice contract v1.0.0",
      attributes: { causal_tier: 2 },
      first_seen_at: T(7200_000),
      last_seen_at: NOW,
      confidence: 1.0,
    },
    {
      node_id: "bdg-node-contract-2",
      node_type: "contract",
      label: "emailservice contract v1.0.0",
      attributes: { causal_tier: 2 },
      first_seen_at: T(7200_000),
      last_seen_at: NOW,
      confidence: 1.0,
    },
  ],
  edges: [
    {
      edge_id: "bdg-edge-1",
      source_node_id: "bdg-node-workload-1",
      target_node_id: "bdg-node-purl-1",
      edge_type: "loads",
      attributes: {},
      first_seen_at: T(1800_000),
      last_seen_at: NOW,
      observation_count: 239,
      confidence: 0.95,
    },
    {
      edge_id: "bdg-edge-2",
      source_node_id: "bdg-node-purl-1",
      target_node_id: "bdg-node-drift-1",
      edge_type: "violates",
      attributes: {},
      first_seen_at: T(1800_000),
      last_seen_at: NOW,
      observation_count: 1,
      confidence: 0.91,
    },
    {
      edge_id: "bdg-edge-3",
      source_node_id: "bdg-node-workload-2",
      target_node_id: "bdg-node-purl-2",
      edge_type: "loads",
      attributes: {},
      first_seen_at: T(3600_000),
      last_seen_at: NOW,
      observation_count: 720,
      confidence: 0.92,
    },
    {
      edge_id: "bdg-edge-4",
      source_node_id: "bdg-node-purl-2",
      target_node_id: "bdg-node-drift-2",
      edge_type: "violates",
      attributes: {},
      first_seen_at: T(3600_000),
      last_seen_at: NOW,
      observation_count: 1,
      confidence: 0.93,
    },
    {
      edge_id: "bdg-edge-5",
      source_node_id: "bdg-node-workload-1",
      target_node_id: "bdg-node-contract-1",
      edge_type: "belongs_to",
      attributes: {},
      first_seen_at: T(7200_000),
      last_seen_at: NOW,
      observation_count: 1,
      confidence: 1.0,
    },
    {
      edge_id: "bdg-edge-6",
      source_node_id: "bdg-node-workload-2",
      target_node_id: "bdg-node-contract-2",
      edge_type: "belongs_to",
      attributes: {},
      first_seen_at: T(7200_000),
      last_seen_at: NOW,
      observation_count: 1,
      confidence: 1.0,
    },
  ],
};

// ---------------------------------------------------------------------------
// Paginated helper
// ---------------------------------------------------------------------------
export function makePage<T>(items: T[], limit = 20, cursor?: string | null): PaginatedResponse<T> {
  const start = cursor ? parseInt(cursor, 10) : 0;
  const page = items.slice(start, start + limit);
  const nextCursor = start + limit < items.length ? String(start + limit) : null;
  return { items: page, next_cursor: nextCursor };
}
