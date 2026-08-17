import type { ISOTimestamp, SHA256Digest, SchemaVersion, UUID } from "./common";

export type RuntimeEventType =
  | "exec"
  | "file_open"
  | "file_write"
  | "network_connect"
  | "network_accept"
  | "privilege_transition"
  | "namespace_change"
  | "module_load";
export type RuntimeSeverity = "low" | "medium" | "high" | "critical";
export type IdentityStatus = "resolved" | "ambiguous" | "missing" | "stale";
export type ViolationType =
  | "unexpected_executable"
  | "unexpected_file"
  | "unexpected_network"
  | "unexpected_syscall_class"
  | "unexpected_purl"
  | "unexpected_process_relation"
  | "privilege_transition"
  | "rate_limit";

export interface ProcessIdentity {
  pid: number;
  tgid: number;
  ppid: number;
  uid: number;
  gid: number;
  comm: string;
  executable_path: string;
  start_time_ns: number;
}

export interface WorkloadIdentity {
  cluster_name: string;
  namespace: string;
  pod_name: string;
  pod_uid: UUID;
  container_name: string;
  container_id: string;
  image_digest: SHA256Digest;
  cgroup_id: number;
  service_account: string | null;
}

export interface SbomBinding {
  sbom_id: UUID;
  purl: string;
  binding_confidence: number;
  binding_status: "resolved" | "ambiguous" | "missing";
}

export interface ContractViolation {
  violation_type: ViolationType;
  expected: string | null;
  observed: string;
  severity: RuntimeSeverity;
  confidence: number;
}

export interface RuntimeEvidence {
  kernel_timestamp_ns: number;
  cpu: number;
  architecture: "x86_64" | "arm64";
  event_loss_observed: boolean;
  correlation_id: UUID | null;
  raw_event_digest: SHA256Digest;
}

export interface DriftEventIngestRequest {
  schema_version: SchemaVersion;
  event_id: UUID;
  observed_at: ISOTimestamp;
  node_name: string;
  event_type: RuntimeEventType;
  process: ProcessIdentity;
  workload: WorkloadIdentity;
  identity_status: IdentityStatus;
  sbom_binding: SbomBinding | null;
  violations: ContractViolation[];
  evidence: RuntimeEvidence;
  agent_sequence: number;
  tenant_id: UUID;
}

export interface DriftEventRecord {
  drift_event_id: UUID;
  event_id: UUID;
  bdg_update_id: UUID;
  ingestion_status: "accepted" | "duplicate";
  received_at: ISOTimestamp;
}

export interface DriftEventDetailResponse extends DriftEventIngestRequest {
  drift_event_id: UUID;
}
