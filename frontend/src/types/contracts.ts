/**
 * @fileoverview TypeScript type definitions aligned with PHANTOM API contracts.
 *
 * These types mirror the canonical JSON Schema definitions in
 * services/contracts/http/ and services/contracts/events/.
 * Types must be kept in sync with future schema changes.
 */

import type { ISOTimestamp, SHA256Digest, SchemaVersion, UUID } from "./common";

export type ActivationStatus = "inactive" | "active" | "expired" | "revoked";
export type SyscallClass =
  | "process"
  | "file_read"
  | "file_write"
  | "network_connect"
  | "network_accept"
  | "namespace"
  | "privilege"
  | "module";

export interface NetworkDestination {
  protocol: "tcp" | "udp";
  cidr: string;
  port_min: number;
  port_max: number;
}

export interface ProcessRelation {
  parent_executable: string;
  child_executable: string;
}

export interface BehavioralConstraints {
  allowed_executables: string[];
  allowed_file_path_prefixes: string[];
  allowed_network_destinations: NetworkDestination[];
  allowed_syscall_classes: SyscallClass[];
  allowed_purls: string[];
  allowed_parent_child_pairs: ProcessRelation[];
  allow_privilege_transition: boolean;
  max_new_processes_per_5m: number;
}

export interface WorkloadSelector {
  cluster_name: string;
  namespace: string;
  service_account: string | null;
  labels: Record<string, string>;
}

export interface BehavioralContractRegisterRequest {
  schema_version: SchemaVersion;
  image_digest: SHA256Digest;
  sbom_id: UUID;
  workload_selector: WorkloadSelector;
  constraints: BehavioralConstraints;
  valid_from: ISOTimestamp;
  valid_until: ISOTimestamp | null;
  contract_version: string;
  signature_bundle_uri: string;
  expected_signing_identity: string;
  expected_issuer: string;
  tenant_id: UUID;
}

export interface BehavioralContractRecord {
  contract_id: UUID;
  image_digest: SHA256Digest;
  sbom_id: UUID;
  contract_version: string;
  verification_status: "pending" | "verified" | "failed";
  activation_status: ActivationStatus;
  created_at: ISOTimestamp;
}

export interface BehavioralContractDetailResponse {
  record: BehavioralContractRecord;
  workload_selector: WorkloadSelector;
  constraints: BehavioralConstraints;
  valid_from: ISOTimestamp;
  valid_until: ISOTimestamp | null;
  signature_bundle_uri: string;
  signing_identity: string | null;
  issuer: string | null;
  rekor_entry_uuid: UUID | null;
  revocation_reason: string | null;
}

export interface ContractListParams {
  image_digest?: SHA256Digest;
  namespace?: string;
  activation_status?: ActivationStatus;
  limit?: number;
  cursor?: string | null;
}
