import type { ISOTimestamp, JsonObject, SHA256Digest, SchemaVersion, UUID } from "./common";

export type VerificationStatus = "pending" | "verified" | "failed";
export type SbomSource = "syft" | "external";

export interface SbomIngestRequest {
  schema_version: SchemaVersion;
  image_digest: SHA256Digest;
  artifact_uri: string;
  cyclonedx_document: JsonObject;
  declared_sbom_digest: SHA256Digest;
  source: SbomSource;
  generated_at: ISOTimestamp;
  signature_bundle_uri: string | null;
  tenant_id: UUID;
}

export interface SbomRecord {
  sbom_id: UUID;
  image_digest: SHA256Digest;
  sbom_digest: SHA256Digest;
  format: "CycloneDX";
  spec_version: string;
  component_count: number;
  verification_status: VerificationStatus;
  created_at: ISOTimestamp;
}

export interface SbomListParams {
  image_digest?: SHA256Digest;
  limit?: number;
  cursor?: string | null;
}

export interface SbomDetailResponse {
  record: SbomRecord;
  cyclonedx_document: JsonObject;
  purl_count: number;
  signature_bundle_uri: string | null;
  verified_at: ISOTimestamp | null;
  verification_error: string | null;
}

export interface SbomVerificationRequest {
  expected_identity: string;
  expected_issuer: string;
  rekor_required: boolean;
}

export interface VerificationJobResponse {
  verification_job_id: UUID;
  sbom_id: UUID;
  status: "queued" | "running" | "verified" | "failed";
  submitted_at: ISOTimestamp;
}

export interface SbomVerificationResponse {
  verification_job_id: UUID;
  sbom_id: UUID;
  status: "queued" | "running" | "verified" | "failed";
  signing_identity: string | null;
  issuer: string | null;
  rekor_entry_uuid: UUID | null;
  verified_at: ISOTimestamp | null;
  failure_reason: string | null;
}
