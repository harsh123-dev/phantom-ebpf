import type { ISOTimestamp, SHA256Digest, SchemaVersion, UUID } from "./common";

export type IncidentStatus = "draft" | "open" | "resolved" | "archived";
export type IncidentClassification = "untriaged" | "benign" | "suspicious" | "confirmed";

export interface IncidentCreateRequest {
  schema_version: SchemaVersion;
  title: string;
  summary: string;
  drift_event_ids: UUID[];
  attribution_ids: UUID[];
  score_ids: UUID[];
  snapshot_id: UUID;
  classification: IncidentClassification;
  tags: string[];
  tenant_id: UUID;
}

export interface IncidentReport {
  incident_id: UUID;
  revision: number;
  status: IncidentStatus;
  title: string;
  summary: string;
  classification: IncidentClassification;
  evidence_hash: SHA256Digest;
  score_ids?: UUID[];
  drift_event_ids?: UUID[];
  created_by: string;
  created_at: ISOTimestamp;
  updated_at: ISOTimestamp;
}

export interface IncidentDetailResponse {
  report: IncidentReport;
  drift_event_ids: UUID[];
  attribution_ids: UUID[];
  score_ids: UUID[];
  snapshot_id: UUID;
  tags: string[];
  resolution_notes: string | null;
  archived_at: ISOTimestamp | null;
}

export interface IncidentListParams {
  status?: IncidentStatus;
  classification?: IncidentClassification;
  created_after?: ISOTimestamp;
  created_before?: ISOTimestamp;
  limit?: number;
  cursor?: string | null;
}

export interface IncidentUpdateRequest {
  expected_revision: number;
  title?: string | null;
  summary?: string | null;
  classification?: IncidentClassification | null;
  status?: IncidentStatus | null;
  tags?: string[] | null;
  resolution_notes?: string | null;
}

export interface IncidentArchiveResponse {
  incident_id: UUID;
  status: "archived";
  archived_at: ISOTimestamp;
  revision: number;
}
