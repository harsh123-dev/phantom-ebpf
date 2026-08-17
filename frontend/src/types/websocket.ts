import type { ISOTimestamp, SchemaVersion, UUID } from "./common";
import type { IdentityStatus, RuntimeEventType, RuntimeSeverity } from "./drift";

export interface DriftStreamSubscribe {
  schema_version: SchemaVersion;
  type: "subscribe";
  namespace_filters: string[];
  minimum_severity: RuntimeSeverity;
  resume_after_event_id: UUID | null;
}

export interface LiveDriftEvent {
  schema_version: SchemaVersion;
  type: "drift_event";
  stream_event_id: UUID;
  published_at: ISOTimestamp;
  drift_event_id: UUID;
  event_type: RuntimeEventType;
  severity: RuntimeSeverity;
  namespace: string | null;
  pod_name: string | null;
  image_digest: string | null;
  identity_status: IdentityStatus;
  violation_types: string[];
  attribution_id: UUID | null;
  pceps_score: number | null;
}
