import type { ErrorResponse, LiveDriftEvent } from "../types/phantom";

export const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

export const isErrorResponse = (value: unknown): value is ErrorResponse =>
  isRecord(value) &&
  typeof value.error_code === "string" &&
  typeof value.message === "string" &&
  typeof value.request_id === "string" &&
  isRecord(value.details);

export const isLiveDriftEvent = (value: unknown): value is LiveDriftEvent =>
  isRecord(value) &&
  value.type === "drift_event" &&
  typeof value.stream_event_id === "string" &&
  typeof value.drift_event_id === "string" &&
  typeof value.published_at === "string" &&
  typeof value.event_type === "string" &&
  typeof value.severity === "string" &&
  typeof value.identity_status === "string" &&
  Array.isArray(value.violation_types);
