export type UUID = string;
export type ISOTimestamp = string;
export type SHA256Digest = string;
export type SchemaVersion = "v1";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export interface ErrorResponse {
  schema_version: SchemaVersion;
  error_code: string;
  message: string;
  request_id: UUID;
  details: Record<string, string | number | boolean | null>;
}

export interface PaginationParams {
  limit: number;
  cursor: string | null;
}

export interface PaginatedResponse<T> {
  items: T[];
  next_cursor: string | null;
}

export interface HealthResponse {
  status: "ok";
  service: string;
  timestamp: ISOTimestamp;
}

export interface ReadinessResponse {
  status: "ready" | "not_ready";
  service: string;
  checks: Record<string, "pass" | "fail" | "not_applicable">;
  timestamp: ISOTimestamp;
}
