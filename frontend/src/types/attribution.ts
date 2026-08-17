import type { ISOTimestamp, SchemaVersion, UUID } from "./common";

export type EstimatorType =
  | "backdoor.linear_regression"
  | "backdoor.propensity_score_matching"
  | "backdoor.generalized_linear_model";
export type CovariateSource =
  | "workload"
  | "container"
  | "process"
  | "purl"
  | "network"
  | "cluster"
  | "temporal";
export type AttributionStatus =
  | "queued"
  | "running"
  | "completed"
  | "not_identifiable"
  | "failed";

export interface TreatmentSpec {
  variable: string;
  observed_value: 0 | 1;
  source_node_ids: UUID[];
}

export interface OutcomeSpec {
  variable: "runtime_sbom_drift";
  observed_value: 0 | 1;
  target_node_ids: UUID[];
}

export interface CovariateSpec {
  variable: string;
  source: CovariateSource;
  observed_value: string | number | boolean | null;
}

export interface AttributionRequest {
  schema_version: SchemaVersion;
  snapshot_id: UUID;
  drift_event_id: UUID;
  treatment: TreatmentSpec;
  outcome: OutcomeSpec;
  covariates: CovariateSpec[];
  estimator: EstimatorType;
  counterfactual_treatment_value: 0 | 1;
  tenant_id: UUID;
}

export interface AttributionJobResponse {
  attribution_id: UUID;
  status: AttributionStatus;
  snapshot_id: UUID;
  submitted_at: ISOTimestamp;
}

export interface AttributionConfidence {
  score: number;
  data_coverage: number;
  identity_resolution_confidence: number;
  contract_verification_confidence: number;
  graph_temporal_consistency: number;
  refutation_stability: number;
  loss_penalty: number;
  explanation: string[];
}

export interface RefutationResult {
  method: "random_common_cause" | "placebo_treatment_refuter" | "data_subset_refuter";
  passed: boolean;
  effect_estimate: number | null;
  notes: string;
}

export interface AttributionResultResponse {
  attribution_id: UUID;
  status: AttributionStatus;
  snapshot_id: UUID;
  drift_event_id: UUID;
  estimand: string | null;
  identified: boolean;
  identification_method: string | null;
  average_treatment_effect: number | null;
  effect_ci_lower: number | null;
  effect_ci_upper: number | null;
  counterfactual_drift_probability: number | null;
  attribution_confidence: AttributionConfidence | null;
  refutation_results: RefutationResult[];
  failure_reason: string | null;
  completed_at: ISOTimestamp | null;
}

export interface PcepsScoreRequest {
  schema_version: SchemaVersion;
  drift_event_id: UUID;
  attribution_id: UUID;
  model_version: string;
  allow_imputation: boolean;
  tenant_id: UUID;
}

export interface PcepsScoreResponse {
  score_id: UUID;
  drift_event_id: UUID;
  attribution_id: UUID;
  model_version: string;
  score: number;
  severity: "informational" | "low" | "medium" | "high" | "critical";
  feature_completeness: number;
  imputed_features: string[];
  scored_at: ISOTimestamp;
}
