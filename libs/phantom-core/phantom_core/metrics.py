"""
phantom_core.metrics — Central Prometheus metric definitions for all PHANTOM services.

All Prometheus metrics for PHANTOM are defined here as module-level constants
to prevent duplicate registration and ensure consistent metric names and labels.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

# ===========================================================================
# === eBPF Collection ===
# ===========================================================================

# Measures the total number of kernel events successfully captured and emitted
# by eBPF programs. Incremented whenever an eBPF program emits an event to the ring buffer.
EBPF_EVENTS_CAPTURED = Counter(
    "phantom_ebpf_events_captured_total",
    "Events successfully emitted by eBPF programs",
    ["node", "event_type", "program"],
)
EBPF_EVENTS_CAPTURED_TOTAL = EBPF_EVENTS_CAPTURED

# Measures the number of failed ring-buffer reservation attempts in eBPF programs.
# Incremented when bpf_ringbuf_reserve fails due to buffer overflow or memory pressure.
EBPF_RINGBUF_RESERVE_FAILURES = Counter(
    "phantom_ebpf_ringbuf_reserve_failures_total",
    "Total failed eBPF ring buffer space reservations",
    ["node", "cpu", "event_type"],
)
EBPF_RINGBUF_RESERVE_FAILURES_TOTAL = EBPF_RINGBUF_RESERVE_FAILURES

# ===========================================================================
# === Agent Transport ===
# ===========================================================================

# Measures the total number of events submitted by the eBPF agent to downstream sinks.
# Incremented when the agent attempts to publish an event to Redis or REST endpoints.
AGENT_EVENTS_SUBMITTED = Counter(
    "phantom_agent_events_submitted_total",
    "Total events submitted by the eBPF agent to downstream transport",
    ["node", "event_type", "result"],
)
AGENT_EVENTS_SUBMITTED_TOTAL = AGENT_EVENTS_SUBMITTED

# Measures the current queue depth of events waiting to be dispatched by the agent.
# Observed/updated periodically or on enqueue/dequeue within the agent transport queue.
AGENT_EVENT_QUEUE_DEPTH = Gauge(
    "phantom_agent_event_queue_depth",
    "Current number of events waiting in the agent transport queue",
    ["node"],
)

# Measures the time lag in seconds between event occurrence in eBPF and submission by the agent.
# Observed whenever an event is dequeued and successfully submitted.
AGENT_EVENT_LAG = Histogram(
    "phantom_agent_event_lag_seconds",
    "Lag in seconds between event timestamp and agent submission",
    ["node", "event_type"],
)
AGENT_EVENT_LAG_SECONDS = AGENT_EVENT_LAG

# ===========================================================================
# === Identity and SBOM ===
# ===========================================================================

# Measures the total number of identity resolution attempts for Kubernetes workloads.
# Incremented whenever the identity resolver resolves a workload's identity from K8s metadata.
IDENTITY_RESOLUTION_TOTAL = Counter(
    "phantom_identity_resolution_total",
    "Total identity resolution attempts for Kubernetes workloads",
    ["status", "source"],
)
IDENTITY_RESOLUTION = IDENTITY_RESOLUTION_TOTAL

# Measures the total number of SBOM verification operations performed.
# Incremented when an SBOM signature or provenance claim is verified
# by cosign or verification service.
SBOM_VERIFICATION_TOTAL = Counter(
    "phantom_sbom_verification_total",
    "Total SBOM verification operations performed",
    ["result", "source"],
)
SBOM_VERIFICATION = SBOM_VERIFICATION_TOTAL

# Measures the total number of component bindings generated from verified SBOMs.
# Incremented when software components in an SBOM are bound to behavioral contracts.
SBOM_COMPONENT_BINDINGS_TOTAL = Counter(
    "phantom_sbom_component_bindings_total",
    "Total SBOM component bindings generated and registered",
    ["status"],
)
SBOM_COMPONENT_BINDINGS = SBOM_COMPONENT_BINDINGS_TOTAL

# ===========================================================================
# === Contract Validation ===
# ===========================================================================

# Measures the total number of runtime behavioral contract validation checks.
# Incremented each time a runtime event is checked against an active behavioral contract.
CONTRACT_VALIDATION_TOTAL = Counter(
    "phantom_contract_validation_total",
    "Total behavioral contract validation checks performed",
    ["result", "violation_type", "identity_status"],
)
CONTRACT_VALIDATION = CONTRACT_VALIDATION_TOTAL

# Measures the current number of active behavioral contracts in the cluster.
# Observed/updated when contracts are registered, updated, or removed in a namespace.
CONTRACT_ACTIVE_TOTAL = Gauge(
    "phantom_contract_active_total",
    "Current number of active behavioral contracts in the cluster",
    ["namespace", "verification_status"],
)
CONTRACT_ACTIVE = CONTRACT_ACTIVE_TOTAL

# ===========================================================================
# === Drift Detection ===
# ===========================================================================

# Measures the total number of drift events generated due to contract violations.
# Incremented when a runtime behavior deviates from the allowed behavioral contract.
DRIFT_EVENTS_TOTAL = Counter(
    "phantom_drift_events_total",
    "Total runtime drift events detected and generated",
    ["event_type", "severity", "identity_status"],
)
DRIFT_EVENTS = DRIFT_EVENTS_TOTAL

# ===========================================================================
# === Behavioral Dependency Graph ===
# ===========================================================================

# Measures the current number of nodes in a Behavioral Dependency Graph snapshot.
# Observed/updated whenever a new BDG snapshot is generated or updated.
BDG_NODES = Gauge(
    "phantom_bdg_nodes",
    "Current number of nodes in a Behavioral Dependency Graph snapshot",
    ["snapshot_id", "node_type"],
)

# Measures the current number of edges in a Behavioral Dependency Graph snapshot.
# Observed/updated whenever a new BDG snapshot is generated or updated.
BDG_EDGES = Gauge(
    "phantom_bdg_edges",
    "Current number of edges in a Behavioral Dependency Graph snapshot",
    ["snapshot_id", "edge_type"],
)

# Measures the duration in seconds to update or construct the Behavioral Dependency Graph.
# Observed whenever a BDG mutation or snapshot update operation completes.
BDG_UPDATE_DURATION = Histogram(
    "phantom_bdg_update_duration_seconds",
    "Duration in seconds to update the Behavioral Dependency Graph",
    ["mutation_trigger", "result"],
)
BDG_UPDATE_DURATION_SECONDS = BDG_UPDATE_DURATION

# Measures the age in seconds of the active Behavioral Dependency Graph snapshot.
# Observed/updated to track freshness of the BDG snapshot per tenant.
BDG_SNAPSHOT_AGE = Gauge(
    "phantom_bdg_snapshot_age_seconds",
    "Age in seconds of the current active BDG snapshot",
    ["tenant"],
)
BDG_SNAPSHOT_AGE_SECONDS = BDG_SNAPSHOT_AGE

# ===========================================================================
# === Causal Attribution ===
# ===========================================================================

# Measures the total number of causal attribution estimation jobs executed.
# Incremented when a causal attribution estimation job finishes (completed or not_identifiable).
CAUSAL_JOBS_TOTAL = Counter(
    "phantom_causal_jobs_total",
    "Total causal attribution estimation jobs executed",
    ["status", "estimator"],
)
CAUSAL_JOBS = CAUSAL_JOBS_TOTAL

# Measures the duration in seconds of causal attribution estimation runs.
# Observed after each causal estimation execution finishes.
CAUSAL_ESTIMATION_DURATION = Histogram(
    "phantom_causal_estimation_duration_seconds",
    "Duration in seconds of causal attribution estimation runs",
    ["estimator", "status"],
)
CAUSAL_ESTIMATION_DURATION_SECONDS = CAUSAL_ESTIMATION_DURATION

# Measures the distribution of causal attribution confidence scores (0.0 to 1.0).
# Observed when a causal attribution score is computed, categorized by confidence_band label.
CAUSAL_ATTRIBUTION_CONFIDENCE = Histogram(
    "phantom_causal_attribution_confidence",
    "Distribution of causal attribution confidence scores",
    ["confidence_band"],
)

# Measures the total number of causal refutation validation tests performed.
# Incremented after running a refutation test on an estimated causal model.
CAUSAL_REFUTATIONS_TOTAL = Counter(
    "phantom_causal_refutations_total",
    "Total causal refutation tests executed",
    ["method", "result"],
)
CAUSAL_REFUTATIONS = CAUSAL_REFUTATIONS_TOTAL

# ===========================================================================
# === PCEPS Scoring ===
# ===========================================================================

# Measures the total number of PCEPS priority and severity scoring evaluations performed.
# Incremented whenever a drift event or incident is scored using PCEPS.
PCEPS_SCORING_TOTAL = Counter(
    "phantom_pceps_scoring_total",
    "Total PCEPS scoring evaluations performed",
    ["severity", "imputation_used"],
)
PCEPS_SCORING = PCEPS_SCORING_TOTAL

# Measures the completeness ratio (0.0 to 1.0) of feature vectors used in PCEPS scoring.
# Observed during each PCEPS scoring evaluation to track feature availability.
PCEPS_FEATURE_COMPLETENESS = Histogram(
    "phantom_pceps_feature_completeness",
    "Feature completeness ratio of PCEPS scoring vectors",
    ["model_version"],
)

# ===========================================================================
# === Incident Reports ===
# ===========================================================================

# Measures the total number of security incident reports generated by PHANTOM.
# Incremented whenever an incident report is created or its classification status changes.
INCIDENT_REPORTS_TOTAL = Counter(
    "phantom_incident_reports_total",
    "Total security incident reports generated",
    ["status", "classification"],
)
INCIDENT_REPORTS = INCIDENT_REPORTS_TOTAL

# ===========================================================================
# === API Gateway ===
# ===========================================================================

# Measures the total number of HTTP requests processed by the API gateway.
# Incremented upon completion of each HTTP request processed by PrometheusMiddleware.
API_REQUESTS_TOTAL = Counter(
    "phantom_api_requests_total",
    "Total HTTP requests handled by the API Gateway",
    ["route", "method", "status_code"],
)
API_REQUESTS = API_REQUESTS_TOTAL

# Measures the duration in seconds of HTTP requests processed by the API gateway.
# Observed upon completion of each HTTP request processed by PrometheusMiddleware.
API_REQUEST_DURATION = Histogram(
    "phantom_api_request_duration_seconds",
    "Duration in seconds of HTTP requests handled by the API Gateway",
    ["route", "method", "status_code"],
)
API_REQUEST_DURATION_SECONDS = API_REQUEST_DURATION

# ===========================================================================
# === Infrastructure ===
# ===========================================================================

# Measures the lag in message count across Redis Streams consumer groups.
# Observed periodically by consumer workers monitoring stream processing delay.
REDIS_STREAM_LAG = Gauge(
    "phantom_redis_stream_lag",
    "Lag in message count for Redis stream consumer groups",
    ["stream", "consumer_group"],
)

# Measures the duration in seconds of PostgreSQL database operations.
# Observed after each timed query or repository operation completes.
POSTGRES_OPERATION_DURATION = Histogram(
    "phantom_postgres_operation_duration_seconds",
    "Duration in seconds of PostgreSQL database operations",
    ["operation", "result"],
)
POSTGRES_OPERATION_DURATION_SECONDS = POSTGRES_OPERATION_DURATION

__all__ = [
    "EBPF_EVENTS_CAPTURED",
    "EBPF_EVENTS_CAPTURED_TOTAL",
    "EBPF_RINGBUF_RESERVE_FAILURES",
    "EBPF_RINGBUF_RESERVE_FAILURES_TOTAL",
    "AGENT_EVENTS_SUBMITTED",
    "AGENT_EVENTS_SUBMITTED_TOTAL",
    "AGENT_EVENT_QUEUE_DEPTH",
    "AGENT_EVENT_LAG",
    "AGENT_EVENT_LAG_SECONDS",
    "IDENTITY_RESOLUTION_TOTAL",
    "IDENTITY_RESOLUTION",
    "SBOM_VERIFICATION_TOTAL",
    "SBOM_VERIFICATION",
    "SBOM_COMPONENT_BINDINGS_TOTAL",
    "SBOM_COMPONENT_BINDINGS",
    "CONTRACT_VALIDATION_TOTAL",
    "CONTRACT_VALIDATION",
    "CONTRACT_ACTIVE_TOTAL",
    "CONTRACT_ACTIVE",
    "DRIFT_EVENTS_TOTAL",
    "DRIFT_EVENTS",
    "BDG_NODES",
    "BDG_EDGES",
    "BDG_UPDATE_DURATION",
    "BDG_UPDATE_DURATION_SECONDS",
    "BDG_SNAPSHOT_AGE",
    "BDG_SNAPSHOT_AGE_SECONDS",
    "CAUSAL_JOBS_TOTAL",
    "CAUSAL_JOBS",
    "CAUSAL_ESTIMATION_DURATION",
    "CAUSAL_ESTIMATION_DURATION_SECONDS",
    "CAUSAL_ATTRIBUTION_CONFIDENCE",
    "CAUSAL_REFUTATIONS_TOTAL",
    "CAUSAL_REFUTATIONS",
    "PCEPS_SCORING_TOTAL",
    "PCEPS_SCORING",
    "PCEPS_FEATURE_COMPLETENESS",
    "INCIDENT_REPORTS_TOTAL",
    "INCIDENT_REPORTS",
    "API_REQUESTS_TOTAL",
    "API_REQUESTS",
    "API_REQUEST_DURATION",
    "API_REQUEST_DURATION_SECONDS",
    "REDIS_STREAM_LAG",
    "POSTGRES_OPERATION_DURATION",
    "POSTGRES_OPERATION_DURATION_SECONDS",
]
