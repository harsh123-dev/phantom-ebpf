"""
phantom_core.constants — Central configuration constants for all PHANTOM services.

All magic numbers, string literals, and tunable parameters live here.
Service code MUST import from this module instead of using inline literals.

Sections:
- Schema / versioning
- API pagination
- Digest format
- Behavioral contract limits
- Drift event limits
- BDG query limits
- Attribution limits
- PCEPS limits
- Incident limits
- WebSocket limits
- Metric label constraints
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Schema / versioning
# ---------------------------------------------------------------------------

APP_NAME: str = "PHANTOM"

SCHEMA_VERSION: str = "v1"
"""Immutable schema version tag embedded in every persisted entity."""

ABI_VERSION: int = 1
"""eBPF ring-buffer ABI version embedded in phantom_event_header."""

# ---------------------------------------------------------------------------
# Digest format
# ---------------------------------------------------------------------------

DIGEST_PREFIX: str = "sha256:"
DIGEST_HEX_LENGTH: int = 64
"""sha256:<64 lowercase hexadecimal characters>"""

DIGEST_PATTERN: str = r"^sha256:[0-9a-f]{64}$"
"""Compiled regex pattern for validating digest fields."""

# ---------------------------------------------------------------------------
# API pagination
# ---------------------------------------------------------------------------

PAGINATION_LIMIT_MIN: int = 1
PAGINATION_LIMIT_MAX: int = 200
PAGINATION_LIMIT_DEFAULT: int = 50

# ---------------------------------------------------------------------------
# SBOM limits (B.2)
# ---------------------------------------------------------------------------

SBOM_ARTIFACT_URI_SCHEMES: tuple[str, ...] = ("https", "s3")
"""Only https and s3 URIs are accepted for artifact_uri and signature_bundle_uri."""

# ---------------------------------------------------------------------------
# Behavioral contract limits (B.3)
# ---------------------------------------------------------------------------

CONTRACT_ALLOWED_EXECUTABLES_MAX: int = 1024
CONTRACT_ALLOWED_FILE_PATH_PREFIXES_MAX: int = 1024
CONTRACT_ALLOWED_NETWORK_DESTINATIONS_MAX: int = 1024
CONTRACT_ALLOWED_SYSCALL_CLASSES_MIN: int = 1
CONTRACT_ALLOWED_SYSCALL_CLASSES_MAX: int = 128
CONTRACT_ALLOWED_PURLS_MAX: int = 4096
CONTRACT_ALLOWED_PARENT_CHILD_PAIRS_MAX: int = 1024
CONTRACT_MAX_NEW_PROCESSES_PER_5M_MAX: int = 1_000_000
CONTRACT_WORKLOAD_SELECTOR_LABELS_MAX: int = 32
CONTRACT_VERSION_PATTERN: str = r"^[0-9]+\.[0-9]+\.[0-9]+$"
CONTRACT_EXPECTED_IDENTITY_MIN_LENGTH: int = 1
CONTRACT_EXPECTED_IDENTITY_MAX_LENGTH: int = 512
CONTRACT_CLUSTER_NAME_MAX_LENGTH: int = 253

# ---------------------------------------------------------------------------
# Drift event limits (B.4)
# ---------------------------------------------------------------------------

DRIFT_VIOLATIONS_MIN: int = 1
DRIFT_VIOLATIONS_MAX: int = 64
DRIFT_COMM_MAX_LENGTH: int = 16
DRIFT_EXECUTABLE_PATH_MAX_LENGTH: int = 4096
DRIFT_CONTAINER_ID_MAX_LENGTH: int = 256
DRIFT_PURL_MAX_LENGTH: int = 2048
DRIFT_BINDING_CONFIDENCE_MIN: float = 0.0
DRIFT_BINDING_CONFIDENCE_MAX: float = 1.0
DRIFT_VIOLATION_CONFIDENCE_MIN: float = 0.0
DRIFT_VIOLATION_CONFIDENCE_MAX: float = 1.0

# ---------------------------------------------------------------------------
# BDG query limits (B.5)
# ---------------------------------------------------------------------------

BDG_SUBGRAPH_ROOT_NODES_MIN: int = 1
BDG_SUBGRAPH_ROOT_NODES_MAX: int = 50
BDG_SUBGRAPH_MAX_HOPS_MIN: int = 0
BDG_SUBGRAPH_MAX_HOPS_MAX: int = 6
BDG_SUBGRAPH_MAX_NODES_MIN: int = 1
BDG_SUBGRAPH_MAX_NODES_MAX: int = 5000
BDG_NODE_CONFIDENCE_MIN: float = 0.0
BDG_NODE_CONFIDENCE_MAX: float = 1.0

# ---------------------------------------------------------------------------
# Attribution limits (B.6)
# ---------------------------------------------------------------------------

ATTRIBUTION_COVARIATES_MIN: int = 1
ATTRIBUTION_COVARIATES_MAX: int = 128
ATTRIBUTION_TREATMENT_NODES_MIN: int = 1
ATTRIBUTION_TREATMENT_NODES_MAX: int = 100
ATTRIBUTION_OUTCOME_NODES_MIN: int = 1
ATTRIBUTION_OUTCOME_NODES_MAX: int = 100
ATTRIBUTION_VARIABLE_PATTERN: str = r"^[A-Za-z][A-Za-z0-9_]{0,127}$"
ATTRIBUTION_CONFIDENCE_EXPLANATION_MAX: int = 16
ATTRIBUTION_REFUTATION_NOTES_MAX_LENGTH: int = 2048

# ---------------------------------------------------------------------------
# PCEPS limits (B.7)
# ---------------------------------------------------------------------------

PCEPS_MODEL_VERSION_MAX_LENGTH: int = 128
PCEPS_SCORE_MIN: float = 0.0
PCEPS_SCORE_MAX: float = 100.0
PCEPS_FEATURE_COMPLETENESS_MIN: float = 0.0
PCEPS_FEATURE_COMPLETENESS_MAX: float = 1.0

# ---------------------------------------------------------------------------
# Incident report limits (B.8)
# ---------------------------------------------------------------------------

INCIDENT_TITLE_MIN_LENGTH: int = 1
INCIDENT_TITLE_MAX_LENGTH: int = 240
INCIDENT_SUMMARY_MIN_LENGTH: int = 1
INCIDENT_SUMMARY_MAX_LENGTH: int = 8000
INCIDENT_RESOLUTION_NOTES_MAX_LENGTH: int = 8000
INCIDENT_DRIFT_EVENT_IDS_MIN: int = 1
INCIDENT_DRIFT_EVENT_IDS_MAX: int = 1000
INCIDENT_ATTRIBUTION_IDS_MAX: int = 1000
INCIDENT_SCORE_IDS_MAX: int = 1000
INCIDENT_TAGS_MAX: int = 32
INCIDENT_TAG_MIN_LENGTH: int = 1
INCIDENT_TAG_MAX_LENGTH: int = 64

# ---------------------------------------------------------------------------
# WebSocket limits (B.9)
# ---------------------------------------------------------------------------

WS_NAMESPACE_FILTERS_MAX: int = 64

# WebSocket close codes (non-standard, application-level)
WS_CLOSE_UNAUTHENTICATED: int = 4401
WS_CLOSE_UNAUTHORIZED: int = 4403
WS_CLOSE_INVALID_SUBSCRIPTION: int = 4408
WS_CLOSE_OVERLOADED: int = 1013

# ---------------------------------------------------------------------------
# Prometheus metric label constraints (Part D)
# ---------------------------------------------------------------------------

# High-cardinality identifiers MUST NOT be used as Prometheus label values.
# Forbidden: pod UID, container ID, executable path, PURL, raw IP, incident ID.
# These belong in PostgreSQL evidence, not Prometheus.
PROMETHEUS_FORBIDDEN_LABEL_FIELDS: tuple[str, ...] = (
    "pod_uid",
    "container_id",
    "executable_path",
    "purl",
    "raw_ip",
    "incident_id",
)

# ---------------------------------------------------------------------------
# Port defaults (local development only; override via env vars in production)
# ---------------------------------------------------------------------------

DEFAULT_API_GATEWAY_PORT: int = 8080
DEFAULT_SBOM_SERVICE_PORT: int = 8000
DEFAULT_CAUSAL_ENGINE_HEALTH_PORT: int = 8001
DEFAULT_REPORT_GENERATOR_HEALTH_PORT: int = 8002
DEFAULT_PROMETHEUS_PORT: int = 9090
DEFAULT_GRAFANA_PORT: int = 3000
