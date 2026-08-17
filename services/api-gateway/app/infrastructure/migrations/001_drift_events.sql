-- services/api-gateway/app/infrastructure/migrations/001_drift_events.sql
--
-- Drift event transactional outbox table.
--
-- The api-gateway writes here atomically with every POST /api/v1/drift-events.
-- The causal-engine reads from this table (via Redis Streams) to update the BDG.
--
-- Idempotent: CREATE TABLE / INDEX use IF NOT EXISTS.
-- Compatible with PostgreSQL 15+.

BEGIN;

CREATE EXTENSION IF NOT EXISTS "pgcrypto";  -- gen_random_uuid()

-- ---------------------------------------------------------------------------
-- drift_events: one row per accepted POST /api/v1/drift-events ingestion
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS drift_events (
    -- Gateway-assigned surrogate UUID (drift_event_id in DriftEventRecord).
    drift_event_id          UUID        NOT NULL DEFAULT gen_random_uuid(),

    -- Agent-generated stable UUID used for idempotency deduplication.
    -- Unique per tenant to allow agents across tenants to use the same UUIDs.
    event_id                UUID        NOT NULL,
    tenant_id               UUID        NOT NULL,

    -- Observation timing.
    observed_at             TIMESTAMPTZ NOT NULL,
    received_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Runtime event category (matches RuntimeEventType literal).
    event_type              TEXT        NOT NULL
        CONSTRAINT drift_events_event_type_check
            CHECK (event_type IN (
                'exec', 'file_open', 'file_write', 'network_connect',
                'network_accept', 'privilege_transition',
                'namespace_change', 'module_load'
            )),

    -- Kubernetes node where the event was captured.
    node_name               TEXT        NOT NULL,

    -- Identity resolution quality.
    identity_status         TEXT        NOT NULL
        CONSTRAINT drift_events_identity_status_check
            CHECK (identity_status IN ('resolved', 'ambiguous', 'missing', 'stale')),

    -- Process identity (normalized subset; full record in process_json).
    tgid                    INT         NOT NULL,
    pid_start_time_ns       BIGINT      NOT NULL,
    comm                    TEXT        NOT NULL,
    executable_path         TEXT        NOT NULL,
    uid                     INT         NOT NULL,
    gid                     INT         NOT NULL,

    -- Workload identity.
    cluster_name            TEXT        NOT NULL,
    namespace               TEXT        NOT NULL,
    pod_name                TEXT        NOT NULL,
    pod_uid                 UUID        NOT NULL,
    container_name          TEXT        NOT NULL,
    container_id            TEXT        NOT NULL,
    image_digest            TEXT        NOT NULL
        CONSTRAINT drift_events_image_digest_format
            CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    service_account         TEXT,

    -- SBOM binding (nullable; present only when identity_status = 'resolved').
    sbom_id                 UUID,
    purl                    TEXT,
    binding_confidence      DOUBLE PRECISION
        CONSTRAINT drift_events_binding_confidence_range
            CHECK (binding_confidence IS NULL OR (binding_confidence >= 0.0 AND binding_confidence <= 1.0)),
    binding_status          TEXT
        CONSTRAINT drift_events_binding_status_check
            CHECK (binding_status IS NULL OR binding_status IN ('resolved', 'ambiguous', 'missing')),

    -- Contract violations (1..64 items per DriftEventIngestRequest).
    violations              JSONB       NOT NULL DEFAULT '[]',
    violation_count         SMALLINT    NOT NULL DEFAULT 0
        CONSTRAINT drift_events_violation_count_range
            CHECK (violation_count >= 1 AND violation_count <= 64),

    -- Low-level runtime evidence.
    kernel_timestamp_ns     BIGINT      NOT NULL,
    cpu                     INT         NOT NULL,
    architecture            TEXT        NOT NULL
        CONSTRAINT drift_events_architecture_check
            CHECK (architecture IN ('x86_64', 'arm64')),
    event_loss_observed     BOOLEAN     NOT NULL DEFAULT FALSE,
    correlation_id          UUID,
    raw_event_digest        TEXT        NOT NULL
        CONSTRAINT drift_events_raw_event_digest_format
            CHECK (raw_event_digest ~ '^sha256:[0-9a-f]{64}$'),

    -- Agent monotonic sequence for ordering.
    agent_sequence          BIGINT      NOT NULL,

    -- Outbox routing: UUID of the bdg_mutations_outbox row enqueued for this event.
    bdg_update_id           UUID,

    -- Ingestion deduplication result.
    ingestion_status        TEXT        NOT NULL DEFAULT 'accepted'
        CONSTRAINT drift_events_ingestion_status_check
            CHECK (ingestion_status IN ('accepted', 'duplicate')),

    CONSTRAINT drift_events_pkey PRIMARY KEY (drift_event_id)
);

-- This index serves: GET /api/v1/drift-events?tenant_id=&image_digest= list query,
-- and causal engine workload-scoped event retrieval.
CREATE INDEX IF NOT EXISTS drift_events_tenant_image_idx
    ON drift_events (tenant_id, image_digest, observed_at DESC);

-- This index serves: GET /api/v1/drift-events?tenant_id=&namespace=&pod_uid= queries.
CREATE INDEX IF NOT EXISTS drift_events_tenant_pod_idx
    ON drift_events (tenant_id, pod_uid, observed_at DESC);

-- This index serves: idempotency check on POST /api/v1/drift-events (event_id dedupe).
CREATE UNIQUE INDEX IF NOT EXISTS drift_events_event_id_tenant_uq
    ON drift_events (event_id, tenant_id);

-- This index serves: causal engine attribution window queries over time range.
CREATE INDEX IF NOT EXISTS drift_events_tenant_observed_at_idx
    ON drift_events (tenant_id, observed_at DESC);

-- This index serves: GIN queries into violations JSONB for violation_type filtering.
CREATE INDEX IF NOT EXISTS drift_events_violations_gin_idx
    ON drift_events USING GIN (violations);

-- ---------------------------------------------------------------------------
-- Schema version tracking (api-gateway migrations)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INT         NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description TEXT        NOT NULL,
    CONSTRAINT schema_migrations_pkey PRIMARY KEY (version)
);

INSERT INTO schema_migrations (version, description)
VALUES (1, 'drift_events: transactional outbox ingestion table')
ON CONFLICT (version) DO NOTHING;

COMMIT;
