-- services/api-gateway/app/infrastructure/migrations/002_graph_mutations_outbox.sql
--
-- Transactional outbox for BDG mutation events.
--
-- The api-gateway writes a row here atomically with every accepted drift event.
-- The causal-engine Redis consumer reads and ACKs from here (via XREADGROUP)
-- to apply BDG mutations, implementing the transactional outbox pattern.
--
-- Idempotent: CREATE TABLE / INDEX use IF NOT EXISTS.
-- Compatible with PostgreSQL 15+.

BEGIN;

-- ---------------------------------------------------------------------------
-- graph_mutations_outbox: one row per BDG mutation queued for the causal engine
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS graph_mutations_outbox (
    -- Outbox row UUID.  This is the bdg_update_id returned in DriftEventRecord.
    bdg_update_id           UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id               UUID        NOT NULL,

    -- Source drift event (FK to drift_events; ON DELETE CASCADE for cleanup).
    drift_event_id          UUID        NOT NULL
        REFERENCES drift_events (drift_event_id) ON DELETE CASCADE,

    -- Serialized mutation payload forwarded to the causal engine via Redis Streams.
    -- Contains all fields needed by UpdateBdgUseCase without a DB round-trip.
    mutation_payload        JSONB       NOT NULL,

    -- Outbox processing lifecycle.
    status                  TEXT        NOT NULL DEFAULT 'pending'
        CONSTRAINT graph_mutations_outbox_status_check
            CHECK (status IN ('pending', 'published', 'failed')),

    -- Timestamps.
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at            TIMESTAMPTZ,

    -- Redis Streams message ID for correlation and at-least-once tracking.
    redis_message_id        TEXT,

    -- Retry tracking.
    attempt_count           SMALLINT    NOT NULL DEFAULT 0
        CONSTRAINT graph_mutations_outbox_attempt_count_nonneg
            CHECK (attempt_count >= 0),
    last_error              TEXT,

    CONSTRAINT graph_mutations_outbox_pkey PRIMARY KEY (bdg_update_id)
);

-- This index serves: outbox publisher poll — fetches pending rows ordered by
-- created_at for at-least-once delivery to Redis Streams.
CREATE INDEX IF NOT EXISTS graph_mutations_outbox_pending_idx
    ON graph_mutations_outbox (tenant_id, created_at)
    WHERE status = 'pending';

-- This index serves: drift event to outbox row lookup for status checks and
-- correlation in POST /api/v1/drift-events response construction.
CREATE INDEX IF NOT EXISTS graph_mutations_outbox_drift_event_idx
    ON graph_mutations_outbox (drift_event_id);

-- This index serves: failed row requeue — periodic job retries rows where
-- status = 'failed' and attempt_count < MAX_ATTEMPTS.
CREATE INDEX IF NOT EXISTS graph_mutations_outbox_failed_idx
    ON graph_mutations_outbox (tenant_id, created_at)
    WHERE status = 'failed';

INSERT INTO schema_migrations (version, description)
VALUES (2, 'graph_mutations_outbox: BDG mutation transactional outbox')
ON CONFLICT (version) DO NOTHING;

COMMIT;
