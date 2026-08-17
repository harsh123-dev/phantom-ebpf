-- services/api-gateway/app/infrastructure/migrations/003_bdg_snapshots.sql
--
-- BDG snapshot registry table.
--
-- A snapshot is an immutable, point-in-time serialization of the
-- Behavioral Dependency Graph, stored here so attribution jobs can
-- reference a stable, reproducible graph state.
--
-- The causal-engine writes snapshots here; the api-gateway reads them
-- to validate AttributionRequest.snapshot_id and serve
-- GET /api/v1/bdg/snapshots/{snapshot_id}.
--
-- Idempotent: CREATE TABLE / INDEX use IF NOT EXISTS.
-- Compatible with PostgreSQL 15+.

BEGIN;

-- ---------------------------------------------------------------------------
-- bdg_snapshots: one row per immutable BDG graph snapshot
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS bdg_snapshots (
    snapshot_id             UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id               UUID        NOT NULL,

    -- Snapshot metadata.
    node_count              INT         NOT NULL DEFAULT 0
        CONSTRAINT bdg_snapshots_node_count_nonneg CHECK (node_count >= 0),
    edge_count              INT         NOT NULL DEFAULT 0
        CONSTRAINT bdg_snapshots_edge_count_nonneg CHECK (edge_count >= 0),

    -- High-watermark of the last drift event UUID included in this snapshot.
    -- Used by the causal engine to detect stale snapshot references.
    event_id_high_watermark UUID,

    -- Full serialized graph stored as JSONB.
    -- Schema: { "nodes": [...], "edges": [...] }
    graph_data              JSONB       NOT NULL DEFAULT '{"nodes":[],"edges":[]}',

    -- sha256 digest of the canonical graph_data bytes (reproducibility check).
    graph_digest            TEXT
        CONSTRAINT bdg_snapshots_graph_digest_format
            CHECK (graph_digest IS NULL OR graph_digest ~ '^sha256:[0-9a-f]{64}$'),

    -- Audit timestamp (immutable).
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT bdg_snapshots_pkey PRIMARY KEY (snapshot_id)
);

-- This index serves: GET /api/v1/bdg/snapshots?tenant_id= list, most-recent-first.
CREATE INDEX IF NOT EXISTS bdg_snapshots_tenant_created_idx
    ON bdg_snapshots (tenant_id, created_at DESC);

-- This index serves: POST /api/v1/attributions → snapshot_id validation
-- (point lookup: does this snapshot exist for this tenant?).
CREATE INDEX IF NOT EXISTS bdg_snapshots_tenant_snapshot_idx
    ON bdg_snapshots (tenant_id, snapshot_id);

-- This index serves: causal engine snapshot lookup by high-watermark to
-- detect which events are included in a snapshot.
CREATE INDEX IF NOT EXISTS bdg_snapshots_hwm_idx
    ON bdg_snapshots (tenant_id, event_id_high_watermark)
    WHERE event_id_high_watermark IS NOT NULL;

INSERT INTO schema_migrations (version, description)
VALUES (3, 'bdg_snapshots: immutable BDG point-in-time snapshot registry')
ON CONFLICT (version) DO NOTHING;

COMMIT;
