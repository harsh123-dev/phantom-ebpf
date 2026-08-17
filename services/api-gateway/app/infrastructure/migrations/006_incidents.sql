-- services/api-gateway/app/infrastructure/migrations/006_incidents.sql
--
-- Incident report tables.
--
-- Covers:
--   incidents:             one row per POST /api/v1/incidents (with optimistic locking)
--   incident_evidence:     M:N join table linking incidents to forensic evidence UUIDs
--   incident_tags:         one row per tag per incident
--
-- Forensic evidence (drift events, attributions, PCEPS scores, BDG snapshots) is
-- NEVER deleted — archive is a soft status change only.
--
-- Idempotent: CREATE TABLE / INDEX use IF NOT EXISTS.
-- Compatible with PostgreSQL 15+.

BEGIN;

-- ---------------------------------------------------------------------------
-- incidents: one row per incident report lifecycle
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS incidents (
    incident_id             UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id               UUID        NOT NULL,

    -- Optimistic concurrency lock counter (monotonically increasing).
    revision                INT         NOT NULL DEFAULT 1
        CONSTRAINT incidents_revision_min CHECK (revision >= 1),

    -- Lifecycle status.
    status                  TEXT        NOT NULL DEFAULT 'draft'
        CONSTRAINT incidents_status_check
            CHECK (status IN ('draft', 'open', 'resolved', 'archived')),

    -- Analyst classification.
    classification          TEXT        NOT NULL DEFAULT 'untriaged'
        CONSTRAINT incidents_classification_check
            CHECK (classification IN ('untriaged', 'benign', 'suspicious', 'confirmed')),

    -- Human-readable fields (mutable, validated at application layer).
    title                   TEXT        NOT NULL
        CONSTRAINT incidents_title_length
            CHECK (LENGTH(title) BETWEEN 1 AND 240),
    summary                 TEXT        NOT NULL
        CONSTRAINT incidents_summary_length
            CHECK (LENGTH(summary) BETWEEN 1 AND 8000),
    resolution_notes        TEXT
        CONSTRAINT incidents_resolution_notes_length
            CHECK (resolution_notes IS NULL OR LENGTH(resolution_notes) <= 8000),

    -- Forensic evidence anchor (BDG snapshot used for reproducibility).
    snapshot_id             UUID        NOT NULL
        REFERENCES bdg_snapshots (snapshot_id) ON DELETE RESTRICT,

    -- Evidence hash: sha256 over the sorted, canonical evidence UUID set.
    -- Recomputed on every PATCH that modifies the evidence set.
    evidence_hash           TEXT        NOT NULL
        CONSTRAINT incidents_evidence_hash_format
            CHECK (evidence_hash ~ '^sha256:[0-9a-f]{64}$'),

    -- Principal identifier of the analyst who created this report.
    created_by              TEXT        NOT NULL,

    -- Timestamps.
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    archived_at             TIMESTAMPTZ,

    CONSTRAINT incidents_pkey PRIMARY KEY (incident_id)
);

-- This index serves: GET /api/v1/incidents?tenant_id= list (paginated, most-recent-first).
CREATE INDEX IF NOT EXISTS incidents_tenant_created_idx
    ON incidents (tenant_id, created_at DESC);

-- This index serves: GET /api/v1/incidents?status= — filter by lifecycle status
-- within a tenant (e.g., all open incidents on the dashboard).
CREATE INDEX IF NOT EXISTS incidents_tenant_status_idx
    ON incidents (tenant_id, status, created_at DESC);

-- This index serves: GET /api/v1/incidents?classification= — filter by analyst
-- classification (e.g., all confirmed incidents for a tenant).
CREATE INDEX IF NOT EXISTS incidents_tenant_classification_idx
    ON incidents (tenant_id, classification, created_at DESC);

-- This index serves: GET /api/v1/incidents/{incident_id} — primary point lookup
-- for incident detail and update/archive operations.
CREATE INDEX IF NOT EXISTS incidents_tenant_incident_idx
    ON incidents (tenant_id, incident_id);

-- ---------------------------------------------------------------------------
-- incident_evidence: M:N join between incidents and forensic evidence UUIDs
--
-- Instead of storing arrays in the incidents table (which makes FK integrity
-- impossible), we normalise to a join table.  evidence_type discriminates
-- the target table (drift_event, attribution, pceps_score).
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS incident_evidence (
    evidence_link_id        UUID        NOT NULL DEFAULT gen_random_uuid(),
    incident_id             UUID        NOT NULL
        REFERENCES incidents (incident_id) ON DELETE CASCADE,
    tenant_id               UUID        NOT NULL,

    -- Evidence type discriminator.
    evidence_type           TEXT        NOT NULL
        CONSTRAINT incident_evidence_type_check
            CHECK (evidence_type IN ('drift_event', 'attribution', 'pceps_score')),

    -- UUID of the referenced evidence row.
    evidence_id             UUID        NOT NULL,

    -- Immutable; evidence links are append-only.
    linked_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT incident_evidence_pkey PRIMARY KEY (evidence_link_id),
    -- Prevent duplicate links of the same evidence to the same incident.
    CONSTRAINT incident_evidence_uq UNIQUE (incident_id, evidence_type, evidence_id)
);

-- This index serves: GET /api/v1/incidents/{incident_id} — fetch all evidence
-- UUIDs grouped by type for IncidentDetailResponse construction.
CREATE INDEX IF NOT EXISTS incident_evidence_incident_idx
    ON incident_evidence (incident_id, evidence_type);

-- This index serves: cross-reference query — "which incidents reference this
-- drift event?" (used by POST /api/v1/incidents duplicate detection).
CREATE INDEX IF NOT EXISTS incident_evidence_evidence_idx
    ON incident_evidence (evidence_type, evidence_id, tenant_id);

-- ---------------------------------------------------------------------------
-- incident_tags: one row per tag per incident
--
-- Normalised out of the incidents table to support tag-based list filtering
-- with a proper index.  Tags are immutable after creation per version;
-- a PATCH replaces the tag set by deleting all existing rows and reinserting.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS incident_tags (
    tag_id                  UUID        NOT NULL DEFAULT gen_random_uuid(),
    incident_id             UUID        NOT NULL
        REFERENCES incidents (incident_id) ON DELETE CASCADE,
    tenant_id               UUID        NOT NULL,
    tag                     TEXT        NOT NULL
        CONSTRAINT incident_tags_length
            CHECK (LENGTH(tag) BETWEEN 1 AND 64),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT incident_tags_pkey PRIMARY KEY (tag_id),
    CONSTRAINT incident_tags_uq UNIQUE (incident_id, tag)
);

-- This index serves: GET /api/v1/incidents?tag= — list incidents by tag
-- within a tenant.
CREATE INDEX IF NOT EXISTS incident_tags_tenant_tag_idx
    ON incident_tags (tenant_id, tag, incident_id);

-- This index serves: GET /api/v1/incidents/{incident_id} — fetch all tags
-- for a single incident.
CREATE INDEX IF NOT EXISTS incident_tags_incident_idx
    ON incident_tags (incident_id);

INSERT INTO schema_migrations (version, description)
VALUES (6, 'incidents + incident_evidence + incident_tags: incident report lifecycle')
ON CONFLICT (version) DO NOTHING;

COMMIT;
