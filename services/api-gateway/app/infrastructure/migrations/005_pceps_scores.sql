-- services/api-gateway/app/infrastructure/migrations/005_pceps_scores.sql
--
-- PCEPS priority score records.
--
-- One row per POST /api/v1/pceps:scores invocation.
-- Stores all fields from PcepsScoreResponse plus the raw and calibrated
-- probability values for audit and research evaluation.
--
-- Idempotent: CREATE TABLE / INDEX use IF NOT EXISTS.
-- Compatible with PostgreSQL 15+.

BEGIN;

-- ---------------------------------------------------------------------------
-- pceps_scores: one row per PCEPS scoring computation
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS pceps_scores (
    score_id                UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id               UUID        NOT NULL,

    -- Input references (immutable).
    drift_event_id          UUID        NOT NULL
        REFERENCES drift_events (drift_event_id) ON DELETE RESTRICT,
    attribution_id          UUID        NOT NULL
        REFERENCES attribution_jobs (attribution_id) ON DELETE RESTRICT,

    -- Model identification.
    model_version           TEXT        NOT NULL
        CONSTRAINT pceps_scores_model_version_length
            CHECK (LENGTH(model_version) BETWEEN 1 AND 128),

    -- Scoring results.
    score                   DOUBLE PRECISION NOT NULL
        CONSTRAINT pceps_scores_score_range
            CHECK (score >= 0.0 AND score <= 100.0),
    severity                TEXT        NOT NULL
        CONSTRAINT pceps_scores_severity_check
            CHECK (severity IN ('informational', 'low', 'medium', 'high', 'critical')),

    -- Calibration provenance (for research audit trail).
    raw_probability         DOUBLE PRECISION NOT NULL
        CONSTRAINT pceps_scores_raw_prob_range
            CHECK (raw_probability >= 0.0 AND raw_probability <= 1.0),
    calibrated_probability  DOUBLE PRECISION NOT NULL
        CONSTRAINT pceps_scores_cal_prob_range
            CHECK (calibrated_probability >= 0.0 AND calibrated_probability <= 1.0),

    -- Feature vector completeness.
    feature_completeness    DOUBLE PRECISION NOT NULL DEFAULT 1.0
        CONSTRAINT pceps_scores_completeness_range
            CHECK (feature_completeness >= 0.0 AND feature_completeness <= 1.0),

    -- Names of features that were imputed (empty array when none).
    imputed_features        JSONB       NOT NULL DEFAULT '[]',

    -- Full 16-element feature vector (for research reproducibility).
    feature_vector          JSONB       NOT NULL DEFAULT '[]',

    -- Feature mask (16 booleans; true = was imputed).
    feature_mask            JSONB       NOT NULL DEFAULT '[]',

    -- Whether imputation was allowed by the request.
    allow_imputation        BOOLEAN     NOT NULL DEFAULT TRUE,

    -- Audit timestamp.
    scored_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT pceps_scores_pkey PRIMARY KEY (score_id)
);

-- This index serves: GET /api/v1/pceps:scores?tenant_id=&drift_event_id= — retrieve
-- scores for a specific drift event (used by incident report assembly).
CREATE INDEX IF NOT EXISTS pceps_scores_tenant_drift_event_idx
    ON pceps_scores (tenant_id, drift_event_id, scored_at DESC);

-- This index serves: GET /api/v1/pceps:scores?attribution_id= — retrieve all
-- scores derived from a specific attribution job.
CREATE INDEX IF NOT EXISTS pceps_scores_attribution_idx
    ON pceps_scores (attribution_id, tenant_id);

-- This index serves: GET /api/v1/pceps:scores?severity= — dashboard queries
-- filtering by severity band within a tenant, most-recent first.
CREATE INDEX IF NOT EXISTS pceps_scores_tenant_severity_idx
    ON pceps_scores (tenant_id, severity, scored_at DESC);

-- This index serves: research evaluation — retrieve all scores for a specific
-- model version to compute aggregate calibration metrics.
CREATE INDEX IF NOT EXISTS pceps_scores_model_version_idx
    ON pceps_scores (model_version, tenant_id, scored_at DESC);

INSERT INTO schema_migrations (version, description)
VALUES (5, 'pceps_scores: XGBoost+Platt PCEPS priority score records')
ON CONFLICT (version) DO NOTHING;

COMMIT;
