-- services/api-gateway/app/infrastructure/migrations/004_attribution_jobs.sql
--
-- Attribution job lifecycle tables.
--
-- Covers:
--   attribution_jobs:      one row per POST /api/v1/attributions job
--   attribution_refutations: one row per DoWhy refutation result
--
-- The causal-engine writes results here via PostgresAttributionRepository.
-- The api-gateway reads them to serve GET /api/v1/attributions/{attribution_id}.
--
-- Idempotent: CREATE TABLE / INDEX use IF NOT EXISTS.
-- Compatible with PostgreSQL 15+.

BEGIN;

-- ---------------------------------------------------------------------------
-- attribution_jobs: one row per causal attribution job lifecycle
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS attribution_jobs (
    attribution_id              UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id                   UUID        NOT NULL,

    -- Input references (immutable after creation).
    snapshot_id                 UUID        NOT NULL
        REFERENCES bdg_snapshots (snapshot_id) ON DELETE RESTRICT,
    drift_event_id              UUID        NOT NULL
        REFERENCES drift_events (drift_event_id) ON DELETE RESTRICT,

    -- SCM specification (immutable; stored as JSONB for flexibility).
    treatment_spec              JSONB       NOT NULL,
    outcome_spec                JSONB       NOT NULL,
    covariates                  JSONB       NOT NULL DEFAULT '[]',
    estimator                   TEXT        NOT NULL
        CONSTRAINT attribution_jobs_estimator_check
            CHECK (estimator IN (
                'backdoor.linear_regression',
                'backdoor.propensity_score_matching',
                'backdoor.generalized_linear_model'
            )),
    counterfactual_treatment_value SMALLINT NOT NULL
        CONSTRAINT attribution_jobs_counterfactual_check
            CHECK (counterfactual_treatment_value IN (0, 1)),

    -- Job lifecycle state (mutable).
    status                      TEXT        NOT NULL DEFAULT 'queued'
        CONSTRAINT attribution_jobs_status_check
            CHECK (status IN (
                'queued', 'running', 'completed',
                'not_identifiable', 'failed'
            )),

    -- DoWhy identification result fields.
    estimand                    TEXT,
    identified                  BOOLEAN     NOT NULL DEFAULT FALSE,
    identification_method       TEXT,

    -- Estimation results (populated on status = 'completed').
    average_treatment_effect    DOUBLE PRECISION,
    effect_ci_lower             DOUBLE PRECISION,
    effect_ci_upper             DOUBLE PRECISION,
    counterfactual_drift_probability DOUBLE PRECISION
        CONSTRAINT attribution_jobs_cfp_range
            CHECK (counterfactual_drift_probability IS NULL
                OR (counterfactual_drift_probability >= 0.0
                    AND counterfactual_drift_probability <= 1.0)),

    -- Multi-dimensional confidence decomposition (populated on 'completed').
    confidence_score                DOUBLE PRECISION
        CONSTRAINT attribution_jobs_conf_score_range
            CHECK (confidence_score IS NULL
                OR (confidence_score >= 0.0 AND confidence_score <= 1.0)),
    confidence_data_coverage        DOUBLE PRECISION,
    confidence_identity_resolution  DOUBLE PRECISION,
    confidence_contract_verification DOUBLE PRECISION,
    confidence_graph_consistency    DOUBLE PRECISION,
    confidence_refutation_stability DOUBLE PRECISION,
    confidence_loss_penalty         DOUBLE PRECISION,
    confidence_explanation          JSONB   NOT NULL DEFAULT '[]',

    -- Failure / not_identifiable reason.
    failure_reason              TEXT,

    -- Timestamps.
    submitted_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at                  TIMESTAMPTZ,
    completed_at                TIMESTAMPTZ,

    CONSTRAINT attribution_jobs_pkey PRIMARY KEY (attribution_id)
);

-- This index serves: GET /api/v1/attributions/{attribution_id} — primary point lookup.
CREATE INDEX IF NOT EXISTS attribution_jobs_tenant_id_idx
    ON attribution_jobs (tenant_id, attribution_id);

-- This index serves: GET /api/v1/attributions?drift_event_id= — list attributions
-- for a specific drift event (used by incident report assembly).
CREATE INDEX IF NOT EXISTS attribution_jobs_drift_event_idx
    ON attribution_jobs (drift_event_id, tenant_id);

-- This index serves: causal engine job queue — fetches queued jobs ordered
-- by submission time for FIFO processing.
CREATE INDEX IF NOT EXISTS attribution_jobs_queued_idx
    ON attribution_jobs (tenant_id, submitted_at)
    WHERE status = 'queued';

-- This index serves: snapshot reference integrity check —
-- POST /api/v1/attributions validates snapshot_id belongs to requesting tenant.
CREATE INDEX IF NOT EXISTS attribution_jobs_snapshot_idx
    ON attribution_jobs (snapshot_id, tenant_id);

-- ---------------------------------------------------------------------------
-- attribution_refutations: one row per DoWhy refutation result per job
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS attribution_refutations (
    refutation_id           UUID        NOT NULL DEFAULT gen_random_uuid(),
    attribution_id          UUID        NOT NULL
        REFERENCES attribution_jobs (attribution_id) ON DELETE CASCADE,
    tenant_id               UUID        NOT NULL,

    -- Refutation parameters (immutable).
    method                  TEXT        NOT NULL
        CONSTRAINT attribution_refutations_method_check
            CHECK (method IN (
                'random_common_cause',
                'placebo_treatment_refuter',
                'data_subset_refuter'
            )),

    -- Result fields.
    passed                  BOOLEAN     NOT NULL,
    effect_estimate         DOUBLE PRECISION,
    notes                   TEXT        NOT NULL DEFAULT '',

    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT attribution_refutations_pkey PRIMARY KEY (refutation_id)
);

-- This index serves: GET /api/v1/attributions/{attribution_id} — fetch all
-- refutation results for a completed attribution job.
CREATE INDEX IF NOT EXISTS attribution_refutations_job_idx
    ON attribution_refutations (attribution_id);

INSERT INTO schema_migrations (version, description)
VALUES (4, 'attribution_jobs + attribution_refutations: causal attribution lifecycle')
ON CONFLICT (version) DO NOTHING;

COMMIT;
