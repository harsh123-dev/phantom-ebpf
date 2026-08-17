-- services/sbom-service/app/infrastructure/postgres/migrations/001_initial.sql
--
-- Initial DDL for the SBOM service.
-- All tables use UUID primary keys, tenant_id for logical isolation,
-- and immutable audit columns (created_at is never updated).
--
-- Idempotent: can be re-run with "IF NOT EXISTS" guards.
-- Compatible with PostgreSQL 15+.

BEGIN;

-- ---------------------------------------------------------------------------
-- Extension
-- ---------------------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS "pgcrypto";  -- gen_random_uuid()

-- ---------------------------------------------------------------------------
-- sboms: primary SBOM record table
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sboms (
    sbom_id              UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id            UUID        NOT NULL,

    -- Image association (immutable after write)
    image_digest         TEXT        NOT NULL
        CONSTRAINT sboms_image_digest_format
            CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),

    -- SBOM document digest (immutable; used for deduplication)
    sbom_digest          TEXT        NOT NULL
        CONSTRAINT sboms_sbom_digest_format
            CHECK (sbom_digest ~ '^sha256:[0-9a-f]{64}$'),

    -- CycloneDX document stored as JSONB for efficient querying
    cyclonedx_document   JSONB       NOT NULL,

    -- Metadata
    spec_version         TEXT        NOT NULL DEFAULT 'unknown',
    source               TEXT        NOT NULL
        CONSTRAINT sboms_source_check
            CHECK (source IN ('syft', 'external')),
    artifact_uri         TEXT        NOT NULL,
    signature_bundle_uri TEXT,

    -- Verification state (mutable)
    verification_status  TEXT        NOT NULL DEFAULT 'pending'
        CONSTRAINT sboms_verification_status_check
            CHECK (verification_status IN ('pending', 'verified', 'failed')),
    signing_identity     TEXT,
    issuer               TEXT,
    rekor_entry_uuid     UUID,
    verification_error   TEXT,
    verified_at          TIMESTAMPTZ,

    -- Component summary counts (denormalized for list-endpoint performance)
    purl_count           INT         NOT NULL DEFAULT 0
        CONSTRAINT sboms_purl_count_nonneg CHECK (purl_count >= 0),

    -- Provenance timestamps
    generated_at         TIMESTAMPTZ NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT sboms_pkey PRIMARY KEY (sbom_id)
);

-- Tenant-scoped primary lookup
CREATE INDEX IF NOT EXISTS sboms_tenant_id_idx
    ON sboms (tenant_id, sbom_id);

-- Image digest lookup (used by drift event ingestion)
CREATE INDEX IF NOT EXISTS sboms_image_digest_idx
    ON sboms (image_digest, tenant_id);

-- Deduplication: one SBOM document digest per tenant
-- (409 returned when same digest bound to different image_digest)
CREATE UNIQUE INDEX IF NOT EXISTS sboms_sbom_digest_image_digest_uq
    ON sboms (sbom_digest, image_digest, tenant_id);

-- GIN index for CycloneDX document JSONB queries
CREATE INDEX IF NOT EXISTS sboms_cyclonedx_gin_idx
    ON sboms USING GIN (cyclonedx_document);

-- ---------------------------------------------------------------------------
-- sbom_components: one row per CycloneDX component in an SBOM
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sbom_components (
    component_id        UUID        NOT NULL DEFAULT gen_random_uuid(),
    sbom_id             UUID        NOT NULL
        REFERENCES sboms (sbom_id) ON DELETE CASCADE,
    tenant_id           UUID        NOT NULL,

    -- PURL (normalized to at most 2048 chars)
    purl                TEXT        NOT NULL
        CONSTRAINT sbom_components_purl_length CHECK (LENGTH(purl) <= 2048),
    name                TEXT        NOT NULL DEFAULT '',
    version             TEXT        NOT NULL DEFAULT '',
    component_type      TEXT        NOT NULL DEFAULT 'library',

    -- Runtime binding quality
    binding_status      TEXT        NOT NULL DEFAULT 'missing'
        CONSTRAINT sbom_components_binding_status_check
            CHECK (binding_status IN ('resolved', 'ambiguous', 'missing')),
    binding_confidence  DOUBLE PRECISION NOT NULL DEFAULT 0.0
        CONSTRAINT sbom_components_confidence_range
            CHECK (binding_confidence >= 0.0 AND binding_confidence <= 1.0),

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT sbom_components_pkey PRIMARY KEY (component_id)
);

-- SBOM-scoped lookup (used to list components for an SBOM)
CREATE INDEX IF NOT EXISTS sbom_components_sbom_id_idx
    ON sbom_components (sbom_id, tenant_id);

-- PURL lookup (used by causal engine for SBOM-to-runtime binding)
CREATE INDEX IF NOT EXISTS sbom_components_purl_idx
    ON sbom_components (purl, tenant_id);

-- ---------------------------------------------------------------------------
-- verification_jobs: async cosign verification job lifecycle
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS verification_jobs (
    verification_job_id UUID        NOT NULL DEFAULT gen_random_uuid(),
    sbom_id             UUID        NOT NULL
        REFERENCES sboms (sbom_id) ON DELETE CASCADE,
    tenant_id           UUID        NOT NULL,

    -- Verification parameters (immutable after creation)
    expected_identity   TEXT        NOT NULL
        CONSTRAINT verification_jobs_identity_length
            CHECK (LENGTH(expected_identity) BETWEEN 1 AND 512),
    expected_issuer     TEXT        NOT NULL,
    rekor_required      BOOLEAN     NOT NULL DEFAULT TRUE,

    -- Job lifecycle state (mutable)
    status              TEXT        NOT NULL DEFAULT 'queued'
        CONSTRAINT verification_jobs_status_check
            CHECK (status IN ('queued', 'running', 'verified', 'failed')),
    submitted_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ,

    -- Result fields (populated on completion)
    signing_identity    TEXT,
    issuer              TEXT,
    rekor_entry_uuid    UUID,
    failure_reason      TEXT,

    CONSTRAINT verification_jobs_pkey PRIMARY KEY (verification_job_id)
);

-- Most-recent job per SBOM lookup
CREATE INDEX IF NOT EXISTS verification_jobs_sbom_id_idx
    ON verification_jobs (sbom_id, tenant_id, submitted_at DESC);

-- Active job lookup (used for 409 detection)
CREATE INDEX IF NOT EXISTS verification_jobs_active_idx
    ON verification_jobs (sbom_id, tenant_id)
    WHERE status IN ('queued', 'running');

-- ---------------------------------------------------------------------------
-- Schema version tracking
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INT         NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description TEXT        NOT NULL,
    CONSTRAINT schema_migrations_pkey PRIMARY KEY (version)
);

INSERT INTO schema_migrations (version, description)
VALUES (1, 'Initial SBOM service schema: sboms, sbom_components, verification_jobs')
ON CONFLICT (version) DO NOTHING;

COMMIT;
