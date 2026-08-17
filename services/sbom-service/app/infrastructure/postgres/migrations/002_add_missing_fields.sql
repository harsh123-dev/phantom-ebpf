-- services/sbom-service/app/infrastructure/postgres/migrations/002_add_missing_fields.sql
--
-- Additive migration: adds fields that are present in the API contract models
-- but absent from 001_initial.sql.
--
-- Changes:
--   sboms:               + format (Literal["CycloneDX"]), + component_count alias
--   behavioral_contracts: new table (referenced in B.3 API contract)
--
-- NOT recreating: sboms, sbom_components, verification_jobs — they exist correctly.
-- NOT renaming:   verification_jobs — kept as-is; the Python repo layer aliases it.
--
-- Idempotent: all ALTER TABLE use ADD COLUMN IF NOT EXISTS.
-- Compatible with PostgreSQL 15+.

BEGIN;

-- ---------------------------------------------------------------------------
-- sboms: add missing columns present in SbomRecord / SbomDetailResponse
-- ---------------------------------------------------------------------------

-- format: always "CycloneDX" (Literal from SbomRecord). Stored for API projection.
ALTER TABLE sboms
    ADD COLUMN IF NOT EXISTS format TEXT NOT NULL DEFAULT 'CycloneDX'
        CONSTRAINT sboms_format_check CHECK (format IN ('CycloneDX'));

-- component_count: denormalized alias for purl_count exposed by SbomRecord.
-- Kept separate so the API can return component_count without aliasing every query.
ALTER TABLE sboms
    ADD COLUMN IF NOT EXISTS component_count INT NOT NULL DEFAULT 0
        CONSTRAINT sboms_component_count_nonneg CHECK (component_count >= 0);

-- ---------------------------------------------------------------------------
-- behavioral_contracts: stores Markov behavioral contracts (B.3)
--
-- One row per (image_digest, purl, tenant_id) — the contract for a specific
-- component binding observed at runtime.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS behavioral_contracts (
    contract_id             UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id               UUID        NOT NULL,

    -- Scope: contract applies to all containers sharing this image+PURL pair.
    image_digest            TEXT        NOT NULL
        CONSTRAINT behavioral_contracts_image_digest_format
            CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    purl                    TEXT        NOT NULL
        CONSTRAINT behavioral_contracts_purl_length
            CHECK (LENGTH(purl) <= 2048),

    -- Version of this contract (semver: "MAJOR.MINOR.PATCH").
    contract_version        TEXT        NOT NULL
        CONSTRAINT behavioral_contracts_version_format
            CHECK (contract_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'),

    -- Serialized Markov model (JSON from domain.markov.serializer.serialize).
    model_json              JSONB       NOT NULL,

    -- sha256 digest over the canonical model_json bytes (for deduplication
    -- and change detection on drift events).
    model_digest            TEXT        NOT NULL
        CONSTRAINT behavioral_contracts_model_digest_format
            CHECK (model_digest ~ '^sha256:[0-9a-f]{64}$'),

    -- Cosign signature bundle URI.  Required for external-source contracts.
    signature_bundle_uri    TEXT,

    -- Signing identity and issuer from the cosign bundle (populated after signing).
    signing_identity        TEXT
        CONSTRAINT behavioral_contracts_identity_length
            CHECK (signing_identity IS NULL OR LENGTH(signing_identity) BETWEEN 1 AND 512),
    signing_issuer          TEXT,
    rekor_entry_uuid        UUID,

    -- Lifecycle state.
    status                  TEXT        NOT NULL DEFAULT 'draft'
        CONSTRAINT behavioral_contracts_status_check
            CHECK (status IN ('draft', 'active', 'superseded', 'revoked')),

    -- Training window metadata.
    training_window_start   TIMESTAMPTZ,
    training_window_end     TIMESTAMPTZ,
    training_event_count    INT         NOT NULL DEFAULT 0
        CONSTRAINT behavioral_contracts_event_count_nonneg
            CHECK (training_event_count >= 0),

    -- Workload selector: JSON object of Kubernetes label selectors.
    workload_selector       JSONB       NOT NULL DEFAULT '{}',

    -- Audit timestamps.
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at            TIMESTAMPTZ,
    superseded_at           TIMESTAMPTZ,

    CONSTRAINT behavioral_contracts_pkey PRIMARY KEY (contract_id)
);

-- Tenant + image + PURL lookup (primary query for drift event matching).
-- This index serves: POST /api/v1/drift-events → contract lookup for violation evaluation.
CREATE INDEX IF NOT EXISTS behavioral_contracts_tenant_image_purl_idx
    ON behavioral_contracts (tenant_id, image_digest, purl);

-- Active-only index for runtime enforcement hot path.
-- This index serves: eBPF agent contract fetch → only active contracts are evaluated.
CREATE INDEX IF NOT EXISTS behavioral_contracts_active_idx
    ON behavioral_contracts (tenant_id, image_digest)
    WHERE status = 'active';

-- Model digest deduplication: prevent storing identical model twice per tenant.
-- This index serves: POST /api/v1/contracts → 409 Conflict on re-submission.
CREATE UNIQUE INDEX IF NOT EXISTS behavioral_contracts_model_digest_uq
    ON behavioral_contracts (model_digest, tenant_id);

-- ---------------------------------------------------------------------------
-- Schema version
-- ---------------------------------------------------------------------------

INSERT INTO schema_migrations (version, description)
VALUES (2, 'Add sboms.format, sboms.component_count; add behavioral_contracts table')
ON CONFLICT (version) DO NOTHING;

COMMIT;
