# PHANTOM — sbom-service

## Purpose

Ingests CycloneDX JSON SBOMs associated with immutable container image digests,
validates their structure, orchestrates cosign/Sigstore signature verification,
and exposes an internal REST API consumed exclusively by the `api-gateway`.

This service is **not internet-facing**. All public traffic is routed through
`services/api-gateway`.

## Clean Architecture Layers

| Layer | Path | Rule |
|---|---|---|
| Domain | `app/domain/` | No framework imports; pure Python + stdlib |
| Application | `app/application/` | Imports domain ports only |
| Infrastructure | `app/infrastructure/` | asyncpg, S3, cosign CLI, object store |
| Interface | `app/interface/` | FastAPI routers, Pydantic DTOs, DI |

## Local Development

### Prerequisites

- Python 3.11+
- Docker (for PostgreSQL and S3-compatible object store)
- `cosign` CLI on `PATH`

### Setup

```bash
# From repo root — start infrastructure
make docker-up

# Install in editable mode
cd services/sbom-service
pip install -e ".[dev]" -e "../../libs/phantom-core"

# Copy and populate environment
cp ../../.env.example ../../.env
# Edit .env with local values

# Run service locally
uvicorn app.main:app --reload --port 8000
```

### Run Tests

```bash
pytest tests/ -v
```

### Lint and Type-check

```bash
ruff check app/ tests/
mypy --strict app/
```

## Environment Variables

See `.env.example` at the repo root for the full list of required variables.
Key variables for this service:

| Variable | Description |
|---|---|
| `SBOM_SERVICE_DB_URL` | asyncpg DSN for PostgreSQL |
| `SBOM_SERVICE_S3_BUCKET` | S3 bucket for SBOM artifact storage |
| `SBOM_SERVICE_S3_REGION` | AWS region for the configured bucket |
| `SBOM_SERVICE_S3_KEY_PREFIX` | Prefix for SBOM artifacts (must be covered by the configured IAM grant) |
| `SBOM_SERVICE_ALLOWED_ARTIFACT_PREFIX` | Prefix accepted for verifying pre-existing versioned artifacts |

For the self-managed k3s EC2 lab, S3 credentials are configured through a
short-lived `credential_process` and the optional token-review broker described
in [`infra/k8s/k3s-lab/S3_WORKLOAD_IDENTITY.md`](../../infra/k8s/k3s-lab/S3_WORKLOAD_IDENTITY.md).
Do not configure static AWS keys, mount the EC2 instance profile into this pod,
or increase the node's IMDSv2 hop limit. `AWS_EC2_METADATA_DISABLED=true` is
part of the client overlay so missing broker credentials fail closed.
| `SBOM_SERVICE_S3_ENDPOINT_URL` | S3 endpoint (empty = AWS; set for local MinIO) |
| `COSIGN_PATH` | Absolute path to cosign binary (default: `cosign`) |

## API

Internal endpoints (not publicly routable):

| Method | Path | Description |
|---|---|---|
| `POST` | `/sboms` | Ingest CycloneDX SBOM |
| `GET` | `/sboms/{sbom_id}` | Retrieve SBOM metadata and document |
| `POST` | `/sboms/{sbom_id}/verification` | Enqueue cosign verification |
| `GET` | `/sboms/{sbom_id}/verification` | Get verification status |
| `GET` | `/healthz` | Liveness probe |
| `GET` | `/readyz` | Readiness probe |

For importing an already-generated artifact, `POST /api/v1/sboms` may include
`artifact_download_url`, `artifact_version_id`, `artifact_content_sha256`, and
`artifact_manifest_digest` together. The download URL must be a short-lived
AWS S3 presigned GET URL for the exact `s3://` artifact URI and configured
allowed prefix. The service checks the S3 version, raw SHA-256, image-config
and image-manifest metadata, and parsed CycloneDX document before opening a
database transaction. Do not pass static AWS access keys to this service.

To verify an attached Cosign image attestation, ingestion must also include
`image_reference` as the fully qualified immutable
`registry/repository@sha256:<digest>` value. Its digest must exactly equal
`image_digest`; the verifier uses this reference to locate the OCI attestation
and fails closed for legacy digest-only records. An identical re-ingest may
fill a missing image reference once, but cannot replace a different reference.

The k3s-lab renderer `infra/k8s/k3s-lab/render-sbom-s3-egress.py` generates a
NetworkPolicy from the AWS-managed regional S3 prefix list and current Sigstore
TUF, Rekor, and Fulcio DNS answers. It permits cluster DNS, in-cluster Postgres, the private
node credential-broker endpoint, and HTTPS to those S3 / Sigstore addresses.
Kubernetes NetworkPolicy has no portable AWS prefix-list or FQDN selector, so
refresh and review the rendered policy when those addresses change. This
pod-level policy does not govern host-network workloads or the EC2 security
group; it does not grant the SBOM pod general public egress or IMDS access.
