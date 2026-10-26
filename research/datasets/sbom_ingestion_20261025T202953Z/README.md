# Live SBOM ingestion and pipeline evidence — 2026-10-25

This batch records a targeted SBOM service configuration/deployment and a harmless runtime smoke in the existing lab. It did not create cloud resources, apply Terraform, run attack/control scenarios, or alter earlier evidence.

## Results

- Existing generated CycloneDX artifact: Syft 1.55.0, S3 bucket `phantom-k3s-lab-253490771520-ap-south-1-evidence`, key `phantom/evidence/live_attribution_20261025T194226Z/evaluation-image.cdx.json`, version `SV8YOafJ8buQsqEpJiK7bgE6c0jezWIu`. Raw SHA-256 `sha256:c5b3a412b3534cfb0647b639cbc3e2993bbd2b09797aff9b34ce5a3904e04c80`; canonical CycloneDX SHA-256 `sha256:65fc90d4219c3d53bf2ed82f365376f5433920309406d62af0f799f515daf5bb`. Exact evaluation image config digest `sha256:149440c61b866ba5265959ea4ce2eb8864be9e4c8e0f6d5cc88546f899ecb8e7`; platform manifest `sha256:ec4370b0af44b4ba2ffe0247f1b1339c4f4debdba319d025d5753140ccec4184`.
- Real SBOM service ingestion returned HTTP 201 for SBOM `f6ffce2a-50c1-4284-91f4-5d515e43da9e`, 22,823 components. GET retrieval returned HTTP 200 and matching canonical digest. PostgreSQL count is 1 SBOM / 22,823 components. Verification status is `pending`; artifact identity/integrity was checked but no signing verification was asserted.
- Invalid artifact hash returned HTTP 503 and did not create a row. The idempotency implementation returns the same SBOM ID on an identical retry (HTTP 201); counts remained 1 / 22,823.
- Targeted SBOM egress permits DNS, Postgres, and regional S3 address ranges. The service fetched the actual S3 object through the short-lived presigned URL. IMDS and the reserved TEST-NET probe were unreachable from the SBOM pod. These are probes of the configured policy, not comprehensive proof of public egress denial. The service pod did not acquire node-role credentials; ordinary SDK upload authentication is not live-verified.
- Harmless GETs to the evaluation recommendationservice returned HTTP 200. The separate observed runtime event (`b7869afd-36ce-423a-81e9-3f17e5331a07`) was `runc:[2:INIT]`, without run/scenario IDs or executable hash. It was published to `phantom:drift-events` as Redis ID `1792960618952-0`; the group state was entries-read 49, pending 0, lag 0. The mapper returned `insufficient_evidence` because the SBOM remains pending verification; no SBOM ID, PURL, or confidence was assigned.
- The oracle trust store has 0 trusted keys and 0 revoked keys. No independent live observer or signed observation was configured. The pilot remains 18 planned / 0 attempted / 0 valid.

## Files

- `live_ingestion_result.json`: machine-readable summary and command IDs.
- `sbom_*_ssm.json`: actual SSM invocation outputs for build, deployment, indexing, failure/idempotent retry, network and pipeline checks.
- `build-context*.tar.gz`, `.sha256`, and S3 response: source context used to build the SBOM service.
- `sbom-restricted-egress.yaml`: rendered pod-specific policy.

## Verification limits

The real service, Postgres, S3 object, and Redis stream were exercised. The indexed CycloneDX document is not yet trusted as verified; executable-to-component attribution remains unknown; no independent contract oracle or receipt was produced. No pilot or performance measurement is included.
