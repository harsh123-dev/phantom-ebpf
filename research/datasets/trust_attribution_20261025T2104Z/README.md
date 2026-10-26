# Live trust and attribution check — 2026-10-25 21:04 UTC

This directory contains raw AWS SSM command results and the read-only S3 object
listing from the existing PHANTOM lab. It is a harmless smoke check, not a
research-pilot run. No attack scenario was executed.

- `cluster_status.json`: k3s pod readiness from SSM command
  `6815a36d-98f5-409d-b541-f124f010681a`; all listed PHANTOM pods were 1/1.
  A separate JSONPath image query in that command failed to parse; no image
  identity claim is based on it.
- `trust_and_agent_status.json`: SSM command
  `4f18c5d9-044f-4d0d-9405-79e2031c1744`; deployed oracle trust ConfigMap
  contained zero keys. Recent agent logs contained `identity_insufficient`.
- `direct_application_probe.json`: SSM command
  `76ab00f9-02db-47e6-85f9-26ad0092de8b`; a host-side HTTP GET to the
  internal recommendationservice ClusterIP returned 200. The subsequent agent
  log sample contained `identity_insufficient` and no attributable application
  `dispatcher.success` entry.
- `application_and_agent_logs.json`: SSM command
  `d4ded387-eee8-41cf-9f96-48766d1c27da`; application logs show the direct
  `curl/7.81.0` request at 21:04:44 UTC. The first log command returned no
  `dispatcher.success` entries in the sampled two-minute interval.
- `source_prefix_objects.json`: the source S3 prefix contained the indexed
  CycloneDX JSON and a SQLite backup, with no separate attestation object in
  that prefix. This listing does not prove that no attestation exists elsewhere.
- `signer_binary_and_oracle_trust.json`: SSM command
  `095a0343-62e3-44b6-a469-20225b3fc5e0`; `command -v cosign` inside the
  deployed SBOM container returned no path. The deployed oracle trust
  ConfigMap again contained zero keys.

Previously verified exact image-config digest:
`sha256:149440c61b866ba5265959ea4ce2eb8864be9e4c8e0f6d5cc88546f899ecb8e7`.
Previously verified CycloneDX canonical digest:
`sha256:65fc90d4219c3d53bf2ed82f365376f5433920309406d62af0f799f515daf5bb`.
See the earlier `sbom_ingestion_20261025T202953Z` batch for ingestion and
retrieval evidence. This check did not re-ingest or re-verify the artifact.

The SBOM is still not independently signed and trusted; the oracle public-key
store is empty; no live independent scenario assertion exists. Application
process identity, executable hash, component binding, and run correlation were
not demonstrated. Research pilot gate remains closed (0 attempted / 18 planned).
The source verifier was tightened and tested locally after this live check;
those changes have not been deployed and do not change this evidence.
