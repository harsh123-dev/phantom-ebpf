# PHANTOM live attribution and evidence check — 2026-10-25

This is a fresh, non-pilot evidence batch for the already-running lab. No AWS resources were created, no Terraform was applied, and no attack or benign-control scenario was run. The evidence includes live cluster queries, one harmless evaluation workload file-read smoke action, a real sink receipt, a manual off-node S3 backup/restore, and a Syft-generated SBOM for the exact evaluation image.

## Deployment and event path

- AWS account `253490771520`, region `ap-south-1`; EC2 `i-06bb29d253668fa5f` remained running at private IP `10.89.2.125`.
- k3s node `ip-10-89-2-125` was Ready on Ubuntu 22.04.5, kernel `6.8.0-1066-aws`; all listed PHANTOM and evaluation pods were Ready at the final check.
- Evaluation runtime image: reported image config digest `sha256:149440c61b866ba5265959ea4ce2eb8864be9e4c8e0f6d5cc88546f899ecb8e7`, linked by containerd to `linux/amd64` manifest `sha256:ec4370b0af44b4ba2ffe0247f1b1339c4f4debdba319d025d5753140ccec4184` and index `sha256:65e64e74e7dae09ad70c005a252021cfd3b8dfe5bb83b1d40d3f6ac8e51ea58d`. The evaluation pods reported the same config digest.
- After a harmless file-read invocation in `recommendationservice`, API rows and Redis stream messages were present. Example event IDs are in `runtime_event_smoke.csv`; records had no run/scenario identity, no executable hash, and unbound SBOM evidence. The Redis consumer group's `entries-read` was 22, pending 0, lag 0. The causal metric later reported 28 cumulative successes; this counter is not a per-event experiment label.
- A cross-namespace TCP connect attempt from `phantom-eval` to the PHANTOM Redis service returned `connect_ex=111` (connection refused). The applied evaluation egress policy permits DNS and selected in-namespace/sink destinations, not the PHANTOM namespace. No public endpoint was contacted; host egress still permits TCP 80/443 via NAT.

## SBOM artifact

Syft `1.55.0` was downloaded from the official release and its Linux amd64 archive matched the published SHA-256 `bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d`. It scanned the exact `linux/amd64` manifest digest above with `--scope all-layers`, producing CycloneDX 1.7 with 22,823 components (22,268 file entries). The artifact SHA-256 is `sha256:c5b3a412b3534cfb0647b639cbc3e2993bbd2b09797aff9b34ce5a3904e04c80`; the SBOM service's canonical JSON digest, if ingested, is `sha256:65fc90d4219c3d53bf2ed82f365376f5433920309406d62af0f799f515daf5bb`.

Syft listed `/usr/local/bin/python3.11` as a file with SHA-256 `46d05ca7094b029959f0218e990a7f2737dbc87d5b2e783ecfc44e978937922a`; hashing that file inside the running evaluation container produced the same value. This is file-level image evidence. The eBPF event still carries `executable_hash: null`, the executable is an interpreter, and no package occurrence/PURL associates that file with an application package. The live mapper therefore remains unbound.

The document is preserved locally and in the existing versioned evidence bucket. It was **not indexed** in the SBOM service: the service has no configured artifact bucket or S3 credentials, defaults to `phantom-sbom-artifacts`, and its artifact key path (`sboms/<id>/...`) is outside the lab role's permitted `phantom/evidence/*` prefix. We did not call ingest because the use case persists the SBOM/components before attempting the failing artifact upload, which would leave a partial database record. The live `phantom_sbom.sboms` count remained zero.

## Sink and S3 recovery

The real FastAPI sink accepted receipt `0956698a-668c-55e8-9033-e61de20f677c`, correctly recorded outcome `unknown`, and returned integrity hash `sha256:c0b61d991288437dd5407b9863eb853db2fd66229e4afe902b3a9eb74a29d6aa`. Receipt retrieval and integrity verification remained valid after restarting the sink deployment. Authenticity and independence remain unverified.

A SQLite online snapshot from the restarted sink passed `integrity_check` and contained two receipts. The existing `S3EvidenceBackupClient` wrote it to the actual AWS bucket, then restored the object to a fresh database. The object was versioned and AES256 encrypted; the restored database passed SQLite integrity checks and matched both receipt IDs and canonical payload hashes. Object key: `phantom/evidence/live_attribution_20261025T194226Z/sink-receipts-20261025T194226Z.sqlite3`; version ID and hashes are in `s3_backup_restore_result.json`. This was a manual backup/recovery test, not an automated schedule or proof against every node-loss mode. The active PVC remains single-node `local-path`.

## Pilot decision

The 18-run pilot was not run. The production oracle trust ConfigMap has no keys; no live independent observer supplied a signed contract observation; SBOM component binding remains unbound; the artifact is not indexed; and public egress was not directly probed. Although the manual S3 backup/restore passed and cross-namespace isolation was observed, required ground-truth and attribution gates remain closed. No detection-performance, latency, resource-overhead, or causal-effect result is claimed.

Detailed raw SSM responses are in `ssm/`; SBOM and receipt artifacts, AWS metadata, backup metadata, and SHA-256 checks are retained alongside this README.


## Evidence timestamps and credentials

The receipt response records `created_at=2026-10-25T19:46:14.185107+00:00`. Its run ID contains a `194800Z` string that was only an operator-selected smoke label and does not match the server timestamp; no experiment or scenario timing is inferred from it. The manual S3 backup/restore used `S3EvidenceBackupClient` with the existing controller AWS identity `arn:aws:iam::253490771520:user/harsh2`; the SBOM artifact object was separately uploaded by the lab instance profile. Neither action created new AWS infrastructure.
