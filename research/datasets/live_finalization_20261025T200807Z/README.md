# PHANTOM live finalization check — 2026-10-25 20:08–20:12 UTC

This is a new evidence batch collected from the already-running lab. No Terraform apply, AWS resource creation, deployment change, attack scenario, benign-control scenario, or pilot run occurred. One harmless `cat /etc/hostname` read was issued in `recommendationservice` to check current telemetry. The initial local working tree and historical evidence were preserved.

## Environment and current services

- AWS account `253490771520`, region `ap-south-1`; EC2 `i-06bb29d253668fa5f` remains running as `t3.xlarge`, private IP `10.89.2.125`, no public IP. SSM reports Online.
- k3s node `ip-10-89-2-125` is Ready, Kubernetes `v1.36.5+k3s1`, Ubuntu `22.04.5`, kernel `6.8.0-1066-aws`. PHANTOM API, Redis, causal engine, eBPF agent, Postgres, SBOM service, sink and evaluation workloads were Running/Ready at inventory time.
- The evaluation image ID is config digest `sha256:149440c61b866ba5265959ea4ce2eb8864be9e4c8e0f6d5cc88546f899ecb8e7`; it corresponds to the `linux/amd64` manifest `sha256:ec4370b0af44b4ba2ffe0247f1b1339c4f4debdba319d025d5753140ccec4184` recorded in the prior batch.

## SBOM status

- The existing Syft `1.55.0` CycloneDX artifact scans the exact platform manifest above. Artifact bytes SHA-256: `sha256:c5b3a412b3534cfb0647b639cbc3e2993bbd2b09797aff9b34ce5a3904e04c80`. The raw artifact remains in this directory and in the existing versioned, AES256 S3 evidence bucket; current S3 HEAD succeeded. Service canonical JSON digest previously computed as `sha256:65fc90d4219c3d53bf2ed82f365376f5433920309406d62af0f799f515daf5bb`.
- The live `phantom_sbom.sboms` table still contains **0** rows. A live request to `/internal/v1/runtime-bindings` for event `7893c151-30ff-4c78-b1d2-38c695c658ec` and the exact image config digest returned `binding_status=unbound`, null SBOM/PURL, and `No SBOM indexed for image_digest=...`.
- The deployed SBOM pod has only its DB URL and log-level environment configured: bucket, region, static credential values, role ARN and web-identity token file are unset. EC2 metadata requires IMDSv2 with hop limit 1; a host request worked, but a request from the SBOM pod timed out. The instance role policy permits objects under `phantom/evidence/*`, while current SBOM source writes `sboms/<id>/cyclonedx.json`. The SBOM namespace egress policy also does not authorize S3. Current role policy and metadata settings are saved in `iam_role_policy.json` and `ec2_metadata_options.json`.
- The live ingestion use case currently saves SBOM metadata/components before attempting artifact upload. Because the pod has no safe role credential path and its key prefix is outside the role grant, an ingestion attempt could leave a misleading partial DB record. We did not invoke it. Exposing the shared node role to application pods by increasing IMDS hop reachability would broaden access to experiment evidence; that was not done.
- The interpreter file hash previously matched a file record in the SBOM, but that record did not identify an application package/PURL. In the current event, the process is `runc:[1:CHILD]`, while the associated workload is `recommendationservice`; the agent event has no executable hash. Hashing this host-side runtime process and attributing it to the container image would be unsound. No live component binding is supported.

## Current harmless event trace

The harmless read generated live event `7893c151-30ff-4c78-b1d2-38c695c658ec`, gateway drift ID `3301755f-fe9e-4824-a93a-13f5549e0ea5`, and outbox ID `80a87336-a48e-4783-b510-48ea46d4e08b`. Postgres showed the same event/outbox with status `published` and Redis ID `1792958994132-0`. Redis `XRANGE` returned the event payload; its `run_id` and `scenario_id` are null, `process.executable_hash` is null, and `sbom_binding` is `unbound` with no evidence. It identifies `runc:[1:CHILD]`, PID `55130`, cgroup-associated `recommendationservice`, and the image config digest above.

At the corresponding live stream check, consumer group `causal-engine-bdg-updater` had advanced through Redis ID `1792958994132-0`, `pending=0`, and `lag=0`. A live causal metrics scrape later returned cumulative `phantom_redis_stream_messages_total{result="success",stream="phantom:drift-events"} 35.0`. This is a cumulative service counter, not an event-specific effect or pilot measurement. No event-specific causal result was found in the causal logs, so this establishes delivery/consumer progress but not causal attribution.

## Oracle, sink, and backup

- The `phantom-eval/phantom-oracle-trust` ConfigMap exists, but `keys` and `revoked_keys` are empty. The repository observer requires direct scenario assertions; no live independent collector is configured. No signed independent observation was created. The harmless smoke event cannot be treated as ground truth.
- Existing sink receipt `0956698a-668c-55e8-9033-e61de20f677c` remains retrievable from the live sink after its earlier pod restart. Current live `/readyz` and `/verify` returned ready and `integrity=valid`, hash `sha256:c0b61d991288437dd5407b9863eb853db2fd66229e4afe902b3a9eb74a29d6aa`; authenticity and independence remain `unverified`. The receipt's oracle result remains unknown.
- A real S3 backup/restore was already completed in the prior evidence batch using the existing project backup client and actual encrypted, versioned bucket. Restore passed SQLite integrity and matched both receipt IDs and hashes. This check made no new backup and did not alter the active database. Backup is manual, not scheduled, and the sink still uses node-local storage.

## Pilot decision

The research readiness gate remains **CLOSED**: SBOM ingestion/indexing and executable-to-component binding are absent; no production trust anchor or independent live observer exists; public egress was not directly tested (only the prior cross-namespace Redis denial was observed); and automated off-node backup is not configured. The planned pilot remains **18 planned / 0 attempted / 0 valid**. No attacks or controls ran. No confusion-matrix metric, detection latency, overhead, or causal-effect estimate is supported.

Raw SSM command outputs, EC2 metadata, SBOM artifact, live binding response, sink verification, prior S3 restore evidence, and checksums are in this directory. The S3 recovery artifacts are carried forward as prior verification, not represented as a new backup test.
