# PHANTOM signed oracle and evidence sink

## Trust model

The oracle accepts only schema `1.0` Ed25519 envelopes. It signs canonical UTF-8
JSON (sorted keys, compact separators, no NaN) containing the observation ID,
run/scenario/event IDs, workload and immutable image digest, contract snapshot,
expected and observed state, timestamp, behavior, details, evidence references,
and interval completeness. The sink loads public keys from
`PHANTOM_ORACLE_TRUSTED_KEYS_FILE`, a JSON trust configuration with
`schema_version`, immutable `trust_store_id`, monotonically increasing
`generation`, `keys`, and `revoked_key_ids`; incoming messages cannot add keys.
The sink pins the configuration hash and active/revoked key IDs in the receipt
database. A restart with a generation rollback, same-generation edit, removed
key without explicit revocation, or reactivated revoked key fails closed. For
rotation, publish a higher generation that adds the replacement key and lists
the retired key in `revoked_key_ids`, then restart the single sink writer.
Revocations are persisted monotonically. Private keys must remain with the
independent collector. No production private key is included here.

Only configured keys marked `independent_of_phantom: true` can establish a
confirmed outcome. This is an operator trust decision, not something a digital
signature proves. The signature proves that the configured key signed these
bytes; it does not prove the collector's conclusion is true or that its data
collection is independent. The actual independent observation source is still
missing: no separately operated collector presently observes runtime behavior
and compares it with a separately authenticated contract snapshot. A production
integration must supply both, bind them to run/scenario/workload/image/event
identity and evidence references, and protect its signing key outside PHANTOM.
The Kubernetes trust ConfigMap intentionally has no trusted keys, so the
deployment can record attempts as `unknown` but cannot establish live confirmed
contract outcomes. Test-only signing keys exercise cryptography and do not
provide production trust anchors.

Signatures bind every observation field. Invalid signatures, unknown keys,
unsupported algorithms, malformed payloads, stale observations (default five
minutes with 30 seconds future skew), and request/payload identity mismatches
are rejected. A signed but missing/ambiguous evidence set, incomplete compliance
interval, or observation that conflicts with contract evaluation remains
`unknown`. A key/observation ID may be consumed once. An identical retry for
the same event returns the existing receipt; changed evidence conflicts.

## HTTP service

The service runs `research/evaluation/evidence_sink_service.py` on port 9191.
`POST /v1/receipts` takes strict JSON fields `run_id`, `scenario_id`, optional
UUID `event_id`, `workload`, `processing_outcome`, `provenance`, and optional
`signed_observation`. Without the signed observation the response is explicitly
unknown. `GET /v1/receipts/{receipt_id}`, `/v1/receipts/{receipt_id}/verify`,
and `/v1/runs/{run_id}/receipts` retrieve and verify records. A 201 response is
returned only after SQLite commits the receipt with `synchronous=FULL`.

Legacy scenario beacon TCP ports 8443, 4445, 4446, and 8080 now persist a
separate passive connection record (peer address/port, local port, byte count,
and SHA-256 of up to 64 KiB received). These raw connections do not carry run
or scenario identity, so their receipt explicitly reports both as null and the
outcome as unknown. They must not be used alone as run-level ground truth.

The canonical API runtime-evidence schema permits optional `run_id` and
`scenario_id` correlation fields. The current eBPF agent does not know the
runner's IDs and does not populate them; a scenario observer must correlate and
sign those values independently before run-level evidence can be accepted.

## Kubernetes persistence and access

The deployment uses one replica and `Recreate`, a 2 GiB `ReadWriteOnce`
`local-path` PVC, non-root UID/GID 10001, dropped capabilities, the runtime
default seccomp profile, and a read-only root filesystem. The service is a
ClusterIP and the sink ingress policy permits beacon ports only from the
configured evaluation workload labels; HTTP receipts are limited to a labeled
evidence collector or the API gateway. There is no public service or ingress.
SQLite WAL files and database are
created with owner-only permissions; commits use FULL synchronous mode.

This is single-node persistence, not replicated storage. The local-path PVC
survives a container restart and normally a pod recreation on that node, but it
does not protect against node/disk loss or instance termination. Successful
HTTP responses follow an SQLite transaction commit using `synchronous=FULL`;
this is a local commit guarantee, not a backup guarantee.

`evidence_backup.py` uses SQLite's online backup API, checks SQLite integrity,
and verifies every stored receipt hash before publishing a backup. It refuses
to overwrite an existing backup path. It can restore only to a new path and
verifies the restored database using the same checks. The helper's behavior is
covered by local tests, including tamper rejection; this is not an automated
backup schedule or a test against node/disk loss. For the AWS lab, mount a
separately encrypted EBS backup volume at `/backup`, restrict it to the sink
operator, and schedule a unique timestamped backup while the sink is running:

```bash
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
python -m research.evaluation.evidence_backup backup \
  /data/evidence.sqlite3 "/backup/phantom-evidence-${STAMP}.sqlite3"
python -m research.evaluation.evidence_backup verify \
  "/backup/phantom-evidence-${STAMP}.sqlite3"
```

Do not copy only the SQLite main file while WAL writes are active. This helper
does not configure off-node storage or node-loss recovery.

### S3 off-node backup path

`evidence_s3.py` provides a boto3 client and CLI (`python -m
research.evaluation.evidence_s3 backup <database>` and `restore <object-key>
<new-database-path>`). It creates and validates a SQLite online snapshot,
computes SHA-256 over the database bytes, sends an S3 SHA-256 checksum, asks for
SSE-S3 (`AES256`), stores integrity/count metadata, and uses conditional
`If-None-Match: *` writes. Each normal backup key contains a UTC timestamp and
random UUID. Restore checks server encryption, object size, SHA-256, SQLite
integrity, and every receipt hash before writing to a new destination. It
supports a specific version ID. A single PUT is limited to 5 GiB; larger files
fail closed. Interrupted PUTs do not expose partial objects; retry with a new
backup ID, or inspect the known key after an ambiguous network timeout.

The S3 client test suite uses an in-memory protocol test double. One test deletes
the source SQLite database and restores a receipt into a new database through
that double. This verifies client logic, not AWS S3, IAM, bucket policy,
versioning, or independent off-node durability. The Terraform bucket is
opt-in (`enable_evidence_backups = true`), versioned, public-access-blocked,
SSE-S3 encrypted, TLS-only, and tagged for PHANTOM. The instance role is
limited to listing and reading/writing the configured evidence prefix; it has
no object-delete permission. The EC2 metadata endpoint requires IMDSv2 and uses
hop limit 1, so Kubernetes pods cannot use the host instance profile. Backups
must be initiated by a controlled host-side job with the instance profile;
there is no scheduled job in this checkout.

Set `PHANTOM_EVIDENCE_BACKUP_BUCKET` from the Terraform output,
`PHANTOM_EVIDENCE_BACKUP_PREFIX` to the configured prefix, and `AWS_REGION` to
the lab region in that host job. Retain all current and prior object versions
through experiment analysis and paper archival. No automatic expiry is
configured; incomplete multipart uploads are cleaned after seven days. Delete
versions only after the research owner approves retention cleanup and confirms
that reports and required evidence have been archived.

Recovery: stop the single sink writer; select a backup key and version; run the
S3 `restore` command to a new local path; retrieve representative receipt IDs
with the sink store and verify the restored receipt count/hash report; then
point the sink at the restored DB and restart it. Preserve the original DB and
backup objects until recovery is reviewed.

## Scenario observer boundary

`scenario_oracle_policies.yaml` fixes the scenario IDs, expected state, direct
assertion identifier, and behavior type. `scenario_observer.py` does not accept
PHANTOM alerts or causal results. It requires a successful injection, the
scenario's matching direct assertion, immutable image/workload identity,
evidence references, a fresh timestamp, and a separately Ed25519-signed active
contract snapshot signed by a distinct `verified_contract_registry` key.
Compliance additionally requires a complete independent observation interval.
It signs the canonical payload only after these checks; the sink independently
verifies the observer signature and the nested contract-registry signature,
then recomputes the contract outcome. Missing registry attestation leaves a
signed observation unknown; an invalid, unknown, or revoked registry key is
rejected.

The private signing key is loaded only by the observer process from a regular
0600 file named by `PHANTOM_ORACLE_SIGNING_KEY_FILE`; it must not be mounted in
the detector or evidence-sink pod. The contract-registry public key and
observer public key are separate entries in the sink trust configuration.
Operators control that public trust configuration and rotate it by incrementing
the trust-store generation and explicitly revoking retired IDs. No production
private key or trusted public key is provided here. The repository still lacks
the live scenario-specific collector that produces `HarnessAssertion` records
from read-only workload checks and independently retained sink/audit evidence.
Until that adapter and a production trust anchor are deployed, runner results
remain unknown; unit fixtures do not establish live independence.

## Verification status — 2026-10-25

Latest local suites: evaluation 265 passed, core 48, agent 160, SBOM 185,
gateway 63, and causal engine 375 passed with one skipped because local
`redis-server` is unavailable. Total across these suites: 1,096 passed, one
skipped, zero failed. The composed test uses fake Redis and an in-memory S3
protocol test double; FastAPI routes and file-backed SQLite are actual local
components. It deletes the test source DB and restores it through the test
double, so it does not prove AWS object durability or node-loss recovery.

Terraform formatting and validation passed. A read-only plan with
`enable_evidence_backups=true` proposed 13 creates, no changes, and no destroys,
including the dedicated EC2 lab and opt-in S3 bucket. The plan was saved to
`/tmp/phantom-evidence-backup.tfplan` and was not applied. No S3 bucket or other
AWS resource has been created. The plan still uses a public IPv4 address and
unrestricted security-group egress; both require review before any apply.

The deployment gate remains closed: no production contract-registry or
observer key is configured, no separate live harness collector produces
`HarnessAssertion` records, no actual AWS backup/restore was exercised, and no
live agent-to-SBOM evidence exists. Agent executable hashes remain unavailable.

Build with the repository root as context:

```bash
docker build -f research/evaluation/Dockerfile.evidence-sink -t phantom/evidence-sink:latest .
```

Import that image into the lab node's k3s containerd before applying
`research/evaluation/k8s/target-workloads.yaml`. No image was built or deployed
as part of the local code/tests in this change.
