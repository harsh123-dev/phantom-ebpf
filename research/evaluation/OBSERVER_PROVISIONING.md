# Independent observer provisioning gate

This is an operational handoff, not a production trust anchor. No private key
or approved public key is checked into this repository. The deployed
`phantom-oracle-trust` ConfigMap intentionally contains zero keys.

## Required separation

1. A contract-registry owner outside the PHANTOM detector approves the exact
   workload selector, immutable image digest, active contract constraints,
   version, and effective time. That owner signs the canonical contract
   snapshot with an Ed25519 key. The registry private key must be controlled
   by the registry owner, not mounted into the agent, gateway, causal engine,
   SBOM service, sink, or scenario runner.
2. A separate observer operator runs a collector with read-only Kubernetes
   access to the evaluation namespace and read access to independent audit or
   sink receipts. The collector must implement each direct assertion named in
   `scenario_oracle_policies.yaml`, including injection success and a complete
   observation interval for compliance. It must retain raw responses and
   timestamps under a unique run ID. It must not read PHANTOM alerts or causal
   decisions to decide contract state.
3. The observer signs the complete canonical payload through
   `scenario_observer.py` only after direct assertions and the registry-signed
   contract pass validation. Its private key stays in that separately
   administered process. `load_observer_private_key` requires a regular 0600
   PEM file and rejects symlinks; a production KMS/HSM adapter would need the
   same isolation and an explicit implementation before use.
4. An owner independent of both PHANTOM and the observation payload verifies
   public-key fingerprints out of band, records key ownership and validity,
   and provisions only public keys to the sink trust configuration. Merely
   generating a key and marking it `independent_of_phantom=true` does not
   establish independence.

## Trust configuration format

The sink reads `PHANTOM_ORACLE_TRUSTED_KEYS_FILE`, currently mounted from the
`phantom-oracle-trust` ConfigMap. Its JSON must contain `schema_version: "1.0"`,
`trust_store_id`, monotonically increasing integer `generation`, `keys`, and
`revoked_key_ids`. Each `keys` entry has `key_id`, `source_id`, `source_type`,
`public_key_pem`, and `independent_of_phantom`. Use source types
`verified_contract_registry` and `independent_runtime_monitor` only after
separately confirming those operational roles. The sink rejects private PEM,
unknown/revoked IDs, unsupported algorithms, invalid signatures, stale
observations, identity mismatch, and replay. Rotate by publishing a higher
generation with the old ID in `revoked_key_ids`; do not reuse key IDs. Retain
the signed approval record and old trust-store hashes with the experiment.

## Missing live integration

The current runner saves unknown receipts because no separate collector emits
`HarnessAssertion` records. It also lacks a verified per-run event ID and an
independently queried immutable workload image identity for the observer
handoff. Before any live pilot, implement and test an observer process that
receives each unique run ID, collects raw scenario-specific assertions from
Kubernetes/audit/sink sources, records the corresponding event ID, and sends
its signed observation to the sink. Verify a receipt by retrieval after sink
restart and by off-node backup/restore. A signed assertion cannot repair a
failed injection, missing interval, untrusted contract, or ambiguous workload.

The key owner must provide the approved public keys, their fingerprints,
source IDs, trust-store generation, custody/rotation record, and the signed
contract snapshot. The separate collector owner must provide its deployment
identity and read-only evidence access. Until then, keep the trust file empty
and the research pilot closed.
