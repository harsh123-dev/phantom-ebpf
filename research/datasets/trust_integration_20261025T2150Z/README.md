# SBOM verifier rollout and trust gate

The source archive was used to build/deploy `phantom/sbom-service:trustfix-20261025T2150Z` on the existing lab. `sbom_rollout.json` records a successful SSM build/import/rollout and Cosign v3.1.4 in the running pod. `cosign_release_metadata.json` records the official release asset metadata used to pin the binary checksum. `live_verifier_check2.json` records HTTP 503 for a verification request with no operator-configured signer/issuer. `sbom_retrieval_record.json` records live GET of indexed SBOM `f6ffce2a-50c1-4284-91f4-5d515e43da9e` with 22,823 components and `pending` verification status. `live_verifier_check.json` is an earlier command that failed to stream the in-pod Python script; its output is retained for transparency.

`SHA256SUMS` hashes each other file in this directory. The rollback-safe trust check is source/live engineering validation only; it is not a verified SBOM attestation.
