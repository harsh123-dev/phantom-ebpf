# Paper Completion Report

**Empirical paper status: incomplete; no experimental results are available.** The lab was provisioned and the application stack deployed. Harmless smoke tests confirmed real eBPF events, API persistence, current Prometheus metrics, workload-level identity for some events, and access to the internal sink. The experiment was then withheld because the causal consumer does not receive the gateway's published stream, event records lack SBOM binding/provenance, and no independent contract oracle exists.

The manuscript contains the requested sections and verified primary-source background, but it is a transparent research draft, not a completed empirical paper. It makes no performance, causal-effect, or novelty claim. All smoke values are explicitly separated from pilot results. The pilot remains 18 planned / 0 attempted; the extended profile was not run.

Before a valid campaign, align gateway/consumer Redis stream and payload schemas, establish SBOM binding with image digest and provenance, provide independently verifiable contracts and durable sink receipts, and rerun the smoke suite. Then execute a fresh unique pilot and analyze only its actual run artifacts.

## Current source update (2026-10-25)

The Redis schema/stream mismatch and Redis DB mismatch have been repaired and covered by local fake-Redis tests. Agent event records no longer invent a generic violation or placeholder digests; cluster identity is configurable and maps to `phantom-k3s-lab`. Historical zero-only overhead samples are treated as unavailable. The controller's current AWS identity is verified, and no PHANTOM lab resources are present. The SBOM resolver still operates outside the ingestion path; independent contract oracle and durable sink receipts are also unimplemented. Therefore the deployment and pilot remain unready, and this manuscript remains incomplete. The prior deployed smoke evidence is historical and predates these source changes.
## Current status — 2026-10-25

The dedicated AWS lab is running on EC2 `i-06bb29d253668fa5f` in `ap-south-1`. SBOM ingestion and live event delivery are demonstrated; the rebuilt SBOM service now includes Cosign v3.1.4 and rejects verification without an operator-configured signer identity/issuer. The indexed SBOM remains `pending`. The latest harmless event is not attributable to an application component, and no independent observer or production oracle keys exist. The research pilot has **0 attempted and 0 valid runs of 18 planned**. Consequently no experimental detection, overhead, or causal claim is ready for the paper. The lab and prior evidence were preserved; no AWS resource was destroyed. See `PHANTOM_EXECUTION_LOG.md` for commands and timestamped evidence.
