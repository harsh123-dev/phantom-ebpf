PHANTOM lab smoke evidence (not attack/control experiment data)

Captured 2026-10-25 UTC. This directory contains actual deployment and harmless smoke evidence only. No attack scenario was executed and these values are not part of the 18-run pilot.

The API gateway returned 200 for a bounded in-cluster `emailservice` request. The sink accepted a TCP connection from `phantom-eval`; the unauthorized cross-namespace Prometheus service connection was refused (connect_ex 111). A reserved TEST-NET connection was also refused, but that alone is not treated as proof of network-policy enforcement. The active egress policy and internal connection checks are saved alongside these logs.

Prometheus reported the causal-engine, API, agent, and cAdvisor scrape targets UP. The SBOM service has no exporter and was deliberately removed from the scrape list after returning HTTP 404. The agent histogram contained live samples. Preflight snapshots read CPU, RSS memory, and kernel-to-callback event lag from actual Prometheus queries; they are smoke-only measurements, not experimental overhead estimates.

API runtime events included records resolved to the `phantom-eval` emailservice Pod, demonstrating workload attribution by container ID. Those records still contain null SBOM ID/PURL/binding provenance. Contract state is unavailable, and the payload currently contains generic violation entries without evidence of matching an independently registered contract. For those reasons the controlled pilot was withheld.
