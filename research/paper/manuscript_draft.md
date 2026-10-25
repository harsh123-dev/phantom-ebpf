# PHANTOM: Causal Attribution of Runtime SBOM Drift via eBPF Behavioral Contracts in Kubernetes

## Abstract

PHANTOM is a research prototype intended to connect eBPF observations of Kubernetes workloads with software bills of materials (SBOMs), behavioral contracts, and causal analysis. We provisioned a dedicated single-node k3s lab and verified live kernel-event capture, API persistence, Prometheus scraping, and workload identity for a subset of harmless smoke events. The experiment was withheld before any attack or control run: the API gateway publisher and causal-engine consumer use incompatible Redis stream names and message schemas, resolved events lack SBOM component binding and provenance, and no independent contract oracle is available. Thus this execution reports no detection-performance, causal-effect, or attack-overhead result. The smoke measurements are infrastructure validation only and are not experimental observations.

## 1. Introduction

An SBOM records software components and supply-chain relationships, providing a foundation for transparency [1]. It does not by itself establish which components or behaviors are active in a particular runtime. PHANTOM explores whether kernel-level observations can be attributed to deployed workloads and linked to component-level behavior contracts, and whether a causal model can help explain observed drift.

This execution establishes a real deployment path but also identifies an end-to-end gap between event persistence and causal processing. Without component bindings and independent contract state, a system cannot support the study's central attribution claim. Accordingly, this manuscript reports the deployment and its negative readiness result rather than treating successful event capture as evidence of SBOM drift detection.

## 2. Related Work

The NTIA minimum-elements report defines SBOM data fields, automation support, and practices that support component transparency [1]. Kubernetes NetworkPolicy expresses pod-level ingress and egress controls, while enforcement depends on the cluster networking implementation [2]. Linux kernel documentation describes eBPF, including verifier, helper, map, and program interfaces [3]. These primary sources contextualize PHANTOM's design. This brief review is not exhaustive and establishes no novelty claim; comparison with runtime integrity monitoring, workload behavior systems, software supply-chain security, and causal inference research remains future work.

## 3. Methodology

The intended design observes kernel events, attributes events to a workload and SBOM component, compares runtime behavior with a declared behavioral contract, records detector outputs separately from independent ground truth, and analyzes causal hypotheses only when assumptions and diagnostics support identification.

The event-delivery metric uses a kernel monotonic timestamp and the userspace monotonic clock at ring-buffer callback entry. It measures kernel-to-callback delivery delay only. It is distinct from API ingestion lag, detection latency, and total end-to-end latency. Scenario detection latency, if evaluated in a future valid campaign, is measured from intervention time to the first qualifying PHANTOM record.

## 4. Implementation

The repository contains an eBPF agent, API gateway, causal engine, SBOM service, Kubernetes manifests, Prometheus configuration, and a YAML-driven scenario runner. In this execution, the agent loaded on an Ubuntu 22.04.5 EC2 host with kernel BTF. The API gateway persisted actual event records, and Prometheus scraped the API, causal engine, agent, and cAdvisor. A harmless emailservice event resolved to a Pod and container, but its SBOM ID, PURL, binding status, and provenance were null.

The live inspection found the gateway publishing to `phantom:bdg:mutations`, while the causal consumer listens on `phantom:drift-events` and expects different fields. Its consumer group had not delivered any messages. The agent also attached a generic violation to events without a verified contract oracle. These implementation gaps block the intended component-level attribution.

## 5. Evaluation Design

The configured pilot defines three attack scenarios and three benign controls, each repeated three times, for 18 planned runs. A separate extended design defines six attacks plus three controls, each repeated three times, for 27 total. The runner's 18-case dry-run matrix was checked. No attack or control injection was executed because the pipeline did not pass causal-consumer, SBOM-binding, and ground-truth readiness checks.

## 6. Results and Discussion

The cluster deployed and reached Ready state. The eBPF agent exported live events; the API stored them; four actual Prometheus target groups were UP. A harmless request to the emailservice returned HTTP 200, and an evaluation Pod reached the internal sink. The network policy refused a connection from the evaluation namespace to the monitoring service in another namespace.

At 2026-10-25 15:08 UTC, smoke-only Prometheus queries returned an agent CPU rate of 0.00942 cores, RSS of 69.73 MiB, and a kernel-to-callback p95 of 32.96 ms. These are point-in-time infrastructure observations and are not attack overhead or scenario latency. No pilot run was attempted, so detection performance, false-positive rate, confidence intervals, causal effect, and experimental overhead are not estimable.

The key negative result is that durable API ingestion did not imply causal-engine processing: the live stream group remained at ID `0-0`. Furthermore, workload-level attribution did not reach SBOM-component attribution. These findings identify missing integration work; they do not establish that the PHANTOM method succeeds or fails as a detector.

## 7. Limitations and Threats to Validity

No controlled run data exists. Contract drift was not independently verified, and no alert outcome can be scored. Sample smoke events included ambiguous host/runtime events and generic violation entries. Workload identity was resolved for some records but not component identity. NetworkPolicy checks establish the active rules and observed in-cluster connection behavior, not universal isolation guarantees. The single-node lab and smoke point estimates cannot establish performance, statistical power, external validity, or causal identification.

## 8. Conclusion

A dedicated lab demonstrated that the eBPF agent can produce events that the API gateway persists and Prometheus can scrape. The causal engine did not consume those events under the deployed stream configuration, and SBOM/contract bindings were unavailable. We therefore withheld the 18-run pilot and made no empirical detection or causal claim. The next valid step is to align the stream schema, implement provenance-backed component binding, provide independent contract and sink evidence, then repeat the readiness checks before a new uniquely recorded campaign.

## References

1. National Telecommunications and Information Administration. *The Minimum Elements for a Software Bill of Materials (SBOM)*, July 12, 2021. https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom
2. Kubernetes Authors. *Network Policies*. https://kubernetes.io/docs/concepts/services-networking/network-policies/
3. Linux Kernel Documentation. *BPF Documentation*. https://docs.kernel.org/bpf/

## Current implementation status note (2026-10-25)

After the historical smoke deployment described above, the AWS lab was destroyed and read-only checks found no PHANTOM lab resources. The source now uses a shared versioned Redis event envelope and no longer fabricates agent contract violations or identity digests. Local tests cover the message adapter and isolated SBOM resolver, but the SBOM resolver is not connected to event ingestion and independent contract/sink evidence remains unavailable. No deployment or pilot has been performed with this updated source. These code changes are engineering validation only and do not alter the manuscript's empirical conclusions.
