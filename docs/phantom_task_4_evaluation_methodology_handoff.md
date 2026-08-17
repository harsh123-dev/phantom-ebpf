# PHANTOM Task 4: Evaluation Methodology Design

This document is the ground-truth evaluation specification for "PHANTOM: Causal Attribution of Runtime SBOM Drift via eBPF Behavioral Contracts in Kubernetes." It is written for an IEEE EuroS&P / ACM SACMAT style paper and for implementation by Claude Code Task 8. Numeric outcomes are intentionally represented as `[RESULT_X]` placeholders.

Methodological precedent: the evaluation follows common systems-security practice used in runtime intrusion detection, provenance/causal attack investigation, and security artifact papers: controlled attack/control scenarios, independent ground-truth manifests, per-detector comparison under identical workloads, time-to-detection reporting, calibration analysis, refutation tests, and overhead measurement against an instrumented/uninstrumented deployment.

## Section 1: Formal Research Questions

RQ1: Can PHANTOM detect runtime SBOM drift caused by supply-chain component substitution that rule-based and static SBOM tools miss?

Motivation: Supply-chain drift is dangerous because the deployed component may still satisfy static dependency metadata while its runtime behavior changes. This question tests whether PHANTOM's behavioral contracts and eBPF-derived runtime evidence detect attacks that are invisible to static scanning or to generic rule triggers.

How answered: Run the three attack scenarios and three benign controls under identical Online Boutique load, then compare PHANTOM against Falco, Trivy, Isolation Forest, and CVSS-only prioritization using TPR, FPR, precision, recall, F1, false positives per hour, and MTTD.

Baseline comparison: Falco default rules for runtime policy, Trivy SBOM static scan for declared package state, Isolation Forest over syscall frequencies for unsupervised anomaly detection, and CVSS-only priority ranking for non-runtime vulnerability triage.

Null hypothesis: PHANTOM does not improve drift detection over the strongest baseline.

Supports null: PHANTOM's F1, TPR, and MTTD are statistically indistinguishable from or worse than the strongest baseline, with no reduction in benign false positives.

Rejects null: PHANTOM obtains higher F1/TPR and lower or comparable FPR/MTTD than the strongest baseline across attack scenarios while remaining quiet on benign controls.

---

RQ2: Can PHANTOM accurately attribute detected runtime SBOM drift to the substituted component, and does it correctly withhold causal claims when the causal effect is not identifiable?

Motivation: Detection alone is insufficient for response; operators need to know which component caused the behavior and when the evidence does not justify a causal claim. This question evaluates both attribution correctness and epistemic restraint through the explicit `not_identifiable` state.

How answered: Compare PHANTOM's top attributed PURL and causal-effect status against independent oracle manifests for each injected attack. Add ambiguous temporal projections and missing-confounder stress cases to test whether DoWhy returns `not_identifiable` instead of a forced attribution.

Baseline comparison: Compare against non-causal ranking by KL divergence only, graph centrality only, Isolation Forest anomaly score localization, and random component selection among active PURLs.

Null hypothesis: PHANTOM's causal attribution is no more accurate than non-causal localization and does not reliably identify non-identifiable cases.

Supports null: Attribution accuracy is indistinguishable from KL-only or centrality-only ranking, or `not_identifiable` cases are incorrectly assigned to concrete components.

Rejects null: PHANTOM improves exact/partial attribution accuracy and returns `not_identifiable` for designed non-identifiable cases at the expected rate.

---

RQ3: Can PCEPS predict exploitation risk before an attack fully materializes?

Motivation: The paper's pre-compromise claim depends on estimating exploit probability before the full attack behavior appears. This question tests whether PCEPS adds predictive value beyond CVSS and drift score alone and whether the probabilities are calibrated.

How answered: Score sliding windows before, during, and after attack injection. Label a pre-compromise window positive if it occurs after substitution begins but before the oracle-defined compromise marker. Compare AUC-ROC, AUC-PR, Brier score, reliability diagrams, and lead time.

Baseline comparison: CVSS v3 score only, KL-divergence score only, graph centrality only, and uncalibrated XGBoost without Platt scaling.

Null hypothesis: PCEPS does not predict exploitation earlier or more accurately than CVSS-only or drift-only scoring.

Supports null: PCEPS AUC/calibration and mean lead time are indistinguishable from or worse than baselines.

Rejects null: PCEPS improves AUC-ROC/AUC-PR and Brier score, and its alert time precedes the oracle compromise marker by `[RESULT_X]` seconds on average.

---

RQ4: Is PHANTOM's eBPF collection and analysis overhead acceptable for production Kubernetes workloads?

Motivation: Runtime security systems must not meaningfully degrade service latency, throughput, CPU, memory, or event fidelity. This question determines whether PHANTOM is practical for continuously monitored Kubernetes deployments.

How answered: Run the benchmark with PHANTOM disabled and enabled under identical load, measuring CPU, memory, p50/p95/p99 request latency, throughput, event loss, and collection latency. Repeat each trial three times.

Baseline comparison: Compare uninstrumented workload, Falco-enabled workload, and PHANTOM-enabled workload.

Null hypothesis: PHANTOM imposes unacceptable overhead relative to uninstrumented and Falco deployments.

Supports null: PHANTOM causes material degradation in latency, throughput, CPU, memory, or event loss beyond the paper's declared acceptability threshold.

Rejects null: PHANTOM overhead remains within the declared threshold, with p95 collection latency and event loss low enough for timely detection.

---

## Section 2: Attack Scenario Specifications

SCENARIO NAME: XZ-Utils Style Library Backdoor

Attack family: supply_chain_backdoor

Target workload: Online Boutique `recommendationservice`, because it is Python-based, imports compression/utility libraries naturally, and has enough request-driven execution to expose process and network anomalies without modifying checkout/payment logic.

Target component: `pkg:pypi/lzmaffi@1.0.0` is declared clean and replaced by `pkg:pypi/lzmaffi@1.0.1-phantom-backdoor`.

Injection mechanism: The container image keeps the same service entrypoint but replaces the installed wheel under site-packages with a backdoored wheel. On import, the modified module forks `/bin/sh -c python /tmp/.phantom_beacon.py` and opens an outbound TCP connection to a controlled ClusterIP endpoint `phantom-sink.phantom-eval.svc.cluster.local:8443`.

Expected eBPF evidence: Increased `execve`, `fork/clone`, `connect`, `tcp_sendmsg`, `openat` on the substituted module path, child process lineage inconsistent with the signed behavioral contract, and new DNS/TCP flow from `recommendationservice` to `phantom-sink`.

Expected KL divergence: Should spike sharply for the substituted PURL's process-spawn and network-transition distributions, then remain elevated while the beacon persists.

Ground truth source: Experiment oracle manifest `oracles/xz_style_library_backdoor.yaml`, containing substituted PURL, image digest, injection timestamp, expected child command, expected sink endpoint, and compromise marker.

Detection window: A PHANTOM detection within 120 seconds after injection counts as TP.

Recovery mechanism: Roll back Deployment to the clean image digest, delete mutated Pods, clear the controlled sink logs, wait for Pods ready, and verify contract hashes match clean cosign signatures.

Repetitions: 3

---

SCENARIO NAME: Dependency Confusion Beacon Package

Attack family: dependency_confusion

Target workload: Online Boutique `emailservice`, because it is Python-based, represents an auxiliary production service, and internal helper packages are plausible in email rendering/notification pipelines.

Target component: Internal `pkg:pypi/acme-email-templates@0.9.4` is shadowed by public `pkg:pypi/acme-email-templates@9.9.9`.

Injection mechanism: The build stage changes Python package index resolution order so the public higher-version package is installed. The service code is unchanged, but import activation starts a lightweight beacon process that periodically resolves and connects to `phantom-sink`.

Expected eBPF evidence: Changed file-open path for imported package, new package activation event binding the public PURL, unexpected `execve`/`clone`, periodic `connect`/DNS lookups, and contract state transition from `bound_internal` to `bound_public`.

Expected KL divergence: Should spike at first import and show periodic smaller spikes aligned to beacon intervals.

Ground truth source: Experiment oracle manifest `oracles/dependency_confusion_beacon.yaml`, containing resolver configuration, package lock diff, public PURL, injection timestamp, and beacon interval.

Detection window: A PHANTOM detection within 180 seconds after rollout counts as TP, allowing for service import timing.

Recovery mechanism: Restore private-index-first resolver config, pin internal package by hash, redeploy clean image, delete Pods, and verify runtime package path and PURL binding.

Repetitions: 3

---

SCENARIO NAME: SolarWinds-Style Build Artifact Tampering

Attack family: build_pipeline_tampering

Target workload: Online Boutique `cartservice`, because it is a long-lived service with predictable request/response behavior and a clear declared SBOM, making sidecar-like background activity easy to distinguish.

Target component: Declared clean component `pkg:nuget/StackExchange.Redis@2.6.122` remains in the SBOM, while the runtime image additionally contains `pkg:generic/phantom-background-worker@0.1.0` not declared in the SBOM.

Injection mechanism: The Docker build adds `/usr/local/bin/phantom-worker` and changes entrypoint to launch the legitimate cart service plus the worker in the same container namespace. The SBOM artifact remains the clean pre-tamper SBOM.

Expected eBPF evidence: Additional persistent process under the same container ID, unexpected `execve`, periodic file reads and TCP attempts by `phantom-worker`, increased process count, and runtime component with no declared SBOM binding.

Expected KL divergence: Should increase for container-level process-count and component-interaction contracts, with a stable elevated plateau while the worker runs.

Ground truth source: Experiment oracle manifest `oracles/build_artifact_tampering.yaml`, containing clean SBOM digest, tampered image digest, extra binary hash, injection timestamp, and expected process name.

Detection window: A PHANTOM detection within 120 seconds after Pod ready counts as TP.

Recovery mechanism: Redeploy clean image digest and clean SBOM, delete tampered ReplicaSet, wait for ready state, and confirm no `phantom-worker` process remains.

Repetitions: 3

---

SCENARIO NAME: Benign Dependency Patch Update

Scenario type: benign_update

What happens: `recommendationservice` receives a hash-pinned patch update to a declared Python dependency with no added child process, network endpoint, or contract-violating transition.

Expected PHANTOM behavior: Should update SBOM binding and observe minor contract drift below threshold; should not emit a drift detection.

Purpose: Measures false positives for legitimate maintenance and version churn.

---

SCENARIO NAME: Benign High Load Burst

Scenario type: high_load

What happens: k6 increases request rate to the declared stress profile for Online Boutique without changing images, packages, or network destinations.

Expected PHANTOM behavior: Should observe higher event volume but stable transition probabilities after normalization; should not attribute component substitution.

Purpose: Measures false positives caused by load-induced syscall frequency changes.

---

SCENARIO NAME: Benign Pod Restart and Reschedule

Scenario type: pod_restart

What happens: Kubernetes deletes Pods for `cartservice` and `emailservice`; Deployments recreate them on possibly different nodes with the same image digests and SBOMs.

Expected PHANTOM behavior: Should observe lifecycle events and process restarts but maintain the same component contracts and not trigger drift.

Purpose: Measures false positives caused by ordinary orchestration churn.

---

## Section 3: Baseline Comparison Design

Baseline 1: Falco with default ruleset

Exact version and configuration: Falco `0.44.1`, deployed as a DaemonSet with the upstream default ruleset and default priority thresholds. JSON output enabled. No PHANTOM-specific custom rules.

Comparable metric: Alert-level TPR, FPR, precision, recall, F1, false positives per hour, and MTTD.

Advantage over PHANTOM: Mature production runtime detection with curated rules and broad operational adoption.

What PHANTOM does that this baseline cannot do: It binds runtime behavior to signed SBOM component contracts, computes component-level KL drift, and performs SCM-based causal attribution with `not_identifiable`.

Why inclusion strengthens the paper: It tests whether PHANTOM adds value beyond a well-known runtime security baseline.

Reviewer objection if missing: "The paper compares against weak baselines and ignores the de facto Kubernetes runtime detection tool."

---

Baseline 2: Trivy SBOM static scan

Exact version and configuration: Trivy `0.70.0`, run as `trivy image --format cyclonedx --scanners vuln,secret,misconfig,license --output trivy.json <image>` against each clean and injected image before runtime execution. Database cache is refreshed once before the experiment batch and then frozen for reproducibility.

Comparable metric: Static detection of declared package/version differences and CVE-based priority ranking, mapped to scenario-level TP/FP when Trivy reports the substituted or vulnerable component.

Advantage over PHANTOM: Fast, deterministic, widely used static scanner that does not require runtime instrumentation.

What PHANTOM does that this baseline cannot do: It observes runtime behavior that is absent from the SBOM, detects tampered runtime behavior despite clean declarations, and attributes drift causally.

Why inclusion strengthens the paper: The central claim concerns runtime SBOM drift, so a static SBOM scanner is the natural foil.

Reviewer objection if missing: "The paper criticizes static SBOMs without comparing to a representative SBOM scanner."

---

Baseline 3: Isolation Forest on syscall frequency vectors

Exact version and configuration: Python `scikit-learn` IsolationForest with `n_estimators=200`, `contamination` matched to PHANTOM's validation-set alert budget, `random_state=42`, trained per service on benign windows only.

Comparable metric: Window-level anomaly score thresholded into detections; same TPR, FPR, precision, recall, F1, false positives per hour, and MTTD.

Feature vector definition: For each 10-second service window, compute normalized counts for `execve`, `clone`, `fork`, `openat`, `connect`, `accept`, `sendmsg`, `recvmsg`, `tcp_sendmsg`, `tcp_cleanup_rbuf`, `dns_query`, `unlink`, `chmod`, `ptrace`, `setuid`, and `capset`, plus total event count as a scale feature. Frequencies are L1-normalized; total count is log-scaled.

Training data: Same benign contract-training windows used by PHANTOM, excluding validation and test windows.

Threshold selection method: Choose threshold on validation controls to match PHANTOM's target false-positive budget, then freeze before test scenarios.

Fairness justification: It uses the same eBPF event source and benign training period, but lacks SBOM binding, behavioral contracts, graph causality, and calibration.

Advantage over PHANTOM: Simpler unsupervised anomaly detector with fewer assumptions about component identity or causal graph structure.

What PHANTOM does that this baseline cannot do: It localizes anomalies to PURLs, signs/verifies contracts, reasons over BDG temporal DAGs, and returns causal identifiability status.

Why inclusion strengthens the paper: It distinguishes PHANTOM's contribution from generic syscall anomaly detection.

Reviewer objection if missing: "The results may only show that syscall anomalies are useful, not that behavioral contracts or causality matter."

---

Baseline 4: Static CVE score only

Exact version and configuration: CVSS v3.1 base score from the frozen Trivy vulnerability database. Priority score equals max CVSS over declared components in the workload image; no runtime input.

Comparable metric: Scenario priority ranking, PCEPS risk-ranking correlation, AUC-ROC/AUC-PR for pre-compromise labels when interpreted as a static score.

Advantage over PHANTOM: Extremely cheap, explainable, and already used in vulnerability management workflows.

What PHANTOM does that this baseline cannot do: It detects exploit-relevant runtime behavior for substituted or undeclared components and updates risk dynamically.

Why inclusion strengthens the paper: It tests the paper's claim that runtime causal evidence improves pre-compromise prioritization beyond static severity.

Reviewer objection if missing: "PCEPS is not compared to the operational baseline most organizations actually use for prioritization."

---

## Section 4: Metric Definitions

Let `TP`, `FP`, `TN`, and `FN` be counts over detector decisions in labeled windows or scenarios, using oracle manifests rather than PHANTOM output as ground truth.

True Positive Rate: `\mathrm{TPR} = \frac{TP}{TP + FN}`. Appropriate for attack detection coverage. Criticism: it can hide false positives. Preemption: always report with FPR and FP/hour.

False Positive Rate: `\mathrm{FPR} = \frac{FP}{FP + TN}`. Appropriate for benign-control safety. Criticism: window imbalance can make FPR look small. Preemption: also report FP/hour.

Precision: `\mathrm{Precision} = \frac{TP}{TP + FP}`. Appropriate for operator alert quality. Criticism: depends on scenario prevalence. Preemption: report per-scenario and prevalence-independent FPR.

Recall: `\mathrm{Recall} = \frac{TP}{TP + FN}`. Same as TPR for binary detection. Criticism: duplicates TPR. Preemption: include because reviewers expect precision/recall/F1.

F1 Score: `\mathrm{F1} = 2 \cdot \frac{\mathrm{Precision}\cdot\mathrm{Recall}}{\mathrm{Precision}+\mathrm{Recall}}`. Appropriate for balancing misses and alert noise. Criticism: ignores TN and timing. Preemption: report MTTD and FP/hour separately.

False Positives per Hour: `\mathrm{FPH} = \frac{FP}{T_{\mathrm{benign}}/3600}`, where `T_{\mathrm{benign}}` is benign experiment duration in seconds. Appropriate for operational burden. Criticism: short runs may be unstable. Preemption: aggregate over repetitions and report variance.

Mean Time to Detection: For attack repetition `i`, `\Delta_i = t_{\mathrm{detection},i} - t_{\mathrm{injection},i}` if detection occurs within the scenario window. `t_{\mathrm{injection}}` is the oracle timestamp at which the malicious image/package becomes active. `t_{\mathrm{detection}}` is the first persisted alert timestamp from the detector after injection. `\mathrm{MTTD}=\frac{1}{N_{TP}}\sum_{i:TP}\Delta_i`. FN cases are excluded from MTTD and separately counted as misses; a sensitivity table assigns FN the full scenario timeout. Appropriate for timeliness. Criticism: excluding FN can flatter a detector. Preemption: always pair with TPR and timeout-penalized sensitivity analysis.

Causal Attribution Accuracy: For each true attack, exact credit `1` if PHANTOM's top attributed PURL equals the oracle substituted/added PURL; partial credit `0.5` if the top PURL is in the same dependency chain and the oracle PURL is in PHANTOM's top-3; zero otherwise. `\mathrm{CAA}=\frac{1}{N}\sum_i c_i`. Ground truth comes from oracle manifests, package lock diffs, image digests, and controlled injection scripts, never PHANTOM output. Appropriate for response utility. Criticism: partial credit may be subjective. Preemption: report exact-match and partial-credit accuracy separately.

PCEPS Calibration: Brier score `\mathrm{BS}=\frac{1}{N}\sum_{i=1}^{N}(p_i-y_i)^2`, where `p_i` is PCEPS predicted exploit probability and `y_i\in\{0,1\}` is the oracle pre-compromise label. Appropriate for probability quality. Criticism: can be dominated by common negatives. Preemption: include reliability diagram and class-stratified analysis.

Identifiability Rate: `\mathrm{IDRate}=\frac{N_{\mathrm{identified}}}{N_{\mathrm{attribution\ attempts}}}` where `N_{\mathrm{identified}}` counts DoWhy cases where a causal effect expression is identified. Appropriate for causal claim scope. Criticism: high rate alone is not accuracy. Preemption: report with attribution accuracy and refutation tests.

Not-Identifiable Rate: `\mathrm{NIRate}=\frac{N_{\mathrm{not\_identifiable}}}{N_{\mathrm{attribution\ attempts}}}`. This is positive when it occurs on oracle-designed ambiguous cases. Appropriate for honest uncertainty. Criticism: may look like failure. Preemption: separate expected ambiguous cases from identifiable attack cases.

CPU Overhead Percent: For each trial, `\mathrm{CPUOverhead}=100\cdot\frac{\overline{CPU}_{\mathrm{PHANTOM}}-\overline{CPU}_{\mathrm{base}}}{\overline{CPU}_{\mathrm{base}}}` using node-level and container-level Prometheus CPU seconds rates over identical load windows. Appropriate for production cost. Criticism: noisy under autoscaling. Preemption: disable autoscaling, pin load, and repeat.

Memory Overhead MB: `\mathrm{MemOverhead}=\overline{RSS}_{\mathrm{PHANTOM}}-\overline{RSS}_{\mathrm{base}}` in MB, measured from container working set and node RSS. Appropriate for capacity planning. Criticism: cache effects may confound. Preemption: warm-up, fixed trial length, report agent and workload memory separately.

Event Loss Rate: `\mathrm{LossRate}=\frac{E_{\mathrm{lost}}}{E_{\mathrm{lost}}+E_{\mathrm{processed}}}`, where lost and processed are agent ring-buffer counters. Appropriate for data fidelity. Criticism: only measures known drops. Preemption: cross-check with synthetic event injectors during calibration.

Collection Latency P95: `P95(t_{\mathrm{ingest}}-t_{\mathrm{kernel}})` over processed events, where `t_kernel` is event timestamp and `t_ingest` is agent persistence timestamp. Appropriate for timeliness. Criticism: clock skew can distort distributed measures. Preemption: compute on the same node where possible and synchronize nodes with chrony.

---

## Section 5: Dataset Schema

`traces.parquet` fields:

| Field name | Data type | Description | Why included | Privacy/security justification |
|---|---|---|---|---|
| `trace_id` | string | Stable UUID for event row | Join/debug key | Random, no PII |
| `experiment_id` | string | Trial identifier | Reproducibility | Synthetic label |
| `scenario_id` | string | Scenario/control identifier | Supervised evaluation | No user data |
| `repetition` | int32 | Repetition number | Variance reporting | No PII |
| `timestamp_ns` | int64 | Kernel event timestamp | Temporal ordering | System time only |
| `node_id_hash` | string | Salted node identifier | Node-level grouping | Salted per release |
| `namespace` | string | Kubernetes namespace | Workload context | Synthetic namespace |
| `pod_uid_hash` | string | Salted Pod UID | Pod grouping | Salted, not reversible |
| `container_id_hash` | string | Salted container ID | Container grouping | Salted, not reversible |
| `service_name` | string | Benchmark service | Service-level analysis | Benchmark name only |
| `image_digest` | string | OCI image digest | SBOM/runtime binding | Digest is artifact metadata |
| `purl` | string | Package URL attributed to event | Component-level contracts | Public/synthetic package names |
| `purl_binding_status` | string | `declared`, `runtime_only`, `substituted`, `unknown` | Drift labels | No personal data |
| `event_type` | string | eBPF event category | Feature construction | Kernel event class only |
| `syscall` | string | Syscall name if applicable | Baseline features | No arguments by default |
| `process_name` | string | Executable basename | Process anomaly evidence | Synthetic workload binaries |
| `pid_hash` | string | Salted PID/session hash | Process lineage | Salted, no raw PID needed |
| `ppid_hash` | string | Salted parent hash | Causal lineage | Salted |
| `uid_class` | string | `root`, `service`, `unknown` | Privilege behavior | Coarse category only |
| `argv_fingerprint` | string | Hash of command arguments | Detect changed commands | No raw command secrets |
| `file_path_class` | string | Coarse path category | File behavior | No raw paths with secrets |
| `file_hash` | string | Hash for touched artifact when relevant | Component verification | Hash only |
| `remote_ip_class` | string | `cluster`, `private`, `public`, `none` | Network anomaly | No raw IP by default |
| `remote_port` | int32 | Remote port or null | Network behavior | Port alone is not PII |
| `dns_domain_class` | string | `cluster_service`, `controlled_sink`, `external`, `none` | Beacon evidence | Domains bucketed |
| `edge_src_purl` | string | BDG source component | Graph reconstruction | Synthetic/public PURL |
| `edge_dst_purl` | string | BDG destination component | Graph reconstruction | Synthetic/public PURL |
| `edge_type` | string | `process`, `file`, `network`, `ipc` | Causal graph feature | No PII |
| `edge_weight` | float32 | Decayed BDG edge weight | Graph analysis | Derived numeric |
| `contract_state` | string | Behavioral contract state | KL computation | Abstract state only |
| `kl_score` | float32 | Component KL divergence | Drift scoring | Derived numeric |
| `agent_lag_ms` | float32 | Collection latency | Overhead/timeliness | Derived numeric |
| `ringbuf_lost_delta` | int64 | Lost event counter delta | Data quality | Counter only |
| `phantom_version` | string | Git commit/version | Reproducibility | Public code metadata |

`labels.parquet` fields:

| Field name | Data type | Description |
|---|---|---|
| `label_id` | string | Stable label UUID |
| `experiment_id` | string | Trial identifier |
| `scenario_id` | string | Attack/control scenario |
| `repetition` | int32 | Repetition number |
| `window_start_ns` | int64 | Label window start |
| `window_end_ns` | int64 | Label window end |
| `is_attack` | bool | Whether window belongs to attack scenario |
| `is_pre_compromise` | bool | Positive PCEPS label before compromise marker |
| `is_compromised` | bool | Whether full compromise marker has occurred |
| `attack_family` | string | Attack taxonomy value or `benign` |
| `ground_truth_purl` | string | Substituted/added component PURL or null |
| `ground_truth_service` | string | Target service |
| `injection_time_ns` | int64 | Oracle injection timestamp |
| `compromise_time_ns` | int64 | Oracle compromise marker timestamp |
| `expected_identifiable` | bool | Whether causal effect should be identifiable |
| `oracle_manifest_path` | string | Relative oracle manifest |
| `clean_image_digest` | string | Clean image digest |
| `attack_image_digest` | string | Injected image digest or null |
| `notes` | string | Controlled notes without secrets |

Dataset split strategy: Split by scenario family and time, not random event rows. Train uses benign baseline windows and one repetition each of benign controls; validation uses separate benign windows plus one attack repetition for threshold selection only where a supervised threshold is needed; test uses held-out repetitions for all three attacks and all three controls. No Pod UID, container ID, or time-adjacent windows may cross train/validation/test boundaries. This prevents leakage from repeated Pods, temporal autocorrelation, or the same injected image appearing in both threshold tuning and final reporting.

Scenario families by split: Train contains clean Online Boutique and benign update/load/restart windows. Validation contains held-out benign controls and calibration slices from each attack family. Test contains all three attack families and all benign controls with held-out repetitions.

Parquet justification: Parquet is preferred to CSV because it preserves typed columns, compresses high-volume traces, and supports column projection. It is preferred to HDF5 because it is easier to inspect with standard data science tools, integrates with Spark/DuckDB/Pandas, and avoids monolithic file-locking workflows. It is preferred to JSON Lines because nested/semi-structured flexibility is unnecessary here and JSONL is larger and slower for typed analytic scans.

Dataset DOI/release plan: Release on Zenodo with a reserved DOI before submission and final DOI after camera-ready. License: CC BY 4.0 for trace/label data and Apache-2.0 for packaging scripts. README must include threat model, schema, collection environment, attack oracle definitions, split files, reproduction commands, privacy treatment, known limitations, checksums, citation, and contact.

---

## Section 6: Experimental Setup

Kubernetes cluster: AWS EKS Kubernetes `1.36.2` (`eks.6` platform), three worker nodes of type `m7i.large`, Amazon Linux 2023 EKS-optimized AMI, containerd runtime, one dedicated monitoring namespace, and no cluster autoscaler during experiments.

PHANTOM version: Use immutable git commit references. Each run records `phantom_version=$(git rev-parse HEAD)`, Helm chart version, container image digest, contract-signing key ID, and Terraform state version.

Workload: Online Boutique is the primary benchmark because it is a maintained, multi-service cloud-native application with realistic service interactions, multiple implementation languages, and common use in cloud systems evaluations. It is preferred over a custom app because it reduces benchmark bias and gives reviewers a recognizable workload. Use the standard Online Boutique service set; record the exact upstream commit and deployed service count in the run manifest.

Baseline load profile: Generate steady load at `[RESULT_RPS_BASELINE]` requests/second and stress load at `[RESULT_RPS_STRESS]` requests/second. Use k6 because it produces reproducible scripted traffic, explicit arrival rates, and machine-readable latency summaries. Keep product browsing, cart add, checkout initiation, and email-triggering paths in the script.

Prometheus collection: Scrape PHANTOM agent, API Gateway, Kubernetes kubelet/cAdvisor, Falco, and workload metrics every 5 seconds. Store raw Prometheus snapshots and query outputs for each run. Grafana is visualization only, not the measurement source of record.

PHANTOM timestamps: Use the first transactional-outbox persisted detection event after oracle injection. Record kernel timestamp, agent ingest timestamp, API persistence timestamp, and frontend display timestamp, but use API persistence timestamp for detector comparison.

Baseline timestamps: Falco uses first JSON alert timestamp. Trivy uses scan completion timestamp and is counted as detecting only if the static scan identifies the substituted/vulnerable declared component before runtime. Isolation Forest uses first anomalous 10-second window end time. CVSS-only has no runtime timestamp; for timing analysis it is marked `not_applicable`.

CPU overhead isolation: Measure workload container CPU separately from PHANTOM/Falco DaemonSet CPU using cAdvisor labels. Compare identical deployments with monitoring disabled/enabled. Disable autoscaling, pin node count, warm up for `[RESULT_WARMUP]` minutes, and measure over `[RESULT_DURATION]` minutes.

Threats and mitigations: Load variability is mitigated with fixed k6 arrival rates and repetitions. Kubernetes scheduling noise is mitigated by fixed node count and recording Pod placement. Cloud noisy neighbors are reported as a limitation and reduced through same-instance repeated trials. Cache warm-up effects are mitigated by warm-up periods. Clock skew is mitigated by node time sync and same-node latency calculations. Rule/configuration bias is mitigated by freezing baseline configs before tests. Threshold overfitting is mitigated by held-out test repetitions. Attack realism is limited by controlled synthetic payloads and is reported. Benchmark generality is limited to Online Boutique and selected Sock Shop-compatible service choices if extended. eBPF event loss is measured and reported. Ground-truth error is mitigated by oracle manifests, image digests, and sink logs independent of PHANTOM.

---

## Section 7: Complete Evaluation Section Draft

### 7.1 Experimental Setup

We evaluate PHANTOM on an AWS EKS cluster running Kubernetes `1.36.2` with three `m7i.large` worker nodes. PHANTOM is deployed using its Helm chart and identified in every trial by an immutable git commit, container digest, and contract-signing key identifier. The workload is Online Boutique, a multi-service cloud-native benchmark with realistic request paths and heterogeneous service implementations. We use Online Boutique rather than a custom workload to reduce benchmark bias and to expose PHANTOM to service interactions representative of production microservice applications.

Traffic is generated with k6 using a fixed arrival-rate script that exercises browsing, cart, checkout initiation, and notification paths. Each trial contains a warm-up interval, a measurement interval, and a teardown interval. Prometheus scrapes PHANTOM, Kubernetes, workload, and baseline metrics every five seconds. Detection timestamps are taken from the first persisted detector output: the PHANTOM transactional outbox for PHANTOM, JSON alert output for Falco, scan completion for Trivy, and anomalous window end time for the Isolation Forest baseline.

### 7.2 Attack Scenarios

We use three controlled supply-chain attacks and three benign controls. The attacks represent a library backdoor, dependency confusion, and build artifact tampering. Each attack is specified by an oracle manifest containing the clean image digest, injected image or package digest, target PURL, injection timestamp, expected process/network evidence, and compromise marker. Benign controls model a dependency patch, a high-load burst, and Pod restart/rescheduling. The oracle manifests, not PHANTOM outputs, define ground truth for all metrics.

### 7.3 RQ1: Detection Performance

To answer RQ1, we compare PHANTOM with Falco, Trivy, Isolation Forest, and CVSS-only prioritization across the attack and benign-control scenarios. A detection is counted as a true positive only if it occurs within the scenario-specific detection window after oracle injection. False positives are measured on benign controls under the same load profile.

Table [TABLE_1] shows per-scenario detection performance for all detectors.

[TABLE_1] Detection performance by detector and scenario. Columns: `Detector`, `Scenario`, `Attack Family`, `TP`, `FP`, `TN`, `FN`, `TPR`, `FPR`, `Precision`, `Recall`, `F1`, `FP/hour`, `MTTD(s)`.

The results in Table [TABLE_1] show that PHANTOM detects runtime behavioral drift associated with substituted or undeclared components with TPR `[RESULT_X]` and FPR `[RESULT_X]`. Falco captures generic process or network violations when default rules happen to match, but Table [TABLE_1] shows `[RESULT_X]` misses in scenarios where the behavior is anomalous only relative to the component contract. Trivy identifies static SBOM differences when the modified package is declared, but it cannot observe the runtime-only worker in the tampered artifact scenario. The Isolation Forest baseline detects some syscall-distribution shifts, yet Table [TABLE_1] shows that it lacks component binding and produces `[RESULT_X]` false positives during load bursts. These results reject the RQ1 null hypothesis if PHANTOM's F1 and MTTD improve over the strongest baseline without increasing benign false positives.

### 7.4 RQ2: Causal Attribution Accuracy

RQ2 evaluates whether PHANTOM attributes drift to the correct substituted component and whether it withholds claims when the causal effect is not identifiable. We compare PHANTOM's top attributed PURL and identifiability state against oracle manifests. We also compare against KL-only ranking, graph-centrality ranking, Isolation Forest localization, and random active-component selection.

Table [TABLE_2] reports exact-match attribution, partial-credit attribution, and identifiability outcomes.

[TABLE_2] Causal attribution results. Columns: `Method`, `Scenario`, `Ground Truth PURL`, `Top Attributed PURL`, `Top-3 Contains Truth`, `Exact Accuracy`, `Partial Accuracy`, `Identifiable`, `Not Identifiable`, `Refutation Passed`.

[FIGURE_1] Attribution confidence distribution for PHANTOM and non-causal localization baselines.

Table [TABLE_2] and Figure [FIGURE_1] show whether PHANTOM's SCM-based attribution improves over non-causal drift localization. A correct attribution requires the top PURL to match the oracle substituted or added component; partial credit is reported separately when PHANTOM localizes the correct dependency chain. The `not_identifiable` outcome is treated as a positive result on oracle-designed ambiguous cases because it prevents unsupported causal claims. If Table [TABLE_2] shows exact attribution `[RESULT_X]`, partial attribution `[RESULT_X]`, and expected not-identifiable behavior `[RESULT_X]`, the RQ2 null hypothesis is rejected.

### 7.5 RQ3: PCEPS Prediction Performance

RQ3 measures whether PCEPS predicts exploitation risk before the attack fully materializes. We label sliding windows as pre-compromise positives after substitution begins but before the oracle compromise marker. PCEPS is compared with CVSS-only, KL-only, graph-centrality-only, and uncalibrated XGBoost scores.

[FIGURE_2] Reliability diagram comparing PCEPS predicted probabilities with observed pre-compromise labels.

[FIGURE_3] AUC-ROC comparison for PCEPS, CVSS-only, KL-only, graph-centrality-only, and uncalibrated XGBoost.

Figure [FIGURE_2] evaluates calibration, while Figure [FIGURE_3] evaluates ranking performance. The Brier score `[RESULT_X]` indicates whether Platt scaling produces probabilities suitable for prioritization rather than only relative anomaly scores. Figure [FIGURE_3] shows whether causal effect, behavioral drift, and graph topology features improve pre-compromise prediction over static severity. The RQ3 null hypothesis is rejected if PCEPS improves AUC-ROC/AUC-PR and calibration while producing an average lead time of `[RESULT_X]` seconds before the compromise marker.

### 7.6 RQ4: Overhead Analysis

RQ4 measures whether PHANTOM can run continuously on Kubernetes workloads. We compare uninstrumented Online Boutique, Falco-enabled Online Boutique, and PHANTOM-enabled Online Boutique under the same k6 arrival-rate profile. CPU and memory are measured separately for workload containers and monitoring components.

Table [TABLE_3] reports overhead and fidelity metrics.

[TABLE_3] Overhead comparison. Columns: `Configuration`, `Throughput`, `p50 Latency`, `p95 Latency`, `p99 Latency`, `CPU Overhead %`, `Memory Overhead MB`, `Event Loss Rate`, `Collection Latency P95`, `Repetitions`.

Table [TABLE_3] shows PHANTOM's CPU overhead `[RESULT_X]`, memory overhead `[RESULT_X]`, event loss rate `[RESULT_X]`, and p95 collection latency `[RESULT_X]`. These measurements determine whether the eBPF collection path preserves enough fidelity for timely attribution while remaining practical for production workloads. The RQ4 null hypothesis is rejected if Table [TABLE_3] shows overhead within the declared acceptability threshold and no material throughput or tail-latency degradation relative to the uninstrumented and Falco deployments.

### 7.7 Threats to Validity

Internal validity: The main risks are threshold overfitting, timestamp inconsistency, detector configuration bias, and ground-truth mistakes. We mitigate these risks with frozen validation thresholds, oracle manifests independent of PHANTOM, per-detector timestamp rules, repeated trials, and immutable image/package digests.

External validity: Online Boutique is representative of microservice architectures but cannot cover every language, kernel version, cloud provider, or supply-chain attack. We report this limitation and release the trace schema and attack harness so future work can add workloads such as Sock Shop.

Construct validity: Runtime SBOM drift is operationalized as divergence between signed component behavioral contracts and eBPF-observed runtime behavior. This may miss attacks that preserve behavior while changing semantics. We therefore report detection, attribution, calibration, and overhead separately rather than collapsing them into a single score.

Conclusion validity: Numeric conclusions depend on repeated controlled trials and variance reporting. We avoid claiming universal superiority from one workload and use `[RESULT_X]` placeholders until measurements are produced. Statistical comparisons should report confidence intervals or non-parametric paired tests where sample size permits.

---

## Handoff to Claude Code Task 8

Attack scenario implementation:

1. XZ-style library backdoor: create clean and backdoored Python wheel for `pkg:pypi/lzmaffi`; modify `recommendationservice` image to install backdoored wheel; on import spawn `/tmp/.phantom_beacon.py`; beacon connects to `phantom-sink:8443`; emit oracle `oracles/xz_style_library_backdoor.yaml`; output sink logs and image digests.

2. Dependency confusion: configure build resolver so public `pkg:pypi/acme-email-templates@9.9.9` overrides internal `@0.9.4`; target `emailservice`; package starts beacon on import; emit resolver diff, lockfile diff, oracle `oracles/dependency_confusion_beacon.yaml`, and package hashes.

3. Build artifact tampering: modify `cartservice` image entrypoint to run legitimate service plus `/usr/local/bin/phantom-worker`; keep clean SBOM attached; emit oracle `oracles/build_artifact_tampering.yaml`, clean/tampered image digests, and worker binary hash.

Baseline implementation:

1. Falco: deploy Falco `0.44.1` DaemonSet with upstream default rules; enable JSON output; write alerts to `results/falco/<experiment_id>.jsonl`.

2. Trivy: run Trivy `0.70.0` with frozen DB cache; command output `results/trivy/<image_digest>.json`; include CycloneDX SBOM and vulnerability JSON.

3. Isolation Forest: implement Python runner using scikit-learn IsolationForest with `n_estimators=200`, `contamination` matched to PHANTOM validation FP budget, 10-second windows, syscall feature vector from Section 3, and output `results/isoforest/<experiment_id>.parquet`.

4. CVSS-only: parse frozen Trivy vulnerability output; compute max CVSS v3.1 per image/service; output `results/cvss/<experiment_id>.json`.

Dataset packager:

Implement Parquet writer producing exactly `traces.parquet` and `labels.parquet` schemas from Section 5. Include schema validation, salted hashing for node/pod/container/process IDs, raw-secret exclusion tests, checksums, `splits/train.txt`, `splits/validation.txt`, `splits/test.txt`, and Zenodo-ready README.

Evaluation runner sequence:

1. Provision EKS cluster and monitoring stack.
2. Deploy clean Online Boutique and PHANTOM.
3. Warm up workload and collect clean training windows.
4. Run benign controls with three repetitions each.
5. Run attack scenarios with three repetitions each, restoring clean state after each run.
6. Run Falco, Trivy, Isolation Forest, and CVSS baselines using frozen configs.
7. Export Prometheus, PHANTOM, baseline, sink, oracle, and Kubernetes event logs.
8. Build dataset Parquet files and split manifests.
9. Compute metrics from Section 4.
10. Generate tables/figures for Section 7 with `[RESULT_X]` replaced only by measured values.

Paper notebooks:

1. `notebooks/table_1_detection_performance.ipynb`: produces [TABLE_1].
2. `notebooks/table_2_attribution_accuracy.ipynb`: produces [TABLE_2].
3. `notebooks/figure_1_attribution_confidence.ipynb`: produces [FIGURE_1].
4. `notebooks/figure_2_pceps_reliability.ipynb`: produces [FIGURE_2].
5. `notebooks/figure_3_pceps_auc.ipynb`: produces [FIGURE_3].
6. `notebooks/table_3_overhead.ipynb`: produces [TABLE_3].

Version/source pins checked on 2026-07-26: Falco `0.44.1`, Trivy `0.70.0`, and EKS Kubernetes `1.36.2`/`eks.6`. Record implementation-time verification in the artifact README.

