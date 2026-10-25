# PHANTOM Additional Experiments

The checked-in raw3 records support only six completed attack runs with event-positive drift records. Three build-pipeline attack injections failed, and there are no benign controls. The experiments below are proposed; none should be described as completed until raw artifacts are produced and validated.

## Priority 1: Re-run attack and control scenarios with a valid oracle

**Question:** Does PHANTOM detect malicious runtime behavior without alerting on benign changes?

**Design:** Run XZ-style, dependency-confusion, and SolarWinds-style scenarios after verifying each injection succeeded, then add benign workload restart, scaling, rolling update, and normal feature-use controls. Use at least 10 independent repetitions per scenario as an initial engineering study; pre-register a larger sample size based on desired interval width before confirmatory claims. Randomize run order and freeze PHANTOM rules/contracts before evaluation.

**Independent variables:** Scenario family, attack/control status, workload condition. **Dependent variables:** run-level TP/FN/FP/TN; event-level alert counts; latency; event loss; resolved-identity rate. **Baseline:** frozen PHANTOM contract and the same workload/image under control and attack. **Metrics:** confusion matrix, Wilson intervals, false alerts per monitored hour, MTTD with timestamp semantics, run exclusions. **Interpretation:** TPR is measurable only for successfully injected labeled attacks; FPR requires benign exposure windows and all event records. Keep failed injections visible but exclude them from effectiveness denominators.

## Priority 2: Fix component identity and validate causal attribution

**Question:** Does the system map an observed drift to the injected component, and is a causal estimate more accurate than non-causal localization?

**Design:** Instrument a deterministic attack with ground-truth component PURL, image digest, process lineage and expected behavior. Add blinded per-run oracle labels. Record the raw event, identity resolver decision, verified SBOM, contract ID, BDG snapshot, SCM treatment/outcome/covariates, DoWhy estimand and status, and final ranked component. Include negative and deliberately non-identifiable cases.

**Independent variables:** candidate substituted component; confounder availability; identity ambiguity; graph topology. **Dependent variables:** exact top-1 attribution, top-k attribution, abstention rate, false attribution rate, identity resolution rate, ATE error where a known effect is constructed. **Baselines:** KL-only localization, graph centrality, random choice among active components. **Metrics:** exact accuracy and confidence intervals, top-k recall, abstention precision/recall, calibration of confidence if called probability. **Interpretation:** PID/container/pod resolution is a separate metric from correct cause attribution. A graph edge alone is not causal evidence.

## Priority 3: Implement and evaluate a thresholded drift detector

**Question:** Does component-conditioned sequence behavior improve drift detection over frequency-only baselines at a fixed alert budget?

**Design:** Add benign calibration windows disjoint in time and workload from test windows. Freeze signed contracts and a split-conformal threshold before attacks. Compare temporal conditional KL, marginal event frequency, and Jensen-Shannon/L1 ablations using identical event availability. Preserve an explicit `not_scorable` outcome for missing/ambiguous contracts and insufficient events.

**Independent variables:** scorer (conditional KL, marginal frequency, ablation), threshold alpha, contract version. **Dependent variables:** recall at target false-alarm rate, AUPRC, detection latency, not-scorable frequency. **Baseline:** frequency-only Isolation Forest and the current event-rule behavior. **Interpretation:** Report calibration age and workload shift; conformal false-alarm statements require exchangeability and must be qualified under drift.

## Priority 4: Validate PCEPS as a prospective prediction model

**Question:** Does PCEPS predict an independently defined future compromise outcome before a compromise marker, beyond simpler features?

**Design:** Define the prediction time and future horizon before collecting scores. Extract only features available at prediction time. Split by attack family, image/workload family, and chronology so no windows from a scenario template cross train/calibration/test partitions. Train on independent historical runs; calibrate Platt parameters on a separate calibration set; evaluate once on held-out families and later time periods. Include benign and attack labels.

**Independent variables:** full PCEPS, CVSS-only, KL-only, graph-centrality-only, uncalibrated XGBoost, and simple logistic model. **Dependent variables:** AUROC, AUPRC, Brier score, ECE/reliability plot, precision at operational alert budget, lead time, confidence intervals. **Interpretation:** If the oracle marks compromise contemporaneously with drift detection rather than prospectively, call the output a prioritization score and remove future-prediction language.

## Priority 5: Measure runtime cost and telemetry fidelity

**Question:** What resource cost and event loss does PHANTOM impose under representative load?

**Design:** Use paired runs with collector disabled/enabled and, separately, Falco enabled. Capture Prometheus raw samples and benchmark request throughput/latency, node CPU, agent CPU/memory, event queue depth, ring-buffer loss and end-to-end event delay. Record kernel, container runtime, node type, image digests, PHANTOM commit and configuration. Repeat across workload load levels.

**Independent variables:** instrumentation, workload load, event burst rate. **Dependent variables:** CPU, memory, throughput, p50/p95/p99 request latency, captured/dropped events, collection/analysis lag. **Interpretation:** Zero or absent telemetry is missing measurement unless instrumentation proves it is a measured zero.

## Priority 6: Contract stability and threshold sensitivity

**Question:** How often do benign workload changes trigger drift, and how sensitive are results to model/threshold parameters?

**Design:** Repeatedly restart pods and vary normal request mix, configuration, autoscaling, and signed image updates. Compare frozen contract versions, explicit reviewed updates, and workload-context-conditioned models. Sweep `k_max`, minimum training tokens, calibration alpha, window length, and event-loss penalty while freezing attack data for final test.

**Independent variables:** contract condition, workload variation, parameter setting. **Dependent variables:** benign alert rate, attack recall, score distributions, unresolved identity fraction, contract update frequency. **Interpretation:** Report the sensitivity curve, not only the best threshold. Never tune on final attack repetitions.

## Minimum submission gate

Before restoring strong empirical claims, collect: successful raw logs for each named attack; independent attack oracle labels; benign control windows; PURL/image/process mappings; saved metric denominators and raw resource measurements; baseline raw detections under documented versions/settings; a reproducibility manifest with cluster/kernel/container/image digests; and PCEPS training/calibration/test records if predictive claims remain. The SolarWinds-style injection failures must be repaired and rerun. Any event without a resolved identity should remain a drift alert without a component attribution.
