# PHANTOM Drift Detector — Technical Reference

> **Scope**: This document covers the behavioral drift detection algorithm
> only (Part 2 of the staged research improvement).  It does not cover
> causal attribution, BDG redesign, PCEPS, or the frontend.

---

## 1. Input Feature Representation

Each eBPF event is tokenised into a 4-tuple **Token** by the function `tau()`:

```
Token = (event_type, operation_class, resource_class, privilege_class)
```

| Field | Values |
|-------|--------|
| `event_type` | Raw string from the eBPF probe (e.g. `"exec"`, `"file_open"`, `"net_connect"`) |
| `operation_class` | One of `{exec, read, write, connect, accept, credential_change, namespace_change, module_change}` |
| `resource_class` | Normalised resource path or `OTHER_RESOURCE` |
| `privilege_class` | One of `{unprivileged, elevated, unknown}` |

Unknown values map to `UNK_TOKEN` / `OTHER_RESOURCE_TOKEN` / `"unknown"`, not
silently discarded.  The mapping is deterministic and documented in
`domain/markov/chain.py`.

An **observation window** is a `list[Token]` produced by collecting and
tokenising all eBPF events for a container during a fixed time interval.

---

## 2. Markov Contract Representation

A **behavioral contract** is a trained `MarkovModel` stored in
`domain/markov/chain.py`.

Key fields:

| Field | Meaning |
|-------|---------|
| `sigma` | Frozen alphabet of Tokens seen during training + UNK, OTHER_RESOURCE |
| `k_star` | Selected Markov order (BIC argmin over 0 … k_max) |
| `retained_contexts` | Set of contexts kept after LocalBIC pruning |
| `transition[ctx][tok]` | Laplace-smoothed P(tok \| ctx) |
| `epsilon[ctx]` | Minimum probability = 1 / (n(ctx) + \|Σ\|) |
| `N` | Total training token count |

### Training Algorithm (Algorithm 1)

1. Collect baseline eBPF events → tokenise with `tau()`.
2. For k = 0 … k_max: build sparse count maps; compute BIC(k).
3. Select k\* = argmin BIC(k).
4. Prune contexts: retain h iff LocalBIC(h) < LocalBIC(suffix(h)).
5. Compute Laplace-smoothed transition probabilities for retained contexts.
6. Serialise to JSON (schema v1) and sign with cosign.

The contract is keyed by **image digest** (sha256) and **PURL** (SBOM Package URL).
A new image digest or PURL version requires a new contract candidate; the model is
never updated online.

---

## 3. Divergence Score Actually Implemented

### 3.1 KL-divergence score (`KlDriftScorer.score()`)

```
total_KL = Σ_h  P_obs(h) · KL(P_obs(·|h) ‖ P_contract(·|h))

         = Σ_h  [n(h)/N] · Σ_x  P_obs(x|h) · log(P_obs(x|h) / P_contract(x|h))
```

where:
- h is a Markov context (up to k\* preceding tokens)
- P_obs(x|h) = n_obs(x,h) / n_obs(h)  (empirical from observation window)
- P_contract(x|h) = model.predict(h, x)  (Laplace-smoothed from contract)
- For tokens absent from the contract alphabet: P_contract = epsilon(h) = 1 / (n(h) + |Σ|)

### 3.2 Event-loss multiplier

If ring-buffer or transport loss is reported:

```
final_score = total_KL × loss_penalty_factor   (default 1.5)
```

This does **not** change the divergence formula; it scales the result to
reflect reduced confidence in completeness.

### 3.3 Adjusted score (novelty term, disabled by default)

```
adjusted_score = final_score + novelty_weight × novel_token_fraction
```

With `novelty_weight = 0.0` (the default), `adjusted_score == final_score`.
The novelty term is an optional additive correction, not a change to the KL
formula.  Paper metrics must always report which setting was used.

### 3.4 Novel token fraction

```
novel_token_fraction = |{t ∈ obs : t ∉ sigma}| / N
```

Tracked separately from the KL score.  Provided in the DriftResult for
diagnostic use.

---

## 4. Threshold Calibration Method

### 4.1 Procedure

The drift alert threshold is an **empirical upper quantile** of
KL scores from independent benign baseline windows:

1. Score all available benign baseline windows using the same contract.
2. Sort scores ascending; select the q-th quantile (default q = 0.99).
3. That value becomes the threshold for the contract version.

### 4.2 Assumptions (must be satisfied for the threshold to be valid)

- All calibration windows are ground-truth labelled as benign.
- Calibration windows are exchangeable with future benign traffic on the
  same workload, same image digest, and same contract.
- Attack windows are **completely excluded** from calibration input.
- The calibration split is held out from training **and** from evaluation.
- The calibration split does not leak across time windows from the same run.

### 4.3 What is NOT implemented

This is **not** conformal calibration.  A conformal procedure would require:
- A formal exchangeability guarantee between calibration and test distributions.
- A non-conformity score with provable coverage.
- An independent calibration/test split with no time-leakage.

Those requirements are not verified for live eBPF workloads and are not claimed.

### 4.4 Current status

**No real benign calibration dataset exists in this repository.**
The default `threshold = float('inf')`.
No alert fires until calibration is explicitly run with real benign data.
`ThresholdCalibrator.calibrate()` returns `is_valid=False` with a detailed
explanation when fewer than `min_calibration_windows` (default 30) windows
are provided.

---

## 5. Output Decision States

`DriftOutcome` (enum, `domain/drift/decider.py`):

| State | Meaning |
|-------|---------|
| `drift` | adjusted_score > threshold AND all evidence criteria are met |
| `no_drift` | adjusted_score ≤ threshold AND all evidence criteria are met |
| `insufficient_evidence` | Evidence is inadequate; no alert issued |

The decision is recorded in a `DriftResult` dataclass with full provenance.

---

## 6. Insufficient-Evidence Conditions

A decision is `insufficient_evidence` when any of the following are true:

| Condition | Flag added to `missing_data_flags` |
|-----------|-----------------------------------|
| `len(obs) < min_observation_tokens` | `observation_tokens=N_below_minimum=M` |
| `model.N < min_training_tokens` | `model_training_tokens=N_below_minimum=M` |
| `image_digest == UNRESOLVED` and `require_identity=True` | `image_digest_unresolved` |
| `purl == UNRESOLVED` and `require_identity=True` | `purl_unresolved` |
| `threshold == inf` (uncalibrated) | `threshold_uncalibrated` (added as flag, **not** IE) |

Note: an uncalibrated threshold produces `no_drift` (not `insufficient_evidence`)
because the model and observation are still valid — the threshold is simply not set.
The flag `threshold_uncalibrated` signals this to downstream consumers.

---

## 7. Training / Calibration / Test Separation

```
Timeline:
  ┌──────────────────┬───────────────────────┬──────────────────────┐
  │   Training        │   Calibration          │   Test (evaluation)  │
  │   (baseline       │   (benign-only, held   │   (attack + benign   │
  │    eBPF events)   │    out from training)  │    scenarios)        │
  └──────────────────┴───────────────────────┴──────────────────────┘
```

- **Training**: Events from a designated baseline period. Must not overlap
  with calibration or test periods. Attack windows must be excluded.
- **Calibration**: Independent benign windows scored with the trained contract.
  Must not include attack data. Must not overlap with training or test.
- **Test**: The Part 1 evaluation pipeline (`run_all_scenarios.py`). Threshold
  is fixed before test evaluation; not adjusted based on test outcomes.

---

## 8. How the Experiment Runner Evaluates the Detector

The Part 1 pipeline (`ScenarioRunner`, `ScenarioEvaluator`) evaluates detection
at the **run level**: one scenario repetition = one unit of analysis.

The drift detector produces a `DriftResult` per observation window within a
scenario.  For evaluation purposes:

- A run is a **True Positive (TP)** if at least one `drift` decision occurs
  within `detection_window_s` after `injection_timestamp`.
- A run is a **False Negative (FN)** if no `drift` decision occurs within
  the window.
- A run is a **False Positive (FP)** if a `drift` decision occurs during a
  benign run.
- A run is a **True Negative (TN)** if no `drift` decision occurs during a
  benign run.
- `insufficient_evidence` results are **not** counted as detections.

**MTTD** is the time from `injection_timestamp` to the first `drift` decision
within the window.

---

## 9. What Is Implemented vs. What Remains Unvalidated

### Implemented and tested
- Variable-order Markov model with BIC order selection
- Laplace-smoothed KL divergence (weighted by context frequency)
- Novel-token fraction tracking
- Event-loss multiplier
- Contract JSON serialization/deserialization (v1 schema)
- Three-state decision rule with full provenance
- Threshold calibration interface with invalid-calibration handling
- Explicit configuration (no magic numbers)
- 60 Part 1 unit tests (all passing)
- 62 Part 2 unit tests (see below)

### Not yet validated scientifically
- **Threshold validity**: No real benign calibration dataset → threshold remains
  `float('inf')` → no real false-positive rate can be claimed.
- **FPR and precision**: Cannot be reported without benign-run data in the
  evaluation pipeline (only 6 attack runs exist; 0 benign runs evaluated).
- **MTTD distribution**: 6 TP runs from the real evaluation → p95 estimate is
  unreliable (pilot measurement only).
- **Novelty term effectiveness**: `novelty_weight=0.0` → not evaluated.
- **Real-time overhead**: Not measured; no claims made.

---

## 10. Commands

### Run unit tests

```bash
# From services/ebpf-agent/
python -m pytest tests/test_drift_decider.py tests/test_kl_scorer.py tests/test_markov.py -v

# Part 1 pipeline tests (from repo root):
python -m pytest research/evaluation/tests/ -v
```

### Train a contract (dry-run)

```bash
python research/evaluation/scenarios/run_all_scenarios.py --dry-run
```

### Score an observation window (Python REPL)

```python
from domain.markov.chain import train, tau
from domain.drift import DriftDecider, DriftDetectorConfig

# Train on benign sequences (SYNTHETIC example):
seq = [tau("exec","exec","/usr/bin/python3","unprivileged")] * 200
model = train([seq], k_max=3)

# Create decider (threshold uncalibrated by default):
cfg = DriftDetectorConfig()
decider = DriftDecider(
    model=model, config=cfg,
    image_digest="sha256:abc123",
    purl="pkg:pypi/example@1.0.0",
)

# Score an observation window:
obs = [tau("module_load","module_change","/evil.ko","elevated")] * 50
result = decider.decide(obs)
print(result.outcome, result.adjusted_score, result.explanation)
```

### Run threshold calibration (once real benign data is available)

```python
from domain.drift import ThresholdCalibrator, DriftDetectorConfig

cfg = DriftDetectorConfig()
calibrator = ThresholdCalibrator(model, cfg)
scores = calibrator.score_windows(benign_windows)
cal_result = calibrator.calibrate(scores)

if cal_result.is_valid:
    cfg.threshold = cal_result.threshold
    cfg.threshold_version = cal_result.threshold_version
else:
    print("Calibration failed:", cal_result.reason_invalid)
```
