# PHANTOM Algorithm Specification

## Scope and implementation status

This document records source-verified implementation in this repository. It does not treat the handoff specifications as evidence that an experiment executed successfully. The implementation contains SBOM ingestion and signature-verification paths, a Markov behavioral model, a KL drift scorer, graph updates, a DoWhy estimation path, and an XGBoost/Platt PCEPS scorer. The checked-in evaluation does not validate all of those paths end to end.

## 1. Trusted SBOM ingestion and component binding

The SBOM service computes a canonical digest of the CycloneDX document, compares it with the declared digest, associates the resulting SBOM with an image digest, and persists its metadata/components. Its Cosign adapter verifies the signed attestation for an image digest. A mismatch or failed verification is an error, not an accepted trusted SBOM. Runtime cgroup/pod association is handled by the eBPF agent; a PURL binding is populated only after identity and SBOM resolution. The raw evaluation evidence inspected here has unresolved/ambiguous bindings and cannot demonstrate this pipeline during the reported attacks.

## 2. Behavioral contract construction (implemented)

### Inputs and representation

Training input is a list of event sequences scoped by image digest and PURL over an explicit UTC interval. Each normalized token is

\[
\tau(e)=(\text{event type},\text{operation class},\text{resource class},\text{privilege class}).
\]

The finite alphabet \(\Sigma\) is the observed token set plus reserved `UNK` and `OTHER_RESOURCE` tokens. The implementation accepts candidate orders up to `k_max` (default parameter is 5 in the domain function) and requires at least 100 training tokens by default at the use-case boundary. The training-window filter, resolved-identity input requirement, approved data review, and signing are separate responsibilities; they are not validated by the raw3 evaluation.

### Model

For candidate order \(k\), count transitions \(n_k(h,x)\) for context \(h\), next token \(x\), and total \(N\). With \(m=|\Sigma|\), the model uses

\[
\hat P_k(x\mid h)=\frac{n_k(h,x)+1}{n_k(h)+m},\quad
\epsilon(h)=\frac{1}{n_k(h)+m}.
\]

The implemented smoothed log likelihood and parameter count are

\[
\log L_k=\sum_{h,x:n(h,x)>0}n(h,x)\log\frac{n(h,x)+1}{n(h)+m},
\qquad q_k=|H_k|(m-1),
\]

and \(\mathrm{BIC}(k)=-2\log L_k+q_k\log N\). Select \(k^*=\arg\min_k\mathrm{BIC}(k)\). The code then retains contexts whose local BIC improves on the retained suffix context, always retaining the empty context. The serialized model, image digest, PURL, training count and BIC are hashed, signed through the signer port, and persisted.

### Contract limitations visible in code

The tokenizer maps an unknown operation class to `exec` rather than a distinct unknown operation marker. The sequence scorer counts tokens outside the training alphabet as novel but scores those raw tokens using a fallback probability; it does not explicitly remap every unseen token to the reserved `UNK` token. These details should be fixed or documented before stronger claims about a stable canonical vocabulary are made. The scorer itself does not implement a benign calibration set, split-conformal threshold, minimum-scoreable-window status, or drift decision rule.

## 3. KL behavioral divergence (implemented score; threshold policy absent)

For observed token sequence \(O=(x_1,\ldots,x_l)\), construct context-conditioned empirical counts using the model's retained suffix contexts. Let

\[
Q_O(x\mid h)=\frac{n_O(h,x)}{n_O(h)},\qquad
w_O(h)=\frac{n_O(h)}{l}.
\]

The implemented score is

\[
D_{KL}(O\Vert BC)=\sum_h w_O(h)\sum_{x:n_O(h,x)>0}Q_O(x\mid h)
\log\frac{Q_O(x\mid h)}{P_{BC}(x\mid h)}.
\]

The code reports this in nats, records a novel-token fraction and optionally multiplies the total score by a configurable event-loss penalty (default 1.5). Empty input returns zero. Despite the design handoff proposing a split-conformal threshold over benign calibration windows, that threshold and the non-scorable contract state are not implemented in `KlDriftScorer`; this specification therefore does not claim a validated binary drift detector or false-alarm guarantee.

If `l` is observation length, `k` selected order, and `A_O` the number of observed context-token pairs, the implemented loop is \(O(lk+A_O)\) expected time with hash maps and \(O(A_O)\) auxiliary count storage, excluding suffix lookup implementation constants. Model storage is \(O(A_C m)\) dense probabilities for retained contexts \(A_C\). Training over `N` tokens and `K` candidate orders costs \(O(KN+N\bar{k})\) expected time for count-map construction/scoring/pruning, and \(O(KN+A_Cm)\) peak auxiliary/model storage in the direct implementation because candidate count maps are retained.

## 4. Behavioral Dependency Graph update (implemented)

The in-memory graph is a typed directed multigraph \(G_t=(V_t,E_t,\phi_t,\psi_t)\) using NetworkX `MultiDiGraph`. Natural keys include tenant and workload identity; process keys include container ID, TGID and process start timestamp to reduce PID-reuse merges. Implemented node classes include workload, container, process, PURL, file, network endpoint, contract, and drift event. Event mapping includes process execution, file reads/writes, network connect/accept, and contract violations. Unsupported event kinds do not create invented relations.

Each edge stores type, weight, last observation, count, bounded evidence references, and UUID. For repeated observation time `t`, previous time `t_prev`, `lambda` and `Delta`, the update is

\[
w_e(t)=\lambda^{(t-t_{prev})/\Delta}w_e(t_{prev})+q_e,
\quad q_e=\text{collector confidence}\times\text{identity confidence}\times\text{SBOM-binding confidence}.
\]

New edges begin at the new increment. Duplicate event UUIDs are ignored. Snapshots are cut every configured batch (default 100 events). The formula is implemented; edges are not causal proof. A missing PURL leaves process/container relationships but cannot create a component attribution edge.

For `n` event updates, `v` nodes, and `e` edges, indexed dictionary/NetworkX mutation is expected near \(O(n)\) total, but existing multiedge type lookup scans parallel edges and may cost \(O(n\bar d)\) in dense cases. Graph memory is \(O(v+e)\), plus bounded evidence references and snapshots.

## 5. Temporal projection and DoWhy causal estimation (implemented pathway, not validated on raw3)

The projection maps observed BDG node types into semantic variable classes, expands each class across `W` windows, adds forward-window edges for observed graph relations, and adds same-window edges only when the hard-coded causal tier strictly increases. It records excluded edges and diagnoses strongly connected components. Given the construction rules, projected edges are forward in window or strictly upward in tier; a treatment/outcome SCC is checked and causes abstention.

The SCM builder constructs an observation DataFrame containing binary treatment/outcome and supplied covariates (missing covariates default to zero), checks variation and positivity, builds a semantic DAG with the projection relations plus treatment-to-outcome and covariate-to-treatment/outcome edges, serializes it to GML, and constructs `dowhy.CausalModel`. The use case asks DoWhy to identify the effect with `proceed_when_unidentifiable=False`, estimates an ATE with the configured estimator and confidence intervals, attempts a treated-cohort counterfactual prediction when supported, then runs random-common-cause, placebo-treatment and data-subset refutations. It returns `not_identifiable` for observed cycle, variation, positivity, construction, identification, or estimation failures.

The code’s `compute_attribution_confidence` is a heuristic product of event completeness, identity-resolution rate, a 0.5 penalty for an unverified contract, a confidence-interval-width penalty only above width 0.5, and the fraction of refutations passing a 50%-relative-effect tolerance. It is not a calibrated probability that the attribution is causal. Confounding control depends on caller-supplied covariates and graph assumptions. The SCM code adds treatment-to-outcome and covariate arrows by construction; this is a specified causal model assumption, not learned causal structure. Raw3 has no per-run treatment/outcome table or ground-truth PURL attribution; no causal-accuracy estimate can be reproduced.

For `V` semantic variables, `W` windows, and `E` source edges, projection creates `O(VW)` nodes and up to `O(EW^2)` forward-window edges. SCC detection is `O(V_p+E_p)` in projected graph size. DoWhy identification/estimation cost is estimator- and graph-dependent and is not assigned a tighter complexity claim here.

## 6. PCEPS scoring (implementation exists; reported performance unsupported)

The 16 ordered input features are:

1. ATE-derived causal effect (clamped to [0,1]); 2. attribution confidence; 3. contract-violation rate; 4. KL divergence divided by threshold; 5. new-process rate; 6. unexpected-network rate; 7. unexpected privilege transition; 8. sensitive-file violation rate; 9. component criticality; 10. invalid image signature; 11. namespace risk; 12. high-privilege service account; 13. event-loss rate; 14. graph-centrality delta; 15. Beta-smoothed prior drift frequency; and 16. runtime-component novelty.

Every feature is clamped to [0,1]. Missing values use training-partition medians and an imputation mask, except security-conservative defaults of 1 for missing signature validity, privilege, event-loss, and runtime novelty. The scorer concatenates 16 values and 16 mask bits. For model raw probability `p`, Platt calibration parameters `a,b`, and clamp \(\epsilon=10^{-7}\),

\[
p_{cal}=\sigma(a\,\mathrm{logit}(\mathrm{clamp}(p))+b),
\qquad \mathrm{PCEPS}=100p_{cal}.
\]

The numerical score is bounded by [0,100] and the code maps it into fixed severity bands at 20, 40, 60 and 80. In mathematical form, `p_cal` is a probability output from a trained binary classifier, but it is not a calibrated prospective compromise probability absent a well-defined future-outcome label and held-out calibration/evaluation. The paper's former AUC 0.923 and Brier 0.081 could not be linked to checked-in trained artifacts or scored windows.

The training utility has a nominal train/validation/calibration workflow, training-partition medians/MADs, XGBoost, Platt fit, Brier/ECE calculation and save routine. Its actual split procedure is not implemented inside `train_pceps_model`; callers supply already split windows. Training complexity depends on XGBoost tree settings and sample/feature counts; inference cost is proportional to evaluated tree nodes and memory to the serialized model plus one 32-value input. No PCEPS AUC or prospective claim is included as a result.

## 7. Report generation

The report service assembles drift evidence, identity status, graph/attribution data, and PCEPS score fields into an analyst-facing report. Reports are evidence summaries. Their contents inherit the evidence quality above and do not independently validate the inferred cause.

## 8. End-to-end pseudocode (implemented parts only)

```text
INGEST SBOM(document, declared_digest, image_digest, signature):
    canonical_digest <- hash(canonicalize(document))
    reject if canonical_digest != declared_digest
    verify signature/attestation against image_digest; reject on failure
    persist verified SBOM and component PURLs

GENERATE CONTRACT(image_digest, purl, [start,end], token_sequences):
    require total_tokens >= minimum_training_tokens
    Sigma <- observed_tokens union {UNK, OTHER_RESOURCE}
    for k in 0..min(k_max, max_sequence_length-1):
        count transitions; compute smoothed log likelihood and BIC
    k_star <- argmin BIC
    retain contexts whose local BIC beats retained suffix
    store Laplace-smoothed transition table and epsilon values
    serialize; hash; sign; persist model and provenance

SCORE WINDOW(model, observed_tokens, loss_observed):
    construct empirical context/token counts
    compute weighted conditional KL and novelty fraction
    multiply KL by configured loss penalty if loss_observed
    return numeric drift score and diagnostics
    # A calibrated threshold/decision and non-scorable status are absent.

UPDATE BDG(event):
    return unchanged if event UUID already processed
    upsert workload, container, process with composite confidence
    if binding is resolved, upsert PURL and container-to-PURL edge
    map supported event type to typed resource edge
    add drift and contract nodes/edges for supplied violations
    decay/update edge weights and cut snapshot at batch boundary

ESTIMATE ATTRIBUTION(projection, observations, specs):
    return not_identifiable on treatment/outcome cycle
    build treatment/outcome/covariate table; check variation and positivity
    build DAG and DoWhy model; identify with unidentifiable effects disallowed
    return not_identifiable if identification/estimation fails
    estimate configured ATE and confidence interval
    attempt supported counterfactual prediction; run configured refutations
    return estimate plus heuristic confidence and diagnostics

SCORE PCEPS(features, model, calibration):
    derive 16 bounded values and missing-value mask
    raw <- XGBoost probability on concatenated 32-value vector
    calibrated <- sigmoid(a * logit(clamp(raw)) + b)
    score <- 100 * calibrated; map fixed severity band; persist/report
```

## 9. Unimplemented or unsupported elements

The following elements are specified in design handoffs or paper prose but lack corresponding complete validated evidence: split-conformal drift threshold and decision; end-to-end event normalization and high-confidence component mapping in the raw dataset; a causal attribution evaluation with independent component ground truth; deployed PCEPS model and future-outcome labels; benign controls; nonzero/validated resource-overhead measurement; complete cluster/image/version manifest; and successful SolarWinds-style attack injection. These are methodological/implementation follow-ups, not silently filled assumptions.
