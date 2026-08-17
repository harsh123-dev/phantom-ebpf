# PHANTOM Task 3: Causal Engine Algorithm Specification Handoff

Full title: "PHANTOM: Causal Attribution of Runtime SBOM Drift via eBPF Behavioral Contracts in Kubernetes"

This document specifies the exact algorithms for behavioral contracts, runtime divergence, BDG maintenance, causal attribution, and PCEPS. It refines the Task 1 architecture and Task 2 API contracts without changing their public resource shapes. All probabilities and feature values are retained with their uncertainty provenance.

## 1. Research Framing

PHANTOM's research claim is not that a rare system call proves compromise. Its claim is that a signed artifact baseline can be enriched with a learned, explainable behavioral baseline; deviations can be located in a dependency graph; and a causal effect may be estimated only where the graph, temporal evidence, and covariates identify that effect. This task makes that claim falsifiable by fixing the learning rule, divergence statistic, graph projection, non-identifiability behavior, and supervised-priority data protocol.

## 2. Shared Definitions and Notation

An `EBPFEvent` is a normalized, identity-resolved event from Task 2. A trace `T = (e_1,...,e_n)` is a sequence from one resolved `(tenant_id, image_digest, component_purl, workload_epoch)` partition, ordered by `(kernel_timestamp_ns, event_id)`. Events with `identity_status != resolved` or `binding_status != resolved` are retained as evidence but excluded from contract training. A workload epoch begins at container start and ends at container termination or image change.

The deterministic tokenization function is:

`tau(e) = (event_type, operation_class, resource_class, privilege_class)`.

`operation_class` is one of `exec`, `read`, `write`, `connect`, `accept`, `credential_change`, `namespace_change`, or `module_change`. `resource_class` is a contract-normalized class (for example an allow-listed path-prefix class, CIDR/port class, PURL class, or `OTHER_RESOURCE`), never a raw path, raw IP address, PID, argument, or payload. `privilege_class` is one of `unprivileged`, `elevated`, or `unknown`. The finite alphabet `Sigma` contains tokens seen during training plus the preallocated `UNK` token. A token not in `Sigma` at scoring time maps to `UNK` and emits a separate novelty flag.

Let `N` be total training tokens, `m = |Sigma|`, `K_max` be maximum candidate Markov order, `H_k` be the number of observed contexts of length `k`, `H = sum(k=0..K_max) H_k`, `Q` be the number of nonzero context-to-token transitions, and `W` be the number of event-time windows used for causal observations. All time windows are fixed before evaluation; the initial parameter is five minutes and is an experiment configuration, not a universal security constant.

## 3. Algorithm 1: Behavioral Contract Generation

### 3.1 Motivation and Formal Definition

For component PURL `p`, training traces `T_p = {T_1,...,T_r}`, and permitted maximum order `K_max`, Behavioral Contract Generation produces:

`BC_p = (M_p, C_p, tau, sigma)`.

`M_p` is the learned variable-order Markov model. `C_p` is the signed, operator-reviewed constraint set from Task 1; learned behavior can propose additions but cannot activate an allow-list exception. `tau` is the interval `[training_start, training_end]` and `sigma` is the cosign/Sigstore signature envelope. The learned model is an evidence-bearing field of the contract, not a substitute for signature verification.

For a context `h` with `|h| <= K_max` and next token `x in Sigma`, the posterior-predictive transition probability is:

`P_p(x | h) = (n_p(h,x) + 1) / (n_p(h) + m)`.

The effective context is the longest retained suffix of the preceding sequence. Thus the model is variable-order: it uses a longer history only when that history has evidence and is selected by the BIC pruning rule below; otherwise it backs off to a shorter suffix.

Input:

`traces: list[EBPFEvent]`, all for a candidate PURL after deterministic partitioning; `component_purl: str`; `order: int | None`; `training_window`; and signed contract metadata.

Output:

one `BehavioralContract` with status `active_candidate`, `unobservable`, or `insufficient_evidence`. Only a signature-verified and reviewer-approved candidate may become an active contract.

### 3.2 Design Rationale

PHANTOM uses a variable-order Markov chain because it captures local, ordered behavior such as `exec -> file_write -> network_connect`, supports explicit transition probabilities, permits bounded memory, and produces evidence an analyst can inspect. It has a direct likelihood needed for BIC, KL divergence, and reproducible replay.

An HMM is worse for this first research artifact because its latent states have no stable security meaning unless separately identified and validated. HMM inference/training adds local optima, state-count selection, and opaque latent explanations while the available observations are already semantically normalized events. An HMM may be evaluated later as an ablation, not the default contract generator.

An LSTM is worse because it requires materially more representative traces, creates a difficult-to-audit hidden state, and makes bounded eBPF-event loss and concept drift difficult to separate from learned representation drift. Its sequence likelihood is not enough reason to trade away contract explainability, artifact portability, and evaluator reproducibility.

A fixed-order n-gram model is worse because a single global order either loses short-context behavior or sparsifies longer-context behavior. The variable-order backoff model retains a long context only where it reduces penalized description length, which is appropriate for components whose different operations have different dependency depths.

Order selection uses BIC rather than raw likelihood or hand-selected order. For candidate order `k`, define:

`BIC(k) = -2 log L_k + q_k log N`,

where `log L_k = sum(h,x) n(h,x) log((n(h,x)+1)/(n(h)+m))` and `q_k = sum(h in H_k) (m-1)` is the number of free transition parameters before the simplex constraint. Select `k* = argmin BIC(k)` over the eligible candidate set. BIC is selected over MDL because, under regular finite-model conditions, it is an asymptotic approximation to a model-evidence penalty, needs no separate codebook specification, and yields a deterministic rule that can be reproduced from counts. MDL would also be defensible but requires encoding choices that would become an extra experimental degree of freedom.

For each observed context `h` of length at most `k*`, retain `h` only when:

`BIC_local(h) < BIC_local(suffix(h))`,

where `BIC_local(h) = -2 sum(x) n(h,x) log P(x|h) + (m-1) log(max(1,n(h)))`. Every unretained context uses its immediate suffix, recursively ending at the empty context. This is the exact variable-order pruning rule.

### 3.3 Laplace Smoothing and Zero Probability

The smoothing constant is not arbitrary. For each context, adopt the symmetric Dirichlet prior `Dirichlet(1,...,1)` over the `m` predefined symbols, including `UNK`. Given counts `n(h,x)`, the posterior is `Dirichlet(n(h,x)+1)`. Its posterior-predictive mean is the transition equation above. Therefore the minimum conditional probability assigned to any unseen token is formally:

`epsilon_h = 1 / (n(h) + m)`.

This is Laplace add-one smoothing, derived from the unit pseudocount prior and the observed context count, rather than selected by a security analyst. It guarantees `P_p(x|h) >= epsilon_h > 0`. An unseen test event type maps to the preallocated `UNK` symbol, receives `epsilon_h` when not previously observed after `h`, and is reported as `novel_token=true`; it is never silently treated as normal. A raw event attribute that has not been normalized to an allowed finite class also maps to `OTHER_RESOURCE`, which is distinct from `UNK` and itself included in `Sigma` when the contract schema is initialized.

### 3.4 Pseudocode

```text
ALGORITHM 1 GenerateBehavioralContract(traces, component_purl, order, training_window, metadata)
01  REQUIRE component_purl is a canonical PURL
02  REQUIRE training_window.start < training_window.end
03  R <- [e in traces where e.component_purl = component_purl
04                         and e.identity_status = resolved
05                         and e.sbom_binding.status = resolved
06                         and training_window contains e.observed_at]
07  PARTITION R into workload epochs by (tenant, pod_uid, container_id, image_digest, start/end)
08  SORT each epoch by (kernel_timestamp_ns, event_id)
09  S <- [map tau over each nonempty epoch sequence]
10  IF number of tokens in S = 0 THEN
11      RETURN BehavioralContract(status=unobservable, model=null,
12                                reason=no_resolved_component_events, metadata=metadata)
13  Sigma <- unique tokens in S UNION {UNK, OTHER_RESOURCE}
14  m <- cardinality(Sigma); N <- total token count in S
15  K_limit <- min(K_max from configuration, maximum(length(s)-1 for s in S))
16  IF order is not null THEN REQUIRE 0 <= order <= K_limit; Candidates <- {order}
17  ELSE Candidates <- {0, 1, ..., K_limit}
18  FOR each k in Candidates DO
19      Counts[k] <- empty sparse map from context to token-count map
20      FOR each sequence s in S DO
21          FOR i from 0 to length(s)-1 DO
22              h <- suffix of s[0:i] of length min(k, i)
23              Counts[k][h][s[i]] <- Counts[k][h][s[i]] + 1
24      END FOR
25      log_likelihood[k] <- sum over h,x of Counts[k][h][x] *
26                           log((Counts[k][h][x] + 1) / (sum_y Counts[k][h][y] + m))
27      parameter_count[k] <- number_of_contexts(Counts[k]) * (m - 1)
28      BIC[k] <- -2 * log_likelihood[k] + parameter_count[k] * log(N)
29  END FOR
30  k_star <- smallest k attaining min(BIC[k])
31  RetainedContexts <- {empty context}
32  FOR each observed context h of lengths 1 through k_star, ordered by increasing length DO
33      parent <- suffix(h) with its first token removed
34      local_bic_h <- LocalBIC(Counts[k_star][h], m)
35      local_bic_parent <- LocalBIC(EffectiveCounts(parent, Counts[k_star], RetainedContexts), m)
36      IF local_bic_h < local_bic_parent THEN add h to RetainedContexts
37  END FOR
38  FOR each retained context h DO
39      c_h <- sum_x Counts[k_star][h][x]
40      FOR each x in Sigma DO
41          Transition[h][x] <- (Counts[k_star][h][x] + 1) / (c_h + m)
42      END FOR
43      epsilon[h] <- 1 / (c_h + m)
44  END FOR
45  Metrics <- ComputeTrainingCoverageAndLoss(R, S)
46  status <- active_candidate IF N >= minimum_training_tokens AND Metrics.loss_rate <= configured_limit
47            ELSE insufficient_evidence
48  RETURN BehavioralContract(component_purl, model=(Sigma, k_star, RetainedContexts,
49                             Transition, epsilon, BIC[k_star], Metrics), metadata, status)
```

`LocalBIC(count_map, m)` uses the expression in Section 3.2 with the count-map's total as `n(h)`. `EffectiveCounts` uses the longest retained suffix; it does not fabricate a context not in the model. `minimum_training_tokens` and the collection-loss limit are pre-registered evaluation parameters selected before testing and stored in the contract, not hidden implementation constants.

### 3.5 Complexity Analysis

Training time is `O(N*K_limit + K_limit*H*m)` with dense probability materialization. With sparse count maps and final materialization only for nonzero transitions plus one epsilon, it is `O(N*K_limit + Q)`. The conservative worst case is `O(N*K_limit + K_limit*m^(K_limit+1))` when every possible context is observed. BIC context pruning is `O(H*m)` dense or `O(Q)` sparse.

Model storage is `O(H + Q + m)` with sparse transition counts/probabilities and suffix links. A dense table has worst-case `O(m^(k_star+1))` space and is prohibited. Contract storage also includes bounded metadata and signature references; raw traces are not embedded.

### 3.6 Failure Cases and Mitigations

| Failure | Required behavior |
|---|---|
| Component generates no resolved events | Return `status=unobservable`, no learned model, and no KL score. The signed declarative constraints may still exist, but PHANTOM must not claim learned normality. |
| Too few events or excessive loss | Return `insufficient_evidence`; retain training count and loss statistics; do not activate learned permissiveness. |
| Event type appears only at test | Map to `UNK`, use derived `epsilon_h`, set novelty flag, and retain the raw event evidence separately. |
| New resource/path/IP class | Map to `OTHER_RESOURCE` or `UNK` according to tokenizer rule and emit a contract violation candidate; never add it online to `Sigma`. |
| Benign software update changes behavior | New image digest/PURL version requires a new contract candidate and signature review; do not mutate an old signed contract. |
| Trace contains mixed components due to ambiguous mapping | Exclude it from training and record the excluded count. |
| Attacker poisons training traces | Training accepts only verified image digest, approved time window, and resolved identity; contract activation requires cosign verification and reviewer approval. This mitigates but cannot eliminate a compromised trusted training environment. |

## 4. Algorithm 2: KL-Divergence Drift Scorer

### 4.1 Formal Definition and Motivation

Let `BC` contain the transition model `P_BC(x|h)`. Let observation window `O=(x_1,...,x_l)` be tokenized using the same `tau` and `Sigma`. For every position `i`, choose `h_i` as the longest retained suffix context preceding `x_i`, and define the observed conditional empirical distribution:

`Q_O(x|h) = count_O(h,x) / sum_y count_O(h,y)`.

Let `w_O(h) = sum_y count_O(h,y) / sum_{h',y} count_O(h',y)`. PHANTOM's behavioral divergence is the directed conditional KL divergence:

`D(BC,O) = sum_h w_O(h) * sum_(x in Sigma) Q_O(x|h) * log(Q_O(x|h) / P_BC(x|h))`.

Only terms with `Q_O(x|h)>0` are evaluated. Laplace smoothing guarantees the denominator is nonzero. The score is in nats, is nonnegative up to floating-point tolerance, and is not a probability. The companion novelty rate is `u(O) = count(tokens mapped to UNK)/l`; it is recorded separately because a low-frequency novel event can be operationally important even when window-level divergence is modest.

The anomaly threshold is a split-conformal upper quantile over benign calibration windows, not a hand-tuned constant. Given `n_cal` benign, time-disjoint calibration scores sorted ascending as `d_(1) <= ... <= d_(n_cal)` and a preregistered false-alarm budget `alpha in (0,1)`, set:

`j = ceil((n_cal + 1)(1-alpha))`, `theta_alpha = d_(min(j,n_cal))`.

Flag `behavioral_drift=true` iff `D(BC,O) > theta_alpha`. Under exchangeability of future benign windows with calibration windows, the split-conformal guarantee bounds marginal false-alarm probability by `alpha`; deployment drift may violate exchangeability, so the paper must report calibration age and distribution shift. A score is `not_scorable` rather than benign when `BC.status != active` or `l < minimum_scoring_tokens`.

### 4.2 Why KL Divergence

KL divergence is selected because PHANTOM asks a directional question: how surprising is the observed conditional behavior `Q_O` under the trusted expected model `P_BC`? Its log-ratio is additive over observed transitions and aligns with negative log likelihood, making analyst evidence traceable to individual low-probability transitions.

L1 distance is worse because every absolute probability difference has linear, symmetric cost and it does not distinguish a rare-but-contract-forbidden event from a comparable change in a common transition relative to what the baseline expected. L2 is worse because squaring amplifies large aggregate differences but has the same baseline-insensitivity and is not naturally decomposed as a likelihood ratio. Cosine distance is worse because it emphasizes vector angle and discounts absolute probability mass, so a sparse anomalous distribution can appear directionally similar. Jensen-Shannon divergence is bounded and symmetric, but symmetry is undesirable here: the baseline is the signed expected distribution and the observation is the candidate deviation. Its mixture distribution also dampens the diagnostic impact of low-probability expected transitions relative to directed `KL(Q||P)`. Jensen-Shannon is retained only as an ablation metric.

### 4.3 Pseudocode

```text
ALGORITHM 2 ScoreBehavioralDrift(contract, observation_window, calibration_scores, alpha)
01  REQUIRE contract.status = active
02  REQUIRE 0 < alpha < 1
03  tokens <- [MapToAlphabet(tau(e), contract.Sigma) for e in observation_window]
04  IF length(tokens) < minimum_scoring_tokens THEN
05      RETURN DriftScore(status=not_scorable, reason=insufficient_observation_tokens)
06  TransitionCounts <- empty map
07  unknown_count <- 0
08  FOR i from 0 to length(tokens)-1 DO
09      h <- LongestRetainedSuffix(tokens[0:i], contract.RetainedContexts)
10      x <- tokens[i]
11      IF x = UNK THEN unknown_count <- unknown_count + 1
12      TransitionCounts[h][x] <- TransitionCounts[h][x] + 1
13  END FOR
14  total <- sum over h,x of TransitionCounts[h][x]
15  divergence <- 0
16  FOR each context h in TransitionCounts DO
17      c_h <- sum_x TransitionCounts[h][x]
18      weight <- c_h / total
19      local <- 0
20      FOR each token x with TransitionCounts[h][x] > 0 DO
21          q <- TransitionCounts[h][x] / c_h
22          p <- contract.Transition[h][x]
23          local <- local + q * log(q / p)
24      END FOR
25      divergence <- divergence + weight * local
26  END FOR
27  sorted <- sort(calibration_scores ascending)
28  j <- ceil((length(sorted)+1) * (1-alpha))
29  theta <- sorted[min(j, length(sorted))]
30  RETURN DriftScore(status=scored, kl_divergence=divergence, threshold=theta,
31                    behavioral_drift=(divergence > theta),
32                    novelty_rate=unknown_count/length(tokens), alpha=alpha)
```

### 4.4 Complexity Analysis

For an observation of `l` tokens, context lookup is `O(k_star)` per token with suffix links and count accumulation is `O(l)`, so scoring is `O(l*k_star)` time and `O(min(l,Q_O))` space, where `Q_O` is observed window transitions. Threshold lookup is `O(1)` when sorted calibration scores and their indexed quantiles are stored with the contract; the pseudocode's direct sorting is `O(n_cal log n_cal)` only at calibration publication. The model is not retrained during scoring.

### 4.5 Failure Cases and Mitigations

| Failure | Required behavior |
|---|---|
| Empty/too-short observation | Return `not_scorable`; do not set divergence to zero. |
| No active, verified contract | Return `not_scorable` and keep raw contract violation evidence separate. |
| Zero baseline probability | Impossible under required Laplace smoothing; if malformed legacy model lacks a probability, reject the model and mark it invalid. |
| Calibration contamination by attacks | Calibration windows must originate from preregistered benign runs; retain provenance and recalibrate only through a new signed contract version. |
| Nonstationary benign workload | Report calibration age and rolling score distribution; require contract review/new version rather than silently raising threshold. |
| High event loss | Score may be biased; retain score but apply the loss penalty to attribution confidence and PCEPS feature completeness. |
| Attack mimics normal transitions | KL alone may not detect it; graph context, signed SBOM mismatch, contract constraints, and causal evidence remain independent signals. |

## 5. Algorithm 3: BDG Construction and Streaming Update

### 5.1 Formal Definition and Graph Update Rule

The operational BDG is a typed, directed multigraph `G_t=(V_t,E_t,phi_t,psi_t)` implemented as a NetworkX `MultiDiGraph`. It retains cycles because runtime dependency observations can be cyclic. Each node has a stable natural key and an immutable UUID:

`node_key(type, tenant, scope, value)`.

Node scopes are:

| Node type | Natural key and merge rule |
|---|---|
| `workload` | `(tenant, cluster, namespace, pod_uid)`; never merge pods. |
| `container` | `(tenant, container_id, image_digest)`; never merge restarts with new container IDs. |
| `process` | `(tenant, container_id, tgid, pid_start_time_ns)`; prevents PID-reuse merging. |
| `purl` | `(tenant, canonical_purl)`; **one node is shared by all pods** using the same versioned PURL. |
| `file` | `(tenant, normalized_path_class)`; a class, not raw sensitive pathname. |
| `network_endpoint` | `(tenant, protocol, normalized_cidr_class, port_class)`; never raw unbounded endpoint values. |
| `contract` | `(tenant, contract_id)`. |
| `drift_event` | `(tenant, drift_event_id)`; immutable and never merged. |

The same PURL from two pods is therefore one artifact/provenance node with distinct `container --belongs_to/loads--> purl` edges. This preserves component-level common cause/dependency reasoning while maintaining pod-specific execution context. The graph must never merge same-named PURLs with different canonical version/qualifiers.

An event adds a node iff its natural key is absent. It adds a typed edge iff the `(source_key,target_key,edge_type)` relation is absent; otherwise it updates that edge. For a prior edge observation at time `t_prev`, current event time `t`, and decay constant `lambda in (0,1]` declared in the experiment manifest, update:

`w_e(t) = lambda^((t-t_prev)/Delta) * w_e(t_prev) + q_e`,

where `Delta` is the predeclared decay interval and `q_e` is the event evidence confidence in `[0,1]` (product of identity, SBOM-binding, and collector-quality confidence). Also set `last_seen=max(last_seen,t)`, increment `observation_count`, and append a bounded evidence reference. A new edge begins with `w_e=q_e`. Node `last_seen` and `observation_count` are updated similarly. Immutable graph snapshots are cut after committed batches; no query may observe a partial mutation.

### 5.2 Cycles and SCM Projection

Cycles are legitimate in the BDG, for example process A connects to service B, which triggers a process whose later callback reaches A. The SCM must be a DAG. PHANTOM does not delete or arbitrarily orient such observations.

For causal use, construct a temporal DAG projection `G^DAG` by converting each selected semantic variable `z` into `(z,w)` for time window `w`. Add an edge `(z,w) -> (z',w')` only if one of these rules holds:

1. `w < w'`, using event-time precedence; or
2. `w = w'` and the fixed causal-tier order is satisfied: `environment/RBAC/image -> component_version -> process_behavior -> file/network/privilege behavior -> contract_deviation -> runtime_sbOM_drift`.

An observed edge that violates or cannot be oriented by those rules is retained in `G_t` but added to `projection_exclusions`. After projection, run strongly connected component detection. If an SCC has more than one node or a self-loop, collapse it only into an opaque macro-variable when neither the treatment nor outcome is inside the SCC. If treatment or outcome lies in it, the causal query is `not_identifiable` because a component-level acyclic causal interpretation cannot be defended. No edge deletion merely to satisfy DoWhy is permitted.

### 5.3 Pseudocode

```text
ALGORITHM 3 UpdateBDGStreaming(graph, event, identity, binding, contract_result, time_window)
01  REQUIRE event.event_id has not been applied to graph snapshot lineage
02  REQUIRE event.tenant_id = identity.tenant_id
03  q <- CollectorConfidence(event) * IdentityConfidence(identity) * BindingConfidence(binding)
04  workload <- UpsertNode(type=workload, key=(tenant, cluster, namespace, pod_uid), event.time, q)
05  container <- UpsertNode(type=container, key=(tenant, container_id, image_digest), event.time, q)
06  process <- UpsertNode(type=process, key=(tenant, container_id, event.tgid, event.pid_start_time_ns), event.time, q)
07  UpsertEdge(workload, container, runs, event.time, q, event.event_id)
08  UpsertEdge(container, process, executes, event.time, q, event.event_id)
09  IF binding.status = resolved THEN
10      component <- UpsertNode(type=purl, key=(tenant, Canonicalize(binding.purl)), event.time, q)
11      UpsertEdge(container, component, belongs_to, event.time, q, event.event_id)
12  END IF
13  FOR each event-derived target relation r in MapEventToRelations(event) DO
14      target <- UpsertNode(r.target_type, r.natural_key, event.time, q)
15      UpsertEdge(process, target, r.edge_type, event.time, q, event.event_id)
16  END FOR
17  IF contract_result has one or more violations THEN
18      drift <- UpsertNode(type=drift_event, key=(tenant, contract_result.drift_event_id), event.time, q)
19      UpsertEdge(process, drift, derived_from, event.time, q, event.event_id)
20      IF component exists THEN UpsertEdge(component, drift, violates, event.time, q, event.event_id)
21      contract <- UpsertNode(type=contract, key=(tenant, contract_result.contract_id), event.time, q)
22      UpsertEdge(drift, contract, violates, event.time, q, event.event_id)
23  END IF
24  AppendEventIdToIdempotencyIndex(event.event_id)
25  IF batch boundary reached THEN CommitImmutableSnapshot(graph, time_window)
26  RETURN graph mutation identifier
```

`UpsertNode` adds a node only when its natural key is absent; otherwise it updates confidence by a documented bounded exponentially weighted moving average and `last_seen`. `UpsertEdge` uses the edge weight equation above. `MapEventToRelations` is a fixed mapping from Task 2 runtime event types to typed edges; unsupported event types are retained in raw evidence but do not create invented graph semantics.

### 5.4 Complexity Analysis

For one event with `r` derived target relations and expected O(1) indexed natural-key lookups, update time is `O(r)` and update space is `O(r)` only when all nodes/edges are new; otherwise it is O(1) additional space plus bounded evidence references. `r` is bounded by the event schema. Snapshot creation is `O(|V_delta|+|E_delta|)` for a delta representation; a full NetworkX materialized copy is `O(|V|+|E|)` and is not permitted on every event. Temporal DAG projection is `O(|V_p|+|E_p|)` plus SCC detection `O(|V_p|+|E_p|)`.

### 5.5 Failure Cases and Mitigations

| Failure | Required behavior |
|---|---|
| Duplicate event delivery | Idempotency index prevents double weight increment. |
| Out-of-order delivery | Retain source timestamp; deterministic ordering window; late event mutates a new snapshot and is marked late. |
| Ambiguous identity/PURL | Add only resolvable workload/process evidence and preserve uncertainty; do not create a PURL causal edge. |
| Same PURL in different pods | Use one PURL node, separate pod/container edges exactly as above. |
| Cycle contains treatment/outcome | Retain BDG cycle; return causal `not_identifiable`. |
| High-cardinality raw values | Normalize to bounded resource/endpoint classes before node key creation; raw forensic evidence stays in PostgreSQL. |
| Memory pressure | Use immutable snapshot retention policy and database-backed evidence; never evict the active snapshot without publishing successor. |

## 6. Algorithm 4: SCM Construction and Causal Attribution

### 6.1 Formal Causal Query

For a selected component instance in time window `w`, define treatment `C_w in {0,1}` as `1` when the component runs the experimentally designated malicious or manipulated version and `0` when it runs the approved version. In operational incidents where maliciousness is unknown, this variable must be named `candidate_component_version`; PHANTOM must not relabel suspicion as ground truth.

Define outcome `D_(w,w+h) in {0,1}` as whether a contract deviation meeting the predeclared outcome rule occurs within horizon `h` after window `w`. Let `X_w` be observed pre-treatment covariates only: workload role, namespace risk policy, image-signature state before deployment, service-account privilege, baseline event rate, collector loss rate, and pre-window graph features. No post-treatment event, drift score, or attribution result may enter `X_w`.

The interventional query is:

`P(D_(w,w+h)=1 | do(C_w=1), X_w=x)`.

The causal effect is `ATE = E[D | do(C=1)] - E[D | do(C=0)]`. For a treated cohort with covariates `x`, the operational counterfactual query is:

`P(D_(w,w+h), C_w<-0 = 1 | C_w=1, X_w=x)`.

This is a cohort-level counterfactual risk, estimated only under consistency, conditional exchangeability, positivity, correct time ordering, and the SCM assumptions below. An individual retrospective counterfactual conditioned on an already observed `D=1` is generally not identifiable from passive eBPF traces; PHANTOM must not present a population intervention estimate as an exact individual "what would have happened" fact.

### 6.2 Causal Assumptions Encoded

1. **Acyclicity:** only the temporal DAG projection from Algorithm 3 is passed to DoWhy.
2. **Causal Markov condition:** each SCM variable is independent of its non-descendants conditional on its parents in the projected DAG.
3. **Faithfulness:** observed conditional independencies reflect the projected DAG rather than exact parameter cancellations.
4. **Consistency:** a window's observed outcome equals the potential outcome under its observed treatment.
5. **Conditional exchangeability:** after adjustment by declared pre-treatment covariates `X`, no unmeasured common cause jointly affects `C` and `D` enough to bias the estimated effect.
6. **Positivity:** for relevant `X=x`, both approved and manipulated/candidate component versions have nonzero support.
7. **Measurement adequacy:** event loss and identity uncertainty are measured and represented; they are not assumed absent.

These are scientific assumptions, not properties guaranteed by DoWhy. DoWhy encodes the proposed graph and tests identification/refutation logic; it cannot prove that hidden confounding is absent.

### 6.3 NetworkX to DoWhy Construction

Input is a fixed snapshot and selected observation cohort. Create one row per `(component instance, window)` in a pandas-compatible causal data table, with binary columns `component_version_treatment` and `runtime_sbom_drift`, plus declared covariates. Construct a NetworkX `DiGraph` whose nodes are these variable names, not raw BDG UUIDs. Directed edges are projected parent-to-child dependencies. Convert the graph to the graph representation accepted by the pinned DoWhy release; the implementation must pin and test the release because exact accepted graph serializers may vary. The documented `CausalModel(data, treatment, outcome, graph)` workflow accepts a causal graph and then supports `identify_effect`, `estimate_effect`, and `refute_estimate`. [DoWhy effect-estimation guide](https://www.pywhy.org/dowhy/v0.12/user_guide/causal_tasks/estimating_causal_effects/effect_estimation_with_estimators.html)

The required call sequence is conceptually:

```text
model <- CausalModel(data=causal_dataframe,
                     treatment="component_version_treatment",
                     outcome="runtime_sbom_drift",
                     graph=projected_dag)
estimand <- model.identify_effect(method_name="default",
                                  proceed_when_unidentifiable=false,
                                  optimize_backdoor=false)
IF estimand is absent OR estimand has no valid adjustment strategy: return not_identifiable
estimate <- model.estimate_effect(estimand,
                                  method_name=selected_backdoor_estimator,
                                  control_value=0,
                                  treatment_value=1,
                                  target_units="ate",
                                  confidence_intervals=true)
refutations <- model.refute_estimate(estimand, estimate, required_refuter)
```

The selected estimator is one of the Task 2 request values: `backdoor.linear_regression`, `backdoor.propensity_score_matching`, or `backdoor.generalized_linear_model`. With binary outcome, generalized linear model is the default when a valid backdoor set exists; propensity-score matching is the required sensitivity estimator where overlap permits. DoWhy's documented model/identify/estimate/refute workflow and the supported backdoor estimator naming inform this contract. [DoWhy API documentation](https://www.pywhy.org/dowhy/v0.9/_modules/dowhy/causal_model.html)

### 6.4 Pseudocode

```text
ALGORITHM 4 BuildAndEstimateSCM(snapshot, treatment_spec, outcome_spec, covariates, estimator, horizon)
01  REQUIRE snapshot is immutable and tenant-scoped
02  projected <- TemporalDAGProject(snapshot, treatment_spec, outcome_spec, horizon)
03  IF projected.treatment_or_outcome_in_unresolved_cycle THEN
04      RETURN Attribution(status=not_identifiable, reason=cyclic_treatment_or_outcome)
05  data <- BuildWindowedCausalTable(snapshot, projected, treatment_spec, outcome_spec, covariates)
06  REMOVE rows with unresolved treatment, outcome, or required pre-treatment covariate
07  IF no variation in treatment OR no variation in outcome THEN
08      RETURN Attribution(status=not_identifiable, reason=no_empirical_variation)
09  IF PositivityDiagnostic(data, treatment, covariates) fails THEN
10      RETURN Attribution(status=not_identifiable, reason=positivity_failure)
11  graph <- NetworkXDiGraphFromProjectedVariables(projected)
12  model <- DoWhyCausalModel(data, treatment, outcome, graph)
13  estimand <- model.identify_effect(method_name=default,
14                                    proceed_when_unidentifiable=false,
15                                    optimize_backdoor=false)
16  IF estimand is null OR estimand has no identified valid adjustment set THEN
17      RETURN Attribution(status=not_identifiable, reason=unidentified_effect,
18                         graph_diagnostics=projected.diagnostics)
19  estimate <- model.estimate_effect(estimand, method_name=estimator,
20                                    control_value=0, treatment_value=1,
21                                    target_units=ate, confidence_intervals=true)
22  counterfactual_risk <- EstimateCohortRiskUnderIntervention(data, estimand, estimator,
23                                                            intervention=0, treated_covariates=true)
24  refutations <- [RandomCommonCause, PlaceboTreatment, DataSubset] applied to estimate
25  confidence <- ComputeAttributionConfidence(data, projected, estimate, refutations,
26                                               event_loss, identity_resolution, contract_verification)
27  RETURN Attribution(status=completed, estimand, estimate, counterfactual_risk,
28                     refutations, confidence, snapshot_id)
```

`EstimateCohortRiskUnderIntervention` is a model-based estimate of `E[D|do(C=0),X=x]` for the treated cohort. It is permitted only when the selected estimator exposes or can be paired with a documented outcome-prediction interface for the pinned DoWhy release; otherwise `counterfactual_drift_probability` is `null` with `counterfactual_status=unavailable`. The implementation must not substitute an uncontrolled classifier prediction.

### 6.5 Complexity Analysis

Let `V_p,E_p` be projected graph nodes/edges, `W` cohort rows, `d` selected covariates, and `I` estimator iterations. Temporal projection and SCC detection are `O(V_p+E_p)`. Causal table assembly is `O(W*d)` after indexed event retrieval. Identification is graph-structural and may be exponential in the worst case for exhaustive adjustment/ID reasoning; PHANTOM uses the default bounded backdoor strategy and enforces configured graph and covariate limits. Generalized linear estimation is approximately `O(I*W*d^2)` for dense iterative fitting; matching is dominated by propensity fit plus neighbor search, `O(I*W*d^2 + W log W)` with indexed scores. Refutation cost is the sum of the configured refuter re-estimations and must be recorded rather than hidden.

### 6.6 Non-identifiability and Failure Cases

| Condition | Required output/mitigation |
|---|---|
| DoWhy cannot identify an estimand | `status=not_identifiable`, null effect and counterfactual fields, explicit reason; no numeric fallback. |
| Treatment/outcome in unresolved cycle | `not_identifiable`; retain BDG evidence and possibly score non-causal contract signals separately. |
| No treatment or outcome variation | `not_identifiable`; request controlled data or a different cohort. |
| Positivity/overlap fails | `not_identifiable`; do not extrapolate beyond observed version/workload support. |
| Too few rows after valid filtering | `not_identifiable` using pre-registered minimum cohort size. |
| Refuters fail or estimates unstable | completed result carries reduced confidence and failed refuter details; it is not automatically causal proof. |
| Unobserved confounding | Cannot be solved from trace data alone; disclose limitation, use sensitivity/refutation analyses, and prefer controlled version interventions. |
| Graph serializer/API differs by DoWhy release | Pin tested DoWhy version in the causal-engine lockfile and run contract tests around CausalModel construction. |

The obvious alternative, always estimating a classifier's feature importance or a correlation coefficient, is worse because neither identifies `P(D|do(C))`, distinguishes confounding from intervention, nor provides a defensible non-identifiability state.

## 7. Algorithm 5: PCEPS Feature Engineering and Calibration

### 7.1 Formal Definition

PCEPS is a calibrated probability-derived priority score, not a CVSS replacement and not causal evidence. For incident/window `i`, the feature vector is `F_i in [0,1]^16`; raw observations, normalization statistics, model version, and imputed-feature mask are retained. The model predicts `p_raw = XGBoost(F_i)`. Calibration produces `p_cal`, and `PCEPS_i = 100*p_cal`.

This vector refines the Task 1 feature list by making behavioral divergence an explicit feature; all Task 1 features remain present.

| Index / name | Derivation | Source | Missing-value rule |
|---|---|---|---|
| `f1_causal_effect` | `max(0, min(1, ATE))` for binary drift outcome. | Algorithm 4 attribution. | Median from training split plus imputed mask; PCEPS request fails if attribution is not identifiable. |
| `f2_attribution_confidence` | Published `AttributionConfidence.score`. | Algorithm 4. | Median plus mask. |
| `f3_contract_violation_rate` | `violations / max(1, evaluated_contract_rules)` in the window. | Contract validator. | `0` only if evaluation completed and found none; otherwise median plus mask. |
| `f4_behavioral_divergence_ratio` | `min(1, D(BC,O) / max(theta_alpha, delta))`, where `delta` is machine epsilon only when threshold is zero. | Algorithm 2. | Median plus mask; never call non-scorable behavior zero. |
| `f5_new_process_rate` | `new_processes_not_in_contract / max(1, total_exec_events)`. | BDG and contract validator. | Median plus mask. |
| `f6_unexpected_network_rate` | `unexpected_connect_or_accept / max(1, total_network_events)`. | Contract validator. | Median plus mask. |
| `f7_privilege_transition` | `1` if a verified unexpected privilege transition occurs, else `0`. | eBPF privilege event + contract validator. | Median plus mask. |
| `f8_sensitive_file_access_rate` | `sensitive_path_violations / max(1, file_events)`. Sensitive classes are signed contract metadata. | Contract validator. | Median plus mask. |
| `f9_component_criticality` | Signed policy value `kappa(purl) in [0,1]`, set by the project owner from component role/deployment impact, not invented CVE data. | SBOM/contract metadata. | Tenant median plus mask. |
| `f10_image_signature_invalid` | `1` if image/SBOM verification is failed or absent when required; otherwise `0`. | SBOM verifier. | `1` plus mask, because unknown trust state must not improve priority. |
| `f11_namespace_risk_weight` | Signed tenant policy `rho(namespace) in [0,1]`. | Gateway/contract policy. | Tenant median plus mask. |
| `f12_service_account_privilege` | `1` if effective RBAC includes any configured high-impact permission (secret read, pod exec/create, workload mutation, or cluster-admin equivalent); otherwise `0`. | Kubernetes RBAC resolver. | `1` plus mask, conservative uncertainty. |
| `f13_event_loss_rate` | `dropped / max(1, captured + dropped)`. | Agent loss events/metrics. | `1` plus mask, so missing collection does not overstate confidence. |
| `f14_graph_centrality_delta` | `min(1, max(0, (c_i - median_baseline(c)) / max(MAD_baseline(c), delta)))`, where `c` is declared normalized PageRank on the snapshot projection. | BDG engine. | Baseline median plus mask. |
| `f15_prior_drift_frequency` | `(prior_drift_windows + 1) / (prior_observed_windows + 2)`, using only windows preceding `i`. | PostgreSQL historical drift store. | Tenant-level beta-smoothed prior plus mask. |
| `f16_runtime_component_novelty` | `1` when binding is missing/ambiguous or a resolved runtime PURL is absent from verified SBOM; else `0`. | SBOM resolver and BDG. | `1` plus mask. |

`delta` is only a numerical guard to avoid division by zero and must equal the runtime's documented positive machine epsilon, never an analyst-selected threshold. Every normalization baseline is computed only on the training partition and versioned with the model; validation/test data must not update it.

### 7.2 Model and Calibration Rationale

XGBoost is selected because this is structured, heterogeneous, small-to-medium tabular evidence with nonlinear interactions, bounded missingness indicators, and a need for feature contribution inspection. It handles interactions such as high causal effect combined with invalid signature and elevated service account without manually expanding every cross term.

Logistic regression is worse as the primary model because it assumes additive log-odds unless interactions are manually specified; the signal is expected to be conditional and nonlinear. It remains a required baseline. Random forest is worse because its averaged piecewise predictions are often less sample-efficient for rare priority positives, cannot natively optimize sequential residual errors as boosting does, and may yield coarse probability outputs; it is another ablation baseline. A neural network is worse because the proposed labeled corpus is intentionally limited, tabular rather than high-dimensional unstructured data, and must remain explainable/reproducible for a final-year research artifact. No model family establishes causation; `f1` is a causal estimate input, while XGBoost predicts prioritization.

Platt scaling is selected over isotonic regression. Fit `p_cal = sigmoid(a*logit(clamp(p_raw)) + b)` on a held-out calibration set only. The two-parameter calibration is less prone to overfitting than isotonic regression when controlled attack data and independently confirmed incidents are limited. Isotonic regression may be reported as an ablation only if the calibration set size and reliability diagrams support it. `a`, `b`, calibration sample count, Brier score, expected calibration error definition, and split provenance are versioned alongside the model.

### 7.3 Training Data Strategy

Training labels must come from controlled, reproducible scenarios and independently adjudicated outcomes, not from PHANTOM's own predictions. Each scenario manifest fixes image digest, SBOM, contract version, workload, injection time, expected ground-truth effect, and benign/attack label.

Positive label `y=1`: a preregistered synthetic attack or controlled adverse deployment produces the manifest's confirmed security-relevant outcome, such as unauthorized process execution, unauthorized network communication to a controlled endpoint, prohibited sensitive-file class access, or unexpected privilege transition. The label is supplied by the experiment oracle/manifest and post-run evidence, never by KL score, causal effect, PCEPS score, or analyst suspicion.

Negative label `y=0`: benign baseline execution, benign workload upgrade, or benign fault scenario that does not produce the predeclared adverse outcome. Benign updates must be labeled separately in metadata so their rate can be reported, not hidden among ordinary negatives.

Split data by workload/image family, scenario family, and time so near-duplicate windows from the same run cannot cross train/validation/test boundaries. Use training for XGBoost fit, validation for hyperparameter selection, calibration partition for Platt scaling, and untouched test for final paper results. Maintain class prevalence and all synthetic-scenario provenance. Do not train on production incidents without independent labels and explicit ethics/consent review.

### 7.4 Pseudocode

```text
ALGORITHM 5 TrainAndScorePCEPS(labeled_windows, model_config, calibration_windows, candidate_window)
01  REQUIRE labels originate from scenario manifests or independent adjudication
02  SPLIT labeled_windows by workload/image family, scenario family, and time into train and validation
03  FOR each window i in train, validation, calibration, candidate DO
04      F_i <- DeriveSixteenFeaturesUsingOnlyPredeclaredSources(i)
05      mask_i <- MissingFeatureMask(F_i)
06      F_i <- ImputeUsingTrainingPartitionStatisticsOnly(F_i, mask_i)
07      F_i <- Concatenate(F_i, mask_i) for model input; retain original 16-feature report vector
08  END FOR
09  xgb <- FitXGBoost(train.features, train.labels, model_config selected on validation only)
10  raw_calibration <- xgb.predict_proba(calibration.features)
11  (a,b) <- FitPlattScaling(raw_calibration, calibration.labels)
12  raw_candidate <- xgb.predict_proba(candidate.features)
13  p_cal <- sigmoid(a * logit(Clamp(raw_candidate)) + b)
14  score <- 100 * p_cal
15  severity <- MapScoreToPreRegisteredSeverityBand(score)
16  RETURN PcepsScore(score, severity, feature_completeness=1-mean(mask_candidate),
17                    imputed_features=Names(mask_candidate), model_version, calibration=(a,b))
```

Severity bands are policy labels derived from preregistered operating points on the validation set; they are not learned from the test set. The implementation must retain the raw probability and calibration parameters even when rendering a severity string.

### 7.5 Complexity Analysis

For `n` training windows, 16 reported features, `b` trees, and maximum tree depth `d`, gradient-boosted training is approximately `O(b*n*16*d)` for histogram-style tree construction, with implementation-dependent constants. Inference is `O(b*d)` time and `O(16)` reported-feature space per window, plus model storage `O(b*2^d)` in the worst case. Platt fitting is `O(n_cal*I)` for iterative two-parameter logistic optimization; scoring is O(1). Exact performance must be measured, not claimed from these asymptotic bounds.

### 7.6 Failure Cases and Mitigations

| Failure | Required behavior |
|---|---|
| Causal attribution not identifiable | Reject PCEPS request under the Task 2 contract; do not impute `f1` as causal evidence. |
| Feature missing at inference | Apply only the feature-specific rule above, append mask, list imputed feature, and reduce completeness. |
| Signature/collection status missing | Conservative value `1` plus mask as defined; uncertainty cannot lower priority. |
| Synthetic-to-real distribution shift | Report it; never claim deployment generalization without an external/held-out evaluation. |
| Class imbalance | Use training-only class weights and report precision-recall/calibration; do not oversample across split boundaries. |
| Calibration drift | Recalibrate on a newly approved, independent calibration set; preserve old model/calibration version for reproducibility. |
| Leakage from post-outcome features | Feature derivation enforces temporal cutoff before outcome horizon; audit by manifest and column lineage. |

## 8. Assumptions for IEEE/ACM Review

A1: Normalized eBPF tokens preserve behavior relevant to component drift while discarding raw identifiers and payloads — needed for bounded, privacy-conscious models — validate against a curated event-to-contract ground-truth set.

A2: A variable-order Markov process is an adequate baseline approximation for the evaluated component behavior — needed for explainable contract learning — compare with declared HMM/LSTM/fixed n-gram ablations without overstating universal superiority.

A3: Training windows are benign and free from material attacker poisoning — needed for normality estimation — validate provenance, image signatures, controlled workloads, and reviewer approval.

A4: The symmetric Dirichlet(1) prior is an acceptable noninformative smoothing convention — needed to make zero-probability behavior scoreable — sensitivity-test alternative priors in an ablation without changing the preregistered main result.

A5: Benign calibration windows are exchangeable with future benign windows for the stated conformal false-alarm interpretation — needed for threshold validity — measure time/workload shift and report calibration age.

A6: Canonical PURLs identify the same component version across pods — needed for PURL-node merge — validate canonicalization and qualifier handling against SBOM fixtures.

A7: Event-time ordering and causal tiers permit defensible orientation of selected BDG relationships — needed for DAG projection — validate against controlled workload timelines and report projection exclusions.

A8: The causal Markov, faithfulness, consistency, exchangeability, and positivity assumptions are plausible for each reported cohort — needed for causal interpretation — publish DAGs, covariates, overlap diagnostics, and refutation results.

A9: Event loss, identity uncertainty, and signature state are measured well enough to penalize confidence — needed to avoid treating observability gaps as benign — validate loss counters and mapping status with injected failures.

A10: Synthetic attack outcomes provide labels representative enough for a prioritization experiment — needed to train PCEPS — isolate families in splits and present external validity as a limitation, not a solved fact.

A11: PCEPS is used for prioritization, not to determine compromise or establish causation — needed to keep the inference boundary clear — evaluate calibration/ranking separately from causal effect validity.

## 9. HANDOFF TO CLAUDE CODE

Implement these algorithms exactly in the paths below. Pseudocode and interface definitions are normative; no alternate model family, smoothing constant, graph-cycle deletion, or causal numeric fallback is permitted without an explicit project-owner revision.

Required files implied by Task 2 structure:

```text
services/causal-engine/app/domain/behavioral_contract.py
services/causal-engine/app/domain/bdg.py
services/causal-engine/app/domain/causal.py
services/causal-engine/app/domain/pceps.py
services/causal-engine/app/application/generate_contract.py
services/causal-engine/app/application/score_drift.py
services/causal-engine/app/application/update_bdg.py
services/causal-engine/app/application/estimate_attribution.py
services/causal-engine/app/application/score_pceps.py
services/causal-engine/app/infrastructure/networkx_repository.py
services/causal-engine/app/infrastructure/dowhy_adapter.py
services/causal-engine/app/infrastructure/xgboost_adapter.py
services/causal-engine/app/infrastructure/postgres_repository.py
services/causal-engine/app/infrastructure/redis_consumer.py
services/causal-engine/app/interface/worker.py
services/contracts/events/behavioral_contract_v1.schema.json
services/contracts/events/attribution_v1.schema.json
```

Exact Python interface definitions (signatures only; implementations must follow the algorithms above):

```text
def generate_behavioral_contract(
    traces: list[EBPFEvent],
    component_purl: str,
    order: int | None = None,
    training_window: TimeWindow | None = None,
    metadata: ContractMetadata | None = None,
) -> BehavioralContract

def select_markov_order_by_bic(
    token_sequences: list[list[BehaviorToken]],
    candidate_orders: list[int],
) -> MarkovOrderSelection

def score_behavioral_drift(
    contract: BehavioralContract,
    observation_window: list[EBPFEvent],
    calibration_scores: list[float],
    alpha: float,
) -> DriftScore

def update_behavioral_dependency_graph(
    graph: BehavioralDependencyGraph,
    event: EBPFEvent,
    identity: WorkloadIdentity,
    binding: SBOMComponentBinding | None,
    contract_result: ContractValidationResult | None,
    time_window: TimeWindow,
) -> GraphMutation

def project_bdg_to_temporal_dag(
    snapshot: BDGSnapshot,
    treatment_spec: TreatmentSpec,
    outcome_spec: OutcomeSpec,
    horizon: TimeWindow,
) -> TemporalDAGProjection

def construct_causal_model(
    projection: TemporalDAGProjection,
    observations: list[CausalObservation],
    treatment_name: str,
    outcome_name: str,
    covariate_names: list[str],
) -> CausalModelHandle

def estimate_causal_attribution(
    snapshot: BDGSnapshot,
    treatment_spec: TreatmentSpec,
    outcome_spec: OutcomeSpec,
    covariates: list[CovariateSpec],
    estimator: CausalEstimatorName,
    horizon: TimeWindow,
) -> AttributionResult

def derive_pceps_features(
    drift_event: DriftEventRecord,
    attribution: AttributionResult,
    contract_score: DriftScore | None,
    graph_snapshot: BDGSnapshot,
    feature_baseline: PcepsFeatureBaseline,
) -> PcepsFeatureVector

def train_pceps_model(
    labeled_windows: list[LabeledPcepsWindow],
    validation_windows: list[LabeledPcepsWindow],
    calibration_windows: list[LabeledPcepsWindow],
    model_config: PcepsModelConfig,
) -> CalibratedPcepsModel

def score_pceps(
    model: CalibratedPcepsModel,
    features: PcepsFeatureVector,
) -> PcepsScore
```

Implementation invariants:

1. Allocate `UNK` before training and use the derived `epsilon_h = 1/(n(h)+m)`; never use an arbitrary epsilon.
2. Never mutate a signed active contract's learned model. Generate a new candidate/version for new behavior.
3. Never use raw PIDs, full paths, IPs, argv, or payloads as unbounded Markov tokens or BDG keys.
4. Retain cycles in the BDG. Only use the temporal DAG projection for DoWhy; do not delete cyclic evidence.
5. Return `not_identifiable` on any causal identification, positivity, variation, or treatment/outcome-cycle failure. Never substitute correlation, feature importance, or a classifier score for causal effect.
6. Make feature derivation temporally causal: no post-outcome information may enter PCEPS features.
7. Persist model/order/BIC/calibration/normalization provenance, snapshot ID, smoothing rule, missing-feature mask, loss rate, and all refutation results with every result.

✓ CODEX TASK 3 COMPLETE
HANDOFF DOC READY FOR CLAUDE CODE
