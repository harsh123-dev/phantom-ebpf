"""
services/ebpf-agent/domain/markov/chain.py

Variable-order Markov chain for PHANTOM behavioral contract generation.

Implements Algorithm 1 (GenerateBehavioralContract) from the handoff doc
(Task 3, Section 3) exactly as specified. No external ML library is used.

Algorithm summary:
1. Filter and sort resolved events; tokenize via tau().
2. For each candidate order k in 0..K_limit: accumulate counts, compute BIC.
3. Select k* = argmin BIC(k).
4. Prune contexts using LocalBIC: retain context h iff LocalBIC(h) < LocalBIC(suffix(h)).
5. Compute Laplace-smoothed transition probabilities and epsilon values.
6. Return the trained model.

Key design decisions (from handoff Section 3.2):
- Laplace add-one smoothing (symmetric Dirichlet(1,...,1) prior).
- BIC order selection (not raw likelihood, not hand-tuned order).
- Sparse count maps (not dense tables) to avoid m^(k+1) explosion.
- UNK and OTHER_RESOURCE tokens are pre-allocated in Sigma.
- No online model update: a new image digest/PURL version requires a new
  contract candidate.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# ABI: Reserved tokens (must match handoff Section 2)
# ---------------------------------------------------------------------------

UNK_TOKEN: str = "UNK"
OTHER_RESOURCE_TOKEN: str = "OTHER_RESOURCE"

# ---------------------------------------------------------------------------
# Token type (a 4-tuple per handoff Section 2)
# ---------------------------------------------------------------------------

Token = tuple[str, str, str, str]
"""(event_type, operation_class, resource_class, privilege_class)"""

Context = tuple[Token, ...]
"""Immutable sequence of preceding tokens used as Markov context."""


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

# operation_class: one of the 8 values from the handoff definition.
VALID_OPERATION_CLASSES: frozenset[str] = frozenset({
    "exec", "read", "write", "connect", "accept",
    "credential_change", "namespace_change", "module_change",
})

# privilege_class: one of 3 values.
VALID_PRIVILEGE_CLASSES: frozenset[str] = frozenset({
    "unprivileged", "elevated", "unknown",
})


def tau(
    event_type: str,
    operation_class: str,
    resource_class: str,
    privilege_class: str,
) -> Token:
    """Deterministic tokenization function tau(e) from handoff Section 2.

    Normalizes each field to the finite alphabet. Unknown values map to
    UNK_TOKEN (event_type) or OTHER_RESOURCE_TOKEN (resource_class) or
    "unknown" (privilege_class). operation_class unknown → "exec" as
    the most conservative fallback; this is documented behavior, not
    silent normalization.

    Args:
        event_type: Raw event type string from the eBPF event.
        operation_class: One of VALID_OPERATION_CLASSES or unmapped.
        resource_class: Normalized resource class; OTHER_RESOURCE if unknown.
        privilege_class: One of VALID_PRIVILEGE_CLASSES or "unknown".

    Returns:
        A 4-tuple Token for inclusion in a training sequence.
    """
    op   = operation_class if operation_class in VALID_OPERATION_CLASSES else "exec"
    res  = resource_class if resource_class else OTHER_RESOURCE_TOKEN
    priv = privilege_class if privilege_class in VALID_PRIVILEGE_CLASSES else "unknown"
    return (event_type, op, res, priv)


# ---------------------------------------------------------------------------
# Sparse count maps
# ---------------------------------------------------------------------------

# CountMap: context (tuple of tokens) → token → count
CountMap = dict[Context, dict[Token, int]]


def _build_count_map(sequences: list[list[Token]], order: int) -> CountMap:
    """Build sparse count maps for a given Markov order.

    For each position i in each sequence, the context is the suffix of
    the preceding tokens of length min(order, i). The count map stores
    the number of times each (context, token) pair is observed.

    Args:
        sequences: List of tokenized event sequences.
        order: The Markov order k.

    Returns:
        Sparse CountMap mapping (context, token) → count.
    """
    counts: CountMap = defaultdict(lambda: defaultdict(int))
    for seq in sequences:
        for i, token in enumerate(seq):
            context_len = min(order, i)
            context = tuple(seq[i - context_len: i])
            counts[context][token] += 1
    return {ctx: dict(tok_counts) for ctx, tok_counts in counts.items()}


def _log_likelihood(count_map: CountMap, m: int) -> float:
    """Compute log-likelihood for a count map under Laplace smoothing.

    Per handoff Eq. (log L_k):
      log L_k = sum_{h,x} n(h,x) * log( (n(h,x)+1) / (n(h)+m) )

    Args:
        count_map: Sparse count map for order k.
        m: Alphabet size |Sigma|.

    Returns:
        The log-likelihood (negative value; closer to 0 is better).
    """
    ll = 0.0
    for tok_counts in count_map.values():
        n_h = sum(tok_counts.values())
        for n_hx in tok_counts.values():
            if n_hx > 0:
                prob = (n_hx + 1) / (n_h + m)
                ll  += n_hx * math.log(prob)
    return ll


def _parameter_count(count_map: CountMap, m: int) -> int:
    """Count the number of free transition parameters.

    Per handoff: q_k = sum_{h in H_k} (m - 1).

    Args:
        count_map: Sparse count map for order k.
        m: Alphabet size |Sigma|.

    Returns:
        The number of free parameters.
    """
    return len(count_map) * (m - 1)


def _bic(count_map: CountMap, m: int, N: int) -> float:
    """Compute the BIC score for a given order.

    Per handoff: BIC(k) = -2 * log L_k + q_k * log(N).

    Args:
        count_map: Sparse count map for order k.
        m: Alphabet size |Sigma|.
        N: Total training token count.

    Returns:
        The BIC score (lower is better).
    """
    if N <= 0:
        return float("inf")
    ll = _log_likelihood(count_map, m)
    q  = _parameter_count(count_map, m)
    return -2 * ll + q * math.log(max(1, N))


def _local_bic(tok_counts: dict[Token, int], m: int) -> float:
    """Compute LocalBIC for one context's count map.

    Per handoff:
      LocalBIC(h) = -2 * sum_x n(h,x) * log P(x|h) + (m-1) * log(max(1, n(h)))
    where P(x|h) = (n(h,x)+1) / (n(h)+m).

    Args:
        tok_counts: Dict of token → count for context h.
        m: Alphabet size.

    Returns:
        The local BIC score for context h.
    """
    n_h = sum(tok_counts.values())
    denom = n_h + m
    ll_part = 0.0
    for n_hx in tok_counts.values():
        if n_hx > 0:
            ll_part += n_hx * math.log((n_hx + 1) / denom)
    return -2 * ll_part + (m - 1) * math.log(max(1, n_h))


def _suffix(context: Context) -> Context:
    """Return the immediate suffix of a context (drop the first token).

    Args:
        context: An immutable context tuple.

    Returns:
        The context with its first element removed; empty tuple for len-1.
    """
    return context[1:]


# ---------------------------------------------------------------------------
# Trained model dataclass
# ---------------------------------------------------------------------------


@dataclass
class MarkovModel:
    """A trained variable-order Markov model (PHANTOM behavioral contract model).

    Attributes:
        sigma: The finite token alphabet (including UNK and OTHER_RESOURCE).
        k_star: Selected Markov order (0..K_max).
        retained_contexts: Set of contexts retained after BIC pruning.
        transition: Mapping context → token → probability (Laplace-smoothed).
        epsilon: Mapping context → minimum probability (1 / (n(h) + m)).
        bic_score: BIC score of the selected model.
        N: Total training token count.
        m: Alphabet size |Sigma|.
        training_sequences_count: Number of sequences used for training.
    """

    sigma: frozenset[Token]
    k_star: int
    retained_contexts: frozenset[Context]
    transition: dict[Context, dict[Token, float]]
    epsilon: dict[Context, float]
    bic_score: float
    N: int
    m: int
    training_sequences_count: int

    def predict(self, context: Context, token: Token) -> float:
        """Return P(token | context) using the longest retained suffix.

        Args:
            context: The context tuple preceding the token.
            token: The token to score.

        Returns:
            The Laplace-smoothed conditional probability.
        """
        # Walk back to the longest retained suffix.
        effective = self._effective_context(context)
        probs = self.transition.get(effective)
        if probs is None:
            # Empty context fallback.
            empty_probs = self.transition.get(())
            if empty_probs and token in empty_probs:
                return empty_probs[token]
            eps = self.epsilon.get((), 1.0 / (1 + self.m))
            return eps

        if token in probs:
            return probs[token]
        # Token not seen after this context: return epsilon.
        return self.epsilon.get(effective, 1.0 / (1 + self.m))

    def _effective_context(self, context: Context) -> Context:
        """Find the longest retained suffix of the given context.

        Args:
            context: The full preceding context tuple.

        Returns:
            The longest suffix that is in retained_contexts.
        """
        ctx = context[-self.k_star:] if self.k_star > 0 else ()
        while ctx and ctx not in self.retained_contexts:
            ctx = _suffix(ctx)
        return ctx

    def is_novel_token(self, token: Token) -> bool:
        """Return True if the token was not seen during training (maps to UNK).

        Args:
            token: The token to check.

        Returns:
            True if the token is not in the training alphabet.
        """
        return token not in self.sigma


# ---------------------------------------------------------------------------
# Training function (Algorithm 1)
# ---------------------------------------------------------------------------


def train(
    sequences: list[list[Token]],
    k_max: int = 5,
    order: int | None = None,
    minimum_training_tokens: int = 100,
) -> MarkovModel:
    """Train a variable-order Markov model (Algorithm 1 from handoff).

    Args:
        sequences: List of tokenized event sequences (each a list of Tokens).
        k_max: Maximum candidate Markov order.
        order: If not None, fix the order rather than using BIC selection.
        minimum_training_tokens: Threshold N below which a model is considered
            to have insufficient evidence (logged but not raised).

    Returns:
        A trained MarkovModel.

    Raises:
        ValueError: If sequences is empty (no training data at all).
    """
    if not sequences:
        raise ValueError("No training sequences provided")

    # --- Step 1: Build alphabet Sigma ---
    all_tokens: set[Token] = set()
    for seq in sequences:
        all_tokens.update(seq)
    # Always include reserved tokens.
    unk_token_4  = (UNK_TOKEN, UNK_TOKEN, UNK_TOKEN, UNK_TOKEN)
    other_token_4 = (
        OTHER_RESOURCE_TOKEN, OTHER_RESOURCE_TOKEN,
        OTHER_RESOURCE_TOKEN, OTHER_RESOURCE_TOKEN,
    )
    all_tokens.add(unk_token_4)
    all_tokens.add(other_token_4)
    sigma = frozenset(all_tokens)
    m     = len(sigma)
    sigma_list = list(sigma)  # For stable ordering in transitions.

    # N: total token count.
    N = sum(len(s) for s in sequences)

    # K_limit: bounded by data length.
    max_seq_len = max((len(s) for s in sequences), default=0)
    k_limit = min(k_max, max_seq_len - 1) if max_seq_len > 1 else 0

    # --- Step 2: Candidate orders ---
    if order is not None:
        candidates = [min(max(0, order), k_limit)]
    else:
        candidates = list(range(k_limit + 1))

    # --- Step 3: Build count maps and compute BIC for each order ---
    count_maps: dict[int, CountMap] = {}
    bic_scores: dict[int, float]   = {}

    for k in candidates:
        cm          = _build_count_map(sequences, k)
        count_maps[k] = cm
        bic_scores[k] = _bic(cm, m, N)

    # --- Step 4: Select k* = argmin BIC ---
    k_star = min(candidates, key=lambda k: bic_scores[k])
    best_bic = bic_scores[k_star]

    # --- Step 5: Variable-order pruning ---
    # Retain context h iff LocalBIC(h) < LocalBIC(suffix(h)).
    # Process contexts in increasing length order.
    best_cm = dict(count_maps[k_star])
    if 0 in count_maps and () in count_maps[0]:
        best_cm[()] = count_maps[0][()]
    else:
        best_cm[()] = _build_count_map(sequences, 0).get((), {})
    retained: set[Context] = {()}  # Empty context is always retained.

    # Sort contexts by length ascending.
    all_contexts = sorted(best_cm.keys(), key=len)
    for ctx in all_contexts:
        if len(ctx) == 0:
            continue
        parent = _suffix(ctx)
        # Get count map for h.
        tok_counts_h = best_cm.get(ctx, {})
        # Get effective count map for parent (using retained chain).
        effective_parent = parent
        while effective_parent and effective_parent not in retained:
            effective_parent = _suffix(effective_parent)
        tok_counts_parent = best_cm.get(effective_parent, {})

        local_bic_h      = _local_bic(tok_counts_h, m)
        local_bic_parent = _local_bic(tok_counts_parent, m) if tok_counts_parent else float("inf")

        if local_bic_h < local_bic_parent:
            retained.add(ctx)

    retained_contexts = frozenset(retained)

    # --- Step 6: Compute Laplace-smoothed transition probabilities ---
    transition: dict[Context, dict[Token, float]] = {}
    epsilon:    dict[Context, float]              = {}

    for ctx in retained_contexts:
        tok_counts = best_cm.get(ctx, {})
        n_h        = sum(tok_counts.values())
        denom      = n_h + m
        probs: dict[Token, float] = {}
        for tok in sigma_list:
            n_hx        = tok_counts.get(tok, 0)
            probs[tok]  = (n_hx + 1) / denom
        transition[ctx] = probs
        epsilon[ctx]    = 1.0 / denom

    return MarkovModel(
        sigma=sigma,
        k_star=k_star,
        retained_contexts=retained_contexts,
        transition=transition,
        epsilon=epsilon,
        bic_score=best_bic,
        N=N,
        m=m,
        training_sequences_count=len(sequences),
    )
