"""
services/ebpf-agent/domain/drift/kl_scorer.py

KL-divergence drift scorer for PHANTOM behavioral contracts.

Implements the KL-divergence calculation from the handoff (Task 3, Section 4)
exactly as specified:

    KL(P_obs || P_contract) = sum_{x} P_obs(x) * log(P_obs(x) / P_contract(x))

with Laplace smoothing applied to P_contract to guarantee P_contract(x) > 0
for all x in the observation set (no division by zero).

Epsilon derivation (handoff Section 4.2):
    epsilon(h) = 1 / (n(h) + |Sigma|)

where n(h) is the count of observations of context h in the training corpus
and |Sigma| is the alphabet size. This is precisely the Laplace-smoothed
probability assigned to unseen tokens, making epsilon the minimum non-zero
probability in the model. It ensures P_contract(x|h) > 0 for all x in Sigma,
which is required for the KL divergence to be finite.

The score returned is a dimensionless float; values near 0.0 indicate
behavior close to the model, positive values indicate drift.

Design:
- No external library dependency (no scipy); KL is computed from primitives.
- All arithmetic is in log-space for numerical stability.
- The per-context KL is decomposed for diagnostics (used in confidence scoring).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from domain.markov.chain import Context, MarkovModel, Token

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ContextKlResult:
    """KL divergence result for one context.

    Attributes:
        context: The Markov context (h) for which KL was computed.
        kl_divergence: D_KL(P_obs(·|h) || P_contract(·|h)).
        obs_count: Total observations for this context in the test sequence.
        tokens_observed: Number of distinct tokens observed after this context.
        novel_tokens: Number of tokens not in the training alphabet (→ UNK).
    """

    context: Context
    kl_divergence: float
    obs_count: int
    tokens_observed: int
    novel_tokens: int


@dataclass
class KlScoreResult:
    """Aggregate KL-divergence drift score.

    Attributes:
        total_kl: Aggregate KL divergence (weighted sum over all contexts).
        per_context: Per-context KL breakdown for diagnostics.
        observation_count: Total tokens in the observed sequence.
        contexts_evaluated: Number of distinct contexts evaluated.
        novel_token_fraction: Fraction of observed tokens not in training alphabet.
        loss_observed: True if event loss was reported in the observation window.
        loss_penalty: Multiplier applied to final KL when loss_observed is True.
        final_score: total_kl * loss_penalty (the reported drift score).
    """

    total_kl: float
    per_context: list[ContextKlResult] = field(default_factory=list)
    observation_count: int = 0
    contexts_evaluated: int = 0
    novel_token_fraction: float = 0.0
    loss_observed: bool = False
    loss_penalty: float = 1.0
    final_score: float = 0.0


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------


class KlDriftScorer:
    """Computes KL-divergence drift score between observed token sequence
    and a trained MarkovModel.

    Args:
        model: The trained MarkovModel representing the behavioral contract.
        loss_penalty_factor: Multiplier to apply to the KL score when event
            loss is reported. Per the handoff, loss makes the evidence less
            trustworthy, so the drift score is scaled up to reflect higher
            uncertainty. Must be >= 1.0.
    """

    def __init__(
        self,
        model: MarkovModel,
        loss_penalty_factor: float = 1.5,
    ) -> None:
        """Initialise the drift scorer.

        Args:
            model: The MarkovModel behavioral contract.
            loss_penalty_factor: Score multiplier when event loss is observed.
        """
        if loss_penalty_factor < 1.0:
            raise ValueError(
                f"loss_penalty_factor must be >= 1.0, got {loss_penalty_factor}"
            )
        self._model = model
        self._loss_penalty = loss_penalty_factor

    def score(
        self,
        observed_sequence: list[Token],
        loss_observed: bool = False,
    ) -> KlScoreResult:
        """Compute the KL-divergence drift score for an observed token sequence.

        Algorithm:
        1. Build empirical distribution P_obs(x|h) from observed_sequence
           using the same context extraction as the MarkovModel.
        2. For each observed context h:
             KL(h) = sum_x P_obs(x|h) * log( P_obs(x|h) / P_contract(x|h) )
           where P_contract(x|h) uses the model's epsilon for unseen tokens.
        3. Aggregate: total_KL = sum_h P(h) * KL(h)
           where P(h) = obs_count(h) / N.
        4. Apply loss penalty.

        Args:
            observed_sequence: List of Tokens from the runtime observation window.
            loss_observed: True if ring-buffer or transport loss was reported
                in this window (applies loss_penalty_factor to the final score).

        Returns:
            A KlScoreResult with total KL, per-context breakdown, and final score.
        """
        if not observed_sequence:
            return KlScoreResult(
                total_kl=0.0,
                observation_count=0,
                contexts_evaluated=0,
                novel_token_fraction=0.0,
                loss_observed=loss_observed,
                loss_penalty=self._loss_penalty if loss_observed else 1.0,
                final_score=0.0,
            )

        N = len(observed_sequence)
        k_star = self._model.k_star

        # --- Step 1: Build per-context observation counts ---
        # obs_counts: context → token → count
        obs_counts: dict[Context, dict[Token, int]] = {}
        novel_count = 0

        for i, token in enumerate(observed_sequence):
            context_len = min(k_star, i)
            raw_context = tuple(observed_sequence[i - context_len: i])
            # Use the model's effective context (longest retained suffix).
            context = self._model._effective_context(raw_context)

            if token not in self._model.sigma:
                novel_count += 1
            # Always record the observation; novel tokens still count against
            # the distribution as UNK.

            if context not in obs_counts:
                obs_counts[context] = {}
            obs_counts[context][token] = obs_counts[context].get(token, 0) + 1

        novel_fraction = novel_count / N if N > 0 else 0.0

        # --- Step 2: Compute per-context KL ---
        per_context_results: list[ContextKlResult] = []
        total_kl = 0.0

        for context, tok_counts in obs_counts.items():
            n_h = sum(tok_counts.values())

            kl_h = 0.0
            for token, n_hx in tok_counts.items():
                p_obs = n_hx / n_h  # Empirical probability.

                # P_contract: get from model; use epsilon for unseen tokens.
                p_contract = self._model.predict(context, token)

                # Guard against degenerate values (should not occur after
                # epsilon guarantee, but defensive).
                if p_contract <= 0.0:
                    p_contract = self._model.epsilon.get(context, 1e-10)
                if p_obs > 0.0:
                    kl_h += p_obs * math.log(p_obs / p_contract)

            # Weight by fraction of total observations for this context.
            weight = n_h / N
            total_kl += weight * kl_h

            per_context_results.append(ContextKlResult(
                context=context,
                kl_divergence=kl_h,
                obs_count=n_h,
                tokens_observed=len(tok_counts),
                novel_tokens=sum(
                    1 for t in tok_counts if t not in self._model.sigma
                ),
            ))

        # --- Step 3: Loss penalty ---
        penalty = self._loss_penalty if loss_observed else 1.0
        final_score = total_kl * penalty

        return KlScoreResult(
            total_kl=total_kl,
            per_context=per_context_results,
            observation_count=N,
            contexts_evaluated=len(obs_counts),
            novel_token_fraction=novel_fraction,
            loss_observed=loss_observed,
            loss_penalty=penalty,
            final_score=final_score,
        )

    def epsilon_for_context(self, context: Context) -> float:
        """Return the minimum non-zero probability for a context.

        This is the Laplace-smoothed probability epsilon(h) = 1 / (n(h) + |Sigma|)
        from the training corpus. Used by consumers to set detection thresholds.

        Args:
            context: The Markov context h.

        Returns:
            epsilon(h) as a float in (0, 1).
        """
        effective = self._model._effective_context(context)
        return self._model.epsilon.get(effective, 1.0 / (1 + self._model.m))
