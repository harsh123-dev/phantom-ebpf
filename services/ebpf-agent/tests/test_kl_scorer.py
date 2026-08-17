"""
tests/ebpf-agent/test_kl_scorer.py

Unit tests for the KL-divergence drift scorer (domain/drift/kl_scorer.py).

Coverage:
- Score of 0.0 for sequence identical to training distribution.
- Score increases monotonically as drift increases.
- Novel tokens contribute positively to the score.
- Loss penalty multiplies the final score correctly.
- Per-context breakdown accounts for all observed tokens.
- epsilon_for_context() returns finite positive values.
"""

from __future__ import annotations

import pytest

from domain.drift.kl_scorer import KlDriftScorer
from domain.markov.chain import MarkovModel, Token, tau, train

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_repeated_sequence(length: int = 200) -> list[Token]:
    """Build a deterministic repeating sequence for controlled tests."""
    pattern = [
        tau("exec",        "exec",    "/usr/bin/python3", "unprivileged"),
        tau("file_open",   "read",    "/etc/hosts",       "unprivileged"),
        tau("net_connect", "connect", "8.8.8.8:443",      "unprivileged"),
    ]
    return (pattern * (length // len(pattern) + 1))[:length]


@pytest.fixture()
def trained_model() -> MarkovModel:
    """A MarkovModel trained on a highly structured sequence."""
    seq = _make_repeated_sequence(300)
    return train([seq], k_max=3)


@pytest.fixture()
def scorer(trained_model: MarkovModel) -> KlDriftScorer:
    """A KlDriftScorer using the trained model with default penalty."""
    return KlDriftScorer(trained_model, loss_penalty_factor=2.0)


# ---------------------------------------------------------------------------
# Zero drift
# ---------------------------------------------------------------------------


class TestZeroDrift:
    """Tests that identical-distribution sequences produce near-zero KL."""

    def test_same_distribution_near_zero(
        self, scorer: KlDriftScorer, trained_model: MarkovModel
    ) -> None:
        """Observed sequence drawn from same pattern → KL ≈ 0."""
        obs = _make_repeated_sequence(100)
        result = scorer.score(obs, loss_observed=False)
        # Perfect match should yield very small KL (not necessarily exactly 0
        # due to Laplace smoothing, but << 1).
        assert result.final_score < 0.5, (
            f"Expected near-zero KL for identical distribution, got {result.final_score}"
        )

    def test_empty_sequence_returns_zero(self, scorer: KlDriftScorer) -> None:
        """Empty observation sequence returns KL = 0."""
        result = scorer.score([], loss_observed=False)
        assert result.total_kl == 0.0
        assert result.final_score == 0.0
        assert result.observation_count == 0


# ---------------------------------------------------------------------------
# Drift increases with novelty
# ---------------------------------------------------------------------------


class TestDriftIncrease:
    """Tests that introduced drift raises the KL score."""

    def test_novel_tokens_increase_score(
        self, scorer: KlDriftScorer, trained_model: MarkovModel
    ) -> None:
        """Inserting novel tokens increases the drift score."""
        # Baseline: pure in-distribution sequence.
        baseline_seq = _make_repeated_sequence(50)
        baseline = scorer.score(baseline_seq, loss_observed=False)

        # Drifted: inject novel tokens.
        novel = tau("module_load", "module_change", "/kernel/evil.ko", "elevated")
        drifted_seq = baseline_seq[:40] + [novel] * 10
        drifted = scorer.score(drifted_seq, loss_observed=False)

        assert drifted.final_score > baseline.final_score, (
            f"Drifted score {drifted.final_score} should exceed "
            f"baseline {baseline.final_score}"
        )

    def test_monotone_increase_with_more_novel_tokens(
        self, scorer: KlDriftScorer
    ) -> None:
        """More novel tokens → higher KL score (monotone property)."""
        base_seq = _make_repeated_sequence(30)
        novel = tau("module_load", "module_change", "/kernel/evil.ko", "elevated")

        scores = []
        for n_novel in [0, 5, 10, 20]:
            obs = base_seq + [novel] * n_novel
            result = scorer.score(obs, loss_observed=False)
            scores.append(result.final_score)

        # Scores should be non-decreasing.
        for i in range(1, len(scores)):
            assert scores[i] >= scores[i - 1] - 1e-9, (
                f"Score not monotone: {scores}"
            )


# ---------------------------------------------------------------------------
# Loss penalty
# ---------------------------------------------------------------------------


class TestLossPenalty:
    """Tests for the event-loss penalty multiplier."""

    def test_loss_multiplies_score(
        self, scorer: KlDriftScorer
    ) -> None:
        """loss_observed=True multiplies the final score by loss_penalty_factor."""
        obs = _make_repeated_sequence(50)
        no_loss = scorer.score(obs, loss_observed=False)
        with_loss = scorer.score(obs, loss_observed=True)

        if no_loss.total_kl > 0:
            ratio = with_loss.final_score / no_loss.final_score
            assert abs(ratio - 2.0) < 1e-9, (
                f"Expected 2x loss penalty, got ratio={ratio}"
            )

    def test_loss_flag_reflected_in_result(
        self, scorer: KlDriftScorer
    ) -> None:
        """loss_observed field is faithfully reflected in the result."""
        obs = _make_repeated_sequence(10)
        r = scorer.score(obs, loss_observed=True)
        assert r.loss_observed is True
        assert r.loss_penalty == 2.0

    def test_invalid_penalty_raises(self, trained_model: MarkovModel) -> None:
        """loss_penalty_factor < 1.0 raises ValueError."""
        with pytest.raises(ValueError, match="loss_penalty_factor"):
            KlDriftScorer(trained_model, loss_penalty_factor=0.5)


# ---------------------------------------------------------------------------
# Novel token fraction
# ---------------------------------------------------------------------------


class TestNovelTokenFraction:
    """Tests for novel_token_fraction tracking."""

    def test_no_novel_tokens_zero_fraction(
        self, scorer: KlDriftScorer
    ) -> None:
        """In-distribution sequence has zero novel token fraction."""
        obs = _make_repeated_sequence(50)
        result = scorer.score(obs, loss_observed=False)
        assert result.novel_token_fraction == 0.0

    def test_all_novel_tokens_fraction_one(
        self, scorer: KlDriftScorer
    ) -> None:
        """Sequence of all-novel tokens has fraction = 1.0."""
        novel = [
            tau("module_load", "module_change", f"/kernel/mod_{i}.ko", "elevated")
            for i in range(20)
        ]
        result = scorer.score(novel, loss_observed=False)
        assert result.novel_token_fraction == 1.0


# ---------------------------------------------------------------------------
# Per-context breakdown
# ---------------------------------------------------------------------------


class TestPerContextBreakdown:
    """Tests for per-context KL breakdown."""

    def test_per_context_kl_non_negative(
        self, scorer: KlDriftScorer
    ) -> None:
        """KL divergence for each context is non-negative (Gibbs' inequality)."""
        obs = _make_repeated_sequence(60)
        novel = tau("module_load", "module_change", "/evil.ko", "elevated")
        obs = obs + [novel] * 5
        result = scorer.score(obs, loss_observed=False)
        for ctx_result in result.per_context:
            assert ctx_result.kl_divergence >= -1e-12, (
                f"Negative KL for context {ctx_result.context}: "
                f"{ctx_result.kl_divergence}"
            )

    def test_per_context_obs_counts_sum_to_N(
        self, scorer: KlDriftScorer
    ) -> None:
        """Sum of per-context obs_count equals total observation_count."""
        obs = _make_repeated_sequence(50)
        result = scorer.score(obs, loss_observed=False)
        total_obs = sum(r.obs_count for r in result.per_context)
        assert total_obs == result.observation_count


# ---------------------------------------------------------------------------
# epsilon_for_context
# ---------------------------------------------------------------------------


class TestEpsilonForContext:
    """Tests for KlDriftScorer.epsilon_for_context()."""

    def test_epsilon_positive(
        self, scorer: KlDriftScorer
    ) -> None:
        """Epsilon for any context is strictly positive."""
        eps = scorer.epsilon_for_context(())
        assert eps > 0.0

    def test_epsilon_less_than_one(
        self, scorer: KlDriftScorer
    ) -> None:
        """Epsilon is a valid probability (< 1)."""
        eps = scorer.epsilon_for_context(())
        assert eps < 1.0

    def test_epsilon_formula(
        self, scorer: KlDriftScorer, trained_model: MarkovModel
    ) -> None:
        """Epsilon for empty context equals 1 / (N + m) within precision."""
        eps = scorer.epsilon_for_context(())
        expected = trained_model.epsilon.get((), 1.0 / (1 + trained_model.m))
        assert abs(eps - expected) < 1e-12
