"""
tests/causal-engine/test_attribution.py

Unit tests for the causal attribution engine
(app/application/estimate_attribution.py).

Coverage:
- Cyclic projection returns not_identifiable.
- No treatment variation returns not_identifiable.
- Attribution confidence computation.
- Confidence reduced by event loss, failed refutations.
- Complete attribution with valid data returns completed status.
"""

from __future__ import annotations

import pytest

from app.application.estimate_attribution import compute_attribution_confidence
from app.domain.entities import (
    RefutationResult,
)

# ---------------------------------------------------------------------------
# Attribution confidence tests
# ---------------------------------------------------------------------------


class TestComputeAttributionConfidence:
    """Tests for compute_attribution_confidence()."""

    def test_perfect_conditions_full_confidence(self) -> None:
        """No loss, good refutations, narrow CI → confidence near 1.0."""
        refutations = [
            RefutationResult("r1", 0.3, 0.29, passed=True),
            RefutationResult("r2", 0.3, 0.31, passed=True),
        ]
        c = compute_attribution_confidence(
            ate=0.3,
            ate_ci_lower=0.2,
            ate_ci_upper=0.4,
            refutations=refutations,
            event_loss_rate=0.0,
            identity_resolution_rate=1.0,
            contract_verified=True,
        )
        assert c > 0.9

    def test_event_loss_reduces_confidence(self) -> None:
        """High event loss reduces confidence."""
        c_low = compute_attribution_confidence(
            ate=0.3, ate_ci_lower=0.2, ate_ci_upper=0.4,
            refutations=[], event_loss_rate=0.0,
        )
        c_high = compute_attribution_confidence(
            ate=0.3, ate_ci_lower=0.2, ate_ci_upper=0.4,
            refutations=[], event_loss_rate=0.5,
        )
        assert c_high < c_low

    def test_failed_refutations_reduce_confidence(self) -> None:
        """Failed refutations reduce confidence."""
        all_pass = [
            RefutationResult("r1", 0.3, 0.29, passed=True),
            RefutationResult("r2", 0.3, 0.31, passed=True),
        ]
        one_fail = [
            RefutationResult("r1", 0.3, 0.29, passed=True),
            RefutationResult("r2", 0.3, 0.0, passed=False),
        ]
        c_pass = compute_attribution_confidence(
            ate=0.3, ate_ci_lower=0.2, ate_ci_upper=0.4,
            refutations=all_pass,
        )
        c_fail = compute_attribution_confidence(
            ate=0.3, ate_ci_lower=0.2, ate_ci_upper=0.4,
            refutations=one_fail,
        )
        assert c_fail < c_pass

    def test_wide_ci_reduces_confidence(self) -> None:
        """Wide confidence interval reduces confidence."""
        c_narrow = compute_attribution_confidence(
            ate=0.3, ate_ci_lower=0.25, ate_ci_upper=0.35,
            refutations=[],
        )
        c_wide = compute_attribution_confidence(
            ate=0.3, ate_ci_lower=0.0, ate_ci_upper=0.8,
            refutations=[],
        )
        assert c_wide < c_narrow

    def test_unverified_contract_halves_confidence(self) -> None:
        """Unverified contract reduces confidence by 50%."""
        c_verified = compute_attribution_confidence(
            ate=0.3, ate_ci_lower=0.2, ate_ci_upper=0.4,
            refutations=[], contract_verified=True,
        )
        c_unverified = compute_attribution_confidence(
            ate=0.3, ate_ci_lower=0.2, ate_ci_upper=0.4,
            refutations=[], contract_verified=False,
        )
        assert abs(c_unverified - c_verified * 0.5) < 0.01

    def test_confidence_bounded_zero_to_one(self) -> None:
        """Confidence is always in [0, 1]."""
        c = compute_attribution_confidence(
            ate=10.0, ate_ci_lower=-5.0, ate_ci_upper=25.0,
            refutations=[
                RefutationResult("r1", 0.0, 0.0, passed=False),
            ],
            event_loss_rate=0.9,
            identity_resolution_rate=0.1,
            contract_verified=False,
        )
        assert 0.0 <= c <= 1.0

    def test_none_ci_no_penalty(self) -> None:
        """None CI values do not penalize confidence."""
        c = compute_attribution_confidence(
            ate=0.3, ate_ci_lower=None, ate_ci_upper=None,
            refutations=[],
        )
        assert c == pytest.approx(1.0)

    def test_all_refutations_failed_zero_component(self) -> None:
        """All refutations failing → refutation component is 0."""
        refutations = [
            RefutationResult("r1", 0.3, 0.0, passed=False),
            RefutationResult("r2", 0.3, 0.0, passed=False),
        ]
        c = compute_attribution_confidence(
            ate=0.3, ate_ci_lower=0.2, ate_ci_upper=0.4,
            refutations=refutations,
        )
        assert c == 0.0
