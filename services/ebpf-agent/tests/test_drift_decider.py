"""
tests/test_drift_decider.py

Comprehensive unit tests for the PHANTOM drift decision rule.

All data in this file is SYNTHETIC.  No real experimental results are
used or modified.  See conftest.py for shared Markov fixtures.

Test coverage (Tasks A–J from the Part 2 specification):
  A. Expected behavior       — in-distribution window → no_drift
  B. Changed behavior        — drifted window → higher score than baseline
  C. Unseen event            — novel token → novel_token_fraction > 0
  D. Insufficient window     — short/empty window → insufficient_evidence
  E. Missing identity        — unresolved PURL/digest → insufficient_evidence
  F. Missing telemetry       — loss flag, NaN timestamps
  G. Invalid contract        — corrupt / low-N contract
  H. Threshold boundary      — below, at, above threshold
  I. Baseline contamination  — attack windows blocked from calibration
  J. Determinism             — same inputs → same outputs
"""

from __future__ import annotations

import math
import copy
from datetime import datetime, timezone

import pytest

from domain.drift.calibrator import ThresholdCalibrator, _quantile
from domain.drift.config import DriftDetectorConfig
from domain.drift.decider import DriftDecider, DriftOutcome, DriftResult
from domain.drift.kl_scorer import KlDriftScorer
from domain.markov.chain import MarkovModel, Token, tau, train

# ---------------------------------------------------------------------------
# Synthetic sequence builders (clearly labelled — no real data)
# ---------------------------------------------------------------------------

_BENIGN_PATTERN: list[Token] = [
    tau("exec",        "exec",    "/usr/bin/python3",          "unprivileged"),
    tau("file_open",   "read",    "/etc/ssl/certs/ca.crt",     "unprivileged"),
    tau("net_connect", "connect", "8.8.8.8:443",               "unprivileged"),
    tau("file_open",   "read",    "/usr/lib/python3.11/abc.py","unprivileged"),
]

_ATTACK_TOKEN: Token = tau(
    "module_load", "module_change", "/kernel/evil.ko", "elevated"
)


def _benign_seq(n: int = 200) -> list[Token]:
    """SYNTHETIC repeating benign pattern of length n."""
    return (_BENIGN_PATTERN * (n // len(_BENIGN_PATTERN) + 1))[:n]


def _drifted_seq(n_benign: int = 150, n_attack: int = 50) -> list[Token]:
    """SYNTHETIC mixed sequence with novel attack tokens appended."""
    return _benign_seq(n_benign) + [_ATTACK_TOKEN] * n_attack


@pytest.fixture()
def trained_model() -> MarkovModel:
    """SYNTHETIC: MarkovModel trained solely on benign data."""
    return train([_benign_seq(400)], k_max=3)


@pytest.fixture()
def cfg_uncalibrated() -> DriftDetectorConfig:
    """Config with uncalibrated (infinite) threshold."""
    return DriftDetectorConfig()


@pytest.fixture()
def cfg_calibrated() -> DriftDetectorConfig:
    """Config with a finite threshold set to a known value for boundary tests."""
    cfg = DriftDetectorConfig(
        threshold=0.3,
        threshold_version="synthetic-boundary-test",
        min_observation_tokens=20,
        min_training_tokens=10,   # relaxed for small synthetic model
    )
    return cfg


@pytest.fixture()
def decider_uncalibrated(trained_model, cfg_uncalibrated) -> DriftDecider:
    """DriftDecider with uncalibrated threshold and resolved identity."""
    return DriftDecider(
        model=trained_model,
        config=cfg_uncalibrated,
        contract_id="test-contract-001",
        image_digest="sha256:abc123",
        purl="pkg:pypi/lzmaffi@1.0.0",
    )


@pytest.fixture()
def decider_calibrated(trained_model, cfg_calibrated) -> DriftDecider:
    """DriftDecider with calibrated finite threshold."""
    return DriftDecider(
        model=trained_model,
        config=cfg_calibrated,
        contract_id="test-contract-001",
        image_digest="sha256:abc123",
        purl="pkg:pypi/lzmaffi@1.0.0",
    )


# ===========================================================================
# Test A: Expected behavior → no_drift (or uncalibrated no_drift)
# ===========================================================================


class TestA_ExpectedBehavior:
    """SYNTHETIC: In-distribution window should not trigger drift."""

    def test_in_distribution_outcome_no_drift(self, decider_calibrated) -> None:
        """A window identical to training distribution produces no_drift."""
        result = decider_calibrated.decide(_benign_seq(100))
        assert result.outcome != DriftOutcome.DRIFT, (
            f"Expected no_drift for in-distribution window, got {result.outcome}; "
            f"score={result.adjusted_score:.4f}, threshold={result.threshold}"
        )
        assert result.outcome == DriftOutcome.NO_DRIFT

    def test_in_distribution_score_small(self, decider_calibrated) -> None:
        """In-distribution window has a small adjusted score."""
        result = decider_calibrated.decide(_benign_seq(100))
        assert math.isfinite(result.final_score)
        assert result.final_score < result.threshold, (
            f"In-distribution final_score {result.final_score:.4f} "
            f"should be below threshold {result.threshold}"
        )

    def test_uncalibrated_returns_no_drift_with_flag(
        self, decider_uncalibrated
    ) -> None:
        """Uncalibrated decider always returns no_drift with 'threshold_uncalibrated' flag."""
        result = decider_uncalibrated.decide(_benign_seq(100))
        assert result.outcome == DriftOutcome.NO_DRIFT
        assert "threshold_uncalibrated" in result.missing_data_flags

    def test_provenance_fields_populated(self, decider_calibrated) -> None:
        """contract_id, image_digest, purl are all set in result."""
        result = decider_calibrated.decide(_benign_seq(100))
        assert result.contract_id == "test-contract-001"
        assert result.image_digest == "sha256:abc123"
        assert result.purl == "pkg:pypi/lzmaffi@1.0.0"
        assert result.contract_version == "v1"


# ===========================================================================
# Test B: Changed behavior → higher drift score
# ===========================================================================


class TestB_ChangedBehavior:
    """SYNTHETIC: Injecting attack tokens raises the drift score."""

    def test_drifted_score_higher_than_baseline(self, decider_calibrated) -> None:
        """A sequence with novel attack tokens produces a higher score."""
        benign_result = decider_calibrated.decide(_benign_seq(100))
        drifted_result = decider_calibrated.decide(_drifted_seq(100, 50))
        assert drifted_result.adjusted_score > benign_result.adjusted_score, (
            f"Drifted score {drifted_result.adjusted_score:.4f} should exceed "
            f"benign score {benign_result.adjusted_score:.4f}"
        )

    def test_drifted_triggers_drift_outcome(self, decider_calibrated) -> None:
        """A heavily drifted sequence triggers drift outcome."""
        # Use a sequence that is mostly attack tokens — should exceed threshold=0.3
        heavy_drift = [_ATTACK_TOKEN] * 100
        result = decider_calibrated.decide(heavy_drift)
        assert result.outcome == DriftOutcome.DRIFT, (
            f"Expected drift for heavy-drift sequence, got {result.outcome}; "
            f"score={result.adjusted_score:.4f}"
        )

    def test_score_monotone_with_attack_fraction(self, decider_calibrated) -> None:
        """Increasing attack-token fraction monotonically raises the score."""
        scores = []
        for n_attack in [0, 10, 30, 60, 100]:
            seq = _benign_seq(100) + [_ATTACK_TOKEN] * n_attack
            r = decider_calibrated.decide(seq)
            scores.append(r.adjusted_score)
        for i in range(1, len(scores)):
            assert scores[i] >= scores[i - 1] - 1e-9, (
                f"Score not monotone: {scores}"
            )


# ===========================================================================
# Test C: Unseen event → novel token fraction > 0
# ===========================================================================


class TestC_UnseenEvent:
    """SYNTHETIC: Tokens absent from training alphabet are tracked as novel."""

    def test_novel_token_fraction_positive(self, decider_calibrated) -> None:
        """Inserting a completely new token produces novel_token_fraction > 0."""
        truly_novel = tau("dns_lookup", "connect", "evil.example.com:53", "elevated")
        seq = _benign_seq(80) + [truly_novel] * 20
        result = decider_calibrated.decide(seq)
        assert result.novel_token_fraction > 0.0

    def test_novel_token_fraction_in_distribution_zero(self, decider_calibrated) -> None:
        """In-distribution window has novel_token_fraction == 0.0."""
        result = decider_calibrated.decide(_benign_seq(100))
        assert result.novel_token_fraction == 0.0

    def test_all_novel_fraction_one(self, decider_calibrated) -> None:
        """A window of only novel tokens has novel_token_fraction == 1.0."""
        novel_seq = [tau(f"novel_{i}", "exec", f"/novel_{i}", "elevated")
                     for i in range(30)]
        result = decider_calibrated.decide(novel_seq)
        assert result.novel_token_fraction == pytest.approx(1.0)

    def test_novel_tokens_reflected_in_explanation(self, decider_calibrated) -> None:
        """Explanation mentions novel tokens when novel_token_fraction > 0."""
        novel = tau("dns_lookup", "connect", "evil.example.com:53", "elevated")
        seq = _benign_seq(80) + [novel] * 20
        result = decider_calibrated.decide(seq)
        assert "novel" in result.explanation.lower()


# ===========================================================================
# Test D: Insufficient observation window
# ===========================================================================


class TestD_InsufficientObservationWindow:
    """SYNTHETIC: Short or empty windows must not produce confident decisions."""

    def test_empty_sequence_insufficient(self, decider_calibrated) -> None:
        """Empty observation sequence → insufficient_evidence."""
        result = decider_calibrated.decide([])
        assert result.outcome == DriftOutcome.INSUFFICIENT_EVIDENCE

    def test_empty_reason_populated(self, decider_calibrated) -> None:
        """insufficient_evidence_reason is non-empty for empty sequence."""
        result = decider_calibrated.decide([])
        assert len(result.insufficient_evidence_reason) > 0

    def test_below_min_tokens_insufficient(self) -> None:
        """Window with fewer than min_observation_tokens → insufficient_evidence."""
        cfg = DriftDetectorConfig(
            min_observation_tokens=50,
            min_training_tokens=10,
            threshold=0.3,
        )
        model = train([_benign_seq(400)], k_max=3)
        decider = DriftDecider(
            model=model, config=cfg,
            image_digest="sha256:abc", purl="pkg:pypi/x@1.0",
        )
        result = decider.decide(_benign_seq(10))   # 10 < 50
        assert result.outcome == DriftOutcome.INSUFFICIENT_EVIDENCE
        assert "observation_tokens" in " ".join(result.missing_data_flags)

    def test_exactly_min_tokens_not_insufficient(self) -> None:
        """Window with exactly min_observation_tokens is NOT insufficient."""
        cfg = DriftDetectorConfig(
            min_observation_tokens=20,
            min_training_tokens=10,
            threshold=1.0,   # large threshold so we get no_drift
        )
        model = train([_benign_seq(400)], k_max=3)
        decider = DriftDecider(
            model=model, config=cfg,
            image_digest="sha256:abc", purl="pkg:pypi/x@1.0",
        )
        result = decider.decide(_benign_seq(20))   # == min
        assert result.outcome != DriftOutcome.INSUFFICIENT_EVIDENCE
        assert result.observation_count == 20

    def test_insufficient_result_score_is_nan(self, decider_calibrated) -> None:
        """insufficient_evidence results carry NaN final_score (not 0.0)."""
        result = decider_calibrated.decide([])
        assert math.isnan(result.final_score)
        assert math.isnan(result.adjusted_score)


# ===========================================================================
# Test E: Missing or ambiguous component identity
# ===========================================================================


class TestE_MissingIdentity:
    """SYNTHETIC: Unresolved identity must be preserved, not fabricated."""

    def test_unresolved_digest_with_require_identity(self, trained_model) -> None:
        """UNRESOLVED image_digest + require_identity=True → insufficient_evidence."""
        cfg = DriftDetectorConfig(require_identity=True, threshold=0.3,
                                  min_training_tokens=10)
        decider = DriftDecider(
            model=trained_model, config=cfg,
            image_digest=DriftDetectorConfig.UNRESOLVED_IDENTITY,
            purl="pkg:pypi/x@1.0",
        )
        result = decider.decide(_benign_seq(100))
        assert result.outcome == DriftOutcome.INSUFFICIENT_EVIDENCE
        assert result.image_digest == DriftDetectorConfig.UNRESOLVED_IDENTITY

    def test_unresolved_purl_with_require_identity(self, trained_model) -> None:
        """UNRESOLVED purl + require_identity=True → insufficient_evidence."""
        cfg = DriftDetectorConfig(require_identity=True, threshold=0.3,
                                  min_training_tokens=10)
        decider = DriftDecider(
            model=trained_model, config=cfg,
            image_digest="sha256:abc123",
            purl=DriftDetectorConfig.UNRESOLVED_IDENTITY,
        )
        result = decider.decide(_benign_seq(100))
        assert result.outcome == DriftOutcome.INSUFFICIENT_EVIDENCE
        assert result.purl == DriftDetectorConfig.UNRESOLVED_IDENTITY

    def test_unresolved_identity_preserved_in_result(self, trained_model) -> None:
        """UNRESOLVED sentinel is preserved in the DriftResult, never replaced."""
        cfg = DriftDetectorConfig(require_identity=False, threshold=0.3,
                                  min_training_tokens=10)
        decider = DriftDecider(
            model=trained_model, config=cfg,
            image_digest=DriftDetectorConfig.UNRESOLVED_IDENTITY,
            purl=DriftDetectorConfig.UNRESOLVED_IDENTITY,
        )
        result = decider.decide(_benign_seq(100))
        # require_identity=False so decision may proceed
        assert result.image_digest == DriftDetectorConfig.UNRESOLVED_IDENTITY
        assert result.purl == DriftDetectorConfig.UNRESOLVED_IDENTITY
        # But the flags mention it
        assert "image_digest_unresolved" in result.missing_data_flags
        assert "purl_unresolved" in result.missing_data_flags

    def test_require_identity_false_still_scores(self, trained_model) -> None:
        """require_identity=False allows scoring with UNRESOLVED identity."""
        cfg = DriftDetectorConfig(require_identity=False, threshold=1.0,
                                  min_training_tokens=10)
        decider = DriftDecider(
            model=trained_model, config=cfg,
            image_digest=DriftDetectorConfig.UNRESOLVED_IDENTITY,
            purl=DriftDetectorConfig.UNRESOLVED_IDENTITY,
        )
        result = decider.decide(_benign_seq(100))
        assert result.outcome in (DriftOutcome.DRIFT, DriftOutcome.NO_DRIFT)


# ===========================================================================
# Test F: Missing telemetry (loss flag, missing timestamps)
# ===========================================================================


class TestF_MissingTelemetry:
    """SYNTHETIC: Loss flags and missing timestamps are handled correctly."""

    def test_loss_flag_reflected(self, decider_calibrated) -> None:
        """loss_observed=True is reflected in the DriftResult."""
        result = decider_calibrated.decide(_benign_seq(100), loss_observed=True)
        assert result.loss_observed is True
        assert result.loss_penalty > 1.0

    def test_loss_flag_raises_score(self, decider_calibrated) -> None:
        """Loss penalty multiplies the score above the no-loss value."""
        r_no_loss = decider_calibrated.decide(_benign_seq(100), loss_observed=False)
        r_loss    = decider_calibrated.decide(_benign_seq(100), loss_observed=True)
        if r_no_loss.final_score > 0:
            assert r_loss.final_score > r_no_loss.final_score

    def test_none_timestamps_accepted(self, decider_calibrated) -> None:
        """None observation timestamps are valid (window times are optional)."""
        result = decider_calibrated.decide(
            _benign_seq(100),
            observation_window_start=None,
            observation_window_end=None,
        )
        assert result.observation_window_start is None
        assert result.observation_window_end is None
        assert result.outcome in (DriftOutcome.DRIFT, DriftOutcome.NO_DRIFT)

    def test_explicit_timestamps_preserved(self, decider_calibrated) -> None:
        """Explicit timestamps are preserved in the DriftResult."""
        start = datetime(2000, 1, 1, tzinfo=timezone.utc)
        end   = datetime(2000, 1, 1, 0, 5, tzinfo=timezone.utc)
        result = decider_calibrated.decide(
            _benign_seq(100),
            observation_window_start=start,
            observation_window_end=end,
        )
        assert result.observation_window_start == start
        assert result.observation_window_end == end

    def test_loss_explanation_mentioned(self, decider_calibrated) -> None:
        """Explanation mentions loss penalty when loss is observed."""
        # Need non-zero KL to trigger the penalty branch in explanation
        seq = _drifted_seq(80, 40)
        result = decider_calibrated.decide(seq, loss_observed=True)
        assert "loss" in result.explanation.lower()


# ===========================================================================
# Test G: Invalid contract (low-N / corrupt model)
# ===========================================================================


class TestG_InvalidContract:
    """SYNTHETIC: Contracts with insufficient training data → insufficient_evidence."""

    def test_low_training_n_insufficient(self) -> None:
        """Contract with model.N < min_training_tokens → insufficient_evidence."""
        cfg = DriftDetectorConfig(
            min_training_tokens=1000,   # very high
            min_observation_tokens=5,
            threshold=0.3,
        )
        # Train on tiny data: model.N will be small
        tiny_model = train([_benign_seq(20)], k_max=1)
        decider = DriftDecider(
            model=tiny_model, config=cfg,
            image_digest="sha256:abc", purl="pkg:pypi/x@1.0",
        )
        result = decider.decide(_benign_seq(100))
        assert result.outcome == DriftOutcome.INSUFFICIENT_EVIDENCE
        assert "model_training_tokens" in " ".join(result.missing_data_flags)

    def test_insufficient_reason_mentions_model_n(self) -> None:
        """insufficient_evidence_reason mentions the actual model.N."""
        tiny_model = train([_benign_seq(20)], k_max=1)
        cfg = DriftDetectorConfig(min_training_tokens=1000, min_observation_tokens=5,
                                  threshold=0.3)
        decider = DriftDecider(
            model=tiny_model, config=cfg,
            image_digest="sha256:abc", purl="pkg:pypi/x@1.0",
        )
        result = decider.decide(_benign_seq(100))
        assert str(tiny_model.N) in result.insufficient_evidence_reason

    def test_model_metadata_preserved_in_ie_result(self) -> None:
        """model_n, model_m, model_k_star are set even in insufficient_evidence."""
        tiny_model = train([_benign_seq(20)], k_max=1)
        cfg = DriftDetectorConfig(min_training_tokens=1000, min_observation_tokens=5,
                                  threshold=0.3)
        decider = DriftDecider(
            model=tiny_model, config=cfg,
            image_digest="sha256:abc", purl="pkg:pypi/x@1.0",
        )
        result = decider.decide(_benign_seq(100))
        assert result.model_n == tiny_model.N
        assert result.model_m == tiny_model.m
        assert result.model_k_star == tiny_model.k_star


# ===========================================================================
# Test H: Threshold boundary (below, at, above)
# ===========================================================================


class TestH_ThresholdBoundary:
    """SYNTHETIC: Exact boundary behaviour of the threshold decision."""

    def _make_decider(self, threshold: float, model: MarkovModel) -> DriftDecider:
        cfg = DriftDetectorConfig(
            threshold=threshold,
            min_observation_tokens=5,
            min_training_tokens=10,
        )
        return DriftDecider(
            model=model, config=cfg,
            image_digest="sha256:abc", purl="pkg:pypi/x@1.0",
        )

    def test_score_below_threshold_no_drift(self, trained_model) -> None:
        """score < threshold → no_drift."""
        # Get actual score first
        scorer = KlDriftScorer(trained_model)
        actual_score = scorer.score(_benign_seq(100)).final_score
        # Set threshold well above
        decider = self._make_decider(actual_score + 10.0, trained_model)
        result = decider.decide(_benign_seq(100))
        assert result.outcome == DriftOutcome.NO_DRIFT

    def test_score_above_threshold_drift(self, trained_model) -> None:
        """score > threshold → drift."""
        # Get actual score for drifted sequence first
        scorer = KlDriftScorer(trained_model)
        drifted = _drifted_seq(50, 200)
        actual_score = scorer.score(drifted).final_score
        # Set threshold just below actual score
        decider = self._make_decider(actual_score - 0.001, trained_model)
        result = decider.decide(drifted)
        assert result.outcome == DriftOutcome.DRIFT

    def test_score_equal_threshold_no_drift(self, trained_model) -> None:
        """score == threshold → no_drift (boundary is exclusive on drift side).

        The decision rule is: adjusted_score > threshold → drift.
        Equality produces no_drift.
        """
        scorer = KlDriftScorer(trained_model)
        actual_score = scorer.score(_benign_seq(100)).final_score
        # Set threshold exactly equal to the score
        decider = self._make_decider(actual_score, trained_model)
        result = decider.decide(_benign_seq(100))
        # Score == threshold: not strictly greater → no_drift
        assert result.outcome == DriftOutcome.NO_DRIFT

    def test_threshold_version_preserved(self, trained_model) -> None:
        """threshold_version from config is preserved in the result."""
        cfg = DriftDetectorConfig(
            threshold=0.5, threshold_version="my-test-v42",
            min_observation_tokens=5, min_training_tokens=10,
        )
        decider = DriftDecider(
            model=trained_model, config=cfg,
            image_digest="sha256:abc", purl="pkg:pypi/x@1.0",
        )
        result = decider.decide(_benign_seq(100))
        assert result.threshold_version == "my-test-v42"

    def test_infinite_threshold_never_drifts(self, trained_model) -> None:
        """threshold=inf (uncalibrated) never produces DRIFT."""
        cfg = DriftDetectorConfig()  # default: threshold=inf
        decider = DriftDecider(
            model=trained_model, config=cfg,
            image_digest="sha256:abc", purl="pkg:pypi/x@1.0",
        )
        result = decider.decide(_drifted_seq(50, 200))
        assert result.outcome != DriftOutcome.DRIFT


# ===========================================================================
# Test I: Baseline contamination prevention
# ===========================================================================


class TestI_BaselineContaminationPrevention:
    """SYNTHETIC: Attack windows must not silently enter calibration."""

    def test_calibrator_rejects_too_few_windows(self, trained_model) -> None:
        """Calibration with fewer than min_calibration_windows is rejected."""
        cfg = DriftDetectorConfig(min_calibration_windows=30)
        calibrator = ThresholdCalibrator(trained_model, cfg)
        scores = calibrator.score_windows([_benign_seq(50)] * 5)
        result = calibrator.calibrate(scores)
        assert result.is_valid is False
        assert result.threshold == float("inf")
        assert result.threshold_version == "uncalibrated"
        assert "30" in result.reason_invalid   # mentions required count

    def test_calibrator_rejects_nan_only_windows(self, trained_model) -> None:
        """Windows shorter than min_observation_tokens become NaN, may fail calibration."""
        cfg = DriftDetectorConfig(
            min_observation_tokens=50,   # short windows become NaN
            min_calibration_windows=5,
        )
        calibrator = ThresholdCalibrator(trained_model, cfg)
        # All windows are 10 tokens — below min_observation_tokens → all NaN
        scores = calibrator.score_windows([_benign_seq(10)] * 10)
        assert all(math.isnan(s) for s in scores)
        result = calibrator.calibrate(scores)
        assert result.is_valid is False

    def test_calibrator_invalid_returns_inf_threshold(self, trained_model) -> None:
        """Invalid calibration never sets a finite threshold."""
        cfg = DriftDetectorConfig(min_calibration_windows=100)
        calibrator = ThresholdCalibrator(trained_model, cfg)
        scores = calibrator.score_windows([_benign_seq(50)] * 10)
        result = calibrator.calibrate(scores)
        assert result.is_valid is False
        assert math.isinf(result.threshold)

    def test_valid_calibration_with_enough_windows(self, trained_model) -> None:
        """30+ benign windows produce a valid, finite calibration."""
        cfg = DriftDetectorConfig(min_calibration_windows=30)
        calibrator = ThresholdCalibrator(trained_model, cfg)
        windows = [_benign_seq(50)] * 35
        scores = calibrator.score_windows(windows)
        result = calibrator.calibrate(scores)
        assert result.is_valid is True
        assert math.isfinite(result.threshold)
        assert result.threshold >= 0.0
        assert result.n_windows == 35

    def test_threshold_version_changes_with_different_windows(
        self, trained_model
    ) -> None:
        """Different calibration inputs produce different threshold_version hashes."""
        cfg = DriftDetectorConfig(min_calibration_windows=5)
        calibrator = ThresholdCalibrator(trained_model, cfg)

        scores_a = calibrator.score_windows([_benign_seq(50)] * 10)
        scores_b = calibrator.score_windows([_drifted_seq(40, 10)] * 10)
        result_a = calibrator.calibrate(scores_a)
        result_b = calibrator.calibrate(scores_b)

        assert result_a.threshold_version != result_b.threshold_version

    def test_calibration_result_metadata(self, trained_model) -> None:
        """Valid calibration result carries correct n_windows, quantile, score stats."""
        cfg = DriftDetectorConfig(min_calibration_windows=5,
                                  calibration_quantile=0.90)
        calibrator = ThresholdCalibrator(trained_model, cfg)
        windows = [_benign_seq(50)] * 10
        scores = calibrator.score_windows(windows)
        result = calibrator.calibrate(scores)
        assert result.is_valid
        assert result.n_windows == 10
        assert result.quantile == pytest.approx(0.90)
        assert math.isfinite(result.score_min)
        assert math.isfinite(result.score_max)
        assert result.score_max >= result.score_min


# ===========================================================================
# Test J: Determinism
# ===========================================================================


class TestJ_Determinism:
    """SYNTHETIC: Same inputs always produce identical outputs."""

    def test_same_inputs_same_score(self, trained_model) -> None:
        """Calling decide() twice with identical inputs gives identical final_score."""
        cfg = DriftDetectorConfig(min_training_tokens=10, threshold=0.3)
        decider = DriftDecider(
            model=trained_model, config=cfg,
            contract_id="det-test",
            image_digest="sha256:abc",
            purl="pkg:pypi/x@1.0",
        )
        seq = _drifted_seq(80, 40)
        r1 = decider.decide(seq)
        r2 = decider.decide(seq)
        assert r1.final_score == pytest.approx(r2.final_score, abs=1e-15)
        assert r1.adjusted_score == pytest.approx(r2.adjusted_score, abs=1e-15)
        assert r1.outcome == r2.outcome

    def test_same_inputs_same_outcome(self, trained_model) -> None:
        """outcome is identical for repeated calls with the same inputs."""
        cfg = DriftDetectorConfig(min_training_tokens=10, threshold=0.3)
        decider = DriftDecider(
            model=trained_model, config=cfg,
            image_digest="sha256:abc", purl="pkg:pypi/x@1.0",
        )
        seq = _benign_seq(100)
        outcomes = {decider.decide(seq).outcome for _ in range(5)}
        assert len(outcomes) == 1, f"Non-deterministic outcomes: {outcomes}"

    def test_same_inputs_same_novel_fraction(self, trained_model) -> None:
        """novel_token_fraction is identical for repeated calls."""
        cfg = DriftDetectorConfig(min_training_tokens=10, threshold=0.3)
        decider = DriftDecider(
            model=trained_model, config=cfg,
            image_digest="sha256:abc", purl="pkg:pypi/x@1.0",
        )
        seq = _drifted_seq(70, 30)
        fracs = [decider.decide(seq).novel_token_fraction for _ in range(3)]
        assert all(f == fracs[0] for f in fracs), f"Non-deterministic fractions: {fracs}"

    def test_config_change_changes_outcome(self, trained_model) -> None:
        """Changing the threshold changes the outcome (not a no-op)."""
        # Get the actual score
        scorer = KlDriftScorer(trained_model)
        drifted = _drifted_seq(50, 200)
        actual_score = scorer.score(drifted).final_score

        cfg_below = DriftDetectorConfig(
            threshold=actual_score - 0.001,
            min_observation_tokens=5, min_training_tokens=10,
        )
        cfg_above = DriftDetectorConfig(
            threshold=actual_score + 10.0,
            min_observation_tokens=5, min_training_tokens=10,
        )
        d_below = DriftDecider(model=trained_model, config=cfg_below,
                               image_digest="sha256:abc", purl="pkg:pypi/x@1.0")
        d_above = DriftDecider(model=trained_model, config=cfg_above,
                               image_digest="sha256:abc", purl="pkg:pypi/x@1.0")

        r_below = d_below.decide(drifted)
        r_above = d_above.decide(drifted)

        assert r_below.outcome == DriftOutcome.DRIFT
        assert r_above.outcome == DriftOutcome.NO_DRIFT


# ===========================================================================
# _quantile helper tests
# ===========================================================================


class TestQuantileHelper:
    """Unit tests for the linear-interpolation quantile helper."""

    def test_median_odd_length(self) -> None:
        assert _quantile([1.0, 2.0, 3.0], 0.5) == pytest.approx(2.0)

    def test_median_even_length(self) -> None:
        assert _quantile([1.0, 2.0, 3.0, 4.0], 0.5) == pytest.approx(2.5)

    def test_min_is_zero_quantile(self) -> None:
        assert _quantile([5.0, 10.0, 20.0], 0.0) == pytest.approx(5.0)

    def test_max_is_one_quantile(self) -> None:
        assert _quantile([5.0, 10.0, 20.0], 1.0) == pytest.approx(20.0)

    def test_single_element(self) -> None:
        assert _quantile([42.0], 0.99) == pytest.approx(42.0)

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            _quantile([], 0.5)

    def test_out_of_range_q_raises(self) -> None:
        with pytest.raises(ValueError):
            _quantile([1.0, 2.0], 1.5)


# ===========================================================================
# DriftDetectorConfig validation
# ===========================================================================


class TestConfigValidation:
    """Config rejects invalid parameter values immediately."""

    def test_loss_penalty_below_one_raises(self) -> None:
        with pytest.raises(ValueError, match="loss_penalty_factor"):
            DriftDetectorConfig(loss_penalty_factor=0.5)

    def test_min_obs_zero_raises(self) -> None:
        with pytest.raises(ValueError, match="min_observation_tokens"):
            DriftDetectorConfig(min_observation_tokens=0)

    def test_calibration_quantile_zero_raises(self) -> None:
        with pytest.raises(ValueError, match="calibration_quantile"):
            DriftDetectorConfig(calibration_quantile=0.0)

    def test_calibration_quantile_above_one_raises(self) -> None:
        with pytest.raises(ValueError, match="calibration_quantile"):
            DriftDetectorConfig(calibration_quantile=1.5)

    def test_negative_novelty_weight_raises(self) -> None:
        with pytest.raises(ValueError, match="novelty_weight"):
            DriftDetectorConfig(novelty_weight=-0.1)

    def test_valid_config_constructs(self) -> None:
        cfg = DriftDetectorConfig(
            threshold=0.5,
            min_observation_tokens=20,
            loss_penalty_factor=2.0,
            calibration_quantile=0.95,
        )
        assert cfg.threshold == 0.5
