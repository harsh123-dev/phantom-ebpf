"""
services/ebpf-agent/domain/drift/config.py

Explicit configuration for the PHANTOM drift detector.

All tuneable parameters live here so that magic numbers are never
scattered across the scoring or decision code.  The defaults are
documented with their rationale; none are presented as experimentally
validated unless stated otherwise.

Usage::

    from domain.drift.config import DriftDetectorConfig

    cfg = DriftDetectorConfig()                  # all defaults
    cfg = DriftDetectorConfig(threshold=0.85)    # override one field
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DriftDetectorConfig:
    """Configuration for DriftDecider and ThresholdCalibrator.

    Attributes:
        threshold:
            KL-divergence score above which a ``drift`` decision is
            issued.  Unit: nats (natural-log KL).
            Default: ``float('inf')`` — meaning *no alert fires* until
            the threshold has been explicitly calibrated with real benign
            baseline data.  This is intentional; see §5 of the research
            prompt.  Setting a finite value without calibration data
            constitutes an arbitrary choice and must be clearly documented
            in any paper reporting on it.

        threshold_version:
            A human-readable or hash identifier for this threshold.
            Updated by ThresholdCalibrator.calibrate() to the sha256 of
            the calibration input.  The default "uncalibrated" sentinel
            signals that no valid calibration has been performed.

        min_observation_tokens:
            Minimum number of tokens that must be present in an
            observation window for a reliable drift decision.  Windows
            below this count yield ``insufficient_evidence``.
            Default: 20 (arbitrary conservative lower bound; not
            experimentally validated).

        min_training_tokens:
            Minimum model.N required to trust the contract at inference
            time.  If the loaded contract was trained on fewer tokens the
            decision is ``insufficient_evidence``.
            Default: 100 (matches GenerateContractUseCase default).

        loss_penalty_factor:
            Multiplier applied to the KL score when event loss is
            reported (ring-buffer or transport loss).  Must be >= 1.0.
            Default: 1.5 (handoff §4 recommendation).

        require_identity:
            If True, a decision is ``insufficient_evidence`` when either
            image_digest or purl is UNRESOLVED.  If False, the decision
            proceeds on the contract content alone.
            Default: True (fail-safe).

        novelty_weight:
            Additional score contribution per unit of novel_token_fraction:
                adjusted_score = final_score + novelty_weight * novel_fraction
            Set to 0.0 to disable the novelty term entirely.
            Default: 0.0 (disabled until experimentally calibrated).

        min_calibration_windows:
            Minimum number of independent benign baseline windows required
            for ThresholdCalibrator to accept a calibration request.
            Default: 30 (provides a minimal empirical quantile estimate;
            for 99th-percentile calibration this means at most 0 windows
            in the tail, so the threshold may be conservative).

        calibration_quantile:
            Upper quantile of benign-window scores used as the threshold.
            Default: 0.99 — the 99th percentile of scored benign windows
            becomes the drift threshold.  This means approximately 1% of
            benign windows will exceed the threshold (false-positive rate
            of ~0.01 on the calibration set, ignoring finite-sample error).
            Assumption: calibration windows are exchangeable with future
            benign windows (same workload, same image, same contract).
    """

    threshold: float = float("inf")
    threshold_version: str = "uncalibrated"
    min_observation_tokens: int = 20
    min_training_tokens: int = 100
    loss_penalty_factor: float = 1.5
    require_identity: bool = True
    novelty_weight: float = 0.0
    min_calibration_windows: int = 30
    calibration_quantile: float = 0.99

    # Sentinel used to represent an unresolved image digest or PURL.
    UNRESOLVED_IDENTITY: str = "UNRESOLVED"

    def __post_init__(self) -> None:
        """Validate configuration values on construction.

        Raises:
            ValueError: If any parameter is out of its valid range.
        """
        if self.loss_penalty_factor < 1.0:
            raise ValueError(
                f"loss_penalty_factor must be >= 1.0, got {self.loss_penalty_factor}"
            )
        if self.min_observation_tokens < 1:
            raise ValueError(
                f"min_observation_tokens must be >= 1, got {self.min_observation_tokens}"
            )
        if self.min_training_tokens < 1:
            raise ValueError(
                f"min_training_tokens must be >= 1, got {self.min_training_tokens}"
            )
        if not (0.0 < self.calibration_quantile <= 1.0):
            raise ValueError(
                f"calibration_quantile must be in (0, 1], got {self.calibration_quantile}"
            )
        if self.novelty_weight < 0.0:
            raise ValueError(
                f"novelty_weight must be >= 0.0, got {self.novelty_weight}"
            )
        if self.min_calibration_windows < 2:
            raise ValueError(
                f"min_calibration_windows must be >= 2, got {self.min_calibration_windows}"
            )
