"""
services/ebpf-agent/domain/drift/decider.py

PHANTOM behavioral drift decision rule.

Maps the raw KL-divergence score produced by KlDriftScorer into one of
three reproducible decision states:

    drift               — sufficient evidence; score exceeds threshold
    no_drift            — sufficient evidence; score is at or below threshold
    insufficient_evidence — evidence is inadequate for a reliable decision

Design contract:
- A decision is reproducible: given the same inputs, the same result is
  always returned.
- A decision preserves all provenance: contract ID, image digest, PURL,
  threshold version, window timestamps, raw score, event counts.
- No decision is silently suppressed.  Every call returns a DriftResult.
- Unresolved identity is preserved, never fabricated.
- Empty or too-short observation windows always produce
  insufficient_evidence, never "no_drift".
- The threshold is externally injected via DriftDetectorConfig so that
  it can be replaced without code changes.

Mathematical note:
    The adjusted score used for the threshold comparison is:

        adjusted_score = final_score + novelty_weight * novel_token_fraction

    where final_score = total_kl * loss_penalty (from KlScoreResult).
    With novelty_weight = 0.0 (the default), adjusted_score == final_score
    and no novelty bonus is applied.

    This is NOT a new divergence formula — it is an additive correction
    term that can be zeroed out.  It is labelled "adjusted_score" in all
    outputs so that paper metrics are reproducible with either setting.
"""

from __future__ import annotations

import enum
import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from domain.drift.config import DriftDetectorConfig
from domain.drift.kl_scorer import ContextKlResult, KlDriftScorer, KlScoreResult
from domain.markov.chain import MarkovModel, Token

# ---------------------------------------------------------------------------
# Outcome enum
# ---------------------------------------------------------------------------


class DriftOutcome(str, enum.Enum):
    """Three-state drift decision.

    Members:
        DRIFT: Score exceeds the configured threshold and evidence is
            sufficient.  Behavioral drift is detected.
        NO_DRIFT: Score is at or below the threshold and evidence is
            sufficient.  No drift is detected.
        INSUFFICIENT_EVIDENCE: The required data (contract, telemetry,
            component identity, or observation volume) is inadequate for
            a reliable decision.  No alert is issued.
    """

    DRIFT = "drift"
    NO_DRIFT = "no_drift"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

UNRESOLVED: str = DriftDetectorConfig.UNRESOLVED_IDENTITY


@dataclass
class DriftResult:
    """Full provenance record for one drift decision.

    This dataclass is the authoritative output of DriftDecider.decide().
    It preserves all information required to reproduce, audit, and
    explain the decision.

    Attributes:
        outcome: The drift decision state (drift / no_drift /
            insufficient_evidence).
        final_score: Raw KL-divergence score with loss penalty applied
            (total_kl * loss_penalty, from KlScoreResult).
        adjusted_score: final_score + novelty_weight * novel_token_fraction.
            Equals final_score when novelty_weight == 0.0 (default).
        threshold: The threshold against which adjusted_score is compared.
        threshold_version: Identifier for the threshold (e.g. calibration
            hash or "uncalibrated").
        contract_id: Identifier of the behavioral contract used.
        contract_version: Schema version of the contract (e.g. "v1").
        image_digest: sha256 image digest, or UNRESOLVED.
        purl: SBOM PURL of the component, or UNRESOLVED.
        observation_window_start: Start of the scored observation window.
        observation_window_end: End of the scored observation window.
        observation_count: Number of tokens in the observation window.
        contexts_evaluated: Number of distinct Markov contexts observed.
        novel_token_fraction: Fraction of observation tokens not in the
            training alphabet.
        loss_observed: Whether event loss was reported in this window.
        loss_penalty: The loss multiplier that was applied.
        missing_data_flags: Ordered list of human-readable flags describing
            any missing or suspect inputs (empty if none).
        explanation: Short, evidence-based explanation of the decision.
            Generated from actual scoring features, never invented.
        insufficient_evidence_reason: Non-empty string when outcome is
            INSUFFICIENT_EVIDENCE, explaining exactly which condition
            triggered it.
        per_context_kl: Per-context KL breakdown from the scorer, for
            diagnostic use.
        model_n: Total training token count (from the contract model).
        model_m: Alphabet size of the contract model.
        model_k_star: Markov order selected by BIC.
    """

    outcome: DriftOutcome
    final_score: float
    adjusted_score: float
    threshold: float
    threshold_version: str
    contract_id: str
    contract_version: str
    image_digest: str
    purl: str
    observation_window_start: Optional[datetime]
    observation_window_end: Optional[datetime]
    observation_count: int
    contexts_evaluated: int
    novel_token_fraction: float
    loss_observed: bool
    loss_penalty: float
    missing_data_flags: list[str] = field(default_factory=list)
    explanation: str = ""
    insufficient_evidence_reason: str = ""
    per_context_kl: list[ContextKlResult] = field(default_factory=list)
    model_n: int = 0
    model_m: int = 0
    model_k_star: int = 0

    def is_drift(self) -> bool:
        """True iff the outcome is DRIFT."""
        return self.outcome == DriftOutcome.DRIFT

    def is_actionable(self) -> bool:
        """True iff the outcome is DRIFT or NO_DRIFT (sufficient evidence)."""
        return self.outcome in (DriftOutcome.DRIFT, DriftOutcome.NO_DRIFT)


# ---------------------------------------------------------------------------
# Decider
# ---------------------------------------------------------------------------


class DriftDecider:
    """Maps a KL-divergence score to a reproducible drift decision.

    Args:
        model: The trained MarkovModel (behavioral contract).
        config: DriftDetectorConfig with threshold and evidence requirements.
        contract_id: Identifier of the contract (e.g. database UUID string).
        image_digest: sha256 image digest or UNRESOLVED.
        purl: SBOM PURL or UNRESOLVED.
    """

    _CONTRACT_VERSION: str = "v1"

    def __init__(
        self,
        model: MarkovModel,
        config: DriftDetectorConfig,
        contract_id: str = "",
        image_digest: str = UNRESOLVED,
        purl: str = UNRESOLVED,
    ) -> None:
        """Initialise the decider.

        Args:
            model: Trained MarkovModel representing the behavioral contract.
            config: Configuration controlling thresholds and evidence rules.
            contract_id: Stable identifier for this contract (e.g. UUID).
            image_digest: sha256 digest of the container image (may be
                UNRESOLVED if the mapping could not be established).
            purl: SBOM PURL of the component (may be UNRESOLVED).
        """
        self._model = model
        self._cfg = config
        self._contract_id = contract_id
        self._image_digest = image_digest
        self._purl = purl
        self._scorer = KlDriftScorer(
            model, loss_penalty_factor=config.loss_penalty_factor
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def decide(
        self,
        observed_sequence: list[Token],
        loss_observed: bool = False,
        observation_window_start: Optional[datetime] = None,
        observation_window_end: Optional[datetime] = None,
    ) -> DriftResult:
        """Produce a three-state drift decision for an observation window.

        Args:
            observed_sequence: Tokenised eBPF events from the window.
            loss_observed: True if ring-buffer or transport loss was
                reported in this window.
            observation_window_start: Start timestamp of the window (UTC).
            observation_window_end: End timestamp of the window (UTC).

        Returns:
            A DriftResult with full provenance and a reproducible outcome.
        """
        missing_flags: list[str] = []

        # --- 1. Identity checks -------------------------------------------
        if self._image_digest == UNRESOLVED:
            missing_flags.append("image_digest_unresolved")
        if self._purl == UNRESOLVED:
            missing_flags.append("purl_unresolved")
        if self._cfg.require_identity and (
            self._image_digest == UNRESOLVED or self._purl == UNRESOLVED
        ):
            return self._ie_result(
                reason="Component identity (image_digest or purl) is unresolved "
                       "and require_identity=True",
                obs_count=len(observed_sequence),
                loss_observed=loss_observed,
                missing_flags=missing_flags,
                win_start=observation_window_start,
                win_end=observation_window_end,
            )

        # --- 2. Contract training-data sufficiency -------------------------
        if self._model.N < self._cfg.min_training_tokens:
            missing_flags.append(
                f"model_training_tokens={self._model.N}"
                f"_below_minimum={self._cfg.min_training_tokens}"
            )
            return self._ie_result(
                reason=(
                    f"Contract was trained on only {self._model.N} tokens "
                    f"(minimum required: {self._cfg.min_training_tokens})"
                ),
                obs_count=len(observed_sequence),
                loss_observed=loss_observed,
                missing_flags=missing_flags,
                win_start=observation_window_start,
                win_end=observation_window_end,
            )

        # --- 3. Observation-window size check ------------------------------
        if len(observed_sequence) < self._cfg.min_observation_tokens:
            missing_flags.append(
                f"observation_tokens={len(observed_sequence)}"
                f"_below_minimum={self._cfg.min_observation_tokens}"
            )
            return self._ie_result(
                reason=(
                    f"Observation window has only {len(observed_sequence)} tokens "
                    f"(minimum required: {self._cfg.min_observation_tokens})"
                ),
                obs_count=len(observed_sequence),
                loss_observed=loss_observed,
                missing_flags=missing_flags,
                win_start=observation_window_start,
                win_end=observation_window_end,
            )

        # --- 4. Score ------------------------------------------------------
        score_result: KlScoreResult = self._scorer.score(
            observed_sequence, loss_observed=loss_observed
        )

        # --- 5. Adjusted score (novelty term) ------------------------------
        adjusted = score_result.final_score + (
            self._cfg.novelty_weight * score_result.novel_token_fraction
        )

        # --- 6. Threshold check --------------------------------------------
        if math.isfinite(self._cfg.threshold):
            outcome = (
                DriftOutcome.DRIFT
                if adjusted > self._cfg.threshold
                else DriftOutcome.NO_DRIFT
            )
        else:
            # threshold=inf → uncalibrated → cannot fire drift
            outcome = DriftOutcome.NO_DRIFT
            missing_flags.append("threshold_uncalibrated")

        # --- 7. Build explanation ------------------------------------------
        explanation = self._build_explanation(
            outcome, score_result, adjusted, loss_observed
        )

        return DriftResult(
            outcome=outcome,
            final_score=score_result.final_score,
            adjusted_score=adjusted,
            threshold=self._cfg.threshold,
            threshold_version=self._cfg.threshold_version,
            contract_id=self._contract_id,
            contract_version=self._CONTRACT_VERSION,
            image_digest=self._image_digest,
            purl=self._purl,
            observation_window_start=observation_window_start,
            observation_window_end=observation_window_end,
            observation_count=score_result.observation_count,
            contexts_evaluated=score_result.contexts_evaluated,
            novel_token_fraction=score_result.novel_token_fraction,
            loss_observed=score_result.loss_observed,
            loss_penalty=score_result.loss_penalty,
            missing_data_flags=missing_flags,
            explanation=explanation,
            insufficient_evidence_reason="",
            per_context_kl=score_result.per_context,
            model_n=self._model.N,
            model_m=self._model.m,
            model_k_star=self._model.k_star,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _ie_result(
        self,
        reason: str,
        obs_count: int,
        loss_observed: bool,
        missing_flags: list[str],
        win_start: Optional[datetime],
        win_end: Optional[datetime],
    ) -> DriftResult:
        """Build an insufficient_evidence DriftResult.

        Args:
            reason: Human-readable explanation of why evidence is insufficient.
            obs_count: Number of tokens in the observation window.
            loss_observed: Whether event loss was reported.
            missing_flags: Accumulated missing-data flags.
            win_start: Window start timestamp.
            win_end: Window end timestamp.

        Returns:
            A DriftResult with outcome=INSUFFICIENT_EVIDENCE.
        """
        return DriftResult(
            outcome=DriftOutcome.INSUFFICIENT_EVIDENCE,
            final_score=float("nan"),
            adjusted_score=float("nan"),
            threshold=self._cfg.threshold,
            threshold_version=self._cfg.threshold_version,
            contract_id=self._contract_id,
            contract_version=self._CONTRACT_VERSION,
            image_digest=self._image_digest,
            purl=self._purl,
            observation_window_start=win_start,
            observation_window_end=win_end,
            observation_count=obs_count,
            contexts_evaluated=0,
            novel_token_fraction=float("nan"),
            loss_observed=loss_observed,
            loss_penalty=self._cfg.loss_penalty_factor if loss_observed else 1.0,
            missing_data_flags=missing_flags,
            explanation=f"Decision not possible: {reason}",
            insufficient_evidence_reason=reason,
            per_context_kl=[],
            model_n=self._model.N,
            model_m=self._model.m,
            model_k_star=self._model.k_star,
        )

    @staticmethod
    def _build_explanation(
        outcome: DriftOutcome,
        score_result: KlScoreResult,
        adjusted_score: float,
        loss_observed: bool,
    ) -> str:
        """Build a short, evidence-based explanation string.

        Only includes facts that are derivable from the actual scoring
        result.  Never invents an attack explanation or causal relationship.

        Args:
            outcome: The decided outcome.
            score_result: The KlScoreResult from the scorer.
            adjusted_score: The adjusted score used for the threshold.
            loss_observed: Whether event loss was reported.

        Returns:
            A concise explanation string.
        """
        parts: list[str] = []

        if outcome == DriftOutcome.DRIFT:
            parts.append(
                f"Drift detected: adjusted KL score {adjusted_score:.4f} "
                f"exceeds threshold."
            )
        else:
            parts.append(
                f"No drift: adjusted KL score {adjusted_score:.4f} "
                f"is at or below threshold."
            )

        # Novel-token contribution
        nf = score_result.novel_token_fraction
        if nf > 0.0:
            parts.append(
                f"{nf * 100:.1f}% of observed tokens were absent from the "
                "contract alphabet (novel events)."
            )

        # Loss penalty
        if loss_observed:
            parts.append(
                f"Event loss was reported; score was multiplied by "
                f"{score_result.loss_penalty:.2f} (loss penalty)."
            )

        # Highest-KL context
        if score_result.per_context:
            top = max(score_result.per_context, key=lambda r: r.kl_divergence)
            if top.kl_divergence > 0.0:
                ctx_str = (
                    "→".join(str(t) for t in top.context)
                    if top.context
                    else "<empty context>"
                )
                parts.append(
                    f"Highest per-context KL {top.kl_divergence:.4f} "
                    f"at context [{ctx_str}] "
                    f"({top.obs_count} observations, "
                    f"{top.novel_tokens} novel token(s))."
                )

        return "  ".join(parts)
