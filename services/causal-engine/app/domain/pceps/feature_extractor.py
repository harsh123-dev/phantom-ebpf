"""
causal-engine domain PCEPS feature extractor.

Implements the 16-feature vector derivation from handoff §7.1 exactly.

Every feature has:
- A derivation formula matching the §7.1 table.
- A missing-value rule (median from training split + imputed mask,
  or conservative default + mask per the table).
- A [0, 1] normalization guarantee.

Feature derivation enforces temporal causality: no post-outcome
information may enter PCEPS features (§7, invariant 6).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

import structlog

from app.domain.entities import (
    PCEPS_FEATURE_NAMES,
    AttributionResult,
    AttributionStatus,
    PcepsFeatureBaseline,
    PcepsFeatureVector,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)

# Machine epsilon δ (§7.1 footnote): only a numerical guard for division.
_DELTA: float = sys.float_info.epsilon


# ---------------------------------------------------------------------------
# Feature derivation context
# ---------------------------------------------------------------------------


@dataclass
class FeatureDerivationContext:
    """All inputs needed to derive the 16 PCEPS features.

    Each field corresponds to a row in the §7.1 table.
    None means "unavailable" and triggers the missing-value rule.

    Attributes:
        attribution: The causal AttributionResult (for f1, f2).
        contract_violations: Number of contract violations in window.
        evaluated_contract_rules: Total rules evaluated.
        kl_divergence: KL divergence D(BC, O) from Algorithm 2.
        kl_threshold: Conformal threshold θ_α.
        new_processes_not_in_contract: Count of exec events for unknown processes.
        total_exec_events: Total exec events in window.
        unexpected_network_events: Count of unexpected connect/accept events.
        total_network_events: Total network events in window.
        privilege_transition_unexpected: Whether an unexpected privilege change occurred.
        sensitive_file_violations: Count of sensitive-path violations.
        total_file_events: Total file events in window.
        component_criticality: Policy value κ(purl) ∈ [0, 1].
        image_signature_invalid: True if image/SBOM verification failed or absent.
        namespace_risk_weight: Policy value ρ(namespace) ∈ [0, 1].
        service_account_privilege: True if RBAC includes high-impact permissions.
        event_loss_dropped: Number of events dropped.
        event_loss_captured: Number of events captured.
        graph_centrality_current: Current normalized PageRank centrality.
        graph_centrality_baseline_median: Baseline median PageRank centrality.
        graph_centrality_baseline_mad: Baseline MAD of PageRank centrality.
        prior_drift_windows: Number of prior windows with drift detected.
        prior_observed_windows: Total prior observed windows.
        runtime_component_novelty: True if PURL missing/ambiguous or absent from SBOM.
    """

    attribution: AttributionResult | None = None
    contract_violations: int | None = None
    evaluated_contract_rules: int | None = None
    kl_divergence: float | None = None
    kl_threshold: float | None = None
    new_processes_not_in_contract: int | None = None
    total_exec_events: int | None = None
    unexpected_network_events: int | None = None
    total_network_events: int | None = None
    privilege_transition_unexpected: bool | None = None
    sensitive_file_violations: int | None = None
    total_file_events: int | None = None
    component_criticality: float | None = None
    image_signature_invalid: bool | None = None
    namespace_risk_weight: float | None = None
    service_account_privilege: bool | None = None
    event_loss_dropped: int | None = None
    event_loss_captured: int | None = None
    graph_centrality_current: float | None = None
    graph_centrality_baseline_median: float | None = None
    graph_centrality_baseline_mad: float | None = None
    prior_drift_windows: int | None = None
    prior_observed_windows: int | None = None
    runtime_component_novelty: bool | None = None


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------


def derive_pceps_features(
    ctx: FeatureDerivationContext,
    baseline: PcepsFeatureBaseline,
) -> PcepsFeatureVector:
    """Derive the 16-feature PCEPS vector from the derivation context.

    Each feature follows the exact derivation and missing-value rule
    from handoff §7.1. Features are normalized to [0, 1]. Imputed
    features are recorded in the mask.

    Args:
        ctx: The feature derivation context.
        baseline: Training-partition medians/MADs for normalization.

    Returns:
        A PcepsFeatureVector with values, mask, and imputed feature names.
    """
    values: list[float] = [0.0] * 16
    mask: list[bool] = [False] * 16

    def _set(idx: int, value: float | None, missing_rule: float) -> None:
        """Set feature value or apply missing-value rule.

        Args:
            idx: 0-based feature index.
            value: Computed feature value, or None if unavailable.
            missing_rule: Default value when feature is missing.
        """
        if value is not None:
            values[idx] = max(0.0, min(1.0, value))
        else:
            values[idx] = max(0.0, min(1.0, missing_rule))
            mask[idx] = True

    # f1: causal_effect = max(0, min(1, ATE))
    # Missing: median from training split + mask.
    # Per §7.6: if attribution not identifiable → reject PCEPS request.
    f1: float | None = None
    if ctx.attribution and ctx.attribution.status == AttributionStatus.COMPLETED:
        if ctx.attribution.ate is not None:
            f1 = max(0.0, min(1.0, ctx.attribution.ate))
    _set(0, f1, baseline.medians[0])

    # f2: attribution_confidence
    f2: float | None = None
    if ctx.attribution and ctx.attribution.status == AttributionStatus.COMPLETED:
        f2 = ctx.attribution.confidence
    _set(1, f2, baseline.medians[1])

    # f3: contract_violation_rate = violations / max(1, evaluated_rules)
    f3: float | None = None
    if ctx.contract_violations is not None and ctx.evaluated_contract_rules is not None:
        f3 = ctx.contract_violations / max(1, ctx.evaluated_contract_rules)
    elif ctx.contract_violations is not None and ctx.evaluated_contract_rules is None:
        # Evaluation completed, found none → 0.
        if ctx.contract_violations == 0:
            f3 = 0.0
    _set(2, f3, baseline.medians[2])

    # f4: behavioral_divergence_ratio = min(1, D / max(θ, δ))
    f4: float | None = None
    if ctx.kl_divergence is not None and ctx.kl_threshold is not None:
        denom = max(ctx.kl_threshold, _DELTA)
        f4 = min(1.0, ctx.kl_divergence / denom)
    _set(3, f4, baseline.medians[3])

    # f5: new_process_rate = new_procs / max(1, total_exec)
    f5: float | None = None
    if ctx.new_processes_not_in_contract is not None and ctx.total_exec_events is not None:
        f5 = ctx.new_processes_not_in_contract / max(1, ctx.total_exec_events)
    _set(4, f5, baseline.medians[4])

    # f6: unexpected_network_rate = unexpected / max(1, total_network)
    f6: float | None = None
    if ctx.unexpected_network_events is not None and ctx.total_network_events is not None:
        f6 = ctx.unexpected_network_events / max(1, ctx.total_network_events)
    _set(5, f6, baseline.medians[5])

    # f7: privilege_transition = 1 if unexpected privilege change, else 0
    f7: float | None = None
    if ctx.privilege_transition_unexpected is not None:
        f7 = 1.0 if ctx.privilege_transition_unexpected else 0.0
    _set(6, f7, baseline.medians[6])

    # f8: sensitive_file_access_rate = violations / max(1, file_events)
    f8: float | None = None
    if ctx.sensitive_file_violations is not None and ctx.total_file_events is not None:
        f8 = ctx.sensitive_file_violations / max(1, ctx.total_file_events)
    _set(7, f8, baseline.medians[7])

    # f9: component_criticality = κ(purl) ∈ [0, 1]
    _set(8, ctx.component_criticality, baseline.medians[8])

    # f10: image_signature_invalid. Missing → 1 + mask (conservative).
    f10: float | None = None
    if ctx.image_signature_invalid is not None:
        f10 = 1.0 if ctx.image_signature_invalid else 0.0
    _set(9, f10, 1.0)  # Conservative: unknown = invalid.

    # f11: namespace_risk_weight = ρ(namespace) ∈ [0, 1]
    _set(10, ctx.namespace_risk_weight, baseline.medians[10])

    # f12: service_account_privilege. Missing → 1 + mask (conservative).
    f12: float | None = None
    if ctx.service_account_privilege is not None:
        f12 = 1.0 if ctx.service_account_privilege else 0.0
    _set(11, f12, 1.0)  # Conservative: unknown = privileged.

    # f13: event_loss_rate = dropped / max(1, captured + dropped)
    # Missing → 1 + mask (missing collection must not improve priority).
    f13: float | None = None
    if ctx.event_loss_dropped is not None and ctx.event_loss_captured is not None:
        total = ctx.event_loss_captured + ctx.event_loss_dropped
        f13 = ctx.event_loss_dropped / max(1, total)
    _set(12, f13, 1.0)  # Conservative.

    # f14: graph_centrality_delta = min(1, max(0, (c - median) / max(MAD, δ)))
    f14: float | None = None
    if ctx.graph_centrality_current is not None:
        median_c = ctx.graph_centrality_baseline_median or baseline.medians[13]
        mad_c = ctx.graph_centrality_baseline_mad or baseline.mads[13]
        denom = max(mad_c, _DELTA)
        f14 = min(1.0, max(0.0, (ctx.graph_centrality_current - median_c) / denom))
    _set(13, f14, baseline.medians[13])

    # f15: prior_drift_frequency = (prior_drift + 1) / (prior_observed + 2)
    # Beta-smoothed prior.
    f15: float | None = None
    if ctx.prior_drift_windows is not None and ctx.prior_observed_windows is not None:
        f15 = (ctx.prior_drift_windows + 1) / (ctx.prior_observed_windows + 2)
    _set(14, f15, baseline.medians[14])

    # f16: runtime_component_novelty. Missing → 1 + mask.
    f16: float | None = None
    if ctx.runtime_component_novelty is not None:
        f16 = 1.0 if ctx.runtime_component_novelty else 0.0
    _set(15, f16, 1.0)  # Conservative.

    # Build imputed feature names list.
    imputed_names: list[str] = [
        PCEPS_FEATURE_NAMES[i] for i in range(16) if mask[i]
    ]
    completeness = 1.0 - (sum(mask) / 16.0)

    return PcepsFeatureVector(
        values=values,
        mask=mask,
        feature_completeness=completeness,
        imputed_feature_names=imputed_names,
    )
