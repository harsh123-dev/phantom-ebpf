"""Regression tests for contract-drift ground-truth labeling semantics.

Ensures strict compliance with the contract-drift ground-truth labeling rule:
1. Label Y_drift = 0 only when the applicable contract and independent evidence
   establish that observed behavior conforms to the allowed behavior.
2. Label Y_drift = 1 only when verified behavior violates an applicable contract rule.
3. If the contract is missing, ambiguous, incomplete, or silent about behavior that
   cannot otherwise be established as authorized, preserve Y_drift = unknown.
4. Do not infer ground truth from PHANTOM alerts.
"""

from typing import Optional
import pytest

from app.domain.observation_builder import (
    CausalObservationBuilder,
    OutcomeLabel,
    RunManifest,
    RunManifestPhase,
)


def _build_manifest(
    run_id: str = "run_test_01",
    is_attack: bool = True,
    contract_status: Optional[str] = None,
    contract_evidence_verified: Optional[bool] = None,
    verified_contract_drift: Optional[int] = None,
    first_phantom_detection_timestamp: Optional[str] = None,
    is_true_positive: bool = False,
    inject_ok: bool = True,
) -> RunManifest:
    """Helper to construct a RunManifest for contract drift tests."""
    inject_note = "inject_ok=True" if inject_ok else "inject_ok=False"
    phases = [
        RunManifestPhase("baseline", "2026-10-24T00:00:00Z", "2026-10-24T00:01:00Z", 60.0),
        RunManifestPhase("inject", "2026-10-24T00:01:00Z", "2026-10-24T00:01:05Z", 5.0, inject_note),
        RunManifestPhase("attack", "2026-10-24T00:01:05Z", "2026-10-24T00:02:05Z", 60.0),
        RunManifestPhase("recover", "2026-10-24T00:02:05Z", "2026-10-24T00:02:10Z", 5.0, "recover_ok=True"),
        RunManifestPhase("post_recovery", "2026-10-24T00:02:10Z", "2026-10-24T00:03:10Z", 60.0),
    ]
    return RunManifest(
        run_id=run_id,
        attack_id="test-scenario",
        attack_family="backdoor" if is_attack else "benign",
        repetition=1,
        namespace="default",
        pod_name="test-pod",
        ground_truth_label=1 if is_attack else 0,
        injection_timestamp="2026-10-24T00:01:00Z" if is_attack else None,
        first_phantom_detection_timestamp=first_phantom_detection_timestamp,
        mttd_s=10.0 if first_phantom_detection_timestamp else None,
        is_true_positive=is_true_positive,
        verified_contract_drift=verified_contract_drift,
        contract_status=contract_status,
        contract_evidence_verified=contract_evidence_verified,
        phases=phases,
        target_purl="pkg:pypi/test@1.0.1" if is_attack else "",
        clean_purl="pkg:pypi/test@1.0.0",
        detection_window_s=120.0,
    )


class TestContractDriftGroundTruthSemantics:
    """Regression test suite for contract-drift ground-truth labeling rules."""

    def test_explicitly_allowed_behavior_produces_negative(self) -> None:
        """Requirement: Label Y_drift = 0 only when applicable contract and independent

        evidence establish that observed behavior conforms to allowed behavior.
        """
        builder = CausalObservationBuilder()

        # Case 1: contract_status = "conforming" with evidence verified
        manifest1 = _build_manifest(
            run_id="run_allowed_1",
            is_attack=False,
            contract_status="conforming",
            contract_evidence_verified=True,
        )
        batch1 = builder.build_from_run_manifest_only(manifest1)
        assert batch1.included_count == 1
        assert len(batch1.observations) == 1
        assert batch1.observations[0].outcome_value == 0
        assert batch1.provenance_records[0].outcome_label == OutcomeLabel.NEGATIVE
        assert batch1.provenance_records[0].outcome_label_source == "verified_contract_conformance"

        # Case 2: verified_contract_drift = 0 (independent oracle confirmed conformance)
        manifest2 = _build_manifest(
            run_id="run_allowed_2",
            is_attack=False,
            verified_contract_drift=0,
            contract_evidence_verified=True,
        )
        batch2 = builder.build_from_run_manifest_only(manifest2)
        assert batch2.included_count == 1
        assert batch2.observations[0].outcome_value == 0
        assert batch2.provenance_records[0].outcome_label == OutcomeLabel.NEGATIVE

    def test_explicitly_prohibited_behavior_produces_positive(self) -> None:
        """Requirement: Label Y_drift = 1 only when verified behavior violates
        an applicable contract rule.
        """
        builder = CausalObservationBuilder()

        # Case 1: contract_status = "violating" with verified evidence
        manifest1 = _build_manifest(
            run_id="run_violating_1",
            is_attack=True,
            contract_status="violating",
            contract_evidence_verified=True,
        )
        batch1 = builder.build_from_run_manifest_only(manifest1)
        assert batch1.included_count == 1
        assert len(batch1.observations) == 1
        assert batch1.observations[0].outcome_value == 1
        assert batch1.provenance_records[0].outcome_label == OutcomeLabel.POSITIVE
        assert batch1.provenance_records[0].outcome_label_source == "verified_contract_violation"

        # Case 2: verified_contract_drift = 1 (separate authoritative oracle)
        manifest2 = _build_manifest(
            run_id="run_violating_2",
            is_attack=True,
            verified_contract_drift=1,
        )
        batch2 = builder.build_from_run_manifest_only(manifest2)
        assert batch2.included_count == 1
        assert batch2.observations[0].outcome_value == 1
        assert batch2.provenance_records[0].outcome_label == OutcomeLabel.POSITIVE
        assert batch2.provenance_records[0].outcome_label_source == "verified_contract_drift"

    def test_conforming_status_with_missing_evidence(self) -> None:
        """Requirement: contract_status='conforming' with contract_evidence_verified=None

        must produce OutcomeLabel.UNKNOWN (missing evidence).
        """
        builder = CausalObservationBuilder()
        manifest = _build_manifest(
            run_id="run_conforming_missing_evidence",
            is_attack=False,
            contract_status="conforming",
            contract_evidence_verified=None,
        )
        batch = builder.build_from_run_manifest_only(manifest)
        assert batch.included_count == 0
        assert batch.excluded_count == 1
        assert len(batch.observations) == 0
        assert batch.provenance_records[0].outcome_label == OutcomeLabel.UNKNOWN
        assert batch.provenance_records[0].outcome_label_source == "contract_unverified_evidence"
        assert batch.insufficiencies[0].reason_code == "unknown_outcome"

    def test_conforming_status_with_verified_evidence(self) -> None:
        """Requirement: contract_status='conforming' with contract_evidence_verified=True

        produces Y_drift=0 (OutcomeLabel.NEGATIVE).
        """
        builder = CausalObservationBuilder()
        manifest = _build_manifest(
            run_id="run_conforming_verified",
            is_attack=False,
            contract_status="conforming",
            contract_evidence_verified=True,
        )
        batch = builder.build_from_run_manifest_only(manifest)
        assert batch.included_count == 1
        assert len(batch.observations) == 1
        assert batch.observations[0].outcome_value == 0
        assert batch.provenance_records[0].outcome_label == OutcomeLabel.NEGATIVE
        assert batch.provenance_records[0].outcome_label_source == "verified_contract_conformance"

    def test_violating_status_without_verified_evidence(self) -> None:
        """Requirement: contract_status='violating' without verified evidence

        (contract_evidence_verified=None or False) must produce OutcomeLabel.UNKNOWN.
        """
        builder = CausalObservationBuilder()

        # None evidence
        manifest_none = _build_manifest(
            run_id="run_violating_unverified_none",
            is_attack=True,
            contract_status="violating",
            contract_evidence_verified=None,
        )
        batch_none = builder.build_from_run_manifest_only(manifest_none)
        assert batch_none.included_count == 0
        assert batch_none.excluded_count == 1
        assert len(batch_none.observations) == 0
        assert batch_none.provenance_records[0].outcome_label == OutcomeLabel.UNKNOWN
        assert batch_none.provenance_records[0].outcome_label_source == "contract_unverified_violation"

        # False evidence
        manifest_false = _build_manifest(
            run_id="run_violating_unverified_false",
            is_attack=True,
            contract_status="violating",
            contract_evidence_verified=False,
        )
        batch_false = builder.build_from_run_manifest_only(manifest_false)
        assert batch_false.included_count == 0
        assert batch_false.excluded_count == 1
        assert batch_false.provenance_records[0].outcome_label == OutcomeLabel.UNKNOWN
        assert batch_false.provenance_records[0].outcome_label_source == "contract_unverified_violation"

    def test_missing_or_silent_contract_with_authoritative_resolution(self) -> None:
        """Requirement: Missing or silent contracts produce verified outcomes if

        a separate authoritative source (e.g. verified_contract_drift) explicitly resolves it.
        """
        builder = CausalObservationBuilder()

        # Missing contract status but verified_contract_drift=1
        manifest_drift_1 = _build_manifest(
            run_id="run_missing_but_drift_1",
            is_attack=True,
            contract_status="missing",
            verified_contract_drift=1,
        )
        batch1 = builder.build_from_run_manifest_only(manifest_drift_1)
        assert batch1.included_count == 1
        assert batch1.observations[0].outcome_value == 1
        assert batch1.provenance_records[0].outcome_label == OutcomeLabel.POSITIVE

        # Silent contract status but verified_contract_drift=0
        manifest_drift_0 = _build_manifest(
            run_id="run_silent_but_drift_0",
            is_attack=False,
            contract_status="silent",
            verified_contract_drift=0,
            contract_evidence_verified=True,
        )
        batch0 = builder.build_from_run_manifest_only(manifest_drift_0)
        assert batch0.included_count == 1
        assert batch0.observations[0].outcome_value == 0
        assert batch0.provenance_records[0].outcome_label == OutcomeLabel.NEGATIVE

    def test_missing_contract_preserves_unknown(self) -> None:
        """Requirement: If contract is missing, preserve Y_drift = unknown."""
        builder = CausalObservationBuilder()

        manifest = _build_manifest(
            run_id="run_missing_contract",
            is_attack=True,
            contract_status="missing",
        )
        batch = builder.build_from_run_manifest_only(manifest)
        assert batch.included_count == 0
        assert batch.excluded_count == 1
        assert len(batch.observations) == 0
        assert batch.provenance_records[0].outcome_label == OutcomeLabel.UNKNOWN
        assert batch.provenance_records[0].outcome_label_source == "contract_missing"
        assert batch.insufficiencies[0].reason_code == "unknown_outcome"

    def test_ambiguous_contract_rules_preserve_unknown(self) -> None:
        """Requirement: If contract rule is ambiguous, preserve Y_drift = unknown."""
        builder = CausalObservationBuilder()

        manifest = _build_manifest(
            run_id="run_ambiguous_contract",
            is_attack=True,
            contract_status="ambiguous",
        )
        batch = builder.build_from_run_manifest_only(manifest)
        assert batch.included_count == 0
        assert batch.excluded_count == 1
        assert batch.provenance_records[0].outcome_label == OutcomeLabel.UNKNOWN
        assert batch.provenance_records[0].outcome_label_source == "contract_ambiguous"
        assert batch.insufficiencies[0].reason_code == "unknown_outcome"

    def test_incomplete_or_silent_contract_preserves_unknown(self) -> None:
        """Requirement: If contract is incomplete or silent, preserve Y_drift = unknown."""
        builder = CausalObservationBuilder()

        # Incomplete contract
        manifest_inc = _build_manifest(
            run_id="run_incomplete",
            contract_status="incomplete",
        )
        batch_inc = builder.build_from_run_manifest_only(manifest_inc)
        assert batch_inc.included_count == 0
        assert batch_inc.provenance_records[0].outcome_label == OutcomeLabel.UNKNOWN
        assert batch_inc.provenance_records[0].outcome_label_source == "contract_incomplete"

        # Silent contract
        manifest_sil = _build_manifest(
            run_id="run_silent",
            contract_status="silent",
        )
        batch_sil = builder.build_from_run_manifest_only(manifest_sil)
        assert batch_sil.included_count == 0
        assert batch_sil.provenance_records[0].outcome_label == OutcomeLabel.UNKNOWN
        assert batch_sil.provenance_records[0].outcome_label_source == "contract_silent"

    def test_unverified_evidence_preserves_unknown(self) -> None:
        """Requirement: Even if marked conforming, if evidence is unverified (contract_evidence_verified=False),

        preserve Y_drift = unknown.
        """
        builder = CausalObservationBuilder()

        manifest = _build_manifest(
            run_id="run_unverified_evidence",
            contract_status="conforming",
            contract_evidence_verified=False,
        )
        batch = builder.build_from_run_manifest_only(manifest)
        assert batch.included_count == 0
        assert batch.provenance_records[0].outcome_label == OutcomeLabel.UNKNOWN
        assert batch.provenance_records[0].outcome_label_source == "contract_unverified_evidence"

    def test_no_ground_truth_inferred_from_phantom_alerts(self) -> None:
        """Requirement: Do NOT infer ground truth from PHANTOM alerts.

        A detector alert (Y_hat = 1, is_true_positive = True) without verified
        contract drift MUST NOT produce Y_drift = 1.
        """
        builder = CausalObservationBuilder()

        manifest = _build_manifest(
            run_id="run_alert_only",
            is_attack=True,
            first_phantom_detection_timestamp="2026-10-24T00:01:20Z",
            is_true_positive=True,  # detector alert fired and classified as TP by detector
            verified_contract_drift=None,  # No independent contract verification
            contract_status=None,
        )
        batch = builder.build_from_run_manifest_only(manifest)
        # Must abstain with UNKNOWN, excluded from observation set!
        assert batch.included_count == 0
        assert batch.excluded_count == 1
        assert len(batch.observations) == 0
        assert batch.provenance_records[0].outcome_label == OutcomeLabel.UNKNOWN
        assert batch.insufficiencies[0].reason_code == "unknown_outcome"

    def test_unverified_benign_run_preserves_unknown(self) -> None:
        """Requirement: Benign runs without contract verification must NOT be assumed

        negative (Y_drift = 0). They must preserve Y_drift = unknown.
        """
        builder = CausalObservationBuilder()

        manifest = _build_manifest(
            run_id="run_benign_unverified",
            is_attack=False,
            contract_status=None,
            verified_contract_drift=None,
        )
        batch = builder.build_from_run_manifest_only(manifest)
        assert batch.included_count == 0
        assert batch.excluded_count == 1
        assert batch.provenance_records[0].outcome_label == OutcomeLabel.UNKNOWN
