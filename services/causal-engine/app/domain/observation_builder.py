"""
services/causal-engine/app/domain/observation_builder.py

CausalObservation builder: bridge between the Behavioral Dependency Graph
(BDG) evidence and the Part 4 causal-validation interface.

This module implements the missing bridge identified in the Part 5 audit
(Blocker 1). It converts run-level manifest data and BDG graph state into
``CausalObservation`` rows that can be consumed by
``estimate_causal_attribution()``.

Design contract (matches Part 5 §Step 3):
  - Observations are produced ONLY from fields that genuinely exist in the
    upstream evidence. No fields are fabricated.
  - Each observation retains its full provenance: run ID, window boundaries,
    mapping status, evidence IDs, drift result, and outcome value.
  - Outcome values are carefully discriminated:
      POSITIVE (1): A drift event was observed in this window.
      NEGATIVE (0): No drift event was observed AND coverage evidence
                    supports that claim (i.e. observation_count > 0,
                    no loss reported).
      UNKNOWN: No outcome label can be assigned (null detections, no
               coverage evidence, or run did not complete).
      INCOMPLETE_RUN: The run phase did not complete or inject failed.
      FAILED_INJECTION: Injection was attempted but inject_ok=False.
  - Missing outcomes are NOT converted to NEGATIVE labels.
  - Absence of a recorded event is only treated as NEGATIVE when
    collection coverage evidence supports it.
  - If insufficient evidence prevents building a valid observation, the
    builder emits a structured ``BuilderInsufficiency`` result, never a
    silent exclusion.
  - The unit of analysis is explicit: a time window within an experiment
    run, not an event, container, or run.

IMPORTANT — what this module does NOT claim:
  - Observations from synthetic fixtures do not establish causal accuracy.
  - A valid observation set does not prove the causal estimate is correct.
  - ``outcome_value == 0`` is NOT equivalent to "the attack failed".
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any


# ---------------------------------------------------------------------------
# Outcome label vocabulary
# ---------------------------------------------------------------------------


class OutcomeLabel(str, Enum):
    """Per-window outcome classification.

    Members:
        POSITIVE: Drift event observed in this window (outcome_value = 1).
        NEGATIVE: No drift event observed; collection coverage supports
            the negative interpretation (outcome_value = 0).
        UNKNOWN: Outcome cannot be determined from available evidence.
        INCOMPLETE_RUN: The run did not reach the point where this
            window's outcome could be determined.
        FAILED_INJECTION: The intervention was attempted but the inject
            phase reported inject_ok=False. Cannot attribute outcome to
            the intervention.
    """

    POSITIVE = "positive"
    NEGATIVE = "negative"
    UNKNOWN = "unknown"
    INCOMPLETE_RUN = "incomplete_run"
    FAILED_INJECTION = "failed_injection"


# ---------------------------------------------------------------------------
# Observation provenance
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WindowProvenance:
    """Full provenance record for one causal observation window.

    Attributes:
        run_id: Stable experiment run identifier.
        scenario_id: Scenario / attack identifier.
        window_index: Zero-based time-window index within the run.
        window_start_iso: ISO 8601 UTC start timestamp of this window.
        window_end_iso: ISO 8601 UTC end timestamp of this window.
        event_count: Number of raw eBPF events in this window.
        mapping_statuses: MappingStatus value strings for events
            contributing to the treatment column. Empty if not available.
        evidence_ids: UUIDs of RuntimeEventRecords or BDG evidence refs
            contributing to the treatment node. Empty if not available.
        drift_outcome: DriftOutcome string from the decider
            (``"drift"`` / ``"no_drift"`` / ``"insufficient_evidence"``).
            Empty string if drift was not evaluated for this window.
        drift_score: KL-divergence score from the drift decider.
            None if not evaluated.
        outcome_label: OutcomeLabel for this window.
        outcome_label_source: How the outcome label was assigned
            (e.g. ``"drift_decider"``, ``"run_manifest"``, ``"synthetic"``).
        missing_fields: List of fields that could not be populated,
            with their reasons.
        exclusion_reason: Non-empty if this window is excluded from the
            observation set, explaining why.
    """

    run_id: str
    scenario_id: str
    window_index: int
    window_start_iso: str
    window_end_iso: str
    event_count: int = 0
    mapping_statuses: tuple[str, ...] = field(default_factory=tuple)
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    drift_outcome: str = ""
    drift_score: Optional[float] = None
    outcome_label: OutcomeLabel = OutcomeLabel.UNKNOWN
    outcome_label_source: str = "unknown"
    missing_fields: tuple[str, ...] = field(default_factory=tuple)
    exclusion_reason: str = ""
    window_id: str = ""
    event_refs: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.window_id and self.run_id:
            object.__setattr__(self, "window_id", f"{self.run_id}_w{self.window_index}")
        if not self.event_refs and self.evidence_ids:
            object.__setattr__(self, "event_refs", self.evidence_ids)


@dataclass(frozen=True)
class ObservationRecord:
    """Rich causal observation schema associating every observation with stable
    run_id, window_id, immutable event references, and full provenance.

    Decouples T_inject (external scenario intervention) from T_purl (component
    software substitution) and records independent ground-truth drift (Y_drift)
    separately from detector alerts (Y_hat_phantom).

    Attributes:
        run_id: Stable experiment run identifier.
        window_id: Stable window identifier within the run (e.g., 'run_01_w0').
        window_index: Integer time window index.
        t_inject: External attack scenario injection intervention flag (T_inject in {0, 1}).
        t_purl: Component-level software substitution treatment flag (T_purl in {0, 1}).
        treatment_value: Value of the active treatment variable for estimation.
        outcome_value: Verified ground-truth contract drift outcome (Y_drift in {0, 1, None}).
        y_hat_phantom: PHANTOM detection alert indicator (Y_hat in {0, 1, None}).
        pre_treatment_covariates: Strictly Tier 0 pre-treatment confounders.
        event_refs: Tuple of immutable event UUIDs or hashes contributing evidence.
        provenance: Associated WindowProvenance instance.
    """

    run_id: str
    window_id: str
    window_index: int
    t_inject: int
    t_purl: int
    treatment_value: int
    outcome_value: Optional[int]
    y_hat_phantom: Optional[int] = None
    pre_treatment_covariates: dict[str, float] = field(default_factory=dict)
    event_refs: tuple[str, ...] = field(default_factory=tuple)
    provenance: Optional[WindowProvenance] = None


# ---------------------------------------------------------------------------
# Builder result
# ---------------------------------------------------------------------------


@dataclass
class BuilderInsufficiency:
    """Structured result when a valid observation cannot be built.

    Attributes:
        run_id: The run for which building failed.
        reason_code: Machine-readable reason (snake_case).
        explanation: Human-readable explanation.
        missing_fields: Fields that were absent or invalid.
    """

    run_id: str
    reason_code: str
    explanation: str
    missing_fields: list[str] = field(default_factory=list)


@dataclass
class ObservationBatch:
    """Result of building causal observations for one run or window set.

    Attributes:
        run_id: Experiment run identifier.
        observations: Valid CausalObservation rows (may be empty).
        observation_records: Rich ObservationRecord instances with stable
            IDs, event references, decoupled treatments, and provenance.
        provenance_records: WindowProvenance for each observation.
        insufficiencies: Structured insufficiency results for excluded
            windows or the run as a whole.
        treatment_mapping_statuses: All mapping status strings across
            the batch (for Part 4 gate G2).
        treatment_evidence_ids: All evidence UUID strings across the batch.
        excluded_count: Number of windows excluded with documented reason.
        included_count: Number of windows included as observations.
    """

    run_id: str
    observations: list[Any] = field(default_factory=list)  # list[CausalObservation]
    observation_records: list[ObservationRecord] = field(default_factory=list)
    provenance_records: list[WindowProvenance] = field(default_factory=list)
    insufficiencies: list[BuilderInsufficiency] = field(default_factory=list)
    treatment_mapping_statuses: list[str] = field(default_factory=list)
    treatment_evidence_ids: list[uuid.UUID] = field(default_factory=list)
    excluded_count: int = 0
    included_count: int = 0

    @property
    def can_proceed_to_estimation(self) -> bool:
        """True only when at least the minimum observation count is available."""
        return self.included_count >= _MINIMUM_OBSERVATIONS

    @property
    def has_valid_outcome_labels(self) -> bool:
        """True when at least one observation has a positive or negative label."""
        for p in self.provenance_records:
            if p.outcome_label in (OutcomeLabel.POSITIVE, OutcomeLabel.NEGATIVE):
                return True
        return False


_MINIMUM_OBSERVATIONS: int = 10


# ---------------------------------------------------------------------------
# Run manifest schema
# ---------------------------------------------------------------------------


@dataclass
class RunManifestPhase:
    """One phase record from a raw experiment run JSON.

    Attributes:
        name: Phase name (``"baseline"``, ``"inject"``, ``"attack"``,
              ``"recover"``, ``"post_recovery"``).
        start_time: ISO 8601 UTC start timestamp string.
        end_time: ISO 8601 UTC end timestamp string.
        duration_s: Duration in seconds.
        notes: Free-text notes (may contain ``"inject_ok=True"``).
    """

    name: str
    start_time: str
    end_time: str
    duration_s: float
    notes: str = ""

    @property
    def inject_ok(self) -> Optional[bool]:
        """Parse inject_ok flag from notes, or None if not applicable."""
        if "inject_ok=True" in self.notes:
            return True
        if "inject_ok=False" in self.notes:
            return False
        return None

    @property
    def recover_ok(self) -> Optional[bool]:
        """Parse recover_ok flag from notes, or None if not applicable."""
        if "recover_ok=True" in self.notes:
            return True
        if "recover_ok=False" in self.notes:
            return False
        return None


@dataclass
class RunManifest:
    """Parsed representation of a raw experiment run JSON record.

    Attributes:
        run_id: Stable run identifier.
        attack_id: Scenario identifier.
        attack_family: Attack family string.
        repetition: Repetition number.
        namespace: Kubernetes namespace.
        pod_name: Pod name.
        ground_truth_label: 1 for attack, 0 for benign.
        injection_timestamp: ISO 8601 injection time (may be None for benign).
        first_phantom_detection_timestamp: ISO 8601 detection time (may be None).
        mttd_s: Mean time to detect in seconds (may be None).
        is_true_positive: Whether PHANTOM detected the attack.
        phases: List of run phase records.
        phantom_detections: List of raw detection records (may be empty).
        target_purl: SBOM PURL of the target component (may be empty).
        clean_purl: SBOM PURL of the clean component.
        detection_window_s: Detection window in seconds.
        error: Error string if the run failed.
    """

    run_id: str
    attack_id: str
    attack_family: str
    repetition: int
    namespace: str
    pod_name: str
    ground_truth_label: int
    injection_timestamp: Optional[str]
    first_phantom_detection_timestamp: Optional[str]
    mttd_s: Optional[float]
    is_true_positive: bool
    phases: list[RunManifestPhase] = field(default_factory=list)
    phantom_detections: list[dict[str, Any]] = field(default_factory=list)
    target_purl: str = ""
    clean_purl: str = ""
    detection_window_s: float = 120.0
    error: str = ""
    verified_contract_drift: Optional[int] = None
    contract_status: Optional[str] = None
    contract_evidence_verified: Optional[bool] = None
    sink_receipt_verified: Optional[bool] = None
    pre_treatment_covariates: dict[str, float] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RunManifest:
        """Parse a run manifest from the raw JSON dict.

        Args:
            d: Raw dict loaded from the JSON experiment record.

        Returns:
            Parsed RunManifest.
        """
        phases = [
            RunManifestPhase(
                name=p["name"],
                start_time=p["start_time"],
                end_time=p["end_time"],
                duration_s=p["duration_s"],
                notes=p.get("notes", ""),
            )
            for p in d.get("phases", [])
        ]
        sl = d.get("scenario_label", {})
        return cls(
            run_id=d["run_id"],
            attack_id=d.get("attack_id", ""),
            attack_family=d.get("attack_family", ""),
            repetition=d.get("repetition", 1),
            namespace=d.get("namespace", ""),
            pod_name=d.get("pod_name", ""),
            ground_truth_label=d.get("ground_truth_label", 0),
            injection_timestamp=d.get("injection_timestamp"),
            first_phantom_detection_timestamp=d.get("first_phantom_detection_timestamp"),
            mttd_s=d.get("mttd_s"),
            is_true_positive=d.get("is_true_positive", False),
            phases=phases,
            phantom_detections=d.get("phantom_detections", []),
            target_purl=sl.get("target_purl", ""),
            clean_purl=sl.get("clean_purl", ""),
            detection_window_s=sl.get("detection_window_s", 120.0),
            error=d.get("error", ""),
            verified_contract_drift=d.get("verified_contract_drift"),
            contract_status=d.get("contract_status"),
            contract_evidence_verified=d.get("contract_evidence_verified"),
            sink_receipt_verified=d.get("sink_receipt_verified"),
            pre_treatment_covariates=d.get("pre_treatment_covariates", {}),
        )

    @property
    def is_attack_run(self) -> bool:
        """True when this is an attack (ground_truth_label == 1) run."""
        return self.ground_truth_label == 1

    @property
    def injection_succeeded(self) -> Optional[bool]:
        """True if inject phase succeeded, False if failed, None if no inject phase."""
        for ph in self.phases:
            if ph.name == "inject":
                return ph.inject_ok
        return None

    @property
    def run_completed(self) -> bool:
        """True when the run has no error and has all expected phases."""
        return self.error == "" and len(self.phases) >= 4


# ---------------------------------------------------------------------------
# CausalObservationBuilder
# ---------------------------------------------------------------------------


class CausalObservationBuilder:
    """Builds CausalObservation rows from BDG evidence and run manifests.

    Implements the missing bridge identified in the Part 5 audit.
    Observations are built from genuine evidence only.

    Per the Part 5 design contract:
    - Missing outcomes are NOT converted to negative labels.
    - Absence of a recorded event is only negative when coverage supports it.
    - The builder never synthesizes missing data.
    - If evidence is insufficient, a BuilderInsufficiency is returned.

    Args:
        minimum_observations: Minimum observation count for the output
            batch to be considered adequate for estimation.
    """

    def __init__(self, minimum_observations: int = _MINIMUM_OBSERVATIONS) -> None:
        """Initialise the builder.

        Args:
            minimum_observations: Minimum observations needed to proceed.
        """
        self._minimum = minimum_observations

    def build_from_run_manifest_only(
        self,
        manifest: RunManifest,
        bdg_node_data: Optional[list[dict[str, Any]]] = None,
        treatment_target: str = "purl",
    ) -> ObservationBatch:
        """Build an ObservationBatch from a run manifest and optional BDG data.

        This is the only currently supported build path. A per-window BDG-based
        builder would require the BDG to produce per-window snapshots aligned
        with the run timeline — functionality that does not yet exist.

        The current implementation can produce AT MOST ONE observation per run
        (using the run-level outcome label), which is below ``minimum_observations``
        (default 10). The batch will therefore have
        ``can_proceed_to_estimation == False`` for every real run.

        This is the honest, documented outcome of the audit finding that
        per-window outcome labels do not exist in the current dataset.

        Args:
            manifest: Parsed RunManifest for the run.
            bdg_node_data: Optional list of BDG node attribute dicts. Used
                to populate mapping_statuses and evidence_ids if available.
            treatment_target: Target estimand treatment: "purl" (component) or "inject".

        Returns:
            ObservationBatch with observations (if buildable), insufficiencies,
            and full provenance.
        """
        batch = ObservationBatch(run_id=manifest.run_id)
        missing: list[str] = []

        # --- Determine run-level outcome label ---
        outcome_label, label_source = self._classify_run_outcome(manifest)

        # --- Check for failed injection ---
        if outcome_label == OutcomeLabel.FAILED_INJECTION:
            batch.insufficiencies.append(BuilderInsufficiency(
                run_id=manifest.run_id,
                reason_code="failed_injection",
                explanation=(
                    f"Run '{manifest.run_id}': The inject phase reported "
                    "inject_ok=False. The intervention was attempted but did "
                    "not succeed. This run cannot be treated as a completed "
                    "attack outcome."
                ),
                missing_fields=["inject_ok"],
            ))
            batch.excluded_count += 1
            return batch

        # --- Check for incomplete run ---
        if not manifest.run_completed:
            batch.insufficiencies.append(BuilderInsufficiency(
                run_id=manifest.run_id,
                reason_code="incomplete_run",
                explanation=(
                    f"Run '{manifest.run_id}': The run did not complete "
                    f"(error='{manifest.error}' or missing phases). "
                    "Cannot determine outcome."
                ),
                missing_fields=["phases", "error"],
            ))
            batch.excluded_count += 1
            return batch

        # --- Extract mapping provenance from BDG node data if available ---
        mapping_statuses: list[str] = []
        evidence_ids_str: list[str] = []
        if bdg_node_data:
            for node in bdg_node_data:
                if node.get("node_type") == "purl":
                    ms = node.get("mapping_status")
                    if ms:
                        mapping_statuses.append(ms)
                    for eid in node.get("evidence_refs", []):
                        evidence_ids_str.append(str(eid))
        else:
            missing.append(
                "mapping_statuses: BDG node data not supplied; "
                "mapping provenance unavailable"
            )
            missing.append(
                "evidence_ids: BDG node data not supplied; "
                "evidence IDs unavailable"
            )

        # --- Decouple T_inject and T_purl ---
        # Dimension 1: Intervention delivery (T_inject in {0, 1})
        t_inject = 1 if (manifest.is_attack_run and manifest.injection_succeeded is True) else 0

        # Component software attribution (T_purl in {0, 1})
        t_purl = 1 if manifest.is_attack_run else 0

        # Active treatment variable selected for causal estimation
        if treatment_target == "inject":
            treatment_value = t_inject
        else:
            treatment_value = t_purl

        # Dimension 4: PHANTOM detection alert indicator (Y_hat in {0, 1})
        y_hat_phantom = 1 if manifest.first_phantom_detection_timestamp is not None else 0

        # --- Determine outcome value ---
        # outcome_value is set to 1 only when verified contract drift occurred.
        # Detector alerts alone do NOT constitute ground-truth drift.
        outcome_value, outcome_note = self._classify_outcome_value(
            manifest, outcome_label
        )

        # Always record mapping statuses and evidence IDs on the batch for provenance
        batch.treatment_mapping_statuses.extend(mapping_statuses)
        for eid in evidence_ids_str:
            try:
                batch.treatment_evidence_ids.append(uuid.UUID(eid))
            except (ValueError, AttributeError):
                pass

        if outcome_value is None:
            # Cannot build an observation without an outcome value.
            batch.insufficiencies.append(BuilderInsufficiency(
                run_id=manifest.run_id,
                reason_code="unknown_outcome",
                explanation=(
                    f"Run '{manifest.run_id}': Outcome cannot be determined. "
                    f"{outcome_note} "
                    "Per-window drift labels are not available in the current "
                    "dataset. The observation cannot be constructed without "
                    "fabricating a label."
                ),
                missing_fields=["runtime_sbom_drift", "verified_contract_drift"],
            ))
            batch.excluded_count += 1

            # Still record provenance for the report.
            prov = WindowProvenance(
                run_id=manifest.run_id,
                scenario_id=manifest.attack_id,
                window_index=0,
                window_start_iso=self._phase_start(manifest, "baseline"),
                window_end_iso=self._phase_end(manifest, "post_recovery"),
                event_count=0,
                mapping_statuses=tuple(mapping_statuses),
                evidence_ids=tuple(evidence_ids_str),
                drift_outcome="",
                drift_score=None,
                outcome_label=outcome_label,
                outcome_label_source=label_source,
                missing_fields=tuple(missing),
                exclusion_reason="unknown_outcome",
                window_id=f"{manifest.run_id}_w0",
                event_refs=tuple(evidence_ids_str),
            )
            batch.provenance_records.append(prov)
            return batch

        # --- Build the single run-level observation ---
        # Import here to avoid circular imports at module load time.
        from app.domain.entities import CausalObservation  # noqa: PLC0415

        # Pre-treatment covariates: strictly Tier 0 pre-treatment confounders only.
        # Post-treatment execution artifacts (such as run_duration_s, intermediate
        # process spawns, or detection alerts) MUST NOT be conditioned on as confounders.
        pre_treatment_covs: dict[str, float] = {}
        if manifest.pre_treatment_covariates:
            pre_treatment_covs.update(manifest.pre_treatment_covariates)
        else:
            pre_treatment_covs["repetition"] = float(manifest.repetition)

        obs = CausalObservation(
            window_index=0,
            treatment_value=treatment_value,
            outcome_value=outcome_value,
            covariates=pre_treatment_covs,
        )

        # Attach rich provenance & decoupled treatment attributes to observation
        setattr(obs, "run_id", manifest.run_id)
        setattr(obs, "window_id", f"{manifest.run_id}_w0")
        setattr(obs, "t_inject", t_inject)
        setattr(obs, "t_purl", t_purl)
        setattr(obs, "y_hat_phantom", y_hat_phantom)
        setattr(obs, "event_refs", tuple(evidence_ids_str))

        prov = WindowProvenance(
            run_id=manifest.run_id,
            scenario_id=manifest.attack_id,
            window_index=0,
            window_start_iso=self._phase_start(manifest, "baseline"),
            window_end_iso=self._phase_end(manifest, "post_recovery"),
            event_count=0,
            mapping_statuses=tuple(mapping_statuses),
            evidence_ids=tuple(evidence_ids_str),
            drift_outcome="",
            drift_score=None,
            outcome_label=outcome_label,
            outcome_label_source=label_source,
            missing_fields=tuple(missing),
            exclusion_reason="",
            window_id=f"{manifest.run_id}_w0",
            event_refs=tuple(evidence_ids_str),
        )
        setattr(obs, "provenance", prov)

        obs_record = ObservationRecord(
            run_id=manifest.run_id,
            window_id=f"{manifest.run_id}_w0",
            window_index=0,
            t_inject=t_inject,
            t_purl=t_purl,
            treatment_value=treatment_value,
            outcome_value=outcome_value,
            y_hat_phantom=y_hat_phantom,
            pre_treatment_covariates=pre_treatment_covs,
            event_refs=tuple(evidence_ids_str),
            provenance=prov,
        )

        batch.observations.append(obs)
        batch.observation_records.append(obs_record)
        batch.provenance_records.append(prov)
        batch.included_count += 1

        # Warn: one observation per run is always below minimum_observations.
        if batch.included_count < self._minimum:
            batch.insufficiencies.append(BuilderInsufficiency(
                run_id=manifest.run_id,
                reason_code="too_few_observations",
                explanation=(
                    f"Run '{manifest.run_id}': Only {batch.included_count} "
                    f"observation(s) built; minimum required is {self._minimum}. "
                    "The current dataset provides at most one run-level "
                    "observation per experiment run. Per-window drift labels "
                    "are required to build a valid causal observation set."
                ),
                missing_fields=["per_window_drift_labels"],
            ))

        return batch

    def build_from_run_batch(
        self,
        manifests: list[RunManifest],
        treatment_target: str = "purl",
    ) -> ObservationBatch:
        """Build an ObservationBatch from a list of run manifests.

        Combines one observation per run (where buildable) into a single
        batch. This is the multi-run aggregation path.

        The resulting batch will only satisfy ``can_proceed_to_estimation``
        when at least ``minimum_observations`` valid observations are included.

        Args:
            manifests: List of parsed run manifests.
            treatment_target: Target estimand treatment: "purl" (component) or "inject".

        Returns:
            Combined ObservationBatch.
        """
        combined = ObservationBatch(run_id="<multi-run>")
        for manifest in manifests:
            single = self.build_from_run_manifest_only(
                manifest, treatment_target=treatment_target
            )
            combined.observations.extend(single.observations)
            combined.observation_records.extend(single.observation_records)
            combined.provenance_records.extend(single.provenance_records)
            combined.insufficiencies.extend(single.insufficiencies)
            combined.treatment_mapping_statuses.extend(
                single.treatment_mapping_statuses
            )
            combined.treatment_evidence_ids.extend(
                single.treatment_evidence_ids
            )
            combined.excluded_count += single.excluded_count
            combined.included_count += single.included_count
        return combined

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    def _classify_run_outcome(
        self,
        manifest: RunManifest,
    ) -> tuple[OutcomeLabel, str]:
        """Determine the run-level outcome label and its source.

        Strictly derives ground-truth drift (Y_drift) from independent oracle
        verification and signed contract conformance, NEVER from PHANTOM detection
        alerts (Y_hat_phantom).

        Labeling Rules:
        - Y_drift = 0 only when the applicable contract and independent evidence
          establish that observed behavior conforms to the allowed behavior.
        - Y_drift = 1 only when verified behavior violates an applicable contract rule.
        - If the contract is missing, ambiguous, incomplete, or silent about behavior
          that cannot otherwise be established as authorized, preserve Y_drift = unknown.
        - Do NOT infer ground truth from PHANTOM alerts.

        Returns:
            Tuple of (OutcomeLabel, source_string).
        """
        # Failed injection: cannot be treated as completed attack.
        if manifest.is_attack_run and manifest.injection_succeeded is False:
            return OutcomeLabel.FAILED_INJECTION, "inject_phase_notes"

        # Explicit contract rule status evaluation:
        # Check if contract is missing, ambiguous, incomplete, or silent.
        if manifest.contract_status is not None:
            status_norm = manifest.contract_status.strip().lower()
            if status_norm in ("missing", "ambiguous", "incomplete", "silent"):
                # Missing, ambiguous, incomplete, or silent contracts remain unknown
                # unless another authoritative source explicitly resolves the outcome.
                if manifest.verified_contract_drift == 1:
                    return OutcomeLabel.POSITIVE, "verified_contract_drift"
                elif manifest.verified_contract_drift == 0 and manifest.contract_evidence_verified is not False:
                    return OutcomeLabel.NEGATIVE, "verified_contract_drift"
                return OutcomeLabel.UNKNOWN, f"contract_{status_norm}"

            if status_norm in ("violating", "violation", "prohibited"):
                # contract_status="violating" must produce Y_drift=1 only when the violation
                # is independently verified against an applicable contract rule.
                if manifest.contract_evidence_verified is True or manifest.verified_contract_drift == 1:
                    return OutcomeLabel.POSITIVE, "verified_contract_violation"
                return OutcomeLabel.UNKNOWN, "contract_unverified_violation"

            if status_norm in ("conforming", "conformance", "allowed"):
                # contract_status="conforming" produces Y_drift=0 only when contract_evidence_verified is True,
                # with the applicable contract and independent behavior evidence actually available.
                # contract_evidence_verified=None or False must produce OutcomeLabel.UNKNOWN
                # unless a separate, explicitly verified evidence field independently establishes the outcome.
                if manifest.contract_evidence_verified is True:
                    return OutcomeLabel.NEGATIVE, "verified_contract_conformance"
                if manifest.verified_contract_drift == 0:
                    return OutcomeLabel.NEGATIVE, "verified_contract_drift"
                if manifest.verified_contract_drift == 1:
                    return OutcomeLabel.POSITIVE, "verified_contract_drift"
                return OutcomeLabel.UNKNOWN, "contract_unverified_evidence"

        # Independent oracle verified contract drift (separate authoritative source):
        if manifest.verified_contract_drift is not None:
            if manifest.verified_contract_drift == 1:
                return OutcomeLabel.POSITIVE, "verified_contract_drift"
            elif manifest.verified_contract_drift == 0:
                if manifest.contract_evidence_verified is False:
                    return OutcomeLabel.UNKNOWN, "contract_unverified_evidence"
                return OutcomeLabel.NEGATIVE, "verified_contract_drift"

        # If contract and independent evidence do not establish conformance or violation,
        # preserve Y_drift = unknown. Never infer ground truth from PHANTOM alerts
        # or automatically assume unverified benign runs are negative.
        return OutcomeLabel.UNKNOWN, "unverified_drift_telemetry"

    def _classify_outcome_value(
        self,
        manifest: RunManifest,
        outcome_label: OutcomeLabel,
    ) -> tuple[Optional[int], str]:
        """Convert an OutcomeLabel to a binary outcome_value for CausalObservation.

        Returns:
            Tuple of (outcome_value or None, reason_note).
        """
        if outcome_label == OutcomeLabel.POSITIVE:
            return 1, "Verified contract drift/violation confirmed by independent evidence"
        if outcome_label == OutcomeLabel.NEGATIVE:
            return 0, "Verified contract conformance confirmed by applicable contract and evidence"
        if outcome_label == OutcomeLabel.FAILED_INJECTION:
            return None, "Injection failed; outcome is undefined"
        if outcome_label == OutcomeLabel.INCOMPLETE_RUN:
            return None, "Run incomplete; outcome is undefined"
        # UNKNOWN
        return (
            None,
            "Contract missing, ambiguous, incomplete, or unverified; outcome is unknown. "
            "Cannot attribute causal effect without ground-truth labels.",
        )

    @staticmethod
    def _phase_start(manifest: RunManifest, name: str) -> str:
        """Return the start_time of the named phase, or empty string."""
        for ph in manifest.phases:
            if ph.name == name:
                return ph.start_time
        return ""

    @staticmethod
    def _phase_end(manifest: RunManifest, name: str) -> str:
        """Return the end_time of the named phase, or empty string."""
        for ph in manifest.phases:
            if ph.name == name:
                return ph.end_time
        return ""

    @staticmethod
    def _run_duration(manifest: RunManifest) -> float:
        """Total run duration in seconds across all phases."""
        return sum(ph.duration_s for ph in manifest.phases)

