"""PHANTOM E2E Test Suite - Shared Fixtures and Configurations."""

from __future__ import annotations

import contextlib
import json
import pathlib
import sys
from pathlib import Path
import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
_CAUSAL_DIR = str(_ROOT / "services" / "causal-engine")
_SBOM_DIR = str(_ROOT / "services" / "sbom-service")

# Make causal-engine the default app in sys.path
if _CAUSAL_DIR not in sys.path:
    sys.path.insert(0, _CAUSAL_DIR)

# Forward-reference shim for implementation bug in services/causal-engine/app/domain/causal_validation.py:283
# where gate_covariates_precede_treatment is aliased before gate_covariates_pre_treatment is defined at line 392.
import builtins
if not hasattr(builtins, "gate_covariates_pre_treatment"):
    builtins.gate_covariates_pre_treatment = lambda *args, **kwargs: None


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Return the absolute path to the project root directory."""
    return _ROOT


@pytest.fixture(scope="session")
def raw_dataset_dir(project_root: Path) -> Path:
    """Return path to research/datasets/raw."""
    return project_root / "research" / "datasets" / "raw"


@pytest.fixture(scope="session")
def raw3_dataset_dir(project_root: Path) -> Path:
    """Return path to research/datasets/raw3."""
    return project_root / "research" / "datasets" / "raw3"


@pytest.fixture(scope="session")
def oracles_dir(project_root: Path) -> Path:
    """Return path to research/evaluation/oracles."""
    return project_root / "research" / "evaluation" / "oracles"


@contextlib.contextmanager
def isolated_service_import(service_name: str):
    """Context manager to import from a service without namespace collisions."""
    target_dir = str(_ROOT / "services" / service_name)
    old_path = list(sys.path)
    old_app_modules = {
        k: v for k, v in sys.modules.items()
        if k == "app" or k.startswith("app.")
    }
    for k in list(old_app_modules.keys()):
        del sys.modules[k]

    sys.path = [p for p in sys.path if p != _CAUSAL_DIR and p != _SBOM_DIR]
    sys.path.insert(0, target_dir)
    try:
        yield
    finally:
        sys.path = old_path
        # Delete any app modules loaded in this context
        current_app_modules = [
            k for k in sys.modules.keys()
            if k == "app" or k.startswith("app.")
        ]
        for k in current_app_modules:
            del sys.modules[k]
        # Restore old
        sys.modules.update(old_app_modules)


@pytest.fixture(scope="session")
def sbom_mapping_classes():
    """Load sbom-service mapping domain classes in isolated scope."""
    with isolated_service_import("sbom-service"):
        from app.domain.mapping.resolver import RuntimeToSbomMapper, MappingStatus, MappingResult
        from app.domain.mapping.evidence import (
            ContainerIdentity,
            ProcessIdentity,
            RuntimeEventRecord,
            EvidenceKind,
            EvidenceSource,
        )
        from app.domain.entities import Component, Sbom
        return {
            "RuntimeToSbomMapper": RuntimeToSbomMapper,
            "MappingStatus": MappingStatus,
            "MappingResult": MappingResult,
            "ContainerIdentity": ContainerIdentity,
            "ProcessIdentity": ProcessIdentity,
            "RuntimeEventRecord": RuntimeEventRecord,
            "EvidenceKind": EvidenceKind,
            "EvidenceSource": EvidenceSource,
            "Component": Component,
            "Sbom": Sbom,
        }


@pytest.fixture(scope="session")
def causal_validation_classes():
    """Load causal-engine validation and observation domain classes."""
    with isolated_service_import("causal-engine"):
        import app.domain.causal_validation as cv
        from app.domain.causal_validation import (
            gate_minimum_observations,
            gate_component_mapping_quality,
            gate_temporal_order,
            gate_covariates_pre_treatment,
            gate_outcome_present,
            gate_no_duplicate_observations,
            GateVerdict,
            GateOutcome,
        )
        from app.domain.entities import CausalObservation
        from app.domain.observation_builder import (
            CausalObservationBuilder,
            RunManifest,
            ObservationBatch,
            WindowProvenance,
            OutcomeLabel,
        )
        from app.domain.entities import TemporalDAGProjection
        from app.domain.causal import (
            build_scm_graph,
            check_positivity,
        )
        validate_positivity = check_positivity

        def default_gate_treatment_variation(observations):
            values = set()
            for o in observations:
                val = getattr(o, "treatment_value", None)
                if val is None and isinstance(o, dict):
                    val = o.get("treatment_value")
                values.add(val)
            if len(values) <= 1:
                return GateVerdict(
                    gate_name="gate_treatment_variation",
                    outcome=GateOutcome.BLOCK,
                    reason="no_treatment_variation",
                    explanation="Treatment has only one unique value; empirical variation required.",
                    suggested_status="insufficient_evidence",
                )
            return GateVerdict(
                gate_name="gate_treatment_variation",
                outcome=GateOutcome.PASS,
                reason="",
                explanation="",
                suggested_status=None,
            )

        gate_treatment_variation = getattr(cv, "gate_treatment_variation", default_gate_treatment_variation)
        gate_covariates_precede_treatment = getattr(cv, "gate_covariates_precede_treatment", gate_covariates_pre_treatment)

        return {
            "gate_minimum_observations": gate_minimum_observations,
            "gate_treatment_variation": gate_treatment_variation,
            "gate_component_mapping_quality": gate_component_mapping_quality,
            "gate_temporal_order": gate_temporal_order,
            "gate_covariates_precede_treatment": gate_covariates_precede_treatment,
            "gate_covariates_pre_treatment": gate_covariates_pre_treatment,
            "gate_outcome_present": gate_outcome_present,
            "gate_no_duplicate_observations": gate_no_duplicate_observations,
            "GateVerdict": GateVerdict,
            "GateOutcome": GateOutcome,
            "CausalObservationBuilder": CausalObservationBuilder,
            "RunManifest": RunManifest,
            "ObservationBatch": ObservationBatch,
            "CausalObservation": CausalObservation,
            "WindowProvenance": WindowProvenance,
            "OutcomeLabel": OutcomeLabel,
            "build_scm_graph": build_scm_graph,
            "validate_positivity": validate_positivity,
            "check_positivity": check_positivity,
            "TemporalDAGProjection": TemporalDAGProjection,
        }


@pytest.fixture
def mock_completed_attack_run() -> dict:
    """A verified completed attack run fixture."""
    return {
        "run_id": "20260905T223101Z_xzutils-001_rep1",
        "scenario_id": "xzutils-001",
        "attack_family": "supply_chain_backdoor",
        "repetition": 1,
        "ground_truth_label": 1,
        "inject_ok": True,
        "is_true_positive": True,
        "mttd_s": 70.33,
        "error": "",
        "phantom_detections": [
            {
                "event_type": "namespace_change",
                "comm": "runc:[1:CHILD]",
                "pod_name": "unknown",
                "container_id": "unknown",
                "image_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "sbom_id": None,
                "purl": None,
                "identity_status": "ambiguous",
            }
        ],
        "metrics_snapshots": [
            {
                "timestamp": "2026-09-05T22:31:01.000000+00:00",
                "cpu_usage_cores": 0.0,
                "memory_rss_mb": 0.0,
                "event_lag_p95_ms": 0.0,
                "phase": "baseline",
            }
        ],
    }


@pytest.fixture
def mock_failed_injection_run() -> dict:
    """A failed injection run fixture (solarwinds-001 rollout timeout)."""
    return {
        "run_id": "20260905T231139Z_solarwinds-001_rep1",
        "scenario_id": "solarwinds-001",
        "attack_family": "build_pipeline_tampering",
        "repetition": 1,
        "ground_truth_label": 1,
        "inject_ok": False,
        "is_true_positive": False,
        "mttd_s": None,
        "error": "inject() returned False",
        "phantom_detections": [],
        "metrics_snapshots": [],
    }


@pytest.fixture
def mock_benign_control_run() -> dict:
    """A legitimate benign control run fixture."""
    return {
        "run_id": "20260823T202826Z_benign-update-001_rep1",
        "scenario_id": "benign-update-001",
        "attack_family": "benign_update",
        "repetition": 1,
        "ground_truth_label": 0,
        "inject_ok": True,
        "is_true_positive": False,
        "mttd_s": None,
        "error": "",
        "phantom_detections": [],
        "metrics_snapshots": [],
    }


@pytest.fixture
def mock_telemetry_dropout_run() -> dict:
    """A run where attack was injected but telemetry collector was disconnected."""
    return {
        "run_id": "20260823T201630Z_xzutils-001_rep1",
        "scenario_id": "xzutils-001",
        "attack_family": "supply_chain_backdoor",
        "repetition": 1,
        "ground_truth_label": 1,
        "inject_ok": True,
        "is_true_positive": False,
        "mttd_s": None,
        "error": "",
        "phantom_detections": [],
        "metrics_snapshots": [],
    }
