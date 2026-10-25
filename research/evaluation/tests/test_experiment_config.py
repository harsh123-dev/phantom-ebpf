"""Configuration source-of-truth tests; all inputs are local and synthetic."""

from pathlib import Path

from research.evaluation.scenarios.config import (
    DEFAULT_CONFIG_PATH,
    load_experiment_config,
    resolve_batch_output,
    scenario_ids,
)
from research.evaluation.scenarios.run_all_scenarios import (
    EXTENDED_SCENARIO_IDS,
    PILOT_SCENARIO_IDS,
)


def test_config_drives_pilot_and_extended_runner_profiles():
    config = load_experiment_config(DEFAULT_CONFIG_PATH)
    assert scenario_ids(config, "pilot") == (
        "xzutils-001", "dep-confusion-001", "solarwinds-001",
        "benign-update-001", "benign-load-001", "benign-restart-001",
    )
    assert len(scenario_ids(config, "pilot")) * config["repetitions"] == 18
    assert len(scenario_ids(config, "extended")) * config["repetitions"] == 27
    assert PILOT_SCENARIO_IDS == scenario_ids(config, "pilot")
    assert EXTENDED_SCENARIO_IDS == scenario_ids(config, "extended")


def test_config_has_matched_targets_and_safe_output_root():
    config = load_experiment_config()
    scenarios = config["_scenario_by_id"]
    assert scenarios["xzutils-001"]["target_service"] == scenarios["benign-update-001"]["target_service"]
    assert scenarios["dep-confusion-001"]["target_service"] == scenarios["benign-load-001"]["target_service"]
    assert scenarios["solarwinds-001"]["target_service"] == scenarios["benign-restart-001"]["target_service"]
    assert config["raw_output_dir"] == "research/datasets/pilot_batch01"
    assert Path(config["raw_output_dir"]).name not in {"raw", "raw3"}


def test_output_resolution_is_unique_and_protects_historical_datasets(tmp_path):
    config = load_experiment_config()
    existing = tmp_path / "already-used"
    existing.mkdir()
    import pytest
    with pytest.raises(FileExistsError):
        resolve_batch_output(config, existing)
    with pytest.raises(ValueError, match="historical dataset"):
        resolve_batch_output(config, DEFAULT_CONFIG_PATH.parents[2] / "research" / "datasets" / "raw" / "new-batch")
