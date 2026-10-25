"""Validated experiment configuration loading for the PHANTOM runner."""

from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CONFIG_PATH = REPO_ROOT / "research" / "evaluation" / "experiment_config.yaml"
ALLOWED_TARGETS = {"recommendationservice", "emailservice", "cartservice"}


def load_experiment_config(path: str | Path = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    """Load and validate the experiment matrix, repetitions, and output root."""
    config_path = Path(path)
    if not config_path.is_absolute():
        config_path = (REPO_ROOT / config_path).resolve()
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ValueError(f"Experiment config must be a YAML mapping: {config_path}")

    repetitions = config.get("repetitions")
    if not isinstance(repetitions, int) or repetitions < 1:
        raise ValueError("repetitions must be a positive integer")
    if not isinstance(config.get("namespace"), str) or not config["namespace"]:
        raise ValueError("namespace must be a non-empty string")
    if config["namespace"] != "phantom-eval":
        raise ValueError("namespace must remain the safety-allowlisted 'phantom-eval'")
    if not isinstance(config.get("raw_output_dir"), str) or not config["raw_output_dir"]:
        raise ValueError("raw_output_dir must be a non-empty string")
    for key in ("baseline_duration_s", "attack_duration_s", "recovery_duration_s"):
        if not isinstance(config.get(key), int) or config[key] < 1:
            raise ValueError(f"{key} must be a positive integer")

    attacks = config.get("attack_scenarios")
    extended = config.get("extended_attack_scenarios", [])
    controls = config.get("benign_scenarios")
    for field, rows in (("attack_scenarios", attacks), ("extended_attack_scenarios", extended), ("benign_scenarios", controls)):
        if not isinstance(rows, list):
            raise ValueError(f"{field} must be a list")
        for row in rows:
            if not isinstance(row, dict) or not row.get("id") or row.get("target_service") not in ALLOWED_TARGETS:
                raise ValueError(f"Invalid scenario entry in {field}: {row!r}")

    all_ids = [row["id"] for row in attacks + extended + controls]
    if len(all_ids) != len(set(all_ids)):
        raise ValueError("Scenario IDs must be unique across the configured matrix")
    config["_config_path"] = str(config_path)
    config["_scenario_by_id"] = {row["id"]: row for row in attacks + extended + controls}
    config["_pilot_ids"] = tuple(row["id"] for row in attacks + controls)
    config["_extended_ids"] = tuple(row["id"] for row in attacks + extended + controls)
    return config


def scenario_ids(config: dict[str, Any], campaign: str) -> tuple[str, ...]:
    """Return configured scenario IDs for a named campaign."""
    if campaign == "pilot":
        return config["_pilot_ids"]
    if campaign in {"extended", "all"}:
        return config["_extended_ids"]
    raise ValueError(f"Unknown campaign: {campaign}")


def resolve_batch_output(config: dict[str, Any], explicit: str | Path | None = None) -> Path:
    """Resolve a unique output directory and fail closed on existing evidence paths."""
    if explicit is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        candidate = (REPO_ROOT / config["raw_output_dir"] / stamp).resolve()
    else:
        candidate = Path(explicit).expanduser().resolve()
    historical = (REPO_ROOT / "research" / "datasets" / "raw").resolve(), (
        REPO_ROOT / "research" / "datasets" / "raw3"
    ).resolve()
    if any(candidate == path or path in candidate.parents for path in historical):
        raise ValueError(f"Refusing historical dataset path: {candidate}")
    if candidate.exists():
        raise FileExistsError(f"Refusing existing output directory: {candidate}")
    return candidate
