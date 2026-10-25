"""Standard-library configuration tests usable without the full evaluation stack."""

import tempfile
import unittest
from pathlib import Path

from research.evaluation.scenarios.config import (
    DEFAULT_CONFIG_PATH,
    load_experiment_config,
    resolve_batch_output,
    scenario_ids,
)


class ExperimentConfigTests(unittest.TestCase):
    def test_config_defines_expected_campaign_sizes_and_pairings(self):
        config = load_experiment_config()
        self.assertEqual(len(scenario_ids(config, "pilot")) * config["repetitions"], 18)
        self.assertEqual(len(scenario_ids(config, "extended")) * config["repetitions"], 27)
        scenarios = config["_scenario_by_id"]
        self.assertEqual(scenarios["xzutils-001"]["target_service"], scenarios["benign-update-001"]["target_service"])
        self.assertEqual(scenarios["dep-confusion-001"]["target_service"], scenarios["benign-load-001"]["target_service"])
        self.assertEqual(scenarios["solarwinds-001"]["target_service"], scenarios["benign-restart-001"]["target_service"])

    def test_output_paths_are_unique_and_refuse_existing_or_historical_data(self):
        config = load_experiment_config()
        with tempfile.TemporaryDirectory() as directory:
            existing = Path(directory) / "existing"
            existing.mkdir()
            with self.assertRaises(FileExistsError):
                resolve_batch_output(config, existing)
        repository = DEFAULT_CONFIG_PATH.parents[2]
        historical_child = repository / "research" / "datasets" / "raw" / "new-batch"
        with self.assertRaisesRegex(ValueError, "historical dataset"):
            resolve_batch_output(config, historical_child)


if __name__ == "__main__":
    unittest.main()
