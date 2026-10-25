"""Evidence persistence tests ensure oracle records are immutable."""

import pytest

from research.evaluation.attacks.base_attack import AttackManifest


def test_oracle_save_refuses_to_overwrite_existing_evidence(tmp_path):
    manifest = AttackManifest(
        attack_id="unit-test-oracle", attack_family="test", target_service="cartservice",
        target_image="", target_component_purl="", clean_component_purl="",
        injection_time_offset_s=0, expected_behavioral_changes=[], ground_truth_label=0,
        control_endpoint="", recovery_steps=[],
    )
    path = manifest.save_oracle(tmp_path)
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        manifest.save_oracle(tmp_path)
    assert path.read_bytes() == original
