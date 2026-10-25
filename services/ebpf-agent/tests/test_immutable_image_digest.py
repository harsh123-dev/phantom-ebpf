import importlib.util
import sys
from pathlib import Path


MODULE = Path(__file__).resolve().parents[1] / "infrastructure/k8s/attributor.py"
spec = importlib.util.spec_from_file_location("phantom_attributor_test", MODULE)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def test_immutable_digest_extracted_from_runtime_image_id():
    digest = "sha256:" + "a" * 64
    assert module.immutable_image_digest(f"containerd://registry/image@{digest}") == digest


def test_mutable_tag_or_missing_image_id_is_not_a_digest():
    assert module.immutable_image_digest("registry/image:latest") is None
    assert module.immutable_image_digest(None) is None
