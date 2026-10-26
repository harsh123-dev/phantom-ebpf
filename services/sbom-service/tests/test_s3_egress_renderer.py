from __future__ import annotations

import importlib.util
import socket
from pathlib import Path
from types import ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[3]
RENDERER = ROOT / "infra/k8s/k3s-lab/render-sbom-s3-egress.py"


def _load_renderer() -> ModuleType:
    spec = importlib.util.spec_from_file_location("phantom_s3_egress_renderer", RENDERER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _dns_record(ip: str) -> tuple[object, ...]:
    return (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))


def test_renderer_limits_s3_sigstore_and_broker_egress(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    renderer = _load_renderer()
    monkeypatch.setenv("AWS_REGION", "ap-south-1")
    monkeypatch.setenv("PHANTOM_CREDENTIAL_BROKER_NODE_IP", "10.89.1.98")
    monkeypatch.setattr(
        renderer,
        "aws_json",
        lambda *_args: (
            {"PrefixLists": [{"PrefixListName": "com.amazonaws.ap-south-1.s3", "PrefixListId": "pl-test"}]}
            if "describe-prefix-lists" in _args
            else {"Entries": [{"Cidr": "52.219.156.0/22"}, {"Cidr": "16.12.3.0/24"}]}
        ),
    )
    monkeypatch.setattr(
        renderer.socket,
        "getaddrinfo",
        lambda hostname, *_args, **_kwargs: [
            _dns_record(
                "8.8.8.8" if hostname.startswith("rekor")
                else "1.1.1.1" if hostname.startswith("fulcio")
                else "9.9.9.9"
            )
        ],
    )

    assert renderer.main() == 0
    output = capsys.readouterr().out
    assert "cidr: 10.89.1.98/32" in output
    assert "cidr: 52.219.156.0/22" in output
    assert "cidr: 16.12.3.0/24" in output
    assert "cidr: 8.8.8.8/32" in output
    assert "cidr: 1.1.1.1/32" in output
    assert "cidr: 9.9.9.9/32" in output
    assert "cidr: 0.0.0.0/0" not in output
    assert "phantom-sbom-restricted-egress" in output


def test_renderer_fails_closed_without_private_broker_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    renderer = _load_renderer()
    monkeypatch.setenv("PHANTOM_CREDENTIAL_BROKER_NODE_IP", "203.0.113.8")
    with pytest.raises(RuntimeError, match="private IPv4"):
        renderer.main()
