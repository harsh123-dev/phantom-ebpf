from __future__ import annotations

import json
import shlex
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.infrastructure import aws_credential_process as credential_process


def _response(expiration: str | None = None) -> bytes:
    return json.dumps(
        {
            "AccessKeyId": "ASIAEXAMPLEACCESSKEY",
            "SecretAccessKey": "test-only-secret",
            "Token": "test-only-session-token",
            "Expiration": expiration
            or (datetime.now(UTC) + timedelta(minutes=15)).isoformat(),
        }
    ).encode()


def _configure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("test-only-service-account-token")
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("test-only-ca")
    monkeypatch.setenv(
        "PHANTOM_AWS_CREDENTIAL_BROKER_URL",
        "https://10.89.1.98:18443/v1/credentials",
    )
    monkeypatch.setenv("PHANTOM_AWS_CREDENTIAL_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("PHANTOM_AWS_CREDENTIAL_CA_FILE", str(ca_file))


def test_credential_process_posts_projected_token_and_returns_sdk_format(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _configure(monkeypatch, tmp_path)
    captured: dict[str, object] = {}

    class FakeResponse:
        status = 200

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _size: int) -> bytes:
            return _response()

    def fake_urlopen(request: object, *, timeout: float, context: object) -> FakeResponse:
        captured["request"] = request
        captured["timeout"] = timeout
        captured["context"] = context
        return FakeResponse()

    monkeypatch.setattr(credential_process, "urlopen", fake_urlopen)
    monkeypatch.setattr(credential_process.ssl, "create_default_context", lambda **_: object())

    result = credential_process.fetch_credentials()

    request = captured["request"]
    assert request.full_url == "https://10.89.1.98:18443/v1/credentials"
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == "Bearer test-only-service-account-token"
    assert result["Version"] == 1
    assert result["AccessKeyId"] == "ASIAEXAMPLEACCESSKEY"
    assert result["SessionToken"] == "test-only-session-token"
    assert "SecretAccessKey" in result


@pytest.mark.parametrize(
    "url",
    [
        "http://broker.phantom-identity.svc/credentials",
        "https://user:password@broker.phantom-identity.svc/credentials",
        "https://broker.phantom-identity.svc/credentials?token=secret",
    ],
)
def test_credential_process_rejects_unsafe_endpoint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, url: str
) -> None:
    _configure(monkeypatch, tmp_path)
    monkeypatch.setenv("PHANTOM_AWS_CREDENTIAL_BROKER_URL", url)
    with pytest.raises(credential_process.CredentialProcessError):
        credential_process.fetch_credentials()


def test_credential_process_rejects_expired_credentials(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _configure(monkeypatch, tmp_path)

    class FakeResponse:
        status = 200

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _size: int) -> bytes:
            return _response((datetime.now(UTC) - timedelta(seconds=1)).isoformat())

    monkeypatch.setattr(credential_process, "urlopen", lambda *_a, **_k: FakeResponse())
    monkeypatch.setattr(credential_process.ssl, "create_default_context", lambda **_: object())
    with pytest.raises(credential_process.CredentialProcessError, match="expired"):
        credential_process.fetch_credentials()


@pytest.mark.asyncio
async def test_aiobotocore_uses_configured_credential_process(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    helper = tmp_path / "fake-credential-process.py"
    helper.write_text(
        "import json\n"
        "from datetime import datetime, timedelta, timezone\n"
        f"counter = {str(tmp_path / 'invocations')!r}\n"
        "try: count = int(open(counter).read())\n"
        "except FileNotFoundError: count = 0\n"
        "open(counter, 'w').write(str(count + 1))\n"
        "print(json.dumps({"
        "'Version':1,'AccessKeyId':f'ASIATESTKEY{count + 1}',"
        "'SecretAccessKey':'test-secret','SessionToken':'test-session',"
        "'Expiration':(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()"
        "}))\n"
    )
    config = tmp_path / "config"
    cmd_proc = (
        subprocess.list2cmdline([sys.executable, str(helper)])
        if sys.platform == "win32"
        else f"{shlex.quote(sys.executable)} {shlex.quote(str(helper))}"
    )
    config.write_text(
        "[profile phantom-sbom]\n"
        "region = ap-south-1\n"
        f"credential_process = {cmd_proc}\n"
    )
    credentials_file = tmp_path / "credentials"
    credentials_file.write_text("")
    monkeypatch.setenv("AWS_PROFILE", "phantom-sbom")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(credentials_file))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(name, raising=False)

    from aiobotocore.session import get_session

    session = get_session()
    credentials = await session.get_credentials()
    assert credentials is not None
    assert credentials.method == "custom-process"
    frozen = await credentials.get_frozen_credentials()
    assert frozen.access_key == "ASIATESTKEY1"
    assert frozen.secret_key == "test-secret"
    assert frozen.token == "test-session"

    # Botocore must invoke credential_process again inside its refresh window.
    credentials._expiry_time = datetime.now(UTC) + timedelta(minutes=10)
    refreshed = await credentials.get_frozen_credentials()
    assert refreshed.access_key == "ASIATESTKEY2"
