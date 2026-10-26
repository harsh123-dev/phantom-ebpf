from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import HTTPException

from app import CredentialBroker, Settings


POD_UID = "25e5f13a-9f2a-4f09-a4e7-311a5e3b2240"


class FakeResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def json(self) -> dict[str, Any]:
        return self._payload

    def raise_for_status(self) -> None:
        return None


class FakeHttpClient:
    def __init__(
        self,
        payload: dict[str, Any],
        *,
        deployment_owner: str = "phantom-sbom-service",
        pod_image: str = "phantom/sbom-service:latest",
        template_image: str = "phantom/sbom-service:latest",
    ) -> None:
        self.payload = payload
        self.request: dict[str, Any] | None = None
        self.gets: list[str] = []
        self.deployment_owner = deployment_owner
        self.pod_image = pod_image
        self.template_image = template_image

    async def post(self, url: str, *, headers: dict[str, str], json: dict[str, Any]) -> FakeResponse:
        self.request = {"url": url, "headers": headers, "json": json}
        return FakeResponse(self.payload)

    async def get(self, url: str, *, headers: dict[str, str]) -> FakeResponse:
        self.gets.append(url)
        if "/pods/" in url:
            value = {
                "metadata": {
                    "name": "phantom-sbom-service-abc-123",
                    "namespace": "phantom",
                    "uid": POD_UID,
                    "labels": {"app": "phantom-sbom-service"},
                    "ownerReferences": [{
                        "kind": "ReplicaSet", "name": "phantom-sbom-service-abc",
                        "uid": "replicaset-uid", "controller": True,
                    }],
                },
                "spec": {
                    "serviceAccountName": "phantom-sbom-service",
                    "automountServiceAccountToken": False,
                    "containers": [{"name": "sbom-service", "image": self.pod_image}],
                    "volumes": [],
                },
                "status": {"phase": "Running"},
            }
        elif "/replicasets/" in url:
            value = {
                "metadata": {
                    "name": "phantom-sbom-service-abc",
                    "uid": "replicaset-uid",
                    "ownerReferences": [{
                        "kind": "Deployment", "name": self.deployment_owner,
                        "uid": "deployment-uid", "controller": True,
                    }],
                }
            }
        elif "/deployments/" in url:
            value = {
                "metadata": {"name": "phantom-sbom-service", "uid": "deployment-uid"},
                "spec": {
                    "selector": {"matchLabels": {"app": "phantom-sbom-service"}},
                    "template": {
                        "metadata": {"labels": {"app": "phantom-sbom-service"}},
                        "spec": {
                            "serviceAccountName": "phantom-sbom-service",
                            "automountServiceAccountToken": False,
                            "containers": [{"name": "sbom-service", "image": self.template_image}],
                            "volumes": [],
                        },
                    },
                },
            }
        else:
            raise AssertionError(f"unexpected Kubernetes API path: {url}")
        return FakeResponse(value)


class FakeStsClient:
    def __init__(self) -> None:
        self.request: dict[str, Any] | None = None
        self.calls = 0

    async def __aenter__(self) -> FakeStsClient:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def assume_role(self, **kwargs: Any) -> dict[str, Any]:
        self.request = kwargs
        self.calls += 1
        return {
            "Credentials": {
                "AccessKeyId": "ASIATESTKEY",
                "SecretAccessKey": "test-only-secret",
                "SessionToken": "test-only-session-token",
                "Expiration": datetime.now(UTC) + timedelta(hours=1),
            }
        }


class FakeStsSession:
    def __init__(self) -> None:
        self.client = FakeStsClient()

    def create_client(self, *_args: object, **_kwargs: object) -> FakeStsClient:
        return self.client


def _settings(tmp_path: Path) -> Settings:
    token = tmp_path / "broker-token"
    token.write_text("broker-only-kubernetes-token")
    return Settings(
        region="ap-south-1",
        role_arn="arn:aws:iam::253490771520:role/phantom-sbom-workload-role",
        bucket="phantom-evidence-test",
        prefix="phantom/evidence/sboms",
        api_server="https://10.43.0.1:443",
        api_ca_file=tmp_path / "ca.crt",
        broker_token_file=token,
    )


def _review(username: str = "system:serviceaccount:phantom:phantom-sbom-service", *, authenticated: bool = True, audiences: list[str] | None = None, pod_uids: list[str] | None = None) -> dict[str, Any]:
    return {
        "status": {
            "authenticated": authenticated,
            "audiences": audiences if audiences is not None else ["phantom-aws-credential-broker"],
            "user": {
                "username": username,
                "extra": {
                    "authentication.kubernetes.io/pod-uid": pod_uids if pod_uids is not None else [POD_UID],
                    "authentication.kubernetes.io/pod-name": ["phantom-sbom-service-abc-123"],
                },
            },
        }
    }


@pytest.mark.asyncio
async def test_issues_short_lived_role_credentials_only_after_tokenreview(tmp_path: Path) -> None:
    http = FakeHttpClient(_review())
    sts = FakeStsSession()
    broker = CredentialBroker(_settings(tmp_path), http_client=http, sts_session=sts)

    result = await broker.credentials_for("Bearer projected-service-account-token")

    assert result["Version"] == 1
    assert result["AccessKeyId"] == "ASIATESTKEY"
    assert result["Token"] == "test-only-session-token"
    assert http.request is not None
    assert http.request["json"]["spec"]["audiences"] == ["phantom-aws-credential-broker"]
    assert http.request["headers"]["Authorization"] == "Bearer broker-only-kubernetes-token"
    assert len(http.gets) == 3
    assert sts.client.request is not None
    assert sts.client.request["RoleArn"] == "arn:aws:iam::253490771520:role/phantom-sbom-workload-role"
    assert sts.client.request["DurationSeconds"] == 3600
    session_policy = json.loads(sts.client.request["Policy"])
    assert session_policy["Statement"][0]["Resource"] == (
        "arn:aws:s3:::phantom-evidence-test/phantom/evidence/sboms/*"
    )
    assert session_policy["Statement"][0]["Action"] == ["s3:GetObject", "s3:PutObject"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "review",
    [
        _review(username="system:serviceaccount:default:other"),
        _review(authenticated=False),
        _review(audiences=["other-audience"]),
        _review(pod_uids=[]),
    ],
)
async def test_rejects_untrusted_or_unbound_tokens_without_assuming_role(
    tmp_path: Path, review: dict[str, Any]
) -> None:
    sts = FakeStsSession()
    broker = CredentialBroker(_settings(tmp_path), http_client=FakeHttpClient(review), sts_session=sts)
    with pytest.raises(HTTPException) as error:
        await broker.credentials_for("Bearer not-a-real-token")
    assert error.value.status_code == 401
    assert sts.client.request is None


@pytest.mark.asyncio
async def test_missing_bearer_token_is_rejected(tmp_path: Path) -> None:
    broker = CredentialBroker(_settings(tmp_path), http_client=FakeHttpClient(_review()), sts_session=FakeStsSession())
    with pytest.raises(HTTPException) as error:
        await broker.credentials_for(None)
    assert error.value.status_code == 401


@pytest.mark.asyncio
async def test_tokenreview_failure_fails_closed(tmp_path: Path) -> None:
    class FailedHttp:
        async def post(self, *_args: object, **_kwargs: object) -> FakeResponse:
            raise httpx.ConnectError("test unavailable")

    broker = CredentialBroker(_settings(tmp_path), http_client=FailedHttp(), sts_session=FakeStsSession())
    with pytest.raises(HTTPException) as error:
        await broker.credentials_for("Bearer projected-token")
    assert error.value.status_code == 503


@pytest.mark.asyncio
async def test_token_for_same_service_account_outside_sbom_deployment_is_rejected(tmp_path: Path) -> None:
    sts = FakeStsSession()
    http = FakeHttpClient(_review(), deployment_owner="unrelated-deployment")
    broker = CredentialBroker(_settings(tmp_path), http_client=http, sts_session=sts)

    with pytest.raises(HTTPException) as error:
        await broker.credentials_for("Bearer projected-token-for-rogue-pod")

    assert error.value.status_code == 401
    assert sts.client.request is None


@pytest.mark.asyncio
async def test_pod_with_changed_container_image_is_rejected(tmp_path: Path) -> None:
    sts = FakeStsSession()
    http = FakeHttpClient(_review(), pod_image="attacker/image:latest")
    broker = CredentialBroker(_settings(tmp_path), http_client=http, sts_session=sts)

    with pytest.raises(HTTPException) as error:
        await broker.credentials_for("Bearer projected-token")

    assert error.value.status_code == 401
    assert sts.client.request is None


@pytest.mark.asyncio
async def test_missing_pod_name_claim_is_rejected(tmp_path: Path) -> None:
    review = _review()
    review["status"]["user"]["extra"].pop("authentication.kubernetes.io/pod-name")
    sts = FakeStsSession()
    broker = CredentialBroker(_settings(tmp_path), http_client=FakeHttpClient(review), sts_session=sts)

    with pytest.raises(HTTPException) as error:
        await broker.credentials_for("Bearer projected-token")

    assert error.value.status_code == 401
    assert sts.client.request is None


@pytest.mark.asyncio
async def test_cached_session_is_refreshed_before_expiration(tmp_path: Path) -> None:
    sts = FakeStsSession()
    broker = CredentialBroker(_settings(tmp_path), http_client=FakeHttpClient(_review()), sts_session=sts)
    await broker.credentials_for("Bearer projected-token")
    assert sts.client.calls == 1

    broker._credentials[POD_UID]["Expiration"] = datetime.now(UTC) + timedelta(minutes=10)
    await broker.credentials_for("Bearer projected-token")

    assert sts.client.calls == 2
