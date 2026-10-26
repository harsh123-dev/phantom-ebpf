"""Short-lived S3 credentials for one explicitly authorized k3s service account.

The broker runs with host networking so it can use the node's IMDSv2 role while
the IMDS hop limit remains one. It does not return instance-profile credentials:
each authenticated request receives a one-hour session for the dedicated,
prefix-limited SBOM role. Requests are authenticated through Kubernetes
TokenReview with a distinct audience, exact service-account subject, and
verified owner chain to the SBOM Deployment.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from aiobotocore.session import get_session
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict

EXPECTED_AUDIENCE = "phantom-aws-credential-broker"
EXPECTED_USERNAME = "system:serviceaccount:phantom:phantom-sbom-service"
MAX_TOKEN_BYTES = 16 * 1024
CREDENTIAL_TTL_SECONDS = 3600
# Botocore's credential_process provider starts refreshing credentials within
# roughly 15 minutes of expiry. Refresh the broker's cached STS session earlier
# than that so the process returns a fresh session when Botocore asks.
CACHE_REFRESH_MARGIN = timedelta(minutes=20)
TARGET_NAMESPACE = "phantom"
TARGET_DEPLOYMENT = "phantom-sbom-service"


@dataclass(frozen=True)
class Settings:
    region: str
    role_arn: str
    bucket: str
    prefix: str
    api_server: str
    api_ca_file: Path
    broker_token_file: Path

    @classmethod
    def from_env(cls) -> Settings:
        values = {
            "AWS_REGION": os.getenv("AWS_REGION", ""),
            "PHANTOM_S3_WORKLOAD_ROLE_ARN": os.getenv("PHANTOM_S3_WORKLOAD_ROLE_ARN", ""),
            "PHANTOM_S3_BUCKET": os.getenv("PHANTOM_S3_BUCKET", ""),
            "PHANTOM_S3_PREFIX": os.getenv("PHANTOM_S3_PREFIX", ""),
            "KUBERNETES_SERVICE_HOST": os.getenv("KUBERNETES_SERVICE_HOST", ""),
        }
        missing = [name for name, value in values.items() if not value]
        if missing:
            raise RuntimeError("missing required broker configuration: " + ", ".join(missing))
        prefix = values["PHANTOM_S3_PREFIX"].strip("/")
        if not prefix or ".." in prefix.split("/"):
            raise RuntimeError("PHANTOM_S3_PREFIX must be a safe nonempty S3 prefix")
        if not values["PHANTOM_S3_BUCKET"].isascii() or "/" in values["PHANTOM_S3_BUCKET"]:
            raise RuntimeError("PHANTOM_S3_BUCKET must be a bucket name, not a URI")
        host = values["KUBERNETES_SERVICE_HOST"]
        if "://" in host or "/" in host:
            raise RuntimeError("KUBERNETES_SERVICE_HOST must be a host or IP address")
        port = os.getenv("KUBERNETES_SERVICE_PORT_HTTPS", "443")
        return cls(
            region=values["AWS_REGION"],
            role_arn=values["PHANTOM_S3_WORKLOAD_ROLE_ARN"],
            bucket=values["PHANTOM_S3_BUCKET"],
            prefix=prefix,
            api_server=f"https://{host}:{port}",
            api_ca_file=Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"),
            broker_token_file=Path("/var/run/secrets/kubernetes.io/serviceaccount/token"),
        )


class TokenReviewResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    status: dict[str, Any]


class CredentialBroker:
    def __init__(self, settings: Settings, *, http_client: Any | None = None, sts_session: Any | None = None) -> None:
        self.settings = settings
        self.http_client = http_client
        self.sts_session = sts_session or get_session()
        self._credentials: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def _kubernetes_get(self, path: str) -> dict[str, Any]:
        try:
            broker_token = self.settings.broker_token_file.read_text().strip()
            ca = str(self.settings.api_ca_file)
        except OSError as exc:
            raise HTTPException(status_code=503, detail="Kubernetes identity verification is unavailable") from exc
        headers = {"Authorization": f"Bearer {broker_token}"}
        try:
            if self.http_client is None:
                async with httpx.AsyncClient(verify=ca, timeout=3.0) as client:
                    response = await client.get(
                        f"{self.settings.api_server}{path}", headers=headers
                    )
            else:
                response = await self.http_client.get(
                    f"{self.settings.api_server}{path}", headers=headers
                )
            response.raise_for_status()
            value = response.json()
            if not isinstance(value, dict):
                raise ValueError("Kubernetes API returned a non-object response")
            return value
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            raise HTTPException(status_code=401, detail="workload is not an authorized SBOM pod") from exc

    @staticmethod
    def _container_identity(containers: Any) -> list[dict[str, Any]] | None:
        if not isinstance(containers, list):
            return None
        fields = (
            "name", "image", "command", "args", "env", "envFrom",
            "volumeMounts", "securityContext",
        )
        if any(not isinstance(item, dict) for item in containers):
            return None
        return [{field: item.get(field) for field in fields} for item in containers]

    @staticmethod
    def _normalized_volume(volume: dict[str, Any]) -> dict[str, Any]:
        normalized = copy.deepcopy(volume)
        for kind in ("configMap", "secret", "projected"):
            source = normalized.get(kind)
            if isinstance(source, dict):
                source.setdefault("defaultMode", 0o644)
                if kind in ("configMap", "secret"):
                    source.setdefault("optional", False)
        return normalized

    async def _verify_sbom_deployment_pod(self, pod_name: str, pod_uid: str) -> None:
        namespace_path = quote(TARGET_NAMESPACE, safe="")
        pod_path = quote(pod_name, safe="")
        pod = await self._kubernetes_get(
            f"/api/v1/namespaces/{namespace_path}/pods/{pod_path}"
        )
        metadata = pod.get("metadata") or {}
        spec = pod.get("spec") or {}
        status = pod.get("status") or {}
        if (
            metadata.get("uid") != pod_uid
            or metadata.get("namespace") != TARGET_NAMESPACE
            or spec.get("serviceAccountName") != "phantom-sbom-service"
            or spec.get("automountServiceAccountToken") is not False
            or status.get("phase") != "Running"
            or metadata.get("deletionTimestamp") is not None
        ):
            raise HTTPException(status_code=401, detail="workload is not an authorized SBOM pod")

        pod_controllers = [
            ref for ref in metadata.get("ownerReferences", [])
            if ref.get("controller") is True
        ]
        if len(pod_controllers) != 1 or pod_controllers[0].get("kind") != "ReplicaSet":
            raise HTTPException(status_code=401, detail="workload is not owned by the SBOM deployment")
        replica_set_name = pod_controllers[0].get("name")
        replica_set_uid = pod_controllers[0].get("uid")
        if not replica_set_name or not replica_set_uid:
            raise HTTPException(status_code=401, detail="workload is not owned by the SBOM deployment")
        rs_path = quote(str(replica_set_name), safe="")
        replica_set = await self._kubernetes_get(
            f"/apis/apps/v1/namespaces/{namespace_path}/replicasets/{rs_path}"
        )
        rs_metadata = replica_set.get("metadata") or {}
        if rs_metadata.get("uid") != replica_set_uid:
            raise HTTPException(status_code=401, detail="workload is not owned by the SBOM deployment")
        rs_controllers = [
            ref for ref in rs_metadata.get("ownerReferences", [])
            if ref.get("controller") is True
        ]
        if len(rs_controllers) != 1 or rs_controllers[0].get("kind") != "Deployment":
            raise HTTPException(status_code=401, detail="workload is not owned by the SBOM deployment")
        if rs_controllers[0].get("name") != TARGET_DEPLOYMENT:
            raise HTTPException(status_code=401, detail="workload is not owned by the SBOM deployment")
        deployment_uid = rs_controllers[0].get("uid")
        deployment = await self._kubernetes_get(
            f"/apis/apps/v1/namespaces/{namespace_path}/deployments/{TARGET_DEPLOYMENT}"
        )
        deployment_metadata = deployment.get("metadata") or {}
        deployment_spec = deployment.get("spec") or {}
        template = deployment_spec.get("template") or {}
        template_metadata = template.get("metadata") or {}
        template_spec = template.get("spec") or {}
        template_labels = template_metadata.get("labels") or {}
        selector = ((deployment_spec.get("selector") or {}).get("matchLabels") or {})
        pod_labels = metadata.get("labels") or {}
        expected_pod_spec = template.get("spec") or {}
        actual_containers = self._container_identity(spec.get("containers"))
        expected_containers = self._container_identity(expected_pod_spec.get("containers"))
        actual_init = self._container_identity(spec.get("initContainers", []))
        expected_init = self._container_identity(expected_pod_spec.get("initContainers", []))
        actual_volumes = spec.get("volumes") or []
        expected_volumes = expected_pod_spec.get("volumes") or []
        actual_volume_map = {
            volume.get("name"): volume for volume in actual_volumes if isinstance(volume, dict)
        }
        expected_volume_names = {
            volume.get("name") for volume in expected_volumes if isinstance(volume, dict)
        }
        volumes_match = (
            len(actual_volume_map) == len(actual_volumes)
            and set(actual_volume_map) == expected_volume_names
            and all(
                self._normalized_volume(actual_volume_map[volume.get("name")])
                == self._normalized_volume(volume)
                for volume in expected_volumes
                if isinstance(volume, dict) and volume.get("name") in actual_volume_map
            )
            and len(expected_volume_names) == len(expected_volumes)
            and all(volume.get("name") in actual_volume_map for volume in expected_volumes)
        )
        if (
            deployment_metadata.get("uid") != deployment_uid
            or deployment_metadata.get("name") != TARGET_DEPLOYMENT
            or template_spec.get("serviceAccountName") != "phantom-sbom-service"
            or template_spec.get("automountServiceAccountToken") is not False
            or not selector
            or any(pod_labels.get(key) != value for key, value in selector.items())
            or any(pod_labels.get(key) != value for key, value in template_labels.items())
            or any(template_labels.get(key) != value for key, value in selector.items())
            or actual_containers is None
            or actual_containers != expected_containers
            or actual_init is None
            or actual_init != expected_init
            or not volumes_match
        ):
            raise HTTPException(status_code=401, detail="workload is not an authorized SBOM pod")

    async def _review_token(self, token: str) -> str:
        if not token or len(token.encode()) > MAX_TOKEN_BYTES:
            raise HTTPException(status_code=401, detail="unauthorized workload identity")
        try:
            broker_token = self.settings.broker_token_file.read_text().strip()
            ca = str(self.settings.api_ca_file)
        except OSError as exc:
            raise HTTPException(status_code=503, detail="Kubernetes token review is unavailable") from exc
        headers = {"Authorization": f"Bearer {broker_token}"}
        body = {
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenReview",
            "spec": {"token": token, "audiences": [EXPECTED_AUDIENCE]},
        }
        try:
            if self.http_client is None:
                async with httpx.AsyncClient(verify=ca, timeout=3.0) as client:
                    response = await client.post(
                        f"{self.settings.api_server}/apis/authentication.k8s.io/v1/tokenreviews",
                        headers=headers,
                        json=body,
                    )
            else:
                response = await self.http_client.post(
                    f"{self.settings.api_server}/apis/authentication.k8s.io/v1/tokenreviews",
                    headers=headers,
                    json=body,
                )
            response.raise_for_status()
            result = TokenReviewResponse.model_validate(response.json()).status
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            raise HTTPException(status_code=503, detail="Kubernetes token review failed") from exc

        user = result.get("user") or {}
        audiences = result.get("audiences") or []
        if (
            result.get("authenticated") is not True
            or user.get("username") != EXPECTED_USERNAME
            or EXPECTED_AUDIENCE not in audiences
        ):
            raise HTTPException(status_code=401, detail="unauthorized workload identity")
        extra = user.get("extra") or {}
        pod_uids = extra.get("authentication.kubernetes.io/pod-uid") or []
        pod_names = extra.get("authentication.kubernetes.io/pod-name") or []
        if (
            not isinstance(pod_uids, list) or len(pod_uids) != 1 or not pod_uids[0]
            or not isinstance(pod_names, list) or len(pod_names) != 1 or not pod_names[0]
        ):
            raise HTTPException(status_code=401, detail="workload token is not pod-bound")
        pod_uid = str(pod_uids[0])
        await self._verify_sbom_deployment_pod(str(pod_names[0]), pod_uid)
        return pod_uid

    def _session_policy(self) -> str:
        bucket_arn = f"arn:aws:s3:::{self.settings.bucket}"
        object_arn = f"{bucket_arn}/{self.settings.prefix}/*"
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:PutObject"],
                        "Resource": object_arn,
                }],
            },
            separators=(",", ":"),
        )

    async def _assume_workload_role(self, pod_uid: str) -> dict[str, Any]:
        now = datetime.now(UTC)
        async with self._lock:
            cached = self._credentials.get(pod_uid)
            if cached and cached["Expiration"] - now > CACHE_REFRESH_MARGIN:
                return cached
            session_name = "phantom-sbom-" + hashlib.sha256(pod_uid.encode()).hexdigest()[:24]
            try:
                async with self.sts_session.create_client("sts", region_name=self.settings.region) as sts:
                    result = await sts.assume_role(
                        RoleArn=self.settings.role_arn,
                        RoleSessionName=session_name,
                        DurationSeconds=CREDENTIAL_TTL_SECONDS,
                        Policy=self._session_policy(),
                    )
            except (BotoCoreError, ClientError) as exc:
                raise HTTPException(status_code=503, detail="AWS role assumption failed") from exc
            raw = result.get("Credentials") or {}
            try:
                expiration = raw["Expiration"]
                if isinstance(expiration, str):
                    expiration = datetime.fromisoformat(expiration.replace("Z", "+00:00"))
                if expiration.tzinfo is None or expiration <= now:
                    raise ValueError("invalid expiration")
                credentials = {
                    "AccessKeyId": raw["AccessKeyId"],
                    "SecretAccessKey": raw["SecretAccessKey"],
                    "Token": raw["SessionToken"],
                    "Expiration": expiration.astimezone(UTC),
                }
            except (KeyError, TypeError, ValueError) as exc:
                raise HTTPException(status_code=503, detail="AWS returned invalid temporary credentials") from exc
            self._credentials[pod_uid] = credentials
            return credentials

    async def credentials_for(self, authorization: str | None) -> dict[str, str]:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="bearer workload token required")
        token = authorization.removeprefix("Bearer ").strip()
        pod_uid = await self._review_token(token)
        raw = await self._assume_workload_role(pod_uid)
        return {
            "Version": 1,
            "AccessKeyId": raw["AccessKeyId"],
            "SecretAccessKey": raw["SecretAccessKey"],
            "Token": raw["Token"],
            "Expiration": raw["Expiration"].isoformat().replace("+00:00", "Z"),
        }


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.broker = CredentialBroker(Settings.from_env())
    yield


app = FastAPI(
    title="PHANTOM AWS workload credential broker",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/credentials")
async def issue_credentials(
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    broker = getattr(request.app.state, "broker", None)
    if broker is None:
        raise HTTPException(status_code=503, detail="credential broker is not ready")
    return await broker.credentials_for(authorization)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=18443,
        ssl_certfile=os.environ["PHANTOM_BROKER_TLS_CERT_FILE"],
        ssl_keyfile=os.environ["PHANTOM_BROKER_TLS_KEY_FILE"],
    )
