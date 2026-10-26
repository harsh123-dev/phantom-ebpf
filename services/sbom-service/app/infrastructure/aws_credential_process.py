"""AWS ``credential_process`` client for the PHANTOM k3s credential broker.

This command emits only short-lived, broker-issued credentials on stdout for
Botocore to consume. It never logs the token, response body, or credentials.
"""

from __future__ import annotations

import json
import ipaddress
import os
import ssl
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

MAX_RESPONSE_BYTES = 16 * 1024
REQUIRED_FIELDS = ("AccessKeyId", "SecretAccessKey", "Token", "Expiration")


class CredentialProcessError(RuntimeError):
    """Raised when broker credentials cannot be obtained safely."""


def _required_file(env_name: str) -> bytes:
    path = os.environ.get(env_name)
    if not path:
        raise CredentialProcessError(f"{env_name} is not configured")
    try:
        value = Path(path).read_bytes()
    except OSError as exc:
        raise CredentialProcessError(f"configured {env_name} cannot be read") from exc
    if not value:
        raise CredentialProcessError(f"configured {env_name} is empty")
    return value


def fetch_credentials() -> dict[str, object]:
    """Fetch and validate temporary AWS credentials from the internal broker."""
    endpoint = os.environ.get("PHANTOM_AWS_CREDENTIAL_BROKER_URL", "")
    parsed = urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise CredentialProcessError("broker URL must be an HTTPS URL without user information")
    if parsed.query or parsed.fragment:
        raise CredentialProcessError("broker URL must not contain a query or fragment")
    hostname = parsed.hostname.rstrip(".").lower()
    try:
        broker_ip = ipaddress.ip_address(hostname)
    except ValueError:
        if not (hostname.endswith(".svc") or hostname.endswith(".svc.cluster.local")):
            raise CredentialProcessError("broker host must be an internal Kubernetes service")
    else:
        rfc1918 = tuple(
            ipaddress.ip_network(cidr)
            for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        )
        if broker_ip.version != 4 or not any(broker_ip in network for network in rfc1918):
            raise CredentialProcessError("broker IP must be a private IPv4 address")

    token = _required_file("PHANTOM_AWS_CREDENTIAL_TOKEN_FILE").strip()
    ca_path = os.environ.get("PHANTOM_AWS_CREDENTIAL_CA_FILE")
    if not ca_path or not Path(ca_path).is_file():
        raise CredentialProcessError("broker CA bundle is not configured or unavailable")
    context = ssl.create_default_context(cafile=ca_path)
    try:
        authorization_token = token.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise CredentialProcessError("projected workload token is not valid ASCII") from exc
    request = Request(
        endpoint,
        data=b"{}",
        headers={
            "Authorization": "Bearer " + authorization_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=5.0, context=context) as response:
            if response.status != 200:
                raise CredentialProcessError("credential broker returned a non-success status")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        # Do not include URL errors or response bodies; they may include request details.
        raise CredentialProcessError("credential broker request failed") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise CredentialProcessError("credential broker response exceeded size limit")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CredentialProcessError("credential broker returned malformed JSON") from exc
    if not isinstance(payload, dict) or any(
        not isinstance(payload.get(field), str) or not payload[field] for field in REQUIRED_FIELDS
    ):
        raise CredentialProcessError("credential broker response is missing credential fields")
    try:
        expiration = datetime.fromisoformat(str(payload["Expiration"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise CredentialProcessError("credential expiration is invalid") from exc
    if expiration.tzinfo is None or expiration <= datetime.now(UTC):
        raise CredentialProcessError("credential expiration is missing a timezone or is expired")
    return {
        "Version": 1,
        "AccessKeyId": payload["AccessKeyId"],
        "SecretAccessKey": payload["SecretAccessKey"],
        "SessionToken": payload["Token"],
        "Expiration": expiration.astimezone(UTC).isoformat().replace("+00:00", "Z"),
    }


def main() -> int:
    try:
        credentials = fetch_credentials()
    except CredentialProcessError as exc:
        print(f"PHANTOM AWS credential process: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(json.dumps(credentials, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
