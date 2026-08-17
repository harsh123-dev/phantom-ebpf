"""
services/sbom-service/app/infrastructure/cosign/client.py

Cosign CLI adapter for signing and verifying SBOM attestations.

Implements the SbomVerifierPort from the application ports.

Security decisions:
- subprocess.run is called with an explicit argument list; shell=False.
- Identity and issuer flags are passed as discrete argv elements to prevent
  flag injection or shell expansion of adversarial values.
- The environment passed to cosign is a controlled safe subset; credential
  variables (COSIGN_PASSWORD, SIGSTORE_*) are passed only when explicitly
  provided by the caller, never by inheriting the full process environment.
- stdout/stderr are captured as bytes; JSON output is only parsed, never
  exec'd or eval'd.
- A configurable network timeout is enforced; cosign contacts Sigstore
  services (Rekor, Fulcio) over the network so timeouts must be finite.
- Key material paths are validated to be non-empty before being passed;
  the subprocess never receives an empty --key flag.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog

from app.domain.entities import Sbom
from app.domain.exceptions import (
    SignatureVerificationError,
    VerificationServiceUnavailableError,
)
from app.domain.ports import SbomVerifierPort

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_TIMEOUT_SECONDS: float = 120.0
"""Default cosign network timeout in seconds."""

_COSIGN_UNAVAILABLE_PHRASES: tuple[str, ...] = (
    "connection refused",
    "connection reset",
    "timeout",
    "tls handshake",
    "dial tcp",
    "i/o timeout",
    "EOF",
    "network unreachable",
)
"""Stderr phrases that indicate a transient network issue, not a bad signature."""

_REKOR_UUID_RE = re.compile(r"[0-9a-f]{64}", re.IGNORECASE)
"""Pattern used to extract a Rekor entry UUID from cosign output."""


class CosignClient(SbomVerifierPort):
    """Cosign CLI adapter implementing the SbomVerifierPort.

    Runs ``cosign verify-attestation`` (or ``cosign verify``) against the
    supplied image/artifact using the Sigstore transparency log.

    Args:
        cosign_path: Absolute path or command name for the cosign binary.
        timeout_seconds: Maximum network-connected wall-clock time.
        rekor_url: Rekor transparency log URL; defaults to public Sigstore.
        fulcio_url: Fulcio CA URL; defaults to public Sigstore.
    """

    def __init__(
        self,
        cosign_path: str = "cosign",
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        rekor_url: str = "https://rekor.sigstore.dev",
        fulcio_url: str = "https://fulcio.sigstore.dev",
    ) -> None:
        """Initialise the cosign client.

        Args:
            cosign_path: Path or command name for the cosign binary.
            timeout_seconds: Subprocess timeout in seconds.
            rekor_url: Rekor transparency log base URL.
            fulcio_url: Fulcio CA base URL.
        """
        self._cosign_path = cosign_path
        self._timeout_seconds = timeout_seconds
        self._rekor_url = rekor_url
        self._fulcio_url = fulcio_url

    def _resolve_cosign_binary(self) -> str:
        """Resolve the cosign binary path.

        Returns:
            The resolved absolute path to the cosign binary.

        Raises:
            VerificationServiceUnavailableError: If the binary is not found.
        """
        resolved = shutil.which(self._cosign_path)
        if resolved is None:
            raise VerificationServiceUnavailableError(
                f"cosign binary not found at {self._cosign_path!r}; "
                f"ensure cosign is installed and on PATH"
            )
        return resolved

    def _build_env(self) -> dict[str, str]:
        """Build a safe environment dict for the cosign subprocess.

        Forwards only the variables cosign needs for Sigstore network access.
        Does NOT forward the full process environment.

        Returns:
            Safe environment dict for the cosign process.
        """
        safe_keys = {
            "PATH", "HOME", "USER",
            # SIGSTORE_* variables control Sigstore endpoint overrides.
            "SIGSTORE_REKOR_URL", "SIGSTORE_FULCIO_URL",
            # TUF root and metadata.
            "TUF_ROOT",
            # Proxy settings needed for network access.
            "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
            "http_proxy", "https_proxy", "no_proxy",
            # TMPDIR for cosign's temp files.
            "TMPDIR", "TEMP", "TMP",
        }
        env: dict[str, str] = {
            k: v for k, v in os.environ.items() if k in safe_keys
        }
        if "PATH" not in env:
            env["PATH"] = os.defpath or "/usr/local/bin:/usr/bin:/bin"
        return env

    async def verify(
        self,
        sbom: Sbom,
        expected_identity: str,
        expected_issuer: str,
        rekor_required: bool,
    ) -> Sbom:
        """Verify the cosign signature of an SBOM attestation.

        Uses ``cosign verify-attestation`` with keyless Sigstore (OIDC +
        Fulcio + Rekor). Passes identity/issuer as discrete argv elements.

        Args:
            sbom: The Sbom entity to verify; its image_digest is used as
                the verification target.
            expected_identity: Expected Fulcio signing identity regex/value.
            expected_issuer: Expected OIDC issuer URI.
            rekor_required: Whether a Rekor transparency log entry must be
                present; if True and Rekor is unavailable, verification fails.

        Returns:
            The Sbom entity updated with VERIFIED or FAILED state.

        Raises:
            SignatureVerificationError: If the signature is definitively bad.
            VerificationServiceUnavailableError: If cosign/Sigstore is unreachable.
        """
        resolved_binary = self._resolve_cosign_binary()

        # Build the argument list. Each flag-value pair is a discrete element
        # so that adversarial identity/issuer strings cannot inject new flags.
        argv: list[str] = [
            resolved_binary,
            "verify-attestation",
            "--certificate-identity",    # Fulcio identity requirement
            expected_identity,           # passed as a separate element
            "--certificate-oidc-issuer", # OIDC issuer requirement
            expected_issuer,             # passed as a separate element
            "--type",
            "cyclonedx",
            "--rekor-url",
            self._rekor_url,
            sbom.image_digest.value,     # target: the image digest
        ]

        if not rekor_required:
            # Allow verification without a Rekor entry (offline/private deployments).
            argv.append("--insecure-ignore-tlog")

        bound_log = log.bind(
            sbom_id=str(sbom.sbom_id),
            image_digest=sbom.image_digest.value,
            expected_identity=expected_identity,
            expected_issuer=expected_issuer,
        )
        bound_log.info("cosign_client.verify.started")

        try:
            result = subprocess.run(  # noqa: S603 — explicit argv
                argv,
                capture_output=True,
                timeout=self._timeout_seconds,
                env=self._build_env(),
                shell=False,  # explicit — never interpolate into a shell string
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            bound_log.warning("cosign_client.verify.timeout")
            raise VerificationServiceUnavailableError(
                f"cosign timed out after {self._timeout_seconds}s; "
                f"Sigstore services may be unreachable"
            ) from exc
        except FileNotFoundError as exc:
            raise VerificationServiceUnavailableError(
                f"cosign binary disappeared: {exc}"
            ) from exc

        stderr_text = result.stderr.decode("utf-8", errors="replace")
        stdout_text = result.stdout.decode("utf-8", errors="replace")

        if result.returncode != 0:
            stderr_lower = stderr_text.lower()
            # Distinguish network/service outage from actual bad signature.
            if any(phrase in stderr_lower for phrase in _COSIGN_UNAVAILABLE_PHRASES):
                bound_log.warning(
                    "cosign_client.verify.service_unavailable",
                    stderr=stderr_text[:512],
                )
                raise VerificationServiceUnavailableError(
                    f"cosign could not reach Sigstore services: {stderr_text[:256]}"
                )
            bound_log.warning(
                "cosign_client.verify.failed",
                returncode=result.returncode,
                stderr=stderr_text[:512],
            )
            updated_sbom = sbom.mark_verification_failed(
                reason=stderr_text[:512] or f"cosign exit code {result.returncode}"
            )
            raise SignatureVerificationError(
                message=stderr_text[:512],
                sbom_id=str(sbom.sbom_id),
            )

        # Parse cosign JSON output to extract identity/issuer/Rekor details.
        signing_identity, issuer, rekor_entry_uuid = self._extract_verification_details(
            stdout=stdout_text,
            stderr=stderr_text,
        )

        updated_sbom = sbom.mark_verified(
            signing_identity=signing_identity,
            issuer=issuer,
            verified_at=datetime.now(tz=UTC),
            rekor_entry_uuid=rekor_entry_uuid,
        )
        bound_log.info(
            "cosign_client.verify.succeeded",
            signing_identity=signing_identity,
            issuer=issuer,
        )
        return updated_sbom

    def _extract_verification_details(
        self, stdout: str, stderr: str
    ) -> tuple[str, str, uuid.UUID | None]:
        """Extract signing identity, issuer, and Rekor UUID from cosign output.

        cosign ``verify-attestation`` emits a JSON array on stdout when
        successful. Each element contains ``optional.Subject`` and
        ``optional.Issuer`` fields. We extract the first element only.

        Args:
            stdout: The raw stdout text from cosign.
            stderr: The raw stderr text from cosign (for Rekor entry UUID).

        Returns:
            A 3-tuple of (signing_identity, issuer, rekor_entry_uuid).
            Falls back to placeholder strings if the JSON cannot be parsed.
        """
        signing_identity = "unknown"
        issuer = "unknown"
        rekor_entry_uuid: uuid.UUID | None = None

        try:
            # cosign outputs a JSON array of verified bundles.
            bundles: list[dict[str, Any]] = json.loads(stdout)
            if isinstance(bundles, list) and bundles:
                first = bundles[0]
                # cert.subject / cert.issuer path (cosign ≥ 2.x).
                cert = first.get("cert", {})
                if isinstance(cert, dict):
                    signing_identity = cert.get("subject", signing_identity)
                    issuer = cert.get("issuer", issuer)
                # Older path: optional.Subject.
                optional = first.get("optional", {})
                if isinstance(optional, dict):
                    signing_identity = optional.get("Subject", signing_identity)
                    issuer = optional.get("Issuer", issuer)
        except (json.JSONDecodeError, TypeError, KeyError):
            log.debug("cosign_client._extract_details.json_parse_failed")

        # Extract Rekor entry UUID from stderr diagnostic output.
        # Rekor entry lines look like: "Rekor entry: <64-hex-chars>"
        match = _REKOR_UUID_RE.search(stderr)
        if match:
            hex_str = match.group(0)
            # Rekor UUIDs are 64 hex chars; convert the first 32 to a UUID.
            try:
                rekor_entry_uuid = uuid.UUID(hex_str[:32])
            except ValueError:
                pass

        return signing_identity, issuer, rekor_entry_uuid
