"""
services/sbom-service/app/infrastructure/syft/client.py

Subprocess wrapper for the Syft CLI.

Security decisions (all documented below in line comments):
- subprocess.run is called with an explicit list of arguments (no shell=True).
- The image reference is passed as a positional argument, never embedded in a
  shell string, which eliminates shell-injection risk even for adversarially
  crafted image tags.
- stdout/stderr are captured as bytes and decoded after the process exits;
  the pipe buffers are bounded by the --output flag producing JSON to stdout
  and Syft limiting its own stderr to diagnostic text.
- A configurable timeout is enforced; the process is killed (not just waited)
  on expiry so it cannot hold resources indefinitely.
- The environment passed to the subprocess is explicitly constructed from a
  safe subset; the full inherited environment is never forwarded unfiltered
  because it may carry credentials or paths not intended for Syft.
- PATH is explicitly forwarded so Syft can resolve its own dependencies
  (e.g. Java runners for some package types) without requiring an absolute
  Syft binary path.
- No subprocess output is evaluated or exec'd; it is only JSON-parsed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any

import structlog

from app.domain.exceptions import (
    SyftImageNotFoundError,
    SyftNotInstalledError,
    SyftParseError,
    SyftTimeoutError,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_TIMEOUT_SECONDS: float = 300.0
"""Default Syft invocation timeout in seconds (5 min)."""

_SYFT_OUTPUT_FORMAT: str = "cyclonedx-json"
"""Syft output format that produces CycloneDX JSON on stdout."""

# Phrases that appear in Syft stderr when the image is not found.
# These are checked against lowercased stderr; they are informational
# heuristics, not authoritative signals.
_IMAGE_NOT_FOUND_PHRASES: tuple[str, ...] = (
    "image not found",
    "does not exist",
    "pull access denied",
    "manifest unknown",
    "not found",
    "no such image",
)


class SyftClient:
    """Subprocess wrapper for the Syft SBOM generation CLI.

    Invokes ``syft <image_reference> --output cyclonedx-json`` and returns
    the parsed CycloneDX document. All subprocess interactions are safe:
    arguments are passed as an explicit list (not a shell string), and the
    environment is a controlled subset of the host environment.

    Args:
        syft_path: Absolute path or command name for the Syft binary.
            Defaults to ``"syft"`` (resolved via PATH at call time).
        timeout_seconds: Maximum allowed wall-clock time for one Syft
            invocation in seconds. Defaults to 300.
        extra_env: Optional additional environment variables to pass to
            Syft. Merged with the safe base environment; callers must not
            pass secrets here because they appear in process environment.
    """

    def __init__(
        self,
        syft_path: str = "syft",
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        extra_env: dict[str, str] | None = None,
    ) -> None:
        """Initialise the Syft client.

        Args:
            syft_path: Path or command name for the Syft binary.
            timeout_seconds: Subprocess timeout in seconds.
            extra_env: Optional extra environment variables for Syft.
        """
        self._syft_path = syft_path
        self._timeout_seconds = timeout_seconds
        self._extra_env = extra_env or {}

    def _build_env(self) -> dict[str, str]:
        """Build a safe environment dict for the Syft subprocess.

        Only PATH, HOME, and a minimal safe set are forwarded.
        The full process environment is NOT forwarded to prevent
        leaking credentials (e.g., AWS_SECRET_ACCESS_KEY) into Syft.

        Returns:
            A dict of safe environment variables.
        """
        safe_keys = {"PATH", "HOME", "USER", "TMPDIR", "TEMP", "TMP", "DOCKER_HOST"}
        env: dict[str, str] = {
            k: v for k, v in os.environ.items() if k in safe_keys
        }
        # Ensure PATH is always set so Syft's own dependencies resolve.
        if "PATH" not in env:
            env["PATH"] = os.defpath or "/usr/local/bin:/usr/bin:/bin"
        # Merge caller-supplied extras (must not include secrets).
        env.update(self._extra_env)
        return env

    def _resolve_syft_binary(self) -> str:
        """Resolve the Syft binary path, raising if not found.

        Returns:
            The resolved absolute path to the Syft binary.

        Raises:
            SyftNotInstalledError: If the binary cannot be found.
        """
        # shutil.which searches PATH safely without shell expansion.
        resolved = shutil.which(self._syft_path)
        if resolved is None:
            raise SyftNotInstalledError(syft_path=self._syft_path)
        return resolved

    def generate_sbom(self, image_reference: str) -> dict[str, Any]:
        """Generate a CycloneDX SBOM for the specified container image.

        Security: ``image_reference`` is passed as a discrete argv element,
        never interpolated into a shell command string. Shell injection via
        crafted image references (e.g. ``; rm -rf /``) is therefore not
        possible.

        Args:
            image_reference: Docker image reference to analyse (e.g.
                ``"nginx:1.27"`` or ``"sha256:abc123..."``).

        Returns:
            Parsed CycloneDX JSON document as a Python dict.

        Raises:
            SyftNotInstalledError: If the Syft binary is not found.
            SyftImageNotFoundError: If Syft cannot locate or pull the image.
            SyftTimeoutError: If Syft does not complete within the timeout.
            SyftParseError: If Syft output cannot be parsed as CycloneDX JSON.
        """
        resolved_binary = self._resolve_syft_binary()

        # Explicit argument list — NEVER use shell=True or string formatting
        # to embed image_reference into a command string.
        argv: list[str] = [
            resolved_binary,
            image_reference,          # positional: the image to scan
            "--output",               # flag to select output format
            _SYFT_OUTPUT_FORMAT,      # cyclonedx-json
            "--quiet",                # suppress progress output on stderr
        ]

        bound_log = log.bind(
            image_reference=image_reference,
            syft_path=resolved_binary,
            timeout_seconds=self._timeout_seconds,
        )
        bound_log.info("syft_client.generate_sbom.started")

        try:
            result = subprocess.run(  # noqa: S603 — argv is an explicit list
                argv,
                # capture_output=True captures both stdout and stderr as bytes
                # so they are bounded and never fed back to a shell.
                capture_output=True,
                timeout=self._timeout_seconds,
                # Pass controlled environment (not full os.environ).
                env=self._build_env(),
                # Do NOT use shell=True — the image reference must never be
                # interpreted by a shell, even if it contains special chars.
                shell=False,         # explicit for auditing clarity
                # check=False so we can distinguish image-not-found from
                # other non-zero exits by inspecting stderr ourselves.
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            bound_log.warning("syft_client.generate_sbom.timeout")
            raise SyftTimeoutError(timeout_seconds=self._timeout_seconds) from exc
        except FileNotFoundError as exc:
            # Binary disappeared between _resolve_syft_binary() and run().
            raise SyftNotInstalledError(syft_path=resolved_binary) from exc

        stderr_text = result.stderr.decode("utf-8", errors="replace")

        if result.returncode != 0:
            bound_log.warning(
                "syft_client.generate_sbom.nonzero_exit",
                returncode=result.returncode,
                stderr=stderr_text[:512],
            )
            # Distinguish "image not found" from other Syft errors.
            stderr_lower = stderr_text.lower()
            if any(phrase in stderr_lower for phrase in _IMAGE_NOT_FOUND_PHRASES):
                raise SyftImageNotFoundError(image_reference=image_reference)
            raise SyftParseError(
                f"Syft exited with code {result.returncode}; "
                f"stderr: {stderr_text[:256]}"
            )

        # Parse JSON output — subprocess stdout is bytes, not a shell string.
        # This is safe: only JSON parsing happens, no eval or exec.
        stdout_text = result.stdout.decode("utf-8", errors="replace")
        try:
            document: dict[str, Any] = json.loads(stdout_text)
        except json.JSONDecodeError as exc:
            bound_log.error(
                "syft_client.generate_sbom.parse_error",
                preview=stdout_text[:256],
            )
            raise SyftParseError(
                f"Syft produced non-JSON output: {exc}"
            ) from exc

        if not isinstance(document, dict):
            raise SyftParseError(
                f"Syft output is not a JSON object (got {type(document).__name__})"
            )

        bound_log.info(
            "syft_client.generate_sbom.succeeded",
            bom_format=document.get("bomFormat"),
            component_count=len(document.get("components", [])),
        )
        return document
