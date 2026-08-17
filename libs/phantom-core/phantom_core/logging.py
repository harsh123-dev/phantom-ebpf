"""
phantom_core.logging — Canonical structlog configuration for all PHANTOM services.

Usage in every service ``main.py`` or worker entry point::

    from phantom_core.logging import configure_structlog
    configure_structlog(service_name="api-gateway", log_level="INFO")

All PHANTOM code MUST use ``structlog.get_logger()`` and MUST NOT call
``print()`` or use the stdlib ``logging`` module directly for application
log output.

The configuration:
- Adds ``service``, ``schema_version``, and UTC ``timestamp`` to every event.
- Uses JSON renderer in production (LOG_FORMAT=json) and a colored console
  renderer in development (LOG_FORMAT=console).
- Integrates with the stdlib ``logging`` module so that third-party library
  logs (asyncpg, uvicorn, httpx) are captured through the same pipeline.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable, MutableMapping
from typing import Any

import structlog

from phantom_core.constants import SCHEMA_VERSION


def configure_structlog(
    service_name: str,
    log_level: str = "INFO",
    log_format: str = "json",
) -> None:
    """Configure structlog for the given PHANTOM service.

    Must be called once at process startup, before any logger is created.
    Subsequent calls are idempotent (structlog ignores re-configuration after
    the first call in most deployments; services should call this only once).

    Args:
        service_name: Human-readable service identifier injected into every
            log record as the ``service`` field (e.g. ``"api-gateway"``).
        log_level: Standard Python log-level string (``"DEBUG"``, ``"INFO"``,
            ``"WARNING"``, ``"ERROR"``, ``"CRITICAL"``). Defaults to
            ``"INFO"``.
        log_format: Output format. ``"json"`` for structured JSON (production);
            ``"console"`` for coloured human-readable output (development).
            Defaults to ``"json"``.

    Returns:
        None

    Raises:
        ValueError: If ``log_format`` is not one of ``"json"`` or
            ``"console"``.
    """
    if log_format not in ("json", "console"):
        raise ValueError(
            f"log_format must be 'json' or 'console', got {log_format!r}"
        )

    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level!r}")

    # Configure stdlib logging first — this provides a .name attribute on
    # the underlying logger, fixing Python 3.14 compatibility where
    # PrintLogger no longer carries .name.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=numeric_level,
    )

    shared_processors: list[Any] = [
        # Inject service name and schema_version into every event dict.
        structlog.contextvars.merge_contextvars,
        _add_service_fields(service_name),
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if log_format == "json":
        renderer: Any = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def _add_service_fields(
    service_name: str,
) -> Callable[
    [structlog.types.WrappedLogger, str, MutableMapping[str, Any]],
    MutableMapping[str, Any],
]:
    """Return a structlog processor that injects service metadata.

    Args:
        service_name: The service name to embed in every log record.

    Returns:
        A structlog processor callable.
    """

    def processor(
        logger: structlog.types.WrappedLogger,
        method: str,
        event_dict: MutableMapping[str, Any],
    ) -> MutableMapping[str, Any]:
        """Inject ``service`` and ``schema_version`` fields.

        Args:
            logger: The wrapped logger instance (unused).
            method: The log method name (unused).
            event_dict: The mutable structlog event dictionary.

        Returns:
            The mutated event dictionary with service metadata added.
        """
        event_dict.setdefault("service", service_name)
        event_dict.setdefault("schema_version", SCHEMA_VERSION)
        return event_dict

    return processor
