"""
Tests for phantom_core.logging — validates structlog configuration.
"""

from __future__ import annotations

import pytest

from phantom_core.logging import configure_structlog


class TestConfigureStructlog:
    """Tests for the configure_structlog factory."""

    def test_valid_json_format(self) -> None:
        """configure_structlog with 'json' format should not raise."""
        configure_structlog(service_name="test-service", log_format="json")

    def test_valid_console_format(self) -> None:
        """configure_structlog with 'console' format should not raise."""
        configure_structlog(service_name="test-service", log_format="console")

    def test_invalid_format(self) -> None:
        """configure_structlog with an unknown format must raise ValueError."""
        with pytest.raises(ValueError, match="log_format"):
            configure_structlog(service_name="test", log_format="xml")

    def test_invalid_log_level(self) -> None:
        """configure_structlog with an invalid log level must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid log level"):
            configure_structlog(service_name="test", log_level="NONEXISTENT")
