"""
phantom-core: shared PHANTOM library.

Provides all Pydantic models from the API contracts, typed exceptions,
central constants, and structlog configuration for all PHANTOM services.

Import rules:
  - phantom-core MUST NOT import from any PHANTOM service package.
  - All models are Pydantic v2 BaseModel subclasses.
  - All constants are defined in phantom_core.constants; no magic numbers
    in service code.
"""

from phantom_core import metrics
from phantom_core.constants import APP_NAME, SCHEMA_VERSION
from phantom_core.logging import configure_structlog

__all__ = [
    "SCHEMA_VERSION",
    "APP_NAME",
    "configure_structlog",
    "metrics",
]
