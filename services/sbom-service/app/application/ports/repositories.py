"""
services/sbom-service/app/application/ports/repositories.py

Abstract repository interfaces for the SBOM service application layer.

Rules:
- Only imports from domain/ are permitted.
- All methods are abstract with complete type signatures and Google-style docstrings.
- No implementation code is present here.

The domain already defines the port ABCs in domain/ports.py.
This module re-exports them as the canonical application-layer contracts
and provides additional composite port types needed only by use-cases.
"""

from __future__ import annotations

# Re-export the domain port ABCs as the application-layer contract.
# Use-cases import exclusively from this module so that they
# remain decoupled from the domain/ports implementation details.
from app.domain.ports import (
    ArtifactStorePort,
    ComponentRepositoryPort,
    SbomRepositoryPort,
    SbomVerifierPort,
    VerificationJobRepositoryPort,
)

__all__ = [
    "SbomRepositoryPort",
    "ComponentRepositoryPort",
    "VerificationJobRepositoryPort",
    "SbomVerifierPort",
    "ArtifactStorePort",
]
