"""
services/sbom-service/app/main.py

FastAPI application factory for the SBOM service.

Calls configure_structlog at startup and mounts the router.
"""

from __future__ import annotations

import os

from fastapi import FastAPI
from phantom_core.logging import configure_structlog

from app.interface.dependencies import lifespan
from app.interface.routers import router

configure_structlog(
    service_name="sbom-service",
    log_format=os.environ.get("LOG_FORMAT", "json"),
    log_level=os.environ.get("LOG_LEVEL", "INFO"),
)

app = FastAPI(
    title="PHANTOM SBOM Service",
    description="CycloneDX SBOM ingestion, storage, and cosign verification.",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(router)
