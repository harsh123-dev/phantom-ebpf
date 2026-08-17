"""
sbom-service infrastructure layer.

Concrete adapters for:
- asyncpg PostgreSQL repository
- Object-store (S3-compatible) artifact storage
- Syft CLI SBOM generation adapter
- cosign/Sigstore signature verification adapter

May import from domain/ ports only via dependency injection.
"""
