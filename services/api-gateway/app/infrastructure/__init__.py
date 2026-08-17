"""
api-gateway infrastructure layer.

Concrete adapters for:
- asyncpg: transactional outbox and drift event persistence
- aioredis: Redis Streams outbox publisher and WebSocket fan-out
- JWKS auth: JWT validation and role extraction
- HTTP service clients: sbom-service, causal-engine, report-generator
"""
