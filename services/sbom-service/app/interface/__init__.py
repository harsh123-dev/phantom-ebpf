"""
sbom-service interface layer.

Internal FastAPI routers, Pydantic DTOs, and dependency-injection
wiring for all SBOM endpoints. This layer is not internet-facing;
all public traffic is routed through api-gateway.
"""
