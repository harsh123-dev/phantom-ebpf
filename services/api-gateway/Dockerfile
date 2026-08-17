# api-gateway Dockerfile
# Multi-stage build. This is the only internet-facing service image.
#
# IMPORTANT: Build from the repo root, not from services/api-gateway/:
#   docker build -f services/api-gateway/Dockerfile -t phantom/api-gateway:$IMAGE_TAG .

# Stage 1: build phantom-core (local library — not on PyPI)
FROM python:3.11-slim AS core-builder
WORKDIR /build
COPY libs/phantom-core/ ./
RUN pip install --no-cache-dir build && python -m build --wheel

# Stage 2: build the api-gateway service wheel
FROM python:3.11-slim AS svc-builder
WORKDIR /build
COPY services/api-gateway/pyproject.toml ./
RUN pip install --no-cache-dir build && python -m build --wheel

# Stage 3: minimal runtime image
FROM python:3.11-slim AS runtime
LABEL org.opencontainers.image.title="PHANTOM api-gateway"
LABEL org.opencontainers.image.source="https://github.com/phantom-research/phantom"
WORKDIR /app
# Install phantom-core first (local dep), then the service
COPY --from=core-builder /build/dist/*.whl /tmp/
COPY --from=svc-builder  /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
COPY services/api-gateway/app/ ./app/
RUN useradd -r -u 1000 -g root phantom && chown -R phantom:root /app
USER phantom
EXPOSE 8080
ENTRYPOINT ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
