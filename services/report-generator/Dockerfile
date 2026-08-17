# report-generator Dockerfile
# Multi-stage build. Runs as non-root worker; not internet-facing.
#
# IMPORTANT: Build from the repo root, not from services/report-generator/:
#   docker build -f services/report-generator/Dockerfile -t phantom/report-generator:$IMAGE_TAG .

# Stage 1: build phantom-core (local library — not on PyPI)
FROM python:3.11-slim AS core-builder
WORKDIR /build
COPY libs/phantom-core/ ./
RUN pip install --no-cache-dir build && python -m build --wheel

# Stage 2: build the report-generator wheel
FROM python:3.11-slim AS svc-builder
WORKDIR /build
COPY services/report-generator/pyproject.toml ./
RUN pip install --no-cache-dir build && python -m build --wheel

# Stage 3: minimal runtime image
FROM python:3.11-slim AS runtime
LABEL org.opencontainers.image.title="PHANTOM report-generator"
LABEL org.opencontainers.image.source="https://github.com/phantom-research/phantom"
WORKDIR /app
# Install phantom-core first (local dep), then the service
COPY --from=core-builder /build/dist/*.whl /tmp/
COPY --from=svc-builder  /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
COPY services/report-generator/app/ ./app/
RUN useradd -r -u 1000 -g root phantom && chown -R phantom:root /app
USER phantom
ENTRYPOINT ["python", "-m", "app.interface.worker"]
