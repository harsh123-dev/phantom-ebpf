# report-generator Dockerfile
# Multi-stage build. Runs as non-root worker; not internet-facing.

FROM python:3.11-slim AS builder
WORKDIR /build
COPY pyproject.toml ./
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.11-slim AS runtime
LABEL org.opencontainers.image.title="PHANTOM report-generator"
LABEL org.opencontainers.image.source="https://github.com/phantom-research/phantom"
WORKDIR /app
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
COPY app/ ./app/
RUN useradd -r -u 1000 -g root phantom && chown -R phantom:root /app
USER phantom
ENTRYPOINT ["python", "-m", "app.interface.worker"]
