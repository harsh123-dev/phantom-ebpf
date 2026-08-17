# causal-engine Dockerfile
# Multi-stage build. CPU/memory-intensive; runs as non-root non-privileged worker.

FROM python:3.11-slim AS builder
WORKDIR /build
COPY pyproject.toml ./
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.11-slim AS runtime
LABEL org.opencontainers.image.title="PHANTOM causal-engine"
LABEL org.opencontainers.image.source="https://github.com/phantom-research/phantom"
WORKDIR /app
# Install native deps for DoWhy/XGBoost (e.g. libgomp)
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    libgomp1 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
COPY app/ ./app/
RUN useradd -r -u 1000 -g root phantom && chown -R phantom:root /app
USER phantom
ENTRYPOINT ["python", "-m", "app.interface.worker"]
