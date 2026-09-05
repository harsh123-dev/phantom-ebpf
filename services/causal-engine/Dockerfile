# causal-engine Dockerfile
# Multi-stage build. CPU/memory-intensive; runs as non-root non-privileged worker.
#
# IMPORTANT: Build from the repo root, not from services/causal-engine/:
#   docker build -f services/causal-engine/Dockerfile -t phantom/causal-engine:$IMAGE_TAG .

# Stage 1: build phantom-core (local library — not on PyPI)
FROM python:3.11-slim AS core-builder
WORKDIR /build
COPY libs/phantom-core/ ./
RUN pip install --no-cache-dir build && python -m build --wheel

# Stage 2: build the causal-engine service wheel
FROM python:3.11-slim AS svc-builder
WORKDIR /build
COPY services/causal-engine/pyproject.toml ./
RUN pip install --no-cache-dir build && python -m build --wheel

# Stage 3: minimal runtime image
FROM python:3.11-slim AS runtime
LABEL org.opencontainers.image.title="PHANTOM causal-engine"
LABEL org.opencontainers.image.source="https://github.com/phantom-research/phantom"
WORKDIR /app
# Install native deps for DoWhy/XGBoost (e.g. libgomp)
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    libgomp1 && rm -rf /var/lib/apt/lists/*
# Install phantom-core first (local dep), then the service.
# Use the PyTorch CPU-only index so torch+cpu resolves without a CUDA wheel.
COPY --from=core-builder /build/dist/*.whl /tmp/
COPY --from=svc-builder  /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir \
    --extra-index-url https://download.pytorch.org/whl/cpu \
    /tmp/*.whl \
    && rm /tmp/*.whl
COPY services/causal-engine/app/ ./app/
RUN useradd -r -u 1000 -g root phantom && chown -R phantom:root /app
USER phantom
ENTRYPOINT ["python", "-m", "app.interface.worker"]
