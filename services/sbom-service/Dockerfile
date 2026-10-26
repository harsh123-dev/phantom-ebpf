# sbom-service Dockerfile
# Multi-stage build: builder installs dependencies; runtime is minimal.
# This image runs as a non-root user; it is NOT privileged.
#
# IMPORTANT: Build from the repo root, not from services/sbom-service/:
#   docker build -f services/sbom-service/Dockerfile -t phantom/sbom-service:$IMAGE_TAG .

# Stage 1: build phantom-core (local library — not on PyPI)
FROM python:3.11-slim AS core-builder
WORKDIR /build
COPY libs/phantom-core/ ./
RUN pip install --no-cache-dir build && python -m build --wheel

# Stage 2: build the sbom-service wheel
FROM python:3.11-slim AS svc-builder
WORKDIR /build
COPY services/sbom-service/pyproject.toml ./
RUN pip install --no-cache-dir build && python -m build --wheel

# Stage 3: minimal runtime image
FROM python:3.11-slim AS runtime
LABEL org.opencontainers.image.title="PHANTOM sbom-service"
LABEL org.opencontainers.image.source="https://github.com/phantom-research/phantom"
WORKDIR /app
# Pin the official Cosign release binary by its GitHub release SHA-256.
# Tool integrity does not establish trust in any SBOM signer.
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN test "$(dpkg --print-architecture)" = amd64 && \
    curl -fsSL --retry 3 \
      https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64 \
      -o /usr/local/bin/cosign && \
    echo '424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa  /usr/local/bin/cosign' \
      | sha256sum -c - && chmod 0755 /usr/local/bin/cosign
# Install phantom-core first (local dep), then the service
COPY --from=core-builder /build/dist/*.whl /tmp/
COPY --from=svc-builder  /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
COPY services/sbom-service/app/ ./app/
RUN useradd -r -u 1000 -g root phantom && chown -R phantom:root /app
USER phantom
EXPOSE 8000
ENTRYPOINT ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
