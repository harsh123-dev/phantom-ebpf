# ebpf-agent Dockerfile
# Privileged DaemonSet image. Builds CO-RE eBPF objects + C user-space agent.
# SECURITY: This image requires privileged execution to load eBPF programs.
# It must never be exposed to the internet.

FROM ubuntu:22.04 AS builder
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    clang llvm libelf-dev libbpf-dev linux-headers-generic \
    make gcc pkg-config linux-tools-generic && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY include/ ./include/
COPY bpf/     ./bpf/
COPY cmd/     ./cmd/
COPY Makefile ./Makefile
# Download a standard x86_64 vmlinux.h (since /sys/kernel/btf/vmlinux is not accessible inside Docker build).
# The x86/vmlinux.h entry in eunomia-bpf/vmlinux is a symlink; raw GitHub
# serves symlink contents as plain text, so fetch the concrete target instead.
RUN apt-get update -qq && apt-get install -y curl && \
    curl -fsSL "https://raw.githubusercontent.com/eunomia-bpf/vmlinux/master/x86/vmlinux_508.h" -o ./include/vmlinux.h && \
    grep -q "^#ifndef __VMLINUX_H" ./include/vmlinux.h
# Build eBPF objects and user-space loader
RUN make all

FROM python:3.11-slim AS runtime
LABEL org.opencontainers.image.title="PHANTOM ebpf-agent"
LABEL org.opencontainers.image.source="https://github.com/phantom-research/phantom"
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    libelf1 libbpf1 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /agent
COPY --from=builder /build/phantom-agent ./phantom-agent
COPY --from=builder /build/bpf/*.o       ./bpf/

# Install python dependencies
COPY pyproject.toml ./
COPY application/ ./application/
COPY infrastructure/ ./infrastructure/
COPY domain/ ./domain/
COPY include/ ./include/

RUN pip3 install --no-cache-dir \
    'structlog>=23.1.0' 'pydantic>=2.5.0' 'kubernetes>=28.1.0' \
    'redis[hiredis]>=5.0.1' 'aiobotocore>=2.7.0' 'prometheus-client>=0.19.0' \
    'aiohttp>=3.9.0'

# NOTE: Requires privileged + hostPID + hostNetwork in DaemonSet spec.
ENTRYPOINT ["python3", "-m", "application.main"]
