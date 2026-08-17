# ebpf-agent Dockerfile
# Privileged DaemonSet image. Builds CO-RE eBPF objects + C user-space agent.
# SECURITY: This image requires privileged execution to load eBPF programs.
# It must never be exposed to the internet.

FROM ubuntu:22.04 AS builder
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    clang llvm libelf-dev libbpf-dev linux-headers-generic \
    make gcc pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY include/ ./include/
COPY bpf/     ./bpf/
COPY cmd/     ./cmd/
COPY Makefile ./Makefile
# Build eBPF objects and user-space loader
RUN make all

FROM ubuntu:22.04 AS runtime
LABEL org.opencontainers.image.title="PHANTOM ebpf-agent"
LABEL org.opencontainers.image.source="https://github.com/phantom-research/phantom"
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    libelf1 libbpf0 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /agent
COPY --from=builder /build/phantom-agent ./phantom-agent
COPY --from=builder /build/bpf/*.o       ./bpf/
# NOTE: Requires privileged + hostPID + hostNetwork in DaemonSet spec.
ENTRYPOINT ["/agent/phantom-agent"]
