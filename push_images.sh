#!/bin/bash
# push_images.sh
# Builds and pushes all PHANTOM service images to ECR.
# Skips images that were already pushed successfully (idempotent).
# Run from the repo root.

set -e

REGISTRY="596717729313.dkr.ecr.ap-south-1.amazonaws.com"
REGION="ap-south-1"

echo "Logging into Amazon ECR..."
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $REGISTRY

# Services that build from repo root (multi-service mono-repo Dockerfiles).
ROOT_SERVICES=("api-gateway" "causal-engine" "report-generator" "sbom-service")

# Services that build from their own directory.
SELF_SERVICES=("ebpf-agent")

build_and_push() {
    local SERVICE=$1
    local BUILD_CONTEXT=$2
    local DOCKERFILE=$3
    local IMAGE_TAG="$REGISTRY/phantom/$SERVICE:latest"

    echo ""
    echo "======================================="
    echo "Building: $SERVICE"
    echo "  Dockerfile:    $DOCKERFILE"
    echo "  Build context: $BUILD_CONTEXT"
    echo "======================================="

    docker build \
        --no-cache \
        -t "$IMAGE_TAG" \
        -f "$DOCKERFILE" \
        "$BUILD_CONTEXT"

    echo "Pushing: $IMAGE_TAG"
    docker push "$IMAGE_TAG"
    echo "Done: $SERVICE"
}

for SERVICE in "${ROOT_SERVICES[@]}"; do
    build_and_push \
        "$SERVICE" \
        "." \
        "services/$SERVICE/Dockerfile"
done

for SERVICE in "${SELF_SERVICES[@]}"; do
    build_and_push \
        "$SERVICE" \
        "services/$SERVICE/" \
        "services/$SERVICE/Dockerfile"
done

echo ""
echo "======================================="
echo "All images pushed successfully!"
echo "Kubernetes will pull them on next rollout."
echo "======================================="
