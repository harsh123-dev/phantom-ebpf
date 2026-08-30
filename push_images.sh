#!/bin/bash
set -e

REGISTRY="596717729313.dkr.ecr.ap-south-1.amazonaws.com"

echo "Logging into Amazon ECR..."
aws ecr get-login-password --region ap-south-1 | docker login --username AWS --password-stdin $REGISTRY

SERVICES=("api-gateway" "causal-engine" "report-generator" "sbom-service" "ebpf-agent")

for SERVICE in "${SERVICES[@]}"; do
    echo "======================================="
    echo "Building and Pushing $SERVICE"
    echo "======================================="
    IMAGE_TAG="$REGISTRY/phantom/$SERVICE:latest"
    
    if [ "$SERVICE" == "ebpf-agent" ]; then
        docker build -t $IMAGE_TAG -f services/$SERVICE/Dockerfile services/$SERVICE/
    else
        docker build -t $IMAGE_TAG -f services/$SERVICE/Dockerfile .
    fi
    docker push $IMAGE_TAG
done

echo "All images pushed successfully! Kubernetes will now automatically pull them."
