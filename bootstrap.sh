#!/bin/bash
set -e

echo "==========================================="
echo "   PHANTOM Environment Bootstrap Script    "
echo "==========================================="

echo ""
echo "[1/5] Extracting Terraform Outputs..."
cd infra/terraform/environments/dev
RDS_ENDPOINT=$(terraform output -raw rds_endpoint)
REDIS_ENDPOINT=$(terraform output -raw redis_endpoint)
RDS_PASSWORD=$(terraform output -raw rds_password)
cd ../../../../

if [ -z "$RDS_ENDPOINT" ] || [ -z "$REDIS_ENDPOINT" ]; then
    echo "Error: Could not extract Terraform outputs. Are you sure 'terraform apply' succeeded?"
    exit 1
fi

echo ""
echo "[2/5] Configuring Kubernetes Namespaces & RBAC..."
kubectl apply -f infra/k8s/rbac/phantom-rbac.yaml

echo "[3/5] Configuring ConfigMap..."
cp infra/k8s/configmaps.yaml infra/k8s/configmaps.tmp.yaml
sed -i "s/REPLACE_WITH_RDS_ENDPOINT/$RDS_ENDPOINT/g" infra/k8s/configmaps.tmp.yaml
sed -i "s/REPLACE_WITH_ELASTICACHE_ENDPOINT/$REDIS_ENDPOINT/g" infra/k8s/configmaps.tmp.yaml
kubectl apply -f infra/k8s/configmaps.tmp.yaml
rm infra/k8s/configmaps.tmp.yaml

echo "[4/5] Creating Kubernetes Secrets..."
# Delete old secrets if they exist to prevent errors
kubectl delete secret phantom-api-gateway-secret phantom-causal-engine-secret phantom-sbom-service-secret phantom-report-generator-secret phantom-agent-secret -n phantom --ignore-not-found 2>/dev/null

JWT_SECRET=$(openssl rand -hex 32)
API_KEY=$(openssl rand -hex 16)

kubectl create secret generic phantom-api-gateway-secret -n phantom \
  --from-literal=postgres_password="$RDS_PASSWORD" \
  --from-literal=jwks_uri="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_xxxx/.well-known/jwks.json"

kubectl create secret generic phantom-causal-engine-secret -n phantom \
  --from-literal=postgres_password="$RDS_PASSWORD" \
  --from-literal=api_key="$API_KEY"

kubectl create secret generic phantom-sbom-service-secret -n phantom \
  --from-literal=postgres_password="$RDS_PASSWORD" \
  --from-literal=s3_access_key_id="dummy" \
  --from-literal=s3_secret_access_key="dummy"

kubectl create secret generic phantom-report-generator-secret -n phantom \
  --from-literal=postgres_password="$RDS_PASSWORD" \
  --from-literal=api_key="$API_KEY"

kubectl create secret generic phantom-agent-secret -n phantom \
  --from-literal=api_key="$API_KEY"

echo "[5/5] Deploying Microservices..."
kubectl apply -f infra/k8s/api-gateway-deployment.yaml

echo ""
echo "==========================================="
echo "   Bootstrap Complete!                     "
echo "==========================================="
echo "Next Steps:"
echo "1. Run the frontend: cd frontend && npm run dev"
echo "2. Port forward the API: kubectl port-forward svc/phantom-api-gateway 8080:8080 -n phantom --address 0.0.0.0 &"
