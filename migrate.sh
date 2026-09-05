#!/bin/bash
# migrate.sh
# Applies ALL database migrations in order:
#   1. api-gateway migrations (001–006): core schema tables
#   2. sbom-service migrations: sbom-specific tables
#
# Must be run AFTER terraform apply (RDS endpoint must exist).
# Run from the repo root.

set -e

echo "==== PHANTOM Database Migration ===="

# Resolve RDS connection details from Terraform outputs.
cd infra/terraform/environments/dev
RDS_ENDPOINT=$(terraform output -raw rds_endpoint)
RDS_PASSWORD=$(terraform output -raw rds_password)
cd ../../../../

echo "RDS Endpoint: $RDS_ENDPOINT"

# ---------------------------------------------------------------------------
# 1. api-gateway migrations (001_drift_events → 006_incidents)
#    These must run in order because each migration has FK dependencies on
#    tables created in earlier migrations.
# ---------------------------------------------------------------------------

echo ""
echo "--- Running api-gateway migrations ---"

kubectl create configmap api-gateway-migrations \
    --from-file=services/api-gateway/app/infrastructure/migrations/ \
    -n phantom --dry-run=client -o yaml | kubectl apply -f -

cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: api-gateway-migration
  namespace: phantom
spec:
  ttlSecondsAfterFinished: 300
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: psql
        image: postgres:15-alpine
        env:
        - name: PGPASSWORD
          value: "$RDS_PASSWORD"
        command:
        - sh
        - -c
        - |
          set -e
          # Run in explicit numeric order to respect FK constraints.
          for f in \$(ls /migrations/*.sql | sort); do
            echo "Applying \$f ..."
            psql -h $RDS_ENDPOINT -U phantom_admin -d phantom -f "\$f"
          done
          echo "api-gateway migrations complete."
        volumeMounts:
        - name: migrations
          mountPath: /migrations
      volumes:
      - name: migrations
        configMap:
          name: api-gateway-migrations
  backoffLimit: 0
EOF

echo "Waiting for api-gateway migrations to complete (up to 5 minutes)..."
kubectl wait --for=condition=complete job/api-gateway-migration -n phantom --timeout=300s
kubectl delete job api-gateway-migration -n phantom --ignore-not-found
echo "api-gateway migrations applied successfully."

# ---------------------------------------------------------------------------
# 2. sbom-service migrations
# ---------------------------------------------------------------------------

echo ""
echo "--- Running sbom-service migrations ---"

kubectl create configmap sbom-migrations \
    --from-file=services/sbom-service/app/infrastructure/postgres/migrations/ \
    -n phantom --dry-run=client -o yaml | kubectl apply -f -

cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: sbom-migration
  namespace: phantom
spec:
  ttlSecondsAfterFinished: 300
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: psql
        image: postgres:15-alpine
        env:
        - name: PGPASSWORD
          value: "$RDS_PASSWORD"
        command:
        - sh
        - -c
        - |
          set -e
          for f in \$(ls /migrations/*.sql | sort); do
            echo "Applying \$f ..."
            psql -h $RDS_ENDPOINT -U phantom_admin -d phantom -f "\$f"
          done
          echo "sbom-service migrations complete."
        volumeMounts:
        - name: migrations
          mountPath: /migrations
      volumes:
      - name: migrations
        configMap:
          name: sbom-migrations
  backoffLimit: 0
EOF

echo "Waiting for sbom-service migrations to complete (up to 5 minutes)..."
kubectl wait --for=condition=complete job/sbom-migration -n phantom --timeout=300s
kubectl delete job sbom-migration -n phantom --ignore-not-found
echo "sbom-service migrations applied successfully."

echo ""
echo "==== All migrations complete! ===="
