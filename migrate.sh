#!/bin/bash
set -e

cd infra/terraform/environments/dev
RDS_ENDPOINT=$(terraform output -raw rds_endpoint)
RDS_PASSWORD=$(terraform output -raw rds_password)
cd ../../../../

echo "Creating configmap for sbom-service migrations..."
kubectl create configmap sbom-migrations --from-file=services/sbom-service/app/infrastructure/postgres/migrations/ -n phantom --dry-run=client -o yaml | kubectl apply -f -

echo "Running migration job..."
cat << EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: sbom-migration
  namespace: phantom
spec:
  template:
    spec:
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
          for f in /migrations/*.sql; do
            echo "Applying \$f"
            psql -h $RDS_ENDPOINT -U phantom_admin -d phantom -f "\$f"
          done
        volumeMounts:
        - name: migrations
          mountPath: /migrations
      volumes:
      - name: migrations
        configMap:
          name: sbom-migrations
      restartPolicy: Never
  backoffLimit: 1
EOF

echo "Waiting for migrations to finish..."
kubectl wait --for=condition=complete job/sbom-migration -n phantom --timeout=60s
kubectl delete job sbom-migration -n phantom
echo "Migrations complete!"
