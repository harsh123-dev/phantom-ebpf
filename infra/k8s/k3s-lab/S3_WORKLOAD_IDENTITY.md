# SBOM S3 workload identity for self-managed k3s

## Current state and root cause

The SBOM service uses `aiobotocore==2.13.0` / `botocore==1.34.106` and calls
`aiobotocore.session.get_session().create_client("s3", ...)`. Its default AWS
credential chain supports shared-config `credential_process`, web identity,
container credentials, and EC2 metadata. The current pod has bucket/region/
prefix configuration but no AWS credential provider. Its S3 requests therefore
have no credentials. IMDSv2 is required and the EC2 metadata hop limit is 1, so
ordinary pod networking cannot use the node's instance profile. Increasing the
hop limit or mounting node credentials into the pod would expose the EC2 role's
SSM and backup permissions and is not the fix.

## Selected identity flow

```text
SBOM pod projected ServiceAccount JWT (aud=phantom-aws-credential-broker)
  -> HTTPS credential broker on the k3s node
  -> Kubernetes TokenReview: exact namespace/ServiceAccount, audience, pod UID
  -> broker uses node IMDSv2 credentials to call STS AssumeRole
  -> one-hour S3-only workload role credentials
  -> credential_process -> aiobotocore -> existing S3 bucket/prefix
```

The broker is a dedicated, non-root, read-only-root-filesystem DaemonSet using
`hostNetwork` so it can reach IMDSv2 with the existing hop limit of 1. It has no
host PID, host filesystem mounts, or extra Linux capabilities. Its cluster-wide
permission is creating TokenReviews; a namespaced read-only Role lets it get
pods, ReplicaSets, and Deployments in `phantom`. It accepts only a pod-bound
token whose TokenReview username is
`system:serviceaccount:phantom:phantom-sbom-service` and whose audience is
`phantom-aws-credential-broker`. It requires the TokenReview pod UID and fails
closed on API errors, missing identity fields, invalid audience, or STS errors.
It then verifies the live pod UID and its controller ownership chain to the
`phantom-sbom-service` Deployment, plus the service account and pod-template
labels. A pod using the same service account but not owned by that Deployment
is rejected. An actor able to create or mutate resources in `phantom` remains
inside the Kubernetes control-plane trust boundary.
The endpoint is HTTPS, with a separately generated private CA; only the server
key is stored in a Kubernetes TLS Secret. The SBOM pod receives the CA
certificate, not the server key or any AWS credentials.

The broker's source EC2 role remains the existing SSM/backup role, and stays on
the node. Terraform grants that role `sts:AssumeRole` only for the dedicated
SBOM workload role. The workload role is limited to `s3:GetObject` and
`s3:PutObject` for `<bucket>/phantom/evidence/sboms/*`; it has no bucket-list or
delete permission. The broker further applies the same object-prefix session
policy and returns one-hour sessions. It refreshes its cached STS session when
less than 20 minutes remain, leaving margin for Botocore's credential-process
refresh window. The SBOM container sets `AWS_EC2_METADATA_DISABLED=true`,
so a broker failure cannot fall back to the node role.

This is a small, self-managed credential broker, not EKS IRSA or EKS Pod
Identity. It avoids a public OIDC issuer, public ingress, NAT, and new AWS
network resources. Its main trade-off is that the broker is a trusted
host-network workload and can use the node's instance profile to assume the
restricted role. A compromised node or broker remains inside that trust
boundary; the SBOM pod itself never receives the instance-profile credentials.
The broker host-network path, IMDSv2 hop-limit behavior, TokenReview, STS role
assumption, and real S3 operations still require live verification after an
approved deployment.

IAM's trust principal is the EC2 instance role, not a Kubernetes identity:
AWS cannot distinguish the broker process from another process that has stolen
the node role credentials. TokenReview gates the broker API, while IMDSv2 hop
limit 1 and pod networking are expected to prevent ordinary non-host-network
pods from obtaining the source credentials. The host, its administrators,
privileged node workloads, and the broker are therefore trusted. This is not
a hard security boundary against node compromise; a design requiring AWS to
cryptographically validate each pod token would need a supported OIDC issuer
or another independent federation service, which this self-managed k3s lab does
not currently configure.

## Network policy

Kubernetes NetworkPolicy has no portable AWS managed-prefix-list or DNS-name
selector. The renderer queries the regional AWS-managed S3 prefix list and
resolves the current IPv4 addresses for the Sigstore TUF CDN, Rekor, and
Fulcio. It emits only those
CIDRs on TCP 443, the private node `/32` on the broker TCP port 18443, DNS to
kube-dns, and the in-cluster PostgreSQL pod on TCP 5432. TLS hostname
verification remains enabled for Sigstore and S3.

The AWS prefix list and Sigstore DNS addresses can change. Regenerate and review
the policy after address changes and before each deployment. This generated
allowlist is still IP-based: Sigstore may use shared cloud/CDN IPs, so the
policy is not an identity boundary; TLS and Cosign's signer/issuer verification
remain required. Do not retain the temporary `0.0.0.0/0:443` SBOM rule after
the generated policy has been tested. The existing S3 Gateway Endpoint routes
regional S3-prefix traffic privately; S3 gateway endpoints have no hourly
endpoint charge.

The SBOM pod's policy allows DNS, Postgres, the private-node broker endpoint,
S3 prefix-list CIDRs, and Sigstore addresses. The broker uses `hostNetwork`, so
Kubernetes NetworkPolicy does not govern its STS traffic. The current EC2
security group permits outbound TCP 443 to `0.0.0.0/0` for package/image
bootstrap; therefore STS access is available but node-level HTTPS egress is not
restricted to STS. Strict host egress would require an STS interface endpoint
with endpoint-specific security-group rules or a separately enforced host
firewall. That infrastructure is not included in the reviewed three-IAM plan.
Do not describe host egress as restricted until such enforcement is deployed
and tested.

## Terraform plan

The feature is disabled by default. Keep the currently deployed no-NAT and
existing evidence-bucket state explicitly selected when planning:

```bash
cd infra/terraform/environments/k3s-lab
terraform fmt -check
terraform init -input=false -backend=false
terraform validate
terraform plan -input=false \
  -var='aws_region=ap-south-1' \
  -var='enable_nat_gateway=false' \
  -var='enable_evidence_backups=true' \
  -var='enable_s3_workload_identity=true' \
  -var='sbom_workload_prefix=phantom/evidence/sboms' \
  -out=/tmp/phantom-sbom-workload-identity.tfplan
terraform show /tmp/phantom-sbom-workload-identity.tfplan
```

With the existing bucket managed by this state, the intended feature delta is
three IAM resources: a workload role, its S3 prefix policy, and one narrowly
scoped `sts:AssumeRole` policy on the dedicated lab role. Expected monthly cost
of these IAM resources is $0; S3 requests/storage remain usage-based. There
must be no EC2 replacement, VPC/security-group change, NAT Gateway, EIP, bucket
replacement, or deletion. Do not apply until a human reviews the actual plan.
The normal plan with `enable_s3_workload_identity=false` should have no identity
resources.

## Operator deployment procedure (not run by this change)

Run from a trusted operator machine with AWS CLI, OpenSSL, kubectl access to the
verified lab context, and the reviewed Terraform plan. Do not put files in Git.

1. Apply only the reviewed Terraform plan and retrieve the role ARN:

   ```bash
   terraform apply /tmp/phantom-sbom-workload-identity.tfplan
   ROLE_ARN="$(terraform output -raw sbom_workload_role_arn)"
   ```

2. Confirm `kubectl config current-context` is the dedicated k3s lab and
   `kubectl get nodes` shows the intended one-node lab. Set `NODE_IP` to that
   node's private `InternalIP`, and `BUCKET` to the existing evidence bucket.
   Do not use a public address.

3. Generate a short-lived internal broker certificate in a protected temporary
   directory. Keep `ca.key` offline; never commit it. The certificate SAN must
   contain the private node IP because the SBOM workload connects directly to
   `https://<private-node-ip>:18443`.

   ```bash
   umask 077
   IDDIR="$(mktemp -d)"
   openssl req -x509 -newkey rsa:3072 -nodes -days 30 \
     -keyout "$IDDIR/ca.key" -out "$IDDIR/ca.crt" \
     -subj '/CN=PHANTOM k3s workload broker CA' \
     -addext 'basicConstraints=critical,CA:TRUE' \
     -addext 'keyUsage=critical,keyCertSign,cRLSign'
   openssl req -new -newkey rsa:2048 -nodes \
     -keyout "$IDDIR/server.key" -out "$IDDIR/server.csr" \
     -subj '/CN=phantom-aws-credential-broker'
   printf 'subjectAltName=IP:%s\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n' "$NODE_IP" > "$IDDIR/server.ext"
   openssl x509 -req -in "$IDDIR/server.csr" -CA "$IDDIR/ca.crt" \
     -CAkey "$IDDIR/ca.key" -CAcreateserial -days 14 \
     -extfile "$IDDIR/server.ext" -out "$IDDIR/server.crt"
   openssl x509 -in "$IDDIR/server.crt" -noout -checkip "$NODE_IP"
   ```

4. Create only the non-secret broker configuration, CA ConfigMaps, and TLS
   Secret. These commands write no AWS key:

   ```bash
   kubectl create namespace phantom-identity --dry-run=client -o yaml | kubectl apply -f -
   kubectl -n phantom-identity create configmap phantom-aws-workload-config \
     --from-literal=region=ap-south-1 --from-literal=role_arn="$ROLE_ARN" \
     --from-literal=bucket="$BUCKET" \
     --from-literal=prefix=phantom/evidence/sboms \
     --dry-run=client -o yaml | kubectl apply -f -
   kubectl -n phantom-identity create configmap phantom-aws-credential-broker-ca \
     --from-file=ca.crt="$IDDIR/ca.crt" --dry-run=client -o yaml | kubectl apply -f -
   kubectl -n phantom-identity create secret tls phantom-aws-credential-broker-tls \
     --cert="$IDDIR/server.crt" --key="$IDDIR/server.key" \
     --dry-run=client -o yaml | kubectl apply -f -
   ```

5. Build and import the broker image from this exact checkout, then apply its
   manifest. Its read-only namespaced Role/RoleBinding for checking pod
   ownership is included. The normal
   `build-images.sh` does not build or deploy optional identity components:

   ```bash
   docker build -f services/aws-credential-broker/Dockerfile -t phantom/aws-credential-broker:latest .
   docker save phantom/aws-credential-broker:latest | sudo k3s ctr -n k8s.io images import -
   kubectl apply -f infra/k8s/k3s-lab/07-aws-credential-broker.yaml
   kubectl -n phantom-identity rollout status daemonset/phantom-aws-credential-broker --timeout=90s
   ```

   Build and import the changed SBOM image as well, then restart only that
   Deployment after the reviewer authorizes the rollout.

6. Create the SBOM credential-process ConfigMap (the URL is the private node
   IP; `config` contains no credentials), create the CA ConfigMap in `phantom`,
   generate the NetworkPolicy, review it, and apply the patch only after the
   plan review. Before patching, preserve the current deployment spec:

   ```bash
   kubectl -n phantom get deployment phantom-sbom-service -o json \
     | jq '{apiVersion, kind, metadata: {name: .metadata.name, namespace: .metadata.namespace}, spec}' \
     > "$IDDIR/sbom-deployment-before-identity.yaml"
   cat > "$IDDIR/aws-config" <<'EOF'
   [profile phantom-sbom]
   region = ap-south-1
   credential_process = python -m app.infrastructure.aws_credential_process
   EOF
   kubectl -n phantom create configmap phantom-sbom-aws-client \
     --from-literal=broker_url="https://${NODE_IP}:18443/v1/credentials" \
     --from-file=config="$IDDIR/aws-config" --dry-run=client -o yaml | kubectl apply -f -
   kubectl -n phantom create configmap phantom-aws-credential-broker-ca \
     --from-file=ca.crt="$IDDIR/ca.crt" --dry-run=client -o yaml | kubectl apply -f -
   AWS_REGION=ap-south-1 PHANTOM_CREDENTIAL_BROKER_NODE_IP="$NODE_IP" \
     python3 infra/k8s/k3s-lab/render-sbom-s3-egress.py > "$IDDIR/sbom-egress.yaml"
   kubectl apply --dry-run=server -f "$IDDIR/sbom-egress.yaml"
   # Review the generated YAML: it must contain no 0.0.0.0/0 egress.
   kubectl apply -f "$IDDIR/sbom-egress.yaml"
   kubectl patch deployment phantom-sbom-service -n phantom \
     --type=strategic --patch-file infra/k8s/k3s-lab/08-sbom-credential-client-patch.yaml
   kubectl rollout status deployment/phantom-sbom-service -n phantom --timeout=90s
   ```

7. Verify credentials without printing them. Run a Python check using
   `aiobotocore.session.get_session().get_credentials()`, assert the method is
   `custom-process`, and call S3 `PutObject` then `GetObject` on a new random
   key beneath `phantom/evidence/sboms/.connectivity-test/`. Print only the
   object key, version ID, byte count, and a content digest. Before deletion,
   verify the exact generated UUID key has no pre-existing versions. The SBOM
   role intentionally cannot delete. An operator with AWS authorization may
   delete only the just-created version by exact `Key` and `VersionId`; never
   issue a prefix-wide delete. Confirm the object/version is absent afterward.
   Also check that the SBOM pod has no AWS key environment variables, that
   `AWS_EC2_METADATA_DISABLED=true`, and that the broker token-review logs do
   not contain tokens or credentials.

8. Only after the S3 probe passes, submit a real signature-verified SBOM via the
   existing API and confirm the exact S3 object plus database record. Do not
   bypass the Cosign trust checks or create a fabricated SBOM record.

## Rollback

1. Save deployment and policy YAMLs as new evidence before changing anything.
2. Restore the SBOM Deployment to its saved pre-feature spec, then wait for
   rollout:

   ```bash
   kubectl apply -f "$IDDIR/sbom-deployment-before-identity.yaml"
   kubectl -n phantom rollout status deployment/phantom-sbom-service --timeout=90s
   ```

3. Remove only broker resources and its client configuration:

   ```bash
   kubectl -n phantom delete configmap phantom-sbom-aws-client phantom-aws-credential-broker-ca --ignore-not-found
   kubectl -n phantom-identity delete configmap phantom-aws-workload-config phantom-aws-credential-broker-ca --ignore-not-found
   kubectl -n phantom-identity delete secret phantom-aws-credential-broker-tls --ignore-not-found
   kubectl delete -f infra/k8s/k3s-lab/07-aws-credential-broker.yaml
   ```

   Preserve any required audit evidence first. Do not remove the evidence
   bucket or its objects.
4. Plan with `enable_s3_workload_identity=false`, `enable_nat_gateway=false`,
   and `enable_evidence_backups=true`; inspect that only the workload role,
   its two IAM inline policies, and the source-role AssumeRole grant are
   removed. Apply only after human review. The existing SSM role, backup grant,
   bucket, S3 endpoint, instance, and evidence remain.
5. Delete local certificate working files only after the CA key is securely
   archived offline or intentionally destroyed under the operator's key policy.

## Verification status in this change

Implemented locally: role/policy definitions (feature off by default), broker,
TokenReview checks, short-lived role assumption, credential-process helper,
optional Kubernetes manifests/patch, and dynamic egress renderer. Local unit
tests exercise the signed-in identity validation and the actual aiobotocore
`credential_process` provider using test-only credentials. No Terraform apply,
AWS write, Kubernetes apply, pod restart, S3 object test, or live broker
verification was performed. Deployment remains pending plan approval and live
verification of host-network IMDSv2 access, TokenReview, STS role assumption,
S3 least-privilege, and the generated NetworkPolicy.
