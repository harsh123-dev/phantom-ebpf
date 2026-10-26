# PHANTOM disposable lab: cost and network options

**Prepared:** 2026-10-26 UTC  
**Region:** `ap-south-1` (Mumbai)  
**Terraform environment:** `infra/terraform/environments/k3s-lab/`  
**Status:** analysis and non-applying plan only; no AWS resource was created.

## Price basis

I queried the AWS Price List API on 2026-10-26 for `Asia Pacific (Mumbai)`. The exact returned On-Demand rates used below are:

| Resource | Rate used | Source and notes |
|---|---:|---|
| Linux `t3.xlarge`, shared tenancy | `$0.1792` / instance-hour | AWS Price List API, `AmazonEC2`, `APS3-BoxUsage:t3.xlarge`, Linux, shared, On-Demand. 4 vCPU and 16 GiB. |
| gp3 storage | `$0.0912` / GB-month | AWS Price List API, `AmazonEC2`, `APS3-EBS:VolumeUsage.gp3`; Terraform provisions 50 GB. Baseline 3,000 IOPS and 125 MiB/s are included. [AWS EBS pricing](https://aws.amazon.com/ebs/pricing/) |
| NAT Gateway | `$0.056` / NAT-hour | AWS Price List API, `AmazonEC2`, `APS3-NatGateway-Hours`. [AWS VPC pricing](https://aws.amazon.com/vpc/pricing/) |
| NAT processing | `$0.056` / GB processed | AWS Price List API, `AmazonEC2`, `APS3-NatGateway-Bytes`, in addition to hourly rate. Internet data transfer may also apply. |
| Public IPv4 | `$0.005` / address-hour | AWS Price List API, `AmazonVPC`, `APS3-PublicIPv4:InUseAddress`; AWS documents the hourly public IPv4 charge on its [VPC pricing page](https://aws.amazon.com/vpc/pricing/). |
| SSM interface endpoint | `$0.013` / endpoint-hour; `$0.01` / GB processed at the first tier | AWS Price List API, `AmazonVPC`, `APS3-VpcEndpoint-Hours` and `APS3-VpcEndpoint-Bytes`. The configuration creates three interface endpoints (`ssm`, `ssmmessages`, `ec2messages`). [AWS PrivateLink pricing](https://aws.amazon.com/privatelink/pricing/) |
| S3 Gateway endpoint | `$0` endpoint-hour | Gateway endpoint itself has no hourly charge. If evidence backups are enabled, S3 storage and request charges apply. Current queried S3 Standard storage is `$0.025`/GB-month for the first 50 TB, PUT/LIST `$0.005` per 1,000, GET `$0.004` per 10,000. |

AWS pricing pages describe the charge categories and regional examples; regional line-item rates above came from the AWS Price List API, not a third-party calculator. Prices exclude taxes and are subject to change. EC2/VPC objects such as VPCs, subnets, route tables, associations, security groups, IAM roles, and an Internet Gateway have no separate hourly line item in this estimate.

## Terraform resource inventory

Always created by the current dedicated environment (using SSM and the sample defaults): one VPC, one Internet Gateway, two subnets, two route tables and associations, two security groups, three SSM interface endpoints, one IAM role/instance profile/managed-policy attachment, one EC2 instance, and its encrypted 50 GB gp3 root volume. The EC2 AMI and availability-zone lookups are data sources, not created resources. With SSM enabled, no SSH keypair or local private key is generated.

With the existing NAT mode enabled, Terraform additionally creates one NAT Gateway and one Elastic IP. With `enable_evidence_backups=true`, it additionally creates an S3 bucket and its public-access, ownership, versioning, encryption, lifecycle, and policy configuration, an IAM prefix-scoped policy, and an S3 Gateway endpoint. The bucket is not created by the example configuration; its object storage, request, and version-retention costs depend on evidence volume.

The current state file reports no managed resources. No apply or destroy was performed.

## Cost scenarios for the current NAT design

Assumptions: Linux shared-tenancy On-Demand `t3.xlarge`; 50 GB gp3; three SSM endpoints in one AZ; one NAT Gateway and its public IPv4; no optional backup bucket; resources exist only for the stated duration and are then destroyed. EBS is prorated using a 30-day/720-hour month. The table is a fixed-cost floor at **zero NAT and endpoint data processing**.

| Cost line | 8 hours | 24 hours | 30 days (720 h) |
|---|---:|---:|---:|
| EC2 `t3.xlarge` | `$1.4336` | `$4.3008` | `$129.0240` |
| 50 GB gp3 | `$0.0507` | `$0.1520` | `$4.5600` |
| NAT Gateway hours | `$0.4480` | `$1.3440` | `$40.3200` |
| NAT public IPv4 | `$0.0400` | `$0.1200` | `$3.6000` |
| Three SSM endpoints | `$0.3120` | `$0.9360` | `$28.0800` |
| **Known fixed subtotal** | **`$2.2843`** | **`$6.8528`** | **`$205.5840`** |

Add `$0.056 × NAT-processed GB`, `$0.01 × SSM-endpoint-processed GB` at the first tier, internet data transfer out, and any S3 storage/requests. Bootstrap downloads and pulling images traverse NAT in this mode, so the real bill will exceed the fixed subtotal. An instance left stopped without destroying the rest still retains EBS and network endpoint/NAT charges; terminate/destroy the dedicated stack after the session to stop those meters.

## No-NAT option and recommendation

I added a safe-to-review `enable_nat_gateway` toggle. The existing default remains `true` for backwards-compatible NAT behavior. The sample variables set it to `false`, selecting one EC2 instance in the public egress subnet with an outbound public IPv4 address and **no security-group ingress rules**. The host can reach bootstrap package/image repositories through only TCP 80/443; the group also permits VPC DNS and Amazon Time Sync. SSM administration still uses the three private interface endpoints. Kubernetes API, PHANTOM APIs, Prometheus, SSH, and sink ports have no inbound security-group rules.

This is **not a host-level public-egress deny**: the node can initiate HTTP/HTTPS to arbitrary destinations. The workload network policy in `infra/k8s/k3s-lab/06-network-policies.yaml` denies unlisted egress from `phantom-eval`; K3s includes a NetworkPolicy controller ([K3s networking docs](https://docs.k3s.io/networking/networking-services)). Effective isolation still must be proved after deployment with an allowed internal connectivity check and a harmless blocked-egress check from that namespace. Do not run attack scenarios as part of that validation.

The no-NAT fixed-cost floor uses the same resources except it replaces the NAT Gateway's EIP with one public IPv4 on the instance:

| Cost line | 8 hours | 24 hours | 30 days (720 h) |
|---|---:|---:|---:|
| EC2 `t3.xlarge` | `$1.4336` | `$4.3008` | `$129.0240` |
| 50 GB gp3 | `$0.0507` | `$0.1520` | `$4.5600` |
| Instance public IPv4 | `$0.0400` | `$0.1200` | `$3.6000` |
| Three SSM endpoints | `$0.3120` | `$0.9360` | `$28.0800` |
| **Known fixed subtotal** | **`$1.8363`** | **`$5.5088`** | **`$165.2640`** |

This saves `$0.056` per wall-clock hour versus NAT at the same data volume, and avoids NAT processing charges. It still has normal internet transfer charges and public host egress. It is the lowest-cost fit for the **current bootstrap**, conditional on confirming there are no SG ingress rules and validating k3s NetworkPolicy enforcement before any experiment. If policy requires the host to have no public IP or direct internet egress, this option is not acceptable.

A fully private no-NAT node is also possible in principle, but the current user-data script runs `apt`, downloads Docker and k3s installers, clones/builds source, and pulls public images. Those steps will fail without internet. A private design needs a prebuilt, verified AMI plus private artifact/image delivery (for example, staged artifacts in S3 through the Gateway endpoint, or ECR endpoints and private images). Its endpoint, AMI build, artifact storage, and transfer costs are not included here. Do not simply remove NAT from the current private-subnet design.

## Capacity and technical risks

- Summing Kubernetes YAML requests for the 11 one-replica workload objects gives **1.0 CPU core and 1,568 MiB (1.53 GiB)**, excluding k3s/system pods, container runtime overhead, page cache, and Docker builds. `t3.xlarge` has 4 vCPU/16 GiB and is plausible for one-replica integration validation, but it leaves limited headroom for Docker builds and host/Kubernetes overhead. The 50 GB root disk may be tight because Docker build layers and k3s containerd images coexist. Verify free disk and pod memory after bootstrap; if required, 80 GB adds `$2.736` per 30 days at the queried gp3 rate.
- T3 is burstable. In Mumbai the Price List API returns `$0.05` per vCPU-hour for Linux T3 surplus CPU credits. This is not included; sustained load above baseline can add charges. Monitor `CPUSurplusCreditsCharged`, or choose a fixed-performance instance and re-price it if test performance is unstable.
- The Terraform plan with the sample `enable_nat_gateway=false` was generated with `-refresh=false` for configuration review only: **17 creates, 0 updates, 0 deletes**, with no NAT Gateway, EIP, or backup bucket. It is not authorization to apply and is not a live infrastructure inventory.
- The EC2 user-data bootstrap installs Docker and k3s but does **not** clone or copy this repository. This checkout has uncommitted source/configuration changes, so a plain clone of `main` would not reproduce the code tested here. Before building, transfer the approved working-tree snapshot to `/opt/phantom-ebpf` using a separately verified secure transfer path and verify its manifest/checksums. No source transfer was performed.
- Terraform validation does not prove cloud-init, package mirrors, SSM connectivity, image builds, eBPF loading, or NetworkPolicy behavior. Those remain post-provision validation gates.

## Commands after provisioning is separately authorized

From the repository root, review and save a fresh plan before any apply:

```bash
cd infra/terraform/environments/k3s-lab
cp terraform.tfvars.example terraform.tfvars
terraform fmt -check
terraform init -backend=false
terraform validate
terraform plan -var-file=terraform.tfvars -out=/tmp/phantom-lab.tfplan
terraform show /tmp/phantom-lab.tfplan
```

Only after plan actions and ownership are reviewed and approved:

```bash
terraform apply /tmp/phantom-lab.tfplan
terraform output
aws ssm start-session --target "$(terraform output -raw instance_id)" --region ap-south-1
```

On the dedicated lab node, after checking `/var/log/phantom-bootstrap.done`, BTF, disk, SSM and node readiness:

```bash
# First stage the approved source snapshot and verify its checksums at /opt/phantom-ebpf.
cd /opt/phantom-ebpf
sudo -u ubuntu -- env KUBECONFIG=/home/ubuntu/.kube/config bash infra/k8s/k3s-lab/build-images.sh
sudo -u ubuntu -- env KUBECONFIG=/home/ubuntu/.kube/config bash infra/k8s/k3s-lab/deploy-all.sh
sudo -u ubuntu -- env KUBECONFIG=/home/ubuntu/.kube/config kubectl get nodes,pods -A -o wide
```

These commands were not run here. Do not use the shared SQL Server controller for the privileged agent. Before any later manual attack session, separately verify network policies, telemetry, oracle/trust, SBOM mapping, sink persistence/recovery, and the operator's scenario controls.
