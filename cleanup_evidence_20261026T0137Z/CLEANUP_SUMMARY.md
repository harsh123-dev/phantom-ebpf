# PHANTOM lab cleanup record

- Cleanup window: 2026-10-26 UTC.
- AWS identity verified before changes: account `253490771520`.
- Region: `ap-south-1`.
- Target: `i-06bb29d253668fa5f`, tagged `Project=PHANTOM`, `Environment=disposable-lab`.
- Kubernetes: namespaces `phantom`, `phantom-eval`, and the lab-only `monitoring` namespace were deleted. Final node listing contained only k3s system pods; the node was then terminated. A leftover SBOM port-forward process was stopped by its exact PID/command.
- Terraform plan: 28 delete actions, zero create/update/replace actions, target EC2 ID and PHANTOM tags checked. Terraform apply result: `Apply complete! Resources: 0 added, 0 changed, 28 destroyed.[0m`.
- Final direct service checks: target instance is `terminated`; attached encrypted root volume is `NotFound`; NAT gateway is `deleted`; EIP allocation, VPC, and VPC endpoints are `NotFound`; PHANTOM evidence and transfer buckets return 404; account query for buckets containing `phantom` returned an empty list; Terraform managed state is empty.
- Terraform also removed the lab-only VPC, subnets, route tables, security groups, SSM endpoints, instance profile, role and evidence policy.
- Preserved S3 artifacts: 28 object versions were downloaded and checked against size and SHA-256 metadata. Seven historical source archives contained Kubernetes Secret YAML documents; those documents were omitted from the local copies and the derivative hashes/removal list are in `archive_sanitization_manifest.json`. The original S3 hashes remain recorded in `preserved_s3_evidence_versions.json`.
- The temporary transfer bucket had only `patches/phantom-attribution-fix.tar.gz` (null version), which was downloaded and checksummed before object and bucket deletion.
- Snapshot `snap-09eeb6885e00b8443` was retained: it belongs to Canonical account `099720109477` and is the base snapshot for Ubuntu AMI `ami-082a1ff88c78c6290`; it was not PHANTOM-owned.
- Resource Groups Tagging API temporarily returned stale deleted-resource mappings. Direct EC2 queries for PHANTOM-tagged volumes, snapshots, active instances, EIPs, NAT gateways and VPCs returned empty; bucket and exact-ID checks confirmed removal.
- Repository source, existing reports, datasets, and prior dirty changes were not edited or deleted. The cleanup evidence directory is the only new untracked path.

Detailed inventories, command results, Terraform plan/apply output, evidence versions, checksums, and sanitized lab logs are stored alongside this file.
