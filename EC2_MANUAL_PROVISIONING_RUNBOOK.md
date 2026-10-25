# PHANTOM Part 7B: EC2 Manual Provisioning Runbook

**Target System**: PHANTOM (*Causal Attribution of Runtime SBOM Drift via eBPF Behavioral Contracts in Kubernetes*)  
**Evaluation Stage**: Part 7B — Stage 2 Manual EC2 Provisioning  
**Authoritative Location**: `infra/terraform/environments/k3s-lab/`  
**Execution Gate Status**: **STOP GATE — AWAITING MANUAL HUMAN PROVISIONING**

---

## 1. Operating Rules & Safety Directives

> [!IMPORTANT]
> **Strict Agent Operating Rules**:
> 1. The agent will **NEVER** run `terraform apply` or `terraform destroy` automatically.
> 2. The agent will **NEVER** print private SSH keys, AWS access keys, or secrets into conversation logs.
> 3. The operator must inspect the `terraform plan` and execute `terraform apply` manually.
> 4. Do not proceed to Stage 3 until the human operator confirms successful provisioning.

---

## 2. Infrastructure Sizing & Specifications

| Parameter | Recommended Specification | Rationale & Verification |
| :--- | :--- | :--- |
| **AWS Region** | `ap-south-1` (Mumbai) | Default evaluation region; low network latency for operator. |
| **Instance Type** | `t3.xlarge` (4 vCPU, 16 GiB RAM) | Sufficient memory for k3s, 4 PHANTOM microservices, 3 victim workloads, Prometheus, PostgreSQL, and Redis simultaneously. |
| **Operating System** | Ubuntu 22.04 LTS (Jammy AMD64) | Includes Linux kernel 5.15+ with native BTF (`/sys/kernel/btf/vmlinux`) and CO-RE eBPF support. |
| **Root Volume** | 50 GB `gp3` (encrypted) | Baseline 3,000 IOPS / 125 MB/s; storage for OS, Docker Engine, k3s containerd image cache, and Prometheus TSDB. |
| **Inbound Security** | Port 22 (SSH) from `operator_ip/32` ONLY | All services (6443, 8080, 9090, sinks) are completely closed to the internet. Accessed via SSH local tunnel or AWS SSM. |
| **IAM Profile** | `AmazonSSMManagedInstanceCore` | Enables zero-open-port management via AWS Systems Manager Session Manager. |

---

## 3. Expected AWS Resources Created

Running `terraform apply` will create exactly the following 8 resources in the selected AWS account:

1. `aws_instance.k3s_lab`: One disposable Ubuntu 22.04 LTS EC2 instance (`t3.xlarge`).
2. `aws_security_group.lab`: One security group with port 22 open exclusively to `operator_ip/32` and egress to `0.0.0.0/0`.
3. `aws_iam_role.ssm`: One IAM role allowing `ec2.amazonaws.com` assume-role action.
4. `aws_iam_role_policy_attachment.ssm`: One IAM role attachment of `AmazonSSMManagedInstanceCore`.
5. `aws_iam_instance_profile.ssm`: One instance profile binding `aws_iam_role.ssm` to the EC2 instance.
6. `tls_private_key.lab`: One 4096-bit RSA key generated in Terraform memory (if `var.key_name` is blank).
7. `aws_key_pair.generated`: One AWS Key Pair registered using the public key.
8. `local_file.private_key`: One local `.pem` key file saved to `infra/terraform/environments/k3s-lab/.ssh/phantom-lab-key.pem` with `0600` permissions.

---

## 4. Cost Breakdown & Budget Cap

- **Hourly Breakdown**:
  - `t3.xlarge` EC2 On-Demand rate: **$0.1664 / hr**
  - 50 GB `gp3` EBS volume ($0.080/GB-mo): **$0.0055 / hr**
  - Public IPv4 Address charge: **$0.0050 / hr**
  - Data transfer & SSM: **$0.00 / hr**
  - **Total Hourly Rate**: **$0.1769 / hour** ($\approx \$0.177\text{/hr}$)
- **Budget by Time Window**:
  - 2-Hour Verification Window: **$0.35 USD**
  - 4-Hour Standard Pilot Execution: **$0.71 USD**
  - 8-Hour Conservative Maximum Window: **$1.42 USD**

---

## 5. Step-by-Step Manual Provisioning Instructions

Execute these commands manually on your workstation terminal:

### Step 5.1: Navigate to the Lab Terraform Directory
In PowerShell:
```powershell
cd D:\project-1\infra\terraform\environments\k3s-lab
```

### Step 5.2: Detect Operator Public IP & Generate `terraform.tfvars`
Fetch your public IPv4 address to restrict SSH access strictly to your machine:
```powershell
$MY_IP = (Invoke-RestMethod -Uri "https://ifconfig.me/ip").Trim()
Write-Host "Detected Operator IP: $MY_IP"

@"
aws_region       = "ap-south-1"
instance_type    = "t3.xlarge"
root_volume_size = 50
operator_ip      = "$MY_IP"
enable_ssm       = true
"@ | Out-File -FilePath terraform.tfvars -Encoding utf8
```

### Step 5.3: Initialize Terraform
```powershell
terraform init
```
*(Plugins are already cached in `.terraform/` from validation)*

### Step 5.4: Generate and Review the Execution Plan
```powershell
terraform plan -out=tfplan
```
**Verify before proceeding**:
- Confirm `Plan: 8 to add, 0 to change, 0 to destroy`.
- Confirm `instance_type = "t3.xlarge"`.
- Confirm `operator_ip` matches `$MY_IP`.
- Confirm `delete_on_termination = true` on `root_block_device`.

### Step 5.5: Manually Apply the Plan
```powershell
terraform apply tfplan
```
*Wait ~2–3 minutes for EC2 provisioning and cloud-init bootstrap.*

### Step 5.6: Safe Retrieval of Connection Outputs
Retrieve the connection details without exposing keys:
```powershell
# Get public IP:
terraform output -raw public_ip

# View the SSH connection command:
terraform output -raw ssh_command

# View the SSM Session Manager command:
terraform output -raw ssm_session_command

# View the local port forwarding tunnel command:
terraform output -raw ssh_tunnel_command
```

---

## 6. Verifying Instance Bootstrap Readiness

Cloud-init runs the bootstrap script in the background to install Docker, k3s, and pre-cache images.

Log in to the instance:
```bash
ssh -i .ssh/phantom-lab-key.pem ubuntu@<LAB_PUBLIC_IP>
```
*(Or via SSM: `aws ssm start-session --target <INSTANCE_ID> --region ap-south-1`)*

Check if cloud-init bootstrap has completed:
```bash
# Follow cloud-init output until finished:
tail -f /var/log/cloud-init-output.log

# Verify bootstrap completion sentinel:
cat /var/log/phantom-bootstrap.done
```
When `cat /var/log/phantom-bootstrap.done` returns without error, the instance is ready for Stage 3 deployment.

---

## 7. Teardown Procedure (End of Experiment)

When the evaluation or testing window concludes, tear down the environment immediately:

```powershell
cd D:\project-1\infra\terraform\environments\k3s-lab
terraform destroy -auto-approve
```

### Teardown Verification:
```powershell
# Confirm all resources destroyed:
terraform show
# Expected output: (empty state)
```

> [!WARNING]
> If you terminate the instance via the AWS Console instead of running `terraform destroy`, verify that the root EBS volume was deleted. `delete_on_termination = true` ensures it is removed automatically, but `terraform destroy` also cleans up the security group, IAM role, and local keys.

---

## 8. Completion Gate (Wait for Operator Confirmation)

> [!CAUTION]
> **STOP HERE.**
> Do not attempt to run Stage 3 deployment or execute any test scenarios until the human operator has executed `terraform apply` and confirmed that the instance is running and bootstrap is complete.
