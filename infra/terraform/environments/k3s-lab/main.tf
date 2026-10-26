terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# Dedicated PHANTOM network. The existing default VPC contains unrelated
# resources and an existing subnet covering its entire CIDR, so the lab gets
# its own VPC instead of changing shared routes or subnet settings.
# ---------------------------------------------------------------------------

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "lab" {
  cidr_block           = "10.89.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name        = "${var.lab_name}-vpc"
    Project     = "PHANTOM"
    Environment = "disposable-lab"
  }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags = {
    Name        = "${var.lab_name}-igw"
    Project     = "PHANTOM"
    Environment = "disposable-lab"
  }
}

resource "aws_subnet" "public_nat" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.89.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false
  tags = {
    Name        = "${var.lab_name}-${var.enable_nat_gateway ? "nat-public" : "public-egress"}"
    Project     = "PHANTOM"
    Environment = "disposable-lab"
    Purpose     = var.enable_nat_gateway ? "nat-egress-only" : "lab-node-restricted-egress"
  }
}

resource "aws_subnet" "lab_private" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.89.2.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false
  tags = {
    Name        = "${var.lab_name}-private"
    Project     = "PHANTOM"
    Environment = "disposable-lab"
  }
}

resource "aws_route_table" "public_nat" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }
  tags = {
    Name        = "${var.lab_name}-${var.enable_nat_gateway ? "nat-public" : "public-egress"}"
    Project     = "PHANTOM"
    Environment = "disposable-lab"
  }
}

resource "aws_route_table_association" "public_nat" {
  subnet_id      = aws_subnet.public_nat.id
  route_table_id = aws_route_table.public_nat.id
}

resource "aws_eip" "nat" {
  count  = var.enable_nat_gateway ? 1 : 0
  domain = "vpc"
  tags = {
    Name        = "${var.lab_name}-nat-eip"
    Project     = "PHANTOM"
    Environment = "disposable-lab"
  }
}

resource "aws_nat_gateway" "lab" {
  count             = var.enable_nat_gateway ? 1 : 0
  allocation_id     = aws_eip.nat[0].id
  subnet_id         = aws_subnet.public_nat.id
  connectivity_type = "public"
  depends_on        = [aws_internet_gateway.lab, aws_route_table_association.public_nat]
  tags = {
    Name        = "${var.lab_name}-nat"
    Project     = "PHANTOM"
    Environment = "disposable-lab"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.lab.id
  dynamic "route" {
    for_each = var.enable_nat_gateway ? [true] : []
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = aws_nat_gateway.lab[0].id
    }
  }
  tags = {
    Name        = "${var.lab_name}-private"
    Project     = "PHANTOM"
    Environment = "disposable-lab"
  }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.lab_private.id
  route_table_id = aws_route_table.private.id
}

resource "aws_security_group" "ssm_endpoints" {
  name        = "${var.lab_name}-ssm-endpoints-sg"
  description = "HTTPS from the private PHANTOM lab node to AWS SSM endpoints"
  vpc_id      = aws_vpc.lab.id
  ingress {
    description     = "Private lab node to SSM interface endpoints"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.lab.id]
  }
  egress = []
  tags = {
    Name        = "${var.lab_name}-ssm-endpoints-sg"
    Project     = "PHANTOM"
    Environment = "disposable-lab"
  }
}

resource "aws_vpc_endpoint" "ssm" {
  for_each            = var.enable_ssm ? toset(["ssm", "ssmmessages", "ec2messages"]) : []
  vpc_id              = aws_vpc.lab.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.lab_private.id]
  security_group_ids  = [aws_security_group.ssm_endpoints.id]
  private_dns_enabled = true
  tags = {
    Name        = "${var.lab_name}-${each.key}"
    Project     = "PHANTOM"
    Environment = "disposable-lab"
  }
}

resource "aws_vpc_endpoint" "s3" {
  count             = var.enable_evidence_backups ? 1 : 0
  vpc_id            = aws_vpc.lab.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = var.enable_nat_gateway ? [aws_route_table.private.id] : [aws_route_table.public_nat.id]
  tags = {
    Name        = "${var.lab_name}-s3"
    Project     = "PHANTOM"
    Environment = "disposable-lab"
  }
}

# ---------------------------------------------------------------------------
# Ubuntu 22.04 LTS AMI Lookup (Kernel 5.15 / 6.5 with BTF support)
# ---------------------------------------------------------------------------

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# ---------------------------------------------------------------------------
# Security Group: SSM-only administration and restricted host egress
# ---------------------------------------------------------------------------
# No public Kubernetes API (6443), PHANTOM API (8080), Prometheus (9090),
# SSH, or sink ports are exposed: this security group has no ingress rules.
# With NAT enabled the instance is private. With NAT disabled, it receives a
# public IPv4 address for outbound bootstrap but still has no inbound rule.
# Administration uses Systems Manager in either mode.

resource "aws_security_group" "lab" {
  name        = "${var.lab_name}-sg"
  description = "Strict security group for disposable PHANTOM k3s lab"
  vpc_id      = aws_vpc.lab.id

  # Bootstrap uses package/image registries over HTTP(S). Limit host egress to
  # HTTP(S), VPC DNS, and Amazon Time Sync; this is controlled public egress,
  # not a host-level public-egress-deny policy.
  egress {
    description = "Ubuntu package mirror access (APT repository signatures remain verified)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "HTTPS package and image retrieval"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "VPC DNS resolution"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [aws_vpc.lab.cidr_block]
  }
  egress {
    description = "VPC DNS over TCP"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.lab.cidr_block]
  }
  egress {
    description = "Amazon Time Sync Service"
    from_port   = 123
    to_port     = 123
    protocol    = "udp"
    cidr_blocks = ["169.254.169.123/32"]
  }

  tags = {
    Name        = "${var.lab_name}-sg"
    Project     = "PHANTOM"
    Environment = "disposable-lab"
  }
}

# ---------------------------------------------------------------------------
# IAM Role for AWS Systems Manager (SSM)
# ---------------------------------------------------------------------------
# Allows zero-inbound-port access via AWS Console or 'aws ssm start-session'.

resource "aws_iam_role" "ssm" {
  count = (var.enable_ssm || var.enable_evidence_backups || var.enable_s3_workload_identity) ? 1 : 0
  name  = "${var.lab_name}-ssm-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.lab_name}-ssm-role"
    Project     = "PHANTOM"
    Environment = "disposable-lab"
  }
}

resource "aws_iam_role_policy_attachment" "ssm" {
  count      = var.enable_ssm ? 1 : 0
  role       = aws_iam_role.ssm[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ssm" {
  count = (var.enable_ssm || var.enable_evidence_backups || var.enable_s3_workload_identity) ? 1 : 0
  name  = "${var.lab_name}-instance-profile"
  role  = aws_iam_role.ssm[0].name
}

locals {
  sbom_workload_bucket_name = var.enable_evidence_backups ? aws_s3_bucket.evidence_backups[0].bucket : var.sbom_workload_bucket_name
  sbom_workload_bucket_arn  = local.sbom_workload_bucket_name == "" ? "" : "arn:aws:s3:::${local.sbom_workload_bucket_name}"
}

# The broker keeps EC2 instance-profile credentials on the node and exchanges
# them for this short-lived, S3-prefix-limited role only after TokenReview has
# authenticated the exact phantom/phantom-sbom-service service account.
resource "aws_iam_role" "sbom_workload" {
  count                = var.enable_s3_workload_identity ? 1 : 0
  name                 = "${var.lab_name}-sbom-workload-role"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = aws_iam_role.ssm[0].arn }
    }]
  })

  tags = {
    Name        = "${var.lab_name}-sbom-workload-role"
    Project     = "PHANTOM"
    Environment = "disposable-lab"
    Purpose     = "sbom-s3-workload-identity"
  }

  lifecycle {
    precondition {
      condition     = var.enable_evidence_backups || var.sbom_workload_bucket_name != ""
      error_message = "Set sbom_workload_bucket_name or enable the existing PHANTOM evidence bucket before enabling workload identity."
    }
  }
}

resource "aws_iam_role_policy" "sbom_workload_s3" {
  count = var.enable_s3_workload_identity ? 1 : 0
  name  = "${var.lab_name}-sbom-s3-prefix"
  role  = aws_iam_role.sbom_workload[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReadAndWriteSbomObjects"
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "${local.sbom_workload_bucket_arn}/${var.sbom_workload_prefix}/*"
    }]
  })
}

resource "aws_iam_role_policy" "ssm_assume_sbom_workload" {
  count = var.enable_s3_workload_identity ? 1 : 0
  name  = "${var.lab_name}-assume-sbom-workload"
  role  = aws_iam_role.ssm[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AssumeOnlySbomWorkloadRole"
      Effect   = "Allow"
      Action   = ["sts:AssumeRole"]
      Resource = aws_iam_role.sbom_workload[0].arn
    }]
  })
}

# ---------------------------------------------------------------------------
# Disposable SSH KeyPair Generation (optional)
# ---------------------------------------------------------------------------

resource "tls_private_key" "lab" {
  # SSM-only labs do not need an SSH credential. Avoid generating a private
  # key into Terraform state or the working tree when SSM is enabled.
  count     = var.key_name == "" && !var.enable_ssm ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "generated" {
  count      = var.key_name == "" && !var.enable_ssm ? 1 : 0
  key_name   = "${var.lab_name}-key"
  public_key = tls_private_key.lab[0].public_key_openssh

  tags = {
    Name        = "${var.lab_name}-key"
    Project     = "PHANTOM"
    Environment = "disposable-lab"
  }
}

resource "local_file" "private_key" {
  count           = var.key_name == "" && !var.enable_ssm ? 1 : 0
  content         = tls_private_key.lab[0].private_key_pem
  filename        = "${path.module}/.ssh/phantom-lab-key.pem"
  file_permission = "0600"
}

# ---------------------------------------------------------------------------
# EC2 Instance & UserData Bootstrap
# ---------------------------------------------------------------------------

resource "aws_instance" "k3s_lab" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  subnet_id                   = var.enable_nat_gateway ? aws_subnet.lab_private.id : aws_subnet.public_nat.id
  vpc_security_group_ids      = [aws_security_group.lab.id]
  iam_instance_profile        = (var.enable_ssm || var.enable_evidence_backups || var.enable_s3_workload_identity) ? aws_iam_instance_profile.ssm[0].name : null
  key_name                    = var.key_name != "" ? var.key_name : (var.enable_ssm ? null : aws_key_pair.generated[0].key_name)
  associate_public_ip_address = !var.enable_nat_gateway

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size           = var.root_volume_size
    volume_type           = "gp3"
    iops                  = 3000
    throughput            = 125
    delete_on_termination = true
    encrypted             = true
    tags = {
      Name        = "${var.lab_name}-root-vol"
      Project     = "PHANTOM"
      Environment = "disposable-lab"
    }
  }

  user_data = <<-EOF
              #!/bin/bash
              set -euxo pipefail

              export DEBIAN_FRONTEND=noninteractive
              echo ">>> [1/7] Updating system and installing base dependencies..."
              apt-get update -qq
              apt-get install -y --no-install-recommends \
                  apt-transport-https ca-certificates curl gnupg lsb-release \
                  git jq socat netcat-openbsd htop tar \
                  build-essential clang llvm libelf-dev libbpf-dev \
                  linux-headers-generic linux-tools-generic \
                  python3-pip python3-venv

              echo ">>> [2/7] Verifying eBPF & BTF prerequisites..."
              # Ensure debugfs is mounted
              mount -t debugfs none /sys/kernel/debug || true
              if [ -f /sys/kernel/btf/vmlinux ]; then
                  echo "BTF_STATUS=OK"
              else
                  echo "BTF_STATUS=MISSING_WARNING"
              fi

              echo ">>> [3/7] Installing Docker Engine for local image builds..."
              install -m 0755 -d /etc/apt/keyrings
              curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
              chmod a+r /etc/apt/keyrings/docker.gpg
              echo \
                "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
                "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
                tee /etc/apt/sources.list.d/docker.list > /dev/null
              apt-get update -qq
              apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin
              usermod -aG docker ubuntu

              echo ">>> [4/7] Installing lightweight k3s Kubernetes..."
              # Install k3s with flannel, disabled Traefik and ServiceLB
              curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--write-kubeconfig-mode 644 --disable traefik --disable servicelb" sh -

              # Wait for k3s node readiness
              timeout 60 bash -c 'until k3s kubectl get nodes | grep -q " Ready"; do sleep 2; done'
              echo "k3s cluster is online."

              echo ">>> [5/7] Configuring kubectl for ubuntu user..."
              mkdir -p /home/ubuntu/.kube
              cp /etc/rancher/k3s/k3s.yaml /home/ubuntu/.kube/config
              chown -R ubuntu:ubuntu /home/ubuntu/.kube
              echo "export KUBECONFIG=/home/ubuntu/.kube/config" >> /home/ubuntu/.bashrc

              echo ">>> [6/7] Pre-caching victim service images..."
              docker pull tiangolo/uwsgi-nginx-flask:python3.11 || true
              docker pull python:3.11-slim || true
              docker pull redis:7-alpine || true
              docker pull postgres:15-alpine || true
              docker pull prom/prometheus:v2.45.0 || true

              # Import images into k3s containerd namespace (k8s.io)
              docker save tiangolo/uwsgi-nginx-flask:python3.11 | k3s ctr -n k8s.io images import - || true
              docker save python:3.11-slim | k3s ctr -n k8s.io images import - || true
              docker save redis:7-alpine | k3s ctr -n k8s.io images import - || true
              docker save postgres:15-alpine | k3s ctr -n k8s.io images import - || true
              docker save prom/prometheus:v2.45.0 | k3s ctr -n k8s.io images import - || true

              echo ">>> [7/7] Bootstrap complete. Lab is ready for PHANTOM deployment."
              touch /var/log/phantom-bootstrap.done
              EOF

  tags = {
    Name         = var.lab_name
    Project      = "PHANTOM"
    Environment  = "disposable-lab"
    AutoTeardown = "true"
  }

  lifecycle {
    precondition {
      condition     = var.enable_ssm
      error_message = "This private PHANTOM lab requires Systems Manager for administration."
    }
  }
}

# ---------------------------------------------------------------------------
# Optional versioned off-node evidence backup bucket
# ---------------------------------------------------------------------------
# Disabled by default. Enabling creates a project-dedicated bucket and grants
# only the lab instance role access to the configured object prefix.

resource "aws_s3_bucket" "evidence_backups" {
  count         = var.enable_evidence_backups ? 1 : 0
  bucket        = "${var.lab_name}-${data.aws_caller_identity.current.account_id}-${var.aws_region}-evidence"
  force_destroy = false

  tags = {
    Name        = "${var.lab_name}-evidence-backups"
    Project     = "PHANTOM"
    Environment = "disposable-lab"
    Purpose     = "evidence-backups"
  }
}

resource "aws_s3_bucket_public_access_block" "evidence_backups" {
  count                   = var.enable_evidence_backups ? 1 : 0
  bucket                  = aws_s3_bucket.evidence_backups[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "evidence_backups" {
  count  = var.enable_evidence_backups ? 1 : 0
  bucket = aws_s3_bucket.evidence_backups[0].id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_versioning" "evidence_backups" {
  count  = var.enable_evidence_backups ? 1 : 0
  bucket = aws_s3_bucket.evidence_backups[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence_backups" {
  count  = var.enable_evidence_backups ? 1 : 0
  bucket = aws_s3_bucket.evidence_backups[0].id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
    bucket_key_enabled = false
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence_backups" {
  count  = var.enable_evidence_backups ? 1 : 0
  bucket = aws_s3_bucket.evidence_backups[0].id
  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"
    filter { prefix = "${var.evidence_backup_prefix}/" }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

resource "aws_s3_bucket_policy" "evidence_backups" {
  count  = var.enable_evidence_backups ? 1 : 0
  bucket = aws_s3_bucket.evidence_backups[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [aws_s3_bucket.evidence_backups[0].arn,
      "${aws_s3_bucket.evidence_backups[0].arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.evidence_backups]
}

resource "aws_iam_role_policy" "evidence_backups" {
  count = var.enable_evidence_backups ? 1 : 0
  name  = "${var.lab_name}-evidence-backups"
  role  = aws_iam_role.ssm[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListBackupPrefix"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.evidence_backups[0].arn
        Condition = { StringLike = {
          "s3:prefix" = ["${var.evidence_backup_prefix}", "${var.evidence_backup_prefix}/*"]
        } }
      },
      {
        Sid      = "WriteAndRecoverEvidenceObjects"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion"]
        Resource = "${aws_s3_bucket.evidence_backups[0].arn}/${var.evidence_backup_prefix}/*"
      }
    ]
  })
}
