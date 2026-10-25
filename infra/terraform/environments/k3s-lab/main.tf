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

# ---------------------------------------------------------------------------
# Network & Subnet Discovery (uses default VPC to eliminate VPC NAT gateway costs)
# ---------------------------------------------------------------------------

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
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
# Security Group: STRICT INBOUND RESTRICTION
# ---------------------------------------------------------------------------
# No public Kubernetes API (6443), PHANTOM API (8080), Prometheus (9090),
# or sink ports are exposed to the internet.
# Administrator accesses services via SSH local port forwarding or SSM.

resource "aws_security_group" "lab" {
  name        = "${var.lab_name}-sg"
  description = "Strict security group for disposable PHANTOM k3s lab"
  vpc_id      = data.aws_vpc.default.id

  # Inbound: SSH only from operator's specific IP (if provided)
  dynamic "ingress" {
    for_each = var.operator_ip != "" ? [var.operator_ip] : []
    content {
      description = "Operator SSH access"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["${ingress.value}/32"]
    }
  }

  # Outbound: All traffic allowed for package updates, container images, and GitHub
  egress {
    description = "Allow outbound traffic for dependencies"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
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
  count = var.enable_ssm ? 1 : 0
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
  count = var.enable_ssm ? 1 : 0
  name  = "${var.lab_name}-instance-profile"
  role  = aws_iam_role.ssm[0].name
}

# ---------------------------------------------------------------------------
# Disposable SSH KeyPair Generation (optional)
# ---------------------------------------------------------------------------

resource "tls_private_key" "lab" {
  count     = var.key_name == "" ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "generated" {
  count      = var.key_name == "" ? 1 : 0
  key_name   = "${var.lab_name}-key"
  public_key = tls_private_key.lab[0].public_key_openssh

  tags = {
    Name        = "${var.lab_name}-key"
    Project     = "PHANTOM"
    Environment = "disposable-lab"
  }
}

resource "local_file" "private_key" {
  count           = var.key_name == "" ? 1 : 0
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
  subnet_id                   = tolist(data.aws_subnets.default.ids)[0]
  vpc_security_group_ids      = [aws_security_group.lab.id]
  iam_instance_profile        = var.enable_ssm ? aws_iam_instance_profile.ssm[0].name : null
  key_name                    = var.key_name != "" ? var.key_name : aws_key_pair.generated[0].key_name
  associate_public_ip_address = true

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
}
