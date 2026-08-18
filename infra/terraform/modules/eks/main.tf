terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
    tls = {
      source = "hashicorp/tls"
    }
  }
}

variable "cluster_name" {}

variable "kubernetes_version" {
  default = "1.31"  # 1.29 is end-of-life; 1.31 is current AWS EKS stable
}

variable "node_instance_type" {
  default = "t3.medium"
}

variable "node_min_size" {
  default = 2
}

variable "node_max_size" {
  default = 10
}

variable "node_desired_size" {
  default = 3
}

variable "vpc_id" {}

variable "subnet_ids" {
  type = list(string)
}

variable "environment" {
  default = "dev"
}

# Required for: allowing the EKS control plane to manage cluster resources.
resource "aws_iam_role" "cluster" {
  name = "${var.cluster_name}-cluster"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Environment = var.environment
    Service     = "phantom"
  }
}

# Required for: EKS control plane management of Kubernetes resources.
resource "aws_iam_role_policy_attachment" "cluster_policy" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

# Required for: the control plane to create and manage VPC resources for EKS.
resource "aws_iam_role_policy_attachment" "cluster_vpc_resource_controller" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
}

# Required for: restricting control-plane network access to EKS worker nodes.
resource "aws_security_group" "cluster" {
  name        = "${var.cluster_name}-cluster"
  description = "PHANTOM EKS control plane security group"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Kubernetes API access from PHANTOM EKS nodes"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.node.id]
  }

  egress {
    description = "Control plane service communication"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.cluster_name}-cluster"
    Environment = var.environment
    Service     = "phantom"
  }
}

# Required for: securing worker-node and pod network traffic within the VPC.
resource "aws_security_group" "node" {
  name        = "${var.cluster_name}-node"
  description = "PHANTOM EKS worker node security group"
  vpc_id      = var.vpc_id

  ingress {
    description = "Node-to-node and pod-to-pod traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  egress {
    description = "Worker access to AWS services and external dependencies"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.cluster_name}-node"
    Environment = var.environment
    Service     = "phantom"
  }
}

resource "aws_eks_cluster" "phantom" {
  name     = var.cluster_name
  role_arn = aws_iam_role.cluster.arn
  version  = var.kubernetes_version

  vpc_config {
    subnet_ids              = var.subnet_ids
    security_group_ids      = [aws_security_group.cluster.id]
    endpoint_private_access = true
    endpoint_public_access  = true
    # Public endpoint enabled for dev: allows kubectl from local machine.
  }

  enabled_cluster_log_types = [
    "api",
    "audit",
    "authenticator",
    # api: control plane API server logs.
    # audit: Kubernetes audit logs for compliance.
    # authenticator: IAM authentication logs.
  ]

  tags = {
    Environment = var.environment
    Service     = "phantom"
  }

  depends_on = [
    aws_iam_role_policy_attachment.cluster_policy,
    aws_iam_role_policy_attachment.cluster_vpc_resource_controller,
  ]
}

# Required for: worker nodes to join and run workloads in the EKS cluster.
resource "aws_iam_role" "node" {
  name = "${var.cluster_name}-node"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Environment = var.environment
    Service     = "phantom"
  }
}

# Required for: EKS worker node registration and cluster communication.
resource "aws_iam_role_policy_attachment" "node_worker" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

# Required for: worker nodes to pull PHANTOM images from Amazon ECR.
resource "aws_iam_role_policy_attachment" "node_ecr" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# Required for: Amazon VPC CNI networking for pods running on worker nodes.
resource "aws_iam_role_policy_attachment" "node_cni" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

# Required for: attaching the PHANTOM worker-node security group to managed nodes.
resource "aws_launch_template" "node" {
  name_prefix = "${var.cluster_name}-node-"

  vpc_security_group_ids = [aws_security_group.node.id]

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name        = "${var.cluster_name}-node"
      Environment = var.environment
      Service     = "phantom"
    }
  }
}

# Required for: providing scalable compute capacity for PHANTOM workloads.
resource "aws_eks_node_group" "phantom" {
  cluster_name    = aws_eks_cluster.phantom.name
  node_group_name = "${var.cluster_name}-nodes"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.subnet_ids
  instance_types  = [var.node_instance_type]
  capacity_type   = "ON_DEMAND"

  scaling_config {
    min_size     = var.node_min_size
    max_size     = var.node_max_size
    desired_size = var.node_desired_size
  }

  launch_template {
    id      = aws_launch_template.node.id
    version = aws_launch_template.node.latest_version
  }

  tags = {
    Environment = var.environment
    Service     = "phantom"
  }

  depends_on = [
    aws_iam_role_policy_attachment.node_worker,
    aws_iam_role_policy_attachment.node_ecr,
    aws_iam_role_policy_attachment.node_cni,
  ]
}

# Required for: deriving the EKS OIDC certificate thumbprint for IRSA trust.
data "tls_certificate" "eks_oidc" {
  url = aws_eks_cluster.phantom.identity[0].oidc[0].issuer
}

# Required for: IAM roles for Kubernetes service accounts via IRSA.
resource "aws_iam_openid_connect_provider" "phantom" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks_oidc.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.phantom.identity[0].oidc[0].issuer

  tags = {
    Environment = var.environment
    Service     = "phantom"
  }
}

output "cluster_endpoint" {
  value = aws_eks_cluster.phantom.endpoint
}

output "cluster_name" {
  value = aws_eks_cluster.phantom.name
}

output "oidc_provider_arn" {
  value = aws_iam_openid_connect_provider.phantom.arn
}

output "node_security_group_id" {
  value = aws_security_group.node.id
}
