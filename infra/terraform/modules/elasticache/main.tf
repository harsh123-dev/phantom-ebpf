terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

variable "cluster_id" {}

variable "node_type" {
  default = "cache.t3.micro"
}

variable "vpc_id" {}

variable "subnet_ids" {
  type = list(string)
}

variable "allowed_security_group_id" {}

resource "aws_elasticache_subnet_group" "phantom" {
  name       = "${var.cluster_id}-subnets"
  subnet_ids = var.subnet_ids
}

resource "aws_security_group" "redis" {
  name        = "${var.cluster_id}-redis"
  description = "PHANTOM Redis access from EKS nodes"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [var.allowed_security_group_id]
    description     = "Redis from EKS nodes only"
  }

  egress = []
}

resource "aws_elasticache_replication_group" "phantom" {
  replication_group_id = var.cluster_id
  description          = "PHANTOM Redis cache and stream broker"

  node_type          = var.node_type
  num_cache_clusters = 1
  # Single node for research prototype simplicity.
  # Production: set num_cache_clusters=2 for a replica.

  engine_version = "7.0"
  port           = 6379

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  subnet_group_name  = aws_elasticache_subnet_group.phantom.name
  security_group_ids = [aws_security_group.redis.id]
}

output "primary_endpoint_address" {
  value = aws_elasticache_replication_group.phantom.primary_endpoint_address
}

output "port" {
  value = aws_elasticache_replication_group.phantom.port
}
