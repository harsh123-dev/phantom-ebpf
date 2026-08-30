terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  # Backend: use local state for dev, S3 for production.
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  default = "ap-south-1"
}

variable "cluster_name" {
  default = "phantom-dev"
}

variable "environment" {
  default = "dev"
}

# For dev, PHANTOM assumes the selected AWS region has a default VPC and
# default subnets. Production must supply dedicated VPC and private subnets.
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

module "eks" {
  source             = "../../modules/eks"
  cluster_name       = var.cluster_name
  node_instance_type = "m7i-flex.large"  # 2 vCPU, 8 GiB — best for PHANTOM (Causal Engine needs RAM)
  node_min_size      = 1
  node_desired_size  = 2
  node_max_size      = 3
  vpc_id             = data.aws_vpc.default.id
  subnet_ids         = data.aws_subnets.default.ids
  environment        = var.environment
}

module "rds" {
  source                    = "../../modules/rds"
  identifier                = "phantom-dev"
  instance_class            = "db.t3.micro" # Dev: smallest instance.
  multi_az                  = false         # Dev: no multi-AZ.
  vpc_id                    = data.aws_vpc.default.id
  subnet_ids                = data.aws_subnets.default.ids
  allowed_security_group_id = module.eks.node_security_group_id
  environment               = var.environment
}

module "elasticache" {
  source                    = "../../modules/elasticache"
  cluster_id                = "phantom-dev"
  node_type                 = "cache.t3.micro"
  vpc_id                    = data.aws_vpc.default.id
  subnet_ids                = data.aws_subnets.default.ids
  allowed_security_group_id = module.eks.node_security_group_id
}

module "ecr" {
  source = "../../modules/ecr"
}

output "cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "rds_endpoint" {
  value = module.rds.endpoint
}

output "redis_endpoint" {
  value = module.elasticache.primary_endpoint_address
}

output "ecr_repository_urls" {
  value = module.ecr.repository_urls
}

output "rds_password" {
  value     = module.rds.db_password
  sensitive = true
}

# After terraform apply, the bootstrap script will automatically update infra/k8s/configmaps.yaml
# and inject the RDS password into the Kubernetes secrets.
