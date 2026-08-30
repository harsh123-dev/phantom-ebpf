terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
    random = {
      source = "hashicorp/random"
    }
  }
}

variable "identifier" {}

variable "instance_class" {
  default = "db.t3.medium"
}

variable "multi_az" {
  default = false
}

variable "vpc_id" {}

variable "subnet_ids" {
  type = list(string)
}

variable "allowed_security_group_id" {}

variable "environment" {}

# Required for: generating the RDS administrator password without hardcoding it.
resource "random_password" "db_password" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "aws_db_subnet_group" "phantom" {
  name       = "${var.identifier}-subnets"
  subnet_ids = var.subnet_ids

  tags = {
    Name        = "${var.identifier}-subnets"
    Environment = var.environment
    Service     = "phantom"
  }
}

resource "aws_security_group" "rds" {
  name        = "${var.identifier}-rds"
  description = "PHANTOM PostgreSQL access from EKS nodes"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.allowed_security_group_id]
    description     = "PostgreSQL from EKS nodes only"
  }

  # No egress rule: RDS does not initiate connections.
  egress = []

  tags = {
    Name        = "${var.identifier}-rds"
    Environment = var.environment
    Service     = "phantom"
  }
}

resource "aws_db_instance" "phantom" {
  identifier        = var.identifier
  engine            = "postgres"
  engine_version    = "15"   # Major version only — AWS picks the latest patch
  instance_class    = var.instance_class
  allocated_storage = 20
  storage_encrypted = false  # Free tier does not support encrypted storage
  multi_az          = var.multi_az

  db_name  = "phantom"
  username = "phantom_admin"
  password = random_password.db_password.result

  backup_retention_period = 0
  # Free tier restriction: automated backups must be disabled (retention = 0).
  # Set to 7+ in production when upgrading away from free tier.

  skip_final_snapshot       = var.environment == "dev"
  final_snapshot_identifier = var.environment == "dev" ? null : "${var.identifier}-final"
  publicly_accessible       = false

  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.phantom.name

  tags = {
    Name        = var.identifier
    Environment = var.environment
    Service     = "phantom"
  }
}

output "endpoint" {
  value = aws_db_instance.phantom.address
}

output "port" {
  value = aws_db_instance.phantom.port
}

output "database_name" {
  value = aws_db_instance.phantom.db_name
}

output "db_password" {
  value     = random_password.db_password.result
  sensitive = true
}
