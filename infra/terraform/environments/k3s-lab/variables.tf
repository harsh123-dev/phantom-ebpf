variable "aws_region" {
  type        = string
  description = "AWS region for the disposable PHANTOM lab"
  default     = "ap-south-1"
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type for the single-node k3s lab (t3.xlarge: 4 vCPU, 16 GiB RAM)"
  default     = "t3.xlarge"
}

variable "root_volume_size" {
  type        = number
  description = "Size of root EBS volume in GB (gp3)"
  default     = 50
}

variable "enable_nat_gateway" {
  type        = bool
  description = "Route the private lab node through a NAT Gateway. When false, the lab node receives a public IPv4 address for outbound bootstrap only; its security group still has no ingress rules and allows only HTTP/HTTPS egress plus VPC DNS and time sync."
  default     = true
}

variable "operator_ip" {
  type        = string
  description = "Deprecated compatibility variable; the private PHANTOM lab has no inbound SSH rule and uses SSM only."
  default     = ""
}

variable "key_name" {
  type        = string
  description = "Deprecated compatibility variable; the private SSM-only lab does not require or use SSH keys."
  default     = ""
}

variable "lab_name" {
  type        = string
  description = "Tag name and prefix for lab resources"
  default     = "phantom-k3s-lab"

  validation {
    condition     = length(var.lab_name) <= 30 && can(regex("^[a-z0-9][a-z0-9-]*$", var.lab_name))
    error_message = "lab_name must be lowercase DNS-style text no longer than 30 characters so the derived S3 bucket name is valid."
  }
}

variable "enable_ssm" {
  type        = bool
  description = "Enable AWS Systems Manager Session Manager access (allows SSH/terminal without open inbound ports)"
  default     = true
}

variable "enable_evidence_backups" {
  type        = bool
  description = "Create an encrypted, versioned S3 evidence-backup bucket and grant the lab role prefix-scoped access"
  default     = false
}

variable "enable_s3_workload_identity" {
  type        = bool
  description = "Create a dedicated S3-only IAM role and allow the node credential broker to assume it. Requires explicit operator deployment of the k3s token-review broker."
  default     = false
}

variable "sbom_workload_bucket_name" {
  type        = string
  description = "Existing S3 bucket for SBOM artifacts when evidence_backups does not manage the bucket."
  default     = ""

  validation {
    condition     = var.sbom_workload_bucket_name == "" || (length(var.sbom_workload_bucket_name) >= 3 && length(var.sbom_workload_bucket_name) <= 63 && can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]$", var.sbom_workload_bucket_name)))
    error_message = "sbom_workload_bucket_name must be empty or a valid lowercase S3 bucket name."
  }
}

variable "sbom_workload_prefix" {
  type        = string
  description = "Exact S3 object prefix used by the SBOM workload role."
  default     = "phantom/evidence/sboms"

  validation {
    condition     = length(var.sbom_workload_prefix) > 0 && can(regex("^[a-zA-Z0-9/_-]+$", var.sbom_workload_prefix)) && !startswith(var.sbom_workload_prefix, "/") && !endswith(var.sbom_workload_prefix, "/") && !strcontains(var.sbom_workload_prefix, "..")
    error_message = "sbom_workload_prefix must be a safe, relative S3 prefix without traversal or wildcard characters."
  }
}

variable "evidence_backup_prefix" {
  type        = string
  description = "Object prefix the PHANTOM lab role may list, write, and restore"
  default     = "phantom/evidence"

  validation {
    condition     = length(var.evidence_backup_prefix) > 0 && can(regex("^[a-zA-Z0-9/_-]+$", var.evidence_backup_prefix)) && !startswith(var.evidence_backup_prefix, "/") && !endswith(var.evidence_backup_prefix, "/") && !strcontains(var.evidence_backup_prefix, "..")
    error_message = "evidence_backup_prefix must be a safe nonempty S3 key prefix without traversal, wildcards, or edge slashes."
  }
}
