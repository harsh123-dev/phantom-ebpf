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

variable "operator_ip" {
  type        = string
  description = "Operator public IPv4 address for SSH access (e.g. 203.0.113.50). Leave empty if using SSM Session Manager only."
  default     = ""
}

variable "key_name" {
  type        = string
  description = "Name of an existing EC2 KeyPair. If empty, a new disposable keypair will be generated."
  default     = ""
}

variable "lab_name" {
  type        = string
  description = "Tag name and prefix for lab resources"
  default     = "phantom-k3s-lab"
}

variable "enable_ssm" {
  type        = bool
  description = "Enable AWS Systems Manager Session Manager access (allows SSH/terminal without open inbound ports)"
  default     = true
}
