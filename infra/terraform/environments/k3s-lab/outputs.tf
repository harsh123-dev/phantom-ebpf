output "instance_id" {
  description = "EC2 Instance ID of the k3s lab node"
  value       = aws_instance.k3s_lab.id
}

output "public_ip" {
  description = "Public IPv4 address of the lab node; null when NAT mode keeps the node private"
  value       = aws_instance.k3s_lab.public_ip
}

output "private_ip" {
  description = "Private IPv4 address of the PHANTOM k3s node"
  value       = aws_instance.k3s_lab.private_ip
}

output "ssh_private_key_path" {
  description = "SSH key path is unused; this private lab is administered through SSM"
  value       = "SSH disabled; use SSM"
}

output "ssh_command" {
  description = "SSH is not exposed; use the SSM session command"
  value       = "SSH disabled; use SSM"
}

output "ssh_tunnel_command" {
  description = "Use SSM port forwarding; no SSH or public service ingress is configured"
  value       = "aws ssm start-session --target ${aws_instance.k3s_lab.id} --region ${var.aws_region} --document-name AWS-StartPortForwardingSession --parameters '{\"portNumber\":[\"6443\"],\"localPortNumber\":[\"16443\"]}'"
}

output "ssm_session_command" {
  description = "Command to connect via AWS Systems Manager Session Manager (no inbound ports required)"
  value       = "aws ssm start-session --target ${aws_instance.k3s_lab.id} --region ${var.aws_region}"
}

output "cost_scope_note" {
  description = "Cost categories requiring current regional price verification"
  value       = "EC2, gp3 EBS, NAT Gateway, NAT data processing, NAT Elastic IP, SSM interface endpoints, optional S3, and transfer charges vary by region and usage; verify before deployment."
}

output "evidence_backup_bucket" {
  description = "Versioned PHANTOM evidence bucket; null when off-node backups are disabled"
  value       = var.enable_evidence_backups ? aws_s3_bucket.evidence_backups[0].bucket : null
}

output "evidence_backup_prefix" {
  description = "Prefix authorized for the dedicated lab instance role"
  value       = var.enable_evidence_backups ? var.evidence_backup_prefix : null
}

output "sbom_workload_role_arn" {
  description = "Dedicated S3-only role for the SBOM credential broker; null when workload identity is disabled"
  value       = var.enable_s3_workload_identity ? aws_iam_role.sbom_workload[0].arn : null
}
