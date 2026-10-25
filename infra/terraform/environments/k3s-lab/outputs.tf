output "instance_id" {
  description = "EC2 Instance ID of the k3s lab node"
  value       = aws_instance.k3s_lab.id
}

output "public_ip" {
  description = "Public IPv4 address of the k3s lab node"
  value       = aws_instance.k3s_lab.public_ip
}

output "ssh_private_key_path" {
  description = "Path to the generated SSH key, existing key name, or SSM-only status"
  value       = var.key_name == "" ? (var.enable_ssm ? "SSH key not generated; use SSM" : local_file.private_key[0].filename) : "Using user-provided key: ${var.key_name}"
}

output "ssh_command" {
  description = "Command to SSH into the disposable lab instance"
  value       = var.enable_ssm && var.key_name == "" ? "SSH disabled; connect with SSM" : (var.key_name == "" ? "ssh -i ${local_file.private_key[0].filename} ubuntu@${aws_instance.k3s_lab.public_ip}" : "ssh -i <YOUR_KEY.pem> ubuntu@${aws_instance.k3s_lab.public_ip}")
}

output "ssh_tunnel_command" {
  description = "Command to establish secure port forwarding for kubectl, PHANTOM API, and Prometheus"
  value       = var.enable_ssm && var.key_name == "" ? "Use SSM Session Manager port forwarding; no SSH ingress is configured" : (var.key_name == "" ? "ssh -i ${local_file.private_key[0].filename} -N -L 6443:127.0.0.1:6443 -L 8080:127.0.0.1:8080 -L 9090:127.0.0.1:9090 ubuntu@${aws_instance.k3s_lab.public_ip}" : "ssh -i <YOUR_KEY.pem> -N -L 6443:127.0.0.1:6443 -L 8080:127.0.0.1:8080 -L 9090:127.0.0.1:9090 ubuntu@${aws_instance.k3s_lab.public_ip}")
}

output "ssm_session_command" {
  description = "Command to connect via AWS Systems Manager Session Manager (no inbound ports required)"
  value       = "aws ssm start-session --target ${aws_instance.k3s_lab.id} --region ${var.aws_region}"
}

output "cost_scope_note" {
  description = "Cost categories requiring current regional price verification"
  value       = "EC2, gp3 EBS, public IPv4, and data transfer charges vary by region and usage; verify before deployment."
}
