output "instance_id" {
  description = "EC2 Instance ID of the k3s lab node"
  value       = aws_instance.k3s_lab.id
}

output "public_ip" {
  description = "Public IPv4 address of the k3s lab node"
  value       = aws_instance.k3s_lab.public_ip
}

output "ssh_private_key_path" {
  description = "Path to the auto-generated private key (if generated)"
  value       = var.key_name == "" ? local_file.private_key[0].filename : "Using user-provided key: ${var.key_name}"
}

output "ssh_command" {
  description = "Command to SSH into the disposable lab instance"
  value       = var.key_name == "" ? "ssh -i ${local_file.private_key[0].filename} ubuntu@${aws_instance.k3s_lab.public_ip}" : "ssh -i <YOUR_KEY.pem> ubuntu@${aws_instance.k3s_lab.public_ip}"
}

output "ssh_tunnel_command" {
  description = "Command to establish secure port forwarding for kubectl, PHANTOM API, and Prometheus"
  value       = var.key_name == "" ? "ssh -i ${local_file.private_key[0].filename} -N -L 6443:127.0.0.1:6443 -L 8080:127.0.0.1:8080 -L 9090:127.0.0.1:9090 ubuntu@${aws_instance.k3s_lab.public_ip}" : "ssh -i <YOUR_KEY.pem> -N -L 6443:127.0.0.1:6443 -L 8080:127.0.0.1:8080 -L 9090:127.0.0.1:9090 ubuntu@${aws_instance.k3s_lab.public_ip}"
}

output "ssm_session_command" {
  description = "Command to connect via AWS Systems Manager Session Manager (no inbound ports required)"
  value       = "aws ssm start-session --target ${aws_instance.k3s_lab.id} --region ${var.aws_region}"
}

output "estimated_hourly_cost_usd" {
  description = "Estimated hourly cost for all billable resources"
  value       = "~$0.170 / hour ($0.1664 for t3.xlarge + $0.0055 for 50GB gp3 EBS)"
}
