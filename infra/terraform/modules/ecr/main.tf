locals {
  repositories = [
    "phantom/api-gateway",
    "phantom/causal-engine",
    "phantom/sbom-service",
    "phantom/report-generator",
    "phantom/ebpf-agent",
  ]
}

resource "aws_ecr_repository" "phantom" {
  for_each     = toset(local.repositories)
  name         = each.value
  force_delete = true

  image_scanning_configuration {
    scan_on_push = true
    # Scans every pushed image for CVEs using ECR native scanning.
  }

  encryption_configuration {
    encryption_type = "KMS"
    # KMS encryption for research artifact supply chain integrity.
  }
}

resource "aws_ecr_lifecycle_policy" "phantom" {
  for_each   = aws_ecr_repository.phantom
  repository = each.value.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 10 images per repo"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}

output "repository_urls" {
  value = {
    for name, repo in aws_ecr_repository.phantom : name => repo.repository_url
  }
}
