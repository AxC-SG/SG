# The frontend is hosted on Vercel (owner decision, November 13, 2026); its headers and CSP live in
# prototype-app/frontend/vercel.json. The Amplify app and branch were retired with the lab cutover.

resource "aws_ecr_repository" "backend" {
  name                 = "${local.name}-backend"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

output "release_targets" {
  value = {
    aws_region           = var.aws_region
    backend_registry_url = aws_ecr_repository.backend.repository_url
  }
}
