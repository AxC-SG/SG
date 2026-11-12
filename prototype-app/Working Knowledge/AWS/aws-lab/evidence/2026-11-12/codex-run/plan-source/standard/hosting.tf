locals {
  frontend_security_headers = {
    Content-Security-Policy = join("; ", [
      "default-src 'self'",
      "script-src 'self' https://challenges.cloudflare.com",
      "frame-src https://challenges.cloudflare.com",
      "connect-src 'self' ${var.api_origin} https://${aws_s3_bucket.artifacts["imports"].bucket_regional_domain_name} https://challenges.cloudflare.com https://*.ingest.sentry.io",
      "img-src 'self' data: blob:",
      "style-src 'self' 'unsafe-inline'",
      "font-src 'self' data:",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "upgrade-insecure-requests",
    ])
    Cache-Control          = "no-cache"
    Referrer-Policy        = "no-referrer"
    X-Content-Type-Options = "nosniff"
    X-Frame-Options        = "DENY"
    Permissions-Policy     = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
  }
}

resource "aws_amplify_app" "frontend" {
  name     = "${local.name}-frontend"
  platform = "WEB"

  enable_auto_branch_creation = false
  enable_branch_auto_build    = false

  custom_rule {
    source = "</^\\/(?!assets(?:\\/|$))[^.]*$/>"
    status = "200"
    target = "/index.html"
  }

  custom_headers = yamlencode({
    customHeaders = [
      {
        pattern = "**"
        headers = [for key, value in local.frontend_security_headers : { key = key, value = value }]
      },
      {
        pattern = "/assets/**"
        headers = [{ key = "Cache-Control", value = "public, max-age=31536000, immutable" }]
      }
    ]
  })
}

resource "aws_amplify_branch" "frontend" {
  app_id            = aws_amplify_app.frontend.id
  branch_name       = var.environment
  enable_auto_build = false
  stage             = local.is_production ? "PRODUCTION" : "DEVELOPMENT"
}

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
    frontend_app_id      = aws_amplify_app.frontend.id
    frontend_branch      = aws_amplify_branch.frontend.branch_name
    backend_registry_url = aws_ecr_repository.backend.repository_url
  }
}
