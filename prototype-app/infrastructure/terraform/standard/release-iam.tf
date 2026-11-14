# GitHub Free cannot require reviewers or restrict branches on private-repository
# environments, so the subject itself carries the restriction: the repository's
# OIDC subject template includes job_workflow_ref, and the role trusts only the
# publisher workflow as it exists on main. Main changes only through reviewed PRs.
variable "github_publisher" {
  description = "Existing account-local GitHub OIDC provider and the exact subject: this environment plus the publisher workflow on main."
  type = object({
    provider_arn = string
    subject      = string
  })
  default = null

  validation {
    condition = var.github_publisher == null ? true : (
      var.github_publisher.provider_arn == "arn:aws:iam::${var.account_id}:oidc-provider/token.actions.githubusercontent.com" &&
      can(regex("^repo:(AxC-SG/SG|AxC-SG@[0-9]+/SG@[0-9]+):environment:aws-standard-${var.environment}:job_workflow_ref:AxC-SG/SG/\\.github/workflows/aws-publish-candidate\\.yml@refs/heads/main$", var.github_publisher.subject))
    )
    error_message = "Use the selected account's GitHub OIDC provider and the exact AxC-SG/SG subject for this Standard environment and the publisher workflow on main."
  }
}

resource "aws_iam_role" "github_publisher" {
  count                = var.github_publisher == null ? 0 : 1
  name                 = "${local.name}-github-ecr-publish"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = var.github_publisher.provider_arn }
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = var.github_publisher.subject
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "github_publisher" {
  count = length(aws_iam_role.github_publisher)
  name  = "publish-backend-image"
  role  = aws_iam_role.github_publisher[count.index].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:CompleteLayerUpload",
          "ecr:InitiateLayerUpload",
          "ecr:PutImage",
          "ecr:UploadLayerPart"
        ]
        Resource = aws_ecr_repository.backend.arn
      }
    ]
  })
}

output "github_ecr_publish_role_arn" {
  value = one(aws_iam_role.github_publisher[*].arn)
}
