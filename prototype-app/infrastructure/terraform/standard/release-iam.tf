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

# The lab's runtime-only releaser (CD plan 4.3 and 5; phase 4 slice 2). Only the manual
# reconcile workflow on main, in its own protected environment, can assume it. It may roll
# api and worker to a published image and nothing else: it can neither register nor pass
# the migrator, start or stop tasks, snapshot or change the database, read secret values or
# change IAM. release.py's runtime-only path refuses the same work in code.
#
# Accepted risk (CD plan 5): ECS cannot constrain what a registered task definition contains,
# so a malicious change merged to main could register an api task that runs another lab ECR
# image or command. Only reviewed main runs the workflow, release.py's plan allowlist limits
# the change to api/worker, and the role holds no secret values or migrator authority.
# ecs:DeregisterTaskDefinition has no resource-level scope, so it cannot be denied for the
# migrator family alone (grants/bootstrap-deregister-migrator.INEFFECTIVE-scoped-arn.json).
variable "github_releaser" {
  description = "Existing account-local GitHub OIDC provider and the exact subject: the lab release environment plus the reconcile workflow on main. Lab only."
  type = object({
    provider_arn = string
    subject      = string
  })
  default = null

  validation {
    condition = var.github_releaser == null ? true : (
      var.environment == "lab" &&
      var.github_releaser.provider_arn == "arn:aws:iam::${var.account_id}:oidc-provider/token.actions.githubusercontent.com" &&
      can(regex("^repo:(AxC-SG/SG|AxC-SG@[0-9]+/SG@[0-9]+):environment:aws-standard-lab-release:job_workflow_ref:AxC-SG/SG/\\.github/workflows/lab-reconcile\\.yml@refs/heads/main$", var.github_releaser.subject))
    )
    error_message = "The releaser is lab only: use the selected account's GitHub OIDC provider and the exact AxC-SG/SG subject for the aws-standard-lab-release environment and the reconcile workflow on main."
  }
}

locals {
  releaser_ecs         = "arn:aws:ecs:${var.aws_region}:${var.account_id}"
  releaser_state       = "arn:aws:s3:::scoutgrid-${var.environment}-tfstate-${var.account_id}-${var.aws_region}"
  releaser_release     = "${local.releaser_state}/standard/${var.environment}/release"
  releaser_runtime     = ["api", "worker"]
  releaser_task_family = { for role in concat(local.releaser_runtime, ["migrator"]) : role => "${local.releaser_ecs}:task-definition/${local.name}-${role}:*" }
  releaser_required_tags = {
    "aws:RequestedRegion"        = var.aws_region
    "aws:RequestTag/Application" = "ScoutGrid"
    "aws:RequestTag/Environment" = var.environment
    "aws:RequestTag/Profile"     = "Standard"
    "aws:RequestTag/ManagedBy"   = "Terraform"
  }
  # The read policies the Release role already uses for Terraform plans: state and lock access,
  # provider metadata reads, an explicit deny on secret values, and deployment watches.
  releaser_managed_policies = {
    for name in ["common-read-state-part1", "common-read-state-part2", "waf-association-read", "cycle-watch"] :
    name => "arn:aws:iam::${var.account_id}:policy/ScoutGridSydneyLab-${name}"
  }
}

resource "aws_iam_role" "github_releaser" {
  count                = var.github_releaser == null ? 0 : 1
  name                 = "${local.name}-github-release"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = var.github_releaser.provider_arn }
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = var.github_releaser.subject
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "github_releaser" {
  count = length(aws_iam_role.github_releaser)
  name  = "runtime-only-release"
  role  = aws_iam_role.github_releaser[count.index].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [for role in local.releaser_runtime : {
        Sid      = "RegisterReviewed${title(role)}TaskDefinition"
        Effect   = "Allow"
        Action   = ["ecs:RegisterTaskDefinition"]
        Resource = local.releaser_task_family[role]
        Condition = {
          StringEquals                = local.releaser_required_tags
          StringEqualsIfExists        = { "ecs:privileged" = "false" }
          NumericEquals               = { "ecs:task-cpu" = local.task_shapes[role].cpu, "ecs:task-memory" = local.task_shapes[role].memory }
          "ForAllValues:StringEquals" = { "ecs:compute-compatibility" = "FARGATE" }
          Null                        = { "ecs:compute-compatibility" = "false" }
        }
      }],
      [
        {
          Sid       = "TagNewRuntimeTaskDefinitions"
          Effect    = "Allow"
          Action    = ["ecs:TagResource"]
          Resource  = [for role in local.releaser_runtime : local.releaser_task_family[role]]
          Condition = { StringEquals = local.releaser_required_tags }
        },
        {
          # Terraform retires the revision a replacement supersedes; the action takes no resource scope.
          Sid       = "RetireReplacedTaskDefinitions"
          Effect    = "Allow"
          Action    = ["ecs:DeregisterTaskDefinition"]
          Resource  = "*"
          Condition = { StringEquals = { "aws:RequestedRegion" = var.aws_region } }
        },
        {
          Sid    = "PassOnlyApiAndWorkerRoles"
          Effect = "Allow"
          Action = ["iam:PassRole"]
          Resource = flatten([for role in local.releaser_runtime : [
            "arn:aws:iam::${var.account_id}:role/${local.name}-${role}-execution",
            "arn:aws:iam::${var.account_id}:role/${local.name}-${role}-task",
          ]])
          Condition = { StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } }
        },
        {
          Sid      = "UpdateApiAndWorkerServices"
          Effect   = "Allow"
          Action   = ["ecs:UpdateService"]
          Resource = [for role in local.releaser_runtime : "${local.releaser_ecs}:service/${local.name}/${role}"]
          Condition = {
            ArnEquals       = { "ecs:cluster" = "${local.releaser_ecs}:cluster/${local.name}" }
            ArnLikeIfExists = { "ecs:task-definition" = [for role in local.releaser_runtime : local.releaser_task_family[role]] }
            StringEquals    = { "aws:RequestedRegion" = var.aws_region }
          }
        },
        {
          Sid       = "ReadApiTargetHealth"
          Effect    = "Allow"
          Action    = ["elasticloadbalancing:DescribeTargetGroups", "elasticloadbalancing:DescribeTargetHealth"]
          Resource  = "*"
          Condition = { StringEquals = { "aws:RequestedRegion" = var.aws_region } }
        },
        {
          Sid    = "ReadApiAndWorkerLogs"
          Effect = "Allow"
          Action = ["logs:FilterLogEvents", "logs:GetLogEvents"]
          Resource = flatten([for role in local.releaser_runtime : [
            "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:/ecs/${local.name}/${role}",
            "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:/ecs/${local.name}/${role}:*",
          ]])
        },
        {
          Sid      = "ManageReleaseInputsAndRecords"
          Effect   = "Allow"
          Action   = ["s3:GetObject", "s3:PutObject"]
          Resource = ["${local.releaser_release}/inputs.json", "${local.releaser_release}/records/*"]
        },
        {
          Sid      = "ManageReleaseLock"
          Effect   = "Allow"
          Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
          Resource = ["${local.releaser_release}/lock.json"]
        },
        {
          # A targeted runtime plan refreshes the import/export buckets (the Release role needed this in PR #110).
          Sid       = "ReadOnlyNamedLabBucketWebsiteMetadata"
          Effect    = "Allow"
          Action    = ["s3:GetBucketWebsite"]
          Resource  = ["arn:aws:s3:::${local.name}-${var.account_id}-imports", "arn:aws:s3:::${local.name}-${var.account_id}-exports"]
          Condition = { StringEquals = { "s3:ResourceAccount" = var.account_id } }
        },
        # Explicit denies: belt and braces, though nothing above allows them.
        {
          Sid      = "DenyTaskLaunchAndStop"
          Effect   = "Deny"
          Action   = ["ecs:RunTask", "ecs:StartTask", "ecs:StopTask", "ecs:ExecuteCommand"]
          Resource = "*"
        },
        {
          Sid      = "DenyMigratorTaskDefinitions"
          Effect   = "Deny"
          Action   = ["ecs:RegisterTaskDefinition", "ecs:TagResource"]
          Resource = local.releaser_task_family["migrator"]
        },
        {
          Sid      = "DenyMigratorRole"
          Effect   = "Deny"
          Action   = ["iam:PassRole"]
          Resource = "arn:aws:iam::${var.account_id}:role/${local.name}-migrator-execution"
        },
        {
          Sid      = "DenyDatabaseSnapshotsAndChanges"
          Effect   = "Deny"
          Action   = ["rds:CreateDBSnapshot", "rds:RestoreDBInstance*", "rds:Modify*", "rds:Delete*"]
          Resource = "*"
        },
        {
          Sid      = "DenySecretValues"
          Effect   = "Deny"
          Action   = ["secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue"]
          Resource = "*"
        },
        {
          Sid    = "DenyIamWrites"
          Effect = "Deny"
          Action = [
            "iam:Add*", "iam:Attach*", "iam:Change*", "iam:Create*", "iam:Deactivate*", "iam:Delete*", "iam:Detach*",
            "iam:Enable*", "iam:Put*", "iam:Remove*", "iam:Reset*", "iam:Resync*", "iam:Set*", "iam:Tag*",
            "iam:Untag*", "iam:Update*", "iam:Upload*"
          ]
          Resource = "*"
        },
        {
          # Terraform's own S3 lock (use_lockfile) is released by deleting it, so it is the one other exception.
          Sid         = "DenyDeletesOutsideTheLocks"
          Effect      = "Deny"
          Action      = ["s3:DeleteObject"]
          NotResource = ["${local.releaser_release}/lock.json", "${local.releaser_state}/standard/${var.environment}/terraform.tfstate.tflock"]
        },
        {
          Sid      = "DenyHistoryAndBucketDeletion"
          Effect   = "Deny"
          Action   = ["s3:DeleteObjectVersion", "s3:DeleteBucket", "s3:PutBucketPolicy", "s3:PutBucketVersioning", "s3:PutLifecycleConfiguration"]
          Resource = "*"
        }
      ]
    )
  })
}

resource "aws_iam_role_policy_attachment" "github_releaser" {
  for_each   = length(aws_iam_role.github_releaser) == 0 ? {} : local.releaser_managed_policies
  role       = aws_iam_role.github_releaser[0].name
  policy_arn = each.value
}

output "github_release_role_arn" {
  value = one(aws_iam_role.github_releaser[*].arn)
}
