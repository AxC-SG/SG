# Review documents only: no operator roles or attachments are created here.
# A migrator session remains privileged: ECS IAM cannot constrain command/env
# overrides or RunTask subnet/security-group/public-IP parameters. Review the
# exact request below and use only a trusted, short-lived release operator.
locals {
  lab_operator_documents = local.backend_enabled && var.environment == "lab" ? {
    image_publisher = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid       = "AuthenticateSelectedRegistry"
          Effect    = "Allow"
          Action    = ["ecr:GetAuthorizationToken"]
          Resource  = "*"
          Condition = { StringEquals = { "aws:RequestedRegion" = var.aws_region } }
        },
        {
          Sid    = "PublishOnlyLabBackend"
          Effect = "Allow"
          Action = [
            "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:CompleteLayerUpload",
            "ecr:DescribeImages", "ecr:DescribeRepositories", "ecr:InitiateLayerUpload",
            "ecr:PutImage", "ecr:UploadLayerPart"
          ]
          Resource  = aws_ecr_repository.backend.arn
          Condition = { StringEquals = { "aws:RequestedRegion" = var.aws_region } }
        }
      ]
    })
    migration_operator = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid      = "RunOnlyReviewedMigratorRevision"
          Effect   = "Allow"
          Action   = ["ecs:RunTask"]
          Resource = aws_ecs_task_definition.backend["migrator"].arn
          Condition = {
            ArnEquals = { "ecs:cluster" = aws_ecs_cluster.standard["standard"].arn }
            StringEquals = {
              "aws:RequestedRegion"           = var.aws_region
              "aws:RequestTag/Application"    = "ScoutGrid"
              "aws:RequestTag/Environment"    = "lab"
              "aws:RequestTag/ReleasePurpose" = "Migration"
            }
            StringEqualsIfExists = {
              "ecs:enable-execute-command" = "false"
              "ecs:enable-ebs-volumes"     = "false"
            }
          }
        },
        {
          Sid      = "TagOnlyTasksAtApprovedLaunch"
          Effect   = "Allow"
          Action   = ["ecs:TagResource"]
          Resource = "arn:aws:ecs:${var.aws_region}:${var.account_id}:task/${local.name}/*"
          Condition = {
            StringEquals = {
              "ecs:CreateAction"              = "RunTask"
              "aws:RequestedRegion"           = var.aws_region
              "aws:RequestTag/Application"    = "ScoutGrid"
              "aws:RequestTag/Environment"    = "lab"
              "aws:RequestTag/ReleasePurpose" = "Migration"
            }
            "ForAllValues:StringEquals" = { "aws:TagKeys" = ["Application", "Environment", "ReleasePurpose"] }
            Null                        = { "aws:TagKeys" = "false" }
          }
        },
        {
          Sid       = "PassOnlyMigratorExecutionRole"
          Effect    = "Allow"
          Action    = ["iam:PassRole"]
          Resource  = aws_iam_role.execution["migrator"].arn
          Condition = { StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } }
        },
        {
          Sid      = "InspectOrStopOnlyTaggedLabMigrations"
          Effect   = "Allow"
          Action   = ["ecs:DescribeTasks", "ecs:StopTask"]
          Resource = "arn:aws:ecs:${var.aws_region}:${var.account_id}:task/${local.name}/*"
          Condition = {
            ArnEquals = { "ecs:cluster" = aws_ecs_cluster.standard["standard"].arn }
            StringEquals = {
              "aws:RequestedRegion"            = var.aws_region
              "aws:ResourceTag/Application"    = "ScoutGrid"
              "aws:ResourceTag/Environment"    = "lab"
              "aws:ResourceTag/ReleasePurpose" = "Migration"
            }
          }
        },
        {
          Sid       = "ReadMigratorLogStreams"
          Effect    = "Allow"
          Action    = ["logs:DescribeLogStreams"]
          Resource  = aws_cloudwatch_log_group.backend["migrator"].arn
          Condition = { StringEquals = { "aws:RequestedRegion" = var.aws_region } }
        },
        {
          Sid       = "ReadOnlyMigratorLogEvents"
          Effect    = "Allow"
          Action    = ["logs:GetLogEvents"]
          Resource  = "${aws_cloudwatch_log_group.backend["migrator"].arn}:log-stream:migrator/*"
          Condition = { StringEquals = { "aws:RequestedRegion" = var.aws_region } }
        }
      ]
    })
  } : {}
}

output "lab_operator_policy_documents" {
  description = "Unattached review documents bound to this plan's repository, exact migration revision and execution role. Refresh after every revision."
  value       = local.lab_operator_documents
}

output "lab_migration_task_request" {
  description = "Review before launch; IAM does not enforce the private network parameters or prohibit overrides. Contains metadata only."
  value = local.backend_enabled && var.environment == "lab" ? {
    cluster              = aws_ecs_cluster.standard["standard"].arn
    taskDefinition       = aws_ecs_task_definition.backend["migrator"].arn
    launchType           = "FARGATE"
    platformVersion      = "1.4.0"
    count                = 1
    enableExecuteCommand = false
    networkConfiguration = {
      awsvpcConfiguration = {
        subnets        = module.network.boundaries.task_subnet_ids
        securityGroups = [aws_security_group.backend["migrator"].id]
        assignPublicIp = "DISABLED"
      }
    }
    tags = [
      { key = "Application", value = "ScoutGrid" },
      { key = "Environment", value = "lab" },
      { key = "ReleasePurpose", value = "Migration" }
    ]
  } : null
}
