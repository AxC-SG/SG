locals {
  ecs_trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:ecs:${var.aws_region}:${var.account_id}:*" }
      }
    }]
  })

  runtime_secrets = local.backend_enabled ? {
    DB_USERNAME                       = "${var.backend_candidate.runtime_db_secret}:username::"
    DB_PASSWORD                       = "${var.backend_candidate.runtime_db_secret}:password::"
    APP_CREDENTIAL_ENCRYPTION_KEY     = "${var.backend_candidate.application_secret}:credential_encryption_key::"
    APP_AI_SECURITY_IDENTITY_HMAC_KEY = "${var.backend_candidate.application_secret}:ai_identity_hmac_key::"
    APP_TURNSTILE_SECRET_KEY          = "${var.backend_candidate.application_secret}:turnstile_secret_key::"
  } : {}

  managed_installation_fields = {
    APP_MANAGED_INSTALLATION_OWNER_EMAIL            = "owner_email"
    APP_MANAGED_INSTALLATION_OWNER_SUBJECT          = "owner_subject"
    APP_MANAGED_INSTALLATION_INTERNAL_ADMIN_EMAIL   = "internal_admin_email"
    APP_MANAGED_INSTALLATION_INTERNAL_ADMIN_SUBJECT = "internal_admin_subject"
  }

  execution_secret_arns = {
    for role in keys(local.backend_tasks) : role => concat(
      [var.backend_candidate.runtime_db_secret, var.backend_candidate.application_secret],
      role == "migrator" ? concat([local.db_owner_arn], compact([local.managed_installation_secret])) : []
    )
  }

  task_secrets = {
    api    = local.runtime_secrets
    worker = local.runtime_secrets
    migrator = local.backend_enabled ? merge({
      MIGRATION_DB_USERNAME         = "${local.db_owner_arn}:username::"
      MIGRATION_DB_PASSWORD         = "${local.db_owner_arn}:password::"
      RUNTIME_DB_USERNAME           = "${var.backend_candidate.runtime_db_secret}:username::"
      RUNTIME_DB_PASSWORD           = "${var.backend_candidate.runtime_db_secret}:password::"
      APP_CREDENTIAL_ENCRYPTION_KEY = "${var.backend_candidate.application_secret}:credential_encryption_key::"
      }, local.managed_installation_secret == null ? {} : {
      for name, field in local.managed_installation_fields : name => "${local.managed_installation_secret}:${field}::${var.backend_candidate.managed_installation.version_id}"
    }) : {}
  }

  import_permissions = {
    api = {
      s3  = ["s3:PutObject", "s3:GetObject"]
      kms = ["kms:GenerateDataKey", "kms:Decrypt"]
    }
    worker = {
      s3  = ["s3:GetObjectVersion"]
      kms = ["kms:Decrypt"]
    }
  }
}

resource "aws_iam_role" "execution" {
  for_each           = local.backend_tasks
  name               = "${local.name}-${each.key}-execution"
  assume_role_policy = local.ecs_trust

  lifecycle {
    precondition {
      condition     = !contains(compact([var.backend_candidate.runtime_db_secret, var.backend_candidate.application_secret, local.managed_installation_secret]), local.db_owner_arn)
      error_message = "The RDS owner secret must remain separate from runtime and enrollment inputs."
    }
  }
}

resource "aws_iam_role_policy" "execution" {
  for_each = local.backend_tasks
  name     = "ecs-startup"
  role     = aws_iam_role.execution[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
        Resource = aws_ecr_repository.backend.arn
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.backend[each.key].arn}:log-stream:${each.key}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = local.execution_secret_arns[each.key]
      },
      {
        Effect = "Allow"
        Action = ["kms:Decrypt"]
        Resource = concat(
          [var.backend_candidate.secrets_kms_key_arn],
          each.key == "migrator" ? [aws_kms_key.database.arn] : []
        )
        Condition = {
          StringEquals = {
            "kms:ViaService"                  = "secretsmanager.${var.aws_region}.amazonaws.com"
            "kms:EncryptionContext:SecretARN" = local.execution_secret_arns[each.key]
          }
        }
      }
    ])
  })
}

resource "aws_iam_role" "application" {
  for_each           = local.backend_enabled ? local.import_permissions : {}
  name               = "${local.name}-${each.key}-task"
  assume_role_policy = local.ecs_trust
}

resource "aws_iam_role_policy" "imports" {
  for_each = local.backend_enabled ? local.import_permissions : {}
  name     = "bom-imports"
  role     = aws_iam_role.application[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = each.value.s3
        Resource = "${local.imports_arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = each.value.kms
        Resource = aws_kms_key.objects.arn
        Condition = {
          StringEquals = {
            "kms:ViaService"                   = "s3.${var.aws_region}.amazonaws.com"
            "kms:EncryptionContext:aws:s3:arn" = local.imports_arn
          }
        }
      }
    ]
  })
}
