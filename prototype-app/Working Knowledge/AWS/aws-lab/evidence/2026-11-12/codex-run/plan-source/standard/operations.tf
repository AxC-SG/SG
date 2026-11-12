variable "operations" {
  description = "Reviewed audit recovery role and existing operator alert topic. Leave null until audit scope and spend are approved."
  type = object({
    audit_recovery_role_arn  = string
    alert_topic_arn          = string
    config_recorder_role_arn = optional(string)
    guardduty_detector_id    = optional(string)
    security_topic_arn       = optional(string)
  })
  default = null

  validation {
    condition = var.operations == null ? true : (
      can(regex("^arn:aws:iam::${var.account_id}:role/[A-Za-z0-9_+=,.@/-]+$", var.operations.audit_recovery_role_arn)) &&
      can(regex("^arn:aws:sns:${var.aws_region}:${var.account_id}:[A-Za-z0-9_-]{1,256}$", var.operations.alert_topic_arn))
    )
    error_message = "Use an audit recovery role and a standard SNS topic in the selected account, with the topic in the selected region."
  }

  validation {
    condition = var.operations == null ? true : alltrue([
      var.operations.config_recorder_role_arn == null ||
      var.operations.config_recorder_role_arn == "arn:aws:iam::${var.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
      var.operations.guardduty_detector_id == null || can(regex("^[a-f0-9]{32}$", var.operations.guardduty_detector_id)),
      var.operations.security_topic_arn == null ? (
        var.operations.config_recorder_role_arn == null && var.operations.guardduty_detector_id == null
        ) : (
        can(regex("^arn:aws:sns:${var.aws_region}:${var.account_id}:[A-Za-z0-9_-]{1,256}$", var.operations.security_topic_arn)) &&
        var.operations.security_topic_arn != var.operations.alert_topic_arn
      )
    ])
    error_message = "Use the selected account's AWS Config service-linked role, a verified GuardDuty detector ID, and a separate account-local security SNS topic in the selected region."
  }
}

locals {
  audit_trail_name = "${local.name}-operations"
  audit_trail_arn  = "arn:aws:cloudtrail:${var.aws_region}:${var.account_id}:trail/${local.audit_trail_name}"
  alert_prefix     = "${local.name}-ops"
}

resource "aws_kms_key" "audit" {
  count                   = var.operations == null ? 0 : 1
  description             = "${local.name} CloudTrail audit archive"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid       = "DelegateKeyAdministrationToAccount"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "EncryptForThisTrail"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:GenerateDataKey*"
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceArn" = local.audit_trail_arn }
          StringLike   = { "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${var.account_id}:trail/${local.audit_trail_name}" }
        }
      },
      {
        Sid       = "DescribeKeyForThisTrail"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:DescribeKey"
        Resource  = "*"
        Condition = { StringEquals = { "aws:SourceArn" = local.audit_trail_arn } }
      }
      ], [for statement in [
        {
          Sid       = "EncryptConfigArchive"
          Effect    = "Allow"
          Principal = { Service = "config.amazonaws.com" }
          Action    = ["kms:GenerateDataKey", "kms:Decrypt"]
          Resource  = "*"
          Condition = {
            StringEquals = { "aws:SourceAccount" = var.account_id }
            ArnLike      = { "aws:SourceArn" = local.config_source_arn }
          }
        }
    ] : statement if local.config_enabled])
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket" "audit" {
  count  = var.operations == null ? 0 : 1
  bucket = local.audit_bucket_name

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "audit" {
  count                   = length(aws_s3_bucket.audit)
  bucket                  = aws_s3_bucket.audit[count.index].id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "audit" {
  count  = length(aws_s3_bucket.audit)
  bucket = aws_s3_bucket.audit[count.index].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "audit" {
  count  = length(aws_s3_bucket.audit)
  bucket = aws_s3_bucket.audit[count.index].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  count  = length(aws_s3_bucket.audit)
  bucket = aws_s3_bucket.audit[count.index].id

  rule {
    bucket_key_enabled = false

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.audit[count.index].arn
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  count  = length(aws_s3_bucket.audit)
  bucket = aws_s3_bucket.audit[count.index].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid       = "CheckBucketForThisTrail"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.audit[count.index].arn
        Condition = { StringEquals = { "aws:SourceArn" = local.audit_trail_arn } }
      },
      {
        Sid       = "DeliverForThisTrail"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.audit[count.index].arn}/AWSLogs/${var.account_id}/*"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = local.audit_trail_arn
            "s3:x-amz-acl"  = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid       = "DenyWritesFromOtherPrincipals"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.audit[count.index].arn}/*"
        Condition = {
          StringNotEqualsIfExists = {
            "aws:PrincipalServiceName" = local.config_enabled ? ["cloudtrail.amazonaws.com", "config.amazonaws.com"] : ["cloudtrail.amazonaws.com"]
          }
        }
      },
      {
        Sid       = "ProtectAuditObjects"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
        Resource  = "${aws_s3_bucket.audit[count.index].arn}/*"
        Condition = { ArnNotEqualsIfExists = { "aws:PrincipalArn" = var.operations.audit_recovery_role_arn } }
      },
      {
        Sid       = "ProtectAuditRetention"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:DeleteBucket", "s3:PutBucketVersioning", "s3:PutLifecycleConfiguration"]
        Resource  = aws_s3_bucket.audit[count.index].arn
        Condition = { ArnNotEqualsIfExists = { "aws:PrincipalArn" = var.operations.audit_recovery_role_arn } }
      },
      {
        Sid       = "RequireTLSForDirectClients"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.audit[count.index].arn, "${aws_s3_bucket.audit[count.index].arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false", "aws:PrincipalIsAWSService" = "false" } }
      }
      ], [for statement in [
        {
          Sid       = "CheckConfigArchive"
          Effect    = "Allow"
          Principal = { Service = "config.amazonaws.com" }
          Action    = ["s3:GetBucketAcl", "s3:ListBucket"]
          Resource  = aws_s3_bucket.audit[count.index].arn
          Condition = {
            StringEquals = { "aws:SourceAccount" = var.account_id }
            ArnLike      = { "aws:SourceArn" = local.config_source_arn }
          }
        },
        {
          Sid       = "DeliverConfigArchive"
          Effect    = "Allow"
          Principal = { Service = "config.amazonaws.com" }
          Action    = "s3:PutObject"
          Resource  = "${aws_s3_bucket.audit[count.index].arn}/${local.config_object_prefix}/*"
          Condition = {
            StringEquals = {
              "aws:SourceAccount" = var.account_id
              "s3:x-amz-acl"      = "bucket-owner-full-control"
            }
            ArnLike = { "aws:SourceArn" = local.config_source_arn }
          }
        }
    ] : statement if local.config_enabled])
  })

  depends_on = [aws_s3_bucket_public_access_block.audit, aws_s3_bucket_versioning.audit]
}

resource "aws_cloudtrail" "standard" {
  count                         = length(aws_s3_bucket.audit)
  name                          = local.audit_trail_name
  s3_bucket_name                = aws_s3_bucket.audit[count.index].id
  kms_key_id                    = aws_kms_key.audit[count.index].arn
  enable_logging                = true
  enable_log_file_validation    = true
  include_global_service_events = true
  is_multi_region_trail         = true

  event_selector {
    include_management_events = true
    read_write_type           = "All"
  }

  depends_on = [
    aws_s3_bucket_policy.audit,
    aws_s3_bucket_server_side_encryption_configuration.audit,
    aws_s3_bucket_ownership_controls.audit,
  ]
}

locals {
  database_alarms = var.operations == null ? {} : {
    "database-storage" = {
      description = "RDS has less than 10 GiB of free storage."
      namespace   = "AWS/RDS"
      metric      = "FreeStorageSpace"
      dimensions  = { DBInstanceIdentifier = aws_db_instance.standard.identifier }
      statistic   = "Minimum"
      comparison  = "LessThanThreshold"
      threshold   = 10 * 1024 * 1024 * 1024
      missing     = "missing"
    }
    "database-cpu" = {
      description = "Average RDS CPU utilization is at least 80 percent."
      namespace   = "AWS/RDS"
      metric      = "CPUUtilization"
      dimensions  = { DBInstanceIdentifier = aws_db_instance.standard.identifier }
      statistic   = "Average"
      comparison  = "GreaterThanOrEqualToThreshold"
      threshold   = 80
      missing     = "missing"
    }
  }

  service_alarms = var.operations == null || !try(var.backend_candidate.start_services, false) ? {} : {
    "api-unavailable" = {
      description = "The API target group reports no healthy targets or no health samples."
      namespace   = "AWS/ApplicationELB"
      metric      = "HealthyHostCount"
      dimensions = {
        LoadBalancer = aws_lb.api["standard"].arn_suffix
        TargetGroup  = aws_lb_target_group.api["standard"].arn_suffix
      }
      statistic  = "Maximum"
      comparison = "LessThanThreshold"
      threshold  = 1
      missing    = "breaching"
    }
    "api-target-errors" = {
      description = "The API reports at least five target-generated 5xx responses per minute."
      namespace   = "AWS/ApplicationELB"
      metric      = "HTTPCode_Target_5XX_Count"
      dimensions = {
        LoadBalancer = aws_lb.api["standard"].arn_suffix
        TargetGroup  = aws_lb_target_group.api["standard"].arn_suffix
      }
      statistic  = "Sum"
      comparison = "GreaterThanOrEqualToThreshold"
      threshold  = 5
      missing    = "notBreaching"
    }
    "api-load-balancer-errors" = {
      description = "The load balancer reports at least five load-balancer-generated 5xx responses per minute."
      namespace   = "AWS/ApplicationELB"
      metric      = "HTTPCode_ELB_5XX_Count"
      dimensions  = { LoadBalancer = aws_lb.api["standard"].arn_suffix }
      statistic   = "Sum"
      comparison  = "GreaterThanOrEqualToThreshold"
      threshold   = 5
      missing     = "notBreaching"
    }
    "worker-unavailable" = {
      description = "The worker service has fewer running tasks than desired or no task count samples."
      namespace   = "ECS/ContainerInsights"
      metric      = "RunningTaskCount"
      dimensions = {
        ClusterName = aws_ecs_cluster.standard["standard"].name
        ServiceName = aws_ecs_service.backend["worker"].name
      }
      statistic  = "Minimum"
      comparison = "LessThanThreshold"
      threshold  = aws_ecs_service.backend["worker"].desired_count
      missing    = "breaching"
    }
    "worker-cpu" = {
      description = "Average ECS worker CPU utilization is at least 85 percent."
      namespace   = "AWS/ECS"
      metric      = "CPUUtilization"
      dimensions = {
        ClusterName = aws_ecs_cluster.standard["standard"].name
        ServiceName = aws_ecs_service.backend["worker"].name
      }
      statistic  = "Average"
      comparison = "GreaterThanOrEqualToThreshold"
      threshold  = 85
      missing    = "missing"
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "operations" {
  for_each            = merge(local.database_alarms, local.service_alarms)
  alarm_name          = "${local.alert_prefix}-${each.key}"
  alarm_description   = each.value.description
  namespace           = each.value.namespace
  metric_name         = each.value.metric
  dimensions          = each.value.dimensions
  statistic           = each.value.statistic
  comparison_operator = each.value.comparison
  threshold           = each.value.threshold
  treat_missing_data  = each.value.missing
  period              = 60
  evaluation_periods  = 3
  datapoints_to_alarm = 2
  alarm_actions       = [var.operations.alert_topic_arn]
  ok_actions          = [var.operations.alert_topic_arn]
}

output "operations" {
  value = var.operations == null ? null : {
    audit_trail_arn  = local.audit_trail_arn
    audit_bucket     = one(aws_s3_bucket.audit).id
    audit_key_arn    = one(aws_kms_key.audit).arn
    alert_source_arn = "arn:aws:cloudwatch:${var.aws_region}:${var.account_id}:alarm:${local.alert_prefix}-*"
    alarm_names      = { for purpose, alarm in aws_cloudwatch_metric_alarm.operations : purpose => alarm.alarm_name }
  }
}
