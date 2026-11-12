locals {
  audit_bucket_name    = "${local.name}-${var.account_id}-audit"
  config_enabled       = try(var.operations.config_recorder_role_arn, null) != null
  config_name          = "${local.name}-config"
  config_source_arn    = "arn:aws:config:${var.aws_region}:${var.account_id}:*"
  config_prefix        = "config"
  config_object_prefix = "${local.config_prefix}/AWSLogs/${var.account_id}/Config"

  config_rules = local.config_enabled ? {
    rds-private = {
      identifier    = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
      resource_type = "AWS::RDS::DBInstance"
    }
    rds-encrypted = {
      identifier    = "RDS_STORAGE_ENCRYPTED"
      resource_type = "AWS::RDS::DBInstance"
    }
    s3-private-read = {
      identifier    = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
      resource_type = "AWS::S3::Bucket"
    }
    s3-private-write = {
      identifier    = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
      resource_type = "AWS::S3::Bucket"
    }
  } : {}

  security_event_patterns = merge(
    try(var.operations.guardduty_detector_id, null) == null ? {} : {
      guardduty = jsonencode({
        source        = ["aws.guardduty"]
        "detail-type" = ["GuardDuty Finding"]
        detail = {
          service  = { detectorId = [var.operations.guardduty_detector_id] }
          severity = [{ numeric = [">=", 4] }]
        }
      })
    },
    local.config_enabled ? {
      config = jsonencode({
        source        = ["aws.config"]
        "detail-type" = ["Config Rules Compliance Change"]
        detail = {
          configRuleName      = sort([for key in keys(local.config_rules) : "${local.name}-${key}"])
          newEvaluationResult = { complianceType = ["NON_COMPLIANT"] }
        }
      })
    } : {},
  )
}

resource "aws_config_configuration_recorder" "standard" {
  count    = local.config_enabled ? 1 : 0
  name     = local.config_name
  role_arn = var.operations.config_recorder_role_arn

  recording_group {
    all_supported                 = false
    include_global_resource_types = false
    resource_types                = sort(distinct([for rule in values(local.config_rules) : rule.resource_type]))

    recording_strategy {
      use_only = "INCLUSION_BY_RESOURCE_TYPES"
    }
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
}

resource "aws_config_delivery_channel" "standard" {
  count          = length(aws_config_configuration_recorder.standard)
  name           = local.config_name
  s3_bucket_name = aws_s3_bucket.audit[0].id
  s3_key_prefix  = local.config_prefix
  s3_kms_key_arn = aws_kms_key.audit[0].arn

  depends_on = [
    aws_config_configuration_recorder.standard,
    aws_s3_bucket_policy.audit,
    aws_s3_bucket_server_side_encryption_configuration.audit,
    aws_s3_bucket_ownership_controls.audit,
  ]
}

resource "aws_config_configuration_recorder_status" "standard" {
  count      = length(aws_config_configuration_recorder.standard)
  name       = aws_config_configuration_recorder.standard[count.index].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.standard]
}

resource "aws_config_config_rule" "standard" {
  for_each = local.config_rules
  name     = "${local.name}-${each.key}"

  scope {
    compliance_resource_types = [each.value.resource_type]
  }

  source {
    owner             = "AWS"
    source_identifier = each.value.identifier
  }

  depends_on = [aws_config_configuration_recorder_status.standard]
}

resource "aws_cloudwatch_event_rule" "security" {
  for_each = local.security_event_patterns
  name     = "${local.alert_prefix}-${each.key}"
  event_pattern = jsonencode(merge(jsondecode(each.value), {
    account = [var.account_id]
    region  = [var.aws_region]
  }))
}

resource "aws_iam_role" "security_events" {
  count = length(local.security_event_patterns) == 0 ? 0 : 1
  name  = "${local.alert_prefix}-security-events"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.account_id }
        ArnEquals = {
          "aws:SourceArn" = [for rule in aws_cloudwatch_event_rule.security :
            "arn:aws:events:${var.aws_region}:${var.account_id}:rule/${rule.name}"
          ]
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "security_events" {
  count = length(aws_iam_role.security_events)
  name  = "publish-security-alerts"
  role  = aws_iam_role.security_events[count.index].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sns:Publish"
      Resource = var.operations.security_topic_arn
    }]
  })
}

resource "aws_cloudwatch_event_target" "security" {
  for_each = aws_cloudwatch_event_rule.security
  rule     = each.value.name
  arn      = var.operations.security_topic_arn
  role_arn = aws_iam_role.security_events[0].arn

  input_transformer {
    input_paths = {
      event_id = "$.id"
      account  = "$.account"
      region   = "$.region"
      subject  = each.key == "config" ? "$.detail.configRuleName" : "$.detail.id"
    }
    input_template = "\"ScoutGrid ${each.key} alert in account <account> (<region>). Review ${each.key == "config" ? "AWS Config rule" : "GuardDuty finding"} <subject>. EventBridge event <event_id>.\""
  }

  depends_on = [aws_iam_role_policy.security_events]
}

output "security_operations" {
  value = length(local.security_event_patterns) == 0 ? null : {
    config_recorder_name   = one(aws_config_configuration_recorder.standard[*].name)
    config_delivery_prefix = local.config_enabled ? local.config_object_prefix : null
    config_rules           = { for purpose, rule in aws_config_config_rule.standard : purpose => rule.name }
    guardduty_detector_id  = var.operations.guardduty_detector_id
    event_rule_arns        = { for purpose, rule in aws_cloudwatch_event_rule.security : purpose => rule.arn }
    security_topic_arn     = var.operations.security_topic_arn
  }
}
