variable "release_alarms_enabled" {
  description = "Lab release alarms that do not depend on `operations`: an SNS topic plus log-derived API error, worker progress and fatal-pattern alarms. Subscribe the owner's address out of band (see infrastructure/lab/README.md)."
  type        = bool
  default     = false
}

# Every alarm reads log metrics or Container Insights by fixed names, never service or load
# balancer attributes, so parking and starting the lab (lab.sh) plans no change here. While
# parked, the series are missing and every alarm treats that as not breaching.
locals {
  release_alarms       = var.release_alarms_enabled && local.backend_enabled ? toset(["standard"]) : toset([])
  release_alarm_prefix = "${local.name}-release"
  release_namespace    = "ScoutGrid/${local.name}/release"
  # The defined failures: keep in step with FATAL_PATTERNS in infrastructure/lab/scripts/release.py.
  release_fatal_pattern = join(" ", [
    "?\"outside this release's supported range\"",
    "?\"violates row-level security policy\"",
    "?\"Tenant-scoped background work failed\"",
    "?\"Unhandled API error\"",
  ])
  release_log_metrics = {
    worker-progress     = { role = "worker", pattern = "?\"tenant_work_progress outcome=healthy\" ?\"tenant_work_progress outcome=degraded\"" }
    worker-failing      = { role = "worker", pattern = "\"tenant_work_progress outcome=failing\"" }
    worker-fatal-errors = { role = "worker", pattern = local.release_fatal_pattern }
    api-fatal-errors    = { role = "api", pattern = local.release_fatal_pattern }
  }
  release_metric_alarms = {
    "api-fatal-errors" = {
      description = "The API logged a defined failure: unhandled API error (HTTP 500), row-level security rejection or unsupported schema range."
      metric      = "api-fatal-errors"
      periods     = 1
    }
    "worker-fatal-errors" = {
      description = "The worker logged a defined failure: tenant background work failed, row-level security rejection or unsupported schema range."
      metric      = "worker-fatal-errors"
      periods     = 1
    }
    "worker-tenant-work-failing" = {
      description = "No tenant-scoped background work succeeded for ten minutes while some ran and failed."
      metric      = "worker-failing"
      periods     = 2
    }
  }
}

resource "aws_sns_topic" "release_alarms" {
  for_each = local.release_alarms
  name     = local.release_alarm_prefix
  # Alarm messages carry alarm names and states only. CloudWatch cannot publish to a topic
  # encrypted with the AWS-managed SNS key, and a customer key is not justified for the lab.
}

resource "aws_sns_topic_policy" "release_alarms" {
  for_each = local.release_alarms
  arn      = aws_sns_topic.release_alarms[each.key].arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "ReleaseAlarmsPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.release_alarms[each.key].arn
      Condition = {
        ArnLike      = { "aws:SourceArn" = "arn:aws:cloudwatch:${var.aws_region}:${var.account_id}:alarm:${local.release_alarm_prefix}-*" }
        StringEquals = { "aws:SourceAccount" = var.account_id }
      }
    }]
  })
}

resource "aws_cloudwatch_log_metric_filter" "release" {
  for_each       = length(local.release_alarms) == 0 ? {} : local.release_log_metrics
  name           = "${local.release_alarm_prefix}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.backend[each.value.role].name
  pattern        = each.value.pattern

  metric_transformation {
    name      = each.key
    namespace = local.release_namespace
    value     = "1"
    unit      = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "release" {
  for_each            = length(local.release_alarms) == 0 ? {} : local.release_metric_alarms
  alarm_name          = "${local.release_alarm_prefix}-${each.key}"
  alarm_description   = each.value.description
  namespace           = local.release_namespace
  metric_name         = aws_cloudwatch_log_metric_filter.release[each.value.metric].metric_transformation[0].name
  statistic           = "Sum"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  period              = 300
  evaluation_periods  = each.value.periods
  datapoints_to_alarm = each.value.periods
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.release_alarms["standard"].arn]
  ok_actions          = [aws_sns_topic.release_alarms["standard"].arn]
}

resource "aws_cloudwatch_metric_alarm" "release_api_unavailable" {
  for_each            = local.release_alarms
  alarm_name          = "${local.release_alarm_prefix}-api-unavailable"
  alarm_description   = "The API service reported no running task for three minutes while its task count was being sampled."
  namespace           = "ECS/ContainerInsights"
  metric_name         = "RunningTaskCount"
  dimensions          = { ClusterName = local.name, ServiceName = "api" }
  statistic           = "Minimum"
  comparison_operator = "LessThanThreshold"
  threshold           = 1
  period              = 60
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.release_alarms[each.key].arn]
  ok_actions          = [aws_sns_topic.release_alarms[each.key].arn]
}

# A worker task is running but reports no tenant work succeeding for fifteen minutes (stale or
# absent progress). With no worker task (parked), the expression has no data and stays OK.
resource "aws_cloudwatch_metric_alarm" "release_worker_progress_stale" {
  for_each            = local.release_alarms
  alarm_name          = "${local.release_alarm_prefix}-worker-progress-stale"
  alarm_description   = "A worker task is running but no tenant-scoped background work succeeded for fifteen minutes."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.release_alarms[each.key].arn]
  ok_actions          = [aws_sns_topic.release_alarms[each.key].arn]

  metric_query {
    id          = "stale"
    expression  = "IF(FILL(running, 0) >= 1 AND FILL(progress, 0) < 1, 1, 0)"
    label       = "Worker running without progress"
    return_data = true
  }

  metric_query {
    id = "running"
    metric {
      namespace   = "ECS/ContainerInsights"
      metric_name = "RunningTaskCount"
      dimensions  = { ClusterName = local.name, ServiceName = "worker" }
      stat        = "Maximum"
      period      = 300
    }
  }

  metric_query {
    id = "progress"
    metric {
      namespace   = local.release_namespace
      metric_name = aws_cloudwatch_log_metric_filter.release["worker-progress"].metric_transformation[0].name
      stat        = "Sum"
      period      = 300
    }
  }
}

output "release_alarms" {
  value = length(local.release_alarms) == 0 ? null : {
    topic_arn = aws_sns_topic.release_alarms["standard"].arn
    alarm_names = concat(
      [for alarm in aws_cloudwatch_metric_alarm.release : alarm.alarm_name],
      [aws_cloudwatch_metric_alarm.release_api_unavailable["standard"].alarm_name],
      [aws_cloudwatch_metric_alarm.release_worker_progress_stale["standard"].alarm_name],
    )
  }
}
