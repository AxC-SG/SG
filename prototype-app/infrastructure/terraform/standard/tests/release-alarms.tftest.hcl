# Synthetic references only. Proves the lab release alarms stand apart from `operations` and
# are identical whether the lab is running or parked, so lab.sh cycles never plan them.
mock_provider "aws" {
  override_during = plan

  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:ap-southeast-2:736486260824:key/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" }
  }
  mock_resource "aws_lb" {
    defaults = { arn = "arn:aws:elasticloadbalancing:ap-southeast-2:736486260824:loadbalancer/app/test/aaaaaaaaaaaaaaaa" }
  }
  mock_resource "aws_lb_target_group" {
    defaults = { arn = "arn:aws:elasticloadbalancing:ap-southeast-2:736486260824:targetgroup/test/bbbbbbbbbbbbbbbb" }
  }
  mock_resource "aws_lb_listener" {
    defaults = { arn = "arn:aws:elasticloadbalancing:ap-southeast-2:736486260824:listener/app/test/aaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbb" }
  }
  mock_resource "aws_wafv2_web_acl" {
    defaults = { arn = "arn:aws:wafv2:ap-southeast-2:736486260824:regional/webacl/test/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::736486260824:role/test" }
  }
  mock_resource "aws_ecs_cluster" {
    defaults = { arn = "arn:aws:ecs:ap-southeast-2:736486260824:cluster/scoutgrid-lab" }
  }
  mock_resource "aws_ecs_task_definition" {
    defaults = { arn = "arn:aws:ecs:ap-southeast-2:736486260824:task-definition/test:1" }
  }
  mock_resource "aws_cognito_user_pool" {
    defaults = { endpoint = "cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_testpool" }
  }
  mock_resource "aws_cognito_user_pool_client" {
    defaults = { id = "scoutgridbrowserclient" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:ap-southeast-2:736486260824:log-group:/ecs/scoutgrid-lab/test" }
  }
  mock_resource "aws_db_instance" {
    defaults = {
      address  = "scoutgrid.example.ap-southeast-2.rds.amazonaws.com"
      endpoint = "scoutgrid.example.ap-southeast-2.rds.amazonaws.com:5432"
      master_user_secret = [{
        secret_arn = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:rds-owner-a1b2c3" # gitleaks:allow synthetic test fixture
      }]
    }
  }
  mock_resource "aws_ecr_repository" {
    defaults = {
      arn            = "arn:aws:ecr:ap-southeast-2:736486260824:repository/scoutgrid-lab-backend"
      repository_url = "736486260824.dkr.ecr.ap-southeast-2.amazonaws.com/scoutgrid-lab-backend"
    }
  }
  mock_resource "aws_sns_topic" {
    defaults = { arn = "arn:aws:sns:ap-southeast-2:736486260824:scoutgrid-lab-release" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::scoutgrid-lab-736486260824-imports" }
  }
}

variables {
  account_id              = "736486260824"
  environment             = "lab"
  aws_region              = "ap-southeast-2"
  availability_zone_ids   = ["apse2-az1", "apse2-az3"]
  vpc_cidr                = "10.21.0.0/16"
  postgres_engine_version = "16.15"
  frontend_origin         = "https://scoutgrid.io"
  api_origin              = "https://api-lab.scoutgrid.io"
  cognito_domain_prefix   = "scoutgrid-lab-736486260824"
  github_publisher        = null
  release_alarms_enabled  = true
  backend_images = {
    runtime  = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    migrator = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
  monthly_budget = {
    amount_usd     = 100
    operator_email = "billing@example.com"
  }
}

run "release_alarms_while_lab_runs" {
  command = plan

  variables {
    nat_gateway_mode        = "single"
    runtime_ingress_enabled = true
    backend_candidate = {
      certificate_arn     = "arn:aws:acm:ap-southeast-2:736486260824:certificate/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      runtime_db_secret   = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:runtime-db-a1b2c3"
      application_secret  = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:app-settings-a1b2c3"
      secrets_kms_key_arn = "arn:aws:kms:ap-southeast-2:736486260824:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      start_services      = true
      enable_managed_auth = true
      enable_bom_uploads  = true
    }
  }

  assert {
    condition = (
      toset(output.release_alarms.alarm_names) == toset(["scoutgrid-lab-release-api-fatal-errors", "scoutgrid-lab-release-worker-fatal-errors", "scoutgrid-lab-release-worker-tenant-work-failing", "scoutgrid-lab-release-api-unavailable", "scoutgrid-lab-release-worker-progress-stale"]) &&
      length(aws_cloudwatch_metric_alarm.operations) == 0 && length(aws_kms_key.audit) == 0
    )
    error_message = "Release alarms must exist without the operations audit stack."
  }

  assert {
    condition = alltrue([
      for alarm in concat(values(aws_cloudwatch_metric_alarm.release), values(aws_cloudwatch_metric_alarm.release_api_unavailable), values(aws_cloudwatch_metric_alarm.release_worker_progress_stale)) :
      alarm.treat_missing_data == "notBreaching" &&
      alarm.alarm_actions == toset(["arn:aws:sns:ap-southeast-2:736486260824:scoutgrid-lab-release"]) &&
      alarm.ok_actions == toset(["arn:aws:sns:ap-southeast-2:736486260824:scoutgrid-lab-release"])
    ])
    error_message = "Every release alarm notifies the release topic and stays OK while its series is missing (parked)."
  }

  assert {
    condition = (
      aws_cloudwatch_metric_alarm.release_api_unavailable["standard"].dimensions["ClusterName"] == "scoutgrid-lab" &&
      aws_cloudwatch_metric_alarm.release_api_unavailable["standard"].dimensions["ServiceName"] == "api" &&
      aws_cloudwatch_log_metric_filter.release["worker-progress"].log_group_name == "/ecs/scoutgrid-lab/worker" &&
      aws_cloudwatch_log_metric_filter.release["api-fatal-errors"].log_group_name == "/ecs/scoutgrid-lab/api" &&
      strcontains(aws_cloudwatch_log_metric_filter.release["worker-fatal-errors"].pattern, "outside this release's supported range") &&
      strcontains(aws_cloudwatch_log_metric_filter.release["api-fatal-errors"].pattern, "violates row-level security policy")
    )
    error_message = "Release alarms read fixed cluster, service and log group names, never service or load balancer attributes."
  }
}

run "release_alarms_unchanged_while_parked" {
  command = plan

  variables {
    nat_gateway_mode        = "none"
    runtime_ingress_enabled = false
    backend_candidate = {
      certificate_arn     = "arn:aws:acm:ap-southeast-2:736486260824:certificate/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      runtime_db_secret   = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:runtime-db-a1b2c3"
      application_secret  = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:app-settings-a1b2c3"
      secrets_kms_key_arn = "arn:aws:kms:ap-southeast-2:736486260824:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      start_services      = false
      enable_managed_auth = true
      enable_bom_uploads  = true
    }
  }

  assert {
    condition = (
      toset(output.release_alarms.alarm_names) == toset(["scoutgrid-lab-release-api-fatal-errors", "scoutgrid-lab-release-worker-fatal-errors", "scoutgrid-lab-release-worker-tenant-work-failing", "scoutgrid-lab-release-api-unavailable", "scoutgrid-lab-release-worker-progress-stale"]) &&
      length(aws_cloudwatch_metric_alarm.operations) == 0 && length(aws_kms_key.audit) == 0
    )
    error_message = "Release alarms must exist without the operations audit stack."
  }

  assert {
    condition = alltrue([
      for alarm in concat(values(aws_cloudwatch_metric_alarm.release), values(aws_cloudwatch_metric_alarm.release_api_unavailable), values(aws_cloudwatch_metric_alarm.release_worker_progress_stale)) :
      alarm.treat_missing_data == "notBreaching" &&
      alarm.alarm_actions == toset(["arn:aws:sns:ap-southeast-2:736486260824:scoutgrid-lab-release"]) &&
      alarm.ok_actions == toset(["arn:aws:sns:ap-southeast-2:736486260824:scoutgrid-lab-release"])
    ])
    error_message = "Every release alarm notifies the release topic and stays OK while its series is missing (parked)."
  }

  assert {
    condition = (
      aws_cloudwatch_metric_alarm.release_api_unavailable["standard"].dimensions["ClusterName"] == "scoutgrid-lab" &&
      aws_cloudwatch_metric_alarm.release_api_unavailable["standard"].dimensions["ServiceName"] == "api" &&
      aws_cloudwatch_log_metric_filter.release["worker-progress"].log_group_name == "/ecs/scoutgrid-lab/worker" &&
      aws_cloudwatch_log_metric_filter.release["api-fatal-errors"].log_group_name == "/ecs/scoutgrid-lab/api" &&
      strcontains(aws_cloudwatch_log_metric_filter.release["worker-fatal-errors"].pattern, "outside this release's supported range") &&
      strcontains(aws_cloudwatch_log_metric_filter.release["api-fatal-errors"].pattern, "violates row-level security policy")
    )
    error_message = "Release alarms read fixed cluster, service and log group names, never service or load balancer attributes."
  }
}

run "lab_smoke_fixtures_only_on_the_api" {
  command = plan

  variables {
    nat_gateway_mode        = "single"
    runtime_ingress_enabled = true
    backend_candidate = {
      certificate_arn       = "arn:aws:acm:ap-southeast-2:736486260824:certificate/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      runtime_db_secret     = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:runtime-db-a1b2c3"
      application_secret    = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:app-settings-a1b2c3"
      secrets_kms_key_arn   = "arn:aws:kms:ap-southeast-2:736486260824:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      start_services        = true
      enable_smoke_fixtures = true
    }
  }

  assert {
    condition = alltrue([
      for role in ["api", "worker"] :
      one([for entry in one(jsondecode(aws_ecs_task_definition.backend[role].container_definitions)).environment :
      entry.value if entry.name == "APP_DEMO_SMOKE_FIXTURES_ENABLED"]) == (role == "api" ? "true" : "false")
    ])
    error_message = "Smoke fixtures are enabled on the lab api only."
  }
}

run "release_alarms_are_opt_in" {
  command = plan

  variables {
    release_alarms_enabled  = false
    nat_gateway_mode        = "single"
    runtime_ingress_enabled = true
    backend_candidate = {
      certificate_arn     = "arn:aws:acm:ap-southeast-2:736486260824:certificate/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      runtime_db_secret   = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:runtime-db-a1b2c3"
      application_secret  = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:app-settings-a1b2c3"
      secrets_kms_key_arn = "arn:aws:kms:ap-southeast-2:736486260824:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      start_services      = true
      enable_managed_auth = true
      enable_bom_uploads  = true
    }
  }

  assert {
    condition = (
      output.release_alarms == null && length(aws_sns_topic.release_alarms) == 0 &&
      length(aws_cloudwatch_log_metric_filter.release) == 0 && length(aws_cloudwatch_metric_alarm.release) == 0
    )
    error_message = "Release alarms stay off until enabled."
  }
}
