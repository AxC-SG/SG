# Synthetic references only. Proves the parked (lab-down) and running (lab-up) modes of the
# whole root module, including outputs and operations alarms, without live AWS access.
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
  operations = {
    audit_recovery_role_arn = "arn:aws:iam::736486260824:role/audit-recovery"
    alert_topic_arn         = "arn:aws:sns:ap-southeast-2:736486260824:operations"
  }
  monthly_budget = {
    amount_usd     = 100
    operator_email = "billing@example.com"
  }
}

run "lab_up_runs_api_behind_ingress_with_single_nat" {
  command = plan

  variables {
    nat_gateway_mode        = "single"
    runtime_ingress_enabled = true
    backend_candidate = {
      image_digest        = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
      length(output.network.egress_ips_by_zone) == 1 &&
      output.network.task_egress_nat_zones == { "apse2-az1" = "apse2-az1", "apse2-az3" = "apse2-az1" } &&
      length(aws_lb.api) == 1 && length(aws_lb_target_group.api) == 1 && length(aws_lb_listener.https) == 1 &&
      length(aws_lb_listener_rule.api) == 1 && length(aws_wafv2_web_acl.api) == 1 &&
      length(aws_wafv2_web_acl_association.api) == 1 &&
      toset(keys(aws_ecs_service.backend)) == toset(["api", "worker"]) &&
      contains(keys(aws_cloudwatch_metric_alarm.operations), "api-unavailable") &&
      length(aws_cloudwatch_metric_alarm.operations) == 7
    )
    error_message = "Lab-up must restore one NAT with both task egress routes, the ALB tree, WAF, both services and the service alarms."
  }

  assert {
    condition     = output.backend_runtime.cluster_arn != null && aws_budgets_budget.standard[0].limit_amount == "100"
    error_message = "Lab-up keeps the runtime outputs and the $100 lab budget alert."
  }
}

run "lab_down_parks_billable_runtime_and_keeps_state" {
  command = plan

  variables {
    nat_gateway_mode        = "none"
    runtime_ingress_enabled = false
    backend_candidate = {
      image_digest        = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
      length(output.network.egress_ips_by_zone) == 0 && length(output.network.task_egress_nat_zones) == 0 &&
      length(aws_lb.api) == 0 && length(aws_lb_target_group.api) == 0 && length(aws_lb_listener.https) == 0 &&
      length(aws_lb_listener_rule.api) == 0 && length(aws_wafv2_web_acl.api) == 0 &&
      length(aws_wafv2_web_acl_association.api) == 0 &&
      length(aws_ecs_service.backend) == 0
    )
    error_message = "Lab-down must remove NAT egress, the ALB tree, WAF, both services and their alarms."
  }

  assert {
    condition = (
      length(aws_ecs_task_definition.backend) == 3 && length(aws_ecs_cluster.standard) == 1 &&
      length(aws_security_group.alb) == 1 &&
      toset(keys(aws_cloudwatch_metric_alarm.operations)) == toset(["database-storage", "database-cpu"]) &&
      length(aws_ecr_repository.backend.repository_url) > 0 &&
      output.backend_runtime.api_load_balancer_dns_name == null &&
      output.backend_runtime.api_load_balancer_zone_id == null &&
      aws_budgets_budget.standard[0].limit_amount == "100"
    )
    error_message = "Lab-down keeps task definitions, the cluster, security groups, database alarms, ECR and the budget, with null ingress outputs."
  }
}

run "reject_parked_ingress_with_services_running" {
  command = plan

  variables {
    nat_gateway_mode        = "single"
    runtime_ingress_enabled = false
    backend_candidate = {
      image_digest        = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      certificate_arn     = "arn:aws:acm:ap-southeast-2:736486260824:certificate/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      runtime_db_secret   = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:runtime-db-a1b2c3"
      application_secret  = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:app-settings-a1b2c3"
      secrets_kms_key_arn = "arn:aws:kms:ap-southeast-2:736486260824:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      start_services      = true
    }
  }

  expect_failures = [var.runtime_ingress_enabled]
}

run "reject_parked_nat_with_services_running" {
  command = plan

  variables {
    nat_gateway_mode        = "none"
    runtime_ingress_enabled = true
    backend_candidate = {
      image_digest        = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      certificate_arn     = "arn:aws:acm:ap-southeast-2:736486260824:certificate/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      runtime_db_secret   = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:runtime-db-a1b2c3"
      application_secret  = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:app-settings-a1b2c3"
      secrets_kms_key_arn = "arn:aws:kms:ap-southeast-2:736486260824:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      start_services      = true
    }
  }

  expect_failures = [var.nat_gateway_mode]
}
