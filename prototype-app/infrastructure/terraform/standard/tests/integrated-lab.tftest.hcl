# Synthetic references only. This plan cannot establish live certificate, secret,
# DNS, image publication or operator enrollment readiness.
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
  nat_gateway_mode        = "single"
  vpc_cidr                = "10.21.0.0/16"
  postgres_engine_version = "16.15"
  frontend_origin         = "https://lab.scoutgrid.io"
  api_origin              = "https://api-lab.scoutgrid.io"
  cognito_domain_prefix   = "scoutgrid-lab-736486260824"
  github_publisher        = null
}

run "prepare_integrated_lab_before_bootstrap" {
  command = plan

  variables {
    backend_candidate = {
      image_digest        = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      certificate_arn     = "arn:aws:acm:ap-southeast-2:736486260824:certificate/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      runtime_db_secret   = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:runtime-db-a1b2c3"
      application_secret  = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:app-settings-a1b2c3"
      secrets_kms_key_arn = "arn:aws:kms:ap-southeast-2:736486260824:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      managed_installation = {
        secret_arn = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:operator-enrollment-a1b2c3" # gitleaks:allow synthetic test fixture
        version_id = "11111111-2222-3333-4444-555555555555"
      }
    }
  }

  assert {
    condition = (
      length(aws_ecs_task_definition.backend) == 3 && length(aws_ecs_service.backend) == 0 &&
      length(aws_lb.api) == 1 && length(aws_wafv2_web_acl.api) == 1 &&
      length(output.network.egress_ips_by_zone) == 1 &&
      output.network.task_egress_nat_zones == { "apse2-az1" = "apse2-az1", "apse2-az3" = "apse2-az1" } &&
      output.backend_runtime.runtime_db_connection_budget == { steady = 12, rollout = 24, login_limit = 25 } &&
      length(aws_iam_role.github_publisher) == 0 &&
      !strcontains(aws_iam_role_policy.execution["api"].policy, var.backend_candidate.managed_installation.secret_arn) &&
      !strcontains(aws_iam_role_policy.execution["worker"].policy, var.backend_candidate.managed_installation.secret_arn)
    )
    error_message = "Prepare three task definitions behind HTTPS/WAF with one NAT, services stopped, and enrollment accessible only to the migrator."
  }

  assert {
    condition = (
      jsondecode(output.lab_operator_policy_documents.migration_operator).Statement[0].Resource == aws_ecs_task_definition.backend["migrator"].arn &&
      jsondecode(output.lab_operator_policy_documents.migration_operator).Statement[2].Resource == aws_iam_role.execution["migrator"].arn &&
      jsondecode(output.lab_operator_policy_documents.image_publisher).Statement[1].Resource == aws_ecr_repository.backend.arn &&
      output.lab_migration_task_request.networkConfiguration.awsvpcConfiguration.assignPublicIp == "DISABLED" &&
      output.lab_migration_task_request.count == 1 && !output.lab_migration_task_request.enableExecuteCommand &&
      !strcontains(output.lab_operator_policy_documents.migration_operator, "GetSecretValue") &&
      !strcontains(output.lab_operator_policy_documents.migration_operator, "RegisterTaskDefinition")
    )
    error_message = "Unattached release policies must bind the exact migration revision/role and repository without direct secret reads or task registration."
  }
}

run "start_integrated_lab_after_enrollment_removed" {
  command = plan

  variables {
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
      toset(keys(aws_ecs_service.backend)) == toset(["api", "worker"]) &&
      alltrue([for service in aws_ecs_service.backend :
        service.desired_count == 1 && !one(service.network_configuration).assign_public_ip
      ]) &&
      length(output.network.egress_ips_by_zone) == 1 &&
      alltrue([for policy in aws_iam_role_policy.execution : !strcontains(policy.policy, "operator-enrollment")]) &&
      alltrue([for task in aws_ecs_task_definition.backend :
        one(jsondecode(task.container_definitions)).logConfiguration.options["awslogs-region"] == "ap-southeast-2"
      ])
    )
    error_message = "Start exactly one private API and worker only after removing enrollment references, keeping Sydney logs and one lab NAT."
  }
}
