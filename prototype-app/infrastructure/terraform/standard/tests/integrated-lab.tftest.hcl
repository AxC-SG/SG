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
  frontend_origin         = "https://scoutgrid.io"
  api_origin              = "https://api-lab.scoutgrid.io"
  cognito_domain_prefix   = "scoutgrid-lab-736486260824"
  backend_images = {
    runtime  = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    migrator = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
  github_publisher = {
    provider_arn = "arn:aws:iam::736486260824:oidc-provider/token.actions.githubusercontent.com"
    subject      = "repo:AxC-SG@351325919/SG@1427276590:environment:aws-standard-lab:job_workflow_ref:AxC-SG/SG/.github/workflows/aws-publish-candidate.yml@refs/heads/main"
  }
}

# Distinct identities are necessary to test that service operators cannot select
# the privileged migrator or pass its execution role.
override_resource {
  override_during = plan
  target          = module.network.aws_subnet.tier["task-apse2-az1"]
  values          = { id = "subnet-00000000000000001" }
}
override_resource {
  override_during = plan
  target          = module.network.aws_subnet.tier["task-apse2-az3"]
  values          = { id = "subnet-00000000000000002" }
}
override_resource {
  override_during = plan
  target          = aws_security_group.backend["migrator"]
  values          = { id = "sg-00000000000000001" }
}
override_resource {
  override_during = plan
  target          = aws_iam_role.execution["migrator"]
  values          = { arn = "arn:aws:iam::736486260824:role/scoutgrid-lab-migrator-execution" }
}
override_resource {
  override_during = plan
  target          = aws_iam_role.execution["api"]
  values          = { arn = "arn:aws:iam::736486260824:role/scoutgrid-lab-api-execution" }
}
override_resource {
  override_during = plan
  target          = aws_iam_role.execution["worker"]
  values          = { arn = "arn:aws:iam::736486260824:role/scoutgrid-lab-worker-execution" }
}
override_resource {
  override_during = plan
  target          = aws_iam_role.application["api"]
  values          = { arn = "arn:aws:iam::736486260824:role/scoutgrid-lab-api-task" }
}
override_resource {
  override_during = plan
  target          = aws_iam_role.application["worker"]
  values          = { arn = "arn:aws:iam::736486260824:role/scoutgrid-lab-worker-task" }
}
override_resource {
  override_during = plan
  target          = aws_ecs_task_definition.backend["migrator"]
  values          = { arn = "arn:aws:ecs:ap-southeast-2:736486260824:task-definition/scoutgrid-lab-migrator:1" }
}
override_resource {
  override_during = plan
  target          = aws_ecs_task_definition.backend["api"]
  values          = { arn = "arn:aws:ecs:ap-southeast-2:736486260824:task-definition/scoutgrid-lab-api:1" }
}
override_resource {
  override_during = plan
  target          = aws_ecs_task_definition.backend["worker"]
  values          = { arn = "arn:aws:ecs:ap-southeast-2:736486260824:task-definition/scoutgrid-lab-worker:1" }
}

run "prepare_integrated_lab_before_bootstrap" {
  command = plan

  variables {
    backend_candidate = {
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
      length(aws_iam_role.github_publisher) == 1 &&
      aws_iam_role.github_publisher[0].name == "scoutgrid-lab-github-ecr-publish" &&
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
      !strcontains(output.lab_operator_policy_documents.migration_operator, "RegisterTaskDefinition") &&
      !strcontains(output.lab_operator_policy_documents.service_operator, aws_ecs_task_definition.backend["migrator"].arn) &&
      !strcontains(output.lab_operator_policy_documents.service_operator, aws_iam_role.execution["migrator"].arn) &&
      !strcontains(output.lab_operator_policy_documents.service_operator, "RegisterTaskDefinition")
    )
    error_message = "Unattached release policies must bind the exact migration revision/role and repository without direct secret reads or task registration."
  }
}

run "start_integrated_lab_after_enrollment_removed" {
  command = plan

  variables {
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

# Phase 4 slice 2: the runtime-only GitHub releaser is a strict subset of the Release role.
run "github_releaser_is_runtime_only" {
  command = plan

  variables {
    github_releaser = {
      provider_arn = "arn:aws:iam::736486260824:oidc-provider/token.actions.githubusercontent.com"
      subject      = "repo:AxC-SG@351325919/SG@1427276590:environment:aws-standard-lab-release:job_workflow_ref:AxC-SG/SG/.github/workflows/lab-reconcile.yml@refs/heads/main"
    }
  }

  assert {
    condition = (
      aws_iam_role.github_releaser[0].name == "scoutgrid-lab-github-release" &&
      aws_iam_role.github_releaser[0].max_session_duration == 3600 &&
      one(jsondecode(aws_iam_role.github_releaser[0].assume_role_policy).Statement).Condition.StringEquals == {
        "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        "token.actions.githubusercontent.com:sub" = var.github_releaser.subject
      }
    )
    error_message = "Only the reconcile workflow on main, in the lab release environment, may assume the releaser."
  }

  assert {
    condition = toset(flatten([
      for statement in jsondecode(aws_iam_role_policy.github_releaser[0].policy).Statement : statement.Action if statement.Effect == "Allow"
      ])) == toset([
      "ecs:RegisterTaskDefinition", "ecs:TagResource", "ecs:DeregisterTaskDefinition", "iam:PassRole", "ecs:UpdateService",
      "elasticloadbalancing:DescribeTargetGroups", "elasticloadbalancing:DescribeTargetHealth",
      "logs:FilterLogEvents", "logs:GetLogEvents", "s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:GetBucketWebsite",
    ])
    error_message = "The releaser may only roll api and worker and keep the release records; no RunTask, snapshot, secret or IAM write."
  }

  assert {
    condition = alltrue(flatten([
      for statement in jsondecode(aws_iam_role_policy.github_releaser[0].policy).Statement : [
        for resource in flatten([statement.Resource]) : !strcontains(resource, "migrator")
      ] if statement.Effect == "Allow"
    ]))
    error_message = "No allowed action may name the migrator family or its execution role."
  }

  assert {
    condition = toset([
      for statement in jsondecode(aws_iam_role_policy.github_releaser[0].policy).Statement : statement.Sid if statement.Effect == "Deny"
      ]) == toset([
      "DenyTaskLaunchAndStop", "DenyMigratorTaskDefinitions", "DenyMigratorRole", "DenyDatabaseSnapshotsAndChanges",
      "DenySecretValues", "DenyIamWrites", "DenyDeletesOutsideTheLocks", "DenyHistoryAndBucketDeletion",
    ])
    error_message = "The releaser must explicitly deny migrator, task, database, secret, IAM and state-deletion actions."
  }

  assert {
    condition = (
      one([for statement in jsondecode(aws_iam_role_policy.github_releaser[0].policy).Statement : statement.Resource if statement.Sid == "DenyMigratorTaskDefinitions"]) ==
      "arn:aws:ecs:ap-southeast-2:736486260824:task-definition/scoutgrid-lab-migrator:*" &&
      one([for statement in jsondecode(aws_iam_role_policy.github_releaser[0].policy).Statement : statement.Resource if statement.Sid == "DenyMigratorRole"]) ==
      "arn:aws:iam::736486260824:role/scoutgrid-lab-migrator-execution" &&
      toset(one([for statement in jsondecode(aws_iam_role_policy.github_releaser[0].policy).Statement : statement.NotResource if statement.Sid == "DenyDeletesOutsideTheLocks"])) == toset([
        "arn:aws:s3:::scoutgrid-lab-tfstate-736486260824-ap-southeast-2/standard/lab/release/lock.json",
        "arn:aws:s3:::scoutgrid-lab-tfstate-736486260824-ap-southeast-2/standard/lab/terraform.tfstate.tflock",
      ])
    )
    error_message = "The denies must name the lab migrator family and role, and allow deletes only of the two locks."
  }

  assert {
    condition = toset([for attachment in aws_iam_role_policy_attachment.github_releaser : attachment.policy_arn]) == toset([
      "arn:aws:iam::736486260824:policy/ScoutGridSydneyLab-common-read-state-part1",
      "arn:aws:iam::736486260824:policy/ScoutGridSydneyLab-common-read-state-part2",
      "arn:aws:iam::736486260824:policy/ScoutGridSydneyLab-waf-association-read",
      "arn:aws:iam::736486260824:policy/ScoutGridSydneyLab-cycle-watch",
    ])
    error_message = "The releaser reuses exactly the Release role's four Terraform read policies."
  }
}

run "github_releaser_is_off_until_set" {
  command = plan

  assert {
    condition     = length(aws_iam_role.github_releaser) == 0 && length(aws_iam_role_policy_attachment.github_releaser) == 0
    error_message = "The releaser must not exist until the owner sets github_releaser."
  }
}

run "github_releaser_rejects_the_publisher_subject" {
  command = plan

  variables {
    github_releaser = {
      provider_arn = "arn:aws:iam::736486260824:oidc-provider/token.actions.githubusercontent.com"
      subject      = "repo:AxC-SG@351325919/SG@1427276590:environment:aws-standard-lab:job_workflow_ref:AxC-SG/SG/.github/workflows/aws-publish-candidate.yml@refs/heads/main"
    }
  }

  expect_failures = [var.github_releaser]
}

run "github_releaser_rejects_the_publisher_environment" {
  command = plan

  variables {
    github_releaser = {
      provider_arn = "arn:aws:iam::736486260824:oidc-provider/token.actions.githubusercontent.com"
      subject      = "repo:AxC-SG@351325919/SG@1427276590:environment:aws-standard-lab:job_workflow_ref:AxC-SG/SG/.github/workflows/lab-reconcile.yml@refs/heads/main"
    }
  }

  expect_failures = [var.github_releaser]
}

run "github_releaser_rejects_branch_workflows" {
  command = plan

  variables {
    github_releaser = {
      provider_arn = "arn:aws:iam::736486260824:oidc-provider/token.actions.githubusercontent.com"
      subject      = "repo:AxC-SG@351325919/SG@1427276590:environment:aws-standard-lab-release:job_workflow_ref:AxC-SG/SG/.github/workflows/lab-reconcile.yml@refs/heads/feature"
    }
  }

  expect_failures = [var.github_releaser]
}
