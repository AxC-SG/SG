mock_provider "aws" {
  override_during = plan

  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-east-1:123456789012:key/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" }
  }

  mock_resource "aws_lb" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test/aaaaaaaaaaaaaaaa" }
  }

  mock_resource "aws_lb_target_group" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test/bbbbbbbbbbbbbbbb" }
  }

  mock_resource "aws_lb_listener" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/test/aaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbb" }
  }

  mock_resource "aws_wafv2_web_acl" {
    defaults = { arn = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" }
  }

  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/test" }
  }

  mock_resource "aws_ecs_cluster" {
    defaults = { arn = "arn:aws:ecs:us-east-1:123456789012:cluster/test" }
  }

  mock_resource "aws_ecs_task_definition" {
    defaults = { arn = "arn:aws:ecs:us-east-1:123456789012:task-definition/test:1" }
  }
  mock_resource "aws_cognito_user_pool" {
    defaults = { endpoint = "cognito-idp.us-east-1.amazonaws.com/us-east-1_testpool" }
  }

  mock_resource "aws_cognito_user_pool_client" {
    defaults = { id = "scoutgridbrowserclient" }
  }

  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/ecs/scoutgrid-production/test" }
  }

  mock_resource "aws_db_instance" {
    defaults = {
      address  = "scoutgrid.example.us-east-1.rds.amazonaws.com"
      endpoint = "scoutgrid.example.us-east-1.rds.amazonaws.com:5432"
      master_user_secret = [{
        secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds-owner-a1b2c3" # gitleaks:allow synthetic test fixture
      }]
    }
  }

  mock_resource "aws_ecr_repository" {
    defaults = {
      arn            = "arn:aws:ecr:us-east-1:123456789012:repository/scoutgrid-production-backend"
      repository_url = "123456789012.dkr.ecr.us-east-1.amazonaws.com/scoutgrid-production-backend"
    }
  }

  mock_resource "aws_s3_bucket" {
    defaults = {
      arn = "arn:aws:s3:::scoutgrid-production-123456789012-imports"
    }
  }
}

variables {
  account_id              = "123456789012"
  environment             = "production"
  availability_zone_ids   = ["use1-az1", "use1-az2"]
  vpc_cidr                = "10.21.0.0/16"
  postgres_engine_version = "16.6"
  frontend_origin         = "https://app.example.com"
  api_origin              = "https://api.example.com"
  cognito_domain_prefix   = "scoutgrid-runtime-test"
}

run "foundation_without_candidate" {
  command = plan

  assert {
    condition = (
      output.network.nat_gateway_mode == "zonal" &&
      length(output.network.egress_ips_by_zone) == 2 &&
      alltrue([for zone, nat_zone in output.network.task_egress_nat_zones : zone == nat_zone])
    )
    error_message = "The production default must retain one NAT per AZ."
  }

  assert {
    condition     = length(aws_ecs_task_definition.backend) == 0 && length(aws_lb.api) == 0
    error_message = "Foundation-only configuration must omit the application runtime."
  }

  assert {
    condition = (
      length(aws_cloudtrail.standard) == 0 && length(aws_s3_bucket.audit) == 0 &&
      length(aws_kms_key.audit) == 0 && length(aws_cloudwatch_metric_alarm.operations) == 0 &&
      length(aws_config_configuration_recorder.standard) == 0 &&
      length(aws_cloudwatch_event_rule.security) == 0 && length(aws_budgets_budget.standard) == 0
    )
    error_message = "Audit and alarms must be omitted until explicitly enabled."
  }
}

run "audit_foundation_uses_private_archive_and_exact_service_permissions" {
  command = plan

  variables {
    operations = {
      audit_recovery_role_arn = "arn:aws:iam::123456789012:role/audit-recovery"
      alert_topic_arn         = "arn:aws:sns:us-east-1:123456789012:operations"
    }
  }

  override_resource {
    target          = aws_s3_bucket.audit[0]
    override_during = plan
    values          = { arn = "arn:aws:s3:::scoutgrid-production-123456789012-audit" }
  }

  assert {
    condition = (
      aws_cloudtrail.standard[0].enable_logging && aws_cloudtrail.standard[0].enable_log_file_validation &&
      aws_cloudtrail.standard[0].is_multi_region_trail && aws_cloudtrail.standard[0].include_global_service_events &&
      one(aws_cloudtrail.standard[0].event_selector).include_management_events &&
      one(aws_cloudtrail.standard[0].event_selector).read_write_type == "All" &&
      length(one(aws_cloudtrail.standard[0].event_selector).data_resource) == 0 &&
      aws_cloudtrail.standard[0].kms_key_id == aws_kms_key.audit[0].arn &&
      aws_s3_bucket_public_access_block.audit[0].block_public_policy &&
      aws_s3_bucket_public_access_block.audit[0].restrict_public_buckets &&
      one(aws_s3_bucket_ownership_controls.audit[0].rule).object_ownership == "BucketOwnerEnforced" &&
      one(aws_s3_bucket_versioning.audit[0].versioning_configuration).status == "Enabled"
    )
    error_message = "The audit foundation must deliver management events with validation and encryption to private versioned storage."
  }

  assert {
    condition = one([
      for statement in jsondecode(aws_s3_bucket_policy.audit[0].policy).Statement : statement
      if statement.Sid == "DeliverForThisTrail"
      ]).Condition.StringEquals["aws:SourceArn"] == output.operations.audit_trail_arn && one([
      for statement in jsondecode(aws_s3_bucket_policy.audit[0].policy).Statement : statement
      if statement.Sid == "DeliverForThisTrail"
      ]).Resource == "arn:aws:s3:::scoutgrid-production-123456789012-audit/AWSLogs/123456789012/*" && alltrue([
      for statement in jsondecode(aws_kms_key.audit[0].policy).Statement :
      statement.Condition.StringEquals["aws:SourceArn"] == output.operations.audit_trail_arn
      if try(statement.Principal.Service == "cloudtrail.amazonaws.com", false)
    ])
    error_message = "The CloudTrail S3 and KMS grants must match the exact trail and the delivery path must match the account."
  }

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_s3_bucket_policy.audit[0].policy).Statement :
      statement.Effect == "Deny" && statement.Condition.ArnNotEqualsIfExists["aws:PrincipalArn"] == var.operations.audit_recovery_role_arn
      if contains(["ProtectAuditObjects", "ProtectAuditRetention"], statement.Sid)
    ]) && toset(keys(aws_cloudwatch_metric_alarm.operations)) == toset(["database-cpu", "database-storage"])
    error_message = "Protect versions and retention from ordinary principals, and omit application alarms until services start."
  }
}

run "prepare_candidate_before_bootstrap" {
  command = plan

  variables {
    environment = "lab"
    backend_candidate = {
      image_digest        = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      certificate_arn     = "arn:aws:acm:us-east-1:123456789012:certificate/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      runtime_db_secret   = "arn:aws:secretsmanager:us-east-1:123456789012:secret:runtime-db-a1b2c3"
      application_secret  = "arn:aws:secretsmanager:us-east-1:123456789012:secret:app-settings-a1b2c3"
      secrets_kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    }
  }

  assert {
    condition     = length(aws_ecs_task_definition.backend) == 3 && length(aws_ecs_service.backend) == 0
    error_message = "The operator must be able to run bootstrap before starting either service."
  }

  assert {
    condition     = output.backend_runtime.runtime_db_connection_budget == { steady = 12, rollout = 24, login_limit = 25 }
    error_message = "The lab budget must include full API and worker overlap and one runtime probe."
  }
}

run "separate_runtime_roles" {
  command = plan

  variables {
    backend_candidate = {
      image_digest        = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      certificate_arn     = "arn:aws:acm:us-east-1:123456789012:certificate/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      runtime_db_secret   = "arn:aws:secretsmanager:us-east-1:123456789012:secret:runtime-db-a1b2c3"
      application_secret  = "arn:aws:secretsmanager:us-east-1:123456789012:secret:app-settings-a1b2c3"
      secrets_kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      start_services      = true
      enable_bom_uploads  = true
      enable_managed_auth = true
      customer_limit      = 3
    }
    operations = {
      audit_recovery_role_arn = "arn:aws:iam::123456789012:role/audit-recovery"
      alert_topic_arn         = "arn:aws:sns:us-east-1:123456789012:operations"
    }
  }

  assert {
    condition = alltrue([
      for role, service in aws_ecs_service.backend :
      !one(service.network_configuration).assign_public_ip &&
      length(service.load_balancer) == (role == "api" ? 1 : 0) &&
      service.desired_count == (role == "api" ? 2 : 1) &&
      one(service.deployment_circuit_breaker).rollback
    ]) && toset(keys(aws_ecs_service.backend)) == toset(["api", "worker"])
    error_message = "Only the API is behind the ALB, both services are private, and rolling failures trigger rollback."
  }

  assert {
    condition = alltrue([
      for service in values(aws_ecs_service.backend) : service.health_check_grace_period_seconds >= 300
    ])
    error_message = "API cold start takes about 155 s on 0.5 vCPU (Sydney lab, November 12); the health-check grace must cover it."
  }

  assert {
    condition = alltrue([
      for role, task in aws_ecs_task_definition.backend : (
        toset(split(";", one([for entry in one(jsondecode(task.container_definitions)).environment :
          entry.value if entry.name == "HTTP_OUTBOUND_ALLOWED_HOSTS"
        ]))) ==
        setunion(
          toset(flatten(regexall("\"([a-z-]+=[^\"]+)\"", regex("(?s)DEFAULT_ALLOWLIST = String\\.join\\(\";\",(.*?)\\);", file("${path.module}/../../../backend/src/main/java/com/prototype/vulnwatch/client/http/OutboundHostPolicy.java"))[0]))),
          toset(["cognito=scoutgrid-runtime-test.auth.us-east-1.amazoncognito.com,cognito-idp.us-east-1.amazonaws.com"])
        )
      ) if role != "migrator"
    ])
    error_message = "API and worker must allow the backend's default outbound hosts plus the Cognito login and signing-key hosts used by managed sign-in."
  }

  assert {
    condition = alltrue([
      for role, task in aws_ecs_task_definition.backend :
      endswith(one(jsondecode(task.container_definitions)).image, "@${var.backend_candidate.image_digest}") &&
      anytrue([for entry in one(jsondecode(task.container_definitions)).environment :
        entry.name == "DB_URL" && strcontains(entry.value, "sslmode=verify-full&sslrootcert=/app/rds-ca.pem")
      ]) &&
      anytrue([for entry in one(jsondecode(task.container_definitions)).environment :
        entry.name == "APP_STANDARD_CUSTOMER_LIMIT" && entry.value == "3"
      ]) == (role == "migrator") &&
      alltrue([for secret in one(jsondecode(task.container_definitions)).secrets :
        !startswith(secret.valueFrom, local.db_owner_arn)
      ]) == (role != "migrator") &&
      strcontains(aws_iam_role_policy.execution[role].policy, local.db_owner_arn) == (role == "migrator")
    ])
    error_message = "Every task must use a digest and verified TLS. Only the migrator receives the owner secret and the enrollment limit."
  }

  assert {
    condition = alltrue([
      for role, task in aws_ecs_task_definition.backend :
      anytrue([for secret in one(jsondecode(task.container_definitions)).secrets :
        secret.name == "RESEND_API_KEY" && secret.valueFrom == "${var.backend_candidate.application_secret}:resend_api_key::"
      ]) == (role != "migrator") &&
      anytrue([for entry in one(jsondecode(task.container_definitions)).environment :
        entry.name == "RESEND_FROM_EMAIL" && entry.value == "Scoutgrid <noreply@scoutgrid.io>"
      ]) == (role != "migrator")
    ])
    error_message = "API and worker must receive the Resend key from the application secret and the scoutgrid.io sender, so invitation and campaign email can be delivered; the migrator sends none."
  }

  assert {
    condition = output.backend_runtime.runtime_db_connection_budget == { steady = 20, rollout = 40, login_limit = 41 } && alltrue([
      for role, task in aws_ecs_task_definition.backend :
      anytrue([for entry in one(jsondecode(task.container_definitions)).environment :
        entry.name == "APP_STANDARD_RUNTIME_DB_CONNECTION_LIMIT" && entry.value == "41"
      ]) == (role == "migrator") &&
      anytrue([for entry in one(jsondecode(task.container_definitions)).environment :
        entry.name == "DB_MAX_POOL_SIZE" && entry.value == (role == "worker" ? "8" : "6")
      ]) == (role != "migrator")
    ])
    error_message = "The login limit and task pools must match the production rollout budget."
  }

  assert {
    condition = (
      toset(keys(aws_cloudwatch_metric_alarm.operations)) == toset([
        "database-cpu", "database-storage", "api-unavailable", "api-target-errors",
        "api-load-balancer-errors", "worker-cpu", "worker-unavailable",
      ]) &&
      aws_cloudwatch_metric_alarm.operations["api-unavailable"].treat_missing_data == "breaching" &&
      aws_cloudwatch_metric_alarm.operations["api-target-errors"].treat_missing_data == "notBreaching" &&
      aws_cloudwatch_metric_alarm.operations["worker-unavailable"].metric_name == "RunningTaskCount" &&
      aws_cloudwatch_metric_alarm.operations["worker-unavailable"].treat_missing_data == "breaching" &&
      aws_cloudwatch_metric_alarm.operations["worker-unavailable"].threshold == aws_ecs_service.backend["worker"].desired_count &&
      aws_cloudwatch_metric_alarm.operations["worker-cpu"].dimensions.ServiceName == "worker" &&
      alltrue([
        for alarm in values(aws_cloudwatch_metric_alarm.operations) :
        alarm.alarm_actions == toset([var.operations.alert_topic_arn]) && alarm.ok_actions == toset([var.operations.alert_topic_arn])
      ])
    )
    error_message = "Operations alarms must use the approved notification topic and signal meaningful missing data."
  }

  assert {
    condition = one(jsondecode(aws_ecs_task_definition.backend["migrator"].container_definitions)).command[1] == "--run-once" && alltrue([
      for role, task in aws_ecs_task_definition.backend :
      anytrue([for entry in one(jsondecode(task.container_definitions)).environment :
        entry.name == "APP_BOM_UPLOADS_ENABLED" && entry.value == tostring(role == "api")
        ]) && anytrue([for entry in one(jsondecode(task.container_definitions)).environment :
        entry.name == "APP_MANAGED_AUTH_ENABLED" && entry.value == tostring(role == "api")
      ]) if role != "migrator"
    ])
    error_message = "The migrator must exit on completion. Only the API may enable browser uploads and managed sign-in."
  }

  assert {
    condition = (
      !strcontains(aws_iam_role_policy.imports["worker"].policy, "s3:PutObject") &&
      strcontains(aws_iam_role_policy.imports["worker"].policy, "s3:GetObjectVersion") &&
      !strcontains(aws_iam_role_policy.imports["api"].policy, "s3:GetObjectVersion") &&
      strcontains(aws_iam_role_policy.imports["api"].policy, "s3:PutObject")
    )
    error_message = "The API signs uploads and verifies current objects. The worker can only read an exact object version."
  }
}

run "reject_mutable_image" {
  command = plan

  variables {
    backend_candidate = {
      image_digest        = "latest"
      certificate_arn     = "arn:aws:acm:us-east-1:123456789012:certificate/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      runtime_db_secret   = "arn:aws:secretsmanager:us-east-1:123456789012:secret:runtime-db-a1b2c3"
      application_secret  = "arn:aws:secretsmanager:us-east-1:123456789012:secret:app-settings-a1b2c3"
      secrets_kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    }
  }

  expect_failures = [var.backend_candidate]
}

run "publisher_can_only_push_to_standard_repository" {
  command = plan

  variables {
    github_publisher = {
      provider_arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      subject      = "repo:AxC-SG/SG:environment:aws-standard-production:job_workflow_ref:AxC-SG/SG/.github/workflows/aws-publish-candidate.yml@refs/heads/main"
    }
  }

  assert {
    condition = (
      one(jsondecode(aws_iam_role.github_publisher[0].assume_role_policy).Statement).Condition.StringEquals["token.actions.githubusercontent.com:sub"] == var.github_publisher.subject &&
      jsondecode(aws_iam_role_policy.github_publisher[0].policy).Statement[1].Resource == aws_ecr_repository.backend.arn &&
      alltrue(flatten([for statement in jsondecode(aws_iam_role_policy.github_publisher[0].policy).Statement :
        [for action in statement.Action : startswith(action, "ecr:")]
      ]))
    )
    error_message = "The publisher must trust only the selected GitHub environment and have only ECR permissions."
  }
}

# Without reviewers on the environment, a bare environment subject would let any
# branch's workflow publish; only the publisher workflow on main is accepted.
run "publisher_rejects_subjects_not_pinned_to_the_main_publisher" {
  command = plan

  variables {
    github_publisher = {
      provider_arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      subject      = "repo:AxC-SG/SG:environment:aws-standard-production"
    }
  }

  expect_failures = [var.github_publisher]
}

run "publisher_rejects_branch_workflows" {
  command = plan

  variables {
    github_publisher = {
      provider_arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      subject      = "repo:AxC-SG/SG:environment:aws-standard-production:job_workflow_ref:AxC-SG/SG/.github/workflows/aws-publish-candidate.yml@refs/heads/feature"
    }
  }

  expect_failures = [var.github_publisher]
}

run "publisher_rejects_other_workflows" {
  command = plan

  variables {
    github_publisher = {
      provider_arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      subject      = "repo:AxC-SG/SG:environment:aws-standard-production:job_workflow_ref:AxC-SG/SG/.github/workflows/quality.yml@refs/heads/main"
    }
  }

  expect_failures = [var.github_publisher]
}

run "prepare_managed_operator_enrollment" {
  command = plan

  variables {
    backend_candidate = {
      image_digest        = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      certificate_arn     = "arn:aws:acm:us-east-1:123456789012:certificate/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      runtime_db_secret   = "arn:aws:secretsmanager:us-east-1:123456789012:secret:runtime-db-a1b2c3"
      application_secret  = "arn:aws:secretsmanager:us-east-1:123456789012:secret:app-settings-a1b2c3"
      secrets_kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      managed_installation = {
        secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:operator-enrollment-a1b2c3" # gitleaks:allow synthetic test fixture
        version_id = "11111111-2222-3333-4444-555555555555"
      }
    }
  }

  assert {
    condition = length(aws_ecs_service.backend) == 0 && alltrue([
      for role, task in aws_ecs_task_definition.backend :
      strcontains(task.container_definitions, var.backend_candidate.managed_installation.secret_arn) == (role == "migrator") &&
      strcontains(aws_iam_role_policy.execution[role].policy, var.backend_candidate.managed_installation.secret_arn) == (role == "migrator")
    ])
    error_message = "Enrollment inputs belong to the one-shot migrator with services stopped."
  }

  assert {
    condition = (
      length([for secret in one(jsondecode(aws_ecs_task_definition.backend["migrator"].container_definitions)).secrets :
        secret if startswith(secret.valueFrom, var.backend_candidate.managed_installation.secret_arn) &&
        endswith(secret.valueFrom, "::${var.backend_candidate.managed_installation.version_id}")
      ]) == 4 &&
      !aws_ecs_task_definition.backend["migrator"].skip_destroy
    )
    error_message = "All four fields must reference the reviewed version, and replaced enrollment task revisions must be deregistered."
  }
}

run "reject_managed_enrollment_with_services_running" {
  command = plan

  variables {
    backend_candidate = {
      image_digest        = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      certificate_arn     = "arn:aws:acm:us-east-1:123456789012:certificate/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      runtime_db_secret   = "arn:aws:secretsmanager:us-east-1:123456789012:secret:runtime-db-a1b2c3"
      application_secret  = "arn:aws:secretsmanager:us-east-1:123456789012:secret:app-settings-a1b2c3"
      secrets_kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      start_services      = true
      managed_installation = {
        secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:operator-enrollment-a1b2c3" # gitleaks:allow synthetic test fixture
        version_id = "11111111-2222-3333-4444-555555555555"
      }
    }
  }

  expect_failures = [var.backend_candidate]
}

run "reject_external_operations_destinations" {
  command = plan

  variables {
    operations = {
      audit_recovery_role_arn = "arn:aws:iam::123456789012:role/audit-recovery"
      alert_topic_arn         = "arn:aws:sns:us-east-1:999999999999:operations"
    }
  }

  expect_failures = [var.operations]
}

run "scoped_security_monitoring_and_monthly_cost_alerts" {
  command = plan

  variables {
    operations = {
      audit_recovery_role_arn  = "arn:aws:iam::123456789012:role/audit-recovery"
      alert_topic_arn          = "arn:aws:sns:us-east-1:123456789012:operations"
      config_recorder_role_arn = "arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
      guardduty_detector_id    = "abcdef0123456789abcdef0123456789"
      security_topic_arn       = "arn:aws:sns:us-east-1:123456789012:security-alerts"
    }
    monthly_budget = {
      amount_usd     = 1000
      operator_email = "billing@example.com"
    }
  }

  override_resource {
    target          = aws_s3_bucket.audit[0]
    override_during = plan
    values          = { arn = "arn:aws:s3:::scoutgrid-production-123456789012-audit" }
  }

  assert {
    condition = (
      aws_config_configuration_recorder.standard[0].role_arn == var.operations.config_recorder_role_arn &&
      toset(one(aws_config_configuration_recorder.standard[0].recording_group).resource_types) == toset(["AWS::RDS::DBInstance", "AWS::S3::Bucket"]) &&
      !one(aws_config_configuration_recorder.standard[0].recording_group).all_supported &&
      aws_config_configuration_recorder_status.standard[0].is_enabled &&
      aws_config_delivery_channel.standard[0].s3_kms_key_arn == aws_kms_key.audit[0].arn &&
      toset([for rule in aws_config_config_rule.standard : one(rule.source).source_identifier]) == toset([
        "RDS_INSTANCE_PUBLIC_ACCESS_CHECK", "RDS_STORAGE_ENCRYPTED",
        "S3_BUCKET_PUBLIC_READ_PROHIBITED", "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
      ])
    )
    error_message = "Config must record only RDS and S3 with an encrypted delivery channel and four managed rules."
  }

  assert {
    condition = (
      one([for s in jsondecode(aws_s3_bucket_policy.audit[0].policy).Statement : s if s.Sid == "DeliverConfigArchive"]).Resource == "arn:aws:s3:::scoutgrid-production-123456789012-audit/config/AWSLogs/123456789012/Config/*" &&
      one([for s in jsondecode(aws_kms_key.audit[0].policy).Statement : s if s.Sid == "EncryptConfigArchive"]).Condition.ArnLike["aws:SourceArn"] == "arn:aws:config:us-east-1:123456789012:*"
    )
    error_message = "The Config service must be limited to the reviewed archive prefix and account/region key grant."
  }

  assert {
    condition = (
      jsondecode(aws_cloudwatch_event_rule.security["guardduty"].event_pattern).detail.service.detectorId[0] == var.operations.guardduty_detector_id &&
      jsondecode(aws_cloudwatch_event_rule.security["guardduty"].event_pattern).account[0] == var.account_id &&
      jsondecode(aws_cloudwatch_event_rule.security["config"].event_pattern).detail.newEvaluationResult.complianceType[0] == "NON_COMPLIANT" &&
      length(jsondecode(aws_cloudwatch_event_rule.security["config"].event_pattern).detail.configRuleName) == 4 &&
      alltrue([for target in aws_cloudwatch_event_target.security : target.arn == var.operations.security_topic_arn && target.role_arn == aws_iam_role.security_events[0].arn]) &&
      one(jsondecode(aws_iam_role_policy.security_events[0].policy).Statement).Resource == var.operations.security_topic_arn &&
      toset(one(jsondecode(aws_iam_role.security_events[0].assume_role_policy).Statement).Condition.ArnEquals["aws:SourceArn"]) == toset([
        "arn:aws:events:us-east-1:123456789012:rule/scoutgrid-production-ops-config",
        "arn:aws:events:us-east-1:123456789012:rule/scoutgrid-production-ops-guardduty"
      ])
    )
    error_message = "Route only the selected detector and rule events through the dedicated SNS role and topic."
  }

  assert {
    condition = (
      aws_budgets_budget.standard[0].account_id == var.account_id &&
      aws_budgets_budget.standard[0].limit_amount == "1000" &&
      aws_budgets_budget.standard[0].time_unit == "MONTHLY" &&
      toset([for alert in aws_budgets_budget.standard[0].notification : "${alert.notification_type}:${alert.threshold}"]) == toset(["ACTUAL:80", "FORECASTED:100"])
    )
    error_message = "The selected account must receive both actual and forecast monthly cost alerts."
  }
}

run "accept_lab_budget_at_owner_allowance" {
  command = plan

  variables {
    environment = "lab"
    monthly_budget = {
      amount_usd     = 100
      operator_email = "billing@example.com"
    }
  }

  assert {
    condition = (
      aws_budgets_budget.standard[0].limit_amount == "100" &&
      !one(aws_budgets_budget.standard[0].cost_types).include_credit &&
      !one(aws_budgets_budget.standard[0].cost_types).include_refund
    )
    error_message = "The lab must accept the owner's inclusive $100 monthly ceiling, measured as gross usage without credits."
  }
}

run "reject_lab_budget_above_owner_allowance" {
  command = plan

  variables {
    environment = "lab"
    monthly_budget = {
      amount_usd     = 100.01
      operator_email = "billing@example.com"
    }
  }

  expect_failures = [var.monthly_budget]
}

run "sydney_lab_uses_regional_runtime_and_release_targets" {
  command = plan

  variables {
    environment           = "lab"
    aws_region            = "ap-southeast-2"
    availability_zone_ids = ["apse2-az1", "apse2-az3"]
    backend_candidate = {
      image_digest        = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      certificate_arn     = "arn:aws:acm:ap-southeast-2:123456789012:certificate/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      runtime_db_secret   = "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:runtime-db-a1b2c3"
      application_secret  = "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:app-settings-a1b2c3"
      secrets_kms_key_arn = "arn:aws:kms:ap-southeast-2:123456789012:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    }
    operations = {
      audit_recovery_role_arn  = "arn:aws:iam::123456789012:role/audit-recovery"
      alert_topic_arn          = "arn:aws:sns:ap-southeast-2:123456789012:operations"
      config_recorder_role_arn = "arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
      guardduty_detector_id    = "abcdef0123456789abcdef0123456789"
      security_topic_arn       = "arn:aws:sns:ap-southeast-2:123456789012:security-alerts"
    }
  }

  override_resource {
    target          = aws_cognito_user_pool.humans
    override_during = plan
    values          = { endpoint = "cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_testpool" }
  }

  override_resource {
    target          = aws_db_instance.standard
    override_during = plan
    values = {
      address  = "scoutgrid.example.ap-southeast-2.rds.amazonaws.com"
      endpoint = "scoutgrid.example.ap-southeast-2.rds.amazonaws.com:5432"
      master_user_secret = [{
        secret_arn = "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:rds-owner-a1b2c3" # gitleaks:allow synthetic test fixture
      }]
    }
  }

  override_resource {
    target          = aws_ecr_repository.backend
    override_during = plan
    values          = { repository_url = "123456789012.dkr.ecr.ap-southeast-2.amazonaws.com/scoutgrid-lab-backend" }
  }

  assert {
    condition = (
      output.release_targets.aws_region == "ap-southeast-2" &&
      strcontains(output.release_targets.backend_registry_url, ".dkr.ecr.ap-southeast-2.") &&
      alltrue([
        for task in aws_ecs_task_definition.backend :
        one(jsondecode(task.container_definitions)).logConfiguration.options["awslogs-region"] == "ap-southeast-2" &&
        anytrue([for entry in one(jsondecode(task.container_definitions)).environment :
          entry.name == "DB_URL" && strcontains(entry.value, "sslmode=verify-full&sslrootcert=/app/rds-ca-ap-southeast-2.pem")
        ])
      ]) &&
      alltrue([for name in ["AWS_REGION", "APP_BOM_UPLOADS_REGION"] :
        one([for entry in one(jsondecode(aws_ecs_task_definition.backend["api"].container_definitions)).environment :
          entry.value if entry.name == name
        ]) == "ap-southeast-2"
      ]) &&
      one([for entry in one(jsondecode(aws_ecs_task_definition.backend["api"].container_definitions)).environment :
        entry.value if entry.name == "APP_MANAGED_AUTH_LOGIN_ORIGIN"
      ]) == "https://scoutgrid-runtime-test.auth.ap-southeast-2.amazoncognito.com"
    )
    error_message = "Sydney releases and tasks must use the regional ECR, logs, Cognito, S3 and pinned RDS trust paths."
  }

  assert {
    condition = (
      output.operations.audit_trail_arn == "arn:aws:cloudtrail:ap-southeast-2:123456789012:trail/scoutgrid-lab-operations" &&
      jsondecode(aws_cloudwatch_event_rule.security["guardduty"].event_pattern).region[0] == "ap-southeast-2" &&
      one([for s in jsondecode(aws_iam_role_policy.imports["worker"].policy).Statement :
        s.Condition.StringEquals["kms:ViaService"] if try(s.Condition.StringEquals["kms:ViaService"] != "", false)
      ]) == "s3.ap-southeast-2.amazonaws.com"
    )
    error_message = "Audit, findings and KMS permissions must stay in the Sydney environment."
  }
}

run "sydney_lab_rejects_other_region_credentials" {
  command = plan

  variables {
    environment           = "lab"
    aws_region            = "ap-southeast-2"
    availability_zone_ids = ["apse2-az1", "apse2-az3"]
    backend_candidate = {
      image_digest        = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      certificate_arn     = "arn:aws:acm:us-east-1:123456789012:certificate/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      runtime_db_secret   = "arn:aws:secretsmanager:us-east-1:123456789012:secret:runtime-db-a1b2c3"
      application_secret  = "arn:aws:secretsmanager:us-east-1:123456789012:secret:app-settings-a1b2c3"
      secrets_kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    }
  }

  expect_failures = [var.backend_candidate]
}

run "sydney_single_nat_foundation" {
  command = plan

  variables {
    account_id            = "736486260824"
    environment           = "lab"
    aws_region            = "ap-southeast-2"
    availability_zone_ids = ["apse2-az1", "apse2-az3"]
    nat_gateway_mode      = "single"
  }

  assert {
    condition = (
      output.network.nat_gateway_mode == "single" &&
      toset(keys(output.network.egress_ips_by_zone)) == toset(["apse2-az1"]) &&
      output.network.task_egress_nat_zones == { "apse2-az1" = "apse2-az1", "apse2-az3" = "apse2-az1" } &&
      length(output.network.public_subnet_ids) == 2 &&
      length(output.network.task_subnet_ids) == 2 &&
      length(output.network.database_subnet_ids) == 2 &&
      !aws_db_instance.standard.multi_az && !aws_db_instance.standard.publicly_accessible &&
      aws_ecr_repository.backend.image_tag_mutability == "IMMUTABLE" &&
      length(aws_iam_role.github_publisher) == 0 && length(aws_ecs_service.backend) == 0
    )
    error_message = "The lab must share one NAT while keeping two-AZ networking, private Single-AZ RDS, ECR, and publishing disabled."
  }
}

run "reject_single_nat_in_production" {
  command = plan

  variables {
    nat_gateway_mode = "single"
  }

  expect_failures = [var.nat_gateway_mode]
}

run "reject_parked_nat_in_production" {
  command = plan

  variables {
    nat_gateway_mode = "none"
  }

  expect_failures = [var.nat_gateway_mode]
}

run "reject_unknown_nat_topology" {
  command = plan

  variables {
    environment      = "lab"
    nat_gateway_mode = "shared"
  }

  expect_failures = [var.nat_gateway_mode]
}

run "reject_parked_ingress_in_production" {
  command = plan

  variables {
    runtime_ingress_enabled = false
  }

  expect_failures = [var.runtime_ingress_enabled]
}
