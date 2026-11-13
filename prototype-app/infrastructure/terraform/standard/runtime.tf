variable "backend_candidate" {
  description = "Reviewed AWS image and credential references. Leave null for a foundation-only plan."
  type = object({
    image_digest        = string
    certificate_arn     = string
    runtime_db_secret   = string
    application_secret  = string
    secrets_kms_key_arn = string
    start_services      = optional(bool, false)
    enable_bom_uploads  = optional(bool, false)
    enable_managed_auth = optional(bool, false)
    customer_limit      = optional(number, 10)
    managed_installation = optional(object({
      secret_arn = string
      version_id = string
    }))
  })
  default = null

  validation {
    condition     = var.backend_candidate == null ? true : contains([3, 10], var.backend_candidate.customer_limit)
    error_message = "Select the approved Standard enrollment limit of 3 or 10 customers."
  }

  validation {
    condition     = var.backend_candidate == null ? true : can(regex("^sha256:[0-9a-f]{64}$", var.backend_candidate.image_digest))
    error_message = "Pin the backend candidate by ECR image digest."
  }

  validation {
    condition = var.backend_candidate == null ? true : (
      alltrue([for arn in [var.backend_candidate.runtime_db_secret, var.backend_candidate.application_secret] :
        can(regex("^arn:aws:secretsmanager:${var.aws_region}:${var.account_id}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", arn))
      ]) &&
      var.backend_candidate.runtime_db_secret != var.backend_candidate.application_secret &&
      can(regex("^arn:aws:kms:${var.aws_region}:${var.account_id}:key/[a-zA-Z0-9-]+$", var.backend_candidate.secrets_kms_key_arn)) &&
      can(regex("^arn:aws:acm:${var.aws_region}:${var.account_id}:certificate/[a-f0-9-]+$", var.backend_candidate.certificate_arn))
    )
    error_message = "Supply distinct full Secrets Manager ARNs, a KMS key ARN, and an ACM certificate ARN in the selected account and region."
  }

  validation {
    condition = try(var.backend_candidate.managed_installation, null) == null ? true : (
      can(regex("^arn:aws:secretsmanager:${var.aws_region}:${var.account_id}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", var.backend_candidate.managed_installation.secret_arn)) &&
      can(regex("^[A-Za-z0-9-]{32,64}$", var.backend_candidate.managed_installation.version_id)) &&
      !contains([var.backend_candidate.runtime_db_secret, var.backend_candidate.application_secret], var.backend_candidate.managed_installation.secret_arn) &&
      !var.backend_candidate.start_services
    )
    error_message = "Pin a separate account-local enrollment secret version while the API and worker services are stopped."
  }
}

locals {
  backend_enabled             = var.backend_candidate != null
  backend                     = local.backend_enabled ? { standard = var.backend_candidate } : {}
  managed_installation_secret = try(var.backend_candidate.managed_installation.secret_arn, null)
  app_port                    = 8080
  readiness_path              = "/actuator/health/readiness"
  task_shapes = {
    api      = { cpu = 512, memory = 2048, replicas = local.is_production ? 2 : 1, db_pool_size = 6 }
    worker   = { cpu = 1024, memory = 4096, replicas = 1, db_pool_size = local.is_production ? 8 : 6 }
    migrator = { cpu = 1024, memory = 4096, replicas = 0, db_pool_size = 0 }
  }
  backend_deployment_maximum_percent = 200
  runtime_db_steady_connections      = sum([for task in values(local.task_shapes) : task.replicas * task.db_pool_size])
  runtime_db_rollout_connections = sum([
    for task in values(local.task_shapes) :
    floor(task.replicas * local.backend_deployment_maximum_percent / 100) * task.db_pool_size
  ])
  # Bootstrap and targeted provisioning serialize their runtime verification under the migration lock.
  runtime_db_connection_limit = local.runtime_db_rollout_connections + 1
  backend_tasks               = local.backend_enabled ? local.task_shapes : {}
  backend_services = local.backend_enabled ? {
    for role, shape in local.backend_tasks : role => shape
    if role != "migrator" && var.backend_candidate.start_services
  } : {}
  rds_ca_bundle  = var.aws_region == "us-east-1" ? "/app/rds-ca.pem" : "/app/rds-ca-${var.aws_region}.pem"
  db_url         = "jdbc:postgresql://${aws_db_instance.standard.endpoint}/${aws_db_instance.standard.db_name}?sslmode=verify-full&sslrootcert=${local.rds_ca_bundle}&connectTimeout=10&socketTimeout=30"
  db_owner_arn   = aws_db_instance.standard.master_user_secret[0].secret_arn
  imports_arn    = aws_s3_bucket.artifacts["imports"].arn
  cognito_issuer = "https://${aws_cognito_user_pool.humans.endpoint}"
  cognito_login  = "${aws_cognito_user_pool_domain.login.domain}.auth.${var.aws_region}.amazoncognito.com"

  # Setting HTTP_OUTBOUND_ALLOWED_HOSTS replaces the backend default, so this repeats
  # OutboundHostPolicy.DEFAULT_ALLOWLIST and adds the Cognito hosts that managed sign-in calls
  # for the token exchange and signing keys. tests/runtime.tftest.hcl fails if the two drift.
  # Once a backend image that reads HTTP_OUTBOUND_ADDITIONAL_ALLOWED_HOSTS is deployed, set
  # only the Cognito entry there instead and drop this copy.
  outbound_allowed_hosts = join(";", [
    "github=api.github.com",
    "nvd=services.nvd.nist.gov",
    "epss=api.first.org",
    "eol=endoflife.date",
    "openai=api.openai.com",
    "resend=api.resend.com",
    "turnstile=challenges.cloudflare.com",
    "kev=www.cisa.gov",
    "jvn=jvndb.jvn.jp",
    "euvd=euvdservices.enisa.europa.eu",
    "csaf-microsoft=msrc.microsoft.com",
    "csaf-redhat=security.access.redhat.com",
    "csaf-cisa=www.cisa.gov",
    "osv=api.osv.dev",
    "msrc=api.msrc.microsoft.com",
    "azure-management=management.azure.com",
    "gcp=cloudasset.googleapis.com,compute.googleapis.com,osconfig.googleapis.com,cloudresourcemanager.googleapis.com",
    "intune=graph.microsoft.com,login.microsoftonline.com",
    "cognito=${local.cognito_login},cognito-idp.${var.aws_region}.amazonaws.com",
  ])

  runtime_environment = {
    HTTP_OUTBOUND_ALLOWED_HOSTS               = local.outbound_allowed_hosts
    SPRING_PROFILES_ACTIVE                    = "prod"
    APP_ENVIRONMENT                           = local.is_production ? "production" : "preproduction"
    SERVER_PORT                               = tostring(local.app_port)
    APP_PLATFORM_MIGRATION_ENABLED            = "false"
    APP_SCHEMA_MIGRATION_ENABLED              = "false"
    APP_JWT_AUTH_MODE                         = "EXTERNAL"
    APP_JWT_ISSUER_URI                        = local.cognito_issuer
    APP_JWT_JWK_SET_URI                       = "${local.cognito_issuer}/.well-known/jwks.json"
    APP_SECURITY_JWT_AUDIENCE                 = var.api_origin
    APP_CORS_ALLOWED_ORIGINS                  = var.frontend_origin
    APP_PUBLIC_RATE_LIMIT_TRUSTED_PROXY_CIDRS = join(",", module.network.boundaries.public_subnet_cidrs)
    APP_DEMO_APP_BASE_URL                     = var.frontend_origin
    RESEND_FROM_EMAIL                         = "Scoutgrid <noreply@scoutgrid.io>"
    APP_TURNSTILE_EXPECTED_HOSTNAME           = trimprefix(var.frontend_origin, "https://")
    MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE = "health"
    DB_MIN_IDLE                               = "1"
    APP_BOM_UPLOADS_BUCKET                    = aws_s3_bucket.artifacts["imports"].bucket
    APP_BOM_UPLOADS_REGION                    = var.aws_region
    AWS_REGION                                = var.aws_region
  }

  migrator_environment = {
    APP_RUNTIME_ROLE                         = "schema-migrator"
    MIGRATION_DB_HOST                        = aws_db_instance.standard.address
    MIGRATION_DB_PORT                        = tostring(aws_db_instance.standard.port)
    MIGRATION_DB_NAME                        = aws_db_instance.standard.db_name
    APP_PLATFORM_OWNER_BOOTSTRAP_ENABLED     = "false"
    PLATFORM_OWNER_SETUP_LINK_ENABLED        = "false"
    APP_MANAGED_INSTALLATION_ENABLED         = tostring(local.managed_installation_secret != null)
    APP_MANAGED_INSTALLATION_ISSUER          = local.managed_installation_secret == null ? "" : local.cognito_issuer
    APP_JWT_ISSUER_URI                       = local.cognito_issuer
    APP_STANDARD_CUSTOMER_LIMIT              = tostring(try(var.backend_candidate.customer_limit, 10))
    APP_STANDARD_RUNTIME_DB_CONNECTION_LIMIT = tostring(local.runtime_db_connection_limit)
  }
}

resource "aws_ecs_cluster" "standard" {
  for_each = local.backend
  name     = local.name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_cloudwatch_log_group" "backend" {
  for_each          = local.backend_tasks
  name              = "/ecs/${local.name}/${each.key}"
  retention_in_days = local.is_production ? 90 : 14
}

resource "aws_security_group" "backend" {
  for_each    = local.backend_tasks
  name        = "${local.name}-${each.key}"
  description = "Standard ECS ${each.key} network boundary"
  vpc_id      = module.network.boundaries.vpc_id
}

resource "aws_vpc_security_group_egress_rule" "backend_https" {
  for_each          = local.backend_tasks
  security_group_id = aws_security_group.backend[each.key].id
  description       = "HTTPS through reviewed NAT topology or S3 gateway"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "backend_to_database" {
  for_each                     = local.backend_tasks
  security_group_id            = aws_security_group.backend[each.key].id
  referenced_security_group_id = aws_security_group.database.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_vpc_security_group_ingress_rule" "database_from_backend" {
  for_each                     = local.backend_tasks
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = aws_security_group.backend[each.key].id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_ecs_task_definition" "backend" {
  for_each                 = local.backend_tasks
  family                   = "${local.name}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = each.value.cpu
  memory                   = each.value.memory
  execution_role_arn       = aws_iam_role.execution[each.key].arn
  task_role_arn            = try(aws_iam_role.application[each.key].arn, null)
  skip_destroy             = each.key != "migrator"

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([merge({
    name        = each.key
    image       = "${aws_ecr_repository.backend.repository_url}@${var.backend_candidate.image_digest}"
    essential   = true
    stopTimeout = 120
    environment = [for name, value in merge(
      { DB_URL = local.db_url },
      each.key == "migrator" ? local.migrator_environment : merge(local.runtime_environment, {
        APP_RUNTIME_ROLE              = each.key
        APP_BOM_UPLOADS_ENABLED       = tostring(each.key == "api" && var.backend_candidate.enable_bom_uploads)
        APP_MANAGED_AUTH_ENABLED      = tostring(each.key == "api" && var.backend_candidate.enable_managed_auth)
        APP_MANAGED_AUTH_LOGIN_ORIGIN = "https://${local.cognito_login}"
        APP_MANAGED_AUTH_CLIENT_ID    = aws_cognito_user_pool_client.browser.id
        DB_MAX_POOL_SIZE              = tostring(each.value.db_pool_size)
        SERVER_ADDRESS                = each.key == "worker" ? "127.0.0.1" : "0.0.0.0"
      })
    ) : { name = name, value = value }]
    secrets = [for name, reference in local.task_secrets[each.key] : {
      name      = name
      valueFrom = reference
    }]
    linuxParameters = { initProcessEnabled = true }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.backend[each.key].name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = each.key
        mode                  = "blocking"
      }
    }
    }, each.key == "migrator" ? {
    command = ["/app/scripts/run-schema-migration.sh", "--run-once"]
    } : {}, each.key != "migrator" ? {
    healthCheck = {
      command     = ["CMD", "busybox", "wget", "-q", "-O", "/dev/null", "http://127.0.0.1:${local.app_port}/actuator/health/liveness"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 120
    }
    } : {}, each.key == "api" ? {
    portMappings = [{ containerPort = local.app_port, protocol = "tcp" }]
  } : {})])
}

resource "aws_ecs_service" "backend" {
  for_each                           = local.backend_services
  name                               = each.key
  cluster                            = aws_ecs_cluster.standard["standard"].arn
  task_definition                    = aws_ecs_task_definition.backend[each.key].arn
  launch_type                        = "FARGATE"
  platform_version                   = "1.4.0"
  desired_count                      = each.value.replicas
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = local.backend_deployment_maximum_percent
  health_check_grace_period_seconds  = 300
  wait_for_steady_state              = true
  enable_execute_command             = false

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = module.network.boundaries.task_subnet_ids
    security_groups  = [aws_security_group.backend[each.key].id]
    assign_public_ip = false
  }

  dynamic "load_balancer" {
    for_each = each.key == "api" ? [aws_lb_target_group.api["standard"].arn] : []
    content {
      target_group_arn = load_balancer.value
      container_name   = each.key
      container_port   = local.app_port
    }
  }

  depends_on = [
    aws_iam_role_policy.execution,
    aws_iam_role_policy.imports,
    aws_vpc_security_group_ingress_rule.database_from_backend,
    aws_vpc_security_group_egress_rule.backend_to_database,
    aws_vpc_security_group_egress_rule.backend_https,
    aws_vpc_security_group_ingress_rule.api_from_alb,
    aws_vpc_security_group_egress_rule.alb_to_api,
    aws_lb_listener_rule.api,
    aws_wafv2_web_acl_association.api,
    module.network,
  ]
}

output "backend_runtime" {
  value = local.backend_enabled ? {
    cluster_arn                = aws_ecs_cluster.standard["standard"].arn
    service_names              = { for role, service in aws_ecs_service.backend : role => service.name }
    task_definition_arns       = { for role, task in aws_ecs_task_definition.backend : role => task.arn }
    task_subnet_ids            = module.network.boundaries.task_subnet_ids
    migrator_security_group_id = aws_security_group.backend["migrator"].id
    api_load_balancer_dns_name = try(aws_lb.api["standard"].dns_name, null)
    api_load_balancer_zone_id  = try(aws_lb.api["standard"].zone_id, null)
    runtime_db_connection_budget = {
      steady      = local.runtime_db_steady_connections
      rollout     = local.runtime_db_rollout_connections
      login_limit = local.runtime_db_connection_limit
    }
  } : null
}
