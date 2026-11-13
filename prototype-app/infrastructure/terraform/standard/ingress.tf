variable "runtime_ingress_enabled" {
  description = "Set false only to park a non-production lab: removes the API load balancer tree and WAF while keeping security groups, task definitions and data."
  type        = bool
  default     = true

  validation {
    condition     = var.runtime_ingress_enabled || var.environment != "production"
    error_message = "Production keeps its API ingress."
  }

  validation {
    condition     = var.runtime_ingress_enabled || try(!var.backend_candidate.start_services, true)
    error_message = "Stop the API and worker services before removing API ingress."
  }
}

locals {
  # Security groups and their rules are free and stay; the billable ingress tree is parked.
  ingress = var.runtime_ingress_enabled ? local.backend : {}
}

resource "aws_security_group" "alb" {
  for_each    = local.backend
  name        = "${local.name}-alb"
  description = "Public HTTPS entry point for the Standard API"
  vpc_id      = module.network.boundaries.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  for_each          = local.backend
  security_group_id = aws_security_group.alb[each.key].id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "alb_to_api" {
  for_each                     = local.backend
  security_group_id            = aws_security_group.alb[each.key].id
  referenced_security_group_id = aws_security_group.backend["api"].id
  ip_protocol                  = "tcp"
  from_port                    = local.app_port
  to_port                      = local.app_port
}

resource "aws_vpc_security_group_ingress_rule" "api_from_alb" {
  for_each                     = local.backend
  security_group_id            = aws_security_group.backend["api"].id
  referenced_security_group_id = aws_security_group.alb[each.key].id
  ip_protocol                  = "tcp"
  from_port                    = local.app_port
  to_port                      = local.app_port
}

resource "aws_lb" "api" {
  for_each           = local.ingress
  name               = "${local.name}-api"
  load_balancer_type = "application"
  internal           = false
  subnets            = module.network.boundaries.public_subnet_ids
  security_groups    = [aws_security_group.alb[each.key].id]

  enable_deletion_protection = local.is_production
  drop_invalid_header_fields = true
  desync_mitigation_mode     = "strictest"
  xff_header_processing_mode = "append"
}

resource "aws_lb_target_group" "api" {
  for_each             = local.ingress
  name                 = "${local.name}-api"
  port                 = local.app_port
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = module.network.boundaries.vpc_id
  deregistration_delay = 60

  health_check {
    path                = local.readiness_path
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "https" {
  for_each          = local.ingress
  load_balancer_arn = aws_lb.api[each.key].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = each.value.certificate_arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      status_code  = "404"
    }
  }
}

resource "aws_lb_listener_rule" "api" {
  for_each     = local.ingress
  listener_arn = aws_lb_listener.https[each.key].arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api[each.key].arn
  }

  condition {
    host_header {
      values = [trimprefix(var.api_origin, "https://")]
    }
  }

  condition {
    path_pattern {
      values = ["/api/*"]
    }
  }
}

resource "aws_wafv2_web_acl" "api" {
  for_each = local.ingress
  name     = "${local.name}-api"
  scope    = "REGIONAL"

  default_action {
    allow {}
  }

  dynamic "rule" {
    for_each = {
      AWSManagedRulesAmazonIpReputationList = 10
      AWSManagedRulesKnownBadInputsRuleSet  = 20
    }
    content {
      name     = rule.key
      priority = rule.value

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = rule.key
          vendor_name = "AWS"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.key
        sampled_requests_enabled   = false
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-api"
    sampled_requests_enabled   = false
  }
}

resource "aws_wafv2_web_acl_association" "api" {
  for_each     = local.ingress
  resource_arn = aws_lb.api[each.key].arn
  web_acl_arn  = aws_wafv2_web_acl.api[each.key].arn
}
