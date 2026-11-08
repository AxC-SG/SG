variable "api_origin" {
  description = "Exact HTTPS API origin. Also used as the Cognito resource audience."
  type        = string

  validation {
    condition     = can(regex("^https://[a-z0-9.-]+$", var.api_origin)) && var.api_origin != var.frontend_origin
    error_message = "Use a distinct HTTPS API origin without a path or wildcard."
  }
}

variable "cognito_domain_prefix" {
  description = "Available Cognito managed-login domain prefix for this environment."
  type        = string
}

resource "aws_cognito_user_pool" "humans" {
  name                     = "${local.name}-humans"
  user_pool_tier           = "ESSENTIALS"
  deletion_protection      = "ACTIVE"
  mfa_configuration        = "ON"
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  username_configuration {
    case_sensitive = false
  }

  software_token_mfa_configuration {
    enabled = true
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  admin_create_user_config {
    allow_admin_create_user_only = true

    invite_message_template {
      email_subject = "Set your ScoutGrid password"
      email_message = "<p>Your ScoutGrid account is ready.</p><p><a href=\"${var.frontend_origin}/login\">Set your password</a>. Sign in with the work email that received this message and the temporary password below, then choose a new password.</p><p>Temporary password: <strong>{####}</strong></p><p>Account reference: {username}</p>"
      sms_message   = "Your ScoutGrid account is {username}. Temporary password: {####}"
    }
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cognito_resource_server" "standard_api" {
  user_pool_id = aws_cognito_user_pool.humans.id
  identifier   = var.api_origin
  name         = "ScoutGrid Standard API"

  scope {
    scope_name        = "session"
    scope_description = "Establish a ScoutGrid browser session"
  }
}

resource "aws_cognito_user_pool_client" "browser" {
  name                                 = "${local.name}-browser"
  user_pool_id                         = aws_cognito_user_pool.humans.id
  generate_secret                      = false
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = concat(["openid", "email"], aws_cognito_resource_server.standard_api.scope_identifiers)
  callback_urls                        = ["${var.api_origin}/api/auth/callback"]
  logout_urls                          = ["${var.frontend_origin}/login"]
  supported_identity_providers         = ["COGNITO"]
  explicit_auth_flows                  = ["ALLOW_REFRESH_TOKEN_AUTH"]
  prevent_user_existence_errors        = "ENABLED"
  enable_token_revocation              = true
}

resource "aws_cognito_user_pool_domain" "login" {
  domain                = var.cognito_domain_prefix
  user_pool_id          = aws_cognito_user_pool.humans.id
  managed_login_version = 2
}

resource "aws_cognito_managed_login_branding" "browser" {
  user_pool_id                = aws_cognito_user_pool.humans.id
  client_id                   = aws_cognito_user_pool_client.browser.id
  use_cognito_provided_values = true
}

output "identity" {
  value = {
    issuer       = "https://${aws_cognito_user_pool.humans.endpoint}"
    login_origin = "https://${aws_cognito_user_pool_domain.login.domain}.auth.${var.aws_region}.amazoncognito.com"
    client_id    = aws_cognito_user_pool_client.browser.id
    audience     = var.api_origin
    scope        = "${var.api_origin}/session"
  }
}
