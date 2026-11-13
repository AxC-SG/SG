variable "monthly_budget" {
  description = "Account-wide monthly USD cost alert and approved billing operator email. Supply an amount approved for this account."
  type = object({
    amount_usd     = number
    operator_email = string
  })
  default = null

  validation {
    condition = var.monthly_budget == null ? true : (
      var.monthly_budget.amount_usd > 0 &&
      (var.environment != "lab" || var.monthly_budget.amount_usd <= 100) &&
      can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.monthly_budget.operator_email))
    )
    error_message = "Provide a positive USD amount, at most 100 for the disposable lab, and a valid billing operator email."
  }
}

resource "aws_budgets_budget" "standard" {
  count        = var.monthly_budget == null ? 0 : 1
  account_id   = var.account_id
  name         = "${local.name}-monthly-account-cost"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget.amount_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  # Track gross usage: credits would otherwise net the actual spend to zero and the alerts never fire.
  cost_types {
    include_credit = false
    include_refund = false
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.monthly_budget.operator_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.monthly_budget.operator_email]
  }
}

output "monthly_budget_name" {
  value = one(aws_budgets_budget.standard[*].name)
}
