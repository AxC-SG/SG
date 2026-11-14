# Hostnames confirmed November 11; frontend moved to the Vercel apex on November 13 (lab is the
# only environment). Recheck CIDR, budget and run authorization before applying.
account_id              = "736486260824"
environment             = "lab"
aws_region              = "ap-southeast-2"
availability_zone_ids   = ["apse2-az1", "apse2-az3"]
# Safe default for foundation-only plans. Each runtime file sets the mode explicitly.
nat_gateway_mode        = "single"
vpc_cidr                = "10.21.0.0/16"
postgres_engine_version = "16.15"
frontend_origin         = "https://scoutgrid.io"
api_origin              = "https://api-lab.scoutgrid.io"
cognito_domain_prefix   = "scoutgrid-lab-736486260824"
backend_candidate       = null

# Owner decision 2026-11-15: GitHub publishes qualified main commits to the lab ECR.
# The repository's OIDC subject template must include job_workflow_ref (see A03).
github_publisher = {
  provider_arn = "arn:aws:iam::736486260824:oidc-provider/token.actions.githubusercontent.com"
  subject      = "repo:AxC-SG/SG:environment:aws-standard-lab:job_workflow_ref:AxC-SG/SG/.github/workflows/aws-publish-candidate.yml@refs/heads/main"
}

# Owner decision 2026-11-12: MFA off for platform and tenant sign-in.
cognito_mfa_configuration = "OFF"

# Owner decision 2026-11-13: $100 inclusive monthly lab ceiling. This is an alert, not a cap.
monthly_budget = {
  amount_usd     = 100
  operator_email = "scoutgrid.io@gmail.com"
}
