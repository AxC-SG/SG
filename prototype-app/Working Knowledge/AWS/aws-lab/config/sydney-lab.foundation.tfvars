# Hostnames confirmed November 11; recheck CIDR, budget and run authorization before applying.
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
backend_candidate       = null
github_publisher        = null

# Owner decision 2026-11-12: MFA off for platform and tenant sign-in.
cognito_mfa_configuration = "OFF"
