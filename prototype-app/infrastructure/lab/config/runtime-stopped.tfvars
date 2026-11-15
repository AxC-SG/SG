# Pass explicitly with -var-file after sydney-lab.foundation.tfvars.
runtime_ingress_enabled = true
nat_gateway_mode        = "single"

backend_candidate = {
  certificate_arn     = "arn:aws:acm:ap-southeast-2:736486260824:certificate/2fdafd2b-1c89-47d0-80ba-d27158736e40"
  runtime_db_secret   = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:scoutgrid-lab/runtime-db-4KTTWJ"
  application_secret  = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:scoutgrid-lab/application-settings-9RiIwg"
  secrets_kms_key_arn = "arn:aws:kms:ap-southeast-2:736486260824:key/084de131-918e-43dd-a56f-aa8f6d6f0174"
  start_services      = false
  enable_bom_uploads  = true
  enable_managed_auth = true
  # Release smoke fixtures (infrastructure/lab/README.md#signed-in-smoke); lab only.
  enable_smoke_fixtures = true
  customer_limit        = 10
  managed_installation = {
    secret_arn = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:scoutgrid-lab/managed-installation-jbAtYE"
    version_id = "884b5bcc-83c3-49ec-ba3c-22c950aaff1b"
  }
}
