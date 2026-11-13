# Lab-down (parked): services, API ingress tree, WAF and NAT egress removed; data, identity,
# task definitions and the cluster kept. Pass explicitly with -var-file after the foundation file.
runtime_ingress_enabled = false
nat_gateway_mode        = "none"

backend_candidate = {
  image_digest        = "sha256:e0477a842367866505e469c7dc97aef77759fce5febf3a59d10d49acbe3a3ad5"
  certificate_arn     = "arn:aws:acm:ap-southeast-2:736486260824:certificate/2fdafd2b-1c89-47d0-80ba-d27158736e40"
  runtime_db_secret   = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:scoutgrid-lab/runtime-db-4KTTWJ"
  application_secret  = "arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:scoutgrid-lab/application-settings-9RiIwg"
  secrets_kms_key_arn = "arn:aws:kms:ap-southeast-2:736486260824:key/084de131-918e-43dd-a56f-aa8f6d6f0174"
  start_services      = false
  enable_bom_uploads  = true
  enable_managed_auth = true
  customer_limit      = 10
}
