variable "postgres_engine_version" {
  description = "PostgreSQL 16 minor verified against the release candidate and target account."
  type        = string

  validation {
    condition     = can(regex("^16[.][0-9]+$", var.postgres_engine_version))
    error_message = "Pin an exact PostgreSQL 16 minor."
  }
}

variable "frontend_origin" {
  description = "Exact HTTPS frontend origin for the environment."
  type        = string

  validation {
    condition     = can(regex("^https://[a-z0-9.-]+$", var.frontend_origin))
    error_message = "Use a single HTTPS origin without a path or wildcard."
  }
}

locals {
  name          = "scoutgrid-${var.environment}"
  is_production = var.environment == "production"
  buckets       = toset(["imports", "exports"])
}

resource "aws_kms_key" "database" {
  description         = "${local.name} PostgreSQL and recovery"
  enable_key_rotation = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_key" "objects" {
  description         = "${local.name} import and export objects"
  enable_key_rotation = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_db_subnet_group" "standard" {
  name       = local.name
  subnet_ids = module.network.boundaries.database_subnet_ids
}

resource "aws_security_group" "database" {
  name        = "${local.name}-postgres"
  description = "Standard PostgreSQL, ingress added only for approved task groups"
  vpc_id      = module.network.boundaries.vpc_id
}

resource "aws_db_parameter_group" "standard" {
  name   = "${local.name}-postgres16"
  family = "postgres16"

  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }
}

resource "aws_db_instance" "standard" {
  identifier                    = local.name
  engine                        = "postgres"
  engine_version                = var.postgres_engine_version
  instance_class                = local.is_production ? "db.m7g.large" : "db.t4g.medium"
  multi_az                      = local.is_production
  allocated_storage             = 100
  max_allocated_storage         = local.is_production ? 400 : 200
  storage_type                  = "gp3"
  storage_encrypted             = true
  kms_key_id                    = aws_kms_key.database.arn
  db_name                       = "scoutgrid"
  port                          = 5432
  username                      = "scout_install_owner"
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.database.arn
  db_subnet_group_name          = aws_db_subnet_group.standard.name
  parameter_group_name          = aws_db_parameter_group.standard.name
  vpc_security_group_ids        = [aws_security_group.database.id]
  publicly_accessible           = false
  auto_minor_version_upgrade    = false
  backup_retention_period       = local.is_production ? 14 : 7
  deletion_protection           = true
  copy_tags_to_snapshot         = true
  final_snapshot_identifier     = "${local.name}-final"

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket" "artifacts" {
  for_each = local.buckets
  bucket   = "${local.name}-${var.account_id}-${each.key}"

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  for_each = aws_s3_bucket.artifacts
  bucket   = each.value.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "artifacts" {
  for_each = aws_s3_bucket.artifacts
  bucket   = each.value.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "artifacts" {
  for_each = aws_s3_bucket.artifacts
  bucket   = each.value.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  for_each = aws_s3_bucket.artifacts
  bucket   = each.value.id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.objects.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_cors_configuration" "imports" {
  bucket = aws_s3_bucket.artifacts["imports"].id

  cors_rule {
    allowed_origins = [var.frontend_origin]
    allowed_methods = ["PUT"]
    allowed_headers = ["content-type", "if-none-match", "x-amz-checksum-sha256", "x-amz-sdk-checksum-algorithm"]
    max_age_seconds = 300
  }
}

resource "aws_s3_bucket_policy" "artifacts" {
  for_each = aws_s3_bucket.artifacts
  bucket   = each.value.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid       = "RequireTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [each.value.arn, "${each.value.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "RequireBucketDefaultEncryption"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = ["${each.value.arn}/*"]
        Condition = {
          Null = { "s3:x-amz-server-side-encryption" = "false" }
        }
      }
      ], each.key == "imports" ? [
      {
        Sid       = "RequireCreateOnlyUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = ["${each.value.arn}/*"]
        Condition = { StringNotEquals = { "s3:if-none-match" = "*" } }
      }
    ] : [])
  })

  depends_on = [aws_s3_bucket_public_access_block.artifacts]
}

output "data" {
  value = {
    database_host              = aws_db_instance.standard.address
    database_name              = aws_db_instance.standard.db_name
    database_security_group_id = aws_security_group.database.id
    owner_secret_arn           = aws_db_instance.standard.master_user_secret[0].secret_arn
    object_bucket_names        = { for kind, bucket in aws_s3_bucket.artifacts : kind => bucket.id }
    object_key_arn             = aws_kms_key.objects.arn
  }
}
