# Operational cleanup configuration, never an application deployment source.
# Review a NORMAL saved plan against the existing protected state.
# Initially retain both fresh data keys until dependent inventory is empty.
terraform {
  required_version = ">= 1.11.0, < 2.0.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "6.64.0" }
  }
  backend "s3" {
    encrypt = true
    use_lockfile = true
  }
}
provider "aws" {
  region = "ap-southeast-2"
  allowed_account_ids = ["736486260824"]
  default_tags {
    tags = {
      Application = "ScoutGrid"
      Environment = "lab"
      Profile = "Standard"
      ManagedBy = "Terraform"
    }
  }
}
resource "aws_ecr_repository" "backend" {
  name = "scoutgrid-lab-backend"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
  lifecycle { prevent_destroy = true }
}
resource "aws_kms_key" "database" {
  description = "scoutgrid-lab PostgreSQL and recovery"
  enable_key_rotation = true
  lifecycle { prevent_destroy = true }
}
resource "aws_kms_key" "objects" {
  description = "scoutgrid-lab import and export objects"
  enable_key_rotation = true
  lifecycle { prevent_destroy = true }
}
