terraform {
  required_version = ">= 1.11.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.64.0"
    }
  }

  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = {
      Application = "ScoutGrid"
      Environment = var.environment
      Profile     = "Standard"
      ManagedBy   = "Terraform"
    }
  }
}

variable "account_id" {
  description = "Account ID verified at G00 for this environment."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "Provide the verified 12-digit AWS account ID."
  }
}

variable "environment" {
  type = string

  validation {
    condition     = contains(["lab", "production"], var.environment)
    error_message = "Use lab or production."
  }
}

variable "aws_region" {
  description = "Environment region. Supported regions have a pinned RDS CA bundle in the candidate image."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = contains(["us-east-1", "ap-southeast-2"], var.aws_region)
    error_message = "Select us-east-1 or ap-southeast-2."
  }
}

variable "availability_zone_ids" {
  description = "Two explicitly selected AZ IDs in the environment region."
  type        = list(string)

  validation {
    condition     = length(var.availability_zone_ids) == 2 && length(distinct(var.availability_zone_ids)) == 2
    error_message = "Provide two distinct AZ IDs."
  }
}

variable "vpc_cidr" {
  description = "Environment CIDR, approved against existing network allocations."
  type        = string

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr)) && can(regex("/(1[6-9]|2[0-4])$", var.vpc_cidr))
    error_message = "Provide an IPv4 /16 through /24 so each ALB subnet is at least a /27."
  }
}

variable "nat_gateway_mode" {
  description = "Use single only for a bounded disposable lab. Production requires independent zonal egress."
  type        = string
  default     = "zonal"

  validation {
    condition     = contains(["zonal", "single"], var.nat_gateway_mode)
    error_message = "Use zonal or single NAT gateway mode."
  }

  validation {
    condition     = var.environment != "production" || var.nat_gateway_mode == "zonal"
    error_message = "Production requires one NAT gateway per selected AZ."
  }
}

module "network" {
  source = "../modules/standard-network"

  name                  = "scoutgrid-${var.environment}"
  vpc_cidr              = var.vpc_cidr
  availability_zone_ids = var.availability_zone_ids
  nat_gateway_mode      = var.nat_gateway_mode
}

output "network" {
  value = module.network.boundaries
}
