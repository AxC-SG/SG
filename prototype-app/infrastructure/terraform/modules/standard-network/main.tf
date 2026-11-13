terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

variable "name" {
  type = string
}

variable "vpc_cidr" {
  type = string
}

variable "availability_zone_ids" {
  type = list(string)
}

variable "nat_gateway_mode" {
  description = "zonal creates a NAT in each AZ; single shares the first selected AZ's NAT for disposable labs; none removes NAT egress while a lab is parked."
  type        = string
  default     = "zonal"

  validation {
    condition     = contains(["zonal", "single", "none"], var.nat_gateway_mode)
    error_message = "Use zonal, single or none NAT gateway mode."
  }
}

locals {
  zones = { for index, id in var.availability_zone_ids : id => index }
  nat_zones = {
    for zone, index in local.zones : zone => index
    if var.nat_gateway_mode == "zonal" || (var.nat_gateway_mode == "single" && index == 0)
  }
  task_egress_nat_zones = {
    for zone in var.availability_zone_ids : zone => (
      var.nat_gateway_mode == "single" ? var.availability_zone_ids[0] : zone
    ) if var.nat_gateway_mode != "none"
  }
  subnets = merge([
    for tier, offset in { public = 0, task = 2, database = 4 } : {
      for zone, index in local.zones : "${tier}-${zone}" => {
        tier = tier
        zone = zone
        cidr = cidrsubnet(var.vpc_cidr, 3, offset + index)
      }
    }
  ]...)
}

data "aws_region" "current" {}

resource "aws_vpc" "standard" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = var.name }
}

resource "aws_subnet" "tier" {
  for_each = local.subnets

  vpc_id                  = aws_vpc.standard.id
  availability_zone_id    = each.value.zone
  cidr_block              = each.value.cidr
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name}-${each.key}" }
}

resource "aws_internet_gateway" "public" {
  vpc_id = aws_vpc.standard.id
  tags   = { Name = var.name }
}

resource "aws_eip" "egress" {
  for_each = local.nat_zones
  domain   = "vpc"
  tags     = { Name = "${var.name}-${each.key}" }
}

resource "aws_nat_gateway" "zonal" {
  for_each = local.nat_zones

  subnet_id     = aws_subnet.tier["public-${each.key}"].id
  allocation_id = aws_eip.egress[each.key].id
  tags          = { Name = "${var.name}-${each.key}" }

  depends_on = [aws_internet_gateway.public]
}

resource "aws_route_table" "tier" {
  for_each = local.subnets

  vpc_id = aws_vpc.standard.id
  tags   = { Name = "${var.name}-${each.key}" }
}

resource "aws_route" "public" {
  for_each = local.zones

  route_table_id         = aws_route_table.tier["public-${each.key}"].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.public.id
}

resource "aws_route" "task_egress" {
  for_each = local.task_egress_nat_zones

  route_table_id         = aws_route_table.tier["task-${each.key}"].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.zonal[each.value].id
}

resource "aws_route_table_association" "tier" {
  for_each = local.subnets

  subnet_id      = aws_subnet.tier[each.key].id
  route_table_id = aws_route_table.tier[each.key].id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.standard.id
  vpc_endpoint_type = "Gateway"
  service_name      = "com.amazonaws.${data.aws_region.current.region}.s3"
  route_table_ids   = [for zone in var.availability_zone_ids : aws_route_table.tier["task-${zone}"].id]
  tags              = { Name = "${var.name}-s3" }
}

output "boundaries" {
  value = {
    vpc_id                = aws_vpc.standard.id
    public_subnet_ids     = [for zone in var.availability_zone_ids : aws_subnet.tier["public-${zone}"].id]
    public_subnet_cidrs   = [for zone in var.availability_zone_ids : aws_subnet.tier["public-${zone}"].cidr_block]
    task_subnet_ids       = [for zone in var.availability_zone_ids : aws_subnet.tier["task-${zone}"].id]
    database_subnet_ids   = [for zone in var.availability_zone_ids : aws_subnet.tier["database-${zone}"].id]
    egress_ips_by_zone    = { for zone, address in aws_eip.egress : zone => address.public_ip }
    nat_gateway_mode      = var.nat_gateway_mode
    task_egress_nat_zones = local.task_egress_nat_zones
    s3_endpoint_id        = aws_vpc_endpoint.s3.id
  }
}
