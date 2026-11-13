mock_provider "aws" {
  mock_data "aws_region" {
    defaults = { region = "ap-southeast-2" }
  }
}

variables {
  name                  = "scoutgrid-lab"
  vpc_cidr              = "10.21.0.0/16"
  availability_zone_ids = ["apse2-az3", "apse2-az1"]
}

run "default_keeps_independent_zonal_egress" {
  command = apply

  assert {
    condition = (
      length(aws_nat_gateway.zonal) == 2 && length(aws_eip.egress) == 2 &&
      alltrue([for zone in var.availability_zone_ids :
        aws_route.task_egress[zone].nat_gateway_id == aws_nat_gateway.zonal[zone].id &&
        aws_nat_gateway.zonal[zone].subnet_id == aws_subnet.tier["public-${zone}"].id
      ])
    )
    error_message = "The default must retain a NAT and EIP in each task subnet's AZ."
  }
}

run "single_nat_keeps_two_az_boundaries" {
  command = apply

  variables {
    nat_gateway_mode = "single"
  }

  assert {
    condition = (
      toset(keys(aws_nat_gateway.zonal)) == toset(["apse2-az3"]) &&
      toset(keys(aws_eip.egress)) == toset(["apse2-az3"]) &&
      aws_nat_gateway.zonal["apse2-az3"].allocation_id == aws_eip.egress["apse2-az3"].id &&
      aws_nat_gateway.zonal["apse2-az3"].subnet_id == aws_subnet.tier["public-apse2-az3"].id &&
      alltrue([for route in aws_route.task_egress :
        route.nat_gateway_id == aws_nat_gateway.zonal["apse2-az3"].id
      ])
    )
    error_message = "Both task subnet routes must share the NAT in the first selected AZ, preserving its EIP."
  }

  assert {
    condition = (
      length(aws_subnet.tier) == 6 && length(aws_route_table.tier) == 6 &&
      length(aws_route.public) == 2 && length(aws_route.task_egress) == 2 &&
      length(aws_route_table_association.tier) == 6 &&
      length(output.boundaries.public_subnet_ids) == 2 &&
      length(output.boundaries.task_subnet_ids) == 2 &&
      length(output.boundaries.database_subnet_ids) == 2 &&
      length(aws_vpc_endpoint.s3.route_table_ids) == 2 &&
      alltrue([for subnet in aws_subnet.tier : !subnet.map_public_ip_on_launch]) &&
      alltrue([for zone in var.availability_zone_ids :
        !contains([for route in aws_route.task_egress : route.route_table_id], aws_route_table.tier["database-${zone}"].id)
      ])
    )
    error_message = "Single NAT must preserve two AZs, private task/database subnets and S3 endpoint routes, without adding DB internet routes."
  }
}

run "none_parks_egress_and_keeps_network_boundaries" {
  command = apply

  variables {
    nat_gateway_mode = "none"
  }

  assert {
    condition = (
      length(aws_nat_gateway.zonal) == 0 && length(aws_eip.egress) == 0 &&
      length(aws_route.task_egress) == 0 && length(output.boundaries.egress_ips_by_zone) == 0 &&
      length(output.boundaries.task_egress_nat_zones) == 0
    )
    error_message = "A parked lab must hold no NAT gateway, Elastic IP or task egress route."
  }

  assert {
    condition = (
      length(aws_subnet.tier) == 6 && length(aws_route_table.tier) == 6 &&
      length(aws_route.public) == 2 && length(aws_route_table_association.tier) == 6 &&
      length(aws_vpc_endpoint.s3.route_table_ids) == 2 &&
      length(output.boundaries.task_subnet_ids) == 2
    )
    error_message = "Parking egress must keep every subnet, route table, public route and the S3 endpoint."
  }
}
