"""Reproduce a bounded lab planning allowance; does not query AWS or apply IaC."""
import json
from decimal import Decimal as D
from pathlib import Path

root = Path(__file__).resolve().parent
evidence = json.loads((root / "price-list-evidence.json").read_text())


def rate(group, name, operation=None):
    products = evidence[group][name]["products"]
    if operation:
        products = [p for p in products if p.get("attributes", p.get("product", {}).get("attributes", {})).get("operation") == operation]
    assert len(products) == 1, (group, name)
    product = products[0]
    terms = product["terms"].get("OnDemand", product["terms"])
    dimensions = [d for t in terms.values() for d in t["priceDimensions"].values()]
    assert len(dimensions) == 1, name
    return D(dimensions[0]["pricePerUnit"]["USD"])


cpu = rate("runtime", "fargate_cpu")
memory = rate("runtime", "fargate_memory")
task_hour = D("1.5") * cpu + D(6) * memory  # API 0.5/2 + worker 1/4.
hourly = {
    "one_nat": rate("fixed", "nat_hour"),
    "nat_and_minimum_two_alb_public_ips": D(3) * rate("fixed", "public_ipv4"),
    "rds_single_az": rate("fixed", "rds_hour"),
    "rds_100_gib_gp3": D(100) * rate("runtime", "rds_storage") / D(730),
    "api_and_worker": task_hour,
    "alb": rate("fixed", "alb_hour"),
    "one_alb_lcu_allowance": rate("runtime", "alb_lcu", "LoadBalancing:Application"),
    "waf_acl_and_two_managed_rule_references": D(7) / D(730),
}
reserves = {
    "three_kms_keys_and_four_secrets_full_month_allowance": D("4.60"),
    "five_gb_nat_processing": D(5) * rate("fixed", "nat_gb"),
    "other_transfer_including_cross_az": D(1),
    "24_surplus_t4g_vcpu_hours_dated_rate_allowance": D("1.80"),
    "backup_and_s3_storage_dated_allowance": D("0.12"),
    "one_gb_month_retained_ecr": D("0.10"),
    "logs_container_insights_amplify_identity_and_email_allowance": D(2),
    "100000_waf_requests": D("0.06"),
    "other_api_requests": D("0.10"),
}
scenarios = {}
for hours in [4, 8]:
    # Conservatively allow full service overlap for the entire window plus
    # one cumulative hour of exit-once migrator/provisioner execution.
    total = sum(hourly.values()) * hours + task_hour * hours + cpu + D(4) * memory + sum(reserves.values())
    scenarios[str(hours)] = {"hours": hours, "modeled_usd_before_tax": total}
spend = json.loads((root / "aws-read-only-inventory.json").read_text())["return_value"]["checks"]["spend"]
posted = sum(D(x["Total"]["UnblendedCost"]["Amount"]) for x in spend["ResultsByTime"])
result = {
    "status": "PROPOSED; not approved for a new run; not a final bill or a hard cost cap",
    "monthly_limit_usd": "20", "proposed_run_reserve_usd": "15",
    "pre_run_condition": "All other posted plus known unposted monthly charges must be below $5; include the completed foundation run.",
    "hours_target": 4, "cleanup_contingency_deadline_hours": 8,
    "hourly_usd": hourly, "steady_hourly_subtotal_usd": sum(hourly.values()),
    "one_nat_plus_ip_monthly_usd_at_730_hours": (rate("fixed", "nat_hour") + rate("fixed", "public_ipv4")) * D(730),
    "usage_reserves_usd": reserves, "scenarios": scenarios,
    "estimated_spend_returned_on_2026_11_11_usd": posted,
    "billing_caveat": "All returned days are estimated; November 11 is zero in this reading and today's foundation usage is not reconciled.",
    "excluded": ["tax", "new domain registration", "production", "24-hour capacity soak", "new GuardDuty/Config/CloudTrail archive coverage", "unbounded provider scans or reference feed catch-up"],
}
print(json.dumps(result, indent=2, default=str))
