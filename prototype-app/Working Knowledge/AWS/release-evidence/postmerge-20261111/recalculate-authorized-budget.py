"""Recalculate the authorized inclusive lab allocation from retained evidence."""
from decimal import Decimal as D
from pathlib import Path
import json

root = Path(__file__).resolve().parent
prior = json.loads((root / "prior-run-budget-bound.json").read_text())
billing = json.loads((root / "billing-api-refresh-20261112.json").read_text())["return_value"]
posted = sum(D(x["Total"]["UnblendedCost"]["Amount"]) for x in billing["billing"]["ResultsByTime"])
tax = D(prior["tax_assumption"])
prior_bound = (sum(D(v) for v in prior["prior_cost_items"].values()) + posted) * (1 + tax) + D("0.50")
ceiling, reserve = D("50"), D("25")
scenarios = {}
for hours in ("4", "8"):
    before = D(prior["application_scenarios"][hours]["before_tax"])
    inclusive = before * (1 + tax) + D("0.50")
    assert inclusive <= reserve
    scenarios[hours] = {"before_tax_usd": str(before), "including_tax_and_variance_usd": str(inclusive), "reserve_margin_usd": str(reserve - inclusive)}
assert prior_bound + reserve <= ceiling
result = {
    "status": "authorized allocation; conservative planning estimate, not a final bill or guaranteed hard cost cap",
    "account": "736486260824", "region": "ap-southeast-2", "authorized_date": "2026-11-11", "billing_observed_utc": billing["observed_utc"],
    "authorization": "Owner continuation prompt supersedes older $20 monthly/$15 run and unapproved-budget statements; no repeat budget approval required.",
    "monthly_ceiling_including_prior_unposted_tax_contingency_usd": str(ceiling),
    "application_run_reserve_inclusive_usd": str(reserve),
    "prior_run_bound_including_tax_variance_usd": str(prior_bound),
    "combined_allocated_usd": str(prior_bound + reserve),
    "unallocated_monthly_headroom_usd": str(ceiling - prior_bound - reserve),
    "estimated_posted_excluding_credits_refunds_usd": str(posted),
    "prior_unposted_accounting": "Bound includes posted charges additionally, two fixed-component hours, full-month retired-key/secret allowance, usage/storage reserves, 18% tax and $0.50 variance. Missing data is not zero; posted foundation charges are not netted off the retained bound, deliberately avoiding undercounting; final usage and tax remain unreconciled.",
    "tax_assumption": str(tax), "tax_source": "https://aws.amazon.com/tax-help/india/",
    "application_scenarios": scenarios,
    "target_hours": 4, "cleanup_completed_by_hours": 8,
    "clock_start": "first new billable application dependency creation",
    "operational_boundary": "Start cleanup at hour four if tests are incomplete, sooner on failure, unexpected usage or loss of cleanup capability. Finish by eight hours. Do not exceed $25 run reserve or $50 inclusive monthly ceiling. Contingency is not permission to extend duration or scope.",
    "operator": "Codex executes and verifies cleanup in the active chat; owner is fallback",
    "excluded": prior["excluded"],
    "remaining_release_access_secret_preconditions_not_waived": True,
    "billable_stack_started": False,
}
print(json.dumps(result, indent=2))
