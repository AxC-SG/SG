#!/usr/bin/env bash
# Sydney lab cycle: bring the only ScoutGrid environment up or park it.
#
#   lab.sh status       RDS, services, ALB, NAT, DNS and month-to-date cost against the $100 rule
#   lab.sh simulate     IAM simulation of every up and down action for the cycle role
#   lab.sh plan-up      saved plan for lab-up, checked against the up allowlist (no apply)
#   lab.sh up           start RDS, apply lab-up, wait for healthy API, update api-lab DNS, smoke test
#   lab.sh plan-down    saved plan for lab-down, checked against the down allowlist (no apply)
#   lab.sh down         simulate gate, apply lab-down, remove api-lab DNS, stop RDS
#
# Environment:
#   LAB_PROFILE   AWS CLI profile for the ScoutGridSydneyLabCycle role (default sglab-cycle)
#   TERRAFORM     Terraform 1.13.5 binary (default terraform)
#
# Never prints credentials. Cloudflare DNS uses a Keychain token (service scoutgrid-cloudflare-dns)
# limited to DNS Edit on scoutgrid.io; without it the script prints the record to set by hand.
# See ../README.md, ../grants/LAB_CYCLE_MATRIX.md and LAB_SOLE_ENVIRONMENT_PLAN.md.

set -euo pipefail

readonly ACCOUNT_ID="736486260824"
readonly REGION="ap-southeast-2"
readonly TF_REQUIRED="1.13.5"
readonly DB_ID="scoutgrid-lab"
readonly CLUSTER="scoutgrid-lab"
readonly TARGET_GROUP="scoutgrid-lab-api"
readonly ZONE_NAME="scoutgrid.io"
readonly API_HOST="api-lab.scoutgrid.io"
readonly CYCLE_ROLE="ScoutGridSydneyLabCycle"
readonly BUDGET_USD=100
readonly SHUTDOWN_MTD_USD=80

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly LAB_DIR="${SCRIPT_DIR%/scripts}"
readonly CFG="${LAB_DIR}/config"
TF_ROOT="$(cd "${LAB_DIR}/../../../infrastructure/terraform/standard" && pwd)"
readonly TF_ROOT
readonly PROFILE="${LAB_PROFILE:-sglab-cycle}"
readonly TF="${TERRAFORM:-terraform}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/scoutgrid-lab.XXXXXX")"
chmod 700 "${WORK}"
trap 'rm -rf "${WORK}"' EXIT

log() { printf '%s %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }
aws_lab() { aws --profile "${PROFILE}" --region "${REGION}" "$@"; }

guard_identity() {
  local account
  account="$(aws_lab sts get-caller-identity --query Account --output text)" ||
    die "No credentials for profile ${PROFILE}. Run: aws login --profile scoutgrid-lab --region ${REGION}"
  [[ "${account}" == "${ACCOUNT_ID}" ]] || die "Profile ${PROFILE} is account ${account}, not the lab ${ACCOUNT_ID}."
  [[ "$(aws --profile "${PROFILE}" configure get region || true)" == "${REGION}" ]] ||
    die "Profile ${PROFILE} must default to ${REGION}."
}

guard_terraform() {
  local version
  version="$("${TF}" version -json | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["terraform_version"])')"
  [[ "${version}" == "${TF_REQUIRED}" ]] || die "Terraform ${TF_REQUIRED} wrote the lab state; found ${version}."
}

with_credentials() {
  # Exported only into the Terraform child process environment.
  ( eval "$(aws configure export-credentials --profile "${PROFILE}" --format env)"
    export AWS_REGION="${REGION}"
    "$@" )
}

tf() { with_credentials "${TF}" -chdir="${TF_ROOT}" "$@"; }

tf_init() {
  tf init -input=false -no-color -lockfile=readonly \
    -backend-config="${CFG}/sydney-lab.s3.tfbackend" >/dev/null
}

# Exact var-file arguments for each mode. Later files win; each runtime file sets
# start_services, runtime_ingress_enabled and nat_gateway_mode explicitly.
runtime_file() {
  case "$1" in
    up) printf '%s' "${CFG}/runtime-running.tfvars" ;;
    down) printf '%s' "${CFG}/runtime-down.tfvars" ;;
    *) die "unknown mode $1" ;;
  esac
}

# Refuse any plan that touches something outside the mode's billable runtime set,
# deletes data or identity, or registers a task definition (Bootstrap path only).
check_plan() {
  local mode="$1" plan="$2"
  tf show -json "${plan}" | python3 -I -c '
import json, re, sys
mode = sys.argv[1]
runtime = [
    r"^module\.network\.aws_eip\.egress\[",
    r"^module\.network\.aws_nat_gateway\.zonal\[",
    r"^module\.network\.aws_route\.task_egress\[",
    r"^aws_lb\.api\[", r"^aws_lb_target_group\.api\[", r"^aws_lb_listener\.https\[",
    r"^aws_lb_listener_rule\.api\[", r"^aws_wafv2_web_acl\.api\[",
    r"^aws_wafv2_web_acl_association\.api\[", r"^aws_ecs_service\.backend\[",
]
allowed_actions = {"up": {("create",)}, "down": {("delete",)}}[mode]
changes, refused = [], []
for rc in json.load(sys.stdin).get("resource_changes", []):
    actions = tuple(rc["change"]["actions"])
    if actions in {("no-op",), ("read",)}:
        continue
    address = rc["address"]
    shown = "+".join(actions)
    changes.append(f"{shown:>14}  {address}")
    in_set = any(re.match(p, address) for p in runtime)
    if not in_set or actions not in allowed_actions:
        refused.append(f"{shown:>14}  {address}")
print("\n".join(changes) if changes else "(no changes)", file=sys.stderr)
if refused:
    print("\nREFUSED - outside the " + mode + " allowlist:", file=sys.stderr)
    print("\n".join(refused), file=sys.stderr)
    print("Task-definition, data, identity or foundation changes go through the reviewed Bootstrap/Apply path.", file=sys.stderr)
    sys.exit(3)
' "${mode}"
}

plan_mode() {
  local mode="$1" plan="${WORK}/$1.tfplan" runtime
  runtime="$(runtime_file "${mode}")"
  tf_init
  log "Planning lab-${mode}: sydney-lab.foundation.tfvars + ${runtime##*/}"
  tf plan -input=false -no-color -lock-timeout=60s -out="${plan}" \
    -var-file="${CFG}/sydney-lab.foundation.tfvars" -var-file="${runtime}" >/dev/null
  check_plan "${mode}" "${plan}"
  printf '%s\n' "${plan}"
}

confirm() {
  local answer
  read -r -p "$1 Type yes to continue: " answer </dev/tty
  [[ "${answer}" == "yes" ]] || die "Not confirmed; nothing applied."
}

db_status() {
  aws_lab rds describe-db-instances --db-instance-identifier "${DB_ID}" \
    --query 'DBInstances[0].DBInstanceStatus' --output text
}

start_database() {
  local status
  status="$(db_status)"
  case "${status}" in
    available) log "RDS already available." ;;
    stopped) log "Starting RDS (5-10 min)."; aws_lab rds start-db-instance --db-instance-identifier "${DB_ID}" >/dev/null ;;
    starting) log "RDS already starting." ;;
    *) die "RDS is ${status}; wait until it is stopped or available." ;;
  esac
  aws_lab rds wait db-instance-available --db-instance-identifier "${DB_ID}"
  log "RDS available."
}

stop_database() {
  local status
  status="$(db_status)"
  if [[ "${status}" == "available" ]]; then
    aws_lab rds stop-db-instance --db-instance-identifier "${DB_ID}" >/dev/null
    log "RDS stopping (finishes on its own in 5-10 min)."
    log "AWS restarts a stopped instance after 7 days: by $(date -u -v+7d +%Y-%m-%dT%H:%MZ 2>/dev/null || date -u -d '+7 days' +%Y-%m-%dT%H:%MZ). Run lab.sh down again before then."
  else
    log "RDS is ${status}; not stopping."
  fi
}

wait_api_healthy() {
  local tg deadline state
  tg="$(aws_lab elbv2 describe-target-groups --names "${TARGET_GROUP}" \
    --query 'TargetGroups[0].TargetGroupArn' --output text)"
  deadline=$(( $(date +%s) + 900 ))
  log "Waiting for a healthy API target (cold start is about 155 s)."
  while :; do
    state="$(aws_lab elbv2 describe-target-health --target-group-arn "${tg}" \
      --query 'TargetHealthDescriptions[].TargetHealth.State' --output text)"
    [[ " ${state} " == *" healthy "* ]] && { log "API target healthy."; return 0; }
    (( $(date +%s) < deadline )) || die "No healthy API target after 15 minutes (states: ${state:-none})."
    sleep 20
  done
}

alb_dns() {
  aws_lab elbv2 describe-load-balancers --names "${TARGET_GROUP}" \
    --query 'LoadBalancers[0].DNSName' --output text 2>/dev/null || true
}

cloudflare_token() {
  security find-generic-password -s scoutgrid-cloudflare-dns -w 2>/dev/null || true
}

# The token is passed to curl on stdin as a header file, never as an argument.
cf() {
  local method="$1" path="$2" body="${3:-}" token
  token="$(cloudflare_token)"
  [[ -n "${token}" ]] || return 2
  local -a args=(-fsS -X "${method}" -H @- -H 'Content-Type: application/json' "https://api.cloudflare.com/client/v4${path}")
  [[ -n "${body}" ]] && args+=(--data "${body}")
  printf 'Authorization: Bearer %s\n' "${token}" | curl "${args[@]}"
}

dns_record() {
  local zone record
  zone="$(cf GET "/zones?name=${ZONE_NAME}" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["result"][0]["id"])')" || return 2
  record="$(cf GET "/zones/${zone}/dns_records?type=CNAME&name=${API_HOST}" |
    python3 -I -c 'import json,sys; r=json.load(sys.stdin)["result"]; print(r[0]["id"]+" "+r[0]["content"] if r else "")')"
  printf '%s %s\n' "${zone}" "${record}"
}

dns_point_api_at() {
  local target="$1" zone id current body
  if [[ -z "$(cloudflare_token)" ]]; then
    log "No Cloudflare token in the Keychain. In Cloudflare set: CNAME ${API_HOST} -> ${target} (DNS only, TTL Auto)."
    return 0
  fi
  read -r zone id current < <(dns_record)
  body="$(python3 -I -c 'import json,sys; print(json.dumps({"type":"CNAME","name":sys.argv[1],"content":sys.argv[2],"proxied":False,"ttl":1,"comment":"Sydney lab API ALB; managed by lab.sh"}))' "${API_HOST}" "${target}")"
  if [[ -z "${id:-}" ]]; then
    cf POST "/zones/${zone}/dns_records" "${body}" >/dev/null
  elif [[ "${current}" != "${target}" ]]; then
    cf PUT "/zones/${zone}/dns_records/${id}" "${body}" >/dev/null
  fi
  log "DNS ${API_HOST} -> ${target}"
}

dns_remove_api() {
  local zone id current
  if [[ -z "$(cloudflare_token)" ]]; then
    log "No Cloudflare token in the Keychain. In Cloudflare delete the CNAME ${API_HOST}."
    return 0
  fi
  read -r zone id current < <(dns_record)
  if [[ -n "${id:-}" ]]; then
    cf DELETE "/zones/${zone}/dns_records/${id}" >/dev/null
    log "DNS ${API_HOST} removed (was ${current})."
  fi
}

smoke_test() {
  local _
  for _ in $(seq 1 20); do
    if curl -fsS -o /dev/null --max-time 10 "https://${API_HOST}/api/auth/csrf"; then
      log "Smoke test passed: https://${API_HOST}/api/auth/csrf"
      return 0
    fi
    sleep 15
  done
  die "Smoke test failed after DNS update; check DNS propagation and target health."
}

cost_summary() {
  local start end next mtd forecast
  start="$(date -u +%Y-%m-01)"
  end="$(date -u -v+1d +%Y-%m-%d 2>/dev/null || date -u -d '+1 day' +%Y-%m-%d)"
  next="$(date -u -v+1m -v1d +%Y-%m-%d 2>/dev/null || date -u -d "$(date -u +%Y-%m-01) +1 month" +%Y-%m-%d)"
  # Gross usage: credits are excluded so the rule tracks consumption, matching the budget alert.
  mtd="$(aws --profile "${PROFILE}" --region us-east-1 ce get-cost-and-usage \
    --time-period "Start=${start},End=${end}" --granularity MONTHLY --metrics UnblendedCost \
    --filter '{"Not":{"Dimensions":{"Key":"RECORD_TYPE","Values":["Credit","Refund"]}}}' \
    --query 'ResultsByTime[0].Total.UnblendedCost.Amount' --output text 2>/dev/null || echo unknown)"
  forecast="$(aws --profile "${PROFILE}" --region us-east-1 ce get-cost-forecast \
    --time-period "Start=${end},End=${next}" --granularity MONTHLY --metric UNBLENDED_COST \
    --filter '{"Not":{"Dimensions":{"Key":"RECORD_TYPE","Values":["Credit","Refund"]}}}' \
    --query 'Total.Amount' --output text 2>/dev/null || echo unknown)"
  # shellcheck disable=SC2016  # Python source, not shell expansion.
  python3 -I -c '
import sys
mtd, forecast, budget, trigger = sys.argv[1:5]
def num(v):
    try: return float(v)
    except ValueError: return None
m, f = num(mtd), num(forecast)
shown = mtd if m is None else "$" + format(m, ",.2f")
print(f"Usage month-to-date (gross, before credits): {shown}  (Cost Explorer lags by hours)")
if m is not None and f is None:
    print("Projection unavailable (Cost Explorer needs more history); apply the rule to month-to-date only.")
    if m >= float(trigger):
        print(f"SHUTDOWN RULE TRIGGERED: month-to-date >= ${float(trigger):,.0f}. Run lab.sh down today.")
if m is not None and f is not None:
    total = m + f
    print(f"Projected month-end: ${total:,.2f} against the ${float(budget):,.0f} ceiling")
    if m >= float(trigger) or total > float(budget):
        print(f"SHUTDOWN RULE TRIGGERED: month-to-date >= ${float(trigger):,.0f} or projection > ${float(budget):,.0f}. Run lab.sh down today.")
' "${mtd}" "${forecast}" "${BUDGET_USD}" "${SHUTDOWN_MTD_USD}"
}

cmd_status() {
  guard_identity
  printf 'RDS %s: %s\n' "${DB_ID}" "$(db_status)"
  aws_lab ecs describe-services --cluster "${CLUSTER}" --services api worker \
    --query 'services[].[serviceName,status,desiredCount,runningCount]' --output text 2>/dev/null |
    awk '{printf "Service %s: %s desired=%s running=%s\n", $1, $2, $3, $4}' || echo "Services: none"
  local alb
  alb="$(alb_dns)"
  printf 'ALB: %s\n' "${alb:-none}"
  printf 'NAT gateways: %s\n' "$(aws_lab ec2 describe-nat-gateways \
    --filter Name=tag:Environment,Values=lab Name=state,Values=pending,available \
    --query 'length(NatGateways)' --output text)"
  printf 'DNS %s: %s\n' "${API_HOST}" "$(dig +short CNAME "${API_HOST}" 2>/dev/null | head -1 || true)"
  cost_summary
}

# Representative ARNs: the simulator evaluates resource patterns and the context below.
cmd_simulate() {
  guard_identity
  local role="arn:aws:iam::${ACCOUNT_ID}:role/${CYCLE_ROLE}"
  local ec2="arn:aws:ec2:${REGION}:${ACCOUNT_ID}" elb="arn:aws:elasticloadbalancing:${REGION}:${ACCOUNT_ID}"
  local waf="arn:aws:wafv2:${REGION}:${ACCOUNT_ID}:regional/webacl/scoutgrid-lab-api/00000000-0000-0000-0000-000000000000"
  local alb="${elb}:loadbalancer/app/scoutgrid-lab-api/0000000000000000"
  local tg="${elb}:targetgroup/scoutgrid-lab-api/0000000000000000"
  local listener="${elb}:listener/app/scoutgrid-lab-api/0000000000000000/0000000000000000"
  local rule="${elb}:listener-rule/app/scoutgrid-lab-api/0000000000000000/0000000000000000/0000000000000000"
  local svc="arn:aws:ecs:${REGION}:${ACCOUNT_ID}:service/${CLUSTER}"
  local db="arn:aws:rds:${REGION}:${ACCOUNT_ID}:db:${DB_ID}"
  local rtb="${ec2}:route-table/rtb-0ea5f3d8c7fee4ee9"
  python3 -I -c '
import json, sys
region, account = sys.argv[1:3]
tags = {"Application": "ScoutGrid", "Environment": "lab", "Profile": "Standard", "ManagedBy": "Terraform"}
ctx = {"aws:RequestedRegion": region,
       "elasticloadbalancing:Scheme": "internet-facing",
       "elasticloadbalancing:ListenerProtocol": "HTTPS",
       "elasticloadbalancing:SecurityPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
       "ec2:CreateAction": "CreateNatGateway", "ecs:CreateAction": "CreateService",
       "ecs:cluster": f"arn:aws:ecs:{region}:{account}:cluster/scoutgrid-lab",
       "ecs:task-definition": f"arn:aws:ecs:{region}:{account}:task-definition/scoutgrid-lab-api:9",
       "iam:PassedToService": "ecs-tasks.amazonaws.com",
       "iam:AWSServiceName": "elasticloadbalancing.amazonaws.com"}
ctx.update({f"aws:RequestTag/{k}": v for k, v in tags.items()})
ctx.update({f"aws:ResourceTag/{k}": v for k, v in tags.items()})
print(json.dumps([{"ContextKeyName": k, "ContextKeyValues": [v], "ContextKeyType": "string"} for k, v in ctx.items()]))
' "${REGION}" "${ACCOUNT_ID}" >"${WORK}/context.json"

  # elasticloadbalancing:SetWebAcl is granted but not simulated: the IAM simulator does not know the
  # action (it returns implicitDeny with no matched statements even for the Apply role that used the
  # same grant live on November 12, 2026).
  local -a checks=(
    "up ec2:AllocateAddress ${ec2}:elastic-ip/eipalloc-00000000000000000"
    "up ec2:CreateNatGateway ${ec2}:natgateway/nat-00000000000000000"
    "up ec2:CreateNatGateway ${ec2}:subnet/subnet-00000000000000000"
    "up ec2:CreateNatGateway ${ec2}:elastic-ip/eipalloc-00000000000000000"
    "up ec2:CreateTags ${ec2}:natgateway/nat-00000000000000000"
    "up ec2:CreateRoute ${rtb}"
    "up ec2:DescribeAccountAttributes *"
    "up elasticloadbalancing:CreateLoadBalancer ${alb}"
    "up elasticloadbalancing:CreateTargetGroup ${tg}"
    "up elasticloadbalancing:CreateListener ${alb}"
    "up elasticloadbalancing:CreateRule ${listener}"
    "up elasticloadbalancing:ModifyLoadBalancerAttributes ${alb}"
    "up elasticloadbalancing:ModifyTargetGroupAttributes ${tg}"
    "up elasticloadbalancing:AddTags ${alb}"
    "up wafv2:CreateWebACL ${waf}"
    "up wafv2:TagResource ${waf}"
    "up wafv2:AssociateWebACL ${waf}"
    "up wafv2:AssociateWebACL ${alb}"
    "up ecs:CreateService ${svc}/api"
    "up ecs:CreateService ${svc}/worker"
    "up ecs:TagResource ${svc}/api"
    "up iam:PassRole arn:aws:iam::${ACCOUNT_ID}:role/scoutgrid-lab-api-task"
    "up iam:PassRole arn:aws:iam::${ACCOUNT_ID}:role/scoutgrid-lab-worker-execution"
    "up rds:StartDBInstance ${db}"
    "up s3:GetBucketWebsite arn:aws:s3:::scoutgrid-lab-${ACCOUNT_ID}-imports"
    "down ecs:UpdateService ${svc}/api"
    "down ecs:DeleteService ${svc}/worker"
    "down elasticloadbalancing:DeleteLoadBalancer ${alb}"
    "down elasticloadbalancing:DeleteListener ${listener}"
    "down elasticloadbalancing:DeleteRule ${rule}"
    "down elasticloadbalancing:DeleteTargetGroup ${tg}"
    "down wafv2:DisassociateWebACL ${alb}"
    "down wafv2:DeleteWebACL ${waf}"
    "down ec2:DeleteNatGateway ${ec2}:natgateway/nat-00000000000000000"
    "down ec2:DisassociateAddress ${ec2}:elastic-ip/eipalloc-00000000000000000"
    "down ec2:ReleaseAddress ${ec2}:elastic-ip/eipalloc-00000000000000000"
    "down ec2:DeleteRoute ${rtb}"
    "down rds:StopDBInstance ${db}"
  )
  local only="${1:-all}" denied=0 phase action resource decision
  for check in "${checks[@]}"; do
    read -r phase action resource <<<"${check}"
    [[ "${only}" == "all" || "${only}" == "${phase}" ]] || continue
    decision="$(aws_lab iam simulate-principal-policy --policy-source-arn "${role}" \
      --action-names "${action}" --resource-arns "${resource}" \
      --context-entries "file://${WORK}/context.json" \
      --query 'EvaluationResults[0].EvalDecision' --output text)"
    printf '%-5s %-9s %-46s %s\n' "${phase}" "${decision}" "${action}" "${resource##*:}"
    [[ "${decision}" == "allowed" ]] || denied=$((denied + 1))
  done
  (( denied == 0 )) || die "${denied} simulated action(s) denied for ${CYCLE_ROLE}."
  log "Simulation passed (${only})."
}

cmd_plan() {
  guard_identity
  guard_terraform
  plan_mode "$1" >/dev/null
  log "Plan-only: nothing applied."
}

cmd_up() {
  guard_identity
  guard_terraform
  start_database
  local plan
  plan="$(plan_mode up)"
  confirm "Lab-up creates NAT egress, the API load balancer, WAF and both services (about \$0.30/hour while up)."
  tf apply -input=false -no-color -lock-timeout=60s "${plan}" >/dev/null
  log "Lab-up applied."
  wait_api_healthy
  dns_point_api_at "$(alb_dns)"
  smoke_test
  cmd_status
}

cmd_down() {
  guard_identity
  guard_terraform
  cmd_simulate up
  local plan
  plan="$(plan_mode down)"
  confirm "Lab-down takes scoutgrid.io sign-in and the demo form offline until the next lab-up."
  tf apply -input=false -no-color -lock-timeout=60s "${plan}" >/dev/null
  log "Lab-down applied."
  dns_remove_api
  stop_database
  cmd_status
}

case "${1:-}" in
  status) cmd_status ;;
  simulate) cmd_simulate "${2:-all}" ;;
  plan-up) cmd_plan up ;;
  plan-down) cmd_plan down ;;
  up) cmd_up ;;
  down) cmd_down ;;
  *) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
