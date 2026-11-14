#!/usr/bin/env bash
# Stubs are called indirectly by lab.sh, and scenario overrides are eval'd later.
# shellcheck disable=SC2329,SC2016
# Offline tests for lab.sh failure handling. No AWS, Terraform or Cloudflare access:
# every cloud call is replaced by a stub that records the step it would take.
#
#   bash prototype-app/infrastructure/lab/scripts/tests/lab.test.sh

set -uo pipefail

LAB_SH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lab.sh"
STEPS="$(mktemp "${TMPDIR:-/tmp}/lab-test.XXXXXX")"
trap 'rm -f "${STEPS}"' EXIT
failures=0

# Runs one scenario in a subshell: loads lab.sh, stubs every external step, applies the
# scenario's overrides ($2), runs the command ($3) and prints the exit code.
run_case() {
  : >"${STEPS}"
  (
    # shellcheck source=/dev/null
    source "${LAB_SH}"
    set +e
    step() { printf '%s\n' "$1" >>"${STEPS}"; }
    guard_identity() { :; }
    guard_terraform() { :; }
    cmd_simulate() { :; }
    plan_mode() { printf '%s\n' "/tmp/$1.tfplan"; }
    confirm() { step confirm; }
    tf() { step "tf $1"; }
    start_database() { step start_db; }
    stop_database() { step stop_db; }
    dns_remove_api() { step dns_remove; }
    dns_point_api_at() { step dns_point; }
    wait_api_healthy() { :; }
    alb_dns() { printf 'alb.example\n'; }
    smoke_test() { :; }
    cmd_status() { step status; }
    log() { :; }
    eval "$2"
    set -e
    "$3"
  ) >/dev/null 2>&1
  printf '%s\n' "$?"
}

# Like run_case, but keeps lab.sh's own helpers and stubs only the cloud calls in $2.
run_helper() {
  : >"${STEPS}"
  (
    # shellcheck source=/dev/null
    source "${LAB_SH}"
    set +e
    step() { printf '%s\n' "$1" >>"${STEPS}"; }
    log() { :; }
    eval "$2"
    set -e
    "$3"
  ) >/dev/null 2>&1
  printf '%s\n' "$?"
}

steps() { paste -sd, "${STEPS}"; }

expect() {
  local name="$1" actual="$2" expected="$3"
  if [[ "${actual}" == "${expected}" ]]; then
    printf 'ok   %s\n' "${name}"
  else
    printf 'FAIL %s\n     expected: %s\n     actual:   %s\n' "${name}" "${expected}" "${actual}"
    failures=$((failures + 1))
  fi
}

code="$(run_case down-ok '' cmd_down)"
expect "down stops RDS before removing DNS" "${code}:$(steps)" "0:confirm,tf apply,stop_db,dns_remove,status"

code="$(run_case down-dns-fails 'dns_remove_api() { step dns_remove; return 1; }' cmd_down)"
expect "down still stops RDS when DNS removal fails, and exits 1" "${code}:$(steps)" "1:confirm,tf apply,stop_db,dns_remove,status"

code="$(run_case down-db-fails 'stop_database() { step stop_db; return 1; }' cmd_down)"
expect "down still removes DNS when stopping RDS fails, and exits 1" "${code}:$(steps)" "1:confirm,tf apply,stop_db,dns_remove,status"

code="$(run_case down-apply-fails 'tf() { step "tf $1"; return 1; }' cmd_down)"
expect "down keeps RDS and DNS when the apply fails" "${code}:$(steps)" "1:confirm,tf apply"

code="$(run_case up-ok '' cmd_up)"
expect "up starts RDS only after confirmation" "${code}:$(steps)" "0:confirm,start_db,tf apply,dns_point,status"

code="$(run_case up-declined 'confirm() { step confirm; die "Not confirmed"; }' cmd_up)"
expect "up leaves RDS parked when not confirmed" "${code}:$(steps)" "1:confirm"

code="$(run_case up-apply-fails 'tf() { step "tf $1"; return 1; }' cmd_up)"
expect "up stops at a failed apply" "${code}:$(steps)" "1:confirm,start_db,tf apply"

# The real helpers must report failure instead of logging success.
code="$(run_helper dns-delete-fails '
  cloudflare_token() { printf token; }
  dns_record() { printf "zone1 rec1 old.example\n"; }
  cf() { step "cf $1"; return 22; }' dns_remove_api)"
expect "dns_remove_api returns 1 when the Cloudflare delete fails" "${code}:$(steps)" "1:cf DELETE"

code="$(run_helper dns-read-fails '
  cloudflare_token() { printf token; }
  dns_record() { return 2; }
  cf() { step "cf $1"; }' dns_remove_api)"
expect "dns_remove_api returns 1 when the record cannot be read" "${code}:$(steps)" "1:"

code="$(run_helper db-stop-fails '
  db_status() { printf available; }
  aws_lab() { step "aws $2"; return 254; }' stop_database)"
expect "stop_database returns 1 when the stop request fails" "${code}:$(steps)" "1:aws stop-db-instance"

if (( failures )); then
  printf '\n%d failed\n' "${failures}"
  exit 1
fi
printf '\nall passed\n'
