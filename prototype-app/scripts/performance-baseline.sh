#!/usr/bin/env sh
set -eu

CERTIFICATION_STRICT="${CERTIFICATION_STRICT:-false}"
export CERTIFICATION_STRICT

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
API_KEY="${API_KEY:-change-me-in-prod}"
CREATOR_KEY="${CREATOR_KEY:-}"
OUT_DIR="${OUT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/vulnwatch-baseline.XXXXXX")}"
ITERATIONS="${ITERATIONS:-3}"
SEED_DEMO_DATA="${SEED_DEMO_DATA:-false}"
ROUTE_AUTH_MODE="${ROUTE_AUTH_MODE:-auto}"
ROUTE_BEARER_TOKEN="${ROUTE_BEARER_TOKEN:-}"
ROUTE_LOGIN_EMAIL="${ROUTE_LOGIN_EMAIL:-tenant.admin@localhost}"
ROUTE_LOGIN_PASSWORD="${ROUTE_LOGIN_PASSWORD:-LocalDevTenant123!}"
SETTLE_MAX_WAIT_SECONDS="${SETTLE_MAX_WAIT_SECONDS:-90}"
SETTLE_POLL_INTERVAL_SECONDS="${SETTLE_POLL_INTERVAL_SECONDS:-5}"
FAIL_ON_AUTH_SKIPS="${FAIL_ON_AUTH_SKIPS:-false}"
SEED_ALLOWED_PROFILES="${SEED_ALLOWED_PROFILES:-local test certification}"
SEED_ALLOWED_BASE_URLS="${SEED_ALLOWED_BASE_URLS:-http://127.0.0.1:8080 http://localhost:8080}"
ROUTE_AUTH_NOTE=""

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
if [ "$CERTIFICATION_STRICT" = "true" ]; then
  python3 "$SCRIPT_DIR/validate-certification.py" iterations "$ITERATIONS"
fi

mkdir -p "$OUT_DIR"

routes_file="$OUT_DIR/routes.tsv"
samples_file="$OUT_DIR/route-samples.tsv"
summary_file="$OUT_DIR/route-summary.tsv"

cat >"$routes_file" <<'EOF'
dashboard-summary	/api/dashboard
dashboard-applicable-software	/api/dashboard/applicable-software?page=0&size=10
dashboard-impacted-cves	/api/dashboard/impacted-cves?page=0&size=10
dashboard-cve-inventory-map	/api/dashboard/cve-inventory-map?limit=5
findings-list	/api/findings?page=0&size=25
findings-summary	/api/findings/summary
findings-distributions	/api/findings/distributions
findings-backlog-health	/api/findings/backlog-health
findings-filters	/api/findings/filters
findings-projection-status	/api/findings/projection-status
inventory-components	/api/inventory/components?page=0&size=25
inventory-component-filters	/api/inventory/components/filters
software-identities	/api/inventory/software-identities?page=0&size=25
software-identity-funnel	/api/inventory/software-identities/funnel
vulnerability-intelligence-list	/api/vulnerability-intelligence?page=0&size=25
vulnerability-intelligence-filters	/api/vulnerability-intelligence/filters
vuln-repo-dashboard	/api/vuln-repo/dashboard
vuln-repo-vulnerabilities	/api/vuln-repo/vulnerabilities?page=0&size=25
vuln-repo-org-cves	/api/vuln-repo/org-cves?page=0&size=25
vuln-repo-org-cves-status	/api/vuln-repo/org-cves/status
EOF

printf 'route\titeration\tstatus\trequest_id\tserver_timing\tclassification\n' >"$samples_file"

json_token() {
  file="$1"
  token_line="$(grep -o '"token"[[:space:]]*:[[:space:]]*"[^"]*"' "$file" | head -n 1 || true)"
  printf '%s' "$token_line" | sed 's/^[^"]*"token"[[:space:]]*:[[:space:]]*"//; s/"$//'
}

attempt_route_login() {
  login_body="$OUT_DIR/route-login.json"
  login_headers="$OUT_DIR/route-login.headers"
  login_payload="$(cat <<EOF
{"email":"$ROUTE_LOGIN_EMAIL","password":"$ROUTE_LOGIN_PASSWORD"}
EOF
)"

  curl -sS \
    -D "$login_headers" \
    -o "$login_body" \
    -H "Content-Type: application/json" \
    -X POST \
    "$BASE_URL/api/auth/login" \
    --data "$login_payload" >/dev/null || return 1

  login_status="$(awk 'NR==1 {print $2}' "$login_headers")"
  if [ "${login_status:-}" != "200" ]; then
    ROUTE_AUTH_NOTE="$(tr -d '\r' <"$login_body" 2>/dev/null || true)"
    return 1
  fi

  ROUTE_BEARER_TOKEN="$(json_token "$login_body")"
  [ -n "$ROUTE_BEARER_TOKEN" ]
}

route_request() {
  route_path="$1"
  headers_file="$2"
  body_file="$3"

  if [ -n "$ROUTE_BEARER_TOKEN" ]; then
    curl -sS \
      -D "$headers_file" \
      -o "$body_file" \
      -H "Authorization: Bearer $ROUTE_BEARER_TOKEN" \
      "$BASE_URL$route_path" >/dev/null
    return
  fi

  if [ -n "$CREATOR_KEY" ]; then
    curl -sS \
      -D "$headers_file" \
      -o "$body_file" \
      -H "X-API-Key: $API_KEY" \
      -H "X-Creator-Key: $CREATOR_KEY" \
      "$BASE_URL$route_path" >/dev/null
    return
  fi

  curl -sS \
    -D "$headers_file" \
    -o "$body_file" \
    -H "X-API-Key: $API_KEY" \
    "$BASE_URL$route_path" >/dev/null
}

seed_profile_is_allowed() {
  profiles="$(printf '%s' "${SPRING_PROFILES_ACTIVE:-}" | tr ',' ' ')"
  for profile in $profiles; do
    for allowed in $SEED_ALLOWED_PROFILES; do
      if [ "$profile" = "$allowed" ]; then
        return 0
      fi
    done
  done
  return 1
}

seed_base_url_is_allowed() {
  for allowed in $SEED_ALLOWED_BASE_URLS; do
    if [ "$BASE_URL" = "$allowed" ]; then
      return 0
    fi
  done
  return 1
}

guard_demo_seeding() {
  if ! seed_profile_is_allowed; then
    echo "Refusing demo seeding: SPRING_PROFILES_ACTIVE='${SPRING_PROFILES_ACTIVE:-}' is not in the approved allowlist: $SEED_ALLOWED_PROFILES" >&2
    exit 1
  fi
  if ! seed_base_url_is_allowed; then
    echo "Refusing demo seeding: BASE_URL='$BASE_URL' is not in the approved allowlist: $SEED_ALLOWED_BASE_URLS" >&2
    exit 1
  fi
}

warmup_slos_are_settled() {
  settle_file="$OUT_DIR/settle-slo.json"
  if [ -n "$CREATOR_KEY" ]; then
    curl -fsS \
      -H "X-API-Key: $API_KEY" \
      -H "X-Creator-Key: $CREATOR_KEY" \
      "$BASE_URL/api/slo/status" >"$settle_file" || return 1
  else
    return 0
  fi

  payload="$(tr -d '\n' <"$settle_file")"
  for slo_name in delta_queue_depth delta_queue_processing_depth delta_queue_processing_oldest_age finding_projection_freshness; do
    if printf '%s' "$payload" | grep -q "\"name\":\"$slo_name\".*\"compliant\":false"; then
      return 1
    fi
  done
  return 0
}

wait_for_settle() {
  if [ "$SETTLE_MAX_WAIT_SECONDS" -le 0 ] || [ -z "$CREATOR_KEY" ]; then
    return
  fi

  elapsed=0
  while [ "$elapsed" -lt "$SETTLE_MAX_WAIT_SECONDS" ]; do
    if warmup_slos_are_settled; then
      if [ "$elapsed" -gt 0 ]; then
        echo "Warmup queue settled after ${elapsed}s"
      fi
      return
    fi
    sleep "$SETTLE_POLL_INTERVAL_SECONDS"
    elapsed=$((elapsed + SETTLE_POLL_INTERVAL_SECONDS))
  done

  echo "Warmup queue did not fully settle within ${SETTLE_MAX_WAIT_SECONDS}s; continuing with latest SLO state"
}

if [ -z "$ROUTE_BEARER_TOKEN" ] && [ "$ROUTE_AUTH_MODE" != "api-key" ]; then
  if attempt_route_login; then
    echo "Using tenant-scoped JWT login for route sampling"
  elif [ "$ROUTE_AUTH_MODE" = "jwt" ]; then
    echo "Failed to obtain route JWT for tenant-scoped sampling" >&2
    exit 1
  else
    echo "Falling back to API-key route sampling"
    if [ -n "$ROUTE_AUTH_NOTE" ]; then
      echo "Route JWT login was unavailable: $ROUTE_AUTH_NOTE"
    fi
  fi
fi

if [ "$SEED_DEMO_DATA" = "true" ]; then
  guard_demo_seeding
  echo "!!! Seeding demo advisory data before baseline collection against $BASE_URL using profile ${SPRING_PROFILES_ACTIVE:-unset} !!!"
  if [ -n "$CREATOR_KEY" ]; then
    curl -fsS \
      -H "X-API-Key: $API_KEY" \
      -H "X-Creator-Key: $CREATOR_KEY" \
      -X POST \
      "$BASE_URL/api/demo/seed" >/dev/null
  else
    curl -fsS \
      -H "X-API-Key: $API_KEY" \
      -X POST \
      "$BASE_URL/api/demo/seed" >/dev/null
  fi
fi

wait_for_settle

echo "Collecting route samples into $OUT_DIR"

iteration=1
while [ "$iteration" -le "$ITERATIONS" ]; do
  while IFS="$(printf '\t')" read -r route_key route_path; do
    [ -n "$route_key" ] || continue
    headers_file="$OUT_DIR/${route_key}-${iteration}.headers"
    body_file="$OUT_DIR/${route_key}-${iteration}.body"

    route_request "$route_path" "$headers_file" "$body_file"

    status_code="$(awk 'NR==1 {print $2}' "$headers_file")"
    request_id="$(awk 'tolower($0) ~ /^x-request-id:/ {sub(/\r$/, "", $0); sub(/^[^:]+:[[:space:]]*/, "", $0); print $0}' "$headers_file" | tail -n 1)"
    server_timing="$(awk 'tolower($0) ~ /^server-timing:/ {sub(/\r$/, "", $0); sub(/^[^:]+:[[:space:]]*/, "", $0); print $0}' "$headers_file" | tail -n 1)"
    classification="ok"
    if [ "${status_code:-}" = "403" ] && grep -q 'Tenant context is required\|Platform owner must switch into an approved tenant context' "$body_file"; then
      classification="tenant_context_required"
    elif [ "${status_code:-unknown}" != "${status_code#2}" ]; then
      classification="ok"
    elif [ "${status_code:-unknown}" != "${status_code#3}" ]; then
      classification="redirect"
    else
      classification="http_failure"
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$route_key" \
      "$iteration" \
      "${status_code:-unknown}" \
      "${request_id:-missing}" \
      "${server_timing:-missing}" \
      "$classification" >>"$samples_file"
  done <"$routes_file"
  iteration=$((iteration + 1))
done

wait_for_settle

awk -F '\t' '
BEGIN {
  OFS = "\t";
}
NR > 1 {
  samples[$1] += 1;
  if ($6 == "tenant_context_required") {
    auth_skips[$1] += 1;
  } else if ($3 !~ /^2/) {
    failures[$1] += 1;
  }
  if ($5 == "missing") {
    missing[$1] += 1;
  }
}
END {
  for (route in samples) {
    print route, samples[route], failures[route] + 0, missing[route] + 0, auth_skips[route] + 0;
  }
}
' "$samples_file" | sort >"$summary_file.tmp"

{
  printf 'route\tsamples\tfailures\tmissing_server_timing\tauth_skips\n'
  cat "$summary_file.tmp"
} >"$summary_file"
rm -f "$summary_file.tmp"

echo "Route sample summary:"
cat "$summary_file"

if [ "$FAIL_ON_AUTH_SKIPS" = "true" ]; then
  auth_skip_failures="$(awk -F '\t' '
  NR == 1 { next }
  ($2 + 0) > 0 && ($2 + 0) == ($5 + 0) {
    print $1
  }
  ' "$summary_file")"
  if [ -n "$auth_skip_failures" ]; then
    echo "Certification route sampling is invalid because these routes only returned tenant/auth skips:" >&2
    printf '%s\n' "$auth_skip_failures" >&2
    exit 1
  fi
fi

echo "Collecting scorecard and SLO artifacts"
OUT_DIR="$OUT_DIR" \
BASE_URL="$BASE_URL" \
API_KEY="$API_KEY" \
CREATOR_KEY="$CREATOR_KEY" \
"$(dirname "$0")/performance-scorecard.sh"

if [ "$CERTIFICATION_STRICT" = "true" ]; then
  python3 "$SCRIPT_DIR/validate-certification.py" baseline "$routes_file" "$samples_file" "$ITERATIONS"
fi

echo "Baseline collection complete: $OUT_DIR"
