#!/usr/bin/env sh
set -eu

CERTIFICATION_STRICT="${CERTIFICATION_STRICT:-false}"
export CERTIFICATION_STRICT

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
API_KEY="${API_KEY:-change-me-in-prod}"
CREATOR_KEY="${CREATOR_KEY:-}"
OUT_DIR="${OUT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/vulnwatch-performance.XXXXXX")}"

mkdir -p "$OUT_DIR"

readiness_file="$OUT_DIR/readiness.json"
prometheus_file="$OUT_DIR/prometheus.txt"
scorecard_file="$OUT_DIR/performance-scorecard.json"
slo_file="$OUT_DIR/slo-status.json"
prometheus_exposure_hint="Enable Prometheus exposure with MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE=health,info,prometheus before running performance certification."

capture_public_endpoint() {
  path="$1"
  outfile="$2"
  label="$3"
  hint="${4:-}"
  error_file="$OUT_DIR/$(basename "$outfile").err"

  if ! curl -fsS "$BASE_URL$path" >"$outfile" 2>"$error_file"; then
    echo "Failed to fetch $label from $BASE_URL$path" >&2
    if [ -n "$hint" ]; then
      echo "$hint" >&2
    fi
    cat "$error_file" >&2 2>/dev/null || true
    exit 1
  fi
}

capture_authenticated_endpoint() {
  path="$1"
  outfile="$2"
  label="$3"
  hint="${4:-}"
  error_file="$OUT_DIR/$(basename "$outfile").err"

  if ! curl -fsS -H "X-API-Key: $API_KEY" "$BASE_URL$path" >"$outfile" 2>"$error_file"; then
    echo "Failed to fetch $label from $BASE_URL$path" >&2
    if [ -n "$hint" ]; then
      echo "$hint" >&2
    fi
    cat "$error_file" >&2 2>/dev/null || true
    exit 1
  fi
}

json_scalar() {
  file="$1"
  field="$2"
  value="$(grep -o "\"$field\":[^,}]*" "$file" | head -n 1 | cut -d: -f2- || true)"
  value="$(printf '%s' "$value" | tr -d '\r' | sed 's/^"//; s/"$//' | tr -d '[:space:]')"
  printf '%s' "${value:-}"
}

echo "Collecting readiness, Prometheus, and performance scorecard data from $BASE_URL"

capture_public_endpoint "/actuator/health/readiness" "$readiness_file" "readiness probe"
capture_authenticated_endpoint "/actuator/prometheus" "$prometheus_file" "Prometheus metrics" "$prometheus_exposure_hint"

if [ -n "$CREATOR_KEY" ]; then
  curl -fsS \
    -H "X-API-Key: $API_KEY" \
    -H "X-Creator-Key: $CREATOR_KEY" \
    "$BASE_URL/api/operations/performance-scorecard" >"$scorecard_file"

  curl -fsS \
    -H "X-API-Key: $API_KEY" \
    -H "X-Creator-Key: $CREATOR_KEY" \
    "$BASE_URL/api/slo/status" >"$slo_file"
else
  curl -fsS \
    -H "X-API-Key: $API_KEY" \
    "$BASE_URL/api/operations/performance-scorecard" >"$scorecard_file"
fi

overall="$(json_scalar "$scorecard_file" "overallCompliant")"
route_failures="$(json_scalar "$scorecard_file" "routeFailureCount")"
route_no_data="$(json_scalar "$scorecard_file" "routeNoDataCount")"
freshness_failures="$(json_scalar "$scorecard_file" "freshnessFailureCount")"
resource_failures="$(json_scalar "$scorecard_file" "resourceFailureCount")"
resource_no_data="$(json_scalar "$scorecard_file" "resourceNoDataCount")"

echo "Performance scorecard overall compliant: ${overall:-unknown}"
echo "Route failures: $route_failures"
echo "Routes without current samples: $route_no_data"
echo "Freshness failures in scorecard: ${freshness_failures:-unknown}"
echo "Resource ceiling failures: ${resource_failures:-unknown}"
echo "Resource ceiling checks without data: ${resource_no_data:-unknown}"
echo "Artifacts written to: $OUT_DIR"

if [ -f "$slo_file" ]; then
  slo_noncompliant="$(grep -o '"compliant":false' "$slo_file" | wc -l | tr -d '[:space:]')"
  echo "Non-compliant SLO entries: $slo_noncompliant"
fi

if [ "$CERTIFICATION_STRICT" = "true" ]; then
  SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
  if [ -n "$CREATOR_KEY" ]; then
    python3 "$SCRIPT_DIR/validate-certification.py" reports "$OUT_DIR" --require-slo
  else
    python3 "$SCRIPT_DIR/validate-certification.py" reports "$OUT_DIR"
  fi
fi
