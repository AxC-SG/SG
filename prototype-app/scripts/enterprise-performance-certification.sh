#!/usr/bin/env sh
set -eu

CERTIFICATION_STRICT="${CERTIFICATION_STRICT:-true}"
export CERTIFICATION_STRICT

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
API_KEY="${API_KEY:-change-me-in-prod}"
CREATOR_KEY="${CREATOR_KEY:-}"
OUT_DIR="${OUT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/vulnwatch-enterprise-certification.XXXXXX")}"
SEED_DEMO_DATA="${SEED_DEMO_DATA:-false}"
RUN_BASELINE="${RUN_BASELINE:-true}"
RUN_CORRELATION="${RUN_CORRELATION:-true}"
RUN_FINAL_SCORECARD="${RUN_FINAL_SCORECARD:-true}"
BASELINE_ITERATIONS="${BASELINE_ITERATIONS:-3}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-5}"
MAX_WAIT_SECONDS="${MAX_WAIT_SECONDS:-600}"
TRIGGER_ORG_CVE_RECOMPUTE="${TRIGGER_ORG_CVE_RECOMPUTE:-false}"
ORG_CVE_RECOMPUTE_MODE="${ORG_CVE_RECOMPUTE_MODE:-targeted}"
TRIGGER_FINDING_PROJECTION_REBUILD="${TRIGGER_FINDING_PROJECTION_REBUILD:-false}"
REQUIRE_QUEUE_DRAIN="${REQUIRE_QUEUE_DRAIN:-false}"
MAX_STALE_EVENTS="${MAX_STALE_EVENTS:-0}"
MAX_FAILED_EVENTS="${MAX_FAILED_EVENTS:-0}"
MAX_FAILED_GROWTH="${MAX_FAILED_GROWTH:-0}"
MAX_OLDEST_QUEUE_AGE_SECONDS="${MAX_OLDEST_QUEUE_AGE_SECONDS:-600}"
MAX_PROJECTION_LAG_SECONDS="${MAX_PROJECTION_LAG_SECONDS:-900}"
MAX_PENDING_GROWTH="${MAX_PENDING_GROWTH:-0}"
MAX_PROCESSING_GROWTH="${MAX_PROCESSING_GROWTH:-0}"
MAX_INGESTION_QUEUED_GROWTH="${MAX_INGESTION_QUEUED_GROWTH:-0}"
MAX_OLDEST_PROCESSING_AGE_SECONDS="${MAX_OLDEST_PROCESSING_AGE_SECONDS:-600}"
FAIL_ON_NONCOMPLIANT="${FAIL_ON_NONCOMPLIANT:-true}"
FAIL_ON_AUTH_SKIPS="${FAIL_ON_AUTH_SKIPS:-true}"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"

mkdir -p "$OUT_DIR"
manifest_file="$OUT_DIR/run-manifest.txt"
summary_file="$OUT_DIR/certification-summary.txt"

write_manifest() {
  {
    printf 'certification_strict=%s\n' "$CERTIFICATION_STRICT"
    printf 'base_url=%s\n' "$BASE_URL"
    printf 'seed_demo_data=%s\n' "$SEED_DEMO_DATA"
    printf 'run_baseline=%s\n' "$RUN_BASELINE"
    printf 'run_correlation=%s\n' "$RUN_CORRELATION"
    printf 'run_final_scorecard=%s\n' "$RUN_FINAL_SCORECARD"
    printf 'baseline_iterations=%s\n' "$BASELINE_ITERATIONS"
    printf 'poll_interval_seconds=%s\n' "$POLL_INTERVAL_SECONDS"
    printf 'max_wait_seconds=%s\n' "$MAX_WAIT_SECONDS"
    printf 'trigger_org_cve_recompute=%s\n' "$TRIGGER_ORG_CVE_RECOMPUTE"
    printf 'org_cve_recompute_mode=%s\n' "$ORG_CVE_RECOMPUTE_MODE"
    printf 'trigger_finding_projection_rebuild=%s\n' "$TRIGGER_FINDING_PROJECTION_REBUILD"
    printf 'require_queue_drain=%s\n' "$REQUIRE_QUEUE_DRAIN"
    printf 'max_stale_events=%s\n' "$MAX_STALE_EVENTS"
    printf 'max_failed_events=%s\n' "$MAX_FAILED_EVENTS"
    printf 'max_failed_growth=%s\n' "$MAX_FAILED_GROWTH"
    printf 'max_oldest_queue_age_seconds=%s\n' "$MAX_OLDEST_QUEUE_AGE_SECONDS"
    printf 'max_projection_lag_seconds=%s\n' "$MAX_PROJECTION_LAG_SECONDS"
    printf 'max_pending_growth=%s\n' "$MAX_PENDING_GROWTH"
    printf 'max_processing_growth=%s\n' "$MAX_PROCESSING_GROWTH"
    printf 'max_ingestion_queued_growth=%s\n' "$MAX_INGESTION_QUEUED_GROWTH"
    printf 'max_oldest_processing_age_seconds=%s\n' "$MAX_OLDEST_PROCESSING_AGE_SECONDS"
    printf 'fail_on_noncompliant=%s\n' "$FAIL_ON_NONCOMPLIANT"
  } >"$manifest_file"
}

json_scalar() {
  file="$1"
  field="$2"
  value="$(grep -o "\"$field\":[^,}]*" "$file" | head -n 1 | cut -d: -f2- || true)"
  value="$(printf '%s' "$value" | tr -d '\r' | sed 's/^"//; s/"$//' | tr -d '\n')"
  printf '%s' "$value"
}

baseline_status="SKIPPED"
correlation_status="SKIPPED"
final_scorecard_status="SKIPPED"
overall_status=0

write_manifest
if [ "$CERTIFICATION_STRICT" = "true" ] && { [ "$RUN_BASELINE" != "true" ] || [ "$RUN_CORRELATION" != "true" ] || [ "$RUN_FINAL_SCORECARD" != "true" ]; }; then
  echo "Strict certification requires all phases" >&2
  overall_status=1
fi

if [ "$RUN_BASELINE" = "true" ]; then
  echo "Running enterprise read-path baseline into $OUT_DIR/baseline"
  baseline_dir="$OUT_DIR/baseline"
  if OUT_DIR="$baseline_dir" \
    BASE_URL="$BASE_URL" \
    API_KEY="$API_KEY" \
    CREATOR_KEY="$CREATOR_KEY" \
    ITERATIONS="$BASELINE_ITERATIONS" \
    SEED_DEMO_DATA="$SEED_DEMO_DATA" \
    FAIL_ON_AUTH_SKIPS="$FAIL_ON_AUTH_SKIPS" \
    "$SCRIPT_DIR/performance-baseline.sh"; then
    baseline_status="PASS"
  else
    baseline_status="FAIL"
    overall_status=1
  fi
fi

if [ "$RUN_CORRELATION" = "true" ]; then
  echo "Running enterprise correlation certification into $OUT_DIR/correlation"
  correlation_dir="$OUT_DIR/correlation"
  if OUT_DIR="$correlation_dir" \
    BASE_URL="$BASE_URL" \
    API_KEY="$API_KEY" \
    CREATOR_KEY="$CREATOR_KEY" \
    POLL_INTERVAL_SECONDS="$POLL_INTERVAL_SECONDS" \
    MAX_WAIT_SECONDS="$MAX_WAIT_SECONDS" \
    TRIGGER_ORG_CVE_RECOMPUTE="$TRIGGER_ORG_CVE_RECOMPUTE" \
    ORG_CVE_RECOMPUTE_MODE="$ORG_CVE_RECOMPUTE_MODE" \
    TRIGGER_FINDING_PROJECTION_REBUILD="$TRIGGER_FINDING_PROJECTION_REBUILD" \
    REQUIRE_QUEUE_DRAIN="$REQUIRE_QUEUE_DRAIN" \
    MAX_STALE_EVENTS="$MAX_STALE_EVENTS" \
    MAX_FAILED_EVENTS="$MAX_FAILED_EVENTS" \
    MAX_FAILED_GROWTH="$MAX_FAILED_GROWTH" \
    MAX_OLDEST_QUEUE_AGE_SECONDS="$MAX_OLDEST_QUEUE_AGE_SECONDS" \
    MAX_PROJECTION_LAG_SECONDS="$MAX_PROJECTION_LAG_SECONDS" \
    MAX_PENDING_GROWTH="$MAX_PENDING_GROWTH" \
    MAX_PROCESSING_GROWTH="$MAX_PROCESSING_GROWTH" \
    MAX_INGESTION_QUEUED_GROWTH="$MAX_INGESTION_QUEUED_GROWTH" \
    MAX_OLDEST_PROCESSING_AGE_SECONDS="$MAX_OLDEST_PROCESSING_AGE_SECONDS" \
    FAIL_ON_NONCOMPLIANT="$FAIL_ON_NONCOMPLIANT" \
    RUN_BASELINE_AFTER="false" \
    "$SCRIPT_DIR/correlation-certification.sh"; then
    correlation_status="PASS"
  else
    correlation_status="FAIL"
    overall_status=1
  fi
fi

if [ "$RUN_FINAL_SCORECARD" = "true" ]; then
  echo "Capturing final enterprise scorecard into $OUT_DIR/final-scorecard"
  final_scorecard_dir="$OUT_DIR/final-scorecard"
  if OUT_DIR="$final_scorecard_dir" \
    BASE_URL="$BASE_URL" \
    API_KEY="$API_KEY" \
    CREATOR_KEY="$CREATOR_KEY" \
    "$SCRIPT_DIR/performance-scorecard.sh"; then
    final_scorecard_status="PASS"
    if [ "$FAIL_ON_NONCOMPLIANT" = "true" ]; then
      scorecard_overall="$(json_scalar "$final_scorecard_dir/performance-scorecard.json" "overallCompliant")"
      if [ "$scorecard_overall" != "true" ]; then
        final_scorecard_status="NON_COMPLIANT"
        overall_status=1
      fi
    fi
  else
    final_scorecard_status="FAIL"
    overall_status=1
  fi
fi

final_route_failures="n/a"
final_freshness_failures="n/a"
final_resource_failures="n/a"
final_resource_no_data="n/a"
if [ -f "$OUT_DIR/final-scorecard/performance-scorecard.json" ]; then
  final_route_failures="$(json_scalar "$OUT_DIR/final-scorecard/performance-scorecard.json" "routeFailureCount")"
  final_freshness_failures="$(json_scalar "$OUT_DIR/final-scorecard/performance-scorecard.json" "freshnessFailureCount")"
  final_resource_failures="$(json_scalar "$OUT_DIR/final-scorecard/performance-scorecard.json" "resourceFailureCount")"
  final_resource_no_data="$(json_scalar "$OUT_DIR/final-scorecard/performance-scorecard.json" "resourceNoDataCount")"
fi

final_slo_overall="n/a"
final_scorecard_overall="n/a"
final_pending_events="n/a"
final_processing_events="n/a"
final_ingestion_queued_jobs="n/a"
final_projection_stale="n/a"
if [ -f "$OUT_DIR/correlation/final-slo-status.json" ]; then
  final_slo_overall="$(json_scalar "$OUT_DIR/correlation/final-slo-status.json" "overallCompliant")"
fi
if [ -f "$OUT_DIR/correlation/final-performance-scorecard.json" ]; then
  final_scorecard_overall="$(json_scalar "$OUT_DIR/correlation/final-performance-scorecard.json" "overallCompliant")"
fi
if [ -f "$OUT_DIR/correlation/final-org-cves-status.json" ]; then
  final_pending_events="$(json_scalar "$OUT_DIR/correlation/final-org-cves-status.json" "pendingEventCount")"
  final_processing_events="$(json_scalar "$OUT_DIR/correlation/final-org-cves-status.json" "processingEventCount")"
  final_ingestion_queued_jobs="$(json_scalar "$OUT_DIR/correlation/final-org-cves-status.json" "ingestionQueuedJobCount")"
fi
if [ -f "$OUT_DIR/correlation/final-finding-projection-status.json" ]; then
  final_projection_stale="$(json_scalar "$OUT_DIR/correlation/final-finding-projection-status.json" "stale")"
fi

{
  printf 'Enterprise Performance Certification Summary\n'
  printf '==========================================\n'
  printf 'Output directory: %s\n' "$OUT_DIR"
  printf 'Baseline status: %s\n' "$baseline_status"
  printf 'Correlation certification status: %s\n' "$correlation_status"
  printf 'Final scorecard capture status: %s\n' "$final_scorecard_status"
  printf '\n'
  printf 'Final route failures: %s\n' "${final_route_failures:-n/a}"
  printf 'Final freshness failures: %s\n' "${final_freshness_failures:-n/a}"
  printf 'Final resource failures: %s\n' "${final_resource_failures:-n/a}"
  printf 'Final resource no-data count: %s\n' "${final_resource_no_data:-n/a}"
  printf '\n'
  printf 'Correlation final SLO overall compliant: %s\n' "${final_slo_overall:-n/a}"
  printf 'Correlation final scorecard overall compliant: %s\n' "${final_scorecard_overall:-n/a}"
  printf 'Final pending delta events: %s\n' "${final_pending_events:-n/a}"
  printf 'Final processing delta events: %s\n' "${final_processing_events:-n/a}"
  printf 'Final queued ingestion jobs: %s\n' "${final_ingestion_queued_jobs:-n/a}"
  printf 'Final projection stale: %s\n' "${final_projection_stale:-n/a}"
  printf '\n'
  printf 'Artifacts:\n'
  printf '  manifest: %s\n' "$manifest_file"
  printf '  baseline summary: %s\n' "$OUT_DIR/baseline/route-summary.tsv"
  printf '  correlation summary: %s\n' "$OUT_DIR/correlation/correlation-certification-summary.tsv"
  printf '  final scorecard: %s\n' "$OUT_DIR/final-scorecard/performance-scorecard.json"
} >"$summary_file"

cat "$summary_file"
exit "$overall_status"
