#!/usr/bin/env sh
set -eu

CERTIFICATION_STRICT="${CERTIFICATION_STRICT:-false}"
export CERTIFICATION_STRICT

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
API_KEY="${API_KEY:-change-me-in-prod}"
CREATOR_KEY="${CREATOR_KEY:-}"
OUT_DIR="${OUT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/vulnwatch-correlation.XXXXXX")}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-5}"
MAX_WAIT_SECONDS="${MAX_WAIT_SECONDS:-600}"
TRIGGER_ORG_CVE_RECOMPUTE="${TRIGGER_ORG_CVE_RECOMPUTE:-false}"
ORG_CVE_RECOMPUTE_MODE="${ORG_CVE_RECOMPUTE_MODE:-targeted}"
TRIGGER_FINDING_PROJECTION_REBUILD="${TRIGGER_FINDING_PROJECTION_REBUILD:-false}"
RUN_BASELINE_AFTER="${RUN_BASELINE_AFTER:-false}"
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
FAIL_ON_NONCOMPLIANT="${FAIL_ON_NONCOMPLIANT:-false}"
prometheus_exposure_hint="Enable Prometheus exposure with MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE=health,info,prometheus before running correlation certification."

mkdir -p "$OUT_DIR"
mkdir -p "$OUT_DIR/polls"

api_get() {
  path="$1"
  outfile="$2"
  if [ -n "$CREATOR_KEY" ]; then
    curl -fsS \
      -H "X-API-Key: $API_KEY" \
      -H "X-Creator-Key: $CREATOR_KEY" \
      "$BASE_URL$path" >"$outfile"
  else
    curl -fsS \
      -H "X-API-Key: $API_KEY" \
      "$BASE_URL$path" >"$outfile"
  fi
}

api_post() {
  path="$1"
  outfile="$2"
  if [ -n "$CREATOR_KEY" ]; then
    curl -fsS \
      -X POST \
      -H "X-API-Key: $API_KEY" \
      -H "X-Creator-Key: $CREATOR_KEY" \
      "$BASE_URL$path" >"$outfile"
  else
    curl -fsS \
      -X POST \
      -H "X-API-Key: $API_KEY" \
      "$BASE_URL$path" >"$outfile"
  fi
}

json_scalar() {
  file="$1"
  field="$2"
  value="$(grep -o "\"$field\":[^,}]*" "$file" | head -n 1 | cut -d: -f2- || true)"
  value="$(printf '%s' "$value" | tr -d '\r' | sed 's/^"//; s/"$//')"
  printf '%s' "$value"
}

prometheus_metric() {
  file="$1"
  metric="$2"
  awk -v metric="$metric" '$1 ~ ("^" metric "($|\\{)") {print $2; exit}' "$file"
}

capture_prometheus() {
  outfile="$1"
  error_file="${outfile}.err"

  if ! curl -fsS -H "X-API-Key: $API_KEY" "$BASE_URL/actuator/prometheus" >"$outfile" 2>"$error_file"; then
    echo "Failed to fetch Prometheus metrics from $BASE_URL/actuator/prometheus" >&2
    echo "$prometheus_exposure_hint" >&2
    cat "$error_file" >&2 2>/dev/null || true
    exit 1
  fi
}

capture_snapshot() {
  prefix="$1"
  api_get "/api/vuln-repo/org-cves/status" "$OUT_DIR/${prefix}-org-cves-status.json"
  api_get "/api/findings/projection-status" "$OUT_DIR/${prefix}-finding-projection-status.json"
  api_get "/api/operations/performance-scorecard" "$OUT_DIR/${prefix}-performance-scorecard.json"
  api_get "/api/slo/status" "$OUT_DIR/${prefix}-slo-status.json"
  capture_prometheus "$OUT_DIR/${prefix}-prometheus.txt"
}

write_summary_header() {
  summary_file="$1"
  printf 'checkpoint\tpending_events\tprocessing_events\tstale_events\tfailed_events\tfailed_event_growth\tprojection_stale\toldest_processing_age_seconds\tingestion_queued_jobs\tingestion_running_jobs\tqueue_oldest_age_seconds\tprojection_max_lag_seconds\tslo_overall_compliant\tscorecard_overall_compliant\troute_failure_count\tresource_failure_count\tresource_no_data_count\n' >"$summary_file"
}

append_summary_row() {
  checkpoint="$1"
  org_status_file="$2"
  projection_file="$3"
  slo_file="$4"
  scorecard_file="$5"
  prometheus_file="$6"
  summary_file="$7"

  pending_events="$(json_scalar "$org_status_file" "pendingEventCount")"
  processing_events="$(json_scalar "$org_status_file" "processingEventCount")"
  stale_events="$(json_scalar "$org_status_file" "staleEventCount")"
  failed_events="$(json_scalar "$org_status_file" "failedEventCount")"
  failed_growth="missing"
  if [ -n "${initial_failed_events:-}" ] && [ -n "${failed_events:-}" ]; then
    failed_growth="$((failed_events - initial_failed_events))"
  fi
  oldest_processing_age_seconds="$(json_scalar "$org_status_file" "oldestProcessingEventAgeSeconds")"
  ingestion_queued_jobs="$(json_scalar "$org_status_file" "ingestionQueuedJobCount")"
  ingestion_running_jobs="$(json_scalar "$org_status_file" "ingestionRunningJobCount")"
  projection_stale="$(json_scalar "$projection_file" "stale")"
  slo_overall="$(json_scalar "$slo_file" "overallCompliant")"
  scorecard_overall="$(json_scalar "$scorecard_file" "overallCompliant")"
  route_failure_count="$(json_scalar "$scorecard_file" "routeFailureCount")"
  resource_failure_count="$(json_scalar "$scorecard_file" "resourceFailureCount")"
  resource_no_data_count="$(json_scalar "$scorecard_file" "resourceNoDataCount")"
  queue_oldest_age="$(prometheus_metric "$prometheus_file" "scoutgrid.finding_delta_queue.oldest_age_seconds" || true)"
  projection_max_lag="$(prometheus_metric "$prometheus_file" "scoutgrid.finding_projection.max_lag_seconds" || true)"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$checkpoint" \
    "${pending_events:-missing}" \
    "${processing_events:-missing}" \
    "${stale_events:-missing}" \
    "${failed_events:-missing}" \
    "${failed_growth:-missing}" \
    "${projection_stale:-missing}" \
    "${oldest_processing_age_seconds:-missing}" \
    "${ingestion_queued_jobs:-missing}" \
    "${ingestion_running_jobs:-missing}" \
    "${queue_oldest_age:-missing}" \
    "${projection_max_lag:-missing}" \
    "${slo_overall:-missing}" \
    "${scorecard_overall:-missing}" \
    "${route_failure_count:-missing}" \
    "${resource_failure_count:-missing}" \
    "${resource_no_data_count:-missing}" >>"$summary_file"
}

steady_state_reached() {
  org_status_file="$1"
  projection_file="$2"
  prometheus_file="$3"

  pending_events="$(json_scalar "$org_status_file" "pendingEventCount")"
  stale_events="$(json_scalar "$org_status_file" "staleEventCount")"
  failed_events="$(json_scalar "$org_status_file" "failedEventCount")"
  failed_growth=0
  projection_stale="$(json_scalar "$projection_file" "stale")"
  queue_oldest_age="$(prometheus_metric "$prometheus_file" "scoutgrid.finding_delta_queue.oldest_age_seconds" || true)"
  projection_max_lag="$(prometheus_metric "$prometheus_file" "scoutgrid.finding_projection.max_lag_seconds" || true)"

  if [ -z "$stale_events" ] || [ -z "$failed_events" ] || [ -z "$projection_stale" ]; then
    return 1
  fi

  if [ "$stale_events" -gt "$MAX_STALE_EVENTS" ]; then
    return 1
  fi
  if [ -n "${initial_failed_events:-}" ] && [ -n "${failed_events:-}" ]; then
    failed_growth=$((failed_events - initial_failed_events))
  fi
  if [ "$failed_events" -gt "$MAX_FAILED_EVENTS" ] && [ "$failed_growth" -gt "$MAX_FAILED_GROWTH" ]; then
    return 1
  fi
  if [ "$projection_stale" != "false" ]; then
    return 1
  fi

  if [ -n "$queue_oldest_age" ] && [ "${queue_oldest_age%.*}" -gt "$MAX_OLDEST_QUEUE_AGE_SECONDS" ]; then
    return 1
  fi
  if [ -n "$projection_max_lag" ] && [ "${projection_max_lag%.*}" -gt "$MAX_PROJECTION_LAG_SECONDS" ]; then
    return 1
  fi
  if [ "$REQUIRE_QUEUE_DRAIN" = "true" ] && [ -n "$pending_events" ] && [ "$pending_events" -gt 0 ]; then
    return 1
  fi

  return 0
}

summary_file="$OUT_DIR/correlation-certification-summary.tsv"
write_summary_header "$summary_file"

echo "Collecting initial correlation and freshness snapshots into $OUT_DIR"
capture_snapshot "initial"
initial_pending_events="$(json_scalar "$OUT_DIR/initial-org-cves-status.json" "pendingEventCount")"
initial_processing_events="$(json_scalar "$OUT_DIR/initial-org-cves-status.json" "processingEventCount")"
initial_ingestion_queued_jobs="$(json_scalar "$OUT_DIR/initial-org-cves-status.json" "ingestionQueuedJobCount")"
initial_failed_events="$(json_scalar "$OUT_DIR/initial-org-cves-status.json" "failedEventCount")"
append_summary_row \
  "initial" \
  "$OUT_DIR/initial-org-cves-status.json" \
  "$OUT_DIR/initial-finding-projection-status.json" \
  "$OUT_DIR/initial-slo-status.json" \
  "$OUT_DIR/initial-performance-scorecard.json" \
  "$OUT_DIR/initial-prometheus.txt" \
  "$summary_file"

if [ "$TRIGGER_ORG_CVE_RECOMPUTE" = "true" ]; then
  echo "Triggering org CVE recompute in $ORG_CVE_RECOMPUTE_MODE mode"
  api_post "/api/vuln-repo/org-cves/recompute?mode=$ORG_CVE_RECOMPUTE_MODE" \
    "$OUT_DIR/org-cve-recompute-response.json"
fi

if [ "$TRIGGER_FINDING_PROJECTION_REBUILD" = "true" ]; then
  echo "Triggering finding projection rebuild"
  api_post "/api/findings/projection-rebuild" \
    "$OUT_DIR/finding-projection-rebuild-response.json"
fi

start_epoch="$(date +%s)"
poll_number=1
steady_state="false"

while :; do
  now_epoch="$(date +%s)"
  elapsed="$((now_epoch - start_epoch))"
  if [ "$elapsed" -gt "$MAX_WAIT_SECONDS" ]; then
    break
  fi

  poll_prefix="$(printf 'polls/poll-%03d' "$poll_number")"
  api_get "/api/vuln-repo/org-cves/status" "$OUT_DIR/${poll_prefix}-org-cves-status.json"
  api_get "/api/findings/projection-status" "$OUT_DIR/${poll_prefix}-finding-projection-status.json"
  capture_prometheus "$OUT_DIR/${poll_prefix}-prometheus.txt"

  pending_events="$(json_scalar "$OUT_DIR/${poll_prefix}-org-cves-status.json" "pendingEventCount")"
  processing_events="$(json_scalar "$OUT_DIR/${poll_prefix}-org-cves-status.json" "processingEventCount")"
  stale_events="$(json_scalar "$OUT_DIR/${poll_prefix}-org-cves-status.json" "staleEventCount")"
  failed_events="$(json_scalar "$OUT_DIR/${poll_prefix}-org-cves-status.json" "failedEventCount")"
  oldest_processing_age_seconds="$(json_scalar "$OUT_DIR/${poll_prefix}-org-cves-status.json" "oldestProcessingEventAgeSeconds")"
  ingestion_queued_jobs="$(json_scalar "$OUT_DIR/${poll_prefix}-org-cves-status.json" "ingestionQueuedJobCount")"
  ingestion_running_jobs="$(json_scalar "$OUT_DIR/${poll_prefix}-org-cves-status.json" "ingestionRunningJobCount")"
  projection_stale="$(json_scalar "$OUT_DIR/${poll_prefix}-finding-projection-status.json" "stale")"
  queue_oldest_age="$(prometheus_metric "$OUT_DIR/${poll_prefix}-prometheus.txt" "scoutgrid.finding_delta_queue.oldest_age_seconds" || true)"
  projection_max_lag="$(prometheus_metric "$OUT_DIR/${poll_prefix}-prometheus.txt" "scoutgrid.finding_projection.max_lag_seconds" || true)"

  echo "Poll $poll_number after ${elapsed}s: pending=${pending_events:-missing} processing=${processing_events:-missing} stale=${stale_events:-missing} failed=${failed_events:-missing} oldest_processing_age_s=${oldest_processing_age_seconds:-missing} ingestion_queued=${ingestion_queued_jobs:-missing} ingestion_running=${ingestion_running_jobs:-missing} projection_stale=${projection_stale:-missing} oldest_queue_age_s=${queue_oldest_age:-missing} projection_max_lag_s=${projection_max_lag:-missing}"

  if steady_state_reached \
    "$OUT_DIR/${poll_prefix}-org-cves-status.json" \
    "$OUT_DIR/${poll_prefix}-finding-projection-status.json" \
    "$OUT_DIR/${poll_prefix}-prometheus.txt"; then
    steady_state="true"
    break
  fi

  poll_number=$((poll_number + 1))
  sleep "$POLL_INTERVAL_SECONDS"
done

capture_snapshot "final"
append_summary_row \
  "final" \
  "$OUT_DIR/final-org-cves-status.json" \
  "$OUT_DIR/final-finding-projection-status.json" \
  "$OUT_DIR/final-slo-status.json" \
  "$OUT_DIR/final-performance-scorecard.json" \
  "$OUT_DIR/final-prometheus.txt" \
  "$summary_file"

final_slo_overall="$(json_scalar "$OUT_DIR/final-slo-status.json" "overallCompliant")"
final_scorecard_overall="$(json_scalar "$OUT_DIR/final-performance-scorecard.json" "overallCompliant")"
final_route_failure_count="$(json_scalar "$OUT_DIR/final-performance-scorecard.json" "routeFailureCount")"
final_resource_failure_count="$(json_scalar "$OUT_DIR/final-performance-scorecard.json" "resourceFailureCount")"
final_resource_no_data_count="$(json_scalar "$OUT_DIR/final-performance-scorecard.json" "resourceNoDataCount")"
final_pending_events="$(json_scalar "$OUT_DIR/final-org-cves-status.json" "pendingEventCount")"
final_processing_events="$(json_scalar "$OUT_DIR/final-org-cves-status.json" "processingEventCount")"
final_stale_events="$(json_scalar "$OUT_DIR/final-org-cves-status.json" "staleEventCount")"
final_failed_events="$(json_scalar "$OUT_DIR/final-org-cves-status.json" "failedEventCount")"
final_failed_growth="missing"
if [ -n "${initial_failed_events:-}" ] && [ -n "${final_failed_events:-}" ]; then
  final_failed_growth="$((final_failed_events - initial_failed_events))"
fi
final_oldest_processing_age_seconds="$(json_scalar "$OUT_DIR/final-org-cves-status.json" "oldestProcessingEventAgeSeconds")"
final_ingestion_queued_jobs="$(json_scalar "$OUT_DIR/final-org-cves-status.json" "ingestionQueuedJobCount")"
final_ingestion_running_jobs="$(json_scalar "$OUT_DIR/final-org-cves-status.json" "ingestionRunningJobCount")"
final_projection_stale="$(json_scalar "$OUT_DIR/final-finding-projection-status.json" "stale")"
final_queue_oldest_age="$(prometheus_metric "$OUT_DIR/final-prometheus.txt" "scoutgrid.finding_delta_queue.oldest_age_seconds" || true)"
final_projection_max_lag="$(prometheus_metric "$OUT_DIR/final-prometheus.txt" "scoutgrid.finding_projection.max_lag_seconds" || true)"

if [ "$RUN_BASELINE_AFTER" = "true" ]; then
  echo "Running read-path baseline after correlation certification"
  BASELINE_OUT_DIR="$OUT_DIR/post-certification-baseline"
  OUT_DIR="$BASELINE_OUT_DIR" \
  BASE_URL="$BASE_URL" \
  API_KEY="$API_KEY" \
  CREATOR_KEY="$CREATOR_KEY" \
  "$(dirname "$0")/performance-baseline.sh"
fi

status=0
if [ "$CERTIFICATION_STRICT" = "true" ]; then
  if ! python3 "$(dirname "$0")/validate-certification.py" scorecard "$OUT_DIR/final-performance-scorecard.json"; then
    status=1
  fi
fi
if [ "$steady_state" != "true" ]; then
  echo "Certification did not reach steady state within ${MAX_WAIT_SECONDS}s"
  status=1
fi
if [ -n "$initial_pending_events" ] && [ -n "$final_pending_events" ] && [ $((final_pending_events - initial_pending_events)) -gt "$MAX_PENDING_GROWTH" ]; then
  echo "Pending delta queue backlog grew by $((final_pending_events - initial_pending_events)) events (max allowed growth: $MAX_PENDING_GROWTH)"
  status=1
fi
if [ -n "$initial_processing_events" ] && [ -n "$final_processing_events" ] && [ $((final_processing_events - initial_processing_events)) -gt "$MAX_PROCESSING_GROWTH" ]; then
  echo "Processing delta queue backlog grew by $((final_processing_events - initial_processing_events)) events (max allowed growth: $MAX_PROCESSING_GROWTH)"
  status=1
fi
if [ -n "$initial_ingestion_queued_jobs" ] && [ -n "$final_ingestion_queued_jobs" ] && [ $((final_ingestion_queued_jobs - initial_ingestion_queued_jobs)) -gt "$MAX_INGESTION_QUEUED_GROWTH" ]; then
  echo "Queued ingestion backlog grew by $((final_ingestion_queued_jobs - initial_ingestion_queued_jobs)) jobs (max allowed growth: $MAX_INGESTION_QUEUED_GROWTH)"
  status=1
fi
if [ -n "$final_oldest_processing_age_seconds" ] && [ "${final_oldest_processing_age_seconds%.*}" -gt "$MAX_OLDEST_PROCESSING_AGE_SECONDS" ]; then
  echo "Oldest processing delta event age ${final_oldest_processing_age_seconds}s exceeds limit ${MAX_OLDEST_PROCESSING_AGE_SECONDS}s"
  status=1
fi
if [ -n "${final_failed_events:-}" ] && [ -n "${initial_failed_events:-}" ] \
  && [ "$final_failed_events" -gt "$MAX_FAILED_EVENTS" ] \
  && [ "$final_failed_growth" -gt "$MAX_FAILED_GROWTH" ]; then
  echo "Failed delta events grew by ${final_failed_growth} above baseline (current=${final_failed_events}, initial=${initial_failed_events}, allowed growth=${MAX_FAILED_GROWTH})"
  status=1
fi
if [ "$FAIL_ON_NONCOMPLIANT" = "true" ] && [ "$final_slo_overall" != "true" ]; then
  echo "Final SLO status is non-compliant"
  status=1
fi
if [ "$FAIL_ON_NONCOMPLIANT" = "true" ] && [ "$final_scorecard_overall" != "true" ]; then
  echo "Final performance scorecard is non-compliant"
  echo "Route failure count: ${final_route_failure_count:-missing}"
  echo "Resource failure count: ${final_resource_failure_count:-missing}"
  echo "Resource no-data count: ${final_resource_no_data_count:-missing}"
  status=1
fi

echo "Correlation certification summary:"
cat "$summary_file"
echo "Final queue pending: ${final_pending_events:-missing}"
echo "Final queue processing: ${final_processing_events:-missing}"
echo "Final stale events: ${final_stale_events:-missing}"
echo "Final failed events: ${final_failed_events:-missing}"
echo "Final failed event growth: ${final_failed_growth:-missing}"
echo "Final oldest processing age seconds: ${final_oldest_processing_age_seconds:-missing}"
echo "Final queued ingestion jobs: ${final_ingestion_queued_jobs:-missing}"
echo "Final running ingestion jobs: ${final_ingestion_running_jobs:-missing}"
echo "Final projection stale: ${final_projection_stale:-missing}"
echo "Final oldest queue age seconds: ${final_queue_oldest_age:-missing}"
echo "Final max projection lag seconds: ${final_projection_max_lag:-missing}"
echo "Final SLO overall compliant: ${final_slo_overall:-missing}"
echo "Final performance scorecard overall compliant: ${final_scorecard_overall:-missing}"
echo "Final route failure count: ${final_route_failure_count:-missing}"
echo "Final resource failure count: ${final_resource_failure_count:-missing}"
echo "Final resource no-data count: ${final_resource_no_data_count:-missing}"
echo "Artifacts written to: $OUT_DIR"

exit "$status"
