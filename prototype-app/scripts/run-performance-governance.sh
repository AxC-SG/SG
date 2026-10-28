#!/usr/bin/env sh
set -eu

CERTIFICATION_STRICT="${CERTIFICATION_STRICT:-true}"
export CERTIFICATION_STRICT

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
BACKEND_DIR="${BACKEND_DIR:-$PROJECT_DIR/backend}"
BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
OUT_DIR="${OUT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/vulnwatch-governance.XXXXXX")}"
START_BACKEND="${START_BACKEND:-false}"
BACKEND_STARTUP_TIMEOUT_SECONDS="${BACKEND_STARTUP_TIMEOUT_SECONDS:-180}"
BACKEND_HEALTH_PATH="${BACKEND_HEALTH_PATH:-/actuator/health/readiness}"
BACKEND_LOG_FILE="${BACKEND_LOG_FILE:-$OUT_DIR/backend.log}"
BOOTSTRAP_LOG_FILE="${BOOTSTRAP_LOG_FILE:-$OUT_DIR/production-bootstrap.log}"
SPRING_PROFILES_ACTIVE_VALUE="${SPRING_PROFILES_ACTIVE:-local}"
MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE_VALUE="${MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE:-health,info,prometheus}"
SEED_DEMO_DATA="${SEED_DEMO_DATA:-false}"
BASELINE_ITERATIONS="${BASELINE_ITERATIONS:-3}"
FAIL_ON_NONCOMPLIANT="${FAIL_ON_NONCOMPLIANT:-true}"
FAIL_ON_AUTH_SKIPS="${FAIL_ON_AUTH_SKIPS:-true}"

BACKEND_PID=""

mkdir -p "$OUT_DIR"

cleanup() {
  if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" 2>/dev/null || true
    wait "$BACKEND_PID" 2>/dev/null || true
  fi
}

trap cleanup EXIT INT TERM

wait_for_backend() {
  elapsed=0
  while [ "$elapsed" -lt "$BACKEND_STARTUP_TIMEOUT_SECONDS" ]; do
    if curl -fsS "$BASE_URL$BACKEND_HEALTH_PATH" >/dev/null 2>&1; then
      return 0
    fi
    if [ -n "$BACKEND_PID" ] && ! kill -0 "$BACKEND_PID" 2>/dev/null; then
      echo "Backend process exited before readiness check passed." >&2
      if [ -f "$BACKEND_LOG_FILE" ]; then
        echo "--- backend log ---" >&2
        tail -n 200 "$BACKEND_LOG_FILE" >&2 || true
      fi
      return 1
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done

  echo "Backend did not become ready within ${BACKEND_STARTUP_TIMEOUT_SECONDS}s." >&2
  if [ -f "$BACKEND_LOG_FILE" ]; then
    echo "--- backend log ---" >&2
    tail -n 200 "$BACKEND_LOG_FILE" >&2 || true
  fi
  return 1
}

run_production_bootstrap() {
  if [ "$START_BACKEND" != "true" ]; then
    return 0
  fi

  echo "Running production bootstrap before performance governance backend startup"
  (
    cd "$BACKEND_DIR"
    mvn -q -DskipTests package
    BACKEND_JAR="$(find target -maxdepth 1 -name 'vulnwatch-backend-*.jar' ! -name '*.original' | head -n 1)"
    java ${JAVA_TOOL_OPTIONS:-} ${JAVA_OPTS:-} \
      -Dloader.main=com.prototype.vulnwatch.migration.ProductionBootstrapCli \
      -cp "$BACKEND_JAR" \
      org.springframework.boot.loader.launch.PropertiesLauncher
  ) >"$BOOTSTRAP_LOG_FILE" 2>&1 || {
    echo "Production bootstrap failed before performance governance." >&2
    echo "--- production bootstrap log ---" >&2
    tail -n 200 "$BOOTSTRAP_LOG_FILE" >&2 || true
    return 1
  }
}

start_backend_if_requested() {
  if [ "$START_BACKEND" != "true" ]; then
    return 0
  fi

  echo "Starting backend for performance governance with profile ${SPRING_PROFILES_ACTIVE_VALUE}"
  (
    cd "$BACKEND_DIR"
    SPRING_PROFILES_ACTIVE="$SPRING_PROFILES_ACTIVE_VALUE" \
    MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE="$MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE_VALUE" \
    mvn -q -DskipTests spring-boot:run
  ) >"$BACKEND_LOG_FILE" 2>&1 &
  BACKEND_PID=$!
  wait_for_backend
}

run_production_bootstrap
start_backend_if_requested

CERT_OUT_DIR="$OUT_DIR/certification"
mkdir -p "$CERT_OUT_DIR"

echo "Running performance governance certification into $CERT_OUT_DIR"
OUT_DIR="$CERT_OUT_DIR" \
BASE_URL="$BASE_URL" \
SEED_DEMO_DATA="$SEED_DEMO_DATA" \
BASELINE_ITERATIONS="$BASELINE_ITERATIONS" \
FAIL_ON_NONCOMPLIANT="$FAIL_ON_NONCOMPLIANT" \
FAIL_ON_AUTH_SKIPS="$FAIL_ON_AUTH_SKIPS" \
"$SCRIPT_DIR/enterprise-performance-certification.sh"

echo "Performance governance run complete: $CERT_OUT_DIR"
