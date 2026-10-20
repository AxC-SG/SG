#!/bin/sh
set -eu

validation_only=false
run_once=false
case "${1:-}" in
  "") ;;
  --validate-env-only) validation_only=true ;;
  --run-once) run_once=true ;;
  *) echo "migration_env_validation=failed reason=unsupported_argument" >&2; exit 2 ;;
esac

: "${MIGRATION_DB_HOST:?MIGRATION_DB_HOST is required}"
: "${MIGRATION_DB_PORT:=5432}"
: "${MIGRATION_DB_NAME:?MIGRATION_DB_NAME is required}"
: "${MIGRATION_DB_USERNAME:?MIGRATION_DB_USERNAME is required}"
: "${MIGRATION_DB_PASSWORD:?MIGRATION_DB_PASSWORD is required}"
: "${RUNTIME_DB_USERNAME:=scout_runtime}"
: "${RUNTIME_DB_PASSWORD:?RUNTIME_DB_PASSWORD is required}"
# Credential ciphertext is shared with the permanent runtime service. This must
# be the same stable secret configured there; generating a temporary key would
# leave any credentials written by this process unreadable by the runtime.
: "${APP_CREDENTIAL_ENCRYPTION_KEY:?APP_CREDENTIAL_ENCRYPTION_KEY is required and must match the permanent runtime service}"

validate_ipv4() {
  printf '%s\n' "$1" | awk -F. '
    NF != 4 { exit 1 }
    { for (i = 1; i <= 4; i++) if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255) exit 1 }
  '
}

validate_host() {
  host=$1
  case "$host" in
    *[!A-Za-z0-9.-]*|.*|*.|-*|*-) return 1 ;;
  esac
  if printf '%s' "$host" | grep -Eq '^[0-9.]+$'; then
    validate_ipv4 "$host"
  else
    printf '%s' "$host" | grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$'
  fi
}

if ! validate_host "$MIGRATION_DB_HOST"; then
  echo "migration_env_validation=failed reason=invalid_host" >&2
  exit 2
fi
case "$MIGRATION_DB_PORT" in ''|*[!0-9]*) echo "migration_env_validation=failed reason=invalid_port" >&2; exit 2 ;; esac
if [ "$MIGRATION_DB_PORT" -lt 1 ] || [ "$MIGRATION_DB_PORT" -gt 65535 ]; then
  echo "migration_env_validation=failed reason=invalid_port" >&2
  exit 2
fi

if [ "${PLATFORM_OWNER_SETUP_LINK_ENABLED:-false}" = "true" ]; then
  : "${PLATFORM_OWNER_SETUP_EMAIL:=${APP_SECURITY_BOOTSTRAP_PLATFORM_OWNERS_USERS_0_EMAIL:-}}"
  : "${PLATFORM_OWNER_SETUP_EMAIL:?PLATFORM_OWNER_SETUP_EMAIL is required when setup-link delivery is enabled}"
  : "${RESEND_API_KEY:?RESEND_API_KEY is required when setup-link delivery is enabled}"
  : "${RESEND_FROM_EMAIL:?RESEND_FROM_EMAIL is required when setup-link delivery is enabled}"
  : "${RESEND_FROM_DOMAIN:?RESEND_FROM_DOMAIN is required when setup-link delivery is enabled}"
  export PLATFORM_OWNER_SETUP_EMAIL
fi

# Preserve explicitly supplied TLS/transport options. The CLI validates identity.
: "${DB_URL:=jdbc:postgresql://${MIGRATION_DB_HOST}:${MIGRATION_DB_PORT}/${MIGRATION_DB_NAME}?connectTimeout=10&socketTimeout=30}"
export DB_URL
export DB_USERNAME="$MIGRATION_DB_USERNAME"
export DB_PASSWORD="$MIGRATION_DB_PASSWORD"
export EXPECTED_DB_NAME="$MIGRATION_DB_NAME"
export RUNTIME_DB_USERNAME
export RUNTIME_DB_PASSWORD

if [ "$validation_only" = true ]; then
  echo "migration_env_validation=passed"
  exit 0
fi

if [ "$run_once" = true ]; then
  exec java ${JAVA_TOOL_OPTIONS:-} ${JAVA_OPTS:-} -Dloader.main=com.prototype.vulnwatch.migration.ProductionBootstrapCli -cp /app/vulnwatch-backend.jar org.springframework.boot.loader.launch.PropertiesLauncher
fi

mkdir -p /tmp/scout-maintenance
printf 'schema bootstrap running\n' > /tmp/scout-maintenance/index.txt
busybox httpd -f -p "0.0.0.0:${PORT:-10000}" -h /tmp/scout-maintenance >/dev/null 2>&1 &
maintenance_listener_pid=$!
cleanup() {
  kill "$maintenance_listener_pid" 2>/dev/null || true
}
trap cleanup EXIT
migration_pid=""
cancel_migration() {
  if [ -n "$migration_pid" ]; then kill -TERM "$migration_pid" 2>/dev/null || true; fi
  exit "$1"
}
trap 'cancel_migration 130' INT
trap 'cancel_migration 143' TERM

success_file=/tmp/scout-schema-migration-success
rm -f "$success_file"

# JVM option variables intentionally expand into separate arguments.
# shellcheck disable=SC2086
java ${JAVA_TOOL_OPTIONS:-} ${JAVA_OPTS:-} \
  -Dloader.main=com.prototype.vulnwatch.migration.ProductionBootstrapCli \
  -cp /app/vulnwatch-backend.jar \
  org.springframework.boot.loader.launch.PropertiesLauncher &
migration_pid=$!
wait "$migration_pid"
migration_pid=""

printf 'success\n' > "$success_file"
printf 'schema bootstrap complete; privileged service awaiting deletion\n' > /tmp/scout-maintenance/index.txt
echo "migration_job_status=complete runtime_role=${RUNTIME_DB_USERNAME}"

# A Render web service is supervised and automatically restarted when its
# process exits. Keep the successful maintenance container alive so the
# privileged bootstrap cannot run repeatedly while the operator verifies the
# report and deletes the temporary service.
wait "$maintenance_listener_pid"
