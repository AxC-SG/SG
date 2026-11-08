#!/bin/sh
set -eu

validation_only=false
case "${1:-}" in
  --validate-env-only) validation_only=true; shift ;;
  --run-once) shift ;;
  *) echo "migration_env_validation=failed reason=unsupported_argument" >&2; exit 2 ;;
esac
if [ "$#" -gt 0 ]; then
  case "$validation_only:$1:$#" in
    false:--provision-standard:4|false:--provision-standard-request:2|false:--link-standard-admin:3|false:--record-standard-setup-email:4|false:--record-standard-setup-failure:3) ;;
    *) echo "migration_env_validation=failed reason=unsupported_run_once_arguments" >&2; exit 2 ;;
  esac
fi

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

case "${APP_MANAGED_INSTALLATION_ENABLED:-false}" in
  true)
    if [ "${PLATFORM_OWNER_SETUP_LINK_ENABLED:-false}" = "true" ] ||
       [ "${APP_PLATFORM_OWNER_BOOTSTRAP_ENABLED:-false}" = "true" ]; then
      echo "migration_env_validation=failed reason=conflicting_installation_modes" >&2
      exit 2
    fi
    : "${APP_MANAGED_INSTALLATION_ISSUER:?Managed Cognito issuer is required}"
    : "${APP_MANAGED_INSTALLATION_OWNER_EMAIL:?Managed owner email is required}"
    : "${APP_MANAGED_INSTALLATION_OWNER_SUBJECT:?Managed owner subject is required}"
    : "${APP_MANAGED_INSTALLATION_INTERNAL_ADMIN_EMAIL:?Managed internal admin email is required}"
    : "${APP_MANAGED_INSTALLATION_INTERNAL_ADMIN_SUBJECT:?Managed internal admin subject is required}"
    ;;
  false) ;;
  *) echo "migration_env_validation=failed reason=invalid_managed_enrollment_flag" >&2; exit 2 ;;
esac

if [ "${PLATFORM_OWNER_SETUP_LINK_ENABLED:-false}" = "true" ] || [ "${APP_PLATFORM_OWNER_BOOTSTRAP_ENABLED:-false}" = "true" ]; then
  : "${PLATFORM_OWNER_SETUP_EMAIL:=${APP_SECURITY_BOOTSTRAP_PLATFORM_OWNERS_USERS_0_EMAIL:-}}"
  : "${PLATFORM_OWNER_SETUP_EMAIL:?A platform-owner email alias is required for installation bootstrap}"
  : "${SG_INTERNAL_ADMIN_EMAIL:?A distinct SG Internal administrator email alias is required for installation bootstrap}"
  if [ "$(printf '%s' "$PLATFORM_OWNER_SETUP_EMAIL" | tr '[:upper:]' '[:lower:]')" = "$(printf '%s' "$SG_INTERNAL_ADMIN_EMAIL" | tr '[:upper:]' '[:lower:]')" ]; then
    echo "migration_env_validation=failed reason=identical_account_aliases" >&2
    exit 2
  fi
  # The migrator encrypts intent only. The runtime owns provider submission.
  export PLATFORM_OWNER_SETUP_EMAIL SG_INTERNAL_ADMIN_EMAIL
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

# JVM option variables intentionally expand into separate arguments.
# shellcheck disable=SC2086
exec java ${JAVA_TOOL_OPTIONS:-} ${JAVA_OPTS:-} \
  -Dloader.main=com.prototype.vulnwatch.migration.ProductionBootstrapCli \
  -cp /app/vulnwatch-backend.jar \
  org.springframework.boot.loader.launch.PropertiesLauncher "$@"
