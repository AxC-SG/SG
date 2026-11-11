#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
migrator="$script_dir/run-schema-migration.sh"

run_validation() {
  test_host=$1
  test_port=$2
  env \
    MIGRATION_DB_HOST="$test_host" \
    MIGRATION_DB_PORT="$test_port" \
    MIGRATION_DB_NAME=scout \
    MIGRATION_DB_USERNAME=scout_migrator \
    MIGRATION_DB_PASSWORD=test-password \
    RUNTIME_DB_USERNAME=scout_runtime \
    RUNTIME_DB_PASSWORD=test-runtime-password \
    APP_CREDENTIAL_ENCRYPTION_KEY=test-encryption-key \
    sh "$migrator" --validate-env-only >/dev/null 2>&1
}

expect_valid() {
  if ! run_validation "$1" "$2"; then
    echo "expected valid migration environment: host=$1 port=$2" >&2
    exit 1
  fi
}

expect_invalid() {
  if run_validation "$1" "$2"; then
    echo "expected invalid migration environment: host=$1 port=$2" >&2
    exit 1
  fi
}

expect_valid db.internal 5432
expect_valid 127.0.0.1 65535
expect_invalid '' 5432
expect_invalid 'https://db.internal' 5432
expect_invalid 'db.internal:5432' 5432
expect_invalid 'db.internal/path' 5432
expect_invalid 'db internal' 5432
expect_invalid '2001:db8::1' 5432
expect_invalid '999.1.1.1' 5432
expect_invalid db.internal abc
expect_invalid db.internal 0
expect_invalid db.internal 65536

# Capture only controlled fixture values; the run-once path must preserve TLS options.
transport_fixture=$(mktemp -d)
trap 'rm -rf "$transport_fixture"' EXIT HUP INT TERM
cat > "$transport_fixture/java" <<'FAKE_JAVA'
#!/bin/sh
printf '%s\n' "$DB_URL" > "$MIGRATION_TEST_CAPTURE"
printf '%s\n' "$@" > "$MIGRATION_TEST_CAPTURE.args"
FAKE_JAVA
chmod 700 "$transport_fixture/java"
transport_url='jdbc:postgresql://db.internal/scout?sslmode=verify-full&sslrootcert=/tmp/fixture%20CA.pem&connectTimeout=7&socketTimeout=11'
env PATH="$transport_fixture:$PATH" \
  MIGRATION_TEST_CAPTURE="$transport_fixture/captured-url" \
  MIGRATION_DB_HOST=db.internal MIGRATION_DB_PORT=5432 MIGRATION_DB_NAME=scout \
  MIGRATION_DB_USERNAME=scout_migrator MIGRATION_DB_PASSWORD=test-password \
  RUNTIME_DB_USERNAME=scout_runtime RUNTIME_DB_PASSWORD=test-runtime-password \
  APP_CREDENTIAL_ENCRYPTION_KEY=test-encryption-key DB_URL="$transport_url" \
  sh "$migrator" --run-once
if [ "$(cat "$transport_fixture/captured-url")" != "$transport_url" ]; then
  echo "migration wrapper changed explicit JDBC transport options" >&2
  exit 1
fi

provisioning_id=00000000-0000-4000-8000-000000000123
env PATH="$transport_fixture:$PATH" \
  MIGRATION_TEST_CAPTURE="$transport_fixture/captured-url" \
  MIGRATION_DB_HOST=db.internal MIGRATION_DB_NAME=scout \
  MIGRATION_DB_USERNAME=scout_migrator MIGRATION_DB_PASSWORD=test-password \
  RUNTIME_DB_PASSWORD=test-runtime-password APP_CREDENTIAL_ENCRYPTION_KEY=test-encryption-key \
  sh "$migrator" --run-once --provision-standard "$provisioning_id" standard-fixture "Standard Fixture"
if [ "$(tail -n 4 "$transport_fixture/captured-url.args")" != "$(printf '%s\n' --provision-standard "$provisioning_id" standard-fixture 'Standard Fixture')" ]; then
  echo "migration wrapper changed Standard provisioning arguments" >&2
  exit 1
fi

managed_fixture() {
  env PATH="$transport_fixture:$PATH" \
    MIGRATION_TEST_CAPTURE="$transport_fixture/captured-url" \
    MIGRATION_DB_HOST=db.internal MIGRATION_DB_PORT=5432 MIGRATION_DB_NAME=scout \
    MIGRATION_DB_USERNAME=scout_migrator MIGRATION_DB_PASSWORD=test-password \
    RUNTIME_DB_PASSWORD=test-runtime-password APP_CREDENTIAL_ENCRYPTION_KEY=test-encryption-key \
    APP_MANAGED_INSTALLATION_ENABLED=true \
    APP_MANAGED_INSTALLATION_ISSUER=https://cognito-idp.us-east-1.amazonaws.com/us-east-1_fixture \
    APP_MANAGED_INSTALLATION_OWNER_EMAIL=owner@example.test \
    APP_MANAGED_INSTALLATION_OWNER_SUBJECT=owner-subject \
    APP_MANAGED_INSTALLATION_INTERNAL_ADMIN_EMAIL=admin@example.test \
    APP_MANAGED_INSTALLATION_INTERNAL_ADMIN_SUBJECT=admin-subject \
    "$@"
}

managed_fixture sh "$migrator" --run-once
if managed_fixture APP_MANAGED_INSTALLATION_OWNER_SUBJECT= sh "$migrator" --validate-env-only >/dev/null 2>&1; then
  echo "expected managed enrollment to require both subjects" >&2
  exit 1
fi
if managed_fixture APP_PLATFORM_OWNER_BOOTSTRAP_ENABLED=true sh "$migrator" --validate-env-only >/dev/null 2>&1; then
  echo "expected managed enrollment to reject legacy setup mode" >&2
  exit 1
fi

echo "Schema migration environment validation tests passed"
