#!/usr/bin/env bash
# Effective-owner benchmark harness (ownership MVP design §7, plan §7.5 / §13).
#
# Creates a DISPOSABLE database, applies the real tenant V20/V21 ownership migrations into schema "bench",
# seeds the topology from seed.sql and runs queries.sql. Output (EXPLAIN plans + p50/p95 per query) is written to
# results/<timestamp>-<findings>.txt. Decision rule: if any p95 misses its budget at the expected size
# (1M open findings, 5M occurrences), enable ownership_effective_cache for that read path.
#
# Usage: run_benchmark.sh [findings=1000000] [occurrences=5000000] [runs=20]
# Env:   PGHOST/PGPORT/PGUSER as usual; BENCH_DB (must start with ownership_bench_, default ownership_bench_run).
#        KEEP_DB=1 keeps the database afterwards.
set -euo pipefail

FINDINGS="${1:-1000000}"
OCCURRENCES="${2:-5000000}"
RUNS="${3:-20}"
DB="${BENCH_DB:-ownership_bench_run}"
TENANT="00000000-0000-0000-0000-0000000000be"
HERE="$(cd "$(dirname "$0")" && pwd)"
MIGRATIONS="$HERE/../../../src/main/resources/db/migration/tenant"

case "$DB" in ownership_bench_*) ;; *) echo "Refusing: BENCH_DB must start with ownership_bench_ (it is dropped)" >&2; exit 2 ;; esac

mkdir -p "$HERE/results"
OUT="$HERE/results/$(date +%Y%m%dT%H%M%S)-${FINDINGS}f-${OCCURRENCES}o.txt"

dropdb --if-exists "$DB"
createdb "$DB"
trap '[ "${KEEP_DB:-0}" = 1 ] || dropdb --if-exists "$DB"' EXIT

psql -X -q -v ON_ERROR_STOP=1 -d "$DB" <<SQL
CREATE SCHEMA platform;
CREATE TABLE platform.tenants (id uuid PRIMARY KEY);
INSERT INTO platform.tenants VALUES ('$TENANT');
CREATE SCHEMA bench;
SQL

for m in V21__identity_and_teams.sql V22__ownership_core.sql; do
  sed -e "s/\${tenantSchema}/bench/g" -e "s/\${tenantId}/$TENANT/g" "$MIGRATIONS/$m" | psql -X -q -v ON_ERROR_STOP=1 -d "$DB"
done

{
  echo "# ownership effective-owner benchmark  findings=$FINDINGS occurrences=$OCCURRENCES runs=$RUNS  $(date -u +%FT%TZ)"
  psql -X -At -d "$DB" -c "SELECT version()"
  /usr/bin/time -p psql -X -q -v ON_ERROR_STOP=1 -v findings="$FINDINGS" -v occurrences="$OCCURRENCES" -d "$DB" -f "$HERE/seed.sql" 2>&1 \
    | sed 's/^/seed: /'
  PGOPTIONS="-c bench.runs=$RUNS" psql -X -v ON_ERROR_STOP=1 -d "$DB" -f "$HERE/queries.sql" 2>&1
} | tee "$OUT"
echo "Results: $OUT"
