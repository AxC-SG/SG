#!/usr/bin/env bash
# Keep credentialed smoke configuration private and delete it on every exit.
set -euo pipefail
umask 077
smoke="$(mktemp -d "$RUNNER_TEMP/smoke.XXXXXX")"
trap 'rm -rf -- "$smoke"' EXIT
if [[ -n "$SMOKE_CONFIG_JSON" ]]; then
  mkdir -p "$smoke"
  printf '%s' "$SMOKE_CONFIG_JSON" > "$smoke/config.json"
  # Owner decision S1: only the dedicated tenant smoke admin, never a platform owner's password.
  if ! jq -e 'type == "object" and (has("platform") | not) and (.tenant | type == "object")' \
      "$smoke/config.json" > /dev/null 2>&1; then
    echo "::error::LAB_SMOKE_TENANT_CONFIG must be a tenant-only smoke configuration."
    exit 1
  fi
  export LAB_SMOKE_CONFIG="$smoke/config.json"
fi
unset SMOKE_CONFIG_JSON
args=(reconcile --yes)
if [[ "$FRONTEND" == true ]]; then
  args+=(--frontend)
fi
status=0
python3 -I prototype-app/infrastructure/lab/scripts/release.py "${args[@]}" > "$RUNNER_TEMP/reconcile.json" || status=$?
cat "$RUNNER_TEMP/reconcile.json"
exit "$status"
