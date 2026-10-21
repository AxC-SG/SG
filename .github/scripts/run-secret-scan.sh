#!/usr/bin/env bash
set -euo pipefail

# The same scan runs for human and Dependabot PRs without organization secrets.
base_sha=${GITLEAKS_BASE_SHA:-}
head_sha=${GITLEAKS_HEAD_SHA:-HEAD}
log_opts=--all
if [[ -n "$base_sha" && ! "$base_sha" =~ ^0+$ ]]; then
  [[ "$base_sha" =~ ^[0-9a-f]{40}$ ]] || { echo "Invalid scan base SHA" >&2; exit 2; }
  [[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || { echo "Invalid scan head SHA" >&2; exit 2; }
  git cat-file -e "$base_sha^{commit}"
  git cat-file -e "$head_sha^{commit}"
  log_opts="$base_sha..$head_sha"
fi
"${RUNNER_TEMP:?}/gitleaks" git . --redact \
  --config .gitleaks.toml --gitleaks-ignore-path .gitleaksignore \
  --log-opts="$log_opts" --report-format sarif \
  --report-path "$RUNNER_TEMP/gitleaks.sarif"
