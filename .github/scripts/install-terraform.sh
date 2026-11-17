#!/usr/bin/env bash
# Install the pinned Linux runner CLI only after verifying the downloaded archive.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
manifest="${script_dir}/../tool-versions.json"
version="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["terraform"]["version"])' "$manifest")"
checksum="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["terraform"]["linux_amd64_sha256"])' "$manifest")"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$checksum" =~ ^[a-f0-9]{64}$ ]]
archive="$RUNNER_TEMP/terraform.zip"
install_dir="$RUNNER_TEMP/terraform-cli"
mkdir -p "$install_dir"
curl --fail --silent --show-error --location \
  "https://releases.hashicorp.com/terraform/$version/terraform_${version}_linux_amd64.zip" \
  --output "$archive"
printf '%s  %s\n' "$checksum" "$archive" | sha256sum -c -
unzip -qo "$archive" -d "$install_dir"
printf '%s\n' "$install_dir" >> "$GITHUB_PATH"
