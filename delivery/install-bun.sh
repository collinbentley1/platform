#!/usr/bin/env bash
set -euo pipefail
version="$(jq -r .version delivery/bun.json)"
checksum="$(jq -r .linuxX64 delivery/bun.json)"
curl --proto '=https' --tlsv1.2 -fsSL "https://github.com/oven-sh/bun/releases/download/bun-v${version}/bun-linux-x64.zip" -o "$RUNNER_TEMP/bun.zip"
echo "${checksum}  $RUNNER_TEMP/bun.zip" | sha256sum --check --strict
unzip -qo "$RUNNER_TEMP/bun.zip" -d "$RUNNER_TEMP/bun-bin"
echo "$RUNNER_TEMP/bun-bin/bun-linux-x64" >> "$GITHUB_PATH"
