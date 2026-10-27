#!/usr/bin/env bash
set -euo pipefail
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/oven-sh/bun/releases/download/bun-v1.4.2/bun-linux-x64.zip -o "$RUNNER_TEMP/bun.zip"
echo "36368faef7527875d5ffa52e53cd48021741f2a83eb6208a8dd64068d422a913  $RUNNER_TEMP/bun.zip" | sha256sum --check --strict
unzip -qo "$RUNNER_TEMP/bun.zip" -d "$RUNNER_TEMP/bun-bin"
echo "$RUNNER_TEMP/bun-bin/bun-linux-x64" >> "$GITHUB_PATH"
