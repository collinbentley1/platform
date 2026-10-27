#!/usr/bin/env bash
set -euo pipefail
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/regclient/regclient/releases/download/v0.11.5/regctl-linux-amd64 -o "$RUNNER_TEMP/regctl"
echo "c93aa7638749f5aaac1a8e01787321889c78f0101809bb2880343478d0ba0467  $RUNNER_TEMP/regctl" | sha256sum --check --strict
chmod 700 "$RUNNER_TEMP/regctl"
echo "$RUNNER_TEMP" >> "$GITHUB_PATH"
