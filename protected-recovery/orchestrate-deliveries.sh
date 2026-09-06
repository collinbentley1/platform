#!/bin/bash
set -euo pipefail
exec bun --no-env-file run "$(dirname "$0")/orchestrate-deliveries.ts" "$@"
