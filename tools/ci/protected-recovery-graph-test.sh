#!/bin/bash
# Inspect Terraform's own dependency graph without reading cloud state.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
graph="$(mktemp)"
trap 'rm -f -- "$graph"' EXIT
terraform -chdir="$root/terraform/modules/protected-recovery" graph -type=plan > "$graph"
python3 - "$graph" <<'PY'
import re
import sys
from pathlib import Path

edges = {}
for source, target in re.findall(r'"\[root\] ([^"\\]+)" -> "\[root\] ([^"\\]+)"', Path(sys.argv[1]).read_text()):
    edges.setdefault(source, set()).add(target)

def depends_on(source, target):
    pending = [source + " (expand)"]
    seen = set()
    while pending:
        node = pending.pop()
        if node == target + " (expand)":
            return True
        if node not in seen:
            seen.add(node)
            pending.extend(edges.get(node, ()))
    return False

reads = [
    "data.google_project.current",
    "data.google_client_openid_userinfo.deployer",
    "data.google_project.consumer",
    "data.google_service_account.target",
    "data.external.deny_state",
    "data.external.service_state",
    "data.external.allow_state",
    "data.external.apply_lease",
]
authority = [
    "google_project_iam_custom_role.actuator",
    "google_service_account_iam_member.actuator",
    "google_project_iam_custom_role.inventory",
    "google_project_iam_member.broker_inventory",
    "google_organization_iam_custom_role.inventory",
    "google_organization_iam_member.broker_inventory",
    "google_organization_iam_member.broker_deny_reviewer",
]
for read in reads:
    if not depends_on(read, "terraform_data.authority_gate"):
        raise SystemExit(f"{read} must refresh after the per-apply gate")
for resource in authority:
    if not depends_on(resource, "local.evidence_verified"):
        raise SystemExit(f"{resource} must consume verified evidence")
    for read in reads:
        # Target identity applies to the per-account grant; every grant still
        # requires every consumer's successful ancestry and admission reads.
        if read == "data.google_service_account.target" and resource != "google_service_account_iam_member.actuator":
            continue
        if not depends_on(resource, read):
            raise SystemExit(f"{resource} must wait for successful {read}")
print("authority graph: 8 apply-time reads precede all 7 authority resources; target identity precedes its account grant")
PY
