#!/bin/bash
# Read the live IAM Deny policies attached to one attachment point for the
# protected-recovery Terraform module (data "external" "deny_state"). The
# credential is obtained here, from the application default credentials the
# Google provider itself applies with, and used only in this process: nothing
# that leaves this script carries it, so the module's state records the typed
# policy projection and never a bearer (tools/ci/protected-recovery-state-
# scan-test.sh proves it with a sentinel).
#
# The query names the attachment point; the answer is the listing status and
# the policies attached there, each with its name, etag, and deny rules. A
# listing or policy that cannot be read answers with its status and no
# policies, so the module reports an unread state rather than a provider
# error. The IAM endpoint and the credential command are overridable for the
# offline test only.
set -uo pipefail

query="$(cat)"
attachment="$(jq -er '.attachment' <<< "$query")" || { jq -cn '{status: "400", policies: "[]", reason: "the query names no attachment point"}'; exit 0; }
[[ "$attachment" =~ ^cloudresourcemanager\.googleapis\.com/(projects|folders|organizations)/[A-Za-z0-9._-]+$ ]] || { jq -cn '{status: "400", policies: "[]", reason: "the attachment point is malformed"}'; exit 0; }

endpoint="${PROTECTED_RECOVERY_IAM_ENDPOINT:-https://iam.googleapis.com}"
workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT
umask 077
if ! token="$(gcloud auth application-default print-access-token 2> "$workdir/error")"; then
  jq -cn --rawfile reason "$workdir/error" '{status: "401", policies: "[]", reason: ("no application default credential: " + ($reason | .[0:200]))}'
  exit 0
fi
printf 'header = "Authorization: Bearer %s"\n' "$token" > "$workdir/auth.cfg"
unset token

call() {
  curl --silent --show-error --config "$workdir/auth.cfg" --request GET --output "$workdir/body" --write-out '%{http_code}' "$1" || echo 000
}

encoded="$(jq -rn --arg attachment "$attachment" '$attachment | @uri')"
status="$(call "${endpoint}/v2/policies/${encoded}/denypolicies")"
if [ "$status" != 200 ]; then
  jq -cn --arg status "$status" '{status: $status, policies: "[]", reason: ("listing the deny policies answered HTTP " + $status)}'
  exit 0
fi
jq -r '.policies[]?.name' "$workdir/body" > "$workdir/names"
: > "$workdir/policies.jsonl"
while IFS= read -r name; do
  [ -n "$name" ] || continue
  [[ "$name" =~ ^policies/[A-Za-z0-9%._-]+/denypolicies/[A-Za-z0-9._-]+$ ]] || { jq -cn '{status: "502", policies: "[]", reason: "the listing names a malformed policy"}'; exit 0; }
  status="$(call "${endpoint}/v2/${name}")"
  if [ "$status" != 200 ]; then
    jq -cn --arg status "$status" --arg name "$name" '{status: $status, policies: "[]", reason: ("reading " + $name + " answered HTTP " + $status)}'
    exit 0
  fi
  jq -c '{name: .name, etag: .etag, rules: [.rules[]? | select(.denyRule != null) | {denialCondition: (.denyRule.denialCondition // null), deniedPermissions: (.denyRule.deniedPermissions // []), deniedPrincipals: (.denyRule.deniedPrincipals // []), exceptionPermissions: (.denyRule.exceptionPermissions // []), exceptionPrincipals: (.denyRule.exceptionPrincipals // [])}]}' "$workdir/body" >> "$workdir/policies.jsonl"
done < "$workdir/names"
jq -cn --slurpfile policies "$workdir/policies.jsonl" '{status: "200", policies: ($policies | tojson), reason: ""}'
