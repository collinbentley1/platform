#!/bin/bash
# Read, for the protected-recovery Terraform module (data "external"
# "allow_state"), the roles one principal holds in the IAM allow policy of one
# attachment point: the retirement check of the Deny canary's temporary
# Allows. The credential is obtained here, from the application default
# credentials the Google provider itself applies with, and used only in this
# process: nothing that leaves this script carries it, so the module's state
# records the typed projection and never a bearer
# (tools/ci/protected-recovery-state-scan-test.sh proves it with a sentinel).
#
# The query names the resource (projects/<id> or organizations/<id>) and the
# service-account email; the answer is the read's status, the policy's etag,
# and the sorted roles of every binding -- conditional or not -- whose members
# name the principal. A policy that cannot be read answers with its status
# and no roles, so the module reports an unread state rather than a provider
# error. The Resource Manager endpoint and the credential command are
# overridable for the offline test only.
set -uo pipefail

query="$(cat)"
resource="$(jq -er '.resource' <<< "$query")" || { jq -cn '{status: "400", etag: "", roles: "[]", reason: "the query names no resource"}'; exit 0; }
principal="$(jq -er '.principal' <<< "$query")" || { jq -cn '{status: "400", etag: "", roles: "[]", reason: "the query names no principal"}'; exit 0; }
[[ "$resource" =~ ^(projects|organizations)/[A-Za-z0-9._-]+$ ]] || { jq -cn '{status: "400", etag: "", roles: "[]", reason: "the resource is malformed"}'; exit 0; }
[[ "$principal" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$ ]] || { jq -cn '{status: "400", etag: "", roles: "[]", reason: "the principal is malformed"}'; exit 0; }

endpoint="${PROTECTED_RECOVERY_RESOURCEMANAGER_ENDPOINT:-https://cloudresourcemanager.googleapis.com}"
workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT
umask 077
if ! token="$(gcloud auth application-default print-access-token 2> "$workdir/error")"; then
  jq -cn --rawfile reason "$workdir/error" '{status: "401", etag: "", roles: "[]", reason: ("no application default credential: " + ($reason | .[0:200]))}'
  exit 0
fi
printf 'header = "Authorization: Bearer %s"\n' "$token" > "$workdir/auth.cfg"
unset token

printf '{"options":{"requestedPolicyVersion":3}}' > "$workdir/request.json"
status="$(curl --silent --show-error --config "$workdir/auth.cfg" --request POST --header 'Content-Type: application/json' --data-binary "@$workdir/request.json" --output "$workdir/body" --write-out '%{http_code}' "${endpoint}/v3/${resource}:getIamPolicy" || echo 000)"
if [ "$status" != 200 ]; then
  jq -cn --arg status "$status" '{status: $status, etag: "", roles: "[]", reason: ("reading the allow policy answered HTTP " + $status)}'
  exit 0
fi
jq -c --arg member "serviceAccount:${principal}" '
  if (.etag | type) != "string" then {status: "502", etag: "", roles: "[]", reason: "the allow policy carries no etag"}
  else {status: "200", etag: .etag, roles: ([.bindings[]? | select((.members // []) | index($member)) | .role] | unique | tojson), reason: ""} end
' "$workdir/body" 2> /dev/null || jq -cn '{status: "502", etag: "", roles: "[]", reason: "the allow policy is malformed"}'
