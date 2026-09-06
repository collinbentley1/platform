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
: > "$workdir/roles.jsonl"
original="$resource"
root_etag=""
read_resource() {
  local method="$1" name="$2"
  local args=(--silent --show-error --max-time 30 --max-filesize 1048576 --config "$workdir/auth.cfg" --request "$method" --output "$workdir/body" --write-out '%{http_code}')
  if [ "$method" = POST ]; then args+=(--header 'Content-Type: application/json' --data-binary "@$workdir/request.json"); fi
  status="$(curl "${args[@]}" "${endpoint}/v3/${name}" || echo 000)"
}
unread() {
  jq -cn --arg status "$1" --arg reason "$2" '{status: $status, etag: "", roles: "[]", cleanup_status: "UNREAD", reason: $reason}'
  exit 0
}
# A project can inherit the canary grant from any folder or the organization.
# Every parent read is mandatory; a direct empty policy alone is insufficient.
seen="|"
for depth in $(seq 1 20); do
  [[ "$resource" =~ ^(projects/[A-Za-z0-9._-]+|(folders|organizations)/[1-9][0-9]*)$ ]] || unread 502 "malformed ancestor"
  [[ "$seen" != *"|${resource}|"* ]] || unread 502 "ancestry cycle"
  seen="${seen}${resource}|"
  read_resource POST "${resource}:getIamPolicy"
  [ "$status" = 200 ] || unread "$status" "an Allow attachment could not be read"
  jq -ce --arg member "serviceAccount:${principal}" '
    if (.etag | type) != "string" or .etag == "" then error("missing etag") else
      [.bindings[]? | select((.members // []) | index($member)) | .role] end
  ' "$workdir/body" >> "$workdir/roles.jsonl" || unread 502 "the Allow policy is malformed"
  if [ -z "$root_etag" ]; then root_etag="$(jq -r '.etag' "$workdir/body")"; fi
  if [[ "$resource" == organizations/* ]]; then break; fi
  read_resource GET "$resource"
  [ "$status" = 200 ] || unread "$status" "an Allow ancestor could not be read"
  resource="$(jq -r '.parent // ""' "$workdir/body")"
  [[ "$resource" =~ ^(folders|organizations)/[1-9][0-9]*$ ]] || unread 502 "the Allow ancestry is incomplete"
  [ "$depth" != 20 ] || unread 502 "the Allow ancestry exceeds the read bound"
done
roles="$(jq -sc 'add | unique' "$workdir/roles.jsonl")"
cleanup_status=NOT_REQUESTED
folder="$(jq -r '.folder_id // ""' <<< "$query")"
project="$(jq -r '.canary_project // ""' <<< "$query")"
display="$(jq -r '.expected_display // ""' <<< "$query")"
if [ -n "$folder" ] || [ -n "$project" ]; then
  [[ "$original" =~ ^organizations/[1-9][0-9]*$ && "$folder" =~ ^[1-9][0-9]*$ && "$project" =~ ^deny-canary-[0-9]{1,12}$ && "$display" = "$project" ]] || unread 400 "the cleanup identity is malformed"
  if [ "$roles" != '[]' ]; then
    cleanup_status=NOT_RETIRED
  else
    cleanup_status=CLEAN
    for resource in "folders/${folder}" "projects/${project}"; do
      read_resource GET "$resource"
      if [ "$status" = 404 ]; then continue; fi
      [ "$status" = 200 ] || unread "$status" "the exact cleanup identity is unreadable after Allow retirement"
      if [[ "$resource" == folders/* ]]; then
        jq -e --arg name "$resource" --arg parent "$original" --arg display "$display" '.name == $name and .parent == $parent and .displayName == $display and .state == "DELETE_REQUESTED"' "$workdir/body" > /dev/null || cleanup_status=RETAINED
      else
        jq -e --arg id "$project" --arg parent "$original" '.projectId == $id and .parent == $parent and .state == "DELETE_REQUESTED"' "$workdir/body" > /dev/null || cleanup_status=RETAINED
      fi
    done
  fi
fi
jq -cn --arg etag "$root_etag" --arg roles "$roles" --arg cleanup "$cleanup_status" '{status: "200", etag: $etag, roles: $roles, cleanup_status: $cleanup, reason: ""}'
