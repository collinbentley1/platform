#!/bin/bash
# Produce the control, deny, or cleanup predicate for the reviewed Deny
# canary workflow. The control prepares every retained resource and grant
# before observing any request. It restores each exercise's state before the
# next observation; the deny phase makes the same requests under Deny.
#
# A separate, reviewed read-only witness reads actual preconditions and
# brackets every observation and its restoration with Allow evidence. Each
# snapshot binds project/folder ancestry, full Allow bindings, and the exact
# permission sets and versions of their roles. Only unconditional grants
# count. Policy etags are retained at phase boundaries; semantic policy
# hashes permit the observed no-op IAM writes to advance their etags.
#
# Every observation retains the raw request, body hash, actual pre-state,
# digest, required permissions, and terminal response. Four IAM create APIs
# reserve deleted names. Those rows use fresh control/deny names, with a
# comparison that substitutes only the documented create identifier and its
# matching resource name. All other bytes remain bound. The account-enable
# row uses its own prepared disabled account. The witness reads ledger state
# even when the canary cannot. Unknown state is never a positive precondition.
#
# Cleanup uses the persisted numeric folder identity and requires a readable
# terminal result. A disabled API or unread resource is unresolved. The live
# retirement reader subsequently checks inherited grants and rereads the
# exact folder/project IDs. Neither predicate includes a bearer credential.
#
# Required environment: PHASE, CONTROL_RUN_ID, ACCESS_TOKEN,
# CANARY_SERVICE_ACCOUNT, CANARY_WITNESS_ACCESS_TOKEN,
# CANARY_WITNESS_SERVICE_ACCOUNT, ORGANIZATION_ID, BROKER_IMAGE, and the
# GitHub run context. The witness must match authority.json and must differ
# from the canary. The workflow's existing controller mapping and read-only
# permissions are deployment prerequisites; this script grants neither.
# TRANSIENT_CLEANUP=1 removes this run's keys and queued builds and fails
# closed when it cannot enumerate or remove them. The sole argument is the
# output predicate path.
set -euo pipefail

output="${1:?output path}"
: "${PHASE:?}" "${CONTROL_RUN_ID:?}" "${ACCESS_TOKEN:?}" "${CANARY_SERVICE_ACCOUNT:?}" "${ORGANIZATION_ID:?}" "${BROKER_IMAGE:?}"
: "${CANARY_WITNESS_ACCESS_TOKEN:?}" "${CANARY_WITNESS_SERVICE_ACCOUNT:?}"
: "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}" "${GITHUB_SHA:?}" "${GITHUB_EVENT_NAME:?}" "${GITHUB_REPOSITORY_ID:?}" "${GITHUB_WORKFLOW_REF:?}"
[[ "$PHASE" =~ ^(control|deny|cleanup)$ ]] || { echo "PHASE must be control, deny, or cleanup." >&2; exit 2; }
[[ "$CONTROL_RUN_ID" =~ ^[1-9][0-9]*$ ]] || { echo "CONTROL_RUN_ID must be a run ID." >&2; exit 2; }
if [ "$PHASE" = control ] && [ "$CONTROL_RUN_ID" != "$GITHUB_RUN_ID" ]; then
  echo "The control phase names its own run; CONTROL_RUN_ID=${CONTROL_RUN_ID} is not run ${GITHUB_RUN_ID}." >&2
  exit 2
fi
if [ "$PHASE" != control ] && [ "$CONTROL_RUN_ID" = "$GITHUB_RUN_ID" ]; then
  echo "The ${PHASE} phase must name the control run, not itself." >&2
  exit 2
fi
[[ "$ORGANIZATION_ID" =~ ^[1-9][0-9]*$ ]]
[[ "$BROKER_IMAGE" =~ ^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]]
[[ "$CANARY_SERVICE_ACCOUNT" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$ ]]
transient_cleanup="${TRANSIENT_CLEANUP:-0}"
prepare_only=0

root="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=tools/ci/protected-recovery-canary-digest.sh
. "$root/tools/ci/protected-recovery-canary-digest.sh"
authority="$root/protected-recovery/authority.json"
reviewed_witness="$(jq -er '.broker.canaryWitnessServiceAccount | select(type == "string")' "$authority")"
[ "$CANARY_WITNESS_SERVICE_ACCOUNT" = "$reviewed_witness" ] || { echo "The witness differs from reviewed authority." >&2; exit 2; }
[ "$CANARY_WITNESS_SERVICE_ACCOUNT" != "$CANARY_SERVICE_ACCOUNT" ] || { echo "The read witness must differ from the mutating canary." >&2; exit 2; }
broker_project="$(jq -er '.broker.projectId | select(type == "string")' "$authority")"
broker_region="$(jq -er '.broker.region' "$authority")"
ledger_database="$(jq -er '.broker.firestoreDatabase' "$authority")"
evidence_bucket="${broker_project}-protected-recovery-evidence"
canary_principal="principal://iam.googleapis.com/projects/-/serviceAccounts/${CANARY_SERVICE_ACCOUNT}"
canary_member="serviceAccount:${CANARY_SERVICE_ACCOUNT}"
suffix="$(printf '%s' "$CONTROL_RUN_ID" | tail -c 12)"
throwaway="deny-canary-${suffix}"
throwaway_new="${throwaway}-new"
throwaway_gone="${throwaway}-gone"
delegate="${throwaway}-d"
enable_account="${throwaway}-e"
role_id="denyCanary${suffix}"
role_new="${role_id}New"
role_gone="${role_id}Gone"
create_new="${throwaway_new}-${PHASE:0:1}"
create_role_new="${role_new}${PHASE:0:1}"
canary_project="$throwaway"
constraint_new="compute.skipDefaultNetworkCreation"
constraint_kept="compute.requireOsLogin"
constraint_v1="compute.requireShieldedVm"
workflow_path="${GITHUB_WORKFLOW_REF#*/*/}"
workflow_path="${workflow_path%@*}"
zone="${broker_region}-a"

workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT
umask 077
printf 'header = "Authorization: Bearer %s"\n' "$ACCESS_TOKEN" > "$workdir/auth.cfg"
unset ACCESS_TOKEN
printf 'header = "Authorization: Bearer %s"\n' "$CANARY_WITNESS_ACCESS_TOKEN" > "$workdir/witness-auth.cfg"
unset CANARY_WITNESS_ACCESS_TOKEN
request_auth="$workdir/auth.cfg"

iam="https://iam.googleapis.com/v1"
credentials="https://iamcredentials.googleapis.com/v1"
crm="https://cloudresourcemanager.googleapis.com/v3"
crm_v1="https://cloudresourcemanager.googleapis.com/v1"
run="https://run.googleapis.com/v2"
scheduler="https://cloudscheduler.googleapis.com/v1"
registry="https://artifactregistry.googleapis.com"
firestore="https://firestore.googleapis.com/v1"
gcs="https://storage.googleapis.com"
compute="https://compute.googleapis.com/compute/v1"
cloudbuild="https://cloudbuild.googleapis.com/v1"
orgpolicy="https://orgpolicy.googleapis.com/v2"
serviceusage="https://serviceusage.googleapis.com/v1"
hello_image="us-docker.pkg.dev/cloudrun/container/hello"
token_creator="roles/iam.serviceAccountTokenCreator"

observations="$workdir/observations.jsonl"
: > "$observations"
allow_interval="$workdir/allow-interval.jsonl"
: > "$allow_interval"
allow_policies="$workdir/allow-policies.jsonl"
: > "$allow_policies"
removed="$workdir/removed"
: > "$removed"
failures="$workdir/failures"
: > "$failures"
last_status=000
last_outcome=ERROR
operation_json=null
pre_observed=unknown
pre_detail=""
folder_id=""
declare -A manifest_gone=()
manifest_ids="$workdir/manifest-ids.jsonl"
: > "$manifest_ids"

fail() {
  echo "$1" >> "$failures"
  echo "${PHASE}: $1" >&2
}

# One API call: the HTTP status in $last_status, the body in $workdir/body.
# The optional body is a file; a body's content type defaults to JSON.
call() {
  local method="$1" url="$2" body="${3:-}" content_type="${4:-}"
  local args=(--silent --show-error --max-time 120 --config "$request_auth" --request "$method" --output "$workdir/body" --write-out '%{http_code}')
  if [ -n "$body" ]; then
    [ -n "$content_type" ] || content_type=application/json
    args+=(--header "Content-Type: ${content_type}" --data-binary "@$body")
  fi
  : > "$workdir/body"
  last_status="$(curl "${args[@]}" "$url" || echo 000)"
}

# The witness only reads. Its reviewed identity has no canary mutation role.
witness_call() {
  local method="$1" url="$2"
  if [ "$method" != GET ] && ! { [ "$method" = POST ] && [[ "$url" == *:getIamPolicy ]]; }; then
    fail "the witness may only read resource state and Allow policies"
    last_status=000
    return 1
  fi
  request_auth="$workdir/witness-auth.cfg"
  call "$@"
  request_auth="$workdir/auth.cfg"
}

json_body() {
  local file
  file="$(mktemp "$workdir/request.XXXXXX")"
  printf '%s' "$1" > "$file"
  printf '%s\n' "$file"
}

# Classify the answer of one exercise from the API's own words: success is
# ALLOWED; a 403 whose ErrorInfo is an IAM permission denial is DENIED and
# names the permission it denied; a 403 whose ErrorInfo is SERVICE_DISABLED
# is UNSERVICEABLE and names the service; anything else is ERROR. A 403 with
# no ErrorInfo at all is ERROR: the denial's cause is what is attested, never
# the status alone.
classify() {
  jq -c --arg status "$last_status" '
    def v2(p): if (p | test("googleapis\\.com/")) then p
      elif (p | test("^resourcemanager\\.")) then ("cloudresourcemanager.googleapis.com/" + (p | sub("^resourcemanager\\."; "")))
      else ((p | split(".")[0]) + ".googleapis.com/" + (p | sub("^[a-z]+\\."; ""))) end;
    (try (.error.details // []) catch []) as $details
    | ([$details[] | select(type == "object" and ((."@type" // "") | endswith("ErrorInfo")))] | .[0]) as $info
    | (try (.error.message // "" | .[0:300]) catch "") as $message
    | {status: $status, reason: ($info.reason // ""), rawPermission: ($info.metadata.permission // ""), service: ($info.metadata.service // ""), message: $message}
    | .permission = (if .rawPermission == "" then "" else v2(.rawPermission) end)
    | .outcome = (if ($status | test("^2")) then "ALLOWED"
        elif $status == "403" and .reason == "IAM_PERMISSION_DENIED" and .permission != "" then "DENIED"
        elif $status == "403" and .reason == "SERVICE_DISABLED" then "UNSERVICEABLE"
        else "ERROR" end)
  ' "$workdir/body" 2> /dev/null || jq -cn --arg status "$last_status" '{status: $status, reason: "", rawPermission: "", service: "", message: "", permission: "", outcome: (if ($status | test("^2")) then "ALLOWED" else "ERROR" end)}'
}

service_disabled() {
  [ "$last_status" = 403 ] && jq -e '[.error.details[]? | select(.reason == "SERVICE_DISABLED")] | length > 0' "$workdir/body" > /dev/null 2>&1
}

# Wait for the long-running operation the last answer named. IAM, Cloud Run,
# Artifact Registry, Resource Manager, and Service Usage operations are read
# at their own name; Compute operations at their self link. The result is
# $operation_json; an operation that ends in error, or does not end within
# the bound, returns 1 and is recorded as a failure of the phase.
wait_operation() {
  local kind="$1" name="" url=""
  operation_json=null
  [[ "$last_status" =~ ^2 ]] || return 0
  case "$kind" in
    iam) name="$(jq -r '.name // ""' "$workdir/body")"; url="${iam}/${name}" ;;
    run) name="$(jq -r '.name // ""' "$workdir/body")"; url="${run}/${name}" ;;
    registry) name="$(jq -r '.name // ""' "$workdir/body")"; url="${registry}/v1/${name}" ;;
    crm) name="$(jq -r '.name // ""' "$workdir/body")"; url="${crm}/${name}" ;;
    serviceusage) name="$(jq -r '.name // ""' "$workdir/body")"; url="${serviceusage}/${name}" ;;
    compute) name="$(jq -r '.name // ""' "$workdir/body")"; url="$(jq -r '.selfLink // ""' "$workdir/body")" ;;
  esac
  [ -n "$name" ] && [ -n "$url" ] || return 0
  local _
  for _ in $(seq 1 90); do
    if [ "$kind" = compute ]; then
      if [ "$(jq -r '.status // ""' "$workdir/body")" = DONE ]; then
        operation_json="$(jq -c '{name: .name, done: true, error: (.error // null)}' "$workdir/body")"
        break
      fi
    elif [ "$(jq -r '.done // false' "$workdir/body")" = true ]; then
      operation_json="$(jq -c '{name: .name, done: true, error: (.error // null)}' "$workdir/body")"
      break
    fi
    sleep 2
    call GET "$url"
    [[ "$last_status" =~ ^2 ]] || { fail "operation ${url} could not be read: HTTP ${last_status}"; operation_json="$(jq -cn --arg name "$name" '{name: $name, done: false, error: null}')"; return 1; }
  done
  if [ "$operation_json" = null ]; then
    fail "operation ${url} did not complete in time"
    operation_json="$(jq -cn --arg name "$name" '{name: $name, done: false, error: null}')"
    return 1
  fi
  if [ "$(jq -r '.error' <<< "$operation_json")" != null ]; then
    fail "operation ${url} ended in error: $(jq -c '.error' <<< "$operation_json" | cut -c1-300)"
    return 1
  fi
  return 0
}

# The existence state of the resource a row's permission is judged on, read
# immediately before the request: present, absent, deleted (a soft-deleted
# name), enabled or disabled (an API), or unknown when the read itself is
# refused or the API is disabled. A project's detail is its current parent.
pre_state() {
  local kind="$1" name="$2"
  pre_observed=unknown
  pre_detail=""
  case "$kind" in
    none) pre_observed=none; return 0 ;;
    iam)
      local read_name="$name"
      if [[ "$name" == projects/-/serviceAccounts/*@*.iam.gserviceaccount.com ]]; then
        local account_project="${name##*@}"
        account_project="${account_project%.iam.gserviceaccount.com}"
        read_name="projects/${account_project}/serviceAccounts/${name##*/}"
      fi
      witness_call GET "${iam}/${read_name}"
      ;;
    run) witness_call GET "${run}/${name}" ;;
    scheduler) witness_call GET "${scheduler}/${name}" ;;
    registry) witness_call GET "${registry}/v1/${name}" ;;
    firestore) witness_call GET "${firestore}/${name}" ;;
    gcs) witness_call GET "${gcs}/storage/v1/${name}" ;;
    compute) witness_call GET "${compute}/${name}" ;;
    project) witness_call GET "${crm}/${name}" ;;
    orgpolicy) witness_call GET "${orgpolicy}/${name}" ;;
    service) witness_call GET "${serviceusage}/${name}" ;;
    *) fail "unknown pre-state kind ${kind}"; return 0 ;;
  esac
  if [ "$last_status" = 404 ]; then
    pre_observed=absent
  elif [[ "$last_status" =~ ^2 ]]; then
    case "$kind" in
      service)
        case "$(jq -r '.state // ""' "$workdir/body")" in
          ENABLED) pre_observed=enabled ;;
          DISABLED) pre_observed=disabled ;;
        esac
        ;;
      project)
        pre_observed=present
        pre_detail="$(jq -r '.parent // ""' "$workdir/body")"
        ;;
      iam)
        if jq -e '(.state == "DELETED") or (.deleted == true)' "$workdir/body" > /dev/null 2>&1; then
          pre_observed=deleted
        else
          pre_observed=present
          if [[ "$name" == */serviceAccounts/* ]]; then
            pre_detail="$(jq -r 'if .disabled == true then "disabled" else "enabled" end' "$workdir/body")"
          fi
        fi
        ;;
      *)
        if jq -e '(.state == "DELETED") or (.deleted == true)' "$workdir/body" > /dev/null 2>&1; then pre_observed=deleted; else pre_observed=present; fi
        ;;
    esac
  fi
}

# The exercise of one row: the pre-state read, one real request, its answer
# classified -- a started operation waited to its end, a denial naming any
# permission but the row's turned into an error -- and recorded against the
# attachment point, the permission, the requesting principal, the request
# and its digest, the pre-state, and the permissions the request needs.
#
#   observe <attachment> <permission> <method> <url> <body|""> <content-type|""> <pre-kind> <pre-name> <expected> <requires> [lro-kind]
observe() {
  local attachment="$1" permission="$2" method="$3" url="$4" body="${5:-}" content_type="${6:-}" pre_kind="$7" pre_name="$8" expected="$9" requires="${10}" lro="${11:-}"
  [ -z "$body" ] || [ -n "$content_type" ] || content_type=application/json
  if [ -n "${pending_attachment:-}" ]; then record_allow_boundary after "$pending_attachment" "$pending_permission"; fi
  record_allow_boundary before "$attachment" "$permission"
  [ ! -s "$failures" ] || return 1
  pending_attachment="$attachment"
  pending_permission="$permission"
  pre_state "$pre_kind" "$pre_name"
  local body_sha digest classified
  body_sha="$(canary_body_sha256 "$body" "$content_type")"
  digest="$(canary_digest "$method" "$url" "$content_type" "$body_sha" "$pre_name" "$expected" "$pre_detail" "$pre_observed")"
  local comparison=null pair=null current_id canonical_id
  case "$permission" in
    iam.googleapis.com/serviceAccounts.create|iam.googleapis.com/workloadIdentityPools.create|iam.googleapis.com/workloadIdentityPoolProviders.create)
      current_id="$create_new"; canonical_id="$throwaway_new" ;;
    iam.googleapis.com/roles.create) current_id="$create_role_new"; canonical_id="$role_new" ;;
    *) current_id=""; canonical_id="" ;;
  esac
  if [ -n "$current_id" ]; then
    comparison="$(canary_create_comparison "$permission" "$url" "$body" "$pre_name" "$current_id" "$canonical_id" "$expected" "$pre_detail" "$pre_observed")" || { fail "the create request does not match its exact paired identifier"; return 0; }
    pair="$(jq -cn --arg kind "$permission" --arg actual "$current_id" --arg canonical "$canonical_id" '{kind: $kind, actualId: $actual, canonicalId: $canonical}')"
  fi
  call "$method" "$url" "$body" "$content_type"
  classified="$(classify)"
  last_outcome="$(jq -r '.outcome' <<< "$classified")"
  operation_json=null
  if [ "$last_outcome" = ALLOWED ] && [ -n "$lro" ] && ! wait_operation "$lro"; then
    classified="$(jq -c '.outcome = "ERROR" | .message = "the operation the request started did not complete successfully"' <<< "$classified")"
    last_outcome=ERROR
  fi
  if [ "$last_outcome" = DENIED ] && [ "$(jq -r '.permission' <<< "$classified")" != "$permission" ]; then
    fail "${attachment#cloudresourcemanager.googleapis.com/} ${permission}: the denial names $(jq -r '.permission' <<< "$classified"), not the row's permission"
    classified="$(jq -c '.outcome = "ERROR"' <<< "$classified")"
    last_outcome=ERROR
  fi
  jq -cn --arg attachment "$attachment" --arg permission "$permission" --arg principal "$canary_principal" --arg method "$method" --arg url "$url" --arg content_type "$content_type" --arg body_sha "$body_sha" \
    --arg resource "$pre_name" --arg expected "$expected" --arg observed "$pre_observed" --arg detail "$pre_detail" --arg requires "$requires" --arg digest "$digest" --argjson comparison "$comparison" --argjson pair "$pair" --argjson operation "$operation_json" --argjson answer "$classified" \
    '{attachment: $attachment, permission: $permission, principal: $principal, observedAt: (now | todateiso8601), outcome: $answer.outcome,
      request: {method: $method, url: $url, contentType: $content_type, bodySha256: $body_sha},
      preState: {resource: $resource, expected: $expected, observed: $observed, detail: $detail},
      comparison: $comparison, resourcePair: $pair,
      requires: ($requires | split(",") | map(select(length > 0))), operation: $operation, digest: $digest, response: ($answer | del(.outcome))}' >> "$observations"
  echo "${PHASE}: ${attachment#cloudresourcemanager.googleapis.com/} ${permission} -> ${last_outcome} (${last_status}; pre-state ${pre_observed}, required ${expected})"
}

# A provisioning or reverting request of the control phase, never an
# observation: it must succeed, and an operation it starts must end without
# error, or the phase has failed to establish the state the observations
# require and is refused attestation.
provision() {
  local method="$1" url="$2" body="${3:-}" content_type="${4:-}" lro="${5:-}"
  [ -z "$body" ] || [ -n "$content_type" ] || content_type=application/json
  call "$method" "$url" "$body" "$content_type"
  if ! [[ "$last_status" =~ ^2 ]]; then
    fail "provisioning ${method} ${url} answered HTTP ${last_status}: $(jq -r '.error.message // "" | .[0:200]' "$workdir/body" 2> /dev/null)"
    return 1
  fi
  [ -z "$lro" ] || wait_operation "$lro" || return 1
  return 0
}

# The control phase provisions and reverts; the deny phase makes only the
# observed requests, which the rules refuse.
provisioning() {
  [ "$PHASE" = control ]
}

preparing() {
  [ "$prepare_only" = 1 ]
}

# Snapshot the unconditional grant paths used by the exercises. The witness
# binds every project ancestor and every role definition, including custom
# roles. Policy etags are retained; semantic hashes permit only the canary's
# observed no-op policy writes to advance their compare-and-set tokens.
allow_snapshot() {
  local resource="$1" url="$2" delegate_member="${3:-}"
  witness_call POST "$url" "$(json_body '{"options":{"requestedPolicyVersion":3}}')"
  if [ "$last_status" != 200 ]; then
    fail "the allow policy of ${resource} could not be read: HTTP ${last_status}"
    return 0
  fi
  jq -ce --arg resource "$resource" --arg canary "$canary_member" --arg delegate "$delegate_member" '
    if (.etag | type) != "string" or .etag == "" then error("missing policy etag") else . end
    | {resource: $resource, etag: .etag,
      bindings: ([.bindings[]? | {role, members: (.members | sort), condition: (.condition // null)}] | sort_by(.role, .condition)),
      canaryRoles: ([.bindings[]? | select((.members // []) | index($canary)) | select(.condition == null) | .role] | unique),
      delegateRoles: (if $delegate == "" then [] else ([.bindings[]? | select((.members // []) | index($delegate)) | select(.condition == null) | .role] | unique) end)}
  ' "$workdir/body" >> "$allow_policies" || fail "the Allow policy of ${resource} is malformed"
}

allow_snapshots() {
  : > "$allow_policies"
  : > "$workdir/hierarchy.jsonl"
  local attachment project scope resource parent depth
  declare -A seen=()
  while IFS=$'\t' read -r attachment project scope; do
    if [ "$scope" = organization ]; then resource="organizations/${ORGANIZATION_ID}"; else resource="projects/${project}"; fi
    for depth in $(seq 1 20); do
      if [ -n "${seen[$resource]:-}" ]; then break; fi
      seen[$resource]=1
      allow_snapshot "$resource" "${crm}/${resource}:getIamPolicy"
      if [[ "$resource" == organizations/* ]]; then
        [ "$resource" = "organizations/${ORGANIZATION_ID}" ] || fail "${resource}: ancestor differs from reviewed organization"
        break
      fi
      witness_call GET "${crm}/${resource}"
      parent="$(jq -r '.parent // ""' "$workdir/body")"
      if [ "$last_status" != 200 ] || ! [[ "$parent" =~ ^(folders|organizations)/[1-9][0-9]*$ ]]; then
        fail "${resource}: ancestry is unreadable"
        break
      fi
      jq -cn --arg resource "$resource" --arg parent "$parent" '{resource: $resource, parent: $parent}' >> "$workdir/hierarchy.jsonl"
      resource="$parent"
      if [ "$depth" = 20 ]; then fail "the project ancestry exceeds the read bound"; fi
    done
  done < "$attachments"
  # Movement exercises also inherit from their created project and folder.
  allow_snapshot "projects/${canary_project}" "${crm}/projects/${canary_project}:getIamPolicy"
  allow_snapshot "folders/${folder_id}" "${crm}/folders/${folder_id}:getIamPolicy"
  witness_call GET "${crm}/projects/${canary_project}"
  if [ "$last_status" != 200 ] || [ "$(jq -r '.parent // ""' "$workdir/body")" != "organizations/${ORGANIZATION_ID}" ]; then fail "the movement project was not restored to its original parent"; fi
  jq -cn --arg resource "projects/${canary_project}" --arg parent "organizations/${ORGANIZATION_ID}" '{resource: $resource, parent: $parent}' >> "$workdir/hierarchy.jsonl"
  witness_call GET "${crm}/folders/${folder_id}"
  if [ "$last_status" != 200 ] || ! jq -e --arg name "folders/${folder_id}" --arg parent "organizations/${ORGANIZATION_ID}" --arg display "$throwaway" '.name == $name and .parent == $parent and .displayName == $display and .state == "ACTIVE"' "$workdir/body" > /dev/null; then fail "the movement folder identity or parent changed"; fi
  jq -cn --arg resource "folders/${folder_id}" --arg parent "organizations/${ORGANIZATION_ID}" '{resource: $resource, parent: $parent}' >> "$workdir/hierarchy.jsonl"
  allow_snapshot "projects/${broker_project}/serviceAccounts/$(service_account_email "$throwaway" "$broker_project")" "${iam}/projects/${broker_project}/serviceAccounts/$(service_account_email "$throwaway" "$broker_project"):getIamPolicy" "serviceAccount:$(service_account_email "$delegate" "$broker_project")"
  allow_snapshot "projects/${broker_project}/serviceAccounts/$(service_account_email "$delegate" "$broker_project")" "${iam}/projects/${broker_project}/serviceAccounts/$(service_account_email "$delegate" "$broker_project"):getIamPolicy"
  : > "$workdir/roles.jsonl"
  local role
  while IFS= read -r role; do
    [[ "$role" =~ ^(roles/[A-Za-z0-9._]+|(projects|organizations)/[A-Za-z0-9._-]+/roles/[A-Za-z0-9._]+)$ ]] || { fail "malformed role in Allow evidence"; continue; }
    witness_call GET "${iam}/${role}"
    if [ "$last_status" != 200 ]; then fail "${role}: role definition is unreadable"; continue; fi
    jq -ce --arg name "$role" '
      def v2(p): (p | split(".")) as $parts | (if $parts[0] == "resourcemanager" then "cloudresourcemanager" else $parts[0] end) + ".googleapis.com/" + ($parts[1:] | join("."));
      if .name != $name or (.includedPermissions | type) != "array" or .deleted == true or .stage == "DISABLED" then error("unusable role") else . end
      | {name, etag: (.etag // ""), stage, permissions: ([.includedPermissions[] | v2(.)] | unique)}
    ' "$workdir/body" >> "$workdir/roles.jsonl" || fail "${role}: role definition cannot confer the exercised permissions"
  done < <(jq -sr '[.[] | (.canaryRoles + .delegateRoles)[]] | unique[]' "$allow_policies")
  jq -scS --slurpfile roles "$workdir/roles.jsonl" --slurpfile hierarchy "$workdir/hierarchy.jsonl" '
    ($hierarchy | map({key: .resource, value: .parent}) | from_entries) as $parents
    | {policies: (sort_by(.resource) | map(del(.etag))), roles: ($roles | sort_by(.name)), hierarchy: ($hierarchy | sort_by(.resource)),
      paths: ([$parents | keys[] | {resource: ., ancestors: [limit(21; recurse($parents[.] // empty))]}] | sort_by(.resource))}
  ' "$allow_policies" > "$workdir/allow-snapshot.json"
}

record_allow_boundary() {
  local position="$1" attachment="${2:-}" permission="${3:-}"
  allow_snapshots
  local snapshot_sha
  snapshot_sha="$(canary_snapshot_sha256 "$workdir/allow-snapshot.json")"
  jq -cn --arg snapshot "$snapshot_sha" --arg position "$position" --arg attachment "$attachment" --arg permission "$permission" --arg witness "$CANARY_WITNESS_SERVICE_ACCOUNT" '{snapshotSha256: $snapshot, position: $position, attachment: $attachment, permission: $permission, witness: $witness, observedAt: (now | todateiso8601)}' >> "$allow_interval"
  if [ ! -f "$workdir/allow-baseline.json" ]; then
    cp "$workdir/allow-snapshot.json" "$workdir/allow-baseline.json"
  elif ! cmp -s "$workdir/allow-baseline.json" "$workdir/allow-snapshot.json"; then
    fail "the effective Allow policies, ancestry, or role definitions changed during the exercise"
  fi
}

service_account_email() {
  printf '%s@%s.iam.gserviceaccount.com' "$1" "$2"
}

# What later phases cannot rederive -- the unique ID of the deleted account
# the undelete row addresses, the folder the movement row addresses -- is
# kept in the description of the retained throwaway account of the project.
manifest_write() {
  local project="$1"
  local email
  email="$(service_account_email "$throwaway" "$project")"
  jq -cn --arg project "$project" --arg id "${manifest_gone[$project]:-}" '{key: $project, value: $id}' >> "$manifest_ids"
  provision PATCH "${iam}/projects/-/serviceAccounts/${email}?updateMask=description" "$(json_body "$(jq -cn --arg gone "${manifest_gone[$project]:-}" --arg folder "$folder_id" --arg control "$CONTROL_RUN_ID" --arg sha "$GITHUB_SHA" '{description: ({gone: $gone, folder: $folder, controlRunId: $control, headSha: $sha} | tojson)}')")" || true
}

manifest_read() {
  local project="$1"
  if [ -z "${CONTROL_PREDICATE:-}" ] || [ ! -f "$CONTROL_PREDICATE" ]; then
    # Failed controls still need cleanup. Their prepared carrier records the
    # exact folder ID. Successful controls use the immutable signed artifact,
    # which remains available after the carrier has been deleted.
    [ "$PHASE" = cleanup ] || { fail "the verified control artifact is required"; return 1; }
    witness_call GET "${iam}/projects/${project}/serviceAccounts/$(service_account_email "$throwaway" "$project")"
    if [ "$last_status" != 200 ] || ! jq -e --arg control "$CONTROL_RUN_ID" --arg sha "$GITHUB_SHA" '(.description | fromjson) | .controlRunId == $control and .headSha == $sha and (.folder | test("^[1-9][0-9]*$"))' "$workdir/body" > /dev/null; then
      fail "the failed control's cleanup identities are unreadable"
      return 1
    fi
    folder_id="$(jq -r '.description | fromjson | .folder' "$workdir/body")"
    manifest_gone[$project]="$(jq -r '.description | fromjson | .gone' "$workdir/body")"
    return 0
  fi
  if ! jq -e --arg control "$CONTROL_RUN_ID" --arg sha "$GITHUB_SHA" --arg image "$BROKER_IMAGE" --arg name "$throwaway" --arg witness "$CANARY_WITNESS_SERVICE_ACCOUNT" '.schema == "protected-recovery/deny-canary/v3" and .phase == "control" and .controlRunId == $control and .run.headSha == $sha and .brokerImage == $image and .throwaways.name == $name and .throwaways.project == $name and .witnessServiceAccount == $witness and (.throwaways.folder | test("^[1-9][0-9]*$"))' "$CONTROL_PREDICATE" > /dev/null; then
    fail "the verified control manifest does not match this phase"
    return 1
  fi
  manifest_gone[$project]="$(jq -er --arg project "$project" '.throwaways.goneUniqueIds[$project] | select(type == "string" and test("^[1-9][0-9]*$"))' "$CONTROL_PREDICATE")" || { fail "the control manifest has no permanent deleted-account identity for ${project}"; return 1; }
  folder_id="$(jq -r '.throwaways.folder' "$CONTROL_PREDICATE")"
  jq -cn --arg project "$project" --arg id "${manifest_gone[$project]}" '{key: $project, value: $id}' >> "$manifest_ids"

}

# ---------------------------------------------------------------------------
# The identity rows of one project: the throwaway accounts and their keys,
# tokens, signatures, policy, and lifecycle; the throwaway pools and
# providers. The control phase provisions the retained, deleted, and delegate
# names; both phases make the same requests in the same pre-states.
# ---------------------------------------------------------------------------
identity_rows() {
  local attachment="$1" project="$2" scope="$3"
  local email sa email_new sa_new email_gone sa_gone email_delegate sa_delegate pool pool_new pool_gone provider provider_new provider_gone unique_id
  email="$(service_account_email "$throwaway" "$project")"
  sa="projects/-/serviceAccounts/${email}"
  email_new="$(service_account_email "$create_new" "$project")"
  sa_new="projects/-/serviceAccounts/${email_new}"
  email_gone="$(service_account_email "$throwaway_gone" "$project")"
  sa_gone="projects/-/serviceAccounts/${email_gone}"
  email_delegate="$(service_account_email "$delegate" "$project")"
  sa_delegate="projects/-/serviceAccounts/${email_delegate}"
  pool="projects/${project}/locations/global/workloadIdentityPools/${throwaway}"
  pool_new="projects/${project}/locations/global/workloadIdentityPools/${create_new}"
  pool_gone="projects/${project}/locations/global/workloadIdentityPools/${throwaway_gone}"
  provider="${pool}/providers/${throwaway}"
  provider_new="${pool}/providers/${create_new}"
  provider_gone="${pool}/providers/${throwaway_gone}"
  local account_body='{"serviceAccount":{"displayName":"Protected recovery Deny canary throwaway"}}'
  local pool_body='{"displayName":"Protected recovery Deny canary throwaway"}'
  local provider_body='{"displayName":"Protected recovery Deny canary throwaway","oidc":{"issuerUri":"https://token.actions.githubusercontent.com/"},"attributeMapping":{"google.subject":"assertion.sub"},"attributeCondition":"false"}'

  if preparing; then
    provision POST "${iam}/projects/${project}/serviceAccounts" "$(json_body "$(jq -cn --arg id "$throwaway" --argjson base "$account_body" '$base + {accountId: $id}')")" || true
    if [ "$scope" = broker ]; then
      provision POST "${iam}/projects/${project}/serviceAccounts" "$(json_body "$(jq -cn --arg id "$delegate" --argjson base "$account_body" '$base + {accountId: $id}')")" || true
    fi
    if provision POST "${iam}/projects/${project}/serviceAccounts" "$(json_body "$(jq -cn --arg id "$throwaway_gone" --argjson base "$account_body" '$base + {accountId: $id}')")"; then
      manifest_gone[$project]="$(jq -r '.uniqueId // ""' "$workdir/body")"
      provision DELETE "${iam}/${sa_gone}" || true
    fi
    provision POST "${iam}/projects/${project}/locations/global/workloadIdentityPools?workloadIdentityPoolId=${throwaway}" "$(json_body "$pool_body")" "" iam || true
    provision POST "${iam}/${pool}/providers?workloadIdentityPoolProviderId=${throwaway}" "$(json_body "$provider_body")" "" iam || true
    provision POST "${iam}/projects/${project}/locations/global/workloadIdentityPools?workloadIdentityPoolId=${throwaway_gone}" "$(json_body "$pool_body")" "" iam && provision DELETE "${iam}/${pool_gone}" "" "" iam || true
    provision POST "${iam}/${pool}/providers?workloadIdentityPoolProviderId=${throwaway_gone}" "$(json_body "$provider_body")" "" iam && provision DELETE "${iam}/${provider_gone}" "" "" iam || true
    provision POST "${iam}/projects/${project}/serviceAccounts" "$(json_body "$(jq -cn --arg id "$enable_account" --argjson base "$account_body" '$base + {accountId: $id}')")" && provision POST "${iam}/projects/-/serviceAccounts/$(service_account_email "$enable_account" "$project"):disable" "$(json_body '{}')" || true
    # New accounts and pools propagate before they are addressed.
    sleep 15
  elif [ "$PHASE" = deny ]; then
    manifest_read "$project"
  fi
  local gone_id="${manifest_gone[$project]:-0}"

  if preparing; then
    if [ "$scope" = broker ]; then
      provision POST "${iam}/${sa_delegate}:setIamPolicy" "$(json_body "$(jq -cn --arg role "$token_creator" --arg canary "$canary_member" '{policy: {bindings: [{role: $role, members: [$canary]}], version: 3}, updateMask: "bindings"}')")" || true
      provision POST "${iam}/${sa}:setIamPolicy" "$(json_body "$(jq -cn --arg role "$token_creator" --arg canary "$canary_member" --arg delegate "serviceAccount:${email_delegate}" '{policy: {bindings: [{role: $role, members: [$canary, $delegate]}], version: 3}, updateMask: "bindings"}')")" || true
    fi
    return 0
  fi
  observe "$attachment" iam.googleapis.com/serviceAccounts.create POST "${iam}/projects/${project}/serviceAccounts" "$(json_body "$(jq -cn --arg id "$create_new" --argjson base "$account_body" '$base + {accountId: $id}')")" "" iam "$sa_new" absent iam.googleapis.com/serviceAccounts.create
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision DELETE "${iam}/${sa_new}" || true; fi

  observe "$attachment" iam.googleapis.com/serviceAccountKeys.create POST "${iam}/${sa}/keys" "$(json_body '{"privateKeyType":"TYPE_GOOGLE_CREDENTIALS_FILE","keyAlgorithm":"KEY_ALG_RSA_2048"}')" "" iam "$sa" present iam.googleapis.com/serviceAccountKeys.create
  if [ "$last_outcome" = ALLOWED ]; then
    local key
    key="$(jq -r '.name // ""' "$workdir/body")"
    [ -n "$key" ] && provision DELETE "${iam}/${key}" || true
  fi

  if [ "$scope" = broker ]; then
    # The chain: the canary may delegate through the delegate, the delegate
    # may mint for the target, and the canary may mint for the target
    # directly. The observed policy write on the target is the provisioning
    # of the target's edge; the delegate's edge is provisioned quietly.
    observe "$attachment" iam.googleapis.com/serviceAccounts.setIamPolicy POST "${iam}/${sa}:setIamPolicy" "$(json_body "$(jq -cn --arg role "$token_creator" --arg canary "$canary_member" --arg delegate "serviceAccount:${email_delegate}" '{policy: {bindings: [{role: $role, members: [$canary, $delegate]}], version: 3}, updateMask: "bindings"}')")" "" iam "$sa" present iam.googleapis.com/serviceAccounts.setIamPolicy
    # A new grant propagates before the token requests that rest on it.
    if provisioning && [ "$last_outcome" = ALLOWED ]; then sleep 60; fi
    observe "$attachment" iam.googleapis.com/serviceAccounts.getAccessToken POST "${credentials}/${sa}:generateAccessToken" "$(json_body '{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"300s"}')" "" iam "$sa" present iam.googleapis.com/serviceAccounts.getAccessToken
    observe "$attachment" iam.googleapis.com/serviceAccounts.getOpenIdToken POST "${credentials}/${sa}:generateIdToken" "$(json_body '{"audience":"https://deny-canary.invalid","includeEmail":false}')" "" iam "$sa" present iam.googleapis.com/serviceAccounts.getOpenIdToken
    observe "$attachment" iam.googleapis.com/serviceAccounts.implicitDelegation POST "${credentials}/${sa}:generateAccessToken" "$(json_body "$(jq -cn --arg delegate "$sa_delegate" '{scope: ["https://www.googleapis.com/auth/cloud-platform"], lifetime: "300s", delegates: [$delegate]}')")" "" iam "$sa" present "iam.googleapis.com/serviceAccounts.implicitDelegation,iam.googleapis.com/serviceAccounts.getAccessToken"
    observe "$attachment" iam.googleapis.com/serviceAccounts.signBlob POST "${credentials}/${sa}:signBlob" "$(json_body '{"payload":"ZGVueS1jYW5hcnk="}')" "" iam "$sa" present iam.googleapis.com/serviceAccounts.signBlob
    observe "$attachment" iam.googleapis.com/serviceAccounts.signJwt POST "${credentials}/${sa}:signJwt" "$(json_body '{"payload":"{\"iss\":\"deny-canary\"}"}')" "" iam "$sa" present iam.googleapis.com/serviceAccounts.signJwt
  else
    observe "$attachment" iam.googleapis.com/serviceAccounts.setIamPolicy POST "${iam}/${sa}:setIamPolicy" "$(json_body '{"policy":{"version":3},"updateMask":"bindings"}')" "" iam "$sa" present iam.googleapis.com/serviceAccounts.setIamPolicy
  fi

  observe "$attachment" iam.googleapis.com/serviceAccounts.disable POST "${iam}/${sa}:disable" "$(json_body '{}')" "" iam "$sa" present iam.googleapis.com/serviceAccounts.disable
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision POST "${iam}/${sa}:enable" "$(json_body '{}')" || true; fi
  local sa_enable="projects/-/serviceAccounts/$(service_account_email "$enable_account" "$project")"
  observe "$attachment" iam.googleapis.com/serviceAccounts.enable POST "${iam}/${sa_enable}:enable" "$(json_body '{}')" "" iam "$sa_enable" present iam.googleapis.com/serviceAccounts.enable
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision POST "${iam}/${sa_enable}:disable" "$(json_body '{}')" || true; fi

  call GET "${iam}/${sa}"
  unique_id="$(jq -r '.uniqueId // ""' "$workdir/body")"
  observe "$attachment" iam.googleapis.com/serviceAccounts.delete DELETE "${iam}/${sa}" "" "" iam "$sa" present iam.googleapis.com/serviceAccounts.delete
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision POST "${iam}/projects/-/serviceAccounts/${unique_id:-0}:undelete" "$(json_body '{}')" || true; fi
  # IAM get does not expose a deleted-account tombstone. Read the permanent
  # ID from the control manifest, never a reusable email. The successful
  # control undelete and subsequent delete bind this ID; Terraform limits
  # the control-to-deny interval to 24 hours, within the recovery window.
  observe "$attachment" iam.googleapis.com/serviceAccounts.undelete POST "${iam}/projects/-/serviceAccounts/${gone_id}:undelete" "$(json_body '{}')" "" iam "projects/${project}/serviceAccounts/${gone_id}" absent iam.googleapis.com/serviceAccounts.undelete
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision DELETE "${iam}/${sa_gone}" || true; fi

  observe "$attachment" iam.googleapis.com/workloadIdentityPools.create POST "${iam}/projects/${project}/locations/global/workloadIdentityPools?workloadIdentityPoolId=${create_new}" "$(json_body "$pool_body")" "" iam "$pool_new" absent iam.googleapis.com/workloadIdentityPools.create iam
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision DELETE "${iam}/${pool_new}" "" "" iam || true; fi
  observe "$attachment" iam.googleapis.com/workloadIdentityPoolProviders.create POST "${iam}/${pool}/providers?workloadIdentityPoolProviderId=${create_new}" "$(json_body "$provider_body")" "" iam "$provider_new" absent iam.googleapis.com/workloadIdentityPoolProviders.create iam
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision DELETE "${iam}/${provider_new}" "" "" iam || true; fi
  observe "$attachment" iam.googleapis.com/workloadIdentityPools.update PATCH "${iam}/${pool}?updateMask=description" "$(json_body '{"description":"protected-recovery deny canary"}')" "" iam "$pool" present iam.googleapis.com/workloadIdentityPools.update iam
  observe "$attachment" iam.googleapis.com/workloadIdentityPoolProviders.update PATCH "${iam}/${provider}?updateMask=description" "$(json_body '{"description":"protected-recovery deny canary"}')" "" iam "$provider" present iam.googleapis.com/workloadIdentityPoolProviders.update iam
  observe "$attachment" iam.googleapis.com/workloadIdentityPoolProviders.delete DELETE "${iam}/${provider}" "" "" iam "$provider" present iam.googleapis.com/workloadIdentityPoolProviders.delete iam
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision POST "${iam}/${provider}:undelete" "$(json_body '{}')" "" iam || true; fi
  observe "$attachment" iam.googleapis.com/workloadIdentityPoolProviders.undelete POST "${iam}/${provider_gone}:undelete" "$(json_body '{}')" "" iam "$provider_gone" deleted iam.googleapis.com/workloadIdentityPoolProviders.undelete iam
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision DELETE "${iam}/${provider_gone}" "" "" iam || true; fi
  observe "$attachment" iam.googleapis.com/workloadIdentityPools.delete DELETE "${iam}/${pool}" "" "" iam "$pool" present iam.googleapis.com/workloadIdentityPools.delete iam
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision POST "${iam}/${pool}:undelete" "$(json_body '{}')" "" iam || true; fi
  observe "$attachment" iam.googleapis.com/workloadIdentityPools.undelete POST "${iam}/${pool_gone}:undelete" "$(json_body '{}')" "" iam "$pool_gone" deleted iam.googleapis.com/workloadIdentityPools.undelete iam
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision DELETE "${iam}/${pool_gone}" "" "" iam || true; fi
}

# actAs is checked when a workload is attached to an account. Cloud Scheduler
# checks exactly that permission and nothing the matrix denies: a job whose
# HTTP target mints an OIDC token as the throwaway account, on a yearly
# schedule against an address that resolves to nothing, removed again by the
# control phase so both phases address an absent job. Where Cloud Scheduler
# is not enabled the answer is SERVICE_DISABLED, which the module does not
# accept for this row: the attachment project must enable the API before the
# row can be proven.
act_as_row() {
  local attachment="$1" project="$2"
  local email job
  email="$(service_account_email "$throwaway" "$project")"
  job="projects/${project}/locations/${broker_region}/jobs/${throwaway}"
  observe "$attachment" iam.googleapis.com/serviceAccounts.actAs POST "${scheduler}/projects/${project}/locations/${broker_region}/jobs" "$(json_body "$(jq -cn --arg name "$job" --arg email "$email" '{name: $name, schedule: "0 0 1 1 *", timeZone: "Etc/UTC", httpTarget: {uri: "https://deny-canary.invalid/", httpMethod: "GET", oidcToken: {serviceAccountEmail: $email}}}')")" "" scheduler "$job" absent iam.googleapis.com/serviceAccounts.actAs
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision DELETE "${scheduler}/${job}" || true; fi
}

# The project IAM row: the project's own policy written back unchanged, with
# its etag, which the canonical body excludes.
project_iam_row() {
  local attachment="$1" project="$2"
  witness_call POST "${crm}/projects/${project}:getIamPolicy" "$(json_body '{"options":{"requestedPolicyVersion":3}}')"
  local policy
  policy="$(mktemp "$workdir/request.XXXXXX")"
  jq -c '{policy: ., updateMask: "bindings,etag"}' "$workdir/body" > "$policy"
  observe "$attachment" cloudresourcemanager.googleapis.com/projects.setIamPolicy POST "${crm}/projects/${project}:setIamPolicy" "$policy" "" project "projects/${project}" present cloudresourcemanager.googleapis.com/projects.setIamPolicy
}

# Cloud Run rows: the throwaway service (every project), and at consumers
# the throwaway job and worker pool. Every Cloud Run write checks actAs on
# the runtime account beside its own permission, so each row declares that
# co-denied permission. The control phase creates the retained resources,
# removes what the create rows created, and recreates what the delete row
# deleted.
run_rows() {
  local attachment="$1" project="$2" scope="$3"
  local email parent service service_new job job_new pool pool_new service_body job_body pool_body
  email="$(service_account_email "$throwaway" "$project")"
  parent="projects/${project}/locations/${broker_region}"
  service="${parent}/services/${throwaway}"
  service_new="${parent}/services/${throwaway_new}"
  job="${parent}/jobs/${throwaway}"
  job_new="${parent}/jobs/${throwaway_new}"
  pool="${parent}/workerPools/${throwaway}"
  pool_new="${parent}/workerPools/${throwaway_new}"
  service_body="$(jq -cn --arg image "$hello_image" --arg email "$email" '{template: {serviceAccount: $email, containers: [{image: $image}]}, ingress: "INGRESS_TRAFFIC_INTERNAL_ONLY"}')"
  job_body="$(jq -cn --arg image "$hello_image" --arg email "$email" '{template: {template: {serviceAccount: $email, containers: [{image: $image}]}}}')"
  pool_body="$(jq -cn --arg image "$hello_image" --arg email "$email" '{template: {serviceAccount: $email, containers: [{image: $image}]}, scaling: {scalingMode: "MANUAL", manualInstanceCount: 0}}')"
  if preparing; then
    provision POST "${run}/${parent}/services?serviceId=${throwaway}" "$(json_body "$service_body")" "" run || true
    if [ "$scope" = consumer ]; then
      provision POST "${run}/${parent}/jobs?jobId=${throwaway}" "$(json_body "$job_body")" "" run || true
      provision POST "${run}/${parent}/workerPools?workerPoolId=${throwaway}" "$(json_body "$pool_body")" "" run || true
    fi
  fi
  if preparing; then return 0; fi
  observe "$attachment" run.googleapis.com/services.create POST "${run}/${parent}/services?serviceId=${throwaway_new}" "$(json_body "$service_body")" "" run "$service_new" absent "run.googleapis.com/services.create,iam.googleapis.com/serviceAccounts.actAs" run
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision DELETE "${run}/${service_new}" "" "" run || true; fi
  observe "$attachment" run.googleapis.com/services.update PATCH "${run}/${service}?updateMask=description" "$(json_body '{"description":"protected-recovery deny canary"}')" "" run "$service" present "run.googleapis.com/services.update,iam.googleapis.com/serviceAccounts.actAs" run
  if [ "$scope" = broker ]; then
    observe "$attachment" run.googleapis.com/services.setIamPolicy POST "${run}/${service}:setIamPolicy" "$(json_body '{"policy":{"version":3},"updateMask":"bindings"}')" "" run "$service" present run.googleapis.com/services.setIamPolicy
    observe "$attachment" run.googleapis.com/services.delete DELETE "${run}/${service}" "" "" run "$service" present run.googleapis.com/services.delete run
    if provisioning && [ "$last_outcome" = ALLOWED ]; then provision POST "${run}/${parent}/services?serviceId=${throwaway}" "$(json_body "$service_body")" "" run || true; fi
  else
    observe "$attachment" run.googleapis.com/jobs.create POST "${run}/${parent}/jobs?jobId=${throwaway_new}" "$(json_body "$job_body")" "" run "$job_new" absent "run.googleapis.com/jobs.create,iam.googleapis.com/serviceAccounts.actAs" run
    if provisioning && [ "$last_outcome" = ALLOWED ]; then provision DELETE "${run}/${job_new}" "" "" run || true; fi
    observe "$attachment" run.googleapis.com/jobs.update PATCH "${run}/${job}?updateMask=labels" "$(json_body '{"labels":{"protected-recovery":"deny-canary"}}')" "" run "$job" present "run.googleapis.com/jobs.update,iam.googleapis.com/serviceAccounts.actAs" run
    observe "$attachment" run.googleapis.com/workerpools.create POST "${run}/${parent}/workerPools?workerPoolId=${throwaway_new}" "$(json_body "$pool_body")" "" run "$pool_new" absent "run.googleapis.com/workerpools.create,iam.googleapis.com/serviceAccounts.actAs" run
    if provisioning && [ "$last_outcome" = ALLOWED ]; then provision DELETE "${run}/${pool_new}" "" "" run || true; fi
    observe "$attachment" run.googleapis.com/workerpools.update PATCH "${run}/${pool}?updateMask=description" "$(json_body '{"description":"protected-recovery deny canary"}')" "" run "$pool" present "run.googleapis.com/workerpools.update,iam.googleapis.com/serviceAccounts.actAs" run
  fi
}

# The broker's image row: one tiny generic artifact uploaded into the
# throwaway generic repository the control phase creates, and removed again
# so both phases address an absent version.
registry_row() {
  local attachment="$1" project="$2"
  local repository="projects/${project}/locations/${broker_region}/repositories/${throwaway}"
  local version="${repository}/packages/deny-canary/versions/${suffix}"
  if preparing; then
    provision POST "${registry}/v1/projects/${project}/locations/${broker_region}/repositories?repositoryId=${throwaway}" "$(json_body '{"format":"GENERIC","description":"protected-recovery deny canary throwaway"}')" "" registry || true
  fi
  local boundary="protected-recovery-deny-canary"
  {
    printf -- '--%s\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n' "$boundary"
    jq -cn --arg version "$suffix" '{package_id: "deny-canary", version_id: $version, filename: "canary.txt"}'
    printf '\r\n--%s\r\nContent-Type: text/plain\r\n\r\nprotected-recovery deny canary %s\r\n--%s--\r\n' "$boundary" "$suffix" "$boundary"
  } > "$workdir/upload.body"
  if preparing; then return 0; fi
  observe "$attachment" artifactregistry.googleapis.com/repositories.uploadArtifacts POST "${registry}/upload/v1/${repository}/genericArtifacts:create?uploadType=multipart" "$workdir/upload.body" "multipart/related; boundary=${boundary}" registry "$version" absent artifactregistry.googleapis.com/repositories.uploadArtifacts registry
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision DELETE "${registry}/v1/${version}" "" "" registry || true; fi
}

# The ledger rows: one retained document, read, listed, updated, and deleted
# (and created again), and one document the create row creates and the
# control phase removes. The independent witness reads the same actual
# document state before both phases' requests.
ledger_rows() {
  local attachment="$1" project="$2"
  local documents="projects/${project}/databases/${ledger_database}/documents"
  local name="${documents}/canary/${suffix}"
  local name_new="${documents}/canary/${suffix}-new"
  local create create_new update delete delete_new
  create="$(jq -cn --arg name "$name" '{writes: [{update: {name: $name, fields: {run: {stringValue: "canary"}}}, currentDocument: {exists: false}}]}')"
  create_new="$(jq -cn --arg name "$name_new" '{writes: [{update: {name: $name, fields: {run: {stringValue: "canary"}}}, currentDocument: {exists: false}}]}')"
  update="$(jq -cn --arg name "$name" '{writes: [{update: {name: $name, fields: {run: {stringValue: "canary"}}}, currentDocument: {exists: true}}]}')"
  delete="$(jq -cn --arg name "$name" '{writes: [{delete: $name}]}')"
  delete_new="$(jq -cn --arg name "$name_new" '{writes: [{delete: $name}]}')"
  if preparing; then provision POST "${firestore}/${documents}:commit" "$(json_body "$create")" || true; fi
  if preparing; then return 0; fi
  observe "$attachment" datastore.googleapis.com/entities.create POST "${firestore}/${documents}:commit" "$(json_body "$create_new")" "" firestore "$name_new" absent datastore.googleapis.com/entities.create
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision POST "${firestore}/${documents}:commit" "$(json_body "$delete_new")" || true; fi
  observe "$attachment" datastore.googleapis.com/entities.get GET "${firestore}/${name}" "" "" firestore "$name" present datastore.googleapis.com/entities.get
  observe "$attachment" datastore.googleapis.com/entities.list GET "${firestore}/${documents}/canary?pageSize=1" "" "" none - none datastore.googleapis.com/entities.list
  observe "$attachment" datastore.googleapis.com/entities.update POST "${firestore}/${documents}:commit" "$(json_body "$update")" "" firestore "$name" present datastore.googleapis.com/entities.update
  observe "$attachment" datastore.googleapis.com/entities.delete POST "${firestore}/${documents}:commit" "$(json_body "$delete")" "" firestore "$name" present datastore.googleapis.com/entities.delete
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision POST "${firestore}/${documents}:commit" "$(json_body "$create")" || true; fi
}

# The evidence rows: one retained object, updated and deleted (and created
# again), and one object the create row creates and the control phase
# removes.
evidence_rows() {
  local attachment="$1"
  local object="canary%2F${suffix}"
  local object_new="canary%2F${suffix}-new"
  local bucket="b/${evidence_bucket}"
  if preparing; then provision POST "${gcs}/upload/storage/v1/${bucket}/o?uploadType=media&name=${object}&ifGenerationMatch=0" "$(json_body '{"canary":true}')" || true; fi
  if preparing; then return 0; fi
  observe "$attachment" storage.googleapis.com/objects.create POST "${gcs}/upload/storage/v1/${bucket}/o?uploadType=media&name=${object_new}&ifGenerationMatch=0" "$(json_body '{"canary":true}')" "" gcs "${bucket}/o/${object_new}" absent storage.googleapis.com/objects.create
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision DELETE "${gcs}/storage/v1/${bucket}/o/${object_new}" || true; fi
  observe "$attachment" storage.googleapis.com/objects.update PATCH "${gcs}/storage/v1/${bucket}/o/${object}" "$(json_body '{"metadata":{"protected-recovery":"deny-canary"}}')" "" gcs "${bucket}/o/${object}" present storage.googleapis.com/objects.update
  observe "$attachment" storage.googleapis.com/objects.delete DELETE "${gcs}/storage/v1/${bucket}/o/${object}" "" "" gcs "${bucket}/o/${object}" present storage.googleapis.com/objects.delete
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision POST "${gcs}/upload/storage/v1/${bucket}/o?uploadType=media&name=${object}&ifGenerationMatch=0" "$(json_body '{"canary":true}')" || true; fi
}

# The attachment-freeze rows of a consumer: Compute instances and templates,
# Cloud Build builds, and API enablement. The Compute and Cloud Build
# requests attach no service account, so each needs its own permission alone.
# Compute and Cloud Build are not enabled in the consumer projects; the
# identical request then answers SERVICE_DISABLED in both phases. Where an
# API is enabled the exercise is real: an instance created and removed, a
# stopped retained instance whose account is detached, a template created
# and removed, a build created and cancelled at once. The API rows disable
# and then enable an API the platform never enables, both from the disabled
# state, and the control phase disables it again.
freeze_rows() {
  local attachment="$1" project="$2"
  local instance instance_new template_new service
  instance="projects/${project}/zones/${zone}/instances/${throwaway}"
  instance_new="projects/${project}/zones/${zone}/instances/${throwaway_new}"
  template_new="projects/${project}/global/instanceTemplates/${throwaway_new}"
  service="projects/${project}/services/websecurityscanner.googleapis.com"
  local instance_body template_body
  instance_body="$(jq -cn --arg name "$throwaway_new" --arg zone "$zone" '{name: $name, machineType: ("zones/" + $zone + "/machineTypes/e2-micro"), disks: [{boot: true, autoDelete: true, initializeParams: {sourceImage: "projects/debian-cloud/global/images/family/debian-12"}}], networkInterfaces: [{network: "global/networks/default"}]}')"
  template_body="$(jq -cn --arg name "$throwaway_new" '{name: $name, properties: {machineType: "e2-micro", disks: [{boot: true, autoDelete: true, initializeParams: {sourceImage: "projects/debian-cloud/global/images/family/debian-12"}}], networkInterfaces: [{network: "global/networks/default"}]}}')"
  if preparing; then
    call GET "${compute}/projects/${project}/zones/${zone}"
    if [[ "$last_status" =~ ^2 ]]; then
      provision POST "${compute}/projects/${project}/zones/${zone}/instances" "$(json_body "$(jq -c --arg name "$throwaway" '.name = $name' <<< "$instance_body")")" "" compute && provision POST "${compute}/${instance}/stop" "" "" compute || true
    fi
  fi
  if preparing; then return 0; fi
  observe "$attachment" compute.googleapis.com/instances.create POST "${compute}/projects/${project}/zones/${zone}/instances" "$(json_body "$instance_body")" "" compute "$instance_new" absent compute.googleapis.com/instances.create compute
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision DELETE "${compute}/${instance_new}" "" "" compute || true; fi
  observe "$attachment" compute.googleapis.com/instances.setServiceAccount POST "${compute}/${instance}/setServiceAccount" "$(json_body '{}')" "" compute "$instance" present compute.googleapis.com/instances.setServiceAccount compute
  observe "$attachment" compute.googleapis.com/instanceTemplates.create POST "${compute}/projects/${project}/global/instanceTemplates" "$(json_body "$template_body")" "" compute "$template_new" absent compute.googleapis.com/instanceTemplates.create compute
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision DELETE "${compute}/${template_new}" "" "" compute || true; fi
  observe "$attachment" cloudbuild.googleapis.com/builds.create POST "${cloudbuild}/projects/${project}/locations/global/builds" "$(json_body '{"steps":[{"name":"gcr.io/cloud-builders/gcloud","args":["version"]}],"tags":["protected-recovery-deny-canary"],"options":{"logging":"CLOUD_LOGGING_ONLY"}}')" "" none - none cloudbuild.googleapis.com/builds.create
  if [ "$last_outcome" = ALLOWED ]; then
    local build
    build="$(jq -r '.metadata.build.id // ""' "$workdir/body")"
    [ -n "$build" ] && provision POST "${cloudbuild}/projects/${project}/locations/global/builds/${build}:cancel" "$(json_body '{}')" || true
  fi
  observe "$attachment" serviceusage.googleapis.com/services.disable POST "${serviceusage}/${service}:disable" "$(json_body '{"disableDependentServices":false}')" "" service "$service" disabled serviceusage.googleapis.com/services.disable serviceusage
  observe "$attachment" serviceusage.googleapis.com/services.enable POST "${serviceusage}/${service}:enable" "$(json_body '{}')" "" service "$service" disabled serviceusage.googleapis.com/services.enable serviceusage
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision POST "${serviceusage}/${service}:disable" "$(json_body '{"disableDependentServices":false}')" "" serviceusage || true; fi
}

# The organization rows: throwaway custom roles at the organization;
# organization policies set on the broker project through both APIs, which
# the organization's rules govern as a descendant; and a throwaway project
# under the organization that the movement rows relabel and move into a
# throwaway folder, and that the control phase moves back.
organization_rows() {
  local attachment="$1"
  local role="organizations/${ORGANIZATION_ID}/roles/${role_id}"
  local role_new_name="organizations/${ORGANIZATION_ID}/roles/${create_role_new}"
  local role_gone_name="organizations/${ORGANIZATION_ID}/roles/${role_gone}"
  local policies="projects/${broker_project}/policies"
  local role_body='{"role":{"title":"Protected recovery Deny canary throwaway","includedPermissions":["resourcemanager.projects.get"],"stage":"DISABLED"}}'
  if preparing; then
    provision POST "${iam}/organizations/${ORGANIZATION_ID}/roles" "$(json_body "$(jq -cn --arg id "$role_id" --argjson base "$role_body" '$base + {roleId: $id}')")" || true
    provision POST "${iam}/organizations/${ORGANIZATION_ID}/roles" "$(json_body "$(jq -cn --arg id "$role_gone" --argjson base "$role_body" '$base + {roleId: $id}')")" && provision DELETE "${iam}/${role_gone_name}" || true
    provision POST "${orgpolicy}/${policies}" "$(json_body "$(jq -cn --arg name "${policies}/${constraint_kept}" '{name: $name, spec: {rules: [{enforce: true}]}}')")" || true
    provision POST "${crm}/projects" "$(json_body "$(jq -cn --arg id "$canary_project" --arg parent "organizations/${ORGANIZATION_ID}" '{projectId: $id, parent: $parent, displayName: "Protected recovery Deny canary throwaway"}')")" "" crm || true
    if provision POST "${crm}/folders" "$(json_body "$(jq -cn --arg name "$throwaway" --arg parent "organizations/${ORGANIZATION_ID}" '{displayName: $name, parent: $parent}')")" "" crm; then
      folder_id="$(jq -r '.response.name // "" | sub("^folders/"; "")' <<< "$operation_json")"
      [ -n "$folder_id" ] || folder_id="$(jq -r '.response.name // "" | sub("^folders/"; "")' "$workdir/body")"
    fi
    [ -n "$folder_id" ] || fail "the throwaway folder was not created"
  elif [ "$PHASE" = deny ]; then
    manifest_read "$broker_project"
    [ -n "$folder_id" ] || fail "the retained throwaway account names no folder"
  fi
  if preparing; then return 0; fi
  observe "$attachment" iam.googleapis.com/roles.create POST "${iam}/organizations/${ORGANIZATION_ID}/roles" "$(json_body "$(jq -cn --arg id "$create_role_new" --argjson base "$role_body" '$base + {roleId: $id}')")" "" iam "$role_new_name" absent iam.googleapis.com/roles.create
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision DELETE "${iam}/${role_new_name}" || true; fi
  observe "$attachment" iam.googleapis.com/roles.update PATCH "${iam}/${role}?updateMask=description" "$(json_body '{"description":"protected-recovery deny canary"}')" "" iam "$role" present iam.googleapis.com/roles.update
  observe "$attachment" iam.googleapis.com/roles.delete DELETE "${iam}/${role}" "" "" iam "$role" present iam.googleapis.com/roles.delete
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision POST "${iam}/${role}:undelete" "$(json_body '{}')" || true; fi
  observe "$attachment" iam.googleapis.com/roles.undelete POST "${iam}/${role_gone_name}:undelete" "$(json_body '{}')" "" iam "$role_gone_name" deleted iam.googleapis.com/roles.undelete
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision DELETE "${iam}/${role_gone_name}" || true; fi
  observe "$attachment" orgpolicy.googleapis.com/policies.create POST "${orgpolicy}/${policies}" "$(json_body "$(jq -cn --arg name "${policies}/${constraint_new}" '{name: $name, spec: {rules: [{enforce: true}]}}')")" "" orgpolicy "${policies}/${constraint_new}" absent orgpolicy.googleapis.com/policies.create
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision DELETE "${orgpolicy}/${policies}/${constraint_new}" || true; fi
  observe "$attachment" orgpolicy.googleapis.com/policies.update PATCH "${orgpolicy}/${policies}/${constraint_kept}" "$(json_body "$(jq -cn --arg name "${policies}/${constraint_kept}" '{name: $name, spec: {rules: [{enforce: false}]}}')")" "" orgpolicy "${policies}/${constraint_kept}" present orgpolicy.googleapis.com/policies.update
  observe "$attachment" orgpolicy.googleapis.com/policies.delete DELETE "${orgpolicy}/${policies}/${constraint_kept}" "" "" orgpolicy "${policies}/${constraint_kept}" present orgpolicy.googleapis.com/policies.delete
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision POST "${orgpolicy}/${policies}" "$(json_body "$(jq -cn --arg name "${policies}/${constraint_kept}" '{name: $name, spec: {rules: [{enforce: true}]}}')")" || true; fi
  observe "$attachment" orgpolicy.googleapis.com/policy.set POST "${crm_v1}/projects/${broker_project}:setOrgPolicy" "$(json_body "$(jq -cn --arg constraint "constraints/${constraint_v1}" '{policy: {constraint: $constraint, booleanPolicy: {enforced: true}}}')")" "" orgpolicy "${policies}/${constraint_v1}" absent orgpolicy.googleapis.com/policy.set
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision POST "${crm_v1}/projects/${broker_project}:clearOrgPolicy" "$(json_body "$(jq -cn --arg constraint "constraints/${constraint_v1}" '{constraint: $constraint}')")" || true; fi
  observe "$attachment" cloudresourcemanager.googleapis.com/projects.update PATCH "${crm}/projects/${canary_project}?updateMask=labels" "$(json_body '{"labels":{"protected-recovery":"deny-canary"}}')" "" project "projects/${canary_project}" present cloudresourcemanager.googleapis.com/projects.update crm
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision PATCH "${crm}/projects/${canary_project}?updateMask=labels" "$(json_body '{"labels":{}}')" "" crm || true; fi
  observe "$attachment" cloudresourcemanager.googleapis.com/projects.move POST "${crm}/projects/${canary_project}:move" "$(json_body "$(jq -cn --arg parent "folders/${folder_id}" '{destinationParent: $parent}')")" "" project "projects/${canary_project}" present "cloudresourcemanager.googleapis.com/projects.move,cloudresourcemanager.googleapis.com/projects.update" crm
  if provisioning && [ "$last_outcome" = ALLOWED ]; then provision POST "${crm}/projects/${canary_project}:move" "$(json_body "$(jq -cn --arg parent "organizations/${ORGANIZATION_ID}" '{destinationParent: $parent}')")" "" crm || true; fi
}

# ---------------------------------------------------------------------------
# Cleanup: everything a control run created, addressed by the same names.
# Every deletion is attempted; what could not be deleted is a leftover, the
# phase fails, and the leftover is never attested away.
# ---------------------------------------------------------------------------
# One deletion: completed success or authoritative absence is clean.
# Disabled APIs and authorization failures leave resource state unresolved.
remove() {
  local method="$1" url="$2" what="$3" kind="${4:-}" body="${5:-}"
  call "$method" "$url" "$body"
  if [[ "$last_status" =~ ^2 ]]; then
    if [ -n "$kind" ] && ! wait_operation "$kind"; then
      echo "${what}: the removal operation did not complete" >> "$failures"
      return 0
    fi
    echo "$what" >> "$removed"
    echo "cleanup: removed ${what}"
  elif [ "$last_status" = 404 ]; then
    echo "cleanup: ${what} is absent"
  else
    echo "${what}: HTTP ${last_status} $(jq -r '.error.message // "" | .[0:200]' "$workdir/body" 2> /dev/null)" >> "$failures"
    echo "cleanup: ${what} answered HTTP ${last_status}"
  fi
}

# A soft-deletable name is removed only while it is active: a name that is
# already deleted is clean.
remove_unless_deleted() {
  local url="$1" what="$2" kind="${3:-}"
  call GET "$url"
  if [ "$last_status" = 404 ]; then
    echo "cleanup: ${what} is absent"
    return 0
  fi
  if [[ "$last_status" =~ ^2 ]] && jq -e '(.state == "DELETED") or (.deleted == true)' "$workdir/body" > /dev/null 2>&1; then
    echo "cleanup: ${what} is already deleted"
    return 0
  fi
  if ! [[ "$last_status" =~ ^2 ]]; then
    fail "${what}: state unread before cleanup: HTTP ${last_status}"
    return 0
  fi
  remove DELETE "$url" "$what" "$kind"
}

cleanup_project() {
  local project="$1" scope="$2"
  local email parent pool name
  parent="projects/${project}/locations/${broker_region}"
  remove DELETE "${scheduler}/${parent}/jobs/${throwaway}" "scheduler job of ${project}"
  for name in "$throwaway" "$throwaway_new"; do
    remove DELETE "${run}/${parent}/services/${name}" "Cloud Run service ${name} of ${project}" run
  done
  if [ "$scope" = consumer ]; then
    for name in "$throwaway" "$throwaway_new"; do
      remove DELETE "${run}/${parent}/jobs/${name}" "Cloud Run job ${name} of ${project}" run
      remove DELETE "${run}/${parent}/workerPools/${name}" "Cloud Run worker pool ${name} of ${project}" run
      remove DELETE "${compute}/projects/${project}/zones/${zone}/instances/${name}" "Compute instance ${name} of ${project}" compute
    done
    remove DELETE "${compute}/projects/${project}/global/instanceTemplates/${throwaway_new}" "Compute template of ${project}" compute
    remove POST "${serviceusage}/projects/${project}/services/websecurityscanner.googleapis.com:disable" "web security scanner API of ${project}" serviceusage "$(json_body '{"disableDependentServices":false}')"
  else
    remove DELETE "${registry}/v1/${parent}/repositories/${throwaway}" "registry repository of ${project}" registry
    for name in "$suffix" "${suffix}-new"; do
      remove POST "${firestore}/projects/${project}/databases/${ledger_database}/documents:commit" "ledger document ${name} of ${project}" "" "$(json_body "$(jq -cn --arg name "projects/${project}/databases/${ledger_database}/documents/canary/${name}" '{writes: [{delete: $name}]}')")"
      remove DELETE "${gcs}/storage/v1/b/${evidence_bucket}/o/canary%2F${name}" "evidence object ${name} of ${project}"
    done
    for name in "$constraint_new" "$constraint_kept" "$constraint_v1"; do
      remove DELETE "${orgpolicy}/projects/${project}/policies/${name}" "organization policy ${name} of ${project}"
    done
  fi
  pool="projects/${project}/locations/global/workloadIdentityPools/${throwaway}"
  for name in "$throwaway" "$throwaway_new" "${throwaway_new}-c" "${throwaway_new}-d" "$throwaway_gone"; do
    remove_unless_deleted "${iam}/${pool}/providers/${name}" "pool provider ${name} of ${project}" iam
  done
  for name in "$throwaway" "$throwaway_new" "${throwaway_new}-c" "${throwaway_new}-d" "$throwaway_gone"; do
    remove_unless_deleted "${iam}/projects/${project}/locations/global/workloadIdentityPools/${name}" "pool ${name} of ${project}" iam
  done
  transient_keys "$project"
  for name in "$throwaway" "$throwaway_new" "${throwaway_new}-c" "${throwaway_new}-d" "$throwaway_gone" "$delegate" "$enable_account"; do
    email="$(service_account_email "$name" "$project")"
    if [ "$name" = "$delegate" ] && [ "$scope" != broker ]; then continue; fi
    if [ "$scope" = broker ] && [ "$name" = "$throwaway" ] && [ -s "$failures" ]; then
      fail "account ${name} of ${project}: retained to preserve unresolved cleanup identities"
      continue
    fi
    remove DELETE "${iam}/projects/${project}/serviceAccounts/${email}" "account ${name} of ${project}"
  done
}

# The manifest owns this numeric identity. An unread or mismatched object
# cannot authorize deletion, and an accepted delete is followed by a read.
cleanup_folder() {
  if ! [[ "$folder_id" =~ ^[1-9][0-9]*$ ]]; then
    fail "throwaway folder: the control manifest has no numeric folder identity"
    return 0
  fi
  local name="folders/${folder_id}" state
  call GET "${crm}/${name}"
  if [ "$last_status" = 404 ]; then return 0; fi
  if [ "$last_status" != 200 ]; then
    fail "${name}: state unread before cleanup: HTTP ${last_status}"
    return 0
  fi
  if ! jq -e --arg name "$name" --arg parent "organizations/${ORGANIZATION_ID}" --arg display "$throwaway" '.name == $name and .parent == $parent and .displayName == $display' "$workdir/body" > /dev/null; then
    fail "${name}: identity, parent, or display name differs from the control manifest"
    return 0
  fi
  state="$(jq -r '.state // ""' "$workdir/body")"
  if [ "$state" = DELETE_REQUESTED ]; then return 0; fi
  if [ "$state" != ACTIVE ]; then
    fail "${name}: unknown folder state ${state}"
    return 0
  fi
  remove DELETE "${crm}/${name}" "throwaway folder ${name}" crm
  call GET "${crm}/${name}"
  if [ "$last_status" = 404 ]; then return 0; fi
  if [ "$last_status" != 200 ] || ! jq -e --arg name "$name" --arg parent "organizations/${ORGANIZATION_ID}" --arg display "$throwaway" '.name == $name and .parent == $parent and .displayName == $display and .state == "DELETE_REQUESTED"' "$workdir/body" > /dev/null; then
    fail "${name}: terminal deletion state is not readable after cleanup: HTTP ${last_status}"
  fi
}

cleanup_organization() {
  local name
  for name in "$role_id" "$role_new" "${role_new}c" "${role_new}d" "$role_gone"; do
    remove_unless_deleted "${iam}/organizations/${ORGANIZATION_ID}/roles/${name}" "custom role ${name} of organizations/${ORGANIZATION_ID}"
  done
  # The throwaway project: moved back under the organization if a move stood, then deleted.
  call GET "${crm}/projects/${canary_project}"
  if [ "$last_status" = 200 ]; then
    if [ "$(jq -r '.parent // ""' "$workdir/body")" != "organizations/${ORGANIZATION_ID}" ] && [ "$(jq -r '.state // ""' "$workdir/body")" = ACTIVE ]; then
      provision POST "${crm}/projects/${canary_project}:move" "$(json_body "$(jq -cn --arg parent "organizations/${ORGANIZATION_ID}" '{destinationParent: $parent}')")" "" crm || echo "throwaway project ${canary_project}: could not be moved back under the organization" >> "$failures"
      call GET "${crm}/projects/${canary_project}"
      if [ "$last_status" != 200 ]; then
        fail "throwaway project ${canary_project}: state unread after move: HTTP ${last_status}"
        cleanup_folder
        return 0
      fi
    fi
    if [ "$(jq -r '.state // ""' "$workdir/body")" = ACTIVE ]; then
      remove DELETE "${crm}/projects/${canary_project}" "throwaway project ${canary_project}" crm
      call GET "${crm}/projects/${canary_project}"
      if [ "$last_status" != 404 ] && { [ "$last_status" != 200 ] || ! jq -e --arg id "$canary_project" --arg parent "organizations/${ORGANIZATION_ID}" '.projectId == $id and .parent == $parent and .state == "DELETE_REQUESTED"' "$workdir/body" > /dev/null; }; then
        fail "throwaway project ${canary_project}: terminal deletion state is not readable"
      fi
    elif [ "$(jq -r ' .state // "" ' "$workdir/body")" = DELETE_REQUESTED ]; then
      echo "cleanup: throwaway project ${canary_project} is already deleted"
    else
      fail "throwaway project ${canary_project}: unknown deletion state"
    fi
  elif [ "$last_status" = 404 ]; then
    echo "cleanup: throwaway project ${canary_project} is absent"
  else
    echo "throwaway project ${canary_project}: HTTP ${last_status}" >> "$failures"
  fi
  cleanup_folder

}

# The keys of the throwaway accounts, if any survived a phase. A listing that
# fails is a leftover: an unlisted key is not an absent key.
transient_keys() {
  local project="$1" name email
  for name in "$throwaway" "$delegate"; do
    email="$(service_account_email "$name" "$project")"
    if [ "$name" = "$delegate" ] && [ "$project" != "$broker_project" ]; then continue; fi
    call GET "${iam}/projects/${project}/serviceAccounts/${email}/keys?keyTypes=USER_MANAGED"
    if [ "$last_status" = 404 ]; then
      continue
    elif [ "$last_status" != 200 ]; then
      echo "keys of ${email}: could not be listed: HTTP ${last_status}" >> "$failures"
      continue
    fi
    local key
    while IFS= read -r key; do
      [ -n "$key" ] || continue
      remove DELETE "${iam}/${key}" "key ${key##*/} of ${email}"
    done < <(jq -r '.keys[]?.name' "$workdir/body")
  done
}

# Canary builds still queued or working, if any survived a phase. A listing
# that fails is a leftover, including a disabled API with unenumerated resources.
transient_builds() {
  local project="$1"
  local filter
  filter="$(jq -rn '"(status=\"QUEUED\" OR status=\"WORKING\") AND tags=\"protected-recovery-deny-canary\"" | @uri')"
  call GET "${cloudbuild}/projects/${project}/locations/global/builds?filter=${filter}"
  if [ "$last_status" != 200 ]; then
    echo "builds of ${project}: could not be listed: HTTP ${last_status}" >> "$failures"
    return 0
  fi
  local build
  while IFS= read -r build; do
    [ -n "$build" ] || continue
    remove POST "${cloudbuild}/projects/${project}/locations/global/builds/${build}:cancel" "build ${build} of ${project}" "" "$(json_body '{}')"
  done < <(jq -r '.builds[]?.id' "$workdir/body")
}

consumer_projects() {
  jq -r '.consumers[].projectId' "$authority"
}

if [ "$transient_cleanup" = 1 ]; then
  transient_keys "$broker_project"
  while IFS= read -r project; do
    transient_keys "$project"
    transient_builds "$project"
  done < <(consumer_projects)
  jq -n --arg phase "$PHASE" --arg control "$CONTROL_RUN_ID" --rawfile failures "$failures" --rawfile removed "$removed" '{schema: "protected-recovery/deny-canary-transient-cleanup/v3", phase: $phase, controlRunId: $control, removed: ($removed | split("\n") | map(select(length > 0))), leftovers: ($failures | split("\n") | map(select(length > 0)))}' > "$output"
  jq -r '"transient cleanup: removed: \(.removed | length); leftovers: \(.leftovers | length)"' "$output"
  [ ! -s "$failures" ]
  exit 0
fi

if [ "$PHASE" = cleanup ]; then
  # Recover numeric identities from the verified control artifact even if
  # an earlier cleanup already deleted the account that carried the manifest.
  manifest_read "$broker_project"
  cleanup_organization
  cleanup_project "$broker_project" broker
  while IFS= read -r project; do
    cleanup_project "$project" consumer
  done < <(consumer_projects)
  jq -n \
    --arg control "$CONTROL_RUN_ID" \
    --arg folder "$folder_id" --arg project "$canary_project" \
    --arg brokerImage "$BROKER_IMAGE" \
    --arg organization "organizations/${ORGANIZATION_ID}" \
    --argjson attempt "$GITHUB_RUN_ATTEMPT" \
    --arg event "$GITHUB_EVENT_NAME" \
    --arg headSha "$GITHUB_SHA" \
    --argjson id "$GITHUB_RUN_ID" \
    --arg repositoryId "$GITHUB_REPOSITORY_ID" \
    --arg workflow "$workflow_path" \
    --rawfile failures "$failures" \
    --rawfile removed "$removed" '{
      schema: "protected-recovery/deny-canary-cleanup/v3",
      phase: "cleanup",
      controlRunId: $control,
      brokerImage: $brokerImage,
      organization: $organization,
      run: {attempt: $attempt, event: $event, headSha: $headSha, id: $id, repositoryId: $repositoryId, workflow: $workflow},
      throwaways: {folder: $folder, project: $project},
      removed: ($removed | split("\n") | map(select(length > 0))),
      leftovers: ($failures | split("\n") | map(select(length > 0)))
    }' > "$output"
  jq -r '"cleanup of control run \(.controlRunId): removed: \(.removed | length); leftovers: \(.leftovers | length)"' "$output"
  [ ! -s "$failures" ]
  exit 0
fi

# ---------------------------------------------------------------------------
# The attested phases. First the live Deny policies at every attachment
# point, by name, with their etags and rules: what the module binds the
# observations to. The deny phase then records the Allows it starts under.
# Then every exercise, in dependency order per scope. The control phase
# records the Allows it ends under. Finally the predicate: each live rule
# with the observations of its permissions at its attachment point, the
# allow policies, and every permission no exercise reached.
# ---------------------------------------------------------------------------
policies="$workdir/policies.jsonl"
: > "$policies"
attachments="$workdir/attachments"
{
  printf '%s\t%s\tbroker\n' "cloudresourcemanager.googleapis.com/projects/${broker_project}" "$broker_project"
  printf '%s\t%s\torganization\n' "cloudresourcemanager.googleapis.com/organizations/${ORGANIZATION_ID}" "$ORGANIZATION_ID"
  jq -r '.consumers[] | "cloudresourcemanager.googleapis.com/projects/\(.projectId)\t\(.projectId)\tconsumer"' "$authority"
} > "$attachments"
while IFS=$'\t' read -r attachment project scope; do
  encoded="$(jq -rn --arg attachment "$attachment" '$attachment | @uri')"
  call GET "https://iam.googleapis.com/v2/policies/${encoded}/denypolicies"
  [ "$last_status" = 200 ] || { echo "Listing the deny policies of ${attachment} answered HTTP ${last_status}." >&2; exit 1; }
  jq -r '.policies[]?.name' "$workdir/body" > "$workdir/names"
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    [[ "$name" =~ ^policies/[A-Za-z0-9%._-]+/denypolicies/[A-Za-z0-9._-]+$ ]] || { echo "The listing of ${attachment} names a malformed policy." >&2; exit 1; }
    call GET "https://iam.googleapis.com/v2/${name}"
    [ "$last_status" = 200 ] || { echo "Reading ${name} answered HTTP ${last_status}." >&2; exit 1; }
    jq -c --arg attachment "$attachment" '{attachmentPoint: $attachment, etag: .etag, name: .name, rules: [.rules[]? | .denyRule | select(. != null) | {deniedPermissions: (.deniedPermissions // []), deniedPrincipals: (.deniedPrincipals // []), exceptionPrincipals: (.exceptionPrincipals // []), exceptionPermissions: (.exceptionPermissions // []), denialCondition: (.denialCondition // null)}]}' "$workdir/body" >> "$policies"
  done < "$workdir/names"
done < "$attachments"

if provisioning; then
  prepare_only=1
  while IFS=$'\t' read -r attachment project scope; do
    case "$scope" in
      broker)
        identity_rows "$attachment" "$project" broker
        run_rows "$attachment" "$project" broker
        registry_row "$attachment" "$project"
        ledger_rows "$attachment" "$project"
        evidence_rows "$attachment"
        ;;
      consumer)
        identity_rows "$attachment" "$project" consumer
        run_rows "$attachment" "$project" consumer
        freeze_rows "$attachment" "$project"
        manifest_write "$project"
        ;;
      organization) organization_rows "$attachment" ;;
    esac
  done < "$attachments"
  manifest_write "$broker_project"
  prepare_only=0
  [ ! -s "$failures" ] || exit 1
fi

if ! provisioning; then manifest_read "$broker_project"; fi
record_allow_boundary start

while IFS=$'\t' read -r attachment project scope; do
  case "$scope" in
    broker)
      identity_rows "$attachment" "$project" broker
      act_as_row "$attachment" "$project"
      project_iam_row "$attachment" "$project"
      run_rows "$attachment" "$project" broker
      registry_row "$attachment" "$project"
      ledger_rows "$attachment" "$project"
      evidence_rows "$attachment"
      ;;
    consumer)
      identity_rows "$attachment" "$project" consumer
      act_as_row "$attachment" "$project"
      project_iam_row "$attachment" "$project"
      run_rows "$attachment" "$project" consumer
      freeze_rows "$attachment" "$project"
      if provisioning; then manifest_write "$project"; fi
      ;;
    organization)
      organization_rows "$attachment"
      ;;
  esac
done < "$attachments"

if provisioning; then
  manifest_write "$broker_project"
fi
if [ -n "${pending_attachment:-}" ]; then record_allow_boundary after "$pending_attachment" "$pending_permission"; fi
record_allow_boundary end

jq -n \
  --arg phase "$PHASE" \
  --arg controlRunId "$CONTROL_RUN_ID" \
  --arg brokerImage "$BROKER_IMAGE" \
  --arg organization "organizations/${ORGANIZATION_ID}" \
  --argjson attempt "$GITHUB_RUN_ATTEMPT" \
  --arg event "$GITHUB_EVENT_NAME" \
  --arg headSha "$GITHUB_SHA" \
  --argjson id "$GITHUB_RUN_ID" \
  --arg repositoryId "$GITHUB_REPOSITORY_ID" \
  --arg workflow "$workflow_path" \
  --arg throwaway "$throwaway" \
  --arg throwaway_new "$throwaway_new" \
  --arg throwaway_gone "$throwaway_gone" \
  --arg delegate "$delegate" \
  --arg role "$role_id" \
  --arg project "$canary_project" \
  --arg folder "$folder_id" \
  --slurpfile policies "$policies" \
  --slurpfile observations "$observations" \
  --slurpfile allow "$allow_policies" \
  --slurpfile allow_interval "$allow_interval" \
  --slurpfile allow_snapshot "$workdir/allow-baseline.json" \
  --slurpfile manifest_ids "$manifest_ids" \
  --arg witness "$CANARY_WITNESS_SERVICE_ACCOUNT" \
  --rawfile failures "$failures" '
    ($observations) as $seen
    | {
      schema: "protected-recovery/deny-canary/v3",
      phase: $phase,
      controlRunId: $controlRunId,
      brokerImage: $brokerImage,
      organization: $organization,
      run: {attempt: $attempt, event: $event, headSha: $headSha, id: $id, repositoryId: $repositoryId, workflow: $workflow},
      throwaways: {name: $throwaway, new: $throwaway_new, gone: $throwaway_gone, delegate: $delegate, role: $role, project: $project, folder: $folder, goneUniqueIds: ($manifest_ids | from_entries)},
      witnessServiceAccount: $witness,
      allowPolicies: ($allow | sort_by(.resource)),
      allowInterval: $allow_interval,
      allowSnapshot: $allow_snapshot[0],
      policies: [$policies[] | .attachmentPoint as $attachment | .rules |= [.[] | .deniedPermissions as $permissions | . + {canary: [$seen[] | select(.attachment == $attachment and (.permission | IN($permissions[]))) | del(.attachment)]}]],
      failures: ($failures | split("\n") | map(select(length > 0)))
    }
    | .unexercised = ([.policies[] | .attachmentPoint as $attachment | .rules[] | .deniedPermissions[] as $permission | select([.canary[] | select(.permission == $permission)] | length == 0) | ($attachment + "|" + $permission)] | unique)
  ' > "$output"
jq -r '"\(.phase): policies: \(.policies | length); observations: \([.policies[].rules[].canary[]] | length); allowed: \([.policies[].rules[].canary[] | select(.outcome == "ALLOWED")] | length); denied: \([.policies[].rules[].canary[] | select(.outcome == "DENIED")] | length); unserviceable: \([.policies[].rules[].canary[] | select(.outcome == "UNSERVICEABLE")] | length); error: \([.policies[].rules[].canary[] | select(.outcome == "ERROR")] | length); allow policies: \(.allowPolicies | length); unexercised: \(.unexercised | length); failures: \(.failures | length)"' "$output"
