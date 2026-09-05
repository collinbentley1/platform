#!/bin/bash
# The Deny canary producer of the protected-recovery deployment: one phase of
# the two-phase, paired exercise of every IAM Deny rule attached to the
# broker project, to the organization, and to every consumer project, as the
# canary identity, written as the predicate the deny-canary workflow attests
# (schema protected-recovery/deny-canary/v2).
#
# The two attested phases make the same requests against the same throwaway
# resources and differ in exactly one thing, the live exception set:
#
#   control   the root has excepted the canary principal from every rule and
#             granted it the routine allow roles the requests need. Every
#             request must succeed (ALLOWED); its success proves the Allow
#             is in place and the request is well-formed against a resource
#             that exists in the attachment scope, so a later refusal of the
#             same request cannot be a missing Allow or a bad request.
#   deny      the root has removed the canary from every exception set and
#             left the allow roles in place. The same request, as the same
#             principal, against the same resource must now be refused with
#             an IAM permission denial that names exactly the row's
#             permission (DENIED). The pairing attributes the refusal to the
#             Deny rule and to nothing else.
#   cleanup   not evidence: the throwaway resources of a control run are
#             removed, under the control form again.
#
# Every throwaway resource lives in the attachment scope of the row it
# exercises -- a service account, a workload identity pool and provider, a
# Cloud Run service, job, and worker pool, a Cloud Scheduler job, a generic
# Artifact Registry repository, an organization custom role, an organization
# policy on the broker project, a ledger document, an evidence object -- and
# is named deterministically from the CONTROL run, so the deny phase and the
# cleanup phase address exactly the resources the control phase created.
# Within the control phase a resource that a row deletes is created again
# afterwards (quietly, never recorded) so that every deny-phase request meets
# an existing resource and the only reason it can be refused is the rule.
#
# Every observation carries the request (method and URL), the answer's status,
# the IAM ErrorInfo reason and the permission it names (normalized to the
# deny-policy form, with the raw value kept), the service a SERVICE_DISABLED
# answer names, and the message. The module binds each row to a DENIED
# observation naming the row's permission and to an ALLOWED observation of the
# byte-identical request from the control run. A permission whose attachment
# API is not enabled in the attachment project cannot reach IAM at all: both
# phases then answer SERVICE_DISABLED for the identical request, recorded as
# UNSERVICEABLE, which the module accepts only for the Compute and Cloud Build
# attachment rows and only together with a live read proving the API disabled
# (terraform/modules/protected-recovery/main.tf, unserviceable rows). A
# permission of a live rule that this script has no exercise for is listed in
# `unexercised`; the workflow refuses to attest a predicate whose list is not
# empty, and the module refuses one all the same.
#
# Inputs (environment): PHASE (control|deny|cleanup), CONTROL_RUN_ID (the run
# ID of the control phase; the deny and cleanup phases derive every throwaway
# name from it, the control phase must be given its own run ID), ACCESS_TOKEN
# of the canary identity, CANARY_SERVICE_ACCOUNT, ORGANIZATION_ID,
# BROKER_IMAGE, and the GitHub run context. The one argument is the output
# path. With TRANSIENT_CLEANUP=1 the script only removes what a phase creates
# and deletes within itself -- user-managed keys of the throwaway accounts,
# queued canary builds -- and answers 0 whatever it finds: it is the
# always() step of every run.
set -euo pipefail

output="${1:?output path}"
: "${PHASE:?}" "${CONTROL_RUN_ID:?}" "${ACCESS_TOKEN:?}" "${CANARY_SERVICE_ACCOUNT:?}" "${ORGANIZATION_ID:?}" "${BROKER_IMAGE:?}"
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
transient_cleanup="${TRANSIENT_CLEANUP:-0}"

root="$(cd "$(dirname "$0")/../.." && pwd)"
authority="$root/protected-recovery/authority.json"
broker_project="$(jq -er '.broker.projectId | select(type == "string")' "$authority")"
broker_region="$(jq -er '.broker.region' "$authority")"
ledger_database="$(jq -er '.broker.firestoreDatabase' "$authority")"
evidence_bucket="${broker_project}-protected-recovery-evidence"
canary_principal="principal://iam.googleapis.com/projects/-/serviceAccounts/${CANARY_SERVICE_ACCOUNT}"
suffix="$(printf '%s' "$CONTROL_RUN_ID" | tail -c 12)"
throwaway="deny-canary-${suffix}"
role_id="denyCanary${suffix}"
workflow_path="${GITHUB_WORKFLOW_REF#*/*/}"
workflow_path="${workflow_path%@*}"
zone="${broker_region}-a"

workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT
umask 077
printf 'header = "Authorization: Bearer %s"\n' "$ACCESS_TOKEN" > "$workdir/auth.cfg"
unset ACCESS_TOKEN

iam="https://iam.googleapis.com/v1"
credentials="https://iamcredentials.googleapis.com/v1"
crm="https://cloudresourcemanager.googleapis.com/v3"
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

observations="$workdir/observations.jsonl"
: > "$observations"
failures="$workdir/failures"
: > "$failures"
last_status=000
last_outcome=ERROR

# One API call: the HTTP status in $last_status, the body in $workdir/body.
# The optional body is a file; the optional content type defaults to JSON.
call() {
  local method="$1" url="$2" body="${3:-}" content_type="${4:-application/json}"
  local args=(--silent --show-error --max-time 120 --config "$workdir/auth.cfg" --request "$method" --output "$workdir/body" --write-out '%{http_code}')
  [ -n "$body" ] && args+=(--header "Content-Type: ${content_type}" --data-binary "@$body")
  : > "$workdir/body"
  last_status="$(curl "${args[@]}" "$url" || echo 000)"
}

json_body() {
  printf '%s' "$1" > "$workdir/request.json"
  printf '%s\n' "$workdir/request.json"
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

# The exercise of one row: one real request, its answer classified and
# recorded against the attachment point, the permission, the requesting
# principal, and the request itself.
observe() {
  local attachment="$1" permission="$2" method="$3" url="$4" body="${5:-}" content_type="${6:-application/json}"
  call "$method" "$url" "$body" "$content_type"
  local classified
  classified="$(classify)"
  last_outcome="$(jq -r '.outcome' <<< "$classified")"
  jq -cn --arg attachment "$attachment" --arg permission "$permission" --arg principal "$canary_principal" --arg method "$method" --arg url "$url" --argjson answer "$classified" \
    '{attachment: $attachment, permission: $permission, principal: $principal, observedAt: (now | todateiso8601), outcome: $answer.outcome, request: {method: $method, url: $url}, response: ($answer | del(.outcome))}' >> "$observations"
  echo "${PHASE}: ${attachment#cloudresourcemanager.googleapis.com/} ${permission} -> ${last_outcome} (${last_status})"
}

# A provisioning or reverting request that is not an observation.
quiet() {
  local method="$1" url="$2" body="${3:-}" content_type="${4:-application/json}"
  call "$method" "$url" "$body" "$content_type"
}

# Wait for a long-running operation named by the last answer: IAM, Cloud Run,
# and Artifact Registry operations are read at their own name; Compute
# operations at their self link. Bounded; a wait that runs out is a failure
# of the phase, recorded and reported.
wait_operation() {
  local kind="$1" name url
  [[ "$last_status" =~ ^2 ]] || return 0
  case "$kind" in
    iam) name="$(jq -r '.name // ""' "$workdir/body")"; url="${iam}/${name}" ;;
    run) name="$(jq -r '.name // ""' "$workdir/body")"; url="${run}/${name}" ;;
    registry) name="$(jq -r '.name // ""' "$workdir/body")"; url="${registry}/v1/${name}" ;;
    compute) url="$(jq -r '.selfLink // ""' "$workdir/body")" ;;
  esac
  [ -n "${name:-}" ] || [ -n "$url" ] || return 0
  [ "$(jq -r '.done // false' "$workdir/body")" = true ] && return 0
  [ "$(jq -r '.status // ""' "$workdir/body")" = DONE ] && return 0
  local attempt
  for attempt in $(seq 1 90); do
    sleep 2
    quiet GET "$url"
    if [ "$kind" = compute ]; then
      [ "$(jq -r '.status // ""' "$workdir/body")" = DONE ] && return 0
    else
      [ "$(jq -r '.done // false' "$workdir/body")" = true ] && return 0
    fi
  done
  echo "operation ${url} did not complete in time" >> "$failures"
  return 1
}

same_policy() {
  jq -c '{policy: ., updateMask: "bindings,etag"}' "$workdir/body" > "$workdir/request.json"
  printf '%s\n' "$workdir/request.json"
}

service_account_email() {
  printf '%s@%s.iam.gserviceaccount.com' "$throwaway" "$1"
}

# ---------------------------------------------------------------------------
# The identity rows of one project: the throwaway account and its keys,
# tokens, signatures, policy, and lifecycle; the throwaway pool and provider.
# The control phase creates them; both phases request the same things.
# ---------------------------------------------------------------------------
identity_rows() {
  local attachment="$1" project="$2" full="$3"
  local email sa pool provider unique_id
  email="$(service_account_email "$project")"
  sa="projects/-/serviceAccounts/${email}"
  pool="projects/${project}/locations/global/workloadIdentityPools/${throwaway}"
  provider="${pool}/providers/${throwaway}"

  observe "$attachment" iam.googleapis.com/serviceAccounts.create POST "${iam}/projects/${project}/serviceAccounts" "$(json_body "$(jq -cn --arg id "$throwaway" '{accountId: $id, serviceAccount: {displayName: "Protected recovery Deny canary throwaway"}}')")"
  if [ "$PHASE" = control ] && [ "$last_outcome" = ALLOWED ]; then sleep 5; fi

  observe "$attachment" iam.googleapis.com/serviceAccountKeys.create POST "${iam}/${sa}/keys" "$(json_body '{"privateKeyType":"TYPE_GOOGLE_CREDENTIALS_FILE","keyAlgorithm":"KEY_ALG_RSA_2048"}')"
  if [ "$last_outcome" = ALLOWED ]; then
    local key
    key="$(jq -r '.name // ""' "$workdir/body")"
    [ -n "$key" ] && quiet DELETE "${iam}/${key}"
  fi

  if [ "$full" = broker ]; then
    observe "$attachment" iam.googleapis.com/serviceAccounts.getAccessToken POST "${credentials}/${sa}:generateAccessToken" "$(json_body '{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"300s"}')"
    observe "$attachment" iam.googleapis.com/serviceAccounts.getOpenIdToken POST "${credentials}/${sa}:generateIdToken" "$(json_body '{"audience":"https://deny-canary.invalid","includeEmail":false}')"
    observe "$attachment" iam.googleapis.com/serviceAccounts.implicitDelegation POST "${credentials}/${sa}:generateAccessToken" "$(json_body "$(jq -cn --arg delegate "$sa" '{scope: ["https://www.googleapis.com/auth/cloud-platform"], lifetime: "300s", delegates: [$delegate]}')")"
    observe "$attachment" iam.googleapis.com/serviceAccounts.signBlob POST "${credentials}/${sa}:signBlob" "$(json_body '{"payload":"ZGVueS1jYW5hcnk="}')"
    observe "$attachment" iam.googleapis.com/serviceAccounts.signJwt POST "${credentials}/${sa}:signJwt" "$(json_body '{"payload":"{\"iss\":\"deny-canary\"}"}')"
  fi

  quiet POST "${iam}/${sa}:getIamPolicy" "$(json_body '{"options":{"requestedPolicyVersion":3}}')"
  observe "$attachment" iam.googleapis.com/serviceAccounts.setIamPolicy POST "${iam}/${sa}:setIamPolicy" "$(same_policy)"

  observe "$attachment" iam.googleapis.com/serviceAccounts.disable POST "${iam}/${sa}:disable" "$(json_body '{}')"
  observe "$attachment" iam.googleapis.com/serviceAccounts.enable POST "${iam}/${sa}:enable" "$(json_body '{}')"

  quiet GET "${iam}/${sa}"
  unique_id="$(jq -r '.uniqueId // ""' "$workdir/body")"
  observe "$attachment" iam.googleapis.com/serviceAccounts.delete DELETE "${iam}/${sa}"
  observe "$attachment" iam.googleapis.com/serviceAccounts.undelete POST "${iam}/projects/-/serviceAccounts/${unique_id:-0}:undelete" "$(json_body '{}')"

  observe "$attachment" iam.googleapis.com/workloadIdentityPools.create POST "${iam}/projects/${project}/locations/global/workloadIdentityPools?workloadIdentityPoolId=${throwaway}" "$(json_body '{"displayName":"Protected recovery Deny canary throwaway"}')"
  wait_operation iam || true
  observe "$attachment" iam.googleapis.com/workloadIdentityPoolProviders.create POST "${iam}/${pool}/providers?workloadIdentityPoolProviderId=${throwaway}" "$(json_body '{"displayName":"Protected recovery Deny canary throwaway","oidc":{"issuerUri":"https://token.actions.githubusercontent.com/"},"attributeMapping":{"google.subject":"assertion.sub"},"attributeCondition":"false"}')"
  wait_operation iam || true
  observe "$attachment" iam.googleapis.com/workloadIdentityPools.update PATCH "${iam}/${pool}?updateMask=description" "$(json_body '{"description":"protected-recovery deny canary"}')"
  wait_operation iam || true
  observe "$attachment" iam.googleapis.com/workloadIdentityPoolProviders.update PATCH "${iam}/${provider}?updateMask=description" "$(json_body '{"description":"protected-recovery deny canary"}')"
  wait_operation iam || true
  observe "$attachment" iam.googleapis.com/workloadIdentityPoolProviders.delete DELETE "${iam}/${provider}"
  wait_operation iam || true
  observe "$attachment" iam.googleapis.com/workloadIdentityPoolProviders.undelete POST "${iam}/${provider}:undelete" "$(json_body '{}')"
  wait_operation iam || true
  observe "$attachment" iam.googleapis.com/workloadIdentityPools.delete DELETE "${iam}/${pool}"
  wait_operation iam || true
  observe "$attachment" iam.googleapis.com/workloadIdentityPools.undelete POST "${iam}/${pool}:undelete" "$(json_body '{}')"
  wait_operation iam || true
}

# actAs is checked when a workload is attached to an account. Cloud Scheduler
# checks exactly that permission and nothing the matrix denies: a job whose
# HTTP target mints an OIDC token as the throwaway account, on a yearly
# schedule against an address that resolves to nothing, paused as soon as it
# exists. Where Cloud Scheduler is not enabled the answer is SERVICE_DISABLED,
# which the module does not accept for this row: the attachment project must
# enable the API before the row can be proven.
act_as_row() {
  local attachment="$1" project="$2"
  local email job
  email="$(service_account_email "$project")"
  job="projects/${project}/locations/${broker_region}/jobs/${throwaway}"
  observe "$attachment" iam.googleapis.com/serviceAccounts.actAs POST "${scheduler}/projects/${project}/locations/${broker_region}/jobs" "$(json_body "$(jq -cn --arg name "$job" --arg email "$email" '{name: $name, schedule: "0 0 1 1 *", timeZone: "Etc/UTC", httpTarget: {uri: "https://deny-canary.invalid/", httpMethod: "GET", oidcToken: {serviceAccountEmail: $email}}}')")"
  [ "$last_outcome" = ALLOWED ] && quiet POST "${scheduler}/${job}:pause" "$(json_body '{}')"
  return 0
}

# The project IAM row: the project's own policy written back unchanged.
project_iam_row() {
  local attachment="$1" project="$2"
  quiet POST "${crm}/projects/${project}:getIamPolicy" "$(json_body '{"options":{"requestedPolicyVersion":3}}')"
  observe "$attachment" cloudresourcemanager.googleapis.com/projects.setIamPolicy POST "${crm}/projects/${project}:setIamPolicy" "$(same_policy)"
}

# Cloud Run rows: the throwaway service (every project), and at consumers
# the throwaway job and worker pool. The broker's delete row deletes the
# service and the control phase creates it again for the deny phase.
run_rows() {
  local attachment="$1" project="$2" scope="$3"
  local email parent service
  email="$(service_account_email "$project")"
  parent="projects/${project}/locations/${broker_region}"
  service="${parent}/services/${throwaway}"
  local service_body
  service_body="$(jq -cn --arg image "$hello_image" --arg email "$email" '{template: {serviceAccount: $email, containers: [{image: $image}]}, ingress: "INGRESS_TRAFFIC_INTERNAL_ONLY"}')"
  observe "$attachment" run.googleapis.com/services.create POST "${run}/${parent}/services?serviceId=${throwaway}" "$(json_body "$service_body")"
  wait_operation run || true
  observe "$attachment" run.googleapis.com/services.update PATCH "${run}/${service}?updateMask=description" "$(json_body '{"description":"protected-recovery deny canary"}')"
  wait_operation run || true
  if [ "$scope" = broker ]; then
    quiet POST "${run}/${service}:getIamPolicy" "$(json_body '{"options":{"requestedPolicyVersion":3}}')"
    observe "$attachment" run.googleapis.com/services.setIamPolicy POST "${run}/${service}:setIamPolicy" "$(same_policy)"
    observe "$attachment" run.googleapis.com/services.delete DELETE "${run}/${service}"
    wait_operation run || true
    if [ "$PHASE" = control ] && [ "$last_outcome" = ALLOWED ]; then
      quiet POST "${run}/${parent}/services?serviceId=${throwaway}" "$(json_body "$service_body")"
      wait_operation run || true
    fi
  else
    observe "$attachment" run.googleapis.com/jobs.create POST "${run}/${parent}/jobs?jobId=${throwaway}" "$(json_body "$(jq -cn --arg image "$hello_image" --arg email "$email" '{template: {template: {serviceAccount: $email, containers: [{image: $image}]}}}')")"
    wait_operation run || true
    observe "$attachment" run.googleapis.com/jobs.update PATCH "${run}/${parent}/jobs/${throwaway}?updateMask=labels" "$(json_body '{"labels":{"protected-recovery":"deny-canary"}}')"
    wait_operation run || true
    observe "$attachment" run.googleapis.com/workerpools.create POST "${run}/${parent}/workerPools?workerPoolId=${throwaway}" "$(json_body "$(jq -cn --arg image "$hello_image" --arg email "$email" '{template: {serviceAccount: $email, containers: [{image: $image}]}, scaling: {scalingMode: "MANUAL", manualInstanceCount: 0}}')")"
    wait_operation run || true
    observe "$attachment" run.googleapis.com/workerpools.update PATCH "${run}/${parent}/workerPools/${throwaway}?updateMask=description" "$(json_body '{"description":"protected-recovery deny canary"}')"
    wait_operation run || true
  fi
}

# The broker's image row: one tiny generic artifact uploaded into the
# throwaway generic repository the control phase creates.
registry_row() {
  local attachment="$1" project="$2"
  local repository="projects/${project}/locations/${broker_region}/repositories/${throwaway}"
  if [ "$PHASE" = control ]; then
    quiet POST "${registry}/v1/projects/${project}/locations/${broker_region}/repositories?repositoryId=${throwaway}" "$(json_body '{"format":"GENERIC","description":"protected-recovery deny canary throwaway"}')"
    wait_operation registry || true
  fi
  local boundary="protected-recovery-deny-canary"
  {
    printf -- '--%s\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n' "$boundary"
    jq -cn --arg version "$suffix" '{package_id: "deny-canary", version_id: $version, filename: "canary.txt"}'
    printf '\r\n--%s\r\nContent-Type: text/plain\r\n\r\nprotected-recovery deny canary %s\r\n--%s--\r\n' "$boundary" "$suffix" "$boundary"
  } > "$workdir/upload.body"
  observe "$attachment" artifactregistry.googleapis.com/repositories.uploadArtifacts POST "${registry}/upload/v1/${repository}/genericArtifacts:create?uploadType=multipart" "$workdir/upload.body" "multipart/related; boundary=${boundary}"
  wait_operation registry || true
}

# The ledger rows: one document in the ledger database, created, read,
# listed, updated, deleted, and created again for the deny phase.
ledger_rows() {
  local attachment="$1" project="$2"
  local documents="projects/${project}/databases/${ledger_database}/documents"
  local name="${documents}/canary/${suffix}"
  local create update delete
  create="$(jq -cn --arg name "$name" '{writes: [{update: {name: $name, fields: {run: {stringValue: "canary"}}}, currentDocument: {exists: false}}]}')"
  update="$(jq -cn --arg name "$name" '{writes: [{update: {name: $name, fields: {run: {stringValue: "canary"}}}, currentDocument: {exists: true}}]}')"
  delete="$(jq -cn --arg name "$name" '{writes: [{delete: $name}]}')"
  observe "$attachment" datastore.googleapis.com/entities.create POST "${firestore}/${documents}:commit" "$(json_body "$create")"
  observe "$attachment" datastore.googleapis.com/entities.get GET "${firestore}/${name}"
  observe "$attachment" datastore.googleapis.com/entities.list GET "${firestore}/${documents}/canary?pageSize=1"
  observe "$attachment" datastore.googleapis.com/entities.update POST "${firestore}/${documents}:commit" "$(json_body "$update")"
  observe "$attachment" datastore.googleapis.com/entities.delete POST "${firestore}/${documents}:commit" "$(json_body "$delete")"
  if [ "$PHASE" = control ] && [ "$last_outcome" = ALLOWED ]; then quiet POST "${firestore}/${documents}:commit" "$(json_body "$create")"; fi
}

# The evidence rows: one object in the evidence bucket, created, updated,
# deleted, and created again for the deny phase.
evidence_rows() {
  local attachment="$1"
  local object="canary%2F${suffix}"
  observe "$attachment" storage.googleapis.com/objects.create POST "${gcs}/upload/storage/v1/b/${evidence_bucket}/o?uploadType=media&name=${object}&ifGenerationMatch=0" "$(json_body '{"canary":true}')"
  observe "$attachment" storage.googleapis.com/objects.update PATCH "${gcs}/storage/v1/b/${evidence_bucket}/o/${object}" "$(json_body '{"metadata":{"protected-recovery":"deny-canary"}}')"
  observe "$attachment" storage.googleapis.com/objects.delete DELETE "${gcs}/storage/v1/b/${evidence_bucket}/o/${object}"
  if [ "$PHASE" = control ] && [ "$last_outcome" = ALLOWED ]; then quiet POST "${gcs}/upload/storage/v1/b/${evidence_bucket}/o?uploadType=media&name=${object}&ifGenerationMatch=0" "$(json_body '{"canary":true}')"; fi
}

# The attachment-freeze rows of a consumer: Compute instances and templates,
# Cloud Build builds, and API disablement. Compute and Cloud Build are not
# enabled in the consumer projects; the identical request then answers
# SERVICE_DISABLED in both phases. Where an API is enabled the exercise is
# real: an instance created and stopped so its account can be re-set, a
# template created, a build created and cancelled at once.
freeze_rows() {
  local attachment="$1" project="$2"
  local email instance
  email="$(service_account_email "$project")"
  instance="projects/${project}/zones/${zone}/instances/${throwaway}"
  observe "$attachment" compute.googleapis.com/instances.create POST "${compute}/projects/${project}/zones/${zone}/instances" "$(json_body "$(jq -cn --arg name "$throwaway" --arg zone "$zone" --arg email "$email" '{name: $name, machineType: ("zones/" + $zone + "/machineTypes/e2-micro"), disks: [{boot: true, autoDelete: true, initializeParams: {sourceImage: "projects/debian-cloud/global/images/family/debian-12"}}], networkInterfaces: [{network: "global/networks/default"}], serviceAccounts: [{email: $email, scopes: ["https://www.googleapis.com/auth/cloud-platform"]}]}')")"
  if [ "$PHASE" = control ] && [ "$last_outcome" = ALLOWED ]; then
    wait_operation compute || true
    quiet POST "${compute}/${instance}/stop"
    wait_operation compute || true
  fi
  observe "$attachment" compute.googleapis.com/instances.setServiceAccount POST "${compute}/${instance}/setServiceAccount" "$(json_body "$(jq -cn --arg email "$email" '{email: $email, scopes: ["https://www.googleapis.com/auth/cloud-platform"]}')")"
  wait_operation compute || true
  observe "$attachment" compute.googleapis.com/instanceTemplates.create POST "${compute}/projects/${project}/global/instanceTemplates" "$(json_body "$(jq -cn --arg name "$throwaway" --arg email "$email" '{name: $name, properties: {machineType: "e2-micro", disks: [{boot: true, autoDelete: true, initializeParams: {sourceImage: "projects/debian-cloud/global/images/family/debian-12"}}], networkInterfaces: [{network: "global/networks/default"}], serviceAccounts: [{email: $email, scopes: ["https://www.googleapis.com/auth/cloud-platform"]}]}}')")"
  wait_operation compute || true
  observe "$attachment" cloudbuild.googleapis.com/builds.create POST "${cloudbuild}/projects/${project}/locations/global/builds" "$(json_body "$(jq -cn --arg project "$project" --arg email "$email" '{steps: [{name: "gcr.io/cloud-builders/gcloud", args: ["version"]}], serviceAccount: ("projects/" + $project + "/serviceAccounts/" + $email), options: {logging: "CLOUD_LOGGING_ONLY"}}')")"
  if [ "$last_outcome" = ALLOWED ]; then
    local build
    build="$(jq -r '.metadata.build.id // ""' "$workdir/body")"
    [ -n "$build" ] && quiet POST "${cloudbuild}/projects/${project}/locations/global/builds/${build}:cancel" "$(json_body '{}')"
  fi
  # An API the platform never enables: disabling it changes nothing when the rule fails.
  observe "$attachment" serviceusage.googleapis.com/services.disable POST "${serviceusage}/projects/${project}/services/websecurityscanner.googleapis.com:disable" "$(json_body '{"disableDependentServices":false}')"
}

# The organization rows: a throwaway custom role at the organization, and an
# organization policy set on the broker project, which the organization's
# Deny rules govern as a descendant.
organization_rows() {
  local attachment="$1"
  local role="organizations/${ORGANIZATION_ID}/roles/${role_id}"
  observe "$attachment" iam.googleapis.com/roles.create POST "${iam}/organizations/${ORGANIZATION_ID}/roles" "$(json_body "$(jq -cn --arg id "$role_id" '{roleId: $id, role: {title: "Protected recovery Deny canary throwaway", includedPermissions: ["resourcemanager.projects.get"], stage: "DISABLED"}}')")"
  observe "$attachment" iam.googleapis.com/roles.update PATCH "${iam}/${role}?updateMask=description" "$(json_body '{"description":"protected-recovery deny canary"}')"
  observe "$attachment" iam.googleapis.com/roles.delete DELETE "${iam}/${role}"
  observe "$attachment" iam.googleapis.com/roles.undelete POST "${iam}/${role}:undelete" "$(json_body '{}')"
  observe "$attachment" orgpolicy.googleapis.com/policy.set POST "${orgpolicy}/projects/${broker_project}/policies" "$(json_body "$(jq -cn --arg project "$broker_project" '{name: ("projects/" + $project + "/policies/compute.skipDefaultNetworkCreation"), spec: {rules: [{enforce: true}]}}')")"
}

# ---------------------------------------------------------------------------
# Cleanup: everything a control run created, addressed by the same names.
# Every deletion is attempted; what could not be deleted is reported and
# the phase fails, so a leftover is never silent.
# ---------------------------------------------------------------------------
cleanup_project() {
  local project="$1" scope="$2"
  local email sa parent pool
  email="$(service_account_email "$project")"
  sa="projects/-/serviceAccounts/${email}"
  parent="projects/${project}/locations/${broker_region}"
  pool="projects/${project}/locations/global/workloadIdentityPools/${throwaway}"
  remove DELETE "${scheduler}/${parent}/jobs/${throwaway}" "scheduler job of ${project}"
  remove DELETE "${run}/${parent}/services/${throwaway}" "Cloud Run service of ${project}" run
  if [ "$scope" = consumer ]; then
    remove DELETE "${run}/${parent}/jobs/${throwaway}" "Cloud Run job of ${project}" run
    remove DELETE "${run}/${parent}/workerPools/${throwaway}" "Cloud Run worker pool of ${project}" run
    remove DELETE "${compute}/projects/${project}/zones/${zone}/instances/${throwaway}" "Compute instance of ${project}" compute
    remove DELETE "${compute}/projects/${project}/global/instanceTemplates/${throwaway}" "Compute template of ${project}" compute
  else
    remove DELETE "${registry}/v1/${parent}/repositories/${throwaway}" "registry repository of ${project}" registry
    remove POST "${firestore}/projects/${project}/databases/${ledger_database}/documents:commit" "ledger document of ${project}" "" "$(json_body "$(jq -cn --arg name "projects/${project}/databases/${ledger_database}/documents/canary/${suffix}" '{writes: [{delete: $name}]}')")"
    remove DELETE "${gcs}/storage/v1/b/${evidence_bucket}/o/canary%2F${suffix}" "evidence object of ${project}"
    remove DELETE "${orgpolicy}/projects/${project}/policies/compute.skipDefaultNetworkCreation" "organization policy of ${project}"
  fi
  remove DELETE "${iam}/${pool}/providers/${throwaway}" "pool provider of ${project}" iam
  remove DELETE "${iam}/${pool}" "pool of ${project}" iam
  transient_keys "$project"
  remove DELETE "${iam}/${sa}" "throwaway account of ${project}"
}

cleanup_organization() {
  remove DELETE "${iam}/organizations/${ORGANIZATION_ID}/roles/${role_id}" "custom role of organizations/${ORGANIZATION_ID}"
}

# One deletion: 2xx and 404 are clean; anything else is a leftover.
remove() {
  local method="$1" url="$2" what="$3" kind="${4:-}" body="${5:-}"
  call "$method" "$url" "$body"
  if [[ "$last_status" =~ ^2 ]]; then
    [ -n "$kind" ] && { wait_operation "$kind" || true; }
    echo "cleanup: removed ${what}"
  elif [ "$last_status" = 404 ]; then
    echo "cleanup: ${what} is absent"
  else
    echo "${what}: HTTP ${last_status} $(jq -r '.error.message // "" | .[0:200]' "$workdir/body" 2> /dev/null)" >> "$failures"
    echo "cleanup: ${what} answered HTTP ${last_status}"
  fi
}

# The keys of the throwaway account, if any survived a phase.
transient_keys() {
  local project="$1" email
  email="$(service_account_email "$project")"
  call GET "${iam}/projects/-/serviceAccounts/${email}/keys?keyTypes=USER_MANAGED"
  [ "$last_status" = 200 ] || return 0
  local key
  while IFS= read -r key; do
    [ -n "$key" ] || continue
    remove DELETE "${iam}/${key}" "key ${key##*/} of ${email}"
  done < <(jq -r '.keys[]?.name' "$workdir/body")
}

# Canary builds still queued or working, if any survived a phase.
transient_builds() {
  local project="$1"
  local filter
  filter="$(jq -rn '"(status=\"QUEUED\" OR status=\"WORKING\") AND tags=\"protected-recovery-deny-canary\"" | @uri')"
  call GET "${cloudbuild}/projects/${project}/locations/global/builds?filter=${filter}"
  [ "$last_status" = 200 ] || return 0
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
  jq -n --arg phase "$PHASE" --arg control "$CONTROL_RUN_ID" --rawfile failures "$failures" '{schema: "protected-recovery/deny-canary-transient-cleanup/v2", phase: $phase, controlRunId: $control, leftovers: ($failures | split("\n") | map(select(length > 0)))}' > "$output"
  jq -r '"transient cleanup: leftovers: \(.leftovers | length)"' "$output"
  exit 0
fi

if [ "$PHASE" = cleanup ]; then
  cleanup_project "$broker_project" broker
  while IFS= read -r project; do
    cleanup_project "$project" consumer
  done < <(consumer_projects)
  cleanup_organization
  jq -n --arg control "$CONTROL_RUN_ID" --argjson run "$GITHUB_RUN_ID" --rawfile failures "$failures" '{schema: "protected-recovery/deny-canary-cleanup/v2", phase: "cleanup", controlRunId: $control, run: {id: $run}, leftovers: ($failures | split("\n") | map(select(length > 0)))}' > "$output"
  jq -r '"cleanup of control run \(.controlRunId): leftovers: \(.leftovers | length)"' "$output"
  [ ! -s "$failures" ]
  exit 0
fi

# ---------------------------------------------------------------------------
# The attested phases. First the live Deny policies at every attachment
# point, by name, with their etags and rules: what the module binds the
# observations to. Then every exercise, in dependency order per scope.
# Finally the predicate: each live rule with the observations of its
# permissions at its attachment point, and every permission no exercise
# reached.
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
      ;;
    organization)
      organization_rows "$attachment"
      ;;
  esac
done < "$attachments"

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
  --arg role "$role_id" \
  --slurpfile policies "$policies" \
  --slurpfile observations "$observations" \
  --rawfile failures "$failures" '
    ($observations) as $seen
    | {
      schema: "protected-recovery/deny-canary/v2",
      phase: $phase,
      controlRunId: $controlRunId,
      brokerImage: $brokerImage,
      organization: $organization,
      run: {attempt: $attempt, event: $event, headSha: $headSha, id: $id, repositoryId: $repositoryId, workflow: $workflow},
      throwaways: {name: $throwaway, role: $role},
      policies: [$policies[] | .attachmentPoint as $attachment | .rules |= [.[] | .deniedPermissions as $permissions | . + {canary: [$seen[] | select(.attachment == $attachment and (.permission | IN($permissions[]))) | del(.attachment)]}]],
      failures: ($failures | split("\n") | map(select(length > 0)))
    }
    | .unexercised = ([.policies[] | .attachmentPoint as $attachment | .rules[] | .deniedPermissions[] as $permission | select([.canary[] | select(.permission == $permission)] | length == 0) | ($attachment + "|" + $permission)] | unique)
  ' > "$output"
jq -r '"\(.phase): policies: \(.policies | length); observations: \([.policies[].rules[].canary[]] | length); allowed: \([.policies[].rules[].canary[] | select(.outcome == "ALLOWED")] | length); denied: \([.policies[].rules[].canary[] | select(.outcome == "DENIED")] | length); unserviceable: \([.policies[].rules[].canary[] | select(.outcome == "UNSERVICEABLE")] | length); error: \([.policies[].rules[].canary[] | select(.outcome == "ERROR")] | length); unexercised: \(.unexercised | length); failures: \(.failures | length)"' "$output"
