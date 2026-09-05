#!/bin/bash
# Exercise every IAM Deny rule attached to the protected-recovery broker
# project and to every consumer project as the canary identity, and write
# the observed matrix as the predicate the deny-canary workflow attests.
#
# For each attachment point the live deny policies are read by name with
# their etags and rules. For each denied permission of each rule the canary
# makes one real API call in a form that is a no-op or self-reverting if the
# Deny fails, and records the API's own answer: DENIED on an IAM permission
# denial, ALLOWED on success (after reverting what it did), ERROR otherwise.
# Permissions this script has no safe exercise for are recorded as
# UNEXERCISED and listed; the module treats a row without a DENIED
# observation as unsatisfied, so nothing here can pass by omission.
#
# Inputs (environment): ACCESS_TOKEN of the canary identity, CANARY_SERVICE_ACCOUNT,
# ORGANIZATION_ID, BROKER_IMAGE, THROWAWAY_SERVICE_ACCOUNT (email, broker
# project), THROWAWAY_WORKLOAD_IDENTITY_POOL (pool ID, broker project), and
# the GitHub run context. The one argument is the output path.
set -euo pipefail

output="${1:?output path}"
: "${ACCESS_TOKEN:?}" "${CANARY_SERVICE_ACCOUNT:?}" "${ORGANIZATION_ID:?}" "${BROKER_IMAGE:?}" "${THROWAWAY_SERVICE_ACCOUNT:?}" "${THROWAWAY_WORKLOAD_IDENTITY_POOL:?}"
: "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}" "${GITHUB_SHA:?}" "${GITHUB_EVENT_NAME:?}" "${GITHUB_REPOSITORY_ID:?}" "${GITHUB_WORKFLOW_REF:?}"
[[ "$ORGANIZATION_ID" =~ ^[1-9][0-9]*$ ]]
[[ "$BROKER_IMAGE" =~ ^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]]
[[ "$THROWAWAY_WORKLOAD_IDENTITY_POOL" =~ ^[a-z][a-z0-9-]{3,31}$ ]]

root="$(cd "$(dirname "$0")/../.." && pwd)"
authority="$root/protected-recovery/authority.json"
broker_project="$(jq -er '.broker.projectId | select(type == "string")' "$authority")"
broker_service="$(jq -er '.broker.serviceName' "$authority")"
broker_region="$(jq -er '.broker.region' "$authority")"
ledger_database="$(jq -er '.broker.firestoreDatabase' "$authority")"
evidence_bucket="${broker_project}-protected-recovery-evidence"
canary_principal="principal://iam.googleapis.com/projects/-/serviceAccounts/${CANARY_SERVICE_ACCOUNT}"
run_suffix="$(printf '%s' "$GITHUB_RUN_ID" | tail -c 12)"
throwaway_name="deny-canary-${run_suffix}"
workflow_path="${GITHUB_WORKFLOW_REF#*/*/}"
workflow_path="${workflow_path%@*}"

workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT
umask 077
printf 'header = "Authorization: Bearer %s"\n' "$ACCESS_TOKEN" > "$workdir/auth.cfg"

# One API call: the HTTP status on stdout, the body in $workdir/body.
call() {
  local method="$1" url="$2" body="${3:-}"
  local args=(--silent --show-error --config "$workdir/auth.cfg" --request "$method" --output "$workdir/body" --write-out '%{http_code}')
  if [ -n "$body" ]; then
    printf '%s' "$body" > "$workdir/request"
    args+=(--header 'Content-Type: application/json' --data-binary "@$workdir/request")
  fi
  curl "${args[@]}" "$url" || echo 000
}

# Classify the answer of one exercise: an IAM permission denial is DENIED,
# success is ALLOWED, anything else is ERROR with the status kept.
classify() {
  local status="$1"
  local api_status
  api_status="$(jq -r '.error.status // ""' "$workdir/body" 2>/dev/null || echo "")"
  if [ "$status" = 403 ] && [ "$api_status" = PERMISSION_DENIED ]; then
    echo DENIED
  elif [[ "$status" =~ ^2 ]]; then
    echo ALLOWED
  else
    echo ERROR
  fi
}

observations="$workdir/observations.jsonl"
: > "$observations"
unexercised="$workdir/unexercised"
: > "$unexercised"

record() {
  local attachment="$1" permission="$2" outcome="$3" status="$4"
  local detail
  detail="$(jq -c --arg status "$status" '{status: $status, message: (.error.message // "" | .[0:200])}' "$workdir/body" 2>/dev/null || jq -cn --arg status "$status" '{status: $status, message: ""}')"
  jq -cn --arg attachment "$attachment" --arg permission "$permission" --arg outcome "$outcome" --arg principal "$canary_principal" --argjson detail "$detail" \
    '{attachment: $attachment, detail: $detail, observedAt: (now | todateiso8601), outcome: $outcome, permission: $permission, principal: $principal}' >> "$observations"
}

# The exercise of one permission at one project: a real call whose success
# is reverted. Returns nothing; records the observation.
exercise() {
  local attachment="$1" permission="$2" project="$3"
  local status outcome iam="https://iam.googleapis.com/v1" credentials="https://iamcredentials.googleapis.com/v1"
  local sa="projects/-/serviceAccounts/${THROWAWAY_SERVICE_ACCOUNT}"
  local consumer_sa="projects/-/serviceAccounts/gha-wif-canary@${project}.iam.gserviceaccount.com"
  local pool="projects/${project}/locations/global/workloadIdentityPools/${THROWAWAY_WORKLOAD_IDENTITY_POOL}"
  case "$permission" in
    datastore.googleapis.com/entities.create)
      status="$(call POST "https://firestore.googleapis.com/v1/projects/${project}/databases/${ledger_database}/documents:commit" "$(jq -cn --arg name "projects/${project}/databases/${ledger_database}/documents/canary/${run_suffix}" '{writes: [{update: {name: $name, fields: {run: {stringValue: "canary"}}}, currentDocument: {exists: false}}]}')")"
      outcome="$(classify "$status")"
      [ "$outcome" = ALLOWED ] && call POST "https://firestore.googleapis.com/v1/projects/${project}/databases/${ledger_database}/documents:commit" "$(jq -cn --arg name "projects/${project}/databases/${ledger_database}/documents/canary/${run_suffix}" '{writes: [{delete: $name}]}')" > /dev/null
      ;;
    datastore.googleapis.com/entities.update)
      status="$(call POST "https://firestore.googleapis.com/v1/projects/${project}/databases/${ledger_database}/documents:commit" "$(jq -cn --arg name "projects/${project}/databases/${ledger_database}/documents/canary/${run_suffix}" '{writes: [{update: {name: $name, fields: {run: {stringValue: "canary"}}}, currentDocument: {exists: true}}]}')")"
      outcome="$(classify "$status")"
      ;;
    datastore.googleapis.com/entities.delete)
      status="$(call POST "https://firestore.googleapis.com/v1/projects/${project}/databases/${ledger_database}/documents:commit" "$(jq -cn --arg name "projects/${project}/databases/${ledger_database}/documents/canary/${run_suffix}" '{writes: [{delete: $name}]}')")"
      outcome="$(classify "$status")"
      ;;
    storage.googleapis.com/objects.create)
      status="$(call POST "https://storage.googleapis.com/upload/storage/v1/b/${evidence_bucket}/o?uploadType=media&name=canary%2F${run_suffix}&ifGenerationMatch=0" '{"canary":true}')"
      outcome="$(classify "$status")"
      [ "$outcome" = ALLOWED ] && call DELETE "https://storage.googleapis.com/storage/v1/b/${evidence_bucket}/o/canary%2F${run_suffix}" > /dev/null
      ;;
    storage.googleapis.com/objects.update)
      status="$(call PATCH "https://storage.googleapis.com/storage/v1/b/${evidence_bucket}/o/canary%2F${run_suffix}" '{"metadata":{"canary":"true"}}')"
      outcome="$(classify "$status")"
      ;;
    storage.googleapis.com/objects.delete)
      status="$(call DELETE "https://storage.googleapis.com/storage/v1/b/${evidence_bucket}/o/canary%2F${run_suffix}")"
      outcome="$(classify "$status")"
      ;;
    iam.googleapis.com/serviceAccountKeys.create)
      status="$(call POST "${iam}/${sa}/keys" '{"privateKeyType":"TYPE_GOOGLE_CREDENTIALS_FILE","keyAlgorithm":"KEY_ALG_RSA_2048"}')"
      outcome="$(classify "$status")"
      if [ "$outcome" = ALLOWED ]; then
        local key
        key="$(jq -r '.name' "$workdir/body")"
        call DELETE "${iam}/${key}" > /dev/null
      fi
      ;;
    iam.googleapis.com/serviceAccounts.getAccessToken)
      status="$(call POST "${credentials}/${sa}:generateAccessToken" '{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"300s"}')"
      outcome="$(classify "$status")"
      ;;
    iam.googleapis.com/serviceAccounts.implicitDelegation)
      status="$(call POST "${credentials}/${sa}:generateAccessToken" "$(jq -cn --arg delegate "$sa" '{scope: ["https://www.googleapis.com/auth/cloud-platform"], lifetime: "300s", delegates: [$delegate]}')")"
      outcome="$(classify "$status")"
      ;;
    iam.googleapis.com/serviceAccounts.getOpenIdToken)
      status="$(call POST "${credentials}/${sa}:generateIdToken" '{"audience":"https://deny-canary.invalid","includeEmail":false}')"
      outcome="$(classify "$status")"
      ;;
    iam.googleapis.com/serviceAccounts.signBlob)
      status="$(call POST "${credentials}/${sa}:signBlob" '{"payload":"ZGVueS1jYW5hcnk="}')"
      outcome="$(classify "$status")"
      ;;
    iam.googleapis.com/serviceAccounts.signJwt)
      status="$(call POST "${credentials}/${sa}:signJwt" '{"payload":"{\"iss\":\"deny-canary\"}"}')"
      outcome="$(classify "$status")"
      ;;
    iam.googleapis.com/serviceAccounts.create)
      status="$(call POST "${iam}/projects/${project}/serviceAccounts" "$(jq -cn --arg id "$throwaway_name" '{accountId: $id, serviceAccount: {displayName: "Deny canary throwaway"}}')")"
      outcome="$(classify "$status")"
      [ "$outcome" = ALLOWED ] && call DELETE "${iam}/projects/${project}/serviceAccounts/${throwaway_name}@${project}.iam.gserviceaccount.com" > /dev/null
      ;;
    iam.googleapis.com/serviceAccounts.disable)
      status="$(call POST "${iam}/${sa}:disable" '{}')"
      outcome="$(classify "$status")"
      [ "$outcome" = ALLOWED ] && call POST "${iam}/${sa}:enable" '{}' > /dev/null
      ;;
    iam.googleapis.com/serviceAccounts.enable)
      status="$(call POST "${iam}/${sa}:enable" '{}')"
      outcome="$(classify "$status")"
      ;;
    iam.googleapis.com/serviceAccounts.delete)
      local unique_id
      call GET "${iam}/${sa}" > /dev/null
      unique_id="$(jq -r '.uniqueId // ""' "$workdir/body")"
      status="$(call DELETE "${iam}/${sa}")"
      outcome="$(classify "$status")"
      [ "$outcome" = ALLOWED ] && [ -n "$unique_id" ] && call POST "${iam}/projects/-/serviceAccounts/${unique_id}:undelete" '{}' > /dev/null
      ;;
    iam.googleapis.com/serviceAccounts.undelete)
      local unique_id
      call GET "${iam}/${sa}" > /dev/null
      unique_id="$(jq -r '.uniqueId // ""' "$workdir/body")"
      status="$(call POST "${iam}/projects/-/serviceAccounts/${unique_id:-0}:undelete" '{}')"
      outcome="$(classify "$status")"
      ;;
    iam.googleapis.com/serviceAccounts.setIamPolicy)
      local resource
      if [ "$project" = "$broker_project" ]; then resource="$sa"; else resource="$consumer_sa"; fi
      call POST "${iam}/${resource}:getIamPolicy" '{"options":{"requestedPolicyVersion":3}}' > /dev/null
      status="$(call POST "${iam}/${resource}:setIamPolicy" "$(jq -c '{policy: ., updateMask: "bindings,etag"}' "$workdir/body")")"
      outcome="$(classify "$status")"
      ;;
    cloudresourcemanager.googleapis.com/projects.setIamPolicy)
      call POST "https://cloudresourcemanager.googleapis.com/v3/projects/${project}:getIamPolicy" '{"options":{"requestedPolicyVersion":3}}' > /dev/null
      status="$(call POST "https://cloudresourcemanager.googleapis.com/v3/projects/${project}:setIamPolicy" "$(jq -c '{policy: ., updateMask: "bindings,etag"}' "$workdir/body")")"
      outcome="$(classify "$status")"
      ;;
    iam.googleapis.com/workloadIdentityPools.create)
      status="$(call POST "${iam}/projects/${project}/locations/global/workloadIdentityPools?workloadIdentityPoolId=${throwaway_name}" '{"displayName":"Deny canary throwaway"}')"
      outcome="$(classify "$status")"
      [ "$outcome" = ALLOWED ] && call DELETE "${iam}/projects/${project}/locations/global/workloadIdentityPools/${throwaway_name}" > /dev/null
      ;;
    iam.googleapis.com/workloadIdentityPools.update)
      status="$(call PATCH "${iam}/${pool}?updateMask=description" '{"description":"deny canary"}')"
      outcome="$(classify "$status")"
      ;;
    iam.googleapis.com/workloadIdentityPools.delete)
      status="$(call DELETE "${iam}/${pool}")"
      outcome="$(classify "$status")"
      [ "$outcome" = ALLOWED ] && call POST "${iam}/${pool}:undelete" '{}' > /dev/null
      ;;
    iam.googleapis.com/workloadIdentityPools.undelete)
      status="$(call POST "${iam}/${pool}:undelete" '{}')"
      outcome="$(classify "$status")"
      ;;
    iam.googleapis.com/workloadIdentityPoolProviders.create)
      status="$(call POST "${iam}/${pool}/providers?workloadIdentityPoolProviderId=${throwaway_name}" '{"displayName":"Deny canary throwaway","oidc":{"issuerUri":"https://token.actions.githubusercontent.com/"},"attributeMapping":{"google.subject":"assertion.sub"}}')"
      outcome="$(classify "$status")"
      [ "$outcome" = ALLOWED ] && call DELETE "${iam}/${pool}/providers/${throwaway_name}" > /dev/null
      ;;
    iam.googleapis.com/workloadIdentityPoolProviders.update)
      status="$(call PATCH "${iam}/${pool}/providers/${throwaway_name}?updateMask=description" '{"description":"deny canary"}')"
      outcome="$(classify "$status")"
      ;;
    iam.googleapis.com/workloadIdentityPoolProviders.delete)
      status="$(call DELETE "${iam}/${pool}/providers/${throwaway_name}")"
      outcome="$(classify "$status")"
      ;;
    iam.googleapis.com/workloadIdentityPoolProviders.undelete)
      status="$(call POST "${iam}/${pool}/providers/${throwaway_name}:undelete" '{}')"
      outcome="$(classify "$status")"
      ;;
    run.googleapis.com/services.create)
      status="$(call POST "https://run.googleapis.com/v2/projects/${project}/locations/${broker_region}/services?serviceId=${throwaway_name}" '{"template":{"containers":[{"image":"us-docker.pkg.dev/cloudrun/container/hello"}]}}')"
      outcome="$(classify "$status")"
      [ "$outcome" = ALLOWED ] && call DELETE "https://run.googleapis.com/v2/projects/${project}/locations/${broker_region}/services/${throwaway_name}" > /dev/null
      ;;
    run.googleapis.com/services.update)
      status="$(call PATCH "https://run.googleapis.com/v2/projects/${project}/locations/${broker_region}/services/${throwaway_name}?updateMask=description" '{"description":"deny canary"}')"
      outcome="$(classify "$status")"
      ;;
    run.googleapis.com/services.delete)
      status="$(call DELETE "https://run.googleapis.com/v2/projects/${project}/locations/${broker_region}/services/${throwaway_name}")"
      outcome="$(classify "$status")"
      ;;
    run.googleapis.com/services.setIamPolicy)
      local service="projects/${project}/locations/${broker_region}/services/${broker_service}"
      call POST "https://run.googleapis.com/v2/${service}:getIamPolicy" '{"options":{"requestedPolicyVersion":3}}' > /dev/null
      status="$(call POST "https://run.googleapis.com/v2/${service}:setIamPolicy" "$(jq -c '{policy: ., updateMask: "bindings,etag"}' "$workdir/body")")"
      outcome="$(classify "$status")"
      ;;
    run.googleapis.com/jobs.create)
      status="$(call POST "https://run.googleapis.com/v2/projects/${project}/locations/${broker_region}/jobs?jobId=${throwaway_name}" '{"template":{"template":{"containers":[{"image":"us-docker.pkg.dev/cloudrun/container/hello"}]}}}')"
      outcome="$(classify "$status")"
      [ "$outcome" = ALLOWED ] && call DELETE "https://run.googleapis.com/v2/projects/${project}/locations/${broker_region}/jobs/${throwaway_name}" > /dev/null
      ;;
    run.googleapis.com/jobs.update)
      status="$(call PATCH "https://run.googleapis.com/v2/projects/${project}/locations/${broker_region}/jobs/${throwaway_name}?updateMask=labels" '{"labels":{"deny-canary":"true"}}')"
      outcome="$(classify "$status")"
      ;;
    compute.googleapis.com/instances.create)
      status="$(call POST "https://compute.googleapis.com/compute/v1/projects/${project}/zones/${broker_region}-a/instances" "$(jq -cn --arg name "$throwaway_name" --arg zone "${broker_region}-a" '{name: $name, machineType: ("zones/" + $zone + "/machineTypes/e2-micro"), disks: [{boot: true, autoDelete: true, initializeParams: {sourceImage: "projects/debian-cloud/global/images/family/debian-12"}}], networkInterfaces: [{network: "global/networks/default"}]}')")"
      outcome="$(classify "$status")"
      [ "$outcome" = ALLOWED ] && call DELETE "https://compute.googleapis.com/compute/v1/projects/${project}/zones/${broker_region}-a/instances/${throwaway_name}" > /dev/null
      ;;
    compute.googleapis.com/instances.setServiceAccount)
      status="$(call POST "https://compute.googleapis.com/compute/v1/projects/${project}/zones/${broker_region}-a/instances/${throwaway_name}/setServiceAccount" '{"email":"","scopes":[]}')"
      outcome="$(classify "$status")"
      ;;
    compute.googleapis.com/instanceTemplates.create)
      status="$(call POST "https://compute.googleapis.com/compute/v1/projects/${project}/global/instanceTemplates" "$(jq -cn --arg name "$throwaway_name" '{name: $name, properties: {machineType: "e2-micro", disks: [{boot: true, autoDelete: true, initializeParams: {sourceImage: "projects/debian-cloud/global/images/family/debian-12"}}], networkInterfaces: [{network: "global/networks/default"}]}}')")"
      outcome="$(classify "$status")"
      [ "$outcome" = ALLOWED ] && call DELETE "https://compute.googleapis.com/compute/v1/projects/${project}/global/instanceTemplates/${throwaway_name}" > /dev/null
      ;;
    cloudbuild.googleapis.com/builds.create)
      status="$(call POST "https://cloudbuild.googleapis.com/v1/projects/${project}/locations/global/builds" '{"steps":[{"name":"gcr.io/cloud-builders/gcloud","args":["version"]}]}')"
      outcome="$(classify "$status")"
      if [ "$outcome" = ALLOWED ]; then
        local build
        build="$(jq -r '.metadata.build.id // ""' "$workdir/body")"
        [ -n "$build" ] && call POST "https://cloudbuild.googleapis.com/v1/projects/${project}/locations/global/builds/${build}:cancel" '{}' > /dev/null
      fi
      ;;
    serviceusage.googleapis.com/services.disable)
      # An API the platform never enables: disabling it changes nothing when the Deny fails.
      status="$(call POST "https://serviceusage.googleapis.com/v1/projects/${project}/services/websecurityscanner.googleapis.com:disable" '{"disableDependentServices":false}')"
      outcome="$(classify "$status")"
      ;;
    *)
      # No safe exercise exists for this permission: actAs is checked only
      # when a workload is attached, and an artifact upload needs an image
      # push. The row stays unsatisfied and activation blocked until a safe
      # exercise is added here.
      echo "$permission" >> "$unexercised"
      printf '{}' > "$workdir/body"
      record "$attachment" "$permission" UNEXERCISED "000"
      return 0
      ;;
  esac
  record "$attachment" "$permission" "$outcome" "$status"
}

# Every attachment point of the deployment, the live deny policies attached
# to each, and every rule exercised.
policies="$workdir/policies.jsonl"
: > "$policies"
while IFS=$'\t' read -r attachment project; do
  encoded="$(jq -rn --arg attachment "$attachment" '$attachment | @uri')"
  status="$(call GET "https://iam.googleapis.com/v2/policies/${encoded}/denypolicies")"
  [ "$status" = 200 ] || { echo "Listing the deny policies of ${attachment} answered HTTP ${status}." >&2; exit 1; }
  jq -r '.policies[]?.name' "$workdir/body" > "$workdir/names"
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    status="$(call GET "https://iam.googleapis.com/v2/${name}")"
    [ "$status" = 200 ] || { echo "Reading ${name} answered HTTP ${status}." >&2; exit 1; }
    cp "$workdir/body" "$workdir/policy.json"
    rules="$(jq -c '[.rules[]? | .denyRule | select(. != null) | {deniedPermissions: (.deniedPermissions // []), deniedPrincipals: (.deniedPrincipals // []), exceptionPrincipals: (.exceptionPrincipals // []), exceptionPermissions: (.exceptionPermissions // []), denialCondition: (.denialCondition // null)}]' "$workdir/policy.json")"
    : > "$workdir/rules.jsonl"
    echo "$rules" | jq -c '.[]' | while IFS= read -r rule; do
      : > "$workdir/rule-observations.jsonl"
      echo "$rule" | jq -r '.deniedPermissions[]' | while IFS= read -r permission; do
        exercise "$attachment" "$permission" "$project"
        tail -n 1 "$observations" >> "$workdir/rule-observations.jsonl"
      done
      jq -c --slurpfile canary "$workdir/rule-observations.jsonl" '. + {canary: ($canary | map(del(.attachment)))}' <<< "$rule" >> "$workdir/rules.jsonl"
    done
    jq -c --arg attachment "$attachment" --slurpfile rules "$workdir/rules.jsonl" '{attachmentPoint: $attachment, etag: .etag, name: .name, rules: $rules}' "$workdir/policy.json" >> "$policies"
  done < "$workdir/names"
done < <(
  printf '%s\t%s\n' "cloudresourcemanager.googleapis.com/projects/${broker_project}" "$broker_project"
  jq -r '.consumers[] | "cloudresourcemanager.googleapis.com/projects/\(.projectId)\t\(.projectId)"' "$authority"
)

jq -n \
  --arg brokerImage "$BROKER_IMAGE" \
  --arg organization "organizations/${ORGANIZATION_ID}" \
  --argjson attempt "$GITHUB_RUN_ATTEMPT" \
  --arg event "$GITHUB_EVENT_NAME" \
  --arg headSha "$GITHUB_SHA" \
  --argjson id "$GITHUB_RUN_ID" \
  --arg repositoryId "$GITHUB_REPOSITORY_ID" \
  --arg workflow "$workflow_path" \
  --slurpfile policies "$policies" \
  --rawfile unexercised "$unexercised" '{
    brokerImage: $brokerImage,
    organization: $organization,
    policies: $policies,
    run: {attempt: $attempt, event: $event, headSha: $headSha, id: $id, repositoryId: $repositoryId, workflow: $workflow},
    schema: "protected-recovery/deny-canary/v1",
    unexercised: ($unexercised | split("\n") | map(select(length > 0)) | unique)
  }' > "$output"
jq -r '"policies: \(.policies | length); observations: \([.policies[].rules[].canary[]] | length); denied: \([.policies[].rules[].canary[] | select(.outcome == "DENIED")] | length); unexercised: \(.unexercised | length)"' "$output"
