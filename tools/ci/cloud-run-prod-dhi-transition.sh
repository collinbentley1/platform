#!/bin/bash

set -euo pipefail

die() {
  echo "$*" >&2
  exit 1
}

readonly COMMAND="${1:-}"
[[ "$COMMAND" == prepare || "$COMMAND" == finalize ]] ||
  die "usage: cloud-run-prod-dhi-transition.sh {prepare|finalize}"

readonly ACCESS_TOKEN="${ACCESS_TOKEN:?}"
readonly PROJECT_ID="${PROJECT_ID:?}"
readonly REGION="${REGION:?}"
readonly SERVICE_NAME="${SERVICE_NAME:?}"
readonly PREVIEW_SERVICE="${PREVIEW_SERVICE:?}"
readonly EXPECTED_PROJECT_NUMBER="${EXPECTED_PROJECT_NUMBER:?}"
readonly REPOSITORY_ID="${REPOSITORY_ID:-${EXPECTED_REPOSITORY_ID:-}}"
readonly EXPECTED_PRODUCTION_IMAGE_NAME="${EXPECTED_PRODUCTION_IMAGE_NAME:?}"
readonly EXPECTED_PREVIEW_IMAGE_NAME="${EXPECTED_PREVIEW_IMAGE_NAME:?}"
readonly EXPECTED_PREVIEW_RUNTIME_SERVICE_ACCOUNT="${EXPECTED_PREVIEW_RUNTIME_SERVICE_ACCOUNT:?}"
readonly EXPECTED_PLATFORM_WORKFLOW_SHA="${EXPECTED_PLATFORM_WORKFLOW_SHA:?}"
readonly DHI_PARITY_ID="${DHI_PARITY_ID:?}"
readonly PARITY_POLICY_ROOT="${PARITY_POLICY_ROOT:?}"
readonly TRANSITION_LEASE_FILE="${TRANSITION_LEASE_FILE:-${RUNNER_TEMP:?}/prod-dhi-transition-lease.json}"

[[ "$PROJECT_ID" =~ ^[a-z][a-z0-9-]{4,29}$ ]]
[[ "$REGION" =~ ^[a-z]+-[a-z]+[0-9]$ ]]
[[ "$SERVICE_NAME" =~ ^[a-z][a-z0-9-]{0,62}$ ]]
[[ "$PREVIEW_SERVICE" =~ ^[a-z][a-z0-9-]{0,62}$ ]]
[[ "$EXPECTED_PROJECT_NUMBER" =~ ^[1-9][0-9]*$ ]]
[[ "$REPOSITORY_ID" =~ ^(1255553151|711292980|1025243085|280932482)$ ]]
[[ "$EXPECTED_PLATFORM_WORKFLOW_SHA" =~ ^[0-9a-f]{40}$ ]]
[[ "$DHI_PARITY_ID" =~ ^[a-z0-9]{50}$ ]]
[[ "$TRANSITION_LEASE_FILE" == "${RUNNER_TEMP:?}"/* ]]
test -x "$PARITY_POLICY_ROOT/tools/ci/deployment-parity-transition.sh"

umask 077
work="$(mktemp -d "${RUNNER_TEMP:?}/prod-dhi-transition.XXXXXX")"
token="$work/access-token"
header="$work/rest-header"
printf '%s' "$ACCESS_TOKEN" > "$token"
printf 'Authorization: Bearer %s\n' "$ACCESS_TOKEN" > "$header"
transition_acquired=false

cleanup() {
  status=$?
  set +e
  rm -f -- "$token" "$header"
  if [[ "$work" == "${RUNNER_TEMP:?}/prod-dhi-transition."* ]] &&
     [ -d "$work" ] && [ ! -L "$work" ]; then
    find "$work" -depth -delete
  fi
  if [ "$status" -ne 0 ] && [ "$transition_acquired" = true ]; then
    echo "CRITICAL: production DHI epoch remains durably poisoned; previews stay SEALED until explicit recovery." >&2
  fi
  trap - EXIT
  exit "$status"
}
trap cleanup EXIT

output_value() {
  sed -n "s/^$1=//p" "$2" | tail -n 1
}

acquire_transition() {
  env ACCESS_TOKEN="$ACCESS_TOKEN" PROJECT_ID="$PROJECT_ID" REPOSITORY_ID="$REPOSITORY_ID" \
    EXPECTED_PLATFORM_WORKFLOW_SHA="$EXPECTED_PLATFORM_WORKFLOW_SHA" DHI_PARITY_ID="$DHI_PARITY_ID" \
    TRANSITION_KIND=prod-dhi-transition TRANSITION_LEASE_FILE="$TRANSITION_LEASE_FILE" \
    "$PARITY_POLICY_ROOT/tools/ci/deployment-parity-transition.sh" acquire
  transition_acquired=true
}

resume_transition() {
  env ACCESS_TOKEN="$ACCESS_TOKEN" PROJECT_ID="$PROJECT_ID" REPOSITORY_ID="$REPOSITORY_ID" \
    EXPECTED_PLATFORM_WORKFLOW_SHA="$EXPECTED_PLATFORM_WORKFLOW_SHA" DHI_PARITY_ID="$DHI_PARITY_ID" \
    TRANSITION_LEASE_FILE="$TRANSITION_LEASE_FILE" \
    "$PARITY_POLICY_ROOT/tools/ci/deployment-parity-transition.sh" resume-prod
  transition_acquired=true
}

assert_transition_clear() {
  env ACCESS_TOKEN="$ACCESS_TOKEN" PROJECT_ID="$PROJECT_ID" REPOSITORY_ID="$REPOSITORY_ID" \
    "$PARITY_POLICY_ROOT/tools/ci/deployment-parity-transition.sh" assert-clear
}

release_transition() {
  env ACCESS_TOKEN="$ACCESS_TOKEN" PROJECT_ID="$PROJECT_ID" REPOSITORY_ID="$REPOSITORY_ID" \
    TRANSITION_LEASE_FILE="$TRANSITION_LEASE_FILE" \
    "$PARITY_POLICY_ROOT/tools/ci/deployment-parity-transition.sh" release
}

capture_candidate_production() {
  local suffix="$1"
  local service="$work/prod-${suffix}-service.json"
  local revision="$work/prod-${suffix}-revision.json"
  local service_v2="$work/prod-${suffix}-service-v2.json"
  local revision_v2="$work/prod-${suffix}-revision-v2.json"
  local outputs="$work/prod-${suffix}.outputs"
  local graph_outputs="$work/prod-${suffix}-graph.outputs"
  local revision_name
  if ! gcloud --access-token-file="$token" run services describe "$SERVICE_NAME" \
    --project="$PROJECT_ID" --region="$REGION" --format=json > "$service" 2>/dev/null; then
    return 1
  fi
  revision_name="$(jq -er '.status.latestReadyRevisionName | select(test("^[a-z][a-z0-9-]{0,62}$"))' "$service")" ||
    return 1
  if ! gcloud --access-token-file="$token" run revisions describe "$revision_name" \
    --project="$PROJECT_ID" --region="$REGION" --format=json > "$revision" 2>/dev/null; then
    return 1
  fi
  if ! curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
    --header "@$header" --output "$service_v2" \
    "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${SERVICE_NAME}"; then return 1; fi
  if ! curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
    --header "@$header" --output "$revision_v2" \
    "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${SERVICE_NAME}/revisions/${revision_name}"; then return 1; fi
  if ! jq -e --arg name "projects/${PROJECT_ID}/locations/${REGION}/services/${SERVICE_NAME}" --arg revision "$revision_name" '
    .name == $name and (.generation == .observedGeneration) and ((.reconciling // false) == false) and
    .terminalCondition.type == "Ready" and .terminalCondition.state == "CONDITION_SUCCEEDED" and
    (.latestReadyRevision | split("/")[-1]) == $revision and
    (.traffic | length) == 1 and .traffic[0].type == "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST" and
    .traffic[0].percent == 100 and ((.traffic[0].tag // "") == "") and ((.traffic[0].revision // "") == "") and
    (.trafficStatuses | length) == 1 and .trafficStatuses[0].type == "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST" and
    .trafficStatuses[0].percent == 100 and ((.trafficStatuses[0].tag // "") == "") and
    ((.trafficStatuses[0].revision // "") == "") and ((.buildConfig // {}) == {}) and
    all(.template.containers[]?; ((.baseImageUri // "") == ""))
  ' "$service_v2" >/dev/null; then return 1; fi
  if ! env GITHUB_OUTPUT="$outputs" PARITY_SERVICE_JSON="$service" PARITY_REVISION_JSON="$revision" \
    EXPECTED_SERVICE_NAME="$SERVICE_NAME" EXPECTED_PROJECT_NUMBER="$EXPECTED_PROJECT_NUMBER" \
    EXPECTED_REPOSITORY_ID="$REPOSITORY_ID" EXPECTED_PRODUCTION_IMAGE_NAME="$EXPECTED_PRODUCTION_IMAGE_NAME" \
    "$PARITY_POLICY_ROOT/tools/ci/cloud-run-dhi-parity.sh" prove-production >/dev/null 2>&1; then
    return 1
  fi
  live_head="$(output_value live_production_head_sha "$outputs")"
  live_index="$(output_value live_production_index_image "$outputs")"
  live_runnable="$(output_value live_production_runnable_image "$outputs")"
  if ! env GITHUB_OUTPUT="$graph_outputs" AR_ACCESS_TOKEN="$ACCESS_TOKEN" \
    BASE_CONTENT_SHA256="${BASE_CONTENT_SHA256:?}" BASE_DOWNLOAD_DIR="${BASE_DOWNLOAD_DIR:?}" \
    BASE_MANIFEST_SHA256="${BASE_MANIFEST_SHA256:?}" LIVE_IMAGE_KIND=production \
    LIVE_IMAGE_HEAD_SHA="$live_head" LIVE_INDEX_IMAGE="$live_index" LIVE_RUNNABLE_IMAGE="$live_runnable" \
    EXPECTED_IMAGE_NAME="$EXPECTED_PRODUCTION_IMAGE_NAME" \
    "$PARITY_POLICY_ROOT/tools/ci/container-artifact-contract.sh" verify-live-production >/dev/null 2>&1; then
    return 1
  fi
  [ "$(output_value dhi_parity_id "$graph_outputs")" = "$DHI_PARITY_ID" ]
  if ! jq -e --arg name "projects/${PROJECT_ID}/locations/${REGION}/services/${SERVICE_NAME}/revisions/${revision_name}" \
    --arg image "$live_runnable" --arg index "${live_index##*@}" --arg runnable "${live_runnable##*@}" '
    def exact_value($name):
      [.containers[0].env[]? | select(.name == $name and (keys | sort) == ["name","value"]) | .value]
      | if length == 1 then .[0] else error("invalid immutable image identity") end;
    .name == $name and ((.reconciling // false) == false) and
    (.containers | length) == 1 and .containers[0].image == $image and
    ((.containers[0].baseImageUri // "") == "") and
    exact_value("PLATFORM_IMAGE_INDEX_DIGEST") == $index and
    exact_value("PLATFORM_IMAGE_RUNNABLE_DIGEST") == $runnable and
    ([.conditions[]? | select(.type == "Ready" and .state == "CONDITION_SUCCEEDED")] | length) == 1
  ' "$revision_v2" >/dev/null; then return 1; fi
  jq -n --arg revision "$revision_name" --arg head "$live_head" --arg index "$live_index" --arg runnable "$live_runnable" \
    '{revision:$revision,head:$head,index:$index,runnable:$runnable}' > "$work/prod-${suffix}-identity.json"
  {
    jq -cS '.' "$service"
    jq -cS '.' "$revision"
    jq -cS '.' "$service_v2"
    jq -cS '.' "$revision_v2"
  } | sha256sum | cut -d ' ' -f 1 > "$work/prod-${suffix}-projection.sha256"
  printf '%s\n' "$revision_name" > "$work/prod-${suffix}-revision-name"
}

fetch_preview_v2() {
  local destination="$1" status
  status="$(curl --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
    --header "@$header" --output "$destination" --write-out '%{http_code}' \
    "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}")"
  [ "$status" = 200 ] || die "Preview service must exist before a production DHI epoch (HTTP ${status})."
  jq -e --arg name "projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}" '
    .name == $name and
    (.etag | type == "string" and length > 0 and length <= 1024 and (test("[[:cntrl:]]") | not)) and
    (.generation == .observedGeneration) and ((.reconciling // false) == false) and
    .terminalCondition.type == "Ready" and .terminalCondition.state == "CONDITION_SUCCEEDED" and
    ((.buildConfig // {}) == {}) and ((.template.vpcAccess // {}) == {}) and
    ((.template.volumes // []) | length == 0) and
    all(.template.containers[]?;
      ((.baseImageUri // "") == "") and ((.volumeMounts // []) | length == 0))
  ' "$destination" >/dev/null
}

wait_operation() {
  local operation_file="$1" result="$2"
  local operation_name done=false
  operation_name="$(jq -er '.name | select(test("^projects/[^/]+/locations/[a-z0-9-]+/operations/[A-Za-z0-9_-]+$"))' "$operation_file")"
  for attempt in $(seq 1 60); do
    curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
      --header "@$header" --output "$result" "https://run.googleapis.com/v2/${operation_name}"
    if jq -e --arg service "projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}" '
      .done == true and (has("error") | not) and .response.name == $service
    ' "$result" >/dev/null; then done=true; break; fi
    [ "$attempt" -eq 60 ] || sleep 2
  done
  [ "$done" = true ]
}

sanitize_invoker_policy() {
  local policy="$work/invoker-policy.json" body="$work/invoker-policy-body.json"
  local result="$work/invoker-policy-result.json" status
  for attempt in $(seq 1 5); do
    curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
      --header "@$header" --output "$policy" \
      "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}:getIamPolicy?options.requestedPolicyVersion=3"
    jq -e '((.bindings // []) | type == "array") and (.etag | type == "string" and length > 0)' "$policy" >/dev/null
    if jq -e --arg project "$PROJECT_ID" '
      def expected: [
        {role:"projects/\($project)/roles/cloudRunRevisionDeployer",members:["serviceAccount:gha-preview-deploy@\($project).iam.gserviceaccount.com"]},
        {role:"projects/\($project)/roles/deploymentParityCloudRunReader",members:["serviceAccount:gha-deploy-parity@\($project).iam.gserviceaccount.com"]},
        {role:"projects/\($project)/roles/previewTrafficCommitter",members:["serviceAccount:gha-preview-commit@\($project).iam.gserviceaccount.com"]}
      ] | sort_by(.role);
      ((.bindings // []) | map(.members |= sort) | sort_by(.role)) == expected
    ' "$policy" >/dev/null; then
      return 0
    fi
    jq --arg project "$PROJECT_ID" '{policy:(. | .bindings = [
      {role:"projects/\($project)/roles/cloudRunRevisionDeployer",members:["serviceAccount:gha-preview-deploy@\($project).iam.gserviceaccount.com"]},
      {role:"projects/\($project)/roles/deploymentParityCloudRunReader",members:["serviceAccount:gha-deploy-parity@\($project).iam.gserviceaccount.com"]},
      {role:"projects/\($project)/roles/previewTrafficCommitter",members:["serviceAccount:gha-preview-commit@\($project).iam.gserviceaccount.com"]}
    ]),updateMask:"bindings,etag"}' "$policy" > "$body"
    status="$(curl --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
      --request POST --header "@$header" --header 'Content-Type: application/json' \
      --data-binary "@$body" --output "$result" --write-out '%{http_code}' \
      "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}:setIamPolicy" || true)"
    if [ "$status" = 200 ] && jq -e --arg project "$PROJECT_ID" '
      def expected: [
        {role:"projects/\($project)/roles/cloudRunRevisionDeployer",members:["serviceAccount:gha-preview-deploy@\($project).iam.gserviceaccount.com"]},
        {role:"projects/\($project)/roles/deploymentParityCloudRunReader",members:["serviceAccount:gha-deploy-parity@\($project).iam.gserviceaccount.com"]},
        {role:"projects/\($project)/roles/previewTrafficCommitter",members:["serviceAccount:gha-preview-commit@\($project).iam.gserviceaccount.com"]}
      ] | sort_by(.role);
      ((.bindings // []) | map(.members |= sort) | sort_by(.role)) == expected
    ' "$result" >/dev/null; then return 0; fi
    # A lost synchronous setIamPolicy response remains poisoned. Re-read on the
    # next iteration and release only after the authoritative exact policy is
    # observed; never infer non-application from the transport result.
  done
  return 1
}

patch_preview_sealed() {
  local before="$1" traffic="$2" suffix="$3"
  local body="$work/${suffix}-patch.json" operation="$work/${suffix}-operation.json"
  local operation_result="$work/${suffix}-operation-result.json" after="$work/${suffix}-after.json"
  jq --slurpfile traffic "$traffic" '{
    name,etag,traffic:$traffic[0],
    ingress:"INGRESS_TRAFFIC_INTERNAL_ONLY",
    invokerIamDisabled:false
  }' "$before" > "$body"
  # Any lost response after this request leaves the GCS poison in place. Never
  # infer non-application or issue a compensating OPEN operation.
  curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
    --request PATCH --header "@$header" --header 'Content-Type: application/json' \
    --data-binary "@$body" --output "$operation" \
    "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}?updateMask=traffic,ingress,invokerIamDisabled&allowMissing=false"
  wait_operation "$operation" "$operation_result"
  fetch_preview_v2 "$after"
  jq -e --slurpfile desired "$traffic" '
    .ingress == "INGRESS_TRAFFIC_INTERNAL_ONLY" and (.invokerIamDisabled // false) == false and
    (.traffic | sort_by(.tag // "")) == ($desired[0] | sort_by(.tag // "")) and
    (.trafficStatuses | length) == ($desired[0] | length) and
    ([.trafficStatuses[]? | select((.tag // "") != "")] | length) == 0
  ' "$after" >/dev/null
  sanitize_invoker_policy
}

case "$COMMAND" in
  prepare)
    readonly PREVIEW_PARITY_ADMITTED="${PREVIEW_PARITY_ADMITTED:?}"
    [[ "$PREVIEW_PARITY_ADMITTED" == true || "$PREVIEW_PARITY_ADMITTED" == false ]]
    production_candidate=false
    if capture_candidate_production before; then production_candidate=true; fi
    if [ "$production_candidate" = true ] && [ "$PREVIEW_PARITY_ADMITTED" = true ] &&
       assert_transition_clear 2>/dev/null; then
      echo "epoch-required=false" >> "${GITHUB_OUTPUT:?}"
      exit 0
    fi
    before="$work/preview-before.json"
    desired="$work/preview-sealed-traffic.json"
    if assert_transition_clear 2>/dev/null; then
      acquire_transition
      fetch_preview_v2 "$before"
    else
      # The exact active SHA/DHI may resume its own stranded production epoch,
      # including first adoption before production changed or preview finished
      # sealing. The marker already excludes admissions; this helper's next and
      # only mutation is an atomic prune+SEALED write. Different-DHI, old-SHA,
      # preview, or otherwise unrelated poison remains nonrecoverable.
      resume_transition
      fetch_preview_v2 "$before"
    fi
    jq -e '
      ([.trafficStatuses[]? | select((.tag // "") == "" and .percent == 100)] | length) == 1 and
      ([.trafficStatuses[]? | select((.tag // "") != "") | .tag] | length) ==
        ([.trafficStatuses[]? | select((.tag // "") != "") | .tag] | unique | length)
    ' "$before" >/dev/null
    jq -e '
      .latestReadyRevision as $latest |
      [.trafficStatuses[] | select((.tag // "") == "" and .percent == 100) |
        ((.revision // "") as $revision |
          if $revision == "" then $latest else $revision end) |
        split("/")[-1] | select(test("^[a-z][a-z0-9-]{0,62}$"))] | length == 1
    ' "$before" >/dev/null
    jq '
      .latestReadyRevision as $latest |
      [.trafficStatuses[] | select((.tag // "") == "" and .percent == 100) | {
        type:"TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION",
        revision:(((.revision // "") as $revision | if $revision == "" then $latest else $revision end) | split("/")[-1]),
        percent:100
      }]
    ' "$before" > "$desired"
    current="$(jq -cS '.traffic // [] | sort_by(.tag // "")' "$before")"
    target="$(jq -cS 'sort_by(.tag // "")' "$desired")"
    exposure="$(jq -r 'if .ingress == "INGRESS_TRAFFIC_INTERNAL_ONLY" and ((.invokerIamDisabled // false) == false) then "sealed" else "other" end' "$before")"
    if [ "$current" != "$target" ] || [ "$exposure" != sealed ]; then
      patch_preview_sealed "$before" "$desired" epoch-prune
    else
      sanitize_invoker_policy
    fi
    echo "epoch-required=true" >> "${GITHUB_OUTPUT:?}"
    echo "transition-lease=$TRANSITION_LEASE_FILE" >> "$GITHUB_OUTPUT"
    ;;

  finalize)
    readonly BASELINE_REVISION="${BASELINE_REVISION:?}"
    readonly EXPECTED_BASELINE_PRODUCTION_HEAD_SHA="${EXPECTED_BASELINE_PRODUCTION_HEAD_SHA:?}"
    readonly EXPECTED_BASELINE_PRODUCTION_INDEX_IMAGE="${EXPECTED_BASELINE_PRODUCTION_INDEX_IMAGE:?}"
    readonly EXPECTED_BASELINE_PRODUCTION_RUNNABLE_IMAGE="${EXPECTED_BASELINE_PRODUCTION_RUNNABLE_IMAGE:?}"
    [[ "$BASELINE_REVISION" =~ ^[a-z][a-z0-9-]{0,62}$ ]]
    [[ "$EXPECTED_BASELINE_PRODUCTION_HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]
    [[ "$EXPECTED_BASELINE_PRODUCTION_INDEX_IMAGE" =~ ^${EXPECTED_PRODUCTION_IMAGE_NAME}@sha256:[0-9a-f]{64}$ ]]
    [[ "$EXPECTED_BASELINE_PRODUCTION_RUNNABLE_IMAGE" =~ ^${EXPECTED_PRODUCTION_IMAGE_NAME}@sha256:[0-9a-f]{64}$ ]]
    [ -f "$TRANSITION_LEASE_FILE" ] && [ ! -L "$TRANSITION_LEASE_FILE" ]
    transition_acquired=true
    capture_candidate_production final-before ||
      die "New production is not remotely proven against the candidate DHI closure."
    jq -e --arg head "$EXPECTED_BASELINE_PRODUCTION_HEAD_SHA" \
      --arg index "$EXPECTED_BASELINE_PRODUCTION_INDEX_IMAGE" \
      --arg runnable "$EXPECTED_BASELINE_PRODUCTION_RUNNABLE_IMAGE" '
      .head == $head and .index == $index and .runnable == $runnable
    ' "$work/prod-final-before-identity.json" >/dev/null ||
      die "The served production identity does not equal the workflow-deployed epoch candidate."
    before="$work/final-preview-before.json"
    desired="$work/final-baseline-traffic.json"
    fetch_preview_v2 "$before"
    jq -n --arg revision "$BASELINE_REVISION" '[{
      type:"TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION",
      revision:$revision,
      percent:100
    }]' > "$desired"
    patch_preview_sealed "$before" "$desired" baseline-swap

    service="$work/final-preview-service.json"
    revisions="$work/final-preview-revisions"
    baseline_v2="$work/final-preview-baseline-v2.json"
    preview_outputs="$work/final-preview.outputs"
    graph_outputs="$work/final-preview-graph.outputs"
    image_set="$work/final-preview-images.json"
    install -d -m 0700 "$revisions"
    gcloud --access-token-file="$token" run services describe "$PREVIEW_SERVICE" \
      --project="$PROJECT_ID" --region="$REGION" --format=json > "$service"
    gcloud --access-token-file="$token" run revisions describe "$BASELINE_REVISION" \
      --project="$PROJECT_ID" --region="$REGION" --format=json > "$revisions/${BASELINE_REVISION}.json"
    jq -e --arg head "$EXPECTED_BASELINE_PRODUCTION_HEAD_SHA" \
      --arg index "${EXPECTED_BASELINE_PRODUCTION_INDEX_IMAGE##*@}" \
      --arg runnable "$EXPECTED_BASELINE_PRODUCTION_RUNNABLE_IMAGE" '
      .metadata.labels["git-head-sha"] == $head and
      .spec.containers[0].image == $runnable and
      ([.spec.containers[0].env[]? | select(.name == "PLATFORM_IMAGE_INDEX_DIGEST") | .value] == [$index]) and
      ([.spec.containers[0].env[]? | select(.name == "PLATFORM_IMAGE_RUNNABLE_DIGEST") | .value] == [($runnable | split("@")[-1])])
    ' "$revisions/${BASELINE_REVISION}.json" >/dev/null
    curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
      --header "@$header" --output "$baseline_v2" \
      "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}/revisions/${BASELINE_REVISION}"
    jq -e --arg name "projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}/revisions/${BASELINE_REVISION}" \
      --arg runtime "$EXPECTED_PREVIEW_RUNTIME_SERVICE_ACCOUNT" \
      --slurpfile v1 "$revisions/${BASELINE_REVISION}.json" '
      .name == $name and ((.reconciling // false) == false) and .serviceAccount == $runtime and
      ((.volumes // []) | length == 0) and ((.vpcAccess // {}) == {}) and
      (.containers | length) == 1 and ((.containers[0].volumeMounts // []) | length == 0) and
      ((.containers[0].baseImageUri // "") == "") and
      .containers[0].command == ["bun"] and
      .containers[0].args == ["-e","Bun.serve({port:+process.env.PORT,fetch(){return new Response(null,{status:404})}})"] and
      ([.containers[0].env[]? | {name,value}] | sort_by(.name)) ==
        ([$v1[0].spec.containers[0].env[]? | {name,value}] | sort_by(.name)) and
      all(.containers[0].env[]?; (keys | sort) == ["name","value"]) and
      .containers[0].image == $v1[0].spec.containers[0].image and
      ([.conditions[]? | select(.type == "Ready" and .state == "CONDITION_SUCCEEDED")] | length) == 1
    ' "$baseline_v2" >/dev/null
    env GITHUB_OUTPUT="$preview_outputs" PARITY_SERVICE_JSON="$service" PARITY_REVISION_DIR="$revisions" \
      EXPECTED_PREVIEW_SERVICE_NAME="$PREVIEW_SERVICE" EXPECTED_REPOSITORY_ID="$REPOSITORY_ID" \
      "$PARITY_POLICY_ROOT/tools/ci/cloud-run-dhi-parity.sh" prove-preview-routes
    [ "$(output_value active_preview_count "$preview_outputs")" = 0 ]
    [ "$(output_value all_routes_candidate_parity "$preview_outputs")" = true ]
    jq -n --arg production "$EXPECTED_PRODUCTION_IMAGE_NAME" \
      --arg head "$(jq -er '.metadata.labels["git-head-sha"]' "$revisions/${BASELINE_REVISION}.json")" \
      --arg index "$EXPECTED_PRODUCTION_IMAGE_NAME@$(jq -er '[.spec.containers[0].env[] | select(.name == "PLATFORM_IMAGE_INDEX_DIGEST") | .value] | if length == 1 then .[0] else error("index") end' "$revisions/${BASELINE_REVISION}.json")" \
      --arg runnable "$(jq -er '.spec.containers[0].image' "$revisions/${BASELINE_REVISION}.json")" \
      '[{kind:"production",head:$head,name:$production,index:$index,runnable:$runnable}]' > "$image_set"
    env GITHUB_OUTPUT="$graph_outputs" AR_ACCESS_TOKEN="$ACCESS_TOKEN" LIVE_IMAGE_SET_FILE="$image_set" \
      "$PARITY_POLICY_ROOT/tools/ci/container-artifact-contract.sh" verify-live-images
    [ "$(output_value dhi_parity_id "$graph_outputs")" = "$DHI_PARITY_ID" ]
    capture_candidate_production final-after ||
      die "Production changed while the sanitized candidate-DHI baseline was proven."
    cmp "$work/prod-final-before-identity.json" "$work/prod-final-after-identity.json" >/dev/null &&
      cmp "$work/prod-final-before-projection.sha256" "$work/prod-final-after-projection.sha256" >/dev/null ||
      die "Production changed while the sanitized candidate-DHI baseline was proven."

    # No Cloud Run cleanup may run after GCS might already be clear.
    transition_acquired=false
    release_transition
    echo "epoch-finalized=true" >> "${GITHUB_OUTPUT:?}"
    ;;
esac
