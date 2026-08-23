#!/bin/bash
set -euo pipefail

if [ "${1:-}" != commit ] || [ "$#" -ne 1 ]; then
  echo "usage: cloud-run-preview-traffic.sh commit" >&2
  exit 64
fi

required=(
  BASELINE_REVISION
  DHI_PARITY_ID
  EXPECTED_BASELINE_PRODUCTION_HEAD_SHA
  EXPECTED_BASELINE_PRODUCTION_INDEX_IMAGE
  EXPECTED_BASELINE_PRODUCTION_RUNNABLE_IMAGE
  EXPECTED_PLATFORM_WORKFLOW_SHA
  EXPECTED_PREVIEW_IMAGE_NAME
  EXPECTED_PREVIEW_RUNTIME_SERVICE_ACCOUNT
  EXPECTED_PRODUCTION_IMAGE_NAME
  EXPECTED_PROJECT_NUMBER
  EXPECTED_REPOSITORY
  EXPECTED_REPOSITORY_ID
  EXPECTED_REVISION
  INITIAL_EXPOSURE
  PARITY_POLICY_ROOT
  PREVIEW_INGRESS
  PREVIEW_SERVICE
  PREVIEW_URL
  PR_NUMBER
  PROJECT_ID
  REGION
  SERVICE_NAME
)
for name in "${required[@]}"; do
  if [ -z "${!name:-}" ]; then
    echo "Missing required preview traffic input: $name" >&2
    exit 64
  fi
done
for identity in "$BASELINE_REVISION" "$EXPECTED_REVISION"; do
  [[ "$identity" =~ ^[a-z][a-z0-9-]{0,62}$ ]]
done
[[ "$PR_NUMBER" =~ ^[1-9][0-9]*$ ]]
[[ "$EXPECTED_REPOSITORY_ID" =~ ^(1255553151|711292980|1025243085|280932482)$ ]]
if [ "$EXPECTED_REPOSITORY_ID" = 280932482 ]; then
  test "${STABLE_PREVIEW_DOMAIN:-}" = preview.ycriticalhistory.org
else
  test -z "${STABLE_PREVIEW_DOMAIN:-}"
fi
case "$INITIAL_EXPOSURE" in open|sealed) ;; *) exit 64 ;; esac
case "$PREVIEW_INGRESS" in all|internal-and-cloud-load-balancing) ;; *) exit 64 ;; esac
test -f "$PARITY_POLICY_ROOT/tools/ci/cloud-run-dhi-parity.sh"
test -f "$PARITY_POLICY_ROOT/tools/ci/container-artifact-contract.sh"
test -x "$PARITY_POLICY_ROOT/tools/ci/deployment-parity-transition.sh"

umask 077
tag="pr-${PR_NUMBER}"
token="$RUNNER_TEMP/preview-traffic-commit-token"
header="$RUNNER_TEMP/preview-traffic-commit-header"
before_v2="$RUNNER_TEMP/preview-traffic-before-v2.json"
before_v1="$RUNNER_TEMP/preview-traffic-before-v1.json"
after_v2="$RUNNER_TEMP/preview-traffic-after-v2.json"
after_v1="$RUNNER_TEMP/preview-traffic-after-v1.json"
desired="$RUNNER_TEMP/preview-traffic-desired.json"
desired_normalized="$RUNNER_TEMP/preview-traffic-desired.normalized.json"
prior="$RUNNER_TEMP/preview-traffic-prior.json"
prior_normalized="$RUNNER_TEMP/preview-traffic-prior.normalized.json"
patch_body="$RUNNER_TEMP/preview-traffic-patch.json"
operation="$RUNNER_TEMP/preview-traffic-operation.json"
operation_result="$RUNNER_TEMP/preview-traffic-operation-result.json"
rollback_operation="$RUNNER_TEMP/preview-traffic-rollback-operation.json"
rollback_result="$RUNNER_TEMP/preview-traffic-rollback-result.json"
rollback_file="$RUNNER_TEMP/preview-traffic-rollback.json"
transition_lease="$RUNNER_TEMP/preview-traffic-transition-lease.json"
patched=false
ambiguous_commit=false
force_seal_on_rollback=false
seal_on_failure=false
transition_acquired=false
unsafe_request_sent=false
effective_exposure="$INITIAL_EXPOSURE"
rollback_exposure="$INITIAL_EXPOSURE"

acquire_transition() {
  local kind="$1"
  env ACCESS_TOKEN="$(<"$token")" PROJECT_ID="$PROJECT_ID" REPOSITORY_ID="$EXPECTED_REPOSITORY_ID" \
    EXPECTED_PLATFORM_WORKFLOW_SHA="$EXPECTED_PLATFORM_WORKFLOW_SHA" DHI_PARITY_ID="$DHI_PARITY_ID" \
    TRANSITION_KIND="$kind" TRANSITION_LEASE_FILE="$transition_lease" \
    "$PARITY_POLICY_ROOT/tools/ci/deployment-parity-transition.sh" acquire
  transition_acquired=true
}

release_transition() {
  env ACCESS_TOKEN="$(<"$token")" PROJECT_ID="$PROJECT_ID" REPOSITORY_ID="$EXPECTED_REPOSITORY_ID" \
    TRANSITION_LEASE_FILE="$transition_lease" \
    "$PARITY_POLICY_ROOT/tools/ci/deployment-parity-transition.sh" release
}

fetch_v2_raw() {
  local destination="$1"
  curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
    --header "@$header" --output "$destination" \
    "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}"
}

fetch_v2() {
  local destination="$1"
  for attempt in $(seq 1 60); do
    if fetch_v2_raw "$destination" && jq -e '
    (.etag | type == "string" and length > 0 and length <= 1024 and (test("[[:cntrl:]]") | not)) and
    (.generation == .observedGeneration) and
    ((.reconciling // false) == false) and
    .terminalCondition.type == "Ready" and .terminalCondition.state == "CONDITION_SUCCEEDED" and
    ((.buildConfig // {}) == {}) and
    all(.template.containers[]?; ((.baseImageUri // "") == ""))
    ' "$destination" >/dev/null; then
      return 0
    fi
    [ "$attempt" -eq 60 ] || sleep 2
  done
  return 1
}

assert_exposure() {
  local service_json="$1" exposure="$2" expected
  case "$PREVIEW_INGRESS" in
    all) expected=INGRESS_TRAFFIC_ALL ;;
    internal-and-cloud-load-balancing) expected=INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER ;;
    *) return 1 ;;
  esac
  if [ "$exposure" = open ]; then
    jq -e --arg ingress "$expected" '
      (.reconciling // false) == false and .ingress == $ingress and
      .invokerIamDisabled == true and (.defaultUriDisabled // false) == false
    ' "$service_json" >/dev/null
  else
    jq -e '
      (.reconciling // false) == false and .ingress == "INGRESS_TRAFFIC_INTERNAL_ONLY" and
      (.invokerIamDisabled // false) == false and (.defaultUriDisabled // false) == false
    ' "$service_json" >/dev/null
  fi
}

normalize_traffic() {
  jq -cS '
    [.[]? | {
      type,
      revision:((.revision // null) | if . == null then null else split("/")[-1] end),
      percent:(.percent // 0),
      tag:(.tag // null)
    }] | sort_by(.tag // "")
  ' "$1"
}

wait_operation() {
  local response="$1" destination="$2" operation_name
  operation_name="$(jq -er '.name | select(test("^projects/[^/]+/locations/[a-z0-9-]+/operations/[A-Za-z0-9_-]+$"))' "$response")"
  for attempt in $(seq 1 60); do
    curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
      --header "@$header" --output "$destination" \
      "https://run.googleapis.com/v2/${operation_name}"
    if jq -e '.done == true' "$destination" >/dev/null; then
      jq -e --arg service "projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}" '
        (has("error") | not) and .response.name == $service
      ' "$destination" >/dev/null
      return 0
    fi
    [ "$attempt" -eq 60 ] || sleep 2
  done
  return 1
}

seal_fail_closed() {
  local seal_body="$RUNNER_TEMP/preview-traffic-seal.json"
  local seal_operation="$RUNNER_TEMP/preview-traffic-seal-operation.json"
  local seal_result="$RUNNER_TEMP/preview-traffic-seal-result.json"
  [ "$transition_acquired" = true ] || return 1
  fetch_v2 "$after_v2" || return 1
  if assert_exposure "$after_v2" sealed >/dev/null 2>&1; then
    sanitize_invoker_policy
    return
  fi
  jq '{name,etag,ingress:"INGRESS_TRAFFIC_INTERNAL_ONLY",invokerIamDisabled:false}' "$after_v2" > "$seal_body"
  # If either response is lost, the durable poison remains. No timed read or
  # later operation is used to infer a safe outcome.
  curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
    --request PATCH --header "@$header" --header 'Content-Type: application/json' \
    --data-binary "@$seal_body" --output "$seal_operation" \
    "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}?updateMask=ingress,invokerIamDisabled&allowMissing=false" || return 1
  wait_operation "$seal_operation" "$seal_result" || return 1
  fetch_v2 "$after_v2" && assert_exposure "$after_v2" sealed && sanitize_invoker_policy
}

rollback_exact_traffic_once() {
  local current_normalized="$RUNNER_TEMP/preview-traffic-current.normalized.json"
  local restored_normalized="$RUNNER_TEMP/preview-traffic-restored.normalized.json"
  local current_exposure target_rollback_exposure rollback_ingress rollback_invoker
  fetch_v2 "$after_v2" || return 1
  if assert_exposure "$after_v2" open >/dev/null 2>&1; then
    current_exposure=open
  elif assert_exposure "$after_v2" sealed >/dev/null 2>&1; then
    current_exposure=sealed
  else
    return 1
  fi
  jq '.traffic // []' "$after_v2" > "$RUNNER_TEMP/preview-traffic-current.json"
  normalize_traffic "$RUNNER_TEMP/preview-traffic-current.json" > "$current_normalized"
  if cmp "$current_normalized" "$prior_normalized" >/dev/null; then
    if [ "$force_seal_on_rollback" = true ]; then
      [ "$current_exposure" = sealed ] || seal_fail_closed
    else
      [ "$current_exposure" = "$rollback_exposure" ] || [ "$current_exposure" = sealed ]
    fi
    return
  fi
  cmp "$current_normalized" "$desired_normalized" >/dev/null || return 1
  if [ "$force_seal_on_rollback" = true ] || [ "$current_exposure" = sealed ] || [ "$rollback_exposure" = sealed ]; then
    target_rollback_exposure=sealed
    rollback_ingress=INGRESS_TRAFFIC_INTERNAL_ONLY
    rollback_invoker=false
  else
    target_rollback_exposure="$rollback_exposure"
    case "$PREVIEW_INGRESS" in
      all) rollback_ingress=INGRESS_TRAFFIC_ALL ;;
      internal-and-cloud-load-balancing) rollback_ingress=INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER ;;
      *) return 1 ;;
    esac
    rollback_invoker=true
  fi
  jq --arg ingress "$rollback_ingress" --argjson invoker "$rollback_invoker" --slurpfile prior "$prior" '{
    name:.name,etag:.etag,traffic:$prior[0],ingress:$ingress,invokerIamDisabled:$invoker
  }' "$after_v2" > "$patch_body"
  rollback_update_mask=traffic,ingress,invokerIamDisabled
  curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
    --request PATCH --header "@$header" --header 'Content-Type: application/json' \
    --data-binary "@$patch_body" --output "$rollback_operation" \
    "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}?updateMask=${rollback_update_mask}&allowMissing=false"
  wait_operation "$rollback_operation" "$rollback_result"
  fetch_v2 "$after_v2"
  jq '.traffic // []' "$after_v2" > "$RUNNER_TEMP/preview-traffic-restored.json"
  normalize_traffic "$RUNNER_TEMP/preview-traffic-restored.json" > "$restored_normalized"
  cmp "$restored_normalized" "$prior_normalized" >/dev/null
  assert_exposure "$after_v2" "$target_rollback_exposure"
}

rollback_exact_traffic() {
  [ "$ambiguous_commit" != true ] || return 1
  rollback_exact_traffic_once
}

cleanup() {
  status=$?
  set +e
  if [ "$status" -ne 0 ] && [ "$transition_acquired" = true ]; then
    if [ "$unsafe_request_sent" = true ] && [ "$ambiguous_commit" = true ]; then
      echo "CRITICAL: preview mutation outcome is ambiguous; retaining the durable parity poison and refusing inference or follow-up mutation." >&2
    elif [ "$patched" = true ]; then
      if ! rollback_exact_traffic; then
        echo "CRITICAL: exact preview rollback was not proven; retaining the durable parity poison for manual recovery." >&2
      elif [ "$force_seal_on_rollback" = true ]; then
        echo "Production changed across preview admission; attempting a sealed recovery while retaining the durable poison." >&2
        seal_fail_closed || echo "CRITICAL: failed to prove sealing after production changed; durable poison retained." >&2
      fi
    else
      echo "Preview admission failed after acquiring the durable marker but before unsafe mutation; poison retained for explicit recovery." >&2
    fi
  elif [ "$status" -ne 0 ] && [ "$seal_on_failure" = true ]; then
    # The workflow's independent fail-closed controller acquires its own durable
    # marker. This transaction must not mutate Cloud Run without one.
    echo "Preview admission evidence failed before the durable transition marker was acquired; no Cloud Run mutation was attempted here." >&2
  fi
  rm -f -- "$token" "$header" "$before_v2" "$before_v1" "$after_v2" "$after_v1" \
    "$desired" "$desired_normalized" "$prior" "$prior_normalized" "$patch_body" \
    "$operation" "$operation_result" \
    "$rollback_operation" "$rollback_result"
  find "$RUNNER_TEMP" -mindepth 1 -maxdepth 1 -type f \
    \( -name 'preview-traffic-*.projection' -o -name 'preview-traffic-*.normalized.json' \
       -o -name 'preview-traffic-*.sha256' -o -name 'preview-traffic-snapshot-*.json' \
       -o -name 'preview-traffic-pr-*.json' -o -name 'preview-traffic-production-*' \
       -o -name 'preview-traffic-invoker-*' \) -delete
  find "$RUNNER_TEMP" -mindepth 1 -maxdepth 1 -type d -name 'preview-traffic-revisions-*' \
    -exec sh -c 'for directory do find "$directory" -depth -delete; done' sh {} +
  if [ "$status" -ne 0 ]; then
    rm -f -- "$rollback_file"
    if [[ "${CREDENTIAL_FILE:-}" == "$GITHUB_WORKSPACE"/* ]]; then
      rm -f -- "$CREDENTIAL_FILE"
    fi
  fi
  trap - EXIT
  exit "$status"
}
trap cleanup EXIT

gcloud auth print-access-token > "$token"
printf 'Authorization: Bearer %s\n' "$(<"$token")" > "$header"

fetch_invoker_policy() {
  local destination="$1"
  curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
    --header "@$header" --output "$destination" \
    "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}:getIamPolicy?options.requestedPolicyVersion=3"
  jq -e '
    ((.version // 1) | type == "number" and . >= 1 and . <= 3) and
    (.etag | type == "string" and length > 0 and length <= 1024 and (test("[[:cntrl:]]") | not)) and
    ((.bindings // []) | type == "array")
  ' "$destination" >/dev/null
}

assert_exact_preview_policy() {
  jq -e --arg project "$PROJECT_ID" '
    def expected: [
      {role:"projects/\($project)/roles/cloudRunRevisionDeployer",members:["serviceAccount:gha-preview-deploy@\($project).iam.gserviceaccount.com"]},
      {role:"projects/\($project)/roles/deploymentParityCloudRunReader",members:["serviceAccount:gha-deploy-parity@\($project).iam.gserviceaccount.com"]},
      {role:"projects/\($project)/roles/previewTrafficCommitter",members:["serviceAccount:gha-preview-commit@\($project).iam.gserviceaccount.com"]}
    ] | sort_by(.role);
    ((.bindings // []) | map(.members |= sort) | sort_by(.role)) == expected
  ' "$1" >/dev/null
}

sanitize_invoker_policy() {
  local policy="$RUNNER_TEMP/preview-traffic-invoker-policy.json"
  local body="$RUNNER_TEMP/preview-traffic-invoker-policy-body.json"
  local result="$RUNNER_TEMP/preview-traffic-invoker-policy-result.json" status
  for attempt in $(seq 1 5); do
    fetch_invoker_policy "$policy" || return 1
    if assert_exact_preview_policy "$policy"; then return 0; fi
    jq --arg project "$PROJECT_ID" '{policy:(. | .bindings = [
      {role:"projects/\($project)/roles/cloudRunRevisionDeployer",members:["serviceAccount:gha-preview-deploy@\($project).iam.gserviceaccount.com"]},
      {role:"projects/\($project)/roles/deploymentParityCloudRunReader",members:["serviceAccount:gha-deploy-parity@\($project).iam.gserviceaccount.com"]},
      {role:"projects/\($project)/roles/previewTrafficCommitter",members:["serviceAccount:gha-preview-commit@\($project).iam.gserviceaccount.com"]}
    ]),updateMask:"bindings,etag"}' "$policy" > "$body"
    set +e
    status="$(curl --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
      --request POST --header "@$header" --header 'Content-Type: application/json' \
      --data-binary "@$body" --output "$result" --write-out '%{http_code}' \
      "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}:setIamPolicy")"
    set -e
    if [ "$status" = 200 ]; then assert_exact_preview_policy "$result" && return 0; fi
    # A lost response is not evidence of non-application. Re-read and keep the
    # durable marker until the exact authoritative policy is observed.
  done
  return 1
}

output_value() {
  sed -n "s/^$1=//p" "$2" | tail -n 1
}

capture_production() {
  local suffix="$1" verify_graph="$2"
  local service="$RUNNER_TEMP/preview-traffic-production-${suffix}-service.json"
  local revision="$RUNNER_TEMP/preview-traffic-production-${suffix}-revision.json"
  local service_v2="$RUNNER_TEMP/preview-traffic-production-${suffix}-service-v2.json"
  local revision_v2="$RUNNER_TEMP/preview-traffic-production-${suffix}-revision-v2.json"
  local outputs="$RUNNER_TEMP/preview-traffic-production-${suffix}.outputs"
  local graph_outputs="$RUNNER_TEMP/preview-traffic-production-${suffix}-graph.outputs"
  local revision_name live_head live_index live_runnable
  gcloud run services describe "$SERVICE_NAME" \
    --project="$PROJECT_ID" --region="$REGION" --format=json > "$service"
  revision_name="$(jq -er '.status.latestReadyRevisionName | select(test("^[a-z][a-z0-9-]{0,62}$"))' "$service")"
  gcloud run revisions describe "$revision_name" \
    --project="$PROJECT_ID" --region="$REGION" --format=json > "$revision"
  env GITHUB_OUTPUT="$outputs" PARITY_SERVICE_JSON="$service" PARITY_REVISION_JSON="$revision" \
    EXPECTED_SERVICE_NAME="$SERVICE_NAME" EXPECTED_PROJECT_NUMBER="$EXPECTED_PROJECT_NUMBER" \
    EXPECTED_REPOSITORY_ID="$EXPECTED_REPOSITORY_ID" EXPECTED_PRODUCTION_IMAGE_NAME="$EXPECTED_PRODUCTION_IMAGE_NAME" \
    "$PARITY_POLICY_ROOT/tools/ci/cloud-run-dhi-parity.sh" prove-production
  live_head="$(output_value live_production_head_sha "$outputs")"
  live_index="$(output_value live_production_index_image "$outputs")"
  live_runnable="$(output_value live_production_runnable_image "$outputs")"
  if [ "$live_head" != "$EXPECTED_BASELINE_PRODUCTION_HEAD_SHA" ] ||
     [ "$live_index" != "$EXPECTED_BASELINE_PRODUCTION_INDEX_IMAGE" ] ||
     [ "$live_runnable" != "$EXPECTED_BASELINE_PRODUCTION_RUNNABLE_IMAGE" ]; then
    echo "Currently served production no longer matches the preview admission baseline." >&2
    if [ "$patched" = true ]; then
      # The EXIT transaction must first restore the exact prior traffic graph;
      # it then seals that restored graph so stale-lineage routes are not public.
      force_seal_on_rollback=true
    elif [ "$transition_acquired" = true ]; then
      seal_fail_closed || echo "CRITICAL: failed to seal previews after production identity changed." >&2
    fi
    return 1
  fi
  curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
    --header "@$header" --output "$service_v2" \
    "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${SERVICE_NAME}"
  curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
    --header "@$header" --output "$revision_v2" \
    "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${SERVICE_NAME}/revisions/${revision_name}"
  jq -e --arg name "projects/${PROJECT_ID}/locations/${REGION}/services/${SERVICE_NAME}" --arg revision "$revision_name" '
    .name == $name and
    (.generation == .observedGeneration) and ((.reconciling // false) == false) and
    .terminalCondition.type == "Ready" and .terminalCondition.state == "CONDITION_SUCCEEDED" and
    ((.buildConfig // {}) == {}) and all(.template.containers[]?; ((.baseImageUri // "") == "")) and
    .ingress == "INGRESS_TRAFFIC_ALL" and .invokerIamDisabled == true and
    ((.defaultUriDisabled // false) == false) and
    (.latestReadyRevision | split("/")[-1]) == $revision and
    (.traffic | length) == 1 and .traffic[0].type == "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST" and
    .traffic[0].percent == 100 and ((.traffic[0].tag // "") == "") and ((.traffic[0].revision // "") == "") and
    (.trafficStatuses | length) == 1 and .trafficStatuses[0].type == "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST" and
    .trafficStatuses[0].percent == 100 and ((.trafficStatuses[0].tag // "") == "") and
    ((.trafficStatuses[0].revision // "") == "")
  ' "$service_v2" >/dev/null
  jq -e --arg name "projects/${PROJECT_ID}/locations/${REGION}/services/${SERVICE_NAME}/revisions/${revision_name}" \
    --arg image "$live_runnable" --arg index "${live_index##*@}" --arg runnable "${live_runnable##*@}" '
    def exact_value($name):
      [.containers[0].env[]? | select(.name == $name and (keys | sort) == ["name","value"]) | .value]
      | if length == 1 then .[0] else error("invalid immutable production image identity") end;
    .name == $name and ((.reconciling // false) == false) and
    (.containers | length) == 1 and .containers[0].image == $image and
    ((.containers[0].baseImageUri // "") == "") and
    exact_value("PLATFORM_IMAGE_INDEX_DIGEST") == $index and
    exact_value("PLATFORM_IMAGE_RUNNABLE_DIGEST") == $runnable and
    ([.conditions[]? | select(.type == "Ready" and .state == "CONDITION_SUCCEEDED")] | length) == 1
  ' "$revision_v2" >/dev/null
  if [ "$verify_graph" = true ]; then
    env GITHUB_OUTPUT="$graph_outputs" AR_ACCESS_TOKEN="$(<"$token")" \
      LIVE_PRODUCTION_HEAD_SHA="$live_head" LIVE_PRODUCTION_INDEX_IMAGE="$live_index" \
      LIVE_PRODUCTION_RUNNABLE_IMAGE="$live_runnable" EXPECTED_PRODUCTION_IMAGE_NAME="$EXPECTED_PRODUCTION_IMAGE_NAME" \
      "$PARITY_POLICY_ROOT/tools/ci/container-artifact-contract.sh" verify-live-production
    [ "$(output_value dhi_parity_id "$graph_outputs")" = "$DHI_PARITY_ID" ]
  fi
  {
    jq -cS '.' "$service" "$revision"
    jq -cS '{name,generation,observedGeneration,etag,ingress,invokerIamDisabled,defaultUriDisabled,traffic,trafficStatuses,latestReadyRevision,reconciling,terminalCondition,urls,uri,template,buildConfig}' "$service_v2"
    jq -cS '{name,generation,labels,serviceAccount,containers,reconciling,conditions,etag}' "$revision_v2"
    LC_ALL=C sort "$outputs"
  } | sha256sum | cut -d ' ' -f 1 > "$RUNNER_TEMP/preview-traffic-production-${suffix}.sha256"
}

capture_snapshot() {
  local suffix="$1" graph="$2"
  local live_service="$RUNNER_TEMP/preview-traffic-snapshot-${suffix}-live.json"
  local service="$RUNNER_TEMP/preview-traffic-snapshot-${suffix}-proposed.json"
  local service_v2="$RUNNER_TEMP/preview-traffic-snapshot-${suffix}-v2.json"
  local revisions="$RUNNER_TEMP/preview-traffic-revisions-${suffix}"
  local revisions_v2="$RUNNER_TEMP/preview-traffic-revisions-${suffix}-v2"
  local outputs="$RUNNER_TEMP/preview-traffic-snapshot-${suffix}.outputs"
  local policy="$RUNNER_TEMP/preview-traffic-snapshot-${suffix}-invoker-policy.json"
  local image_set="$RUNNER_TEMP/preview-traffic-snapshot-${suffix}-images.json"
  local graph_outputs="$RUNNER_TEMP/preview-traffic-snapshot-${suffix}-graphs.outputs"
  local revision live_pr live_revision live_head pr_state
  local -a revision_files revision_v2_files projection_files
  install -d -m 0700 "$revisions" "$revisions_v2"
  gcloud run services describe "$PREVIEW_SERVICE" \
    --project="$PROJECT_ID" --region="$REGION" --format=json > "$live_service"
  fetch_v2 "$service_v2"
  assert_exposure "$service_v2" "$effective_exposure"
  fetch_invoker_policy "$policy"
  assert_exact_preview_policy "$policy"
  jq '.traffic // []' "$service_v2" > "$RUNNER_TEMP/preview-traffic-${suffix}-live.json"
  normalize_traffic "$RUNNER_TEMP/preview-traffic-${suffix}-live.json" > "$RUNNER_TEMP/preview-traffic-${suffix}-live.normalized.json"
  cmp "$RUNNER_TEMP/preview-traffic-${suffix}-live.normalized.json" "$expected_live_normalized" >/dev/null
  jq --slurpfile desired "$desired" '
    .spec.traffic = [$desired[0][] | {
      revisionName:(.revision | split("/")[-1]),
      latestRevision:false,
      percent:(.percent // 0)
    } + (if .tag == null then {} else {tag:.tag} end)] |
    .status.traffic = [$desired[0][] | {
      revisionName:(.revision | split("/")[-1]),
      latestRevision:false,
      percent:(.percent // 0)
    } + (if .tag == null then {} else {tag:.tag} end)]
  ' "$live_service" > "$service"
  while IFS= read -r revision; do
    [[ "$revision" =~ ^[a-z][a-z0-9-]{0,62}$ ]]
    gcloud run revisions describe "$revision" \
      --project="$PROJECT_ID" --region="$REGION" --format=json > "$revisions/${revision}.json"
    curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
      --header "@$header" --output "$revisions_v2/${revision}.json" \
      "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}/revisions/${revision}"
    jq -e --arg name "projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}/revisions/${revision}" \
      --arg runtime "$EXPECTED_PREVIEW_RUNTIME_SERVICE_ACCOUNT" --slurpfile v1 "$revisions/${revision}.json" '
      .name == $name and (.reconciling // false) == false and .serviceAccount == $runtime and
      ((.volumes // []) | length) == 0 and ((.vpcAccess // {}) == {}) and
      (.containers | length) == 1 and ((.containers[0].volumeMounts // []) | length) == 0 and
      ((.containers[0].baseImageUri // "") == "") and
      all(.containers[0].env[]?; (keys | sort) == ["name","value"]) and
      .containers[0].image == $v1[0].spec.containers[0].image and
      ((.containers[0].command // []) == ($v1[0].spec.containers[0].command // [])) and
      ((.containers[0].args // []) == ($v1[0].spec.containers[0].args // [])) and
      ([.containers[0].env[]? | {name,value}] | sort_by(.name)) ==
        ([$v1[0].spec.containers[0].env[]? | {name,value}] | sort_by(.name)) and
      ([.conditions[]? | select(.type == "Ready" and .state == "CONDITION_SUCCEEDED")] | length) == 1
    ' "$revisions_v2/${revision}.json" >/dev/null
  done < <(jq -r '.status.traffic[]?.revisionName' "$service" | sort -u)
  jq -cS '[.status.traffic[]? | {percent,revisionName,tag:(.tag // null)}] | sort_by(.tag // "")' "$live_service" > "$RUNNER_TEMP/preview-traffic-${suffix}-v1.projection"
  jq -cS '[.trafficStatuses[]? | {percent,revisionName:(.revision | split("/")[-1]),tag:(.tag // null)}] | sort_by(.tag // "")' "$service_v2" > "$RUNNER_TEMP/preview-traffic-${suffix}-v2.projection"
  cmp "$RUNNER_TEMP/preview-traffic-${suffix}-v1.projection" "$RUNNER_TEMP/preview-traffic-${suffix}-v2.projection" >/dev/null
  GITHUB_OUTPUT="$outputs" PARITY_SERVICE_JSON="$service" PARITY_REVISION_DIR="$revisions" \
    "$PARITY_POLICY_ROOT/tools/ci/cloud-run-dhi-parity.sh" prove-preview-routes
  [ "$(sed -n 's/^all_routes_candidate_parity=//p' "$outputs" | tail -n 1)" = true ]
  revision_files=("$revisions"/*.json)
  revision_v2_files=("$revisions_v2"/*.json)
  [ -f "${revision_files[0]}" ] && [ -f "${revision_v2_files[0]}" ]
  projection_files=("${revision_files[@]}" "${revision_v2_files[@]}")
  if [ "$graph" = true ]; then
    jq -s --arg preview "$EXPECTED_PREVIEW_IMAGE_NAME" --arg production "$EXPECTED_PRODUCTION_IMAGE_NAME" '[.[] | {
      head:.metadata.labels["git-head-sha"],
      index:((if .metadata.labels["preview-role"] == "baseline" then $production else $preview end) + "@" +
        ([.spec.containers[0].env[]? | select(.name == "PLATFORM_IMAGE_INDEX_DIGEST") | .value] | if length == 1 then .[0] else error("invalid index binding") end)),
      kind:(if .metadata.labels["preview-role"] == "baseline" then "production" else "preview" end),
      name:(if .metadata.labels["preview-role"] == "baseline" then $production else $preview end),
      runnable:.spec.containers[0].image
    }]' "${revision_files[@]}" > "$image_set"
    GITHUB_OUTPUT="$graph_outputs" AR_ACCESS_TOKEN="$(<"$token")" LIVE_IMAGE_SET_FILE="$image_set" \
      "$PARITY_POLICY_ROOT/tools/ci/container-artifact-contract.sh" verify-live-images
    [ "$(sed -n 's/^dhi_parity_id=//p' "$graph_outputs" | tail -n 1)" = "$DHI_PARITY_ID" ]
  fi
  while IFS=$'\t' read -r live_pr live_revision; do
    live_head="$(jq -er '.metadata.labels["git-head-sha"]' "$revisions/${live_revision}.json")"
    pr_state="$RUNNER_TEMP/preview-traffic-pr-${live_pr}.json"
    gh api "repos/${GITHUB_REPOSITORY}/pulls/${live_pr}" > "$pr_state"
    jq -e --arg head "$live_head" --arg repository "$EXPECTED_REPOSITORY" --arg repository_id "$EXPECTED_REPOSITORY_ID" '
      .state == "open" and .draft == false and .head.sha == $head and
      (.head.repo.id | tostring) == $repository_id and .head.repo.full_name == $repository and
      .base.ref == "main"
    ' "$pr_state" >/dev/null
  done < <(jq -r '.status.traffic[]? | select((.tag // "") | test("^pr-[1-9][0-9]*$")) | [(.tag | sub("^pr-"; "")), .revisionName] | @tsv' "$service")
  # Keep two projections. The full projection brackets the final etag before
  # each CAS mutation. The route projection intentionally excludes only
  # exposure/generation fields that change during the reviewed SEALED->OPEN
  # PATCH, while retaining the exact traffic and revision graph.
  {
    jq -cS '{metadata:{name:.metadata.name,namespace:.metadata.namespace,generation:.metadata.generation,annotations:.metadata.annotations,labels:.metadata.labels},spec:.spec,status:{observedGeneration:.status.observedGeneration,traffic:.status.traffic,latestCreatedRevisionName:.status.latestCreatedRevisionName,latestReadyRevisionName:.status.latestReadyRevisionName,conditions:.status.conditions}}' "$live_service"
    jq -cS '{specTraffic:.spec.traffic,statusTraffic:.status.traffic}' "$service"
    jq -cS '{name,generation,observedGeneration,etag,ingress,invokerIamDisabled,defaultUriDisabled,traffic,trafficStatuses,latestReadyRevision,reconciling,terminalCondition,urls,uri,template}' "$service_v2"
    jq -cS '.' "$policy"
    jq -cS '.' "${projection_files[@]}"
  } | sha256sum | cut -d ' ' -f 1 > "$RUNNER_TEMP/preview-traffic-${suffix}-full.sha256"
  {
    jq -cS '{metadata:{name:.metadata.name,namespace:.metadata.namespace},specTraffic:.spec.traffic,status:{traffic:.status.traffic,latestCreatedRevisionName:.status.latestCreatedRevisionName,latestReadyRevisionName:.status.latestReadyRevisionName}}' "$live_service"
    jq -cS '{specTraffic:.spec.traffic,statusTraffic:.status.traffic}' "$service"
    jq -cS '{name,traffic,trafficStatuses,latestReadyRevision}' "$service_v2"
    jq -cS '.' "${projection_files[@]}"
  } | sha256sum | cut -d ' ' -f 1 > "$RUNNER_TEMP/preview-traffic-${suffix}-routes.sha256"
}

gcloud run services describe "$PREVIEW_SERVICE" \
  --project="$PROJECT_ID" --region="$REGION" --format=json > "$before_v1"
fetch_v2 "$before_v2"
assert_exposure "$before_v2" "$effective_exposure"
if [ "$effective_exposure" = open ]; then
  jq -e '
    (.traffic | length) >= 1 and
    all(.traffic[]?;
      .type == "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION" and
      (.revision | type == "string") and (.revision | split("/")[-1] | test("^[a-z][a-z0-9-]{0,62}$")))
  ' "$before_v2" >/dev/null
else
  jq -e '
    all(.traffic[]?;
      .type == "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION" and
      (.revision | type == "string") and (.revision | split("/")[-1] | test("^[a-z][a-z0-9-]{0,62}$")))
  ' "$before_v2" >/dev/null
fi
tag_count="$(jq -r '[.status.traffic[]? | select((.tag // "") != "")] | length' "$before_v1")"
if [ "$tag_count" -eq 0 ] && [ "$effective_exposure" = open ]; then
  gcloud run services update "$PREVIEW_SERVICE" \
    --project="$PROJECT_ID" --region="$REGION" \
    --ingress=internal --invoker-iam-check --quiet
  effective_exposure=sealed
  rollback_exposure=sealed
  fetch_v2 "$before_v2"
  assert_exposure "$before_v2" sealed
  gcloud run services describe "$PREVIEW_SERVICE" \
    --project="$PROJECT_ID" --region="$REGION" --format=json > "$before_v1"
fi

jq -e --arg baseline "$BASELINE_REVISION" --arg candidate "$EXPECTED_REVISION" '
  [.traffic[]? | select((((.revision // "") | split("/")[-1]) == $baseline) or (((.revision // "") | split("/")[-1]) == $candidate))] | length == 0
' "$before_v2" >/dev/null
jq '.traffic // []' "$before_v2" > "$prior"
normalize_traffic "$prior" > "$prior_normalized"
jq --arg baseline "$BASELINE_REVISION" --arg candidate "$EXPECTED_REVISION" --arg tag "$tag" '
  ([.traffic[]? | select((.tag // "") != "" and .tag != $tag) | {
    type:"TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION",
    revision:(.revision | split("/")[-1]),
    percent:0,
    tag:.tag
  }] + [
    {type:"TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION",revision:$baseline,percent:100},
    {type:"TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION",revision:$candidate,percent:0,tag:$tag}
  ]) | sort_by(.tag // "")
' "$before_v2" > "$desired"
normalize_traffic "$desired" > "$desired_normalized"
expected_live_normalized="$prior_normalized"

# Prove the complete proposed graph, including both currently unrouted
# revisions, and bracket the remote OCI/lifecycle reads with an identical
# second control-plane projection before using a fresh service etag.
seal_on_failure=true
capture_snapshot before true
capture_snapshot after false
if ! cmp "$RUNNER_TEMP/preview-traffic-before-full.sha256" "$RUNNER_TEMP/preview-traffic-after-full.sha256" >/dev/null; then
  echo "Proposed preview graph or lifecycle changed during remote OCI verification." >&2
  exit 1
fi

# Acquire the independent, strongly consistent GCS metadata poison before any
# traffic/exposure PATCH. A response-lost Cloud Run operation can never be
# inferred safe: the marker remains non-clear and blocks both preview admission
# and DHI epoch transitions until explicit recovery.
acquire_transition preview-admission
capture_snapshot marker false
cmp "$RUNNER_TEMP/preview-traffic-after-full.sha256" \
  "$RUNNER_TEMP/preview-traffic-marker-full.sha256" >/dev/null || {
  echo "Preview graph changed while the durable transition marker was acquired." >&2
  exit 1
}
capture_production before true
capture_production pre-cas false
cmp "$RUNNER_TEMP/preview-traffic-production-before.sha256" \
  "$RUNNER_TEMP/preview-traffic-production-pre-cas.sha256" >/dev/null || {
  echo "Production changed while its remote OCI graph was being re-proven under the durable preview marker." >&2
  exit 1
}
cp -- "$RUNNER_TEMP/preview-traffic-snapshot-marker-v2.json" "$before_v2"
assert_exposure "$before_v2" "$effective_exposure"
# Every traffic write is atomically SEALED, including an already-SEALED
# service. A delayed response-lost write therefore cannot restore an old route
# graph under a later OPEN exposure. Reopening is a separate proven operation
# while the durable marker remains owned.
jq --slurpfile traffic "$desired" '{
  name:.name,
  etag:.etag,
  traffic:$traffic[0],
  ingress:"INGRESS_TRAFFIC_INTERNAL_ONLY",
  invokerIamDisabled:false
}' "$before_v2" > "$patch_body"
commit_update_mask=traffic,ingress,invokerIamDisabled
jq -n --arg exposure "$rollback_exposure" --slurpfile traffic "$prior" \
  --slurpfile committed "$desired" \
  '{exposure:$exposure,traffic:$traffic[0],committedTraffic:$committed[0]}' > "$rollback_file"

patched=true
ambiguous_commit=true
unsafe_request_sent=true
curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
  --request PATCH --header "@$header" --header 'Content-Type: application/json' \
  --data-binary "@$patch_body" --output "$operation" \
  "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}?updateMask=${commit_update_mask}&allowMissing=false"
wait_operation "$operation" "$operation_result"
ambiguous_commit=false
effective_exposure=sealed
capture_production post-cas false
if ! cmp "$RUNNER_TEMP/preview-traffic-production-pre-cas.sha256" \
  "$RUNNER_TEMP/preview-traffic-production-post-cas.sha256" >/dev/null; then
  force_seal_on_rollback=true
  echo "Production changed across preview traffic commit." >&2
  exit 1
fi
fetch_v2 "$after_v2"
jq '.traffic // []' "$after_v2" > "$RUNNER_TEMP/preview-traffic-committed.json"
normalize_traffic "$RUNNER_TEMP/preview-traffic-committed.json" > "$RUNNER_TEMP/preview-traffic-committed.normalized.json"
cmp "$RUNNER_TEMP/preview-traffic-committed.normalized.json" "$desired_normalized" >/dev/null
assert_exposure "$after_v2" "$effective_exposure"

expected_live_normalized="$desired_normalized"
capture_snapshot sealed-admitted true
capture_snapshot sealed-admitted-after false
if ! cmp "$RUNNER_TEMP/preview-traffic-sealed-admitted-full.sha256" "$RUNNER_TEMP/preview-traffic-sealed-admitted-after-full.sha256" >/dev/null; then
  echo "Committed preview graph or lifecycle changed during post-commit verification." >&2
  exit 1
fi

# Re-prove production immediately before the exposure-only CAS, then keep the
# durable marker until the OPEN LRO, all route health, lifecycle, and final
# production proofs complete.
capture_production pre-open false
cmp "$RUNNER_TEMP/preview-traffic-production-post-cas.sha256" \
  "$RUNNER_TEMP/preview-traffic-production-pre-open.sha256" >/dev/null || {
  force_seal_on_rollback=true
  echo "Production changed before preview exposure was opened." >&2
  exit 1
}
fetch_v2 "$after_v2"
assert_exposure "$after_v2" sealed
jq '.traffic // []' "$after_v2" > "$RUNNER_TEMP/preview-traffic-open.json"
normalize_traffic "$RUNNER_TEMP/preview-traffic-open.json" > "$RUNNER_TEMP/preview-traffic-open.normalized.json"
cmp "$RUNNER_TEMP/preview-traffic-open.normalized.json" "$desired_normalized" >/dev/null
case "$PREVIEW_INGRESS" in
  all) open_ingress=INGRESS_TRAFFIC_ALL ;;
  internal-and-cloud-load-balancing) open_ingress=INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER ;;
  *) exit 1 ;;
esac
jq --arg ingress "$open_ingress" '{name,etag,ingress:$ingress,invokerIamDisabled:true}' "$after_v2" > "$patch_body"
ambiguous_commit=true
unsafe_request_sent=true
curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
  --request PATCH --header "@$header" --header 'Content-Type: application/json' \
  --data-binary "@$patch_body" --output "$operation" \
  "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}?updateMask=ingress,invokerIamDisabled&allowMissing=false"
wait_operation "$operation" "$operation_result"
ambiguous_commit=false
effective_exposure=open
capture_production post-open false
cmp "$RUNNER_TEMP/preview-traffic-production-pre-open.sha256" \
  "$RUNNER_TEMP/preview-traffic-production-post-open.sha256" >/dev/null || {
  force_seal_on_rollback=true
  echo "Production changed across preview exposure opening." >&2
  exit 1
}
fetch_v2 "$after_v2"
assert_exposure "$after_v2" open
jq '.traffic // []' "$after_v2" > "$RUNNER_TEMP/preview-traffic-open.json"
normalize_traffic "$RUNNER_TEMP/preview-traffic-open.json" > "$RUNNER_TEMP/preview-traffic-open.normalized.json"
cmp "$RUNNER_TEMP/preview-traffic-open.normalized.json" "$desired_normalized" >/dev/null
capture_snapshot final false
if ! cmp "$RUNNER_TEMP/preview-traffic-sealed-admitted-after-routes.sha256" "$RUNNER_TEMP/preview-traffic-final-routes.sha256" >/dev/null; then
  echo "Preview routes changed while the admitted graph was being opened." >&2
  exit 1
fi

service_final="$RUNNER_TEMP/preview-traffic-snapshot-final-live.json"
revisions_final="$RUNNER_TEMP/preview-traffic-revisions-final"
health_routes="$RUNNER_TEMP/preview-traffic-health-routes"
while IFS=$'\t' read -r live_tag live_revision live_url; do
  if [ "$EXPECTED_REPOSITORY_ID" = 280932482 ]; then
    live_url="https://${live_tag}.${STABLE_PREVIEW_DOMAIN}"
  fi
  if [ "$live_tag" = "$tag" ]; then
    [ "$live_revision" = "$EXPECTED_REVISION" ]
    [ "$live_url" = "$PREVIEW_URL" ]
  fi
  nonce="$(jq -er '
    [.spec.containers[0].env[]? | select(.name == "PLATFORM_DEPLOY_NONCE" and (keys | sort) == ["name","value"]) | .value]
    | if length == 1 then .[0] else error("invalid preview nonce") end
    | select(test("^[0-9a-f]{64}$"))
  ' "$revisions_final/${live_revision}.json")"
  printf '%s\t%s\t%s\n' "$live_tag" "$live_url" "$nonce"
done < <(jq -r '.status.traffic[]? | select((.tag // "") | test("^pr-[1-9][0-9]*$")) | [.tag,.revisionName,.url] | @tsv' "$service_final") > "$health_routes"

healthy=false
for attempt in $(seq 1 30); do
  failures="$RUNNER_TEMP/preview-traffic-health-failures"
  : > "$failures"
  while IFS=$'\t' read -r live_tag live_url nonce; do
    (
      health_body="$RUNNER_TEMP/preview-traffic-health-${live_tag}.json"
      status="$(curl --silent --show-error --output "$health_body" --write-out '%{http_code}' \
        --max-filesize 1024 --max-time 10 --proto '=https' "${live_url%/}/livez" 2>/dev/null || true)"
      if [ "$status" != 200 ] ||
         ! jq -e -s --arg nonce "$nonce" 'length == 1 and .[0] == {deployment:$nonce,ok:true}' "$health_body" >/dev/null 2>&1; then
        printf '%s\n' "$live_tag" >> "$failures"
      fi
    ) &
  done < "$health_routes"
  wait
  if [ ! -s "$failures" ]; then
    healthy=true
    break
  fi
  [ "$attempt" -eq 30 ] || sleep 5
done
[ "$healthy" = true ]
if [ "$PREVIEW_INGRESS" = all ]; then
  baseline_url="$(jq -er '.uri | select(type == "string" and startswith("https://"))' "$after_v2")"
  baseline_body="$RUNNER_TEMP/preview-traffic-baseline-body"
  baseline_status="$(curl --silent --show-error --output "$baseline_body" --write-out '%{http_code}' \
    --max-filesize 1024 --max-time 10 --proto '=https' "$baseline_url")"
  [ "$baseline_status" = 404 ] && [ ! -s "$baseline_body" ]
fi

# Health can span multiple control-plane/lifecycle transitions. Re-read every
# route and PR after the data-plane proof and keep rollback armed until the
# exact admitted projection is still current.
capture_snapshot health-after false
if ! cmp "$RUNNER_TEMP/preview-traffic-final-full.sha256" "$RUNNER_TEMP/preview-traffic-health-after-full.sha256" >/dev/null; then
  echo "Preview routes, revisions, exposure, or lifecycle changed during health validation." >&2
  exit 1
fi
capture_production health-after false
if ! cmp "$RUNNER_TEMP/preview-traffic-production-post-open.sha256" \
  "$RUNNER_TEMP/preview-traffic-production-health-after.sha256" >/dev/null; then
  force_seal_on_rollback=true
  echo "Production changed during final preview health validation." >&2
  exit 1
fi

# Release is deliberately explicit and occurs only after the Cloud Run LRO,
# post-commit graph/OCI/lifecycle brackets, route health, and final production
# proof all succeeded. EXIT/failure handling never clears the poison.
patched=false
ambiguous_commit=false
force_seal_on_rollback=false
seal_on_failure=false
transition_acquired=false
# Disarm every Cloud Run failure path before releasing the durable marker.
# A lost release response can no longer trigger a mutation after the marker may
# already be clear.
release_transition
rm -f -- "$rollback_file"
{
  echo "admitted=true"
  echo "committed=true"
  echo "initial-exposure=$rollback_exposure"
} >> "$GITHUB_OUTPUT"
cleanup
trap - EXIT
