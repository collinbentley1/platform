#!/bin/bash

set -euo pipefail

die() {
  echo "$*" >&2
  exit 1
}

readonly MODE="${1:-}"
[[ "$MODE" == reconcile || "$MODE" == remove || "$MODE" == seal ]] || die "usage: cloud-run-preview-controller.sh {reconcile|remove|seal}"
readonly PROJECT_ID="${PROJECT_ID:?}"
readonly REGION="${REGION:?}"
readonly PREVIEW_SERVICE="${PREVIEW_SERVICE:?}"

[[ "$PROJECT_ID" =~ ^[a-z][a-z0-9-]{4,29}$ ]]
[[ "$REGION" =~ ^[a-z]+-[a-z]+[0-9]$ ]]
[[ "$PREVIEW_SERVICE" =~ ^[a-z][a-z0-9-]{0,62}$ ]]

# Evidence collection can fail independently of the exposure controller. This
# narrow mode acquires the same durable GCS marker before touching exposure or
# IAM. Failure/EXIT never clears the marker and never infers a lost LRO.
if [ "$MODE" = seal ]; then
  readonly ACCESS_TOKEN="${ACCESS_TOKEN:?}"
  readonly REPOSITORY_ID="${REPOSITORY_ID:?}"
  readonly EXPECTED_PLATFORM_WORKFLOW_SHA="${EXPECTED_PLATFORM_WORKFLOW_SHA:?}"
  readonly DHI_PARITY_ID="${DHI_PARITY_ID:?}"
  readonly PARITY_POLICY_ROOT="${PARITY_POLICY_ROOT:?}"
  test -x "$PARITY_POLICY_ROOT/tools/ci/deployment-parity-transition.sh"
  umask 077
  seal_work="$(mktemp -d "${RUNNER_TEMP:?}/preview-controller-seal.XXXXXX")"
  seal_header="$seal_work/rest-header"
  seal_before="$seal_work/service-before.json"
  seal_body="$seal_work/seal-body.json"
  seal_operation="$seal_work/operation.json"
  seal_operation_result="$seal_work/operation-result.json"
  seal_after="$seal_work/service-after.json"
  seal_policy="$seal_work/policy.json"
  seal_policy_body="$seal_work/policy-body.json"
  seal_policy_result="$seal_work/policy-result.json"
  seal_lease="$seal_work/transition-lease.json"
  seal_transition() {
    if env ACCESS_TOKEN="$ACCESS_TOKEN" PROJECT_ID="$PROJECT_ID" REPOSITORY_ID="$REPOSITORY_ID" \
      EXPECTED_PLATFORM_WORKFLOW_SHA="$EXPECTED_PLATFORM_WORKFLOW_SHA" DHI_PARITY_ID="$DHI_PARITY_ID" \
      TRANSITION_KIND=preview-emergency-seal TRANSITION_LEASE_FILE="$seal_lease" \
      "$PARITY_POLICY_ROOT/tools/ci/deployment-parity-transition.sh" acquire; then
      return 0
    fi
    env ACCESS_TOKEN="$ACCESS_TOKEN" PROJECT_ID="$PROJECT_ID" REPOSITORY_ID="$REPOSITORY_ID" \
      EXPECTED_PLATFORM_WORKFLOW_SHA="$EXPECTED_PLATFORM_WORKFLOW_SHA" DHI_PARITY_ID="$DHI_PARITY_ID" \
      TRANSITION_LEASE_FILE="$seal_lease" \
      "$PARITY_POLICY_ROOT/tools/ci/deployment-parity-transition.sh" resume-seal
  }
  seal_release_transition() {
    env ACCESS_TOKEN="$ACCESS_TOKEN" PROJECT_ID="$PROJECT_ID" REPOSITORY_ID="$REPOSITORY_ID" \
      TRANSITION_LEASE_FILE="$seal_lease" \
      "$PARITY_POLICY_ROOT/tools/ci/deployment-parity-transition.sh" release
  }
  seal_cleanup() {
    status=$?
    set +e
    if [[ "$seal_work" == "${RUNNER_TEMP:?}/preview-controller-seal."* ]] && [ -d "$seal_work" ] && [ ! -L "$seal_work" ]; then
      find "$seal_work" -depth -delete
    fi
    trap - EXIT
    exit "$status"
  }
  trap seal_cleanup EXIT
  printf 'Authorization: Bearer %s\n' "$ACCESS_TOKEN" > "$seal_header"
  seal_url="https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}"
  seal_status="$(curl --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
    --header "@$seal_header" --output "$seal_before" --write-out '%{http_code}' "$seal_url" || true)"
  if [ "$seal_status" = 404 ]; then
    if ! env ACCESS_TOKEN="$ACCESS_TOKEN" PROJECT_ID="$PROJECT_ID" REPOSITORY_ID="$REPOSITORY_ID" \
      "$PARITY_POLICY_ROOT/tools/ci/deployment-parity-transition.sh" assert-clear; then
      seal_transition || die "An absent preview service has an unrelated or unrecoverable transition poison."
      seal_release_transition
    fi
    echo "Shared preview service does not exist; nothing to seal."
    echo "admitted=true" >> "${GITHUB_OUTPUT:?}"
    echo "exposure=absent" >> "$GITHUB_OUTPUT"
    exit 0
  fi
  [ "$seal_status" = 200 ] || die "Preview service seal read failed with HTTP ${seal_status}."
  jq -e --arg name "projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}" '
    .name == $name and (.etag | type == "string" and length > 0 and length <= 1024 and (test("[[:cntrl:]]") | not)) and
    (.generation == .observedGeneration) and ((.reconciling // false) == false) and
    .terminalCondition.type == "Ready" and .terminalCondition.state == "CONDITION_SUCCEEDED" and
    ((.buildConfig // {}) == {}) and all(.template.containers[]?; ((.baseImageUri // "") == ""))
  ' "$seal_before" >/dev/null
  jq -cS '.traffic // []' "$seal_before" > "$seal_work/traffic-before.json"
  jq -cS '.trafficStatuses // []' "$seal_before" > "$seal_work/traffic-statuses-before.json"

  seal_transition

  seal_sanitize_policy() {
    local status
    for attempt in $(seq 1 5); do
      curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
        --header "@$seal_header" --output "$seal_policy" "${seal_url}:getIamPolicy?options.requestedPolicyVersion=3"
      jq -e '((.bindings // []) | type == "array") and (.etag | type == "string" and length > 0)' "$seal_policy" >/dev/null
      if jq -e --arg project "$PROJECT_ID" '
        def expected: [
          {role:"projects/\($project)/roles/cloudRunRevisionDeployer",members:["serviceAccount:gha-preview-deploy@\($project).iam.gserviceaccount.com"]},
          {role:"projects/\($project)/roles/deploymentParityCloudRunReader",members:["serviceAccount:gha-deploy-parity@\($project).iam.gserviceaccount.com"]},
          {role:"projects/\($project)/roles/previewTrafficCommitter",members:["serviceAccount:gha-preview-commit@\($project).iam.gserviceaccount.com"]}
        ] | sort_by(.role);
        ((.bindings // []) | map(.members |= sort) | sort_by(.role)) == expected
      ' "$seal_policy" >/dev/null; then return 0; fi
      jq --arg project "$PROJECT_ID" '{policy:(. | .bindings = [
        {role:"projects/\($project)/roles/cloudRunRevisionDeployer",members:["serviceAccount:gha-preview-deploy@\($project).iam.gserviceaccount.com"]},
        {role:"projects/\($project)/roles/deploymentParityCloudRunReader",members:["serviceAccount:gha-deploy-parity@\($project).iam.gserviceaccount.com"]},
        {role:"projects/\($project)/roles/previewTrafficCommitter",members:["serviceAccount:gha-preview-commit@\($project).iam.gserviceaccount.com"]}
      ]),updateMask:"bindings,etag"}' "$seal_policy" > "$seal_policy_body"
      status="$(curl --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 --request POST \
        --header "@$seal_header" --header 'Content-Type: application/json' --data-binary "@$seal_policy_body" \
        --output "$seal_policy_result" --write-out '%{http_code}' "${seal_url}:setIamPolicy" || true)"
      if [ "$status" = 200 ] && jq -e --arg project "$PROJECT_ID" '
        def expected: [
          {role:"projects/\($project)/roles/cloudRunRevisionDeployer",members:["serviceAccount:gha-preview-deploy@\($project).iam.gserviceaccount.com"]},
          {role:"projects/\($project)/roles/deploymentParityCloudRunReader",members:["serviceAccount:gha-deploy-parity@\($project).iam.gserviceaccount.com"]},
          {role:"projects/\($project)/roles/previewTrafficCommitter",members:["serviceAccount:gha-preview-commit@\($project).iam.gserviceaccount.com"]}
        ] | sort_by(.role);
        ((.bindings // []) | map(.members |= sort) | sort_by(.role)) == expected
      ' "$seal_policy_result" >/dev/null; then return 0; fi
    done
    return 1
  }

  # An exposure-only PATCH can be a semantic no-op when the service is already
  # SEALED. Use two deterministic, etag-bound label writes while preserving the
  # complete traffic graph. A completed first write makes every older etag
  # stale; a completed second write removes the reserved fence before release.
  readonly seal_fence_key=platform-preview-seal-fence
  jq -e '
    ((.labels // {}) | type == "object") and
    all((.labels // {}) | to_entries[]?;
      (.key | type == "string" and length > 0 and length <= 63 and (test("[[:cntrl:]]") | not)) and
      (.value | type == "string" and length <= 63 and (test("[[:cntrl:]]") | not)))
  ' "$seal_before" >/dev/null
  jq -cS --arg key "$seal_fence_key" '(.labels // {}) | del(.[$key])' "$seal_before" > "$seal_work/preserved-labels.json"
  seal_fence_value="$(jq -er '.metadata.nonce | select(test("^[0-9a-f]{64}$")) | .[0:32]' "$seal_lease")"
  stale_fence_value="$(jq -r --arg key "$seal_fence_key" '.labels[$key] // ""' "$seal_before")"
  [ "$seal_fence_value" != "$stale_fence_value" ] || die "Fresh seal fence unexpectedly equals the stale reserved label."
  jq -cS --arg key "$seal_fence_key" --arg value "$seal_fence_value" '. + {($key):$value}' \
    "$seal_work/preserved-labels.json" > "$seal_work/fenced-labels.json"

  seal_validate_read() {
    local path="$1"
    jq -e --arg name "projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}" '
      .name == $name and
      (.etag | type == "string" and length > 0 and length <= 1024 and (test("[[:cntrl:]]") | not)) and
      (.generation | type == "string" and test("^[1-9][0-9]*$")) and
      (.observedGeneration | type == "string" and test("^[1-9][0-9]*$")) and
      (.generation == .observedGeneration) and ((.reconciling // false) == false) and
      .terminalCondition.type == "Ready" and .terminalCondition.state == "CONDITION_SUCCEEDED" and
      ((.buildConfig // {}) == {}) and all(.template.containers[]?; ((.baseImageUri // "") == "")) and
      ((.labels // {}) | type == "object") and
      all((.labels // {}) | to_entries[]?;
        (.key | type == "string" and length > 0 and length <= 63 and (test("[[:cntrl:]]") | not)) and
        (.value | type == "string" and length <= 63 and (test("[[:cntrl:]]") | not)))
    ' "$path" >/dev/null
    jq -cS '.traffic // []' "$path" > "$seal_work/traffic-read.json"
    jq -cS '.trafficStatuses // []' "$path" > "$seal_work/traffic-statuses-read.json"
    cmp "$seal_work/traffic-before.json" "$seal_work/traffic-read.json" >/dev/null
    cmp "$seal_work/traffic-statuses-before.json" "$seal_work/traffic-statuses-read.json" >/dev/null
  }

  seal_patch_fence_leg() {
    local current="$1" expected_labels="$2" destination="$3" phase="$4"
    local status curl_status operation_name done=false
    for attempt in $(seq 1 5); do
      jq --slurpfile labels "$expected_labels" '{
        name,etag,labels:$labels[0],ingress:"INGRESS_TRAFFIC_INTERNAL_ONLY",invokerIamDisabled:false
      }' "$current" > "$seal_body"
      curl_status=0
      status="$(curl --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
        --request PATCH --header "@$seal_header" --header 'Content-Type: application/json' \
        --data-binary "@$seal_body" --output "$seal_operation" --write-out '%{http_code}' \
        "${seal_url}?updateMask=labels,ingress,invokerIamDisabled&allowMissing=false")" || curl_status=$?
      [ "$curl_status" -eq 0 ] || die "Preview ${phase} fence PATCH outcome is ambiguous; durable poison retained."
      if [ "$status" = 200 ]; then
        operation_name="$(jq -er '.name | select(test("^projects/[^/]+/locations/[a-z0-9-]+/operations/[A-Za-z0-9_-]+$"))' "$seal_operation")"
        done=false
        for operation_attempt in $(seq 1 60); do
          curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
            --header "@$seal_header" --output "$seal_operation_result" "https://run.googleapis.com/v2/${operation_name}"
          if jq -e --arg service "projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}" '
            .done == true and (has("error") | not) and .response.name == $service
          ' "$seal_operation_result" >/dev/null; then done=true; break; fi
          [ "$operation_attempt" -eq 60 ] || sleep 2
        done
        [ "$done" = true ] || die "Preview ${phase} fence operation did not complete; durable poison retained."
        curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
          --header "@$seal_header" --output "$destination" "$seal_url"
        seal_validate_read "$destination"
        jq -e --slurpfile before "$current" --slurpfile labels "$expected_labels" '
          .ingress == "INGRESS_TRAFFIC_INTERNAL_ONLY" and (.invokerIamDisabled // false) == false and
          .etag != $before[0].etag and
          ((.generation | tonumber) > ($before[0].generation | tonumber)) and
          (.labels // {}) == $labels[0]
        ' "$destination" >/dev/null || die "Preview ${phase} fence was not authoritatively observed; durable poison retained."
        return 0
      fi
      if [ "$status" != 409 ] && [ "$status" != 412 ]; then
        die "Preview ${phase} fence PATCH failed with HTTP ${status}; durable poison retained."
      fi
      curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
        --header "@$seal_header" --output "$seal_work/service-retry.json" "$seal_url"
      seal_validate_read "$seal_work/service-retry.json"
      if [ "$phase" = apply ]; then
        jq -e --arg key "$seal_fence_key" --slurpfile labels "$seal_work/preserved-labels.json" '
          ((.labels // {}) | del(.[$key])) == $labels[0]
        ' "$seal_work/service-retry.json" >/dev/null
      else
        jq -e --slurpfile labels "$seal_work/fenced-labels.json" '(.labels // {}) == $labels[0]' \
          "$seal_work/service-retry.json" >/dev/null
      fi
      cp -- "$seal_work/service-retry.json" "$current"
    done
    die "Preview ${phase} fence could not acquire the current exact etag; durable poison retained."
  }

  seal_patch_fence_leg "$seal_before" "$seal_work/fenced-labels.json" "$seal_work/service-fenced.json" apply
  seal_patch_fence_leg "$seal_work/service-fenced.json" "$seal_work/preserved-labels.json" "$seal_after" remove
  seal_sanitize_policy
  seal_release_transition
  echo "admitted=true" >> "${GITHUB_OUTPUT:?}"
  echo "exposure=sealed" >> "$GITHUB_OUTPUT"
  exit 0
fi

readonly SERVICE_NAME="${SERVICE_NAME:?}"
readonly REPOSITORY_ID="${REPOSITORY_ID:?}"
readonly EXPECTED_REPOSITORY="${EXPECTED_REPOSITORY:?}"
readonly EXPECTED_PROJECT_NUMBER="${EXPECTED_PROJECT_NUMBER:?}"
readonly EXPECTED_PREVIEW_IMAGE_NAME="${EXPECTED_PREVIEW_IMAGE_NAME:?}"
readonly EXPECTED_PRODUCTION_IMAGE_NAME="${EXPECTED_PRODUCTION_IMAGE_NAME:?}"
readonly EXPECTED_PREVIEW_RUNTIME_SERVICE_ACCOUNT="${EXPECTED_PREVIEW_RUNTIME_SERVICE_ACCOUNT:?}"
readonly EXPECTED_PLATFORM_WORKFLOW_SHA="${EXPECTED_PLATFORM_WORKFLOW_SHA:?}"
readonly DHI_PARITY_ID="${DHI_PARITY_ID:?}"
readonly PARITY_POLICY_ROOT="${PARITY_POLICY_ROOT:?}"
readonly PREVIEW_INGRESS="${PREVIEW_INGRESS:?}"
readonly STABLE_PREVIEW_DOMAIN="${STABLE_PREVIEW_DOMAIN:-}"
readonly TARGET_TAG="${TARGET_TAG:-}"
readonly EXPECTED_TARGET_REVISION="${EXPECTED_TARGET_REVISION:-}"
readonly EXPECTED_TARGET_HEAD_SHA="${EXPECTED_TARGET_HEAD_SHA:-}"
readonly PRESERVE_TARGET_HEAD_SHA="${PRESERVE_TARGET_HEAD_SHA:-}"

[[ "$SERVICE_NAME" =~ ^[a-z][a-z0-9-]{0,62}$ ]]
[[ "$REPOSITORY_ID" =~ ^(1255553151|711292980|1025243085|280932482)$ ]]
[[ "$EXPECTED_PROJECT_NUMBER" =~ ^[1-9][0-9]*$ ]]
[[ "$EXPECTED_REPOSITORY" =~ ^collinbentley1/[A-Za-z0-9._-]+$ ]]
[[ "$EXPECTED_PLATFORM_WORKFLOW_SHA" =~ ^[0-9a-f]{40}$ ]]
[[ "$EXPECTED_PREVIEW_RUNTIME_SERVICE_ACCOUNT" =~ ^cloud-run-preview@[a-z0-9-]+\.iam\.gserviceaccount\.com$ ]]
[[ "$EXPECTED_PREVIEW_IMAGE_NAME" =~ ^us-east4-docker\.pkg\.dev/[a-z0-9-]+/[a-z0-9-]+/[a-z0-9-]+$ ]]
[[ "$EXPECTED_PRODUCTION_IMAGE_NAME" =~ ^us-east4-docker\.pkg\.dev/[a-z0-9-]+/[a-z0-9-]+/[a-z0-9-]+$ ]]
[[ "$DHI_PARITY_ID" =~ ^[0-9a-z]{50}$ ]]
test -x "$PARITY_POLICY_ROOT/tools/ci/deployment-parity-transition.sh"
if [ "$MODE" = remove ]; then
  [[ "$TARGET_TAG" =~ ^pr-[1-9][0-9]*$ ]]
  [ -z "$EXPECTED_TARGET_REVISION" ] || [[ "$EXPECTED_TARGET_REVISION" =~ ^[a-z][a-z0-9-]{0,62}$ ]]
  [ -z "$EXPECTED_TARGET_HEAD_SHA" ] || [[ "$EXPECTED_TARGET_HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]
  [ -z "$PRESERVE_TARGET_HEAD_SHA" ] || [[ "$PRESERVE_TARGET_HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]
fi
case "$PREVIEW_INGRESS" in
  all) readonly OPEN_INGRESS=INGRESS_TRAFFIC_ALL ;;
  internal-and-cloud-load-balancing) readonly OPEN_INGRESS=INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER ;;
  *) die "Preview ingress is outside the reviewed policy." ;;
esac

umask 077
work="$(mktemp -d "${RUNNER_TEMP:?}/preview-controller.XXXXXX")"
token="$work/access-token"
header="$work/rest-header"
operation="$work/operation.json"
operation_result="$work/operation-result.json"
transition_lease="$work/transition-lease.json"
mutated=false
mutation_arm=false
ambiguous_mutation=false
transition_acquired=false
unsafe_request_sent=false
target_exposure=""

cleanup() {
  status=$?
  set +e
  if [ "$status" -ne 0 ] && [ "$transition_acquired" = true ]; then
    if [ "$ambiguous_mutation" = true ]; then
      echo "CRITICAL: preview controller mutation outcome is ambiguous; retaining the durable parity poison and refusing follow-up inference." >&2
    elif [ "$mutated" = true ]; then
      echo "Post-mutation preview proof failed; attempting a known SEALED recovery while retaining the durable poison." >&2
      seal_current || echo "CRITICAL: failed to prove SEALED recovery; durable poison retained." >&2
    else
      echo "Preview controller failed after acquiring the durable marker; poison retained for explicit recovery." >&2
    fi
  fi
  if [[ "$work" == "${RUNNER_TEMP:?}/preview-controller."* ]] && [ -d "$work" ] && [ ! -L "$work" ]; then
    find "$work" -depth -delete
  fi
  trap - EXIT
  exit "$status"
}
trap cleanup EXIT

gcloud auth print-access-token > "$token"
printf 'Authorization: Bearer %s\n' "$(<"$token")" > "$header"

acquire_transition() {
  local kind="$1"
  env ACCESS_TOKEN="$(<"$token")" PROJECT_ID="$PROJECT_ID" REPOSITORY_ID="$REPOSITORY_ID" \
    EXPECTED_PLATFORM_WORKFLOW_SHA="$EXPECTED_PLATFORM_WORKFLOW_SHA" DHI_PARITY_ID="$DHI_PARITY_ID" \
    TRANSITION_KIND="$kind" TRANSITION_LEASE_FILE="$transition_lease" \
    "$PARITY_POLICY_ROOT/tools/ci/deployment-parity-transition.sh" acquire
  transition_acquired=true
}

release_transition() {
  env ACCESS_TOKEN="$(<"$token")" PROJECT_ID="$PROJECT_ID" REPOSITORY_ID="$REPOSITORY_ID" \
    TRANSITION_LEASE_FILE="$transition_lease" \
    "$PARITY_POLICY_ROOT/tools/ci/deployment-parity-transition.sh" release
}

fetch_invoker_policy() {
  local destination="$1"
  curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
    --header "@$header" --output "$destination" \
    "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}:getIamPolicy?options.requestedPolicyVersion=3"
  jq -e '
    ((.version // 1) | type == "number" and . >= 1 and . <= 3) and
    (.etag | type == "string" and length > 0 and length <= 1024 and (test("[[:cntrl:]]") | not)) and
    ((.bindings // []) | type == "array") and
    all(.bindings[]?; (.role | type == "string") and ((.members // []) | type == "array") and all(.members[]; type == "string"))
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
  local policy="$work/invoker-policy.json" body="$work/invoker-policy-body.json" result="$work/invoker-policy-result.json" status
  for attempt in $(seq 1 5); do
    fetch_invoker_policy "$policy" || return 1
    if assert_exact_preview_policy "$policy"; then return 0; fi
    # The preview service policy is authoritative: exactly the three reviewed
    # operational grants from IaC, with no named, public, conditional, deleted,
    # domain, group, service-account, principal-set, or custom-role additions.
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
    # On a lost response, loop back through authoritative getIamPolicy. The
    # durable marker remains held unless the exact policy is observed.
  done
  return 1
}

fetch_service_v2_raw() {
  local destination="$1"
  curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
    --header "@$header" --output "$destination" \
    "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}"
}

validate_service_v2() {
  local path="$1"
  jq -e --arg name "projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}" '
    .name == $name and
    (.etag | type == "string" and length > 0 and length <= 1024 and (test("[[:cntrl:]]") | not)) and
    (.generation == .observedGeneration) and
    ((.reconciling // false) == false) and
    .terminalCondition.type == "Ready" and .terminalCondition.state == "CONDITION_SUCCEEDED" and
    ((.buildConfig // {}) == {}) and
    all(.template.containers[]?; ((.baseImageUri // "") == "")) and
    ((.defaultUriDisabled // false) == false)
  ' "$path" >/dev/null
}

exposure_of() {
  local path="$1"
  if jq -e --arg ingress "$OPEN_INGRESS" '
    .ingress == $ingress and .invokerIamDisabled == true
  ' "$path" >/dev/null; then
    echo open
  elif jq -e '
    .ingress == "INGRESS_TRAFFIC_INTERNAL_ONLY" and (.invokerIamDisabled // false) == false
  ' "$path" >/dev/null; then
    echo sealed
  else
    return 1
  fi
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
      return
    fi
    [ "$attempt" -eq 60 ] || sleep 2
  done
  return 1
}

patch_service() {
  local body="$1" update_mask="$2" http_status curl_status
  if [ "$mutation_arm" = true ]; then
    [ "$transition_acquired" = true ] || return 1
    mutated=true
    unsafe_request_sent=true
    ambiguous_mutation=true
  fi
  set +e
  http_status="$(curl --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
    --request PATCH --header "@$header" --header 'Content-Type: application/json' \
    --data-binary "@$body" --output "$operation" --write-out '%{http_code}' \
    "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}?updateMask=${update_mask}&allowMissing=false")"
  curl_status=$?
  set -e
  if [ "$curl_status" -ne 0 ] || [ "$http_status" != 200 ]; then
    if [ "$mutation_arm" = true ]; then
      if [ "$curl_status" -eq 0 ] && { [ "$http_status" = 409 ] || [ "$http_status" = 412 ]; }; then
        # Only an explicit precondition/conflict response proves non-acceptance.
        mutated=false
        ambiguous_mutation=false
      else
        # A same-etag immediate GET cannot disprove an accepted asynchronous
        # operation whose response was lost and whose mutation is still pending.
        ambiguous_mutation=true
      fi
    fi
    return 1
  fi
  wait_operation "$operation" "$operation_result" || return 1
  ambiguous_mutation=false
}

seal_current() {
  local current="$work/seal-current.json" body="$work/seal-body.json" after="$work/seal-after.json"
  [ "$transition_acquired" = true ] || return 1
  fetch_service_v2_raw "$current" || return 1
  validate_service_v2 "$current" || return 1
  if [ "$(exposure_of "$current")" = sealed ]; then
    sanitize_invoker_policy
    return
  fi
  jq '{name,etag,ingress:"INGRESS_TRAFFIC_INTERNAL_ONLY",invokerIamDisabled:false}' "$current" > "$body"
  # A response-lost seal is never inferred complete. The durable marker stays
  # poisoned and blocks every later preview/production parity transition.
  mutation_arm=true
  patch_service "$body" ingress,invokerIamDisabled || return 1
  mutation_arm=false
  fetch_service_v2_raw "$after" || return 1
  validate_service_v2 "$after" || return 1
  [ "$(exposure_of "$after")" = sealed ] && sanitize_invoker_policy
}

normalize_v2_traffic() {
  jq -cS '[.[]? | {
    type,
    revision:((.revision // "") | if . == "" then null else split("/")[-1] end),
    percent:(.percent // 0),
    tag:(.tag // null)
  }] | sort_by(.tag // "")' "$1"
}

output_value() {
  sed -n "s/^$1=//p" "$2" | tail -n 1
}

capture_proposed() {
  local suffix="$1" verify_graph="$2"
  local prod_service="$work/${suffix}-prod-service.json"
  local prod_revision="$work/${suffix}-prod-revision.json"
  local prod_outputs="$work/${suffix}-prod.outputs"
  local prod_v2="$work/${suffix}-prod-v2.json"
  local prod_revision_v2="$work/${suffix}-prod-revision-v2.json"
  local service="$work/${suffix}-service.json"
  local service_v2="$work/${suffix}-service-v2.json"
  local proposed="$work/${suffix}-proposed-service.json"
  local revisions="$work/${suffix}-revisions"
  local revisions_v2="$work/${suffix}-revisions-v2"
  local lifecycle="$work/${suffix}-lifecycle"
  local remove_tags="$work/${suffix}-remove-tags"
  local desired="$work/${suffix}-desired-traffic.json"
  local outputs="$work/${suffix}-preview.outputs"
  local policy="$work/${suffix}-invoker-policy.json"
  local image_set="$work/${suffix}-images.json"
  local graph_outputs="$work/${suffix}-graphs.outputs"
  local revision live_revision live_tag live_pr live_head pr_json active target_action metadata_candidate
  local -a revision_files revision_v2_files projections
  install -d -m 0700 "$revisions" "$revisions_v2" "$lifecycle"
  : > "$remove_tags"

  gcloud run services describe "$SERVICE_NAME" \
    --project="$PROJECT_ID" --region="$REGION" --format=json > "$prod_service"
  prod_revision_name="$(jq -er '.status.latestReadyRevisionName | select(test("^[a-z][a-z0-9-]{0,62}$"))' "$prod_service")"
  gcloud run revisions describe "$prod_revision_name" \
    --project="$PROJECT_ID" --region="$REGION" --format=json > "$prod_revision"
  env GITHUB_OUTPUT="$prod_outputs" PARITY_SERVICE_JSON="$prod_service" PARITY_REVISION_JSON="$prod_revision" \
    EXPECTED_SERVICE_NAME="$SERVICE_NAME" EXPECTED_PROJECT_NUMBER="$EXPECTED_PROJECT_NUMBER" \
    EXPECTED_REPOSITORY_ID="$REPOSITORY_ID" EXPECTED_PRODUCTION_IMAGE_NAME="$EXPECTED_PRODUCTION_IMAGE_NAME" \
    "$PARITY_POLICY_ROOT/tools/ci/cloud-run-dhi-parity.sh" prove-production
  live_prod_head="$(output_value live_production_head_sha "$prod_outputs")"
  live_prod_index="$(output_value live_production_index_image "$prod_outputs")"
  live_prod_runnable="$(output_value live_production_runnable_image "$prod_outputs")"
  [[ "$live_prod_head" =~ ^[0-9a-f]{40}$ ]]
  [[ "$live_prod_index" == "$EXPECTED_PRODUCTION_IMAGE_NAME@sha256:"* ]]
  [[ "$live_prod_runnable" == "$EXPECTED_PRODUCTION_IMAGE_NAME@sha256:"* ]]
  curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
    --header "@$header" --output "$prod_v2" \
    "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${SERVICE_NAME}"
  curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
    --header "@$header" --output "$prod_revision_v2" \
    "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${SERVICE_NAME}/revisions/${prod_revision_name}"
  jq -e --arg name "projects/${PROJECT_ID}/locations/${REGION}/services/${SERVICE_NAME}" --arg revision "$prod_revision_name" '
    .name == $name and (.generation == .observedGeneration) and ((.reconciling // false) == false) and
    .terminalCondition.type == "Ready" and .terminalCondition.state == "CONDITION_SUCCEEDED" and
    ((.buildConfig // {}) == {}) and all(.template.containers[]?; ((.baseImageUri // "") == "")) and
    .ingress == "INGRESS_TRAFFIC_ALL" and .invokerIamDisabled == true and
    (.latestReadyRevision | split("/")[-1]) == $revision and
    (.traffic | length) == 1 and .traffic[0].type == "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST" and
    .traffic[0].percent == 100 and ((.traffic[0].tag // "") == "") and ((.traffic[0].revision // "") == "") and
    (.trafficStatuses | length) == 1 and .trafficStatuses[0].type == "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST" and
    .trafficStatuses[0].percent == 100 and ((.trafficStatuses[0].tag // "") == "") and
    ((.trafficStatuses[0].revision // "") == "")
  ' "$prod_v2" >/dev/null
  jq -e --arg name "projects/${PROJECT_ID}/locations/${REGION}/services/${SERVICE_NAME}/revisions/${prod_revision_name}" \
    --arg image "$live_prod_runnable" --arg index "${live_prod_index##*@}" --arg runnable "${live_prod_runnable##*@}" '
    def exact_value($name):
      [.containers[0].env[]? | select(.name == $name and (keys | sort) == ["name","value"]) | .value]
      | if length == 1 then .[0] else error("invalid image identity") end;
    .name == $name and ((.reconciling // false) == false) and
    (.containers | length) == 1 and .containers[0].image == $image and
    ((.containers[0].baseImageUri // "") == "") and
    exact_value("PLATFORM_IMAGE_INDEX_DIGEST") == $index and
    exact_value("PLATFORM_IMAGE_RUNNABLE_DIGEST") == $runnable and
    ([.conditions[]? | select(.type == "Ready" and .state == "CONDITION_SUCCEEDED")] | length) == 1
  ' "$prod_revision_v2" >/dev/null

  gcloud run services describe "$PREVIEW_SERVICE" \
    --project="$PROJECT_ID" --region="$REGION" --format=json > "$service"
  fetch_service_v2_raw "$service_v2"
  validate_service_v2 "$service_v2"
  fetch_invoker_policy "$policy"
  assert_exact_preview_policy "$policy"
  current_exposure="$(exposure_of "$service_v2")"
  jq '.traffic // []' "$service_v2" > "$work/${suffix}-current-traffic.json"
  jq -e '
    all(.[]?;
      .type == "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION" and
      (.revision | type == "string") and
      (.revision | split("/")[-1] | test("^[a-z][a-z0-9-]{0,62}$")))
  ' "$work/${suffix}-current-traffic.json" >/dev/null

  while IFS=$'\t' read -r live_tag live_revision; do
    [[ "$live_tag" =~ ^pr-([1-9][0-9]*)$ ]]
    live_pr="${BASH_REMATCH[1]}"
    [[ "$live_revision" =~ ^[a-z][a-z0-9-]{0,62}$ ]]
    gcloud run revisions describe "$live_revision" \
      --project="$PROJECT_ID" --region="$REGION" --format=json > "$work/${suffix}-target-${live_tag}.json"
    live_head="$(jq -r '.metadata.labels["git-head-sha"] // ""' "$work/${suffix}-target-${live_tag}.json")"
    target_action=ordinary
    if [ "$MODE" = remove ] && [ "$live_tag" = "$TARGET_TAG" ]; then
      target_action=remove
      if [ -n "$EXPECTED_TARGET_REVISION" ] && [ "$live_revision" != "$EXPECTED_TARGET_REVISION" ]; then
        target_action=preserve
      elif [ -n "$PRESERVE_TARGET_HEAD_SHA" ] && [ "$live_head" = "$PRESERVE_TARGET_HEAD_SHA" ]; then
        target_action=preserve
      fi
    fi

    # A platform repin must be able to retire marker-incompatible routes before
    # the strict current-workflow proof. These labels are immutable revision
    # metadata; removing the tag is monotonic and the final traffic CAS is
    # performed while SEALED. Never preserve a malformed or predecessor route
    # as an admitted survivor merely because its pull request remains open.
    metadata_candidate=false
    if jq -e --arg repository_id "$REPOSITORY_ID" --arg workflow_sha "$EXPECTED_PLATFORM_WORKFLOW_SHA" \
      --arg pr "$live_pr" --arg parity "$DHI_PARITY_ID" '
      .metadata.labels.environment == "preview" and
      .metadata.labels["preview-role"] == "pr" and
      .metadata.labels["managed-by"] == "github-actions" and
      .metadata.labels["github-repository-id"] == $repository_id and
      .metadata.labels["github-pr"] == $pr and
      .metadata.labels["dhi-parity-id"] == $parity and
      .metadata.labels["platform-workflow-sha"] == $workflow_sha and
      (.metadata.labels["git-head-sha"] | test("^[0-9a-f]{40}$"))
    ' "$work/${suffix}-target-${live_tag}.json" >/dev/null; then
      metadata_candidate=true
    fi
    if [ "$metadata_candidate" != true ]; then
      if [ "$target_action" = preserve ]; then
        echo "A protected newer target has stale or malformed platform provenance; preserving it would block strict admission." >&2
        return 1
      fi
      printf '%s\n' "$live_tag" >> "$remove_tags"
      continue
    fi
    if [ -n "$EXPECTED_TARGET_HEAD_SHA" ] && [ "$target_action" = remove ] && [ "$live_head" != "$EXPECTED_TARGET_HEAD_SHA" ]; then
      echo "Target preview tag identity is neither the exact removable head nor the fresh preserved head." >&2
      return 1
    fi

    pr_json="$lifecycle/${live_tag}.json"
    gh api "repos/${GITHUB_REPOSITORY}/pulls/${live_pr}" > "$pr_json"
    active=false
    if jq -e --arg head "$live_head" --arg repository "$EXPECTED_REPOSITORY" --arg repository_id "$REPOSITORY_ID" '
      .state == "open" and .draft == false and .head.sha == $head and
      (.head.repo.id | tostring) == $repository_id and .head.repo.full_name == $repository and .base.ref == "main"
    ' "$pr_json" >/dev/null; then active=true; fi
    if [ "$target_action" = remove ] || { [ "$target_action" = ordinary ] && [ "$active" != true ]; }; then
      printf '%s\n' "$live_tag" >> "$remove_tags"
    elif [ "$active" != true ]; then
      echo "A protected newer target is not an active exact pull request route." >&2
      return 1
    fi
  done < <(jq -r '.status.traffic[]? | select((.tag // "") != "") | [.tag,.revisionName] | @tsv' "$service")
  sort -u "$remove_tags" -o "$remove_tags"

  jq --rawfile removed "$remove_tags" '
    ($removed | split("\n") | map(select(length > 0))) as $remove |
    [.traffic[]? | select(((.tag // "") as $tag | ($remove | index($tag)) == null)) | {
      type:"TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION",
      revision:(.revision | split("/")[-1]),
      percent:(.percent // 0)
    } + (if ((.tag // "") == "") then {} else {tag:.tag} end)] | sort_by(.tag // "")
  ' "$service_v2" > "$desired"
  jq -e '
    ([.[] | select((.tag // "") == "" and .percent == 100)] | length) == 1 and
    all(.[]; .type == "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION" and
      (.revision | test("^[a-z][a-z0-9-]{0,62}$")) and
      (((.tag // "") == "" and .percent == 100) or ((.tag | test("^pr-[1-9][0-9]*$")) and .percent == 0)))
  ' "$desired" >/dev/null
  desired_tag_count="$(jq -r '[.[] | select((.tag // "") != "")] | length' "$desired")"
  jq --slurpfile desired "$desired" --argjson desired_tag_count "$desired_tag_count" --arg preview_ingress "$PREVIEW_INGRESS" '
    .spec.traffic = [$desired[0][] | {
      revisionName:.revision,latestRevision:false,percent:.percent
    } + (if has("tag") then {tag:.tag} else {} end)] |
    .status.traffic = [.status.traffic[] as $route |
      $desired[0][] | select(.revision == $route.revisionName and ((.tag // "") == ($route.tag // ""))) |
      $route] |
    .metadata.annotations["run.googleapis.com/ingress"] =
      (if $desired_tag_count == 0 then "internal" else $preview_ingress end) |
    .metadata.annotations["run.googleapis.com/invoker-iam-disabled"] =
      (if $desired_tag_count == 0 then "false" else "true" end)
  ' "$service" > "$proposed"

  while IFS= read -r revision; do
    [[ "$revision" =~ ^[a-z][a-z0-9-]{0,62}$ ]]
    gcloud run revisions describe "$revision" \
      --project="$PROJECT_ID" --region="$REGION" --format=json > "$revisions/${revision}.json"
    curl --fail-with-body --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
      --header "@$header" --output "$revisions_v2/${revision}.json" \
      "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}/revisions/${revision}"
    jq -e --arg name "projects/${PROJECT_ID}/locations/${REGION}/services/${PREVIEW_SERVICE}/revisions/${revision}" \
      --arg runtime "$EXPECTED_PREVIEW_RUNTIME_SERVICE_ACCOUNT" --slurpfile v1 "$revisions/${revision}.json" '
      .name == $name and ((.reconciling // false) == false) and .serviceAccount == $runtime and
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
  done < <(jq -r '.[].revision' "$desired" | sort -u)

  GITHUB_OUTPUT="$outputs" PARITY_SERVICE_JSON="$proposed" PARITY_REVISION_DIR="$revisions" \
    EXPECTED_PREVIEW_SERVICE_NAME="$PREVIEW_SERVICE" EXPECTED_REPOSITORY_ID="$REPOSITORY_ID" \
    EXPECTED_BASELINE_PRODUCTION_HEAD_SHA="$live_prod_head" \
    EXPECTED_BASELINE_PRODUCTION_INDEX_IMAGE="$live_prod_index" \
    EXPECTED_BASELINE_PRODUCTION_RUNNABLE_IMAGE="$live_prod_runnable" \
    "$PARITY_POLICY_ROOT/tools/ci/cloud-run-dhi-parity.sh" inspect-preview-routes
  if [ "$(output_value all_routes_candidate_parity "$outputs")" != true ]; then
    # The only non-current-workflow graph that maintenance may carry forward is
    # a sanitized, current-DHI baseline with zero tags under SEALED exposure.
    # This is the deliberately closed retirement state used during a platform
    # repin; it can never be reopened by this controller.
    [ "$desired_tag_count" -eq 0 ]
    [ "$(output_value sealed_baseline "$outputs")" = true ]
    [ "$(output_value dhi_parity_id "$outputs")" = "$DHI_PARITY_ID" ]
  fi
  revision_files=("$revisions"/*.json)
  revision_v2_files=("$revisions_v2"/*.json)
  [ -f "${revision_files[0]}" ] && [ -f "${revision_v2_files[0]}" ]
  if [ "$verify_graph" = true ]; then
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
    [ "$(output_value dhi_parity_id "$graph_outputs")" = "$(output_value dhi_parity_id "$outputs")" ]
  fi
  projections=("${revision_files[@]}" "${revision_v2_files[@]}" "$prod_service" "$prod_revision" "$prod_v2" "$prod_revision_v2")
  {
    jq -cS '{metadata:{name:.metadata.name,namespace:.metadata.namespace,generation:.metadata.generation,annotations:.metadata.annotations,labels:.metadata.labels},spec:.spec,status:{observedGeneration:.status.observedGeneration,traffic:.status.traffic,latestCreatedRevisionName:.status.latestCreatedRevisionName,latestReadyRevisionName:.status.latestReadyRevisionName,conditions:.status.conditions}}' "$service"
    jq -cS '{name,generation,observedGeneration,etag,ingress,invokerIamDisabled,defaultUriDisabled,traffic,trafficStatuses,latestReadyRevision,reconciling,terminalCondition,urls,uri,template,buildConfig}' "$service_v2"
    jq -cS '.' "$desired"
    jq -cS '.' "$policy"
    jq -cS '.' "${projections[@]}"
    find "$lifecycle" -mindepth 1 -maxdepth 1 -type f -name '*.json' -print | sort | while read -r file; do jq -cS '.' "$file"; done
  } | sha256sum | cut -d ' ' -f 1 > "$work/${suffix}-full.sha256"
  cp -- "$desired" "$work/${suffix}-desired.final.json"
  cp -- "$service_v2" "$work/${suffix}-service-v2.final.json"
  cp -- "$remove_tags" "$work/${suffix}-remove-tags.final"
}

# Missing preview service is a clean no-op. Any other initial read failure leaves
# the previously admitted state unchanged; no broad failure trap mutates it.
initial_error="$work/initial-error"
if ! gcloud run services describe "$PREVIEW_SERVICE" \
  --project="$PROJECT_ID" --region="$REGION" --format=json > "$work/initial-service.json" 2> "$initial_error"; then
  if grep -Eqi 'not[ _-]?found|could not be found|404' "$initial_error"; then
    echo "Shared preview service does not exist; nothing to maintain."
    exit 0
  fi
  cat "$initial_error" >&2
  exit 1
fi

set +e
(
  set -e
  capture_proposed before true
)
capture_status=$?
set -e
if [ "$capture_status" -ne 0 ]; then
  echo "Preview survivor graph could not be proven; acquiring durable poison before a traffic-preserving seal." >&2
  acquire_transition preview-emergency-seal
  seal_current || die "Preview survivor proof failed and exact-etag sealing could not be proven."
  mutated=false
  # Legacy service-local IAM drift is repairable under the marker. Re-capture
  # the complete SEALED graph after exact-policy convergence and continue only
  # if every route, production base, OCI graph, and PR lifecycle now proves.
  # Any non-repairable evidence failure retains the durable poison.
  set +e
  (
    set -e
    capture_proposed before true
  )
  repaired_status=$?
  set -e
  [ "$repaired_status" -eq 0 ] || exit "$capture_status"
fi
capture_proposed after false
cmp "$work/before-full.sha256" "$work/after-full.sha256" >/dev/null || die "Preview or production graph changed during remote OCI/lifecycle proof."

before_v2="$work/after-service-v2.final.json"
desired="$work/after-desired.final.json"
removed="$work/after-remove-tags.final"
current="$work/current.normalized.json"
next="$work/desired.normalized.json"
jq '.traffic // []' "$before_v2" > "$work/current.json"
normalize_v2_traffic "$work/current.json" > "$current"
normalize_v2_traffic "$desired" > "$next"
desired_tag_count="$(jq -r '[.[] | select((.tag // "") != "")] | length' "$desired")"
if [ "$desired_tag_count" -gt 0 ]; then target_exposure=open; else target_exposure=sealed; fi
current_exposure="$(exposure_of "$before_v2")"
traffic_changed=false
cmp "$current" "$next" >/dev/null || traffic_changed=true
exposure_changed=false
[ "$current_exposure" = "$target_exposure" ] || exposure_changed=true

if [ "$traffic_changed" = true ] || [ "$exposure_changed" = true ]; then
  if [ "$transition_acquired" = false ]; then
    acquire_transition preview-maintenance
  fi
  capture_proposed marker false
  cmp "$work/after-full.sha256" "$work/marker-full.sha256" >/dev/null ||
    die "Preview or production graph changed while the durable maintenance marker was acquired."
  normalize_v2_traffic "$work/marker-desired.final.json" > "$work/marker.normalized.json"
  cmp "$work/marker.normalized.json" "$next" >/dev/null
  before_v2="$work/marker-service-v2.final.json"
  patch_body="$work/controller-patch.json"

  if [ "$traffic_changed" = true ]; then
    # Every traffic write is atomically SEALED, even if the service was already
    # SEALED. A delayed write can never restore retired routes under OPEN.
    jq --slurpfile traffic "$desired" '{
      name,etag,traffic:$traffic[0],
      ingress:"INGRESS_TRAFFIC_INTERNAL_ONLY",
      invokerIamDisabled:false
    }' "$before_v2" > "$patch_body"
    update_mask=traffic,ingress,invokerIamDisabled
    mutation_arm=true
    patch_service "$patch_body" "$update_mask"
    mutation_arm=false
  elif [ "$target_exposure" = sealed ]; then
    jq '{name,etag,ingress:"INGRESS_TRAFFIC_INTERNAL_ONLY",invokerIamDisabled:false}' "$before_v2" > "$patch_body"
    mutation_arm=true
    patch_service "$patch_body" ingress,invokerIamDisabled
    mutation_arm=false
  fi

  # Prove the exact desired graph while SEALED before any exposure-only OPEN.
  capture_proposed sealed true
  capture_proposed sealed_after false
  cmp "$work/sealed-full.sha256" "$work/sealed_after-full.sha256" >/dev/null ||
    die "SEALED preview graph changed during post-mutation parity/lifecycle proof."
  normalize_v2_traffic "$work/sealed_after-desired.final.json" > "$work/sealed.normalized.json"
  cmp "$work/sealed.normalized.json" "$next" >/dev/null
  [ "$(exposure_of "$work/sealed_after-service-v2.final.json")" = sealed ]
  [ ! -s "$work/sealed_after-remove-tags.final" ]

  if [ "$target_exposure" = open ]; then
    jq --arg ingress "$OPEN_INGRESS" '{name,etag,ingress:$ingress,invokerIamDisabled:true}' \
      "$work/sealed_after-service-v2.final.json" > "$patch_body"
    mutation_arm=true
    patch_service "$patch_body" ingress,invokerIamDisabled
    mutation_arm=false
  fi
fi

capture_proposed admitted true
normalize_v2_traffic "$work/admitted-desired.final.json" > "$work/admitted.normalized.json"
cmp "$work/admitted.normalized.json" "$next" >/dev/null
[ "$(exposure_of "$work/admitted-service-v2.final.json")" = "$target_exposure" ]
[ ! -s "$work/admitted-remove-tags.final" ]

health_routes="$work/health-routes"
service_admitted="$work/admitted-service.json"
revisions_admitted="$work/admitted-revisions"
while IFS=$'\t' read -r tag revision url; do
  if [ "$REPOSITORY_ID" = 280932482 ]; then url="https://${tag}.${STABLE_PREVIEW_DOMAIN}"; fi
  nonce="$(jq -er '[.spec.containers[0].env[]? | select(.name == "PLATFORM_DEPLOY_NONCE") | .value] | if length == 1 then .[0] else error("invalid nonce") end | select(test("^[0-9a-f]{64}$"))' "$revisions_admitted/${revision}.json")"
  printf '%s\t%s\t%s\n' "$tag" "$url" "$nonce"
done < <(jq -r '.status.traffic[]? | select((.tag // "") | test("^pr-[1-9][0-9]*$")) | [.tag,.revisionName,.url] | @tsv' "$service_admitted") > "$health_routes"
if [ "$target_exposure" = open ]; then
  healthy=false
  for attempt in $(seq 1 30); do
    failures="$work/health-failures"
    : > "$failures"
    while IFS=$'\t' read -r tag url nonce; do
      (
        body="$work/health-${tag}.json"
        status="$(curl --silent --show-error --output "$body" --write-out '%{http_code}' --max-filesize 1024 --max-time 10 --proto '=https' "${url%/}/livez" 2>/dev/null || true)"
        if [ "$status" != 200 ] || ! jq -e -s --arg nonce "$nonce" 'length == 1 and .[0] == {deployment:$nonce,ok:true}' "$body" >/dev/null 2>&1; then
          echo "$tag" >> "$failures"
        fi
      ) &
    done < "$health_routes"
    wait
    if [ ! -s "$failures" ]; then healthy=true; break; fi
    [ "$attempt" -eq 30 ] || sleep 5
  done
  [ "$healthy" = true ]
  if [ "$PREVIEW_INGRESS" = all ]; then
    baseline_url="$(jq -er '.uri | select(type == "string" and startswith("https://"))' "$work/admitted-service-v2.final.json")"
    baseline_status="$(curl --silent --show-error --output "$work/baseline-body" --write-out '%{http_code}' --max-filesize 1024 --max-time 10 --proto '=https' "$baseline_url")"
    [ "$baseline_status" = 404 ] && [ ! -s "$work/baseline-body" ]
  fi
fi

capture_proposed health_after false
cmp "$work/admitted-full.sha256" "$work/health_after-full.sha256" >/dev/null || die "Preview graph or lifecycle changed during controller health validation."

if [ -s "$removed" ]; then
  removed_checks="$work/removed-checks"
  while IFS= read -r removed_tag; do
    [ -n "$removed_tag" ] || continue
    if [ "$REPOSITORY_ID" = 280932482 ]; then
      removed_url="https://${removed_tag}.${STABLE_PREVIEW_DOMAIN}"
    else
      removed_url="https://${removed_tag}---${PREVIEW_SERVICE}-${EXPECTED_PROJECT_NUMBER}.${REGION}.run.app"
    fi
    printf '%s\t%s\n' "$removed_tag" "$removed_url"
  done < "$removed" > "$removed_checks"
  removed_ok=false
  for attempt in $(seq 1 30); do
    failures="$work/removed-failures"
    : > "$failures"
    while IFS=$'\t' read -r removed_tag removed_url; do
      (
        status="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' --max-time 10 --proto '=https' "${removed_url%/}/livez" 2>/dev/null || true)"
        [ "$status" = 404 ] || echo "$removed_tag" >> "$failures"
      ) &
    done < "$removed_checks"
    wait
    if [ ! -s "$failures" ]; then removed_ok=true; break; fi
    [ "$attempt" -eq 30 ] || sleep 5
  done
  [ "$removed_ok" = true ]
fi

if [ "$transition_acquired" = true ]; then
  # Explicit normal-path release only after the mutation LRO, two complete
  # DHI/production/lifecycle brackets, route health, and removed-host proof.
  # Disarm every local Cloud Run cleanup path before GCS release. If release is
  # interrupted or its response is lost, no EXIT handler may mutate after the
  # marker might already have become clear.
  transition_acquired=false
  mutated=false
  mutation_arm=false
  ambiguous_mutation=false
  release_transition
fi
{
  echo "admitted=true"
  echo "exposure=$target_exposure"
  echo "removed-count=$(grep -c . "$removed" 2>/dev/null || true)"
} >> "${GITHUB_OUTPUT:?}"
