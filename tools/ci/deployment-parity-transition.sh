#!/bin/bash

set -euo pipefail

die() {
  echo "$*" >&2
  exit 1
}

readonly COMMAND="${1:-}"
[[ "$COMMAND" == acquire || "$COMMAND" == resume-prod || "$COMMAND" == resume-seal || "$COMMAND" == release || "$COMMAND" == assert-clear ]] ||
  die "usage: deployment-parity-transition.sh {acquire|resume-prod|resume-seal|release|assert-clear}"

readonly PROJECT_ID="${PROJECT_ID:?}"
readonly REPOSITORY_ID="${REPOSITORY_ID:-${EXPECTED_REPOSITORY_ID:-}}"
readonly RUNNER_TEMP="${RUNNER_TEMP:?}"
readonly TRANSITION_BUCKET="${TRANSITION_BUCKET:-${PROJECT_ID}-deployment-parity-state}"
readonly TRANSITION_OBJECT="${TRANSITION_OBJECT:-deployment-parity-transition}"
readonly TRANSITION_LEASE_FILE="${TRANSITION_LEASE_FILE:-${RUNNER_TEMP}/deployment-parity-transition-lease.json}"

[[ "$PROJECT_ID" =~ ^[a-z][a-z0-9-]{4,29}$ ]]
[[ "$REPOSITORY_ID" =~ ^(1255553151|711292980|1025243085|280932482)$ ]]
[[ "$TRANSITION_BUCKET" =~ ^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$ ]]
[[ "$TRANSITION_OBJECT" =~ ^[a-z0-9][a-z0-9._-]{0,127}$ ]]
[[ "$TRANSITION_LEASE_FILE" == "$RUNNER_TEMP"/* ]]

umask 077
work="$(mktemp -d "${RUNNER_TEMP}/deployment-parity-transition.XXXXXX")"
header="$work/rest-header"
object_json="$work/object.json"
request_json="$work/request.json"
response_json="$work/response.json"

cleanup() {
  status=$?
  set +e
  if [[ "$work" == "${RUNNER_TEMP}/deployment-parity-transition."* ]] &&
     [ -d "$work" ] && [ ! -L "$work" ]; then
    find "$work" -depth -delete
  fi
  trap - EXIT
  exit "$status"
}
trap cleanup EXIT

if [ -n "${ACCESS_TOKEN:-}" ]; then
  printf 'Authorization: Bearer %s\n' "$ACCESS_TOKEN" > "$header"
else
  gcloud auth print-access-token | awk 'NF == 1 {print "Authorization: Bearer " $0}' > "$header"
fi
[ "$(wc -l < "$header" | tr -d ' ')" = 1 ]

readonly OBJECT_URL="https://storage.googleapis.com/storage/v1/b/${TRANSITION_BUCKET}/o/${TRANSITION_OBJECT}"

fetch_object() {
  local destination="$1" status
  status="$(curl --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
    --header "@$header" --output "$destination" --write-out '%{http_code}' \
    "${OBJECT_URL}?fields=bucket,name,generation,metageneration,metadata")"
  [ "$status" = 200 ] || die "Deployment parity transition state read failed with HTTP ${status}."
  jq -e --arg bucket "$TRANSITION_BUCKET" --arg object "$TRANSITION_OBJECT" --arg repository "$REPOSITORY_ID" '
    .bucket == $bucket and .name == $object and
    (.generation | type == "string" and test("^[1-9][0-9]*$")) and
    (.metageneration | type == "string" and test("^[1-9][0-9]*$")) and
    (.metadata | type == "object") and
    .metadata.version == "1" and .metadata["repository-id"] == $repository and
    (.metadata.state | type == "string")
  ' "$destination" >/dev/null
}

patch_metadata() {
  local generation="$1" metageneration="$2" source="$3" destination="$4" status curl_status
  curl_status=0
  status="$(curl --silent --show-error --connect-timeout 10 --max-time 30 --proto '=https' --tlsv1.2 \
    --request PATCH --header "@$header" --header 'Content-Type: application/json' \
    --data-binary "@$source" --output "$destination" --write-out '%{http_code}' \
    "${OBJECT_URL}?ifGenerationMatch=${generation}&ifMetagenerationMatch=${metageneration}&fields=bucket,name,generation,metageneration,metadata")" || curl_status=$?
  if [ "$curl_status" -ne 0 ]; then return 2; fi
  if [ "$status" = 200 ]; then return 0; fi
  if [ "$status" = 409 ] || [ "$status" = 412 ]; then return 3; fi
  echo "Deployment parity transition metadata update failed with HTTP ${status}." >&2
  return 1
}

case "$COMMAND" in
  assert-clear)
    fetch_object "$object_json"
    jq -e '
      (.metadata | keys | sort) == ["repository-id","state","version"] and
      .metadata.state == "clear"
    ' "$object_json" >/dev/null || die "Deployment parity transition state is poisoned; manual recovery is required."
    ;;

  acquire)
    readonly TRANSITION_KIND="${TRANSITION_KIND:?}"
    readonly EXPECTED_PLATFORM_WORKFLOW_SHA="${EXPECTED_PLATFORM_WORKFLOW_SHA:?}"
    readonly DHI_PARITY_ID="${DHI_PARITY_ID:?}"
    readonly GITHUB_RUN_ID="${GITHUB_RUN_ID:?}"
    readonly GITHUB_RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:?}"
    case "$TRANSITION_KIND" in
      preview-admission|preview-maintenance|preview-emergency-seal|prod-dhi-transition) ;;
      *) die "Unknown deployment parity transition kind." ;;
    esac
    [[ "$EXPECTED_PLATFORM_WORKFLOW_SHA" =~ ^[0-9a-f]{40}$ ]]
    [[ "$DHI_PARITY_ID" =~ ^[0-9a-z]{50}$ ]]
    [[ "$GITHUB_RUN_ID" =~ ^[1-9][0-9]*$ ]]
    [[ "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]]
    fetch_object "$object_json"
    jq -e '
      (.metadata | keys | sort) == ["repository-id","state","version"] and
      .metadata.state == "clear"
    ' "$object_json" >/dev/null || die "Another or ambiguous deployment parity transition is active; refusing unsafe mutation."
    generation="$(jq -er '.generation' "$object_json")"
    metageneration="$(jq -er '.metageneration' "$object_json")"
    nonce="$(printf '%s' "${PROJECT_ID}:${REPOSITORY_ID}:${GITHUB_RUN_ID}:${GITHUB_RUN_ATTEMPT}:$$:${RANDOM}:${RANDOM}" | sha256sum | cut -d ' ' -f 1)"
    jq -n --arg repository "$REPOSITORY_ID" --arg state "$TRANSITION_KIND" \
      --arg nonce "$nonce" --arg workflow "$EXPECTED_PLATFORM_WORKFLOW_SHA" \
      --arg run "$GITHUB_RUN_ID" --arg attempt "$GITHUB_RUN_ATTEMPT" --arg parity "$DHI_PARITY_ID" '{metadata:{
        version:"1",
        "repository-id":$repository,
        state:$state,
        nonce:$nonce,
        "platform-workflow-sha":$workflow,
        "github-run-id":$run,
        "github-run-attempt":$attempt,
        "dhi-parity-id":$parity
      }}' > "$request_json"
    acquired=false
    for attempt in $(seq 1 5); do
      if patch_metadata "$generation" "$metageneration" "$request_json" "$response_json"; then
        patch_status=0
      else
        patch_status=$?
      fi
      if [ "$patch_status" -eq 0 ]; then
        acquired=true
        break
      fi
      # GCS metadata reads are strongly consistent. On a lost response or a
      # precondition failure, retry only this exact nonce/precondition and
      # authorize mutation solely after observing the exact target metadata.
      fetch_object "$object_json"
      if jq -e --argjson expected "$(<"$request_json")" '
        .metadata == $expected.metadata
      ' "$object_json" >/dev/null; then
        cp -- "$object_json" "$response_json"
        acquired=true
        break
      fi
      if ! jq -e --arg generation "$generation" --arg metageneration "$metageneration" '
        .generation == $generation and .metageneration == $metageneration and
        (.metadata | keys | sort) == ["repository-id","state","version"] and
        .metadata.state == "clear"
      ' "$object_json" >/dev/null; then
        die "Deployment parity transition CAS was not observed at its exact nonce; no unsafe mutation is authorized."
      fi
      sleep 1
    done
    [ "$acquired" = true ] || die "Deployment parity transition acquire remained ambiguous; no unsafe mutation is authorized."
    jq -e --arg bucket "$TRANSITION_BUCKET" --arg object "$TRANSITION_OBJECT" \
      --arg generation "$generation" --arg repository "$REPOSITORY_ID" \
      --arg state "$TRANSITION_KIND" --arg nonce "$nonce" \
      --arg workflow "$EXPECTED_PLATFORM_WORKFLOW_SHA" --arg parity "$DHI_PARITY_ID" \
      --arg run "$GITHUB_RUN_ID" --arg attempt "$GITHUB_RUN_ATTEMPT" \
      --arg previous_metageneration "$metageneration" '
      .bucket == $bucket and .name == $object and .generation == $generation and
      (.metageneration | type == "string" and test("^[1-9][0-9]*$") and
        (tonumber > ($previous_metageneration | tonumber))) and
      (.metadata | keys | sort) == ["dhi-parity-id","github-run-attempt","github-run-id","nonce","platform-workflow-sha","repository-id","state","version"] and
      .metadata.version == "1" and .metadata["repository-id"] == $repository and
      .metadata.state == $state and .metadata.nonce == $nonce and
      .metadata["platform-workflow-sha"] == $workflow and
      .metadata["dhi-parity-id"] == $parity and
      .metadata["github-run-id"] == $run and .metadata["github-run-attempt"] == $attempt
    ' "$response_json" >/dev/null
    jq -cS --arg bucket "$TRANSITION_BUCKET" --arg object "$TRANSITION_OBJECT" '{
      bucket:$bucket,
      object:$object,
      generation,
      metageneration,
      metadata
    }' "$response_json" > "$TRANSITION_LEASE_FILE"
    chmod 0600 "$TRANSITION_LEASE_FILE"
    ;;

  resume-seal)
    # A preview poison can be recovered only by the same active workflow and
    # immutable DHI epoch. Recovery rekeys every allowed preview mutation kind
    # to the narrower emergency-seal state; the caller may then perform only a
    # fresh traffic-preserving SEALED operation and exact IAM convergence.
    readonly EXPECTED_PLATFORM_WORKFLOW_SHA="${EXPECTED_PLATFORM_WORKFLOW_SHA:?}"
    readonly DHI_PARITY_ID="${DHI_PARITY_ID:?}"
    readonly GITHUB_RUN_ID="${GITHUB_RUN_ID:?}"
    readonly GITHUB_RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:?}"
    [[ "$EXPECTED_PLATFORM_WORKFLOW_SHA" =~ ^[0-9a-f]{40}$ ]]
    [[ "$DHI_PARITY_ID" =~ ^[0-9a-z]{50}$ ]]
    [[ "$GITHUB_RUN_ID" =~ ^[1-9][0-9]*$ ]]
    [[ "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]]
    fetch_object "$object_json"
    jq -e --arg repository "$REPOSITORY_ID" --arg workflow "$EXPECTED_PLATFORM_WORKFLOW_SHA" --arg parity "$DHI_PARITY_ID" '
      (.metadata | keys | sort) == ["dhi-parity-id","github-run-attempt","github-run-id","nonce","platform-workflow-sha","repository-id","state","version"] and
      .metadata.version == "1" and .metadata["repository-id"] == $repository and
      (.metadata.state | IN("preview-admission","preview-maintenance","preview-emergency-seal")) and
      .metadata["platform-workflow-sha"] == $workflow and
      .metadata["dhi-parity-id"] == $parity and
      (.metadata.nonce | type == "string" and test("^[0-9a-f]{64}$"))
    ' "$object_json" >/dev/null || die "Existing poison is not an exact recoverable preview transition."
    generation="$(jq -er '.generation' "$object_json")"
    metageneration="$(jq -er '.metageneration' "$object_json")"
    nonce="$(printf '%s' "${PROJECT_ID}:${REPOSITORY_ID}:${GITHUB_RUN_ID}:${GITHUB_RUN_ATTEMPT}:resume-seal:$$:${RANDOM}:${RANDOM}" | sha256sum | cut -d ' ' -f 1)"
    jq -n --arg repository "$REPOSITORY_ID" --arg nonce "$nonce" \
      --arg workflow "$EXPECTED_PLATFORM_WORKFLOW_SHA" --arg run "$GITHUB_RUN_ID" \
      --arg attempt "$GITHUB_RUN_ATTEMPT" --arg parity "$DHI_PARITY_ID" '{metadata:{
        version:"1","repository-id":$repository,state:"preview-emergency-seal",nonce:$nonce,
        "platform-workflow-sha":$workflow,"github-run-id":$run,
        "github-run-attempt":$attempt,"dhi-parity-id":$parity
      }}' > "$request_json"
    resumed=false
    for attempt in $(seq 1 5); do
      if patch_metadata "$generation" "$metageneration" "$request_json" "$response_json"; then
        patch_status=0
      else
        patch_status=$?
      fi
      if [ "$patch_status" -eq 0 ]; then resumed=true; break; fi
      fetch_object "$object_json"
      if jq -e --argjson expected "$(<"$request_json")" '.metadata == $expected.metadata' "$object_json" >/dev/null; then
        cp -- "$object_json" "$response_json"
        resumed=true
        break
      fi
      if ! jq -e --arg generation "$generation" --arg metageneration "$metageneration" '
        .generation == $generation and .metageneration == $metageneration
      ' "$object_json" >/dev/null; then
        die "Preview seal recovery CAS was not observed at its exact nonce."
      fi
      sleep 1
    done
    [ "$resumed" = true ] || die "Preview seal recovery remained ambiguous."
    jq -e --arg bucket "$TRANSITION_BUCKET" --arg object "$TRANSITION_OBJECT" \
      --arg generation "$generation" --arg repository "$REPOSITORY_ID" \
      --arg nonce "$nonce" --arg workflow "$EXPECTED_PLATFORM_WORKFLOW_SHA" \
      --arg parity "$DHI_PARITY_ID" --arg run "$GITHUB_RUN_ID" \
      --arg attempt "$GITHUB_RUN_ATTEMPT" --arg previous_metageneration "$metageneration" '
      .bucket == $bucket and .name == $object and .generation == $generation and
      (.metageneration | type == "string" and test("^[1-9][0-9]*$") and
        (tonumber > ($previous_metageneration | tonumber))) and
      (.metadata | keys | sort) == ["dhi-parity-id","github-run-attempt","github-run-id","nonce","platform-workflow-sha","repository-id","state","version"] and
      .metadata.version == "1" and .metadata["repository-id"] == $repository and
      .metadata.state == "preview-emergency-seal" and .metadata.nonce == $nonce and
      .metadata["platform-workflow-sha"] == $workflow and .metadata["dhi-parity-id"] == $parity and
      .metadata["github-run-id"] == $run and .metadata["github-run-attempt"] == $attempt
    ' "$response_json" >/dev/null
    jq -cS --arg bucket "$TRANSITION_BUCKET" --arg object "$TRANSITION_OBJECT" '{
      bucket:$bucket,object:$object,generation,metageneration,metadata
    }' "$response_json" > "$TRANSITION_LEASE_FILE"
    chmod 0600 "$TRANSITION_LEASE_FILE"
    ;;

  resume-prod)
    # Recovery is intentionally limited to the same active workflow and DHI
    # epoch. The caller must first remotely prove that production already serves
    # this candidate DHI and that preview is SEALED with zero tags. We then
    # strongly CAS-rekey the existing prod poison; unrelated, preview, old-SHA,
    # or different-DHI leases remain nonrecoverable.
    readonly EXPECTED_PLATFORM_WORKFLOW_SHA="${EXPECTED_PLATFORM_WORKFLOW_SHA:?}"
    readonly DHI_PARITY_ID="${DHI_PARITY_ID:?}"
    readonly GITHUB_RUN_ID="${GITHUB_RUN_ID:?}"
    readonly GITHUB_RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:?}"
    [[ "$EXPECTED_PLATFORM_WORKFLOW_SHA" =~ ^[0-9a-f]{40}$ ]]
    [[ "$DHI_PARITY_ID" =~ ^[0-9a-z]{50}$ ]]
    [[ "$GITHUB_RUN_ID" =~ ^[1-9][0-9]*$ ]]
    [[ "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]]
    fetch_object "$object_json"
    jq -e --arg repository "$REPOSITORY_ID" --arg workflow "$EXPECTED_PLATFORM_WORKFLOW_SHA" --arg parity "$DHI_PARITY_ID" '
      (.metadata | keys | sort) == ["dhi-parity-id","github-run-attempt","github-run-id","nonce","platform-workflow-sha","repository-id","state","version"] and
      .metadata.version == "1" and .metadata["repository-id"] == $repository and
      .metadata.state == "prod-dhi-transition" and
      .metadata["platform-workflow-sha"] == $workflow and
      .metadata["dhi-parity-id"] == $parity and
      (.metadata.nonce | type == "string" and test("^[0-9a-f]{64}$"))
    ' "$object_json" >/dev/null || die "Existing poison is not the exact recoverable production DHI epoch."
    generation="$(jq -er '.generation' "$object_json")"
    metageneration="$(jq -er '.metageneration' "$object_json")"
    nonce="$(printf '%s' "${PROJECT_ID}:${REPOSITORY_ID}:${GITHUB_RUN_ID}:${GITHUB_RUN_ATTEMPT}:resume:$$:${RANDOM}:${RANDOM}" | sha256sum | cut -d ' ' -f 1)"
    jq -n --arg repository "$REPOSITORY_ID" --arg nonce "$nonce" \
      --arg workflow "$EXPECTED_PLATFORM_WORKFLOW_SHA" --arg run "$GITHUB_RUN_ID" \
      --arg attempt "$GITHUB_RUN_ATTEMPT" --arg parity "$DHI_PARITY_ID" '{metadata:{
        version:"1","repository-id":$repository,state:"prod-dhi-transition",nonce:$nonce,
        "platform-workflow-sha":$workflow,"github-run-id":$run,
        "github-run-attempt":$attempt,"dhi-parity-id":$parity
      }}' > "$request_json"
    resumed=false
    for attempt in $(seq 1 5); do
      if patch_metadata "$generation" "$metageneration" "$request_json" "$response_json"; then
        patch_status=0
      else
        patch_status=$?
      fi
      if [ "$patch_status" -eq 0 ]; then resumed=true; break; fi
      fetch_object "$object_json"
      if jq -e --argjson expected "$(<"$request_json")" '.metadata == $expected.metadata' "$object_json" >/dev/null; then
        cp -- "$object_json" "$response_json"
        resumed=true
        break
      fi
      if ! jq -e --arg generation "$generation" --arg metageneration "$metageneration" '
        .generation == $generation and .metageneration == $metageneration
      ' "$object_json" >/dev/null; then
        die "Production DHI transition resume CAS was not observed at its exact nonce."
      fi
      sleep 1
    done
    [ "$resumed" = true ] || die "Production DHI transition resume remained ambiguous."
    jq -e --arg bucket "$TRANSITION_BUCKET" --arg object "$TRANSITION_OBJECT" \
      --arg generation "$generation" --arg repository "$REPOSITORY_ID" \
      --arg nonce "$nonce" --arg workflow "$EXPECTED_PLATFORM_WORKFLOW_SHA" \
      --arg parity "$DHI_PARITY_ID" --arg run "$GITHUB_RUN_ID" \
      --arg attempt "$GITHUB_RUN_ATTEMPT" --arg previous_metageneration "$metageneration" '
      .bucket == $bucket and .name == $object and .generation == $generation and
      (.metageneration | type == "string" and test("^[1-9][0-9]*$") and
        (tonumber > ($previous_metageneration | tonumber))) and
      (.metadata | keys | sort) == ["dhi-parity-id","github-run-attempt","github-run-id","nonce","platform-workflow-sha","repository-id","state","version"] and
      .metadata.version == "1" and .metadata["repository-id"] == $repository and
      .metadata.state == "prod-dhi-transition" and .metadata.nonce == $nonce and
      .metadata["platform-workflow-sha"] == $workflow and .metadata["dhi-parity-id"] == $parity and
      .metadata["github-run-id"] == $run and .metadata["github-run-attempt"] == $attempt
    ' "$response_json" >/dev/null
    jq -cS --arg bucket "$TRANSITION_BUCKET" --arg object "$TRANSITION_OBJECT" '{
      bucket:$bucket,object:$object,generation,metageneration,metadata
    }' "$response_json" > "$TRANSITION_LEASE_FILE"
    chmod 0600 "$TRANSITION_LEASE_FILE"
    ;;

  release)
    [ -f "$TRANSITION_LEASE_FILE" ] && [ ! -L "$TRANSITION_LEASE_FILE" ] ||
      die "Deployment parity transition lease is missing or unsafe."
    jq -e --arg bucket "$TRANSITION_BUCKET" --arg object "$TRANSITION_OBJECT" --arg repository "$REPOSITORY_ID" '
      .bucket == $bucket and .object == $object and
      (.generation | type == "string" and test("^[1-9][0-9]*$")) and
      (.metageneration | type == "string" and test("^[1-9][0-9]*$")) and
      .metadata.version == "1" and .metadata["repository-id"] == $repository and
      (.metadata | keys | sort) == ["dhi-parity-id","github-run-attempt","github-run-id","nonce","platform-workflow-sha","repository-id","state","version"] and
      (.metadata.state | IN("preview-admission","preview-maintenance","preview-emergency-seal","prod-dhi-transition")) and
      (.metadata.nonce | type == "string" and test("^[0-9a-f]{64}$")) and
      (.metadata["platform-workflow-sha"] | type == "string" and test("^[0-9a-f]{40}$")) and
      (.metadata["dhi-parity-id"] | type == "string" and test("^[0-9a-z]{50}$"))
    ' "$TRANSITION_LEASE_FILE" >/dev/null
    fetch_object "$object_json"
    jq -e --slurpfile lease "$TRANSITION_LEASE_FILE" '
      .generation == $lease[0].generation and
      .metageneration == $lease[0].metageneration and
      .metadata == $lease[0].metadata
    ' "$object_json" >/dev/null || die "Deployment parity transition lease changed; refusing an ABA-unsafe release."
    generation="$(jq -er '.generation' "$object_json")"
    metageneration="$(jq -er '.metageneration' "$object_json")"
    # Objects.patch merges custom metadata; null is required to delete each
    # transient lease key rather than silently leaving an uncleared poison.
    jq -n --arg repository "$REPOSITORY_ID" '{metadata:{
      version:"1",
      "repository-id":$repository,
      state:"clear",
      nonce:null,
      "platform-workflow-sha":null,
      "github-run-id":null,
      "github-run-attempt":null,
      "dhi-parity-id":null
    }}' > "$request_json"
    released=false
    for attempt in $(seq 1 5); do
      if patch_metadata "$generation" "$metageneration" "$request_json" "$response_json"; then
        patch_status=0
      else
        patch_status=$?
      fi
      if [ "$patch_status" -eq 0 ]; then
        released=true
        break
      fi
      fetch_object "$object_json"
      if jq -e --arg generation "$generation" --arg previous_metageneration "$metageneration" --arg repository "$REPOSITORY_ID" '
        .generation == $generation and
        (.metageneration | tonumber) > ($previous_metageneration | tonumber) and
        .metadata == {version:"1","repository-id":$repository,state:"clear"}
      ' "$object_json" >/dev/null; then
        cp -- "$object_json" "$response_json"
        released=true
        break
      fi
      if ! jq -e --slurpfile lease "$TRANSITION_LEASE_FILE" '
        .generation == $lease[0].generation and
        .metageneration == $lease[0].metageneration and
        .metadata == $lease[0].metadata
      ' "$object_json" >/dev/null; then
        die "Deployment parity transition release met an unrelated metadata state; the poison remains authoritative."
      fi
      sleep 1
    done
    [ "$released" = true ] || die "Deployment parity transition release remained ambiguous; the poison remains authoritative."
    jq -e --arg generation "$generation" --arg repository "$REPOSITORY_ID" '
      .generation == $generation and
      (.metageneration | type == "string" and test("^[1-9][0-9]*$")) and
      .metadata == {version:"1","repository-id":$repository,state:"clear"}
    ' "$response_json" >/dev/null
    rm -f -- "$TRANSITION_LEASE_FILE"
    ;;
esac
