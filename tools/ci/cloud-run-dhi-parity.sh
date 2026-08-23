#!/bin/bash

set -euo pipefail

readonly DHI_PARITY_ID=1a4cho1elzg84pavos8mbanvvpmkieiht7kyhpjdofzpivf3k8

die() {
  echo "$*" >&2
  exit 1
}

sha256_file() {
  sha256sum "$1" | cut -d ' ' -f 1
}

require_json() {
  local path="$1"
  test -f "$path" && test ! -L "$path" || die "Cloud Run evidence is not a regular file."
  local size
  size="$(stat -c %s "$path" 2>/dev/null || stat -f %z "$path")"
  test "$size" -le 1048576 || die "Cloud Run evidence exceeds its byte cap."
  jq -e . "$path" >/dev/null || die "Cloud Run evidence is not JSON."
}

prove_production() {
  local service="${PARITY_SERVICE_JSON:?}" revision="${PARITY_REVISION_JSON:?}"
  local service_name="${EXPECTED_SERVICE_NAME:?}" project_number="${EXPECTED_PROJECT_NUMBER:?}"
  local repository_id="${EXPECTED_REPOSITORY_ID:?}" image_name="${EXPECTED_PRODUCTION_IMAGE_NAME:?}"
  [[ "$service_name" =~ ^[a-z][a-z0-9-]{0,62}$ ]] || die "Expected production service name is invalid."
  [[ "$project_number" =~ ^[1-9][0-9]*$ ]] || die "Expected project number is invalid."
  [[ "$repository_id" =~ ^[1-9][0-9]*$ ]] || die "Expected repository id is invalid."
  [[ "$image_name" =~ ^us-east4-docker\.pkg\.dev/[a-z0-9-]+/[a-z0-9-]+/[a-z0-9-]+$ ]] || die "Expected production image name is invalid."
  require_json "$service"
  require_json "$revision"

  jq -e --arg name "$service_name" --arg namespace "$project_number" --arg parity "$DHI_PARITY_ID" '
    .apiVersion == "serving.knative.dev/v1" and .kind == "Service" and
    .metadata.name == $name and .metadata.namespace == $namespace and
    .metadata.generation == .status.observedGeneration and
    .metadata.labels.environment == "production" and
    .metadata.labels["managed-by"] == "github-actions" and
    .metadata.labels["dhi-parity-id"] == $parity and
    ([.metadata.annotations // {}, .spec.template.metadata.annotations // {}]
      | map(keys[] | select(test("(^|/)(base-images|build-base-image|build-enable-automatic-updates|enable-automatic-updates|base-image-update)$")))
      | length) == 0 and
    ((.spec.template.spec.runtimeClassName // "") == "") and
    .status.latestCreatedRevisionName == .status.latestReadyRevisionName and
    (.status.latestReadyRevisionName | test(("^" + $name + "-[a-z0-9-]+$"))) and
    ([.status.conditions[]? | select((.type == "Ready" or .type == "ConfigurationsReady" or .type == "RoutesReady") and .status == "True")] | length) == 3 and
    .spec.traffic == [{latestRevision:true,percent:100}] and
    (.status.traffic | length) == 1 and
    .status.traffic[0].latestRevision == true and .status.traffic[0].percent == 100 and
    .status.traffic[0].revisionName == .status.latestReadyRevisionName and
    (.status.traffic[0] | has("tag") | not)
  ' "$service" >/dev/null || die "Production is not exactly one healthy, untagged, 100%-served latest revision."

  local revision_name
  revision_name="$(jq -er '.status.latestReadyRevisionName' "$service")"
  jq -e --arg name "$revision_name" --arg namespace "$project_number" --arg service "$service_name" \
    --arg repository_id "$repository_id" --arg image_name "$image_name" --arg parity "$DHI_PARITY_ID" '
    def exact_value($name):
      [.spec.containers[0].env[]? | select(.name == $name and (keys | sort) == ["name","value"]) | .value]
      | if length == 1 then .[0] else error("missing or duplicate immutable image identity") end;
    (exact_value("PLATFORM_IMAGE_INDEX_DIGEST")) as $index |
    (exact_value("PLATFORM_IMAGE_RUNNABLE_DIGEST")) as $runnable |
    .apiVersion == "serving.knative.dev/v1" and .kind == "Revision" and
    .metadata.name == $name and .metadata.namespace == $namespace and
    .metadata.labels.environment == "production" and
    .metadata.labels["managed-by"] == "github-actions" and
    .metadata.labels["serving.knative.dev/service"] == $service and
    .metadata.labels["github-repository-id"] == $repository_id and
    .metadata.labels["dhi-parity-id"] == $parity and
    (.metadata.labels["git-head-sha"] | test("^[0-9a-f]{40}$")) and
    (.metadata.labels["platform-workflow-sha"] | test("^[0-9a-f]{40}$")) and
    ([.metadata.annotations // {} | keys[] | select(test("(^|/)(base-images|build-base-image|build-enable-automatic-updates|enable-automatic-updates|base-image-update)$"))] | length) == 0 and
    ((.spec.runtimeClassName // "") == "") and
    .metadata.generation == .status.observedGeneration and
    ([.status.conditions[]? | select(.type == "Ready" and .status == "True")] | length) == 1 and
    (.spec.containers | length) == 1 and
    ($index | test("^sha256:[0-9a-f]{64}$")) and
    ($runnable | test("^sha256:[0-9a-f]{64}$")) and
    .spec.containers[0].image == ($image_name + "@" + $runnable) and
    .status.imageDigest == .spec.containers[0].image
  ' "$revision" >/dev/null || die "The exact 100%-served production revision lacks a bound OCI index, runnable child, or trusted DHI provenance metadata."

  local index_digest runnable_digest
  index_digest="$(jq -er '[.spec.containers[0].env[]? | select(.name == "PLATFORM_IMAGE_INDEX_DIGEST") | .value] | if length == 1 then .[0] else error("invalid index identity") end' "$revision")"
  runnable_digest="$(jq -er '[.spec.containers[0].env[]? | select(.name == "PLATFORM_IMAGE_RUNNABLE_DIGEST") | .value] | if length == 1 then .[0] else error("invalid runnable identity") end' "$revision")"

  local service_projection revision_projection
  service_projection="${RUNNER_TEMP:?}/cloud-run-production-service-projection-$RANDOM.json"
  revision_projection="${RUNNER_TEMP:?}/cloud-run-production-revision-projection-$RANDOM.json"
  jq -cS '{
    generation:.metadata.generation,
    labels:{dhiParityId:.metadata.labels["dhi-parity-id"],environment:.metadata.labels.environment,managedBy:.metadata.labels["managed-by"]},
    latestCreatedRevisionName:.status.latestCreatedRevisionName,
    latestReadyRevisionName:.status.latestReadyRevisionName,
    name:.metadata.name,
    namespace:.metadata.namespace,
    observedGeneration:.status.observedGeneration,
    specTraffic:.spec.traffic,
    statusTraffic:.status.traffic
  }' "$service" > "$service_projection"
  jq -cS '{
    generation:.metadata.generation,
    image:.spec.containers[0].image,
    imageIdentity:[.spec.containers[0].env[]? | select(.name == "PLATFORM_IMAGE_INDEX_DIGEST" or .name == "PLATFORM_IMAGE_RUNNABLE_DIGEST") | {name,value}] | sort_by(.name),
    labels:{
      dhiParityId:.metadata.labels["dhi-parity-id"],
      environment:.metadata.labels.environment,
      gitHeadSha:.metadata.labels["git-head-sha"],
      managedBy:.metadata.labels["managed-by"],
      platformWorkflowSha:.metadata.labels["platform-workflow-sha"],
      repositoryId:.metadata.labels["github-repository-id"],
      service:.metadata.labels["serving.knative.dev/service"]
    },
    name:.metadata.name,
    namespace:.metadata.namespace,
    observedGeneration:.status.observedGeneration,
    statusImageDigest:.status.imageDigest
  }' "$revision" > "$revision_projection"
  {
    echo "dhi_parity_id=$DHI_PARITY_ID"
    echo "live_production_head_sha=$(jq -er '.metadata.labels["git-head-sha"]' "$revision")"
    echo "live_production_index_digest=$index_digest"
    echo "live_production_index_image=${image_name}@${index_digest}"
    echo "live_production_runnable_digest=$runnable_digest"
    echo "live_production_runnable_image=${image_name}@${runnable_digest}"
    echo "production_revision=$revision_name"
    echo "revision_projection_sha256=$(sha256_file "$revision_projection")"
    echo "service_projection_sha256=$(sha256_file "$service_projection")"
  } >> "${GITHUB_OUTPUT:?}"
}

validate_preview_routes() {
  local strict="$1"
  local service="${PARITY_SERVICE_JSON:?}" revision_dir="${PARITY_REVISION_DIR:?}"
  local service_name="${EXPECTED_PREVIEW_SERVICE_NAME:?}" project_number="${EXPECTED_PROJECT_NUMBER:?}"
  local repository_id="${EXPECTED_REPOSITORY_ID:?}" image_name="${EXPECTED_PREVIEW_IMAGE_NAME:?}"
  local production_image_name="${EXPECTED_PRODUCTION_IMAGE_NAME:?}"
  local runtime_service_account="${EXPECTED_PREVIEW_RUNTIME_SERVICE_ACCOUNT:?}"
  local platform_workflow_sha="${EXPECTED_PLATFORM_WORKFLOW_SHA:?}"
  [[ "$service_name" =~ ^[a-z][a-z0-9-]{0,62}$ ]] || die "Expected preview service name is invalid."
  [[ "$project_number" =~ ^[1-9][0-9]*$ ]] || die "Expected project number is invalid."
  [[ "$repository_id" =~ ^[1-9][0-9]*$ ]] || die "Expected repository id is invalid."
  [[ "$image_name" =~ ^us-east4-docker\.pkg\.dev/[a-z0-9-]+/[a-z0-9-]+/[a-z0-9-]+$ ]] || die "Expected preview image name is invalid."
  [[ "$production_image_name" =~ ^us-east4-docker\.pkg\.dev/[a-z0-9-]+/[a-z0-9-]+/[a-z0-9-]+$ ]] || die "Expected production image name is invalid."
  [[ "$runtime_service_account" =~ ^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$ ]] || die "Expected preview runtime service account is invalid."
  [[ "$platform_workflow_sha" =~ ^[0-9a-f]{40}$ ]] || die "Expected platform workflow SHA is invalid."
  test -d "$revision_dir" && test ! -L "$revision_dir" || die "Preview revision evidence directory is invalid."
  require_json "$service"
  local ingress invoker_iam_disabled
  ingress="$(jq -er '.metadata.annotations["run.googleapis.com/ingress"] | select(. == "all" or . == "internal" or . == "internal-and-cloud-load-balancing")' "$service")"
  invoker_iam_disabled="$(jq -er '(.metadata.annotations["run.googleapis.com/invoker-iam-disabled"] // "false") | select(. == "true" or . == "false")' "$service")"
  [[ "$strict" == true || "$strict" == false ]] || die "Preview validation mode is invalid."
  jq -e --arg name "$service_name" --arg namespace "$project_number" --argjson strict "$strict" '
    (.status.traffic[] | select(has("tag") | not) | .revisionName) as $defaultRevision |
    .apiVersion == "serving.knative.dev/v1" and .kind == "Service" and
    .metadata.name == $name and .metadata.namespace == $namespace and
    .metadata.generation == .status.observedGeneration and
    ([.metadata.annotations // {}, .spec.template.metadata.annotations // {}]
      | map(keys[] | select(test("(^|/)(base-images|build-base-image|build-enable-automatic-updates|enable-automatic-updates|base-image-update)$")))
      | length) == 0 and
    ((.spec.template.spec.runtimeClassName // "") == "") and
    ([.status.conditions[]? | select((.type == "Ready" or .type == "ConfigurationsReady" or .type == "RoutesReady") and .status == "True")] | length) == 3 and
    ([.status.traffic[]? | select(has("tag") | not)] | length) == 1 and
    (.status.traffic[] | select(has("tag") | not) | .percent) == 100 and
    ($defaultRevision | test(("^" + $name + "-[a-z0-9-]+$"))) and
    (
      (
        ([.spec.traffic[]? | select(has("tag") | not)] | length) == 1 and
        (.spec.traffic[] | select(has("tag") | not) | .percent) == 100 and
        (.status.traffic[] | select(has("tag") | not) | .revisionName) ==
          (.spec.traffic[] | select(has("tag") | not) | .revisionName) and
        all(.spec.traffic[]?; has("revisionName") and ((.latestRevision // false) == false)) and
        all(.status.traffic[]?; has("revisionName") and ((.latestRevision // false) == false))
      ) or
      (
        $strict == false and
        .spec.traffic == [{latestRevision:true,percent:100}] and
        .status.traffic == [{latestRevision:true,percent:100,revisionName:$defaultRevision}]
      )
    ) and
    ([.status.traffic[]? | select(has("tag")) | .tag] | length) == ([.status.traffic[]? | select(has("tag")) | .tag] | unique | length) and
    all(.status.traffic[]? | select(has("tag")); (.tag | test("^pr-[1-9][0-9]*$")) and (.revisionName | test(("^" + $name + "-[a-z0-9-]+$")))) and
    ([.status.traffic[]? | select(has("tag")) | .revisionName] | length) == ([.status.traffic[]? | select(has("tag")) | .revisionName] | unique | length) and
    ([.status.traffic[]? | select(has("tag")) | .revisionName] | index($defaultRevision) | not) and
    ([.spec.traffic[]? | select(has("tag")) | {tag,revisionName}] | sort_by(.tag)) ==
      ([.status.traffic[]? | select(has("tag")) | {tag,revisionName}] | sort_by(.tag)) and
    (($strict == false and (.spec.traffic[0].latestRevision // false) == true) or
      (([.spec.traffic[]?.revisionName] | sort | unique) == ([.status.traffic[]?.revisionName] | sort | unique)))
  ' "$service" >/dev/null || die "Preview traffic is not exactly one stable 100% default route plus a uniquely tagged pr-N routing set."

  local expected_names actual_names
  expected_names="${RUNNER_TEMP:?}/expected-preview-revisions-$RANDOM"
  actual_names="$expected_names.actual"
  jq -r '.status.traffic[]?.revisionName' "$service" | sort -u > "$expected_names"
  find "$revision_dir" -mindepth 1 -maxdepth 1 -type f -name '*.json' -exec basename {} .json \; | sort -u > "$actual_names"
  cmp "$expected_names" "$actual_names" >/dev/null || die "Preview revision evidence does not exactly cover every live route."

  local candidate_parity=true default_revision revision_name revision revision_projections
  default_revision="$(jq -er '.status.traffic[] | select(has("tag") | not) | .revisionName' "$service")"
  revision_projections="${RUNNER_TEMP:?}/cloud-run-preview-revision-projections-$RANDOM.jsonl"
  : > "$revision_projections"
  while IFS= read -r revision_name; do
    [ -n "$revision_name" ] || continue
    [[ "$revision_name" =~ ^[a-z][a-z0-9-]{0,62}$ ]] || die "Preview revision name is invalid."
    revision="$revision_dir/${revision_name}.json"
    require_json "$revision"
    jq -e --arg name "$revision_name" --arg namespace "$project_number" --arg service "$service_name" --arg runtime "$runtime_service_account" '
      .apiVersion == "serving.knative.dev/v1" and .kind == "Revision" and
      .metadata.name == $name and .metadata.namespace == $namespace and
      .metadata.labels["serving.knative.dev/service"] == $service and
      .metadata.generation == .status.observedGeneration and
      ([.status.conditions[]? | select(.type == "Ready" and .status == "True")] | length) == 1 and
      .spec.serviceAccountName == $runtime and
      ((.spec.volumes // []) | length) == 0 and
      (.spec.containers | length) == 1 and
      ((.spec.containers[0].volumeMounts // []) | length) == 0 and
      ([.metadata.annotations // {} | keys[] | select(
        test("(^|/)(vpc-access-connector|vpc-access-egress|network-interfaces|cloudsql-instances|base-images|build-base-image|build-enable-automatic-updates|enable-automatic-updates|base-image-update)$")
      )] | length) == 0 and
      ((.spec.runtimeClassName // "") == "") and
      all(.spec.containers[0].env[]?; (keys | sort) == ["name","value"]) and
      (.spec.containers[0].image | test("@sha256:[0-9a-f]{64}$")) and
      .status.imageDigest == .spec.containers[0].image
    ' "$revision" >/dev/null || die "A live preview route lacks a healthy immutable image revision."
    if [ "$revision_name" = "$default_revision" ]; then
      if ! jq -e --arg repository_id "$repository_id" --arg image_name "$production_image_name" --arg parity "$DHI_PARITY_ID" \
        --arg workflow_sha "$platform_workflow_sha" '
        def exact_value($name):
          [.spec.containers[0].env[]? | select(.name == $name and (keys | sort) == ["name","value"]) | .value]
          | if length == 1 then .[0] else error("missing or duplicate immutable image identity") end;
        (exact_value("PLATFORM_IMAGE_INDEX_DIGEST")) as $index |
        (exact_value("PLATFORM_IMAGE_RUNNABLE_DIGEST")) as $runnable |
        .metadata.labels.environment == "preview" and
        .metadata.labels["preview-role"] == "baseline" and
        .metadata.labels["managed-by"] == "github-actions" and
        .metadata.labels["github-repository-id"] == $repository_id and
        .metadata.labels["dhi-parity-id"] == $parity and
        (.metadata.labels["git-head-sha"] | test("^[0-9a-f]{40}$")) and
        .metadata.labels["platform-workflow-sha"] == $workflow_sha and
        (.metadata.labels | has("github-pr") | not) and
        .spec.containers[0].command == ["bun"] and
        .spec.containers[0].args == ["-e","Bun.serve({port:+process.env.PORT,fetch(){return new Response(null,{status:404})}})"] and
        ([.spec.containers[0].env[] | .name] | sort) == ["PLATFORM_DEPLOY_ENVIRONMENT","PLATFORM_IMAGE_INDEX_DIGEST","PLATFORM_IMAGE_RUNNABLE_DIGEST"] and
        ([.spec.containers[0].env[] | select(.name == "PLATFORM_DEPLOY_ENVIRONMENT" and .value == "preview-baseline")] | length) == 1 and
        ($index | test("^sha256:[0-9a-f]{64}$")) and
        ($runnable | test("^sha256:[0-9a-f]{64}$")) and
        .spec.containers[0].image == ($image_name + "@" + $runnable)
      ' "$revision" >/dev/null; then
        candidate_parity=false
      fi
    else
      local tag_pr
      tag_pr="$(jq -er --arg revision "$revision_name" '.status.traffic[] | select(has("tag") and .revisionName == $revision) | .tag | sub("^pr-"; "")' "$service")"
      if ! jq -e --arg repository_id "$repository_id" --arg image_name "$image_name" --arg parity "$DHI_PARITY_ID" \
        --arg workflow_sha "$platform_workflow_sha" --arg pr "$tag_pr" '
        def exact_value($name):
          [.spec.containers[0].env[]? | select(.name == $name and (keys | sort) == ["name","value"]) | .value]
          | if length == 1 then .[0] else error("missing or duplicate immutable image identity") end;
        (exact_value("PLATFORM_IMAGE_INDEX_DIGEST")) as $index |
        (exact_value("PLATFORM_IMAGE_RUNNABLE_DIGEST")) as $runnable |
        .metadata.labels.environment == "preview" and
        .metadata.labels["preview-role"] == "pr" and
        .metadata.labels["managed-by"] == "github-actions" and
        .metadata.labels["github-repository-id"] == $repository_id and
        .metadata.labels["github-pr"] == $pr and
        .metadata.labels["dhi-parity-id"] == $parity and
        (.metadata.labels["git-head-sha"] | test("^[0-9a-f]{40}$")) and
        .metadata.labels["platform-workflow-sha"] == $workflow_sha and
        ((.spec.containers[0].command // []) | length) == 0 and
        ((.spec.containers[0].args // []) | length) == 0 and
        (
          if $repository_id == "1255553151" then
            ([.spec.containers[0].env[] | .name] | sort) == [
              "PLATFORM_DEPLOY_ENVIRONMENT","PLATFORM_DEPLOY_NONCE","PLATFORM_IMAGE_INDEX_DIGEST",
              "PLATFORM_IMAGE_RUNNABLE_DIGEST","PLATFORM_PREVIEW_NUMBER"
            ]
          elif $repository_id == "711292980" then
            ([.spec.containers[0].env[] | .name] | sort) == [
              "PLATFORM_DEPLOY_ENVIRONMENT","PLATFORM_DEPLOY_NONCE","PLATFORM_IMAGE_INDEX_DIGEST",
              "PLATFORM_IMAGE_RUNNABLE_DIGEST","PLATFORM_PREVIEW_NUMBER","RUNSETTA_OFFLINE",
              "RUNSETTA_TTS_MODEL","RUNSETTA_TTS_VOICE"
            ] and
            exact_value("RUNSETTA_OFFLINE") == "1" and
            exact_value("RUNSETTA_TTS_MODEL") == "gpt-4o-mini-tts" and
            exact_value("RUNSETTA_TTS_VOICE") == "marin"
          elif $repository_id == "1025243085" then
            ([.spec.containers[0].env[] | .name] | sort) == [
              "ALLOWED_HOSTS","ALLOWED_ORIGINS","CANONICAL_HOST","LEGACY_HOSTS","MEDLOCK_VERSION",
              "PLATFORM_DEPLOY_ENVIRONMENT","PLATFORM_DEPLOY_NONCE","PLATFORM_IMAGE_INDEX_DIGEST",
              "PLATFORM_IMAGE_RUNNABLE_DIGEST","PLATFORM_PREVIEW_NUMBER","WAITLIST_BACKEND",
              "WAITLIST_IDENTITY_KEYSET"
            ] and
            exact_value("ALLOWED_HOSTS") == "medlock.ai,www.medlock.ai,mcp.medlock.ai,healthmcp.ai,www.healthmcp.ai,healthmcp.app,www.healthmcp.app,*.run.app" and
            exact_value("ALLOWED_ORIGINS") == "https://medlock.ai,https://www.medlock.ai,https://mcp.medlock.ai,https://chat.openai.com,https://claude.ai,https://*.run.app" and
            exact_value("CANONICAL_HOST") == "medlock.ai" and
            exact_value("LEGACY_HOSTS") == "healthmcp.ai,www.healthmcp.ai,healthmcp.app,www.healthmcp.app" and
            exact_value("MEDLOCK_VERSION") == "0.2.0" and
            exact_value("WAITLIST_BACKEND") == "memory" and
            (exact_value("WAITLIST_IDENTITY_KEYSET") | test("^[A-Za-z0-9_-]{43}$"))
          elif $repository_id == "280932482" then
            ([.spec.containers[0].env[] | .name] | sort) == [
              "MAPBOX_PUBLIC_TOKEN","PLATFORM_DEPLOY_ENVIRONMENT","PLATFORM_DEPLOY_NONCE",
              "PLATFORM_IMAGE_INDEX_DIGEST","PLATFORM_IMAGE_RUNNABLE_DIGEST","PLATFORM_PREVIEW_NUMBER"
            ] and
            (exact_value("MAPBOX_PUBLIC_TOKEN") | test("^pk\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$"))
          else false end
        ) and
        exact_value("PLATFORM_DEPLOY_ENVIRONMENT") == "preview" and
        (exact_value("PLATFORM_DEPLOY_NONCE") | test("^[0-9a-f]{64}$")) and
        exact_value("PLATFORM_PREVIEW_NUMBER") == $pr and
        ($index | test("^sha256:[0-9a-f]{64}$")) and
        ($runnable | test("^sha256:[0-9a-f]{64}$")) and
        .spec.containers[0].image == ($image_name + "@" + $runnable)
      ' "$revision" >/dev/null; then
        candidate_parity=false
      fi
    fi
    jq -cS '{
      generation:.metadata.generation,
      image:.spec.containers[0].image,
      imageIdentity:[.spec.containers[0].env[]? | select(.name == "PLATFORM_IMAGE_INDEX_DIGEST" or .name == "PLATFORM_IMAGE_RUNNABLE_DIGEST") | {name,value}] | sort_by(.name),
      labels:{
        dhiParityId:.metadata.labels["dhi-parity-id"],
        environment:.metadata.labels.environment,
        gitHeadSha:.metadata.labels["git-head-sha"],
        managedBy:.metadata.labels["managed-by"],
        platformWorkflowSha:.metadata.labels["platform-workflow-sha"],
        previewRole:.metadata.labels["preview-role"],
        pullRequest:.metadata.labels["github-pr"],
        repositoryId:.metadata.labels["github-repository-id"],
        service:.metadata.labels["serving.knative.dev/service"]
      },
      name:.metadata.name,
      namespace:.metadata.namespace,
      observedGeneration:.status.observedGeneration,
      statusImageDigest:.status.imageDigest
    }' "$revision" >> "$revision_projections"
  done < "$expected_names"
  if [ "$strict" = true ] && [ "$candidate_parity" != true ]; then
    die "A live preview route lacks the exact candidate DHI parity provenance."
  fi

  local sealed_baseline=false sealed_bootstrap=false
  if [ "$(jq -r '[.status.traffic[]? | select(has("tag"))] | length' "$service")" = 0 ] &&
     [ "$ingress" = internal ] && [ "$invoker_iam_disabled" = false ]; then
    if jq -e --arg image 'us-docker.pkg.dev/cloudrun/container/hello@sha256:9a0e9a5c7a19281e7617991d2fc61809de4973e6e75a10b2f07df3719ffda33c' '
      .spec.containers[0].image == $image and .status.imageDigest == $image and
      (.metadata.labels["dhi-parity-id"] // "") == "" and
      (.metadata.labels["preview-role"] // "") == ""
    ' "$revision_dir/${default_revision}.json" >/dev/null; then
      sealed_bootstrap=true
    fi
    if jq -e --arg image_name "$production_image_name" '
      def exact_value($name):
        [.spec.containers[0].env[]? | select(.name == $name and (keys | sort) == ["name","value"]) | .value]
        | if length == 1 then .[0] else error("missing or duplicate immutable image identity") end;
      (exact_value("PLATFORM_IMAGE_INDEX_DIGEST")) as $index |
      (exact_value("PLATFORM_IMAGE_RUNNABLE_DIGEST")) as $runnable |
      .metadata.labels.environment == "preview" and
      .metadata.labels["preview-role"] == "baseline" and
      .metadata.labels["managed-by"] == "github-actions" and
      (.metadata.labels["dhi-parity-id"] | test("^[a-z0-9]{50}$")) and
      (.metadata.labels["git-head-sha"] | test("^[0-9a-f]{40}$")) and
      .spec.containers[0].command == ["bun"] and
      .spec.containers[0].args == ["-e","Bun.serve({port:+process.env.PORT,fetch(){return new Response(null,{status:404})}})"] and
      ([.spec.containers[0].env[] | .name] | sort) == ["PLATFORM_DEPLOY_ENVIRONMENT","PLATFORM_IMAGE_INDEX_DIGEST","PLATFORM_IMAGE_RUNNABLE_DIGEST"] and
      ([.spec.containers[0].env[] | select(.name == "PLATFORM_DEPLOY_ENVIRONMENT" and .value == "preview-baseline")] | length) == 1 and
      ($index | test("^sha256:[0-9a-f]{64}$")) and
      ($runnable | test("^sha256:[0-9a-f]{64}$")) and
      .spec.containers[0].image == ($image_name + "@" + $runnable)
    ' "$revision_dir/${default_revision}.json" >/dev/null; then
      sealed_baseline=true
    fi
  fi

  local observed_parity_id
  observed_parity_id="$(jq -er '.metadata.labels["dhi-parity-id"] // ""' "$revision_dir/${default_revision}.json")"
  local baseline_index_digest baseline_index_image
  baseline_index_digest="$(jq -er '[.spec.containers[0].env[]? | select(.name == "PLATFORM_IMAGE_INDEX_DIGEST") | .value] | if length == 1 then .[0] else "" end' "$revision_dir/${default_revision}.json")"
  baseline_index_image=""
  if [[ "$baseline_index_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    baseline_index_image="${production_image_name}@${baseline_index_digest}"
  fi
  local projection="${RUNNER_TEMP:?}/cloud-run-preview-routes-projection-$RANDOM.json"
  jq -cS --slurpfile names <(jq -Rsc 'split("\n") | map(select(length > 0))' "$expected_names") '{
    generation:.metadata.generation,
    ingress:.metadata.annotations["run.googleapis.com/ingress"],
    invokerIamDisabled:(.metadata.annotations["run.googleapis.com/invoker-iam-disabled"] // "false"),
    name:.metadata.name,
    namespace:.metadata.namespace,
    observedGeneration:.status.observedGeneration,
    revisionNames:$names[0],
    specTraffic:[.spec.traffic[]? | {percent,revisionName,tag}] | sort_by(.tag // ""),
    statusTraffic:[.status.traffic[]? | {percent,revisionName,tag}] | sort_by(.tag // "")
  }' "$service" > "$projection"
  {
    echo "active_preview_count=$(jq -r '[.status.traffic[]? | select(has("tag"))] | length' "$service")"
    echo "all_routes_candidate_parity=$candidate_parity"
    echo "baseline_head_sha=$(jq -er '.metadata.labels["git-head-sha"] // ""' "$revision_dir/${default_revision}.json")"
    echo "baseline_index_image=$baseline_index_image"
    echo "baseline_runnable_image=$(jq -er '.spec.containers[0].image' "$revision_dir/${default_revision}.json")"
    echo "baseline_revision=$default_revision"
    echo "candidate_dhi_parity_id=$DHI_PARITY_ID"
    echo "dhi_parity_id=$observed_parity_id"
    echo "ingress=$ingress"
    echo "invoker_iam_disabled=$invoker_iam_disabled"
    echo "preview_projection_sha256=$(sha256_file "$projection")"
    echo "revision_projection_sha256=$(sha256_file "$revision_projections")"
    echo "route_revision_count=$(wc -l < "$expected_names" | tr -d '[:space:]')"
    echo "sealed_baseline=$sealed_baseline"
    echo "sealed_bootstrap=$sealed_bootstrap"
  } >> "${GITHUB_OUTPUT:?}"
}

inspect_preview_routes() {
  validate_preview_routes false
}

prove_preview_routes() {
  validate_preview_routes true
}

case "${1:-}" in
  prove-production) prove_production ;;
  inspect-preview-routes) inspect_preview_routes ;;
  prove-preview-routes) prove_preview_routes ;;
  prove-preview-tags) prove_preview_routes ;;
  *) echo "usage: cloud-run-dhi-parity.sh {prove-production|inspect-preview-routes|prove-preview-routes}" >&2; exit 64 ;;
esac
