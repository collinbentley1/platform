#!/bin/bash
# Read-only GitHub inventory and networkless rescans of saved production SBOMs.
# The credentialed API discovery finishes before any SBOM reaches the scanner.

grype_expected_image() {
  case "$1" in
    1255553151) echo us-east4-docker.pkg.dev/cdbentley/site/cdbentley ;;
    1362801465) echo us-east4-docker.pkg.dev/virtual-care-mcp/site/virtual-care-mcp ;;
    711292980) echo us-east4-docker.pkg.dev/runsetta/api/runsetta ;;
    1025243085) echo us-east4-docker.pkg.dev/medlock-1025243085/site/medlock ;;
    280932482) echo us-east4-docker.pkg.dev/critical-history-16823277/site/critical-history ;;
    *) die "Repository is not registered for production SBOM rescans." ;;
  esac
}

grype_discover_production_sboms() {
  require_linux_x64
  grype_expected_image "${REPOSITORY_ID:?}" >/dev/null
  [[ "$GITHUB_REPOSITORY" =~ ^collinbentley1/[A-Za-z0-9._-]+$ ]] || die "Rescan repository owner is invalid."
  test "$GITHUB_REF" = refs/heads/main || die "Rescans must use the protected default branch."
  local runs="$RUNNER_TEMP/production-runs.json" inventory="$RUNNER_TEMP/production-inventory.jsonl"
  gh api "repos/$GITHUB_REPOSITORY/actions/workflows/deploy-prod.yml/runs?branch=main&event=push&per_page=100" > "$runs"
  grype_require_json "$runs" 1048576
  local baseline
  baseline="$(jq -er --argjson repo "$REPOSITORY_ID" '
    [.workflow_runs[] | select(.conclusion == "success" and .head_branch == "main" and
      .event == "push" and .run_attempt == 1 and .path == ".github/workflows/deploy-prod.yml" and
      .repository.id == $repo and .head_repository.id == $repo)] |
    first | .id | select(type == "number" and . > 0)
  ' "$runs")" || die "No successful production run is available; adopt the new production workflow before rescanning."
  local candidates="$RUNNER_TEMP/production-candidates.jsonl"
  jq -c --argjson repo "$REPOSITORY_ID" --argjson baseline "$baseline" '
    .workflow_runs[] | select(.id >= $baseline and .head_branch == "main" and
      .event == "push" and .run_attempt == 1 and .path == ".github/workflows/deploy-prod.yml" and
      .repository.id == $repo and .head_repository.id == $repo and
      (.head_sha | test("^[0-9a-f]{40}$"))) | {id,head_sha}
  ' "$runs" > "$candidates"
  : > "$inventory"
  local candidate run head artifacts record
  while IFS= read -r candidate; do
    run="$(jq -er .id <<< "$candidate")"
    head="$(jq -er .head_sha <<< "$candidate")"
    artifacts="$RUNNER_TEMP/production-artifacts-$run.json"
    gh api "repos/$GITHUB_REPOSITORY/actions/runs/$run/artifacts?per_page=100" > "$artifacts"
    grype_require_json "$artifacts" 1048576
    record="$(grype_find_sbom_artifact "$artifacts" "$run" "$run" "platform-production-sbom-$run-1.tar")" || {
      # A published inventory is renewed by every successful scanner execution,
      # including scans which find blocking vulnerabilities. It therefore
      # outlives the original GitHub artifact's finite retention period.
      record="$(grype_find_renewed_sbom "$run")" || {
        if [ "$run" = "$baseline" ]; then
          die "The last successful release has no retained production SBOM; deploy once with this platform version."
        fi
        continue
      }
    }
    jq -cn --argjson artifact "$record" --arg run "$run" --arg head "$head" \
      '{artifactId:($artifact.id | tostring),artifactRunId:($artifact.workflow_run.id | tostring),
        contentSha256:($artifact.digest | sub("^sha256:";"")),deploymentRunId:$run,headSha:$head}' >> "$inventory"
  done < "$candidates"
  local count
  count="$(wc -l < "$inventory" | tr -d '[:space:]')"
  [ "$count" -gt 0 ] || die "Rescan inventory is empty; refusing a zero-target success."
  [ "$count" -le 8 ] || die "More than eight production candidates remain since the last successful release; reconcile the failed deployments before rescanning."
  echo "matrix=$(jq -cs '{include:.}' "$inventory")" >> "$GITHUB_OUTPUT"
}

grype_find_sbom_artifact() {
  local artifacts="$1" original_run="$2" producer_run="$3" name="$4"
  jq -cer --arg name "$name" --argjson producer "$producer_run" --argjson repo "$REPOSITORY_ID" '
    [.artifacts[] | select(.name == $name and .expired == false and
      .workflow_run.id == $producer and .workflow_run.repository_id == $repo and
      .workflow_run.head_repository_id == $repo and .size_in_bytes > 0 and .size_in_bytes <= 537919488 and
      (.id | type == "number" and . > 0) and
      (.digest | type == "string" and test("^sha256:[0-9a-f]{64}$")))] |
    select(length == 1) | .[0]
  ' "$artifacts"
}

grype_find_renewed_sbom() {
  local original="$1" runs="$RUNNER_TEMP/rescan-runs-$1.json"
  gh api "repos/$GITHUB_REPOSITORY/actions/workflows/rescan-vulnerabilities.yml/runs?branch=main&status=completed&per_page=30" > "$runs" || return 1
  grype_require_json "$runs" 1048576
  local ids="$RUNNER_TEMP/rescan-producers-$1.txt"
  jq -r --argjson repo "$REPOSITORY_ID" '
    .workflow_runs[] | select(.head_branch == "main" and .run_attempt == 1 and
      (.event == "schedule" or .event == "workflow_dispatch") and
      .path == ".github/workflows/rescan-vulnerabilities.yml" and
      .repository.id == $repo and .head_repository.id == $repo) | .id
  ' "$runs" > "$ids"
  local run artifacts record
  while IFS= read -r run; do
    [[ "$run" =~ ^[1-9][0-9]*$ ]] || die "Renewal producer id is invalid."
    artifacts="$RUNNER_TEMP/renewed-sbom-$run.json"
    gh api "repos/$GITHUB_REPOSITORY/actions/runs/$run/artifacts?per_page=100" > "$artifacts" || continue
    grype_require_json "$artifacts" 1048576
    if record="$(grype_find_sbom_artifact "$artifacts" "$original" "$run" "platform-production-sbom-$original-rescan-$run.tar")"; then
      printf '%s\n' "$record"
      return 0
    fi
  done < "$ids"
  return 1
}

grype_validate_sbom_record() {
  local directory="$1" original="$2" head="$3" image
  image="$(grype_expected_image "${REPOSITORY_ID:?}")"
  grype_require_json "$directory/record.json" 16384
  jq -e --arg image "$image" --arg repo "$REPOSITORY_ID" --arg run "$original" --arg head "$head" '
    (keys | sort) == ["artifactType","deploymentRunAttempt","deploymentRunId","headSha","imageDigest","imageName",
      "repositoryId","sbomSha256","scanEvidenceSha256","schemaVersion","workflowSha"] and
    .artifactType == "platform-production-sbom" and .schemaVersion == 1 and
    .repositoryId == $repo and .deploymentRunId == $run and .deploymentRunAttempt == "1" and
    .headSha == $head and .imageName == $image and
    (.imageDigest | test("^sha256:[0-9a-f]{64}$")) and
    ([.sbomSha256,.scanEvidenceSha256] | all(type == "string" and test("^[0-9a-f]{64}$"))) and
    (.workflowSha | type == "string" and test("^[0-9a-f]{40}$"))
  ' "$directory/record.json" >/dev/null || die "Production SBOM inventory differs from its exact run, repository, or image."
  verify_sha256 "$(jq -er .sbomSha256 "$directory/record.json")" "$directory/sbom.spdx.json"
  verify_sha256 "$(jq -er .scanEvidenceSha256 "$directory/record.json")" "$directory/scan-evidence.json"
  grype_validate_scan_evidence "$directory/scan-evidence.json" \
    "$(jq -er .imageDigest "$directory/record.json")" "$(jq -er .sbomSha256 "$directory/record.json")" false
  grype_require_json "$directory/sbom.spdx.json" "$MAX_SCAN_JSON_BYTES"
  jq -e '(.spdxVersion | startswith("SPDX-")) and (.packages | type == "array")' \
    "$directory/sbom.spdx.json" >/dev/null || die "Production SBOM is invalid."
}

grype_retain_production_sbom() {
  require_linux_x64
  local source="$GITHUB_WORKSPACE/platform-build" bundle="$RUNNER_TEMP/platform-production-sbom-bundle"
  grype_require_json "$source/manifest.json" "$MAX_MANIFEST_JSON_BYTES"
  jq -e --arg repo "$REPOSITORY_ID" --arg run "$GITHUB_RUN_ID" --arg head "$GITHUB_SHA" '
    .schemaVersion == 2 and .repositoryId == $repo and .runId == $run and
    .runAttempt == "1" and .eventName == "push" and .headSha == $head
  ' "$source/manifest.json" >/dev/null || die "Published SBOM manifest differs from the production run."
  local sbom evidence image
  image="$(grype_expected_image "${REPOSITORY_ID:?}")"
  test "${PUBLISHED_IMAGE_NAME:?}" = "$image" || die "Published SBOM image repository differs."
  test "$(jq -er .publishedIndexDigest "$source/manifest.json")" = "${PUBLISHED_IMAGE_DIGEST:?}" ||
    die "Published SBOM subject differs from the copied image digest."
  sbom="$(jq -er .sbomSha256 "$source/manifest.json")"
  evidence="$(jq -er .scanEvidenceSha256 "$source/manifest.json")"
  verify_sha256 "$sbom" "$source/sbom.spdx.json"
  verify_sha256 "$evidence" "$source/scan-evidence.json"
  grype_validate_scan_evidence "$source/scan-evidence.json" "$PUBLISHED_IMAGE_DIGEST" "$sbom"
  install -d -m 0700 "$bundle"
  cp "$source/sbom.spdx.json" "$source/scan-evidence.json" "$bundle/"
  jq -cnS --arg image "$image" --arg digest "$PUBLISHED_IMAGE_DIGEST" --arg repo "$REPOSITORY_ID" \
    --arg head "$GITHUB_SHA" --arg run "$GITHUB_RUN_ID" --arg sbom "$sbom" --arg evidence "$evidence" \
    --arg workflow "$(jq -er .workflowSha "$source/manifest.json")" '
    {artifactType:"platform-production-sbom",schemaVersion:1,imageName:$image,imageDigest:$digest,repositoryId:$repo,
      deploymentRunId:$run,deploymentRunAttempt:"1",headSha:$head,sbomSha256:$sbom,scanEvidenceSha256:$evidence,workflowSha:$workflow}
  ' > "$bundle/record.json"
  grype_validate_sbom_record "$bundle" "$GITHUB_RUN_ID" "$GITHUB_SHA"
  local artifact="$RUNNER_TEMP/platform-production-sbom-$GITHUB_RUN_ID-1.tar"
  write_deterministic_tar "$bundle" "$artifact" 537919488
  echo "artifact=$artifact" >> "$GITHUB_OUTPUT"
}

grype_rescan_sbom() {
  require_linux_x64
  grype_verify_directory "${GRYPE_DATABASE_DIR:?}" "${GRYPE_DATABASE_MANIFEST_SHA256:?}"
  local source="$RUNNER_TEMP/platform-rescan-source" archive
  archive="$(single_regular_file "$RUNNER_TEMP/platform-sbom-download")"
  verify_sha256 "${RESCAN_ARTIFACT_SHA256:?}" "$archive"
  safe_extract_tar "$archive" "$source" 537919488
  test "$(find "$source" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | tr '\n' ' ')" = \
    "record.json sbom.spdx.json scan-evidence.json " || die "Production SBOM archive has an unexpected file set."
  grype_validate_sbom_record "$source" "${RESCAN_DEPLOYMENT_RUN_ID:?}" "${RESCAN_HEAD_SHA:?}"

  local tools="$RUNNER_TEMP/platform-rescan-tools" state="$RUNNER_TEMP/platform-rescan-state" report="$RUNNER_TEMP/platform-rescan-report"
  local policy="$RUNNER_TEMP/platform-rescan-policy"
  install -d -m 0755 "$tools" "$report" "$policy"
  install -d -m 0777 "$state"
  # A restored checkout may have private permissions. Export only the scanner
  # configuration with explicit read access for its unprivileged container UID.
  test -f "$CONTRACT_ROOT/grype.yaml" && test ! -L "$CONTRACT_ROOT/grype.yaml" ||
    die "The rescan configuration must be a regular platform policy file."
  install -m 0444 "$CONTRACT_ROOT/grype.yaml" "$policy/grype.yaml"
  curl --fail --show-error --silent --location --output "$RUNNER_TEMP/rescan-grype.tgz" \
    https://github.com/anchore/grype/releases/download/v0.117.0/grype_0.117.0_linux_amd64.tar.gz
  verify_sha256 38525dab1e06f162ebaa02f94d82d1f807076b011a44180cf2777edf1a7b9c26 "$RUNNER_TEMP/rescan-grype.tgz"
  tar -xzf "$RUNNER_TEMP/rescan-grype.tgz" -C "$tools" grype
  "$tools/grype" version -o json | jq -e \
    '.version == "0.117.0" and .gitCommit == "b5fa92bbcbef655497e3be840a2f718380e2cdd3"' >/dev/null
  chmod -R a-w,go+rX "$tools" "$source" "$GRYPE_DATABASE_DIR" "$policy"
  docker pull "$SCANNER_SANDBOX_IMAGE" >/dev/null
  local image_id
  image_id="$(docker image inspect --format '{{.Id}}' "$SCANNER_SANDBOX_IMAGE")"
  require_digest "$image_id"
  docker image inspect --format '{{json .RepoDigests}}' "$image_id" |
    jq -e --arg image "$SCANNER_SANDBOX_IMAGE" 'index($image) != null' >/dev/null
  local -a sandbox=(
    run --rm --pull never --network none --read-only --cap-drop ALL
    --security-opt no-new-privileges --user 65534:65534 --pids-limit 256 --cpus 2
    --mount "type=bind,src=$source,dst=/input,readonly"
    --mount "type=bind,src=$tools,dst=/tools,readonly"
    --mount "type=bind,src=$policy,dst=/policy,readonly"
    --mount "type=bind,src=$GRYPE_DATABASE_DIR,dst=/database,readonly"
    --mount "type=bind,src=$state,dst=/state"
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=268435456
    --env GRYPE_DB_CACHE_DIR=/state/db --env GRYPE_CHECK_FOR_APP_UPDATE=false
    --env XDG_CACHE_HOME=/state/cache
  )
  /usr/bin/timeout --signal=TERM --kill-after=10s 2m docker "${sandbox[@]}" --memory 4294967296 --entrypoint /tools/grype "$image_id" \
    --config /policy/grype.yaml db import /database/grype-db.tar.zst > "$report/import.log" 2>&1 ||
    die "The networkless rescan database import failed."
  /usr/bin/timeout --signal=TERM --kill-after=10s 1m docker "${sandbox[@]}" --memory 1073741824 --entrypoint /tools/grype "$image_id" \
    --config /policy/grype.yaml db status -o json > "$report/database-status.json" 2> "$report/status.log" ||
    die "The rescan database status check failed."
  jq -e --slurpfile expected "$GRYPE_DATABASE_DIR/manifest.json" \
    '.valid == true and .built == $expected[0].built and .schemaVersion == $expected[0].schemaVersion' \
    "$report/database-status.json" >/dev/null || die "Rescan database metadata differs from the verified snapshot."
  /usr/bin/timeout --signal=TERM --kill-after=10s 10m docker "${sandbox[@]}" --memory 1073741824 --entrypoint /tools/grype "$image_id" \
    --config /policy/grype.yaml sbom:/input/sbom.spdx.json --output json > "$report/grype.json" 2> "$report/scan.log" ||
    die "The networkless SBOM rescan failed."
  grype_require_json "$report/grype.json" "$MAX_SCAN_JSON_BYTES"
  jq -e '.matches | type == "array"' "$report/grype.json" >/dev/null || die "Grype returned an invalid match set."
  jq -f "$CONTRACT_ROOT/grype-blocking.jq" "$report/grype.json" > "$report/blocking.json"
  local count
  count="$(jq -er length "$report/blocking.json")"
  grype_check_freshness "$(jq -er .built "$GRYPE_DATABASE_DIR/manifest.json")"
  jq -cnS --slurpfile record "$source/record.json" --slurpfile database "$GRYPE_DATABASE_DIR/manifest.json" \
    --arg result "$(sha256_file "$report/grype.json")" --arg policy "$GRYPE_DB_POLICY_SHA256" --argjson count "$count" \
    '{schemaVersion:1,imageName:$record[0].imageName,imageDigest:$record[0].imageDigest,
      sbomSha256:$record[0].sbomSha256,deploymentRunId:$record[0].deploymentRunId,database:$database[0],
      policySha256:$policy,grypeVersion:"0.117.0",resultSha256:$result,blockingCount:$count,scannedAt:(now | todateiso8601)}' \
    > "$report/rescan-evidence.json"

  # Preserve the original production evidence, including when new vulnerabilities
  # are found. Renewal does not re-date or reinterpret the original release.
  local artifact="$RUNNER_TEMP/platform-production-sbom-$RESCAN_DEPLOYMENT_RUN_ID-rescan-$GITHUB_RUN_ID.tar"
  write_deterministic_tar "$source" "$artifact" 537919488
  {
    echo "inventory_artifact=$artifact"
    echo "report_directory=$report"
    echo "blocking_count=$count"
  } >> "$GITHUB_OUTPUT"
}
