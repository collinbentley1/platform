#!/bin/bash
# Sourced only by the exact-platform container contract. Vulnerability data may
# advance independently of that code; URLs, schema, age, and byte caps may not.

grype_load_policy() {
  test -z "${DB_MANIFEST_JSON:-}" && test -z "${GRYPE_DB_MANIFEST_JSON:-}" ||
    die "Refusing an injected Grype database manifest."
  test -f "$GRYPE_DB_POLICY" && test ! -L "$GRYPE_DB_POLICY" ||
    die "The Grype database policy is not a regular policy file."
  verify_sha256 "$GRYPE_DB_POLICY_SHA256" "$GRYPE_DB_POLICY"
  require_json_file "$GRYPE_DB_POLICY" 4096
  jq -e '
    . == {
      schemaVersion:1,
      listingUrl:"https://grype.anchore.io/databases/v6/latest.json",
      downloadBaseUrl:"https://grype.anchore.io/databases/v6/",
      databaseSchemaVersion:"v6.1.9",
      maxBuiltAgeSeconds:172800,maxFutureSkewSeconds:3600,
      maxArchiveBytes:536870912,maxListingBytes:4096
    }
  ' "$GRYPE_DB_POLICY" >/dev/null || die "The Grype database policy schema drifted."
}

grype_require_json() {
  require_json_file "$1" "$2"
  jq -es 'length == 1' "$1" >/dev/null || die "Grype metadata must contain exactly one JSON document."
}

grype_validate_manifest() {
  local manifest="$1" check_age="${2:-true}"
  grype_require_json "$manifest" 4096
  jq -e --argjson age "$check_age" --slurpfile policy "$GRYPE_DB_POLICY" '
    $policy[0] as $p | . as $m |
    (keys | sort) == ["built","schemaVersion","sha256","url"] and
    .schemaVersion == $p.databaseSchemaVersion and
    (.sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    (.built | type == "string" and (fromdateiso8601 | todateiso8601) == .) and
    (.url | type == "string" and test(
      "^https://grype\\.anchore\\.io/databases/v6/vulnerability-db_v6\\.1\\.9_[0-9TZ:-]+_[0-9]+\\.tar\\.zst\\?checksum=sha256%3A" + $m.sha256 + "$"
    )) and
    ((now - (.built | fromdateiso8601)) >= -$p.maxFutureSkewSeconds) and
    (if $age then (now - (.built | fromdateiso8601)) <= $p.maxBuiltAgeSeconds else true end)
  ' "$manifest" >/dev/null || die "Grype database identity, schema, or freshness is invalid."
}

grype_check_freshness() {
  grype_load_policy
  local built="$1"
  jq -en --arg built "$built" --slurpfile policy "$GRYPE_DB_POLICY" '
    ($built | fromdateiso8601) as $time |
    ($built | fromdateiso8601 | todateiso8601) == $built and
    (now - $time) >= -$policy[0].maxFutureSkewSeconds and
    (now - $time) <= $policy[0].maxBuiltAgeSeconds
  ' >/dev/null || die "The vulnerability database expired before publication or deployment; rebuild and rescan."
}

grype_validate_scan_evidence() {
  local evidence="$1" image="$2" sbom="$3" check_age="${4:-true}" database="$RUNNER_TEMP/grype-evidence-database-$RANDOM.json"
  grype_load_policy
  grype_require_json "$evidence" 16384
  jq -e --arg image "$image" --arg sbom "$sbom" --arg policy "$GRYPE_DB_POLICY_SHA256" --argjson age "$check_age" '
    (keys | sort) == ["blockingCount","database","grypeVersion","imageDigest","policySha256",
      "resultSha256","sbomSha256","scannedAt","schemaVersion"] and
    .schemaVersion == 1 and .blockingCount == 0 and .grypeVersion == "0.117.0" and
    .imageDigest == $image and .sbomSha256 == $sbom and
    (if $age then .policySha256 == $policy else (.policySha256 | test("^[0-9a-f]{64}$")) end) and
    (.resultSha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    (.scannedAt | type == "string" and (fromdateiso8601 | todateiso8601) == .) and
    (now - (.scannedAt | fromdateiso8601)) >= -3600 and
    (if $age then (now - (.scannedAt | fromdateiso8601)) <= 172800 else true end)
  ' "$evidence" >/dev/null || die "Scan evidence is stale or differs from the exact promoted image and SBOM."
  jq -cS .database "$evidence" > "$database"
  grype_validate_manifest "$database" "$check_age"
  rm -f -- "$database"
}

# Return 2 only for an unavailable upstream. Malformed metadata, rollback,
# unapproved destinations, and integrity failures never become cache fallbacks.
grype_fetch() {
  local url="$1" destination="$2" cap="$3" status rc=0
  status=$(curl --silent --show-error --proto '=https' --connect-timeout 10 --max-time 120 \
    --max-filesize "$cap" --output "$destination" --write-out '%{http_code}' "$url") || rc=$?
  case "$rc" in
    0) ;;
    5|6|7|18|28|35|52|55|56|60) return 2 ;;
    *) die "Grype download failed its transport or byte-limit policy (curl $rc)." ;;
  esac
  case "$status" in
    200) return 0 ;;
    429|5??) return 2 ;;
    *) die "Grype upstream returned HTTP $status; refusing to substitute cached policy data." ;;
  esac
}

grype_verify_directory() {
  local directory="$1" expected_manifest="$2"
  grype_load_policy
  test -d "$directory" && test ! -L "$directory" || die "Grype snapshot directory is invalid."
  verify_sha256 "$expected_manifest" "$directory/manifest.json"
  grype_validate_manifest "$directory/manifest.json"
  test -f "$directory/grype-db.tar.zst" && test ! -L "$directory/grype-db.tar.zst" ||
    die "Grype database archive is not a regular file."
  test "$(file_size "$directory/grype-db.tar.zst")" -le 536870912 || die "Grype database exceeds its byte cap."
  verify_sha256 "$(jq -er .sha256 "$directory/manifest.json")" "$directory/grype-db.tar.zst"
  test -f "$directory/policy.sha256" && test ! -L "$directory/policy.sha256" || die "Grype snapshot policy is not regular."
  test "$(cat "$directory/policy.sha256")" = "$GRYPE_DB_POLICY_SHA256" || die "Grype snapshot policy identity differs."
}

grype_acquire_database() {
  require_linux_x64
  grype_load_policy
  local destination="$RUNNER_TEMP/platform-grype-database"
  local cached="$RUNNER_TEMP/platform-grype-cached" fresh="$RUNNER_TEMP/platform-grype-fresh"
  local cache_available=false cache_fresh=false source=upstream
  test ! -e "$destination" && test ! -L "$destination" || die "Grype snapshot destination exists."
  test ! -e "$cached" && test ! -e "$fresh" || die "Grype preparation directories exist."
  install -d -m 0700 "$fresh"
  if [ -n "${GRYPE_CACHE_CONTENT_SHA256:-}" ]; then
    local archive
    archive="$(single_regular_file "$RUNNER_TEMP/platform-grype-cache-download")"
    verify_sha256 "$GRYPE_CACHE_CONTENT_SHA256" "$archive"
    safe_extract_tar "$archive" "$cached" 537919488
    test "$(find "$cached" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | tr '\n' ' ')" = \
      "grype-db.tar.zst manifest.json policy.sha256 " || die "Grype cache has an unexpected file set."
    find "$cached" -mindepth 1 -maxdepth 1 ! -type f -print -quit | grep -q . &&
      die "Grype cache contains a non-regular file."
    local cached_policy
    cached_policy="$(cat "$cached/policy.sha256")"
    require_sha256 "$cached_policy"
    if [ "$cached_policy" = "$GRYPE_DB_POLICY_SHA256" ]; then
      grype_validate_manifest "$cached/manifest.json" false
      verify_sha256 "$(jq -er .sha256 "$cached/manifest.json")" "$cached/grype-db.tar.zst"
      cache_available=true
      if jq -e --slurpfile policy "$GRYPE_DB_POLICY" \
        '(now - (.built | fromdateiso8601)) <= $policy[0].maxBuiltAgeSeconds' "$cached/manifest.json" >/dev/null; then
        cache_fresh=true
      fi
    else
      echo "The selected cache uses another acquisition policy; requiring a fresh upstream snapshot." >&2
    fi
  fi

  local unavailable=false
  if grype_fetch "$(jq -er .listingUrl "$GRYPE_DB_POLICY")" "$fresh/listing.json" 4096; then
    grype_require_json "$fresh/listing.json" 4096
    jq -e --slurpfile policy "$GRYPE_DB_POLICY" '
      (keys | sort) == ["built","checksum","path","schemaVersion","status"] and
      .status == "active" and .schemaVersion == $policy[0].databaseSchemaVersion and
      (.checksum | type == "string" and test("^sha256:[0-9a-f]{64}$")) and
      (.path | type == "string" and test("^vulnerability-db_v6\\.1\\.9_[0-9TZ:-]+_[0-9]+\\.tar\\.zst$")) and
      (.built | type == "string")
    ' "$fresh/listing.json" >/dev/null || die "Grype upstream listing is outside reviewed policy."
    jq -cnS --slurpfile listing "$fresh/listing.json" --slurpfile policy "$GRYPE_DB_POLICY" '
      $listing[0] as $l |
      {built:$l.built,schemaVersion:$l.schemaVersion,sha256:($l.checksum | sub("^sha256:";"")),
       url:($policy[0].downloadBaseUrl + $l.path + "?checksum=sha256%3A" + ($l.checksum | sub("^sha256:";"")))}
    ' > "$fresh/manifest.json"
    grype_validate_manifest "$fresh/manifest.json"
    if [ "$cache_available" = true ]; then
      jq -e --slurpfile cached "$cached/manifest.json" '
        (.built | fromdateiso8601) >= ($cached[0].built | fromdateiso8601) and
        (if .built == $cached[0].built then .sha256 == $cached[0].sha256 else true end)
      ' "$fresh/manifest.json" >/dev/null || die "Grype upstream attempted a database rollback or same-build substitution."
    fi
    if [ "$cache_available" = true ] && cmp -s <(jq -cS . "$cached/manifest.json") <(jq -cS . "$fresh/manifest.json"); then
      cp "$cached/grype-db.tar.zst" "$fresh/grype-db.tar.zst"
    elif grype_fetch "$(jq -er .url "$fresh/manifest.json")" "$fresh/grype-db.tar.zst" 536870912; then
      verify_sha256 "$(jq -er .sha256 "$fresh/manifest.json")" "$fresh/grype-db.tar.zst"
    else
      unavailable=true
    fi
  else
    unavailable=true
  fi
  if [ "$unavailable" = true ]; then
    [ "$cache_fresh" = true ] || die "Grype upstream is unavailable and no verified database under 48 hours old is cached."
    rm -f -- "$fresh/manifest.json" "$fresh/grype-db.tar.zst"
    cp "$cached/manifest.json" "$cached/grype-db.tar.zst" "$fresh/"
    source=cache
    echo "Using a verified Grype snapshot within the 48-hour limit during an upstream outage." >&2
  fi
  printf '%s\n' "$GRYPE_DB_POLICY_SHA256" > "$fresh/policy.sha256"
  rm -f -- "$fresh/listing.json"
  jq -cnS --arg source "$source" --arg policySha256 "$GRYPE_DB_POLICY_SHA256" \
    '{acquiredAt:(now | todateiso8601),policySha256:$policySha256,source:$source}' > "$fresh/acquisition.json"
  mv "$fresh" "$destination"
  local manifest_sha
  manifest_sha="$(sha256_file "$destination/manifest.json")"
  grype_verify_directory "$destination" "$manifest_sha"
  chmod -R a-w,go+rX "$destination"
  {
    echo "directory=$destination"
    echo "manifest_sha256=$manifest_sha"
    echo "database_built=$(jq -er .built "$destination/manifest.json")"
    echo "database_sha256=$(jq -er .sha256 "$destination/manifest.json")"
    echo "source=$source"
  } >> "$GITHUB_OUTPUT"
}

grype_pack_database() {
  local directory="$RUNNER_TEMP/platform-grype-database" bundle="$RUNNER_TEMP/platform-grype-cache-bundle"
  grype_verify_directory "$directory" "${GRYPE_DATABASE_MANIFEST_SHA256:?}"
  install -d -m 0700 "$bundle"
  cp "$directory/manifest.json" "$directory/grype-db.tar.zst" "$directory/policy.sha256" "$bundle/"
  local artifact="$RUNNER_TEMP/platform-grype-db-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT.tar"
  write_deterministic_tar "$bundle" "$artifact" 537919488
  echo "artifact=$artifact" >> "$GITHUB_OUTPUT"
}

grype_discover_cache() {
  require_linux_x64
  local runs="$RUNNER_TEMP/grype-cache-runs.json" artifacts="$RUNNER_TEMP/grype-cache-artifacts.json"
  # Only the protected default-branch producer in the platform repository may
  # supply this cache. PR artifacts and arbitrary workflow names are excluded.
  if ! gh api 'repos/collinbentley1/platform/actions/workflows/refresh-grype-db.yml/runs?branch=main&status=success&per_page=10' > "$runs"; then
    echo "Grype cache discovery unavailable; acquisition will require the upstream." >&2
    return 0
  fi
  grype_require_json "$runs" 1048576
  local run
  run="$(jq -er '
    [.workflow_runs[] |
      select(.head_branch == "main" and .conclusion == "success" and .run_attempt == 1 and
        (.event == "schedule" or .event == "workflow_dispatch") and
        .path == ".github/workflows/refresh-grype-db.yml" and
        .repository.id == 1255856466 and .head_repository.id == 1255856466 and
        (.created_at | fromdateiso8601) >= (now - 259200))] |
    first | .id | select(type == "number" and . > 0)
  ' "$runs")" || return 0
  if ! gh api "repos/collinbentley1/platform/actions/runs/$run/artifacts?per_page=100" > "$artifacts"; then
    echo "Grype cache artifact lookup unavailable; acquisition will require the upstream." >&2
    return 0
  fi
  grype_require_json "$artifacts" 1048576
  local record
  record="$(jq -cer --argjson run "$run" '
    [.artifacts[] | select(.name == ("platform-grype-db-" + ($run | tostring) + "-1.tar") and
      .expired == false and .workflow_run.id == $run and
      .workflow_run.repository_id == 1255856466 and .workflow_run.head_repository_id == 1255856466 and
      (.digest | type == "string" and test("^sha256:[0-9a-f]{64}$")) and
      .size_in_bytes > 0 and .size_in_bytes <= 537919488)] |
    select(length == 1) | .[0]
  ' "$artifacts")" || return 0
  {
    echo "artifact_id=$(jq -er .id <<< "$record")"
    echo "run_id=$run"
    echo "content_sha256=$(jq -er '.digest | sub("^sha256:";"")' <<< "$record")"
  } >> "$GITHUB_OUTPUT"
}
