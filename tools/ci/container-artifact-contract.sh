#!/bin/bash

set -euo pipefail

readonly REGCTL_VERSION=0.11.5
readonly REGCTL_SHA256=c93aa7638749f5aaac1a8e01787321889c78f0101809bb2880343478d0ba0467
readonly COSIGN_VERSION=3.1.3
readonly COSIGN_SHA256=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71
readonly SCANNER_SANDBOX_IMAGE=moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8
readonly OVEN_TOP_DIGEST=sha256:07235578f79ef8c6f97d94aee7938e76f5cdba5f21ae5dbfdd3d3d38058437eb
readonly OVEN_AMD64_DIGEST=sha256:8aac45197595035f697ea6b11cd73ce2401d82503fcb2540b5fac606973b242b
readonly DHI_DEV_TOP_DIGEST=sha256:d364f4eb6d20f8e906bdb9d12726995f8335878f46e0c1c69c910df9d92df5d8
readonly DHI_RUNTIME_TOP_DIGEST=sha256:b169efde3cf30151d66f3d7988cad69b4d08833cc4cfaeca7da6bda2bd0a89b3
readonly DHI_DEV_AMD64_DIGEST=sha256:58a392f5dec3be5cb20a2495baca84ac785f237a2d2904c5b9cad7ba11f3e475
readonly DHI_RUNTIME_AMD64_DIGEST=sha256:0f9e5f506d653e0f87e44bb5c24fece19f9fb7253016f6e49d7a4783026f876d
# Lossless base36 encoding of SHA-256(canonical dev/runtime top+amd64 tuple),
# left-zero-padded to exactly 50 characters. It fits in a Cloud Run label while
# preserving the full 256-bit identifier, including hashes whose base36 form is
# naturally shorter than 50 characters.
readonly DHI_PARITY_ID=1a4cho1elzg84pavos8mbanvvpmkieiht7kyhpjdofzpivf3k8
readonly MAX_BASE_BYTES=1610612736
readonly MAX_IMAGE_BYTES=1073741824
readonly MAX_TAR_ENTRIES=4096
readonly MAX_INDEX_JSON_BYTES=1048576
readonly MAX_MANIFEST_JSON_BYTES=4194304
readonly MAX_CONFIG_JSON_BYTES=4194304
readonly MAX_ATTESTATION_JSON_BYTES=16777216
readonly MAX_SCAN_JSON_BYTES=536870912
readonly MAX_JSON_DEPTH=64
readonly MAX_OCI_DESCRIPTORS=64
readonly MAX_OCI_LAYERS=256
readonly MAX_OCI_BLOBS=512
readonly DHI_ATTESTATION_POLICY_IMPLEMENTED=true
# Exact BuildKit v0.32.2 pkg:oci resolvedDependencies bytes are frozen by the
# workflow-equivalent tagged fixture and its hostile semantic regressions.
readonly BUILDKIT_PROVENANCE_URI_POLICY_IMPLEMENTED=true
readonly DHI_PUBLIC_KEY_SHA256=1d02bbccf149283ae6288d96264dcad3fb23ee1911d90324a48eab28e4cb8a5f
readonly DHI_CATALOG_LICENSE_SHA256=58881e3f5171ed2e98db7a4dbd64c16b9b5dbb2f5cbd9a56e79608a2360ad5f3
readonly GRYPE_DB_MANIFEST_SHA256=2409add386e2f92996559f098f991f2097c09681bb59fea38e77f67e01ffbf8e
readonly CONTRACT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly DHI_PUBLIC_KEY="$CONTRACT_ROOT/trust/docker-dhi-community-20260822.pub"
readonly DHI_CATALOG_LICENSE="$CONTRACT_ROOT/trust/docker-dhi-catalog-license-140f79e.txt"
readonly GRYPE_DB_MANIFEST="$CONTRACT_ROOT/grype-db.json"

die() {
  echo "$*" >&2
  exit 1
}

require_linux_x64() {
  test "${RUNNER_OS:-}" = Linux || die "This contract supports only GitHub-hosted Linux."
  test "${RUNNER_ARCH:-}" = X64 || die "This contract supports only X64 runners."
  test "${GITHUB_RUN_ATTEMPT:-}" = 1 || die "Workflow reruns are forbidden."
}

sha256_file() {
  sha256sum "$1" | cut -d ' ' -f 1
}

file_size() {
  stat -c %s "$1" 2>/dev/null || stat -f %z "$1"
}

verify_sha256() {
  local expected="$1" path="$2"
  require_sha256 "$expected"
  test "$(sha256_file "$path")" = "$expected" || die "SHA-256 verification failed."
}

require_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]] || die "Expected an unprefixed SHA-256 digest."
}

require_digest() {
  [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]] || die "Expected a sha256 OCI digest."
}

require_json_file() {
  local path="$1" max_bytes="$2"
  test -f "$path" && test ! -L "$path" || die "Expected a regular JSON file."
  [[ "$max_bytes" =~ ^[1-9][0-9]*$ ]] || die "JSON byte cap is invalid."
  test "$(file_size "$path")" -le "$max_bytes" || die "JSON file exceeds its byte cap."
  LC_ALL=C awk -v max="$MAX_JSON_DEPTH" '
    BEGIN { depth = 0; string = 0; escaped = 0; bad = 0 }
    {
      for (i = 1; i <= length($0); i++) {
        c = substr($0, i, 1)
        if (string) {
          if (escaped) escaped = 0
          else if (c == "\\") escaped = 1
          else if (c == "\"") string = 0
          continue
        }
        if (c == "\"") string = 1
        else if (c == "{" || c == "[") { depth++; if (depth > max) bad = 1 }
        else if (c == "}" || c == "]") { depth--; if (depth < 0) bad = 1 }
      }
    }
    END { exit (bad || string || depth != 0) ? 1 : 0 }
  ' "$path" || die "JSON nesting or quoting exceeds the reviewed parser envelope."
  jq -e . "$path" >/dev/null || die "JSON file is invalid."
}

load_reviewed_grype_db_manifest() {
  test -z "${DB_MANIFEST_JSON:-}" && test -z "${GRYPE_DB_MANIFEST_JSON:-}" ||
    die "Refusing an injected Grype database manifest."
  test -f "$GRYPE_DB_MANIFEST" && test ! -L "$GRYPE_DB_MANIFEST" ||
    die "The reviewed Grype database manifest is not a regular policy file."
  verify_sha256 "$GRYPE_DB_MANIFEST_SHA256" "$GRYPE_DB_MANIFEST"
  require_json_file "$GRYPE_DB_MANIFEST" 4096
  jq -cer '
    select((keys | sort) == ["built", "schemaVersion", "sha256", "url"]) |
    .sha256 as $sha |
    .built as $built |
    select($sha | test("^[0-9a-f]{64}$")) |
    select(.schemaVersion | test("^v6\\.[0-9]+\\.[0-9]+$")) |
    select($built | fromdateiso8601 | todateiso8601 == $built) |
    select(.url | test(("^https://grype\\.anchore\\.io/databases/v6/vulnerability-db_v6\\.[0-9]+\\.[0-9]+_[0-9TZ:-]+_[0-9]+\\.tar\\.zst\\?checksum=sha256%3A" + $sha + "$")))
  ' "$GRYPE_DB_MANIFEST" || die "The reviewed Grype database manifest schema drifted."
}

single_regular_file() {
  local directory="$1"
  local -a files
  mapfile -t files < <(find "$directory" -mindepth 1 -maxdepth 1 -type f -print)
  test "${#files[@]}" -eq 1 || die "Expected exactly one downloaded raw artifact."
  test ! -L "${files[0]}" || die "Downloaded artifact must not be a link."
  printf '%s\n' "${files[0]}"
}

validate_ustar_headers() {
  local archive="$1"
  local archive_size total_blocks block=0 entries=0
  archive_size="$(file_size "$archive")"
  test "$((archive_size % 512))" -eq 0 || die "Artifact is not a block-aligned ustar archive."
  total_blocks="$((archive_size / 512))"
  test "$total_blocks" -ge 3 || die "Artifact is too short to be a complete ustar archive."
  local header="$RUNNER_TEMP/platform-ustar-header-$RANDOM"
  while [ "$block" -lt "$total_blocks" ]; do
    dd if="$archive" of="$header" bs=512 skip="$block" count=1 status=none
    test "$(file_size "$header")" -eq 512 || die "Artifact contains a truncated ustar header."
    if [ "$(tr -d '\000' < "$header" | wc -c | tr -d '[:space:]')" = 0 ]; then
      test "$((total_blocks - block))" -ge 2 || die "Artifact is missing the second ustar end block."
      test "$(dd if="$archive" bs=512 skip="$block" status=none | tr -d '\000' | wc -c | tr -d '[:space:]')" = 0 ||
        die "Artifact hides data after the ustar end marker."
      rm -f -- "$header"
      return 0
    fi
    test "$(dd if="$header" bs=1 skip=257 count=5 status=none)" = ustar ||
      die "Artifact contains a non-ustar header."
    local type_byte size_octal size_bytes
    type_byte="$(od -An -t u1 -j 156 -N 1 "$header" | tr -d '[:space:]')"
    case "$type_byte" in
      0|48|53) ;;
      *) die "Artifact contains a link, sparse record, extension, or special file header." ;;
    esac
    size_octal="$(dd if="$header" bs=1 skip=124 count=12 status=none | tr -d '\000 ' )"
    [ -n "$size_octal" ] || size_octal=0
    [[ "$size_octal" =~ ^[0-7]+$ ]] || die "Artifact contains a non-octal ustar size."
    size_bytes="$((8#$size_octal))"
    if [ "$type_byte" = 53 ] && [ "$size_bytes" -ne 0 ]; then
      die "Artifact directory carries unexpected data."
    fi
    block="$((block + 1 + ((size_bytes + 511) / 512)))"
    entries="$((entries + 1))"
    test "$entries" -le "$MAX_TAR_ENTRIES" || die "Artifact has too many entries."
    test "$block" -lt "$total_blocks" || die "Artifact is missing its ustar end marker."
  done
  die "Artifact has no ustar end marker."
}

safe_extract_tar() {
  local archive="$1"
  local destination="$2"
  local max_bytes="$3"
  local listing="$RUNNER_TEMP/platform-tar-$RANDOM.list"
  test -f "$archive" && test ! -L "$archive" || die "Artifact is not a regular file."
  test "$(file_size "$archive")" -le "$max_bytes" || die "Artifact exceeds its byte cap."
  validate_ustar_headers "$archive"
  tar -tf "$archive" > "$listing"
  test "$(wc -l < "$listing")" -le "$MAX_TAR_ENTRIES" || die "Artifact has too many entries."
  local normalized="$listing.normalized"
  : > "$normalized"
  while IFS= read -r path; do
    [[ "$path" =~ ^[A-Za-z0-9._/-]+$ ]] || die "Artifact path contains unsupported bytes."
    local value="$path"
    if [ "$value" = "./" ]; then
      value="."
    else
      value="${value#./}"
      value="${value%/}"
    fi
    [ -n "$value" ] || die "Artifact contains an empty path."
    [[ "$value" != /* && "$value" != ../* && "$value" != */../* && "$value" != */.. ]] || die "Artifact contains path traversal."
    [[ "$value" != ./* && "$value" != */./* && "$value" != */. && "$value" != *//* ]] || die "Artifact contains a non-canonical alias path."
    printf '%s\n' "$value" >> "$normalized"
  done < "$listing"
  test "$(sort "$normalized" | uniq -d | wc -l)" -eq 0 || die "Artifact contains aliased or duplicate paths."
  if tar -tvf "$archive" | awk '
    substr($1, 1, 1) != "-" && substr($1, 1, 1) != "d" { bad = 1 }
    END { exit bad ? 0 : 1 }
  '; then
    die "Artifact contains a link or special file."
  fi
  local expanded="$listing.expanded" pipeline_status="$listing.pipeline-status"
  (
    set +o pipefail
    tar -xOf "$archive" 2> "$listing.extract-error" |
      head -c "$((max_bytes + 1))" |
      wc -c > "$expanded"
    printf '%s %s %s\n' "${PIPESTATUS[0]}" "${PIPESTATUS[1]}" "${PIPESTATUS[2]}" > "$pipeline_status"
  )
  local expanded_bytes tar_status head_status wc_status
  expanded_bytes="$(tr -d '[:space:]' < "$expanded")"
  read -r tar_status head_status wc_status < "$pipeline_status"
  [[ "$expanded_bytes" =~ ^[0-9]+$ ]] || die "Artifact expansion size is invalid."
  test "$expanded_bytes" -le "$max_bytes" || die "Artifact expands beyond its byte cap."
  test "$tar_status" = 0 && test "$head_status" = 0 && test "$wc_status" = 0 || {
    cat "$listing.extract-error" >&2
    die "Artifact could not be completely inspected before extraction."
  }
  test ! -e "$destination" && test ! -L "$destination" || die "Extraction destination already exists."
  install -d -m 0700 "$destination"
  tar -xf "$archive" -C "$destination" --no-same-owner --no-same-permissions
  if find "$destination" -type l -print -quit | grep -q . ||
     find "$destination" ! -type d ! -type f -print -quit | grep -q .; then
    die "Extracted artifact contains a link or special file."
  fi
  while IFS= read -r -d '' path; do
    local relative="${path#"$destination"/}"
    [[ "$relative" =~ ^[A-Za-z0-9._/-]+$ ]] || die "Extracted artifact path contains unsupported bytes."
  done < <(find "$destination" -mindepth 1 -print0)
  rm -f -- "$listing" "$normalized" "$expanded" "$pipeline_status" "$listing.extract-error"
}

write_deterministic_tar() {
  local source="$1"
  local destination="$2"
  local max_bytes="$3"
  test ! -e "$destination" && test ! -L "$destination" || die "Artifact path already exists."
  if find "$source" -type l -print -quit | grep -q . ||
     find "$source" ! -type d ! -type f -print -quit | grep -q .; then
    die "Bundle contains a link or special file."
  fi
  test "$(find "$source" -mindepth 1 | wc -l)" -le "$MAX_TAR_ENTRIES" || die "Bundle has too many entries."
  test "$(du -sb "$source" | cut -f1)" -le "$max_bytes" || die "Bundle exceeds its byte cap."
  tar --sort=name --format=ustar --mtime='UTC 1970-01-01' \
    --owner=0 --group=0 --numeric-owner --mode='u+rwX,go-rwx' \
    -cf "$destination" -C "$source" .
  test "$(file_size "$destination")" -le "$((max_bytes + 1048576))" || die "Tar overhead exceeded its cap."
}

install_regctl() {
  local destination="$1"
  test ! -e "$destination" && test ! -L "$destination" || die "regctl destination already exists."
  curl --disable --fail --show-error --silent --location --proto '=https' --tlsv1.2 \
    --output "$destination" \
    "https://github.com/regclient/regclient/releases/download/v${REGCTL_VERSION}/regctl-linux-amd64"
  verify_sha256 "$REGCTL_SHA256" "$destination"
  chmod 0500 "$destination"
  "$destination" version | grep -F "v${REGCTL_VERSION}" >/dev/null
}

install_cosign() {
  local destination="$1"
  test ! -e "$destination" && test ! -L "$destination" || die "cosign destination already exists."
  curl --disable --fail --show-error --silent --location --proto '=https' --tlsv1.2 \
    --output "$destination" \
    "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64"
  verify_sha256 "$COSIGN_SHA256" "$destination"
  chmod 0500 "$destination"
  "$destination" version --json | jq -e \
    --arg version "v${COSIGN_VERSION}" \
    '.gitVersion == $version and .gitCommit == "11926fa5bbbbde47e88fc006b625a17769b743b2" and .gitTreeState == "clean" and .platform == "linux/amd64"' \
    >/dev/null
}

verify_dhi_attestation() {
  local regctl="$1" cosign="$2" role="$3" child="$4" child_size="$5"
  local predicate="$6" attestation="$7" attestation_size="$8" payload="$9" payload_size="${10}"
  require_digest "$child"
  require_digest "$attestation"
  require_digest "$payload"
  [[ "$child_size" =~ ^[1-9][0-9]*$ && "$attestation_size" =~ ^[1-9][0-9]*$ && "$payload_size" =~ ^[1-9][0-9]*$ ]] ||
    die "DHI attestation sizes are invalid."
  local proof_root="$RUNNER_TEMP/platform-dhi-attestations"
  install -d -m 0700 "$proof_root"
  local stem="${role}-${attestation#sha256:}"
  local signature="$proof_root/${stem}.signature.json"
  local manifest="$proof_root/${stem}.manifest.json"
  local statement="$proof_root/${stem}.statement.json"
  local reference="dhi.io/bun@${attestation}"

  "$cosign" verify --key "$DHI_PUBLIC_KEY" --insecure-ignore-tlog=true "$reference" > "$signature"
  require_json_file "$signature" "$MAX_ATTESTATION_JSON_BYTES"
  jq -e --arg digest "$attestation" --arg child "$child" --arg predicate "$predicate" '
    (type == "array" and length == 1) and
    .[0].critical == {
      identity:{"docker-reference":"registry.scout.docker.com/dhi/bun"},
      image:{"docker-manifest-digest":$digest},
      type:"cosign container image signature"
    } and
    .[0].optional.type == "https://in-toto.io/Statement/v0.1" and
    .[0].optional.predicateType == $predicate and
    .[0].optional.subject == ("dhi/bun@" + $child)
  ' "$signature" >/dev/null

  "$regctl" manifest get "$reference" --format raw-body > "$manifest"
  test "$(file_size "$manifest")" = "$attestation_size" || die "DHI attestation manifest size drifted."
  test "$(sha256_file "$manifest")" = "${attestation#sha256:}" || die "DHI attestation manifest digest drifted."
  require_json_file "$manifest" "$MAX_MANIFEST_JSON_BYTES"
  jq -e --arg child "$child" --argjson childSize "$child_size" --arg predicate "$predicate" \
    --arg payload "$payload" --argjson payloadSize "$payload_size" '
    (keys | sort) == ["annotations", "artifactType", "config", "layers", "mediaType", "schemaVersion", "subject"] and
    .schemaVersion == 2 and .mediaType == "application/vnd.oci.image.manifest.v1+json" and
    .artifactType == "application/vnd.in-toto+json" and
    .annotations == {"in-toto.io/predicate-type":$predicate} and
    .config == {
      data:"e30=",digest:"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
      mediaType:"application/vnd.oci.empty.v1+json",size:2
    } and
    .subject == {digest:$child,mediaType:"application/vnd.oci.image.manifest.v1+json",size:$childSize} and
    .layers == [{annotations:{"in-toto.io/predicate-type":$predicate},digest:$payload,mediaType:"application/vnd.in-toto+json",size:$payloadSize}]
  ' "$manifest" >/dev/null

  "$regctl" blob get dhi.io/bun "$payload" > "$statement"
  test "$(file_size "$statement")" = "$payload_size" || die "DHI attestation statement size drifted."
  test "$(sha256_file "$statement")" = "${payload#sha256:}" || die "DHI attestation statement digest drifted."
  require_json_file "$statement" "$MAX_ATTESTATION_JSON_BYTES"
  jq -e --arg child "${child#sha256:}" --arg predicate "$predicate" '
    ._type == "https://in-toto.io/Statement/v0.1" and .predicateType == $predicate and
    (.subject | type == "array" and length > 0) and
    all(.subject[];
      ((keys | sort) == ["digest", "name"]) and
      (.name | type == "string" and length > 0) and
      .digest == {sha256:$child})
  ' "$statement" >/dev/null
}

verify_dhi_attestations() {
  local regctl="$1" cosign="$2" role="$3" child="$4"
  case "$role" in
    dhi_dev)
      test "$child" = "$DHI_DEV_AMD64_DIGEST" || die "DHI dev child is not the reviewed image."
      verify_dhi_attestation "$regctl" "$cosign" "$role" "$child" 2628 \
        https://cyclonedx.org/bom/v1.6 sha256:7e87da3b5cfb7e77966ff5737a0c5549791d4b392ee4db9791b6553ff55fcaea 757 \
        sha256:08afdf9d5be3ade8380aa62914056840e3efd041e02c9cd77764d7d1054a8764 11073
      verify_dhi_attestation "$regctl" "$cosign" "$role" "$child" 2628 \
        https://docker.com/dhi/source/v0.1 sha256:db2c587f0f4cdae81d1091fc857819daa9543baa834df91a62b61313c7f2df3c 764 \
        sha256:2767bdbf1710c763ee12865c67c450653d99aa1a89ad76d32950b22d587ddb94 1179
      verify_dhi_attestation "$regctl" "$cosign" "$role" "$child" 2628 \
        https://slsa.dev/provenance/v1 sha256:d6023157a42a7a23bae0270c7e6fe94334483174ac6ad17ca9135d83a67a3363 757 \
        sha256:2487fd548d09b100b2df2b9e4017f8b4d819bb3b5259942b61283081e64ea9f7 74015
      verify_dhi_attestation "$regctl" "$cosign" "$role" "$child" 2628 \
        https://spdx.dev/Document sha256:4a19117f77148b150fe191e6a551a382f9798fa97c5cb3d0dfa306efae4f85c4 747 \
        sha256:9c3a03e8bba65010c642b590d81fdef67173eb49de8203d1c4eddebe94c5c539 61844
      ;;
    dhi_runtime)
      test "$child" = "$DHI_RUNTIME_AMD64_DIGEST" || die "DHI runtime child is not the reviewed image."
      verify_dhi_attestation "$regctl" "$cosign" "$role" "$child" 2598 \
        https://cyclonedx.org/bom/v1.6 sha256:c564494dc09316701846d710483f411371bf4e1fbd7e88eb464e0b5f52babfa1 756 \
        sha256:657ec8415ad44143fd6503d545418d13446d09ed41440fbb46675fbe7b06897a 7145
      verify_dhi_attestation "$regctl" "$cosign" "$role" "$child" 2598 \
        https://docker.com/dhi/source/v0.1 sha256:3893314865c6e9a5491a268b84182ff42d72ab1e83880ac7909ab354ce85dff5 764 \
        sha256:0941795b6d575d84225bcced812e0ef9ab30c5d6928baa5d9b485da9cb3fcfc7 1155
      verify_dhi_attestation "$regctl" "$cosign" "$role" "$child" 2598 \
        https://slsa.dev/provenance/v1 sha256:dcbfea0e968e9ccb0ac80f2094ba1162a68e4f45a4aa8ad22ec3a5c913586091 757 \
        sha256:2de62e0f64dc97a492f664bd675d2bba6951958d2dc0a045c7d14cae58d1d43c 71337
      verify_dhi_attestation "$regctl" "$cosign" "$role" "$child" 2598 \
        https://spdx.dev/Document sha256:e9aa59a4fbf051e086fb56f5bae160242ba0080bf5b83bc06bde9631d616dd4d 747 \
        sha256:7aba6d2697e793fcb2dcea4a181b181e16735e4abddb00cda16e30564c5e5e7e 36639
      ;;
    *) die "DHI attestation verification was requested for an unsupported role." ;;
  esac
}

verify_expected_child() {
  local regctl="$1" cosign="$2" role="$3" child="$4" expected_child="$5"
  local verification_mode
  case "$role" in
    oven) verification_mode=exact-only ;;
    dhi_dev | dhi_runtime) verification_mode=dhi-attestations ;;
    *) die "Child verification was requested for an unsupported role." ;;
  esac
  require_digest "$child"
  if [ "$expected_child" = discover ]; then
    return
  fi
  require_digest "$expected_child"
  test "$child" = "$expected_child" || die "Pinned linux/amd64 child digest mismatch for $role."
  if [ "$verification_mode" = dhi-attestations ]; then
    verify_dhi_attestations "$regctl" "$cosign" "$role" "$child"
  fi
}

expected_dhi_proof_stems() {
  cat <<'EOF'
dhi_dev-4a19117f77148b150fe191e6a551a382f9798fa97c5cb3d0dfa306efae4f85c4
dhi_dev-7e87da3b5cfb7e77966ff5737a0c5549791d4b392ee4db9791b6553ff55fcaea
dhi_dev-d6023157a42a7a23bae0270c7e6fe94334483174ac6ad17ca9135d83a67a3363
dhi_dev-db2c587f0f4cdae81d1091fc857819daa9543baa834df91a62b61313c7f2df3c
dhi_runtime-3893314865c6e9a5491a268b84182ff42d72ab1e83880ac7909ab354ce85dff5
dhi_runtime-c564494dc09316701846d710483f411371bf4e1fbd7e88eb464e0b5f52babfa1
dhi_runtime-dcbfea0e968e9ccb0ac80f2094ba1162a68e4f45a4aa8ad22ec3a5c913586091
dhi_runtime-e9aa59a4fbf051e086fb56f5bae160242ba0080bf5b83bc06bde9631d616dd4d
EOF
}

validate_base_manifest() {
  local manifest="$1"
  require_json_file "$manifest" "$MAX_MANIFEST_JSON_BYTES"
  jq -e \
    --arg oven "$OVEN_TOP_DIGEST" \
    --arg dev "$DHI_DEV_TOP_DIGEST" \
    --arg runtime "$DHI_RUNTIME_TOP_DIGEST" \
    --arg ovenChild "$OVEN_AMD64_DIGEST" \
    --arg devChild "$DHI_DEV_AMD64_DIGEST" \
    --arg runtimeChild "$DHI_RUNTIME_AMD64_DIGEST" '
    (keys | sort) == ["artifactType", "images", "proofs", "schemaVersion"] and
    .artifactType == "platform-base-images" and .schemaVersion == 1 and
    [.images[].role] == ["oven", "dhi_dev", "dhi_runtime"] and
    [.images[].topDigest] == [$oven, $dev, $runtime] and
    .images[0].childDigest == $ovenChild and .images[1].childDigest == $devChild and .images[2].childDigest == $runtimeChild and
    [.images[].source] == ["docker.io/oven/bun:1.4.0-alpine", "dhi.io/bun:1-alpine-dev", "dhi.io/bun:1-alpine"] and
    [.images[].distributionLicense] == ["MIT", "Apache-2.0", "Apache-2.0"] and
    [.images[].embeddedLicenseEvidence] == ["upstream-image", "signed-dhi-attestations", "signed-dhi-attestations"] and
    all(.images[];
      (keys | sort) == ["childDigest", "configDigest", "distributionLicense", "embeddedLicenseEvidence", "layers", "role", "source", "topDigest"] and
      (.childDigest | test("^sha256:[0-9a-f]{64}$")) and
      (.configDigest | test("^sha256:[0-9a-f]{64}$")) and
      (.layers | length > 0) and all(.layers[]; test("^sha256:[0-9a-f]{64}$"))) and
    (.proofs | type == "array" and length == 24) and
    all(.proofs[];
      (keys | sort) == ["path", "sha256", "size"] and
      (.path | test("^proofs/dhi/dhi_(dev|runtime)-[0-9a-f]{64}\\.(manifest|signature|statement)\\.json$")) and
      (.sha256 | test("^[0-9a-f]{64}$")) and
      (.size | type == "number" and . > 0 and . <= 16777216))
  ' "$manifest" >/dev/null
}

validate_flat_sha256_blob_directory() {
  local directory="$1" context="$2"
  test -d "$directory" && test ! -L "$directory" || die "$context blob directory is invalid."
  if find "$directory" -mindepth 2 -print -quit | grep -q . ||
     find "$directory" -mindepth 1 -maxdepth 1 ! -type f -print -quit | grep -q .; then
    die "$context blob directory contains a nested or non-regular entry."
  fi
  while IFS= read -r -d '' blob; do
    [[ "${blob##*/}" =~ ^[0-9a-f]{64}$ ]] || die "$context blob path is invalid."
  done < <(find "$directory" -mindepth 1 -maxdepth 1 -type f -print0)
}

validate_oci_layout() {
  local layout="$1"
  local expected_child="$2"
  local expected_config="$3"
  require_digest "$expected_child"
  require_digest "$expected_config"
  test -d "$layout" && test ! -L "$layout" || die "Base OCI layout is invalid."
  test -d "$layout/blobs" && test ! -L "$layout/blobs" || die "Base OCI blob root is invalid."
  require_json_file "$layout/oci-layout" "$MAX_INDEX_JSON_BYTES"
  require_json_file "$layout/index.json" "$MAX_INDEX_JSON_BYTES"
  test "$(jq -er 'select((keys | sort) == ["imageLayoutVersion"]) | .imageLayoutVersion' "$layout/oci-layout")" = 1.0.0
  jq -e --arg child "$expected_child" '
    ((keys - ["manifests", "mediaType", "schemaVersion"]) | length) == 0 and
    .schemaVersion == 2 and
    (.mediaType // "application/vnd.oci.image.index.v1+json") == "application/vnd.oci.image.index.v1+json" and
    (.manifests | length == 1) and
    ((.manifests[0] | keys - ["annotations", "digest", "mediaType", "platform", "size"]) | length) == 0 and
    .manifests[0].digest == $child and
    (.manifests[0].mediaType == "application/vnd.oci.image.manifest.v1+json" or .manifests[0].mediaType == "application/vnd.docker.distribution.manifest.v2+json") and
    (.manifests[0].size | type == "number" and . > 0)
  ' "$layout/index.json" >/dev/null
  local manifest="$layout/blobs/sha256/${expected_child#sha256:}"
  validate_flat_sha256_blob_directory "$layout/blobs/sha256" "Base OCI"
  require_json_file "$manifest" "$MAX_MANIFEST_JSON_BYTES"
  verify_sha256 "${expected_child#sha256:}" "$manifest"
  test "$(file_size "$manifest")" = "$(jq -er '.manifests[0].size' "$layout/index.json")"
  jq -e --arg config "$expected_config" '
    ((keys - ["annotations", "config", "layers", "mediaType", "schemaVersion"]) | length) == 0 and
    .schemaVersion == 2 and .config.digest == $config and
    ((.config | keys - ["annotations", "digest", "mediaType", "size"]) | length) == 0 and
    (.config.mediaType == "application/vnd.oci.image.config.v1+json" or .config.mediaType == "application/vnd.docker.container.image.v1+json") and
    (.config.size | type == "number" and . > 0) and
    (.layers | length > 0) and
    (.layers | length <= 256) and
    all(.layers[];
      ((keys - ["annotations", "digest", "mediaType", "size"]) | length) == 0 and
      (.digest | test("^sha256:[0-9a-f]{64}$")) and (.size > 0) and
      (.mediaType == "application/vnd.oci.image.layer.v1.tar+gzip" or
       .mediaType == "application/vnd.oci.image.layer.v1.tar+zstd" or
       .mediaType == "application/vnd.docker.image.rootfs.diff.tar.gzip"))
  ' "$manifest" >/dev/null
  while IFS=$'\t' read -r digest size; do
    local blob="$layout/blobs/sha256/${digest#sha256:}"
    test "$(file_size "$blob")" = "$size" || die "OCI blob size mismatch."
    verify_sha256 "${digest#sha256:}" "$blob"
  done < <(jq -er '((.config | [.digest, (.size | tostring)]), (.layers[] | [.digest, (.size | tostring)])) | @tsv' "$manifest")
  local config="$layout/blobs/sha256/${expected_config#sha256:}"
  require_json_file "$config" "$MAX_CONFIG_JSON_BYTES"
  jq -e '.os == "linux" and .architecture == "amd64" and .rootfs.type == "layers"' "$config" >/dev/null
  while read -r blob; do
    local name="${blob##*/}"
    [[ "$name" =~ ^[0-9a-f]{64}$ ]] || die "OCI blob path is invalid."
    verify_sha256 "$name" "$blob"
  done < <(find "$layout/blobs/sha256" -mindepth 1 -maxdepth 1 -type f -print | sort)
  local reachable="$RUNNER_TEMP/base-reachable-$RANDOM"
  {
    printf '%s\n' "${expected_child#sha256:}" "${expected_config#sha256:}"
    jq -r '.layers[].digest | sub("^sha256:"; "")' "$manifest"
  } | sort -u > "$reachable"
  find "$layout/blobs/sha256" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort -u > "$reachable.actual"
  test "$(wc -l < "$reachable.actual")" -le "$MAX_OCI_BLOBS" || die "Base layout has too many blobs."
  cmp "$reachable" "$reachable.actual" || die "Base layout contains missing or unreachable blobs."
  test "$(find "$layout" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | tr '\n' ' ')" = "blobs index.json oci-layout " || die "Base layout has extra top-level paths."
  test "$(find "$layout/blobs" -mindepth 1 -maxdepth 1 -printf '%f\n')" = sha256 || die "Base layout has an unsupported digest algorithm path."
}

validate_base_bundle() {
  local root="$1"
  test -d "$root" && test ! -L "$root" || die "Base bundle root is invalid."
  local directory
  for directory in layouts layouts/oven layouts/dhi_dev layouts/dhi_runtime licenses proofs proofs/dhi top-manifests; do
    test -d "$root/$directory" && test ! -L "$root/$directory" || die "Base bundle directory set drifted."
  done
  if find "$root/licenses" "$root/top-manifests" -mindepth 1 -maxdepth 1 ! -type f -print -quit | grep -q . ||
     find "$root/proofs" -mindepth 1 -maxdepth 1 ! -type d -print -quit | grep -q . ||
     find "$root/proofs/dhi" -mindepth 1 -maxdepth 1 ! -type f -print -quit | grep -q .; then
    die "Base bundle contains an unexpected non-regular inventory entry."
  fi
  test "$(find "$root/proofs" -mindepth 1 -type d -printf '%P\n' | sort | tr '\n' ' ')" = "dhi " ||
    die "Base bundle proof directory set drifted."
  validate_base_manifest "$root/manifest.json"
  test "$(find "$root" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | tr '\n' ' ')" = "layouts licenses manifest.json proofs top-manifests " || die "Base bundle has extra top-level paths."
  test "$(find "$root/layouts" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | tr '\n' ' ')" = "dhi_dev dhi_runtime oven " || die "Base bundle has an unexpected layout set."
  test "$(find "$root/top-manifests" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort | tr '\n' ' ')" = "dhi_dev.json dhi_runtime.json oven.json " || die "Base bundle has an unexpected top-manifest set."
  test "$(find "$root/licenses" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort | tr '\n' ' ')" = "DHI-CATALOG-LICENSE.txt DHI-NOTICE.txt " || die "Base bundle has an unexpected license set."
  test "$(sha256_file "$root/licenses/DHI-CATALOG-LICENSE.txt")" = "$DHI_CATALOG_LICENSE_SHA256" || die "Bundled DHI catalog license drifted."

  local expected="$RUNNER_TEMP/base-proofs-expected-$RANDOM"
  local actual="$expected.actual" listed="$expected.listed"
  : > "$expected"
  while read -r stem; do
    for suffix in manifest signature statement; do
      printf 'proofs/dhi/%s.%s.json\n' "$stem" "$suffix" >> "$expected"
    done
  done < <(expected_dhi_proof_stems)
  sort -o "$expected" "$expected"
  (cd "$root" && find proofs -type f -printf '%p\n' | sort) > "$actual"
  jq -r '.proofs[].path' "$root/manifest.json" | sort > "$listed"
  cmp "$expected" "$actual" || die "Base bundle proof file set drifted."
  cmp "$expected" "$listed" || die "Base manifest proof inventory drifted."
  while IFS=$'\t' read -r path digest size; do
    local proof="$root/$path"
    test -f "$proof" && test ! -L "$proof" || die "A declared DHI proof is missing."
    test "$(file_size "$proof")" = "$size" || die "A DHI proof size drifted."
    test "$(sha256_file "$proof")" = "$digest" || die "A DHI proof digest drifted."
    require_json_file "$proof" "$MAX_ATTESTATION_JSON_BYTES"
  done < <(jq -er '.proofs[] | [.path, .sha256, (.size | tostring)] | @tsv' "$root/manifest.json")

  while read -r stem; do
    local role="${stem%%-*}" attestation="sha256:${stem#*-}"
    local manifest="$root/proofs/dhi/${stem}.manifest.json"
    local signature="$root/proofs/dhi/${stem}.signature.json"
    local statement="$root/proofs/dhi/${stem}.statement.json"
    test "$(sha256_file "$manifest")" = "${attestation#sha256:}" || die "A frozen DHI proof manifest digest drifted."
    local child predicate payload
    child="$(jq -er '.subject.digest | select(test("^sha256:[0-9a-f]{64}$"))' "$manifest")"
    predicate="$(jq -er '.annotations["in-toto.io/predicate-type"] | select(type == "string")' "$manifest")"
    payload="$(jq -er '.layers | if length == 1 then .[0].digest else error("expected one statement") end | select(test("^sha256:[0-9a-f]{64}$"))' "$manifest")"
    case "$role" in
      dhi_dev) test "$child" = "$DHI_DEV_AMD64_DIGEST" ;;
      dhi_runtime) test "$child" = "$DHI_RUNTIME_AMD64_DIGEST" ;;
      *) die "A DHI proof role is invalid." ;;
    esac
    test "$(sha256_file "$statement")" = "${payload#sha256:}" || die "A frozen DHI statement digest drifted."
    jq -e --arg digest "$attestation" --arg child "$child" --arg predicate "$predicate" '
      (type == "array" and length == 1) and
      .[0].critical == {
        identity:{"docker-reference":"registry.scout.docker.com/dhi/bun"},
        image:{"docker-manifest-digest":$digest},
        type:"cosign container image signature"
      } and
      .[0].optional.type == "https://in-toto.io/Statement/v0.1" and
      .[0].optional.predicateType == $predicate and
      .[0].optional.subject == ("dhi/bun@" + $child)
    ' "$signature" >/dev/null
    jq -e --arg child "${child#sha256:}" --arg predicate "$predicate" '
      ._type == "https://in-toto.io/Statement/v0.1" and .predicateType == $predicate and
      (.subject | type == "array" and length > 0) and
      all(.subject[]; (keys | sort) == ["digest", "name"] and .digest == {sha256:$child})
    ' "$statement" >/dev/null
  done < <(expected_dhi_proof_stems)

  while IFS=$'\t' read -r role top child config; do
    local top_manifest="$root/top-manifests/$role.json"
    test "$(sha256_file "$top_manifest")" = "${top#sha256:}" || die "A bundled top manifest digest drifted."
    require_json_file "$top_manifest" "$MAX_INDEX_JSON_BYTES"
    validate_oci_layout "$root/layouts/$role" "$child" "$config"
  done < <(jq -er '.images[] | [.role, .topDigest, .childDigest, .configDigest] | @tsv' "$root/manifest.json")
}

prefetch() {
  require_linux_x64
  test -f "$DHI_PUBLIC_KEY" && test ! -L "$DHI_PUBLIC_KEY" || die "Vendored Docker DHI key is absent."
  test "$(sha256_file "$DHI_PUBLIC_KEY")" = "$DHI_PUBLIC_KEY_SHA256" || die "Vendored Docker DHI key drifted."
  test -f "$DHI_CATALOG_LICENSE" && test ! -L "$DHI_CATALOG_LICENSE" || die "Vendored Docker DHI license is absent."
  test "$(sha256_file "$DHI_CATALOG_LICENSE")" = "$DHI_CATALOG_LICENSE_SHA256" || die "Vendored Docker DHI license drifted."
  [ "$DHI_ATTESTATION_POLICY_IMPLEMENTED" = true ] ||
    die "Docker DHI Community signature and SBOM trust material is not yet frozen; prefetch is fail-closed."
  test -n "${DHI_USERNAME:-}" && test -n "${DHI_PUBLIC_READ_TOKEN:-}" || die "DHI read credentials are absent."
  local kind="${ARTIFACT_KIND:-}"
  [[ "$kind" == preview || "$kind" == production ]] || die "Artifact kind must be preview or production."
  umask 077
  local regctl="$RUNNER_TEMP/regctl-v${REGCTL_VERSION}"
  local cosign="$RUNNER_TEMP/cosign-v${COSIGN_VERSION}"
  local auth="$RUNNER_TEMP/platform-regctl-auth"
  local bundle="$RUNNER_TEMP/platform-base-bundle"
  local artifact="$RUNNER_TEMP/platform-${kind}-bases-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}.tar"
  test ! -e "$auth" && test ! -L "$auth" && test ! -e "$bundle" && test ! -L "$bundle" || die "Prefetch path exists."
  install -d -m 0700 "$auth/xdg" "$auth/docker" "$auth/regctl" "$bundle/layouts" "$bundle/top-manifests" "$bundle/licenses" "$bundle/proofs/dhi"
  cleanup_dhi_auth() {
    set +e
    rm -rf -- "$auth"
    unset DHI_PUBLIC_READ_TOKEN DHI_USERNAME docker_auth XDG_CONFIG_HOME DOCKER_CONFIG REGCTL_CONFIG
  }
  trap cleanup_dhi_auth EXIT
  export XDG_CONFIG_HOME="$auth/xdg" DOCKER_CONFIG="$auth/docker" REGCTL_CONFIG="$auth/regctl/config.json"
  printf '{"auths":{}}\n' > "$DOCKER_CONFIG/config.json"
  printf '{"hosts":{}}\n' > "$REGCTL_CONFIG"
  chmod 0600 "$DOCKER_CONFIG/config.json" "$REGCTL_CONFIG"
  install_regctl "$regctl"
  install_cosign "$cosign"

  fetch_one() {
    local role="$1" source="$2" top="$3" expected_child="$4" distribution_license="$5" embedded_license_evidence="$6"
    local top_json="$bundle/top-manifests/$role.json"
    local child_json="$RUNNER_TEMP/$role-child.json"
    local layout="$bundle/layouts/$role"
    "$regctl" manifest get "${source}@${top}" --format raw-body > "$top_json"
    test "$(sha256_file "$top_json")" = "${top#sha256:}" || die "Top manifest digest mismatch."
    require_json_file "$top_json" "$MAX_INDEX_JSON_BYTES"
    local child
    child="$(jq -er '
      select(.schemaVersion == 2) |
      select(.mediaType == "application/vnd.oci.image.index.v1+json" or .mediaType == "application/vnd.docker.distribution.manifest.list.v2+json") |
      [.manifests[] |
        select(.platform.os == "linux" and .platform.architecture == "amd64") |
        select((.platform.variant // "") == "") |
        select((.urls // []) == [] and (.data // "") == "") |
        .digest] |
      if length == 1 then .[0] else error("expected one linux/amd64 child") end |
      select(test("^sha256:[0-9a-f]{64}$"))
    ' "$top_json")"
    verify_expected_child "$regctl" "$cosign" "$role" "$child" "$expected_child"
    "$regctl" manifest get "${source}@${child}" --format raw-body > "$child_json"
    test "$(sha256_file "$child_json")" = "${child#sha256:}" || die "Child manifest digest mismatch."
    require_json_file "$child_json" "$MAX_MANIFEST_JSON_BYTES"
    "$regctl" image copy --digest-tags=false --referrers=false --include-external=false "${source}@${child}" "ocidir://${layout}:base"
    test "$("$regctl" image digest "ocidir://${layout}:base")" = "$child"
    local config
    config="$(jq -er '.config.digest | select(test("^sha256:[0-9a-f]{64}$"))' "$child_json")"
    local layers
    layers="$(jq -c '[.layers[].digest]' "$child_json")"
    jq -cnS --arg child "$child" --arg config "$config" --arg distributionLicense "$distribution_license" \
      --arg embeddedLicenseEvidence "$embedded_license_evidence" --arg role "$role" --arg source "$source" --arg top "$top" --argjson layers "$layers" \
      '{childDigest:$child,configDigest:$config,distributionLicense:$distributionLicense,embeddedLicenseEvidence:$embeddedLicenseEvidence,layers:$layers,role:$role,source:$source,topDigest:$top}' > "$RUNNER_TEMP/$role-record.json"
  }

  fetch_one oven docker.io/oven/bun:1.4.0-alpine "$OVEN_TOP_DIGEST" "$OVEN_AMD64_DIGEST" MIT upstream-image
  docker_auth="$(printf '%s:%s' "$DHI_USERNAME" "$DHI_PUBLIC_READ_TOKEN" | base64 --wrap=0)"
  jq -cn --arg auth "$docker_auth" '{auths:{"dhi.io":{auth:$auth}}}' > "$DOCKER_CONFIG/config.json"
  chmod 0600 "$DOCKER_CONFIG/config.json"
  unset docker_auth
  printf '%s' "$DHI_PUBLIC_READ_TOKEN" | "$regctl" registry login dhi.io --user "$DHI_USERNAME" --pass-stdin
  unset DHI_PUBLIC_READ_TOKEN
  fetch_one dhi_dev dhi.io/bun:1-alpine-dev "$DHI_DEV_TOP_DIGEST" "$DHI_DEV_AMD64_DIGEST" Apache-2.0 signed-dhi-attestations
  fetch_one dhi_runtime dhi.io/bun:1-alpine "$DHI_RUNTIME_TOP_DIGEST" "$DHI_RUNTIME_AMD64_DIGEST" Apache-2.0 signed-dhi-attestations
  "$regctl" registry logout dhi.io
  cleanup_dhi_auth
  test ! -e "$auth" && test ! -L "$auth"
  trap - EXIT

  local proof_source="$RUNNER_TEMP/platform-dhi-attestations"
  test "$(find "$proof_source" -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 24 || die "Expected all 24 DHI public proof files."
  while read -r proof; do
    install -m 0600 "$proof" "$bundle/proofs/dhi/${proof##*/}"
  done < <(find "$proof_source" -mindepth 1 -maxdepth 1 -type f -print | sort)
  local proof_records="$RUNNER_TEMP/platform-dhi-proof-records.json"
  while read -r proof; do
    jq -cnS --arg path "proofs/dhi/${proof##*/}" --arg sha256 "$(sha256_file "$proof")" --argjson size "$(file_size "$proof")" \
      '{path:$path,sha256:$sha256,size:$size}'
  done < <(find "$bundle/proofs/dhi" -mindepth 1 -maxdepth 1 -type f -print | sort) | jq -sS . > "$proof_records"

  # These reviewed notices accompany the exact signed Community image evidence.
  cat > "$bundle/licenses/DHI-NOTICE.txt" <<'EOF'
Docker Hardened Images Community distribution notice

The DHI Community distribution is Apache-2.0 licensed. The Bun program and
embedded packages retain their own licenses; the exact signed CycloneDX, SPDX,
DHI source, and SLSA statements verified by this contract are the authoritative
component-license and source evidence for these immutable image children.
EOF
  install -m 0600 "$DHI_CATALOG_LICENSE" "$bundle/licenses/DHI-CATALOG-LICENSE.txt"
  jq -cnS --argjson oven "$(cat "$RUNNER_TEMP/oven-record.json")" --argjson dev "$(cat "$RUNNER_TEMP/dhi_dev-record.json")" --argjson runtime "$(cat "$RUNNER_TEMP/dhi_runtime-record.json")" --slurpfile proofs "$proof_records" \
    '{artifactType:"platform-base-images",images:[$oven,$dev,$runtime],proofs:$proofs[0],schemaVersion:1}' > "$bundle/manifest.json"
  validate_base_bundle "$bundle"
  write_deterministic_tar "$bundle" "$artifact" "$MAX_BASE_BYTES"
  echo "artifact=$artifact" >> "$GITHUB_OUTPUT"
  echo "content_sha256=$(sha256_file "$artifact")" >> "$GITHUB_OUTPUT"
  echo "manifest_sha256=$(sha256_file "$bundle/manifest.json")" >> "$GITHUB_OUTPUT"
}

verify_base() {
  require_linux_x64
  local artifact
  artifact="$(single_regular_file "${ARTIFACT_DOWNLOAD_DIR:?}")"
  require_sha256 "${EXPECTED_CONTENT_SHA256:?}"
  require_sha256 "${EXPECTED_MANIFEST_SHA256:?}"
  verify_sha256 "$EXPECTED_CONTENT_SHA256" "$artifact"
  local root="$RUNNER_TEMP/platform-verified-bases-$RANDOM"
  safe_extract_tar "$artifact" "$root" "$((MAX_BASE_BYTES + 1048576))"
  verify_sha256 "$EXPECTED_MANIFEST_SHA256" "$root/manifest.json"
  validate_base_bundle "$root"
  for role in oven dhi_dev dhi_runtime; do
    local child config
    child="$(jq -er --arg role "$role" '.images[] | select(.role == $role) | .childDigest' "$root/manifest.json")"
    config="$(jq -er --arg role "$role" '.images[] | select(.role == $role) | .configDigest' "$root/manifest.json")"
    echo "${role}_layout=$root/layouts/$role" >> "$GITHUB_OUTPUT"
    echo "${role}_child_digest=$child" >> "$GITHUB_OUTPUT"
  done
  echo "base_root=$root" >> "$GITHUB_OUTPUT"
}

validate_application_oci() {
  [ "$BUILDKIT_PROVENANCE_URI_POLICY_IMPLEMENTED" = true ] ||
    die "Exact BuildKit v0.32.2 provenance material URIs are not yet frozen; application OCI validation is fail-closed."
  validate_application_oci_impl "$@"
}

validate_runtime_config_lineage() {
  local config="$1" runtime_config="$2" expected_head="$3" expected_repository="$4"
  require_json_file "$config" "$MAX_CONFIG_JSON_BYTES"
  require_json_file "$runtime_config" "$MAX_CONFIG_JSON_BYTES"
  [[ "$expected_head" =~ ^[0-9a-f]{40}$ ]] || die "Runtime config source SHA is invalid."
  [[ "$expected_repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "Runtime config repository is invalid."
  jq -e --slurpfile base "$runtime_config" --arg head "$expected_head" --arg source "https://github.com/${expected_repository}" '
    def without_env($keys):
      [.[] | select((split("=")[0] as $name | $keys | index($name)) == null)];
    (keys | sort) == ["architecture", "config", "created", "history", "os", "rootfs"] and
    .os == "linux" and .architecture == "amd64" and
    ($base[0].config
      | .Env = (((.Env // [])
          | map(if startswith("BUN_VERSION=") then "BUN_VERSION=1.4.0" else . end)
          | without_env(["NODE_ENV", "PORT", "PUBLIC_DIR"])) + [
            "NODE_ENV=production", "PORT=8080", "PUBLIC_DIR=/app/dist/public"
          ])
      | .ExposedPorts = ((.ExposedPorts // {}) + {"8080/tcp":{}})
      | .Labels = ((.Labels // {}) + {
          "org.opencontainers.image.base.digest":"sha256:0f9e5f506d653e0f87e44bb5c24fece19f9fb7253016f6e49d7a4783026f876d",
          "org.opencontainers.image.base.name":"dhi.io/bun:1-alpine",
          "org.opencontainers.image.revision":$head,
          "org.opencontainers.image.source":$source
        })
      | .User = "65532:65532"
      | .WorkingDir = "/app"
      | .ArgsEscaped = true
      | .Cmd = ["/usr/local/bin/bun", "/app/dist/server.js"]
      | del(.Entrypoint)) as $expected_config |
    .config == $expected_config and
    .rootfs.diff_ids as $built_diff_ids | $base[0].rootfs.diff_ids as $base_diff_ids |
    .history as $built_history | $base[0].history as $base_history |
    .rootfs.type == "layers" and $base[0].rootfs.type == "layers" and
    ($built_diff_ids | length) > ($base_diff_ids | length) and
    all(range(0; $base_diff_ids | length); $built_diff_ids[.] == $base_diff_ids[.]) and
    ($built_history | length) > ($base_history | length) and
    all(range(0; $base_history | length); $built_history[.] == $base_history[.])
  ' "$config" >/dev/null || die "Final runtime config does not exactly derive from the reviewed DHI runtime config."
}

validate_runtime_manifest_lineage() {
  local manifest="$1" runtime_manifest="$2"
  require_json_file "$manifest" "$MAX_MANIFEST_JSON_BYTES"
  require_json_file "$runtime_manifest" "$MAX_MANIFEST_JSON_BYTES"
  jq -e --slurpfile runtime "$runtime_manifest" '
    .layers as $built | $runtime[0].layers as $base |
    ($base | type == "array" and length > 0 and length <= 256) and
    ($built | type == "array" and length > ($base | length) and length <= 256) and
    all(range(0; $base | length); $built[.] == $base[.]) and
    all($built[($base | length):][];
      (keys | sort) == ["digest", "mediaType", "size"] and
      (.digest | test("^sha256:[0-9a-f]{64}$")) and (.size > 0) and
      (.mediaType == "application/vnd.oci.image.layer.v1.tar+gzip" or .mediaType == "application/vnd.oci.image.layer.v1.tar+zstd"))
  ' "$manifest" >/dev/null || die "Final runtime layers do not exactly extend the reviewed DHI runtime descriptors."
}

validate_buildkit_provenance_statement() {
  local statement="$1" runnable_digest="$2" expected_kind="$3" expected_head="$4"
  local oven_child="$5" dev_child="$6" runtime_child="$7"
  require_json_file "$statement" "$MAX_ATTESTATION_JSON_BYTES"
  require_digest "$runnable_digest"
  [[ "$expected_kind" == preview || "$expected_kind" == production ]] || die "BuildKit provenance kind is invalid."
  [[ "$expected_head" =~ ^[0-9a-f]{40}$ ]] || die "BuildKit provenance source SHA is invalid."
  require_digest "$oven_child"
  require_digest "$dev_child"
  require_digest "$runtime_child"
  jq -e --arg image "${runnable_digest#sha256:}" --arg kind "$expected_kind" --arg head "$expected_head" --arg oven "${oven_child#sha256:}" --arg dev "${dev_child#sha256:}" --arg runtime "${runtime_child#sha256:}" '
    (keys | sort) == ["_type", "predicate", "predicateType", "subject"] and
    ._type == "https://in-toto.io/Statement/v1" and
    .predicateType == "https://slsa.dev/provenance/v1" and
    .subject == [{
      digest:{sha256:$image},
      name:("pkg:docker/platform-" + $kind + "@" + $head + "?platform=linux%2Famd64")
    }] and
    .predicate.buildDefinition.buildType == "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md" and
    .predicate.buildDefinition.resolvedDependencies == [
      {digest:{sha256:$oven},uri:("pkg:oci/platform.invalid/bun-release?digest=sha256:" + $oven + "&platform=linux%2Famd64")},
      {digest:{sha256:$dev},uri:("pkg:oci/platform.invalid/dhi-bun-dev?digest=sha256:" + $dev + "&platform=linux%2Famd64")},
      {digest:{sha256:$runtime},uri:("pkg:oci/platform.invalid/dhi-bun-runtime?digest=sha256:" + $runtime + "&platform=linux%2Famd64")}
    ]
  ' "$statement" >/dev/null || die "OCI provenance statement drifted from the pinned BuildKit v0.32.2 contract."
}

validate_application_oci_impl() {
  local image_root="$1" expected_index_digest="$2" expected_runnable_digest="$3" trusted_base_root="$4" expected_kind="$5" expected_head="$6"
  [[ "$expected_kind" == preview || "$expected_kind" == production ]] || die "Application OCI kind is invalid."
  [[ "$expected_head" =~ ^[0-9a-f]{40}$ ]] || die "Application OCI source SHA is invalid."
  local expected_repository="${GITHUB_REPOSITORY:?}"
  [[ "$expected_repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "Application OCI repository is invalid."
  require_json_file "$image_root/oci-layout" "$MAX_INDEX_JSON_BYTES"
  require_json_file "$image_root/index.json" "$MAX_INDEX_JSON_BYTES"
  test "$(jq -er 'select((keys | sort) == ["imageLayoutVersion"]) | .imageLayoutVersion' "$image_root/oci-layout")" = 1.0.0
  local index_digest index
  index_digest="$(validate_buildkit_outer_index "$image_root" "$expected_kind" "$expected_head")"
  index="$image_root/blobs/sha256/${index_digest#sha256:}"
  jq -e '
    (keys | sort) == ["manifests", "mediaType", "schemaVersion"] and
    .schemaVersion == 2 and .mediaType == "application/vnd.oci.image.index.v1+json" and
    (.manifests | type == "array" and length == 2) and
    (.manifests[0] | (keys | sort) == ["digest", "mediaType", "platform", "size"] and
      (.digest | test("^sha256:[0-9a-f]{64}$")) and
      .mediaType == "application/vnd.oci.image.manifest.v1+json" and
      (.size | type == "number" and . > 0) and
      .platform == {architecture:"amd64",os:"linux"}) and
    (.manifests[1] | (keys | sort) == ["annotations", "digest", "mediaType", "platform", "size"] and
      (.digest | test("^sha256:[0-9a-f]{64}$")) and
      .mediaType == "application/vnd.oci.image.manifest.v1+json" and
      (.size | type == "number" and . > 0) and
      .platform == {architecture:"unknown",os:"unknown"}) and
    .manifests[1].annotations == {
      "vnd.docker.reference.digest":.manifests[0].digest,
      "vnd.docker.reference.type":"attestation-manifest"
    }
  ' "$index" >/dev/null || die "BuildKit inner OCI index schema drifted."

  local runnable_digest
  runnable_digest="$(jq -er '.manifests[0].digest' "$index")"
  if [ "$expected_index_digest" != discover ]; then
    test "$index_digest" = "$expected_index_digest" || die "Published OCI index digest differs from the reviewed promoted digest."
  fi
  if [ "$expected_runnable_digest" != discover ]; then
    test "$runnable_digest" = "$expected_runnable_digest" || die "Runnable OCI manifest digest differs from the reviewed promoted digest."
  fi
  local runnable_size
  runnable_size="$(jq -er '.manifests[0].size' "$index")"

  local manifest="$image_root/blobs/sha256/${runnable_digest#sha256:}"
  require_json_file "$manifest" "$MAX_MANIFEST_JSON_BYTES"
  test "$(file_size "$manifest")" = "$runnable_size" || die "Runnable OCI manifest size drifted."
  verify_sha256 "${runnable_digest#sha256:}" "$manifest"
  jq -e '
    (keys | sort) == ["config", "layers", "mediaType", "schemaVersion"] and
    .schemaVersion == 2 and .mediaType == "application/vnd.oci.image.manifest.v1+json" and
    (.config | (keys | sort) == ["digest", "mediaType", "size"]) and
    .config.mediaType == "application/vnd.oci.image.config.v1+json" and
    (.config.digest | test("^sha256:[0-9a-f]{64}$")) and (.config.size > 0) and
    (.layers | length > 0 and length <= 256) and
    all(.layers[];
      ((keys | sort) == ["digest", "mediaType", "size"] or
       (keys | sort) == ["annotations", "digest", "mediaType", "size"]) and
      (.digest | test("^sha256:[0-9a-f]{64}$")) and (.size > 0) and
      ((.annotations // {}) | type == "object" and all(to_entries[]; (.key | type == "string") and (.value | type == "string"))) and
      (.mediaType == "application/vnd.oci.image.layer.v1.tar+gzip" or .mediaType == "application/vnd.oci.image.layer.v1.tar+zstd"))
  ' "$manifest" >/dev/null || die "Runnable OCI manifest schema drifted."
  while IFS=$'\t' read -r layer_digest layer_size; do
    local layer="$image_root/blobs/sha256/${layer_digest#sha256:}"
    test -f "$layer" && test ! -L "$layer" || die "Runnable OCI layer is missing or non-regular."
    test "$(file_size "$layer")" = "$layer_size" || die "Runnable OCI layer size drifted."
    verify_sha256 "${layer_digest#sha256:}" "$layer"
  done < <(jq -er '.layers[] | [.digest, (.size | tostring)] | @tsv' "$manifest")
  local config_digest config
  config_digest="$(jq -er '.config.digest' "$manifest")"
  config="$image_root/blobs/sha256/${config_digest#sha256:}"
  require_json_file "$config" "$MAX_CONFIG_JSON_BYTES"
  test "$(file_size "$config")" = "$(jq -er '.config.size' "$manifest")"
  verify_sha256 "${config_digest#sha256:}" "$config"
  local runtime_manifest="$trusted_base_root/layouts/dhi_runtime/blobs/sha256/${DHI_RUNTIME_AMD64_DIGEST#sha256:}"
  local runtime_config_digest runtime_config
  runtime_config_digest="$(jq -er '.config.digest | select(test("^sha256:[0-9a-f]{64}$"))' "$runtime_manifest")"
  runtime_config="$trusted_base_root/layouts/dhi_runtime/blobs/sha256/${runtime_config_digest#sha256:}"
  require_json_file "$runtime_config" "$MAX_CONFIG_JSON_BYTES"
  test "$(file_size "$runtime_config")" = "$(jq -er '.config.size' "$runtime_manifest")"
  verify_sha256 "${runtime_config_digest#sha256:}" "$runtime_config"
  validate_runtime_config_lineage "$config" "$runtime_config" "$expected_head" "$expected_repository"

  validate_runtime_manifest_lineage "$manifest" "$runtime_manifest"

  local attestation_digest attestation_size attestation_manifest
  attestation_digest="$(jq -er '.manifests[1].digest' "$index")"
  attestation_size="$(jq -er '.manifests[1].size' "$index")"
  attestation_manifest="$image_root/blobs/sha256/${attestation_digest#sha256:}"
  require_json_file "$attestation_manifest" "$MAX_MANIFEST_JSON_BYTES"
  test "$(file_size "$attestation_manifest")" = "$attestation_size" || die "OCI provenance manifest size drifted."
  verify_sha256 "${attestation_digest#sha256:}" "$attestation_manifest"
  jq -e --arg image "$runnable_digest" --argjson imageSize "$runnable_size" '
    (keys | sort) == ["artifactType", "config", "layers", "mediaType", "schemaVersion", "subject"] and
    .schemaVersion == 2 and .mediaType == "application/vnd.oci.image.manifest.v1+json" and
    .artifactType == "application/vnd.docker.attestation.manifest.v1+json" and
    .subject == {digest:$image,mediaType:"application/vnd.oci.image.manifest.v1+json",size:$imageSize} and
    .config == {
      data:"e30=",digest:"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
      mediaType:"application/vnd.oci.empty.v1+json",size:2
    } and
    .layers == [(.layers[0])] and
    (.layers[0] | (keys | sort) == ["annotations", "digest", "mediaType", "size"] and
      .annotations == {"in-toto.io/predicate-type":"https://slsa.dev/provenance/v1"} and
      .mediaType == "application/vnd.in-toto+json" and
      (.digest | test("^sha256:[0-9a-f]{64}$")) and (.size > 0))
  ' "$attestation_manifest" >/dev/null || die "OCI provenance manifest schema drifted."
  local empty_config="$image_root/blobs/sha256/44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
  require_json_file "$empty_config" 2
  test "$(file_size "$empty_config")" = 2
  verify_sha256 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a "$empty_config"
  local statement_digest statement_size statement
  statement_digest="$(jq -er '.layers[0].digest' "$attestation_manifest")"
  statement_size="$(jq -er '.layers[0].size' "$attestation_manifest")"
  statement="$image_root/blobs/sha256/${statement_digest#sha256:}"
  require_json_file "$statement" "$MAX_ATTESTATION_JSON_BYTES"
  test "$(file_size "$statement")" = "$statement_size" || die "OCI provenance statement size drifted."
  verify_sha256 "${statement_digest#sha256:}" "$statement"
  local oven_child dev_child runtime_child
  oven_child="$(jq -er '.images[] | select(.role == "oven") | .childDigest' "$trusted_base_root/manifest.json")"
  dev_child="$(jq -er '.images[] | select(.role == "dhi_dev") | .childDigest' "$trusted_base_root/manifest.json")"
  runtime_child="$(jq -er '.images[] | select(.role == "dhi_runtime") | .childDigest' "$trusted_base_root/manifest.json")"
  validate_buildkit_provenance_statement "$statement" "$runnable_digest" "$expected_kind" "$expected_head" "$oven_child" "$dev_child" "$runtime_child"

  local reachable="$RUNNER_TEMP/application-reachable-$RANDOM"
  {
    printf '%s\n' "${index_digest#sha256:}" "${runnable_digest#sha256:}" "${attestation_digest#sha256:}" "${config_digest#sha256:}" "${statement_digest#sha256:}" 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
    jq -r '.layers[].digest | sub("^sha256:"; "")' "$manifest"
  } | sort -u > "$reachable"
  validate_flat_sha256_blob_directory "$image_root/blobs/sha256" "Application OCI"
  (cd "$image_root/blobs/sha256" && find . -mindepth 1 -maxdepth 1 -type f -print | sed 's#^\./##' | sort -u) > "$reachable.actual"
  test "$(wc -l < "$reachable.actual")" -le "$MAX_OCI_BLOBS" || die "Application OCI archive has too many blobs."
  cmp "$reachable" "$reachable.actual" || die "Application OCI archive contains missing or unreachable blobs."
  test "$(cd "$image_root" && find . -mindepth 1 -maxdepth 1 -print | sed 's#^\./##' | sort | tr '\n' ' ')" = "blobs index.json oci-layout " || die "Application OCI archive has extra top-level paths."
  test "$(cd "$image_root/blobs" && find . -mindepth 1 -maxdepth 1 -print | sed 's#^\./##')" = sha256 || die "Application OCI archive has an unsupported digest algorithm path."
  while read -r blob; do
    verify_sha256 "${blob##*/}" "$blob"
  done < <(find "$image_root/blobs/sha256" -mindepth 1 -maxdepth 1 -type f -print | sort)
  printf '%s\t%s\n' "$index_digest" "$runnable_digest"
}

validate_buildkit_outer_index() {
  local image_root="$1" expected_kind="$2" expected_head="$3"
  require_json_file "$image_root/oci-layout" "$MAX_INDEX_JSON_BYTES"
  require_json_file "$image_root/index.json" "$MAX_INDEX_JSON_BYTES"
  test "$(jq -er 'select((keys | sort) == ["imageLayoutVersion"]) | .imageLayoutVersion' "$image_root/oci-layout")" = 1.0.0
  jq -e --arg name "docker.io/library/platform-${expected_kind}:${expected_head}" --arg ref "$expected_head" '
    (keys | sort) == ["manifests", "mediaType", "schemaVersion"] and
    .schemaVersion == 2 and .mediaType == "application/vnd.oci.image.index.v1+json" and
    (.manifests | type == "array" and length == 1) and
    (.manifests[0] | (keys | sort) == ["annotations", "digest", "mediaType", "size"] and
      .mediaType == "application/vnd.oci.image.index.v1+json" and
      (.digest | test("^sha256:[0-9a-f]{64}$")) and
      (.size | type == "number" and . > 0 and . <= 1048576) and
      (.annotations | (keys | sort) == ["io.containerd.image.name", "org.opencontainers.image.created", "org.opencontainers.image.ref.name"]) and
      .annotations["io.containerd.image.name"] == $name and
      .annotations["org.opencontainers.image.ref.name"] == $ref and
      (.annotations["org.opencontainers.image.created"] | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")))
  ' "$image_root/index.json" >/dev/null || die "BuildKit outer OCI wrapper schema drifted."
  local index_digest index_size inner
  index_digest="$(jq -er '.manifests[0].digest' "$image_root/index.json")"
  index_size="$(jq -er '.manifests[0].size' "$image_root/index.json")"
  inner="$image_root/blobs/sha256/${index_digest#sha256:}"
  require_json_file "$inner" "$MAX_INDEX_JSON_BYTES"
  test "$(file_size "$inner")" = "$index_size" || die "BuildKit inner index size drifted."
  verify_sha256 "${index_digest#sha256:}" "$inner"
  printf '%s\n' "$index_digest"
}

promote_image() {
  require_linux_x64
  local kind="${ARTIFACT_KIND:-}"
  [[ "$kind" == preview || "$kind" == production ]] || die "Artifact kind must be preview or production."
  require_sha256 "${BUILT_CONTENT_SHA256:?}"
  require_sha256 "${BASE_CONTENT_SHA256:?}"
  require_sha256 "${BASE_MANIFEST_SHA256:?}"
  [[ "${EXPECTED_HEAD_SHA:?}" =~ ^[0-9a-f]{40}$ ]] || die "Expected source SHA is invalid."
  [[ "${EXPECTED_REPOSITORY_ID:?}" =~ ^[0-9]+$ ]] || die "Expected repository id is invalid."
  [[ "${WORKFLOW_SHA:?}" =~ ^[0-9a-f]{40}$ ]] || die "Reusable workflow SHA is invalid."

  local built base
  built="$(single_regular_file "${BUILT_DOWNLOAD_DIR:?}")"
  base="$(single_regular_file "${BASE_DOWNLOAD_DIR:?}")"
  verify_sha256 "$BUILT_CONTENT_SHA256" "$built"
  verify_sha256 "$BASE_CONTENT_SHA256" "$base"

  local base_root="$RUNNER_TEMP/platform-promoter-bases"
  safe_extract_tar "$base" "$base_root" "$((MAX_BASE_BYTES + 1048576))"
  verify_sha256 "$BASE_MANIFEST_SHA256" "$base_root/manifest.json"
  validate_base_bundle "$base_root"
  local oven_child dev_child runtime_child
  oven_child="$(jq -er '.images[] | select(.role == "oven") | .childDigest' "$base_root/manifest.json")"
  dev_child="$(jq -er '.images[] | select(.role == "dhi_dev") | .childDigest' "$base_root/manifest.json")"
  runtime_child="$(jq -er '.images[] | select(.role == "dhi_runtime") | .childDigest' "$base_root/manifest.json")"

  # Finish every networked download before any scanner sees attacker-shaped OCI
  # bytes. The actual scanners later run without a network or host namespace.
  local tools="$RUNNER_TEMP/platform-verifier-tools"
  local verified="$RUNNER_TEMP/platform-verified"
  local scanner_policy="$RUNNER_TEMP/platform-scanner-policy"
  local scanner_state="$RUNNER_TEMP/platform-scanner-state"
  local scanner_database="$RUNNER_TEMP/platform-scanner-database"
  install -d -m 0700 "$tools" "$verified" "$scanner_policy" "$scanner_state" "$scanner_database"
  install -m 0444 "$CONTRACT_ROOT/syft.yaml" "$scanner_policy/syft.yaml"
  install -m 0444 "$CONTRACT_ROOT/grype.yaml" "$scanner_policy/grype.yaml"
  install -m 0444 "$CONTRACT_ROOT/grype-blocking.jq" "$scanner_policy/grype-blocking.jq"
  curl --fail --show-error --silent --location --output "$RUNNER_TEMP/syft.tgz" https://github.com/anchore/syft/releases/download/v1.51.0/syft_1.51.0_linux_amd64.tar.gz
  verify_sha256 2a2e837a2c8d59ec9af5472ee22d3b04ee463c4e44476ecf993fd1e5ab6ebc7f "$RUNNER_TEMP/syft.tgz"
  tar -xzf "$RUNNER_TEMP/syft.tgz" -C "$tools" syft
  curl --fail --show-error --silent --location --output "$RUNNER_TEMP/grype.tgz" https://github.com/anchore/grype/releases/download/v0.117.0/grype_0.117.0_linux_amd64.tar.gz
  verify_sha256 38525dab1e06f162ebaa02f94d82d1f807076b011a44180cf2777edf1a7b9c26 "$RUNNER_TEMP/grype.tgz"
  tar -xzf "$RUNNER_TEMP/grype.tgz" -C "$tools" grype
  "$tools/grype" version -o json | jq -e '.version == "0.117.0" and .gitCommit == "b5fa92bbcbef655497e3be840a2f718380e2cdd3"' >/dev/null
  local db_manifest_json db_url db_sha expected_schema expected_built db_archive
  db_manifest_json="$(load_reviewed_grype_db_manifest)"
  db_url="$(jq -er '.url' <<< "$db_manifest_json")"
  db_sha="$(jq -er '.sha256' <<< "$db_manifest_json")"
  expected_schema="$(jq -er '.schemaVersion' <<< "$db_manifest_json")"
  expected_built="$(jq -er '.built' <<< "$db_manifest_json")"
  db_archive="$scanner_database/grype-db.tar.zst"
  curl --fail --show-error --silent --location --output "$db_archive" "$db_url"
  verify_sha256 "$db_sha" "$db_archive"
  chmod -R a-w,go+rX "$tools" "$scanner_policy" "$scanner_database"
  docker pull "$SCANNER_SANDBOX_IMAGE" >/dev/null
  local scanner_sandbox_image_id
  scanner_sandbox_image_id="$(docker image inspect --format '{{.Id}}' "$SCANNER_SANDBOX_IMAGE")"
  require_digest "$scanner_sandbox_image_id"
  docker image inspect --format '{{json .RepoDigests}}' "$scanner_sandbox_image_id" |
    jq -e --arg expected "$SCANNER_SANDBOX_IMAGE" 'index($expected) != null' >/dev/null

  local image_root="$RUNNER_TEMP/platform-untrusted-image"
  safe_extract_tar "$built" "$image_root" "$MAX_IMAGE_BYTES"
  local published_index_digest runnable_manifest_digest
  IFS=$'\t' read -r published_index_digest runnable_manifest_digest < <(
    validate_application_oci "$image_root" discover discover "$base_root" "$kind" "$EXPECTED_HEAD_SHA"
  )
  local runtime_manifest="$base_root/layouts/dhi_runtime/blobs/sha256/${DHI_RUNTIME_AMD64_DIGEST#sha256:}"
  local scanner_image="$RUNNER_TEMP/platform-scanner-image"
  local scanner_archive="$RUNNER_TEMP/platform-scanner-image.oci.tar"
  write_deterministic_tar "$image_root" "$scanner_archive" "$MAX_IMAGE_BYTES"
  safe_extract_tar "$scanner_archive" "$scanner_image" "$MAX_IMAGE_BYTES"
  local scanner_before="$RUNNER_TEMP/platform-scanner-before.sha256"
  local scanner_after="$RUNNER_TEMP/platform-scanner-after.sha256"
  (
    cd "$scanner_image"
    find . -type f -print0 | sort -z | xargs -0 sha256sum
  ) > "$scanner_before"
  chmod -R a-w,go+rX "$scanner_image" "$scanner_archive"
  install -d -m 0777 "$scanner_state/probe" "$scanner_state/syft" "$scanner_state/grype"
  chmod 0777 "$scanner_state"
  local host_only_marker="$RUNNER_TEMP/platform-host-only-marker"
  printf 'not mounted\n' > "$host_only_marker"
  local -a sandbox=(
    run --rm --pull never --network none --read-only --cap-drop ALL
    --security-opt no-new-privileges --user 65534:65534
    --pids-limit 256 --memory 1073741824 --cpus 2
    --mount "type=bind,src=$scanner_image,dst=/input,readonly"
    --mount "type=bind,src=$tools,dst=/tools,readonly"
    --mount "type=bind,src=$scanner_policy,dst=/policy,readonly"
    --mount "type=bind,src=$scanner_database,dst=/database,readonly"
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=268435456
    --env GRYPE_DB_CACHE_DIR=/state/grype/db
    --env GRYPE_CHECK_FOR_APP_UPDATE=false
    --env SYFT_CHECK_FOR_APP_UPDATE=false
    --env XDG_CACHE_HOME=/state/cache
    --env "HOST_ONLY_MARKER=$host_only_marker"
  )
  scanner_container() {
    local duration="$1" state_root="$2" entrypoint="$3"
    shift 3
    /usr/bin/timeout --signal=TERM --kill-after=10s "$duration" \
      docker "${sandbox[@]}" --mount "type=bind,src=$state_root,dst=/state" \
      --entrypoint "$entrypoint" "$scanner_sandbox_image_id" "$@"
  }
  scanner_container 2m "$scanner_state/probe" /bin/sh -eu -c '
    test ! -e "$HOST_ONLY_MARKER"
    test "$(ls /sys/class/net | tr "\n" " ")" = "lo "
    ! touch /input/parser-rce-write
    test ! -S /var/run/docker.sock
    printf confined > /state/confinement-probe
  ' > /dev/null 2> "$verified/confinement.stderr" || die "The scanner sandbox confinement probe failed."
  test "$(cat "$scanner_state/probe/confinement-probe")" = confined || die "The scanner sandbox could not write only its bounded state mount."
  scanner_container 15m "$scanner_state/syft" /tools/syft \
    --config /policy/syft.yaml oci-dir:/input --output spdx-json > "$verified/sbom.spdx.json" 2> "$verified/syft.stderr" ||
    die "The isolated Syft scan failed."
  scanner_container 15m "$scanner_state/grype" /tools/grype \
    --config /policy/grype.yaml db import /database/grype-db.tar.zst > /dev/null 2> "$verified/grype-db-import.stderr" ||
    die "The isolated Grype database import failed."
  scanner_container 5m "$scanner_state/grype" /tools/grype \
    --config /policy/grype.yaml db status -o json > "$verified/grype-db-status.json" 2> "$verified/grype-db-status.stderr" ||
    die "The isolated Grype database status check failed."
  jq -e --arg schema "$expected_schema" --arg built "$expected_built" '
    .valid == true and .schemaVersion == $schema and .built == $built and
    ((now - (.built | fromdateiso8601)) >= -3600) and ((now - (.built | fromdateiso8601)) <= 172800)
  ' "$verified/grype-db-status.json" >/dev/null
  scanner_container 15m "$scanner_state/grype" /tools/grype \
    --config /policy/grype.yaml oci-dir:/input --scope squashed --output json > "$verified/grype.json" 2> "$verified/grype.stderr" ||
    die "The isolated Grype image scan failed."
  require_json_file "$verified/grype.json" "$MAX_SCAN_JSON_BYTES"
  jq -f "$scanner_policy/grype-blocking.jq" "$verified/grype.json" > "$verified/blocking.json"
  jq -e 'length == 0' "$verified/blocking.json"
  (
    cd "$scanner_image"
    find . -type f -print0 | sort -z | xargs -0 sha256sum
  ) > "$scanner_after"
  cmp "$scanner_before" "$scanner_after" || die "The unprivileged scanners changed the read-only OCI graph."

  local bundle="$RUNNER_TEMP/platform-promoted-bundle"
  local artifact="$RUNNER_TEMP/platform-${kind}-promoted-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}.tar"
  local canonical="$RUNNER_TEMP/platform-canonical-image.oci.tar"
  local canonical_root="$RUNNER_TEMP/platform-canonical-image"
  write_deterministic_tar "$image_root" "$canonical" "$MAX_IMAGE_BYTES"
  safe_extract_tar "$canonical" "$canonical_root" "$MAX_IMAGE_BYTES"
  (
    cd "$image_root"
    find . -type f -print0 | sort -z | xargs -0 sha256sum
  ) > "$RUNNER_TEMP/original-image-files.sha256"
  (
    cd "$canonical_root"
    find . -type f -print0 | sort -z | xargs -0 sha256sum
  ) > "$RUNNER_TEMP/canonical-image-files.sha256"
  cmp "$RUNNER_TEMP/original-image-files.sha256" "$RUNNER_TEMP/canonical-image-files.sha256" || die "Canonical OCI round trip drifted."
  test "$(jq -er '.manifests[0].digest' "$canonical_root/index.json")" = "$published_index_digest"
  test "$(jq -er --arg index "$published_index_digest" '.manifests[0].digest as $actual | select($actual == $index) | $actual' "$canonical_root/index.json")" = "$published_index_digest"
  test "$(jq -er '.manifests[0].digest' "$canonical_root/blobs/sha256/${published_index_digest#sha256:}")" = "$runnable_manifest_digest"
  install -d -m 0700 "$bundle"
  install -m 0600 "$canonical" "$bundle/image.oci.tar"
  install -m 0600 "$verified/sbom.spdx.json" "$bundle/sbom.spdx.json"
  install -m 0600 "$runtime_manifest" "$bundle/dhi-runtime.manifest.json"
  local image_sha sbom_sha
  image_sha="$(sha256_file "$bundle/image.oci.tar")"
  sbom_sha="$(sha256_file "$bundle/sbom.spdx.json")"
  local base_images
  base_images="$(jq -c '{
    oven:(.images[] | select(.role == "oven") | {childDigest,topDigest}),
    dhiDev:(.images[] | select(.role == "dhi_dev") | {childDigest,topDigest}),
    dhiRuntime:(.images[] | select(.role == "dhi_runtime") | {childDigest,topDigest})
  }' "$base_root/manifest.json")"
  jq -cnS --argjson baseImages "$base_images" --arg event "${EXPECTED_EVENT_NAME:?}" --arg head "$EXPECTED_HEAD_SHA" --arg imageSha256 "$image_sha" --arg publishedIndexDigest "$published_index_digest" --arg repositoryId "$EXPECTED_REPOSITORY_ID" --arg runnableManifestDigest "$runnable_manifest_digest" --arg runAttempt "$GITHUB_RUN_ATTEMPT" --arg runId "$GITHUB_RUN_ID" --arg runtimeManifestSha256 "${DHI_RUNTIME_AMD64_DIGEST#sha256:}" --arg sbomSha256 "$sbom_sha" --arg workflowSha "$WORKFLOW_SHA" \
    '{artifactType:"platform-promoted-image",baseImages:$baseImages,eventName:$event,headSha:$head,imageSha256:$imageSha256,publishedIndexDigest:$publishedIndexDigest,repositoryId:$repositoryId,runnableManifestDigest:$runnableManifestDigest,runAttempt:$runAttempt,runId:$runId,runtimeManifestSha256:$runtimeManifestSha256,sbomSha256:$sbomSha256,schemaVersion:1,workflowSha:$workflowSha}' > "$bundle/manifest.json"
  write_deterministic_tar "$bundle" "$artifact" "$MAX_IMAGE_BYTES"
  echo "artifact=$artifact" >> "$GITHUB_OUTPUT"
  echo "content_sha256=$(sha256_file "$artifact")" >> "$GITHUB_OUTPUT"
  echo "published_index_digest=$published_index_digest" >> "$GITHUB_OUTPUT"
  echo "runnable_manifest_digest=$runnable_manifest_digest" >> "$GITHUB_OUTPUT"
  echo "sbom_sha256=$sbom_sha" >> "$GITHUB_OUTPUT"
}

validate_promoted() {
  require_linux_x64
  local artifact base_artifact
  artifact="$(single_regular_file "${ARTIFACT_DOWNLOAD_DIR:?}")"
  base_artifact="$(single_regular_file "${BASE_DOWNLOAD_DIR:?}")"
  require_sha256 "${EXPECTED_CONTENT_SHA256:?}"
  require_sha256 "${BASE_CONTENT_SHA256:?}"
  require_sha256 "${BASE_MANIFEST_SHA256:?}"
  require_digest "${EXPECTED_PUBLISHED_INDEX_DIGEST:?}"
  require_digest "${EXPECTED_RUNNABLE_MANIFEST_DIGEST:?}"
  verify_sha256 "$EXPECTED_CONTENT_SHA256" "$artifact"
  verify_sha256 "$BASE_CONTENT_SHA256" "$base_artifact"
  local trusted_base_root="$RUNNER_TEMP/platform-publisher-trusted-bases-$RANDOM"
  safe_extract_tar "$base_artifact" "$trusted_base_root" "$((MAX_BASE_BYTES + 1048576))"
  verify_sha256 "$BASE_MANIFEST_SHA256" "$trusted_base_root/manifest.json"
  validate_base_bundle "$trusted_base_root"
  local root="$RUNNER_TEMP/platform-promoted-$RANDOM"
  safe_extract_tar "$artifact" "$root" "$((MAX_IMAGE_BYTES + 1048576))"
  test "$(find "$root" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | tr '\n' ' ')" = "dhi-runtime.manifest.json image.oci.tar manifest.json sbom.spdx.json " || die "Promoted artifact has an unexpected file set."
  find "$root" -mindepth 1 -maxdepth 1 ! -type f -print -quit | grep -q . &&
    die "Promoted artifact contains a non-regular inventory entry."
  require_json_file "$root/manifest.json" "$MAX_MANIFEST_JSON_BYTES"
  jq -e --arg event "${EXPECTED_EVENT_NAME:?}" --arg head "${EXPECTED_HEAD_SHA:?}" --arg published "$EXPECTED_PUBLISHED_INDEX_DIGEST" --arg runnable "$EXPECTED_RUNNABLE_MANIFEST_DIGEST" \
    --arg ovenTop "$OVEN_TOP_DIGEST" --arg devTop "$DHI_DEV_TOP_DIGEST" --arg devChild "$DHI_DEV_AMD64_DIGEST" \
    --arg runtimeTop "$DHI_RUNTIME_TOP_DIGEST" --arg runtimeChild "$DHI_RUNTIME_AMD64_DIGEST" \
    --arg repo "${EXPECTED_REPOSITORY_ID:?}" --arg attempt "$GITHUB_RUN_ATTEMPT" --arg run "$GITHUB_RUN_ID" --arg workflow "${WORKFLOW_SHA:?}" '
    (keys | sort) == ["artifactType", "baseImages", "eventName", "headSha", "imageSha256", "publishedIndexDigest", "repositoryId", "runAttempt", "runId", "runnableManifestDigest", "runtimeManifestSha256", "sbomSha256", "schemaVersion", "workflowSha"] and
    .artifactType == "platform-promoted-image" and .eventName == $event and .headSha == $head and
    .publishedIndexDigest == $published and .runnableManifestDigest == $runnable and
    .repositoryId == $repo and .runAttempt == $attempt and .runId == $run and
    .schemaVersion == 1 and .workflowSha == $workflow and
    .baseImages == {
      dhiDev:{childDigest:$devChild,topDigest:$devTop},
      dhiRuntime:{childDigest:$runtimeChild,topDigest:$runtimeTop},
      oven:{childDigest:.baseImages.oven.childDigest,topDigest:$ovenTop}
    } and
    (.baseImages.oven.childDigest | test("^sha256:[0-9a-f]{64}$")) and
    .runtimeManifestSha256 == ($runtimeChild | sub("^sha256:"; "")) and
    (.imageSha256 | test("^[0-9a-f]{64}$")) and (.sbomSha256 | test("^[0-9a-f]{64}$"))
  ' "$root/manifest.json" >/dev/null
  local expected_base_images
  expected_base_images="$(jq -c '{
    oven:(.images[] | select(.role == "oven") | {childDigest,topDigest}),
    dhiDev:(.images[] | select(.role == "dhi_dev") | {childDigest,topDigest}),
    dhiRuntime:(.images[] | select(.role == "dhi_runtime") | {childDigest,topDigest})
  }' "$trusted_base_root/manifest.json")"
  jq -e --argjson expected "$expected_base_images" '.baseImages == $expected' "$root/manifest.json" >/dev/null
  verify_sha256 "$(jq -er .imageSha256 "$root/manifest.json")" "$root/image.oci.tar"
  verify_sha256 "$(jq -er .sbomSha256 "$root/manifest.json")" "$root/sbom.spdx.json"
  local image_root="$RUNNER_TEMP/platform-publisher-image-$RANDOM"
  safe_extract_tar "$root/image.oci.tar" "$image_root" "$MAX_IMAGE_BYTES"
  local published runnable kind
  case "$EXPECTED_EVENT_NAME" in
    pull_request_target) kind=preview ;;
    push) kind=production ;;
    *) die "Promoted event name cannot select a container kind." ;;
  esac
  IFS=$'\t' read -r published runnable < <(
    validate_application_oci "$image_root" "$EXPECTED_PUBLISHED_INDEX_DIGEST" "$EXPECTED_RUNNABLE_MANIFEST_DIGEST" "$trusted_base_root" "$kind" "$EXPECTED_HEAD_SHA"
  )
  test "$published" = "$EXPECTED_PUBLISHED_INDEX_DIGEST" || die "Promoted OCI index digest drifted."
  test "$runnable" = "$EXPECTED_RUNNABLE_MANIFEST_DIGEST" || die "Promoted OCI runnable digest drifted."
  local embedded_runtime_manifest="$root/dhi-runtime.manifest.json"
  local trusted_runtime_manifest="$trusted_base_root/layouts/dhi_runtime/blobs/sha256/${DHI_RUNTIME_AMD64_DIGEST#sha256:}"
  require_json_file "$embedded_runtime_manifest" "$MAX_MANIFEST_JSON_BYTES"
  cmp "$trusted_runtime_manifest" "$embedded_runtime_manifest" || die "Promoted runtime base evidence differs from the independently downloaded trusted base."
  echo "image_archive=$root/image.oci.tar" >> "$GITHUB_OUTPUT"
}

validate_live_production_graph() {
  local index="$1" manifest="$2" config="$3" attestation_manifest="$4" statement="$5"
  local trusted_base_root="$6" expected_index_digest="$7" expected_head="$8" expected_kind="${9:-production}"
  local expected_runnable_digest="${10:?}"
  require_digest "$expected_index_digest"
  require_digest "$expected_runnable_digest"
  [[ "$expected_head" =~ ^[0-9a-f]{40}$ ]] || die "Live production source SHA is invalid."
  [[ "$expected_kind" == preview || "$expected_kind" == production ]] || die "Live image kind is invalid."
  require_json_file "$index" "$MAX_INDEX_JSON_BYTES"
  test "$(sha256_file "$index")" = "${expected_index_digest#sha256:}" || die "Live production index differs from the Cloud Run image digest."
  jq -e '
    (keys | sort) == ["manifests", "mediaType", "schemaVersion"] and
    .schemaVersion == 2 and .mediaType == "application/vnd.oci.image.index.v1+json" and
    (.manifests | type == "array" and length == 2) and
    (.manifests[0] | (keys | sort) == ["digest", "mediaType", "platform", "size"] and
      (.digest | test("^sha256:[0-9a-f]{64}$")) and
      .mediaType == "application/vnd.oci.image.manifest.v1+json" and
      (.size | type == "number" and . > 0) and
      .platform == {architecture:"amd64",os:"linux"}) and
    (.manifests[1] | (keys | sort) == ["annotations", "digest", "mediaType", "platform", "size"] and
      (.digest | test("^sha256:[0-9a-f]{64}$")) and
      .mediaType == "application/vnd.oci.image.manifest.v1+json" and
      (.size | type == "number" and . > 0) and
      .platform == {architecture:"unknown",os:"unknown"}) and
    .manifests[1].annotations == {
      "vnd.docker.reference.digest":.manifests[0].digest,
      "vnd.docker.reference.type":"attestation-manifest"
    }
  ' "$index" >/dev/null || die "Live production OCI index schema drifted."

  local runnable_digest runnable_size
  runnable_digest="$(jq -er '.manifests[0].digest' "$index")"
  runnable_size="$(jq -er '.manifests[0].size' "$index")"
  test "$runnable_digest" = "$expected_runnable_digest" || die "Cloud Run runnable digest is not the child selected by the proven OCI index."
  require_json_file "$manifest" "$MAX_MANIFEST_JSON_BYTES"
  test "$(file_size "$manifest")" = "$runnable_size" || die "Live production runnable manifest size drifted."
  verify_sha256 "${runnable_digest#sha256:}" "$manifest"
  jq -e '
    (keys | sort) == ["config", "layers", "mediaType", "schemaVersion"] and
    .schemaVersion == 2 and .mediaType == "application/vnd.oci.image.manifest.v1+json" and
    (.config | (keys | sort) == ["digest", "mediaType", "size"]) and
    .config.mediaType == "application/vnd.oci.image.config.v1+json" and
    (.config.digest | test("^sha256:[0-9a-f]{64}$")) and (.config.size > 0) and
    (.layers | length > 0 and length <= 256) and
    all(.layers[];
      ((keys | sort) == ["digest", "mediaType", "size"] or
       (keys | sort) == ["annotations", "digest", "mediaType", "size"]) and
      (.digest | test("^sha256:[0-9a-f]{64}$")) and (.size > 0) and
      ((.annotations // {}) | type == "object" and all(to_entries[]; (.key | type == "string") and (.value | type == "string"))) and
      (.mediaType == "application/vnd.oci.image.layer.v1.tar+gzip" or .mediaType == "application/vnd.oci.image.layer.v1.tar+zstd"))
  ' "$manifest" >/dev/null || die "Live production runnable manifest schema drifted."

  local config_digest
  config_digest="$(jq -er '.config.digest' "$manifest")"
  require_json_file "$config" "$MAX_CONFIG_JSON_BYTES"
  test "$(file_size "$config")" = "$(jq -er '.config.size' "$manifest")" || die "Live production config size drifted."
  verify_sha256 "${config_digest#sha256:}" "$config"

  local runtime_manifest="$trusted_base_root/layouts/dhi_runtime/blobs/sha256/${DHI_RUNTIME_AMD64_DIGEST#sha256:}"
  local runtime_config_digest runtime_config
  runtime_config_digest="$(jq -er '.config.digest | select(test("^sha256:[0-9a-f]{64}$"))' "$runtime_manifest")"
  runtime_config="$trusted_base_root/layouts/dhi_runtime/blobs/sha256/${runtime_config_digest#sha256:}"
  require_json_file "$runtime_config" "$MAX_CONFIG_JSON_BYTES"
  test "$(file_size "$runtime_config")" = "$(jq -er '.config.size' "$runtime_manifest")"
  verify_sha256 "${runtime_config_digest#sha256:}" "$runtime_config"
  validate_runtime_config_lineage "$config" "$runtime_config" "$expected_head" "${GITHUB_REPOSITORY:?}"
  validate_runtime_manifest_lineage "$manifest" "$runtime_manifest"

  local attestation_digest attestation_size
  attestation_digest="$(jq -er '.manifests[1].digest' "$index")"
  attestation_size="$(jq -er '.manifests[1].size' "$index")"
  require_json_file "$attestation_manifest" "$MAX_MANIFEST_JSON_BYTES"
  test "$(file_size "$attestation_manifest")" = "$attestation_size" || die "Live production provenance manifest size drifted."
  verify_sha256 "${attestation_digest#sha256:}" "$attestation_manifest"
  jq -e --arg image "$runnable_digest" --argjson imageSize "$runnable_size" '
    (keys | sort) == ["artifactType", "config", "layers", "mediaType", "schemaVersion", "subject"] and
    .schemaVersion == 2 and .mediaType == "application/vnd.oci.image.manifest.v1+json" and
    .artifactType == "application/vnd.docker.attestation.manifest.v1+json" and
    .subject == {digest:$image,mediaType:"application/vnd.oci.image.manifest.v1+json",size:$imageSize} and
    .config == {
      data:"e30=",digest:"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
      mediaType:"application/vnd.oci.empty.v1+json",size:2
    } and
    .layers == [(.layers[0])] and
    (.layers[0] | (keys | sort) == ["annotations", "digest", "mediaType", "size"] and
      .annotations == {"in-toto.io/predicate-type":"https://slsa.dev/provenance/v1"} and
      .mediaType == "application/vnd.in-toto+json" and
      (.digest | test("^sha256:[0-9a-f]{64}$")) and (.size > 0))
  ' "$attestation_manifest" >/dev/null || die "Live production provenance manifest schema drifted."
  local statement_digest statement_size
  statement_digest="$(jq -er '.layers[0].digest' "$attestation_manifest")"
  statement_size="$(jq -er '.layers[0].size' "$attestation_manifest")"
  require_json_file "$statement" "$MAX_ATTESTATION_JSON_BYTES"
  test "$(file_size "$statement")" = "$statement_size" || die "Live production provenance statement size drifted."
  verify_sha256 "${statement_digest#sha256:}" "$statement"

  local oven_child dev_child runtime_child
  oven_child="$(jq -er '.images[] | select(.role == "oven") | .childDigest' "$trusted_base_root/manifest.json")"
  dev_child="$(jq -er '.images[] | select(.role == "dhi_dev") | .childDigest' "$trusted_base_root/manifest.json")"
  runtime_child="$(jq -er '.images[] | select(.role == "dhi_runtime") | .childDigest' "$trusted_base_root/manifest.json")"
  validate_buildkit_provenance_statement "$statement" "$runnable_digest" "$expected_kind" "$expected_head" "$oven_child" "$dev_child" "$runtime_child"
}

fetch_and_validate_live_image() {
  local regctl="$1" trusted_base_root="$2" live_kind="$3" live_head="$4"
  local expected_image_name="$5" live_index_image="$6" live_runnable_image="$7" graph_id="$8"
  [[ "$live_kind" == preview || "$live_kind" == production ]] || die "Live image kind is invalid."
  [[ "$live_head" =~ ^[0-9a-f]{40}$ ]] || die "Live revision lacks an exact source SHA."
  [[ "$expected_image_name" =~ ^us-east4-docker\.pkg\.dev/[a-z0-9-]+/[a-z0-9-]+/[a-z0-9-]+$ ]] || die "Expected live image name is invalid."
  local expected_index_digest="${live_index_image##*@}"
  require_digest "$expected_index_digest"
  test "$live_index_image" = "${expected_image_name}@${expected_index_digest}" || die "Live OCI index reference is not canonical or is outside the exact repository."
  local expected_runnable_digest="${live_runnable_image##*@}"
  require_digest "$expected_runnable_digest"
  test "$live_runnable_image" = "${expected_image_name}@${expected_runnable_digest}" || die "Cloud Run runnable reference is not canonical or is outside the exact repository."
  [[ "$graph_id" =~ ^[1-9][0-9]*$ ]] || die "Live image graph id is invalid."
  local graph="$RUNNER_TEMP/platform-live-image-session-$BASHPID/graph-${graph_id}"
  test ! -e "$graph" && test ! -L "$graph" || die "Live image graph path exists."
  install -d -m 0700 "$graph"
  local repository="$expected_image_name"
  "$regctl" manifest get "$live_index_image" --format raw-body > "$graph/index.json"
  local runnable_digest attestation_digest
  runnable_digest="$(jq -er '.manifests[0].digest | select(test("^sha256:[0-9a-f]{64}$"))' "$graph/index.json")"
  test "$runnable_digest" = "$expected_runnable_digest" || die "Cloud Run runnable digest is not the child selected by the proven OCI index."
  attestation_digest="$(jq -er '.manifests[1].digest | select(test("^sha256:[0-9a-f]{64}$"))' "$graph/index.json")"
  "$regctl" manifest get "${repository}@${runnable_digest}" --format raw-body > "$graph/manifest.json"
  local config_digest
  config_digest="$(jq -er '.config.digest | select(test("^sha256:[0-9a-f]{64}$"))' "$graph/manifest.json")"
  "$regctl" blob get "$repository" "$config_digest" > "$graph/config.json"
  "$regctl" manifest get "${repository}@${attestation_digest}" --format raw-body > "$graph/attestation.json"
  local statement_digest
  statement_digest="$(jq -er '.layers[0].digest | select(test("^sha256:[0-9a-f]{64}$"))' "$graph/attestation.json")"
  "$regctl" blob get "$repository" "$statement_digest" > "$graph/statement.json"

  validate_live_production_graph "$graph/index.json" "$graph/manifest.json" "$graph/config.json" \
    "$graph/attestation.json" "$graph/statement.json" "$trusted_base_root" "$expected_index_digest" "$live_head" "$live_kind" "$expected_runnable_digest"
}

verify_live_production() {
  require_linux_x64
  require_sha256 "${BASE_CONTENT_SHA256:?}"
  require_sha256 "${BASE_MANIFEST_SHA256:?}"
  test -n "${AR_ACCESS_TOKEN:-}" || die "Deployment parity access token is absent."

  local base_artifact session trusted_base_root
  base_artifact="$(single_regular_file "${BASE_DOWNLOAD_DIR:?}")"
  verify_sha256 "$BASE_CONTENT_SHA256" "$base_artifact"
  session="$RUNNER_TEMP/platform-live-image-session-$BASHPID"
  test ! -e "$session" && test ! -L "$session" || die "Live image validation session path exists."
  install -d -m 0700 "$session"
  trusted_base_root="$session/bases"
  trap 'rm -rf -- "$session"; unset AR_ACCESS_TOKEN DOCKER_CONFIG REGCTL_CONFIG' EXIT
  safe_extract_tar "$base_artifact" "$trusted_base_root" "$((MAX_BASE_BYTES + 1048576))"
  verify_sha256 "$BASE_MANIFEST_SHA256" "$trusted_base_root/manifest.json"
  validate_base_bundle "$trusted_base_root"

  local regctl="$RUNNER_TEMP/regctl-v${REGCTL_VERSION}"
  if [ -f "$regctl" ] && [ ! -L "$regctl" ]; then
    test "$(sha256_file "$regctl")" = "$REGCTL_SHA256" || die "Prepared regctl drifted."
    "$regctl" version | grep -F "v${REGCTL_VERSION}" >/dev/null
  else
    install_regctl "$regctl"
  fi
  local auth="$session/auth"
  install -d -m 0700 "$auth/docker" "$auth/regctl"
  export DOCKER_CONFIG="$auth/docker" REGCTL_CONFIG="$auth/regctl/config.json"
  printf '{"auths":{}}\n' > "$DOCKER_CONFIG/config.json"
  printf '{"hosts":{}}\n' > "$REGCTL_CONFIG"
  printf '%s' "$AR_ACCESS_TOKEN" | "$regctl" registry login us-east4-docker.pkg.dev --user oauth2accesstoken --pass-stdin
  unset AR_ACCESS_TOKEN

  local graph_id=0
  if [ -n "${LIVE_IMAGE_SET_FILE:-}" ]; then
    require_json_file "$LIVE_IMAGE_SET_FILE" "$MAX_INDEX_JSON_BYTES"
    jq -e '
      type == "array" and length > 0 and length <= 100 and
      all(.[];
        (keys | sort) == ["head", "index", "kind", "name", "runnable"] and
        (.kind == "preview" or .kind == "production") and
        (.head | test("^[0-9a-f]{40}$")) and
        (.name | test("^us-east4-docker\\.pkg\\.dev/[a-z0-9-]+/[a-z0-9-]+/[a-z0-9-]+$")) and
        (.index | test("^us-east4-docker\\.pkg\\.dev/[a-z0-9-]+/[a-z0-9-]+/[a-z0-9-]+@sha256:[0-9a-f]{64}$")) and
        (.runnable | test("^us-east4-docker\\.pkg\\.dev/[a-z0-9-]+/[a-z0-9-]+/[a-z0-9-]+@sha256:[0-9a-f]{64}$")))
    ' "$LIVE_IMAGE_SET_FILE" >/dev/null || die "Live image set schema drifted."
    local live_kind live_head expected_image_name live_index_image live_runnable_image
    while IFS=$'\t' read -r live_kind live_head expected_image_name live_index_image live_runnable_image; do
      graph_id=$((graph_id + 1))
      fetch_and_validate_live_image "$regctl" "$trusted_base_root" "$live_kind" "$live_head" \
        "$expected_image_name" "$live_index_image" "$live_runnable_image" "$graph_id"
    done < <(jq -r '.[] | [.kind, .head, .name, .index, .runnable] | @tsv' "$LIVE_IMAGE_SET_FILE")
  else
    graph_id=1
    fetch_and_validate_live_image "$regctl" "$trusted_base_root" \
      "${LIVE_IMAGE_KIND:-production}" \
      "${LIVE_IMAGE_HEAD_SHA:-${LIVE_PRODUCTION_HEAD_SHA:-}}" \
      "${EXPECTED_IMAGE_NAME:-${EXPECTED_PRODUCTION_IMAGE_NAME:-}}" \
      "${LIVE_INDEX_IMAGE:-${LIVE_PRODUCTION_INDEX_IMAGE:-}}" \
      "${LIVE_RUNNABLE_IMAGE:-${LIVE_PRODUCTION_RUNNABLE_IMAGE:-}}" "$graph_id"
  fi
  "$regctl" registry logout us-east4-docker.pkg.dev
  rm -rf -- "$session"
  unset DOCKER_CONFIG REGCTL_CONFIG
  trap - EXIT
  echo "dhi_parity_id=$DHI_PARITY_ID" >> "$GITHUB_OUTPUT"
}

test_live_production_graph() {
  local outer_digest index runnable_digest manifest config_digest config attestation_digest attestation statement_digest statement
  outer_digest="$(jq -er '.manifests[0].digest' "${TEST_IMAGE_ROOT:?}/index.json")"
  index="$TEST_IMAGE_ROOT/blobs/sha256/${outer_digest#sha256:}"
  runnable_digest="$(jq -er '.manifests[0].digest' "$index")"
  manifest="$TEST_IMAGE_ROOT/blobs/sha256/${runnable_digest#sha256:}"
  config_digest="$(jq -er '.config.digest' "$manifest")"
  config="$TEST_IMAGE_ROOT/blobs/sha256/${config_digest#sha256:}"
  attestation_digest="$(jq -er '.manifests[1].digest' "$index")"
  attestation="$TEST_IMAGE_ROOT/blobs/sha256/${attestation_digest#sha256:}"
  statement_digest="$(jq -er '.layers[0].digest' "$attestation")"
  statement="$TEST_IMAGE_ROOT/blobs/sha256/${statement_digest#sha256:}"
  validate_live_production_graph "$index" "$manifest" "$config" "$attestation" "$statement" \
    "${TEST_BASE_ROOT:?}" "${TEST_EXPECTED_INDEX_DIGEST:-$outer_digest}" "${TEST_HEAD_SHA:?}" \
    "${TEST_KIND:-production}" "${TEST_EXPECTED_RUNNABLE_DIGEST:-$runnable_digest}"
}

publish_image() {
  require_linux_x64
  require_digest "${EXPECTED_PUBLISHED_INDEX_DIGEST:?}"
  [[ "${REMOTE_IMAGE:?}" =~ ^us-east4-docker\.pkg\.dev/[a-z0-9-]+/[a-z0-9-]+/[a-z0-9-]+:[A-Za-z0-9._-]+$ ]] || die "Remote image is outside the fixed Artifact Registry shape."
  test -f "${IMAGE_ARCHIVE:?}" && test ! -L "$IMAGE_ARCHIVE" || die "Image archive is invalid."
  test -n "${AR_ACCESS_TOKEN:-}" || die "Artifact Registry access token is absent."
  local regctl="$RUNNER_TEMP/regctl-v${REGCTL_VERSION}"
  if [ -f "$regctl" ] && [ ! -L "$regctl" ]; then
    test "$(sha256_file "$regctl")" = "$REGCTL_SHA256" || die "Prepared regctl drifted."
    "$regctl" version | grep -F "v${REGCTL_VERSION}" >/dev/null
  else
    install_regctl "$regctl"
  fi
  local auth="$RUNNER_TEMP/platform-publisher-auth"
  test ! -e "$auth" && test ! -L "$auth" || die "Publisher auth path exists."
  install -d -m 0700 "$auth/docker" "$auth/regctl"
  export DOCKER_CONFIG="$auth/docker" REGCTL_CONFIG="$auth/regctl/config.json"
  printf '{"auths":{}}\n' > "$DOCKER_CONFIG/config.json"
  printf '{"hosts":{}}\n' > "$REGCTL_CONFIG"
  trap 'rm -rf -- "$auth"; unset AR_ACCESS_TOKEN DOCKER_CONFIG REGCTL_CONFIG' EXIT
  printf '%s' "$AR_ACCESS_TOKEN" | "$regctl" registry login us-east4-docker.pkg.dev --user oauth2accesstoken --pass-stdin
  unset AR_ACCESS_TOKEN
  "$regctl" image import "$REMOTE_IMAGE" "$IMAGE_ARCHIVE"
  local remote_digest
  remote_digest="$("$regctl" image digest "$REMOTE_IMAGE")"
  "$regctl" registry logout us-east4-docker.pkg.dev
  test "$remote_digest" = "$EXPECTED_PUBLISHED_INDEX_DIGEST" || die "Registry changed the promoted index digest."
  rm -rf -- "$auth"
  trap - EXIT
  echo "digest=$remote_digest" >> "$GITHUB_OUTPUT"
}

prepare_publisher() {
  require_linux_x64
  install_regctl "$RUNNER_TEMP/regctl-v${REGCTL_VERSION}"
}

case "${1:-}" in
  prefetch) prefetch ;;
  verify-base) verify_base ;;
  promote) promote_image ;;
  validate-promoted) validate_promoted ;;
  verify-live-production) verify_live_production ;;
  verify-live-image) verify_live_production ;;
  verify-live-images) verify_live_production ;;
  prepare-publisher) prepare_publisher ;;
  publish) publish_image ;;
  print-dhi-parity-id) printf '%s\n' "$DHI_PARITY_ID" ;;
  test-application-oci)
    test "${CONTRACT_TEST_ONLY:-}" = platform-buildkit-v0.32.2-fixture || die "The application OCI test entry point is disabled."
    validate_application_oci "${TEST_IMAGE_ROOT:?}" "${TEST_EXPECTED_INDEX_DIGEST:?}" "${TEST_EXPECTED_RUNNABLE_DIGEST:?}" "${TEST_BASE_ROOT:?}" "${TEST_KIND:?}" "${TEST_HEAD_SHA:?}"
    ;;
  test-runtime-config)
    test "${CONTRACT_TEST_ONLY:-}" = platform-buildkit-v0.32.2-fixture || die "The runtime config test entry point is disabled."
    validate_runtime_config_lineage "${TEST_BUILT_CONFIG:?}" "${TEST_RUNTIME_CONFIG:?}" "${TEST_HEAD_SHA:?}" "${TEST_REPOSITORY:?}"
    ;;
  test-runtime-manifest)
    test "${CONTRACT_TEST_ONLY:-}" = platform-buildkit-v0.32.2-fixture || die "The runtime manifest test entry point is disabled."
    validate_runtime_manifest_lineage "${TEST_BUILT_MANIFEST:?}" "${TEST_RUNTIME_MANIFEST:?}"
    ;;
  test-live-production-graph)
    test "${CONTRACT_TEST_ONLY:-}" = platform-buildkit-v0.32.2-fixture || die "The live production graph test entry point is disabled."
    test_live_production_graph
    ;;
  test-safe-extract)
    test "${CONTRACT_TEST_ONLY:-}" = platform-buildkit-v0.32.2-fixture || die "The tar extraction test entry point is disabled."
    safe_extract_tar "${TEST_ARCHIVE:?}" "${TEST_DESTINATION:?}" "${TEST_MAX_BYTES:?}"
    ;;
  test-child-verification-dispatch)
    test "${CONTRACT_TEST_ONLY:-}" = platform-buildkit-v0.32.2-fixture || die "The child-verification dispatch test entry point is disabled."
    verify_dhi_attestations() { printf '%s\t%s\n' "$3" "$4"; }
    verify_expected_child unused-regctl unused-cosign "${TEST_CHILD_ROLE:?}" "${TEST_CHILD_DIGEST:?}" "${TEST_EXPECTED_CHILD_DIGEST:?}"
    ;;
  test-grype-db-manifest)
    test "${CONTRACT_TEST_ONLY:-}" = platform-buildkit-v0.32.2-fixture || die "The Grype manifest test entry point is disabled."
    load_reviewed_grype_db_manifest >/dev/null
    ;;
  *) echo "usage: container-artifact-contract.sh {prefetch|verify-base|promote|validate-promoted|verify-live-production|verify-live-images|prepare-publisher|publish}" >&2; exit 64 ;;
esac
