#!/bin/bash
# The Deny canary artifact digest contract, in one place: the archive digest
# GitHub records for an uploaded artifact (the sha256 of the archive bytes the
# download endpoint serves) and the raw digest the attestation signs (the
# sha256 of the one file inside). Sourced by the module's verifier
# (tools/ci/protected-recovery-verify-canary.sh), by the canary workflow's
# self-check of its own run, and by the CI artifact-contract job that
# exercises a real upload, record, and download
# (.github/workflows/platform.yml). Functions only; no side effects.

archive_digest() {
  openssl dgst -sha256 -r "$1" | cut -d' ' -f1
}

raw_digest() {
  openssl dgst -sha256 -r "$1" | cut -d' ' -f1
}

# Extract exactly the named file from an archive into the destination path
# and print the destination; refuse an archive with any other entry, so the
# attested subject is the whole artifact.
extract_single_file() {
  local archive="$1" name="$2" destination="$3"
  local entries
  entries="$(unzip -Z1 "$archive")" || return 1
  if [ "$entries" != "$name" ]; then
    echo "the archive lists [$(printf '%s' "$entries" | tr '\n' ',')], not exactly ${name}" >&2
    return 1
  fi
  unzip -p "$archive" "$name" > "$destination" || return 1
  printf '%s\n' "$destination"
}
