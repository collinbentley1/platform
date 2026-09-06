#!/bin/bash
# Verify one Deny canary run for the protected-recovery Terraform module
# (data "external" "canary_verification"): fetch the GitHub run record and
# artifact record through gh, download the artifact, require the downloaded
# archive to carry the evidenced archive digest and the extracted
# deny-canary.json to carry the evidenced raw digest (two distinct values:
# GitHub records the archive's, the attestation signs the file's), and verify
# the attestation cryptographically with gh attestation verify -- the
# Sigstore bundle's signature, certificate chain, and transparency evidence --
# bound to the platform repository and the deny-canary signer workflow. The
# result is the two records, the two digests as computed from the actual
# bytes, the verified certificate summary (whose values only GitHub's OIDC
# token could have put there), and the verified statement; the module then
# requires the certificate's repository, workflow, ref, head, trigger,
# runner, and run invocation to be exactly the named canary execution. Any
# failure answers verified=false with its reason and exits 0, so the module
# reports it as a failed evidence check rather than an opaque provider error.
#
# The digest functions are shared with the artifact-contract test that runs
# in CI against a real upload (tools/ci/protected-recovery-artifact-digests.sh).
set -uo pipefail

# shellcheck source=tools/ci/protected-recovery-artifact-digests.sh
. "$(dirname "$0")/protected-recovery-artifact-digests.sh"

query="$(cat)"
field() { jq -er --arg key "$1" '.[$key]' <<< "$query"; }
answer() {
  jq -cn --arg verified "$1" --arg reason "$2" --arg certificate "${3:-{\}}" --arg statement "${4:-{\}}" --arg run "${5:-{\}}" --arg run_status "${6:-0}" --arg artifact "${7:-{\}}" --arg artifact_status "${8:-0}" --arg archive_sha256 "${9:-}" --arg raw_sha256 "${10:-}" \
    '{verified: $verified, reason: $reason, certificate: $certificate, statement: $statement, run: $run, run_status: $run_status, artifact: $artifact, artifact_status: $artifact_status, archive_sha256: $archive_sha256, raw_sha256: $raw_sha256}'
  exit 0
}

repository="$(field repository)" || answer false "the query names no repository"
run_id="$(field run_id)" || answer false "the query names no run"
artifact_id="$(field artifact_id)" || answer false "the query names no artifact"
artifact_name="$(field artifact_name)" || answer false "the query names no artifact name"
artifact_sha256="$(field artifact_sha256)" || answer false "the query names no raw artifact digest"
archive_sha256="$(field archive_sha256)" || answer false "the query names no archive digest"
signer_workflow="$(field signer_workflow)" || answer false "the query names no signer workflow"
predicate_type="$(field predicate_type)" || answer false "the query names no predicate type"
[[ "$repository" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || answer false "the repository is malformed"
[[ "$run_id" =~ ^[1-9][0-9]*$ ]] && [[ "$artifact_id" =~ ^[1-9][0-9]*$ ]] && [[ "$artifact_sha256" =~ ^[0-9a-f]{64}$ ]] && [[ "$archive_sha256" =~ ^[0-9a-f]{64}$ ]] || answer false "the run, artifact, or digests are malformed"
[[ "$artifact_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || answer false "the artifact name is malformed"
command -v gh > /dev/null || answer false "gh is not installed on the applying machine"
gh auth status > /dev/null 2>&1 || answer false "gh is not authenticated on the applying machine"

workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT

# The authenticated records, exactly as GitHub serves them.
run_status="$(gh api "repos/${repository}/actions/runs/${run_id}" --include > "$workdir/run.raw" 2> "$workdir/error" && head -n 1 "$workdir/run.raw" | tr -d '\r' | cut -d' ' -f2 || echo 0)"
run_json="$(sed -n '/^\r\?$/,$p' "$workdir/run.raw" | sed '1d' | jq -c '.' 2> /dev/null || echo '{}')"
[ "$run_status" = 200 ] || answer false "run ${run_id} of ${repository} answered HTTP ${run_status}: $(tr -d '\n' < "$workdir/error" | cut -c1-200)" "{}" "{}" "$run_json" "$run_status"
artifact_status="$(gh api "repos/${repository}/actions/artifacts/${artifact_id}" --include > "$workdir/artifact.raw" 2> "$workdir/error" && head -n 1 "$workdir/artifact.raw" | tr -d '\r' | cut -d' ' -f2 || echo 0)"
artifact_json="$(sed -n '/^\r\?$/,$p' "$workdir/artifact.raw" | sed '1d' | jq -c '.' 2> /dev/null || echo '{}')"
[ "$artifact_status" = 200 ] || answer false "artifact ${artifact_id} of ${repository} answered HTTP ${artifact_status}: $(tr -d '\n' < "$workdir/error" | cut -c1-200)" "{}" "{}" "$run_json" "$run_status" "$artifact_json" "$artifact_status"

# The bytes: the archive as GitHub serves it, and the one file inside it.
if ! gh api "repos/${repository}/actions/artifacts/${artifact_id}/zip" > "$workdir/artifact.zip" 2> "$workdir/error"; then
  answer false "artifact ${artifact_id} of ${repository} could not be downloaded: $(tr -d '\n' < "$workdir/error" | cut -c1-200)" "{}" "{}" "$run_json" "$run_status" "$artifact_json" "$artifact_status"
fi
actual_archive="$(archive_digest "$workdir/artifact.zip")"
if ! raw="$(extract_single_file "$workdir/artifact.zip" "${artifact_name}.json" "$workdir/deny-canary.json" 2> "$workdir/error")"; then
  answer false "artifact ${artifact_id} does not carry exactly one ${artifact_name}.json: $(tr -d '\n' < "$workdir/error" | cut -c1-200)" "{}" "{}" "$run_json" "$run_status" "$artifact_json" "$artifact_status" "$actual_archive"
fi
actual_raw="$(raw_digest "$raw")"
[ "$actual_archive" = "$archive_sha256" ] || answer false "artifact ${artifact_id} downloads with archive digest ${actual_archive}, not the evidenced ${archive_sha256}" "{}" "{}" "$run_json" "$run_status" "$artifact_json" "$artifact_status" "$actual_archive" "$actual_raw"
[ "$actual_raw" = "$artifact_sha256" ] || answer false "artifact ${artifact_id} carries ${artifact_name}.json with digest ${actual_raw}, not the evidenced ${artifact_sha256}" "{}" "{}" "$run_json" "$run_status" "$artifact_json" "$artifact_status" "$actual_archive" "$actual_raw"
[ "$actual_raw" != "$actual_archive" ] || answer false "the archive digest and the raw digest are one value; the artifact contract is not the modelled one" "{}" "{}" "$run_json" "$run_status" "$artifact_json" "$artifact_status" "$actual_archive" "$actual_raw"

# The attestation, of the raw file.
if ! gh attestation verify "$raw" --repo "$repository" --signer-workflow "$signer_workflow" --predicate-type "$predicate_type" --deny-self-hosted-runners --format json > "$workdir/verified.json" 2> "$workdir/error"; then
  answer false "gh attestation verify refused the attestation: $(tr -d '\n' < "$workdir/error" | cut -c1-300)" "{}" "{}" "$run_json" "$run_status" "$artifact_json" "$artifact_status" "$actual_archive" "$actual_raw"
fi
count="$(jq -r 'length' "$workdir/verified.json" 2> /dev/null)" || answer false "gh attestation verify produced no JSON" "{}" "{}" "$run_json" "$run_status" "$artifact_json" "$artifact_status" "$actual_archive" "$actual_raw"
[ "$count" = 1 ] || answer false "expected exactly one verified attestation for the artifact, found ${count}" "{}" "{}" "$run_json" "$run_status" "$artifact_json" "$artifact_status" "$actual_archive" "$actual_raw"
certificate="$(jq -c '.[0].verificationResult.signature.certificate' "$workdir/verified.json")" || answer false "the verified result carries no certificate" "{}" "{}" "$run_json" "$run_status" "$artifact_json" "$artifact_status" "$actual_archive" "$actual_raw"
statement="$(jq -c '.[0].verificationResult.statement' "$workdir/verified.json")" || answer false "the verified result carries no statement" "{}" "{}" "$run_json" "$run_status" "$artifact_json" "$artifact_status" "$actual_archive" "$actual_raw"
[ "$certificate" != null ] && [ "$statement" != null ] || answer false "the verified result carries no certificate or statement" "{}" "{}" "$run_json" "$run_status" "$artifact_json" "$artifact_status" "$actual_archive" "$actual_raw"
answer true "verified by gh attestation verify for ${repository} run ${run_id}" "$certificate" "$statement" "$run_json" "$run_status" "$artifact_json" "$artifact_status" "$actual_archive" "$actual_raw"
