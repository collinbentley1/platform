#!/bin/bash
# Verify the Deny canary's attestation for the protected-recovery Terraform
# module (data "external" "canary_verification"): fetch the named artifact,
# require its bytes to carry the digest the evidence names, and verify its
# attestation cryptographically with gh attestation verify -- the Sigstore
# bundle's signature, certificate chain, and transparency evidence -- bound
# to the platform repository and the deny-canary signer workflow. The result
# is the verified certificate summary (whose values only GitHub's OIDC token
# could have put there) and the verified statement; the module then requires
# the certificate's repository, workflow, ref, head, trigger, runner, and run
# invocation to be exactly the named canary execution. Any failure answers
# verified=false with its reason and exits 0, so the module reports it as a
# failed evidence check rather than an opaque provider error.
set -uo pipefail

query="$(cat)"
field() { jq -er --arg key "$1" '.[$key]' <<< "$query"; }
answer() {
  jq -cn --arg verified "$1" --arg reason "$2" --arg certificate "${3:-{\}}" --arg statement "${4:-{\}}" '{verified: $verified, reason: $reason, certificate: $certificate, statement: $statement}'
  exit 0
}

repository="$(field repository)" || answer false "the query names no repository"
run_id="$(field run_id)" || answer false "the query names no run"
artifact_id="$(field artifact_id)" || answer false "the query names no artifact"
artifact_sha256="$(field artifact_sha256)" || answer false "the query names no artifact digest"
signer_workflow="$(field signer_workflow)" || answer false "the query names no signer workflow"
predicate_type="$(field predicate_type)" || answer false "the query names no predicate type"
[[ "$repository" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || answer false "the repository is malformed"
[[ "$run_id" =~ ^[1-9][0-9]*$ ]] && [[ "$artifact_id" =~ ^[1-9][0-9]*$ ]] && [[ "$artifact_sha256" =~ ^[0-9a-f]{64}$ ]] || answer false "the run, artifact, or digest is malformed"
command -v gh > /dev/null || answer false "gh is not installed on the applying machine"
gh auth status > /dev/null 2>&1 || answer false "gh is not authenticated on the applying machine"

workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT
if ! gh api "repos/${repository}/actions/artifacts/${artifact_id}/zip" > "$workdir/artifact.zip" 2> "$workdir/error"; then
  answer false "artifact ${artifact_id} of ${repository} could not be fetched: $(tr -d '\n' < "$workdir/error" | cut -c1-200)"
fi
if ! unzip -p "$workdir/artifact.zip" deny-canary.json > "$workdir/deny-canary.json" 2> "$workdir/error"; then
  answer false "artifact ${artifact_id} carries no deny-canary.json"
fi
actual="$(openssl dgst -sha256 -r "$workdir/deny-canary.json" | cut -d' ' -f1)"
[ "$actual" = "$artifact_sha256" ] || answer false "artifact ${artifact_id} has digest ${actual}, not the evidenced ${artifact_sha256}"
if ! gh attestation verify "$workdir/deny-canary.json" --repo "$repository" --signer-workflow "$signer_workflow" --predicate-type "$predicate_type" --deny-self-hosted-runners --format json > "$workdir/verified.json" 2> "$workdir/error"; then
  answer false "gh attestation verify refused the attestation: $(tr -d '\n' < "$workdir/error" | cut -c1-300)"
fi
count="$(jq -r 'length' "$workdir/verified.json" 2> /dev/null)" || answer false "gh attestation verify produced no JSON"
[ "$count" = 1 ] || answer false "expected exactly one verified attestation for the artifact, found ${count}"
certificate="$(jq -c '.[0].verificationResult.signature.certificate' "$workdir/verified.json")" || answer false "the verified result carries no certificate"
statement="$(jq -c '.[0].verificationResult.statement' "$workdir/verified.json")" || answer false "the verified result carries no statement"
[ "$certificate" != null ] && [ "$statement" != null ] || answer false "the verified result carries no certificate or statement"
answer true "verified by gh attestation verify for ${repository} run ${run_id}" "$certificate" "$statement"
