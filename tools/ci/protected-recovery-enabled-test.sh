#!/bin/bash
# Exercise the protected-recovery Terraform module's enabled path -- every
# target's permanent unique ID recorded and verified live, the Deny canary
# evidence verified against GitHub's run, artifact, and attestation records --
# against an isolated copy of the repository. The committed authority records
# no identity and no such records exist offline, so the copy records a test
# identity for each of the thirty-six targets, and the mocked GitHub reads are
# rendered from terraform/modules/protected-recovery/enabled/fixtures into
# enabled/enabled.tftest.hcl.in. The checked-out tree is never modified.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
module="terraform/modules/protected-recovery"
fixture="$root/$module/enabled/fixtures/deny-canary.json"
template="$root/$module/enabled/enabled.tftest.hcl.in"
copy="$(mktemp -d)"
trap 'rm -rf -- "$copy"' EXIT
rsync -a --exclude .git --exclude node_modules --exclude .terraform "$root/" "$copy/"

# The test identity of the target at consumer index c (consumers sorted by
# repository) and account index a (accounts sorted): 1, cc, aa, sixteen zeros.
jq '.consumers |= [range(0; length) as $c | .[$c] | .serviceAccountUniqueIds |= (
      (keys | sort) as $accounts
      | reduce range(0; $accounts | length) as $a ({}; . + {
          ($accounts[$a]): ("1" + (($c + 1) | tostring | if length < 2 then "0" + . else . end) + (($a + 1) | tostring | if length < 2 then "0" + . else . end) + "0000000000000000")
        })
    )]' "$root/protected-recovery/authority.json" > "$copy/protected-recovery/authority.json"
test "$(jq '[.consumers[].serviceAccountUniqueIds[] | select(. != null)] | length' "$copy/protected-recovery/authority.json")" = 36

# The artifact digest GitHub would record for the fixture bytes, and the
# attested statement of each variant of the canary predicate.
artifact_sha256="$(openssl dgst -sha256 -r "$fixture" | cut -d' ' -f1)"
[[ "$artifact_sha256" =~ ^[0-9a-f]{64}$ ]]
variants="$copy/deny-canary-variants"
mkdir -p "$variants"
cp "$fixture" "$variants/consistent.json"
jq '.policies[0].rules[0].exceptionPrincipals += ["principalSet://goog/group/daily-humans@example.com"]' "$fixture" > "$variants/extra-exception.json"
jq '.policies[0].attachmentPoint = "cloudresourcemanager.googleapis.com/projects/unrelated-project"' "$fixture" > "$variants/unrelated-resource.json"
jq '.unsupported = ["cloudresourcemanager.googleapis.com/projects.setIamPolicy"]
    | .policies[].rules[] |= (.deniedPermissions -= ["cloudresourcemanager.googleapis.com/projects.setIamPolicy"] | .canary |= map(select(.permission != "cloudresourcemanager.googleapis.com/projects.setIamPolicy")))' "$fixture" > "$variants/unsupported.json"
jq '.policies[0].rules[] |= (.canary |= map(select(.permission != "iam.googleapis.com/serviceAccountKeys.create")))' "$fixture" > "$variants/missing-observation.json"
jq '.brokerImage = "us-east4-docker.pkg.dev/recovery-test/broker/protected-recovery@sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"' "$fixture" > "$variants/other-image.json"

attestations() {
  local payload
  payload="$(jq -c -n --arg sha "$artifact_sha256" --slurpfile predicate "$1" '{
    "_type": "https://in-toto.io/Statement/v1",
    predicateType: "https://github.com/collinbentley1/platform/protected-recovery/deny-canary/v1",
    subject: [{ name: "deny-canary.json", digest: { sha256: $sha } }],
    predicate: $predicate[0]
  }' | base64 | tr -d '\n')"
  jq -c -n --arg payload "$payload" '{ attestations: [{ bundle: { dsseEnvelope: { payload: $payload, payloadType: "application/vnd.in-toto+json" }, mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json" }, repository_id: 1255856466 }] }'
}

# A line consisting solely of an attestation placeholder becomes that
# variant's attestation record; the artifact digest placeholder is inline.
rendered="$copy/$module/enabled/enabled.tftest.hcl"
while IFS= read -r line; do
  trimmed="${line#"${line%%[![:space:]]*}"}"
  case "$trimmed" in
    @@ATTESTATION:*@@)
      name="${trimmed#@@ATTESTATION:}"
      name="${name%@@}"
      test -f "$variants/$name.json"
      attestations "$variants/$name.json"
      ;;
    *)
      printf '%s\n' "$line"
      ;;
  esac
done < "$template" | sed "s/@@ARTIFACT_SHA256@@/$artifact_sha256/g" > "$rendered"
if grep -q '@@' "$rendered"; then
  echo "The rendered enabled-path test still carries a placeholder." >&2
  exit 1
fi

# Only the rendered enabled-path file runs here: the module's own mocked suite
# asserts the committed, unrecorded state and is run against the checkout.
terraform -chdir="$copy/$module" init -backend=false -input=false -lockfile=readonly
terraform -chdir="$copy/$module" test -test-directory=enabled -filter=enabled/enabled.tftest.hcl -no-color
