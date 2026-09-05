#!/bin/bash
# Exercise the protected-recovery Terraform module's enabled path -- every
# target's permanent unique ID recorded and verified live, the Deny canary's
# attestation verified and bound to its signer, the live Deny state bound to
# the attested one, and the activation sequence applied with mock providers
# -- against an isolated copy of the repository. The committed authority
# records no identity or consumer commit and no such records exist offline,
# so the copy records a test identity for each of the thirty-six targets and
# the active commit for every consumer, and the mocked reads are rendered
# from terraform/modules/protected-recovery/enabled/fixtures into
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
# Every consumer records the active commit; runsetta also records a
# transition commit, so its transition-eligible tuples are bound as well.
active="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
transition="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
jq --arg active "$active" --arg transition "$transition" '.consumers |= [range(0; length) as $c | .[$c]
    | .activeWorkflowSha = $active
    | .transitionWorkflowSha = (if .repository == "runsetta" then $transition else null end)
    | .serviceAccountUniqueIds |= (
      (keys | sort) as $accounts
      | reduce range(0; $accounts | length) as $a ({}; . + {
          ($accounts[$a]): ("1" + (($c + 1) | tostring | if length < 2 then "0" + . else . end) + (($a + 1) | tostring | if length < 2 then "0" + . else . end) + "0000000000000000")
        })
    )]' "$root/protected-recovery/authority.json" > "$copy/protected-recovery/authority.json"
test "$(jq '[.consumers[].serviceAccountUniqueIds[] | select(. != null)] | length' "$copy/protected-recovery/authority.json")" = 36
test "$(jq '[.consumers[] | select(.activeWorkflowSha != null)] | length' "$copy/protected-recovery/authority.json")" = 4

# The artifact digest GitHub would record for the fixture bytes, the
# predicate variants, and the certificate variants: the certificate is what
# gh attestation verify derives from the Sigstore signing certificate, whose
# values only GitHub's OIDC token could have put there.
artifact_sha256="$(openssl dgst -sha256 -r "$fixture" | cut -d' ' -f1)"
[[ "$artifact_sha256" =~ ^[0-9a-f]{64}$ ]]
variants="$copy/deny-canary-variants"
mkdir -p "$variants"
cp "$fixture" "$variants/consistent.json"
jq '.policies[0].rules[0].exceptionPrincipals += ["principalSet://goog/group/daily-humans@example.com"]' "$fixture" > "$variants/extra-exception.json"
jq '.policies[0].attachmentPoint = "cloudresourcemanager.googleapis.com/projects/unrelated-project"' "$fixture" > "$variants/unrelated-resource.json"
jq '.policies[0].rules[] |= (.canary |= map(select(.permission != "iam.googleapis.com/serviceAccountKeys.create")))' "$fixture" > "$variants/missing-observation.json"
jq '.brokerImage = "us-east4-docker.pkg.dev/recovery-test/broker/protected-recovery@sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"' "$fixture" > "$variants/other-image.json"

signer="https://github.com/collinbentley1/platform/.github/workflows/protected-recovery-deny-canary.yml@refs/heads/main"
certificate() {
  jq -cn --arg signer "$signer" --arg head "$active" '{
    certificateIssuer: "CN=sigstore-intermediate,O=sigstore.dev",
    subjectAlternativeName: $signer,
    issuer: "https://token.actions.githubusercontent.com",
    githubWorkflowTrigger: "workflow_dispatch",
    githubWorkflowSHA: $head,
    githubWorkflowName: "Protected recovery deny canary",
    githubWorkflowRepository: "collinbentley1/platform",
    githubWorkflowRef: "refs/heads/main",
    buildSignerURI: $signer,
    buildSignerDigest: $head,
    runnerEnvironment: "github-hosted",
    sourceRepositoryURI: "https://github.com/collinbentley1/platform",
    sourceRepositoryDigest: $head,
    sourceRepositoryRef: "refs/heads/main",
    sourceRepositoryIdentifier: "1255856466",
    sourceRepositoryOwnerURI: "https://github.com/collinbentley1",
    sourceRepositoryOwnerIdentifier: "16823277",
    buildConfigURI: $signer,
    buildConfigDigest: $head,
    buildTrigger: "workflow_dispatch",
    runInvocationURI: "https://github.com/collinbentley1/platform/actions/runs/100000000002/attempts/1",
    sourceRepositoryVisibilityAtSigning: "public"
  }' | case "$1" in
    consistent) cat ;;
    other-workflow) jq -c '.buildSignerURI = "https://github.com/collinbentley1/platform/.github/workflows/protected-recovery-invoke.yml@refs/heads/main" | .subjectAlternativeName = .buildSignerURI' ;;
    other-run) jq -c '.runInvocationURI = "https://github.com/collinbentley1/platform/actions/runs/100000000009/attempts/1"' ;;
    other-head) jq -c '.sourceRepositoryDigest = "cccccccccccccccccccccccccccccccccccccccc"' ;;
    other-repository) jq -c '.sourceRepositoryIdentifier = "999" | .sourceRepositoryURI = "https://github.com/evil/platform"' ;;
    self-hosted) jq -c '.runnerEnvironment = "self-hosted"' ;;
    *) echo "unknown certificate variant $1" >&2; exit 1 ;;
  esac
}

# The verification result as the external data source carries it: a flat map
# of strings, rendered as one HCL values attribute.
verification() {
  local certificate_variant="$1" predicate_variant="$2"
  if [ "$predicate_variant" = unverified ]; then
    printf '  values = { result = { verified = "false", reason = "gh attestation verify refused the attestation: no matching attestations found", certificate = "{}", statement = "{}" } }\n'
    return 0
  fi
  test -f "$variants/$predicate_variant.json"
  local certificate statement
  certificate="$(certificate "$certificate_variant" | jq -R -r '@json')"
  statement="$(jq -cn --arg sha "$artifact_sha256" --slurpfile predicate "$variants/$predicate_variant.json" '{
    "_type": "https://in-toto.io/Statement/v1",
    predicateType: "https://github.com/collinbentley1/platform/protected-recovery/deny-canary/v1",
    subject: [{ name: "deny-canary.json", digest: { sha256: $sha } }],
    predicate: $predicate[0]
  }' | jq -R -r '@json')"
  printf '  values = { result = { verified = "true", reason = "verified by gh attestation verify", certificate = %s, statement = %s } }\n' "$certificate" "$statement"
}

# The live Deny state as the IAM v2 API answers it, derived from the attested
# policies: a listing per attachment point (metadata only, as the API
# documents) and each policy with its etag and rules.
live_policy() {
  local name="$1" variant="${2:-consistent}"
  jq -c --arg name "$name" '.policies[] | select(.name == $name) | {
    name: .name, uid: ("uid-" + (.name | @base64 | .[0:12])), kind: "DenyPolicy", displayName: "protected recovery", etag: .etag,
    createTime: "2026-09-01T00:00:00Z", updateTime: "2026-09-01T00:00:00Z",
    rules: [.rules[] | { denyRule: { deniedPrincipals: .deniedPrincipals, exceptionPrincipals: .exceptionPrincipals, deniedPermissions: .deniedPermissions } }]
  }' "$fixture" | case "$variant" in
    consistent) cat ;;
    etag-moved) jq -c '.etag = (.etag + "-2")' ;;
    exception-widened) jq -c '.rules[0].denyRule.exceptionPrincipals += ["principalSet://goog/group/daily-humans@example.com"]' ;;
    condition-added) jq -c '.rules[0].denyRule.denialCondition = { expression: "!resource.matchTag(\"100000000001/env\", \"canary\")" }' ;;
    permission-missing) jq -c '.rules[4].denyRule.deniedPermissions -= ["cloudresourcemanager.googleapis.com/projects.setIamPolicy"]' ;;
    *) echo "unknown live policy variant $variant" >&2; exit 1 ;;
  esac
}
live_listing() {
  local attachment="$1" variant="${2:-consistent}"
  jq -c --arg attachment "$attachment" '{ policies: [.policies[] | select(.attachmentPoint == $attachment) | { name: .name, uid: ("uid-" + (.name | @base64 | .[0:12])), kind: "DenyPolicy", displayName: "protected recovery", etag: .etag, createTime: "2026-09-01T00:00:00Z", updateTime: "2026-09-01T00:00:00Z" }] }' "$fixture" | case "$variant" in
    consistent) cat ;;
    missing) jq -c '.policies = []' ;;
    *) echo "unknown live listing variant $variant" >&2; exit 1 ;;
  esac
}
override_http() {
  local address="$1" body="$2"
  printf 'override_data {\n  target = %s\n  values = {\n    status_code   = 200\n    response_body = %s\n  }\n}\n' "$address" "$(printf '%s' "$body" | jq -R -r '@json')"
}
broker_attachment="cloudresourcemanager.googleapis.com/projects/recovery-test"
broker_policy="$(jq -r --arg attachment "$broker_attachment" '.policies[] | select(.attachmentPoint == $attachment) | .name' "$fixture")"
live_deny_state() {
  local attachment name
  while IFS= read -r attachment; do
    override_http "data.http.deny_policies[\"$attachment\"]" "$(live_listing "$attachment")"
    while IFS= read -r name; do
      override_http "data.http.deny_policy[\"$name\"]" "$(live_policy "$name")"
    done < <(jq -r --arg attachment "$attachment" '.policies[] | select(.attachmentPoint == $attachment) | .name' "$fixture")
  done < <(jq -r '.policies[].attachmentPoint' "$fixture")
}

# A line consisting solely of a placeholder becomes that record; the artifact
# digest placeholder is inline.
rendered="$copy/$module/enabled/enabled.tftest.hcl"
while IFS= read -r line; do
  trimmed="${line#"${line%%[![:space:]]*}"}"
  case "$trimmed" in
    @@VERIFICATION:*@@)
      spec="${trimmed#@@VERIFICATION:}"
      spec="${spec%@@}"
      verification "${spec%%:*}" "${spec#*:}"
      ;;
    @@LIVE_DENY_STATE@@)
      live_deny_state
      ;;
    @@LIVE_DENY_POLICY:*@@)
      variant="${trimmed#@@LIVE_DENY_POLICY:}"
      variant="${variant%@@}"
      override_http "data.http.deny_policy[\"$broker_policy\"]" "$(live_policy "$broker_policy" "$variant")" | sed 's/^/  /'
      ;;
    @@LIVE_DENY_LISTING:*@@)
      variant="${trimmed#@@LIVE_DENY_LISTING:}"
      variant="${variant%@@}"
      override_http "data.http.deny_policies[\"$broker_attachment\"]" "$(live_listing "$broker_attachment" "$variant")" | sed 's/^/  /'
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
terraform fmt -check "$rendered" > /dev/null || terraform fmt "$rendered" > /dev/null

# Only the rendered enabled-path file runs here: the module's own mocked suite
# asserts the committed, unrecorded state and is run against the checkout.
terraform -chdir="$copy/$module" init -backend=false -input=false -lockfile=readonly
terraform -chdir="$copy/$module" test -test-directory=enabled -filter=enabled/enabled.tftest.hcl -no-color
