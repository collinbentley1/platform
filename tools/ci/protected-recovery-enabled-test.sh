#!/bin/bash
# Exercise the protected-recovery Terraform module's enabled path -- every
# target's permanent unique ID recorded and verified live, both phases of the
# Deny canary verified and bound to their signer and to each other, the live
# Deny state bound to the attested one, the consumer attachment rows that
# rest on a disabled API bound to a live read of that API, the module's Deny
# matrix equal to the broker runtime's in every form, and the activation
# sequence applied with mock providers -- against an isolated copy of the
# repository. The committed authority records no identity or consumer commit
# and no such records exist offline, so the copy records a test identity for
# each of the thirty-six targets and the active commit for every consumer,
# the two phases' predicates are rendered by the canary producer's own shape
# (tools/ci/protected-recovery-canary-fixture.ts), the matrices by the
# runtime's derivation (tools/ci/protected-recovery-matrix.ts), and every
# mocked read is rendered from them into enabled/enabled.tftest.hcl.in. The
# checked-out tree is never modified.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
module="terraform/modules/protected-recovery"
template="$root/$module/enabled/enabled.tftest.hcl.in"
copy="$(mktemp -d)"
trap 'rm -rf -- "$copy"' EXIT
rsync -a --exclude .git --exclude node_modules --exclude .terraform "$root/" "$copy/"

# The test identity of the target at consumer index c (consumers sorted by
# repository) and account index a (accounts sorted): 1, cc, aa, sixteen zeros.
# Every consumer records the active commit; runsetta also records a
# transition commit, so its transition-eligible tuples are bound as well. The
# broker project and the organization are the ones the tests name, and the
# mocked applying identity is declared as the bootstrap principal, so the
# activation apply's own mutations are permitted their principal.
active="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
transition="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
image="us-east4-docker.pkg.dev/recovery-test/broker/protected-recovery@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
authority="$copy/protected-recovery/authority.json"
jq --arg active "$active" --arg transition "$transition" '
  .broker.projectId = "recovery-test" | .broker.projectNumber = "123456789012" | .organizationId = "100000000001"
  | .bootstrapPrincipal = "principal://goog/subject/cloud-root@cdbentley.com"
  | .consumers |= [range(0; length) as $c | .[$c]
    | .activeWorkflowSha = $active
    | .transitionWorkflowSha = (if .repository == "runsetta" then $transition else null end)
    | .serviceAccountUniqueIds |= (
      (keys | sort) as $accounts
      | reduce range(0; $accounts | length) as $a ({}; . + {
          ($accounts[$a]): ("1" + (($c + 1) | tostring | if length < 2 then "0" + . else . end) + (($a + 1) | tostring | if length < 2 then "0" + . else . end) + "0000000000000000")
        })
    )]' "$root/protected-recovery/authority.json" > "$authority"
test "$(jq '[.consumers[].serviceAccountUniqueIds[] | select(. != null)] | length' "$authority")" = 36
test "$(jq '[.consumers[] | select(.activeWorkflowSha != null)] | length' "$authority")" = 4
# The committed module reads the committed authority, whose broker and
# organization are null; the copy's module reads the copy's.
test "$(jq -r '.broker.projectId' "$root/protected-recovery/authority.json")" = null

# The fixtures: the matrices in every form, and the two phases' predicates.
fixtures="$copy/$module/enabled/fixtures"
rm -rf "$fixtures"
mkdir -p "$fixtures"
consumers="$(jq -r '[.consumers[].repository] | join(",")' "$authority")"
(cd "$root" && bun --no-env-file run tools/ci/protected-recovery-matrix.ts "$authority" "$active" steady > "$fixtures/matrix-steady.json")
(cd "$root" && bun --no-env-file run tools/ci/protected-recovery-matrix.ts "$authority" "$active" bootstrap > "$fixtures/matrix-bootstrap.json")
(cd "$root" && bun --no-env-file run tools/ci/protected-recovery-matrix.ts "$authority" "$active" maintenance > "$fixtures/matrix-maintenance.json")
(cd "$root" && bun --no-env-file run tools/ci/protected-recovery-matrix.ts "$authority" "$active" steady "deployment=${consumers}" > "$fixtures/matrix-deployment.json")
(cd "$root" && bun --no-env-file run tools/ci/protected-recovery-canary-fixture.ts "$authority" "$active" control 100000000001 100000000001 "$image" > "$fixtures/control.json")
(cd "$root" && bun --no-env-file run tools/ci/protected-recovery-canary-fixture.ts "$authority" "$active" deny 100000000001 100000000003 "$image" > "$fixtures/deny.json")
test "$(jq 'length' "$fixtures/matrix-steady.json")" = "$((35 + 4 * 28 + 5))"
test "$(jq '[.policies[].rules[].canary[]] | length' "$fixtures/deny.json")" = "$((35 + 4 * 28 + 5))"
test "$(jq '[.policies[].rules[].canary[] | select(.outcome == "UNSERVICEABLE")] | length' "$fixtures/deny.json")" = 16

# The digests each phase's evidence names: the raw digest of the fixture
# bytes the attestation signs, and a distinct archive digest GitHub would
# record for the artifact.
digest() { openssl dgst -sha256 -r "$1" | cut -d' ' -f1; }
raw_control="$(digest "$fixtures/control.json")"
raw_deny="$(digest "$fixtures/deny.json")"
archive_control="$(printf '%s archive' "$raw_control" | openssl dgst -sha256 -r | cut -d' ' -f1)"
archive_deny="$(printf '%s archive' "$raw_deny" | openssl dgst -sha256 -r | cut -d' ' -f1)"
[[ "$raw_control" =~ ^[0-9a-f]{64}$ ]] && [[ "$raw_deny" =~ ^[0-9a-f]{64}$ ]]

run_id() { case "$1" in control) echo 100000000001 ;; deny) echo 100000000003 ;; esac; }
artifact_id() { case "$1" in control) echo 100000000002 ;; deny) echo 100000000004 ;; esac; }
raw_of() { case "$1" in control) echo "$raw_control" ;; deny) echo "$raw_deny" ;; esac; }
archive_of() { case "$1" in control) echo "$archive_control" ;; deny) echo "$archive_deny" ;; esac; }

signer="https://github.com/collinbentley1/platform/.github/workflows/protected-recovery-deny-canary.yml@refs/heads/main"

# The certificate gh attestation verify derives from the Sigstore signing
# certificate of one phase's run, whose values only GitHub's OIDC token could
# have put there, and one deviation of it.
certificate() {
  local phase="$1" variant="$2"
  jq -cn --arg signer "$signer" --arg head "$active" --arg run "$(run_id "$phase")" '{
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
    runInvocationURI: ("https://github.com/collinbentley1/platform/actions/runs/" + $run + "/attempts/1"),
    sourceRepositoryVisibilityAtSigning: "public"
  }' | case "$variant" in
    other-workflow) jq -c '.buildSignerURI = "https://github.com/collinbentley1/platform/.github/workflows/protected-recovery-invoke.yml@refs/heads/main" | .subjectAlternativeName = .buildSignerURI' ;;
    other-run) jq -c '.runInvocationURI = "https://github.com/collinbentley1/platform/actions/runs/100000000009/attempts/1"' ;;
    other-head) jq -c '.sourceRepositoryDigest = "cccccccccccccccccccccccccccccccccccccccc"' ;;
    other-repository) jq -c '.sourceRepositoryIdentifier = "999" | .sourceRepositoryURI = "https://github.com/evil/platform"' ;;
    self-hosted) jq -c '.runnerEnvironment = "self-hosted"' ;;
    *) cat ;;
  esac
}

# The predicate of one phase, exactly as rendered, or with one deviation. The
# broker's key-creation row is the one every observation-level deviation
# touches, so the assertions can name it.
predicate() {
  local phase="$1" variant="$2"
  local key="iam.googleapis.com/serviceAccountKeys.create"
  local broker="cloudresourcemanager.googleapis.com/projects/recovery-test"
  case "$variant" in
    extra-exception) jq -c '.policies[0].rules[0].exceptionPrincipals += ["principalSet://goog/group/daily-humans@example.com"]' "$fixtures/$phase.json" ;;
    unrelated-resource) jq -c '.policies[0].attachmentPoint = "cloudresourcemanager.googleapis.com/projects/unrelated-project"' "$fixtures/$phase.json" ;;
    missing-observation) jq -c --arg key "$key" '.policies[].rules[] |= (.canary |= map(select(.permission != $key)))' "$fixtures/$phase.json" ;;
    other-image) jq -c '.brokerImage = "us-east4-docker.pkg.dev/recovery-test/broker/protected-recovery@sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"' "$fixtures/$phase.json" ;;
    other-phase) jq -c '.phase = (if .phase == "deny" then "control" else "deny" end)' "$fixtures/$phase.json" ;;
    other-control) jq -c '.controlRunId = "100000000009"' "$fixtures/$phase.json" ;;
    request-mismatch) jq -c --arg key "$key" --arg broker "$broker" '(.policies[] | select(.attachmentPoint == $broker) | .rules[].canary[] | select(.permission == $key) | .request.url) |= (. + "?attempt=2")' "$fixtures/$phase.json" ;;
    missing-cause) jq -c --arg key "$key" --arg broker "$broker" '(.policies[] | select(.attachmentPoint == $broker) | .rules[].canary[] | select(.permission == $key) | .response) |= (.reason = "" | .permission = "" | .rawPermission = "")' "$fixtures/$phase.json" ;;
    unexercised) jq -c --arg key "$key" --arg broker "$broker" '.unexercised = [$broker + "|" + $key]' "$fixtures/$phase.json" ;;
    *) jq -c '.' "$fixtures/$phase.json" ;;
  esac
}

# The run and artifact records of one phase as GitHub serves them, or with
# one deviation.
run_record() {
  local phase="$1" variant="$2" created updated
  case "$phase" in
    control) created="2026-09-05T00:00:00Z"; updated="2026-09-05T00:30:00Z" ;;
    deny) created="2026-09-05T01:00:00Z"; updated="2026-09-05T01:30:00Z" ;;
  esac
  jq -cn --argjson id "$(run_id "$phase")" --arg head "$active" --arg created "$created" --arg updated "$updated" '{id: $id, run_attempt: 1, status: "completed", conclusion: "success", head_sha: $head, path: ".github/workflows/protected-recovery-deny-canary.yml", event: "workflow_dispatch", repository: {id: 1255856466}, head_repository: {id: 1255856466}, created_at: $created, updated_at: $updated}' | case "$variant" in
    run-other-head) jq -c '.head_sha = "cccccccccccccccccccccccccccccccccccccccc"' ;;
    control-after-deny) jq -c '.updated_at = "2026-09-05T02:00:00Z"' ;;
    *) cat ;;
  esac
}
artifact_record() {
  local phase="$1" variant="$2"
  jq -cn --argjson id "$(artifact_id "$phase")" --argjson run "$(run_id "$phase")" --arg head "$active" --arg archive "$(archive_of "$phase")" '{id: $id, name: "deny-canary", digest: ("sha256:" + $archive), expired: false, workflow_run: {id: $run, head_sha: $head}}' | case "$variant" in
    artifact-digest) jq -c '.digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' ;;
    *) cat ;;
  esac
}

# The verification result as the external data source carries it: a flat map
# of strings, rendered as one HCL values attribute.
verification() {
  local phase="$1" variant="$2"
  local run_status=200 artifact_status=200 verified=true reason="verified by gh attestation verify"
  local certificate statement run artifact
  run="$(run_record "$phase" "$variant" | jq -R -r '@json')"
  artifact="$(artifact_record "$phase" "$variant" | jq -R -r '@json')"
  case "$variant" in
    run-missing) run_status=404; run='"{}"' ;;
    unverified) verified=false; reason="gh attestation verify refused the attestation: no matching attestations found" ;;
  esac
  if [ "$verified" = true ]; then
    certificate="$(certificate "$phase" "$variant" | jq -R -r '@json')"
    # The predicate carries every row of both phases and exceeds a single
    # argument's size on Linux (MAX_ARG_STRLEN), so it reaches jq as a file
    # rather than as argv.
    predicate "$phase" "$variant" > "$copy/predicate.json"
    statement="$(jq -cn --arg sha "$(raw_of "$phase")" --slurpfile predicate "$copy/predicate.json" '{
      "_type": "https://in-toto.io/Statement/v1",
      predicateType: "https://github.com/collinbentley1/platform/protected-recovery/deny-canary/v2",
      subject: [{ name: "deny-canary.json", digest: { sha256: $sha } }],
      predicate: $predicate[0]
    }' | jq -R -r '@json')"
  else
    certificate='"{}"'
    statement='"{}"'
  fi
  printf '  values = { result = { verified = "%s", reason = %s, certificate = %s, statement = %s, run = %s, run_status = "%s", artifact = %s, artifact_status = "%s", archive_sha256 = "%s", raw_sha256 = "%s" } }\n' \
    "$verified" "$(jq -Rn --arg reason "$reason" '$reason | @json')" "$certificate" "$statement" "$run" "$run_status" "$artifact" "$artifact_status" "$(archive_of "$phase")" "$(raw_of "$phase")"
}

# The live Deny state as the credential-free reader answers it, derived from
# the deny phase's attested policies: the policies of one attachment point
# with their names, etags, and rules, or with one deviation of the broker's.
live_policies() {
  local attachment="$1" variant="${2:-consistent}"
  jq -c --arg attachment "$attachment" '[.policies[] | select(.attachmentPoint == $attachment) | {name: .name, etag: .etag, rules: [.rules[] | {denialCondition: .denialCondition, deniedPermissions: .deniedPermissions, deniedPrincipals: .deniedPrincipals, exceptionPermissions: (.exceptionPermissions // []), exceptionPrincipals: .exceptionPrincipals}]}]' "$fixtures/deny.json" | case "$variant" in
    etag-moved) jq -c '.[0].etag = (.[0].etag + "-2")' ;;
    exception-widened) jq -c '.[0].rules[0].exceptionPrincipals += ["principalSet://goog/group/daily-humans@example.com"]' ;;
    condition-added) jq -c '.[0].rules[0].denialCondition = { expression: "!resource.matchTag(\"100000000001/env\", \"canary\")" }' ;;
    permission-missing) jq -c '.[0].rules[] |= (.deniedPermissions -= ["cloudresourcemanager.googleapis.com/projects.setIamPolicy"])' ;;
    missing) jq -c '[]' ;;
    consistent) cat ;;
    *) echo "unknown live policy variant $variant" >&2; exit 1 ;;
  esac
}
override_deny_state() {
  local attachment="$1" variant="${2:-consistent}"
  printf 'override_data {\n  target          = data.external.deny_state["%s"]\n  override_during = plan\n  values          = { result = { status = "200", reason = "", policies = %s } }\n}\n' "$attachment" "$(live_policies "$attachment" "$variant" | jq -R -r '@json')"
}
broker_attachment="cloudresourcemanager.googleapis.com/projects/recovery-test"
live_deny_state() {
  local attachment
  while IFS= read -r attachment; do
    override_deny_state "$attachment"
  done < <(jq -r '.policies[].attachmentPoint' "$fixtures/deny.json")
}

# The live service-state reads of every consumer project's Compute and Cloud
# Build API, or one of them with the given state.
override_service_state() {
  local project="$1" service="$2" state="$3"
  if [ "$state" = unread ]; then
    printf 'override_data {\n  target          = data.external.service_state["%s|%s"]\n  override_during = plan\n  values          = { result = { status = "503", state = "", reason = "reading the service answered HTTP 503" } }\n}\n' "$project" "$service"
  else
    printf 'override_data {\n  target          = data.external.service_state["%s|%s"]\n  override_during = plan\n  values          = { result = { status = "200", state = "%s", reason = "" } }\n}\n' "$project" "$service" "$state"
  fi
}
live_service_state() {
  local project service
  while IFS= read -r project; do
    for service in cloudbuild.googleapis.com compute.googleapis.com; do
      override_service_state "$project" "$service" DISABLED
    done
  done < <(jq -r '.consumers[].projectId' "$authority")
}

# The thirty-six live account reads, each resolving to its recorded identity.
target_identities() {
  jq -r '.consumers[] as $consumer | $consumer.serviceAccountUniqueIds | to_entries[] | "\($consumer.repository)\t\($consumer.projectId)\t\(.key)\t\(.value)"' "$authority" | while IFS=$'\t' read -r repository project account unique_id; do
    printf 'override_data {\n  target = data.google_service_account.target["%s/%s"]\n  values = {\n    email     = "%s@%s.iam.gserviceaccount.com"\n    name      = "projects/%s/serviceAccounts/%s@%s.iam.gserviceaccount.com"\n    unique_id = "%s"\n  }\n}\n' "$repository" "$account" "$account" "$project" "$project" "$account" "$project" "$unique_id"
  done
}

# A line consisting solely of a placeholder becomes that record; the digest
# placeholders are inline.
rendered="$copy/$module/enabled/enabled.tftest.hcl"
while IFS= read -r line; do
  trimmed="${line#"${line%%[![:space:]]*}"}"
  case "$trimmed" in
    @@TARGET_IDENTITIES@@)
      target_identities
      ;;
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
      override_deny_state "$broker_attachment" "$variant" | sed 's/^/  /'
      ;;
    @@LIVE_DENY_LISTING:missing@@)
      override_deny_state "$broker_attachment" missing | sed 's/^/  /'
      ;;
    @@LIVE_SERVICE_STATE@@)
      live_service_state
      ;;
    @@LIVE_SERVICE_STATE:*@@)
      spec="${trimmed#@@LIVE_SERVICE_STATE:}"
      spec="${spec%@@}"
      project="${spec%%:*}"
      rest="${spec#*:}"
      override_service_state "$project" "${rest%%:*}" "${rest#*:}" | sed 's/^/  /'
      ;;
    *)
      printf '%s\n' "$line"
      ;;
  esac
done < "$template" | sed -e "s/@@RAW_control@@/$raw_control/g" -e "s/@@ARCHIVE_control@@/$archive_control/g" -e "s/@@RAW_deny@@/$raw_deny/g" -e "s/@@ARCHIVE_deny@@/$archive_deny/g" > "$rendered"
if grep -q '@@' "$rendered"; then
  echo "The rendered enabled-path test still carries a placeholder." >&2
  grep -n '@@' "$rendered" | head -5 >&2
  exit 1
fi
terraform fmt -check "$rendered" > /dev/null || terraform fmt "$rendered" > /dev/null
# The rendered file, kept for inspection when a path is named; with the
# render-only switch nothing runs.
[ -z "${PROTECTED_RECOVERY_ENABLED_RENDERED:-}" ] || cp "$rendered" "$PROTECTED_RECOVERY_ENABLED_RENDERED"
[ "${PROTECTED_RECOVERY_ENABLED_RENDER_ONLY:-0}" != 1 ] || exit 0

# Only the rendered enabled-path file runs here: the module's own mocked suite
# asserts the committed, unrecorded state and is run against the checkout.
terraform -chdir="$copy/$module" init -backend=false -input=false -lockfile=readonly
terraform -chdir="$copy/$module" test -test-directory=enabled -filter=enabled/enabled.tftest.hcl -no-color
