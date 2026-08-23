#!/bin/bash
set -euo pipefail

# Read-only admission check for the four standalone preview projects. The caller
# needs cloudasset.assets.analyzeIamPolicy and serviceusage.services.use on every
# project, plus resourcemanager.projects.get/getIamPolicy for standalone-parent
# and exact direct-policy brackets.
# cloudasset.googleapis.com and cloudresourcemanager.googleapis.com must already
# be enabled. WIF should authenticate a dedicated CI verifier with only those
# read permissions; this helper never grants, revokes, or otherwise mutates IAM.
#
# Cloud Asset analysis is best effort rather than a linearizable IAM snapshot.
# The project-policy etag brackets reject concurrent project-level changes, but
# cannot bracket child-resource policies. Run immediately before traffic commit,
# keep the service sealed on any failure, and treat success as a conservative
# admission signal—not a cryptographic proof against a concurrent IAM writer.

if [ "${1:-}" != verify ] || [ "$#" -ne 1 ]; then
  echo "usage: preview-runtime-iam-contract.sh verify" >&2
  exit 64
fi

command -v curl >/dev/null
command -v jq >/dev/null
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

projects=(cdbentley runsetta medlock-1025243085 critical-history-16823277)
umask 077
token_file="$RUNNER_TEMP/preview-runtime-iam-token"
header_file="$RUNNER_TEMP/preview-runtime-iam-header"
snapshot_before="$RUNNER_TEMP/preview-runtime-iam-before.jsonl"
snapshot_after="$RUNNER_TEMP/preview-runtime-iam-after.jsonl"
projects_before="$RUNNER_TEMP/preview-runtime-projects-before.jsonl"
projects_after="$RUNNER_TEMP/preview-runtime-projects-after.jsonl"

cleanup() {
  rm -f -- "$token_file" "$header_file" "$snapshot_before" "$snapshot_after" "$projects_before" "$projects_after"
  find "$RUNNER_TEMP" -mindepth 1 -maxdepth 1 -type f -name 'preview-runtime-iam-analysis-*.json' -delete
}
trap cleanup EXIT

if [ -n "${ACCESS_TOKEN:-}" ]; then
  printf '%s' "$ACCESS_TOKEN" > "$token_file"
else
  command -v gcloud >/dev/null
  gcloud auth print-access-token > "$token_file"
fi
test -s "$token_file"
printf 'Authorization: Bearer %s\n' "$(<"$token_file")" > "$header_file"

snapshot_projects() {
  local destination="$1" project response
  : > "$destination"
  for project in "${projects[@]}"; do
    response="$RUNNER_TEMP/preview-runtime-iam-analysis-project-${project}.json"
    curl --fail-with-body --silent --show-error --proto '=https' --tlsv1.2 \
      --header "@$header_file" --output "$response" \
      "https://cloudresourcemanager.googleapis.com/v1/projects/${project}"
    jq -ec --arg project "$project" '
      select(
        .projectId == $project and
        (.projectNumber | type == "string" and test("^[1-9][0-9]*$")) and
        .lifecycleState == "ACTIVE" and
        ((.parent // null) == null)
      ) |
      {projectId,projectNumber,lifecycleState,parent:(.parent // null)}
    ' "$response" >> "$destination"
  done
  test "$(wc -l < "$destination" | tr -d ' ')" -eq 4
}

snapshot_project_policies() {
  local destination="$1" project response
  : > "$destination"
  for project in "${projects[@]}"; do
    response="$RUNNER_TEMP/preview-runtime-iam-analysis-policy-${project}.json"
    curl --fail-with-body --silent --show-error --proto '=https' --tlsv1.2 \
      --request POST --header "@$header_file" --header 'Content-Type: application/json' \
      --data '{"options":{"requestedPolicyVersion":3}}' --output "$response" \
      "https://cloudresourcemanager.googleapis.com/v1/projects/${project}:getIamPolicy"
    jq -ec --arg project "$project" '
      def forbidden_member:
        . == "allUsers" or . == "allAuthenticatedUsers" or
        test("^(deleted:)?(group|domain):") or
        test("^project(Owner|Editor|Viewer):") or
        test("^principalSet://cloudresourcemanager\\.googleapis\\.com/(projects|folders|organizations)/[^/]+/type/ServiceAccount$") or
        test("^(deleted:)?serviceAccount:cloud-run-preview@(cdbentley|runsetta|medlock-1025243085|critical-history-16823277)\\.iam\\.gserviceaccount\\.com$");
      select(
        (.etag | type == "string" and length > 0) and
        ((.version // 1) == 1 or (.version // 1) == 3) and
        ((.bindings // []) | type == "array") and
        all((.bindings // [])[];
          (.role | (type == "string" and test("^(roles/|projects/[^/]+/roles/)"))) and
          (.members | type == "array") and
          all(.members[]; (type == "string") and (forbidden_member | not)))
      ) |
      {
        project:$project,
        etag,
        version:(.version // 1),
        bindings:[(.bindings // [])[] | .members |= sort] | sort_by(.role, (.condition.expression // "")),
        auditConfigs:((.auditConfigs // []) | sort_by(.service))
      }
    ' "$response" >> "$destination"
  done
  test "$(wc -l < "$destination" | tr -d ' ')" -eq 4
}

analyze_identity_in_scope() {
  local identity_project="$1" scope_project="$2" identity response
  identity="serviceAccount:cloud-run-preview@${identity_project}.iam.gserviceaccount.com"
  response="$RUNNER_TEMP/preview-runtime-iam-analysis-${identity_project}-${scope_project}.json"
  curl --fail-with-body --silent --show-error --proto '=https' --tlsv1.2 \
    --get --header "@$header_file" --output "$response" \
    --data-urlencode "analysisQuery.identitySelector.identity=${identity}" \
    --data-urlencode 'analysisQuery.options.expandRoles=true' \
    --data-urlencode 'analysisQuery.options.expandResources=true' \
    --data-urlencode 'analysisQuery.options.outputGroupEdges=true' \
    --data-urlencode 'analysisQuery.options.analyzeServiceAccountImpersonation=true' \
    --data-urlencode 'executionTimeout=120s' \
    "https://cloudasset.googleapis.com/v1/projects/${scope_project}:analyzeIamPolicy"

  # Absence is accepted only when the envelope and every analysis are complete,
  # warning-free, and empty. Any direct/inherited/conditional/group binding is a
  # result. Any permission to impersonate another service account is also a
  # result; the explicit impersonation analyses must themselves remain empty.
  jq -e --arg identity "$identity" --arg scope "projects/${scope_project}" '
    .fullyExplored == true and
    .mainAnalysis.fullyExplored == true and
    ((.mainAnalysis.nonCriticalErrors // []) | length == 0) and
    ((.mainAnalysis.analysisResults // []) | length == 0) and
    (.mainAnalysis.analysisQuery.scope == $scope) and
    (.mainAnalysis.analysisQuery.identitySelector.identity == $identity) and
    all((.serviceAccountImpersonationAnalysis // [])[];
      .fullyExplored == true and
      ((.nonCriticalErrors // []) | length == 0) and
      ((.analysisResults // []) | length == 0))
  ' "$response" >/dev/null
}

snapshot_projects "$projects_before"
snapshot_project_policies "$snapshot_before"
for identity_project in "${projects[@]}"; do
  for scope_project in "${projects[@]}"; do
    analyze_identity_in_scope "$identity_project" "$scope_project"
  done
done
snapshot_project_policies "$snapshot_after"
snapshot_projects "$projects_after"
cmp "$snapshot_before" "$snapshot_after" >/dev/null
cmp "$projects_before" "$projects_after" >/dev/null

echo "preview_runtime_iam_admitted=true"
echo "preview_runtime_iam_analyses=16"
