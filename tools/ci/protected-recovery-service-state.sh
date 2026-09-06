#!/bin/bash
# Read whether one Google API is enabled in one project for the
# protected-recovery Terraform module (data "external" "service_state").
# A consumer attachment row whose API is not enabled in the consumer project
# cannot be exercised by the Deny canary -- the identical request answers
# SERVICE_DISABLED in both phases -- and the module accepts such a row only
# beside this live read proving the API disabled at plan and at apply. The
# credential is obtained here, from the application default credentials the
# Google provider itself applies with, and used only in this process; the
# module's state records the typed answer and never a bearer
# (tools/ci/protected-recovery-state-scan-test.sh proves it with a sentinel).
#
# The query names the project and the service; the answer is the read's
# status and the service's state (ENABLED or DISABLED). A read that fails
# answers with its status and an empty state, so the module reports an
# unread state rather than a provider error. The Service Usage endpoint and
# the credential command are overridable for the offline test only.
set -uo pipefail

query="$(cat)"
project="$(jq -er '.project' <<< "$query")" || { jq -cn '{status: "400", state: "", reason: "the query names no project"}'; exit 0; }
service="$(jq -er '.service' <<< "$query")" || { jq -cn '{status: "400", state: "", reason: "the query names no service"}'; exit 0; }
[[ "$project" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || { jq -cn '{status: "400", state: "", reason: "the project is malformed"}'; exit 0; }
[[ "$service" =~ ^[a-z][a-z0-9]*\.googleapis\.com$ ]] || { jq -cn '{status: "400", state: "", reason: "the service is malformed"}'; exit 0; }

endpoint="${PROTECTED_RECOVERY_SERVICEUSAGE_ENDPOINT:-https://serviceusage.googleapis.com}"
workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT
umask 077
if ! token="$(gcloud auth application-default print-access-token 2> "$workdir/error")"; then
  jq -cn --rawfile reason "$workdir/error" '{status: "401", state: "", reason: ("no application default credential: " + ($reason | .[0:200]))}'
  exit 0
fi
printf 'header = "Authorization: Bearer %s"\n' "$token" > "$workdir/auth.cfg"
unset token

status="$(curl --silent --show-error --config "$workdir/auth.cfg" --request GET --output "$workdir/body" --write-out '%{http_code}' "${endpoint}/v1/projects/${project}/services/${service}" || echo 000)"
if [ "$status" != 200 ]; then
  jq -cn --arg status "$status" '{status: $status, state: "", reason: ("reading the service answered HTTP " + $status)}'
  exit 0
fi
state="$(jq -r '.state // ""' "$workdir/body")"
case "$state" in
  ENABLED|DISABLED) jq -cn --arg state "$state" '{status: "200", state: $state, reason: ""}' ;;
  *) jq -cn --arg state "$state" '{status: "502", state: "", reason: ("the service answered an unknown state " + $state)}' ;;
esac
