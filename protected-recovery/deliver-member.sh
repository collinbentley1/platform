#!/bin/bash
# Deliver this job's own federated credential to the protected-recovery
# broker. Run inside the one canonical GitHub-hosted job that is a managed
# member -- a consumer-domain id-token job of a platform reusable workflow --
# before that job exchanges for anything, with the platform's authority file
# at PLATFORM_AUTHORITY. The job mints two GitHub OIDC tokens: the member
# credential, for the consumer pool's provider audience (the token the broker
# verifies and exchanges at once to mint as this exact member against every
# target it is bound to, recording the positive control before a quarantine
# and the revocation or post-horizon probe during one), and a delivery
# credential for the broker pool's member provider, exchanged at STS and IAM
# Credentials for an ID token of the consumer's member-delivery identity,
# which holds run.invoker on the broker and nothing else. The member
# credential travels only in the request body to POST /v1/members; the broker
# discards it with the request and stores only the outcomes. Neither token is
# ever printed. With no broker project recorded, nothing is delivered and the
# job carries on.
#
# The delivery must not decide the job's own outcome: a broker that cannot be
# reached, or that refuses the credential, is reported and the job continues,
# because the ledger -- not this step -- is the record of what was delivered,
# and a quarantine's readiness names every delivery still owed. The step is
# therefore the first thing after the rerun guard, before any upstream
# result is required, so the exact tuple delivers on every run of the job
# whether or not the run can deploy.
set -uo pipefail

: "${PLATFORM_AUTHORITY:?}" "${GITHUB_REPOSITORY_ID:?}" "${ACTIONS_ID_TOKEN_REQUEST_URL:?}" "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?}"
authority="$PLATFORM_AUTHORITY"
test -f "$authority" && test ! -L "$authority" || { echo "protected-recovery: the authority file is not a regular file; nothing delivered." >&2; exit 0; }

broker_project="$(jq -r '.broker.projectId // empty' "$authority")"
if [ -z "$broker_project" ]; then
  echo "protected-recovery: authority.json records no broker project; no member credential is delivered."
  exit 0
fi
broker_number="$(jq -er '.broker.projectNumber' "$authority")"
pool="$(jq -er '.broker.workloadIdentityPoolId' "$authority")"
consumer_provider_id="$(jq -er '.broker.workloadIdentityProviderId' "$authority")"
member_provider_id="$(jq -er '.broker.memberWorkloadIdentityProviderId' "$authority")"
broker_url="$(jq -er --arg number "$broker_number" '"https://\(.broker.serviceName)-\($number).\(.broker.region).run.app"' "$authority")"
consumer="$(jq -er --arg id "$GITHUB_REPOSITORY_ID" '.consumers[] | select(.repositoryId == $id) | .repository' "$authority")" || { echo "protected-recovery: repository ${GITHUB_REPOSITORY_ID} is not a declared consumer; nothing delivered." >&2; exit 0; }
consumer_number="$(jq -er --arg id "$GITHUB_REPOSITORY_ID" '.consumers[] | select(.repositoryId == $id) | .projectNumber' "$authority")"
[[ "$consumer" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || exit 0
[[ "$broker_number" =~ ^[1-9][0-9]*$ ]] && [[ "$consumer_number" =~ ^[1-9][0-9]*$ ]] || exit 0

member_provider="projects/${broker_number}/locations/global/workloadIdentityPools/${pool}/providers/${member_provider_id}"
consumer_provider="projects/${consumer_number}/locations/global/workloadIdentityPools/${pool}/providers/${consumer_provider_id}"
delivery_account="gha-member-${consumer}@${broker_project}.iam.gserviceaccount.com"

workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT
umask 077
printf 'header = "Authorization: bearer %s"\n' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" > "$workdir/github.cfg"

fail_soft() {
  echo "protected-recovery: $1; the delivery is recorded by the broker's ledger alone, and a quarantine's readiness names every delivery still owed." >&2
  exit 0
}

# The two GitHub OIDC tokens, each for exactly one audience.
github_token() {
  curl --fail --silent --show-error --max-time 30 --config "$workdir/github.cfg" \
    "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=$(jq -rn --arg audience "$1" '$audience | @uri')" |
    jq -er '.value'
}
github_token "https://iam.googleapis.com/${consumer_provider}" > "$workdir/member.jwt" || fail_soft "the member credential could not be minted"
github_token "https://iam.googleapis.com/${member_provider}" > "$workdir/delivery.jwt" || fail_soft "the delivery credential could not be minted"

# The delivery credential: STS exchange into the broker pool, then an ID token
# of the member-delivery identity for the broker audience.
jq -n --arg audience "//iam.googleapis.com/${member_provider}" --rawfile token "$workdir/delivery.jwt" '{
  audience: $audience,
  grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
  requestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
  scope: "https://www.googleapis.com/auth/cloud-platform",
  subjectToken: ($token | rtrimstr("\n")),
  subjectTokenType: "urn:ietf:params:oauth:token-type:jwt"
}' > "$workdir/sts.json"
curl --fail --silent --show-error --max-time 30 --request POST --header 'Content-Type: application/json' \
  --data-binary "@$workdir/sts.json" https://sts.googleapis.com/v1/token | jq -er '.access_token' > "$workdir/federated.token" || fail_soft "STS refused the delivery credential"
printf 'header = "Authorization: Bearer %s"\n' "$(cat "$workdir/federated.token")" > "$workdir/federated.cfg"
jq -n --arg audience "$broker_url" '{audience: $audience, includeEmail: true}' > "$workdir/idtoken.json"
curl --fail --silent --show-error --max-time 30 --config "$workdir/federated.cfg" --request POST --header 'Content-Type: application/json' \
  --data-binary "@$workdir/idtoken.json" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${delivery_account}:generateIdToken" | jq -er '.token' > "$workdir/delivery.token" || fail_soft "the member-delivery identity could not be reached"

# The delivery itself: the member credential in the body, the delivery
# credential in the header, the broker's verified answer on stdout -- the
# outcomes it recorded, never the credential.
printf 'header = "Authorization: Bearer %s"\n' "$(cat "$workdir/delivery.token")" > "$workdir/broker.cfg"
jq -n --rawfile token "$workdir/member.jwt" '{token: ($token | rtrimstr("\n"))}' > "$workdir/body.json"
status="$(curl --silent --show-error --max-time 100 --config "$workdir/broker.cfg" --request POST \
  --header 'Content-Type: application/json' --data-binary "@$workdir/body.json" --output "$workdir/answer.json" --write-out '%{http_code}' "$broker_url/v1/members" || echo 000)"
if [ "$status" = 200 ]; then
  echo "protected-recovery: delivered; $(jq -c '{member, controls, probes: (.probes | length), rounds, unavailable}' "$workdir/answer.json" 2> /dev/null || cat "$workdir/answer.json")"
  exit 0
fi
fail_soft "the broker answered HTTP ${status}: $(tr -d '\n' < "$workdir/answer.json" | cut -c1-300)"
