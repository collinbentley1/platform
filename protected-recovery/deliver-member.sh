#!/bin/bash
# Deliver this job's own federated credential to the protected-recovery
# broker. Run inside the one canonical GitHub-hosted job that is a managed
# member -- a consumer-domain id-token job of a platform reusable workflow --
# with the platform source checked out at PLATFORM_SOURCE. The job mints two
# GitHub OIDC tokens: the member credential, for the consumer pool's provider
# audience (the token the broker verifies and later exchanges to probe
# issuance as this exact member), and a delivery credential for the broker
# pool's member provider, exchanged at STS and IAM Credentials for an ID token
# of the consumer's member-delivery identity, which holds run.invoker on the
# broker and nothing else. The member credential travels only in the request
# body to POST /v1/members; the broker holds it until it expires. Neither
# token is ever printed. With no broker project recorded, nothing is
# delivered and the job carries on.
set -euo pipefail

: "${PLATFORM_SOURCE:?}" "${GITHUB_REPOSITORY_ID:?}" "${ACTIONS_ID_TOKEN_REQUEST_URL:?}" "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?}"
authority="$PLATFORM_SOURCE/protected-recovery/authority.json"
test -f "$authority" && test ! -L "$authority"

broker_project="$(jq -r '.broker.projectId // empty' "$authority")"
if [ -z "$broker_project" ]; then
  echo "protected-recovery/authority.json records no broker project; no member credential is delivered."
  exit 0
fi
broker_number="$(jq -er '.broker.projectNumber' "$authority")"
pool="$(jq -er '.broker.workloadIdentityPoolId' "$authority")"
consumer_provider_id="$(jq -er '.broker.workloadIdentityProviderId' "$authority")"
member_provider_id="$(jq -er '.broker.memberWorkloadIdentityProviderId' "$authority")"
broker_url="$(jq -er --arg number "$broker_number" '"https://\(.broker.serviceName)-\($number).\(.broker.region).run.app"' "$authority")"
consumer="$(jq -er --arg id "$GITHUB_REPOSITORY_ID" '.consumers[] | select(.repositoryId == $id) | .repository' "$authority")"
consumer_number="$(jq -er --arg id "$GITHUB_REPOSITORY_ID" '.consumers[] | select(.repositoryId == $id) | .projectNumber' "$authority")"
[[ "$consumer" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]
[[ "$broker_number" =~ ^[1-9][0-9]*$ ]] && [[ "$consumer_number" =~ ^[1-9][0-9]*$ ]]

member_provider="projects/${broker_number}/locations/global/workloadIdentityPools/${pool}/providers/${member_provider_id}"
consumer_provider="projects/${consumer_number}/locations/global/workloadIdentityPools/${pool}/providers/${consumer_provider_id}"
delivery_account="gha-member-${consumer}@${broker_project}.iam.gserviceaccount.com"

workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT
umask 077
printf 'header = "Authorization: bearer %s"\n' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" > "$workdir/github.cfg"

# The two GitHub OIDC tokens, each for exactly one audience.
github_token() {
  curl --fail --silent --show-error --config "$workdir/github.cfg" \
    "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=$(jq -rn --arg audience "$1" '$audience | @uri')" |
    jq -er '.value'
}
github_token "https://iam.googleapis.com/${consumer_provider}" > "$workdir/member.jwt"
github_token "https://iam.googleapis.com/${member_provider}" > "$workdir/delivery.jwt"

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
curl --fail --silent --show-error --request POST --header 'Content-Type: application/json' \
  --data-binary "@$workdir/sts.json" https://sts.googleapis.com/v1/token | jq -er '.access_token' > "$workdir/federated.token"
printf 'header = "Authorization: Bearer %s"\n' "$(cat "$workdir/federated.token")" > "$workdir/federated.cfg"
jq -n --arg audience "$broker_url" '{audience: $audience, includeEmail: true}' > "$workdir/idtoken.json"
curl --fail --silent --show-error --config "$workdir/federated.cfg" --request POST --header 'Content-Type: application/json' \
  --data-binary "@$workdir/idtoken.json" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${delivery_account}:generateIdToken" | jq -er '.token' > "$workdir/delivery.token"

# The delivery itself: the member credential in the body, the delivery
# credential in the header, the broker's verified answer on stdout.
printf 'header = "Authorization: Bearer %s"\n' "$(cat "$workdir/delivery.token")" > "$workdir/broker.cfg"
jq -n --rawfile token "$workdir/member.jwt" '{token: ($token | rtrimstr("\n"))}' > "$workdir/body.json"
curl --fail-with-body --silent --show-error --config "$workdir/broker.cfg" --request POST \
  --header 'Content-Type: application/json' --data-binary "@$workdir/body.json" "$broker_url/v1/members"
echo
