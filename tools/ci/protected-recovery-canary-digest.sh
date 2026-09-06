#!/bin/bash
# The canonical request digest of one Deny canary observation, in one place:
# sourced by the canary producer (tools/ci/protected-recovery-deny-canary.sh)
# and cross-checked against the fixture renderer's TypeScript derivation
# (tools/ci/protected-recovery-canary-fixture.ts) by the platform test suite,
# so the two never disagree about what "the same request" means. Functions
# only; no side effects.
#
# A JSON body is canonicalized as compact JSON with keys sorted recursively,
# with one normalization: a top-level policy.etag is removed. The etag is the
# compare-and-set token of an IAM allow-policy write, not part of what the
# request asks for, and a successful control-phase write moves it; every
# other byte of the body must be identical between the two phases. A body of
# any other content type is digested as its bytes; no body is the empty
# string. The observation digest is the sha256 of the canonical JSON of the
# method, the URL, the content type, the body digest, and the required
# pre-state (the resource the row's permission is judged on, the existence
# state the request requires of it, and its detail).

canary_body_sha256() {
  local file="$1" content_type="$2"
  if [ -z "$file" ]; then
    printf ''
    return 0
  fi
  if [[ "$content_type" == application/json* ]]; then
    jq -cS 'if type == "object" and (.policy | type) == "object" then del(.policy.etag) else . end' "$file" | tr -d '\n' | openssl dgst -sha256 -r | cut -d' ' -f1
  else
    openssl dgst -sha256 -r "$file" | cut -d' ' -f1
  fi
}

canary_digest() {
  local method="$1" url="$2" content_type="$3" body_sha256="$4" resource="$5" expected="$6" detail="$7" observed="${8:?actual observed pre-state}"
  jq -cn --arg method "$method" --arg url "$url" --arg content_type "$content_type" --arg body "$body_sha256" --arg resource "$resource" --arg expected "$expected" --arg detail "$detail" --arg observed "$observed" \
    '{method: $method, url: $url, contentType: $content_type, bodySha256: $body, preState: {resource: $resource, expected: $expected, observed: $observed, detail: $detail}}' |
    jq -cS . | tr -d '\n' | openssl dgst -sha256 -r | cut -d' ' -f1
}

# Only these four create APIs reserve deleted names. Normalize their one
# documented identifier field, and the matching pre-state resource name.
# Keep the raw request and digest in the observation as well.
canary_create_comparison() {
  local permission="$1" url="$2" body="$3" resource="$4" current="$5" canonical="$6" expected="$7" detail="$8" observed="$9"
  local comparison_url="$url" comparison_resource comparison_body field=""
  case "$permission" in
    iam.googleapis.com/serviceAccounts.create)
      field=accountId
      [[ "$resource" == */serviceAccounts/"$current"@*.iam.gserviceaccount.com ]] || return 1
      comparison_resource="${resource%/serviceAccounts/*}/serviceAccounts/${canonical}@${resource##*@}"
      ;;
    iam.googleapis.com/roles.create)
      field=roleId
      [[ "$resource" == organizations/*/roles/"$current" ]] || return 1
      comparison_resource="${resource%/*}/${canonical}"
      ;;
    iam.googleapis.com/workloadIdentityPools.create)
      [[ "$url" == *"?workloadIdentityPoolId=${current}" && "$resource" == */workloadIdentityPools/"$current" ]] || return 1
      comparison_url="${url%\?*}?workloadIdentityPoolId=${canonical}"
      comparison_resource="${resource%/*}/${canonical}"
      ;;
    iam.googleapis.com/workloadIdentityPoolProviders.create)
      [[ "$url" == *"?workloadIdentityPoolProviderId=${current}" && "$resource" == */providers/"$current" ]] || return 1
      comparison_url="${url%\?*}?workloadIdentityPoolProviderId=${canonical}"
      comparison_resource="${resource%/*}/${canonical}"
      ;;
    *) return 1 ;;
  esac
  comparison_body="$(jq -ceS --arg field "$field" --arg current "$current" --arg canonical "$canonical" '
    if $field == "" then . elif .[$field] == $current then .[$field] = $canonical else error("create identifier differs") end
  ' "$body" | tr -d '\n' | openssl dgst -sha256 -r | cut -d' ' -f1)" || return 1
  local digest
  digest="$(canary_digest POST "$comparison_url" application/json "$comparison_body" "$comparison_resource" "$expected" "$detail" "$observed")"
  jq -cn --arg url "$comparison_url" --arg body "$comparison_body" --arg resource "$comparison_resource" --arg digest "$digest" '{request: {method: "POST", url: $url, contentType: "application/json", bodySha256: $body}, resource: $resource, digest: $digest}'
}

# Match Terraform jsonencode's documented JSON escaping for the independently
# recomputed Allow snapshot hash, including expressions containing < or &.
canary_snapshot_sha256() {
  jq -cS . "$1" | jq -Rjr 'gsub("<"; "\\u003c") | gsub(">"; "\\u003e") | gsub("&"; "\\u0026") | gsub("\u2028"; "\\u2028") | gsub("\u2029"; "\\u2029")' | openssl dgst -sha256 -r | cut -d' ' -f1
}
