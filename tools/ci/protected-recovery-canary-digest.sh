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
  local method="$1" url="$2" content_type="$3" body_sha256="$4" resource="$5" expected="$6" detail="$7"
  jq -cn --arg method "$method" --arg url "$url" --arg content_type "$content_type" --arg body "$body_sha256" --arg resource "$resource" --arg expected "$expected" --arg detail "$detail" \
    '{method: $method, url: $url, contentType: $content_type, bodySha256: $body, preState: {resource: $resource, expected: $expected, detail: $detail}}' |
    jq -cS . | tr -d '\n' | openssl dgst -sha256 -r | cut -d' ' -f1
}
