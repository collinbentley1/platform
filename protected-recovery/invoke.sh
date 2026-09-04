#!/bin/bash
# Shape one request to the protected-recovery broker for one consumer and one
# effect direction, and print the reply. The purpose is the authenticated
# invoker identity, never an input: this script may only choose between the
# operations the broker exposes for that identity and forward its literal
# consumer and direction. No evidence of any kind travels in a body; probes
# are recorded by the broker from its own source. The ID token reaches curl
# through a private config file, never through argv.
set -euo pipefail

consumer="$1"
direction="$2"
: "${BROKER_URL:?}" "${ID_TOKEN:?}" "${IDEMPOTENCY_KEY:?}" "${OPERATION:?}" "${SHARD:?}"
[[ "$SHARD" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]]
case "$direction" in
  quarantine) intent=QUARANTINE ;;
  restore) intent=RESTORE ;;
  *)
    echo "Unknown direction $direction." >&2
    exit 1
    ;;
esac

workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT
umask 077
printf 'header = "Authorization: Bearer %s"\n' "$ID_TOKEN" > "$workdir/auth.cfg"

method=POST
body="$workdir/body.json"
case "$OPERATION" in
  append)
    path="/v1/shards/$SHARD/entries"
    if [ "$intent" = RESTORE ]; then
      jq -n --arg key "$IDEMPOTENCY_KEY" --arg consumer "$consumer" --arg source "${ARGUMENT:?}" '{key: $key, consumer: $consumer, intent: "RESTORE", source: $source}' > "$body"
    else
      jq -n --arg key "$IDEMPOTENCY_KEY" --arg consumer "$consumer" '{key: $key, consumer: $consumer, intent: "QUARANTINE"}' > "$body"
    fi
    ;;
  close)
    path="/v1/shards/$SHARD/close"
    jq -n --arg key "$IDEMPOTENCY_KEY" '{key: $key}' > "$body"
    ;;
  reconcile)
    path="/v1/shards/$SHARD/reconcile"
    echo '{}' > "$body"
    ;;
  status)
    method=GET
    path="/v1/shards/$SHARD"
    body=""
    ;;
  *)
    echo "Unknown operation $OPERATION." >&2
    exit 1
    ;;
esac

curl --fail-with-body --silent --show-error \
  --config "$workdir/auth.cfg" \
  --request "$method" \
  --header 'Content-Type: application/json' \
  ${body:+--data-binary "@$body"} \
  "$BROKER_URL$path"
echo
