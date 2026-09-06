#!/bin/bash
# Shape one request to the protected-recovery broker for one consumer and one
# effect direction, and print the reply. The purpose is the authenticated
# invoker identity, never an input: this script may only choose between the
# operations the broker exposes for that identity and forward its literal
# consumer and direction. No evidence of any kind travels in a body; probes
# are recorded by the broker from its own source. The ID token reaches curl
# through a private config file, never through argv. The reply is printed
# and, when REPLY_PATH is set, written there for the run's reply artifact.
#
# Operations: append, close, reconcile, and status act on the shard named by
# SHARD; round-open opens a delivery round of the quarantine direction --
# ARGUMENT is <phase>/<label>, SHARD the OPEN quarantine shard a REVOCATION or
# HORIZON round probes, or "-" for a CONTROL round -- and round-status reads
# the round named by ARGUMENT.
set -euo pipefail

consumer="$1"
direction="$2"
: "${BROKER_URL:?}" "${ID_TOKEN:?}" "${IDEMPOTENCY_KEY:?}" "${OPERATION:?}" "${SHARD:?}"
: "${REQUEST_NONCE:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}"
[[ "$REQUEST_NONCE" =~ ^[0-9a-f]{64}$ ]]
[[ "$GITHUB_RUN_ID" =~ ^[1-9][0-9]*$ ]]
[[ "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]]
[[ "$SHARD" =~ ^(-|[a-z0-9][a-z0-9-]{0,62})$ ]]
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
    [ "$SHARD" != "-" ]
    path="/v1/shards/$SHARD/entries"
    if [ "$intent" = RESTORE ]; then
      jq -n --arg key "$IDEMPOTENCY_KEY" --arg consumer "$consumer" --arg source "${ARGUMENT:?}" '{key: $key, consumer: $consumer, intent: "RESTORE", source: $source}' > "$body"
    else
      jq -n --arg key "$IDEMPOTENCY_KEY" --arg consumer "$consumer" '{key: $key, consumer: $consumer, intent: "QUARANTINE"}' > "$body"
    fi
    ;;
  close)
    [ "$SHARD" != "-" ]
    path="/v1/shards/$SHARD/close"
    jq -n --arg key "$IDEMPOTENCY_KEY" '{key: $key}' > "$body"
    ;;
  reconcile)
    [ "$SHARD" != "-" ]
    path="/v1/shards/$SHARD/reconcile"
    echo '{}' > "$body"
    ;;
  status)
    [ "$SHARD" != "-" ]
    method=GET
    path="/v1/shards/$SHARD"
    body=""
    ;;
  round-open)
    [ "$intent" = QUARANTINE ]
    [[ "${ARGUMENT:?}" =~ ^(CONTROL|REVOCATION|HORIZON)/[a-z0-9][a-z0-9-]{0,40}$ ]]
    phase="${ARGUMENT%%/*}"
    label="${ARGUMENT#*/}"
    if [ "$phase" = CONTROL ]; then [ "$SHARD" = "-" ]; else [ "$SHARD" != "-" ]; fi
    path="/v1/rounds"
    jq -n --arg key "$IDEMPOTENCY_KEY" --arg consumer "$consumer" --arg label "$label" --arg phase "$phase" --arg shard "$SHARD" \
      '{key: $key, consumer: $consumer, label: $label, phase: $phase, shard: (if $shard == "-" then null else $shard end)}' > "$body"
    ;;
  round-bind)
    [ "$intent" = QUARANTINE ]
    printf '%s' "${ARGUMENT:?}" > "$workdir/binding.json"
    round="$(jq -er '.round | select(test("^[0-9a-f]{64}$"))' "$workdir/binding.json")"
    path="/v1/rounds/$round/runs"
    jq -e '{runs: .runs}' "$workdir/binding.json" > "$body"
    ;;
  round-status)
    [[ "${ARGUMENT:?}" =~ ^[0-9a-f]{64}$ ]]
    method=GET
    path="/v1/rounds/$ARGUMENT"
    body=""
    ;;
  *)
    echo "Unknown operation $OPERATION." >&2
    exit 1
    ;;
esac

reply="$workdir/reply.json"
status=0
curl --fail-with-body --silent --show-error \
  --config "$workdir/auth.cfg" \
  --request "$method" \
  --header 'Content-Type: application/json' \
  ${body:+--data-binary "@$body"} \
  --output "$reply" \
  "$BROKER_URL$path" || status=$?
if [ -f "$reply" ]; then
  cat "$reply"
  echo
  if [ -n "${REPLY_PATH:-}" ]; then
    jq -n --arg nonce "$REQUEST_NONCE" --arg runId "$GITHUB_RUN_ID" --arg runAttempt "$GITHUB_RUN_ATTEMPT" \
      --arg consumer "$consumer" --arg direction "$direction" --arg operation "$OPERATION" \
      --arg shard "$SHARD" --arg argument "${ARGUMENT:-}" --slurpfile reply "$reply" \
      '{nonce: $nonce, runId: $runId, runAttempt: $runAttempt, request: {consumer: $consumer, direction: $direction, operation: $operation, shard: $shard, argument: $argument}, reply: $reply[0]}' > "$workdir/envelope.json"
    install -m 0600 "$workdir/envelope.json" "$REPLY_PATH"
  fi
fi
exit "$status"
