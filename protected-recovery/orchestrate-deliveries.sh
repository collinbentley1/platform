#!/bin/bash
# Drive one delivery round for one consumer to completion: open the round
# manifest at the broker, make every canonical job that is a managed member
# of that consumer run once so each delivers its own credential into it
# (protected-recovery/deliver-member.sh, wired as the first step after the
# guards of every one of the eleven member jobs of the platform reusable
# workflows), and wait until the broker holds a receipt from every member.
#
#   protected-recovery/orchestrate-deliveries.sh <owner/consumer> <phase> <shard|-> <label>
#
# The phase is CONTROL (before a quarantine, with the bindings standing;
# shard "-"), REVOCATION (after the quarantine is acknowledged; the OPEN
# quarantine shard), or HORIZON (after its token horizon; the same shard).
# The round is opened through the invoke workflow's round-open operation by
# the consumer's quarantine invoker, at exactly these coordinates, so a
# rerun of this script with the same arguments replays the same round rather
# than opening another; the broker binds it at opening to every exact member,
# the platform commits the consumer records, every target's identity, policy
# etag, and inventory hash, and the live Deny state, and admits a receipt
# only from a bound member running a bound platform commit against the bound
# identities. A quarantine is accepted, prepared, or resumed only against one
# complete CONTROL round whose binding still holds.
#
# The fourteen tuples of a consumer and the events that produce them:
#
#   push (empty commit on main)     deploy-prod: canary, publish, deploy;
#                                   infrastructure: terraform-convergence;
#                                   reconcile-previews: reconcile
#   pull_request_target (opened)    deploy-preview: canary, publish-canary,
#                                   publish, deploy, invalidate
#   pull_request_target (synchronize)  cleanup-preview: cleanup, through
#                                   deploy-preview's caller job
#   pull_request_target (closed)    cleanup-preview: cleanup, through its own
#                                   caller
#   workflow_dispatch               reconcile-previews: reconcile
#   schedule (17 past every hour)   reconcile-previews: reconcile; it cannot
#                                   be dispatched, so a round is complete only
#                                   once the hour's run has delivered
#
# Every member job delivers before any upstream result is required and before
# any exchange: the jobs that were gated on their upstream jobs run always()
# and re-establish the gate as a step after the delivery. During a quarantine
# every exchange fails, so every job fails after its delivery, at its exchange
# or at its upstream gate: that is the expected shape of a round, and the
# deliveries are the only thing the round exists for. A rerun of an old run
# is not a delivery: the rerun guard is the first step of every job, before
# the delivery, so only fresh events count.
#
# Before anything is triggered, every platform reusable-workflow pin of the
# consumer's caller workflows on main is checked against the platform commits
# the authority file records for it: a consumer pinned elsewhere delivers
# receipts the round refuses, so it is repinned first, not rounded.
#
# This runs on the owner's machine with the owner's own gh authentication;
# nothing is stored, and no credential of the consumer is handled here. The
# empty commit and the throwaway pull request are the round's footprint in
# the consumer repository; the pull request and its branch are removed on
# every exit. The script exits 0 only when the broker reports the round
# complete, and prints what it still owes otherwise.
set -euo pipefail

repository="${1:?owner/consumer repository}"
phase="${2:?CONTROL, REVOCATION, or HORIZON}"
shard="${3:?the OPEN quarantine shard, or - for a CONTROL round}"
label="${4:?round label, e.g. q1-revocation}"
[[ "$repository" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$ ]]
[[ "$phase" =~ ^(CONTROL|REVOCATION|HORIZON)$ ]]
[[ "$shard" =~ ^(-|[a-z0-9][a-z0-9-]{0,62})$ ]]
[[ "$label" =~ ^[a-z0-9][a-z0-9-]{0,40}$ ]]
if [ "$phase" = CONTROL ]; then [ "$shard" = "-" ]; else [ "$shard" != "-" ]; fi
consumer="${repository#*/}"
platform="collinbentley1/platform"
authority="$(dirname "$0")/authority.json"
test -f "$authority"
gh auth status > /dev/null

workdir="$(mktemp -d)"
number=""
branch="protected-recovery/delivery-${label}"
cleanup() {
  if [ -n "$number" ]; then
    gh pr close --repo "$repository" "$number" --delete-branch > /dev/null 2>&1 || true
  fi
  git ls-remote --exit-code --heads "https://github.com/${repository}.git" "$branch" > /dev/null 2>&1 &&
    git -C "$workdir/repo" push --quiet --delete origin "$branch" > /dev/null 2>&1 || true
  rm -rf -- "$workdir"
}
trap cleanup EXIT
export GIT_CONFIG_NOSYSTEM=1

# 1. The consumer's pins must be the platform commits the round binds.
mapfile -t pins < <(jq -r --arg consumer "$consumer" '.consumers[] | select(.repository == $consumer) | [.activeWorkflowSha, .transitionWorkflowSha] | map(select(type == "string")) | .[]' "$authority")
[ "${#pins[@]}" -gt 0 ] || { echo "authority.json records no workflow pin for ${consumer}; nothing to round" >&2; exit 1; }
for file in deploy-prod.yml deploy-preview.yml cleanup-preview.yml reconcile-previews.yml; do
  content="$(gh api "repos/${repository}/contents/.github/workflows/${file}?ref=main" --jq '.content' 2> /dev/null | base64 --decode)" || continue
  while IFS= read -r used; do
    sha="${used##*@}"
    found=0
    for pin in "${pins[@]}"; do [ "$sha" = "$pin" ] && found=1; done
    if [ "$found" = 0 ]; then
      echo "${repository} .github/workflows/${file} calls ${used}, which is not a platform commit authority.json records for ${consumer} (${pins[*]}); repin the consumer before a round" >&2
      exit 1
    fi
  done < <(grep -oE "collinbentley1/platform/\.github/workflows/[A-Za-z0-9._-]+\.yml@[0-9a-f]{40}" <<< "$content" || true)
done
echo "${repository} main calls the platform at ${pins[*]}"

# One request to the broker through the invoke workflow: dispatched, watched,
# and answered through the run's broker-reply artifact.
invoke() {
  local operation="$1" shard_input="$2" argument="$3" before run_id=""
  before="$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"
  gh workflow run --repo "$platform" protected-recovery-invoke.yml --ref main \
    -f "target_repository=${consumer}" -f direction=quarantine -f "operation=${operation}" -f "shard=${shard_input}" -f "argument=${argument}"
  for _ in $(seq 1 60); do
    run_id="$(gh run list --repo "$platform" --workflow protected-recovery-invoke.yml --event workflow_dispatch --created ">=${before}" --json databaseId --jq 'map(.databaseId) | max // empty')"
    [ -n "$run_id" ] && break
    sleep 5
  done
  [ -n "$run_id" ] || { echo "the ${operation} dispatch started no run of the invoke workflow" >&2; return 1; }
  gh run watch --repo "$platform" "$run_id" > /dev/null || true
  rm -rf -- "$workdir/reply"
  gh run download --repo "$platform" "$run_id" --name broker-reply --dir "$workdir/reply" > /dev/null 2>&1 || true
  if [ ! -f "$workdir/reply/broker-reply.json" ]; then
    echo "invoke run ${run_id} (${operation}) recorded no broker reply; see https://github.com/${platform}/actions/runs/${run_id}" >&2
    return 1
  fi
  cat "$workdir/reply/broker-reply.json"
}

# 2. Open the round at its coordinates, or replay it.
opened="$(invoke round-open "$shard" "${phase}/${label}")" || { echo "the round could not be opened" >&2; exit 1; }
round="$(jq -er '.round.round | select(test("^[0-9a-f]{64}$"))' <<< "$opened")" || { echo "the broker refused the round: $(jq -c . <<< "$opened" 2> /dev/null || printf '%s' "$opened")" >&2; exit 1; }
jq -e --arg consumer "$consumer" --arg phase "$phase" --arg label "$label" '.round | .consumer == $consumer and .phase == $phase and .label == $label' <<< "$opened" > /dev/null
echo "round ${round}: ${phase} ${label} of ${consumer}, opened at $(jq -r '.round.openedAt' <<< "$opened"), $(jq -r '.round.owed | length' <<< "$opened") deliveries owed, platform $(jq -r '.round.platformShas | join(" ")' <<< "$opened")"
if jq -e '.round.complete' <<< "$opened" > /dev/null; then
  echo "round ${round} is already complete"
  exit 0
fi

git clone --quiet --depth=1 --branch main "https://github.com/${repository}.git" "$workdir/repo"
cd "$workdir/repo"
git config user.name "protected-recovery"
git config user.email "protected-recovery@users.noreply.github.com"
started="$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"

# 3. The push tuples: an empty commit on main.
git commit --quiet --allow-empty -m "protected-recovery: ${phase} round ${label} (push)"
git push --quiet origin HEAD:main
push_sha="$(git rev-parse HEAD)"
echo "pushed ${push_sha} to ${repository} main: deploy-prod, infrastructure, and reconcile-previews (push) deliver"

# 4. The pull_request_target tuples: open a throwaway pull request, push to it, close it.
git checkout --quiet -b "$branch"
git commit --quiet --allow-empty -m "protected-recovery: ${phase} round ${label} (pull request)"
git push --quiet origin "$branch"
number="$(gh pr create --repo "$repository" --base main --head "$branch" --title "protected-recovery ${phase} round ${label}" --body "Throwaway pull request that makes every preview job deliver its credential to the protected-recovery broker for round ${round}. It is closed by the same round." | grep -oE '[0-9]+$')"
echo "opened ${repository}#${number}: deploy-preview (canary, publish-canary, publish, deploy, invalidate) delivers"
git commit --quiet --allow-empty -m "protected-recovery: ${phase} round ${label} (synchronize)"
git push --quiet origin "$branch"
echo "pushed to ${repository}#${number}: the cleanup job through deploy-preview's caller delivers"
sleep 30
gh pr close --repo "$repository" "$number" --delete-branch > /dev/null
echo "closed ${repository}#${number}: cleanup-preview delivers"
number=""

# 5. The workflow_dispatch tuple.
gh workflow run --repo "$repository" reconcile-previews.yml --ref main
echo "dispatched reconcile-previews in ${repository}: reconcile-previews (workflow_dispatch) delivers"

# 6. Wait for every triggered run to finish, and for the hour's scheduled run.
wait_runs() {
  local description="$1"; shift
  local ids=""
  for _ in $(seq 1 24); do
    ids="$(gh run list --repo "$repository" "$@" --json databaseId --jq 'map(.databaseId) | .[]')"
    [ -n "$ids" ] && break
    sleep 5
  done
  if [ -z "$ids" ]; then
    echo "no run appeared for ${description}" >&2
    return 1
  fi
  local id
  for id in $ids; do
    echo "waiting for ${description}: https://github.com/${repository}/actions/runs/${id}"
    gh run watch --repo "$repository" "$id" > /dev/null || true
  done
}
wait_runs "the push tuples" --commit "$push_sha" --created ">=${started}"
wait_runs "the pull request tuples" --branch "$branch" --created ">=${started}"
wait_runs "the workflow_dispatch tuple" --workflow reconcile-previews.yml --event workflow_dispatch --created ">=${started}"
echo "the schedule tuple delivers on its own at 17 past the hour"

# 7. The round is complete when the broker holds a receipt from every member.
deadline=$(( $(date +%s) + 100 * 60 ))
while :; do
  status="$(invoke round-status - "$round")" || { echo "the round could not be read" >&2; exit 1; }
  if jq -e '.round.complete' <<< "$status" > /dev/null; then
    echo "round ${round} is complete: $(jq -r '.round.receipts | to_entries | map("\(.key | sub("^.*attribute.authority/"; "")) run \(.value.runId) attempt \(.value.runAttempt)") | join("; ")' <<< "$status")"
    exit 0
  fi
  echo "round ${round} still owes: $(jq -r '.round.owed | map("\(.account)/\(.member | sub("^.*attribute.authority/"; "")): \(.reason)") | join("; ")' <<< "$status")"
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "round ${round} did not complete within its deadline" >&2
    exit 1
  fi
  schedule="$(gh run list --repo "$repository" --workflow reconcile-previews.yml --event schedule --created ">=${started}" --json databaseId --jq 'map(.databaseId) | max // empty')"
  if [ -n "$schedule" ]; then gh run watch --repo "$repository" "$schedule" > /dev/null || true; fi
  sleep 120
done
