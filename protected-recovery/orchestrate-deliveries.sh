#!/bin/bash
# Drive one delivery round for one consumer: make every canonical job that is
# a managed member of that consumer run once, so each delivers its own
# credential to the broker (protected-recovery/deliver-member.sh, wired as the
# first step after the guards of every one of the eleven member jobs of the
# platform reusable workflows). A round is owed before a quarantine (the
# positive controls), after its acknowledgement (the revocation probes), and
# after its horizon (the post-horizon probes); the invoke workflow's status
# operation names every delivery a shard still awaits, member by member.
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
# and re-establish the gate as a step after the delivery, and the consumer's
# deploy-prod caller runs its deploy job always() while the reusable workflow
# requires the run's convergence job to have succeeded before any exchange.
# During a quarantine every exchange fails, so every job fails after its
# delivery, at its exchange or at its upstream gate: that is the expected
# shape of a round, and the deliveries are the only thing the round exists
# for. A rerun of an old run is not a delivery: the rerun guard is the first
# step of every job, before the delivery, so only fresh events count.
#
# This runs on the owner's machine with the owner's own gh authentication;
# nothing is stored, and no credential of the consumer is handled here. The
# empty commit and the throwaway pull request are the round's footprint in
# the consumer repository. Every consumer must call the platform reusable
# workflows at a commit that carries the delivery step: a consumer pinned to
# an older platform commit delivers nothing until it is repinned, and the
# broker's readiness names every delivery it still owes.
#
#   protected-recovery/orchestrate-deliveries.sh <owner/consumer> <round-label>
set -euo pipefail

repository="${1:?owner/consumer repository}"
label="${2:?round label, e.g. q1-revocation}"
[[ "$repository" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$ ]]
[[ "$label" =~ ^[a-z0-9][a-z0-9-]{0,40}$ ]]
gh auth status > /dev/null

workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT
export GIT_CONFIG_NOSYSTEM=1
git clone --quiet --depth=1 --branch main "https://github.com/${repository}.git" "$workdir/repo"
cd "$workdir/repo"
git config user.name "protected-recovery"
git config user.email "protected-recovery@users.noreply.github.com"

# 1. The push tuples: an empty commit on main.
git commit --quiet --allow-empty -m "protected-recovery: delivery round ${label} (push)"
git push --quiet origin HEAD:main
echo "pushed an empty commit to ${repository} main: deploy-prod, infrastructure, and reconcile-previews (push) deliver"

# 2. The pull_request_target tuples: open a throwaway pull request, push to it, close it.
branch="protected-recovery/delivery-${label}"
git checkout --quiet -b "$branch"
git commit --quiet --allow-empty -m "protected-recovery: delivery round ${label} (pull request)"
git push --quiet origin "$branch"
number="$(gh pr create --repo "$repository" --base main --head "$branch" --title "protected-recovery delivery round ${label}" --body "Throwaway pull request that makes every preview job deliver its credential to the protected-recovery broker. It is closed by the same round." | grep -oE '[0-9]+$')"
echo "opened ${repository}#${number}: deploy-preview (canary, publish-canary, publish, deploy, invalidate) delivers"
git commit --quiet --allow-empty -m "protected-recovery: delivery round ${label} (synchronize)"
git push --quiet origin "$branch"
echo "pushed to ${repository}#${number}: the cleanup job through deploy-preview's caller delivers"
sleep 30
gh pr close --repo "$repository" "$number" --delete-branch
echo "closed ${repository}#${number}: cleanup-preview delivers"

# 3. The workflow_dispatch tuple.
gh workflow run --repo "$repository" reconcile-previews.yml --ref main
echo "dispatched reconcile-previews in ${repository}: reconcile-previews (workflow_dispatch) delivers"

echo "the schedule tuple delivers on its own at 17 past the hour; check the shard's deliveriesOwed through the invoke workflow's status operation"
