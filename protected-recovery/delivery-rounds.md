# Delivery rounds

A round names one consumer, phase, quarantine shard, and label. CONTROL has no
shard. REVOCATION requires every quarantine effect acknowledged and a committed
inventory baseline. HORIZON also requires every member's token horizon to be
due. Each round expires 24 hours after opening, and each consumer can have only
one open round.

Run the operator from the reviewed platform checkout after rendering the
consumer callers at their recorded platform pins:

```sh
bash protected-recovery/orchestrate-deliveries.sh \
  collinbentley1/cdbentley CONTROL - control-1
```

The operator requires every expected caller and reusable call. Preview callers
carry the PR event, number, and head in their run names; dispatch callers carry
a random nonce. The invoke workflow returns that nonce, its run and attempt,
and every request coordinate with the broker reply. The operator checks these
fields and records the dispatch API's returned run ID. It refuses ambiguous
run selection or reruns.

The trigger manifest binds each member to one exact run and attempt. Early
verified deliveries can wait in the broker's bounded round buffer until that
binding arrives. A run/member pair cannot count toward another round. Both
active and transition members remain obligations while those authorities
exist; finish a pin transition before attempting a round whose complete set
of channels is unavailable.

The operator creates an empty main commit, a temporary PR branch, its open,
synchronize, and close events, one dispatch, and observes the next scheduled
run at that main commit. These events can run the consumer's ordinary workflows.
Run this command only during an authorized recovery operation.

Operator records live under
`~/.local/state/protected-recovery/<owner>-<consumer>/<round-id>/`.
`PROTECTED_RECOVERY_JOURNAL_DIR` can select another persistent directory.
Records include the main commit, PR number, branch commits, invocation nonces,
exact workflow runs, run bindings, replies, and cleanup results. They contain
no member credentials. Keep this directory through retries and review.

Retry with the same four coordinates. Accepted commits and triggers are reused.
If a dispatch response was lost, the saved nonce locates the original run; the
operator does not send an uncertain dispatch again. An unresolved intent needs
operator reconciliation. A local lock prevents concurrent access to one
journal. After a hard process kill, verify that process has stopped before
removing its `operator.lock` directory.

Use cleanup mode when abandoning an incomplete or expired round:

```sh
bash protected-recovery/orchestrate-deliveries.sh --cleanup \
  collinbentley1/cdbentley CONTROL - control-1
```

Cleanup uses recorded PR and branch identities without requiring a live broker
round or local clone. It refuses changed heads, closes the owned PR, deletes
only the exact recorded branch SHA, and verifies both results. It retains the
main commit and all operator evidence. Cleanup mode abandons normal reuse of
that journal; reconcile the broker round or wait for expiry before starting
replacement work with a new label. Cleanup success does not assert phase
completion.

Normal completion requires verified cleanup followed by a fresh broker status
for the exact round. The broker must report no delivery debt or current binding
blockers and the named phase ready from committed observations. Every receipt
must match the recorded run manifest. A previously downloaded successful reply
cannot substitute for that final read.

Local tests use the Firestore emulator and scripted GitHub/Git stand-ins. They
do not establish live WIF claims, GitHub scheduling, Google API behavior, or
production recovery. Those remain required activation evidence.
