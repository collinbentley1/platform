# Security Rollout

The `0.5.0` trust-boundary migration is deliberately staged. Legacy mode is a
single-use initial-adoption exception: it is valid only with an empty transition
SHA. Every later two-SHA rollout uses `legacy_compatibility_mode = false`; never
combine a transition SHA with legacy mode.

## Pipeline prerequisite

The existing `gha-terraform` service accounts currently have project-wide
Cloud Run, Artifact Registry, and, for some apps, Secret Manager or Datastore
administration. They still cannot modify project IAM, service-account IAM,
service accounts, or Workload Identity Federation providers. The hardened
steady state removes those mutation/data roles and gives routine GitHub
Terraform only a custom metadata reader plus read-only routine-state access.
Consequently, the normal infrastructure workflow is a convergence check; it
cannot apply either bootstrap or production infrastructure and must not pretend
that it can.

The migration bridge is
`.github/workflows/protected-bootstrap-implementation.yml`. It accepts only an
owner `workflow_dispatch` from the platform `main` ref, one repository, and
one exact `bootstrap`, `prod`, or `exposure` root. The v0.5.12 exposure path is
locked in both shell and controller validation to Runsetta's one reviewed
two-mapping adoption; it is not a general exposure mutator. The active workflow SHA is always the
immutable platform commit running the bridge. Initial adoption requires
`legacy_compatibility_mode = true` and an empty transition. A later staged
repin requires `false` and a transition SHA equal to the exact consumer
commit's single consistent, capability-proven current workflow pin; retirement
requires `false` and an empty transition. A DHI-parity-changing rollout cannot
use a two-SHA transition at all and follows the disabled-Actions active-only
protocol below. Production forbids both
migration controls. Its protected environment contains one
fresh Google user OAuth access token, never a refresh token or service-account
key. Before creating any temporary IAM artifact, the controller introspects
Google's documented subject, `exp`, `expires_in`, and scope metadata, requires
the exact owner subject, and rejects a token that cannot cover the mode-specific
bounded bridge and recovery envelope. Plan requires its full same-job recovery
tail and one-minute margin. Apply requires its two-minute main-job tail plus the
complete immediate fresh-runner recovery job, a maximum 59-minute envelope;
replace the protected-environment secret immediately before every dispatch.
GitHub queue delay is not bounded by job timeouts, so each recovery entry
independently requires fifteen minutes of remaining token lifetime. A delayed
fallback fails closed before mutation; the temporary leases independently
expire on their bound. If automatic fresh-runner recovery rejects a stale
token, do not immediately start a normal dispatch: wait at least 55 minutes
after the failed workflow completes, exceeding both the 54-minute conditioned
lease and 35-minute executor-token lifetimes, then replace the environment
secret and issue a new attempt-1 owner dispatch. Any unseen residue is inert by
then, and startup removes visible reserved artifacts before creating new
authority.
Each recovery operation reserves twelve minutes: seven minutes of documented
IAM propagation observation, three minutes of uninterrupted stable-empty
proof, one minute for cumulative read latency, and one minute for a bounded
late retry. Any later or repeated uncertainty still fails closed. Every scan
emits only a closed outcome label plus elapsed, scan, and stable-proof
milliseconds. The breadcrumb never includes an account, role, project, member,
policy, HTTP response, error text, credential, or other caller-controlled
value. Treat `reset-active-artifact`, `reset-observed-artifact`,
`reset-propagation-horizon`, `reset-masked-account`, and
`reset-retryable-read` as proof resets, not as cleanup success;
`proof-complete` is the sole successful terminal scan.
The environment also contains a fine-grained GitHub token with repository **Actions: read** and
**Administration: read** for the four consumers. Keep all four consumers'
Actions disabled: the bridge verifies
that setting, their numeric repository identities, and the absence of active
runs before planning, before applying, and after applying.

The bridge uses hardened system Git to fetch exact public platform and consumer
commits without credentials or checkout actions. `consumer_sha` may be the
current head of an open, unmerged public consumer PR: the fetch asks the public
origin for that exact object, verifies `FETCH_HEAD`, checks out a clean detached
HEAD, and deliberately imposes no consumer-`main` ancestry requirement. The
controller then requires every reusable-workflow call in that exact tree to pin
one consistent expected platform SHA, binds the consumer commit and tree in the
review digest, and runs the trusted platform doctor before authentication.
It executes only the immutable platform deployment root and never runs consumer
Terraform or application scripts. Every run creates a cryptographically random
`gha-pbt-*` service account and random read/mutation custom roles, rejects a
collision, inventories and disables/deletes orphaned prefix artifacts, and
deletes the current identity by immutable unique ID during cleanup. It requires
zero user-managed keys, standing IAM policy, project/resource binding, or
effective state/control-plane/runtime `actAs` permission. The owner OAuth token
is used only by the trusted controller for exact etag-CAS leases, lifecycle
operations on that random identity/role set, and one 35-minute token mint. The
workflow copies exported secrets into non-exported shell variables, unsets the
exported names, and passes one bounded NUL-delimited bundle to Bun over a pipe
after `exec env -i`; Bun consumes and closes stdin. Only the random executor
token reaches Terraform.

Each executor description records an exact versioned repository, run, root,
mode, approved-plan, and lease-expiry provenance tuple. Startup first minimally
identifies every account in the reserved `gha-pbt-*` namespace, reconfirms its
immutable project/email/name/unique-ID tuple, and disables it by unique ID
before trusting the mutable description or display name. Only after all
reserved accounts are contained does it strictly validate provenance, inspect
keys, or read authority. A self-mutated description/display name, key, or
key-inventory API failure therefore stops with every safely identified reserved
executor already disabled; unrelated default and permanent service accounts are
never lifecycle targets. A provenance mismatch remains a manual-cleanup stop
and the controller never re-enables that identity. Google IAM documents that
[`projects.serviceAccounts.disable`](https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/disable)
immediately rejects existing access tokens and new token requests, so mutable
metadata cannot preserve the orphan's token-bearing authority after containment. It
etag-fences and removes only the closed grammar of that run's project/state/receipt/marker,
three runtime-`actAs`, and owner-mint leases across all four projects and exact
service-account policies, deletes the executor and its verified custom roles,
and proves their absence. Expired conditions are still removed. A lost or late
IAM response is reconciled behind an advancing CAS fence; any unknown or altered
binding leaves the executor disabled and stops with an explicit manual-cleanup
error rather than guessing at ownership.

The active and any transition platform commits must each carry the exact
`platform-capabilities/preview-deployment-parity-v1.json` contract. The bridge
recomputes every fixed file hash, requires the transition to be an ancestor of
the active commit, requires both commits to declare the same 50-character DHI
parity ID, and rejects a marker-unaware predecessor. Before any non-initial
bootstrap change, all four fixed GCS markers must exist with positive generation
and metageneration and exactly `{version:"1", repository-id:<immutable-id>,
state:"clear"}` metadata. A marker may be absent only during that repository's
legacy=true, transition-empty initial bootstrap, whose reviewed plan must create
the exact object and whose post-apply proof must observe it clear.

For a DHI tuple change from `P` to `S`, use this active-only cutover; never put
both parity IDs in the trusted set. Finish all platform review, merge, and
release work first, and freeze final `S` before preparing a consumer head. The
protected bridge runs only from platform `main`, and its own commit is the
active workflow SHA. Any platform-`main` advance after that freeze therefore
invalidates every prepared pin, head check, plan, approval, and result receipt;
stop, designate and release the new final `S`, repin all four consumers, and
repeat every check before another protected plan. Never dispatch the bridge
from a tag or pretend an older receipt authorizes a different platform commit.

For every bounded PR-lifecycle proof below, take a complete paginated
`state=all` PR inventory, a repository issue-event ID baseline, a per-PR
timeline ID baseline for every PR created or updated in the window, and an
Actions run-ID baseline. Do not use the repository Events API as a security
gate ([API reference](https://docs.github.com/en/rest/activity/events)): GitHub
documents that it is not real time and may lag by 30 seconds to six hours. Use the
[repository issue events](https://docs.github.com/en/rest/issues/events#list-issue-events-for-a-repository)
and each affected PR's
[timeline](https://docs.github.com/en/rest/issues/timeline#list-timeline-events-for-an-issue)
together with the all-state PR inventory and run list. Prove `opened` from the
sole new PR plus its issue/timeline records; prove draft, ready, reopen, close,
and force-push transitions from issue/timeline records; and rule out
`synchronize` by both the frozen head SHA/tree comparison and timeline records.
For an intentional `edited` trigger, require the expected Actions jobs' exact
event-payload guard to pass and reconcile that run set against every baseline.

1. Prepare one complete branch per consumer whose exact head `C_repo` pins every
   reusable workflow to `S`, then freeze it before opening a draft PR. Never
   enable a marker-unaware legacy PR-triggered privileged deployment merely to
   manufacture a required status. While repository Actions is still globally
   disabled, first disable the base branch's `Deploy preview`, `Cleanup preview`,
   and `Deploy production` workflow files and prove `disabled_manually`.
   `Reconcile previews` must likewise be disabled when registered; the current
   legacy main may return an exact proven absent workflow until the hardened
   caller is merged. Only then, during one bounded monitored check window,
   restore and read back the exact selected/SHA-only `S` Actions policy. Permit
   only the credentialless exact-head Application, Infrastructure validation,
   Socket, and, for Runsetta, Swift package checks. No cloud job, environment,
   DHI credential, or OIDC exchange may run; any missing privileged
   branch-protection status remains missing rather than being synthesized. With
   the frozen PR still a draft and every privileged workflow still
   `disabled_manually`, use the owner PAT for exactly one PR-body-only edit. The
   resulting `pull_request: edited` delivery is the sole check-window trigger.
   Every expected job must first pass the shared fail-closed event-payload guard:
   an `edited` payload is accepted only when `changes` contains exactly `body`
   and that object contains exactly a string-or-null `from`; title, base, mixed,
   missing, and expanded change shapes fail. For non-`edited` pull-request
   deliveries the same guard accepts only `opened`, `reopened`, and
   `synchronize`; applicable push callers remain main-only. Only the normal
   credentialless exact-head checks may run. Reconcile the complete lifecycle and
   run baselines above, then immediately disable and drain Actions after those
   safe checks. A failed check requires a fresh branch and draft attempt assembled
   while disabled,
   never a synchronize, rebase, amend, or force-push. Record each full checked
   head SHA and keep all four heads immutable through the protected plans and
   merges.
2. Keep Actions disabled in all four consumers. Require no active run, drain all
   possible old-`P` tokens, and reject any non-clear marker. In the current
   marker-unaware v0.4 initial adoption, an as-yet-unmigrated repository's marker
   is expected to be absent; a marker created by an earlier serial apply must be
   exactly clear. A later DHI cutover requires all four markers exactly clear
   before its first plan.
3. For each repository, run protected bootstrap plan then apply with
   `consumer_sha=C_repo`, `active=S`, and `transition=""`. The current v0.4
   initial adoption must use `legacy_compatibility_mode=true`; its reviewed plan
   creates that repository's previously absent marker, and its result must prove
   the marker clear. This is the only exception. A generic later active-only DHI
   cutover starts with existing clear markers and must use
   `legacy_compatibility_mode=false`. Never mix those modes across one adoption
   or infer `false` merely because old and new DHI parity IDs differ. The bridge
   fetches the unmerged public head by exact SHA and refuses a tree whose workflow
   pins are not all `S`.
4. Do not merge after bootstrap alone. First require four immutable bootstrap
   result receipts—one for each repository—binding `platformSha=S`, the recorded
   consumer SHA/tree, an empty transition, the reviewed manifest, and the final
   Actions/run/marker proofs. Next complete the one-shot Runsetta exposure-state
   adoption described below and retain its successful `adoption-complete`
   receipt. Then run protected production plan/apply for all four unchanged
   consumer trees; Runsetta must name that exact successful adoption run. Only
   four successful production result receipts, in addition to the four
   bootstrap results and the Runsetta adoption receipt, unlock the first merge.
   Any missing, stale, failed, or mismatched evidence stops the rollout.
5. With Actions still disabled and all nine prerequisite receipts established,
   prepare each of the four unchanged draft PRs for
   merge one at a time. Establish a run-list baseline, mark that exact draft
   ready while Actions remains globally disabled, and prove exactly the one
   expected `ready_for_review` lifecycle event was created, zero workflow runs
   were created after the baseline, and no other event occurred; all privileged
   workflow files remain `disabled_manually` (or the
   pre-hardened reconcile file remains exactly absent); the head SHA, head tree,
   receipt, required checks, and clear-marker snapshot are unchanged. Then merge
   through the pull-request REST endpoint in squash mode using the receipt-bound
   head SHA as the exact `sha` precondition. Repeat for the other three without
   enabling Actions. Verify each resulting `main^{tree}` equals the receipt's
   `consumerTreeSha`; a rebase, conflict resolution, squash-content change, or
   follow-up commit requires a fresh protected plan/apply and four-receipt gate.
6. Recheck disabled Actions, zero runs, and exact-clear markers. Do not merely
   re-enable Actions: GitHub does not replay the merge's disabled `push`, and the
   production workflow intentionally has no manual-dispatch trust path. Use the
   following ordered activation protocol for one consumer at a time; any failed
   proof returns that repository to globally disabled Actions and stops:

   a. From the resulting exact `main`, prepare the complete activation branch
      before opening a PR. It may add exactly one fixed-format line to the
      regular-file `README.md`, with no other content, path, or mode change:
      `<!-- platform-production-activation-v1 platform-sha=<40hex> cutover-tree=<40hex> phase=<phase-a-or-phase-b> attempt=<positive-decimal> -->`.
      The SHA must be `S`. This active-only section selects the literal
      `phase-a`; Phase B step 4 selects the literal `phase-b`. `cutover-tree`
      must equal that phase's protected-result receipt `consumerTreeSha`. Prove
      the canonical `.dockerignore` excludes `README.md`, and prove every
      Dockerfile, build input, and effective image context is byte-identical to
      the cutover tree. Record the activation head SHA and tree, then freeze them
      before the PR is opened.
   b. Derive an exact normalized Actions allowlist from that frozen `S` caller
      graph. The general policy must be
      `{enabled:true,allowed_actions:"selected",sha_pinning_required:true}`.
      The selected policy must set `github_owned_allowed:false` and
      `verified_allowed:false`; `patterns_allowed` may contain only the pinned
      direct actions actually reachable from the frozen graph and each exact
      reusable caller path suffixed by `@S`. Broad owners, wildcards, tags,
      branches, predecessor SHAs, and unused actions are forbidden. Save this
      expected normalized policy before enabling: while Actions is globally
      disabled the selected-actions GET returns 409 and the general GET does not
      expose enough fields to prove it.
   c. With Actions still globally disabled, require unchanged `main` and
      activation head, clear markers, and zero queued or in-progress runs. First
      disable the `Cleanup preview`, `Reconcile previews`, and `Deploy
      production` workflow files and prove all three report `disabled_manually`.
      Then explicitly enable `Deploy
      preview` and require it to report `active`, including on a recovery attempt
      that inherited three disabled workflows; global disablement makes this
      workflow-state preparation non-triggering. Establish a run-list baseline,
      inventory every open PR and its exact head repository and SHA, freeze every
      other same-repository lifecycle source, and begin monitoring the complete
      PR inventory, issue-event, per-PR timeline, and run surfaces defined above.
      Outside the conservative UTC minute `:12` through
      `:22` reconciliation window, PUT the exact general policy and then
      immediately PUT the exact selected policy. Immediately GET both surfaces
      and require an exact normalized readback, then re-read all four workflow
      states. On any write or readback mismatch, immediately PUT
      `{enabled:false}`, drain, and stop. Prove this enable sequence replayed no
      event, created no run, and left none active. The activation draft's
      `opened` event must be the sole PR lifecycle event repository-wide during
      the following bounded window.
   d. Open the already-frozen activation PR as a draft. The sole permitted PR
      lifecycle event is this initial `opened` event. Wait only until that
      event's `Deploy preview` run materializes both `invalidate` and `deploy` as
      skipped before every credential-bearing environment, DHI, or OIDC entry.
      Immediately disable `Deploy preview`, require `disabled_manually`, and
      prove the bounded lifecycle and run surfaces contain no other event or
      unexpected run. All three preview lifecycle workflows are now individually
      disabled; only then wait for and require all normal exact-head checks. A
      draft does not make `synchronize` harmless: it enters the credentialed
      invalidation path. Therefore forbid `synchronize`, `reopened`,
      `ready_for_review`, and `converted_to_draft`, plus any amend, rebase,
      update-branch, force-push, close, or reopen, while Actions is enabled. If a
      new commit is needed, globally disable Actions, drain, close the abandoned
      PR while disabled, and begin again with a fresh immutable branch and
      attempt number.
   e. With all three preview lifecycle workflows still individually disabled,
      globally disable Actions and drain all runs. Establish run-list and event
      baselines, mark the unchanged PR ready while globally disabled, and then
      prove exactly the one expected `ready_for_review` event occurred, zero
      workflow runs and no other event were created after the baselines, Actions
      is still disabled, all three workflow files remain `disabled_manually`, the
      exact head and tree are unchanged, and all four markers remain clear. This
      intentionally suppresses the workflow response to the ready event rather
      than relying on draft semantics.
   f. While still globally disabled, explicitly enable only `Deploy production`,
      require its workflow state `active`, and reprove that all three preview
      lifecycle workflows remain `disabled_manually`. Re-enable with the same
      two-PUT general-then-selected sequence and exact normalized readback from
      step b. Prove GitHub did not replay the missed ready event or any production
      run, re-read the exact `S`-only policy, and repeat the unchanged
      main/head/tree, zero-active-run, exact-check, and clear-marker proofs.
      Merge through the pull-request REST endpoint using the exact frozen head SHA as its `sha`
      precondition and squash mode. A stale or rejected SHA is a stop, never a
      reason to retry against a moved head.
   g. Require the resulting `main^{tree}` to equal the frozen activation-head
      tree. Because `Cleanup preview` remains disabled, no
      `pull_request_target: closed` cleanup may exist for this merge; because
      `Reconcile previews` remains disabled, neither its `push` trigger nor its
      schedule may run. The only cloud mutation admitted by the activation merge
      is the push-only `Deploy production` workflow. Require that exact run to
      succeed and the first `S` production deploy to complete the sealed DHI
      epoch transition before enabling any preview lifecycle workflow.
   h. Outside the UTC minute `:12` through `:22` window, enable `Cleanup
      preview`, `Reconcile previews`, and `Deploy preview`, read back each active
      state, and prove there was no replay of the missed closed, push, ready, or
      scheduled events and no unexpected run before creating the reviewed live
      preview canary. Require the production DHI tuple for that canary; no
      preview may race or precede the production epoch.
   i. If the activation production run fails, immediately globally disable
      Actions, drain, keep all three preview lifecycle workflows individually
      disabled, and freeze every preview event. Do not rerun the failed workflow.
      Inspect and recover the durable deployment-parity marker and production
      state through the reviewed recovery path. Only after all original gates
      are restored may a fresh immutable activation PR with a new attempt number
      create one new push-only production run.

   Never replace this sequence with a direct push, ref rewrite, synthetic check,
   privileged rerun, branch-protection weakening, or a new `workflow_dispatch`
   WIF route.

The active-only apply removes `P` trust and adds only `S`; the bridge waits 300
seconds plus skew before its second freeze/marker proof. Never merge an `S` pin
before all four projects trust `S`, and never use the mixed-SHA transition path
when `P` and `S` declare different DHI parity IDs.

Terraform and the pinned Google provider run only in a pinned Docker image as a
non-root user with a read-only root filesystem, all capabilities dropped,
private PID/IPC namespaces, no host PID or Docker socket, and closed exact
mounts. The exact provider archive SHA-256, committed readonly lock hash,
version/source constraint, extracted two-file shape, and `/plugins` path are
verified before execution. A token-bearing provider with IAM `setIamPolicy` and
runtime `actAs` is inherently privileged; permissions alone cannot contain a
malicious provider. The exact verified provider binary is therefore an explicit
cryptographic trust boundary, followed by a zero-diff post-apply plan and live
policy/permission cleanup proofs.

The executor receives a 54-minute conditioned lease, safely beyond the 41-minute
job timeout. Plan retains its 25-minute bridge cap and complete 16-minute
same-job recovery tail. Apply may use a 34-to-39-minute bridge budget after
setup, retains a two-minute main-job tail for opportunistic containment, and
uses the independent 18-minute fresh-runner job as its authoritative late-failure
recovery path. The wrapper keeps one minute ahead of its hard timeout and the
controller keeps another five minutes for exact cleanup, so apply receives a
28-to-33-minute internal operation deadline. The workflow rejects setup that
leaves less than the 34-minute apply minimum.

Before consuming the receipt or creating mutation authority, apply requires
more than 20 minutes to remain: the unchanged 15-minute post-elevation reserve
plus the full five-minute mutation-permission convergence window. It rechecks
that 20-minute bound after fresh proofs and receipt consumption, then rechecks
the unchanged 15-minute reserve after elevation. The latter reserves seven
minutes for the post-WIF drain and eight for bounded apply/readback/proof work.
Plan gets only read control permissions, read-only state, and immutable
receipt creation; it uses `-lock=false`. Apply creates the mutation role and the
three exact production runtime `actAs` leases only after consuming the approved
receipt. Marker access consists of four distinct conditional bindings whose
`resource.type` and full `resource.name` select only each project's fixed
`deployment-parity-transition` object; no marker lease reaches Terraform state.
Storage is otherwise restricted to registered buckets and exact state/lock
objects. Every normal plan keeps one condition-scoped Storage Object Viewer
binding: the bucket-resource arm supplies Terraform's required workspace object
listing, while the object arm permits payload read only for the exact
`default.tfstate`. Google Storage conditions cannot prefix-limit
`storage.objects.list`, so the executor can temporarily enumerate object names
and metadata in that one backend bucket; it cannot read sibling object payloads.
Runsetta production additionally gets exact-object read of the canonical
exposure state and named adoption receipt, without list access to the exposure
bucket. Receipts have separate exact-object create-only and read-only leases;
the executor never gets receipt overwrite or delete authority. Permission
propagation and revocation use
`testIamPermissions` and a zero-byte effective-overwrite probe. Those permission
probes never read object payloads; the controller separately performs bounded,
generation-qualified state and receipt reads where the protocol requires them. State and
control-plane proofs for one permission transition share one absolute deadline:
together they may retry until the earlier of the manager's remaining API
deadline or a new five-minute consistency window, instead of each receiving a
fresh window or stopping after a fixed scan count. That same absolute deadline
caps every HTTP, gRPC, and overwrite subprobe;
a scan that reaches it stops before touching another permission surface. Exact
permission and runtime `actAs` projections remain unchanged, and failure to
converge by that bound still fails closed. Every API request and subprocess has
a bounded deadline. The `finally` path CAS-removes
only the exact leases from the latest policies, restores the original policy
version when conditions no longer require version 3, proves the still-live token
lost every tested project/state/`actAs` permission, verifies zero keys and
standing bindings, and deletes the executor. Expiration is only the
crash/runner-loss backstop. Every ambiguous IAM write is fenced by CAS-adding,
observing, and CAS-removing an inert already-expired binding with advancing
etags; a delayed predecessor write must fail before cleanup can succeed.

Run `plan` first with empty approved-run and approved-digest inputs. The summary
contains only allowlisted resource identities/actions and SHA-256 commitments;
raw before/after values, variables, outputs, plans, and state never leave the
runner. The plan writes an immutable, six-hour receipt under its exact backend
prefix; the manifest and receipt explicitly bind the plan mode, root, consumer
and platform commits, compatibility phase, transition SHA, and digest. After
reviewing the summary, dispatch `apply` with both the plan run ID and digest.
Apply verifies that the referenced run is a fresh successful owner dispatch at
the same platform SHA, reads the exact receipt, recomputes from live state, and
atomically creates a consumed marker before applying the local saved plan. A
receipt cannot be replayed; a failed apply requires a fresh plan. Plan,
pre-apply-consume, and post-apply result receipts bind exact four-marker
generation/metageneration/metadata snapshots plus Actions-disable, active-run,
and token-drain snapshots. After bootstrap apply and convergence, the bridge
waits 300 seconds plus skew from the completed WIF mutation, then rechecks all
four markers and every consumer before publishing the immutable result receipt.
No raw plan, state, token, or Actions artifact is uploaded. Delete the temporary
OAuth environment secret after the protected runs. Exposure is deliberately
different: v0.5.12 permits only one confirmed Runsetta state adoption, publishes
one terminal `adoption-complete` receipt, and has no plan receipt, approval,
consume marker, Terraform apply, or post-apply result. Any future exposure
mutation requires a separate workflow expansion and adversarial review.

Before its first apply, inventory every Compute Engine default service account,
instance, job, trigger, and attached workload and prove nothing depends on the
default account. The exact bootstrap root then authoritatively removes all
direct project `roles/editor` members and strips the legacy project-owner/editor/
viewer convenience bindings from the routine state, bootstrap state, and
access-log buckets. The state buckets explicitly depend on that Editor removal,
so the new protected bucket is never created while the default Compute identity
can inherit state access. Stop if the reviewed plan contains any other Editor
member or workload fallback.

The four registered personal projects currently have no organization parent.
Google permits Organization Policy Administrator only at organization scope and
marks the policy write permissions unsupported in project custom roles, so these
deployments must keep
`manage_automatic_default_service_account_grants_policy = false`. The protected
root still converges the authoritative empty Editor binding, but that is not
real-time prevention: a future out-of-band service/default-account creation
could regrant Editor between protected applies. Keep Compute disabled, require
every future service/API change to use the protected bootstrap lane, and fail
the post-apply live assertion unless the Editor binding is still empty. If a
project is later moved into an organization, enable
`iam.automaticIamGrantsForDefaultServiceAccounts` only in a separate reviewed
rollout using an organization-scoped bootstrap identity; do not grant a service-
agent role to a user or introduce a static key to approximate that authority.
The module enables Organization Policy Service only in that organization-backed
mode; the current standalone plans must not enable an otherwise unused API.

Existing apps currently keep bootstrap and routine production state in one
bucket. While the exact platform bootstrap root still uses the old backend, the
first privileged apply creates the separately protected
`bootstrap_state_bucket_name`. Save and review the plan, apply it, copy a
recovery snapshot into the new bucket, switch only the bootstrap backend, and
run `terraform init -migrate-state -force-copy -input=false`. Compare lineage
and serial, prove routine `gha-terraform` cannot read the new bucket, then remove
every generation under the old bootstrap prefix through the same reviewed
pipeline. Routine Terraform retains Object Viewer only on the production state
bucket, runs with locking disabled, and must never write any state or see
bootstrap state or recovery objects.

Cloud Run's legacy domain-mapping API has no no-data IAM viewer permission.
Domain mappings therefore live in `terraform/deployments/exposure`, not in the
routine production root. Its backend is the protected bootstrap-state bucket at
the fixed `<app>/exposure` prefix. Routine `gha-terraform` must be unable to list,
read, lock, overwrite, or delete that state.

v0.5.12 exposes only the following one-shot Runsetta adoption. It is a state
mutation performed by the trusted controller, not a Terraform apply:

1. Dispatch the protected workflow at exact platform SHA `S` with
   `target_repository=runsetta`, `terraform_root=exposure`, `mode=plan`, and the
   literal confirmation `ADOPT_RUNSETTA_EXPOSURE_STATE`. Leave plan-approval and
   adoption-run inputs empty. Any other repository, mode, or confirmation fails
   before credentials are mapped.
2. The random keyless executor first receives condition-scoped backend list plus
   exact `runsetta/exposure/default.tfstate` read. It receives no Cloud Run role,
   Domain Mapping permission, Viewer basic role, state write, lock, or delete.
   The controller owner token reads the exact regional Domain Mapping list and
   both mappings, validates the numeric project namespace, immutable IDs, route,
   certificate and Ready conditions, exact DNS records, and both production
   HTTPS health routes. The executor is independently proven unable to call that
   API.
3. If the state is absent, the controller temporarily grants only its exact owner
   member `roles/storage.objectCreator` on that one object, create-only writes a
   deterministic full Terraform v4 state with `ifGenerationMatch=0`, and rereads
   the returned generation through the executor. A 412 or ambiguous response is
   accepted only when the generation-bound bytes equal that invocation's exact
   proposed lineage and state. An existing byte-identical canonical serial-1
   state is idempotently reused; partial, foreign, noncanonical, or changed state
   fails closed. The creator lease is CAS-removed and read back absent before
   Terraform starts; crash recovery recognizes its exact owner-member contract
   and removes only that lease while preserving unrelated IAM.
4. Terraform 1.14.5 with Google provider 7.45.0 initializes from the reviewed
   filesystem mirror and runs only `plan -refresh=false`. The raw plan must be
   non-applyable and contain exactly the two Runsetta mapping resources as
   `no-op`, with equal before/after values, no import identity, no drift or
   unknown/sensitive/replacement data, the one exact relevant-attribute entry,
   and the three exact no-op outputs. No saved plan is applied and no raw state
   or plan leaves the runner.
5. The controller repeats the live API and HTTPS proof and requires exact
   pre/post continuity. Success publishes one immutable terminal
   `adoption-complete` receipt binding the dispatch confirmation, platform and
   frozen consumer SHA/tree, canonical state lineage/serial/generation/hash/size,
   live proofs, adoption outcome, and creator-lease disposition. There is no
   plan receipt, approval, consume marker, Terraform apply, or result receipt.

Runsetta protected production plan and apply must name that exact successful
adoption run via `exposure_adoption_run_id`. Before the production plan receipt,
before approval consumption, and again immediately before mutation, the bridge
generation-reads the terminal receipt and canonical state, verifies the
referenced GitHub run completed successfully on main at `S` as the fixed owner,
and re-proves the two live mappings and HTTPS routes with the owner token. Those
generation/hash commitments are part of the production manifest and receipt.
Only then may the production root's no-destroy `removed` blocks forget the old
state addresses. The temporary cross-state overlap is intentional; the Cloud
Run resources are never destroyed or recreated. Bucket versioning remains a
recovery backstop, not permission to accept unexplained state bytes.

The provider state remains `deletion_policy = "DELETE"` in v0.5.12 because
changing it produces a state update. Resource-level `prevent_destroy`, the
bridge's rejection of every non-no-op adoption plan, and the executor's lack of
Domain Mapping mutation authority are the current protections. A provider
`PREVENT` migration, a fresh-app exposure create, any mapping addition/removal,
or any Critical History load-balancer change requires a new separately reviewed
workflow design; the v0.5.12 route cannot perform it. Existing cdbentley,
Health/Medlock, and Critical History exposure state must remain unchanged.

A fresh scaffold is different: its configured GCS backend cannot exist before
bootstrap creates it. `terraform init -backend=false` only skips backend
initialization; it is not a local-backend override. The privileged pipeline must
create a reviewed ephemeral copy of the exact platform bootstrap root with only
the GCS backend block absent, initialize the default local backend, apply a saved
reviewed plan, copy local state to a fixed `recovery/` object in the newly
created bootstrap bucket, restore the reviewed GCS backend configuration, and
migrate state on the same runner. If anything after local apply fails, preserve
the recovery object and stop; never rerun from empty state.

## Phase A: add the new path

1. Keep every consumer's Actions disabled while establishing the new
   credential and environment boundary. GitHub auto-creates a referenced missing
   environment without the required policy, so create and protect every
   environment explicitly before any workflow names it. The exact steady-state
   matrix for each consumer is:

   - `dhi-base-prefetch-20260822-098dca9280b3`, `preview-publish`,
     `preview-cloud`, `preview-operations`, and `supply-chain`: selected branch
     `main` only, zero reviewers, and administrator bypass disabled.
   - `production` and `production-publish`: selected branch `main` only, the
     owner reviewer, and administrator bypass disabled.

   A missing selected-branch rule on any of these environments is a stop
   condition. In particular, do not enable Actions while `preview-operations`,
   `preview-cloud`, `preview-publish`, or `supply-chain` remains unprotected in
   any consumer. Verify the exact environment inventory and policies through the
   REST API, including zero unwanted reviewers, secrets, variables, tag rules,
   and bypass actors. The DHI environment is intentionally shared by preview
   and production so exact base parity is structural rather than two separately
   managed credential copies.

   Repository Actions must also use the exact general selected-actions policy
   and frozen-SHA allowlist defined by the activation protocol. A bare enable,
   GitHub-owned or verified-publisher blanket, tag or branch pattern, and a
   configuration that omits `sha_pinning_required:true` are all stop
   conditions. Every re-enable repeats the two writes and exact readback; an
   earlier successful read does not authorize later drift.

   Create the DHI environment with no secrets or variables first. Prove a
   default-branch, exact-SHA `pull_request_target` caller can enter it without a
   credential and fails only at the explicit missing-DHI-credential check. Then
   prove a temporary ordinary `pull_request` workflow authored by the PR and
   naming the same environment is denied by the selected-branch policy. Confirm
   the target-controller check is attached to the trusted base SHA while its
   event payload names the different exact PR head SHA; it is not a required
   head-SHA PR check. Remove the temporary negative-canary workflow before merge
   and re-read the policy. Only after both canaries pass may the owner populate
   the one confidential GitHub value,
   `DHI_PUBLIC_READ_TOKEN_20260822_098DCA9280B3`, and the non-confidential
   `DHI_USERNAME` variable in that environment. The token must be public-read
   only and short-lived/rotatable; never define it at repository or organization
   scope.

   Preview and production prefetch the same exact DHI development/runtime and
   Oven Bun children before any application checkout. The isolated prefetch job
   verifies frozen Docker signatures, subject-bound signed SBOM, provenance,
   source, and license evidence; erases registry authentication; then publishes
   only the closed public linux/amd64 OCI closure as a one-day raw artifact. The
   credentialless build gets no OIDC, packages permission, runtime secret, or
   registry credential. It executes the same-repository PR head only inside
   pinned BuildKit and consumes literal local OCI contexts. A fresh verifier
   canonicalizes the result and runs Syft/Grype in a networkless, read-only,
   capability-free container. A separate publisher revalidates the raw artifact
   ID/digest, canonical OCI graph, published inner-index digest, runnable digest,
   DHI runtime lineage, and exact source identity before OIDC and upload. Raw
   build archives and DHI credentials never cross into the publisher.
   The vendored DHI public key is the exact
   `docker-hardened-images/keyring` `publickey/dhi-2.pub` blob from commit
   `d6b11e0475ac7ddf74687268d16a4201a15e163f`, SHA-256
   `1d02bbccf149283ae6288d96264dcad3fb23ee1911d90324a48eab28e4cb8a5f`.
   The catalog license is the exact `LICENSE.txt` from commit
   `140f79eaba13b83e280f6f554f80f9633fae987e`, SHA-256
   `58881e3f5171ed2e98db7a4dbd64c16b9b5dbb2f5cbd9a56e79608a2360ad5f3`.
   The DHI evidence attests the hardened Alpine rootfs/base lineage, not the
   separately provenance-bound Oven Bun 1.4.0 binary overlaid by the canonical
   Dockerfile; the final image scan covers the complete hybrid.

   Do not create `GRYPE_DB_MANIFEST_JSON` or `DB_MANIFEST_JSON` at any GitHub
   variable scope. The verifier loads only the byte-pinned
   `tools/ci/grype-db.json` from the exact platform policy archive. Refresh it by
   reviewed PR before its 48-hour expiry, then authorize and repin the resulting
   platform SHA across every consumer. Treat inability to complete that cadence
   as a release stop condition; it is not the intended long-term update path.
   Socket uses no GitHub secret or paid
   scanner token. Every local scan runs the public policy, and branch protection
   requires the exact successful Socket GitHub App id `156372` checks. Delete
   every `SOCKET_API_TOKEN*` name and the retired `dependency-scan` environment
   after inventory proof, and revoke old Socket provider tokens.

   For Critical History, set `MAPBOX_PUBLIC_TOKEN` as a non-confidential
   protected-environment variable in `preview-cloud` and `production`. It must be
   a least-scope, non-default public `pk.*` value; Mapbox's default public token
   is forbidden because its scopes and URL restrictions cannot be changed.
   Reusing one value restricted to
   `https://ycriticalhistory.org` covers the parent and its preview subdomains;
   a separate preview value may be restricted to
   `https://preview.ycriticalhistory.org`. Mapbox URL restrictions are
   best-effort abuse controls, not authorization, and unsupported wildcard
   syntax or any `sk.*` token is forbidden.

   Medlock/Health has no GitHub waitlist key. Delete
   `WAITLIST_IDENTITY_KEYSET*` from every GitHub environment, repository, and
   organization scope. The trusted production deploy must fail closed unless
   Cloud Run has either zero exact keyset entries or one exact numeric
   `waitlist-identity-keyset` version. With one entry it reuses that enabled
   numeric version; with zero entries it requires zero enabled versions, streams
   a freshly generated key directly to Secret Manager, validates the returned
   resource, and binds Cloud Run to that version. Foreign, malformed, multiple,
   or unbound existing versions are stop conditions. The deploy identity may add
   versions and read version metadata but never access payloads, and the runtime
   may access only this secret.

   Before re-enabling Actions, semantically prove every workflow and caller has
   no secret forwarding, no `secrets: inherit`, no Socket or Health GitHub secret
   reference, and only the epoch DHI prefetch reference. Delete the old
   `preview-build`, `production-build`, and `dependency-scan` environments only
   after their values have been removed and the old DHI/Socket provider tokens
   are revoked. Re-read environment, repository, and organization secret
   inventories and require exact agreement: four consumer DHI environments each
   contain the sole epoch DHI token; every other scoped confidential inventory
   is empty. Any extra, stale, duplicate, shadowed, or differently scoped value
   is a stop condition. Re-enable consumers one at a time only after the new
   workflow commit, consumer pins, WIF transition, and cloud/environment canaries
   all pass; populating a secret alone is never sufficient.
2. Prepare, but do not merge, consumer PRs that pin every caller and Terraform
   mirror to the reviewed full platform SHA, remove caller-controlled commands
   and cloud inputs, remove production `workflow_dispatch`, remove
   `secrets: inherit`, and adopt the canonical Docker/Bun contract.
   Squash/merge this precursor workflow hardening only after review and call its
   immutable commit `S`. A follow-on protected controller commit `C` must
   hardcode and audit `S`; bootstrap exact WIF trust for `S`, then repin all
   consumers to `S`. The historical `161ac5c` tree predates this pipeline and
   must never be substituted for `S`.
   For Critical History, replace the old repository-scoped Mapbox value with
   a non-default public `pk.*` client value with only the required read scopes
   and the parent URL restriction above. Reuse it as the protected `MAPBOX_PUBLIC_TOKEN`
   environment variable in preview and production, or use the optional narrower
   preview value, then verify Mapbox usage and browser referrer behavior and
   delete the old repository secret. The
   workflow maps a value to the runtime `MAPBOX_PUBLIC_TOKEN` only after format
   validation. Never put an `sk.*` token in Cloud Run service metadata.
3. Complete the default-service-account workload inventory above. Wait for all
   old workflow runs to finish. Through the privileged pipeline, authoritatively
   inventory and delete every legacy `${SERVICE}-pr-*` service, including open
   PR previews, and require a second independent zero count. Then apply the exact
   platform bootstrap root with the new reviewed SHA as
   `active_workflow_sha`, an empty `transition_workflow_sha`, and
   `legacy_compatibility_mode = true`. Never allowlist any v0.1.0-v0.4.1 release
   SHA: every pre-migration preview workflow co-locates caller-controlled build
   code with cloud credentials, so a full-SHA rollback would recover that path.
   This first apply must remove every project-wide routine/deployer role,
   all Token Creator grants, routine-Terraform runtime `actAs`, and preview
   `actAs` on the production runtime. It creates the two publisher identities;
   neither publisher gets a generic fallback. The active/new SHA's distinct preview-operator workflow attribute
   binds to `gha-preview-deploy`, while only an explicitly declared transition
   SHA retains the old `gha-preview-operator` binding during repin. With the
   empty initial transition set, the retired
   operator has no workflow binding. Compatibility mode retains only
   path-specific Workload Identity User fallbacks for Terraform,
   production deploy, preview deploy, and preview traffic operations, so tokens
   admitted on one path cannot impersonate another identity. Old workflows stop
   authenticating at this point.
   Every later stable-preview follow-on starts by reading all four live
   bootstrap states and the prepared consumer heads. Call the exact workflow
   SHA that every consumer currently pins `P`; do not infer `P` from this
   document, a branch name, or a mutable tag. Require all four projects to have
   the same active `P`, and prove that no consumer still runs any existing
   transition SHA. For a new reviewed workflow SHA `S` with the same DHI parity
   ID, do not repeat the initial legacy form above. First require all four marker objects exactly
   clear, Actions disabled, no active consumer run, and the previous token
   issuance window drained. Before repinning any consumer, apply all four
   protected bootstrap roots with `active_workflow_sha = S`,
   `transition_workflow_sha = P`, and `legacy_compatibility_mode = false`.
   Retain both exact SHA bindings until all new-SHA canaries and operations
   pass. The final Phase-B apply is
   `active_workflow_sha = S`, an empty transition, and
   `legacy_compatibility_mode = false`. That apply removes `P`; do not admit an
   `S` DHI epoch until the bridge's post-mutation 300-second-plus-skew barrier,
   second Actions/run drain, and second four-marker clear snapshot are present
   in the immutable result receipt.
   If `S` changes the DHI parity ID, skip the transition set and use the
   prepared-consumer, disabled-Actions active-only protocol documented above;
   the same-parity `{S,P}` sequence is forbidden for that cutover.
4. Confirm the first bootstrap plan removes the four direct default Compute
   `Editor` grants and all state-bucket convenience principals before it creates
   the protected bucket. For the current standalone projects, confirm the plan
   contains no Organization Policy resource and the immutable deployment root
   explicitly disables it for the documented reason above. Apply the plan, then
   complete the bootstrap-state-bucket migration above. Prove both the default
   Compute and routine `gha-terraform` identities cannot read bootstrap state
   and neither can write it. Read the live project IAM policy again and require
   exactly zero direct `roles/editor` members before continuing.
5. Merge prepared consumer PRs only after all four bootstrap result receipts,
   the successful one-shot Runsetta adoption receipt, and all four production
   result receipts exist for the exact unchanged heads and platform SHA. For a
   DHI-changing active-only cutover, every unmerged head must be independently
   fetched and bound throughout that ordered nine-receipt gate. Keep
   Actions disabled across the entire four-project gate and all merges, merge
   no changed head, and compare each resulting `main^{tree}` with the receipt's
   `consumerTreeSha`. The normal production Terraform job now executes only
   `terraform/deployments/prod` from the exact platform SHA; checked-out
   consumer Terraform is validation/documentation and is never executed after
   Google authentication. Re-enabling after these merges cannot activate
   production because their `push` events occurred while Actions was disabled;
   use only the reviewed draft-to-ready activation-PR sequence above.
6. Review the immutable runtime map in the platform commit. Confirm Runsetta has
   `RUNSETTA_OFFLINE=1`, no deployed secret mappings, and no runtime secret
   accessor grants; confirm Medlock preview uses memory and production uses only
   its fixed Firestore coordinates, host/origin policy, and environment-scoped
   waitlist identity keyset; confirm cdbentley has
   no product runtime values and Critical History has only the protected public
   Mapbox token exception. Delete the obsolete `GCP_PROD_ENV_VARS`,
   `GCP_PROD_SECRETS`, `GCP_PREVIEW_ENV_VARS`,
   `GCP_EXACT_WIF_CANARY_ENABLED`, and `GCP_CLOUD_PREVIEW_ENABLED` variables.
7. Confirm the canary service account has no project roles and no legacy WIF
   binding. Every cloud workflow performs this exchange unconditionally and
   fails closed before its operational identity if exact reusable-workflow SHA
   trust is absent.
8. After all four bootstrap result receipts exist, perform only the one-shot
   Runsetta exposure-state adoption above and retain its successful terminal
   receipt. Then plan and apply all four trusted production roots before any
   consumer merge. Runsetta must name the exact adoption run and revalidate its
   canonical state, receipt, live mappings, and HTTPS immediately before the
   no-destroy `removed` transition. The other three exposure states and all
   Critical History edge resources remain untouched. Production convergence
   relinquishes Runsetta's old domain-mapping state without destroying it and
   creates the separate preview
   image repository, no-data preview runtime identity, shared preview service,
   and service-level deploy IAM. In the same saved production plan, require each
   repository-scoped Writer member to move from the deploy identity to its
   publisher identity and add only repository-scoped Reader to the matching
   deploy identity. No upload/delete-capable registry grant may remain on a
   deploy identity. Remove the preview operator's exact-service Cloud Run and
   exact-repository download grants during production convergence. Cloud Run
   revalidates the attached service identity and image during `update-traffic`,
   so the API-minimum traffic operation uses `gha-preview-deploy`'s existing
   exact-service update, preview-runtime `actAs`, and exact-preview-repository
   Reader grants. Those permissions are also sufficient to deploy a preview
   revision; contain that irreducible API capability with the distinct
   preview-operator workflow attribute, exact workflow-SHA WIF, protected
   `preview-operations` environment/event claims, immutable project/service
   selection, fixed CLI arguments, and no PR checkout or PR-controlled code
   after authentication. No credential may reach PR-controlled code.
   No subsequent exposure apply exists in v0.5.12. A fresh-app exposure create
   is outside this release and must not be approximated by this adoption route.
9. Critical History's existing load balancer, serverless NEG, TLS policy,
   global address, Certificate Manager authorization/certificate/map, and DNS
   must remain byte-for-byte unchanged during v0.5.12. Verify their already
   established live continuity read-only, including the fixed
   `critical-history-preview` service and missing-tag 404 behavior, but do not
   dispatch the Runsetta-only exposure route for Critical History. Any create,
   update, import, or recovery of those resources requires a separate protected
   workflow expansion with zero-destroy review; never apply an older exposure
   root that omits them.
10. Keep consumer Actions disabled until the no-data preview runtime, shared
   preview service, service-scoped IAM, and exact-WIF bindings are independently
   verified from the protected pipeline. The ordering now forks explicitly for
   Critical History. After all four bootstrap results, the Runsetta terminal
   adoption receipt, and all four protected production results exist, merge the
   four receipt-bound cutover trees with Actions still disabled. For Critical
   History, the read-only edge continuity proof from step 9 is a prerequisite to
   its production plan; there is no v0.5.12 exposure apply. The push-only production caller requires
   infrastructure convergence before its deploy job, so a nonempty deferred
   production plan is a hard stop, not a staging mechanism. The production root
   records the controller's expected open ingress and installs IAM/resources,
   but the preview-service lifecycle deliberately ignores controller-owned
   `ingress` and `invoker_iam_disabled`; this pre-activation apply must therefore
   leave the existing public, zero-tag bootstrap exposure byte-for-byte unchanged.

   After the required Critical History environment values are present and the
   production convergence plan is empty, run the exact ordered activation
   protocol above with all three preview lifecycle workflows disabled across its
   merge. The prerequisite infrastructure exposure proof may admit the public
   zero-tag state only when its labels, service account, traffic, template,
   resources, environment, and immutable Google hello-image digest exactly equal
   the Terraform bootstrap object; it rejects every near match. The reusable
   parity inspection then rejects that non-DHI bootstrap only because that step
   is explicitly `continue-on-error`; the immediately
   following epoch-prepare controller must acquire the durable marker and
   atomically prune traffic, set internal-only ingress, disable public invocation,
   and sanitize IAM before production deployment. Require the push-only new-SHA
   production run to finish, replace the sealed bootstrap with the sanitized
   production-DHI baseline, and clear the epoch marker. Only then re-enable the lifecycle
   workflows under the exact selected/SHA-only policy and create the live preview
   canary. That reviewed new-SHA preview deploy sets the shared preview service
   ingress to `internal-and-cloud-load-balancing` and must nonce-verify a live
   tagged revision through `https://pr-N.preview.ycriticalhistory.org`. The
   preview controller, not Terraform, owns the post-bootstrap ingress and invoker
   fields; the infrastructure workflow shares its deployment-parity lock and
   must prove the live OPEN/tagged or SEALED/zero-tag state instead of converging
   exposure. Require the stable tagged URL healthy and the generated `run.app`
   URL denied.

   With that Critical canary still open, globally disable and drain Critical
   History again under the protocol and require its protected production plan to
   remain empty; no second apply is expected. Reverify the same tagged stable
   URL, the `run.app` denial, and the OPEN/tagged marker projection. Re-enable
   Critical only with the exact two-PUT selected/SHA-only policy and readback,
   then make one reviewed synchronization of the still-open canary.
   Require its invalidation and redeploy to succeed through the restricted
   frontend, nonce-verify the stable tagged URL again, and require the `run.app`
   URL to remain denied. Only then execute fresh activation PRs for cdbentley,
   Runsetta, and Health/Medlock one at a time. For each, require the activation
   production run before its preview, then exercise Terraform convergence,
   preview build/publish/deploy, cleanup, and reconciliation at the new SHA.
   Require every unconditional canary and operation to succeed. Disable that
   consumer again and stop on any unexpected claim or permission; no broad
   project role remains during this proof.
11. Reconciliation must continue to report zero legacy `${SERVICE}-pr-*`
    services. Re-deploy any needed preview onto the shared service only after
    phase B.
12. Use Policy Analyzer across the canary service account, project, parent
    folder, and organization. Rule out project roles and every alternate
    external-principal, public, group, domain, inherited, or custom grant that
    could mint its tokens. The project deny policy is a preventive guard for
    Google-supported, explicitly enumerated in-scope permissions only; it is not
    an absolute-zero-access claim (`iam.denypolicies.*` itself is not supported
    in deny rules). Admission also requires bracketed direct project-policy and
    cross-project Policy Analyzer results proving no effective preview-runtime
    allow. Either guard failing or returning incomplete evidence keeps previews
    sealed.
13. Inspect `gha-terraform`, `gha-prod-deploy`, `gha-preview-deploy`,
    `gha-preview-operator`, `gha-prod-publish`, and `gha-preview-publish`. Require
    the expected identity-specific `attribute.*_workflow_sha/<new-sha>` Workload
    Identity User binding on every active identity and no active-SHA binding on
    the retired operator. Prove both publisher accounts have only one exact
    repository-level Artifact Registry Writer grant, both deploy accounts have
    only Reader on their exact image repository, both publishers have zero Cloud
    Run and runtime `actAs` grants. For Medlock only, prove `gha-prod-deploy` has
    Secret Version Adder on exactly `waitlist-identity-keyset` and zero version
    access, get, list, disable, enable, or destroy permission; prove every other
    deploy identity has zero Secret Manager grants. Prove the active/new SHA's
    `attribute.preview_operator_workflow_sha` principalSet targets only
    `gha-preview-deploy`; only the declared transition SHA may target
    `gha-preview-operator`, and both the transition set and legacy fallback must
    be empty at steady state. Prove the retired operator has zero Cloud Run,
    registry, runtime `actAs`, project, secret, state, data, and production
    grants. Audit the exact cleanup/reconcile workflow SHA, environment/event
    claims, immutable project/service map, fixed CLI arguments, and absence of PR
    checkout or PR-controlled execution after authentication. The canary alone
    cannot prove each operational binding.

### Stable-preview rollback boundary

- If bootstrap, exposure, DNS, certificate, or frontend verification fails
  before the first new-SHA Critical preview changes ingress, stop with consumer
  Actions disabled and preview ingress still `all`. Leave the protected edge
  resources dormant for diagnosis; do not destroy or partially unwind them.
- The WIF predecessor `P` is not a recovery root. It exists only to keep the
  immediately previous workflows authenticating during the rollout; never
  assume that `P`, or any other historical platform root, restores public
  preview ingress or preserves the current edge resources.
- If the first live-tag proof fails after ingress becomes restricted, disable
  Actions in every consumer and wait for every old run to finish. Prepare a
  separate recovery root `R` from `S` that changes only the immutable Critical
  preview ingress map and production preview-ingress value back to public
  ingress while retaining the current exposure resources. Review fresh
  bootstrap, production, and exposure plans from live state through a separately
  reviewed workflow expansion; the v0.5.12 Runsetta adoption lane cannot execute
  this recovery. The recovery plans
  must contain no deletion or replacement of DNS, certificate, load balancer,
  NEG, or URL-map resources. Only after no `P` workflow can run may the protected
  bootstrap transition exact WIF trust from `{P, S}` to `{S, R}`. Run the exact
  `R` recovery pipeline, prove the generated raw URL healthy, and keep DNS and
  the dormant protected frontend in place for diagnosis.
- Never apply `P` or an older exposure root as ingress recovery, and never
  remove DNS as the first recovery step. If a reviewed `R` cannot meet every
  precondition above, leave Actions disabled and stop instead of improvising a
  third trusted SHA or a direct cloud mutation.
- Remove the old workflow-SHA WIF trust only after the new-SHA production,
  Terraform, stable preview, cleanup, and reconciliation operations all pass,
  all four markers are exactly clear, and Actions is disabled with no active
  run. After removal, wait the declared 300-second token lifetime plus skew and
  repeat both proofs before any new-SHA DHI epoch can begin.

Artifact Registry does not provide a predefined upload-only Docker role. The
repository-scoped Writer role is the smallest Google-documented role for a
third-party OCI client to push and then read a tagged image. It permits upload,
download, tag create/update, artifact metadata writes, and attachment deletion,
but not repository image, tag, or version deletion. Production tag immutability
prevents retagging an existing production tag; preview deployment consumes the
verified digest rather than trusting the mutable tag. Treat tag/metadata and
attachment mutation within the one assigned repository as the remaining
publisher blast radius. A future custom role may remove unrelated permissions
only after an owner-reviewed pipeline test captures every permission required
by the pinned `regctl image import` and digest verification path; do not guess
the set and silently lock out
release publication.

Cloud Run's documented deployment contract separately requires
`artifactregistry.repositories.downloadArtifacts` and recommends
repository-scoped Artifact Registry Reader for the deployer. Reader also permits
metadata discovery and downloads within that repository, but no upload or delete
operations. Retain that documented role until an owner-reviewed protected
pipeline test proves a smaller custom role through both production and preview
deployments.

## Phase B: remove the old path

1. Keep all four consumers' Actions disabled and drained, require every marker
   exactly clear, and freeze each current consumer head/tree. Set
   `legacy_compatibility_mode=false` and an empty transition SHA for every
   repository-scoped protected bootstrap plan; this is a four-repository phase,
   not one shared apply.
2. Plan, review, and apply the exact platform bootstrap root separately for
   cdbentley, Runsetta, Health/Medlock, and Critical History. Each apply removes
   that repository's path-specific legacy Workload Identity User bindings.
   Broad project roles, Token Creator, and cross-boundary `actAs` were already
   removed by phase A. Routine Terraform retains only metadata reads and
   read-only state, and each consumer must separately remove any consumer-owned
   preview IAM grant.
3. Do not activate any repository until four immutable successful phase-B result
   receipts exist and bind the four exact pre-activation consumer trees. Confirm
   each service-account policy contains only the expected
   `attribute.*_workflow_sha/<approved-sha>` principal sets, with no legacy or
   transition fallback, and repeat the all-four clear-marker and disabled-run
   proof.
4. Activate all four consumers serially, one complete repository proof at a
   time. A re-enable cannot supply the required new production deploy because
   the production caller is intentionally push-only and GitHub does not replay a
   disabled push. For the selected repository, prepare a new exact one-line
   README activation record using `phase=phase-b`, that repository's phase-B
   receipt tree, and a fresh attempt number. Execute the complete immutable
   draft, three-workflow-disable, exact-policy-readback, exact-SHA merge, tree
   equality, production-success, and no-replay activation protocol above. This
   creates its required new phase-B production push; never rerun a phase-A run or
   add a dispatch trigger. Require that production run and Terraform convergence
   to succeed, then create two preview tags; close one PR; confirm cleanup removes
   only its tag and its stable URL converges to an exact 404 without redirects
   while the other stable preview remains healthy. Run reconciliation and repeat
   the 404 proof for an invalidated tag. Confirm the direct generated `run.app`
   URL remains denied throughout. Globally disable and drain that repository and
   reprove clear markers before starting the next one. After all four serial
   proofs, restore each repository only with the exact selected/SHA-only policy
   and workflow-state readbacks, and prove no missed event was replayed.
   The production deploy must precede the first preview after every platform
   pin or DHI-contract change. Confirm each admitted preview independently
   proves the exact DHI development/runtime top-level and linux/amd64 child
   tuple read from the 100%-served production revision. Preview application
   index and runnable digests are expected to differ from production; a matching
   version string, label, or Dockerfile is not sufficient. Confirm a newly
   admitted secretless baseline is built from the exact production artifact and
   returns an empty 404. A later same-DHI application-only production deploy
   need not invalidate existing previews; the next admission refreshes the
   baseline while independently reproving the immutable DHI tuple.
   Before trusting emergency recovery, exercise the two-write label fence on a
   sealed canary service: the reserved label add and removal must each complete
   through a known Cloud Run operation, advance both service etag and generation,
   preserve every non-fence label, and leave revision and traffic projections
   byte-identical. If either write is a semantic no-op or its response is lost,
   retain the durable transition marker and stop the rollout.
   These post-cutover operations prove the custom revision-deployer role.
   Cloud-mutation jobs key on immutable repository ID and use `queue: max`,
   serializing up to 100 pending runs FIFO across deploy/apply or
   deploy/cleanup/reconcile. Keep hourly reconciliation green and alert on
   failure as recovery for queue saturation, API errors, and lifecycle races.
5. Require only the reviewed post-migration SHA in the WIF trust set. For a
   later same-DHI safe update, the protected bootstrap pipeline first applies
   `{active=new, transition=old}`, consumers repin, all canaries and cloud
   operations are verified, and the pipeline then reapplies
   `{active=new, transition=""}`. Both applies use
   `legacy_compatibility_mode = false`; exact-clear markers and the post-removal
   token barrier are mandatory. Consumer validation permits at most those two
   reviewed safe SHAs. Never use a pre-migration SHA as the transition.
   A later DHI-changing update instead uses the active-only protocol and may
   never put old and new parity IDs in one trusted transition set.

If phase B authentication fails despite a green canary, fail closed. Use the
privileged pipeline to correct or add only the exact reviewed workflow-SHA
binding, investigate the failed claim, and repeat the proof. Do not restore
generic repository/environment bindings, project-wide deploy roles, or
production-runtime `actAs` through an ad hoc cloud command.

Production environments must select only `main`. GitHub OIDC immutable claims,
read-only default workflow tokens, SHA-only Actions policy, and approval for all
external-fork workflows are complementary settings; none replaces cloud-side
claim checks.
