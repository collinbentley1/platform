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
one exact `bootstrap` or `prod` root. The active workflow SHA is always the
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
the exact owner subject, and rejects a token that cannot cover the bounded
bridge, same-job reserve, and one-minute margin;
replace the protected-environment secret immediately before every dispatch.
GitHub queue delay is not bounded by job timeouts, so each recovery entry
independently requires fourteen minutes of remaining token lifetime. A delayed
fallback fails closed before mutation; the temporary leases independently
expire on their bound. If automatic fresh-runner recovery rejects a stale
token, do not immediately start a normal dispatch: wait at least 55 minutes
after the failed workflow completes, exceeding both the 54-minute conditioned
lease and 30-minute executor-token lifetimes, then replace the environment
secret and issue a new attempt-1 owner dispatch. Any unseen residue is inert by
then, and startup removes visible reserved artifacts before creating new
authority.
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
operations on that random identity/role set, and one 30-minute token mint. The
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
both parity IDs in the trusted set:

1. Open one public PR per consumer whose exact head `C_repo` pins every reusable
   workflow to `S`. Record each full head SHA and do not merge, rebase, amend, or
   force-push it.
2. Keep Actions disabled in all four consumers. Require no active run, drain all
   possible old-`P` tokens, and prove all four markers exactly clear.
3. For each repository, run protected bootstrap plan then apply with
   `consumer_sha=C_repo`, `active=S`, `transition=""`, and
   `legacy_compatibility_mode=false`. The bridge fetches the unmerged public
   head by exact SHA and refuses a tree whose workflow pins are not all `S`.
4. Do not merge any PR until four immutable result receipts exist—one for each
   repository—and each binds `platformSha=S`, its recorded `consumerSha` and
   `consumerTreeSha`, `terraformRoot=bootstrap`, an empty transition, the
   reviewed active-only manifest digest, and the post-300-second-plus-skew
   Actions/run/marker proofs. A missing, stale, failed, or mismatched receipt
   stops all four merges.
5. With Actions still disabled, merge the four unchanged prepared heads. Verify
   each resulting `main^{tree}` equals the receipt's `consumerTreeSha`; a rebase,
   conflict resolution, squash-content change, or follow-up commit requires a
   fresh protected plan/apply and four-receipt gate.
6. Recheck disabled Actions, zero runs, and exact-clear markers. Then re-enable
   consumers in the rollout order; the first `S` production deploy performs the
   sealed DHI epoch transition before any preview may use the new tuple.

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
job timeout, while a 24-minute internal deadline leaves a reserved cleanup
window. Apply refuses before consuming/elevating unless at least 15 minutes
remain, reserving seven minutes for the post-WIF drain and eight for bounded
apply/readback/proof work. Plan gets only read control permissions, read-only state, and immutable
receipt creation; it uses `-lock=false`. Apply creates the mutation role and the
three exact production runtime `actAs` leases only after consuming the approved
receipt. Marker access consists of four distinct conditional bindings whose
`resource.type` and full `resource.name` select only each project's fixed
`deployment-parity-transition` object; no marker lease reaches Terraform state.
Storage is otherwise restricted to registered buckets and exact state/lock
objects. Receipts have separate exact-object create-only and read-only leases;
the executor never gets receipt overwrite or delete authority. Permission
propagation and revocation use
`testIamPermissions`; validation never lists or reads a state object. Every API
request and subprocess has a bounded deadline. The `finally` path CAS-removes
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
No raw
plan, state, token, or Actions artifact is uploaded. Delete the temporary OAuth
environment secret after the protected runs. This bridge intentionally rejects
exposure roots; a future exposure mutation requires its own reviewed state lease
and workflow expansion.

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
read, lock, overwrite, or delete that state. For an existing app, migrate in this
order through the protected pipeline:

1. Save checksum-addressed recovery copies of both current production state and
   the initially empty exposure state. Record each state's lineage and serial.
2. Read every existing
   `module.site.google_cloud_run_domain_mapping.site["<domain>"]` instance ID from
   the saved production state. Initialize the exact reviewed exposure root
   against the protected `<app>/exposure` prefix and import each ID at
   `module.domains.google_cloud_run_domain_mapping.site["<domain>"]`.
3. Require an exposure plan with no create, update, or destroy operations. Verify
   that every expected domain remains mapped to the registered production service,
   its reported DNS records are unchanged, and its live HTTPS route still works.
4. Only then apply the exact production root containing the no-destroy `removed`
   block. Confirm the new production-state serial no longer contains any domain
   mapping and the protected exposure state contains all of them. Stop and restore
   the reviewed recovery generations if either state is incomplete; never allow a
   destroy/recreate migration. The production root temporarily retains the inert
   `google.no_attribution` provider alias because the historical state instances
   are bound to that address; no configured production resource uses the alias.
   Remove it in a later reviewed platform release only after all four production
   states prove that every domain-mapping address is gone.

For a fresh app, the protected pipeline applies the production root first to
create the service, then applies the exposure root in its protected prefix. No
import is involved. All later domain additions/removals require a separate
owner-reviewed exposure plan; `prevent_destroy` makes removal fail closed.

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
5. Merge prepared consumer PRs only after the applicable protocol above is
   complete. For a DHI-changing active-only cutover, that means all four exact
   unmerged heads were independently fetched, planned, applied, and named by
   four immutable successful result receipts before the first merge. Keep
   Actions disabled across the entire four-project gate and all merges, merge
   no changed head, and compare each resulting `main^{tree}` with the receipt's
   `consumerTreeSha`. The normal production Terraform job now executes only
   `terraform/deployments/prod` from the exact platform SHA; checked-out
   consumer Terraform is validation/documentation and is never executed after
   Google authentication.
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
8. For existing apps, import and verify every domain mapping in the protected
   exposure state using the migration sequence above. Then apply the trusted
   production root through the protected pipeline. This relinquishes the old
   domain-mapping state without destroying it and creates the separate preview
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
   Require the subsequent exposure plan to remain empty. For a
   fresh app, apply production first and exposure second. The current Critical
   History service already completed this baseline migration with public preview
   ingress. For its follow-on stable namespace, do not apply the new production
   root that restricts ingress until step 9 has activated and verified the
   frontend.
9. For Critical History, use the protected bootstrap root to enable the Compute
   and Certificate Manager APIs, then apply the protected exposure root to
   create the dedicated global external HTTPS load balancer, fixed-service
   serverless NEG, TLS policy, global address, Certificate Manager DNS
   authorization, wildcard certificate, and certificate map. Add exactly the
   emitted DNS-authorization CNAME and wildcard A record
   `*.preview.ycriticalhistory.org` to the authoritative zone, both DNS-only and
   unproxied. Wait until the
   certificate and certificate-map entry are active. The NEG must fix
   `critical-history-preview` and parse only the tag with
   `<tag>.preview.ycriticalhistory.org`; no caller or pull request may mutate DNS
   or load-balancer resources. While the existing preview service still has
   public ingress, confirm a nonexistent tag returns 404 through the stable
   frontend. Do not apply the new Critical production root yet: a 404 proves the
   frontend can reject a missing tag, but does not prove that it can reach a live
   tagged revision after ingress is restricted. Never apply an older exposure
   root that omits this module: review every saved exposure plan for zero destroy
   operations even though both Terraform and provider deletion prevention are
   present.
10. Keep consumer Actions disabled until the no-data preview runtime, shared
   preview service, service-scoped IAM, and exact-WIF bindings are independently
   verified from the protected pipeline. After the required Critical History
   environment values are present, activate Critical History first. Its first
   reviewed new-SHA preview deploy sets the shared preview service ingress to
   `internal-and-cloud-load-balancing` and must nonce-verify a live tagged
   revision through `https://pr-N.preview.ycriticalhistory.org`. The preview
   controller, not Terraform, owns the post-bootstrap ingress and invoker fields;
   the infrastructure workflow shares its deployment-parity lock and must prove
   the live OPEN/tagged or SEALED/zero-tag state instead of converging exposure.
   Require the stable tagged URL to remain healthy and the generated `run.app`
   URL to be denied. Then enable each remaining consumer one at a time and run
   fresh production, Terraform, preview build/publish/deploy, cleanup, and
   reconciliation jobs at the new SHA. Require every unconditional canary and
   operation to succeed. Disable that consumer again and stop on any unexpected
   claim or permission; no broad project role remains during this proof.
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
  bootstrap, production, and exposure plans from live state: the recovery plans
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

1. Set `legacy_compatibility_mode = false` in the protected bootstrap pipeline.
2. Apply the exact platform bootstrap root. This removes path-specific legacy
   Workload Identity User bindings. Broad project roles,
   Token Creator, and cross-boundary `actAs` were already removed by the first
   phase-A apply. Routine Terraform retains only metadata reads and read-only
   state. Each
   consumer must separately remove any consumer-owned preview IAM grant.
3. Confirm each service-account policy contains only the expected
   `attribute.*_workflow_sha/<approved-sha>` principal sets.
4. Run a new production deploy; create two preview tags; close one PR; confirm
   cleanup removes only its tag and its stable URL converges to an exact 404
   without redirects while the other stable preview remains healthy. Run
   reconciliation and repeat the 404 proof for an invalidated tag. Confirm the
   direct generated `run.app` URL remains denied throughout.
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
