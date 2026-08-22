# Security Rollout

The `0.5.0` trust-boundary migration is deliberately two phase. Do not set
`legacy_compatibility_mode = false` until fresh jobs pinned to the reviewed
platform commit have authenticated successfully.

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

Before the cloud half of this migration can run, provision an owner-controlled,
review-gated bootstrap pipeline identity with only the permissions required by
the reviewed plan. Do not copy a user refresh token or static service-account
key into GitHub. The pipeline must check out an exact reviewed `platform` SHA
and execute only `terraform/deployments/bootstrap`,
`terraform/deployments/prod`, and `terraform/deployments/exposure`; it must never
check out or execute consumer Terraform, provider configuration, lockfiles, caches,
functions, or outputs. Its repository ID, target workflow SHA, optional prior
safe transition SHA, migration phase, and backend settings are protected
owner-reviewed inputs. Until that pipeline exists, keep
consumer Actions disabled so no cloud workflow can start against incomplete IAM.

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

1. Create `preview-build` and `production-build` with only rotated DHI
   credentials, an admin-visible `packages:list`-only `SOCKET_API_TOKEN`, the exact reviewed
   `GRYPE_DB_MANIFEST_JSON` environment secret, and owner approval. The manifest
   is non-confidential, but the secret context prevents repository-variable
   substitution. Create an
   owner-approved `dependency-scan` environment in the platform repository
   containing only the same Socket token. Consumer verification jobs do not use
   that environment or credential: the actual preview/production build performs
   exactly one organization-policy `bun pm scan` before package extraction, and
   duplicate application/firewall installs plus Docker use the public policy.
   Platform CI must have imported and validated the
   identical `tools/ci/grype-db.json` object first. Never define the manifest or
   these credentials at repository scope. Rotate both protected environment
   manifest copies from a reviewed manifest PR before its 48-hour build-time
   expiry; this does not alter the WIF workflow SHA. Create secretless,
   owner-approved `preview-publish` environments and owner-approved
   `preview-cloud` environments, plus
   `preview-operations` without secrets/reviewers for automatic teardown and
   `supply-chain` without secrets. Create secretless `production-publish` with
   the same protected-main restriction and owner review as `production`. For
   Critical History only, store the rotated public Mapbox `pk.*` values in the
   `MAPBOX_PUBLIC_TOKEN` environment-secret slots in `preview-cloud` and
   `production`. These values are browser-visible public configuration; the
   secret slots provide approval gating and log masking, not confidentiality.
   The simplest setup reuses one least-scope value restricted to
   `https://ycriticalhistory.org`, which Mapbox also permits on every subdomain.
   If separate values are desired, restrict the preview value to
   `https://preview.ycriticalhistory.org`; that narrows preview-to-production use
   but the production parent still includes preview subdomains. Mapbox URL
   restrictions are best-effort abuse controls, not authorization. Do not enter
   unsupported wildcard syntax. All other deploy environments remain free of
   runtime values.
   Do this before any caller references the new workflow.
   The reusable deploy contracts must explicitly declare each secret name they
   consume, and callers must forward exactly those names without using
   `secrets: inherit`; the protected called-job environment then supplies and
   overrides the value. Otherwise cross-repository `workflow_call` jobs receive
   empty secret values.
   GitHub never releases environment secrets to external-fork or Dependabot
   pull-request jobs. They run only the credential-free checks and never receive
   the org token, DHI credentials, or a cloud preview. Same-repository preview
   builds and production-main builds fail unless their protected build
   environment supplies the token. The canonical local scanner is byte-bound to
   the platform template before release, uses one org-scoped request for at most
   128 lock entries, checks the free quota endpoint first, polls fail closed, and
   rejects malformed, duplicate, missing, unresolved, pending, or unexpected
   results. Bun 1.4 does not submit git, GitHub, remote-tarball, file, link, or
   workspace resolutions to a security scanner, so the immutable contract and
   platform-main pre-token boundary must reject every such direct or transitive
   lock source before claiming complete coverage. Allow only canonical npm
   registry lock tuples with exact resolved versions and sha512 integrity. At
   100 quota units per batch and 500 units per hour, serialize the
   rollout to no more than five protected scans per quota window unless Socket
   raises the limit; never retry the paid POST automatically.
   Platform pull requests are a separate trust-root case: they always use
   Socket's secretless public policy because the PR controls the workflow and
   dependency configuration. Only the post-merge `main` platform run may enter
   `dependency-scan` and receive the organization token. Disable GitHub runner
   workflow-command parsing across the entire untrusted Docker build action with
   a fresh random token held only in the runner temporary directory, then restore
   it in an unconditional next step. This prevents application tests, build code,
   package diagnostics, and BuildKit relays from forging modern or legacy runner
   commands or post-action state.
2. Prepare, but do not merge, consumer PRs that pin every caller and Terraform
   mirror to the reviewed full platform SHA, remove caller-controlled commands
   and cloud inputs, remove production `workflow_dispatch`, remove
   `secrets: inherit`, and adopt the canonical Docker/Bun contract.
   For Critical History, rotate the old repository-scoped Mapbox value to
   a public `pk.*` client value with only the required read scopes and the parent
   URL restriction above. Reuse it in both protected environment
   `MAPBOX_PUBLIC_TOKEN` slots, or use the optional narrower preview value, then
   verify Mapbox usage and browser referrer behavior and delete the old
   repository secret. The
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
   transition SHA. For a new reviewed workflow SHA `S`, do not repeat the
   empty-transition form above. Before repinning any consumer, apply all four
   protected bootstrap roots with `active_workflow_sha = S`,
   `transition_workflow_sha = P`, and `legacy_compatibility_mode = true`.
   Retain both exact SHA bindings until all new-SHA canaries and operations
   pass. The final Phase-B apply is
   `active_workflow_sha = S`, an empty transition, and
   `legacy_compatibility_mode = false`.
4. Confirm the first bootstrap plan removes the four direct default Compute
   `Editor` grants and all state-bucket convenience principals before it creates
   the protected bucket. For the current standalone projects, confirm the plan
   contains no Organization Policy resource and the immutable deployment root
   explicitly disables it for the documented reason above. Apply the plan, then
   complete the bootstrap-state-bucket migration above. Prove both the default
   Compute and routine `gha-terraform` identities cannot read bootstrap state
   and neither can write it. Read the live project IAM policy again and require
   exactly zero direct `roles/editor` members before continuing.
5. Merge the prepared consumer PRs. The normal production Terraform job now
   executes only `terraform/deployments/prod` from the exact platform SHA;
   checked-out consumer Terraform is validation/documentation and is never
   executed after Google authentication.
6. Review the immutable runtime map in the platform commit. Confirm Runsetta has
   `RUNSETTA_OFFLINE=1`, no deployed secret mappings, and no runtime secret
   accessor grants; confirm Medlock preview uses memory and production uses only
   its fixed Firestore coordinates and host/origin policy; confirm cdbentley has
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
   revision through `https://pr-N.preview.ycriticalhistory.org`. Only after that
   proof, apply the reviewed Critical production root to converge the declarative
   ingress setting; require the stable tagged URL to remain healthy and the
   generated `run.app` URL to be denied. Then enable each remaining consumer one
   at a time and run fresh production, Terraform, preview build/publish/deploy,
   cleanup, and reconciliation jobs at the new SHA. Require every unconditional
   canary and operation to succeed. Disable that consumer again and stop on any
   unexpected claim or permission; no broad project role remains during this
   proof.
11. Reconciliation must continue to report zero legacy `${SERVICE}-pr-*`
    services. Re-deploy any needed preview onto the shared service only after
    phase B.
12. Use Policy Analyzer across the canary service account, project, parent
    folder, and organization. Rule out project roles and every alternate
    external-principal, public, group, domain, inherited, or custom grant that
    could mint its tokens.
13. Inspect `gha-terraform`, `gha-prod-deploy`, `gha-preview-deploy`,
    `gha-preview-operator`, `gha-prod-publish`, and `gha-preview-publish`. Require
    the expected identity-specific `attribute.*_workflow_sha/<new-sha>` Workload
    Identity User binding on every active identity and no active-SHA binding on
    the retired operator. Prove both publisher accounts have only one exact
    repository-level Artifact Registry Writer grant, both deploy accounts have
    only Reader on their exact image repository, both publishers have zero Cloud
    Run and runtime `actAs` grants. Prove the active/new SHA's
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
  Terraform, stable preview, cleanup, and reconciliation operations all pass.

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
by `crane copy` and `crane digest`; do not guess the set and silently lock out
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
   These post-cutover operations prove the custom revision-deployer role.
   Cloud-mutation jobs key on immutable repository ID and use `queue: max`,
   serializing up to 100 pending runs FIFO across deploy/apply or
   deploy/cleanup/reconcile. Keep hourly reconciliation green and alert on
   failure as recovery for queue saturation, API errors, and lifecycle races.
5. Require only the reviewed post-migration SHA in the WIF trust set. For a
   later safe update, the protected bootstrap pipeline first applies
   `{active=new, transition=old}`, consumers repin, all canaries and cloud
   operations are verified, and the pipeline then reapplies
   `{active=new, transition=""}`. Consumer validation permits at most those two
   reviewed safe SHAs. Never use a pre-migration SHA as the transition.

If phase B authentication fails despite a green canary, fail closed. Use the
privileged pipeline to correct or add only the exact reviewed workflow-SHA
binding, investigate the failed claim, and repeat the proof. Do not restore
generic repository/environment bindings, project-wide deploy roles, or
production-runtime `actAs` through an ad hoc cloud command.

Production environments must select only `main`. GitHub OIDC immutable claims,
read-only default workflow tokens, SHA-only Actions policy, and approval for all
external-fork workflows are complementary settings; none replaces cloud-side
claim checks.
