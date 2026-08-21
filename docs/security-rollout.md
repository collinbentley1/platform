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
direct project `roles/editor` members, enforces
`iam.automaticIamGrantsForDefaultServiceAccounts`, and strips the legacy
project-owner/editor/viewer convenience bindings from the routine state,
bootstrap state, and access-log buckets. The state buckets explicitly depend on
that Editor removal, so the new protected bucket is never created while the
default Compute identity can inherit state access. Stop if the reviewed plan
contains any other Editor member or workload fallback.

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
   destroy/recreate migration.

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
   credentials, a least-scope `SOCKET_API_TOKEN`, the exact reviewed
   `GRYPE_DB_MANIFEST_JSON` environment secret, and owner approval. The manifest
   is non-confidential, but the secret context prevents repository-variable
   substitution. Create an
   owner-approved `dependency-scan` environment containing only the same
   Socket token with admin-only visibility and only the `packages:list` scope.
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
   Critical History only, store the rotated public Mapbox `pk.*` token as the
   `MAPBOX_PUBLIC_TOKEN` environment secret in `preview-cloud` and `production`;
   all other deploy environments remain free of runtime values.
   Do this before any caller references the new workflow.
   GitHub never releases environment secrets to external-fork or Dependabot
   pull-request jobs. Those two cases therefore run the pinned Socket scanner in
   its public free mode after workflow approval; they never receive the org
   token, DHI credentials, or a cloud preview. Same-repository pull requests and
   main must fail unless the protected organization token is present.
   Platform pull requests are a separate trust-root case: they always use
   Socket's secretless public policy because the PR controls the workflow and
   dependency configuration. Only the post-merge `main` platform run may enter
   `dependency-scan` and receive the organization token.
2. Prepare, but do not merge, consumer PRs that pin every caller and Terraform
   mirror to the reviewed full platform SHA, remove caller-controlled commands
   and cloud inputs, remove production `workflow_dispatch`, remove
   `secrets: inherit`, and adopt the canonical Docker/Bun contract.
   For Critical History, rotate the old repository-scoped Mapbox value to a
   dedicated public `pk.*` client token with only the required read scopes and
   exact preview/production URL restrictions. Store it only as the protected
   environment secret `MAPBOX_PUBLIC_TOKEN` described above, verify Mapbox usage
   and browser referrer behavior, then delete the old repository secret. The
   workflow maps it to `MAPBOX_ACCESS_TOKEN` only after format validation. Never
   put an `sk.*` token in Cloud Run service metadata.
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
   `actAs` on the production runtime. It creates the two publisher identities
   and the traffic-only preview operator with exact environment/workflow-SHA WIF
   bindings; neither publisher gets a generic fallback. Compatibility mode
   retains only path-specific Workload Identity User fallbacks for Terraform,
   production deploy, preview deploy, and preview traffic operations, so tokens
   admitted on one path cannot impersonate another identity. Old workflows stop
   authenticating at this point.
4. Confirm the first bootstrap plan removes the four direct default Compute
   `Editor` grants and all state-bucket convenience principals before it creates
   the protected bucket. Apply it, then complete the bootstrap-state-bucket
   migration above. Prove both the default Compute and routine `gha-terraform`
   identities cannot read bootstrap state and neither can write it.
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
   deploy identity, and the preview operator must have no registry or runtime
   `actAs` grant. Require the subsequent exposure plan to remain empty. For a
   fresh app, apply production first and exposure second.
9. Keep consumer Actions disabled until the no-data preview runtime, shared
   preview service, service-scoped IAM, and exact-WIF bindings are independently
   verified from the protected pipeline. Then enable one consumer at a time and
   run fresh production, Terraform, preview build/publish/deploy, cleanup, and
   reconciliation jobs at the new SHA. Require every unconditional canary and
   operation to succeed. Disable that consumer again and stop on any unexpected
   claim or permission; no broad project role remains during this proof.
10. Reconciliation must continue to report zero legacy `${SERVICE}-pr-*`
    services. Re-deploy any needed preview onto the shared service only after
    phase B.
11. Use Policy Analyzer across the canary service account, project, parent
    folder, and organization. Rule out project roles and every alternate
    external-principal, public, group, domain, inherited, or custom grant that
    could mint its tokens.
12. Inspect `gha-terraform`, `gha-prod-deploy`, `gha-preview-deploy`,
    `gha-preview-operator`, `gha-prod-publish`, and `gha-preview-publish` and require the expected
    identity-specific `attribute.*_workflow_sha/<new-sha>` Workload Identity User
    binding on each. Prove both publisher accounts have only one exact
    repository-level Artifact Registry Writer grant, both deploy accounts have
    only Reader on their exact image repository, both publishers have zero Cloud
    Run and runtime `actAs` grants, and the preview operator has zero Artifact
    Registry and runtime `actAs` grants. The canary alone cannot prove each
    operational binding.

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
4. Run a new production deploy; create a preview tag; close the PR; confirm
   cleanup removes it; and run reconciliation.
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
