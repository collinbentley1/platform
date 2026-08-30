# Follow-up: the two controls an organization parent would restore

Status: **designed, not implemented.** Both items below are blocked on an
account-structure change, not on platform code.

## What is blocked

All four projects — `cdbentley`, `runsetta`, `medlock-1025243085`,
`critical-history-16823277` — are **parentless**. `gcloud projects describe`
returns an empty `parent` for each. That rules out two classes of control:

**1. IAM deny policies.** Writing one needs `iam.denypolicies.create/delete/
replace/update`. Those are `NOT_SUPPORTED` in project custom roles, and the
only predefined role carrying them is `roles/iam.denyAdmin`, which is not in
the grantable set for these projects — `gcloud iam list-grantable-roles` on
`//cloudresourcemanager.googleapis.com/projects/cdbentley` returns 613 roles
and zero matching "deny". `roles/owner` carries only `iam.denypolicies.get`
and `.list`, so there is no out-of-band owner path either. Bootstrap apply run
33291080180 died on exactly this: `Role roles/iam.denyAdmin is not supported
for this resource`.

**2. Organization policy constraints.** Already known — the deployment sets
`manage_automatic_default_service_account_grants_policy = false` for the same
reason. The 12-hour service-account token constraint mentioned earlier in this
rollout is unsettable for the same reason.

## What was lost, and what replaced it

`terraform/modules/bootstrap/preview-runtime-deny.tf` denied the four
`cloud-run-preview@*` principals all of Cloud Storage, Secret Manager, and
Firestore/Datastore. It was **secondary** — `docs/security-rollout.md` §12
always framed Policy Analyzer admission as the primary control.

Replaced by two halves:

* **Preventive, on our write path:** the protected bridge refuses any reviewed
  plan, in any root, whose before/after state grants a `cloud-run-preview@*`
  principal anything. Derived from `REPOSITORIES`, so a new consumer cannot
  escape it.
* **Continuous, unchanged:** `tools/ci/preview-runtime-iam-contract.sh` proves
  zero Policy Analyzer results for those four principals across all four
  projects, before every preview traffic commit and hourly from
  `reconcile-previews.yml`.

**Residual gap.** A deny policy refused the request at evaluation time. These
controls are preventive only where the platform writes, and detective
elsewhere: a grant made out of band with the owner credential is live until
the next proof — at most the reconcile hour — and exploitable only by code
already running as that preview identity within the interval. A public
(`allUsers`) grant on a secret is likewise caught only at the next proof.

## If an organization is created

1. Create a Cloud Identity organization and migrate the four projects into it.
2. Grant `roles/iam.denyAdmin` **on the organization** to the protected
   bridge's executor, as an expiring lease in the existing lease grammar.
3. Restore `preview-runtime-deny.tf`, re-add `google_iam_deny_policy` to
   `BOOTSTRAP_RESOURCE_TYPES` and to `PROVIDER_VOLATILE_ATTRIBUTES` (`etag`),
   and re-add the deny permissions to `executorControlPermissions`. Note the
   permissions are still `NOT_SUPPORTED` in custom roles, so the split between
   `executorControlPermissions` and `executorCustomRolePermissions` must come
   back with it.
4. Keep both replacement controls. The bridge plan gate and the Policy Analyzer
   admission proof are cheap and independent of the deny policy; a deny policy
   that can be deleted by a compromised executor holding its own denyAdmin
   lease is not a reason to stop proving the property.
5. Reconsider the 12-hour service-account token constraint at the same time.
