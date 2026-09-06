# Protected authority apply

Production activation remains blocked on the reviewed organization, permanent
identities, exact consumer pins, successful live Deny canaries, and exclusive
control of the offline bootstrap identity.

The module refreshes broker ancestry, applying identity, consumer ancestry,
target identities, and Deny, service, and Allow state during every apply. Each
authority grant consumes those checks. A saved repair plan therefore cannot
reuse its planner's broker ancestry or applying identity. A failed consumer
ancestry read blocks that consumer's grants and the shared admission check.

These dependencies order reads before writes. An IAM grant does not remotely
compare-and-set a separate Deny policy or project ancestry version. The
controller lease serializes participating applies and excludes broker work;
it does not fence another session holding the offline root credentials.

Before activation, establish one controlled bootstrap credential session and
exclude every independent writer of the protected Deny policies, project
hierarchy, and authority grants for the entire apply interval. The broker and
its ledger must already exist with the lease API. Initial broker creation
without authority evidence remains a separate offline-root bootstrap step.
That first stage creates the broker, ledger, and purpose invokers while leaving
all cross-project authority resources absent. Authority activation accepts only
steady or bootstrap Deny form; an open maintenance ticket prevents acquisition.
The lease route needs only the preprovisioned ledger permissions.
Do not use a self-reported "lease held" variable as proof of this prerequisite.

## Applying a reviewed saved plan

Use the exact reviewed checkout and an existing owner-only saved plan. Provide
an owner-only ID-token file for one canonical RESTORE controller, with the
broker URL as audience. Google reads and Terraform apply use the reviewed
bootstrap application-default credentials. Neither credential enters the
Terraform configuration or lease response.

```sh
bun --no-env-file run tools/ci/protected-recovery-apply.ts apply \
  /absolute/terraform/root /absolute/reviewed.tfplan \
  cdbentley /absolute/controller-id-token
```

The wrapper copies the plan into a private directory and acquires a durable
broker lease bound to its SHA-256, a fresh acquisition key, and the authenticated
controller. It reads the applying identity, all five project identities and
organization parents, their etags and update times, all six Deny attachments,
and all 36 permanent target identities. It then checks lease ownership and
applies that exact copied plan with Terraform's backend lock enabled.

During apply, the module's external lease reader hashes the private plan again
and requires the broker to return the same lease key, digest, acquisition time,
and authenticated owner. An absent context or lease refuses authority grants.
The context contains file paths and lease metadata, never a bearer token.

After Terraform exits successfully, the wrapper rereads the same Google state
and verifies exact equality with the starting snapshot. Missing, malformed,
paginated, or changed reads fail. It checks lease ownership again and releases
only the exact lease it acquired. The private directory retains the saved plan,
context, and successful verification record. Do not commit these local files.

On an exception, failed apply, or changed readback, the wrapper does not release
the lease. There is no automatic timeout or takeover. A lost release response
is ambiguous and requires reading broker state. Reconcile the exact recorded
plan, outstanding cloud operations, and current Deny and hierarchy state before
manually resolving the retained lease. Starting another apply is not recovery.

The coordination record covers both quarantine and restoration shards until
their terminal evidence has been projected. Legacy coordination records without
that coverage marker are refused. A pre-activation test ledger must be reconciled
or replaced with an empty test ledger before using this protocol; an existing
production ledger requires a separately reviewed complete shard migration.

The final reread detects changes in sampled resource versions. It does not
prove the absence of an independent writer or atomicity across resources.
[Resource Manager documents project etags and update times](https://docs.cloud.google.com/resource-manager/reference/rest/v3/projects).

## Local verification

`tools/ci/protected-recovery-graph-test.sh` inspects Terraform's real dependency
graph. The enabled mock-provider tests cover admission refusals. The controller
tests cover saved-plan byte changes, missing or changed leases, failed applies,
and final readback failures. These checks do not establish live credential
exclusivity, Google API propagation, or production activation.
