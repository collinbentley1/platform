# Trusted public-exposure state

Only the owner-controlled protected pipeline may inspect this directory from an
exact reviewed `platform` commit. Routine GitHub Terraform has no access to its
state. Google Cloud exposes no no-data IAM viewer permission for the legacy
Domain Mapping API, so v0.5.13 implements one narrow exception: a confirmed,
Runsetta-only, controller-side state adoption. It has no Terraform exposure
apply route.

The controller proves the exact live `runsetta.com` and `www.runsetta.com`
mappings and HTTPS routes with the owner token, create-only writes a canonical
full serial-1 state with `ifGenerationMatch=0` when the fixed exposure object is
absent, immediately removes that exact owner Object Creator lease, and runs
Terraform only as `plan -refresh=false`. The plan must be non-applyable and show
exactly two no-op mapping resources, one exact relevant-attribute entry, three
exact no-op outputs, and no imports, drift, replacements, unknowns, or sensitive
data. Success writes one terminal `adoption-complete` receipt; no plan receipt,
consume marker, apply, or result exists. The exact idempotency, crash-recovery,
production-prerequisite, and rollout-order contracts are in
`docs/security-rollout.md`.

Critical History's stable wildcard preview load balancer, serverless NEG,
certificate, DNS authorization, and outputs remain represented here but cannot
be changed by the v0.5.13 Runsetta route. Existing cdbentley, Health/Medlock, and
Critical History exposure states must remain unchanged. Any exposure create,
update, delete, import, provider-state migration, or recovery requires a new
separately reviewed workflow expansion. Resource-level `prevent_destroy`, the
bridge's rejection of every non-no-op adoption plan, and the executor's lack of
Domain Mapping create/delete authority are the current defenses. The Runsetta
state deliberately retains provider `deletion_policy = "DELETE"`: changing it
to `PREVENT` is a separate state migration and must be reviewed before any
remote mutation authority is introduced.

Keep the
existing public preview ingress through the protected production apply: that
root installs the reviewed resources and IAM and records the expected
controller-open ingress, but deliberately ignores the preview service's live
`ingress` and `invoker_iam_disabled` fields. On the first new-workflow-SHA
production push, the serialized production epoch controller must durably seal
the zero-tag bootstrap to internal-only before deployment and replace it with a
sanitized production-DHI baseline. Only the subsequent reviewed tagged preview
may open load-balancer-only ingress, and it must be nonce-verified through the
stable frontend. The exact failure recovery and old-SHA trust-retention rules
are in the stable-preview rollback section of the rollout guide.
