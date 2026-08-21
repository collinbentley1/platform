# Trusted public-exposure deployment root

Only the owner-controlled protected pipeline may execute this directory, from an
exact reviewed `platform` commit. It owns the legacy Cloud Run domain-mapping API
resources because Google Cloud does not expose a no-data IAM viewer permission for
them. For Critical History it also owns the stable wildcard preview load balancer,
serverless NEG, certificate, and DNS-authorization outputs. Routine GitHub
Terraform must have no access to this root's state.

The protected pipeline supplies the immutable numeric repository ID and configures
the separately protected bootstrap-state bucket with a fixed `<app>/exposure`
prefix. Existing mappings must be imported into this root and verified before the
production root's no-destroy `removed` block is applied. See
`docs/security-rollout.md` for the migration order. The Critical History preview
records must be copied exactly from `preview_domain_dns_records` into the
authoritative DNS zone as DNS-only records; no pull-request workflow mutates this
root or DNS. After the preview frontend exists, never apply an older platform
exposure root that omits it. Every protected plan must show zero destroys;
resource-level `prevent_destroy` and provider-level `deletion_policy = "PREVENT"`
are defense in depth, not substitutes for reviewing the saved plan. Keep the
existing public preview ingress until a new-workflow-SHA tagged revision is
nonce-verified through the stable frontend; only then converge the restricted
ingress through the protected production root. The exact failure recovery and
old-SHA trust-retention rules are in the stable-preview rollback section of the
rollout guide.
