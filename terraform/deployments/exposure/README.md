# Trusted public-exposure deployment root

Only the owner-controlled protected pipeline may execute this directory, from an
exact reviewed `platform` commit. It owns the legacy Cloud Run domain-mapping API
resources because Google Cloud does not expose a no-data IAM viewer permission for
them. Routine GitHub Terraform must have no access to this root's state.

The protected pipeline supplies the immutable numeric repository ID and configures
the separately protected bootstrap-state bucket with a fixed `<app>/exposure`
prefix. Existing mappings must be imported into this root and verified before the
production root's no-destroy `removed` block is applied. See
`docs/security-rollout.md` for the migration order.
