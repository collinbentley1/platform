# Trusted production deployment root

The routine production Terraform job checks out this directory from the exact
reusable-workflow commit and uses it only for a read-only convergence plan. The
owner-controlled protected pipeline applies the same exact root. Both select one
of the immutable numeric repository IDs above and never execute Terraform
configuration, providers, lockfiles, caches, functions, or outputs from the
consumer repository.

The workflow supplies the corresponding fixed GCS backend bucket and prefix. Changes to
an app's cloud resources therefore require review and release in `platform` before any
consumer pipeline can redirect them. Cloud Run domain mappings are deliberately
owned by the separately protected `terraform/deployments/exposure` root because
their legacy API has no no-data IAM viewer permission. The otherwise-unused
`google.no_attribution` alias remains only so Terraform can recognize and
relinquish historical state instances through the no-destroy `removed` block;
no configured resource in this root uses that provider alias.
