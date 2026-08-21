# Trusted bootstrap deployment root

Any future owner-credentialed bootstrap pipeline must check out and execute this directory
from an exact reviewed `platform` commit. It must never check out or execute consumer
Terraform, provider configuration, lockfiles, caches, functions, or outputs.

The pipeline supplies the immutable numeric repository ID, reviewed target platform SHA,
optional immediately previous safe transition SHA, owner-approved migration phase, and a
reviewed backend bucket/prefix. Those values must come from protected owner-reviewed pipeline
inputs, never consumer repository variables. Initial and existing-state migration sequencing
is documented in `docs/security-rollout.md`.

The registered personal projects currently have no organization parent. Google permits
Organization Policy Administrator only at organization scope and does not support the policy
write permissions in project custom roles, so the trusted deployment root explicitly leaves
`manage_automatic_default_service_account_grants_policy = false`. The authoritative empty
project Editor binding remains mandatory, but it is convergence rather than real-time
prevention: after every protected service/API change, assert live that the Editor binding is
still empty. Enabling the policy requires a separate reviewed move into an organization and
an organization-scoped bootstrap identity; never emulate that authority with a service-agent
role or static key.
