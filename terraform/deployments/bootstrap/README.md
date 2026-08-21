# Trusted bootstrap deployment root

Any future owner-credentialed bootstrap pipeline must check out and execute this directory
from an exact reviewed `platform` commit. It must never check out or execute consumer
Terraform, provider configuration, lockfiles, caches, functions, or outputs.

The pipeline supplies the immutable numeric repository ID, reviewed target platform SHA,
optional immediately previous safe transition SHA, owner-approved migration phase, and a
reviewed backend bucket/prefix. Those values must come from protected owner-reviewed pipeline
inputs, never consumer repository variables. Initial and existing-state migration sequencing
is documented in `docs/security-rollout.md`.
