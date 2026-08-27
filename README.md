# platform

Reusable Bun, GitOps, and Google Cloud Run platform for Collin Bentley projects.

This repository is the source of truth for the operational pattern shared by the
`critical-history`, `healthmcp`, `cdbentley`, and `runsetta` applications:

- Pure Bun application verification, Bun 1.4 native (stable pins, no canary fallbacks).
- Socket Firewall dependency checks.
- Seven-day minimum package-release age for new resolutions.
- Final-image SBOM generation and a fail-closed Grype gate using a reviewed,
  checksum-qualified database snapshot.
- Checkov and Terraform validation.
- GitHub Actions Workload Identity Federation into Google Cloud.
- Docker Hardened Images and immutable Artifact Registry tags.
- Cloud Run production and pull request preview deployments.
- Cloud Run custom-domain lifecycle guardrails.

The app repositories stay independent and keep their source code, content, and
runtime-secret values. This repository owns the repeated delivery mechanics and
the exact project-specific Terraform deployment maps used by authenticated
pipelines; consumer Terraform files are validation/documentation mirrors only.

The staged IAM/WIF migration and its non-negotiable bootstrap prerequisite are
documented in [`docs/security-rollout.md`](docs/security-rollout.md).

## Repository Layout

```text
.github/workflows/          Reusable workflows consumed with workflow_call
terraform/modules/          Google Cloud platform modules
terraform/deployments/      Exact platform-owned bootstrap/production/exposure roots
templates/app/              Starter shape for a new Bun + Cloud Run app
tools/platform.ts           Bun CLI for doctor/scaffold helpers
```

## Use In An App

Pin app repositories to the full 40-character commit SHA of a reviewed platform
release. A semantic release such as `v0.5.0` remains useful for humans, but tags
are not an execution trust boundary.

```yaml
jobs:
  verify:
    name: Bun verify
    uses: collinbentley1/platform/.github/workflows/application.yml@0123456789abcdef0123456789abcdef01234567 # v0.5.0
```

Deploy callers forward no secrets and never use `secrets: inherit`. Preview is
controlled by a default-branch `pull_request_target` caller pinned to the exact
reviewed platform commit; the ordinary Application and Socket checks remain
head-bound `pull_request` workflows. The credentialed prefetch job does not
checkout or evaluate pull-request data. It alone enters
`dhi-base-prefetch-20260822-098dca9280b3`, whose selected-branch policy permits
only `main`, and receives the read-public-only
`DHI_PUBLIC_READ_TOKEN_20260822_098DCA9280B3` secret plus the non-confidential
`DHI_USERNAME` variable. Preview and production use this same environment and
the same immutable base-image digests.

Prefetch verifies the exact linux/amd64 DHI children, frozen Docker signatures,
signed SBOM/provenance/source records, license evidence, and complete OCI blob
closure before publishing a one-day raw artifact. The untrusted BuildKit job is
credentialless: no OIDC, packages permission, runtime secret, registry token, or
host execution of pull-request code. It checks out the exact same-repository PR
head only inside the bounded build lane and consumes the verified bases as fixed
local OCI contexts. A fresh credentialless verifier closes and canonicalizes the
result, runs Syft and Grype in a networkless read-only container sandbox, and
proves the final runtime layer/config lineage. A separate publisher revalidates
the canonical graph without extracting its layers before using its exact WIF
identity. No raw DHI credential or unreviewed OCI archive crosses that boundary.
The vendored Docker DHI public key is pinned to keyring commit
`d6b11e0475ac7ddf74687268d16a4201a15e163f` and SHA-256
`1d02bbccf149283ae6288d96264dcad3fb23ee1911d90324a48eab28e4cb8a5f`;
the catalog license is pinned to commit
`140f79eaba13b83e280f6f554f80f9633fae987e` and SHA-256
`58881e3f5171ed2e98db7a4dbd64c16b9b5dbb2f5cbd9a56e79608a2360ad5f3`.

The resulting runtime is deliberately described as a hybrid: the immutable DHI
Community Bun image supplies the signed hardened Alpine rootfs and exact layer,
history, and configuration prefix, while the Dockerfile overlays the separately
digest-bound Oven Bun 1.4.0+34cbb binary. The final image advertises
`BUN_VERSION=1.4.0` and immutable OCI base name/digest labels; the DHI signature
does not attest the overlaid Oven binary. Preview and production are required to
use byte-identical base contexts and exporter/provenance settings, though their
application source and final image digest naturally differ.

That requirement is enforced against the workload actually serving traffic,
not merely against two build configurations. Preview admission reads the exact
untagged, 100%-served production revision, binds both its outer OCI index and
Cloud Run's runnable child digest, and verifies the live provenance graph
against the reviewed DHI closure. New revisions are staged with no traffic; an
already admitted service may remain open while those unrouted revisions are
proved. A strongly consistent transition marker excludes a concurrent DHI
epoch change, and one exact-etag transaction routes only the fully proved graph.
Its default route is a secretless 404 baseline with the proved production DHI
lineage, and every `pr-N` revision is checked for the same DHI lineage, no-data
runtime configuration, and current pull-request head. A service that began
sealed opens only after the final proof. Production deployment likewise refuses
to cross a DHI lineage boundary while any tagged preview is routable.

Each preview revision records the exact 40-hex platform workflow commit. A
consumer `main` push runs reconciliation immediately (with the hourly schedule
as a backstop) and removes every preview tag whose revision lacks that commit or
names an older one. Consequently, a platform-pin change cannot leave an active
preview on a different DHI contract: even if the corresponding production
deployment fails, the old preview is made unavailable rather than presented as
production parity.

Cleanup and reconciliation remove only the intended tag while preserving other
fully admitted routes. A zero-tag service, an unknown exposure state, or an
ambiguous survivor proof is sealed to internal-only ingress with invoker IAM
checks enabled. Release rollouts therefore deploy production first and create
fresh previews only after the new production image has passed live parity.

Socket scanning is credential-free. The local scanner enforces the public
policy, and the `Socket Firewall` check additionally requires the exact
successful checks produced by Socket GitHub App id `156372`. No Socket token or
`dependency-scan` environment is part of the platform contract.

Application runtime secret names and grants are encoded in this repository's
immutable numeric-repository-ID map; repository variables and deploy callers
cannot add or redirect them. Medlock/Health has no GitHub keyset secret. Its
trusted production deploy either reuses the exact numeric Secret Manager version
already bound to Cloud Run or, only when no binding and no enabled version exist,
generates a new key directly into `waitlist-identity-keyset`. The deploy identity
can add and inspect version metadata but cannot read payloads; Cloud Run is bound
to the returned positive numeric version. Mutable aliases such as `latest` are
forbidden, and the payload never enters GitHub, Terraform state, an image layer,
or Cloud Run's literal environment configuration.
Runsetta is deliberately offline, its old secret containers are retained for
recovery, and its runtime service account has no accessor grant. Critical
History's `MAPBOX_PUBLIC_TOKEN` is the narrow exception because the app returns
it to every browser. It is a non-default Mapbox public `pk.*` token, not a confidential
credential; the protected `preview-cloud` and `production` environments expose
it as the non-confidential `MAPBOX_PUBLIC_TOKEN` variable. Give the value only
the required public read scopes. Mapbox's default public token is forbidden
because its scopes and URL restrictions cannot be changed. The simplest
configuration reuses one value restricted to `https://ycriticalhistory.org`,
which Mapbox also permits on all subdomains, including every stable
`https://pr-N.preview.ycriticalhistory.org` origin. A separate preview value may
instead be restricted to `https://preview.ycriticalhistory.org`, but that is
one-way narrowing: the production parent still includes all of its subdomains.
Mapbox documents URL restrictions as best-effort abuse controls, not an
authorization boundary; never grant a browser token confidential scopes. Do not
enter wildcard syntax. The workflow validates the public format before mapping
it to the app's runtime name; Mapbox `sk.*` tokens are rejected. Do not use
`secrets: inherit` or add caller secret mappings. The canonical dependency-free
scanner rejects git, GitHub, remote-tarball, file, link, and workspace
resolutions; every allowed direct and transitive resolution must use the npm
registry with an exact version and sha512 integrity. Scanner diagnostics are
bounded and neutralized before GitHub parses re-emitted output. Runner command
parsing, Docker build records, summaries, annotations, and implicit GitHub-token
access are disabled across the complete PR-controlled build action.

Cloud publication and Cloud Run mutation use different protected environments
and identities. Secretless `production-publish` and `preview-publish` jobs can
impersonate only `gha-prod-publish` and `gha-preview-publish`; each publisher has
Writer on exactly one Artifact Registry repository and no Cloud Run or runtime
`actAs` access. `production` and `preview-cloud` use separate deploy identities
with the service-scoped Cloud Run role, `actAs` on only the matching runtime,
and Reader on only the matching image repository, as Cloud Run requires; they
cannot upload or delete artifacts. Medlock's production deploy identity alone
also has Secret Version Adder on exactly `waitlist-identity-keyset`; it cannot
read, list, disable, or destroy versions, and every other deploy identity has no
secret grant. `preview-operations` uses
the existing `gha-preview-deploy` identity through the distinct
`attribute.preview_operator_workflow_sha` WIF path. Cloud Run revalidates the
service identity and image during `gcloud run services update-traffic`, so the
API-minimum traffic operation requires the same service-scoped update,
preview-runtime `actAs`, and exact-preview-repository Reader permissions as a
deployment. Those coarse permissions could deploy a preview revision, so their
containment is the exact reviewed cleanup/reconcile workflow SHA,
`preview-operations` environment/event claims, immutable numeric-repository-ID
project/service map, fixed CLI arguments, and the absence of PR checkout or
PR-controlled code after authentication. No credential reaches the untrusted PR
build. `gha-preview-operator` is transition-only: the immediately previous SHA
may retain its old binding during repin, while the active SHA binds the distinct
operator-workflow attribute only to `gha-preview-deploy`; the transition set and
legacy fallback are empty at steady state. The retired operator receives no
steady-state Cloud Run, registry, runtime `actAs`, project, secret, state, data,
or production access. Protect both publish environments before pinning a
consumer to this workflow.

## Runtime Configuration

The platform never executes an app-owned script after cloud authentication and
never reads security-sensitive repository variables. Exact production and
preview environment values, permitted secret references, and the offline/data
mode for each app are selected by immutable numeric repository ID in reviewed
platform code. Every cloud flow must first exchange through its no-role exact-WIF
canary; there is no bypass switch or repository-variable preview enablement.

Preview secrets are authoritatively cleared on every deployment. Apps with
production data permissions must remain build-only until a preview-only runtime
service account is provisioned and the platform registry enables cloud preview.
The untrusted image build has no GitHub OIDC or packages permission and produces
only a one-day raw artifact. A separate verifier canonicalizes the image and a
separate publisher uploads the independently revalidated inner OCI index to
Artifact Registry by digest. The publish runner proves its own
environment-specific exact-SHA WIF binding before it exchanges for the
repository-scoped publisher identity.

Security-critical project, service, provider, and service-account values are
resolved from immutable numeric repository IDs inside the reviewed reusable
workflow; callers cannot redirect a deployment by changing workflow inputs.
Authenticated Terraform jobs likewise check out only the exact platform commit
and never execute consumer HCL, providers, lockfiles, caches, functions, or
outputs.

Critical History previews use one stable wildcard DNS namespace backed by a
dedicated global external HTTPS load balancer. The serverless NEG fixes the
backend service to `critical-history-preview` and derives only the Cloud Run
traffic tag from `<tag>.preview.ycriticalhistory.org`; the workflow is the sole
creator of `pr-N` tags. The preview service accepts external traffic only from
Cloud Load Balancing, so its generated `run.app` URLs cannot bypass the stable
origin. Each deployment receives a random non-confidential nonce, and `/livez`
must echo that exact value through the stable origin before the workflow reports
success; a failed or stale validation removes the tag only when it still targets
that run's exact revision. Closing or invalidating a pull request removes its tag
and makes the corresponding stable hostname stop routing without changing DNS
or load-balancer state.

The preview namespace is same-site with production. Critical History currently
has no authentication or cookies; that remains a security invariant. Before
adding either, use host-only `__Host-` cookies with explicit Origin/CSRF checks
and reject parent-domain cookies, or move previews to a separate registrable
domain. `SameSite` by itself does not isolate pull-request code on a sibling
subdomain.

## CLI

```sh
bun run platform doctor ../critical-history ../healthmcp
bun run platform scaffold my-new-app 0123456789abcdef0123456789abcdef01234567 123456789 ../my-new-app
```

`doctor` checks whether a repository is wired to the platform workflows,
whether its developer-facing verification commands have drifted, and whether it
contains the expected Bun, Docker, and Terraform contract files. Privileged CI
and Docker verification use the byte-matched platform runner with the
checksum-pinned Bun executable, not dependency-shadowable package-script
orchestration. Doctor also rejects committed Terraform state, saved plans,
variable/override files, CLI config, and crash logs.

## Release

Release `0.5.13` only after required checks and adversarial review. Create a
protected GitHub release tag for discovery, then copy the release commit SHA into
consumer workflow and Terraform references. Never move an existing release tag.
Refresh and review `tools/ci/grype-db.json` immediately before the release. After
platform CI imports and validates it, the credentialless verifier loads only
that byte-pinned file from the immutable platform policy archive; every
`GRYPE_DB_MANIFEST_JSON` or `DB_MANIFEST_JSON` override is forbidden. The
snapshot expires after 48 hours, so builds fail closed against stale data. A
refresh changes the platform commit and therefore requires a new reviewed
platform SHA, WIF authorization, and consumer repin. That sub-48-hour rollout
cadence is a release stop condition, not an acceptable steady-state update
mechanism; do not release once the snapshot is stale or if the complete repin
cannot finish inside its validity window.

```sh
gh release create v0.5.13 --target <reviewed-commit-sha> --generate-notes
```
