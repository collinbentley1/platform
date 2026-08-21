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

Deploy callers pass no secrets. `DHI_USERNAME`, `DHI_ACCESS_TOKEN`, and the
least-scope `SOCKET_API_TOKEN` live only in the owner-approved `preview-build` and
`production-build` environments. The same Socket credential lives in the
owner-approved `dependency-scan` environment used by trusted-main dependency
checks. Platform pull requests themselves use Socket's secretless policy because
they control the platform workflow and dependency configuration; the organization
token is released only after merge on `main`.
Application runtime secret references must be positive numeric Google Secret
Manager versions encoded in this repository's immutable numeric-repository-ID
map; repository variables and deploy callers cannot add or redirect them.
Runsetta is deliberately offline, its old secret containers are retained for
recovery, and its runtime service account has no accessor grant. Critical
History's `MAPBOX_PUBLIC_TOKEN` is the narrow exception because the app returns
it to every browser. It is a Mapbox public `pk.*` token, not a confidential
credential; the owner-approved `preview-cloud` and `production` environments use
their `MAPBOX_PUBLIC_TOKEN` secret slots only as approval-gated configuration
channels. Give each value only the required public read scopes. The simplest
configuration reuses one value restricted to `https://ycriticalhistory.org`,
which Mapbox also permits on all subdomains, including every stable
`https://pr-N.preview.ycriticalhistory.org` origin. A separate preview value may
instead be restricted to `https://preview.ycriticalhistory.org`, but that is
one-way narrowing: the production parent still includes all of its subdomains.
Mapbox documents URL restrictions as best-effort abuse controls, not an
authorization boundary; never grant a browser token confidential scopes. Do not
enter wildcard syntax. The workflow validates the public format before mapping
it to the app's runtime name; Mapbox `sk.*` tokens are rejected. Do not use
`secrets: inherit` or add secret parameters to deploy callers.
The Socket token must be admin-visible only, grant only `packages:list`, and be
rotated and usage-audited on the same schedule as other CI credentials.

Cloud publication and Cloud Run mutation use different protected environments
and identities. Secretless `production-publish` and `preview-publish` jobs can
impersonate only `gha-prod-publish` and `gha-preview-publish`; each publisher has
Writer on exactly one Artifact Registry repository and no Cloud Run or runtime
`actAs` access. `production` and `preview-cloud` use separate deploy identities
with the service-scoped Cloud Run role, `actAs` on only the matching runtime,
and Reader on only the matching image repository, as Cloud Run requires; they
cannot upload or delete artifacts. `preview-operations` uses
`gha-preview-operator`, which has only service-scoped Cloud Run get/update and
operation-read permissions, with no registry or runtime `actAs` grant. Protect
both publish environments before pinning a consumer to this workflow.

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
The untrusted image build has no GitHub OIDC permission. It publishes by digest
to an isolated GHCR staging package only after its pinned BuildKit daemon is
destroyed; a separate runner copies the opaque manifest into Artifact Registry.
The publish runner proves its own environment-specific exact-SHA WIF binding
before it exchanges for the repository-scoped publisher identity.

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

Release `0.5.0` only after required checks and adversarial review. Create a
protected GitHub release tag for discovery, then copy the release commit SHA into
consumer workflow and Terraform references. Never move an existing release tag.
Refresh and review `tools/ci/grype-db.json` immediately before the release. After
platform CI imports and validates it, copy that exact one-line JSON object into
the `GRYPE_DB_MANIFEST_JSON` environment secret on both owner-approved build
environments. The manifest is not confidential; the secret context is an
owner-controlled integrity boundary that repository variables cannot override.
The snapshot expires after 48 hours, so builds fail closed against stale data. A
refresh changes both the checked-in manifest and its exact identity assertion in
`tools/lint.ts`; it must arrive through a reviewed PR, but it does not change the
WIF-authorized workflow SHA. Never place this value at repository scope.

```sh
gh release create v0.5.0 --target <reviewed-commit-sha> --generate-notes
```
