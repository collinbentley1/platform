# App Contract

An app repository owns product code and product configuration. The platform owns
the repeated delivery mechanics.

## Required Files

- `.platform/config.json`
- `.github/workflows/application.yml`
- `.github/workflows/socket-firewall.yml`
- `.github/workflows/infrastructure.yml`
- `.github/workflows/deploy-prod.yml`
- `.github/workflows/deploy-preview.yml`
- `.github/workflows/cleanup-preview.yml`
- `.github/workflows/reconcile-previews.yml`
- `Dockerfile`
- `bunfig.toml`
- `bun.lock`
- `package.json`
- `.gitignore`
- `infra/terraform/bootstrap`
- `infra/terraform/prod`

## GitHub Configuration

The app repository should use branch protection on `main` with pull requests
required and these required checks:

- `Bun verify`
- `Terraform validate`
- `Checkov`
- `Socket Firewall`
- a final-image Grype gate whose checksum-qualified database identity comes only
  from the `GRYPE_DB_MANIFEST_JSON` secret on the owner-approved build
  environment and
  expires closed after 48 hours
- the canonical Bun policy, which disables automatic env loading and holds newly
  published package versions for seven days before they may be resolved

Apps can add project-specific checks such as `Swift package check`.

The platform binds the application policy to the immutable numeric repository
ID from the GitHub event. For the four managed apps it requires exact
platform-reviewed `format:check`, `lint`, `typecheck`, `test`, and `build`
commands and this developer-facing composition:

```text
verify = bun ci --no-env-file --ignore-scripts --registry=https://registry.npmjs.org && bun --no-env-file run verify:ci
verify:ci = bun run format:check && bun run lint && bun run typecheck && bun run test && bun run build
```

Implicit `pre*` and `post*` hooks for those commands are forbidden. A pull
request cannot replace a required check with `true` while retaining the expected
job name. CI and the canonical Dockerfile do not execute those package scripts:
the checksum-pinned Bun binary runs each reviewed entrypoint sequentially through
the trusted platform runner, rejects dependency-installed `bun` shims, and calls
the pinned TypeScript entrypoint by its exact installed path. The package scripts
are developer-facing parity, not the privileged verification boundary.

All reusable workflows and Terraform modules must use the same full platform
commit SHA. Deploy callers pass no secrets and must never use `secrets: inherit`.
The `preview-build` and `production-build` environments contain only the DHI
registry credentials, an admin-visible `packages:list`-only Socket policy token,
and the reviewed, non-confidential Grype database manifest stored as an
environment secret for integrity. Only the platform repository's owner-approved
`dependency-scan` environment contains the same Socket token for trusted-main
verification; consumer duplicate checks remain credential-free. Runtime secrets
stay in `production`.
The secretless `production-publish` and `preview-publish` environments are
separate approval and OIDC claim boundaries. Their publisher identities have
Writer on only the matching Artifact Registry repository, no Cloud Run role,
and no runtime-service-account `actAs`. The `production` and `preview-cloud`
deploy identities can update only the pre-created matching Cloud Run service,
`actAs` only as its matching runtime, and read only its exact image repository;
they cannot upload or delete registry artifacts. The `preview-operations`
operator can read and update only the shared preview service and has no Artifact
Registry or runtime `actAs` grant. A stale-deploy invalidation rechecks the
current traffic tag under the shared cloud lock and removes it only when it
still points to the exact revision created by that stale run.
The platform repository is the trust root, so its pull-request job always scans
without that key and the authenticated organization policy runs only from trusted
`main`; a platform PR can change the workflow and package-manager configuration.
Production environments accept only protected `main`. `preview-publish` and
`preview-cloud` require owner approval before an untrusted image can cross first
the service-scoped preview repository and then the no-data preview runtime
boundary.
External-fork and Dependabot pull requests never receive environment secrets and
cannot build or deploy a cloud preview. All application/firewall verification and
Docker dependency installs use Socket's public mode. Organization policy is
mandatory exactly once before package extraction in every same-repository preview
build and production-main build. The canonical dependency-free scanner is an
immutable app-contract file, rejects more than 128 lock packages before any
request, uses the org-scoped batch endpoint, and validates complete fail-closed
NDJSON results. Because Bun 1.4 omits git, GitHub, remote-tarball, file, link,
and workspace resolutions from its scanner payload, the pre-token contract
forbids those sources in both direct specifications and transitive lock entries.
Every allowed lock entry must be a canonical exact-version npm resolution with
sha512 integrity; exact `npm:` aliases are allowed only when their resolved lock
entry satisfies that same registry shape. Remote alert text is length/control
bounded and captured dependency-tool output is re-emitted only while GitHub
workflow-command parsing is disabled with a fresh random marker. The token never
enters BuildKit or an image layer. The same parser boundary spans the complete
Docker build action because pull-request tests and build code can write arbitrary
stdout from inside BuildKit. Its random resume token stays in a mode-0600 runner
temporary file that is neither an action input nor a build argument/secret, and
an unconditional following step restores command parsing even when the build
fails. Docker's default build-record artifact upload is disabled; the explicitly
identified, content-digested SBOM remains the build job's only artifact.

## Runtime Configuration

Product-specific runtime configuration is an immutable numeric-repository-ID map
in the reviewed platform workflow and Terraform root. Repository variables cannot
add environment values, Secret Manager mappings, or enable cloud deployment.
Pull request code is never executed on the runner after Google authentication,
and preview deployments use an identity with no production data access. A future
runtime secret mapping must name a positive numeric Secret Manager version in
platform code; mutable aliases such as `latest` are forbidden. Declaring a secret
container does not grant its payload to a runtime: `runtime_secret_accessor_ids`
defaults to empty and must be a subset of the retained containers. Runsetta stays
offline with no runtime accessor grants until reviewed versions are encoded.

The sole client-token exception is Critical History's `MAPBOX_PUBLIC_TOKEN`.
Because every browser receives it, this is public configuration rather than a
confidential credential. The owner-approved `preview-cloud` and `production`
environments nevertheless carry it in their `MAPBOX_PUBLIC_TOKEN` secret slots
so release approval and log masking stay fail closed. Use public `pk.*` tokens
with only the needed read scopes, never an `sk.*` token. One value restricted to
`https://ycriticalhistory.org` may be reused in both slots because Mapbox also
permits it on every subdomain. If separate values are desired, restrict the
preview value to `https://preview.ycriticalhistory.org`, which covers every
`https://pr-N.preview.ycriticalhistory.org` origin without a wildcard character.
This does not isolate the production value from preview subdomains, and Mapbox
URL restrictions are a best-effort abuse control rather than authorization.
Every cloud flow unconditionally proves its exact workflow-SHA binding through
the no-role canary before authenticating its operational identity.

Critical History is the only app with a stable preview namespace. A dedicated
global external HTTPS load balancer terminates the wildcard certificate and a
serverless NEG fixes the Cloud Run service to `critical-history-preview` while
extracting only `<tag>` from `<tag>.preview.ycriticalhistory.org`. The workflow
maps numeric pull request `N` to tag `pr-N`; callers cannot supply the host,
service, or tag. Its preview service ingress is
`internal-and-cloud-load-balancing`, which blocks direct public `run.app`
bypass. Preview deployments add a random non-confidential
`PLATFORM_DEPLOY_NONCE`; `/livez` must echo it as `deployment` only when the
variable is present. The workflow bounds the response and verifies that exact
nonce through the stable URL, so a stale prior revision cannot satisfy readiness.
Any post-mutation failure compare-and-removes the tag only if it still targets
that run's exact revision. Removing the tag during invalidation, cleanup, or
reconciliation makes the hostname unroutable without per-pull-request DNS
changes.

These preview hosts are same-site with production under `ycriticalhistory.org`.
That is safe only while Critical History has no authentication or cookies. If
either is introduced, use host-only `__Host-` cookies plus explicit Origin and
CSRF validation, and reject every parent-domain cookie; otherwise move previews
to a separate registrable domain before shipping the feature. `SameSite` alone
does not isolate arbitrary pull-request code on a sibling subdomain.

The consumer `infra/terraform` roots are reviewed mirrors for validation. Any
job holding Google credentials executes only the app configuration mapped by
immutable repository ID under `platform/terraform/deployments`; it never runs
consumer Terraform code.

Terraform working directories, state, saved plans, variable files, CLI config,
crash logs, and override files are forbidden in app commits and covered by the
required `.gitignore`. Provider lockfiles remain committed and reviewed.
