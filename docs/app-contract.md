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
- `Socket Security: Project Report` and, for pull requests, `Socket Security:
  Pull Request Alerts`, both owned by Socket GitHub App id `156372`
- the canonical Bun policy, which disables automatic env loading and holds newly
  published package versions for seven days before they may be resolved

The protected deployment controller performs the final-image Syft/Grype gate
with the checksum-qualified `tools/ci/grype-db.json` embedded in the immutable
platform policy archive; mutable repository, organization, and environment
manifest variables are forbidden. The database expires closed after 48 hours. The
`pull_request_target` controller is attached to the trusted base SHA and must not
be configured as a required head-SHA pull-request check.

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
commit SHA. Deploy callers forward no secrets and must never use
`secrets: inherit`. The preview caller uses the trusted default-branch
`pull_request_target` definition, restricts `branches` to `main`, and passes no
caller-controlled inputs. The reusable workflow verifies the immutable numeric
repository ID, exact base/head identities, same-repository numeric head repo ID,
base branch, event, and run attempt before any operation.

Only `prefetch-bases` enters
`dhi-base-prefetch-20260822-098dca9280b3`. That environment must select only
`main`, disable administrator bypass, and contain exactly the public-read-only
`DHI_PUBLIC_READ_TOKEN_20260822_098DCA9280B3` secret and non-confidential
`DHI_USERNAME` variable. Preview and production share it and use the same exact
DHI/Oven linux/amd64 child digests. The credentialed job checks out no app or PR
source, verifies frozen Docker signatures and subject-bound SBOM/provenance/
source/license evidence, erases authentication, and publishes only a one-day
closed public base artifact.

The untrusted BuildKit job has no OIDC, packages permission, runtime secret,
registry token, or host execution of app code. It consumes only literal local
OCI contexts and emits a raw OCI artifact. A fresh credentialless verifier
revalidates and canonicalizes the complete graph, proves the exact DHI runtime
layer/config/history lineage, and runs Syft/Grype in a networkless read-only
container sandbox using only the byte-pinned `tools/ci/grype-db.json` from the
exact platform SHA. Refreshing the 48-hour snapshot requires a new reviewed
platform SHA, WIF authorization, and consumer repin; that cadence is a release
stop condition rather than an acceptable steady-state updater. A separate
publisher downloads by exact artifact id/digest, revalidates the
canonical one-descriptor outer wrapper, published inner-index digest, runnable
digest, source, provenance, and base lineage without extracting layers, then
uses its exact WIF identity. No GHCR staging package or packages permission is
part of the contract.

The final runtime is an explicit hybrid: the immutable DHI Community image
supplies the signed hardened Alpine rootfs and exact compressed layers,
uncompressed diff-id history, and base configuration; the canonical Dockerfile
overlays the separately digest/provenance-bound Oven Bun 1.4.0+34cbb binary.
`BUN_VERSION=1.4.0` and immutable OCI base name/digest labels must describe this
truthfully. DHI's signature does not attest the overlaid Bun binary; the complete
hybrid is covered by the final scan. The vendored DHI key is pinned to keyring
commit `d6b11e0475ac7ddf74687268d16a4201a15e163f` and SHA-256
`1d02bbccf149283ae6288d96264dcad3fb23ee1911d90324a48eab28e4cb8a5f`;
the catalog license is pinned to commit
`140f79eaba13b83e280f6f554f80f9633fae987e` and SHA-256
`58881e3f5171ed2e98db7a4dbd64c16b9b5dbb2f5cbd9a56e79608a2360ad5f3`.

Preview app source, app layers, and final image digest may differ from
production; the exact DHI development/runtime top-level and linux/amd64 child
identities may not. Every preview revision must carry the full platform workflow
commit. A consumer `main` push invokes reconciliation immediately, in addition
to the hourly backstop, and removes traffic from a revision with a stale or
missing commit label. If the matching production rollout fails, the old preview
is unavailable rather than falsely retained as a parity preview.

Preview admission proves this against the exact image currently serving 100%
of untagged production traffic. It verifies the remote outer OCI index and the
runnable child selected by Cloud Run, stages a secretless 404 default route,
and validates every tagged revision's immutable OCI graph and no-data runtime
configuration before any staged revision receives traffic. An already admitted
service may remain open while new revisions are unrouted; the durable transition
marker and final exact-etag traffic transaction, rather than staging itself,
form the privileged admission boundary. A service that began sealed opens only
after the final re-bracketed proof. A production transition is rejected while
any routable preview has a different or unknown DHI lineage.
Cleanup and reconciliation preserve proven sibling tags, but seal zero-tag or
ambiguous service states. Rollouts must deploy production before publishing
fresh previews for a new platform pin.

Socket is credential-free: the local public-policy scanner is byte-bound to the
platform, and `Socket Firewall` requires the exact successful checks from Socket
GitHub App id `156372`. No Socket token or `dependency-scan` environment exists.
Medlock/Health has no GitHub signing-key secret. Production reuses the one exact
numeric `waitlist-identity-keyset` version already bound to Cloud Run, or creates
one directly in Secret Manager only when both the binding and enabled-version
inventory are empty. Foreign, malformed, multiple, or unbound existing versions
fail closed.

The secretless `production-publish` and `preview-publish` environments are
separate OIDC claim boundaries. Their publisher identities have
Writer on only the matching Artifact Registry repository, no Cloud Run role,
and no runtime-service-account `actAs`. The `production` and `preview-cloud`
deploy identities can update only the pre-created matching Cloud Run service,
`actAs` only as its matching runtime, and read only its exact image repository;
they cannot upload or delete registry artifacts. Medlock's production deployer
alone may add a version to exactly `waitlist-identity-keyset`; it cannot read,
list, disable, or destroy versions, and all other deployers have zero Secret
Manager grants. The `preview-operations`
workflows authenticate `gha-preview-deploy` through the distinct
`attribute.preview_operator_workflow_sha` claim path. Cloud Run revalidates the
attached service identity and image during `update-traffic`, so the API-minimum
traffic operation requires the same exact-service update, preview-runtime
`actAs`, and exact-preview-repository Reader grants as deployment. Because that
underlying capability is coarse, only the exact reviewed cleanup/reconcile
workflow SHA can exchange it; environment and event claims, the immutable
numeric-repository-ID project/service map, fixed CLI arguments, and no PR
checkout or PR-controlled code after authentication contain it. No credential
reaches the untrusted PR build. The previous SHA may retain its old
`gha-preview-operator` binding only during repin; active/new SHA trust targets
`gha-preview-deploy`, and the transition set is empty at steady state. The
retired operator has no steady-state service, registry, runtime `actAs`, project,
secret, state, data, or production access. A stale-deploy invalidation rechecks
the current traffic tag under the shared cloud lock and removes it only when it
still points to the exact full-SHA/repository-ID-labelled revision created by
that stale run.

`dhi-base-prefetch-20260822-098dca9280b3`, `preview-publish`,
`preview-cloud`, `preview-operations`, and `supply-chain` select only `main`,
have zero reviewers, and disable administrator bypass. `production` and
`production-publish` select only `main`, require the owner reviewer, and disable
administrator bypass. The DHI environment must be explicitly created empty,
REST-verified, entered by a credentialless exact-SHA trusted-base canary, and
proven inaccessible to an ordinary PR-authored workflow before its token is
populated. Never let a workflow reference auto-create an unprotected
environment.

External-fork, Dependabot, draft, and non-main-target pull requests cannot enter
the preview controller. All application/firewall verification and Docker
dependency installs use Socket's public mode. The canonical dependency-free
scanner is an immutable app-contract file. Because Bun 1.4 omits git, GitHub,
remote-tarball, file, link, and workspace resolutions from its scanner payload,
the contract forbids those sources in both direct specifications and transitive
lock entries.
Every allowed lock entry must be a canonical exact-version npm resolution with
sha512 integrity; exact `npm:` aliases are allowed only when their resolved lock
entry satisfies that same registry shape. Captured dependency/build output is
re-emitted only while GitHub workflow-command parsing is disabled with a fresh
random marker. Docker's build-record upload, summary, checks annotations, and
implicit GitHub token are disabled. The raw application OCI artifact is treated
as hostile; only the independently canonicalized image artifact can reach the
publisher, and the signed SBOM/provenance outputs remain separately
content-digested evidence.

## Runtime Configuration

Product-specific runtime configuration is an immutable numeric-repository-ID map
in the reviewed platform workflow and Terraform root. Repository variables cannot
add environment values, Secret Manager mappings, or enable cloud deployment.
Pull request code is never executed on the runner after Google authentication,
and preview deployments use an identity with no production data access. Runtime
secret mappings must use positive numeric Secret Manager versions; mutable aliases
such as `latest` are forbidden. Medlock's secret name and both least-privilege
grants are fixed in the repository-ID map. Its trusted production deploy reuses
the one exact numeric version currently bound to Cloud Run. Only when no binding
and no enabled version exist may it generate a key directly into Secret Manager,
validate the returned resource name, and pass that numeric version reference to
Cloud Run. It rejects foreign/malformed/multiple entries and never reads a key
payload.
Declaring a secret container grants no payload access: both `runtime_secret_accessor_ids` and
`runtime_secret_version_adder_ids` default to empty and must be subsets of the
retained containers. Runsetta stays offline with no runtime accessor or version-
adder grants.

The sole client-token exception is Critical History's `MAPBOX_PUBLIC_TOKEN`.
Because every browser receives it, this is public configuration rather than a
confidential credential. The protected `preview-cloud` and `production`
environments carry it as the non-confidential `MAPBOX_PUBLIC_TOKEN` variable.
Use a non-default public `pk.*` token with only the needed read scopes, never an
`sk.*` token. Mapbox's default public token is forbidden because its scopes and
URL restrictions cannot be changed. One value restricted to
`https://ycriticalhistory.org` may be reused in both environments because Mapbox also
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
