# platform

Reusable Bun, GitOps, and Google Cloud Run platform for Collin Bentley projects.

This repository is the source of truth for the operational pattern shared by the
`critical-history`, `medlock`, `cdbentley`, and `runsetta` applications:

- Pure Bun application verification.
- Socket Firewall dependency checks.
- Checkov and Terraform validation.
- GitHub Actions Workload Identity Federation into Google Cloud.
- Docker Hardened Images and immutable Artifact Registry tags.
- Cloud Run production and pull request preview deployments.
- Cloud Run custom-domain lifecycle guardrails.

The app repositories stay independent. They keep their source code, content,
domains, secrets, and project-specific Terraform variables. This repository owns
the repeated platform mechanics.

## Repository Layout

```text
.github/workflows/          Reusable workflows consumed with workflow_call
terraform/modules/          Google Cloud platform modules
templates/app/              Starter shape for a new Bun + Cloud Run app
tools/platform.ts           Bun CLI for doctor/scaffold helpers
```

## Use In An App

Pin app repositories to a tagged platform release.

```yaml
jobs:
  verify:
    name: Bun verify
    uses: collinbentley1/platform/.github/workflows/application.yml@v0.1.0
    with:
      bun-version: canary
      verify-command: bun run verify
```

Deploy workflows should use `secrets: inherit` so the shared workflow can read
Docker Hardened Images credentials and app-specific deployment secrets.

## Runtime Flags

Apps that need Cloud Run runtime flags can add a script and pass its path to the
deploy workflow:

```sh
.github/platform/runtime-config.sh
```

The script must append one line to `$GITHUB_OUTPUT`:

```sh
echo "flags=--set-env-vars=EXAMPLE=value" >> "$GITHUB_OUTPUT"
```

The workflow exposes these environment variables to the script:

- `PLATFORM_DEPLOY_ENVIRONMENT`: `production` or `preview`
- `PLATFORM_PREVIEW_NUMBER`: pull request number for preview deploys
- `PROJECT_ID`, `REGION`, `SERVICE_NAME`

## CLI

```sh
bun run platform doctor ../critical-history ../medlock
bun run platform scaffold my-new-app ../my-new-app
```

`doctor` checks whether a repository is wired to the platform workflows and
contains the expected Bun, Docker, and Terraform contract files.

## Release

Create a tag for app repositories to pin:

```sh
git tag v0.1.0
git push origin main v0.1.0
```
