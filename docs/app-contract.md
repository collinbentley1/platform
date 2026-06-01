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
- `Dockerfile`
- `bunfig.toml`
- `package.json`
- `infra/terraform/bootstrap`
- `infra/terraform/prod`

## GitHub Configuration

The app repository should use branch protection on `main` with pull requests
required and these required checks:

- `Bun verify`
- `Terraform validate`
- `Checkov`
- `Socket Firewall`

Apps can add project-specific checks such as `Swift package check`.

## Runtime Configuration

Use `.github/platform/runtime-config.sh` when an app needs Cloud Run deploy
flags that are not universal. Keep product-specific secrets and env decisions in
the app repo, but keep image build and deploy behavior in the shared workflow.
