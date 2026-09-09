# Initial Virtual Care MCP enrollment

This owner-operated root creates the first bootstrap resources for repository
`collinbentley1/virtual-care-mcp`, numeric ID `1362801465`, in the standalone
Google Cloud project `virtual-care-mcp`, number `894875537243`. It has no project,
repository, or service selector. The only input is the exact reviewed platform
commit. It keeps federation disabled throughout initial enrollment.

This root uses local state because its apply creates the remote state buckets.
It retains the same `module.bootstrap` resource addresses as the registered
`terraform/deployments/bootstrap` root. After migration, the registered root
owns the state. Never apply both roots against separate states.

## Before an apply

Use a clean, isolated checkout of the reviewed platform commit. Keep all state,
plans, Terraform data directories, and credentials outside any public checkout,
with owner-only permissions. Reject inherited `TF_CLI_ARGS*`, `TF_WORKSPACE`,
provider overrides, local override files, and an existing unmanaged local state.
Use the reviewed Terraform version and provider lock. An existing state is a
resume operation that requires inspecting its lineage and resources first.

Verify the owner identity, numeric GitHub repository ID, numeric project number,
active billing, and absence of an organization parent through the live APIs.
Require the new repository's Actions to remain disabled and no running jobs.
Before the first apply, verify no existing WIF pool, state bucket, deployment
identity, or Cloud Run service collides with this new enrollment. Never import
an unexplained existing resource or change an existing consumer.

The owner reviews the saved plan at the exact source commit. It may address
only `virtual-care-mcp` and the fixed new-app bucket names. The WIF pool must be
disabled, runtime secrets absent, the preview runtime without a data role, and
the preview IAM auditor bound only inside this new project. The initial root
does not create a Cloud Run service or execute app code.

## State transfer and production provisioning

After the reviewed initial apply succeeds:

1. Inspect the owner-only local state. Record its lineage, serial, resource
   addresses, exact project, and a digest without publishing its contents.
2. Copy the exact registered bootstrap root from the same platform commit into
   a fresh owner-only working directory. Preserve relative module sources.
   Transfer the local state, then run `terraform init -migrate-state` using the
   fixed backend bucket `virtual-care-mcp-tfstate-bootstrap` and prefix
   `virtual-care-mcp/bootstrap`. Verify the remote state matches the transferred
   lineage, serial, and resource addresses before retiring the local copy.
3. Run the registered bootstrap root with `repository_id = "1362801465"`, the
   same `active_workflow_sha`, `legacy_compatibility_mode = false`, an empty
   transition SHA, and `federation_quarantined = true`. Require a no-change plan.
4. Initialize the registered production root with bucket
   `virtual-care-mcp-tfstate`, prefix `virtual-care-mcp/prod`, and repository ID
   `1362801465`. Review and apply its exact new-project plan through the same
   owner-operated, reviewed platform checkout. This creates the separated
   registries, bootstrap services, Firestore database, and visits TTL policy.
   The bootstrap Cloud Run revision uses the no-role bootstrap service account.
5. Verify the new project's effective IAM, state ownership, Firestore TTL,
   runtime separation, and absence of direct project Editor bindings. The
   new project's preview audit cohort contains only this project. Legacy
   consumer auditor memberships and recovery groups remain unchanged.

## Activation is separate

Configure and verify the new repository's required checks and protected
environments before enabling any Actions. Production and production publication
require the owner reviewer with no administrator bypass. Do not auto-create
the DHI credential environment by running a workflow. Its empty-environment
canary and secret setup follow the existing app contract.

After the owner reviews the exact registration and app commits, plan the single
new-project bootstrap change that sets `federation_quarantined = false`. Require
the active SHA to equal every new-app caller and module pin. Apply only that
reviewed change, verify the provider condition and exact role bindings, then
enable the new repository's reviewed workflow policy. Each protected workflow
still performs its no-role WIF canary before its operational exchange.

The legacy protected bootstrap bridge and its four-project recovery group are
not part of this process. Its `PRODUCTION_APPLY_ENABLED` setting remains false.
No recovery receipt, existing-consumer pin, or prior app deployment authorizes
the new app's first activation.
