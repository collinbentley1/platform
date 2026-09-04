import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { chmod, cp, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  type SecretContextReference,
  semanticSecretContextReferences,
} from "../tools/ci/workflow-secret-contract";

const repoRoot = resolve(import.meta.dir, "..");
const cli = join(repoRoot, "tools/platform.ts");
const platformSha = "a".repeat(40);
const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("platform scaffold and doctor", () => {
  test("every runner-backed workflow job has a bounded timeout", async () => {
    const workflowDirectories = [
      join(repoRoot, ".github/workflows"),
      join(repoRoot, "templates/app/.github/workflows"),
    ];
    const runnerJobs: string[] = [];
    let protectedOwnerTimeout: number | undefined;
    let protectedRecoveryTimeout: number | undefined;

    for (const directory of workflowDirectories) {
      for (const entry of (await readdir(directory)).sort()) {
        if (!entry.endsWith(".yml")) continue;
        const workflow = Bun.YAML.parse(await readFile(join(directory, entry), "utf8")) as {
          jobs?: Record<string, Record<string, unknown>>;
        };
        for (const [jobName, job] of Object.entries(workflow.jobs ?? {})) {
          if (job["runs-on"] === undefined) continue;
          runnerJobs.push(`${entry}:${jobName}`);
          const timeout = job["timeout-minutes"];
          expect(Number.isInteger(timeout), `${entry}:${jobName} must declare an integer timeout`).toBe(
            true,
          );
          expect(timeout as number, `${entry}:${jobName} timeout must be positive`).toBeGreaterThan(0);
          const protectedOwner = entry === "protected-bootstrap-implementation.yml" &&
            jobName === "owner-terraform";
          if (protectedOwner) protectedOwnerTimeout = timeout as number;
          if (
            entry === "protected-bootstrap-implementation.yml" &&
            jobName === "owner-terraform-recovery"
          ) {
            protectedRecoveryTimeout = timeout as number;
          }
          const maximumTimeout = entry === "deploy-prod.yml" && jobName === "deploy"
            ? 60
            : protectedOwner ? 43 : 35;
          expect(
            timeout as number,
            `${entry}:${jobName} timeout must not exceed ${maximumTimeout} minutes`,
          ).toBeLessThanOrEqual(maximumTimeout);
        }
      }
    }

    expect(runnerJobs.length).toBeGreaterThan(0);
    // These mirror JOB_TIMEOUT_MINUTES and the recovery job budget in
    // tools/ci/protected-bootstrap-bridge.ts, which is the source of truth --
    // the bridge computes the envelope and the workflow is written from it.
    // They are asserted here as well so a change to the envelope has to be made
    // deliberately in both places rather than drifting silently.
    expect(protectedOwnerTimeout).toBe(42);
    expect(protectedRecoveryTimeout).toBe(17);
    expect(protectedRecoveryTimeout).toBeLessThanOrEqual(35);
  });

  test("scaffold replaces identity and pins every consumer", async () => {
    const app = await scaffold("secure-app");
    const config = JSON.parse(await readFile(join(app, ".platform/config.json"), "utf8")) as {
      githubRepositoryId: string;
      name: string;
      projectId: string;
      serviceName: string;
    };

    expect(config).toMatchObject({
      name: "secure-app",
      githubRepositoryId: "123456789",
      projectId: "secure-app",
      serviceName: "secure-app",
    });
    const bootstrap = await readFile(join(app, "infra/terraform/bootstrap/main.tf"), "utf8");
    expect(bootstrap).toContain(
      "manage_automatic_default_service_account_grants_policy = var.manage_automatic_default_service_account_grants_policy",
    );
    expect(bootstrap).toContain(`active_workflow_sha         = "${platformSha}"`);
    expect(bootstrap).not.toContain("transition_workflow_sha");
    expect(await readFile(join(app, "infra/terraform/bootstrap/variables.tf"), "utf8")).toContain(
      'variable "manage_automatic_default_service_account_grants_policy"',
    );
    expect((await run(["doctor", app])).exitCode).toBe(0);
  });

  test("doctor rejects a mutable workflow ref even beside a SHA-looking comment", async () => {
    const app = await scaffold("mutable-workflow");
    const path = join(app, ".github/workflows/deploy-prod.yml");
    const original = await readFile(path, "utf8");
    await writeFile(
      path,
      original.replace(
        `deploy-prod.yml@${platformSha}`,
        `deploy-prod.yml@v0.5.0 # ${platformSha}`,
      ),
    );

    const result = await run(["doctor", app]);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("uses non-immutable platform ref v0.5.0");
  });

  test("doctor binds the orchestrated infrastructure call to the production pin", async () => {
    const app = await scaffold("orchestration-drift");
    const path = join(app, ".github/workflows/deploy-prod.yml");
    const original = await readFile(path, "utf8");
    await writeFile(
      path,
      original.replace(`infrastructure.yml@${platformSha}`, `infrastructure.yml@${"b".repeat(40)}`),
    );

    const result = await run(["doctor", app]);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("platform version drift");
  });

  test("infrastructure caller grants the OIDC ceiling required by convergence", async () => {
    const caller = await readFile(
      join(repoRoot, "templates/app/.github/workflows/infrastructure.yml"),
      "utf8",
    );
    expect(caller).toContain(
      "permissions:\n      contents: read\n      id-token: write # Permission ceiling for the main-only convergence job in the trusted reusable workflow.",
    );

    const reusable = await readFile(
      join(repoRoot, ".github/workflows/infrastructure.yml"),
      "utf8",
    );
    const validation = reusable.slice(
      reusable.indexOf("  terraform-validate:\n"),
      reusable.indexOf("  checkov:\n"),
    );
    const checkov = reusable.slice(
      reusable.indexOf("  checkov:\n"),
      reusable.indexOf("  terraform-convergence:\n"),
    );
    const convergence = reusable.slice(reusable.indexOf("  terraform-convergence:\n"));
    expect(validation).not.toContain("id-token: write");
    expect(checkov).not.toContain("id-token: write");
    expect(reusable.match(/id-token: write/g) ?? []).toHaveLength(1);
    expect(convergence).toContain(
      "if: github.event_name == 'push' && github.ref == 'refs/heads/main'",
    );
    expect(convergence).toContain("environment: production");
    expect(convergence).toContain("id-token: write");
  });

  test("doctor rejects a block-scalar reusable-call decoy", async () => {
    const app = await scaffold("workflow-decoy");
    const path = join(app, ".github/workflows/deploy-prod.yml");
    const original = await readFile(path, "utf8");
    await writeFile(
      path,
      original.replace(
        "jobs:\n",
        `jobs:\n  decoy:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: |\n          uses: collinbentley1/platform/.github/workflows/deploy-prod.yml@${platformSha}\n`,
      ),
    );

    const result = await run(["doctor", app]);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("must exactly match the rendered platform caller template");
  });

  test("doctor rejects an extra real reusable-workflow job", async () => {
    const app = await scaffold("workflow-extra-job");
    const path = join(app, ".github/workflows/deploy-prod.yml");
    await writeFile(
      path,
      `${await readFile(path, "utf8")}\n  attacker-controlled:\n    uses: attacker/example/.github/workflows/deploy.yml@${"c".repeat(40)}\n`,
    );

    const result = await run(["doctor", app]);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("must exactly match the rendered platform caller template");
  });

  test("doctor rejects an additional executable workflow file", async () => {
    const app = await scaffold("extra-workflow-file");
    await writeFile(
      join(app, ".github/workflows/rogue.yml"),
      "name: Rogue\non: push\njobs:\n  rogue:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: true\n",
    );

    const result = await run(["doctor", app]);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("unreviewed additional workflow .github/workflows/rogue.yml");
  });

  test("doctor and immutable contract reject Bun updater caller drift", async () => {
    const app = await scaffold("bun-updater-caller-drift");
    const path = join(app, ".github/workflows/bun-dependency-update.yml");
    await writeFile(
      path,
      (await readFile(path, "utf8")).replace('cron: "23 13 * * 2"', 'cron: "24 13 * * 2"'),
    );
    for (const result of [await run(["doctor", app]), await runContract(app)]) {
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("must exactly match the rendered");
    }
  });

  test("doctor requires the expected full-SHA Terraform module source", async () => {
    const app = await scaffold("mutable-terraform");
    const path = join(app, "infra/terraform/prod/main.tf");
    const original = await readFile(path, "utf8");
    await writeFile(
      path,
      original.replace(
        `?ref=${platformSha}\"`,
        `?ref=main\" # decoy immutable ref ${platformSha}`,
      ),
    );

    const result = await run(["doctor", app]);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("uses non-immutable platform ref main");
  });

  test("doctor and immutable contract bind module sources inside the unique module block", async () => {
    const app = await scaffold("module-source-decoy");
    const path = join(app, "infra/terraform/prod/main.tf");
    const original = await readFile(path, "utf8");
    await writeFile(
      path,
      original.replace(
        `github.com/collinbentley1/platform//terraform/modules/cloud-run-service?ref=${platformSha}`,
        `github.com/attacker/platform//terraform/modules/cloud-run-service?ref=${platformSha}`,
      ) +
        `\nlocals {\n  source = "github.com/collinbentley1/platform//terraform/modules/cloud-run-service?ref=${platformSha}"\n}\n`,
    );

    for (const result of [await run(["doctor", app]), await runContract(app)]) {
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain(
        "module must contain exactly one top-level canonical cloud-run-service source",
      );
    }
  });

  test("Terraform mirror main files reject resources outside the reviewed module", async () => {
    const app = await scaffold("extra-terraform-resource");
    const path = join(app, "infra/terraform/prod/main.tf");
    await writeFile(
      path,
      `${await readFile(path, "utf8")}\nresource "google_project_iam_member" "rogue" {\n  project = var.project_id\n  role = "roles/owner"\n  member = "user:attacker@example.com"\n}\n`,
    );

    for (const result of [await run(["doctor", app]), await runContract(app)]) {
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain(
        "main.tf must contain only the exact reviewed repository-specific platform module",
      );
    }
  });

  test("bootstrap identity passthroughs cannot be replaced beside comment decoys", async () => {
    const app = await scaffold("bootstrap-identity-drift");
    const path = join(app, "infra/terraform/bootstrap/main.tf");
    const original = await readFile(path, "utf8");
    await writeFile(
      path,
      original.replace(
        "  github_repository_id        = var.github_repository_id",
        [
          '  github_repository_id = "999999999"',
          "  # github_repository_id = var.github_repository_id",
        ].join("\n"),
      ),
    );

    for (const result of [await run(["doctor", app]), await runContract(app)]) {
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain(
        "module bootstrap must exactly match the reviewed repository-specific platform contract",
      );
    }
  });

  test("security-critical Terraform variable defaults are exact", async () => {
    const app = await scaffold("terraform-variable-drift");
    const path = join(app, "infra/terraform/prod/variables.tf");
    const original = await readFile(path, "utf8");
    await writeFile(
      path,
      replaceAfterMarker(
        original,
        'variable "runtime_service_account_email"',
        '  default     = "cloud-run-runtime@terraform-variable-drift.iam.gserviceaccount.com"',
        [
          '  default = "attacker@other-project.iam.gserviceaccount.com"',
          '  # default = "cloud-run-runtime@terraform-variable-drift.iam.gserviceaccount.com"',
        ].join("\n"),
      ),
    );

    for (const result of [await run(["doctor", app]), await runContract(app)]) {
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain(
        "infra/terraform/prod/variables.tf must exactly match the reviewed repository-specific mirror contract",
      );
    }
  });

  test("an empty Terraform mirror file cannot skip validation of the remaining files", async () => {
    const app = await scaffold("empty-mirror-file");
    await writeFile(join(app, "infra/terraform/bootstrap/outputs.tf"), "");
    const variablesPath = join(app, "infra/terraform/prod/variables.tf");
    const variables = await readFile(variablesPath, "utf8");
    await writeFile(
      variablesPath,
      replaceAfterMarker(
        variables,
        'variable "runtime_service_account_email"',
        '  default     = "cloud-run-runtime@empty-mirror-file.iam.gserviceaccount.com"',
        '  default     = "attacker@other-project.iam.gserviceaccount.com"',
      ),
    );

    const result = await run(["doctor", app]);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain(
      "infra/terraform/bootstrap/outputs.tf must exactly match the reviewed repository-specific mirror contract",
    );
    expect(result.stderr).toContain(
      "infra/terraform/prod/variables.tf must exactly match the reviewed repository-specific mirror contract",
    );
  });

  test("Terraform roots reject extra configuration and provider-lock drift", async () => {
    const extraApp = await scaffold("extra-terraform-config");
    await writeFile(
      join(extraApp, "infra/terraform/prod/rogue.tf"),
      'resource "google_project_iam_member" "rogue" {}\n',
    );
    for (const result of [await run(["doctor", extraApp]), await runContract(extraApp)]) {
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr.toLowerCase()).toContain("unreviewed additional terraform mirror file");
    }

    const autoVariablesApp = await scaffold("terraform-auto-variables");
    await writeFile(
      join(autoVariablesApp, "infra/terraform/bootstrap/attacker.auto.tfvars"),
      'github_repository_id = "999999999"\n',
    );
    for (const result of [
      await run(["doctor", autoVariablesApp]),
      await runContract(autoVariablesApp),
    ]) {
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("Terraform state/config artifact");
    }

    const lockApp = await scaffold("terraform-lock-drift");
    const lockPath = join(lockApp, "infra/terraform/prod/.terraform.lock.hcl");
    await writeFile(lockPath, `${await readFile(lockPath, "utf8")}\n# unreviewed checksum\n`);
    for (const result of [await run(["doctor", lockApp]), await runContract(lockApp)]) {
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("exactly match the immutable platform template");
    }

    const symlinkApp = await scaffold("terraform-lock-symlink");
    const symlinkPath = join(symlinkApp, "infra/terraform/prod/.terraform.lock.hcl");
    await rm(symlinkPath);
    await symlink("../bootstrap/.terraform.lock.hcl", symlinkPath);
    for (const result of [await run(["doctor", symlinkApp]), await runContract(symlinkApp)]) {
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("must be a regular, non-symbolic-link file");
    }
  });

  test("immutable contract binds Terraform mirrors to the resolved reusable workflow SHA", async () => {
    const app = await scaffold("immutable-workflow-sha");
    const alternatePlatformSha = "b".repeat(40);
    const updaterCallerPath = join(app, ".github/workflows/bun-dependency-update.yml");
    await writeFile(
      updaterCallerPath,
      (await readFile(updaterCallerPath, "utf8")).replaceAll(platformSha, alternatePlatformSha),
    );
    const result = await runContract(app, "123456789", alternatePlatformSha);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("module source must match the active reusable workflow SHA");
  });

  test("doctor rejects Terraform passthrough drift hidden behind line and block comments", async () => {
    const app = await scaffold("terraform-comment-decoys");
    const path = join(app, "infra/terraform/prod/main.tf");
    const original = await readFile(path, "utf8");
    await writeFile(
      path,
      original
        .replace(
          "  preview_ingress                                = var.preview_ingress",
          "  # preview_ingress = var.preview_ingress",
        )
        .replace(
          "  runtime_secret_version_adder_ids               = var.runtime_secret_version_adder_ids",
          "  /* runtime_secret_version_adder_ids = var.runtime_secret_version_adder_ids */",
        )
        .replace(
          "  runtime_secret_ids                             = var.runtime_secret_ids",
          [
            '  runtime_secret_ids = ["attacker-controlled-secret"]',
            "  # runtime_secret_ids = var.runtime_secret_ids",
          ].join("\n"),
        )
        .replace(
          "  runtime_secret_accessor_ids                    = var.runtime_secret_accessor_ids",
          [
            "  runtime_secret_accessor_ids = var.runtime_secret_ids",
            "  /* runtime_secret_accessor_ids = var.runtime_secret_accessor_ids */",
          ].join("\n"),
        ),
    );

    for (const result of [await run(["doctor", app]), await runContract(app)]) {
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain(
        "module site must pass preview_ingress = var.preview_ingress exactly once",
      );
      expect(result.stderr).toContain(
        "module site must pass runtime_secret_version_adder_ids = var.runtime_secret_version_adder_ids exactly once",
      );
      expect(result.stderr).toContain(
        "module site must pass runtime_secret_ids = var.runtime_secret_ids exactly once",
      );
      expect(result.stderr).toContain(
        "module site must pass runtime_secret_accessor_ids = var.runtime_secret_accessor_ids exactly once",
      );
    }
  });

  test("doctor rejects world-open Critical History preview ingress despite decoys", async () => {
    const app = await scaffold("critical-ingress-drift");
    await setPlatformIdentity(app, {
      githubRepositoryId: "280932482",
      name: "critical-history",
      projectId: "critical-history-16823277",
      serviceName: "critical-history",
    });
    const path = join(app, "infra/terraform/prod/variables.tf");
    const original = (await readFile(path, "utf8")).replaceAll(
      "critical-ingress-drift.iam.gserviceaccount.com",
      "critical-history-16823277.iam.gserviceaccount.com",
    );
    await writeFile(
      path,
      original.replace(
        '  default     = "INGRESS_TRAFFIC_ALL"',
        [
          '  default     = "INGRESS_TRAFFIC_ALL"',
          '  # default = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"',
          '  /* default = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER" */',
        ].join("\n"),
      ),
    );

    for (const result of [
      await run(["doctor", app], { TRUSTED_GITHUB_REPOSITORY_ID: "280932482" }),
      await runContract(app, "280932482"),
    ]) {
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain(
        "preview_ingress must match the reviewed repository-specific ingress contract",
      );
    }
  });

  test("doctor rejects a missing secret subset validation hidden behind comment decoys", async () => {
    const app = await scaffold("secret-subset-decoy");
    const path = join(app, "infra/terraform/prod/variables.tf");
    const original = await readFile(path, "utf8");
    const condition =
      "    condition     = length(setsubtract(var.runtime_secret_version_adder_ids, var.runtime_secret_ids)) == 0";
    await writeFile(
      path,
      replaceAfterMarker(
        original,
        'variable "runtime_secret_version_adder_ids"',
        condition,
        ["    # " + condition.trim(), "    /* " + condition.trim() + " */"].join("\n"),
      ),
    );

    for (const result of [await run(["doctor", app]), await runContract(app)]) {
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain(
        "runtime_secret_version_adder_ids must match the reviewed repository-specific set and subset validation",
      );
    }
  });

  test("doctor accepts the exact Medlock secret contract and rejects one added ID", async () => {
    const app = await scaffold("medlock");
    await configureReviewedMedlock(app);
    const variablesPath = join(app, "infra/terraform/prod/variables.tf");
    const env = { TRUSTED_GITHUB_REPOSITORY_ID: "1025243085" };
    expect((await run(["doctor", app], env)).exitCode).toBe(0);
    expect((await runContract(app, "1025243085")).exitCode).toBe(0);

    const withAddedSecret = replaceAfterMarker(
      await readFile(variablesPath, "utf8"),
      'variable "runtime_secret_version_adder_ids"',
      '    "waitlist-identity-keyset",',
      '    "waitlist-identity-keyset",\n    "attacker-added-secret",',
    );
    await writeFile(variablesPath, withAddedSecret);
    for (const result of [
      await run(["doctor", app], env),
      await runContract(app, "1025243085"),
    ]) {
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain(
        "runtime_secret_version_adder_ids must match the reviewed repository-specific set and subset validation",
      );
    }
  });

  test("doctor binds the Medlock reCAPTCHA site key to the reviewed resource", async () => {
    const env = { TRUSTED_GITHUB_REPOSITORY_ID: "1025243085" };
    for (const replacement of [
      '"copied-public-site-key"',
      "google_recaptcha_enterprise_key.attacker.name",
    ]) {
      const app = await scaffold("medlock");
      await configureReviewedMedlock(app);
      const path = join(app, "infra/terraform/prod/main.tf");
      await writeFile(
        path,
        (await readFile(path, "utf8")).replace(
          "RECAPTCHA_SITE_KEY             = google_recaptcha_enterprise_key.waitlist.name",
          `RECAPTCHA_SITE_KEY             = ${replacement}`,
        ),
      );

      for (const result of [
        await run(["doctor", app], env),
        await runContract(app, "1025243085"),
      ]) {
        expect(result.exitCode).not.toBe(0);
        expect(result.stderr).toContain(
          "infra/terraform/prod/main.tf module site must exactly match the reviewed repository-specific platform contract",
        );
      }
    }
  });

  test("doctor rejects stale preview-operator grant claims even beside canonical decoys", async () => {
    const app = await scaffold("operator-description-drift");
    const path = join(app, "infra/terraform/bootstrap/outputs.tf");
    const original = await readFile(path, "utf8");
    await writeFile(
      path,
      original.replace(
        '  description = "Retired transition-only preview operator service account; receives no steady-state operational grants."',
        [
          '  description = "Preview traffic-reconciliation service account with downloadArtifacts-only access."',
          '  # description = "Retired transition-only preview operator service account; receives no steady-state operational grants."',
          '  /* description = "Retired transition-only preview operator service account; receives no steady-state operational grants." */',
        ].join("\n"),
      ),
    );

    for (const result of [await run(["doctor", app]), await runContract(app)]) {
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain(
        "preview operator output must retain the retired no-grant semantics",
      );
      expect(result.stderr).toContain(
        "must not retain the retired preview-operator downloadArtifacts claim",
      );
    }
  });

  test("doctor rejects inherited secrets", async () => {
    const app = await scaffold("inherited-secrets");
    const path = join(app, ".github/workflows/deploy-preview.yml");
    const original = await readFile(path, "utf8");
    await writeFile(
      path,
      original.replace(
        /(    uses: collinbentley1\/platform\/\.github\/workflows\/deploy-preview\.yml@[^\n]+)/,
        "$1\n    secrets: inherit",
      ),
    );

    const result = await run(["doctor", app]);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("uses secrets: inherit");
  });

  test("doctor rejects missing, redirected, or secret-bearing preview callers", async () => {
    const mutations = [
      [
        "missing-deploy-secret",
        (workflow: string) =>
          workflow.replace(
            "      pull-requests: read # Let the reusable cleanup re-read current lifecycle state.\n",
            "",
          ),
      ],
      [
        "redirected-deploy-secret",
        (workflow: string) =>
          workflow.replace(
            "  pull_request_target:\n",
            "  pull_request:\n",
          ),
      ],
      [
        "additional-deploy-secret",
        (workflow: string) =>
          workflow.replace(
            `    uses: collinbentley1/platform/.github/workflows/deploy-preview.yml@${platformSha}`,
            `    uses: collinbentley1/platform/.github/workflows/deploy-preview.yml@${platformSha}\n` +
              "    secrets: inherit",
          ),
      ],
    ] as const;

    for (const [name, mutate] of mutations) {
      const app = await scaffold(name);
      const path = join(app, ".github/workflows/deploy-preview.yml");
      await writeFile(path, mutate(await readFile(path, "utf8")));

      const result = await run(["doctor", app]);
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("must exactly match the rendered platform caller template");
    }
  });

  test("doctor rejects caller-controlled Checkov configuration symlinks", async () => {
    const app = await scaffold("checkov-symlink");
    await symlink("config/attacker.yml", join(app, ".checkov.yml"));

    const result = await run(["doctor", app]);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("forbidden caller-controlled Checkov configuration .checkov.yml");
  });

  test("doctor requires the frozen Bun lockfile used by CI and Docker", async () => {
    const app = await scaffold("missing-lockfile");
    await rm(join(app, "bun.lock"));

    const result = await run(["doctor", app]);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("missing bun.lock");
  });

  test("empty required package manifests cannot skip doctor policy", async () => {
    const app = await scaffold("empty-package-manifests");
    await writeFile(join(app, "package.json"), "");
    await writeFile(join(app, "bun.lock"), "");

    const result = await run(["doctor", app]);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("package.json is not valid JSON");
    expect(result.stderr).toContain("bun.lock is not valid JSONC");
  });

  test("doctor and immutable contract reject local scanner substitution", async () => {
    const app = await scaffold("scanner-source-substitution");
    const path = join(app, "tools/socket-security-scanner.ts");
    await writeFile(path, `${await readFile(path, "utf8")}\nconsole.log(Bun.env.SOCKET_API_TOKEN);\n`);

    const doctor = await run(["doctor", app]);
    expect(doctor.exitCode).not.toBe(0);
    expect(doctor.stderr).toContain(
      "tools/socket-security-scanner.ts does not exactly match the immutable platform template",
    );

    const contract = await runContract(app);
    expect(contract.exitCode).not.toBe(0);
    expect(contract.stderr).toContain(
      "tools/socket-security-scanner.ts must exactly match the immutable platform template",
    );
  });

  test("doctor and immutable contract reject the released quota-exhausting scanner", async () => {
    const app = await scaffold("published-scanner-substitution");
    const packagePath = join(app, "package.json");
    const packageJson = JSON.parse(await readFile(packagePath, "utf8")) as {
      devDependencies: Record<string, string>;
    };
    packageJson.devDependencies["@socketsecurity/bun-security-scanner"] = "1.1.2";
    await writeFile(packagePath, `${JSON.stringify(packageJson, null, 2)}\n`);

    const doctor = await run(["doctor", app]);
    expect(doctor.exitCode).not.toBe(0);
    expect(doctor.stderr).toContain("uses the quota-exhausting published Socket scanner");

    const contract = await runContract(app);
    expect(contract.exitCode).not.toBe(0);
    expect(contract.stderr).toContain("must not use the quota-exhausting published Socket scanner");
  });

  test("doctor and immutable contract cap one authenticated Socket request", async () => {
    const app = await scaffold("scanner-package-cap");
    const lockPath = join(app, "bun.lock");
    const lock = Bun.JSONC.parse(await readFile(lockPath, "utf8")) as {
      packages: Record<string, unknown>;
    };
    for (let index = Object.keys(lock.packages).length; index < 129; index += 1) {
      lock.packages[`synthetic-${index}`] = [
        `synthetic-${index}@1.0.0`,
        "",
        {},
        `sha512-${"A".repeat(86)}==`,
      ];
    }
    await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);

    const doctor = await run(["doctor", app]);
    expect(doctor.exitCode).not.toBe(0);
    expect(doctor.stderr).toContain("exceeds the reviewed 128-package Socket request limit");

    const contract = await runContract(app);
    expect(contract.exitCode).not.toBe(0);
    expect(contract.stderr).toContain("exceeds the reviewed 128-package Socket request limit");
  });

  test("doctor and immutable contract reject dependency sources Bun omits from scanning", async () => {
    const app = await scaffold("scanner-source-bypass");
    const packagePath = join(app, "package.json");
    const lockPath = join(app, "bun.lock");
    const originalPackage = await readFile(packagePath, "utf8");
    const packageJson = JSON.parse(originalPackage) as {
      dependencies?: Record<string, string>;
    };
    packageJson.dependencies = {
      "safe-looking": "https://registry.npmjs.org/lodahs/-/lodahs-0.0.1-security.tgz",
    };
    await writeFile(packagePath, `${JSON.stringify(packageJson, null, 2)}\n`);

    for (const result of [await run(["doctor", app]), await runContract(app)]) {
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain(
        "must use an exact npm registry version or npm alias",
      );
    }

    await writeFile(packagePath, originalPackage);
    const lock = Bun.JSONC.parse(await readFile(lockPath, "utf8")) as {
      packages: Record<string, unknown>;
    };
    lock.packages["safe-looking"] = [
      "safe-looking@https://registry.npmjs.org/lodahs/-/lodahs-0.0.1-security.tgz",
      {},
      `sha512-${"A".repeat(86)}==`,
    ];
    await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);

    for (const result of [await run(["doctor", app]), await runContract(app)]) {
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain(
        "must be a sha512-pinned npm registry resolution",
      );
    }
  });

  test("doctor and immutable contract reject unreviewed workspaces", async () => {
    const app = await scaffold("scanner-workspace-bypass");
    const packagePath = join(app, "package.json");
    const packageJson = JSON.parse(await readFile(packagePath, "utf8")) as Record<string, unknown>;
    packageJson.workspaces = ["packages/*"];
    await writeFile(packagePath, `${JSON.stringify(packageJson, null, 2)}\n`);

    for (const result of [await run(["doctor", app]), await runContract(app)]) {
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain(
        "package.json workspaces are forbidden by the registry-only dependency policy",
      );
    }
  });

  test("doctor and immutable contract pin the native TypeScript compiler package", async () => {
    const app = await scaffold("typescript-native-substitution");
    const path = join(app, "bun.lock");
    const original = await readFile(path, "utf8");
    await writeFile(
      path,
      original.replace(
        "sha512-EYdf2cNg7rgCWJnxCdJ+F3V39O8ihb37eHAu1LK8oAFizgTQbPOK7zHHXbPt8rX24COqODXeI3sIf0fCXG7H/A==",
        `sha512-${"A".repeat(86)}==`,
      ),
    );

    const doctor = await run(["doctor", app]);
    expect(doctor.exitCode).not.toBe(0);
    expect(doctor.stderr).toContain(
      "bun.lock does not resolve the reviewed TypeScript integrity for @typescript/typescript-linux-x64",
    );

    const contract = await runContract(app);
    expect(contract.exitCode).not.toBe(0);
    expect(contract.stderr).toContain(
      "bun.lock does not resolve the reviewed TypeScript integrity for @typescript/typescript-linux-x64",
    );
  });

  test("doctor and immutable contract reject Bun dependency patches", async () => {
    const app = await scaffold("dependency-patches");
    const packagePath = join(app, "package.json");
    const lockPath = join(app, "bun.lock");
    const originalPackage = await readFile(packagePath, "utf8");
    const packageJson = JSON.parse(originalPackage) as Record<string, unknown>;
    packageJson.patchedDependencies = { "typescript@7.0.2": "patches/typescript.patch" };
    await writeFile(packagePath, `${JSON.stringify(packageJson, null, 2)}\n`);

    for (const result of [await run(["doctor", app]), await runContract(app)]) {
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("package.json patchedDependencies are forbidden");
    }

    await writeFile(packagePath, originalPackage);
    const lock = Bun.JSONC.parse(await readFile(lockPath, "utf8")) as Record<string, unknown>;
    lock.patchedDependencies = { "typescript@7.0.2": "sha512-attacker-controlled" };
    await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);

    for (const result of [await run(["doctor", app]), await runContract(app)]) {
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("bun.lock patchedDependencies are forbidden");
    }
  });

  test("doctor rejects an effective Bun registry override", async () => {
    const app = await scaffold("registry-override");
    const path = join(app, "bunfig.toml");
    const original = await readFile(path, "utf8");
    await writeFile(
      path,
      original.replace(
        'registry = "https://registry.npmjs.org"',
        'registry = "https://invalid.example"',
      ),
    );

    const result = await run(["doctor", app]);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("does not exactly match the immutable platform template");
  });

  test("doctor and immutable contract reject delegated verification bypasses", async () => {
    const app = await scaffold("verification-bypass");
    const path = join(app, "package.json");
    const original = JSON.parse(await readFile(path, "utf8")) as {
      scripts: Record<string, string>;
    };
    for (const script of ["verify", "verify:ci", "test"]) {
      const packageJson = structuredClone(original);
      packageJson.scripts[script] = "true";
      await writeFile(path, `${JSON.stringify(packageJson, null, 2)}\n`);

      const doctor = await run(["doctor", app]);
      expect(doctor.exitCode).not.toBe(0);
      expect(doctor.stderr).toContain(
        `package.json script ${script} must exactly match the immutable platform command`,
      );

      const contract = await runContract(app);
      expect(contract.exitCode).not.toBe(0);
      expect(contract.stderr).toContain(
        `package.json script ${script} must exactly match the immutable platform command`,
      );
    }

    const packageJson = structuredClone(original);
    packageJson.scripts.pretest = "true";
    await writeFile(path, `${JSON.stringify(packageJson, null, 2)}\n`);
    expect((await run(["doctor", app])).stderr).toContain(
      "package.json must not define the implicit pretest hook",
    );
    expect((await runContract(app)).stderr).toContain(
      "package.json must not define the implicit pretest hook",
    );
  });

  test("immutable contract binds app policy to the event repository ID", async () => {
    const app = await scaffold("repository-id-drift");
    const result = await runContract(app, "987654321");
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("must match the immutable GitHub event repository ID");
  });

  test("doctor and immutable contract reject Terraform state and saved plans", async () => {
    const app = await scaffold("terraform-artifacts");
    await writeFile(join(app, "infra/terraform/prod/review.tfplan"), "sensitive plan\n");

    const doctor = await run(["doctor", app]);
    expect(doctor.exitCode).not.toBe(0);
    expect(doctor.stderr).toContain(
      "forbidden committed Terraform state/config artifact infra/terraform/prod/review.tfplan",
    );

    const contract = await runContract(app);
    expect(contract.exitCode).not.toBe(0);
    expect(contract.stderr).toContain(
      "Forbidden Terraform state/config artifact: infra/terraform/prod/review.tfplan",
    );
  });

  test("immutable contract rejects backup copies of Terraform variables and plans", async () => {
    const app = await scaffold("terraform-artifact-backups");
    await writeFile(join(app, "infra/terraform/prod/terraform.tfvars.bak"), "token = \"bad\"\n");
    await writeFile(join(app, "infra/terraform/prod/release.tfplan.backup"), "sensitive plan\n");

    const contract = await runContract(app);
    expect(contract.exitCode).not.toBe(0);
    expect(contract.stderr).toContain("Forbidden Terraform state/config artifact");
  });

  test("immutable contract scans nested directories named like the trusted policy checkout", async () => {
    const app = await scaffold("nested-policy-decoy");
    await mkdir(join(app, "infra/_platform_policy"), { recursive: true });
    await writeFile(join(app, "infra/_platform_policy/leak.tfstate"), "sensitive state\n");

    const contract = await runContract(app);
    expect(contract.exitCode).not.toBe(0);
    expect(contract.stderr).toContain(
      "Forbidden Terraform state/config artifact: infra/_platform_policy/leak.tfstate",
    );
  });

  test("doctor and immutable contract require Terraform leak-prevention ignores", async () => {
    const app = await scaffold("terraform-ignore-drift");
    const path = join(app, ".gitignore");
    await writeFile(path, (await readFile(path, "utf8")).replace("*.tfstate.*\n", ""));

    const doctor = await run(["doctor", app]);
    expect(doctor.exitCode).not.toBe(0);
    expect(doctor.stderr).toContain(".gitignore must include *.tfstate.*");

    const contract = await runContract(app);
    expect(contract.exitCode).not.toBe(0);
    expect(contract.stderr).toContain(".gitignore must include *.tfstate.*");
  });

  test("immutable contract rejects a later gitignore negation of Terraform safety rules", async () => {
    const app = await scaffold("terraform-ignore-negation");
    const path = join(app, ".gitignore");
    await writeFile(path, `${await readFile(path, "utf8")}!infra/leak.tfstate\n`);

    const contract = await runContract(app);
    expect(contract.exitCode).not.toBe(0);
    expect(contract.stderr).toContain(
      ".gitignore must end with the exact platform-managed Terraform safety block",
    );
  });

  test("immutable contract accepts inert env examples and rejects Bun-loaded env files", async () => {
    const app = await scaffold("env-contract");
    await writeFile(join(app, ".env.example"), "EXAMPLE_ONLY=replace-me\n");
    expect((await runContract(app)).exitCode).toBe(0);

    await writeFile(join(app, ".env.local"), "BUN_CONFIG_REGISTRY=https://invalid.example\n");
    const result = await runContract(app);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("Forbidden package-manager environment/config file");
  });

  test("immutable contract rejects Docker drift rather than parsing attacker tokens in shell", async () => {
    const app = await scaffold("docker-drift");
    const path = join(app, "Dockerfile");
    await writeFile(path, `${await readFile(path, "utf8")}\nFROM attacker.example/latest\n`);

    const result = await runContract(app);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("Dockerfile must exactly match the immutable platform template");
  });

  test("doctor and immutable contract reject trusted verification runner drift", async () => {
    const app = await scaffold("verification-runner-drift");
    const path = join(app, "tools/platform-verify.ts");
    await writeFile(path, `${await readFile(path, "utf8")}\nprocess.exit(0);\n`);

    const doctor = await run(["doctor", app]);
    expect(doctor.exitCode).not.toBe(0);
    expect(doctor.stderr).toContain(
      "tools/platform-verify.ts does not exactly match the immutable platform template",
    );

    const contract = await runContract(app);
    expect(contract.exitCode).not.toBe(0);
    expect(contract.stderr).toContain(
      "tools/platform-verify.ts must exactly match the immutable platform template",
    );
  });

  test("trusted checker does not execute a consumer Bun preload", async () => {
    const app = await scaffold("bun-preload");
    const marker = join(app, "preload-ran");
    const preload = join(app, "preload.ts");
    await writeFile(preload, `await Bun.write(${JSON.stringify(marker)}, "bad");\n`);
    const bunfig = join(app, "bunfig.toml");
    await writeFile(bunfig, `preload = ["./preload.ts"]\n${await readFile(bunfig, "utf8")}`);

    const result = await runContract(app);
    expect(result.exitCode).not.toBe(0);
    expect(await Bun.file(marker).exists()).toBe(false);
  });

  test("trusted checker rejects committed node_modules before Socket credentials exist", async () => {
    const app = await scaffold("committed-node-modules");
    await mkdir(join(app, "node_modules", "@socketsecurity", "bun-security-scanner"), {
      recursive: true,
    });
    await writeFile(
      join(app, "node_modules", "@socketsecurity", "bun-security-scanner", "package.json"),
      '{"name":"@socketsecurity/bun-security-scanner","version":"1.1.2"}\n',
    );

    const result = await runContract(app);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("Committed node_modules content is forbidden");
  });

  test("trusted verification runner rejects a dependency-installed Bun executable shadow", async () => {
    const app = await scaffold("dependency-bun-shadow");
    await mkdir(join(app, "node_modules/.bin"), { recursive: true });
    await mkdir(join(app, "node_modules/typescript/bin"), { recursive: true });
    await writeFile(join(app, "node_modules/.bin/bun"), "#!/bin/sh\nexit 0\n");
    await writeFile(join(app, "node_modules/typescript/bin/tsc"), "process.exit(0);\n");

    const result = await runVerification(app);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain(
      process.platform === "linux"
        ? "node_modules/.bin/bun executable shadow"
        : "Privileged application verification requires Linux /proc executable pinning",
    );
  });

  test("trusted verification runner re-executes the loaded Bun inode", async () => {
    const runner = await readFile(
      join(repoRoot, "templates/app/tools/platform-verify.ts"),
      "utf8",
    );
    expect(runner).toContain('process.platform !== "linux"');
    expect(runner).toContain("`/proc/${process.pid}/exe`");
    expect(runner.indexOf('"typecheck"')).toBeLessThan(runner.indexOf('"format check"'));
    expect(runner).not.toContain(
      '[bunExecutable, "--no-env-file", "--no-orphans", join(appRoot, "tools/',
    );

    const platformRunner = await readFile(join(repoRoot, "tools/ci/verify-platform.ts"), "utf8");
    expect(platformRunner).toContain('process.platform !== "linux"');
    expect(platformRunner).toContain("`/proc/${process.pid}/exe`");
    expect(platformRunner.indexOf('"typecheck"')).toBeLessThan(
      platformRunner.indexOf('"format check"'),
    );
  });

  test("trusted checker rejects caller-controlled Syft configuration", async () => {
    const app = await scaffold("syft-config");
    await writeFile(join(app, ".syft.yaml"), "exclude:\n  - '/**'\n");

    const result = await runContract(app);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("Forbidden package-manager environment/config file: .syft.yaml");

    await rm(join(app, ".syft.yaml"));
    await mkdir(join(app, "attacker-syft"));
    await writeFile(join(app, "attacker-syft", "config.yaml"), "exclude:\n  - '/**'\n");
    await symlink("attacker-syft", join(app, ".syft"));
    const symlinkResult = await runContract(app);
    expect(symlinkResult.exitCode).not.toBe(0);
    expect(symlinkResult.stderr).toContain(
      "Forbidden symbolic-link package-manager environment/config file: .syft",
    );
  });

  test("doctor and immutable contract reject every consumer transition SHA", async () => {
    const app = await scaffold("consumer-transition");
    const path = join(app, "infra/terraform/bootstrap/main.tf");
    const original = await readFile(path, "utf8");
    const withTransition = (transition: string) =>
      original.replace(
        `  active_workflow_sha         = "${platformSha}"`,
        `  active_workflow_sha         = "${platformSha}"\n  transition_workflow_sha     = "${transition}"`,
      );
    expect(withTransition("b".repeat(40))).not.toBe(original);

    await writeFile(path, withTransition("b".repeat(40)));
    const doctor = await run(["doctor", app]);
    expect(doctor.exitCode).not.toBe(0);
    expect(doctor.stderr).toContain(
      "transition_workflow_sha must be absent in the consumer steady-state mirror",
    );

    const contract = await runContract(app);
    expect(contract.exitCode).not.toBe(0);
    expect(contract.stderr).toContain(
      "infra/terraform/bootstrap/main.tf transition_workflow_sha must be absent in the consumer steady-state mirror",
    );
    expect(contract.stderr).toContain(
      "module bootstrap must exactly match the reviewed repository-specific platform contract",
    );

    for (const vulnerable of [
      "734d0cd02187f88c6e91263f127dc3f4c0709feb",
      "1378a3e81a5e74c71f2adfd5548b430bb008490e",
      "37bd4b1beea8802ec85c38d69ea08d5992c75a50",
      "42435a3c4c5c063a342765ef7c85047224217fe2",
      "7f01d9f008a7757df12f13ac8fa0f261600cf21a",
      "4f032955477c26b942fdd4f1b01f5272380390ea",
      "92c73184bc527388b5e10ccb5e4f0222a84e68b5",
      "33ab9b9a5f3d8a0553372980c22540cad001f776",
    ]) {
      await writeFile(
        path,
        withTransition(vulnerable),
      );
      for (const result of [await run(["doctor", app]), await runContract(app)]) {
        expect(result.exitCode).not.toBe(0);
        expect(result.stderr).toContain("pre-migration SHA");
      }
    }
  });

  test("doctor and immutable contract reject symlinked Terraform ancestor directories", async () => {
    for (const [index, ancestor] of [
      "infra",
      "infra/terraform",
      "infra/terraform/bootstrap",
      "infra/terraform/prod",
    ].entries()) {
      const app = await scaffold(`terraform-ancestor-symlink-${index}`);
      const original = join(app, ancestor);
      const mirror = join(app, `mirror-${index}`);
      await cp(original, mirror, { recursive: true });
      const rogue =
        index === 0
          ? join(mirror, "terraform/prod/rogue.tf")
          : index === 1
            ? join(mirror, "prod/rogue.tf")
            : join(mirror, "rogue.tf");
      await writeFile(rogue, "resource \"null_resource\" \"rogue\" {}\n");
      await rm(original, { recursive: true });
      await symlink(mirror, original);

      for (const result of [await run(["doctor", app]), await runContract(app)]) {
        expect(result.exitCode).not.toBe(0);
        expect(result.stderr).toContain(
          `${ancestor} must be a real, non-symbolic-link directory`,
        );
      }
    }
  });

  test("doctor binds consumer pins to the active reusable workflow SHA", async () => {
    const app = await scaffold("active-workflow");
    const result = await run(["doctor", app], { PLATFORM_WORKFLOW_SHA: "b".repeat(40) });
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("does not match consumer pin");
  });

  test("only the protected base prefetch receives the sole external credential", async () => {
    expect(await readFile(join(repoRoot, "tools/socket-security-scanner.ts"), "utf8")).toBe(
      await readFile(join(repoRoot, "templates/app/tools/socket-security-scanner.ts"), "utf8"),
    );
    for (const workflow of ["application.yml", "socket-firewall.yml"]) {
      const text = await readFile(join(repoRoot, ".github/workflows", workflow), "utf8");
      expect(text).not.toContain("secrets.SOCKET_API_TOKEN");
      expect(text).not.toContain("environment: dependency-scan");
      expect(text).toContain("unset SOCKET_API_TOKEN SOCKET_API_KEY");
      expect(text).toContain("Socket Security Scanner free mode");
    }

    for (const workflow of ["deploy-preview.yml", "deploy-prod.yml"]) {
      const text = await readFile(join(repoRoot, ".github/workflows", workflow), "utf8");
      expect(semanticSecretContextReferences(text)).toEqual([
        {
          job: "prefetch-bases",
          path: "jobs.prefetch-bases.steps.2.env.DHI_PUBLIC_READ_TOKEN",
          value: "${{ secrets.DHI_PUBLIC_READ_TOKEN_20260822_098DCA9280B3 }}",
        },
      ]);
      expect(text).toContain("environment: dhi-base-prefetch-20260822-098dca9280b3");
      expect(text).toContain("DHI_USERNAME: ${{ vars.DHI_USERNAME }}");
      expect(text).not.toContain("GRYPE_DB_MANIFEST_JSON");
      expect(text).not.toContain("DB_MANIFEST_JSON:");
      expect(text).toContain("MAPBOX_PUBLIC_TOKEN: ${{ vars.MAPBOX_PUBLIC_TOKEN }}");
      expect(text).not.toContain("on:\n  workflow_call:\n    secrets:");
      expect(text).not.toContain("secrets.SOCKET_API_TOKEN");
      expect(text).not.toContain("secrets.WAITLIST_IDENTITY_KEYSET");
      const build = text.slice(text.indexOf("  build:\n"), text.indexOf("\n  verify-image:\n"));
      expect(build).not.toContain("${{ secrets.");
      expect(build).toContain("github-token: \"\"");
      expect(build).toContain("DOCKER_BUILD_RECORD_UPLOAD: \"false\"");
      expect(build).toContain("DOCKER_BUILD_SUMMARY: \"false\"");
      expect(build).toContain("DOCKER_BUILD_CHECKS_ANNOTATIONS: \"false\"");
    }

    for (const workflow of ["deploy-preview.yml", "deploy-prod.yml"]) {
      const caller = await readFile(
        join(repoRoot, "templates/app/.github/workflows", workflow),
        "utf8",
      );
      expect(caller).not.toContain("secrets:");
      expect(caller).not.toContain("secrets: inherit");
    }

    const dockerfile = await readFile(join(repoRoot, "templates/app/Dockerfile"), "utf8");
    expect(dockerfile).toContain("FROM platform.invalid/bun-release AS bun-release");
    expect(dockerfile).toContain("FROM platform.invalid/dhi-bun-dev AS deps");
    expect(dockerfile).toContain("FROM platform.invalid/dhi-bun-runtime AS runtime");
    expect(dockerfile).not.toContain("--mount=type=secret");
    expect(dockerfile).toContain("USER 65532:65532");
    expect(dockerfile).toContain("ENTRYPOINT []");
    expect(dockerfile).toContain('CMD ["/usr/local/bin/bun", "/app/dist/server.js"]');
  });

  test("platform pull requests cannot receive the Socket organization token", async () => {
    const workflow = await readFile(join(repoRoot, ".github/workflows/platform.yml"), "utf8");
    expect(workflow).not.toContain("${{ secrets.");
    expect(workflow).not.toContain("SOCKET_API_TOKEN:");
    expect(workflow).toContain('--config="$GITHUB_WORKSPACE/bunfig.toml" pm scan');
    expect(workflow).toContain("Socket Security Scanner free mode");
    expect(workflow).toContain("unset SOCKET_API_TOKEN SOCKET_API_KEY");
    expect(workflow).not.toContain("workflow_dispatch:");
  });

  test("platform verification mandates the exact live Docker sandbox contract", async () => {
    const source = await readFile(join(repoRoot, ".github/workflows/platform.yml"), "utf8");
    const workflow = Bun.YAML.parse(source) as {
      jobs: { verify: { steps: Array<Record<string, unknown>> } };
    };
    const gates = workflow.jobs.verify.steps.filter(
      (step) => step.name === "Verify platform",
    );
    expect(gates).toHaveLength(1);
    const [gate] = gates;
    expect(gate?.env).toEqual({
      PROTECTED_BOOTSTRAP_DOCKER_BINARY: "/usr/bin/docker",
      PROTECTED_BOOTSTRAP_DOCKER_INTEGRATION: "1",
      TERRAFORM_SANDBOX_IMAGE:
        "docker.io/oven/bun@sha256:8aac45197595035f697ea6b11cd73ce2401d82503fcb2540b5fac606973b242b",
    });
    expect(gate?.run).toBeString();
    const run = gate?.run as string;
    const pull = run.indexOf('"$PROTECTED_BOOTSTRAP_DOCKER_BINARY" pull');
    const inspect = run.indexOf('"$PROTECTED_BOOTSTRAP_DOCKER_BINARY" image inspect');
    const verify = run.indexOf("tools/ci/verify-platform.ts");
    const integration = run.indexOf("./test/integration/protected-bootstrap-docker.ts");
    expect(pull).toBeGreaterThan(-1);
    expect(pull).toBeLessThan(inspect);
    expect(inspect).toBeLessThan(verify);
    expect(verify).toBeLessThan(integration);

    const integrationSource = await readFile(
      join(repoRoot, "test/integration/protected-bootstrap-docker.ts"),
      "utf8",
    );
    expect(integrationSource).toContain(
      `"${(gate?.env as Record<string, string>).TERRAFORM_SANDBOX_IMAGE}"`,
    );
  });

  test("the reusable and platform Socket App gates cannot drift", async () => {
    const gateContract = async (workflowName: string) => {
      const workflow = Bun.YAML.parse(
        await readFile(join(repoRoot, ".github/workflows", workflowName), "utf8"),
      ) as {
        permissions?: Record<string, string>;
        jobs: Record<
          string,
          {
            permissions?: Record<string, string>;
            steps: Array<Record<string, unknown>>;
            "timeout-minutes": number;
          }
        >;
      };
      const job = Object.values(workflow.jobs)[0];
      const gate = job?.steps.find(
        (step) => step.name === "Require successful Socket GitHub App checks",
      );
      expect(gate?.run).toBeString();
      return {
        env: gate?.env,
        permissions: job?.permissions ?? workflow.permissions,
        run: gate?.run as string,
        shell: gate?.shell ?? null,
        timeoutMinutes: job?.["timeout-minutes"],
      };
    };

    const platformGate = await gateContract("platform.yml");
    const reusableGate = await gateContract("socket-firewall.yml");
    expect(reusableGate).toEqual(platformGate);
    expect(reusableGate.run).toContain("&app_id=156372");

    const caller = Bun.YAML.parse(
      await readFile(
        join(repoRoot, "templates/app/.github/workflows/socket-firewall.yml"),
        "utf8",
      ),
    ) as { jobs: { firewall: { permissions: Record<string, string> } } };
    expect(caller.jobs.firewall.permissions).toEqual(reusableGate.permissions);
  });

  test("required callers have no alternate event or base-retarget gap", async () => {
    const pullRequest = {
      types: ["edited", "opened", "reopened", "synchronize"],
    };
    for (const workflowName of ["application.yml", "infrastructure.yml", "socket-firewall.yml"]) {
      const source = await readFile(
        join(repoRoot, "templates/app/.github/workflows", workflowName),
        "utf8",
      );
      const workflow = Bun.YAML.parse(source) as {
        on: Record<string, unknown>;
      };
      expect(workflow.on.pull_request).toEqual(pullRequest);
      expect(source).not.toContain("workflow_dispatch");
      if (workflowName === "infrastructure.yml") {
        expect(Object.keys(workflow.on)).toEqual(["pull_request"]);
      } else {
        expect(Object.keys(workflow.on).sort()).toEqual(["pull_request", "push"]);
        expect(workflow.on.push).toEqual({ branches: ["main"] });
      }
    }

    const appleSource = await readFile(
      join(repoRoot, "templates/additional-workflows/runsetta/apple.yml"),
      "utf8",
    );
    const apple = Bun.YAML.parse(appleSource) as {
      on: Record<string, unknown>;
      jobs: { "swift-package": { steps: Array<Record<string, unknown>> } };
    };
    expect(apple.on).toEqual({
      pull_request: pullRequest,
      push: { branches: ["main"] },
    });
    expect(appleSource).not.toContain("workflow_dispatch");
    expect(apple.jobs["swift-package"].steps.slice(0, 2).map((step) => step.name)).toEqual([
      "Reject workflow reruns before any required check",
      "Reject alternate required-check event paths",
    ]);
  });

  test("required jobs share one fail-closed pull-request action guard", async () => {
    type WorkflowStep = {
      readonly name?: string;
      readonly run?: string;
      readonly shell?: string;
    };
    type WorkflowJob = { readonly steps?: readonly WorkflowStep[] };
    const guardedWorkflows = [
      {
        jobs: ["verify"],
        path: ".github/workflows/application.yml",
      },
      {
        jobs: ["rerun-guard", "terraform-validate", "checkov", "terraform-convergence"],
        path: ".github/workflows/infrastructure.yml",
      },
      {
        jobs: ["firewall"],
        path: ".github/workflows/socket-firewall.yml",
      },
      {
        jobs: ["swift-package"],
        path: "templates/additional-workflows/runsetta/apple.yml",
      },
    ] as const;
    const guards: WorkflowStep[] = [];

    for (const guardedWorkflow of guardedWorkflows) {
      const workflow = Bun.YAML.parse(
        await readFile(join(repoRoot, guardedWorkflow.path), "utf8"),
      ) as { readonly jobs?: Readonly<Record<string, WorkflowJob>> };
      for (const jobName of guardedWorkflow.jobs) {
        const steps = workflow.jobs?.[jobName]?.steps;
        expect(steps, `${guardedWorkflow.path}:${jobName} must have steps`).toBeArray();
        expect(
          steps?.slice(0, 2).map((step) => step.name),
          `${guardedWorkflow.path}:${jobName} must guard before executing caller code`,
        ).toEqual([
          jobName === "swift-package"
            ? "Reject workflow reruns before any required check"
            : "Reject workflow reruns before any privileged action",
          "Reject alternate required-check event paths",
        ]);
        const matching = steps?.filter((step) =>
          step.name === "Reject alternate required-check event paths"
        ) ?? [];
        expect(matching, `${guardedWorkflow.path}:${jobName} must have one action guard`).toHaveLength(
          1,
        );
        guards.push(matching[0]!);
      }
    }

    expect(guards).toHaveLength(7);
    expect(new Set(guards.map((guard) => guard.run)).size).toBe(1);
    expect(new Set(guards.map((guard) => guard.shell))).toEqual(
      new Set(["/bin/bash --noprofile --norc -euo pipefail {0}"]),
    );
    const guard = guards[0]?.run;
    expect(guard).toBeString();
    expect(guard).toContain('if .action == "edited" then');
    expect(guard).toContain('((.changes | keys) == ["body"])');
    expect(guard).toContain('((.changes.body | keys) == ["from"])');
    expect(guard).toContain('.action == "opened"');
    expect(guard).toContain('.action == "reopened"');
    expect(guard).toContain('.action == "synchronize"');
    expect(guard).toContain('test "$GITHUB_EVENT_NAME" = "push"');
    expect(guard).toContain('test "$GITHUB_REF" = "refs/heads/main"');

    const root = await mkdtemp(join(tmpdir(), "platform-required-check-event-guard-"));
    temporaryRoots.push(root);
    const eventPath = join(root, "event.json");
    const executeGuard = async (
      eventName: string,
      eventDocument: Record<string, unknown>,
      ref = eventName === "push" ? "refs/heads/main" : "refs/pull/1/merge",
    ): Promise<number> => {
      await writeFile(eventPath, JSON.stringify(eventDocument));
      const child = Bun.spawn(
        ["/bin/bash", "--noprofile", "--norc", "-c", guard as string],
        {
          cwd: root,
          env: {
            GITHUB_EVENT_NAME: eventName,
            GITHUB_EVENT_PATH: eventPath,
            GITHUB_REF: ref,
            PATH: process.env.PATH ?? "/usr/bin:/bin",
          },
          stderr: "ignore",
          stdout: "ignore",
        },
      );
      return await child.exited;
    };

    for (const eventDocument of [
      { action: "edited", changes: { body: { from: "old body" } } },
      { action: "edited", changes: { body: { from: null } } },
      { action: "opened" },
      { action: "reopened" },
      { action: "synchronize" },
    ]) {
      expect(await executeGuard("pull_request", eventDocument), JSON.stringify(eventDocument)).toBe(
        0,
      );
    }
    expect(await executeGuard("push", {})).toBe(0);

    for (const eventDocument of [
      { action: "edited" },
      { action: "edited", changes: null },
      { action: "edited", changes: {} },
      { action: "edited", changes: { body: null } },
      { action: "edited", changes: { body: { from: 7 } } },
      { action: "edited", changes: { title: { from: "old title" } } },
      { action: "edited", changes: { base: { ref: { from: "staging" } } } },
      {
        action: "edited",
        changes: { body: { from: "old body" }, title: { from: "old title" } },
      },
      { action: "edited", changes: { body: { from: "old body", to: "new body" } } },
      { action: "closed" },
      { action: "ready_for_review" },
    ]) {
      expect(await executeGuard("pull_request", eventDocument), JSON.stringify(eventDocument)).toBe(
        1,
      );
    }
    expect(await executeGuard("push", {}, "refs/heads/feature")).toBe(1);
    expect(await executeGuard("workflow_dispatch", {})).toBe(1);
    expect(await executeGuard("pull_request_target", { action: "edited" })).toBe(1);
  });

  test("Socket check gating binds success to the current pull request and commit", async () => {
    const workflowSource = await readFile(
      join(repoRoot, ".github/workflows/platform.yml"),
      "utf8",
    );
    expect(workflowSource).toContain(
      "types:\n      - edited\n      - opened\n      - reopened\n      - synchronize",
    );
    const workflow = Bun.YAML.parse(workflowSource) as {
      jobs: { verify: { steps: Array<Record<string, unknown>> } };
    };
    const gate = workflow.jobs.verify.steps.find(
      (step) => step.name === "Require successful Socket GitHub App checks",
    );
    expect(gate?.run).toBeString();

    const root = await mkdtemp(join(tmpdir(), "platform-socket-check-gate-"));
    temporaryRoots.push(root);
    const bin = join(root, "bin");
    await mkdir(bin);
    const fixture = join(root, "check-runs.json");
    const event = join(root, "event.json");
    const curlArguments = join(root, "curl-arguments.txt");
    const repositoryId = 1_255_856_466;
    const pullRequestNumber = 16;
    const head = "a".repeat(40);
    const base = "b".repeat(40);
    const merge = "c".repeat(40);
    const updatedAt = "2026-08-22T22:43:02Z";
    const pullRequestEvent = {
      action: "synchronize",
      number: pullRequestNumber,
      pull_request: {
        base: { repo: { id: repositoryId }, sha: base },
        head: { repo: { id: repositoryId }, sha: head },
        updated_at: updatedAt,
      },
      repository: { id: repositoryId },
    };
    await writeFile(
      join(bin, "curl"),
      [
        "#!/bin/sh",
        "set -eu",
        'printf \'%s\\n\' "$@" > "$FAKE_CURL_ARGUMENTS"',
        'grep -Fx -- "Authorization: Bearer test-token" "$FAKE_CURL_ARGUMENTS" >/dev/null',
        'grep -Fx -- "Accept: application/vnd.github+json" "$FAKE_CURL_ARGUMENTS" >/dev/null',
        'grep -Fx -- "X-GitHub-Api-Version: 2022-11-28" "$FAKE_CURL_ARGUMENTS" >/dev/null',
        'grep -Fx -- "$EXPECTED_SOCKET_URL" "$FAKE_CURL_ARGUMENTS" >/dev/null',
        'output=""',
        'while [ "$#" -gt 0 ]; do',
        '  if [ "$1" = "--output" ]; then shift; output="$1"; fi',
        "  shift",
        "done",
        'test -n "$output"',
        '/bin/cp "$SOCKET_CHECK_FIXTURE" "$output"',
        "",
      ].join("\n"),
    );
    await writeFile(join(bin, "seq"), "#!/bin/sh\nprintf '1\\n'\n");
    await writeFile(join(bin, "sleep"), "#!/bin/sh\nexit 0\n");
    await Promise.all(["curl", "seq", "sleep"].map((name) => chmod(join(bin, name), 0o755)));

    const pullRequestAssociation = (
      number = pullRequestNumber,
      associatedBase = base,
      headRepositoryId = repositoryId,
    ) => ({
      base: { repo: { id: repositoryId }, sha: associatedBase },
      head: { repo: { id: headRepositoryId }, sha: head },
      number,
    });
    const exactCheck = (name: string, overrides: Record<string, unknown> = {}) => ({
      app: { id: 156372 },
      completed_at: "2026-08-22T22:43:05Z",
      conclusion: "success",
      head_sha: head,
      name,
      output: {
        title:
          name === "Socket Security: Pull Request Alerts"
            ? `Pull Request #${pullRequestNumber} Alerts: Skipped`
            : "Project Report: Success",
      },
      pull_requests: [pullRequestAssociation()],
      started_at: "2026-08-22T22:43:03Z",
      status: "completed",
      ...overrides,
    });
    const successes = [
      exactCheck("Socket Security: Project Report"),
      exactCheck("Socket Security: Pull Request Alerts"),
    ];
    const execute = async ({
      checkRuns,
      eventDocument = pullRequestEvent,
      eventName = "pull_request",
      expectedTargetSha = head,
      githubSha = merge,
      githubRef = eventName === "push" ? "refs/heads/main" : "refs/pull/16/merge",
      totalCount = checkRuns.length,
    }: {
      checkRuns: Array<Record<string, unknown>>;
      eventDocument?: Record<string, unknown>;
      eventName?: string;
      expectedTargetSha?: string;
      githubSha?: string;
      githubRef?: string;
      totalCount?: number;
    }) => {
      await writeFile(
        fixture,
        JSON.stringify({ check_runs: checkRuns, total_count: totalCount }),
      );
      await writeFile(event, JSON.stringify(eventDocument));
      const child = Bun.spawn(
        ["/bin/bash", "--noprofile", "--norc", "-c", `set -euo pipefail\n${gate?.run as string}`],
        {
          cwd: root,
          env: {
            EXPECTED_SOCKET_URL: `https://api.github.com/repos/collinbentley1/platform/commits/${expectedTargetSha}/check-runs?filter=latest&per_page=100&app_id=156372`,
            FAKE_CURL_ARGUMENTS: curlArguments,
            GH_TOKEN: "test-token",
            GITHUB_EVENT_NAME: eventName,
            GITHUB_EVENT_PATH: event,
            GITHUB_REF: githubRef,
            GITHUB_REPOSITORY: "collinbentley1/platform",
            GITHUB_SHA: githubSha,
            PATH: `${bin}:/usr/bin:/bin`,
            RUNNER_TEMP: root,
            SOCKET_CHECK_FIXTURE: fixture,
          },
          stderr: "pipe",
          stdout: "ignore",
        },
      );
      const [exitCode, stderr] = await Promise.all([
        child.exited,
        new Response(child.stderr).text(),
      ]);
      return { exitCode, stderr };
    };
    const expectTimeout = async (
      checkRuns: Array<Record<string, unknown>>,
      options: Omit<Parameters<typeof execute>[0], "checkRuns"> = {},
    ) => {
      const result = await execute({ checkRuns, ...options });
      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain("Timed out waiting for the exact Socket GitHub App checks");
    };

    expect(await execute({ checkRuns: successes })).toEqual({ exitCode: 0, stderr: "" });
    const failed = await execute({
      checkRuns: [
        exactCheck("Socket Security: Project Report", { conclusion: "failure" }),
        successes[1],
      ],
    });
    expect(failed.exitCode).toBe(1);
    expect(failed.stderr).toContain("completed without success");

    await expectTimeout([...successes, successes[0]]);
    await expectTimeout([successes[0]]);
    await expectTimeout([
      successes[0],
      exactCheck("Socket Security: Pull Request Alerts", {
        completed_at: null,
        conclusion: null,
        status: "in_progress",
      }),
    ]);
    await expectTimeout(successes.map((check) => ({ ...check, app: { id: 1 } })));
    expect(
      await execute({
        checkRuns: [
          ...successes,
          exactCheck("Socket Security: Pull Request Alerts", { app: { id: 1 } }),
        ],
      }),
    ).toEqual({ exitCode: 0, stderr: "" });

    const neutral = await execute({
      checkRuns: [
        successes[0],
        exactCheck("Socket Security: Pull Request Alerts", { conclusion: "neutral" }),
      ],
    });
    expect(neutral.exitCode).toBe(1);
    expect(neutral.stderr).toContain("completed without success");

    await expectTimeout(
      successes.map((check) => ({
        ...check,
        completed_at: "2026-08-22T22:42:59Z",
        started_at: "2026-08-22T22:42:58Z",
      })),
    );
    await expectTimeout(
      successes.map((check) => ({
        ...check,
        pull_requests: [pullRequestAssociation(pullRequestNumber + 1)],
      })),
    );
    await expectTimeout(
      successes.map((check) =>
        check.name === "Socket Security: Pull Request Alerts"
          ? {
              ...check,
              output: { title: `Pull Request #${pullRequestNumber + 1} Alerts: Skipped` },
              pull_requests: [
                pullRequestAssociation(),
                pullRequestAssociation(pullRequestNumber + 1),
              ],
            }
          : check,
      ),
    );
    await expectTimeout(
      successes.map((check) => ({
        ...check,
        pull_requests: [pullRequestAssociation(pullRequestNumber, "d".repeat(40))],
      })),
    );
    await expectTimeout(successes.map((check) => ({ ...check, head_sha: "d".repeat(40) })));
    await expectTimeout(successes, { totalCount: 101 });

    const titleEditEvent = {
      ...pullRequestEvent,
      action: "edited",
      changes: { title: { from: "old title" } },
      pull_request: { ...pullRequestEvent.pull_request, updated_at: "2026-08-22T22:50:00Z" },
    };
    expect(
      await execute({ checkRuns: successes, eventDocument: titleEditEvent }),
    ).toEqual({ exitCode: 0, stderr: "" });
    await expectTimeout(successes, {
      eventDocument: {
        ...titleEditEvent,
        changes: { base: { ref: { from: "staging" } } },
      },
    });

    const forkRepositoryId = 9_999;
    const forkEvent = {
      ...pullRequestEvent,
      pull_request: {
        ...pullRequestEvent.pull_request,
        head: { repo: { id: forkRepositoryId }, sha: head },
      },
    };
    const forkSuccesses = successes.map((check) => ({ ...check, pull_requests: [] }));
    expect(
      await execute({ checkRuns: forkSuccesses, eventDocument: forkEvent }),
    ).toEqual({ exitCode: 0, stderr: "" });
    await expectTimeout(
      forkSuccesses.map((check) =>
        check.name === "Socket Security: Pull Request Alerts"
          ? { ...check, output: { title: "Pull Request #17 Alerts: Skipped" } }
          : check,
      ),
      { eventDocument: forkEvent },
    );

    const pushSha = "e".repeat(40);
    const pushOptions = {
      eventDocument: { repository: { id: repositoryId } },
      eventName: "push",
      expectedTargetSha: pushSha,
      githubSha: pushSha,
    };
    const pushCheck = exactCheck("Socket Security: Project Report", {
      head_sha: pushSha,
      pull_requests: [],
    });
    expect(
      await execute({
        checkRuns: [pushCheck],
        ...pushOptions,
      }),
    ).toEqual({ exitCode: 0, stderr: "" });
    for (const [eventName, githubRef] of [
      ["workflow_dispatch", "refs/heads/feature"],
      ["workflow_dispatch", "refs/heads/main"],
      ["push", "refs/heads/feature"],
    ] as const) {
      const rejected = await execute({
        checkRuns: [pushCheck],
        eventDocument: pushOptions.eventDocument,
        eventName,
        expectedTargetSha: pushSha,
        githubRef,
        githubSha: pushSha,
      });
      expect(rejected.exitCode).toBe(1);
      expect(rejected.stderr).toContain(
        "Socket verification accepts only pull requests or a push to refs/heads/main.",
      );
    }
    await expectTimeout([{ ...pushCheck, completed_at: null, started_at: null }], pushOptions);
    await expectTimeout([{ ...pushCheck, started_at: null }], pushOptions);
    await expectTimeout(
      [
        {
          ...pushCheck,
          completed_at: "2026-08-22T22:43:02Z",
          started_at: "2026-08-22T22:43:03Z",
        },
      ],
      pushOptions,
    );
  });

  test("executable workflow secret contexts reject pre-epoch credential names", async () => {
    for (const path of [
      ".github/workflows/application.yml",
      ".github/workflows/socket-firewall.yml",
      ".github/workflows/infrastructure.yml",
      ".github/workflows/deploy-preview.yml",
      ".github/workflows/deploy-prod.yml",
      ".github/workflows/cleanup-preview.yml",
      ".github/workflows/reconcile-previews.yml",
      ".github/workflows/platform.yml",
      "templates/app/.github/workflows/deploy-preview.yml",
      "templates/app/.github/workflows/deploy-prod.yml",
    ]) {
      const references = semanticSecretContextReferences(
        await readFile(join(repoRoot, path), "utf8"),
      );
      for (const reference of references) {
        for (const retired of [
          "DHI_ACCESS_TOKEN",
          "SOCKET_API_TOKEN",
          "WAITLIST_IDENTITY_KEYSET",
        ]) {
          expect(reference.value).not.toMatch(
            new RegExp(
              `secrets(?:\\.${retired}(?![A-Z0-9_])|\\[['\"]${retired}['\"]\\])`,
            ),
          );
        }
      }
    }
  });

  test("security rollout orders protected-environment canaries and the sole DHI credential before Actions re-enable", async () => {
    const rollout = await readFile(join(repoRoot, "docs/security-rollout.md"), "utf8");
    const orderedGates = [
      "Keep every consumer's Actions disabled while establishing the new",
      "create and protect every\n   environment explicitly before any workflow names it",
      "Create the DHI environment with no secrets or variables first",
      "Prove a\n   default-branch, exact-SHA `pull_request_target` caller can enter it",
      "prove a temporary ordinary `pull_request` workflow authored by the PR",
      "Only after both canaries pass may the owner populate",
      "Before re-enabling Actions, semantically prove every workflow and caller has",
      "Delete the old\n   `preview-build`, `production-build`, and `dependency-scan` environments only",
      "Re-read environment, repository, and organization secret\n   inventories",
      "Re-enable consumers one at a time only after the new",
    ];
    let previous = -1;
    for (const gate of orderedGates) {
      const current = rollout.indexOf(gate);
      expect(current).toBeGreaterThan(previous);
      previous = current;
    }
    for (const environment of [
      "`dhi-base-prefetch-20260822-098dca9280b3`",
      "`preview-publish`",
      "`preview-publish-canary`",
      "`preview-cloud`",
      "`preview-cloud-canary`",
      "`preview-operations`",
      "`supply-chain`",
      "`production`",
      "`production-canary`",
      "`production-publish`",
    ]) {
      expect(rollout).toContain(environment);
    }
    expect(rollout).toContain("selected branch\n     `main` only, zero reviewers, and administrator bypass disabled");
    expect(rollout).toContain("owner reviewer, and administrator bypass disabled");
    expect(rollout).toContain("`DHI_PUBLIC_READ_TOKEN_20260822_098DCA9280B3`");
    expect(rollout).toContain("four consumer DHI environments each\n   contain the sole epoch DHI token");
    expect(rollout).toContain("Socket uses no GitHub secret or paid\n   scanner token");
    expect(rollout).toContain("Medlock/Health has no GitHub waitlist key");
    expect(rollout).toContain("least-scope, non-default public `pk.*` value");
    expect(rollout).toContain("default public token\n   is forbidden");
    expect(rollout).toContain("no secret forwarding, no `secrets: inherit`");
    expect(rollout).toContain("The historical `161ac5c` tree predates this pipeline");
  });

  test("the app contract documents the credentialless artifact boundary and exact environment matrix", async () => {
    const contract = await readFile(join(repoRoot, "docs/app-contract.md"), "utf8");
    expect(contract).toContain("Deploy callers forward no secrets");
    expect(contract).toContain("`pull_request_target` definition");
    expect(contract).toContain("`dhi-base-prefetch-20260822-098dca9280b3`");
    expect(contract).toContain("`DHI_PUBLIC_READ_TOKEN_20260822_098DCA9280B3`");
    expect(contract).toContain("No GHCR staging package or packages permission");
    expect(contract).toContain("Socket GitHub App id `156372`");
    expect(contract).toContain("Medlock/Health has no GitHub signing-key secret");
    expect(contract).toContain("DHI's signature does not attest the overlaid Bun binary");
    expect(contract).toContain("environments carry it as the non-confidential `MAPBOX_PUBLIC_TOKEN` variable");
    expect(contract).toContain("have zero reviewers, and disable administrator bypass");
    expect(contract).toContain("require the owner reviewer, and disable\nadministrator bypass");
    for (const stale of [
      "reviewed five-name preview",
      "six-name production secret contract",
      "DHI_ACCESS_TOKEN_20260822",
      "SOCKET_API_TOKEN_20260822",
      "WAITLIST_IDENTITY_KEYSET_20260822",
      "MAPBOX_PUBLIC_TOKEN` secret slots",
    ]) {
      expect(contract).not.toContain(stale);
    }
  });

  test("PR-controlled Docker output cannot issue GitHub runner commands", async () => {
    for (const [workflowName, buildName] of [
      ["deploy-preview.yml", "Build untrusted preview image into a local OCI archive"],
      ["deploy-prod.yml", "Build production image into a local OCI archive"],
    ] as const) {
      const workflow = await readFile(
        join(repoRoot, ".github/workflows", workflowName),
        "utf8",
      );
      const disable = workflow.indexOf(
        "Disable workflow commands for untrusted build output",
      );
      const build = workflow.indexOf(buildName);
      const restore = workflow.indexOf(
        "Restore workflow commands after untrusted build output",
      );
      expect(disable).toBeGreaterThan(-1);
      expect(disable).toBeLessThan(build);
      expect(build).toBeLessThan(restore);
      expect(workflow).toContain('token_file="$RUNNER_TEMP/platform-build-command-token"');
      expect(workflow).toContain("cat /proc/sys/kernel/random/uuid");
      expect(workflow).toContain("printf '::stop-commands::%s\\n'");
      expect(workflow.slice(restore, workflow.indexOf("\n      - name:", restore + 1))).toContain(
        "if: always() && github.run_attempt == '1'",
      );
      const actionWindow = workflow.slice(build, restore);
      expect(actionWindow).toContain(
        "uses: docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf",
      );
      expect(actionWindow).toContain('DOCKER_BUILD_RECORD_UPLOAD: "false"');
      expect(actionWindow).toContain('DOCKER_BUILD_SUMMARY: "false"');
      expect(actionWindow).toContain('DOCKER_BUILD_CHECKS_ANNOTATIONS: "false"');
      expect(actionWindow).toContain('github-token: ""');
      expect(actionWindow).not.toContain("platform-build-command-token");
    }
  });

  test("Checkov bypasses the action wrapper and accepts only trusted policy mounts", async () => {
    const workflow = await readFile(join(repoRoot, ".github/workflows/platform.yml"), "utf8");
    expect(workflow).toContain(
      "CHECKOV_IMAGE: ghcr.io/bridgecrewio/checkov@sha256:f4c7c5bde21df03432ca8d9d1305ffe21b7205ea752c3d4e65559abae67ead4a",
    );
    for (const boundary of [
      "docker run --rm --pull=never",
      "--network=none",
      "--read-only",
      "--cap-drop=ALL",
      "--security-opt no-new-privileges=true",
      "--user 65532:65532",
      "--workdir /tmp",
      '--mount "type=bind,src=${terraform_root},dst=/scan,readonly"',
      '--mount "type=bind,src=${policy_file},dst=/policy.yml,readonly"',
      "--directory /scan",
      "--config-file /policy.yml",
      "--skip-download",
      "--skip-path '(^|/)\\.terraform(/|$)'",
    ]) {
      expect(workflow).toContain(boundary);
    }
    for (const configName of [".checkov.yml", ".checkov.yaml", "checkov.yml", "checkov.yaml"]) {
      expect(workflow).toContain(configName);
    }
    expect(await readFile(join(repoRoot, "tools/ci/checkov-platform.yml"), "utf8")).toBe(
      "soft-fail: false\n",
    );
    expect(workflow).toContain("The platform Checkov policy must contain only the fail-closed setting.");
    expect(workflow).not.toContain('uses: docker://ghcr.io/bridgecrewio/checkov@');

    const infrastructure = await readFile(
      join(repoRoot, ".github/workflows/infrastructure.yml"),
      "utf8",
    );
    expect(infrastructure).toContain(
      "CHECKOV_IMAGE: ghcr.io/bridgecrewio/checkov@sha256:f4c7c5bde21df03432ca8d9d1305ffe21b7205ea752c3d4e65559abae67ead4a",
    );
    expect(infrastructure).toContain('policy_file="$RUNNER_TEMP/platform-checkov.yml"');
    expect(infrastructure).toContain('chmod 0444 "$policy_file"');
    expect(infrastructure).toContain(
      '--mount "type=bind,src=${scan_root},dst=/scan,readonly"',
    );
    expect(infrastructure).toContain(
      '--mount "type=bind,src=${policy_file},dst=/policy.yml,readonly"',
    );
    expect(infrastructure).toContain("--entrypoint /usr/local/bin/checkov");
    expect(infrastructure).toContain("--skip-path '(^|/)work(/|$)'");
    expect(infrastructure).not.toContain("--skip-path work");
    expect(infrastructure).not.toContain('uses: docker://ghcr.io/bridgecrewio/checkov@');
    expect(infrastructure).toContain("Terraform policy search failed closed.");
    expect(infrastructure).toContain("Terraform module search failed closed for $root.");
    expect(infrastructure).toContain("Platform reference search failed closed.");
    expect(infrastructure).toContain("Checkov suppression search failed closed.");
    expect(infrastructure).not.toMatch(/grep -R/);
    expect(infrastructure).not.toMatch(/\bgrep\s+-[A-Za-z]*I/);
    expect(infrastructure).not.toContain("--binary-files=without-match");
    expect(infrastructure.match(/grep -raE/g)).toHaveLength(2);
    expect(infrastructure.match(/grep -rahcE/g)).toHaveLength(2);
    expect(infrastructure).not.toContain("(^|[^[:alnum:]_])(resource|data)[[:space:]]+");
    expect(infrastructure).toContain(
      'provisioner[[:space:]]+"(local-exec|remote-exec)"',
    );
    expect(infrastructure).toContain(
      "Consumer roots may contain only the exact reviewed Terraform mirror",
    );
    expect(infrastructure).toContain("(^|[^[:alnum:]_])module[[:space:]]+");
    expect(infrastructure).toContain("infra/terraform >/dev/null; then");
    expect(infrastructure).toContain("' . >/dev/null; then");
    expect(infrastructure).not.toContain('printf \'%s\\n\' "$platform_refs"');
  });

  test("security searches reject NUL-bearing and comment-prefixed HCL policy text", async () => {
    const root = await mkdtemp(join(tmpdir(), "platform-grep-text-test-"));
    temporaryRoots.push(root);
    const terraformRoot = join(root, "infra", "terraform");
    const bootstrapRoot = join(terraformRoot, "bootstrap");
    await mkdir(bootstrapRoot, { recursive: true });

    await writeFile(
      join(bootstrapRoot, "safe\n::warning title=Injected::untrusted filename\ntail.tf"),
      Buffer.from(
        '# binary-classification probe \0 remains inside this comment\n/* same-line comment prefix */ resource "terraform_data" "probe" {\n  provisioner "local-exec" {\n    command = "false"\n  }\n}\n',
      ),
    );
    await writeFile(
      join(bootstrapRoot, "modules.tf"),
      Buffer.from(
        '# binary-classification probe \0 remains inside this comment\nmodule "first" { source = "github.com/collinbentley1/platform//terraform/modules/bootstrap?ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }\n/* same-line comment prefix */ module "second" { source = "github.com/collinbentley1/platform//terraform/modules/bootstrap?ref=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }\n',
      ),
    );
    await writeFile(
      join(root, "safe\n::warning title=Injected::untrusted filename\ntail.yaml"),
      Buffer.from(
        '# binary-classification probe \0 remains inside this comment\n# checkov:skip=CKV_TEST:caller suppression must be rejected\n',
      ),
    );

    const forbidden = await grep([
      "-rahcE",
      '(^|[^[:alnum:]_])(resource|data)[[:space:]]+"|provisioner[[:space:]]+"(local-exec|remote-exec)"|(^|[^[:alnum:]_])external([^[:alnum:]_]|$)',
      terraformRoot,
    ]);
    expect(forbidden.exitCode).toBe(0);
    expect(sumGrepCounts(forbidden.stdout)).toBe(2);
    expect(forbidden.stdout).not.toContain("::warning");

    const modules = await grep([
      "-rahcE",
      "--include=*.tf",
      '(^|[^[:alnum:]_])module[[:space:]]+"',
      bootstrapRoot,
    ]);
    expect(modules.exitCode).toBe(0);
    expect(sumGrepCounts(modules.stdout)).toBe(2);

    const references = await grep([
      "-rahcE",
      'collinbentley1/platform|github\\.com/[^"[:space:]]+/platform',
      terraformRoot,
    ]);
    expect(references.exitCode).toBe(0);
    expect(sumGrepCounts(references.stdout)).toBe(2);

    const suppressions = await grep([
      "-rahcE",
      "--exclude-dir=.git",
      "#[[:space:]]*checkov:skip",
      root,
    ]);
    expect(suppressions.exitCode).toBe(0);
    expect(sumGrepCounts(suppressions.stdout)).toBe(1);
    expect(suppressions.stdout).not.toContain("::warning");
  });

  test("hosted-runner workflows do not depend on ambient ripgrep", async () => {
    for (const workflowName of [
      "application.yml",
      "socket-firewall.yml",
      "infrastructure.yml",
      "deploy-prod.yml",
      "deploy-preview.yml",
      "cleanup-preview.yml",
      "reconcile-previews.yml",
      "platform.yml",
    ]) {
      const workflow = await readFile(
        join(repoRoot, ".github/workflows", workflowName),
        "utf8",
      );
      expect(workflow).not.toMatch(/\brg\b/);
    }
  });

  test("raw artifact basenames exactly match every downstream metadata check", async () => {
    const uploadAction =
      "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a";
    const helper = await readFile(
      join(repoRoot, "tools/ci/container-artifact-contract.sh"),
      "utf8",
    );
    const prefetchHelper = helper.slice(
      helper.indexOf("prefetch() {\n"),
      helper.indexOf("\nverify_base() {\n"),
    );
    const promoteHelper = helper.slice(
      helper.indexOf("promote_image() {\n"),
      helper.indexOf("\nvalidate_promoted() {\n"),
    );
    expect(prefetchHelper).toContain(
      'local artifact="$RUNNER_TEMP/platform-${kind}-bases-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}.tar"',
    );
    expect(prefetchHelper).toContain('echo "artifact=$artifact" >> "$GITHUB_OUTPUT"');
    expect(promoteHelper).toContain(
      'local artifact="$RUNNER_TEMP/platform-${kind}-promoted-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}.tar"',
    );
    expect(promoteHelper).toContain('echo "artifact=$artifact" >> "$GITHUB_OUTPUT"');

    for (const [workflowName, kind] of [
      ["deploy-preview.yml", "preview"],
      ["deploy-prod.yml", "production"],
    ] as const) {
      const source = await readFile(join(repoRoot, ".github/workflows", workflowName), "utf8");
      const workflow = Bun.YAML.parse(source) as {
        jobs: Record<
          string,
          {
            steps?: Array<{
              env?: Record<string, unknown>;
              id?: string;
              run?: string;
              uses?: string;
              with?: Record<string, unknown>;
            }>;
          }
        >;
      };
      const uploads = Object.entries(workflow.jobs).flatMap(([jobName, job]) =>
        (job.steps ?? [])
          .filter(
            (step) =>
              typeof step.uses === "string" &&
              step.uses.startsWith("actions/upload-artifact@"),
          )
          .map((step) => ({ jobName, step })),
      );

      expect(uploads).toHaveLength(3);
      expect(uploads.map(({ jobName }) => jobName).sort()).toEqual([
        "build",
        "prefetch-bases",
        "verify-image",
      ]);
      const expectedPaths: Record<string, string> = {
        build: "${{ runner.temp }}/platform-image.oci.tar",
        "prefetch-bases": "${{ steps.bundle.outputs.artifact }}",
        "verify-image": "${{ steps.promote.outputs.artifact }}",
      };
      for (const { jobName, step } of uploads) {
        expect(step.uses, `${workflowName}/${jobName} upload action drifted`).toBe(
          uploadAction,
        );
        expect(step.id, `${workflowName}/${jobName} must expose the exact artifact id`).toBe(
          "upload",
        );
        expect(step.with?.archive, `${workflowName}/${jobName} must remain raw`).toBe(false);
        expect(
          step.with?.name,
          `${workflowName}/${jobName} must not pretend raw-mode name overrides are authoritative`,
        ).toBeUndefined();
        expect(step.with?.path, `${workflowName}/${jobName} upload path drifted`).toBe(
          expectedPaths[jobName],
        );
      }

      for (const [jobName, stepId, operation] of [
        ["prefetch-bases", "bundle", "prefetch"],
        ["verify-image", "promote", "promote"],
      ] as const) {
        const producers = (workflow.jobs[jobName]?.steps ?? []).filter(
          (step) => step.id === stepId,
        );
        expect(producers).toHaveLength(1);
        expect(producers[0]?.env?.ARTIFACT_KIND).toBe(kind);
        expect(producers[0]?.run).toContain(`container-artifact-contract.sh\" ${operation}`);
      }

      const baseName = `platform-${kind}-bases-\${GITHUB_RUN_ID}-\${GITHUB_RUN_ATTEMPT}.tar`;
      const promotedName = `platform-${kind}-promoted-\${GITHUB_RUN_ID}-\${GITHUB_RUN_ATTEMPT}.tar`;
      expect(new Set([baseName, "platform-image.oci.tar", promotedName]).size).toBe(3);
      const baseCheck =
        `verify_artifact "$BASE_ARTIFACT_ID" "$BASE_ARTIFACT_DIGEST" "${baseName}"`;
      const builtCheck =
        'verify_artifact "$BUILT_ARTIFACT_ID" "$BUILT_ARTIFACT_DIGEST" platform-image.oci.tar';
      const promotedCheck =
        `verify_artifact "$ARTIFACT_ID" "$ARTIFACT_DIGEST" "${promotedName}"`;
      const verifyImage = source.slice(
        source.indexOf("  verify-image:\n"),
        source.indexOf("\n  canary:\n"),
      );
      const publish = source.slice(
        source.indexOf("  publish:\n"),
        source.indexOf("\n  attest:\n"),
      );
      expect(verifyImage).toContain(baseCheck);
      expect(verifyImage).toContain(builtCheck);
      expect(publish).toContain(baseCheck);
      expect(publish).toContain(promotedCheck);
      expect(source.split(baseCheck)).toHaveLength(3);
      expect(source.split(builtCheck)).toHaveLength(2);
      expect(source.split(promotedCheck)).toHaveLength(2);
    }
  });

  test("SBOM attest jobs consume the exact uploaded artifact and verify its content", async () => {
    for (const workflowName of ["deploy-preview.yml", "deploy-prod.yml"]) {
      const workflow = await readFile(
        join(repoRoot, ".github/workflows", workflowName),
        "utf8",
      );
      const verify = workflow.slice(workflow.indexOf("  verify-image:\n"), workflow.indexOf("\n  canary:\n"));
      const attest = workflow.slice(workflow.indexOf("  attest:\n"), workflow.indexOf("\n  deploy:\n"));

      expect(verify).toContain(
        "artifact-id: ${{ steps.upload.outputs.artifact-id }}",
      );
      expect(verify).toContain(
        "sbom-content-digest: ${{ steps.promote.outputs.sbom_sha256 }}",
      );
      expect(verify).toContain("id: promote");
      expect(verify).toContain("id: upload");
      expect(verify.indexOf("id: promote")).toBeLessThan(verify.indexOf("id: upload"));
      expect(attest).toContain(
        "artifact-ids: ${{ needs.verify-image.outputs.artifact-id }}",
      );
      expect(attest).toContain("digest-mismatch: error");
      expect(attest).toContain(
        "EXPECTED_SBOM_DIGEST: ${{ needs.verify-image.outputs.sbom-content-digest }}",
      );
      expect(attest).toContain("sha256sum --check --strict");
      expect(attest).toContain("./dhi-runtime.manifest.json");
    }
  });

  test("a new pull request head invalidates the prior preview before rebuilding", async () => {
    const caller = await readFile(
      join(repoRoot, "templates/app/.github/workflows/deploy-preview.yml"),
      "utf8",
    );
    const cleanup = await readFile(
      join(repoRoot, ".github/workflows/cleanup-preview.yml"),
      "utf8",
    );
    const deploy = await readFile(
      join(repoRoot, ".github/workflows/deploy-preview.yml"),
      "utf8",
    );
    const reconcile = await readFile(
      join(repoRoot, ".github/workflows/reconcile-previews.yml"),
      "utf8",
    );
    const reconcileCaller = await readFile(
      join(repoRoot, "templates/app/.github/workflows/reconcile-previews.yml"),
      "utf8",
    );
    const controller = await readFile(
      join(repoRoot, "tools/ci/cloud-run-preview-controller.sh"),
      "utf8",
    );

    expect(caller).toContain("- converted_to_draft");
    expect(caller).toContain("github.event.action == 'synchronize'");
    expect(caller).toContain("github.event.pull_request.draft == false");
    expect(caller).toContain("uses: collinbentley1/platform/.github/workflows/cleanup-preview.yml@");
    expect(caller.indexOf("invalidate:")).toBeLessThan(caller.indexOf("deploy:"));
    expect(caller).toContain("needs: invalidate");
    expect(cleanup).toContain("github.event.action == 'synchronize'");
    expect(cleanup).toContain("github.event.action == 'converted_to_draft'");
    expect(cleanup).toContain("gha-preview-deploy@");
    expect(cleanup).toContain("iam_audit_service_account=gha-preview-operator@");
    expect(cleanup).not.toContain("deploy_service_account=gha-preview-operator@");
    expect(cleanup).not.toContain("actions/checkout@");
    expect(cleanup).toContain("PR_NUMBER: ${{ github.event.pull_request.number }}");
    expect(cleanup).toContain('cloud-run-preview-controller.sh" remove');
    expect(deploy).toContain('--revision-suffix="$revision_suffix"');
    expect(deploy).toContain("EXPECTED_HEAD_SHA: ${{ github.event.pull_request.head.sha }}");
    const publishCanary = deploy.slice(
      deploy.indexOf("  publish-canary:\n"),
      deploy.indexOf("\n  publish:\n"),
    );
    expect(publishCanary).toContain("environment: preview-publish-canary");
    expect(publishCanary).not.toContain("GCP_CLOUD_PREVIEW_ENABLED");
    expect(deploy.slice(deploy.indexOf("  publish:\n"), deploy.indexOf("\n  attest:\n"))).toContain(
      "needs.publish-canary.result == 'success'",
    );
    expect(deploy).toContain("  invalidate:\n");
    const invalidation = deploy.slice(deploy.indexOf("  invalidate:\n"));
    expect(invalidation).toContain("gha-preview-commit@");
    expect(invalidation).not.toContain("gha-preview-deploy@");
    expect(invalidation).toContain("iam_audit_service_account=gha-preview-operator@");
    expect(invalidation).not.toContain("deploy_service_account=gha-preview-operator@");
    expect(invalidation).not.toContain("actions/checkout@");
    expect(invalidation).toContain('cloud-run-preview-controller.sh" remove');
    expect(deploy).toContain("deployed-revision: ${{ steps.deploy.outputs.revision }}");
    expect(deploy).toContain(
      'gh pr comment "$PR_NUMBER" --repo "$GITHUB_REPOSITORY" --body',
    );
    expect(deploy).not.toContain('gh pr comment "$PR_NUMBER" --body');
    const parsedPreview = Bun.YAML.parse(deploy) as {
      jobs: { deploy: { steps: Array<Record<string, unknown>> } };
    };
    const commentStep = parsedPreview.jobs.deploy.steps.find(
      (step) => step.name === "Comment preview URL only after final admission",
    );
    expect(commentStep).toBeDefined();
    const commentRun = commentStep?.run as string;
    const commentRoot = await mkdtemp(join(tmpdir(), "platform-preview-comment-"));
    temporaryRoots.push(commentRoot);
    const commentBin = join(commentRoot, "bin");
    await mkdir(commentBin);
    const commentCapture = join(commentRoot, "arguments.txt");
    const fakeCommentGh = join(commentBin, "gh");
    await writeFile(
      fakeCommentGh,
      ["#!/bin/sh", "set -eu", "printf '%s\\n' \"$@\" > \"$FAKE_GH_CAPTURE\"", ""].join(
        "\n",
      ),
    );
    await chmod(fakeCommentGh, 0o755);
    const commentChild = Bun.spawn(["/bin/bash", "-c", commentRun], {
      cwd: commentRoot,
      env: {
        EXPECTED_HEAD_SHA: "a".repeat(40),
        FAKE_GH_CAPTURE: commentCapture,
        GH_TOKEN: "test-token",
        GITHUB_REPOSITORY: "collinbentley1/cdbentley",
        PATH: `${commentBin}:${process.env.PATH ?? "/usr/bin:/bin"}`,
        PREVIEW_REVISION: "cdbentley-preview-p31-test",
        PREVIEW_URL: "https://pr-31.example.test",
        PR_NUMBER: "31",
      },
      stdout: "ignore",
      stderr: "pipe",
    });
    const [commentExit, commentStderr] = await Promise.all([
      commentChild.exited,
      new Response(commentChild.stderr).text(),
    ]);
    expect({ commentExit, commentStderr }).toEqual({ commentExit: 0, commentStderr: "" });
    expect((await readFile(commentCapture, "utf8")).trim().split("\n")).toEqual([
      "pr",
      "comment",
      "31",
      "--repo",
      "collinbentley1/cdbentley",
      "--body",
      `Preview for commit ${"a".repeat(40)} deployed at https://pr-31.example.test (revision cdbentley-preview-p31-test).`,
    ]);
    expect(invalidation).toContain(
      "EXPECTED_TARGET_REVISION: ${{ needs.deploy.outputs.deployed-revision }}",
    );
    expect(controller).toContain(
      'if [ -n "$EXPECTED_TARGET_REVISION" ] && [ "$live_revision" != "$EXPECTED_TARGET_REVISION" ]',
    );
    expect(deploy).toContain("git-head-sha=${EXPECTED_HEAD_SHA}");
    expect(deploy).toContain("github-repository-id=${REPOSITORY_ID}");
    expect(deploy).toContain("platform-workflow-sha=${PLATFORM_WORKFLOW_SHA}");
    expect(deploy).toContain("PLATFORM_WORKFLOW_SHA: ${{ job.workflow_sha }}");
    expect(deploy).toContain('.metadata.labels["platform-workflow-sha"] == $workflow_sha');
    expect(deploy).toContain('gcloud run revisions describe "$preview_revision"');
    expect(reconcile).toContain('cloud-run-preview-controller.sh" reconcile');
    expect(controller).toContain('gcloud run revisions describe "$live_revision"');
    expect(controller).toContain('.head.sha == $head');
    expect(controller).toContain('.metadata.labels["github-repository-id"] == $repository_id');
    expect(controller).toContain('.metadata.labels["platform-workflow-sha"] == $workflow_sha');
    expect(reconcile).toContain("EXPECTED_PLATFORM_WORKFLOW_SHA: ${{ job.workflow_sha }}");
    expect(reconcileCaller).toContain("on:\n  push:\n    branches:\n      - main\n  schedule:");
    expect(reconcile).not.toContain("expected_revision_prefix");
    expect(reconcile).toContain("gha-preview-deploy@");
    expect(reconcile).toContain("iam_audit_service_account=gha-preview-operator@");
    expect(reconcile).not.toContain("deploy_service_account=gha-preview-operator@");
    expect(reconcile).not.toContain("actions/checkout@");
    expect(controller).toContain('[ "$status" = 404 ]');
  });

  test("Critical History previews use one stable origin without a run.app bypass", async () => {
    const preview = await readFile(
      join(repoRoot, ".github/workflows/deploy-preview.yml"),
      "utf8",
    );
    const deploy = preview.slice(
      preview.indexOf("  deploy:\n"),
      preview.indexOf("\n  invalidate:\n"),
    );
    const transaction = await readFile(
      join(repoRoot, "tools/ci/cloud-run-preview-traffic.sh"),
      "utf8",
    );

    expect(deploy).toContain('stable_preview_domain="preview.ycriticalhistory.org"');
    expect(deploy).toContain('preview_ingress="internal-and-cloud-load-balancing"');
    expect(deploy).not.toContain("--ingress=all");
    expect(deploy).toContain(
      'deterministic_url="https://pr-${PR_NUMBER}---${PREVIEW_SERVICE}-${PROJECT_NUMBER}.${REGION}.run.app"',
    );
    expect(deploy).toContain(
      'public_preview_url="https://pr-${PR_NUMBER}.${STABLE_PREVIEW_DOMAIN}"',
    );
    expect(deploy).toContain("PLATFORM_DEPLOY_NONCE: $deploy_nonce");
    expect(deploy).toContain('preview_nonce="$(openssl rand -hex 32)"');
    expect(deploy).toContain('"${public_preview_url}/livez"');
    expect(deploy).toContain("--max-filesize 1024");
    expect(deploy).not.toContain('"${public_preview_url}/livez" || true');
    expect(deploy).toContain('jq -e -s --arg nonce "$preview_nonce"');
    expect(deploy).not.toContain("*.preview.ycriticalhistory.org");
    expect(deploy).toContain("cloud-run-preview-traffic.sh\" commit");
    expect(deploy).toContain("steps.traffic-commit.outputs.admitted == 'true'");
    expect(transaction).toContain('live_url="https://${live_tag}.${STABLE_PREVIEW_DOMAIN}"');
    expect(transaction).toContain('length == 1 and .[0] == {deployment:$nonce,ok:true}');
    expect(transaction).toContain("capture_snapshot health-after false");
    expect(transaction.indexOf("patched=true")).toBeLessThan(
      transaction.indexOf("?updateMask=${commit_update_mask}&allowMissing=false", transaction.indexOf("patched=true")),
    );
    expect(transaction.lastIndexOf("capture_snapshot health-after false")).toBeLessThan(
      transaction.lastIndexOf("patched=false"),
    );

    const templateServer = await readFile(
      join(repoRoot, "templates/app/src/server.ts"),
      "utf8",
    );
    expect(templateServer).toContain("Bun.env.PLATFORM_DEPLOY_NONCE");

    const router = await readFile(
      join(repoRoot, "terraform/modules/cloud-run-preview-domain/main.tf"),
      "utf8",
    );
    const exposure = await readFile(
      join(repoRoot, "terraform/deployments/exposure/main.tf"),
      "utf8",
    );
    const production = await readFile(
      join(repoRoot, "terraform/deployments/prod/main.tf"),
      "utf8",
    );
    expect(router).toContain('network_endpoint_type = "SERVERLESS"');
    expect(router).toContain("service  = var.preview_service_name");
    expect(router).toContain('url_mask = "<tag>.${var.preview_domain}"');
    expect(router).toContain('load_balancing_scheme = "EXTERNAL_MANAGED"');
    expect(router).toContain('min_tls_version = "TLS_1_2"');
    expect(router).toContain('port_range            = "443"');
    expect(router.match(/deletion_policy\s*=\s*"PREVENT"/g)?.length).toBe(11);
    expect(router).not.toContain("allUsers");
    expect(exposure).toContain('var.repository_id == "280932482"');
    expect(exposure).toContain('toset(["preview.ycriticalhistory.org"])');
    const exposureOutputs = await readFile(
      join(repoRoot, "terraform/deployments/exposure/outputs.tf"),
      "utf8",
    );
    expect(exposureOutputs).not.toContain("try(");
    expect(production).toContain(
      'preview_ingress                          = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"',
    );

    const nonce = "a".repeat(64);
    const healthRoot = await mkdtemp(join(tmpdir(), "platform-health-test-"));
    temporaryRoots.push(healthRoot);
    const validHealth = join(healthRoot, "valid.json");
    const concatenatedHealth = join(healthRoot, "concatenated.json");
    await writeFile(validHealth, `{"deployment":"${nonce}","ok":true}\n`);
    await writeFile(
      concatenatedHealth,
      `{"deployment":"wrong","ok":false}\n{"deployment":"${nonce}","ok":true}\n`,
    );
    const predicate = 'length == 1 and .[0] == {deployment: $nonce, ok: true}';
    const validJq = Bun.spawn(
      ["jq", "-e", "-s", "--arg", "nonce", nonce, predicate, validHealth],
      { stdout: "ignore", stderr: "pipe" },
    );
    const concatenatedJq = Bun.spawn(
      ["jq", "-e", "-s", "--arg", "nonce", nonce, predicate, concatenatedHealth],
      { stdout: "ignore", stderr: "pipe" },
    );
    expect(await validJq.exited).toBe(0);
    expect(await concatenatedJq.exited).not.toBe(0);
  });

  test("Artifact Registry identities retain only their repository-scoped delivery permissions", async () => {
    const approvedModuleFiles = ["main.tf", "outputs.tf", "variables.tf", "versions.tf"];
    for (const moduleName of ["cloud-run-service", "bootstrap"]) {
      const moduleDirectory = join(repoRoot, "terraform/modules", moduleName);
      const approvedEntries = moduleName === "bootstrap"
        ? [...approvedModuleFiles, ".terraform.lock.hcl", "tests", "workflow-authority.json"].sort()
        : approvedModuleFiles;
      expect((await readdir(moduleDirectory)).sort()).toEqual(approvedEntries);
      for (const name of approvedModuleFiles.filter((file) => file !== "main.tf")) {
        expect(await readFile(join(moduleDirectory, name), "utf8")).not.toMatch(
          /^\s*(?:resource|data|module|locals|provider)\s+(?:"|\{)/m,
        );
      }
    }
    const workflowAuthorityTest = await readFile(
      join(repoRoot, "terraform/modules/bootstrap/tests/workflow_authority.tftest.hcl"),
      "utf8",
    );
    for (const run of [
      "active_sha_binds_the_exact_job_tuple_matrix",
      "transition_sha_extends_only_the_preview_operations_tuples",
      "neighbouring_tuples_and_unauthorized_accounts_bind_nothing",
      "federated_principals_reach_only_bound_service_accounts",
    ]) {
      expect(workflowAuthorityTest).toContain(`run "${run}"`);
    }
    expect(workflowAuthorityTest).toContain("expect_failures = [var.transition_workflow_sha]");
    for (const [workflowName, publishEnvironment, publisher, operator] of [
      ["deploy-prod.yml", "production-publish", "gha-prod-publish@", "gha-prod-deploy@"],
      ["deploy-preview.yml", "preview-publish", "gha-preview-publish@", "gha-preview-deploy@"],
    ] as const) {
      const workflow = await readFile(
        join(repoRoot, ".github/workflows", workflowName),
        "utf8",
      );
      const publish = workflow.slice(
        workflow.indexOf("  publish:\n"),
        workflow.indexOf("\n  attest:\n"),
      );
      const deploy = workflow.slice(workflow.indexOf("  deploy:\n"));

      expect(publish).toContain(`environment: ${publishEnvironment}`);
      expect(publish).toContain(publisher);
      expect(publish).not.toContain(operator);
      expect(deploy).toContain(operator);
      expect(deploy).not.toContain(publisher);
    }

    const serviceModuleFiles = await Promise.all(
      approvedModuleFiles.map((name) =>
        readFile(join(repoRoot, "terraform/modules/cloud-run-service", name), "utf8"),
      ),
    );
    const serviceModule = serviceModuleFiles[0]!;
    const allServiceModuleTerraform = serviceModuleFiles.join("\n");
    expect(createHash("sha256").update(serviceModule).digest("hex")).toBe(
      "349780e0b92a85bbf4e6d1f330bfecadbb887c5183cca9a35729bdfec518dbab",
    );
    const productionServiceStart = serviceModule.indexOf(
      'resource "google_cloud_run_v2_service" "site"',
    );
    const productionService = serviceModule.slice(
      productionServiceStart,
      serviceModule.indexOf(
        'resource "google_cloud_run_v2_service_iam_member" "prod_deploy"',
        productionServiceStart,
      ),
    );
    const previewServiceStart = serviceModule.indexOf(
      'resource "google_cloud_run_v2_service" "preview"',
    );
    const previewService = serviceModule.slice(
      previewServiceStart,
      serviceModule.indexOf(
        'resource "google_cloud_run_v2_service_iam_member" "preview_deploy"',
        previewServiceStart,
      ),
    );
    const previewLifecycle = previewService.slice(
      previewService.indexOf("  lifecycle {\n"),
      previewService.indexOf("\n  depends_on"),
    );
    expect(productionService).not.toContain("template[0].revision");
    expect(previewLifecycle).toContain(
      "# deploy-preview owns deterministic revision names. Land preview template\n" +
        "      # changes through that workflow first to avoid immutable-name conflicts.",
    );
    expect(previewService.split("template[0].revision")).toHaveLength(2);
    expect(previewLifecycle.split("      template[0].revision,\n")).toHaveLength(2);
    expect(serviceModule).not.toMatch(/^\s*module\s+"/m);
    expect(serviceModule).not.toMatch(/<<|\/\*|^\s*\/\//m);
    expect(serviceModule).toContain(
      'resource "google_artifact_registry_repository_iam_member" "prod_publisher_writer"',
    );
    expect(serviceModule).toContain(
      'resource "google_artifact_registry_repository_iam_member" "preview_publisher_writer"',
    );
    expect(serviceModule).toContain(
      'member     = "serviceAccount:${var.prod_publisher_service_account_email}"',
    );
    expect(serviceModule).toContain(
      'member     = "serviceAccount:${var.preview_publisher_service_account_email}"',
    );
    expect(serviceModule).not.toContain(
      'resource "google_artifact_registry_repository_iam_member" "prod_deploy_writer" {',
    );
    expect(serviceModule).not.toContain(
      'resource "google_artifact_registry_repository_iam_member" "preview_deploy_writer" {',
    );
    for (const [resource, reader, repository] of [
      ["prod_deploy_reader", "prod_deploy_service_account_email", "site"],
      ["preview_deploy_reader", "preview_deploy_service_account_email", "preview"],
    ] as const) {
      const start = serviceModule.indexOf(
        `resource "google_artifact_registry_repository_iam_member" "${resource}"`,
      );
      const block = serviceModule.slice(start, serviceModule.indexOf("\n}\n", start) + 3);
      expect(block).toContain('role       = "roles/artifactregistry.reader"');
      expect(block).toContain(`member     = "serviceAccount:\${var.${reader}}"`);
      expect(block).toContain(
        `repository = google_artifact_registry_repository.${repository}.repository_id`,
      );
      expect(block).not.toContain("roles/artifactregistry.writer");
    }
    const repositoryIamMembers = [
      ...allServiceModuleTerraform.matchAll(
        /resource\s+"google_artifact_registry_repository_iam_member"\s+"([^"]+)"/g,
      ),
    ]
      .map((match) => match[1])
      .sort();
    expect(repositoryIamMembers).toEqual(
      [
        "deployment_parity_preview_image_reader",
        "deployment_parity_prod_image_reader",
        "preview_commit_preview_image_reader",
        "preview_commit_prod_image_reader",
        "preview_deploy_prod_image_reader",
        "preview_deploy_reader",
        "preview_publisher_writer",
        "prod_deploy_reader",
        "prod_publisher_writer",
      ].sort(),
    );
    expect(allServiceModuleTerraform).not.toMatch(
      /resource\s+"google_artifact_registry_repository_iam_(?:binding|policy)"/,
    );
    expect(allServiceModuleTerraform).not.toMatch(
      /resource\s+"google_project_iam_(?:member|binding|policy)"/,
    );
    const allIamResources = [
      ...allServiceModuleTerraform.matchAll(
        /resource\s+"(google_[^"]+_iam_(?:member|binding|policy))"\s+"([^"]+)"/g,
      ),
    ]
      .map((match) => `${match[1]}.${match[2]}`)
      .sort();
    expect(allIamResources).toEqual(
      [
        "google_artifact_registry_repository_iam_member.deployment_parity_preview_image_reader",
        "google_artifact_registry_repository_iam_member.deployment_parity_prod_image_reader",
        "google_artifact_registry_repository_iam_member.preview_commit_preview_image_reader",
        "google_artifact_registry_repository_iam_member.preview_commit_prod_image_reader",
        "google_artifact_registry_repository_iam_member.preview_deploy_prod_image_reader",
        "google_artifact_registry_repository_iam_member.preview_deploy_reader",
        "google_artifact_registry_repository_iam_member.preview_publisher_writer",
        "google_artifact_registry_repository_iam_member.prod_deploy_reader",
        "google_artifact_registry_repository_iam_member.prod_publisher_writer",
        "google_cloud_run_v2_service_iam_member.deployment_parity_preview_reader",
        "google_cloud_run_v2_service_iam_member.deployment_parity_prod_reader",
        "google_cloud_run_v2_service_iam_member.preview_commit",
        "google_cloud_run_v2_service_iam_member.preview_commit_prod_reader",
        "google_cloud_run_v2_service_iam_member.preview_deploy",
        "google_cloud_run_v2_service_iam_member.prod_deploy",
        "google_secret_manager_secret_iam_member.prod_deploy_version_adder",
        "google_secret_manager_secret_iam_member.prod_deploy_version_metadata_reader",
        "google_secret_manager_secret_iam_member.runtime_accessor",
      ].sort(),
    );
    const exactIamBlocks = [
      [
        'resource "google_artifact_registry_repository_iam_member" "prod_publisher_writer" {',
        "  project    = var.project_id",
        "  location   = google_artifact_registry_repository.site.location",
        "  repository = google_artifact_registry_repository.site.repository_id",
        '  role       = "roles/artifactregistry.writer"',
        '  member     = "serviceAccount:${var.prod_publisher_service_account_email}"',
        "}",
      ].join("\n"),
      [
        'resource "google_artifact_registry_repository_iam_member" "preview_publisher_writer" {',
        "  project    = var.project_id",
        "  location   = google_artifact_registry_repository.preview.location",
        "  repository = google_artifact_registry_repository.preview.repository_id",
        '  role       = "roles/artifactregistry.writer"',
        '  member     = "serviceAccount:${var.preview_publisher_service_account_email}"',
        "}",
      ].join("\n"),
      [
        'resource "google_artifact_registry_repository_iam_member" "prod_deploy_reader" {',
        "  project    = var.project_id",
        "  location   = google_artifact_registry_repository.site.location",
        "  repository = google_artifact_registry_repository.site.repository_id",
        '  role       = "roles/artifactregistry.reader"',
        '  member     = "serviceAccount:${var.prod_deploy_service_account_email}"',
        "}",
      ].join("\n"),
      [
        'resource "google_artifact_registry_repository_iam_member" "preview_deploy_reader" {',
        "  project    = var.project_id",
        "  location   = google_artifact_registry_repository.preview.location",
        "  repository = google_artifact_registry_repository.preview.repository_id",
        '  role       = "roles/artifactregistry.reader"',
        '  member     = "serviceAccount:${var.preview_deploy_service_account_email}"',
        "}",
      ].join("\n"),
      [
        'resource "google_artifact_registry_repository_iam_member" "deployment_parity_prod_image_reader" {',
        "  project    = var.project_id",
        "  location   = google_artifact_registry_repository.site.location",
        "  repository = google_artifact_registry_repository.site.repository_id",
        '  role       = "projects/${var.project_id}/roles/deploymentParityImageDownloader"',
        '  member     = "serviceAccount:${var.deployment_parity_reader_service_account_email}"',
        "}",
      ].join("\n"),
      [
        'resource "google_artifact_registry_repository_iam_member" "deployment_parity_preview_image_reader" {',
        "  project    = var.project_id",
        "  location   = google_artifact_registry_repository.preview.location",
        "  repository = google_artifact_registry_repository.preview.repository_id",
        '  role       = "projects/${var.project_id}/roles/deploymentParityImageDownloader"',
        '  member     = "serviceAccount:${var.deployment_parity_reader_service_account_email}"',
        "}",
      ].join("\n"),
      [
        'resource "google_artifact_registry_repository_iam_member" "preview_commit_prod_image_reader" {',
        "  project    = var.project_id",
        "  location   = google_artifact_registry_repository.site.location",
        "  repository = google_artifact_registry_repository.site.repository_id",
        '  role       = "projects/${var.project_id}/roles/deploymentParityImageDownloader"',
        '  member     = "serviceAccount:${var.preview_commit_service_account_email}"',
        "}",
      ].join("\n"),
      [
        'resource "google_artifact_registry_repository_iam_member" "preview_commit_preview_image_reader" {',
        "  project    = var.project_id",
        "  location   = google_artifact_registry_repository.preview.location",
        "  repository = google_artifact_registry_repository.preview.repository_id",
        '  role       = "projects/${var.project_id}/roles/deploymentParityImageDownloader"',
        '  member     = "serviceAccount:${var.preview_commit_service_account_email}"',
        "}",
      ].join("\n"),
      [
        'resource "google_secret_manager_secret_iam_member" "runtime_accessor" {',
        "  for_each = var.runtime_secret_accessor_ids",
        "",
        "  project   = var.project_id",
        "  secret_id = google_secret_manager_secret.runtime[each.value].secret_id",
        '  role      = "roles/secretmanager.secretAccessor"',
        '  member    = "serviceAccount:${var.runtime_service_account_email}"',
        "}",
      ].join("\n"),
      [
        'resource "google_secret_manager_secret_iam_member" "prod_deploy_version_adder" {',
        "  for_each = var.runtime_secret_version_adder_ids",
        "",
        "  project   = var.project_id",
        "  secret_id = google_secret_manager_secret.runtime[each.value].secret_id",
        '  role      = "roles/secretmanager.secretVersionAdder"',
        '  member    = "serviceAccount:${var.prod_deploy_service_account_email}"',
        "}",
      ].join("\n"),
      [
        'resource "google_cloud_run_v2_service_iam_member" "prod_deploy" {',
        "  project  = var.project_id",
        "  location = google_cloud_run_v2_service.site.location",
        "  name     = google_cloud_run_v2_service.site.name",
        '  role     = "projects/${var.project_id}/roles/cloudRunRevisionDeployer"',
        '  member   = "serviceAccount:${var.prod_deploy_service_account_email}"',
        "}",
      ].join("\n"),
      [
        'resource "google_cloud_run_v2_service_iam_member" "preview_deploy" {',
        "  project  = var.project_id",
        "  location = google_cloud_run_v2_service.preview.location",
        "  name     = google_cloud_run_v2_service.preview.name",
        '  role     = "projects/${var.project_id}/roles/cloudRunRevisionDeployer"',
        '  member   = "serviceAccount:${var.preview_deploy_service_account_email}"',
        "}",
      ].join("\n"),
      [
        'resource "google_cloud_run_v2_service_iam_member" "preview_commit" {',
        "  project  = var.project_id",
        "  location = google_cloud_run_v2_service.preview.location",
        "  name     = google_cloud_run_v2_service.preview.name",
        '  role     = "projects/${var.project_id}/roles/previewTrafficCommitter"',
        '  member   = "serviceAccount:${var.preview_commit_service_account_email}"',
        "}",
      ].join("\n"),
      [
        'resource "google_cloud_run_v2_service_iam_member" "preview_commit_prod_reader" {',
        "  project  = var.project_id",
        "  location = google_cloud_run_v2_service.site.location",
        "  name     = google_cloud_run_v2_service.site.name",
        '  role     = "projects/${var.project_id}/roles/deploymentParityCloudRunReader"',
        '  member   = "serviceAccount:${var.preview_commit_service_account_email}"',
        "}",
      ].join("\n"),
      [
        'resource "google_cloud_run_v2_service_iam_member" "deployment_parity_prod_reader" {',
        "  project  = var.project_id",
        "  location = google_cloud_run_v2_service.site.location",
        "  name     = google_cloud_run_v2_service.site.name",
        '  role     = "projects/${var.project_id}/roles/deploymentParityCloudRunReader"',
        '  member   = "serviceAccount:${var.deployment_parity_reader_service_account_email}"',
        "}",
      ].join("\n"),
      [
        'resource "google_cloud_run_v2_service_iam_member" "deployment_parity_preview_reader" {',
        "  project  = var.project_id",
        "  location = google_cloud_run_v2_service.preview.location",
        "  name     = google_cloud_run_v2_service.preview.name",
        '  role     = "projects/${var.project_id}/roles/deploymentParityCloudRunReader"',
        '  member   = "serviceAccount:${var.deployment_parity_reader_service_account_email}"',
        "}",
      ].join("\n"),
    ];
    for (const exactIamBlock of exactIamBlocks) {
      expect(serviceModule.split(exactIamBlock)).toHaveLength(2);
    }
    expect(serviceModule).not.toContain("preview_operator_service_account_email");
    expect(allServiceModuleTerraform.split("preview_operator_service_account_email")).toHaveLength(
      2,
    );
    expect(
      await readFile(
        join(repoRoot, "terraform/modules/cloud-run-service/variables.tf"),
        "utf8",
      ),
    ).toContain(
      "Deprecated transition-only preview operator email retained for input compatibility; this module intentionally grants it no IAM role.",
    );

    for (const [resource, identity, service] of [
      ["prod_deploy", "prod_deploy_service_account_email", "site"],
      ["preview_deploy", "preview_deploy_service_account_email", "preview"],
    ] as const) {
      const start = serviceModule.indexOf(
        `resource "google_cloud_run_v2_service_iam_member" "${resource}"`,
      );
      const block = serviceModule.slice(start, serviceModule.indexOf("\n}\n", start) + 3);
      expect(block).toContain(
        'role     = "projects/${var.project_id}/roles/cloudRunRevisionDeployer"',
      );
      expect(block).toContain(`member   = "serviceAccount:\${var.${identity}}"`);
      expect(block).toContain(`name     = google_cloud_run_v2_service.${service}.name`);
    }
    const runtimeAccessorStart = serviceModule.indexOf(
      'resource "google_secret_manager_secret_iam_member" "runtime_accessor"',
    );
    const runtimeAccessor = serviceModule.slice(
      runtimeAccessorStart,
      serviceModule.indexOf("\n}\n", runtimeAccessorStart) + 3,
    );
    expect(runtimeAccessor).toContain('role      = "roles/secretmanager.secretAccessor"');
    expect(runtimeAccessor).toContain(
      'member    = "serviceAccount:${var.runtime_service_account_email}"',
    );
    const prodDeployVersionAdderStart = serviceModule.indexOf(
      'resource "google_secret_manager_secret_iam_member" "prod_deploy_version_adder"',
    );
    const prodDeployVersionAdder = serviceModule.slice(
      prodDeployVersionAdderStart,
      serviceModule.indexOf("\n}\n", prodDeployVersionAdderStart) + 3,
    );
    expect(prodDeployVersionAdder).toContain(
      'role      = "roles/secretmanager.secretVersionAdder"',
    );
    expect(prodDeployVersionAdder).toContain(
      'member    = "serviceAccount:${var.prod_deploy_service_account_email}"',
    );

    const bootstrap = await readFile(
      join(repoRoot, "terraform/modules/bootstrap/main.tf"),
      "utf8",
    );
    expect(createHash("sha256").update(bootstrap).digest("hex")).toBe(
      "e8366e4556e4456c74c9abf37cfb4a0cc278a540e0283180de1fd6676bf639cf",
    );
    const expectedImageRole = [
      'resource "google_project_iam_custom_role" "preview_traffic_image_downloader" {',
      "  project     = var.project_id",
      '  role_id     = "previewTrafficImageDownloader"',
      '  title       = "Legacy Preview Traffic Image Downloader"',
      '  description = "Transition-only role definition retained until the retired preview operator repository binding converges away."',
      "  permissions = [",
      '    "artifactregistry.repositories.downloadArtifacts",',
      "  ]",
      "",
      "  depends_on = [google_project_service.required]",
      "}",
    ].join("\n");
    expect(bootstrap.split(expectedImageRole)).toHaveLength(2);
    expect(
      bootstrap.match(
        /^resource\s+"google_project_iam_custom_role"\s+"preview_traffic_image_downloader"\s*\{/gm,
      ),
    ).toHaveLength(1);
    expect(bootstrap).not.toMatch(/<<|\/\*|^\s*\/\//m);
    const bootstrapIamResources = [
      ...bootstrap.matchAll(
        /^resource\s+"(google_[^"]+_iam_(?:member|binding|policy))"\s+"([^"]+)"/gm,
      ),
    ]
      .map((match) => `${match[1]}.${match[2]}`)
      .sort();
    expect(bootstrapIamResources).toEqual(
      [
        "google_project_iam_binding.editor_absent",
        "google_project_iam_member.preview_iam_auditors",
        "google_project_iam_member.prod_deploy_waitlist_recaptcha_key_reader",
        "google_project_iam_member.runtime_project_roles",
        "google_project_iam_member.runtime_waitlist_challenge_sender",
        "google_project_iam_member.terraform_convergence_reader",
        "google_service_account_iam_member.preview_deploy_uses_preview_runtime",
        "google_service_account_iam_member.prod_deploy_uses_runtime",
        "google_service_account_iam_member.workflow_authority",
        "google_storage_bucket_iam_binding.bootstrap_state_no_legacy_access",
        "google_storage_bucket_iam_binding.deployment_parity_transition_no_legacy_access",
        "google_storage_bucket_iam_binding.terraform_state_logs_no_legacy_access",
        "google_storage_bucket_iam_binding.terraform_state_no_legacy_access",
        "google_storage_bucket_iam_member.preview_commit_transition_coordinator",
        "google_storage_bucket_iam_member.terraform_state_access_logs_writer",
        "google_storage_bucket_iam_member.terraform_state_reader",
      ].sort(),
    );
    for (const exactProjectIamBlock of [
      [
        'resource "google_project_iam_member" "terraform_convergence_reader" {',
        "  project = var.project_id",
        "  role    = google_project_iam_custom_role.terraform_convergence_reader.name",
        '  member  = "serviceAccount:${google_service_account.terraform.email}"',
        "}",
      ].join("\n"),
      [
        'resource "google_project_iam_member" "runtime_project_roles" {',
        "  for_each = var.runtime_project_roles",
        "",
        "  project = var.project_id",
        "  role    = each.value",
        '  member  = "serviceAccount:${google_service_account.runtime.email}"',
        "}",
      ].join("\n"),
      [
        'resource "google_project_iam_binding" "editor_absent" {',
        "  #checkov:skip=CKV_GCP_49:An authoritative empty binding removes impersonation-capable basic-role members; it grants no principal access.",
        "  #checkov:skip=CKV_GCP_117:An authoritative empty Editor binding removes the basic role and prevents drift; it grants no principal access.",
        "  project = var.project_id",
        '  role    = "roles/editor"',
        "  members = []",
        "",
        "  depends_on = [google_project_service.required]",
        "}",
      ].join("\n"),
    ]) {
      expect(bootstrap.split(exactProjectIamBlock)).toHaveLength(2);
    }
    expect(bootstrap).not.toMatch(/roles\/artifactregistry\.(?:admin|reader|writer)/);
    expect(bootstrap).not.toMatch(
      /google_service_account\.preview_operator\.(?:email|member)/,
    );
    expect(bootstrap).toContain(
      'role    = google_project_iam_custom_role.preview_iam_auditor.name',
    );
    expect(bootstrap).toContain(
      '"serviceAccount:gha-preview-operator@cdbentley.iam.gserviceaccount.com"',
    );
    const imageRoleStart = bootstrap.indexOf(
      'resource "google_project_iam_custom_role" "preview_traffic_image_downloader"',
    );
    const imageRole = bootstrap.slice(
      imageRoleStart,
      bootstrap.indexOf("\n}\n", imageRoleStart) + 3,
    );
    expect(imageRole).toContain('role_id     = "previewTrafficImageDownloader"');
    expect(imageRole).toContain(
      'description = "Transition-only role definition retained until the retired preview operator repository binding converges away."',
    );
    expect(imageRole).toContain(
      '"artifactregistry.repositories.downloadArtifacts",',
    );
    expect(imageRole.split("permissions =")).toHaveLength(2);
    expect(imageRole).toMatch(
      /permissions\s*=\s*\[\s*"artifactregistry\.repositories\.downloadArtifacts",?\s*\]/,
    );
    expect(imageRole).not.toContain("ignore_changes");
    expect(imageRole.match(/"[a-z]+\.[A-Za-z]+\.[A-Za-z]+",/g)).toEqual([
      '"artifactregistry.repositories.downloadArtifacts",',
    ]);
    expect(
      await readFile(join(repoRoot, "terraform/modules/bootstrap/variables.tf"), "utf8"),
    ).toContain(
      "Retired preview traffic identity retained only for an explicitly declared workflow-SHA transition; receives no steady-state operational grants.",
    );
    expect(await readFile(join(repoRoot, "README.md"), "utf8")).toContain(
      "one job-level `attribute.authority` tuple",
    );
    expect(bootstrap).not.toMatch(/^\s*module\s+"/m);
    for (const outputPath of [
      "terraform/modules/bootstrap/outputs.tf",
      "terraform/deployments/bootstrap/outputs.tf",
      "templates/app/infra/terraform/bootstrap/outputs.tf",
    ]) {
      const output = await readFile(join(repoRoot, outputPath), "utf8");
      expect(output).toContain(
        "Retired transition-only preview operator service account; receives no steady-state operational grants.",
      );
      expect(output).toContain("only declared exact-secret version-add grants.");
    }
    const manifest = JSON.parse(
      await readFile(join(repoRoot, "terraform/modules/bootstrap/workflow-authority.json"), "utf8"),
    ) as Array<{ job: string; purpose: string; serviceAccounts: string[]; transitionEligible: boolean; workflow: string }>;
    const jobKey = (entry: { job: string; workflow: string }) => `${entry.workflow}#${entry.job}`;
    const attestations = manifest.filter((entry) => entry.purpose === "attestation");
    expect(attestations.map(jobKey)).toEqual([
      ".github/workflows/deploy-preview.yml#attest",
      ".github/workflows/deploy-prod.yml#attest",
    ]);
    expect(attestations.map((entry) => entry.serviceAccounts)).toEqual([[], []]);
    expect(manifest.filter((entry) => entry.transitionEligible).map(jobKey)).toEqual([
      ".github/workflows/cleanup-preview.yml#cleanup",
      ".github/workflows/reconcile-previews.yml#reconcile",
    ]);
    expect(manifest.filter((entry) => entry.job.endsWith("canary")).map((entry) => entry.serviceAccounts)).toEqual([
      ["gha-wif-canary"],
      ["gha-wif-canary"],
      ["gha-wif-canary"],
    ]);
    const workflowAuthorityBindingStart = bootstrap.indexOf(
      'resource "google_service_account_iam_member" "workflow_authority"',
    );
    const workflowAuthorityBinding = bootstrap.slice(
      workflowAuthorityBindingStart,
      bootstrap.indexOf("\n}\n", workflowAuthorityBindingStart) + 3,
    );
    expect(workflowAuthorityBinding).toContain("for_each = local.workflow_authority_bindings");
    expect(workflowAuthorityBinding).toContain(
      "service_account_id = local.workflow_authority_service_accounts[each.value.account]",
    );
    expect(workflowAuthorityBinding).toContain('role               = "roles/iam.workloadIdentityUser"');
    expect(workflowAuthorityBinding).toContain("member             = each.value.member");
    expect(bootstrap).toContain(
      "for sha in compact([var.active_workflow_sha, entry.transitionEligible ? var.transition_workflow_sha : null]) : [",
    );
    expect(bootstrap.match(/principalSet:\/\//g)).toHaveLength(1);
    expect(bootstrap).toContain(
      'attribute_condition = "assertion.repository_owner_id == \'${local.github_owner_id}\' && assertion.repository_id == \'${var.github_repository_id}\' && assertion.runner_environment == \'github-hosted\'"',
    );
    expect(bootstrap).toContain('authority_delimiter = ":"');
    expect(bootstrap).toContain(
      '"attribute.authority" = "assertion.workflow_ref + \'${local.authority_delimiter}\' + assertion.job_workflow_ref + \'${local.authority_delimiter}\' + assertion.job_workflow_sha + \'${local.authority_delimiter}\' + assertion.environment + \'${local.authority_delimiter}\' + assertion.event_name"',
    );
    const bootstrapVariables = await readFile(
      join(repoRoot, "terraform/modules/bootstrap/variables.tf"),
      "utf8",
    );
    expect(bootstrapVariables).toContain(
      'condition     = can(regex("^[0-9a-f]{40}$", var.active_workflow_sha))',
    );
    expect(bootstrapVariables).toContain(
      "condition     = var.transition_workflow_sha != var.active_workflow_sha",
    );
    for (const retired of [
      "trusted_platform_workflow_shas",
      "preview_operations_active_workflow_shas",
      "preview_operator_transition_workflow_shas",
      "legacy_compatibility_mode",
      "github_owner_id",
    ]) {
      expect(bootstrapVariables).not.toContain(`variable "${retired}"`);
    }
    for (const retired of [
      "'denied'",
      "run_attempt",
      ".startsWith(",
      "has(assertion.",
      "attribute.legacy_",
      "_workflow_sha/",
      '"attribute.environment"',
      '"attribute.job_workflow_ref"',
      '"attribute.repository_id"',
    ]) {
      expect(bootstrap).not.toContain(retired);
    }
    expect(bootstrap).not.toContain(
      'member             = "serviceAccount:${google_service_account.prod_publisher.email}"',
    );
    expect(bootstrap).not.toContain(
      'member             = "serviceAccount:${google_service_account.preview_publisher.email}"',
    );
    expect(bootstrap).not.toContain(
      'member             = "serviceAccount:${google_service_account.preview_operator.email}"',
    );
  });

  test("credentialless artifacts are canonicalized and independently rebound before publication", async () => {
    const helper = await readFile(
      join(repoRoot, "tools/ci/container-artifact-contract.sh"),
      "utf8",
    );
    expect(helper).toContain('write_deterministic_tar "$image_root" "$canonical"');
    expect(helper).toContain('validate_base_bundle "$trusted_base_root"');
    expect(helper).toContain(
      'validate_application_oci "$image_root" "$EXPECTED_PUBLISHED_INDEX_DIGEST" "$EXPECTED_RUNNABLE_MANIFEST_DIGEST" "$trusted_base_root"',
    );
    expect(helper).toContain('cmp "$trusted_runtime_manifest" "$embedded_runtime_manifest"');
    expect(helper).toContain("BUILDKIT_PROVENANCE_URI_POLICY_IMPLEMENTED=true");
    expect(helper).toContain(
      "scanner_sandbox_image_id=\"$(docker image inspect --format '{{.Id}}' \"$SCANNER_SANDBOX_IMAGE\")\"",
    );
    expect(helper).toContain(
      "docker image inspect --format '{{json .RepoDigests}}' \"$scanner_sandbox_image_id\"",
    );
    expect(helper).toContain('--entrypoint "$entrypoint" "$scanner_sandbox_image_id"');
    expect(helper).toContain('docker pull "$SCANNER_SANDBOX_IMAGE"');
    expect(helper.indexOf('docker pull "$SCANNER_SANDBOX_IMAGE"')).toBeLessThan(
      helper.indexOf('safe_extract_tar "$built"'),
    );
    expect(helper).toContain("--pull never --network none --read-only --cap-drop ALL");
    expect(helper).toContain("--security-opt no-new-privileges --user 65534:65534");
    expect(helper).toContain('test ! -e "$HOST_ONLY_MARKER"');
    expect(helper).toContain('! touch /input/parser-rce-write');
    expect(helper).toContain('test ! -S /var/run/docker.sock');
    expect(helper).toContain('cmp "$scanner_before" "$scanner_after"');

    for (const workflowName of ["deploy-preview.yml", "deploy-prod.yml"]) {
      const workflow = await readFile(
        join(repoRoot, ".github/workflows", workflowName),
        "utf8",
      );
      expect(workflow).not.toContain("ghcr.io");
      expect(workflow).not.toContain("packages: write");
      expect(workflow).not.toContain("cleanup-staging:");
      expect(workflow).toContain("archive: false");
      expect(workflow).toContain("skip-decompress: true");
      expect(workflow).toContain("digest-mismatch: error");
      expect(workflow).toContain(".workflow_run.repository_id == $repo");
      expect(workflow).toContain(".workflow_run.head_repository_id == $repo");
      const publish = workflow.slice(
        workflow.indexOf("  publish:\n"),
        workflow.indexOf("\n  attest:\n"),
      );
      expect(publish).toContain("needs.prefetch-bases.result == 'success'");
      expect(publish).toContain(
        "artifact-ids: ${{ needs.prefetch-bases.outputs.artifact-id }}",
      );
      expect(publish.indexOf("validate-promoted")).toBeLessThan(
        publish.indexOf("Authenticate"),
      );
    }

    const parsedBuilds = await Promise.all(
      ["deploy-preview.yml", "deploy-prod.yml"].map(async (workflowName) =>
        Bun.YAML.parse(
          await readFile(join(repoRoot, ".github/workflows", workflowName), "utf8"),
        ) as { jobs: { build: { steps: Array<Record<string, any>> } } },
      ),
    );
    const buildSteps = parsedBuilds.map((workflow) =>
      workflow.jobs.build.steps.find(
        (step) => step.uses === "docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf",
      ),
    );
    expect(buildSteps[0]).toBeDefined();
    expect(buildSteps[1]).toBeDefined();
    for (const key of [
      "builder",
      "build-contexts",
      "context",
      "file",
      "github-token",
      "outputs",
      "platforms",
      "provenance",
      "pull",
      "push",
    ]) {
      expect(buildSteps[0]?.with[key], `preview/production ${key} drifted`).toEqual(
        buildSteps[1]?.with[key],
      );
    }
    expect(buildSteps[0]?.env).toEqual(buildSteps[1]?.env);
    expect(buildSteps[0]?.env).toEqual({
      DOCKER_BUILD_CHECKS_ANNOTATIONS: "false",
      DOCKER_BUILD_RECORD_UPLOAD: "false",
      DOCKER_BUILD_SUMMARY: "false",
    });
    for (const stepName of [
      "Install checksum-pinned Docker Buildx and create pinned BuildKit",
      "Destroy BuildKit and runner-local bases",
    ]) {
      const steps = parsedBuilds.map((workflow) =>
        workflow.jobs.build.steps.find((step) => step.name === stepName),
      );
      expect(steps[0]?.run, `${stepName} drifted`).toBe(steps[1]?.run);
    }
  });

  test("image policy blocks an unfixable High vulnerability", async () => {
    const report = {
      matches: [
        {
          artifact: { name: "synthetic-package", version: "1.0.0" },
          vulnerability: {
            id: "CVE-2099-0001",
            severity: "High",
            fix: { state: "not-fixed", versions: [] },
          },
        },
      ],
    };
    const child = Bun.spawn(["jq", "-f", join(repoRoot, "tools/ci/grype-blocking.jq")], {
      stdin: new Blob([JSON.stringify(report)]),
      stdout: "pipe",
      stderr: "pipe",
    });
    const [exitCode, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);

    expect(stderr).toBe("");
    expect(exitCode).toBe(0);
    expect(JSON.parse(stdout)).toEqual([
      {
        package: "synthetic-package",
        installed: "1.0.0",
        vulnerability: "CVE-2099-0001",
        severity: "High",
        fixState: "not-fixed",
        fixedIn: [],
      },
    ]);
  });

  test("cloud policy has no repository-variable bypass and exact-WIF canaries are mandatory", async () => {
    for (const workflowName of [
      "application.yml",
      "socket-firewall.yml",
      "infrastructure.yml",
      "deploy-prod.yml",
      "deploy-preview.yml",
      "cleanup-preview.yml",
      "reconcile-previews.yml",
      "platform.yml",
    ]) {
      const workflow = await readFile(join(repoRoot, ".github/workflows", workflowName), "utf8");
      for (const forbidden of ["vars.GCP_", "vars.PROJECT_ID", "vars.SERVICE_ACCOUNT", "vars.WORKLOAD_IDENTITY_PROVIDER"]) {
        expect(workflow).not.toContain(forbidden);
      }
    }

    const production = await readFile(join(repoRoot, ".github/workflows/deploy-prod.yml"), "utf8");
    const preview = await readFile(join(repoRoot, ".github/workflows/deploy-preview.yml"), "utf8");
    expect(production).toContain("needs.canary.result == 'success'");
    expect(preview).toContain("needs.canary.result == 'success'");
    expect(preview).toContain("needs.publish-canary.result == 'success'");
    expect(production).not.toContain("GCP_EXACT_WIF_CANARY_ENABLED");
    expect(preview).not.toContain("GCP_CLOUD_PREVIEW_ENABLED");
  });

  test("every platform job and WIF provider path rejects reruns", async () => {
    const guardedJobs = new Map<string, string[]>([
      ["application.yml", ["verify"]],
      ["socket-firewall.yml", ["firewall"]],
      ["platform.yml", ["verify", "terraform"]],
      [
        "deploy-preview.yml",
        [
          "rerun-guard",
          "prefetch-bases",
          "build",
          "verify-image",
          "canary",
          "publish-canary",
          "publish",
          "attest",
          "deploy",
          "invalidate",
        ],
      ],
      [
        "deploy-prod.yml",
        [
          "rerun-guard",
          "prefetch-bases",
          "build",
          "verify-image",
          "canary",
          "publish",
          "attest",
          "deploy",
        ],
      ],
      ["cleanup-preview.yml", ["rerun-guard", "prefetch-bases", "cleanup"]],
      ["reconcile-previews.yml", ["rerun-guard", "prefetch-bases", "reconcile"]],
      [
        "infrastructure.yml",
        ["rerun-guard", "terraform-validate", "checkov", "terraform-convergence"],
      ],
    ]);
    const expectedJobConditions: Record<string, Record<string, string | null>> = {
      "application.yml": { verify: null },
      "socket-firewall.yml": { firewall: null },
      "platform.yml": { terraform: null, verify: null },
      "deploy-preview.yml": {
        "rerun-guard": null,
        "prefetch-bases":
          "github.event_name == 'pull_request_target' && github.ref == 'refs/heads/main' && github.base_ref == 'main' && github.event.pull_request.head.repo.id == github.event.repository.id && github.event.pull_request.head.repo.full_name == github.repository && github.event.pull_request.user.type == 'User' && github.actor != 'dependabot[bot]' && github.event.pull_request.draft == false",
        build:
          "github.event_name == 'pull_request_target' && github.ref == 'refs/heads/main' && github.base_ref == 'main' && github.event.pull_request.head.repo.id == github.event.repository.id && github.event.pull_request.head.repo.full_name == github.repository && github.event.pull_request.user.type == 'User' && github.actor != 'dependabot[bot]' && github.event.pull_request.draft == false && needs.prefetch-bases.result == 'success'",
        "verify-image": "needs.build.result == 'success' && needs.prefetch-bases.result == 'success'",
        canary:
          "github.event_name == 'pull_request_target' && github.ref == 'refs/heads/main' && github.base_ref == 'main' && github.event.pull_request.head.repo.id == github.event.repository.id && github.event.pull_request.head.repo.full_name == github.repository && github.event.pull_request.user.type == 'User' && github.actor != 'dependabot[bot]' && github.event.pull_request.draft == false",
        "publish-canary":
          "github.event_name == 'pull_request_target' && github.base_ref == 'main' && github.event.pull_request.head.repo.id == github.event.repository.id && github.ref == 'refs/heads/main' && github.event.pull_request.head.repo.full_name == github.repository && github.event.pull_request.user.type == 'User' && github.actor != 'dependabot[bot]' && github.event.pull_request.draft == false",
        publish:
          "always() && needs.canary.result == 'success' && needs.prefetch-bases.result == 'success' && needs.publish-canary.result == 'success' && needs.verify-image.result == 'success'",
        attest: "needs.publish.result == 'success'",
        deploy:
          "needs.attest.result == 'success' && needs.prefetch-bases.result == 'success' && needs.publish.result == 'success'",
        invalidate:
          "always() && needs.deploy.outputs.deployed-revision != '' && (needs.deploy.outputs.lifecycle-keep != 'true' || needs.deploy.outputs.admission-open != 'success')",
      },
      "deploy-prod.yml": {
        "rerun-guard": null,
        "prefetch-bases": "github.event_name == 'push' && github.ref == 'refs/heads/main'",
        build: "github.event_name == 'push' && github.ref == 'refs/heads/main' && needs.prefetch-bases.result == 'success'",
        "verify-image": "needs.build.result == 'success' && needs.prefetch-bases.result == 'success'",
        canary: "github.event_name == 'push' && github.ref == 'refs/heads/main'",
        publish: "always() && needs.canary.result == 'success' && needs.prefetch-bases.result == 'success' && needs.verify-image.result == 'success'",
        attest: "needs.publish.result == 'success'",
        deploy:
          "needs.attest.result == 'success' && needs.prefetch-bases.result == 'success' && needs.publish.result == 'success'",
      },
      "cleanup-preview.yml": {
        "rerun-guard": null,
        "prefetch-bases":
          "github.event_name == 'pull_request_target' && github.ref == 'refs/heads/main' && github.base_ref == 'main' && github.event.pull_request.head.repo.id == github.event.repository.id && github.event.pull_request.head.repo.full_name == github.repository && (github.event.action == 'closed' ||\n github.event.action == 'synchronize' ||\n github.event.action == 'converted_to_draft')",
        cleanup:
          "always() && github.event_name == 'pull_request_target' && github.ref == 'refs/heads/main' && github.base_ref == 'main' && github.event.pull_request.head.repo.id == github.event.repository.id && (github.event.action == 'closed' ||\n github.event.action == 'synchronize' ||\n github.event.action == 'converted_to_draft') &&\ngithub.event.pull_request.head.repo.full_name == github.repository",
      },
      "reconcile-previews.yml": {
        "rerun-guard": null,
        "prefetch-bases":
          "(github.event_name == 'push' || github.event_name == 'schedule' || github.event_name == 'workflow_dispatch') && github.ref == 'refs/heads/main'",
        reconcile:
          "always() && (github.event_name == 'push' || github.event_name == 'schedule' || github.event_name == 'workflow_dispatch') && github.ref == 'refs/heads/main'",
      },
      "infrastructure.yml": {
        "rerun-guard": null,
        "terraform-validate": null,
        checkov: null,
        "terraform-convergence": "github.event_name == 'push' && github.ref == 'refs/heads/main'",
      },
    };

    const hasExactGuardStructure = (
      workflowName: string,
      workflow: string,
      jobs: string[],
    ): boolean => {
      try {
        const normalizeSimpleYamlKey = (token: string): string | undefined => {
          if (/^[A-Za-z][A-Za-z0-9_-]*$/.test(token)) return token;
          const quoted = /^(?:"([A-Za-z][A-Za-z0-9_-]*)"|'([A-Za-z][A-Za-z0-9_-]*)')$/.exec(
            token,
          );
          return quoted?.[1] ?? quoted?.[2];
        };
        const jobsMarker = "\njobs:\n";
        if (workflow.indexOf(jobsMarker) !== workflow.lastIndexOf(jobsMarker)) return false;
        const jobsSection = workflow.slice(workflow.indexOf(jobsMarker) + jobsMarker.length);
        const rawJobKeys = jobsSection
          .split("\n")
          .filter((line) => /^  \S/.test(line))
          .map((line) => line.trim());
        if (JSON.stringify(rawJobKeys) !== JSON.stringify(jobs.map((job) => `${job}:`))) return false;
        const parsedDocument = Bun.YAML.parse(workflow) as {
          jobs?: Record<string, { steps?: Array<Record<string, unknown>> }>;
          defaults?: unknown;
          env?: unknown;
        };
        if (parsedDocument.defaults !== undefined || parsedDocument.env !== undefined) return false;
        const parsed = parsedDocument;
        if (JSON.stringify(Object.keys(parsed.jobs ?? {})) !== JSON.stringify(jobs)) return false;
        const expectedStep = {
          name: "Reject workflow reruns before any privileged action",
          shell: "/bin/bash --noprofile --norc -euo pipefail {0}",
          run: 'set -euo pipefail\ntest "$GITHUB_RUN_ATTEMPT" = "1"\n',
        };
        for (const [index, job] of jobs.entries()) {
          const start = workflow.indexOf(`  ${job}:\n`);
          const nextJob = jobs[index + 1];
          const end = nextJob === undefined
            ? workflow.length
            : workflow.indexOf(`\n  ${nextJob}:\n`, start);
          if (start < 0 || end < 0) return false;
          const rawJob = workflow.slice(start, end);
          const rawJobKeysAtDepth: string[] = [];
          for (const line of rawJob.split("\n")) {
            if (!/^    \S/.test(line)) continue;
            if (line.slice(4).startsWith("#")) continue;
            const separator = line.indexOf(":", 4);
            if (separator < 0) return false;
            const key = normalizeSimpleYamlKey(line.slice(4, separator).trim());
            if (key === undefined) return false;
            rawJobKeysAtDepth.push(key);
          }
          if (new Set(rawJobKeysAtDepth).size !== rawJobKeysAtDepth.length) return false;
          const parsedJob = parsed.jobs?.[job] as Record<string, unknown> | undefined;
          if (parsedJob?.["runs-on"] !== "ubuntu-24.04") return false;
          for (const forbidden of [
            "container",
            "continue-on-error",
            "defaults",
            "env",
            "services",
            "uses",
          ]) {
            if (parsedJob?.[forbidden] !== undefined) return false;
          }
          if ((parsedJob?.if ?? null) !== expectedJobConditions[workflowName]?.[job]) return false;
          const parsedSteps = parsedJob?.steps as Array<Record<string, unknown>> | undefined;
          if (JSON.stringify(parsedSteps?.[0]) !== JSON.stringify(expectedStep)) {
            return false;
          }
          for (const step of parsedSteps?.slice(1) ?? []) {
            const condition = step.if;
            if (
              typeof condition === "string" &&
              /\b(?:always|cancelled|failure|success)\s*\(\s*\)/.test(condition) &&
              condition !== "always() && github.run_attempt == '1'"
            ) {
              return false;
            }
          }
        }
        return !workflow.includes("needs: rerun-guard");
      } catch {
        return false;
      }
    };

    for (const [workflowName, jobs] of guardedJobs) {
      const workflow = await readFile(
        join(repoRoot, ".github/workflows", workflowName),
        "utf8",
      );
      expect(hasExactGuardStructure(workflowName, workflow, jobs)).toBe(true);
      const jobsSection = workflow.slice(workflow.indexOf("\njobs:\n") + "\njobs:\n".length);
      const rawJobKeys = jobsSection
        .split("\n")
        .filter((line) => /^  \S/.test(line))
        .map((line) => line.trim());
      expect(rawJobKeys).toEqual(jobs.map((job) => `${job}:`));

      const parsed = Bun.YAML.parse(workflow) as {
        jobs: Record<string, { steps: Array<Record<string, unknown>> }>;
      };
      expect(Object.keys(parsed.jobs)).toEqual(jobs);
      for (const [index, job] of jobs.entries()) {
        const start = workflow.indexOf(`  ${job}:\n`);
        const nextJob = jobs[index + 1];
        const end = nextJob === undefined ? workflow.length : workflow.indexOf(`\n  ${nextJob}:\n`, start);
        const rawJob = workflow.slice(start, end);
        const rawJobKeysAtDepth = rawJob
          .split("\n")
          .filter((line) => /^    [A-Za-z][A-Za-z0-9_-]*:/.test(line))
          .map((line) => line.trim().split(":", 1)[0]);
        expect(new Set(rawJobKeysAtDepth).size).toBe(rawJobKeysAtDepth.length);
        const firstStep = parsed.jobs[job]?.steps?.[0];
        expect(firstStep).toEqual({
          name: "Reject workflow reruns before any privileged action",
          shell: "/bin/bash --noprofile --norc -euo pipefail {0}",
          run: 'set -euo pipefail\ntest "$GITHUB_RUN_ATTEMPT" = "1"\n',
        });
        expect(rawJob).toContain(
          '    steps:\n      - name: Reject workflow reruns before any privileged action\n        shell: /bin/bash --noprofile --norc -euo pipefail {0}\n        run: |\n          set -euo pipefail\n          test "$GITHUB_RUN_ATTEMPT" = "1"\n',
        );
      }
      expect(workflow).not.toContain("needs: rerun-guard");

      if (jobs.includes("rerun-guard")) {
        const sentinel = parsed.jobs["rerun-guard"] as unknown as Record<string, unknown>;
        expect(sentinel.permissions).toEqual({});
      }
    }

    const application = await readFile(
      join(repoRoot, ".github/workflows/application.yml"),
      "utf8",
    );
    for (const hostile of [
      application.replace("  verify:\n", '  "verify":\n'),
      application.replace("  verify:\n", "  Verify_Job:\n"),
      `${application}\n  verify:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: true\n`,
      application.replace("    steps:\n", "    steps:\n      - uses: attacker/action@main\n"),
      application.replace("    steps:\n", "    steps:\n      - run: echo hostile\n"),
      application.replace(
        "    steps:\n",
        "    steps:\n      - uses: attacker/action@main\n    steps:\n",
      ),
      application.replace(
        "    steps:\n",
        '    "permissions":\n      contents: write\n    steps:\n',
      ),
      application.replace(
        "    steps:\n",
        '    "steps":\n      - uses: attacker/action@main\n    steps:\n',
      ),
      application.replace(
        "      - name: Checkout\n",
        "      - name: Hostile post-guard cleanup\n        if: always()\n        run: echo hostile\n\n      - name: Checkout\n",
      ),
      application.replace("jobs:\n", "env:\n  BASH_ENV: /tmp/hostile\njobs:\n"),
      application.replace("jobs:\n", "defaults:\n  run:\n    shell: hostile {0}\njobs:\n"),
      application.replace("  verify:\n", "  verify:\n    env:\n      BASH_ENV: /tmp/hostile\n"),
      application.replace("  verify:\n", "  verify:\n    defaults:\n      run:\n        shell: hostile {0}\n"),
      application.replace("  verify:\n", "  verify:\n    container: hostile:latest\n"),
      application.replace("  verify:\n", "  verify:\n    services:\n      hostile:\n        image: hostile:latest\n"),
      application.replace("  verify:\n", "  verify:\n    uses: hostile/repo/.github/workflows/pwn.yml@main\n"),
      application.replace("  verify:\n", "  verify:\n    continue-on-error: true\n"),
      application.replace("  verify:\n", "  verify:\n    if: false\n"),
      application.replace("runs-on: ubuntu-24.04", "runs-on: self-hosted"),
    ]) {
      expect(hasExactGuardStructure("application.yml", hostile, ["verify"])).toBe(false);
    }
    for (const workflowName of ["deploy-preview.yml", "deploy-prod.yml"]) {
      const workflow = await readFile(
        join(repoRoot, ".github/workflows", workflowName),
        "utf8",
      );
      expect(workflow).toContain(
        "- name: Restore workflow commands after untrusted build output\n        if: always() && github.run_attempt == '1'",
      );
    }

    for (const attempt of ["1", "2"]) {
      const child = Bun.spawn(["/bin/bash", "--noprofile", "--norc", "-c", 'test "$GITHUB_RUN_ATTEMPT" = "1"'], {
        env: { GITHUB_RUN_ATTEMPT: attempt, PATH: "/usr/bin:/bin" },
        stderr: "pipe",
        stdout: "pipe",
      });
      expect(await child.exited).toBe(attempt === "1" ? 0 : 1);
    }

    const bootstrap = await readFile(
      join(repoRoot, "terraform/modules/bootstrap/main.tf"),
      "utf8",
    );
    // Rerun defence lives in the workflows' own attempt guards above; the WIF
    // provider condition is the literal owner, repository, and GitHub-hosted
    // conjunction only, so both attempts of a run carry identical authority.
    expect(bootstrap).toContain(
      'attribute_condition = "assertion.repository_owner_id == \'${local.github_owner_id}\' && assertion.repository_id == \'${var.github_repository_id}\' && assertion.runner_environment == \'github-hosted\'"',
    );
    expect(bootstrap).not.toContain("run_attempt");
  });

  test("runtime configuration is immutable per repository and Runsetta stays offline", async () => {
    const production = await readFile(join(repoRoot, ".github/workflows/deploy-prod.yml"), "utf8");
    const preview = await readFile(join(repoRoot, ".github/workflows/deploy-preview.yml"), "utf8");

    for (const workflow of [production, preview]) {
      expect(workflow).not.toContain("GRYPE_DB_MANIFEST_JSON");
      expect(workflow).not.toContain("DB_MANIFEST_JSON:");
      expect(workflow).toContain("MAPBOX_PUBLIC_TOKEN: ${{ vars.MAPBOX_PUBLIC_TOKEN }}");
      expect(workflow).toContain('[[ ! "$MAPBOX_PUBLIC_TOKEN" =~ ^pk\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$ ]]');
      expect(workflow).toContain('. + {MAPBOX_PUBLIC_TOKEN: $token}');
      expect(workflow).toContain('RUNSETTA_OFFLINE: "1"');
    }
    expect(production).not.toContain("${{ secrets.WAITLIST_IDENTITY_KEYSET");
    expect(production).toContain('waitlist_entry_count="$(jq -er \'length\' <<< "$waitlist_entries")"');
    expect(production).toContain('if [ "$waitlist_entry_count" = "1" ]; then');
    expect(production).toContain('elif [ "$waitlist_entry_count" = "0" ]; then');
    expect(production).toContain("gcloud secrets versions add waitlist-identity-keyset");
    expect(production).toContain("gcloud secrets versions list");
    expect(production).toContain("Refusing to guess an unbound existing Medlock secret version.");
    expect(production).toContain("gcloud run services describe");
    expect(production).toContain('select(.name == "WAITLIST_IDENTITY_KEYSET")');
    expect(production).toContain('select(.name == "waitlist-identity-keyset")');
    expect(
      production.indexOf("gcloud run services describe"),
    ).toBeLessThan(production.indexOf("gcloud secrets versions add waitlist-identity-keyset"));
    expect(production).toContain("--data-file=-");
    expect(production).toContain("--format='value(name)'");
    expect(production).toContain(
      "^projects/(229383559510|medlock-1025243085)/secrets/waitlist-identity-keyset/versions/([1-9][0-9]*)$",
    );
    expect(production).toContain(
      'secret_args=(--set-secrets="WAITLIST_IDENTITY_KEYSET=waitlist-identity-keyset:${secret_version}")',
    );
    expect(production).not.toContain("WAITLIST_IDENTITY_KEYSET: ${{ secrets.");
    expect(production.split("--set-secrets")).toHaveLength(2);
    expect(production).not.toContain("--update-secrets");
    expect(preview).not.toContain("secrets.WAITLIST_IDENTITY_KEYSET");
    expect(preview).toContain("openssl rand -base64 32");
    expect(preview).toContain('[[ ! "$waitlist_identity_keyset" =~ ^[A-Za-z0-9_-]{43}$ ]]');
    expect(preview).toContain('WAITLIST_IDENTITY_KEYSET: $waitlist_identity_keyset');
    expect(preview).toContain('WAITLIST_BACKEND: "memory"');
    expect(production).toContain('WAITLIST_BACKEND: "firestore"');
    expect(production).toContain('FIRESTORE_PROJECT_ID: "medlock-1025243085"');
    expect(production).toContain('MEDLOCK_OWNERSHIP_REQUIRED: "false"');
    expect(production).toContain(
      "The staged Medlock deploy may not clear an existing ownership boundary.",
    );
    expect(production).toContain('gcloud recaptcha keys describe "$recaptcha_site_key"');
    expect(production).toContain('IDENTITY_PLATFORM_AUDIENCE: "medlock-1025243085"');
    expect(production).toContain(
      'IDENTITY_PLATFORM_CONTINUE_URL: "https://medlock.ai/api/waitlist/confirm"',
    );
    expect(production).toContain('RECAPTCHA_PROJECT_ID: "medlock-1025243085"');
    expect(production).toContain("RECAPTCHA_SITE_KEY: $recaptcha_site_key");
    expect(production).toContain(
      "The served Medlock revision did not preserve the verified ownership configuration.",
    );
    expect(production).toContain('PLATFORM_DEPLOY_ENVIRONMENT: "production"');
    expect(production).toContain("--clear-secrets");
    expect(production).not.toContain("GCP_PROD_ENV_VARS");
    expect(preview).not.toContain("GCP_PREVIEW_ENV_VARS");

    const moduleMain = await readFile(
      join(repoRoot, "terraform/modules/cloud-run-service/main.tf"),
      "utf8",
    );
    const moduleVariables = await readFile(
      join(repoRoot, "terraform/modules/cloud-run-service/variables.tf"),
      "utf8",
    );
    const deployment = await readFile(
      join(repoRoot, "terraform/deployments/prod/main.tf"),
      "utf8",
    );
    const templateProductionMain = await readFile(
      join(repoRoot, "templates/app/infra/terraform/prod/main.tf"),
      "utf8",
    );
    const templateProductionVariables = await readFile(
      join(repoRoot, "templates/app/infra/terraform/prod/variables.tf"),
      "utf8",
    );
    const bootstrapDeployment = await readFile(
      join(repoRoot, "terraform/deployments/bootstrap/main.tf"),
      "utf8",
    );
    const mirrorContract = await readFile(
      join(repoRoot, "tools/ci/terraform-mirror-contract.ts"),
      "utf8",
    );
    expect(moduleMain).toContain("for_each = var.runtime_secret_accessor_ids");
    expect(moduleMain).toContain("for_each = var.runtime_secret_version_adder_ids");
    expect(moduleVariables).toContain("setsubtract(var.runtime_secret_accessor_ids, var.runtime_secret_ids)");
    expect(moduleVariables).toContain(
      "setsubtract(var.runtime_secret_version_adder_ids, var.runtime_secret_ids)",
    );
    expect(templateProductionMain).toContain(
      "runtime_secret_version_adder_ids               = var.runtime_secret_version_adder_ids",
    );
    expect(templateProductionVariables).toContain(
      "setsubtract(var.runtime_secret_version_adder_ids, var.runtime_secret_ids)",
    );
    expect(deployment).toContain("runtime_secret_accessor_ids              = []");
    expect(deployment).toContain("runtime_secret_version_adder_ids = [");
    expect(deployment.split("runtime_secret_version_adder_ids         = []")).toHaveLength(4);
    expect(deployment).toContain('"waitlist-identity-keyset"');
    expect(deployment).toContain(
      "runtime_secret_version_adder_ids               = local.deployment.runtime_secret_version_adder_ids",
    );
    expect(deployment).toContain('RUNSETTA_OFFLINE   = "1"');
    const medlockProduction = deployment.slice(
      deployment.indexOf('    "1025243085" = {'),
      deployment.indexOf('    "280932482" = {'),
    );
    expect(medlockProduction).toContain(
      'runtime_secret_ids = [\n        "waitlist-identity-keyset",\n      ]',
    );
    expect(medlockProduction).toContain(
      'runtime_secret_accessor_ids = [\n        "waitlist-identity-keyset",\n      ]',
    );
    expect(medlockProduction).toContain(
      'runtime_secret_version_adder_ids = [\n        "waitlist-identity-keyset",\n      ]',
    );
    expect(deployment).toContain(
      "container_env                                  = merge(local.deployment.container_env, local.medlock_ownership_env)",
    );
    expect(deployment).toContain(
      'medlock_ownership_enabled = var.repository_id == "1025243085"',
    );
    expect(deployment).toContain(
      "RECAPTCHA_SITE_KEY = one(google_recaptcha_enterprise_key.waitlist[*].name)",
    );
    expect(deployment).not.toContain(
      "RECAPTCHA_SITE_KEY = one(google_recaptcha_enterprise_key.waitlist[*].id)",
    );
    for (const header of [
      'resource "google_firestore_field" "waitlist_entry_ttl"',
      'resource "google_firestore_field" "waitlist_quota_ttl"',
      'resource "google_identity_platform_config" "default"',
      'resource "google_recaptcha_enterprise_key" "waitlist"',
    ]) {
      expect(deployment).toContain(header);
    }
    expect(deployment).not.toContain('resource "google_project_service"');
    const medlockBootstrap = bootstrapDeployment.slice(
      bootstrapDeployment.indexOf('    "1025243085" = {'),
      bootstrapDeployment.indexOf('    "280932482" = {'),
    );
    expect(medlockBootstrap).toContain('"secretmanager.googleapis.com"');
    expect(medlockBootstrap).not.toContain('"orgpolicy.googleapis.com"');
    const criticalBootstrap = bootstrapDeployment.slice(
      bootstrapDeployment.indexOf('    "280932482" = {'),
      bootstrapDeployment.indexOf("\n  }\n\n  deployment", bootstrapDeployment.indexOf('    "280932482" = {')),
    );
    const medlockMirror = mirrorContract.slice(
      mirrorContract.indexOf('  "1025243085": {'),
      mirrorContract.indexOf('  "711292980": {'),
    );
    const criticalMirror = mirrorContract.slice(
      mirrorContract.indexOf('  "280932482": {'),
      mirrorContract.indexOf("\n};", mirrorContract.indexOf('  "280932482": {')),
    );
    // Required API ownership remains entirely in bootstrap state. The consumer
    // mirror names the same service set as a contract, but never declares a
    // second google_project_service owner in production state.
    const serviceSet = (source: string) =>
      [...new Set(
        [...source.matchAll(/"([a-z]+(?:[a-z0-9-]*\.)*googleapis\.com)"/g)].map((match) => match[1]!),
      )].toSorted();
    expect(serviceSet(medlockMirror)).toEqual(serviceSet(medlockBootstrap));
    expect(serviceSet(criticalMirror)).toEqual(serviceSet(criticalBootstrap));
    expect(criticalMirror).toContain('"certificatemanager.googleapis.com"');
    expect(criticalMirror).toContain('"compute.googleapis.com"');
  });

  test("production state can relinquish legacy domain mappings without provider loss", async () => {
    const moduleMain = await readFile(
      join(repoRoot, "terraform/modules/cloud-run-service/main.tf"),
      "utf8",
    );
    const moduleVersions = await readFile(
      join(repoRoot, "terraform/modules/cloud-run-service/versions.tf"),
      "utf8",
    );
    const deployment = await readFile(
      join(repoRoot, "terraform/deployments/prod/main.tf"),
      "utf8",
    );

    expect(moduleVersions).toContain("configuration_aliases = [google.no_attribution]");
    expect(moduleMain).toContain("from = google_cloud_run_domain_mapping.site");
    expect(moduleMain).not.toContain("provider = google.no_attribution");
    expect(deployment).toContain('alias                           = "no_attribution"');
    expect(deployment).toContain("google.no_attribution = google.no_attribution");
  });
});

async function scaffold(name: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "platform-test-"));
  temporaryRoots.push(root);
  const target = join(root, name);
  const result = await run(["scaffold", name, platformSha, "123456789", target]);
  expect(result.exitCode, result.stderr).toBe(0);
  return target;
}

async function setPlatformIdentity(
  app: string,
  identity: {
    githubRepositoryId: string;
    name: string;
    projectId: string;
    serviceName: string;
  },
): Promise<void> {
  const path = join(app, ".platform/config.json");
  const config = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
  Object.assign(config, identity);
  await writeFile(path, JSON.stringify(config, null, 2) + "\n");
}

// Byte-identical to additionalProductionResources in the reviewed Terraform
// mirror contract. Comment-free, because the contract compares parsed documents
// and those strip comments.
const MEDLOCK_REVIEWED_RESOURCES = `resource "google_firestore_field" "waitlist_entry_ttl" {
  project    = var.project_id
  database   = "(default)"
  collection = "waitlist"
  field      = "expiresAt"

  ttl_config {}

  index_config {}

  depends_on = [module.site]
}

resource "google_firestore_field" "waitlist_quota_ttl" {
  project    = var.project_id
  database   = "(default)"
  collection = "waitlist_quota"
  field      = "expiresAt"

  ttl_config {}

  index_config {}

  depends_on = [module.site]
}

resource "google_identity_platform_config" "default" {
  project = var.project_id

  sign_in {
    allow_duplicate_emails = false

    email {
      enabled           = true
      password_required = false
    }
  }

  authorized_domains = [
    "medlock.ai",
    "www.medlock.ai",
  ]
}

resource "google_recaptcha_enterprise_key" "waitlist" {
  project      = var.project_id
  display_name = "Medlock waitlist ownership"

  deletion_policy = "PREVENT"

  web_settings {
    integration_type  = "SCORE"
    allow_all_domains = false
    allow_amp_traffic = false
    allowed_domains   = ["medlock.ai"]
  }
}`;

async function configureReviewedMedlock(app: string): Promise<void> {
  await setPlatformIdentity(app, {
    githubRepositoryId: "1025243085",
    name: "medlock",
    projectId: "medlock-1025243085",
    serviceName: "medlock",
  });

  const productionMainPath = join(app, "infra/terraform/prod/main.tf");
  let productionMain = await readFile(productionMainPath, "utf8");
  productionMain = productionMain
    .replace('artifact_registry_description                  = "Container images for medlock."', 'artifact_registry_description                  = "Container images for Medlock."')
    .replace(
      "  preview_publisher_service_account_email        = var.preview_publisher_service_account_email",
      [
        "  preview_publisher_service_account_email        = var.preview_publisher_service_account_email",
        "  container_env = {",
        '    ALLOWED_HOSTS    = "medlock.ai,www.medlock.ai,mcp.medlock.ai,healthmcp.ai,www.healthmcp.ai,healthmcp.app,www.healthmcp.app,*.run.app"',
        '    ALLOWED_ORIGINS  = "https://medlock.ai,https://www.medlock.ai,https://mcp.medlock.ai,https://chat.openai.com,https://claude.ai,https://*.run.app"',
        '    CANONICAL_HOST   = "medlock.ai"',
        '    LEGACY_HOSTS     = "healthmcp.ai,www.healthmcp.ai,healthmcp.app,www.healthmcp.app"',
        '    MEDLOCK_VERSION  = "0.2.0"',
        '    WAITLIST_BACKEND               = "firestore"',
        '    IDENTITY_PLATFORM_AUDIENCE     = "medlock-1025243085"',
        '    IDENTITY_PLATFORM_CONTINUE_URL = "https://medlock.ai/api/waitlist/confirm"',
        '    RECAPTCHA_PROJECT_ID           = "medlock-1025243085"',
        "    RECAPTCHA_SITE_KEY             = google_recaptcha_enterprise_key.waitlist.name",
        "  }",
      ].join("\n"),
    )
    .replace(
      "  runtime_secret_version_adder_ids               = var.runtime_secret_version_adder_ids",
      [
        "  runtime_secret_version_adder_ids               = var.runtime_secret_version_adder_ids",
        "  firestore_database = {",
        '    name                         = "(default)"',
        '    location_id                  = "nam5"',
        '    runtime_collection_env_name  = "FIRESTORE_COLLECTION"',
        '    runtime_collection_env_value = "waitlist"',
        "  }",
      ].join("\n"),
    );
  // The reviewed contract now pins additional project resources alongside the
  // module, so the fixture has to carry them too or `doctor` correctly refuses.
  productionMain = `${productionMain.trimEnd()}\n\n${MEDLOCK_REVIEWED_RESOURCES}\n`;
  await writeFile(productionMainPath, productionMain);

  const productionVariablesPath = join(app, "infra/terraform/prod/variables.tf");
  let productionVariables = await readFile(productionVariablesPath, "utf8");
  productionVariables = replaceAfterMarker(
    productionVariables,
    'variable "project_id"',
    '  default     = "medlock"',
    '  default     = "medlock-1025243085"',
  ).replaceAll(
    "@medlock.iam.gserviceaccount.com",
    "@medlock-1025243085.iam.gserviceaccount.com",
  );
  const waitlistDefault = '  default = [\n    "waitlist-identity-keyset",\n  ]';
  for (const variable of [
    "runtime_secret_ids",
    "runtime_secret_accessor_ids",
    "runtime_secret_version_adder_ids",
  ]) {
    productionVariables = replaceAfterMarker(
      productionVariables,
      'variable "' + variable + '"',
      "  default     = []",
      waitlistDefault,
    );
  }
  await writeFile(productionVariablesPath, productionVariables);

  const bootstrapMainPath = join(app, "infra/terraform/bootstrap/main.tf");
  let bootstrapMain = await readFile(bootstrapMainPath, "utf8");
  bootstrapMain = bootstrapMain
    .replace(
      "  manage_automatic_default_service_account_grants_policy",
      [
        "  required_services = [",
        '    "artifactregistry.googleapis.com",',
        '    "cloudasset.googleapis.com",',
        '    "cloudresourcemanager.googleapis.com",',
        '    "firestore.googleapis.com",',
        '    "iam.googleapis.com",',
        '    "iamcredentials.googleapis.com",',
        '    "identitytoolkit.googleapis.com",',
        '    "recaptchaenterprise.googleapis.com",',
        '    "run.googleapis.com",',
        '    "secretmanager.googleapis.com",',
        '    "serviceusage.googleapis.com",',
        '    "storage.googleapis.com",',
        '    "sts.googleapis.com",',
        "  ]",
        "  runtime_project_roles = [",
        '    "roles/datastore.user",',
        "  ]",
        "  manage_automatic_default_service_account_grants_policy",
      ].join("\n"),
    )
    .replace(
      '"Runtime identity for the medlock Cloud Run services."',
      '"Runtime identity for the Medlock Cloud Run services."',
    );
  await writeFile(bootstrapMainPath, bootstrapMain);

  const bootstrapVariablesPath = join(app, "infra/terraform/bootstrap/variables.tf");
  let bootstrapVariables = await readFile(bootstrapVariablesPath, "utf8");
  bootstrapVariables = replaceAfterMarker(
    bootstrapVariables,
    'variable "project_id"',
    '  default     = "medlock"',
    '  default     = "medlock-1025243085"',
  )
    .replaceAll('"medlock-tfstate"', '"medlock-tfstate-1025243085"')
    .replaceAll('"medlock-tfstate-bootstrap"', '"medlock-tfstate-1025243085-bootstrap"');
  bootstrapVariables = replaceAfterMarker(
    bootstrapVariables,
    'variable "github_repo"',
    '  default     = "medlock"',
    '  default     = "healthmcp"',
  );
  bootstrapVariables = replaceAfterMarker(
    bootstrapVariables,
    'variable "github_repository_id"',
    '  default     = "123456789"',
    '  default     = "1025243085"',
  );
  await writeFile(bootstrapVariablesPath, bootstrapVariables);

  for (const relativePath of [
    "infra/terraform/bootstrap/versions.tf",
    "infra/terraform/prod/versions.tf",
  ]) {
    const path = join(app, relativePath);
    const versions = (await readFile(path, "utf8"))
      .replaceAll('"medlock-tfstate"', '"medlock-tfstate-1025243085"')
      .replaceAll('"medlock-tfstate-bootstrap"', '"medlock-tfstate-1025243085-bootstrap"');
    await writeFile(path, versions);
  }
}

function replaceAfterMarker(
  source: string,
  marker: string,
  search: string,
  replacement: string,
): string {
  const markerIndex = source.indexOf(marker);
  const searchIndex = source.indexOf(search, markerIndex + marker.length);
  if (markerIndex === -1 || searchIndex === -1) {
    throw new Error("test fixture mutation target was not found");
  }
  return source.slice(0, searchIndex) + replacement + source.slice(searchIndex + search.length);
}

async function runContract(
  app: string,
  repositoryId = "123456789",
  expectedPlatformSha = platformSha,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const contract = join(repoRoot, "tools/ci/enforce-app-contract.ts");
  const template = join(repoRoot, "templates/app");
  const child = Bun.spawn(
    [
      process.execPath,
      "--no-env-file",
      "--no-orphans",
      contract,
      app,
      template,
      repositoryId,
      expectedPlatformSha,
    ],
    {
      cwd: join(repoRoot, "tools/ci"),
      stdout: "pipe",
      stderr: "pipe",
    },
  );
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { exitCode, stdout, stderr };
}

async function runVerification(
  app: string,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const runner = join(repoRoot, "templates/app/tools/platform-verify.ts");
  const child = Bun.spawn(
    [process.execPath, "--no-env-file", "--no-orphans", runner, app],
    {
      cwd: join(repoRoot, "tools/ci"),
      stdout: "pipe",
      stderr: "pipe",
    },
  );
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { exitCode, stdout, stderr };
}

async function grep(
  args: string[],
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const child = Bun.spawn(["grep", ...args], {
    cwd: repoRoot,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { exitCode, stdout, stderr };
}

function sumGrepCounts(output: string): number {
  return output
    .split("\n")
    .filter(Boolean)
    .map((count) => Number.parseInt(count, 10))
    .reduce((total, count) => total + count, 0);
}

async function run(
  args: string[],
  env: Record<string, string> = {},
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const child = Bun.spawn([process.execPath, cli, ...args], {
    cwd: repoRoot,
    env: { ...process.env, ...env },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { exitCode, stdout, stderr };
}
