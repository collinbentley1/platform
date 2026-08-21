import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "..");
const cli = join(repoRoot, "tools/platform.ts");
const platformSha = "a".repeat(40);
const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("platform scaffold and doctor", () => {
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

  test("doctor rejects a duplicate effective scanner lock entry", async () => {
    const app = await scaffold("scanner-lock-substitution");
    const path = join(app, "bun.lock");
    const original = await readFile(path, "utf8");
    const trustedLine = original.match(
      /^    "@socketsecurity\/bun-security-scanner": \[.*\],$/m,
    )?.[0];
    expect(trustedLine).toBeDefined();
    await writeFile(
      path,
      original.replace(
        trustedLine!,
        `${trustedLine}\n    "@socketsecurity/bun-security-scanner": ["@socketsecurity/bun-security-scanner@1.1.2", "", {}, "sha512-invalid"],`,
      ),
    );

    const result = await run(["doctor", app]);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("does not resolve the reviewed Socket scanner integrity");
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

  test("doctor permits one safe transition SHA but rejects pre-migration trust", async () => {
    const app = await scaffold("safe-transition");
    const path = join(app, "infra/terraform/bootstrap/main.tf");
    const original = await readFile(path, "utf8");
    const safePrior = "b".repeat(40);
    await writeFile(path, original.replace(`    "${platformSha}",`, `    "${platformSha}",\n    "${safePrior}",`));
    expect((await run(["doctor", app])).exitCode).toBe(0);

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
        original.replace(`    "${platformSha}",`, `    "${platformSha}",\n    "${vulnerable}",`),
      );
      const result = await run(["doctor", app]);
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("vulnerable pre-migration SHA");
    }
  });

  test("doctor binds consumer pins to the active reusable workflow SHA", async () => {
    const app = await scaffold("active-workflow");
    const result = await run(["doctor", app], { PLATFORM_WORKFLOW_SHA: "b".repeat(40) });
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("does not match consumer pin");
  });

  test("protected Socket token reaches the exact scanner version without free-mode fallback", async () => {
    const authenticated = await loadPinnedScanner("synthetic-regression-token");
    expect(authenticated.exitCode, authenticated.stderr).toBe(0);
    expect(authenticated.stdout).not.toContain("Socket Security Scanner free mode");

    const unauthenticated = await loadPinnedScanner();
    expect(unauthenticated.exitCode, unauthenticated.stderr).toBe(0);
    expect(unauthenticated.stdout).toContain("Socket Security Scanner free mode");

    for (const workflow of ["application.yml", "socket-firewall.yml"]) {
      expect(await readFile(join(repoRoot, ".github/workflows", workflow), "utf8")).toContain(
        "SOCKET_API_KEY: ${{ secrets.SOCKET_API_TOKEN }}",
      );
    }
    expect(await readFile(join(repoRoot, "templates/app/Dockerfile"), "utf8")).toContain(
      'SOCKET_API_KEY="$(cat /run/secrets/socket_api_token)"',
    );
  });

  test("platform pull requests cannot receive the Socket organization token", async () => {
    const workflow = await readFile(join(repoRoot, ".github/workflows/platform.yml"), "utf8");
    expect(workflow).toContain("ALLOW_SOCKET_FREE_MODE: ${{ github.event_name != 'push' }}");
    expect(workflow).toContain(
      "SOCKET_API_KEY: ${{ github.event_name == 'push' && secrets.SOCKET_API_TOKEN || '' }}",
    );
    expect(workflow).not.toContain("SOCKET_API_KEY: ${{ secrets.SOCKET_API_TOKEN }}");
    expect(workflow).not.toContain("workflow_dispatch:");
  });

  test("SBOM attest jobs consume the exact uploaded artifact and verify its content", async () => {
    for (const workflowName of ["deploy-preview.yml", "deploy-prod.yml"]) {
      const workflow = await readFile(
        join(repoRoot, ".github/workflows", workflowName),
        "utf8",
      );
      const build = workflow.slice(workflow.indexOf("  build:\n"), workflow.indexOf("\n  canary:\n"));
      const attest = workflow.slice(workflow.indexOf("  attest:\n"), workflow.indexOf("\n  deploy:\n"));

      expect(build).toContain(
        "sbom-artifact-id: ${{ steps.upload_sbom.outputs.artifact-id }}",
      );
      expect(build).toContain(
        "sbom-content-digest: ${{ steps.sbom_digest.outputs.digest }}",
      );
      expect(build).toContain("id: sbom_digest");
      expect(build).toContain("sha256sum platform-build/sbom.spdx.json");
      expect(build).toContain("id: upload_sbom");
      expect(build.indexOf("id: sbom_digest")).toBeLessThan(
        build.indexOf("id: upload_sbom"),
      );
      expect(attest).toContain(
        "artifact-ids: ${{ needs.build.outputs.sbom-artifact-id }}",
      );
      expect(attest).toContain("digest-mismatch: error");
      expect(attest).toContain(
        "EXPECTED_SBOM_DIGEST: ${{ needs.build.outputs.sbom-content-digest }}",
      );
      expect(attest).toContain("sha256sum --check --strict");
      expect(attest).not.toMatch(/\n\s+name:\s+.*sbom-/);
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

    expect(caller).toContain("- converted_to_draft");
    expect(caller).toContain("github.event.action == 'synchronize'");
    expect(caller).toContain("uses: collinbentley1/platform/.github/workflows/cleanup-preview.yml@");
    expect(caller.indexOf("invalidate:")).toBeLessThan(caller.indexOf("deploy:"));
    expect(caller).toContain("needs: invalidate");
    expect(cleanup).toContain("github.event.action == 'synchronize'");
    expect(cleanup).toContain("github.event.action == 'converted_to_draft'");
    expect(cleanup).toContain("gha-preview-operator@");
    expect(cleanup).not.toContain("gha-preview-deploy@");
    expect(deploy).toContain('--revision-suffix="$revision_suffix"');
    expect(deploy).toContain("EXPECTED_HEAD_SHA: ${{ github.event.pull_request.head.sha }}");
    const publishCanary = deploy.slice(
      deploy.indexOf("  publish-canary:\n"),
      deploy.indexOf("\n  publish:\n"),
    );
    expect(publishCanary).toContain("environment: preview-publish");
    expect(publishCanary).not.toContain("GCP_CLOUD_PREVIEW_ENABLED");
    expect(deploy.slice(deploy.indexOf("  publish:\n"), deploy.indexOf("\n  attest:\n"))).toContain(
      "needs.publish-canary.result == 'success'",
    );
    expect(deploy).toContain("  invalidate:\n");
    const invalidation = deploy.slice(deploy.indexOf("  invalidate:\n"));
    expect(invalidation).toContain("gha-preview-operator@");
    expect(deploy).toContain("deployed-revision: ${{ steps.deploy.outputs.revision }}");
    expect(invalidation).toContain("EXPECTED_REVISION: ${{ needs.deploy.outputs.deployed-revision }}");
    expect(invalidation).toContain('if [ "$current_revision" != "$EXPECTED_REVISION" ]');
    expect(reconcile).toContain("expected_revision_prefix");
    expect(reconcile).toContain("head_sha:0:12");
    expect(reconcile).toContain("gha-preview-operator@");
    expect(reconcile).not.toContain("gha-preview-deploy@");
  });

  test("Artifact Registry publishers, deployers, and preview traffic operators remain disjoint", async () => {
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

    const serviceModule = await readFile(
      join(repoRoot, "terraform/modules/cloud-run-service/main.tf"),
      "utf8",
    );
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
    for (const [resource, deployer] of [
      ["prod_deploy_reader", "prod_deploy_service_account_email"],
      ["preview_deploy_reader", "preview_deploy_service_account_email"],
    ] as const) {
      const start = serviceModule.indexOf(
        `resource "google_artifact_registry_repository_iam_member" "${resource}"`,
      );
      const block = serviceModule.slice(start, serviceModule.indexOf("\n}\n", start) + 3);
      expect(block).toContain('role       = "roles/artifactregistry.reader"');
      expect(block).toContain(`member     = "serviceAccount:\${var.${deployer}}"`);
      expect(block).not.toContain("roles/artifactregistry.writer");
    }
    const registryIam = serviceModule.slice(
      serviceModule.indexOf(
        'resource "google_artifact_registry_repository_iam_member" "prod_publisher_writer"',
      ),
      serviceModule.indexOf('resource "google_secret_manager_secret" "runtime"'),
    );
    expect(registryIam).not.toContain("preview_operator_service_account_email");
    expect(serviceModule).toContain(
      'resource "google_cloud_run_v2_service_iam_member" "preview_operator"',
    );

    const bootstrap = await readFile(
      join(repoRoot, "terraform/modules/bootstrap/main.tf"),
      "utf8",
    );
    for (const attribute of [
      "attribute.prod_publish_workflow_sha",
      "attribute.preview_publish_workflow_sha",
      "attribute.preview_deploy_workflow_sha",
      "attribute.preview_operator_workflow_sha",
      "attribute.legacy_prod_deploy",
      "attribute.legacy_preview_deploy",
      "attribute.legacy_preview_operator",
      "attribute.legacy_terraform",
    ]) {
      expect(bootstrap).toContain(`"${attribute}"`);
    }
    expect(bootstrap).not.toContain('"attribute.environment"');
    expect(bootstrap).not.toContain('"attribute.repository_id"');
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
      expect(workflow).not.toContain("${{ vars.");
    }

    const production = await readFile(join(repoRoot, ".github/workflows/deploy-prod.yml"), "utf8");
    const preview = await readFile(join(repoRoot, ".github/workflows/deploy-preview.yml"), "utf8");
    expect(production).toContain("needs.canary.result == 'success'");
    expect(preview).toContain("needs.canary.result == 'success'");
    expect(preview).toContain("needs.publish-canary.result == 'success'");
    expect(production).not.toContain("GCP_EXACT_WIF_CANARY_ENABLED");
    expect(preview).not.toContain("GCP_CLOUD_PREVIEW_ENABLED");
  });

  test("runtime configuration is immutable per repository and Runsetta stays offline", async () => {
    const production = await readFile(join(repoRoot, ".github/workflows/deploy-prod.yml"), "utf8");
    const preview = await readFile(join(repoRoot, ".github/workflows/deploy-preview.yml"), "utf8");

    for (const workflow of [production, preview]) {
      expect(workflow).toContain("DB_MANIFEST_JSON: ${{ secrets.GRYPE_DB_MANIFEST_JSON }}");
      expect(workflow).toContain("MAPBOX_PUBLIC_TOKEN: ${{ secrets.MAPBOX_PUBLIC_TOKEN }}");
      expect(workflow).toContain('[[ ! "$MAPBOX_PUBLIC_TOKEN" =~ ^pk\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$ ]]');
      expect(workflow).toContain('. + {MAPBOX_ACCESS_TOKEN: $token}');
      expect(workflow).toContain('RUNSETTA_OFFLINE: "1"');
    }
    expect(preview).toContain('WAITLIST_BACKEND: "memory"');
    expect(production).toContain('WAITLIST_BACKEND: "firestore"');
    expect(production).toContain('FIRESTORE_PROJECT_ID: "medlock-1025243085"');
    expect(production).toContain("--clear-secrets");
    expect(production).not.toContain("--set-secrets");
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
    expect(moduleMain).toContain("for_each = var.runtime_secret_accessor_ids");
    expect(moduleVariables).toContain("setsubtract(var.runtime_secret_accessor_ids, var.runtime_secret_ids)");
    expect(deployment).toContain("runtime_secret_accessor_ids       = []");
    expect(deployment).toContain('RUNSETTA_OFFLINE   = "1"');
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

async function runContract(app: string): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const contract = join(repoRoot, "tools/ci/enforce-app-contract.ts");
  const template = join(repoRoot, "templates/app");
  const child = Bun.spawn(
    [process.execPath, "--no-env-file", "--no-orphans", contract, app, template],
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

async function loadPinnedScanner(
  apiKey?: string,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const dataHome = await mkdtemp(join(tmpdir(), "platform-socket-test-"));
  temporaryRoots.push(dataHome);
  const env = { ...process.env, XDG_DATA_HOME: dataHome };
  delete env.SOCKET_API_KEY;
  delete env.SOCKET_API_TOKEN;
  if (apiKey) {
    env.SOCKET_API_KEY = apiKey;
  }
  const child = Bun.spawn(
    [
      process.execPath,
      "--no-env-file",
      "--no-orphans",
      "-e",
      'await import("./node_modules/@socketsecurity/bun-security-scanner/src/index.ts")',
    ],
    {
      cwd: repoRoot,
      env,
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
