import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
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
    expect(bootstrap).toContain("preview_operations_active_workflow_shas = [");
    expect(bootstrap).toContain("preview_operator_transition_workflow_shas");
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

  test("doctor rejects missing, redirected, or additional deploy secret mappings", async () => {
    const mutations = [
      [
        "missing-deploy-secret",
        (workflow: string) =>
          workflow.replace("      DHI_ACCESS_TOKEN: ${{ secrets.DHI_ACCESS_TOKEN }}\n", ""),
      ],
      [
        "redirected-deploy-secret",
        (workflow: string) =>
          workflow.replace(
            "      DHI_ACCESS_TOKEN: ${{ secrets.DHI_ACCESS_TOKEN }}",
            "      DHI_ACCESS_TOKEN: ${{ secrets.DHI_USERNAME }}",
          ),
      ],
      [
        "additional-deploy-secret",
        (workflow: string) =>
          workflow.replace(
            "      SOCKET_API_TOKEN: ${{ secrets.SOCKET_API_TOKEN }}",
            "      SOCKET_API_TOKEN: ${{ secrets.SOCKET_API_TOKEN }}\n" +
              "      UNREVIEWED_TOKEN: ${{ secrets.UNREVIEWED_TOKEN }}",
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

  test("doctor permits one safe transition SHA but rejects pre-migration trust", async () => {
    const app = await scaffold("safe-transition");
    const path = join(app, "infra/terraform/bootstrap/main.tf");
    const original = await readFile(path, "utf8");
    const safePrior = "b".repeat(40);
    const withTransition = (transition: string) =>
      original
        .replace(`    "${platformSha}",`, `    "${platformSha}",\n    "${transition}",`)
        .replace(
          /preview_operator_transition_workflow_shas\s*=\s*\[\]/,
          `preview_operator_transition_workflow_shas = [\n    "${transition}",\n  ]`,
        );
    await writeFile(path, withTransition(safePrior));
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
        withTransition(vulnerable),
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

  test("Socket credentials are confined to one pre-extraction deploy step", async () => {
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
      const expectedSecretContextReferences: SecretContextReference[] = [
        { job: null, path: "on.workflow_call.<key:secrets>", value: "secrets" },
        {
          job: "build",
          path: "jobs.build.steps.7.env.SOCKET_API_TOKEN",
          value: "${{ secrets.SOCKET_API_TOKEN }}",
        },
        {
          job: "build",
          path: "jobs.build.steps.9.with.username",
          value: "${{ secrets.DHI_USERNAME }}",
        },
        {
          job: "build",
          path: "jobs.build.steps.9.with.password",
          value: "${{ secrets.DHI_ACCESS_TOKEN }}",
        },
        {
          job: "build",
          path: "jobs.build.steps.17.env.DB_MANIFEST_JSON",
          value: "${{ secrets.GRYPE_DB_MANIFEST_JSON }}",
        },
        {
          job: "deploy",
          path: "jobs.deploy.steps.4.env.MAPBOX_PUBLIC_TOKEN",
          value: "${{ secrets.MAPBOX_PUBLIC_TOKEN }}",
        },
      ];
      expect(semanticSecretContextReferences(text)).toEqual(expectedSecretContextReferences);
      for (const hostileScalar of [
        "${{ secrets.socket_api_token }}",
        "${{ secrets['socket_api_token'] }}",
        "${{ format('{0}', secrets.DHI_ACCESS_TOKEN) }}",
        "${{ toJSON(secrets) }}",
        "\"${{ \\u0073ecrets.socket_api_token }}\"",
        "\"${{ \\x73ecrets.socket_api_token }}\"",
      ]) {
        const mutated = text.replace(
          "  canary:\n",
          `  canary:\n    env:\n      HOSTILE_SECRET_REFERENCE: ${hostileScalar}\n`,
        );
        expect(semanticSecretContextReferences(mutated)).not.toEqual(
          expectedSecretContextReferences,
        );
      }
      const anchoredEnvironment = text
        .replace(
          "        env:\n          SOCKET_API_TOKEN: ${{ secrets.SOCKET_API_TOKEN }}",
          "        env: &platform_secret_env\n" +
            "          SOCKET_API_TOKEN: ${{ secrets.SOCKET_API_TOKEN }}",
        )
        .replace("  canary:\n", "  canary:\n    env: *platform_secret_env\n");
      expect(semanticSecretContextReferences(anchoredEnvironment)).not.toEqual(
        expectedSecretContextReferences,
      );
      let anchoredStep = text.replace(
        "      - name: Enforce the organization Socket policy before package extraction",
        "      - &platform_secret_step\n" +
          "        name: Enforce the organization Socket policy before package extraction",
      );
      const canaryStart = anchoredStep.indexOf("\n  canary:\n");
      const canarySteps = anchoredStep.indexOf("    steps:\n", canaryStart);
      const canaryStepsBody = canarySteps + "    steps:\n".length;
      anchoredStep =
        anchoredStep.slice(0, canaryStepsBody) +
        "      - *platform_secret_step\n" +
        anchoredStep.slice(canaryStepsBody);
      expect(semanticSecretContextReferences(anchoredStep)).not.toEqual(
        expectedSecretContextReferences,
      );
      const workflowCall = text.slice(0, text.indexOf("\npermissions:"));
      expect(workflowCall.slice(workflowCall.indexOf("    secrets:\n")).trimEnd()).toBe(
        [
          "    secrets:",
          "      DHI_ACCESS_TOKEN:",
          "        required: true",
          "      DHI_USERNAME:",
          "        required: true",
          "      GRYPE_DB_MANIFEST_JSON:",
          "        required: true",
          "      MAPBOX_PUBLIC_TOKEN:",
          "        required: false",
          "      SOCKET_API_TOKEN:",
          "        required: true",
        ].join("\n"),
      );
      expect(text.split("SOCKET_API_TOKEN: ${{ secrets.SOCKET_API_TOKEN }}")).toHaveLength(2);
      expect(text).toContain(
        '--config="$GITHUB_WORKSPACE/_platform_policy/tools/ci/bunfig.toml" pm scan',
      );
      expect(text).not.toContain("socket_api_token=");
      expect(text.indexOf("Enforce the trusted application and container contract")).toBeLessThan(
        text.indexOf("Enforce the organization Socket policy before package extraction"),
      );
      expect(
        text.indexOf("Enforce the organization Socket policy before package extraction"),
      ).toBeLessThan(text.indexOf("Login to Docker Hardened Images"));
      const buildJob = text.slice(text.indexOf("  build:\n"), text.indexOf("\n  canary:\n"));
      const deployStart = text.indexOf("  deploy:\n");
      const deployEnd =
        workflow === "deploy-preview.yml" ? text.indexOf("\n  invalidate:\n") : text.length;
      const deployJob = text.slice(deployStart, deployEnd);
      for (const secret of [
        "DHI_ACCESS_TOKEN",
        "DHI_USERNAME",
        "GRYPE_DB_MANIFEST_JSON",
        "SOCKET_API_TOKEN",
      ]) {
        const reference = `\${{ secrets.${secret} }}`;
        expect(text.split(reference)).toHaveLength(2);
        expect(buildJob).toContain(reference);
        expect(deployJob).not.toContain(reference);
      }
      const mapboxReference = "${{ secrets.MAPBOX_PUBLIC_TOKEN }}";
      expect(text.split(mapboxReference)).toHaveLength(2);
      expect(deployJob).toContain(mapboxReference);
      expect(buildJob).not.toContain(mapboxReference);
    }
    for (const workflow of ["deploy-preview.yml", "deploy-prod.yml"]) {
      const caller = await readFile(
        join(repoRoot, "templates/app/.github/workflows", workflow),
        "utf8",
      );
      const secretMap = caller.slice(caller.indexOf("    secrets:\n")).trimEnd();
      expect(secretMap).toBe(
        [
          "    secrets:",
          "      DHI_ACCESS_TOKEN: ${{ secrets.DHI_ACCESS_TOKEN }}",
          "      DHI_USERNAME: ${{ secrets.DHI_USERNAME }}",
          "      GRYPE_DB_MANIFEST_JSON: ${{ secrets.GRYPE_DB_MANIFEST_JSON }}",
          "      MAPBOX_PUBLIC_TOKEN: ${{ secrets.MAPBOX_PUBLIC_TOKEN }}",
          "      SOCKET_API_TOKEN: ${{ secrets.SOCKET_API_TOKEN }}",
        ].join("\n"),
      );
    }
    const dockerfile = await readFile(join(repoRoot, "templates/app/Dockerfile"), "utf8");
    expect(dockerfile).toContain(
      "oven/bun:1.4.0-alpine@sha256:07235578f79ef8c6f97d94aee7938e76f5cdba5f21ae5dbfdd3d3d38058437eb",
    );
    expect(dockerfile).toContain(
      "dhi.io/bun:1-alpine-dev@sha256:d364f4eb6d20f8e906bdb9d12726995f8335878f46e0c1c69c910df9d92df5d8",
    );
    expect(dockerfile).toContain(
      "dhi.io/bun:1-alpine@sha256:b169efde3cf30151d66f3d7988cad69b4d08833cc4cfaeca7da6bda2bd0a89b3",
    );
    expect(dockerfile).not.toContain("dhi.io/bun:1-dev@");
    expect(dockerfile).not.toContain("dhi.io/bun:1@");
    expect(dockerfile.split("34cbb9a40b4bd1bd767d134a7065e66c2432a676")).toHaveLength(3);
    expect(dockerfile).not.toContain("--mount=type=secret");
    expect(dockerfile).toContain(
      "COPY tools/socket-security-scanner.ts ./tools/socket-security-scanner.ts",
    );
    expect(dockerfile).toContain("unset SOCKET_API_TOKEN SOCKET_API_KEY");
  });

  test("platform pull requests cannot receive the Socket organization token", async () => {
    const workflow = await readFile(join(repoRoot, ".github/workflows/platform.yml"), "utf8");
    expect(workflow).toContain(
      "SOCKET_API_TOKEN: ${{ github.event_name == 'push' && secrets.SOCKET_API_TOKEN || '' }}",
    );
    expect(workflow).not.toContain("SOCKET_API_TOKEN: ${{ secrets.SOCKET_API_TOKEN }}");
    expect(workflow).toContain('--config="$GITHUB_WORKSPACE/bunfig.toml" pm scan');
    expect(workflow).toContain("Platform pull requests must remain credential-free.");
    expect(workflow).toContain("unset SOCKET_API_TOKEN SOCKET_API_KEY");
    expect(workflow).not.toContain("workflow_dispatch:");
  });

  test("PR-controlled Docker output cannot issue GitHub runner commands", async () => {
    for (const [workflowName, buildName] of [
      ["deploy-preview.yml", "Build untrusted preview image without cloud credentials"],
      ["deploy-prod.yml", "Build production image without cloud credentials"],
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
        "if: always()",
      );
      const actionWindow = workflow.slice(build, restore);
      expect(actionWindow).toContain(
        "uses: docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf",
      );
      expect(actionWindow).toContain('DOCKER_BUILD_RECORD_UPLOAD: "false"');
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
    expect(infrastructure).toContain("(^|[^[:alnum:]_])(resource|data)[[:space:]]+");
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
    expect(cleanup).toContain("gha-preview-deploy@");
    expect(cleanup).not.toContain("gha-preview-operator@");
    expect(cleanup).not.toContain("actions/checkout@");
    expect(cleanup).toContain("PR_NUMBER: ${{ github.event.pull_request.number }}");
    expect(cleanup).toContain("verify_stable_preview_absent");
    expect(cleanup).toContain('[ "$status" = "404" ]');
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
    expect(invalidation).toContain("gha-preview-deploy@");
    expect(invalidation).not.toContain("gha-preview-operator@");
    expect(invalidation).not.toContain("actions/checkout@");
    expect(invalidation).toContain("verify_stable_preview_absent");
    expect(invalidation).toContain('[ "$status" = "404" ]');
    expect(deploy).toContain("deployed-revision: ${{ steps.deploy.outputs.revision }}");
    expect(deploy).toContain(
      'gh pr comment "$PR_NUMBER" --repo "$GITHUB_REPOSITORY" --body',
    );
    expect(deploy).not.toContain('gh pr comment "$PR_NUMBER" --body');
    const parsedPreview = Bun.YAML.parse(deploy) as {
      jobs: { deploy: { steps: Array<Record<string, unknown>> } };
    };
    const commentStep = parsedPreview.jobs.deploy.steps.find(
      (step) => step.name === "Comment preview URL",
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
    expect(invalidation).toContain("EXPECTED_REVISION: ${{ needs.deploy.outputs.deployed-revision }}");
    expect(invalidation).toContain('if [ "$current_revision" != "$EXPECTED_REVISION" ]');
    expect(reconcile).toContain("expected_revision_prefix");
    expect(reconcile).toContain("head_sha:0:12");
    expect(reconcile).toContain("gha-preview-deploy@");
    expect(reconcile).not.toContain("gha-preview-operator@");
    expect(reconcile).not.toContain("actions/checkout@");
    expect(reconcile).toContain("verify_stable_preview_absent");
    expect(reconcile).toContain('[ "$status" = "404" ]');
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

    expect(deploy).toContain('stable_preview_domain="preview.ycriticalhistory.org"');
    expect(deploy).toContain('preview_ingress="internal-and-cloud-load-balancing"');
    expect(deploy).toContain('--ingress="$PREVIEW_INGRESS"');
    expect(deploy).not.toContain("--ingress=all");
    expect(deploy).toContain(
      'deterministic_url="https://pr-${PR_NUMBER}---${PREVIEW_SERVICE}-${PROJECT_NUMBER}.${REGION}.run.app"',
    );
    expect(deploy).toContain('[a-z0-9.-]+\\.run\\.app');
    expect(deploy).toContain(
      'public_preview_url="https://pr-${PR_NUMBER}.${STABLE_PREVIEW_DOMAIN}"',
    );
    expect(deploy).toContain("PLATFORM_DEPLOY_NONCE: $deploy_nonce");
    expect(deploy).toContain('preview_nonce="$(openssl rand -hex 32)"');
    expect(deploy).toContain('"${public_preview_url}/livez"');
    expect(deploy).toContain("--max-filesize 1024");
    expect(deploy).toContain('if health_status="$(curl --silent --show-error');
    expect(deploy).not.toContain('"${public_preview_url}/livez" || true');
    expect(deploy).toContain('jq -e -s --arg nonce "$preview_nonce"');
    expect(deploy).toContain('length == 1 and .[0] == {deployment: $nonce, ok: true}');
    expect(deploy).not.toContain("*.preview.ycriticalhistory.org");
    expect(deploy).toContain("rollback_tag=true");
    expect(deploy).toContain('if [ "$current_revision" = "$expected_revision" ]');
    expect(deploy).toContain('--remove-tags="$tag"');
    expect(deploy.indexOf("rollback_tag=true")).toBeLessThan(
      deploy.indexOf('gcloud run deploy "$PREVIEW_SERVICE"'),
    );
    expect(deploy.indexOf('jq -e -s --arg nonce "$preview_nonce"')).toBeLessThan(
      deploy.lastIndexOf("rollback_tag=false"),
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
      'preview_ingress                   = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"',
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
      expect((await readdir(moduleDirectory)).sort()).toEqual(approvedModuleFiles);
      for (const name of approvedModuleFiles.filter((file) => file !== "main.tf")) {
        expect(await readFile(join(moduleDirectory, name), "utf8")).not.toMatch(
          /^\s*(?:resource|data|module|locals|provider)\s+(?:"|\{)/m,
        );
      }
    }
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
      "ba3a42664087637d024128134e610694a9cb7c19487656de063c2361121daebb",
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
        "google_artifact_registry_repository_iam_member.preview_deploy_reader",
        "google_artifact_registry_repository_iam_member.preview_publisher_writer",
        "google_artifact_registry_repository_iam_member.prod_deploy_reader",
        "google_artifact_registry_repository_iam_member.prod_publisher_writer",
        "google_cloud_run_v2_service_iam_member.preview_deploy",
        "google_cloud_run_v2_service_iam_member.prod_deploy",
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

    const bootstrap = await readFile(
      join(repoRoot, "terraform/modules/bootstrap/main.tf"),
      "utf8",
    );
    expect(createHash("sha256").update(bootstrap).digest("hex")).toBe(
      "42b12bb7f5eda9ac0f2131660e54d44fed4174db8a7e4735c48c0f3b995ab7f1",
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
        "google_project_iam_member.runtime_project_roles",
        "google_project_iam_member.terraform_convergence_reader",
        "google_service_account_iam_member.canary_wif_preview_deploy_workflow_sha",
        "google_service_account_iam_member.canary_wif_preview_operator_workflow_sha",
        "google_service_account_iam_member.canary_wif_preview_publish_workflow_sha",
        "google_service_account_iam_member.canary_wif_prod_publish_workflow_sha",
        "google_service_account_iam_member.canary_wif_prod_workflow_sha",
        "google_service_account_iam_member.canary_wif_terraform_workflow_sha",
        "google_service_account_iam_member.preview_deploy_uses_preview_runtime",
        "google_service_account_iam_member.preview_deploy_wif_repo",
        "google_service_account_iam_member.preview_deploy_wif_preview_operations_workflow_sha",
        "google_service_account_iam_member.preview_deploy_wif_workflow_sha",
        "google_service_account_iam_member.preview_operator_wif_repo",
        "google_service_account_iam_member.preview_operator_wif_workflow_sha",
        "google_service_account_iam_member.preview_publisher_wif_workflow_sha",
        "google_service_account_iam_member.prod_deploy_uses_runtime",
        "google_service_account_iam_member.prod_deploy_wif_prod_env",
        "google_service_account_iam_member.prod_deploy_wif_workflow_sha",
        "google_service_account_iam_member.prod_publisher_wif_workflow_sha",
        "google_service_account_iam_member.terraform_wif_prod_env",
        "google_service_account_iam_member.terraform_wif_workflow_sha",
        "google_storage_bucket_iam_binding.bootstrap_state_no_legacy_access",
        "google_storage_bucket_iam_binding.terraform_state_logs_no_legacy_access",
        "google_storage_bucket_iam_binding.terraform_state_no_legacy_access",
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
    expect(bootstrap).not.toContain("serviceAccount:gha-preview-operator@");
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
      "active SHA binds the distinct",
    );
    expect(bootstrap).not.toMatch(/^\s*module\s+"/m);
    for (const outputPath of [
      "terraform/modules/bootstrap/outputs.tf",
      "terraform/deployments/bootstrap/outputs.tf",
      "templates/app/infra/terraform/bootstrap/outputs.tf",
    ]) {
      expect(await readFile(join(repoRoot, outputPath), "utf8")).toContain(
        "Retired transition-only preview operator service account; receives no steady-state operational grants.",
      );
    }
    const activeOperationsBindingStart = bootstrap.indexOf(
      'resource "google_service_account_iam_member" "preview_deploy_wif_preview_operations_workflow_sha"',
    );
    const activeOperationsBinding = bootstrap.slice(
      activeOperationsBindingStart,
      bootstrap.indexOf("\n}\n", activeOperationsBindingStart) + 3,
    );
    expect(activeOperationsBinding).toContain(
      "for_each = var.preview_operations_active_workflow_shas",
    );
    expect(activeOperationsBinding).toContain(
      "service_account_id = google_service_account.preview_deploy.name",
    );
    expect(activeOperationsBinding).toContain("/attribute.preview_operator_workflow_sha/");
    const transitionOperatorBindingStart = bootstrap.indexOf(
      'resource "google_service_account_iam_member" "preview_operator_wif_workflow_sha"',
    );
    const transitionOperatorBinding = bootstrap.slice(
      transitionOperatorBindingStart,
      bootstrap.indexOf("\n}\n", transitionOperatorBindingStart) + 3,
    );
    expect(transitionOperatorBinding).toContain(
      "for_each = var.preview_operator_transition_workflow_shas",
    );
    expect(transitionOperatorBinding).toContain(
      "service_account_id = google_service_account.preview_operator.name",
    );
    expect(transitionOperatorBinding).toContain("/attribute.preview_operator_workflow_sha/");
    expect(bootstrap).toContain(
      'preview_operator_transition_workflow_sha_condition = length(var.preview_operator_transition_workflow_shas) == 0 ? "false"',
    );
    expect(bootstrap).toContain(
      '"attribute.legacy_preview_operator"       = "(${local.legacy_preview_operator_attribute_condition}) ? assertion.repository_id : \'denied\'"',
    );
    const bootstrapVariables = await readFile(
      join(repoRoot, "terraform/modules/bootstrap/variables.tf"),
      "utf8",
    );
    expect(bootstrapVariables).toContain(
      "setunion(var.preview_operations_active_workflow_shas, var.preview_operator_transition_workflow_shas) == var.trusted_platform_workflow_shas",
    );
    expect(bootstrapVariables).toContain(
      "setsubtract(var.preview_operator_transition_workflow_shas, var.trusted_platform_workflow_shas)",
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

  test("verified registry copies are isolated from exact-package staging cleanup", async () => {
    const copyRuns: string[] = [];
    const cleanupRuns: string[] = [];
    const occurrences = (value: string, needle: string) => value.split(needle).length - 1;
    for (const [workflowName, stagingKind] of [
      ["deploy-prod.yml", "production"],
      ["deploy-preview.yml", "preview"],
    ] as const) {
      const workflow = await readFile(
        join(repoRoot, ".github/workflows", workflowName),
        "utf8",
      );
      const runTag = "run-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}";
      expect(workflow).toContain(
        `platform-${"${repository}"}-${stagingKind}-staging-${"${GITHUB_RUN_ID}"}-${"${GITHUB_RUN_ATTEMPT}"}:${runTag}`,
      );
      expect(workflow).not.toContain(
        `platform-${"${source_repository}"}-${stagingKind}-staging-${"${GITHUB_RUN_ID}"}-${"${GITHUB_RUN_ATTEMPT}"}:${runTag}`,
      );
      expect(workflow).not.toContain(`-${stagingKind}-staging:${runTag}`);
      const parsed = Bun.YAML.parse(workflow) as {
        jobs: Record<string, Record<string, unknown>>;
      };
      const build = parsed.jobs.build;
      expect(build.outputs).toEqual({
        digest: "${{ steps.publish.outputs.digest }}",
        "sbom-artifact-id": "${{ steps.upload_sbom.outputs.artifact-id }}",
        "sbom-content-digest": "${{ steps.sbom_digest.outputs.digest }}",
        "staging-image": "${{ steps.metadata.outputs.staging_image }}",
      });
      const publish = parsed.jobs.publish;
      const publishSteps = publish.steps as Array<Record<string, unknown>>;
      const app = publishSteps.find((step) => step.name === "Resolve trusted application configuration");
      expect(app).toBeDefined();
      expect((app?.env as Record<string, string>).BUILD_STAGING_IMAGE).toBe(
        "${{ needs.build.outputs.staging-image }}",
      );
      const appRun = app?.run as string;
      expect(appRun).toContain(
        `platform-${"${source_repository}"}-${stagingKind}-staging-${"${GITHUB_RUN_ID}"}-([1-9][0-9]*):run-${"${GITHUB_RUN_ID}"}-([1-9][0-9]*)`,
      );
      expect(appRun).toContain('[[ ! "$BUILD_STAGING_IMAGE" =~ $staging_pattern ]]');
      expect(appRun).toContain('[[ "${BASH_REMATCH[1]}" != "${BASH_REMATCH[2]}" ]]');
      expect(appRun).toContain('echo "staging_image=$BUILD_STAGING_IMAGE"');
      const copyIndex = publishSteps.findIndex(
        (step) => step.name === "Copy the opaque image by digest",
      );
      const verifyIndex = publishSteps.findIndex(
        (step) => step.name === "Verify registry credentials were retired",
      );
      const authIndex = publishSteps.findIndex((step) => step.id === "auth");
      expect(copyIndex).toBe(authIndex + 1);
      expect(verifyIndex).toBe(copyIndex + 1);
      expect(verifyIndex).toBe(publishSteps.length - 1);
      expect(publish.permissions).toEqual({
        contents: "read",
        "id-token": "write",
        packages: "read",
      });

      const copy = publishSteps[copyIndex];
      expect(Object.keys(copy).sort()).toEqual(["env", "id", "name", "run"]);
      expect(copy.id).toBe("copy");
      expect(copy.env).toEqual({
        AR_ACCESS_TOKEN: "${{ steps.auth.outputs.access_token }}",
        GH_TOKEN: "${{ github.token }}",
        REMOTE_IMAGE: "${{ steps.app.outputs.remote_image }}",
        STAGING_DIGEST: "${{ needs.build.outputs.digest }}",
        STAGING_IMAGE: "${{ steps.app.outputs.staging_image }}",
      });
      const copyRun = copy.run as string;
      copyRuns.push(copyRun);
      expect(copyRun.startsWith("set -euo pipefail\n")).toBe(true);
      expect(occurrences(copyRun, '"$crane" auth login')).toBe(2);
      expect(
        occurrences(copyRun, '"$crane" copy "${STAGING_IMAGE}@${STAGING_DIGEST}" "$REMOTE_IMAGE"'),
      ).toBe(1);
      expect(occurrences(copyRun, '"$crane" digest "$REMOTE_IMAGE"')).toBe(1);
      expect(occurrences(copyRun, 'echo "digest=$remote_digest" >> "$GITHUB_OUTPUT"')).toBe(1);
      expect(copyRun).toContain('docker_config="$RUNNER_TEMP/platform-publisher-docker"');
      expect(copyRun).toContain('trap retire_registry_credentials EXIT');
      expect(copyRun).toContain('export DOCKER_CONFIG="$docker_config"');
      expect(copyRun).toContain('rm -f -- "$docker_config/config.json"');
      expect(copyRun.indexOf('"$crane" copy')).toBeLessThan(
        copyRun.indexOf('remote_digest="$("$crane" digest'),
      );
      expect(copyRun.indexOf('if [ "$remote_digest" != "$STAGING_DIGEST" ]')).toBeLessThan(
        copyRun.indexOf('echo "digest=$remote_digest" >> "$GITHUB_OUTPUT"'),
      );
      expect(copyRun).not.toContain("|| true");

      const verify = publishSteps[verifyIndex];
      expect(Object.keys(verify).sort()).toEqual(["name", "run"]);
      expect(verify.run).toBe(
        "set -euo pipefail\n" +
          'credential_file="$RUNNER_TEMP/platform-publisher-docker/config.json"\n' +
          'if [ -e "$credential_file" ] || [ -L "$credential_file" ]; then\n' +
          '  echo "Registry credentials survived the verified copy step." >&2\n' +
          "  exit 1\n" +
          "fi\n",
      );

      const cleanup = parsed.jobs["cleanup-staging"];
      expect(Object.keys(cleanup).sort()).toEqual([
        "if",
        "name",
        "needs",
        "permissions",
        "runs-on",
        "steps",
        "timeout-minutes",
      ]);
      expect(cleanup.needs).toEqual(["build", "publish"]);
      expect(cleanup.if).toBe("always() && needs.publish.result == 'success'");
      expect(cleanup["timeout-minutes"]).toBe(5);
      expect(cleanup.permissions).toEqual({ packages: "write" });
      const cleanupSteps = cleanup.steps as Array<Record<string, unknown>>;
      expect(cleanupSteps).toHaveLength(1);
      const cleanupStep = cleanupSteps[0];
      expect(Object.keys(cleanupStep).sort()).toEqual([
        "env",
        "name",
        "run",
        "timeout-minutes",
      ]);
      expect(cleanupStep["timeout-minutes"]).toBe(2);
      expect(cleanupStep.env).toEqual({
        GH_TOKEN: "${{ github.token }}",
        STAGING_DIGEST: "${{ needs.build.outputs.digest }}",
        STAGING_IMAGE: "${{ needs.build.outputs.staging-image }}",
      });
      const cleanupRun = cleanupStep.run as string;
      cleanupRuns.push(cleanupRun);
      expect(cleanupRun.startsWith("set -euo pipefail\n")).toBe(true);
      expect(cleanupRun).toContain(
        `(platform-${"${repository}"}-${stagingKind}-staging-${"${GITHUB_RUN_ID}"}-([1-9][0-9]*)):(run-${"${GITHUB_RUN_ID}"}-([1-9][0-9]*))`,
      );
      expect(cleanupRun).toContain('[[ ! "$STAGING_IMAGE" =~ $staging_pattern ]]');
      expect(cleanupRun).toContain('[[ "${BASH_REMATCH[2]}" != "${BASH_REMATCH[4]}" ]]');
      expect(cleanupRun).toContain('package="${BASH_REMATCH[1]}"');
      expect(cleanupRun).toContain('tag="${BASH_REMATCH[3]}"');
      expect(cleanupRun).not.toContain('package="platform-${repository}');
      expect(cleanupRun).not.toContain("--paginate");
      expect(cleanupRun).not.toContain("AR_ACCESS_TOKEN");
      expect(cleanupRun).not.toContain("DOCKER_CONFIG");
      expect(cleanupRun).not.toContain("steps.auth");
      expect(cleanupRun).not.toContain("us-east4-docker.pkg.dev");
      expect(occurrences(cleanupRun, "gh api")).toBe(2);
      expect(occurrences(cleanupRun, "gh api --method DELETE")).toBe(1);
      expect(occurrences(cleanupRun, '/packages/container/${package}"')).toBe(1);
      expect(cleanupRun).not.toContain('/versions/${version_id}');
      expect(occurrences(cleanupRun, "versions?state=active&per_page=100")).toBe(1);
      expect(cleanupRun).not.toContain("continue-on-error");
      expect(cleanupRun).not.toContain("|| true");
    }

    expect(copyRuns[0]).toBe(copyRuns[1]);
    expect(cleanupRuns[0].replace("production-staging-", "KIND-staging-")).toBe(
      cleanupRuns[1].replace("preview-staging-", "KIND-staging-"),
    );

    const digest = `sha256:${"a".repeat(64)}`;
    const tag = "run-123-1";
    const exact = {
      id: 123,
      metadata: { container: { tags: [tag] }, package_type: "container" },
      name: digest,
    };
    const fixtures = [
      { versions: [exact], valid: true },
      { versions: null, valid: false },
      { versions: {}, valid: false },
      { versions: [{ ...exact, name: `sha256:${"b".repeat(64)}` }], valid: false },
      {
        versions: [{ ...exact, metadata: { ...exact.metadata, container: { tags: ["wrong"] } } }],
        valid: false,
      },
      {
        versions: [
          { ...exact, metadata: { ...exact.metadata, container: { tags: [tag, "other"] } } },
        ],
        valid: false,
      },
      { versions: [{ ...exact, metadata: { ...exact.metadata, package_type: "npm" } }], valid: false },
      { versions: [{ id: 123, name: digest }], valid: false },
      { versions: [exact, { ...exact, id: 124 }], valid: false },
      {
        versions: [exact, { ...exact, id: 124, name: `sha256:${"b".repeat(64)}` }],
        valid: false,
      },
      { versions: [{ ...exact, id: "123" }], valid: false },
      { versions: [{ ...exact, id: 123.5 }], valid: false },
      { versions: [{ ...exact, id: 0 }], valid: false },
      { versions: [{ ...exact, id: -1 }], valid: false },
      { versions: [{ ...exact, id: null }], valid: false },
      { versions: [{ ...exact, id: true }], valid: false },
    ];
    for (const cleanupRun of cleanupRuns) {
      const match = cleanupRun.match(
        /jq -er --arg digest "\$STAGING_DIGEST" --arg tag "\$tag" '\n([\s\S]*?)\n\s+' "\$versions" 2>\/dev\/null/,
      );
      expect(match).not.toBeNull();
      const predicate = match?.[1] ?? "";
      for (const fixture of fixtures) {
        const child = Bun.spawn(
          ["jq", "-er", "--arg", "digest", digest, "--arg", "tag", tag, predicate],
          {
            stdin: new Blob([JSON.stringify(fixture.versions)]),
            stdout: "ignore",
            stderr: "ignore",
          },
        );
        expect((await child.exited) === 0).toBe(fixture.valid);
      }
    }

    const harnessRoot = await mkdtemp(join(tmpdir(), "platform-ghcr-cleanup-"));
    temporaryRoots.push(harnessRoot);
    const fakeBin = join(harnessRoot, "bin");
    await mkdir(fakeBin);
    const fakeGh = join(fakeBin, "gh");
    await writeFile(
      fakeGh,
      [
        "#!/bin/sh",
        "set -eu",
        '[ "$1" = "api" ]',
        "shift",
        'delete_request="0"',
        'previous=""',
        'endpoint=""',
        'for argument in "$@"; do',
        '  if [ "$previous" = "--method" ] && [ "$argument" = "DELETE" ]; then',
        '    delete_request="1"',
        "  fi",
        '  previous="$argument"',
        '  endpoint="$argument"',
        "done",
        'if [ "$delete_request" = "1" ]; then',
        '  case "$endpoint" in',
        '    */versions/*) exit 64 ;;',
        '    */packages/container/platform-*) ;;',
        '    *) exit 65 ;;',
        '  esac',
        '  printf \'%s\\n\' "$endpoint" >> "$FAKE_GH_CAPTURE"',
        "  exit 0",
        "fi",
        'case "$endpoint" in',
        '  /user/packages/*) [ "${FAKE_GH_FAIL_USER:-0}" != "1" ] || exit 1 ;;',
        "esac",
        'cat "$FAKE_GH_FIXTURE"',
        "",
      ].join("\n"),
    );
    await chmod(fakeGh, 0o755);

    const functionalFixtures = [
      { versions: [exact], expectedId: 123, failUser: false },
      { versions: [{ ...exact, id: 987654321 }], expectedId: 987654321, failUser: true },
      ...fixtures.filter((fixture) => !fixture.valid).map((fixture) => ({
        versions: fixture.versions,
        expectedId: null,
        failUser: false,
      })),
    ];
    for (const [runIndex, cleanupRun] of cleanupRuns.entries()) {
      const stagingKind = runIndex === 0 ? "production" : "preview";
      for (const [fixtureIndex, fixture] of functionalFixtures.entries()) {
        const runnerTemp = join(harnessRoot, `runner-${runIndex}-${fixtureIndex}`);
        await mkdir(runnerTemp);
        const fixturePath = join(runnerTemp, "fixture.json");
        const capturePath = join(runnerTemp, "delete.txt");
        await writeFile(fixturePath, JSON.stringify(fixture.versions));
        const child = Bun.spawn(["/bin/bash", "-c", cleanupRun], {
          env: {
            FAKE_GH_CAPTURE: capturePath,
            FAKE_GH_FAIL_USER: fixture.failUser ? "1" : "0",
            FAKE_GH_FIXTURE: fixturePath,
            GH_TOKEN: "test-token",
            GITHUB_REPOSITORY: "collinbentley1/cdbentley",
            GITHUB_REPOSITORY_OWNER: "collinbentley1",
            GITHUB_RUN_ATTEMPT: "2",
            GITHUB_RUN_ID: "123",
            PATH: `${fakeBin}:${process.env.PATH ?? "/usr/bin:/bin"}`,
            RUNNER_TEMP: runnerTemp,
            STAGING_DIGEST: digest,
            STAGING_IMAGE: `ghcr.io/collinbentley1/platform-cdbentley-${stagingKind}-staging-123-1:run-123-1`,
          },
          stdout: "ignore",
          stderr: "pipe",
        });
        const exitCode = await child.exited;
        const stderr = await new Response(child.stderr).text();
        const deletes = (await Bun.file(capturePath).exists())
          ? (await Bun.file(capturePath).text()).trim().split("\n").filter(Boolean)
          : [];
        if (fixture.expectedId === null) {
          expect(exitCode).not.toBe(0);
          expect(deletes).toEqual([]);
        } else {
          const apiRoot = fixture.failUser ? "/users/collinbentley1" : "/user";
          expect({ exitCode, stderr }).toEqual({ exitCode: 0, stderr: "" });
          expect(deletes).toEqual([
            `${apiRoot}/packages/container/platform-cdbentley-${stagingKind}-staging-123-1`,
          ]);
        }
      }
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
      expect(workflow).toContain('. + {MAPBOX_PUBLIC_TOKEN: $token}');
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

async function runContract(
  app: string,
  repositoryId = "123456789",
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
