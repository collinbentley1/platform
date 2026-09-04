#!/usr/bin/env bun

import { access, cp, lstat, mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { basename, join, relative, resolve } from "node:path";
import {
  isForbiddenTerraformArtifact,
  validateAppScripts,
  validateRegistryOnlyDependencySpecs,
  validateRegistryOnlyLock,
  validateTerraformGitignore,
  validateTypeScriptLock,
} from "./ci/app-contract";
import { validateTerraformMirrorContract } from "./ci/terraform-mirror-contract";

type PlatformConfig = {
  readonly name?: string;
  readonly projectId?: string;
  readonly githubRepositoryId?: string;
  readonly region?: string;
  readonly serviceName?: string;
  readonly artifactRegistryRepository?: string;
  readonly runtimeConfigScript?: string;
};

const root = join(import.meta.dir, "..");
const requiredFiles = [
  "Dockerfile",
  "bunfig.toml",
  "bun.lock",
  "package.json",
  ".gitignore",
  ".dockerignore",
  "tsconfig.json",
  "tools/build.ts",
  "tools/format.ts",
  "tools/lint.ts",
  "tools/platform-verify.ts",
  "tools/socket-security-scanner.ts",
  "infra/terraform/bootstrap/main.tf",
  "infra/terraform/bootstrap/outputs.tf",
  "infra/terraform/bootstrap/variables.tf",
  "infra/terraform/bootstrap/versions.tf",
  "infra/terraform/bootstrap/.terraform.lock.hcl",
  "infra/terraform/prod/main.tf",
  "infra/terraform/prod/outputs.tf",
  "infra/terraform/prod/variables.tf",
  "infra/terraform/prod/versions.tf",
  "infra/terraform/prod/.terraform.lock.hcl",
];
const requiredDirectories = [
  "infra",
  "infra/terraform",
  "infra/terraform/bootstrap",
  "infra/terraform/prod",
];
const workflowFiles = [
  "application.yml",
  "bun-dependency-update.yml",
  "socket-firewall.yml",
  "infrastructure.yml",
  "deploy-prod.yml",
  "deploy-preview.yml",
  "cleanup-preview.yml",
  "reconcile-previews.yml",
];
const expectedReusableCalls: Readonly<Record<string, readonly string[]>> = {
  "application.yml": ["application.yml"],
  "bun-dependency-update.yml": ["bun-dependency-update.yml"],
  "socket-firewall.yml": ["socket-firewall.yml"],
  "infrastructure.yml": ["infrastructure.yml"],
  "deploy-prod.yml": ["infrastructure.yml", "deploy-prod.yml"],
  "deploy-preview.yml": ["deploy-preview.yml"],
  "cleanup-preview.yml": ["cleanup-preview.yml"],
  "reconcile-previews.yml": ["reconcile-previews.yml"],
};
const canonicalAppFiles = [
  "Dockerfile",
  ".dockerignore",
  "bunfig.toml",
  "tools/platform-verify.ts",
  "tools/socket-security-scanner.ts",
  "infra/terraform/bootstrap/.terraform.lock.hcl",
  "infra/terraform/prod/.terraform.lock.hcl",
];
const allowedTerraformMirrorFiles = new Set([
  "infra/terraform/bootstrap/.terraform.lock.hcl",
  "infra/terraform/bootstrap/main.tf",
  "infra/terraform/bootstrap/outputs.tf",
  "infra/terraform/bootstrap/variables.tf",
  "infra/terraform/bootstrap/versions.tf",
  "infra/terraform/prod/.terraform.lock.hcl",
  "infra/terraform/prod/main.tf",
  "infra/terraform/prod/outputs.tf",
  "infra/terraform/prod/variables.tf",
  "infra/terraform/prod/versions.tf",
]);
const approvedAdditionalWorkflows: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  // Runsetta's credential-free macOS Swift package check is centralized here so
  // a consumer PR cannot add or alter an executable workflow without a platform review.
  "711292980": {
    "apple.yml": "templates/additional-workflows/runsetta/apple.yml",
  },
};
const forbiddenPreMigrationWorkflowShas = new Set([
  "734d0cd02187f88c6e91263f127dc3f4c0709feb",
  "1378a3e81a5e74c71f2adfd5548b430bb008490e",
  "37bd4b1beea8802ec85c38d69ea08d5992c75a50",
  "42435a3c4c5c063a342765ef7c85047224217fe2",
  "7f01d9f008a7757df12f13ac8fa0f261600cf21a",
  "4f032955477c26b942fdd4f1b01f5272380390ea",
  "92c73184bc527388b5e10ccb5e4f0222a84e68b5",
  "33ab9b9a5f3d8a0553372980c22540cad001f776",
]);

const [command, ...args] = Bun.argv.slice(2);

switch (command) {
  case "doctor":
    await doctor(args);
    break;
  case "scaffold":
    await scaffold(args);
    break;
  case "help":
  case undefined:
    help();
    break;
  default:
    console.error(`Unknown command: ${command}`);
    help();
    process.exit(1);
}

async function doctor(repoArgs: string[]): Promise<void> {
  const repos = repoArgs.length > 0 ? repoArgs : ["."];
  const expectedWorkflowSha = Bun.env.PLATFORM_WORKFLOW_SHA;
  const trustedRepositoryId = Bun.env.TRUSTED_GITHUB_REPOSITORY_ID;
  let failures = 0;

  if (expectedWorkflowSha !== undefined && !isFullCommitSha(expectedWorkflowSha)) {
    throw new Error("PLATFORM_WORKFLOW_SHA must be a full lowercase commit SHA when provided.");
  }
  if (trustedRepositoryId !== undefined && !/^[1-9][0-9]*$/.test(trustedRepositoryId)) {
    throw new Error(
      "TRUSTED_GITHUB_REPOSITORY_ID must be a positive numeric ID when provided.",
    );
  }

  for (const repo of repos) {
    const repoPath = resolve(repo);
    const repoName = basename(repoPath);
    const messages: string[] = [];

    for (const directory of requiredDirectories) {
      const metadata = await lstat(join(repoPath, directory)).catch((error: unknown) => {
        if (isNotFound(error)) return undefined;
        throw error;
      });
      if (!metadata) {
        messages.push(`missing ${directory}`);
      } else if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
        messages.push(`${directory} must be a real, non-symbolic-link directory`);
      }
    }

    for (const file of requiredFiles) {
      const metadata = await lstat(join(repoPath, file)).catch((error: unknown) => {
        if (isNotFound(error)) return undefined;
        throw error;
      });
      if (!metadata) {
        messages.push(`missing ${file}`);
      } else if (!metadata.isFile() || metadata.isSymbolicLink()) {
        messages.push(`${file} must be a regular, non-symbolic-link file`);
      }
    }

    const rootEntries = await readdir(repoPath).catch(() => []);
    for (const name of rootEntries) {
      if (
        name === ".npmrc" ||
        name === "npmrc" ||
        name === ".env" ||
        (name.startsWith(".env.") && name !== ".env.example")
      ) {
        messages.push(`forbidden package-manager environment/config file ${name}`);
      }
      if ([".checkov.yml", ".checkov.yaml", "checkov.yml", "checkov.yaml"].includes(name)) {
        messages.push(`forbidden caller-controlled Checkov configuration ${name}`);
      }
    }

    for (const file of canonicalAppFiles) {
      const [actual, expected] = await Promise.all([
        readText(join(repoPath, file)),
        readText(join(root, "templates/app", file)),
      ]);
      if (actual !== expected) {
        messages.push(`${file} does not exactly match the immutable platform template`);
      }
    }

    const scanner = "./tools/socket-security-scanner.ts";
    const forbiddenPublishedScanner = "@socketsecurity/bun-security-scanner";
    const lockText = await readText(join(repoPath, "bun.lock"));
    if (lockText !== undefined) {
      if (lockText.trim().length === 0) {
        messages.push("bun.lock is not valid JSONC");
      } else {
        try {
          const lock = Bun.JSONC.parse(lockText) as {
            packages?: Record<string, unknown>;
            patchedDependencies?: unknown;
            workspaces?: unknown;
          };
          const reviewedLock = Bun.JSONC.parse(
            (await readText(join(root, "templates/app/bun.lock"))) ?? "{}",
          ) as { packages?: Record<string, unknown> };
          messages.push(...validateRegistryOnlyLock(lock));
          if (Object.hasOwn(lock.packages ?? {}, forbiddenPublishedScanner)) {
            messages.push("bun.lock resolves the quota-exhausting published Socket scanner");
          }
          if (Object.keys(lock.packages ?? {}).length > 128) {
            messages.push("bun.lock exceeds the reviewed 128-package Socket request limit");
          }
          if (Object.hasOwn(lock, "patchedDependencies")) {
            messages.push("bun.lock patchedDependencies are forbidden for trusted CI dependencies");
          }
          messages.push(...validateTypeScriptLock(lock.packages, reviewedLock.packages));
        } catch {
          messages.push("bun.lock is not valid JSONC");
        }
      }
    }

    const bunfigText = await readText(join(repoPath, "bunfig.toml"));
    if (bunfigText !== undefined) {
      try {
        const bunfig = Bun.TOML.parse(bunfigText) as {
          install?: {
            registry?: unknown;
            scopes?: unknown;
            security?: { scanner?: unknown };
          };
        };
        const install = bunfig.install;
        if (
          install?.security?.scanner !== scanner ||
          install.registry !== "https://registry.npmjs.org"
        ) {
          messages.push("bunfig.toml does not use the reviewed scanner and official registry");
        }
        if (
          install?.scopes !== undefined &&
          (typeof install.scopes !== "object" ||
            install.scopes === null ||
            Object.keys(install.scopes).length > 0)
        ) {
          messages.push("bunfig.toml contains a package scope registry override");
        }
      } catch {
        messages.push("bunfig.toml is not valid TOML");
      }
    }

    const config = await readJson<PlatformConfig>(join(repoPath, ".platform/config.json"));
    if (!config) {
      messages.push("missing .platform/config.json");
    } else {
      for (const key of ["projectId", "region", "serviceName"] as const) {
        if (!config[key]) {
          messages.push(`.platform/config.json missing ${key}`);
        }
      }
      if (!config.githubRepositoryId || !/^[1-9][0-9]*$/.test(config.githubRepositoryId)) {
        messages.push(".platform/config.json githubRepositoryId must be a positive numeric ID");
      }
      if (
        trustedRepositoryId !== undefined &&
        config.githubRepositoryId !== trustedRepositoryId
      ) {
        messages.push(
          ".platform/config.json githubRepositoryId must match the immutable GitHub event repository ID",
        );
      }
    }

    if (config?.projectId && (trustedRepositoryId ?? config.githubRepositoryId)) {
      const [
        bootstrapMain,
        bootstrapOutputs,
        bootstrapVariables,
        bootstrapVersions,
        productionMain,
        productionOutputs,
        productionVariables,
        productionVersions,
      ] = await Promise.all([
        readText(join(repoPath, "infra/terraform/bootstrap/main.tf")),
        readText(join(repoPath, "infra/terraform/bootstrap/outputs.tf")),
        readText(join(repoPath, "infra/terraform/bootstrap/variables.tf")),
        readText(join(repoPath, "infra/terraform/bootstrap/versions.tf")),
        readText(join(repoPath, "infra/terraform/prod/main.tf")),
        readText(join(repoPath, "infra/terraform/prod/outputs.tf")),
        readText(join(repoPath, "infra/terraform/prod/variables.tf")),
        readText(join(repoPath, "infra/terraform/prod/versions.tf")),
      ]);
      if (
        bootstrapMain !== undefined &&
        bootstrapOutputs !== undefined &&
        bootstrapVariables !== undefined &&
        bootstrapVersions !== undefined &&
        productionMain !== undefined &&
        productionOutputs !== undefined &&
        productionVariables !== undefined &&
        productionVersions !== undefined
      ) {
        messages.push(
          ...validateTerraformMirrorContract(
            {
              expectedPlatformSha: expectedWorkflowSha,
              githubRepositoryId: trustedRepositoryId ?? config.githubRepositoryId!,
              name: config.name,
              projectId: config.projectId,
              serviceName: config.serviceName,
            },
            {
              bootstrapMain,
              bootstrapOutputs,
              bootstrapVariables,
              bootstrapVersions,
              productionMain,
              productionOutputs,
              productionVariables,
              productionVersions,
            },
          ),
        );
      }
    }

    const packageText = await readText(join(repoPath, "package.json"));
    if (packageText !== undefined) {
      try {
        const packageJson = JSON.parse(packageText) as {
          dependencies?: Record<string, unknown>;
          packageManager?: unknown;
          scripts?: Record<string, unknown>;
          devDependencies?: Record<string, unknown>;
          optionalDependencies?: Record<string, unknown>;
          peerDependencies?: Record<string, unknown>;
          patchedDependencies?: unknown;
          workspaces?: unknown;
        };
        if (packageJson.packageManager !== "bun@1.4.0") {
          messages.push("package.json packageManager must be bun@1.4.0");
        }
        if (packageJson.devDependencies?.typescript !== "7.0.2") {
          messages.push("package.json must pin the reviewed TypeScript version");
        }
        messages.push(...validateRegistryOnlyDependencySpecs(packageJson));
        if (
          [
            packageJson.dependencies,
            packageJson.devDependencies,
            packageJson.optionalDependencies,
            packageJson.peerDependencies,
          ].some((dependencies) => Object.hasOwn(dependencies ?? {}, forbiddenPublishedScanner))
        ) {
          messages.push("package.json uses the quota-exhausting published Socket scanner");
        }
        if (Object.hasOwn(packageJson, "patchedDependencies")) {
          messages.push(
            "package.json patchedDependencies are forbidden for trusted CI dependencies",
          );
        }
        messages.push(
          ...validateAppScripts(packageJson.scripts, config?.githubRepositoryId ?? ""),
        );
      } catch {
        messages.push("package.json is not valid JSON");
      }
    }

    const gitignoreText = await readText(join(repoPath, ".gitignore"));
    if (gitignoreText !== undefined) {
      messages.push(...validateTerraformGitignore(gitignoreText));
    }

    for (const path of await trackedFiles(repoPath)) {
      if (isForbiddenTerraformArtifact(path)) {
        messages.push(`forbidden committed Terraform state/config artifact ${path}`);
      }
      if (isAdditionalTerraformMirrorFile(path)) {
        messages.push(`unreviewed additional Terraform mirror file ${path}`);
      }
    }

    const workflowDirectory = join(repoPath, ".github/workflows");
    const workflowEntries = await readdir(workflowDirectory, { withFileTypes: true }).catch(() => []);
    const additionalWorkflows = approvedAdditionalWorkflows[config?.githubRepositoryId ?? ""] ?? {};
    const approvedWorkflowNames = new Set([...workflowFiles, ...Object.keys(additionalWorkflows)]);
    const presentWorkflowNames = new Set<string>();
    for (const entry of workflowEntries) {
      presentWorkflowNames.add(entry.name);
      if (!entry.isFile() || entry.isSymbolicLink()) {
        messages.push(`.github/workflows/${entry.name} must be a regular reviewed workflow file`);
        continue;
      }
      if (!approvedWorkflowNames.has(entry.name)) {
        messages.push(`unreviewed additional workflow .github/workflows/${entry.name}`);
        continue;
      }
      const expectedTemplate = additionalWorkflows[entry.name];
      if (expectedTemplate) {
        const [workflowText, expectedText] = await Promise.all([
          readFile(join(workflowDirectory, entry.name)),
          readFile(join(root, expectedTemplate)),
        ]);
        if (!workflowText.equals(expectedText)) {
          messages.push(`approved additional workflow .github/workflows/${entry.name} has drifted`);
        }
      }
    }
    for (const workflow of Object.keys(additionalWorkflows)) {
      if (!presentWorkflowNames.has(workflow)) {
        messages.push(`missing approved additional workflow .github/workflows/${workflow}`);
      }
    }

    // The pinned platform version is derived from the workflow and Terraform
    // references that actually consume the platform — the single source of truth —
    // rather than a hand-maintained field that can silently drift.
    const platformRefs = new Set<string>();

    for (const workflow of workflowFiles) {
      const workflowPath = join(repoPath, ".github/workflows", workflow);
      const workflowText = await readText(workflowPath);
      if (!workflowText) {
        messages.push(`missing .github/workflows/${workflow}`);
        continue;
      }

      if (/^\s*secrets:\s*inherit\s*(?:#.*)?$/m.test(workflowText)) {
        messages.push(`.github/workflows/${workflow} uses secrets: inherit`);
      }

      for (const reusable of expectedReusableCalls[workflow] ?? []) {
        const expectedCall = new RegExp(
          `^\\s*uses:\\s*collinbentley1/platform/\\.github/workflows/${escapeRegExp(reusable)}@([^\\s#]+)\\s*(?:#.*)?$`,
          "m",
        );
        const call = workflowText.match(expectedCall);
        if (!call) {
          messages.push(
            `.github/workflows/${workflow} does not call the expected platform ${reusable} reusable workflow`,
          );
          continue;
        }

        const ref = call[1]!;
        if (!isFullCommitSha(ref)) {
          messages.push(`.github/workflows/${workflow} uses non-immutable platform ref ${ref}`);
          continue;
        }
        platformRefs.add(ref);
      }
    }

    const terraformRoots = [
      ["infra/terraform/bootstrap/main.tf", "bootstrap"],
      ["infra/terraform/prod/main.tf", "cloud-run-service"],
    ] as const;

    for (const [terraformRoot, expectedModule] of terraformRoots) {
      const terraformText = await readText(join(repoPath, terraformRoot));
      if (!terraformText) {
        continue;
      }

      const expectedSource = new RegExp(
        `^\\s*source\\s*=\\s*"github\\.com/collinbentley1/platform//terraform/modules/${expectedModule}\\?ref=([^"&]+)"\\s*(?:#.*)?$`,
        "m",
      );
      const source = terraformText.match(expectedSource);
      if (!source) {
        messages.push(`${terraformRoot} does not source the expected platform ${expectedModule} module`);
        continue;
      }

      const ref = source[1]!;
      if (!isFullCommitSha(ref)) {
        messages.push(`${terraformRoot} uses non-immutable platform ref ${ref}`);
        continue;
      }
      platformRefs.add(ref);
    }

    let platformRef = "unknown";
    if (platformRefs.size === 1) {
      platformRef = [...platformRefs][0]!;
    } else if (platformRefs.size > 1) {
      messages.push(
        `platform version drift: workflow and Terraform pins disagree (${[...platformRefs].sort().join(", ")})`,
      );
    }
    if (expectedWorkflowSha && platformRef !== expectedWorkflowSha) {
      messages.push(
        `active reusable workflow SHA ${expectedWorkflowSha} does not match consumer pin ${platformRef}`,
      );
    }

    if (platformRef !== "unknown") {
      for (const workflow of workflowFiles) {
        const [actual, template] = await Promise.all([
          readText(join(repoPath, ".github/workflows", workflow)),
          readText(join(root, "templates/app/.github/workflows", workflow)),
        ]);
        const expected = template?.replaceAll("__PLATFORM_SHA__", platformRef);
        if (actual !== expected) {
          messages.push(
            `.github/workflows/${workflow} must exactly match the rendered platform caller template`,
          );
        }
      }
    }

    const bootstrapText = await readText(join(repoPath, "infra/terraform/bootstrap/main.tf"));
    if (bootstrapText !== undefined) {
      const active = bootstrapText.match(/^\s*active_workflow_sha\s*=\s*"([^"]*)"\s*(?:#.*)?$/m);
      if (!active) {
        messages.push("bootstrap main.tf is missing active_workflow_sha");
      } else {
        const ref = active[1]!;
        if (!isFullCommitSha(ref)) {
          messages.push("active_workflow_sha must be one full commit SHA");
        } else if (platformRef !== "unknown" && ref !== platformRef) {
          messages.push("active_workflow_sha must be the active platform SHA");
        }
        if (forbiddenPreMigrationWorkflowShas.has(ref)) {
          messages.push(`active_workflow_sha contains vulnerable pre-migration SHA ${ref}`);
        }
      }
      for (const transition of bootstrapText.matchAll(/^[ \t]*transition_workflow_sha[ \t]*=[ \t]*(.*)$/gm)) {
        messages.push("transition_workflow_sha must be absent in the consumer steady-state mirror");
        const ref = transition[1]!.match(/^"([0-9a-f]{40})"/)?.[1];
        if (ref !== undefined && forbiddenPreMigrationWorkflowShas.has(ref)) {
          messages.push(`transition_workflow_sha contains vulnerable pre-migration SHA ${ref}`);
        }
      }
    }

    if (messages.length > 0) {
      failures += 1;
      console.error(`\n${repoName}`);
      for (const message of messages) {
        console.error(`- ${message}`);
      }
    } else {
      console.log(`${repoName}: ok (platform ${platformRef.slice(0, 12)})`);
    }
  }

  if (failures > 0) {
    process.exit(1);
  }
}

async function scaffold(args: string[]): Promise<void> {
  const [name, platformSha, githubRepositoryId, targetArg] = args;

  if (
    !name ||
    !platformSha ||
    !/^[0-9a-f]{40}$/.test(platformSha) ||
    !githubRepositoryId ||
    !/^[1-9][0-9]*$/.test(githubRepositoryId)
  ) {
    console.error(
      "Usage: bun run platform scaffold <name> <platform-sha> <github-repository-id> [target-dir]",
    );
    process.exit(1);
  }

  const target = resolve(targetArg ?? name);

  if (await exists(target)) {
    const targetStat = await stat(target);
    if (targetStat.isDirectory()) {
      console.error(`Target already exists: ${target}`);
      process.exit(1);
    }
  }

  await mkdir(target, { recursive: true });
  const templateRoot = join(root, "templates/app");
  await cp(templateRoot, target, {
    recursive: true,
    filter: (source) => {
      const templateRelativePath = relative(templateRoot, source).replaceAll("\\", "/");
      const name = basename(source);
      return (
        templateRelativePath.length === 0 ||
        (!isForbiddenTerraformArtifact(templateRelativePath) &&
          !["node_modules", "coverage", "dist", ".DS_Store"].includes(name))
      );
    },
  });
  await replaceTokens(target, {
    __APP_NAME__: name,
    __PROJECT_ID__: name,
    __STATE_BUCKET__: `${name}-tfstate`,
    __GITHUB_REPOSITORY_ID__: githubRepositoryId,
    __PLATFORM_SHA__: platformSha,
  });
  console.log(`Created ${name} scaffold at ${target}`);
}

function help(): void {
  console.log(`Usage:
  bun run platform doctor [repo...]
  bun run platform scaffold <name> <platform-sha> <github-repository-id> [target-dir]`);
}

async function readText(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, "utf8");
  } catch (error) {
    if (isNotFound(error)) {
      return undefined;
    }
    throw error;
  }
}

async function readJson<T>(path: string): Promise<T | undefined> {
  const text = await readText(path);
  return text ? (JSON.parse(text) as T) : undefined;
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch (error) {
    if (isNotFound(error)) {
      return false;
    }
    throw error;
  }
}

async function replaceTokens(directory: string, replacements: Record<string, string>): Promise<void> {
  for await (const filePath of walk(directory)) {
    const original = await readFile(filePath, "utf8");
    let next = original;

    for (const [token, value] of Object.entries(replacements)) {
      next = next.replaceAll(token, value);
    }

    if (next !== original) {
      await writeFile(filePath, next);
    }
  }
}

async function* walk(directory: string): AsyncGenerator<string> {
  const entries = await readdir(directory, { withFileTypes: true });

  for (const entry of entries) {
    const path = join(directory, entry.name);

    if (entry.isDirectory()) {
      yield* walk(path);
    } else if (entry.isFile()) {
      yield path;
    }
  }
}

function isNotFound(error: unknown): boolean {
  return error instanceof Error && "code" in error && (error as { code?: string }).code === "ENOENT";
}

function isFullCommitSha(value: string): boolean {
  return /^[0-9a-f]{40}$/.test(value);
}

function isAdditionalTerraformMirrorFile(path: string): boolean {
  return isTerraformMirrorPath(path) && !allowedTerraformMirrorFiles.has(path);
}

function isTerraformMirrorPath(path: string): boolean {
  return (
    path === "infra" ||
    path === "infra/terraform" ||
    path === "infra/terraform/bootstrap" ||
    path === "infra/terraform/prod" ||
    path.startsWith("infra/terraform/bootstrap/") ||
    path.startsWith("infra/terraform/prod/")
  );
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function trackedFiles(directory: string): Promise<string[]> {
  const child = Bun.spawn(["git", "-C", directory, "ls-files", "-z"], {
    stdout: "pipe",
    stderr: "ignore",
  });
  const [exitCode, output] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
  ]);
  if (exitCode === 0) {
    return output.split("\0").filter(Boolean);
  }

  const paths: string[] = [];
  for await (const path of walk(directory)) {
    paths.push(path.slice(directory.length + 1).replaceAll("\\", "/"));
  }
  return paths;
}
