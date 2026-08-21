#!/usr/bin/env bun

import { access, cp, mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { basename, join, resolve } from "node:path";

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
  ".dockerignore",
  "infra/terraform/bootstrap/main.tf",
  "infra/terraform/prod/main.tf",
];
const workflowFiles = [
  "application.yml",
  "socket-firewall.yml",
  "infrastructure.yml",
  "deploy-prod.yml",
  "deploy-preview.yml",
  "cleanup-preview.yml",
  "reconcile-previews.yml",
];
const expectedReusableCalls: Readonly<Record<string, readonly string[]>> = {
  "application.yml": ["application.yml"],
  "socket-firewall.yml": ["socket-firewall.yml"],
  "infrastructure.yml": ["infrastructure.yml"],
  "deploy-prod.yml": ["infrastructure.yml", "deploy-prod.yml"],
  "deploy-preview.yml": ["deploy-preview.yml"],
  "cleanup-preview.yml": ["cleanup-preview.yml"],
  "reconcile-previews.yml": ["reconcile-previews.yml"],
};
const canonicalAppFiles = ["Dockerfile", ".dockerignore", "bunfig.toml"];
const approvedAdditionalWorkflows: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  // Runsetta's credential-free macOS Swift package check is centralized here so
  // a consumer PR cannot add or alter an executable workflow without a platform review.
  "711292980": {
    "apple.yml": "3af8f8085983a15a1703c1f44aba20d30edbfef915c53f2f678e5769d956513d",
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
  let failures = 0;

  if (expectedWorkflowSha !== undefined && !isFullCommitSha(expectedWorkflowSha)) {
    throw new Error("PLATFORM_WORKFLOW_SHA must be a full lowercase commit SHA when provided.");
  }

  for (const repo of repos) {
    const repoPath = resolve(repo);
    const repoName = basename(repoPath);
    const messages: string[] = [];

    for (const file of requiredFiles) {
      if (!(await exists(join(repoPath, file)))) {
        messages.push(`missing ${file}`);
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

    const scanner = "@socketsecurity/bun-security-scanner";
    const expectedScannerLock = [
      `${scanner}@1.1.2`,
      "",
      {},
      "sha512-TdsAg6SMolubyZ6HfIjLWlANfHvhV6i7pdWof4OQ33zPEwXJm2ilA755levHMR618MKq22+06Ag8efiVKowxqA==",
    ];
    const lockText = await readText(join(repoPath, "bun.lock"));
    if (lockText) {
      try {
        const lock = Bun.JSONC.parse(lockText) as { packages?: Record<string, unknown> };
        if (JSON.stringify(lock.packages?.[scanner]) !== JSON.stringify(expectedScannerLock)) {
          messages.push("bun.lock does not resolve the reviewed Socket scanner integrity");
        }
      } catch {
        messages.push("bun.lock is not valid JSONC");
      }
    }

    const bunfigText = await readText(join(repoPath, "bunfig.toml"));
    if (bunfigText) {
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
      const expectedDigest = additionalWorkflows[entry.name];
      if (expectedDigest) {
        const workflowText = await readFile(join(workflowDirectory, entry.name));
        const digest = createHash("sha256").update(workflowText).digest("hex");
        if (digest !== expectedDigest) {
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
    if (bootstrapText) {
      const trustedBlock = bootstrapText.match(
        /^\s*trusted_platform_workflow_shas\s*=\s*\[([^\]]*)\]/m,
      );
      if (!trustedBlock) {
        messages.push("bootstrap main.tf is missing trusted_platform_workflow_shas");
      } else {
        const lines = trustedBlock[1]!
          .split("\n")
          .map((line) => line.trim())
          .filter(Boolean);
        const trustedRefs: string[] = [];
        let invalidLine = false;
        for (const line of lines) {
          const match = line.match(/^"([0-9a-f]{40})",?(?:\s*#.*)?$/);
          if (!match) {
            invalidLine = true;
          } else {
            trustedRefs.push(match[1]!);
          }
        }
        const uniqueTrustedRefs = new Set(trustedRefs);
        if (
          invalidLine ||
          trustedRefs.length !== uniqueTrustedRefs.size ||
          trustedRefs.length < 1 ||
          trustedRefs.length > 2
        ) {
          messages.push(
            "trusted_platform_workflow_shas must contain one or two unique full commit SHAs",
          );
        }
        if (platformRef !== "unknown" && !uniqueTrustedRefs.has(platformRef)) {
          messages.push("trusted_platform_workflow_shas must include the active platform SHA");
        }
        for (const ref of uniqueTrustedRefs) {
          if (forbiddenPreMigrationWorkflowShas.has(ref)) {
            messages.push(`trusted_platform_workflow_shas contains vulnerable pre-migration SHA ${ref}`);
          }
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
  await cp(join(root, "templates/app"), target, { recursive: true });
  await replaceTokens(target, {
    __APP_NAME__: name,
    __PROJECT_ID__: name,
    __STATE_BUCKET__: `${name}-tfstate`,
    __GITHUB_OWNER_ID__: "16823277",
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

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
