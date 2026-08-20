#!/usr/bin/env bun

import { access, cp, mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";

type PlatformConfig = {
  readonly name?: string;
  readonly projectId?: string;
  readonly region?: string;
  readonly serviceName?: string;
  readonly artifactRegistryRepository?: string;
  readonly runtimeConfigScript?: string;
};

const root = join(import.meta.dir, "..");
const requiredFiles = [
  "Dockerfile",
  "bunfig.toml",
  "package.json",
  ".checkov.yml",
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
];

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
  let failures = 0;

  for (const repo of repos) {
    const repoPath = resolve(repo);
    const repoName = basename(repoPath);
    const messages: string[] = [];

    for (const file of requiredFiles) {
      if (!(await exists(join(repoPath, file)))) {
        messages.push(`missing ${file}`);
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

      const call = workflowText.match(
        /collinbentley1\/platform\/\.github\/workflows\/[^@\s]+@(v\d+\.\d+\.\d+)/,
      );
      if (!call) {
        messages.push(`.github/workflows/${workflow} does not call a version-pinned platform reusable workflow`);
        continue;
      }
      platformRefs.add(call[1]!);
    }

    for (const terraformRoot of ["infra/terraform/bootstrap/main.tf", "infra/terraform/prod/main.tf"]) {
      const terraformText = await readText(join(repoPath, terraformRoot));
      if (!terraformText) {
        continue;
      }
      for (const match of terraformText.matchAll(
        /github\.com\/collinbentley1\/platform\/\/[^"?]+\?ref=(v\d+\.\d+\.\d+)/g,
      )) {
        platformRefs.add(match[1]!);
      }
    }

    let platformVersion = "unknown";
    if (platformRefs.size === 1) {
      platformVersion = [...platformRefs][0]!;
    } else if (platformRefs.size > 1) {
      messages.push(
        `platform version drift: workflow and Terraform pins disagree (${[...platformRefs].sort().join(", ")})`,
      );
    }

    if (messages.length > 0) {
      failures += 1;
      console.error(`\n${repoName}`);
      for (const message of messages) {
        console.error(`- ${message}`);
      }
    } else {
      console.log(`${repoName}: ok (platform ${platformVersion})`);
    }
  }

  if (failures > 0) {
    process.exit(1);
  }
}

async function scaffold(args: string[]): Promise<void> {
  const [name, targetArg] = args;

  if (!name) {
    console.error("Usage: bun run platform scaffold <name> [target-dir]");
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
    __GITHUB_REPOSITORY_ID__: "replace-me",
  });
  console.log(`Created ${name} scaffold at ${target}`);
}

function help(): void {
  console.log(`Usage:
  bun run platform doctor [repo...]
  bun run platform scaffold <name> [target-dir]`);
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
