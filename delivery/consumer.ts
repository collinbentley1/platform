import { readdir, readFile, writeFile, mkdir, lstat, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";

export const releaseSchema = 1;
export type ReleaseLock = { schemaVersion: number; sha: string; managed: Record<string, string> };
export const digest = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");
const shaPattern = /^[a-f0-9]{40}$/;
export function requireSha(sha: string): string { if (!shaPattern.test(sha)) throw new Error("Expected an immutable platform commit."); return sha; }

export async function runtimeFiles(root: string): Promise<Record<string, string>> {
  const entries = await readdir(join(root, "runtime"), { withFileTypes: true });
  const files: Record<string, string> = {};
  for (const entry of entries) {
    if (!entry.isFile() || !/^[a-z-]+\.(ts|json)$/.test(entry.name)) throw new Error("Invalid runtime package file.");
    files[`.platform/runtime/${entry.name}`] = await readFile(join(root, "runtime", entry.name), "utf8");
  }
  return files;
}

export function caller(workflow: string, sha: string, events: string, name: string, permissions: string): string {
  requireSha(sha);
  return `name: ${name}\n\non:\n${events}\npermissions: {}\n\njobs:\n  run:\n    name: ${name}\n    permissions:\n${permissions}\n    with:\n      platform_sha: ${sha}\n    uses: collinbentley1/platform/.github/workflows/${workflow}@${sha}\n`;
}

export async function managedFiles(root: string, sha: string): Promise<Record<string, string>> {
  requireSha(sha);
  const files = await runtimeFiles(root);
  files["Dockerfile"] = await readFile(join(root, "delivery/Dockerfile"), "utf8");
  files[".dockerignore"] = ".git\n.github\n.env\n.env.*\n.npmrc\nnpmrc\n.local\n.data\nnode_modules\ndist\ncoverage\n**/.terraform\n**/*.tfstate*\n**/*.tfplan*\n**/*.pem\n**/*.key\n";
  files["bunfig.toml"] = 'env = false\ntelemetry = false\n\n[install]\nexact = true\nminimumReleaseAge = 604800\nregistry = "https://registry.npmjs.org"\n';
  files[".github/workflows/application.yml"] = caller("application-v1.yml", sha, "  push:\n    branches: [main]\n  pull_request:\n  workflow_dispatch:\n    inputs:\n      pull_request:\n        required: false\n        type: string\n", "Bun verify", "      contents: read\n      pull-requests: read\n      checks: write").replace(/      platform_sha:/, "      pull_request: ${{ inputs.pull_request || '' }}\n      platform_sha:");
  /* Central installation-token upgrader owns release proposals. */
  files[".github/workflows/review-gate.yml"] = caller("review-gate-v1.yml", sha, "  pull_request_target:\n    types: [opened, synchronize, reopened, ready_for_review]\n  issue_comment:\n    types: [created, edited]\n  pull_request_review:\n    types: [submitted]\n", "Automated review", "      contents: read\n      pull-requests: read\n      checks: write");
  files[".github/dependabot.yml"] = 'version: 2\nupdates:\n  - package-ecosystem: bun\n    directory: /\n    schedule:\n      interval: weekly\n    cooldown:\n      default-days: 7\n    groups:\n      dependencies:\n        patterns: ["*"]\n  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n    ignore:\n      - dependency-name: "collinbentley1/platform"\n';
  files["tools/verify-socket-config.ts"] = 'const config = Bun.TOML.parse(await Bun.file("bunfig.toml").text()) as { install?: { registry?: string; minimumReleaseAge?: number; security?: unknown } };\nif (config.install?.registry !== "https://registry.npmjs.org" || config.install.minimumReleaseAge !== 604800 || config.install.security) throw new Error("Dependency policy differs from the managed platform contract.");\nexport {};\n';
  return files;
}

const retiredWorkflows = ["application.yml", "platform-upgrade.yml", "bun-dependency-update.yml", "cleanup-preview.yml", "deploy-preview.yml", "deploy-prod.yml", "infrastructure.yml", "reconcile-previews.yml", "socket-firewall.yml"];

function parseRelease(text: string): ReleaseLock {
  if (text.length > 64_000) throw new Error("Release lock is too large.");
  const value = JSON.parse(text) as ReleaseLock;
  if (value.schemaVersion !== releaseSchema || !shaPattern.test(value.sha) || !value.managed || typeof value.managed !== "object" || Array.isArray(value.managed)) throw new Error("Invalid release lock.");
  for (const [path, hash] of Object.entries(value.managed)) {
    if (!/^\.(?:platform\/runtime|github\/workflows)\/[a-z-]+\.(?:ts|json|yml)$/.test(path) && !["Dockerfile", ".dockerignore", "bunfig.toml", ".github/dependabot.yml", "tools/verify-socket-config.ts"].includes(path)) throw new Error("Release lock contains an unmanaged path.");
    if (!/^[a-f0-9]{64}$/.test(hash)) throw new Error("Invalid managed file hash.");
  }
  return value;
}

async function regularText(root: string, path: string): Promise<string | undefined> {
  // Refuse symbolic-link parents, not just symbolic-link leaf files.
  let cursor = root;
  for (const part of path.split("/")) {
    cursor = join(cursor, part);
    const metadata = await lstat(cursor).catch(error => { if (error.code === "ENOENT") return undefined; throw error; });
    if (metadata?.isSymbolicLink()) throw new Error(`Managed path is a symbolic link: ${path}`);
  }
  return readFile(join(root, path), "utf8").catch(error => { if (error.code === "ENOENT") return undefined; throw error; });
}

export async function upgrade(root: string, source: string, sha: string, options: { adopt?: boolean; check?: boolean } = {}): Promise<string[]> {
  const desired = await managedFiles(source, sha);
  const currentText = await regularText(root, ".platform/release.json");
  const previous = currentText ? parseRelease(currentText) : undefined;
  if (!previous && !options.adopt) throw new Error("Initial adoption requires --adopt; subsequent upgrades protect managed edits.");
  if (previous) {
    for (const [path, expected] of Object.entries(previous.managed)) {
      const actual = await regularText(root, path);
      if (actual === undefined || digest(actual) !== expected) throw new Error(`Resolve the local managed-file change before upgrading: ${path}`);
    }
  }
  const next: ReleaseLock = { schemaVersion: releaseSchema, sha: requireSha(sha), managed: Object.fromEntries(Object.entries(desired).map(([path, content]) => [path, digest(content)])) };
  desired[".platform/release.json"] = JSON.stringify(next, null, 2) + "\n";
  const changed: string[] = [];
  for (const [path, content] of Object.entries(desired)) {
    if (await regularText(root, path) !== content) changed.push(path);
  }
  const removed = new Set<string>();
  for (const file of retiredWorkflows) {
    const path = `.github/workflows/${file}`;
    if (!Object.hasOwn(desired, path) && await regularText(root, path) !== undefined) { changed.push(path); removed.add(path); }
  }
  for (const path of Object.keys(previous?.managed ?? {})) if (!Object.hasOwn(desired, path) && !removed.has(path)) { changed.push(path); removed.add(path); }
  if (!options.check) {
    for (const path of removed) await unlink(join(root, path));
    for (const path of changed.filter(path => !removed.has(path))) { await mkdir(dirname(join(root, path)), { recursive: true }); await writeFile(join(root, path), desired[path]!); }
  }
  return changed;
}

export async function doctor(root: string, source: string, sha: string): Promise<string[]> {
  const expected = await managedFiles(source, sha); const failures: string[] = [];
  const server = await regularText(root, "src/server.ts");
  if (!server || !/import\s*\{[^}]*\bsecureHandler\b[^}]*\}\s*from\s*["'][^"']*\.platform\/runtime\/http\.ts["']/.test(server) || !/\bsecureHandler\s*\(/.test(server)) failures.push("the application entry point must consume the shared HTTP runtime");
  for (const [path, content] of Object.entries(expected)) if (await regularText(root, path) !== content) failures.push(`managed file differs: ${path}`);
  const lockText = await regularText(root, ".platform/release.json");
  if (!lockText) failures.push("missing release lock");
  else {
    const lock = parseRelease(lockText);
    if (lock.sha !== sha || JSON.stringify(Object.keys(lock.managed).sort()) !== JSON.stringify(Object.keys(expected).sort())) failures.push("release lock differs from the selected release");
    for (const [path, content] of Object.entries(expected)) if (lock.managed[path] !== digest(content)) failures.push(`release hash differs: ${path}`);
  }
  return failures;
}
