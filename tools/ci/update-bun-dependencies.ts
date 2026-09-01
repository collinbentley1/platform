import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  validateRegistryOnlyDependencySpecs,
  validateRegistryOnlyLock,
} from "./app-contract";

const OFFICIAL_REGISTRY = "https://registry.npmjs.org";
const MINIMUM_RELEASE_AGE_SECONDS = 7 * 24 * 60 * 60;
const DEPENDENCY_GROUPS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
] as const;
// TypeScript is a platform capability, not an independently movable app
// dependency. Its wrapper/native package set and exact integrity are reviewed
// together in the platform template, so routine proposals must leave it alone.
const COORDINATED_DEPENDENCIES = new Set(["typescript"]);

type DependencyGroup = (typeof DEPENDENCY_GROUPS)[number];
type JsonObject = Record<string, unknown>;

export interface BunDependencyUpdateResult {
  readonly changed: boolean;
  readonly dependencies: readonly {
    readonly from: string;
    readonly group: DependencyGroup;
    readonly name: string;
    readonly to: string;
  }[];
}

function fail(message: string): never {
  throw new Error(`update-bun-dependencies: ${message}`);
}

function isRecord(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).toSorted().map((key) =>
      `${JSON.stringify(key)}:${canonical(value[key])}`
    ).join(",")}}`;
  }
  return JSON.stringify(value);
}

function dependencyMap(manifest: JsonObject, group: DependencyGroup): JsonObject {
  const value = manifest[group];
  if (value === undefined) return {};
  if (!isRecord(value)) fail(`package.json ${group} is not an object.`);
  return value;
}

function parseManifest(text: string, label: string): JsonObject {
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    fail(`${label} package.json is not valid JSON.`);
  }
  if (!isRecord(value)) fail(`${label} package.json is not an object.`);
  const failures = validateRegistryOnlyDependencySpecs(value);
  if (failures.length > 0) fail(`${label} ${failures.join("; ")}.`);
  return value;
}

function parseLock(text: string, label: string): JsonObject {
  let value: unknown;
  try {
    value = Bun.JSONC.parse(text) as unknown;
  } catch {
    fail(`${label} bun.lock is not valid JSONC.`);
  }
  if (!isRecord(value)) fail(`${label} bun.lock is not an object.`);
  if (value.lockfileVersion !== 2 || value.configVersion !== 1) {
    fail(`${label} bun.lock is not the reviewed Bun text-lock v2 format.`);
  }
  const failures = validateRegistryOnlyLock(value);
  if (failures.length > 0) fail(`${label} ${failures.join("; ")}.`);
  return value;
}

function dependencyNames(manifest: JsonObject): string[] {
  const names = new Set<string>();
  for (const group of DEPENDENCY_GROUPS) {
    for (const name of Object.keys(dependencyMap(manifest, group))) {
      if (!COORDINATED_DEPENDENCIES.has(name)) names.add(name);
    }
  }
  return [...names].toSorted();
}

function parsedDependencySpecifier(name: string, specifier: string): {
  readonly alias: boolean;
  readonly packageName: string;
  readonly version: string;
} {
  if (!specifier.startsWith("npm:")) {
    return { alias: false, packageName: name, version: specifier };
  }
  const resolution = specifier.slice("npm:".length);
  const separator = resolution.lastIndexOf("@");
  if (separator < 1) fail(`package.json dependency ${name} has a malformed npm alias.`);
  return {
    alias: true,
    packageName: resolution.slice(0, separator),
    version: resolution.slice(separator + 1),
  };
}

function manifestWithoutDependencyValues(manifest: JsonObject): JsonObject {
  return Object.fromEntries(
    Object.entries(manifest).map(([key, value]) =>
      DEPENDENCY_GROUPS.includes(key as DependencyGroup) ? [key, "[DEPENDENCIES]"] : [key, value]
    ),
  );
}

function rootWorkspace(lock: JsonObject, label: string): JsonObject {
  if (!isRecord(lock.workspaces) || !isRecord(lock.workspaces[""])) {
    fail(`${label} bun.lock does not contain one object-valued root workspace.`);
  }
  return lock.workspaces[""];
}

function assertManifestLockAgreement(manifest: JsonObject, lock: JsonObject, label: string): void {
  const workspace = rootWorkspace(lock, label);
  for (const group of DEPENDENCY_GROUPS) {
    const manifestDependencies = dependencyMap(manifest, group);
    const lockDependencies = workspace[group] === undefined ? {} : workspace[group];
    if (!isRecord(lockDependencies) || canonical(lockDependencies) !== canonical(manifestDependencies)) {
      fail(`${label} ${group} disagree between package.json and bun.lock.`);
    }
  }
}

function coordinatedLockEntries(lock: JsonObject): JsonObject {
  if (!isRecord(lock.packages)) fail("bun.lock packages are malformed.");
  return Object.fromEntries(
    Object.entries(lock.packages).filter(([name]) =>
      name === "typescript" || name.startsWith("@typescript/typescript-")
    ),
  );
}

export function validateBunDependencyUpdate(
  beforeManifestText: string,
  beforeLockText: string,
  afterManifestText: string,
  afterLockText: string,
): BunDependencyUpdateResult {
  const beforeManifest = parseManifest(beforeManifestText, "original");
  const afterManifest = parseManifest(afterManifestText, "updated");
  const beforeLock = parseLock(beforeLockText, "original");
  const afterLock = parseLock(afterLockText, "updated");

  const manifestChanged = beforeManifestText !== afterManifestText;
  const lockChanged = beforeLockText !== afterLockText;
  if (manifestChanged !== lockChanged) {
    fail("package.json and bun.lock must move together in one proposal.");
  }
  assertManifestLockAgreement(beforeManifest, beforeLock, "original");
  assertManifestLockAgreement(afterManifest, afterLock, "updated");
  if (!manifestChanged) return { changed: false, dependencies: [] };

  if (
    canonical(manifestWithoutDependencyValues(beforeManifest)) !==
      canonical(manifestWithoutDependencyValues(afterManifest))
  ) {
    fail("the updater changed package.json outside direct dependency versions.");
  }

  const changes: BunDependencyUpdateResult["dependencies"][number][] = [];
  for (const group of DEPENDENCY_GROUPS) {
    const before = dependencyMap(beforeManifest, group);
    const after = dependencyMap(afterManifest, group);
    if (canonical(Object.keys(before).toSorted()) !== canonical(Object.keys(after).toSorted())) {
      fail(`the updater added or removed a package.json ${group} entry.`);
    }
    for (const name of Object.keys(before).toSorted()) {
      const from = before[name];
      const to = after[name];
      if (typeof from !== "string" || typeof to !== "string") {
        fail(`package.json ${group}.${name} is not a string.`);
      }
      if (COORDINATED_DEPENDENCIES.has(name) && from !== to) {
        fail(`the updater changed coordinated dependency ${name}.`);
      }
      if (from !== to) {
        const beforeSpecifier = parsedDependencySpecifier(name, from);
        const afterSpecifier = parsedDependencySpecifier(name, to);
        if (
          beforeSpecifier.alias !== afterSpecifier.alias ||
          beforeSpecifier.packageName !== afterSpecifier.packageName
        ) {
          fail(`the updater retargeted dependency ${name}.`);
        }
        if (Bun.semver.order(beforeSpecifier.version, afterSpecifier.version) >= 0) {
          fail(`the updater did not strictly upgrade dependency ${name}.`);
        }
        changes.push({ from, group, name, to });
      }
    }
  }
  if (changes.length === 0) {
    fail("bun.lock moved without a direct dependency version changing.");
  }
  if (
    canonical(coordinatedLockEntries(beforeLock)) !== canonical(coordinatedLockEntries(afterLock))
  ) {
    fail("the updater changed the coordinated TypeScript lock entries.");
  }

  return { changed: true, dependencies: changes };
}

async function requireRegularFile(path: string, label: string): Promise<void> {
  const metadata = await lstat(path).catch(() => undefined);
  if (!metadata?.isFile() || metadata.isSymbolicLink()) {
    fail(`${label} must be a regular, non-symbolic-link file.`);
  }
}

async function requireRegularDirectory(path: string, label: string): Promise<void> {
  const metadata = await lstat(path).catch(() => undefined);
  if (!metadata?.isDirectory() || metadata.isSymbolicLink()) {
    fail(`${label} must be a real, non-symbolic-link directory.`);
  }
}

async function runBun(root: string, action: string, args: readonly string[]): Promise<void> {
  const child = Bun.spawn([process.execPath, "--no-env-file", "--no-orphans", ...args], {
    cwd: root,
    env: { ...process.env, NO_COLOR: "1" },
    stderr: "ignore",
    stdout: "ignore",
  });
  const exitCode = await child.exited;
  if (exitCode !== 0) fail(`Bun exited ${exitCode} while ${action}.`);
}

export async function updateBunDependencies(
  rootPath: string,
): Promise<BunDependencyUpdateResult> {
  const root = await realpath(resolve(rootPath));
  const packagePath = join(root, "package.json");
  const lockPath = join(root, "bun.lock");
  await Promise.all([
    requireRegularFile(packagePath, "package.json"),
    requireRegularFile(lockPath, "bun.lock"),
  ]);
  const [beforeManifestText, beforeLockText] = await Promise.all([
    readFile(packagePath, "utf8"),
    readFile(lockPath, "utf8"),
  ]);
  const beforeManifest = parseManifest(beforeManifestText, "original");
  const beforeLock = parseLock(beforeLockText, "original");
  assertManifestLockAgreement(beforeManifest, beforeLock, "original");
  const names = dependencyNames(beforeManifest);
  if (names.length === 0) return { changed: false, dependencies: [] };

  await runBun(root, "resolving dependency updates", [
    "update",
    "--latest",
    "--lockfile-only",
    "--ignore-scripts",
    "--no-cache",
    "--no-progress",
    `--minimum-release-age=${MINIMUM_RELEASE_AGE_SECONDS}`,
    `--registry=${OFFICIAL_REGISTRY}`,
    ...names,
  ]);
  // Bun 1.4's `update --latest` can write an exact package.json specifier but
  // retain a caret specifier in the root lock workspace. A second, script-free
  // lock-only install reconciles the workspace metadata to the exact manifest
  // before the hostile-input validator accepts the proposal.
  await runBun(root, "reconciling the exact manifest and text lock", [
    "install",
    "--lockfile-only",
    "--ignore-scripts",
    "--no-cache",
    "--no-progress",
    `--minimum-release-age=${MINIMUM_RELEASE_AGE_SECONDS}`,
    `--registry=${OFFICIAL_REGISTRY}`,
  ]);

  const [afterManifestText, afterLockText] = await Promise.all([
    readFile(packagePath, "utf8"),
    readFile(lockPath, "utf8"),
  ]);
  return validateBunDependencyUpdate(
    beforeManifestText,
    beforeLockText,
    afterManifestText,
    afterLockText,
  );
}

export async function validateBunDependencyProposal(
  baseRootPath: string,
  proposalRootPath: string,
): Promise<BunDependencyUpdateResult> {
  const unresolvedBase = resolve(baseRootPath);
  const unresolvedProposal = resolve(proposalRootPath);
  await Promise.all([
    requireRegularDirectory(unresolvedBase, "base root"),
    requireRegularDirectory(unresolvedProposal, "proposal root"),
  ]);
  const [baseRoot, proposalRoot] = await Promise.all([
    realpath(unresolvedBase),
    realpath(unresolvedProposal),
  ]);
  if (baseRoot === proposalRoot) fail("base and proposal roots must be distinct.");
  const entries = (await readdir(proposalRoot)).toSorted();
  if (canonical(entries) !== canonical(["bun.lock", "package.json"])) {
    fail("proposal artifact must contain exactly package.json and bun.lock.");
  }
  const basePackagePath = join(baseRoot, "package.json");
  const baseLockPath = join(baseRoot, "bun.lock");
  const proposalPackagePath = join(proposalRoot, "package.json");
  const proposalLockPath = join(proposalRoot, "bun.lock");
  await Promise.all([
    requireRegularFile(basePackagePath, "base package.json"),
    requireRegularFile(baseLockPath, "base bun.lock"),
    requireRegularFile(proposalPackagePath, "proposal package.json"),
    requireRegularFile(proposalLockPath, "proposal bun.lock"),
  ]);
  const [baseManifest, baseLock, proposalManifest, proposalLock] = await Promise.all([
    readFile(basePackagePath, "utf8"),
    readFile(baseLockPath, "utf8"),
    readFile(proposalPackagePath, "utf8"),
    readFile(proposalLockPath, "utf8"),
  ]);
  const result = validateBunDependencyUpdate(
    baseManifest,
    baseLock,
    proposalManifest,
    proposalLock,
  );
  if (!result.changed) fail("proposal artifact does not contain a dependency update.");
  return result;
}

function printResult(result: BunDependencyUpdateResult): void {
  if (!result.changed) {
    console.log("Bun dependencies are already current.");
    return;
  }
  console.log(`Updated ${result.dependencies.length} direct Bun dependencies:`);
  for (const change of result.dependencies) {
    console.log(`  ${change.group}.${change.name}: ${change.from} -> ${change.to}`);
  }
}

if (import.meta.main) {
  const args = Bun.argv.slice(2);
  if (args.length === 1 && args[0] !== "--validate-proposal") {
    printResult(await updateBunDependencies(args[0]!));
  } else if (args.length === 3 && args[0] === "--validate-proposal") {
    printResult(await validateBunDependencyProposal(args[1]!, args[2]!));
  } else {
    fail(
      "usage: update-bun-dependencies.ts <repository-root> | " +
        "--validate-proposal <base-root> <proposal-root>",
    );
  }
}
