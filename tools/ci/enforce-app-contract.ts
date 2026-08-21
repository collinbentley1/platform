import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { join, relative, resolve } from "node:path";

const scanner = "@socketsecurity/bun-security-scanner";
const expectedScannerLock = [
  `${scanner}@1.1.2`,
  "",
  {},
  "sha512-TdsAg6SMolubyZ6HfIjLWlANfHvhV6i7pdWof4OQ33zPEwXJm2ilA755levHMR618MKq22+06Ag8efiVKowxqA==",
];
const canonicalFiles = ["Dockerfile", ".dockerignore", "bunfig.toml"];
const requiredFiles = [...canonicalFiles, "package.json", "bun.lock"];
const ignoredWalkDirectories = new Set([
  ".git",
  ".terraform",
  "coverage",
  "dist",
  "_platform_policy",
]);
const forbiddenSyftConfigs = new Set([
  ".syft",
  ".syft.yaml",
  ".syft.yml",
  ".syft/config.yaml",
  ".syft/config.yml",
]);

const [appArg, templateArg] = Bun.argv.slice(2);
if (!appArg || !templateArg) {
  throw new Error("Usage: enforce-app-contract.ts <application-root> <platform-template-root>");
}

const appRoot = await realpath(resolve(appArg));
const templateRoot = await realpath(resolve(templateArg));

for (const file of requiredFiles) {
  await requireRegularFile(join(appRoot, file), file);
}

for (const file of canonicalFiles) {
  const [actual, expected] = await Promise.all([
    readFile(join(appRoot, file)),
    readFile(join(templateRoot, file)),
  ]);
  if (!actual.equals(expected)) {
    throw new Error(`${file} must exactly match the immutable platform template.`);
  }
}

const packageJson = JSON.parse(await readFile(join(appRoot, "package.json"), "utf8")) as {
  packageManager?: unknown;
  scripts?: Record<string, unknown>;
  devDependencies?: Record<string, unknown>;
};
if (packageJson.packageManager !== "bun@1.4.0") {
  throw new Error("package.json packageManager must be bun@1.4.0.");
}
if (packageJson.devDependencies?.[scanner] !== "1.1.2") {
  throw new Error("package.json must pin the reviewed Socket scanner version.");
}
if (
  typeof packageJson.scripts?.["verify:ci"] !== "string" ||
  packageJson.scripts["verify:ci"].length === 0
) {
  throw new Error("package.json must define a non-empty verify:ci script.");
}

const lock = Bun.JSONC.parse(await readFile(join(appRoot, "bun.lock"), "utf8")) as {
  packages?: Record<string, unknown>;
};
if (JSON.stringify(lock.packages?.[scanner]) !== JSON.stringify(expectedScannerLock)) {
  throw new Error("bun.lock does not resolve the reviewed Socket scanner integrity.");
}

for await (const file of walk(appRoot)) {
  const name = file.split("/").at(-1) ?? "";
  const relativeFile = relative(appRoot, file).replaceAll("\\", "/");
  if (
    name === ".npmrc" ||
    name === "npmrc" ||
    name === ".env" ||
    (name.startsWith(".env.") && name !== ".env.example") ||
    forbiddenSyftConfigs.has(relativeFile)
  ) {
    throw new Error(`Forbidden package-manager environment/config file: ${relative(appRoot, file)}`);
  }
}

console.log("Application dependency and container contract matches the immutable platform source.");

async function requireRegularFile(path: string, label: string): Promise<void> {
  const metadata = await lstat(path).catch(() => undefined);
  if (!metadata?.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} must be a regular, non-symbolic-link file.`);
  }
}

async function* walk(directory: string): AsyncGenerator<string> {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.name === "node_modules") {
      throw new Error(`Committed node_modules content is forbidden: ${relative(appRoot, path)}`);
    }
    if (entry.isSymbolicLink()) {
      const relativePath = relative(appRoot, path).replaceAll("\\", "/");
      if (
        entry.name === ".npmrc" ||
        entry.name === "npmrc" ||
        entry.name === ".env" ||
        (entry.name.startsWith(".env.") && entry.name !== ".env.example") ||
        forbiddenSyftConfigs.has(relativePath)
      ) {
        throw new Error(
          `Forbidden symbolic-link package-manager environment/config file: ${relative(appRoot, path)}`,
        );
      }
      continue;
    }
    if (entry.isDirectory()) {
      if (!ignoredWalkDirectories.has(entry.name)) {
        yield* walk(path);
      }
    } else if (entry.isFile()) {
      yield path;
    }
  }
}
