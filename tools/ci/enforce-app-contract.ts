import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import {
  isForbiddenTerraformArtifact,
  validateAppScripts,
  validateRegistryOnlyDependencySpecs,
  validateRegistryOnlyLock,
  validateTerraformGitignore,
  validateTypeScriptLock,
} from "./app-contract";
import { validateTerraformMirrorContract } from "./terraform-mirror-contract";

const forbiddenPublishedScanner = "@socketsecurity/bun-security-scanner";
const maximumReviewedPackages = 128;
const canonicalFiles = [
  "Dockerfile",
  ".dockerignore",
  "bunfig.toml",
  "tools/platform-verify.ts",
  "tools/socket-security-scanner.ts",
  "infra/terraform/bootstrap/.terraform.lock.hcl",
  "infra/terraform/prod/.terraform.lock.hcl",
];
const requiredFiles = [
  ...canonicalFiles,
  ".gitignore",
  ".platform/config.json",
  "package.json",
  "bun.lock",
  "tsconfig.json",
  "tools/build.ts",
  "tools/format.ts",
  "tools/lint.ts",
  "infra/terraform/bootstrap/main.tf",
  "infra/terraform/bootstrap/outputs.tf",
  "infra/terraform/bootstrap/variables.tf",
  "infra/terraform/bootstrap/versions.tf",
  "infra/terraform/prod/main.tf",
  "infra/terraform/prod/outputs.tf",
  "infra/terraform/prod/variables.tf",
  "infra/terraform/prod/versions.tf",
];
const ignoredWalkPaths = new Set([".git", "_platform_policy"]);
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
const forbiddenSyftConfigs = new Set([
  ".syft",
  ".syft.yaml",
  ".syft.yml",
  ".syft/config.yaml",
  ".syft/config.yml",
]);

const [appArg, templateArg, trustedRepositoryId, expectedPlatformSha] = Bun.argv.slice(2);
if (
  !appArg ||
  !templateArg ||
  !trustedRepositoryId ||
  !/^[1-9][0-9]*$/.test(trustedRepositoryId) ||
  !expectedPlatformSha ||
  !/^[0-9a-f]{40}$/.test(expectedPlatformSha)
) {
  throw new Error(
    "Usage: enforce-app-contract.ts <application-root> <platform-template-root> <trusted-repository-id> <expected-platform-sha>",
  );
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
  dependencies?: Record<string, unknown>;
  packageManager?: unknown;
  scripts?: Record<string, unknown>;
  devDependencies?: Record<string, unknown>;
  optionalDependencies?: Record<string, unknown>;
  peerDependencies?: Record<string, unknown>;
  patchedDependencies?: unknown;
  workspaces?: unknown;
};
const platformConfig = JSON.parse(
  await readFile(join(appRoot, ".platform/config.json"), "utf8"),
) as { githubRepositoryId?: unknown };
if (platformConfig.githubRepositoryId !== trustedRepositoryId) {
  throw new Error(
    ".platform/config.json githubRepositoryId must match the immutable GitHub event repository ID.",
  );
}
const typedPlatformConfig = platformConfig as {
  githubRepositoryId: string;
  name?: string;
  projectId?: string;
  serviceName?: string;
};
if (!typedPlatformConfig.projectId) {
  throw new Error(".platform/config.json projectId is required by the Terraform mirror contract.");
}
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
  readFile(join(appRoot, "infra/terraform/bootstrap/main.tf"), "utf8"),
  readFile(join(appRoot, "infra/terraform/bootstrap/outputs.tf"), "utf8"),
  readFile(join(appRoot, "infra/terraform/bootstrap/variables.tf"), "utf8"),
  readFile(join(appRoot, "infra/terraform/bootstrap/versions.tf"), "utf8"),
  readFile(join(appRoot, "infra/terraform/prod/main.tf"), "utf8"),
  readFile(join(appRoot, "infra/terraform/prod/outputs.tf"), "utf8"),
  readFile(join(appRoot, "infra/terraform/prod/variables.tf"), "utf8"),
  readFile(join(appRoot, "infra/terraform/prod/versions.tf"), "utf8"),
]);
const terraformMirrorFailures = validateTerraformMirrorContract(
  {
    expectedPlatformSha,
    githubRepositoryId: trustedRepositoryId,
    name: typedPlatformConfig.name,
    projectId: typedPlatformConfig.projectId,
    serviceName: typedPlatformConfig.serviceName,
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
);
if (terraformMirrorFailures.length > 0) {
  throw new Error(terraformMirrorFailures.join("\n"));
}
if (packageJson.packageManager !== "bun@1.4.0") {
  throw new Error("package.json packageManager must be bun@1.4.0.");
}
const registryDependencyFailures = validateRegistryOnlyDependencySpecs(packageJson);
if (registryDependencyFailures.length > 0) {
  throw new Error(registryDependencyFailures.join("\n"));
}
if (
  [
    packageJson.dependencies,
    packageJson.devDependencies,
    packageJson.optionalDependencies,
    packageJson.peerDependencies,
  ].some((dependencies) => Object.hasOwn(dependencies ?? {}, forbiddenPublishedScanner))
) {
  throw new Error("package.json must not use the quota-exhausting published Socket scanner.");
}
if (packageJson.devDependencies?.typescript !== "7.0.2") {
  throw new Error("package.json must pin the reviewed TypeScript version.");
}
if (Object.hasOwn(packageJson, "patchedDependencies")) {
  throw new Error("package.json patchedDependencies are forbidden for trusted CI dependencies.");
}
const scriptFailures = validateAppScripts(packageJson.scripts, trustedRepositoryId);
if (scriptFailures.length > 0) {
  throw new Error(scriptFailures.join("\n"));
}

const gitignoreFailures = validateTerraformGitignore(
  await readFile(join(appRoot, ".gitignore"), "utf8"),
);
if (gitignoreFailures.length > 0) {
  throw new Error(gitignoreFailures.join("\n"));
}

const lock = Bun.JSONC.parse(await readFile(join(appRoot, "bun.lock"), "utf8")) as {
  packages?: Record<string, unknown>;
  patchedDependencies?: unknown;
  workspaces?: unknown;
};
const reviewedLock = Bun.JSONC.parse(
  await readFile(join(templateRoot, "bun.lock"), "utf8"),
) as { packages?: Record<string, unknown> };
const registryLockFailures = validateRegistryOnlyLock(lock);
if (registryLockFailures.length > 0) {
  throw new Error(registryLockFailures.join("\n"));
}
if (Object.hasOwn(lock.packages ?? {}, forbiddenPublishedScanner)) {
  throw new Error("bun.lock must not resolve the quota-exhausting published Socket scanner.");
}
if (Object.keys(lock.packages ?? {}).length > maximumReviewedPackages) {
  throw new Error(
    `bun.lock exceeds the reviewed ${maximumReviewedPackages}-package Socket request limit.`,
  );
}
if (Object.hasOwn(lock, "patchedDependencies")) {
  throw new Error("bun.lock patchedDependencies are forbidden for trusted CI dependencies.");
}
const typeScriptLockFailures = validateTypeScriptLock(lock.packages, reviewedLock.packages);
if (typeScriptLockFailures.length > 0) {
  throw new Error(typeScriptLockFailures.join("\n"));
}

for await (const file of walk(appRoot)) {
  const name = file.split("/").at(-1) ?? "";
  const relativeFile = relative(appRoot, file).replaceAll("\\", "/");
  if (isForbiddenTerraformArtifact(relativeFile)) {
    throw new Error(`Forbidden Terraform state/config artifact: ${relativeFile}`);
  }
  if (isAdditionalTerraformMirrorFile(relativeFile)) {
    throw new Error(`Unreviewed additional Terraform mirror file: ${relativeFile}`);
  }
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
    const relativePath = relative(appRoot, path).replaceAll("\\", "/");
    if (entry.name === "node_modules") {
      throw new Error(`Committed node_modules content is forbidden: ${relative(appRoot, path)}`);
    }
    if (isForbiddenTerraformArtifact(relativePath)) {
      throw new Error(`Forbidden Terraform state/config artifact: ${relativePath}`);
    }
    if (entry.isSymbolicLink()) {
      if (isTerraformMirrorPath(relativePath)) {
        throw new Error(`Terraform mirror entries must not be symbolic links: ${relativePath}`);
      }
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
      if (!ignoredWalkPaths.has(relativePath)) {
        yield* walk(path);
      }
    } else if (entry.isFile()) {
      yield path;
    }
  }
}

function isTerraformMirrorPath(path: string): boolean {
  return path.startsWith("infra/terraform/bootstrap/") || path.startsWith("infra/terraform/prod/");
}

function isAdditionalTerraformMirrorFile(path: string): boolean {
  return isTerraformMirrorPath(path) && !allowedTerraformMirrorFiles.has(path);
}
