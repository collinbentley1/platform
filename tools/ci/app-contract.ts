export const expectedVerifyScript =
  "bun ci --no-env-file --ignore-scripts --registry=https://registry.npmjs.org && bun --no-env-file run verify:ci";

const dependencyGroups = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
] as const;
const exactSemanticVersion =
  /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const npmPackageName = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;
const sha512Integrity = /^sha512-[A-Za-z0-9+/]{86}==$/;

type DependencyManifest = Partial<Record<(typeof dependencyGroups)[number], unknown>> & {
  readonly workspaces?: unknown;
};

type BunTextLock = {
  readonly packages?: unknown;
  readonly workspaces?: unknown;
};

/**
 * Bun 1.4 only submits npm-registry resolutions to its security scanner. Keep
 * every declared dependency on an exact registry version so git, GitHub,
 * tarball, file, link, workspace, tag, range, and npm-alias specs cannot bypass
 * the organization policy.
 */
export function validateRegistryOnlyDependencySpecs(manifest: DependencyManifest): string[] {
  const failures: string[] = [];

  if (Object.hasOwn(manifest, "workspaces")) {
    failures.push("package.json workspaces are forbidden by the registry-only dependency policy");
  }

  for (const group of dependencyGroups) {
    const dependencies = manifest[group];
    if (dependencies === undefined) {
      continue;
    }
    if (!isRecord(dependencies)) {
      failures.push(`package.json ${group} must be an object`);
      continue;
    }
    for (const [name, specifier] of Object.entries(dependencies)) {
      if (!npmPackageName.test(name) || typeof specifier !== "string" || !isRegistrySpecifier(specifier)) {
        failures.push(
          `package.json ${group}.${name} must use an exact npm registry version or npm alias`,
        );
      }
    }
  }

  return failures;
}

/**
 * Treat the frozen text lock as hostile input. A registry package has Bun's
 * four-field shape, an exact name/version resolution, the default registry
 * marker, and sha512 integrity. Other source tags use a different shape and
 * are deliberately rejected before the protected scanner credential exists.
 */
export function validateRegistryOnlyLock(lock: BunTextLock): string[] {
  const failures: string[] = [];
  if (!isRecord(lock.workspaces) || Object.keys(lock.workspaces).length !== 1 || !("" in lock.workspaces)) {
    failures.push("bun.lock must contain only the root workspace");
  }
  if (!isRecord(lock.packages)) {
    return [...failures, "bun.lock packages must be an object"];
  }

  for (const [key, entry] of Object.entries(lock.packages)) {
    if (
      !Array.isArray(entry) ||
      entry.length !== 4 ||
      typeof entry[0] !== "string" ||
      entry[1] !== "" ||
      !isRecord(entry[2]) ||
      typeof entry[3] !== "string" ||
      !sha512Integrity.test(entry[3])
    ) {
      failures.push(`bun.lock package ${key} must be a sha512-pinned npm registry resolution`);
      continue;
    }

    const separator = entry[0].lastIndexOf("@");
    const name = entry[0].slice(0, separator);
    const version = entry[0].slice(separator + 1);
    if (separator < 1 || !npmPackageName.test(name) || !exactSemanticVersion.test(version)) {
      failures.push(`bun.lock package ${key} must resolve to an exact npm registry package version`);
    }
  }

  return failures;
}

const expectedScripts: Readonly<Record<string, string>> = {
  verify: expectedVerifyScript,
  "verify:ci": "bun run format:check && bun run lint && bun run typecheck && bun run test && bun run build",
  "format:check": "bun run tools/format.ts --check",
  lint: "bun run tools/lint.ts",
  typecheck: "tsc --noEmit",
  test: "bun test",
  build: "bun run tools/build.ts",
};

export function validateTypeScriptLock(
  packages: Record<string, unknown> | undefined,
  reviewedPackages: Record<string, unknown> | undefined,
): string[] {
  const isTypeScriptPackage = (name: string): boolean =>
    name === "typescript" || name.startsWith("@typescript/typescript-");
  const actualNames = Object.keys(packages ?? {}).filter(isTypeScriptPackage).sort();
  const reviewedNames = Object.keys(reviewedPackages ?? {}).filter(isTypeScriptPackage).sort();

  if (JSON.stringify(actualNames) !== JSON.stringify(reviewedNames)) {
    return ["bun.lock TypeScript wrapper/native package set does not match the reviewed lockfile"];
  }

  const failures: string[] = [];
  for (const name of reviewedNames) {
    if (JSON.stringify(packages?.[name]) !== JSON.stringify(reviewedPackages?.[name])) {
      failures.push(`bun.lock does not resolve the reviewed TypeScript integrity for ${name}`);
    }
  }
  return failures;
}

export const requiredTerraformIgnorePatterns = [
  "**/.terraform/",
  "*.tfstate",
  "*.tfstate.*",
  "*.tfplan",
  "*.tfplan.*",
  "*.plan",
  "*.plan.*",
  "*.tflock",
  "*.tflock.*",
  "*.tfvars",
  "*.tfvars.*",
  "*.tfvars.json",
  "*.auto.tfvars",
  "*.auto.tfvars.json",
  ".terraformrc",
  "terraform.rc",
  "crash.log",
  "crash.*.log",
  "override.tf",
  "override.tf.json",
  "*_override.tf",
  "*_override.tf.json",
  ".terraform.lock.hcl.tmp",
] as const;

export const terraformGitignoreSafetyBlock = [
  "# BEGIN platform-managed Terraform safety rules",
  ...requiredTerraformIgnorePatterns,
  "# END platform-managed Terraform safety rules",
].join("\n");

export function validateAppScripts(
  scripts: Record<string, unknown> | undefined,
  repositoryId: string,
): string[] {
  const failures: string[] = [];

  if (!/^[1-9][0-9]*$/.test(repositoryId)) {
    failures.push("the trusted repository ID must be a positive decimal identifier");
  }

  for (const [name, command] of Object.entries(expectedScripts)) {
    if (scripts?.[name] !== command) {
      failures.push(`package.json script ${name} must exactly match the immutable platform command`);
    }
    for (const hook of [`pre${name}`, `post${name}`]) {
      if (scripts?.[hook] !== undefined) {
        failures.push(`package.json must not define the implicit ${hook} hook`);
      }
    }
  }

  return failures;
}

export function validateTerraformGitignore(text: string): string[] {
  const normalized = text.replaceAll("\r\n", "\n").trimEnd();
  const entries = new Set(
    normalized
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith("#")),
  );
  const failures = requiredTerraformIgnorePatterns
    .filter((pattern) => !entries.has(pattern))
    .map((pattern) => `.gitignore must include ${pattern}`);
  if (!normalized.endsWith(terraformGitignoreSafetyBlock)) {
    failures.push(
      ".gitignore must end with the exact platform-managed Terraform safety block so later negations cannot override it",
    );
  }
  return failures;
}

export function isForbiddenTerraformArtifact(relativePath: string): boolean {
  const normalized = relativePath.replaceAll("\\", "/");
  const parts = normalized.split("/");
  const name = parts.at(-1) ?? "";

  return (
    parts.includes(".terraform") ||
    name === ".terraformrc" ||
    name === "terraform.rc" ||
    name === ".terraform.lock.hcl.tmp" ||
    name === "crash.log" ||
    /^crash\..+\.log$/.test(name) ||
    /\.tfstate(?:\..+)?$/.test(name) ||
    /\.tfplan(?:\..+)?$/.test(name) ||
    /\.plan(?:\..+)?$/.test(name) ||
    /\.tflock(?:\..+)?$/.test(name) ||
    /\.tfvars(?:\..+)?$/.test(name) ||
    /(?:^|_)override\.tf(?:\.json)?$/.test(name)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isRegistrySpecifier(value: string): boolean {
  if (exactSemanticVersion.test(value)) {
    return true;
  }
  if (!value.startsWith("npm:")) {
    return false;
  }
  const resolution = value.slice("npm:".length);
  const separator = resolution.lastIndexOf("@");
  return (
    separator > 0 &&
    npmPackageName.test(resolution.slice(0, separator)) &&
    exactSemanticVersion.test(resolution.slice(separator + 1))
  );
}
