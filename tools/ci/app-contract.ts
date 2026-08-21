export const expectedVerifyScript =
  "bun ci --no-env-file --ignore-scripts --registry=https://registry.npmjs.org && bun --no-env-file run verify:ci";

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
