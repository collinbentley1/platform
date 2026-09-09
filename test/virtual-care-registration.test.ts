import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  renderReviewedTerraformMirrors,
  validateTerraformMirrorContract,
} from "../tools/ci/terraform-mirror-contract";
import { PRODUCTION_APPLY_ENABLED, REPOSITORIES } from "../tools/ci/protected-bootstrap-bridge";
import { reviewedPackageLimitForRepository } from "../tools/ci/app-contract";

const root = resolve(import.meta.dir, "..");
const identity = {
  name: "virtual-care-mcp",
  projectId: "virtual-care-mcp",
  serviceName: "virtual-care-mcp",
  githubRepositoryId: "1362801465",
  expectedPlatformSha: "a".repeat(40),
};

describe("Virtual Care MCP registration", () => {
  test("preserves every existing and unknown repository package budget", () => {
    expect(reviewedPackageLimitForRepository("1362801465")).toBe(135);
    for (const id of ["1255553151", "711292980", "1025243085", "280932482", "999999999", ""]) {
      expect(reviewedPackageLimitForRepository(id)).toBe(128);
    }
  });

  test("renders the reviewed data contract and rejects a redirected project", () => {
    const sources = renderReviewedTerraformMirrors(identity);
    expect(validateTerraformMirrorContract(identity, sources)).toEqual([]);
    expect(sources.bootstrapMain).toMatch(/runtime_project_roles = \[\s*"roles\/datastore\.user",?\s*\]/);
    expect(sources.bootstrapMain).toContain("manage_firestore_field_ttl = true");
    expect(sources.productionMain).toContain('VISIT_STORE = "firestore"');
    expect(sources.productionMain).toContain('location_id = "us-east4"');
    expect(sources.productionMain).toContain('collection = "visits"');
    expect(sources.productionMain).toContain('field = "expiresAt"');
    expect(() => renderReviewedTerraformMirrors({ ...identity, projectId: "cdbentley" })).toThrow(
      "projectId must remain",
    );
    expect(() => renderReviewedTerraformMirrors({ ...identity, githubRepositoryId: "999999999" })).toThrow(
      "not registered",
    );
  });

  test("rejects foreign storage, role expansion, and a mismatched workflow pin", () => {
    const sources = renderReviewedTerraformMirrors(identity);
    for (const changed of [
      { ...sources, productionMain: sources.productionMain.replace('"virtual-care-mcp"', '"foreign-project"') },
      { ...sources, bootstrapMain: sources.bootstrapMain.replace("roles/datastore.user", "roles/owner") },
      { ...sources, bootstrapMain: sources.bootstrapMain.replace(identity.expectedPlatformSha, "b".repeat(40)) },
    ]) {
      expect(validateTerraformMirrorContract(identity, changed).length).toBeGreaterThan(0);
    }
  });

  test("keeps the legacy protected recovery group and production gate unchanged", () => {
    expect(Object.keys(REPOSITORIES).sort()).toEqual([
      "cdbentley", "critical-history", "healthmcp", "runsetta",
    ]);
    expect(PRODUCTION_APPLY_ENABLED).toBe(false);
  });

  test("every deployment resolver binds the new ID and still rejects unknown IDs", async () => {
    let checked = 0;
    for (const file of [
      "deploy-prod.yml", "deploy-preview.yml", "infrastructure.yml",
      "cleanup-preview.yml", "reconcile-previews.yml",
    ]) {
      const text = await readFile(join(root, ".github/workflows", file), "utf8");
      const cases = [...text.matchAll(/case "\$REPOSITORY_ID" in\n[\s\S]*?\n\s*esac/g)]
        .map((match) => match[0])
        .filter((body) => body.includes('project_number="882468538648"'));
      expect(cases.length, file).toBeGreaterThan(0);
      for (const body of cases) {
        const actual = await resolveCase(body, "1362801465");
        expect(actual.exitCode, file).toBe(0);
        expect(actual.stdout.trim(), file).toBe("virtual-care-mcp:894875537243");
        const legacy = await resolveCase(body, "1255553151");
        expect(legacy.exitCode, file).toBe(0);
        expect(legacy.stdout.trim(), file).toBe("cdbentley:882468538648");
        expect((await resolveCase(body, "999999999")).exitCode, file).not.toBe(0);
        checked++;
      }
    }
    expect(checked).toBe(11);
  });
});

async function resolveCase(body: string, repositoryId: string) {
  const child = Bun.spawn([
    "/bin/bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
    `${body}\nprintf '%s:%s\\n' "$project_id" "$project_number"`,
  ], {
    env: { PATH: "/usr/bin:/bin", REPOSITORY_ID: repositoryId },
    stdout: "pipe", stderr: "pipe",
  });
  const [exitCode, stdout] = await Promise.all([child.exited, new Response(child.stdout).text()]);
  await new Response(child.stderr).text();
  return { exitCode, stdout };
}
