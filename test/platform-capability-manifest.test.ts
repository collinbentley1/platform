import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "..");
const manifestPath = join(repoRoot, "platform-capabilities/preview-deployment-parity-v1.json");

const requiredPaths = [
  ".github/workflows/cleanup-preview.yml",
  ".github/workflows/deploy-preview.yml",
  ".github/workflows/deploy-prod.yml",
  ".github/workflows/infrastructure.yml",
  ".github/workflows/reconcile-previews.yml",
  "terraform/modules/bootstrap/main.tf",
  "terraform/modules/bootstrap/preview-runtime-deny.tf",
  "terraform/modules/bootstrap/variables.tf",
  "terraform/modules/cloud-run-service/main.tf",
  "tools/ci/cloud-run-dhi-parity.sh",
  "tools/ci/cloud-run-preview-controller.sh",
  "tools/ci/cloud-run-preview-traffic.sh",
  "tools/ci/cloud-run-prod-dhi-transition.sh",
  "tools/ci/container-artifact-contract.sh",
  "tools/ci/deployment-parity-transition.sh",
  "tools/ci/preview-runtime-iam-contract.sh",
].sort();

describe("preview deployment parity capability manifest", () => {
  test("binds the exact reviewed protocol bytes, DHI tuple, marker schema, and token lifetime", async () => {
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    expect(Object.keys(manifest).sort()).toEqual([
      "capability",
      "dhiParityId",
      "marker",
      "maxMutatorTokenLifetimeSeconds",
      "requiredFiles",
      "schemaVersion",
    ]);
    expect(manifest).toMatchObject({
      capability: "preview-deployment-parity",
      marker: {
        bucketSuffix: "-deployment-parity-state",
        metadataVersion: "1",
        object: "deployment-parity-transition",
      },
      maxMutatorTokenLifetimeSeconds: 300,
      schemaVersion: 1,
    });
    expect(String(manifest.dhiParityId)).toMatch(/^[a-z0-9]{50}$/);
    expect(Object.keys(manifest.requiredFiles).sort()).toEqual(requiredPaths);

    for (const path of requiredPaths) {
      const bytes = await readFile(join(repoRoot, path));
      const digest = createHash("sha256").update(bytes).digest("hex");
      expect(manifest.requiredFiles[path], path).toBe(`sha256:${digest}`);
    }

    const dhi = Bun.spawn(
      ["/bin/bash", join(repoRoot, "tools/ci/container-artifact-contract.sh"), "print-dhi-parity-id"],
      { cwd: repoRoot, stderr: "pipe", stdout: "pipe" },
    );
    const [exitCode, stdout, stderr] = await Promise.all([
      dhi.exited,
      new Response(dhi.stdout).text(),
      new Response(dhi.stderr).text(),
    ]);
    expect(exitCode, stderr).toBe(0);
    expect(stdout.trim()).toBe(manifest.dhiParityId);
  });
});
