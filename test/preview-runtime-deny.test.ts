import { describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const policyPath = join(root, "terraform/modules/bootstrap/preview-runtime-deny.tf");

const expectedPrincipals = [
  "principal://iam.googleapis.com/projects/-/serviceAccounts/cloud-run-preview@cdbentley.iam.gserviceaccount.com",
  "principal://iam.googleapis.com/projects/-/serviceAccounts/cloud-run-preview@critical-history-16823277.iam.gserviceaccount.com",
  "principal://iam.googleapis.com/projects/-/serviceAccounts/cloud-run-preview@medlock-1025243085.iam.gserviceaccount.com",
  "principal://iam.googleapis.com/projects/-/serviceAccounts/cloud-run-preview@runsetta.iam.gserviceaccount.com",
];

describe("preview runtime preventive deny boundary", () => {
  test("has one project-local PREVENT policy with four exact principals", async () => {
    const source = await readFile(policyPath, "utf8");
    expect(source.match(/resource\s+"google_iam_deny_policy"/g)?.length).toBe(1);
    expect(source).toContain('parent          = urlencode("cloudresourcemanager.googleapis.com/projects/${var.project_id}")');
    expect(source).toContain('name            = "preview-runtime-supported-deny"');
    expect(source).toContain('display_name    = "Preview runtime supported-permission deny"');
    expect(source).toContain('deletion_policy = "PREVENT"');
    expect(source).not.toMatch(/exception_(principals|permissions)|denial_condition/);
    expect(extractList(source, "preview_runtime_denied_principals")).toEqual(expectedPrincipals);
  });

  test("uses the exact reviewed supported-permission allowlist", async () => {
    const source = await readFile(policyPath, "utf8");
    const permissions = extractList(source, "preview_runtime_denied_permissions");
    expect(permissions.length).toBe(214);
    expect(new Bun.CryptoHasher("sha256").update(permissions.join("\n")).digest("hex")).toBe(
      "29a577ff5f02ee74c379d556abb74ca25e14778e1f48686cb9dc14a23470d4f9",
    );
    expect(new Set(permissions).size).toBe(permissions.length);
    expect(permissions).toContain("secretmanager.googleapis.com/*.*");
    expect(permissions).toContain("cloudasset.googleapis.com/*.*");
    expect(permissions).toContain("cloudresourcemanager.googleapis.com/projects.*");
    expect(permissions).toContain("certificatemanager.googleapis.com/*.*");
    expect(permissions).toContain("storage.googleapis.com/intelligenceConfigs.*");
    expect(permissions).toContain("artifactregistry.googleapis.com/versions.update");
    expect(permissions).toContain("iam.googleapis.com/serviceAccounts.disable");
    expect(permissions).toContain("iam.googleapis.com/roles.createTagBinding");
    expect(permissions).toContain("iam.googleapis.com/workloadIdentityPools.*");
    expect(permissions).toContain("iam.googleapis.com/workloadIdentityPoolProviders.*");
    expect(permissions).toContain("iam.googleapis.com/principalaccessboundarypolicies.*");
    expect(permissions).toContain("serviceusage.googleapis.com/effectivemcppolicy.*");
    expect(permissions).toContain("logging.googleapis.com/logServiceIndexes.*");
    expect(permissions).toContain("compute.googleapis.com/backendServices.setIamPolicy");
    expect(permissions).toContain("compute.googleapis.com/globalAddresses.*");
    expect(permissions).toContain("compute.googleapis.com/projects.*");
    expect(permissions).toContain("compute.googleapis.com/globalOperations.setIamPolicy");
    expect(permissions).toContain("compute.googleapis.com/regionOperations.setIamPolicy");
    expect(permissions).not.toContain("storage.googleapis.com/*.*");
    expect(permissions).not.toContain("artifactregistry.googleapis.com/*.*");
    expect(permissions).not.toContain("compute.googleapis.com/*.*");
    expect(source).not.toContain("google-beta");
    for (const permission of permissions) {
      expect(permission).toMatch(/^[a-z0-9-]+\.googleapis\.com\/[A-Za-z0-9*]+\.[A-Za-z0-9*]+$/);
    }
  });

  test("is terraform-formatted and validates with the pinned stable provider when cached", async () => {
    const terraform = Bun.which("terraform");
    if (!terraform) return;

    const format = Bun.spawnSync([terraform, "fmt", "-check", policyPath], { cwd: root });
    expect(format.exitCode, format.stderr.toString()).toBe(0);

    const deployment = join(root, "terraform/deployments/bootstrap");
    const lockfile = join(deployment, ".terraform.lock.hcl");
    if (!(await Bun.file(lockfile).exists())) return;

    const fixture = await mkdtemp(join(tmpdir(), "preview-runtime-deny-"));
    try {
      const moduleDir = dirname(policyPath);
      await Bun.$`cp -R ${moduleDir} ${join(fixture, basename(moduleDir))}`.quiet();
      const init = Bun.spawnSync([terraform, "init", "-backend=false", "-lockfile=readonly"], {
        cwd: join(fixture, basename(moduleDir)),
        env: { ...process.env, TF_PLUGIN_CACHE_DIR: join(root, ".terraform.d/plugin-cache") },
      });
      if (init.exitCode !== 0 && /network|registry\.terraform\.io|Failed to query available provider/.test(init.stderr.toString())) return;
      expect(init.exitCode, init.stderr.toString()).toBe(0);
      const validate = Bun.spawnSync([terraform, "validate", "-no-color"], { cwd: join(fixture, basename(moduleDir)) });
      expect(validate.exitCode, validate.stderr.toString()).toBe(0);
    } finally {
      await rm(fixture, { recursive: true, force: true });
    }
  }, 30_000);
});

function extractList(source: string, localName: string): string[] {
  const match = source.match(new RegExp(`${localName}\\s*=\\s*\\[([\\s\\S]*?)\\n\\s*\\]`));
  if (!match) throw new Error(`missing local list ${localName}`);
  return [...match[1].matchAll(/"([^"]+)"/g)].map((item) => item[1]);
}
