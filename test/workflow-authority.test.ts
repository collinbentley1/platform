import { afterEach, describe, expect, test } from "bun:test";
import { cp, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  checkWorkflowAuthority,
  expectedWorkloadIdentityBindings,
  manifestPath,
  parseWorkflowAuthority,
  type WorkflowAuthorityEntry,
} from "../tools/ci/workflow-authority";

const repoRoot = resolve(import.meta.dir, "..");
const temporaryRoots: string[] = [];
const activeSha = "a".repeat(40);
const transitionSha = "b".repeat(40);

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

async function fixtureRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "workflow-authority-"));
  temporaryRoots.push(root);
  await mkdir(join(root, ".github"), { recursive: true });
  await cp(join(repoRoot, ".github/workflows"), join(root, ".github/workflows"), { recursive: true });
  await mkdir(join(root, "terraform/modules/bootstrap"), { recursive: true });
  await cp(join(repoRoot, manifestPath), join(root, manifestPath));
  return root;
}

async function readManifest(root: string): Promise<Array<Record<string, unknown>>> {
  return JSON.parse(await readFile(join(root, manifestPath), "utf8")) as Array<Record<string, unknown>>;
}

async function writeManifest(root: string, manifest: unknown): Promise<void> {
  await writeFile(join(root, manifestPath), `${JSON.stringify(manifest, null, 2)}\n`);
}

async function editWorkflow(root: string, name: string, edit: (text: string) => string): Promise<void> {
  const path = join(root, ".github/workflows", name);
  const original = await readFile(path, "utf8");
  const edited = edit(original);
  expect(edited, `${name} edit must change the file`).not.toBe(original);
  await writeFile(path, edited);
}

async function failuresOf(root: string): Promise<string[]> {
  return [...(await checkWorkflowAuthority(root)).failures];
}

const minimalWorkflow = [
  "name: Rogue",
  "on:",
  "  workflow_call:",
  "permissions: {}",
  "jobs:",
  "  build:",
  "    runs-on: ubuntu-latest",
  "    permissions:",
  "      contents: read",
  "    steps:",
  `      - uses: actions/checkout@${"c".repeat(40)}`,
  "",
].join("\n");

describe("workflow authority manifest", () => {
  test("the live repository declares every workflow and every declaration matches its workflow", async () => {
    const result = await checkWorkflowAuthority(repoRoot);
    expect(result.failures).toEqual([]);
    expect(result.entries.map((entry) => entry.path)).toEqual([
      ".github/workflows/application.yml",
      ".github/workflows/bun-dependency-update.yml",
      ".github/workflows/cleanup-preview.yml",
      ".github/workflows/deploy-preview.yml",
      ".github/workflows/deploy-prod.yml",
      ".github/workflows/infrastructure.yml",
      ".github/workflows/platform.yml",
      ".github/workflows/protected-bootstrap-implementation.yml",
      ".github/workflows/reconcile-previews.yml",
      ".github/workflows/refresh-grype-db.yml",
      ".github/workflows/socket-firewall.yml",
    ]);
    const byAuthority = (authority: string) =>
      result.entries.filter((entry) => entry.authority === authority).map((entry) => entry.path.slice(".github/workflows/".length));
    expect(byAuthority("cloud")).toEqual([
      "cleanup-preview.yml",
      "deploy-preview.yml",
      "deploy-prod.yml",
      "infrastructure.yml",
      "reconcile-previews.yml",
    ]);
    expect(byAuthority("owner-secret")).toEqual(["protected-bootstrap-implementation.yml"]);
    expect(byAuthority("none")).toEqual([
      "application.yml",
      "bun-dependency-update.yml",
      "platform.yml",
      "refresh-grype-db.yml",
      "socket-firewall.yml",
    ]);
    expect(result.entries.filter((entry) => entry.transitionEligible).map((entry) => entry.path)).toEqual([
      ".github/workflows/cleanup-preview.yml",
      ".github/workflows/reconcile-previews.yml",
    ]);
  });

  test("an undeclared workflow on disk fails closed", async () => {
    const root = await fixtureRoot();
    await writeFile(join(root, ".github/workflows/rogue.yml"), minimalWorkflow);
    expect(await failuresOf(root)).toEqual([
      `.github/workflows/rogue.yml: not declared in ${manifestPath}.`,
    ]);
  });

  test("a declared workflow that is absent from disk fails closed", async () => {
    const root = await fixtureRoot();
    await rm(join(root, ".github/workflows/application.yml"));
    expect(await failuresOf(root)).toEqual([
      `.github/workflows/application.yml: declared in ${manifestPath} but is not a regular workflow file on disk.`,
    ]);
  });

  test("a .yaml workflow is enumerated and must be declared under its exact name", async () => {
    const root = await fixtureRoot();
    await rename(join(root, ".github/workflows/application.yml"), join(root, ".github/workflows/application.yaml"));
    expect(await failuresOf(root)).toEqual([
      `.github/workflows/application.yaml: not declared in ${manifestPath}.`,
      `.github/workflows/application.yml: declared in ${manifestPath} but is not a regular workflow file on disk.`,
    ]);
    const manifest = await readManifest(root);
    manifest[0]!.path = ".github/workflows/application.yaml";
    await writeManifest(root, manifest);
    expect(await failuresOf(root)).toEqual([]);
  });

  test("symbolic links and non-workflow entries in the workflow directory fail closed", async () => {
    const root = await fixtureRoot();
    await symlink("application.yml", join(root, ".github/workflows/linked.yml"));
    await writeFile(join(root, ".github/workflows/README.md"), "# not a workflow\n");
    expect(await failuresOf(root)).toEqual([
      ".github/workflows/README.md: only .yml and .yaml workflow files are allowed here.",
      ".github/workflows/linked.yml: must be a regular file, not a symbolic link or directory.",
    ]);
  });

  test("the manifest schema is strict", () => {
    const entry = (overrides: Record<string, unknown>) => ({
      authority: "none",
      environments: [],
      events: ["workflow_call"],
      path: ".github/workflows/application.yml",
      serviceAccounts: [],
      transitionEligible: false,
      ...overrides,
    });
    const failure = (manifest: unknown) => parseWorkflowAuthority(JSON.stringify(manifest)).failures;
    expect(failure([entry({})])).toEqual([]);
    expect(failure("{")).toHaveLength(1);
    expect(failure({})).toEqual([`${manifestPath}: must be a non-empty array of workflow entries.`]);
    expect(failure([])).toEqual([`${manifestPath}: must be a non-empty array of workflow entries.`]);
    expect(failure([entry({ extra: true })])[0]).toContain("keys must be exactly");
    expect(failure([entry({ authority: "cloudy" })])[0]).toContain("authority must be one of");
    expect(failure([entry({ path: "workflows/application.yml" })])[0]).toContain("path must name");
    expect(failure([entry({ path: ".github/workflows/../secrets.yml" })])[0]).toContain("path must name");
    expect(failure([entry({ transitionEligible: "no" })])[0]).toContain("transitionEligible must be a boolean");
    expect(failure([entry({ transitionEligible: true })])[0]).toContain("transitionEligible requires authority cloud");
    expect(failure([entry({ serviceAccounts: ["gha-wif-canary"] })])[0]).toContain("non-empty exactly when authority is cloud");
    expect(failure([entry({ authority: "cloud" })])[0]).toContain("non-empty exactly when authority is cloud");
    expect(failure([entry({ authority: "cloud", serviceAccounts: ["gha-owner"] })])[0]).toContain("known service account IDs");
    expect(failure([entry({ authority: "cloud", serviceAccounts: ["gha-wif-canary", "gha-terraform"] })])[0]).toContain("sorted, unique");
    expect(failure([entry({ authority: "cloud", serviceAccounts: ["gha-terraform", "gha-terraform"] })])[0]).toContain("sorted, unique");
    expect(failure([entry({ environments: "production" })])[0]).toContain("environments must be");
    expect(failure([entry({ events: [] })])[0]).toContain("events must be");
    expect(failure([entry({ events: ["push", 1] })])[0]).toContain("events must be");
    expect(failure([entry({}), entry({})])).toEqual([`${manifestPath}[1]: duplicate path .github/workflows/application.yml.`]);
  });

  test("a job without explicit permissions fails when the workflow declares none", async () => {
    const root = await fixtureRoot();
    await writeFile(
      join(root, ".github/workflows/rogue.yml"),
      minimalWorkflow.replace("permissions: {}\n", "").replace("    permissions:\n      contents: read\n", ""),
    );
    const manifest = await readManifest(root);
    manifest.push({
      authority: "none",
      environments: [],
      events: ["workflow_call"],
      path: ".github/workflows/rogue.yml",
      serviceAccounts: [],
      transitionEligible: false,
    });
    await writeManifest(root, manifest);
    expect(await failuresOf(root)).toEqual([
      ".github/workflows/rogue.yml: job build declares no permissions and the workflow declares none.",
    ]);
  });

  test("id-token: write outside a cloud workflow fails", async () => {
    const root = await fixtureRoot();
    await editWorkflow(root, "refresh-grype-db.yml", (text) =>
      text.replace("      contents: write\n", "      contents: write\n      id-token: write\n"),
    );
    expect(await failuresOf(root)).toEqual([
      ".github/workflows/refresh-grype-db.yml: id-token: write must appear exactly in workflows the manifest marks cloud; this one is none.",
    ]);
  });

  test("a cloud workflow that never requests id-token: write is misclassified", async () => {
    const root = await fixtureRoot();
    await editWorkflow(root, "infrastructure.yml", (text) => text.replaceAll("id-token: write", "id-token: none"));
    expect(await failuresOf(root)).toEqual([
      ".github/workflows/infrastructure.yml: id-token: write must appear exactly in workflows the manifest marks cloud; this one is cloud.",
    ]);
  });

  test("environment drift between the manifest and the workflow fails", async () => {
    const root = await fixtureRoot();
    const manifest = await readManifest(root);
    const infrastructure = manifest.find((entry) => entry.path === ".github/workflows/infrastructure.yml")!;
    infrastructure.environments = ["preview-cloud"];
    await writeManifest(root, manifest);
    expect(await failuresOf(root)).toEqual([
      ".github/workflows/infrastructure.yml: environments [production] do not match the manifest [preview-cloud].",
    ]);
  });

  test("an environment declared as a mapping is read by name", async () => {
    const root = await fixtureRoot();
    await editWorkflow(root, "infrastructure.yml", (text) =>
      text.replace("    environment: production\n", "    environment:\n      name: production\n"),
    );
    expect(await failuresOf(root)).toEqual([]);
  });

  test("trigger drift between the manifest and the workflow fails", async () => {
    const root = await fixtureRoot();
    await editWorkflow(root, "application.yml", (text) => text.replace("on:\n  workflow_call:\n", "on:\n  workflow_call:\n  push:\n    branches:\n      - main\n"));
    expect(await failuresOf(root)).toEqual([
      ".github/workflows/application.yml: triggers [push:main, workflow_call] do not match the manifest events [workflow_call].",
    ]);
  });

  test("a uses reference that is not pinned to a full commit SHA fails", async () => {
    const root = await fixtureRoot();
    await editWorkflow(root, "application.yml", (text) =>
      text.replace(/uses: actions\/checkout@[0-9a-f]{40} # v7\.0\.1/, "uses: actions/checkout@v7"),
    );
    expect(await failuresOf(root)).toEqual([
      '.github/workflows/application.yml: job verify step 2 uses "actions/checkout@v7", which is not pinned to a full 40-hex commit SHA or sha256 image digest.',
    ]);
  });

  test("the owner OAuth secret is referenced only by the owner-secret workflow", async () => {
    const root = await fixtureRoot();
    await editWorkflow(root, "application.yml", (text) =>
      text.replace("    permissions:\n      contents: read\n", "    permissions:\n      contents: read\n    env:\n      OWNER: ${{ secrets.OWNER_OAUTH_ACCESS_TOKEN }}\n"),
    );
    expect(await failuresOf(root)).toEqual([
      ".github/workflows/application.yml: OWNER_OAUTH_ACCESS_TOKEN must be referenced exactly by workflows the manifest marks owner-secret; this one is none.",
    ]);
    await editWorkflow(root, "application.yml", (text) => text.replace("      OWNER: ${{ secrets.OWNER_OAUTH_ACCESS_TOKEN }}\n", "      OWNER: none\n"));
    await editWorkflow(root, "protected-bootstrap-implementation.yml", (text) => text.replaceAll("OWNER_OAUTH_ACCESS_TOKEN", "OWNER_TOKEN"));
    expect(await failuresOf(root)).toEqual([
      ".github/workflows/protected-bootstrap-implementation.yml: OWNER_OAUTH_ACCESS_TOKEN must be referenced exactly by workflows the manifest marks owner-secret; this one is owner-secret.",
    ]);
  });

  test("granting a service account the workflow never names fails", async () => {
    const root = await fixtureRoot();
    const manifest = await readManifest(root);
    const infrastructure = manifest.find((entry) => entry.path === ".github/workflows/infrastructure.yml")!;
    infrastructure.serviceAccounts = ["gha-prod-deploy", "gha-terraform", "gha-wif-canary"];
    await writeManifest(root, manifest);
    expect(await failuresOf(root)).toEqual([
      ".github/workflows/infrastructure.yml: the manifest grants gha-prod-deploy, which the workflow never names.",
    ]);
  });

  test("the expected binding set is the manifest times the active SHA plus transition-eligible paths", async () => {
    const { entries } = await checkWorkflowAuthority(repoRoot);
    const active = expectedWorkloadIdentityBindings(entries, activeSha, null, "123456789012");
    expect(active.size).toBe(20);
    const both = expectedWorkloadIdentityBindings(entries, activeSha, transitionSha, "123456789012");
    expect(both.size).toBe(26);
    const transitionKeys = [...both.keys()].filter((key) => key.endsWith(`@${transitionSha}`)).sort();
    expect(transitionKeys.map((key) => key.split("/").slice(1).join("/").split("@")[0])).toEqual([
      ".github/workflows/cleanup-preview.yml",
      ".github/workflows/reconcile-previews.yml",
      ".github/workflows/cleanup-preview.yml",
      ".github/workflows/reconcile-previews.yml",
      ".github/workflows/cleanup-preview.yml",
      ".github/workflows/reconcile-previews.yml",
    ]);
    expect(both.get(`gha-prod-deploy/.github/workflows/deploy-prod.yml@${activeSha}`)).toEqual({
      account: "gha-prod-deploy",
      member: `principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-actions/attribute.job_workflow_ref/collinbentley1/platform/.github/workflows/deploy-prod.yml@${activeSha}`,
      path: ".github/workflows/deploy-prod.yml",
      sha: activeSha,
    });
    expect(both.has(`gha-prod-deploy/.github/workflows/deploy-prod.yml@${transitionSha}`)).toBe(false);
    expect(() => expectedWorkloadIdentityBindings(entries, "abc", null, "1")).toThrow("not a full lowercase commit SHA");
    expect(() => expectedWorkloadIdentityBindings(entries, activeSha, activeSha, "1")).toThrow("distinct full lowercase commit SHA");
    const none: WorkflowAuthorityEntry[] = entries.filter((entry) => entry.authority !== "cloud");
    expect(expectedWorkloadIdentityBindings(none, activeSha, transitionSha, "1").size).toBe(0);
  });
});
