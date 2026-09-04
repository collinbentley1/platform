import { afterEach, describe, expect, test } from "bun:test";
import { cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  authorityDelimiter,
  checkWorkflowAuthority,
  manifestPath,
  parseWorkflowAuthority,
  type WorkflowAuthorityEntry,
} from "../tools/ci/workflow-authority";

const repoRoot = resolve(import.meta.dir, "..");
const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

async function fixtureRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "workflow-authority-"));
  temporaryRoots.push(root);
  for (const directory of [".github/workflows", "templates/app/.github/workflows"]) {
    await mkdir(join(root, directory, ".."), { recursive: true });
    await cp(join(repoRoot, directory), join(root, directory), { recursive: true });
  }
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

async function editEntry(root: string, workflow: string, job: string, edit: (entry: Record<string, unknown>) => void): Promise<void> {
  const manifest = await readManifest(root);
  const entry = manifest.find((candidate) => candidate.workflow === `.github/workflows/${workflow}` && candidate.job === job);
  expect(entry, `${workflow} ${job} must be declared`).toBeDefined();
  edit(entry!);
  await writeManifest(root, manifest);
}

async function editFile(root: string, path: string, edit: (text: string) => string): Promise<void> {
  const original = await readFile(join(root, path), "utf8");
  const edited = edit(original);
  expect(edited, `${path} edit must change the file`).not.toBe(original);
  await writeFile(join(root, path), edited);
}

async function failuresOf(root: string): Promise<string[]> {
  return [...(await checkWorkflowAuthority(root)).failures];
}

const caller = (workflow: string, ...events: string[]) => ({ events, ref: "refs/heads/main", workflow: `.github/workflows/${workflow}` });
const previewCaller = [caller("deploy-preview.yml", "pull_request_target")];
const productionCaller = [caller("deploy-prod.yml", "push")];
const entry = (
  workflow: string,
  job: string,
  environment: string,
  purpose: "attestation" | "gcp",
  callers: ReturnType<typeof caller>[],
  serviceAccounts: string[],
  transitionEligible = false,
): WorkflowAuthorityEntry => ({ callers, environment, job, purpose, serviceAccounts, transitionEligible, workflow: `.github/workflows/${workflow}` });

// The complete job-level inventory. Every id-token job of every platform
// reusable workflow appears exactly once with the accounts it exchanges for.
const expectedEntries: WorkflowAuthorityEntry[] = [
  entry("cleanup-preview.yml", "cleanup", "preview-operations", "gcp", [caller("cleanup-preview.yml", "pull_request_target"), ...previewCaller], ["gha-preview-commit", "gha-preview-operator", "gha-wif-canary"], true),
  entry("deploy-preview.yml", "attest", "supply-chain", "attestation", previewCaller, []),
  entry("deploy-preview.yml", "canary", "preview-cloud-canary", "gcp", previewCaller, ["gha-wif-canary"]),
  entry("deploy-preview.yml", "deploy", "preview-cloud", "gcp", previewCaller, ["gha-deploy-parity", "gha-preview-commit", "gha-preview-deploy", "gha-preview-operator"]),
  entry("deploy-preview.yml", "invalidate", "preview-operations", "gcp", previewCaller, ["gha-preview-commit", "gha-preview-operator", "gha-wif-canary"]),
  entry("deploy-preview.yml", "publish", "preview-publish", "gcp", previewCaller, ["gha-preview-publish", "gha-wif-canary"]),
  entry("deploy-preview.yml", "publish-canary", "preview-publish-canary", "gcp", previewCaller, ["gha-wif-canary"]),
  entry("deploy-prod.yml", "attest", "supply-chain", "attestation", productionCaller, []),
  entry("deploy-prod.yml", "canary", "production-canary", "gcp", productionCaller, ["gha-wif-canary"]),
  entry("deploy-prod.yml", "deploy", "production", "gcp", productionCaller, ["gha-deploy-parity", "gha-preview-commit", "gha-preview-deploy", "gha-prod-deploy"]),
  entry("deploy-prod.yml", "publish", "production-publish", "gcp", productionCaller, ["gha-prod-publish", "gha-wif-canary"]),
  entry("infrastructure.yml", "terraform-convergence", "production", "gcp", productionCaller, ["gha-terraform", "gha-wif-canary"]),
  entry("reconcile-previews.yml", "reconcile", "preview-operations", "gcp", [caller("reconcile-previews.yml", "push", "schedule", "workflow_dispatch")], ["gha-preview-commit", "gha-preview-operator", "gha-wif-canary"], true),
];

describe("workflow authority manifest", () => {
  test("the live repository declares every id-token job as exactly its job-level tuple", async () => {
    const result = await checkWorkflowAuthority(repoRoot);
    expect(result.failures).toEqual([]);
    expect(result.entries).toEqual(expectedEntries);
    expect(result.workflows).toEqual([
      "application.yml",
      "bun-dependency-update.yml",
      "cleanup-preview.yml",
      "deploy-preview.yml",
      "deploy-prod.yml",
      "infrastructure.yml",
      "platform.yml",
      "protected-bootstrap-implementation.yml",
      "reconcile-previews.yml",
      "refresh-grype-db.yml",
      "socket-firewall.yml",
    ]);
    for (const attestation of result.entries.filter((candidate) => candidate.purpose === "attestation")) {
      expect(attestation.serviceAccounts).toEqual([]);
      expect(attestation.environment).toBe("supply-chain");
    }
    for (const canary of result.entries.filter((candidate) => candidate.job.endsWith("canary"))) {
      expect(canary.serviceAccounts).toEqual(["gha-wif-canary"]);
      expect(canary.environment).toEndWith("-canary");
    }
    const environments = new Set(result.entries.map((candidate) => `${candidate.workflow} ${candidate.environment}`));
    expect(environments.size).toBe(result.entries.length);
  });

  test("an id-token job the manifest does not declare fails closed", async () => {
    const root = await fixtureRoot();
    await editFile(root, ".github/workflows/refresh-grype-db.yml", (text) =>
      text.replace("      contents: write\n", "      contents: write\n      id-token: write\n"),
    );
    expect(await failuresOf(root)).toEqual([
      `.github/workflows/refresh-grype-db.yml: job refresh requests id-token: write but ${manifestPath} declares no authority for it.`,
    ]);
  });

  test("a declared job that is not an id-token job on disk fails closed", async () => {
    const root = await fixtureRoot();
    await editEntry(root, "deploy-prod.yml", "canary", (canary) => {
      canary.job = "canary-smoke";
    });
    expect(await failuresOf(root)).toEqual([
      `.github/workflows/deploy-prod.yml: job canary requests id-token: write but ${manifestPath} declares no authority for it.`,
      `.github/workflows/deploy-prod.yml: job canary-smoke is declared in ${manifestPath} but is not an id-token: write job on disk.`,
    ]);
  });

  test("an environment must be one literal name that matches the manifest", async () => {
    const root = await fixtureRoot();
    await editFile(root, ".github/workflows/deploy-prod.yml", (text) =>
      text.replace("    environment: production-canary\n", "    environment: ${{ vars.CANARY_ENVIRONMENT }}\n"),
    );
    expect(await failuresOf(root)).toEqual([
      ".github/workflows/deploy-prod.yml: job canary environment must be one literal environment name.",
    ]);
    await editFile(root, ".github/workflows/deploy-prod.yml", (text) =>
      text.replace("    environment: ${{ vars.CANARY_ENVIRONMENT }}\n", "    environment:\n      name: production-canary\n"),
    );
    expect(await failuresOf(root)).toEqual([]);
    await editEntry(root, "deploy-prod.yml", "canary", (canary) => {
      canary.environment = "production-smoke";
    });
    expect(await failuresOf(root)).toEqual([
      ".github/workflows/deploy-prod.yml: job canary environment production-canary does not match the manifest environment production-smoke.",
    ]);
  });

  test("two id-token jobs of one reusable workflow may not share an environment", async () => {
    const root = await fixtureRoot();
    await editEntry(root, "deploy-prod.yml", "canary", (canary) => {
      canary.environment = "production";
    });
    expect(await failuresOf(root)).toEqual([
      `${manifestPath}[9]: .github/workflows/deploy-prod.yml job deploy shares environment production with another id-token job, so their authority tuples would collide.`,
      ".github/workflows/deploy-prod.yml: job canary environment production-canary does not match the manifest environment production.",
    ]);
  });

  test("an attestation tuple must attest and must exchange for nothing", async () => {
    const root = await fixtureRoot();
    await editEntry(root, "deploy-prod.yml", "canary", (canary) => {
      canary.purpose = "attestation";
      canary.serviceAccounts = [];
    });
    expect(await failuresOf(root)).toEqual([
      ".github/workflows/deploy-prod.yml: job canary is declared attestation but never runs actions/attest.",
      ".github/workflows/deploy-prod.yml: job canary is declared attestation but exchanges for [gha-wif-canary].",
    ]);
    await editEntry(root, "deploy-prod.yml", "canary", (canary) => {
      canary.purpose = "gcp";
      canary.serviceAccounts = ["gha-wif-canary"];
    });
    await editEntry(root, "deploy-prod.yml", "attest", (attest) => {
      attest.purpose = "gcp";
      attest.serviceAccounts = ["gha-wif-canary"];
    });
    expect(await failuresOf(root)).toEqual([
      ".github/workflows/deploy-prod.yml: job attest exchanges for [] but the manifest binds [gha-wif-canary].",
    ]);
  });

  test("a gcp tuple binds exactly the accounts its job exchanges for", async () => {
    const root = await fixtureRoot();
    await editEntry(root, "deploy-prod.yml", "canary", (canary) => {
      canary.serviceAccounts = ["gha-prod-deploy", "gha-wif-canary"];
    });
    expect(await failuresOf(root)).toEqual([
      ".github/workflows/deploy-prod.yml: job canary exchanges for [gha-wif-canary] but the manifest binds [gha-prod-deploy, gha-wif-canary].",
    ]);
    await editEntry(root, "deploy-prod.yml", "canary", (canary) => {
      canary.serviceAccounts = ["gha-wif-canary"];
    });
    await editEntry(root, "cleanup-preview.yml", "cleanup", (cleanup) => {
      cleanup.serviceAccounts = ["gha-preview-commit", "gha-wif-canary"];
    });
    expect(await failuresOf(root)).toEqual([
      ".github/workflows/cleanup-preview.yml: job cleanup exchanges for [gha-preview-commit, gha-preview-operator, gha-wif-canary] but the manifest binds [gha-preview-commit, gha-wif-canary].",
    ]);
  });

  test("an exchange whose account is not a literal same-job output fails closed", async () => {
    const root = await fixtureRoot();
    await editFile(root, ".github/workflows/deploy-prod.yml", (text) =>
      text.replace("          service_account: ${{ steps.app.outputs.canary_service_account }}\n", "          service_account: ${{ vars.CANARY_SERVICE_ACCOUNT }}\n"),
    );
    expect(await failuresOf(root)).toEqual([
      ".github/workflows/deploy-prod.yml: job canary step 2 service_account must resolve to one known gha-* account through a same-job step output.",
      ".github/workflows/deploy-prod.yml: job canary exchanges for [] but the manifest binds [gha-wif-canary].",
    ]);
  });

  test("every action of a declared job must be pinned to a full commit SHA", async () => {
    const root = await fixtureRoot();
    await editFile(root, ".github/workflows/deploy-prod.yml", (text) =>
      text.replace("uses: google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093", "uses: google-github-actions/auth@v3"),
    );
    expect(await failuresOf(root)).toEqual([
      '.github/workflows/deploy-prod.yml: job canary step 2 uses "google-github-actions/auth@v3", which is not pinned to a full 40-hex commit SHA or sha256 image digest.',
    ]);
  });

  test("write-all permissions are refused on a declared job", async () => {
    const root = await fixtureRoot();
    await editFile(root, ".github/workflows/deploy-prod.yml", (text) =>
      text.replace("    permissions:\n      id-token: write # Exchange only for the no-role exact-WIF canary identity.\n", "    permissions: write-all\n"),
    );
    expect(await failuresOf(root)).toEqual([
      ".github/workflows/deploy-prod.yml: job canary must declare an explicit permissions mapping, not write-all.",
    ]);
  });

  test("write-all permissions a declared job inherits from its workflow are refused", async () => {
    const root = await fixtureRoot();
    await editFile(root, ".github/workflows/deploy-prod.yml", (text) =>
      text.replace("\npermissions: {}\n", "\npermissions: write-all\n").replace("    permissions:\n      id-token: write # Exchange only for the no-role exact-WIF canary identity.\n", ""),
    );
    expect(await failuresOf(root)).toEqual([
      ".github/workflows/deploy-prod.yml: job canary must declare an explicit permissions mapping, not write-all.",
    ]);
  });

  test("the reserved composite delimiter is refused in every manifest value", async () => {
    const root = await fixtureRoot();
    await editEntry(root, "deploy-prod.yml", "canary", (canary) => {
      canary.environment = `production${authorityDelimiter}canary`;
    });
    expect(await failuresOf(root)).toEqual([
      `${manifestPath}: "production:canary" contains the reserved delimiter ":".`,
      `${manifestPath}[8]: environment must be one literal environment name.`,
      `.github/workflows/deploy-prod.yml: job canary requests id-token: write but ${manifestPath} declares no authority for it.`,
    ]);
  });

  test("a caller must be a real trigger of the consumer caller template", async () => {
    const root = await fixtureRoot();
    const template = "templates/app/.github/workflows/cleanup-preview.yml";
    await editFile(root, template, (text) => text.replace("on:\n  pull_request_target:\n", "on:\n  workflow_dispatch:\n  pull_request_target:\n"));
    expect(await failuresOf(root)).toEqual([
      `${template}: triggers [pull_request_target, workflow_dispatch] do not match the manifest caller events [pull_request_target] of .github/workflows/cleanup-preview.yml job cleanup.`,
    ]);
    await editFile(root, template, (text) => text.replace("  workflow_dispatch:\n", "").replace("      - main\n", "      - '**'\n"));
    expect(await failuresOf(root)).toEqual([
      `${template}: pull_request_target must select only the main branch named by the manifest caller ref refs/heads/main.`,
    ]);
    await editFile(root, template, (text) =>
      text.replace("      - '**'\n", "      - main\n").replace("      id-token: write # Exchange only for the exact-SHA preview traffic operator.\n", ""),
    );
    expect(await failuresOf(root)).toEqual([
      `${template}: exactly one job must call collinbentley1/platform/.github/workflows/cleanup-preview.yml@__PLATFORM_SHA__ with id-token: write; found 0.`,
    ]);
  });

  test("a caller job that inherits id-token: write from its workflow permissions is counted", async () => {
    const root = await fixtureRoot();
    const template = "templates/app/.github/workflows/cleanup-preview.yml";
    await editFile(root, template, (text) =>
      text.replace("\npermissions: {}\n", "\npermissions:\n  id-token: write\n").replace("    permissions:\n      actions: read # Download only the exact prefetch artifact id the reusable workflow produces.\n      id-token: write # Exchange only for the exact-SHA preview traffic operator.\n      pull-requests: read # Let the reusable cleanup re-read current lifecycle state.\n", ""),
    );
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
    const base = {
      callers: [productionCaller[0]],
      environment: "production-canary",
      job: "canary",
      purpose: "gcp",
      serviceAccounts: ["gha-wif-canary"],
      transitionEligible: false,
      workflow: ".github/workflows/deploy-prod.yml",
    };
    const manifestEntry = (overrides: Record<string, unknown>) => ({ ...base, ...overrides });
    const withCaller = (overrides: Record<string, unknown>) => manifestEntry({ callers: [{ ...productionCaller[0], ...overrides }] });
    const failure = (manifest: unknown) => parseWorkflowAuthority(JSON.stringify(manifest)).failures;
    expect(failure([manifestEntry({})])).toEqual([]);
    expect(failure("{")).toHaveLength(1);
    expect(failure({})).toEqual([`${manifestPath}: must be a non-empty array of id-token job entries.`]);
    expect(failure([])).toEqual([`${manifestPath}: must be a non-empty array of id-token job entries.`]);
    expect(failure([manifestEntry({ extra: true })])[0]).toContain("keys must be exactly");
    expect(failure([manifestEntry({ purpose: "cloud" })])[0]).toContain("purpose must be one of");
    expect(failure([manifestEntry({ workflow: "workflows/deploy-prod.yml" })])[0]).toContain("workflow must name");
    expect(failure([manifestEntry({ workflow: ".github/workflows/../deploy-prod.yml" })])[0]).toContain("workflow must name");
    expect(failure([manifestEntry({ job: "${{ matrix.job }}" })])[0]).toContain("job must be");
    expect(failure([manifestEntry({ environment: "${{ vars.ENVIRONMENT }}" })])[0]).toContain("environment must be one literal");
    expect(failure([manifestEntry({ transitionEligible: "no" })])[0]).toContain("transitionEligible must be a boolean");
    expect(failure([manifestEntry({ purpose: "attestation", serviceAccounts: [], transitionEligible: true })])[0]).toContain("transitionEligible requires purpose gcp");
    expect(failure([manifestEntry({ serviceAccounts: [] })])[0]).toContain("non-empty exactly when purpose is gcp");
    expect(failure([manifestEntry({ purpose: "attestation" })])[0]).toContain("non-empty exactly when purpose is gcp");
    expect(failure([manifestEntry({ serviceAccounts: ["gha-owner"] })])[0]).toContain("known service account IDs");
    expect(failure([manifestEntry({ serviceAccounts: ["gha-wif-canary", "gha-terraform"] })])[0]).toContain("sorted, unique");
    expect(failure([manifestEntry({ serviceAccounts: ["gha-terraform", "gha-terraform"] })])[0]).toContain("sorted, unique");
    expect(failure([manifestEntry({ callers: [] })])[0]).toContain("callers must be a non-empty list");
    expect(failure([manifestEntry({ callers: [{ events: ["push"], workflow: ".github/workflows/deploy-prod.yml" }] })])[0]).toContain("exactly the keys");
    expect(failure([withCaller({ workflow: "deploy-prod.yml" })])[0]).toContain("caller workflow must name");
    expect(failure([withCaller({ ref: "refs/tags/v1" })])[0]).toContain("caller ref must be");
    expect(failure([withCaller({ events: ["pull_request"] })])[0]).toContain("caller events must be");
    expect(failure([withCaller({ events: [] })])[0]).toContain("caller events must be");
    expect(failure([withCaller({ events: ["workflow_dispatch", "push"] })])[0]).toContain("caller events must be");
    expect(failure([manifestEntry({ callers: [productionCaller[0], productionCaller[0]] })])[0]).toContain("callers must be unique and sorted");
    expect(failure([manifestEntry({ job: "deploy" }), manifestEntry({})])).toEqual([
      `${manifestPath}[1]: entries must be unique and sorted by workflow, then job.`,
      `${manifestPath}[1]: .github/workflows/deploy-prod.yml job canary shares environment production-canary with another id-token job, so their authority tuples would collide.`,
    ]);
    expect(failure([manifestEntry({}), manifestEntry({ environment: "production", job: "deploy", serviceAccounts: ["gha-prod-deploy"] })])).toEqual([]);
    expect(failure([manifestEntry({ callers: [{ events: ["push"], ref: `refs/heads/main${authorityDelimiter}x`, workflow: ".github/workflows/deploy-prod.yml" }] })])).toEqual([
      `${manifestPath}: "refs/heads/main:x" contains the reserved delimiter ":".`,
      `${manifestPath}[0]: caller ref must be a refs/heads/ branch reference.`,
    ]);
  });
});
