import { afterAll, describe, expect, test } from "bun:test";
import { cp, mkdir, mkdtemp, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  type WorkflowCapabilities,
  classifyWorkflowAuthority,
  conditionStructure,
  declaredWorkflowAuthority,
  terraformUniverse,
  trustedWorkflowsFromTerraform,
  validateWorkflowAuthorityInventory,
  workflowCapabilities,
  workflowUniverse,
} from "../tools/ci/workflow-authority-contract";

const root = resolve(import.meta.dir, "..");
const temporaryRoots: string[] = [];

afterAll(async () => {
  await Promise.all(temporaryRoots.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

async function temporaryRoot(prefix: string): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), prefix));
  temporaryRoots.push(path);
  return path;
}

async function liveSources(): Promise<{
  terraform: ReadonlyMap<string, string>;
  workflows: ReadonlyMap<string, string>;
}> {
  const workflows = await workflowUniverse(root);
  const terraform = await terraformUniverse(root);
  if (workflows.kind !== "resolved") throw new Error(workflows.failures.join("\n"));
  if (terraform.kind !== "resolved") throw new Error(terraform.failures.join("\n"));
  return { terraform: terraform.sources, workflows: workflows.sources };
}

function capabilities(source: string): WorkflowCapabilities {
  const analysis = workflowCapabilities(source);
  if (analysis.kind !== "capabilities") {
    throw new Error(`expected capabilities, got: ${analysis.reasons.join("; ")}`);
  }
  return analysis.capabilities;
}

function invalidReasons(source: string): string {
  const analysis = workflowCapabilities(source);
  if (analysis.kind !== "invalid") throw new Error("expected the workflow to be invalid");
  return analysis.reasons.join(" ");
}

// Workflow fixtures. Every job declares read-only permissions unless a test
// is about permissions, so the flags under test are the only thing that moves.
const header = "name: t\non: [push]\npermissions: {}\njobs:\n";
const readOnlyJob = (body: string) =>
  `  a:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n${body}`;
const envStep = (value: string) => `    steps:\n      - run: echo x\n        env:\n          T: ${value}\n`;
const withEnv = (value: string) => header + readOnlyJob(envStep(value));
const withEnvironment = (environment: string) =>
  header + readOnlyJob(`    environment: ${environment}\n    steps:\n      - run: echo x\n`);
const withJob = (job: string) => `${header}  a:\n    runs-on: ubuntu-24.04\n${job}`;
const neither = withEnv("plain");
const cloud = withJob("    permissions:\n      id-token: write\n    steps:\n      - run: echo x\n");
const owner = withEnv("${{ secrets.OWNER_OAUTH_ACCESS_TOKEN }}");
const both = withJob(
  "    permissions:\n      id-token: write\n" + envStep("${{ secrets['OWNER_OAUTH_ACCESS_TOKEN'] }}"),
);

// Terraform fixtures.
const trustLine = (name: string) =>
  `assertion.job_workflow_ref == 'collinbentley1/platform/.github/workflows/${name}@' + assertion.job_workflow_sha`;
const legacyTrustLine = (name: string) =>
  `assertion.job_workflow_ref.startsWith('collinbentley1/platform/.github/workflows/${name}@')`;
const provider = (condition: string, extra = "") =>
  `resource "google_iam_workload_identity_pool_provider" "github" {\n` +
  `  workload_identity_pool_id = "github"\n${extra}  attribute_condition = ${condition}\n` +
  `  oidc {\n    issuer_uri = "https://token.actions.githubusercontent.com/"\n  }\n}\n`;
const terraformTrusting = (...names: string[]) =>
  `locals {\n  condition = "${names.map(trustLine).join(" || ")}"\n}\n\n${provider("local.condition")}`;
const singleFile = (source: string) => new Map([["terraform/modules/bootstrap/main.tf", source]]);
// A provider with no condition at all trusts every token the issuer signs.
const openProvider =
  `resource "google_iam_workload_identity_pool_provider" "extra" {\n` +
  `  workload_identity_pool_provider_id = "github-extra"\n` +
  `  oidc { issuer_uri = "https://token.actions.githubusercontent.com/" }\n}\n`;
// A second provider as an attacker or a hurried operator would add it.
const extraProvider = (condition: string, locals = "") =>
  `${locals}resource "google_iam_workload_identity_pool_provider" "extra" {\n` +
  `  workload_identity_pool_provider_id = "github-extra"\n` +
  `  attribute_condition = ${condition}\n` +
  `  oidc { issuer_uri = "https://token.actions.githubusercontent.com/" }\n}\n`;
const foreign = "assertion.job_workflow_ref.startsWith('attacker-org/backdoor/.github/workflows/pwn.yml@')";
// The reviewed exact clause beside a prefix that admits another repository.
const foreignProvider = extraProvider(`"${trustLine("deploy-prod.yml")} || ${foreign}"`);

function trusted(files: ReadonlyMap<string, string>): string[] {
  const trust = trustedWorkflowsFromTerraform(files);
  if (trust.kind !== "trusted") throw new Error(`expected trust, got: ${trust.failures.join("; ")}`);
  return [...trust.workflows].sort();
}

function trustFailures(files: ReadonlyMap<string, string>): string {
  const trust = trustedWorkflowsFromTerraform(files);
  if (trust.kind !== "invalid") throw new Error("expected the Terraform to be rejected");
  return trust.failures.join(" ");
}

describe("the live inventory agrees with the declaration", () => {
  test("every workflow and Terraform file on disk validates clean", async () => {
    expect(validateWorkflowAuthorityInventory(await liveSources())).toEqual([]);
  });

  test("the universe covers every workflow and every Terraform source in the repository", async () => {
    const { terraform, workflows } = await liveSources();
    const declared = [
      ...declaredWorkflowAuthority.ownerCredential,
      ...declaredWorkflowAuthority.cloudAuthority,
      ...declaredWorkflowAuthority.neither,
    ].sort();
    expect([...workflows.keys()].sort()).toEqual(declared);
    expect(terraform.size).toBeGreaterThanOrEqual(36);
    expect(terraform.has("terraform/modules/bootstrap/main.tf")).toBe(true);
    // The app template ships Terraform outside terraform/; a walk rooted
    // there would never have seen a provider added beside it.
    expect(terraform.has("templates/app/infra/terraform/bootstrap/main.tf")).toBe(true);
    for (const path of terraform.keys()) expect(path).toMatch(/\.tf$/);
  });

  test("Terraform trusts exactly the cloud-authority workflows through one provider", async () => {
    const trust = trustedWorkflowsFromTerraform((await liveSources()).terraform);
    expect(trust.kind).toBe("trusted");
    if (trust.kind !== "trusted") return;
    expect(trust.providers).toEqual([
      "terraform/modules/bootstrap/main.tf: google_iam_workload_identity_pool_provider.github",
    ]);
    expect([...trust.workflows].sort()).toEqual([...declaredWorkflowAuthority.cloudAuthority].sort());
  });

  // The structural gate passes the live condition for reasons that can be
  // checked here: each rendering is a conjunction whose guard -- the owner
  // and repository IDs, the presence checks, the run attempt, the runner, the
  // SHA disjunction -- binds nothing on its own, and whose last conjunct is a
  // disjunction bounded by whole-operand trust forms naming exactly the
  // cloud-authority workflows.
  test("the live condition renders as two conjunctions, each bounded by its workflow disjunction", async () => {
    const trust = trustedWorkflowsFromTerraform((await liveSources()).terraform);
    expect(trust.kind).toBe("trusted");
    if (trust.kind !== "trusted") return;
    expect(trust.conditions.map((condition) => condition.choices)).toEqual([
      ["var.legacy_compatibility_mode is true"],
      ["var.legacy_compatibility_mode is false"],
    ]);
    const guard =
      "assertion.repository_owner_id == 'var.github_owner_id' && assertion.repository_id == 'var.github_repository_id' && " +
      "has(assertion.job_workflow_ref) && has(assertion.job_workflow_sha) && has(assertion.run_attempt) && " +
      "assertion.run_attempt == '1' && assertion.runner_environment == 'github-hosted' && (assertion.job_workflow_sha == 'sha')";
    expect(conditionStructure(guard).kind).toBe("unbounded");
    for (const condition of trust.conditions) {
      expect(condition.text.startsWith(`${guard} && (`)).toBe(true);
      expect(condition.text.endsWith(")")).toBe(true);
      const disjunction = condition.text.slice(guard.length + " && (".length, -1);
      const structure = conditionStructure(disjunction);
      expect(structure.kind).toBe("bounded");
      if (structure.kind !== "bounded") return;
      expect([...structure.names].sort()).toEqual([...declaredWorkflowAuthority.cloudAuthority].sort());
    }
    const [legacy, exact] = trust.conditions;
    expect(legacy?.text).toContain(".startsWith('collinbentley1/platform/.github/workflows/deploy-prod.yml@')");
    expect(exact?.text).not.toContain("startsWith");
  });

  test("each declared set matches the independent flags of its members", async () => {
    const { workflows } = await liveSources();
    const flags = (name: string) => {
      const derived = capabilities(workflows.get(name) ?? "");
      return [derived.readsOwnerCredential, derived.mintsCloudCredentials];
    };
    for (const name of declaredWorkflowAuthority.ownerCredential) expect(flags(name)).toEqual([true, false]);
    for (const name of declaredWorkflowAuthority.cloudAuthority) expect(flags(name)).toEqual([false, true]);
    for (const name of declaredWorkflowAuthority.neither) expect(flags(name)).toEqual([false, false]);
  });

  // The whole point of the exercise: these move branches and open pull
  // requests with GITHUB_TOKEN and hold no cloud or owner authority.
  test.each(["bun-dependency-update.yml", "refresh-grype-db.yml"])(
    "%s writes GitHub without any credential authority",
    async (name) => {
      const derived = capabilities((await liveSources()).workflows.get(name) ?? "");
      expect(derived.writesGitHub).toBe(true);
      expect(derived.mintsCloudCredentials).toBe(false);
      expect(derived.readsOwnerCredential).toBe(false);
      expect(classifyWorkflowAuthority(derived)).toBe("neither");
      expect(declaredWorkflowAuthority.neither).toContain(name);
    },
  );

  test("protected-bootstrap-implementation.yml reads the owner credential and mints nothing", async () => {
    const derived = capabilities(
      (await liveSources()).workflows.get("protected-bootstrap-implementation.yml") ?? "",
    );
    expect(derived.readsOwnerCredential).toBe(true);
    expect(derived.mintsCloudCredentials).toBe(false);
    expect(derived.cloudCredentialEvidence).toEqual([]);
    expect(derived.ownerCredentialEvidence.join(" ")).toContain("protected-bootstrap-owner-token");
  });
});

describe("owner-credential detection is quote-aware and case-aware", () => {
  // A bare word "secrets" in a shell command is not a credential reference,
  // and treating it as one would classify half the fleet as owner-credential.
  test("shell text mentioning secrets stays unprivileged", () => {
    const derived = capabilities(header + readOnlyJob(
      "    steps:\n      - run: |\n          gcloud secrets versions list\n          secret_args=(--clear-secrets)\n",
    ));
    expect(derived.readsOwnerCredential).toBe(false);
  });

  test.each([
    ["dot form", "${{ secrets.DHI_PUBLIC_READ_TOKEN_20260822_098DCA9280B3 }}"],
    ["single-quoted index", "${{ secrets['DHI_PUBLIC_READ_TOKEN_20260822_098DCA9280B3'] }}"],
    ["double-quoted index", '${{ secrets["DHI_PUBLIC_READ_TOKEN_20260822_098DCA9280B3"] }}'],
    ["a }} inside a string literal before the reference", "${{ format('}}{0}', secrets.CONSUMER_ACTIONS_READ_TOKEN) }}"],
  ])("an allowlisted literal in %s does not imply owner authority", (_label, value) => {
    expect(capabilities(withEnv(value)).readsOwnerCredential).toBe(false);
  });

  test.each([
    ["the owner token by name", "${{ secrets.OWNER_OAUTH_ACCESS_TOKEN }}"],
    ["the owner token through a single-quoted index", "${{ secrets['OWNER_OAUTH_ACCESS_TOKEN'] }}"],
    ["the owner token through a double-quoted index", '${{ secrets["OWNER_OAUTH_ACCESS_TOKEN"] }}'],
    ["the owner token through a padded index", "${{ secrets[ 'OWNER_OAUTH_ACCESS_TOKEN' ] }}"],
    ["the owner token in lower case", "${{ secrets.owner_oauth_access_token }}"],
    ["the owner token in mixed case through an index", "${{ secrets['Owner_OAuth_Access_Token'] }}"],
    ["an unlisted secret", "${{ secrets.SOMETHING_NEW }}"],
    ["an index containing an escaped closing delimiter", "${{ secrets['X}}Y'] }}"],
    ["dynamic indexing", "${{ secrets[matrix.name] }}"],
    ["a computed index", "${{ secrets[format('{0}', 'X')] }}"],
    ["whole-context serialisation", "${{ toJSON(secrets) }}"],
    ["a property of another value named secrets", "${{ inputs.secrets }}"],
    ["a second expression after a benign one", "${{ github.sha }}-${{ secrets.NEW }}"],
  ])("%s reads the owner credential", (_label, value) => {
    const derived = capabilities(withEnv(value));
    expect(derived.readsOwnerCredential).toBe(true);
    expect(derived.ownerCredentialEvidence.join(" ")).toContain("jobs.a.steps.0.env.T");
  });

  test("the evidence names the spelling that was used", () => {
    const derived = capabilities(withEnv("${{ secrets['OWNER_OAUTH_ACCESS_TOKEN'] }}"));
    expect(derived.ownerCredentialEvidence).toEqual([
      "jobs.a.steps.0.env.T references the owner token as secrets['OWNER_OAUTH_ACCESS_TOKEN']",
    ]);
  });

  test.each([
    ["exactly", "protected-bootstrap-owner-token"],
    ["in upper case", "PROTECTED-BOOTSTRAP-OWNER-TOKEN"],
    ["in mixed case with padding", '"  Protected-Bootstrap-Owner-Token  "'],
    ["through the name form", "\n      name: Protected-Bootstrap-Owner-Token\n      url: https://example.invalid"],
  ])("binding to the owner-token environment %s is authority on its own", (_label, environment) => {
    const derived = capabilities(withEnvironment(environment));
    expect(derived.readsOwnerCredential).toBe(true);
    expect(derived.ownerCredentialEvidence.join(" ")).toContain("jobs.a.environment");
  });

  test.each([
    ["a run-time environment name", "${{ inputs.environment }}"],
    ["a run-time name in the name form", "\n      name: ${{ github.event.inputs.target }}"],
    ["an environment without a literal name", "\n      url: https://example.invalid"],
  ])("%s fails closed as owner-credential", (_label, environment) => {
    expect(capabilities(withEnvironment(environment)).readsOwnerCredential).toBe(true);
  });

  test("an unrelated environment is not authority", () => {
    expect(capabilities(withEnvironment("production")).readsOwnerCredential).toBe(false);
  });

  test("a secrets passthrough is owner-credential", () => {
    const derived = capabilities(
      `${header}  a:\n    uses: ./.github/workflows/x.yml\n    secrets: inherit\n`,
    );
    expect(derived.readsOwnerCredential).toBe(true);
    expect(derived.ownerCredentialEvidence.join(" ")).toContain("jobs.a.secrets: inherit");
  });

  test("an explicit secrets mapping is judged by its values", () => {
    const explicit = (value: string) =>
      `${header}  a:\n    uses: ./.github/workflows/x.yml\n    secrets:\n      TOKEN: ${value}\n`;
    expect(capabilities(explicit("literal")).readsOwnerCredential).toBe(false);
    expect(capabilities(explicit("${{ secrets.OWNER_OAUTH_ACCESS_TOKEN }}")).readsOwnerCredential).toBe(true);
  });

  test("a reusable workflow accepting secrets is owner-credential", () => {
    const derived = capabilities(
      "name: t\non:\n  workflow_call:\n    secrets:\n      TOKEN:\n        required: true\n" +
        "permissions: {}\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo x\n",
    );
    expect(derived.readsOwnerCredential).toBe(true);
    expect(derived.ownerCredentialEvidence.join(" ")).toContain("on.workflow_call.secrets");
  });
});

describe("cloud authority is detected by several independent signals", () => {
  test.each([
    ["id-token: write on a job", "    permissions:\n      id-token: write\n    steps:\n      - run: echo x\n"],
    ["write-all on a job", "    permissions: write-all\n    steps:\n      - run: echo x\n"],
    ["a google-github-actions step", "    permissions:\n      contents: read\n    steps:\n      - uses: google-github-actions/auth@abc\n"],
    ["a hand-rolled STS exchange", "    permissions:\n      contents: read\n    steps:\n      - run: curl https://sts.googleapis.com/v1/token\n"],
    ["a credentials file", "    permissions:\n      contents: read\n    steps:\n      - run: echo\n        env:\n          X: create_credentials_file\n"],
    ["an access-token print", "    permissions:\n      contents: read\n    steps:\n      - run: gcloud auth print-access-token\n"],
  ])("%s mints cloud credentials", (_label, job) => {
    const derived = capabilities(withJob(job));
    expect(derived.mintsCloudCredentials).toBe(true);
    expect(derived.readsOwnerCredential).toBe(false);
  });

  test("top-level write-all counts as id-token even when every job overrides it", () => {
    const derived = capabilities(
      "name: t\non: [push]\npermissions: write-all\njobs:\n  a:\n    runs-on: ubuntu-24.04\n" +
        "    permissions:\n      contents: read\n    steps:\n      - run: echo x\n",
    );
    expect(derived.mintsCloudCredentials).toBe(true);
    expect(derived.cloudCredentialEvidence).toEqual([
      "top-level permissions grant id-token: write, the default for every job",
    ]);
  });

  test("top-level id-token: write flows to a job that declares nothing", () => {
    const derived = capabilities(
      "name: t\non: [push]\npermissions:\n  id-token: write\njobs:\n  a:\n    runs-on: ubuntu-24.04\n" +
        "    steps:\n      - run: echo x\n",
    );
    expect(derived.cloudCredentialEvidence).toContain("jobs.a effective permissions grant id-token: write");
  });

  test.each([
    ["contents: write", "      contents: write\n"],
    ["pull-requests: write", "      pull-requests: write\n"],
    ["attestations: write", "      attestations: write\n"],
  ])("%s is a GitHub-only write, not cloud authority", (scope, permission) => {
    const derived = capabilities(withJob(`    permissions:\n${permission}    steps:\n      - run: echo x\n`));
    expect(derived.mintsCloudCredentials).toBe(false);
    expect(derived.readsOwnerCredential).toBe(false);
    expect(derived.writesGitHub).toBe(true);
    expect(derived.gitHubWriteEvidence).toEqual([`jobs.a effective permissions grant ${scope}`]);
    expect(classifyWorkflowAuthority(derived)).toBe("neither");
  });

  test("write-all records the GitHub writes as well as id-token", () => {
    const derived = capabilities(withJob("    permissions: write-all\n    steps:\n      - run: echo x\n"));
    expect(derived.writesGitHub).toBe(true);
    expect(derived.gitHubWriteEvidence).toEqual(["jobs.a effective permissions grant write-all"]);
  });

  // Scopes are compared in lower case: whether or not GitHub would honour
  // `ID-TOKEN: write`, the inventory must never file it under the benign
  // GitHub writes, which a case-sensitive comparison used to do.
  test("a scope spelt in upper case is read as the grant it is", () => {
    const derived = capabilities(withJob("    permissions:\n      ID-TOKEN: write\n    steps:\n      - run: echo x\n"));
    expect(derived.mintsCloudCredentials).toBe(true);
    expect(derived.cloudCredentialEvidence).toEqual(["jobs.a effective permissions grant id-token: write"]);
    const writes = capabilities(withJob("    permissions:\n      Contents: write\n    steps:\n      - run: echo x\n"));
    expect(writes.mintsCloudCredentials).toBe(false);
    expect(writes.gitHubWriteEvidence).toEqual(["jobs.a effective permissions grant contents: write"]);
  });
});

describe("the two authorities are independent flags", () => {
  test("a workflow can hold both and neither hides the other", () => {
    const derived = capabilities(both);
    expect(derived.readsOwnerCredential).toBe(true);
    expect(derived.mintsCloudCredentials).toBe(true);
    expect(classifyWorkflowAuthority(derived)).toBe("owner-credential+cloud-authority");
  });

  test("top-level write-all with the owner environment is both", () => {
    const derived = capabilities(
      "name: t\non: [push]\npermissions: write-all\njobs:\n  a:\n    runs-on: ubuntu-24.04\n" +
        "    environment: protected-bootstrap-owner-token\n    steps:\n      - run: echo x\n",
    );
    expect(derived.readsOwnerCredential).toBe(true);
    expect(derived.mintsCloudCredentials).toBe(true);
  });

  test.each([
    ["owner-credential", { cloudAuthority: [], neither: [], ownerCredential: ["b.yml"] }],
    ["cloud-authority", { cloudAuthority: ["b.yml"], neither: [], ownerCredential: [] }],
    ["neither", { cloudAuthority: [], neither: ["b.yml"], ownerCredential: [] }],
  ])("the inventory rejects a workflow holding both even when declared %s", (_label, declared) => {
    const out = validateWorkflowAuthorityInventory({
      declared,
      terraform: singleFile(terraformTrusting("b.yml")),
      workflows: new Map([["b.yml", both]]),
    });
    const joined = out.join(" ");
    expect(joined).toContain(".github/workflows/b.yml both reads the owner credential");
    expect(joined).toContain("mints cloud credentials");
    expect(joined).toContain("the two authorities must never meet in one workflow");
  });
});

describe("a workflow that cannot be analysed is invalid, not classified", () => {
  test("unparseable YAML is an explicit failure", () => {
    const source = "name: [unclosed\n  : :";
    expect(invalidReasons(source)).toContain("does not parse as a workflow");
    const out = validateWorkflowAuthorityInventory({
      declared: { cloudAuthority: [], neither: ["bad.yml"], ownerCredential: [] },
      terraform: singleFile(terraformTrusting("c.yml")),
      workflows: new Map([["bad.yml", source]]),
    });
    expect(out.join(" ")).toContain(".github/workflows/bad.yml does not parse as a workflow");
    expect(out.join(" ")).toContain("cannot be classified");
  });

  test.each([
    ["a multi-document stream", "a: 1\n---\nb: 2\n"],
    ["a bare scalar", "just text\n"],
    ["an empty document", ""],
  ])("%s is not a workflow", (_label, source) => {
    expect(invalidReasons(source)).toContain("is not a single YAML mapping");
  });

  test("a workflow without jobs is invalid", () => {
    expect(invalidReasons("name: t\non: [push]\npermissions: {}\n")).toContain("declares no jobs");
    expect(invalidReasons("name: t\non: [push]\npermissions: {}\njobs: {}\n")).toContain("declares no jobs");
  });

  test("a job that is not a mapping is invalid", () => {
    expect(invalidReasons("name: t\non: [push]\npermissions: {}\njobs:\n  a: []\n")).toContain("jobs.a is not a mapping");
  });

  test("permissions absent at both levels fail closed", () => {
    const reasons = invalidReasons(
      "name: t\non: [push]\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo x\n",
    );
    expect(reasons).toContain("jobs.a declares no permissions and neither does the top level");
  });

  test.each([
    ["at the top level only", "permissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo x\n"],
    ["on the job only", "jobs:\n  a:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n    steps:\n      - run: echo x\n"],
  ])("permissions declared %s are effective", (_label, rest) => {
    const derived = capabilities(`name: t\non: [push]\n${rest}`);
    expect(derived.mintsCloudCredentials).toBe(false);
    expect(derived.writesGitHub).toBe(false);
  });

  test.each([
    ["a list", "    permissions: [contents]\n"],
    ["an unknown level", "    permissions:\n      contents: 1\n"],
    ["an unknown word", "    permissions: everything\n"],
    ["an unknown scope", "    permissions:\n      id_token: write\n"],
  ])("permissions given as %s are invalid", (_label, permissions) => {
    expect(invalidReasons(withJob(`${permissions}    steps:\n      - run: echo x\n`))).toContain("jobs.a.permissions");
  });

  test("a scope GitHub does not define is refused, not recorded as a write", () => {
    expect(invalidReasons(withJob("    permissions:\n      id_token: write\n    steps:\n      - run: echo x\n"))).toContain(
      'jobs.a.permissions grants "id_token", which is not a GitHub permission scope',
    );
  });

  // A mapping under `steps` used to be scanned as an empty list, which read
  // as "no Google action" for a job GitHub would not even run.
  test("steps that are not a list fail rather than scanning as empty", () => {
    const reasons = invalidReasons(withJob(
      "    permissions:\n      contents: read\n    steps:\n      auth:\n        uses: google-github-actions/auth@abc\n",
    ));
    expect(reasons).toContain("jobs.a.steps is not a list, so its actions cannot be scanned");
  });
});

describe("the file universe refuses what it cannot classify", () => {
  test("both .yml and .yaml workflows are read", async () => {
    const temporary = await temporaryRoot("platform-authority-universe-");
    await mkdir(join(temporary, ".github/workflows"), { recursive: true });
    await writeFile(join(temporary, ".github/workflows/a.yml"), neither);
    await writeFile(join(temporary, ".github/workflows/b.yaml"), cloud);
    const universe = await workflowUniverse(temporary);
    expect(universe.kind).toBe("resolved");
    if (universe.kind !== "resolved") return;
    expect([...universe.sources.keys()].sort()).toEqual(["a.yml", "b.yaml"]);
    expect(universe.sources.get("b.yaml")).toBe(cloud);
  });

  test("a symbolic link, a directory, a FIFO and a stray file are each named", async () => {
    const temporary = await temporaryRoot("platform-authority-hostile-");
    const directory = join(temporary, ".github/workflows");
    await mkdir(join(directory, "d.yml"), { recursive: true });
    await writeFile(join(directory, "a.yml"), neither);
    await symlink("a.yml", join(directory, "c.yml"));
    await writeFile(join(directory, "notes.txt"), "not a workflow\n");
    expect(await Bun.spawn(["mkfifo", join(directory, "e.yml")]).exited).toBe(0);
    const universe = await workflowUniverse(temporary);
    expect(universe.kind).toBe("rejected");
    if (universe.kind !== "rejected") return;
    expect(universe.failures).toEqual([
      ".github/workflows/c.yml is a symbolic link; the workflow directory may hold only regular *.yml or *.yaml files.",
      ".github/workflows/d.yml is a directory; the workflow directory may hold only regular *.yml or *.yaml files.",
      ".github/workflows/e.yml is a FIFO; the workflow directory may hold only regular *.yml or *.yaml files.",
      ".github/workflows/notes.txt is not a workflow (*.yml or *.yaml); the workflow directory may hold nothing else.",
    ]);
    // The entry that did resolve travels with the rejection, so the lint can
    // still classify it rather than skip the authority check.
    expect([...universe.sources.keys()]).toEqual(["a.yml"]);
  });

  test("a missing workflow directory is a failure, not an empty set", async () => {
    const universe = await workflowUniverse(await temporaryRoot("platform-authority-empty-"));
    expect(universe.kind).toBe("rejected");
    if (universe.kind !== "rejected") return;
    expect(universe.failures.join(" ")).toContain(".github/workflows could not be listed");
  });

  test("Terraform sources are found in every module and fetched copies are ignored", async () => {
    const temporary = await temporaryRoot("platform-authority-terraform-");
    await mkdir(join(temporary, "terraform/modules/x"), { recursive: true });
    await mkdir(join(temporary, "terraform/deployments/y/.terraform/modules/z"), { recursive: true });
    await writeFile(join(temporary, "terraform/modules/x/main.tf"), "locals {}\n");
    await writeFile(join(temporary, "terraform/modules/x/tests.tftest.hcl"), "run \"x\" {}\n");
    await writeFile(join(temporary, "terraform/deployments/y/main.tf"), "locals {}\n");
    await writeFile(join(temporary, "terraform/deployments/y/.terraform/modules/z/main.tf"), "locals {}\n");
    const universe = await terraformUniverse(temporary);
    expect(universe.kind).toBe("resolved");
    if (universe.kind !== "resolved") return;
    expect([...universe.sources.keys()].sort()).toEqual([
      "terraform/deployments/y/main.tf",
      "terraform/modules/x/main.tf",
    ]);
  });

  test("a symbolic link, a linked directory, a FIFO and JSON configuration are refused", async () => {
    const temporary = await temporaryRoot("platform-authority-terraform-hostile-");
    await mkdir(join(temporary, "terraform/modules/x"), { recursive: true });
    await mkdir(join(temporary, "elsewhere"), { recursive: true });
    await writeFile(join(temporary, "terraform/modules/x/main.tf"), "locals {}\n");
    await symlink("main.tf", join(temporary, "terraform/modules/x/linked.tf"));
    await symlink("../../elsewhere", join(temporary, "terraform/modules/outside"));
    await writeFile(join(temporary, "terraform/modules/x/extra.tf.json"), "{}\n");
    expect(await Bun.spawn(["mkfifo", join(temporary, "terraform/modules/x/pipe.tf")]).exited).toBe(0);
    const universe = await terraformUniverse(temporary);
    expect(universe.kind).toBe("rejected");
    if (universe.kind !== "rejected") return;
    expect(universe.failures).toEqual([
      "terraform/modules/outside is a symbolic link; Terraform sources must be regular files.",
      "terraform/modules/x/extra.tf.json is JSON Terraform configuration, which the authority scan cannot read; express it in HCL.",
      "terraform/modules/x/linked.tf is a symbolic link; Terraform sources must be regular files.",
      "terraform/modules/x/pipe.tf is a FIFO; Terraform sources must be regular files.",
    ]);
  });

  // A provider with no condition placed at infra/wif.tf used to lint clean,
  // because the walk started at terraform/ and never looked anywhere else.
  test("Terraform outside terraform/ is found, and unscanned directories are skipped", async () => {
    const temporary = await temporaryRoot("platform-authority-terraform-root-");
    for (const directory of ["infra/.terraform/modules/z", "terraform/modules/x", ".git/hooks", "node_modules/pkg"]) {
      await mkdir(join(temporary, directory), { recursive: true });
    }
    await writeFile(join(temporary, "infra/wif.tf"), openProvider);
    await writeFile(join(temporary, "infra/.terraform/modules/z/main.tf"), "locals {}\n");
    await writeFile(join(temporary, "terraform/modules/x/main.tf"), "locals {}\n");
    await writeFile(join(temporary, ".git/hooks/decoy.tf"), "locals {}\n");
    await writeFile(join(temporary, "node_modules/pkg/decoy.tf"), "locals {}\n");
    await writeFile(join(temporary, "README.md"), "not terraform\n");
    const universe = await terraformUniverse(temporary);
    expect(universe.kind).toBe("resolved");
    if (universe.kind !== "resolved") return;
    expect([...universe.sources.keys()].sort()).toEqual(["infra/wif.tf", "terraform/modules/x/main.tf"]);
    expect(trustFailures(universe.sources)).toContain(
      "infra/wif.tf: google_iam_workload_identity_pool_provider.extra has no attribute_condition",
    );
  });

  test("JSON configuration and a symbolic link outside terraform/ are refused", async () => {
    const temporary = await temporaryRoot("platform-authority-terraform-root-hostile-");
    await mkdir(join(temporary, "infra"), { recursive: true });
    await writeFile(join(temporary, "infra/main.tf"), "locals {}\n");
    await writeFile(join(temporary, "infra/extra.tf.json"), "{}\n");
    await symlink("main.tf", join(temporary, "infra/linked.tf"));
    const universe = await terraformUniverse(temporary);
    expect(universe.kind).toBe("rejected");
    if (universe.kind !== "rejected") return;
    expect(universe.failures).toEqual([
      "infra/extra.tf.json is JSON Terraform configuration, which the authority scan cannot read; express it in HCL.",
      "infra/linked.tf is a symbolic link; Terraform sources must be regular files.",
    ]);
    expect([...universe.sources.keys()]).toEqual(["infra/main.tf"]);
  });

  test("a missing repository root is a failure, not an empty set", async () => {
    const universe = await terraformUniverse(join(await temporaryRoot("platform-authority-absent-"), "absent"));
    expect(universe.kind).toBe("rejected");
    if (universe.kind !== "rejected") return;
    expect(universe.failures.join(" ")).toContain("the repository root could not be listed");
  });
});

describe("Terraform trust is read from provider conditions only", () => {
  test("decoys in comments, unrelated resources and descriptions are ignored", () => {
    const decoy = trustLine("deploy-prod.yml");
    const source =
      `# ${decoy}\n// ${decoy}\n/* ${decoy}\n   ${decoy} */\n` +
      `resource "google_service_account" "decoy" {\n  description = "${decoy}"\n}\n` +
      `variable "decoy" {\n  default = "${decoy}"\n}\n` +
      provider(`"${trustLine("c.yml")}"`, `  description = "${decoy}"\n  display_name = "x" # ${decoy}\n`);
    expect(trusted(singleFile(source))).toEqual(["c.yml"]);
  });

  test("a trailing comment on the condition line contributes nothing", () => {
    const source = provider(`"${trustLine("c.yml")}" # ${trustLine("deploy-prod.yml")}`);
    expect(trusted(singleFile(source))).toEqual(["c.yml"]);
  });

  // `local.decoy` inside a CEL string is prose Terraform never evaluates.
  test("a decoy inside an unrelated local is not followed", () => {
    const source =
      `locals {\n  real  = "${trustLine("c.yml")}"\n  decoy = "${trustLine("deploy-prod.yml")}"\n}\n` +
      provider(`"${"${local.real}"} && assertion.ref == 'local.decoy'"`);
    expect(trusted(singleFile(source))).toEqual(["c.yml"]);
  });

  test("a condition defined in a second file of the same module is found", () => {
    const files = new Map([
      ["terraform/modules/bootstrap/main.tf", provider("local.condition")],
      ["terraform/modules/bootstrap/conditions.tf", `locals {\n  condition = "${trustLine("c.yml")}"\n}\n`],
    ]);
    expect(trusted(files)).toEqual(["c.yml"]);
  });

  test("a second provider block in another file is found and unioned", () => {
    const files = new Map([
      ["terraform/modules/bootstrap/main.tf", terraformTrusting("c.yml")],
      ["terraform/modules/other/main.tf", provider(`"${trustLine("d.yml")}"`)],
    ]);
    const trust = trustedWorkflowsFromTerraform(files);
    expect(trust.kind).toBe("trusted");
    if (trust.kind !== "trusted") return;
    expect([...trust.workflows].sort()).toEqual(["c.yml", "d.yml"]);
    expect(trust.providers).toHaveLength(2);
  });

  test("locals are module-scoped", () => {
    const files = new Map([
      ["terraform/modules/a/main.tf", provider("local.condition")],
      ["terraform/modules/b/main.tf", `locals {\n  condition = "${trustLine("c.yml")}"\n}\n`],
    ]);
    expect(trustFailures(files)).toContain(
      "terraform/modules/a/main.tf: google_iam_workload_identity_pool_provider.github references local.condition, which no locals block in terraform/modules/a defines",
    );
  });

  test("references are followed through nested locals, interpolation and both branches of a conditional", () => {
    const source =
      `locals {\n  a = "${trustLine("c.yml")}"\n  b = join(" || ", [\n    "(${"${local.a}"})",\n    "${legacyTrustLine("d.yml")}",\n  ])\n` +
      `  exact  = "x && (${"${local.b}"})"\n  legacy = "${trustLine("e.yaml")}"\n` +
      `  chosen = var.legacy ? local.legacy : local.exact\n}\n` +
      provider("local.chosen");
    expect(trusted(singleFile(source))).toEqual(["c.yml", "d.yml", "e.yaml"]);
  });

  test("a heredoc condition is read", () => {
    const source = provider(`<<-EOT\n    ${trustLine("c.yml")}\n  EOT`);
    expect(trusted(singleFile(source))).toEqual(["c.yml"]);
  });

  test("zero provider blocks fail rather than agreeing with nothing", () => {
    expect(trustFailures(singleFile(`locals {\n  condition = "${trustLine("c.yml")}"\n}\n`))).toContain(
      "no google_iam_workload_identity_pool_provider block was found",
    );
    expect(trustFailures(new Map())).toContain("no google_iam_workload_identity_pool_provider block was found");
  });

  test("a provider without a condition fails", () => {
    const source =
      `resource "google_iam_workload_identity_pool_provider" "open" {\n  workload_identity_pool_id = "github"\n` +
      `  description = "${trustLine("c.yml")}"\n}\n`;
    expect(trustFailures(singleFile(source))).toContain(
      "google_iam_workload_identity_pool_provider.open has no attribute_condition",
    );
  });

  test("a condition naming no workflow fails", () => {
    expect(trustFailures(singleFile(provider("\"assertion.repository == 'x'\"")))).toContain(
      "names no workflow through assertion.job_workflow_ref",
    );
    expect(trustFailures(singleFile(provider("var.condition")))).toContain("names no workflow");
    expect(trustFailures(singleFile(provider("var.condition")))).toContain(
      "uses var.condition where its value could reach the condition text",
    );
  });

  test("an ambiguous local fails", () => {
    const source =
      `locals {\n  condition = "${trustLine("c.yml")}"\n}\nlocals {\n  condition = "${trustLine("d.yml")}"\n}\n` +
      provider("local.condition");
    expect(trustFailures(singleFile(source))).toContain("local.condition is defined more than once");
  });

  test("malformed HCL names the file and line", () => {
    expect(trustFailures(singleFile('locals {\n  a = "unterminated\n}\n'))).toContain(
      "terraform/modules/bootstrap/main.tf: unterminated string",
    );
    expect(trustFailures(singleFile("resource \"x\" \"y\" {\n  a = 1\n"))).toContain("unclosed block resource at line 1");
  });
});

describe("the effective condition must be read in full", () => {
  const hole = (body: string) => "${" + body + "}";

  // One recognisable clause used to satisfy the cross-check for the whole
  // condition; every clause beside it must now be read, or the provider fails.
  test.each([
    ["a prefix that stops short of a file name", "assertion.job_workflow_ref.startsWith('collinbentley1/platform/.github/workflows/')"],
    ["another repository", foreign],
    ["a membership test", "assertion.job_workflow_ref in ['collinbentley1/platform/.github/workflows/deploy-prod.yml@x']"],
    ["an indexed spelling", "assertion['job_workflow_ref'] == 'x'"],
    ["a reversed comparison", "'collinbentley1/platform/.github/workflows/deploy-prod.yml@' + assertion.job_workflow_sha == assertion.job_workflow_ref"],
  ])("a reviewed clause does not vouch for %s beside it", (_label, clause) => {
    const out = trustFailures(singleFile(provider(`"${trustLine("deploy-prod.yml")} || ${clause}"`)));
    expect(out).toContain(
      "attribute_condition (terraform/modules/bootstrap/main.tf line 3) uses job_workflow_ref in a form the inventory does not read",
    );
  });

  test.each([
    ["a prefix that stops short of a file name", "assertion.job_workflow_ref.startsWith('collinbentley1/platform/.github/workflows/')"],
    ["another repository", foreign],
    ["another attribute", "assertion.sub.startsWith('repo:collinbentley1/platform:')"],
  ])("startsWith on %s is refused", (_label, call) => {
    expect(trustFailures(singleFile(provider(`"${trustLine("c.yml")} || ${call}"`)))).toContain(
      "calls startsWith outside the legacy trust form",
    );
  });

  test("the message quotes the clause that could not be read", () => {
    const out = trustFailures(singleFile(provider(`"${trustLine("deploy-prod.yml")} || ${foreign}"`)));
    expect(out).toContain("attacker-org/backdoor/.github/workflows/pwn.yml@");
  });

  test("a presence check on job_workflow_ref is read, not refused", () => {
    expect(trusted(singleFile(provider(`"has(assertion.job_workflow_ref) && ${trustLine("c.yml")}"`)))).toEqual(["c.yml"]);
  });

  test("an interpolated workflow name is not a name the inventory can read", () => {
    const source =
      `locals {\n  n = "deploy-prod"\n}\n` +
      provider(
        `"assertion.job_workflow_ref == 'collinbentley1/platform/.github/workflows/${hole("local.n")}.yml@' + assertion.job_workflow_sha"`,
      );
    expect(trustFailures(singleFile(source))).toContain("uses job_workflow_ref in a form the inventory does not read");
  });

  test("a template directive is refused whatever it would expand to", () => {
    const source =
      `locals {\n  names = ["deploy-prod"]\n}\n` +
      provider(
        `"${trustLine("c.yml")}%{ for w in local.names } || assertion.job_workflow_ref.startsWith('collinbentley1/platform/.github/workflows/${hole("w")}.yml@')%{ endfor }"`,
      );
    const out = trustFailures(singleFile(source));
    expect(out).toContain("contains the template directive");
    expect(out).toContain(`interpolates ${hole("w")} where it cannot be bounded`);
  });

  test("a variable spliced as a clause is refused", () => {
    const out = trustFailures(singleFile(provider(`"${trustLine("c.yml")} || (${hole("var.extra_condition")})"`)));
    expect(out).toContain(
      `interpolates ${hole("var.extra_condition")} where it cannot be bounded: a value from outside the module is admitted only as the whole of a single-quoted CEL literal`,
    );
  });

  test("an escaped template sequence is refused", () => {
    const escaped = "$" + hole("true");
    expect(trustFailures(singleFile(provider(`"${trustLine("c.yml")} || ${escaped}"`)))).toContain(
      "contains the escaped template sequence",
    );
  });

  test("a bare variable, an unreadable reference and a rewriting call are each refused", () => {
    const locals = `locals {\n  real = "${trustLine("c.yml")}"\n}\n`;
    expect(trustFailures(singleFile(locals + provider(`join(" || ", ["${hole("local.real")}", var.extra])`)))).toContain(
      "uses var.extra where its value could reach the condition text",
    );
    expect(
      trustFailures(singleFile(
        locals + provider(`join(" || ", ["${hole("local.real")}", data.google_secret_manager_secret_version.extra.secret_data])`),
      )),
    ).toContain("references data.google_secret_manager_secret_version.extra.secret_data, which the inventory cannot follow");
    expect(trustFailures(singleFile(locals + provider(`replace(local.real, "platform", "backdoor")`)))).toContain(
      "calls replace(...), which can change the condition after it was read",
    );
  });

  test("residue inside a followed local names the local, its file and its line", () => {
    const files = new Map([
      ["terraform/modules/bootstrap/main.tf", provider("local.condition")],
      ["terraform/modules/bootstrap/conditions.tf", `locals {\n  condition = "${trustLine("c.yml")} || ${foreign}"\n}\n`],
    ]);
    expect(trustFailures(files)).toContain(
      "terraform/modules/bootstrap/main.tf: google_iam_workload_identity_pool_provider.github: local.condition (terraform/modules/bootstrap/conditions.tf line 2) uses job_workflow_ref",
    );
  });

  // The live module splices the numeric owner and repository IDs and the
  // trusted commit SHAs from variables. Each is admitted only because its
  // validation pins it to an alphanumeric alphabet, and only as the whole of
  // one single-quoted literal.
  const pinnedVariables =
    `variable "owner" {\n  type = string\n\n  validation {\n    condition     = can(regex("^[1-9][0-9]*$", var.owner))\n    error_message = "x"\n  }\n}\n` +
    `variable "shas" {\n  type = set(string)\n\n  validation {\n    condition = (\n      length(var.shas) > 0 &&\n` +
    `      alltrue([for sha in var.shas : can(regex("^[0-9a-f]{40}$", sha))])\n    )\n    error_message = "x"\n  }\n}\n`;
  const shaLoop = (result: string) => `  shas = join(" || ", [\n    for sha in sort(tolist(var.shas)) : ${result}\n  ])\n`;
  const shaLiteral = `"assertion.job_workflow_sha == '${hole("sha")}'"`;
  const pinnedCondition =
    `locals {\n${shaLoop(shaLiteral)}` +
    `  condition = "assertion.repository_owner_id == '${hole("var.owner")}' && (${hole("local.shas")}) && (${trustLine("c.yml")})"\n}\n`;

  test("a pinned variable spliced as one literal is admitted, from its own file", () => {
    expect(trusted(new Map([
      ["terraform/modules/bootstrap/main.tf", pinnedCondition + provider("local.condition")],
      ["terraform/modules/bootstrap/variables.tf", pinnedVariables],
    ]))).toEqual(["c.yml"]);
  });

  test("a variable that chooses a branch or is counted contributes no text", () => {
    const source =
      pinnedVariables +
      `locals {\n  a = "${trustLine("c.yml")}"\n  b = "${trustLine("d.yml")}"\n  chosen = var.flag ? local.a : local.b\n` +
      `  counted = length(var.shas) == 0 ? local.a : local.chosen\n}\n` +
      provider("local.counted");
    expect(trusted(singleFile(source))).toEqual(["c.yml", "d.yml"]);
  });

  // The live module chooses `"false"` when a transition set is empty. Wired
  // into the provider, that branch is a bare literal and is refused, and the
  // message names the choice that led to it.
  test("a conditional branch that is a boolean literal is refused, and the choice is named", () => {
    const source =
      pinnedVariables +
      `locals {\n  a = "${trustLine("c.yml")}"\n  counted = length(var.shas) == 0 ? "false" : local.a\n}\n` +
      provider("local.counted");
    expect(trustFailures(singleFile(source))).toContain(
      "when length(var.shas) == 0 is true, the condition uses the boolean literal false as an operand",
    );
  });

  test.each([
    ["no validation", `variable "owner" {\n  type = string\n}\n`, "var.owner has no validation that pins it"],
    [
      "a regex that could admit a quote",
      `variable "owner" {\n  type = string\n  validation {\n    condition     = can(regex("^.*$", var.owner))\n    error_message = "x"\n  }\n}\n`,
      "var.owner has no validation that pins it",
    ],
    [
      "a pin weakened by ||",
      `variable "owner" {\n  type = string\n  validation {\n    condition     = can(regex("^[0-9]+$", var.owner)) || true\n    error_message = "x"\n  }\n}\n`,
      "var.owner has no validation that pins it",
    ],
    [
      "a negated pin",
      `variable "owner" {\n  type = string\n  validation {\n    condition     = !can(regex("^[0-9]+$", var.owner))\n    error_message = "x"\n  }\n}\n`,
      "var.owner has no validation that pins it",
    ],
    [
      "a pin on a different variable",
      `variable "owner" {\n  type = string\n  validation {\n    condition     = can(regex("^[0-9]+$", var.other))\n    error_message = "x"\n  }\n}\n`,
      "var.owner has no validation that pins it",
    ],
    ["no declaration at all", "", "var.owner is not declared in this module"],
    [
      "two declarations",
      `variable "owner" {\n  type = string\n}\nvariable "owner" {\n  type = string\n}\n`,
      "var.owner is declared more than once",
    ],
  ])("a spliced variable with %s is refused", (_label, declaration, message) => {
    const source = declaration + provider(`"assertion.repository_owner_id == '${hole("var.owner")}' && ${trustLine("c.yml")}"`);
    expect(trustFailures(singleFile(source))).toContain(message);
  });

  test("a pinned value is admitted only as the whole of one literal", () => {
    const source = pinnedVariables +
      provider(`"assertion.repository_owner_id == 'id-${hole("var.owner")}' && ${trustLine("c.yml")}"`);
    expect(trustFailures(singleFile(source))).toContain("admitted only as the whole of a single-quoted CEL literal");
  });

  test("an iterator is read only over a pinned collection and only inside a literal", () => {
    const conditionOf = (locals: string) => locals + provider(`"(${hole("local.shas")}) && ${trustLine("c.yml")}"`);
    expect(
      trustFailures(singleFile(conditionOf(`variable "shas" {\n  type = set(string)\n}\nlocals {\n${shaLoop(shaLiteral)}}\n`))),
    ).toContain("sha iterates over var.shas, and var.shas has no validation that pins it");
    expect(trustFailures(singleFile(conditionOf(pinnedVariables + `locals {\n${shaLoop("sha")}}\n`)))).toContain(
      "uses the iterator sha outside a single-quoted CEL literal",
    );
    expect(
      trustFailures(singleFile(conditionOf(`locals {\n  list = []\n  shas = join(" || ", [for sha in local.list : ${shaLiteral}])\n}\n`))),
    ).toContain('iterates over "local.list", which is not one variable inside list-shaping calls');
  });
});

describe("the effective condition is bounded by its boolean structure", () => {
  const hole = (body: string) => "${" + body + "}";
  const exact = trustLine("deploy-prod.yml");
  const widened = (clause: string) => trustFailures(singleFile(provider(`"${exact} || ${clause}"`)));

  // The demonstrated fail-open: a clause that mentions nothing the fragment
  // scan refuses, joined with || to a reviewed clause, admits every token the
  // issuer signs, and the lint used to exit 0 for it.
  test.each([
    ["true", "true"],
    ["false", "false"],
    ["another claim", "assertion.repository == 'x'"],
    ["a tautology", "(1 == 1)"],
    ["a presence check", "has(assertion.job_workflow_ref)"],
    ["a negation", "!has(assertion.environment)"],
  ])("|| %s beside a reviewed clause is refused", (_label, clause) => {
    expect(widened(clause)).toContain(
      `admits a token from any workflow through the || operand ${JSON.stringify(clause.replace(/^\((.*)\)$/, "$1"))}`,
    );
  });

  test.each(["true", "false"])("the literal %s is refused wherever it stands", (literal) => {
    expect(widened(literal)).toContain(`uses the boolean literal ${literal} as an operand`);
    // Beside a conjunct that binds, the disjunction admits nothing extra,
    // and the literal is refused all the same.
    expect(trustFailures(singleFile(provider(`"${exact} && (${trustLine("c.yml")} || ${literal})"`)))).toContain(
      `uses the boolean literal ${literal} as an operand`,
    );
    expect(trustFailures(singleFile(provider(`"${exact} && assertion.ref == 'x' == ${literal}"`)))).toContain(
      `uses the boolean literal ${literal} inside the operand`,
    );
  });

  test("a || true nested inside parentheses is refused where no conjunct beside it binds", () => {
    expect(trustFailures(singleFile(provider(`"has(assertion.job_workflow_ref) && (${exact} || true)"`)))).toContain(
      'admits a token from any workflow through the || operand "true"',
    );
  });

  // CEL reads `T == false` as `(T) == false`: the reviewed clause, negated,
  // with every token it names satisfying the fragment scan.
  test("a trust form inside a larger comparison is a negation in disguise", () => {
    expect(trustFailures(singleFile(provider(`"${exact} == false"`)))).toContain(
      "is not a recognised trust form read as a whole operand",
    );
  });

  test("a name mentioned only inside a larger operand is not a trust, even beside a conjunct that binds", () => {
    const out = trustFailures(singleFile(provider(`"${exact} && (${trustLine("c.yml")}) == has(assertion.environment)"`)));
    expect(out).toContain("compares job_workflow_ref to c.yml only inside a larger operand");
  });

  test("a disjunction of whole trust forms is bounded", () => {
    expect(trusted(singleFile(provider(`"${exact} || ${trustLine("c.yml")} || ${legacyTrustLine("d.yml")}"`)))).toEqual([
      "c.yml",
      "d.yml",
      "deploy-prod.yml",
    ]);
  });

  test("each || operand may be a conjunction that opens with a trust form", () => {
    const source = provider(
      `"(${exact} && assertion.event_name == 'push') || (${trustLine("c.yml")} && (assertion.ref == 'a' || assertion.ref == 'b'))"`,
    );
    expect(trusted(singleFile(source))).toEqual(["c.yml", "deploy-prod.yml"]);
  });

  // The live SHA disjunction names no workflow. It is admitted because it is
  // a conjunct, and refused the moment it becomes an alternative.
  test("a disjunction naming no workflow is admitted as a conjunct and refused as an alternative", () => {
    const shas = "(assertion.job_workflow_sha == 'a' || assertion.job_workflow_sha == 'b')";
    expect(trusted(singleFile(provider(`"${shas} && ${exact}"`)))).toEqual(["deploy-prod.yml"]);
    expect(trustFailures(singleFile(provider(`"${shas} || ${exact}"`)))).toContain(
      `admits a token from any workflow through the || operand "assertion.job_workflow_sha == 'a' || assertion.job_workflow_sha == 'b'"`,
    );
  });

  test("a negation is admitted as a conjunct", () => {
    const source = provider(`"${exact} && !has(assertion.environment) && (!has(assertion.ref) || assertion.ref == 'x')"`);
    expect(trusted(singleFile(source))).toEqual(["deploy-prod.yml"]);
  });

  test("a conditional binds only when both branches do", () => {
    const chosen = (otherwise: string) => provider(`"assertion.event_name == 'push' ? ${exact} : ${otherwise}"`);
    expect(trusted(singleFile(chosen(trustLine("c.yml"))))).toEqual(["c.yml", "deploy-prod.yml"]);
    expect(trustFailures(singleFile(chosen("has(assertion.job_workflow_ref)")))).toContain(
      'admits a token from any workflow through the conditional branch "has(assertion.job_workflow_ref)"',
    );
  });

  test("the structure names the workflows of its whole-operand trust forms", () => {
    const out = conditionStructure(
      `has(assertion.job_workflow_ref) && ((${exact} && assertion.ref == 'x') || ${legacyTrustLine("c.yml")})`,
    );
    expect(out.kind).toBe("bounded");
    if (out.kind !== "bounded") return;
    expect([...out.names].sort()).toEqual(["c.yml", "deploy-prod.yml"]);
  });

  // A CEL comment hides the rest of the line from CEL but not from a split
  // on operators: `T || x // && T2` is `T || x` to CEL. Every lexical form the
  // reader does not follow refuses the condition rather than being split.
  test.each([
    ["a CEL comment", `${exact} || assertion.repository == 'x' // && ${trustLine("c.yml")}`, "hides the rest of the line from CEL"],
    ["a prefixed string literal", `${exact} && assertion.ref == r'x'`, "the prefixed string literal"],
    ["a triple-quoted string literal", `${exact} && assertion.ref == '''x'''`, "the triple-quoted string literal"],
    ["an unterminated string literal", `${exact} && assertion.ref == 'x`, "is unterminated"],
    ["adjacent string literals", `${exact} && assertion.ref == 'x''y'`, "is followed directly by another"],
    ["a single |", `${exact} | true`, "a single | in"],
    ["unbalanced brackets", `(${exact}`, "do not balance"],
    ["a ? without :", `assertion.ref == 'x' ? ${exact}`, "has no matching :"],
    ["a : without ?", `${exact} : true`, "has no ?"],
    ["an empty operand", `${exact} && ()`, "an operand is empty"],
  ])("%s cannot be decomposed and is refused", (_label, condition, message) => {
    const out = conditionStructure(condition);
    expect(out.kind).toBe("unbounded");
    if (out.kind !== "unbounded") return;
    expect(out.failures.join(" ")).toContain("cannot be decomposed");
    expect(out.failures.join(" ")).toContain(message);
  });

  // The HCL that builds the condition is rendered only in the shapes the
  // bootstrap module uses; a shape the renderer does not know refuses the
  // provider even when every fragment read clean.
  test.each([
    ["an HCL comparison around a string", `"${exact}" == "x"`, "is an expression around a string"],
    ["a join over a computed list", `join(" || ", concat(["${exact}"], ["x"]))`, "joins something other than a list literal"],
    ["a join with a chosen separator", `join(local.sep, ["${exact}"])`, "separator that is not one literal string"],
  ])("%s is not rendered", (_label, condition, message) => {
    const locals = `locals {\n  sep = var.flag ? " || " : " && "\n}\n`;
    expect(trustFailures(singleFile(locals + provider(condition)))).toContain(message);
  });

  test("a for over a collection that may be empty is rendered empty as well", () => {
    const regexOnly =
      `variable "shas" {\n  type = set(string)\n\n  validation {\n` +
      `    condition     = alltrue([for sha in var.shas : can(regex("^[0-9a-f]{40}$", sha))])\n    error_message = "x"\n  }\n}\n`;
    const shas =
      `locals {\n  shas = join(" || ", [\n    for sha in sort(tolist(var.shas)) : "assertion.job_workflow_sha == '${hole("sha")}'"\n  ])\n}\n`;
    expect(trustFailures(singleFile(regexOnly + shas + provider(`"(${hole("local.shas")}) && ${exact}"`)))).toContain(
      "when var.shas is empty, the condition cannot be decomposed: an operand is empty",
    );
  });
});

describe("the inventory fails closed on drift", () => {
  const declared = { cloudAuthority: ["c.yml"], neither: ["n.yml"], ownerCredential: [] as string[] };
  const terraform = singleFile(terraformTrusting("c.yml"));

  test("a clean set passes", () => {
    expect(validateWorkflowAuthorityInventory({
      declared,
      terraform,
      workflows: new Map([["c.yml", cloud], ["n.yml", neither]]),
    })).toEqual([]);
  });

  test("an undeclared new workflow fails and its derived flags are shown", () => {
    const out = validateWorkflowAuthorityInventory({
      declared,
      terraform,
      workflows: new Map([["c.yml", cloud], ["n.yml", neither], ["new.yaml", owner]]),
    });
    const joined = out.join(" ");
    expect(joined).toContain(".github/workflows/new.yaml is not declared");
    expect(joined).toContain("its source shows owner-credential");
    expect(joined).toContain("reads owner credential: yes");
  });

  test("a workflow silently gaining cloud authority fails", () => {
    const out = validateWorkflowAuthorityInventory({
      declared,
      terraform,
      workflows: new Map([["c.yml", cloud], ["n.yml", cloud]]),
    });
    expect(out.join(" ")).toContain(".github/workflows/n.yml is declared neither but its source shows cloud-authority");
  });

  test("a workflow silently gaining the owner credential fails", () => {
    const out = validateWorkflowAuthorityInventory({
      declared,
      terraform,
      workflows: new Map([["c.yml", cloud], ["n.yml", owner]]),
    });
    expect(out.join(" ")).toContain(".github/workflows/n.yml is declared neither but its source shows owner-credential");
  });

  test("a declared cloud workflow that mints nothing fails", () => {
    const out = validateWorkflowAuthorityInventory({
      declared,
      terraform,
      workflows: new Map([["c.yml", neither], ["n.yml", neither]]),
    });
    expect(out.join(" ")).toContain(".github/workflows/c.yml is declared cloud-authority but its source shows neither");
  });

  test("GitHub writes on a neither workflow are recorded but not a violation", () => {
    const writes = withJob("    permissions:\n      contents: write\n    steps:\n      - run: echo x\n");
    expect(validateWorkflowAuthorityInventory({
      declared,
      terraform,
      workflows: new Map([["c.yml", cloud], ["n.yml", writes]]),
    })).toEqual([]);
  });

  test("cloud authority without a Terraform trust fails", () => {
    const out = validateWorkflowAuthorityInventory({
      declared,
      terraform: singleFile(terraformTrusting("other.yml")),
      workflows: new Map([["c.yml", cloud], ["n.yml", neither]]),
    });
    expect(out.join(" ")).toContain("without a Terraform trust condition: c.yml");
  });

  test("a stale Terraform trust fails", () => {
    const out = validateWorkflowAuthorityInventory({
      declared,
      terraform: singleFile(terraformTrusting("c.yml", "gone.yml")),
      workflows: new Map([["c.yml", cloud], ["n.yml", neither]]),
    });
    expect(out.join(" ")).toContain("do not mint cloud credentials: gone.yml");
  });

  test("a Terraform trust of the wrong extension is stale and missing at once", () => {
    const out = validateWorkflowAuthorityInventory({
      declared,
      terraform: singleFile(terraformTrusting("c.yaml")),
      workflows: new Map([["c.yml", cloud], ["n.yml", neither]]),
    }).join(" ");
    expect(out).toContain("without a Terraform trust condition: c.yml");
    expect(out).toContain("do not mint cloud credentials: c.yaml");
  });

  test("invalid Terraform fails rather than agreeing with nothing", () => {
    const out = validateWorkflowAuthorityInventory({
      declared,
      terraform: singleFile("# no provider here\n"),
      workflows: new Map([["c.yml", cloud], ["n.yml", neither]]),
    });
    expect(out.join(" ")).toContain("cannot be cross-checked");
  });

  test("an empty workflow set fails", () => {
    expect(validateWorkflowAuthorityInventory({ declared, terraform, workflows: new Map() }).join(" "))
      .toContain("found no workflows");
  });

  test("a declared workflow that no longer exists fails", () => {
    expect(validateWorkflowAuthorityInventory({
      declared,
      terraform,
      workflows: new Map([["c.yml", cloud]]),
    }).join(" ")).toContain("n.yml, which does not exist");
  });

  test("a workflow declared twice fails", () => {
    expect(validateWorkflowAuthorityInventory({
      declared: { cloudAuthority: ["c.yml"], neither: ["c.yml"], ownerCredential: [] },
      terraform,
      workflows: new Map([["c.yml", cloud]]),
    }).join(" ")).toContain("declares c.yml in more than one set");
  });
});

// The wiring itself is under test here: each hostile fixture is dropped into
// a copy of the repository and the real lint entrypoint is run against it.
describe("the lint entrypoint refuses hostile workflow entries", () => {
  async function lintCopy(
    mutate: (copy: string) => Promise<void>,
  ): Promise<{ readonly exitCode: number; readonly output: string }> {
    const copy = await temporaryRoot("platform-authority-lint-");
    for (const entry of await readdir(root)) {
      if (entry === ".git" || entry === "node_modules") continue;
      await cp(join(root, entry), join(copy, entry), { recursive: true });
    }
    await mutate(copy);
    const child = Bun.spawn([process.execPath, "run", "tools/lint.ts"], {
      cwd: copy,
      stderr: "pipe",
      stdout: "pipe",
    });
    const [stdout, stderr] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    return { exitCode: await child.exited, output: `${stdout}${stderr}` };
  }

  // Without this, every failure below could be the copy itself being broken.
  test("the copied repository lints clean", async () => {
    const result = await lintCopy(async () => {});
    expect(result.output).toBe("");
    expect(result.exitCode).toBe(0);
  }, 30_000);

  test("a .yaml workflow with owner authority fails", async () => {
    const result = await lintCopy(async (copy) => {
      await writeFile(join(copy, ".github/workflows/hostile.yaml"), owner);
    });
    expect(result.exitCode).not.toBe(0);
    expect(result.output).toContain(".github/workflows/hostile.yaml is not declared in the workflow authority inventory");
    expect(result.output).toContain("its source shows owner-credential");
    expect(result.output).toContain(".github/workflows/hostile.yaml is not covered by the platform workflow lint set");
  }, 30_000);

  test("a symbolically linked workflow fails", async () => {
    const result = await lintCopy(async (copy) => {
      await symlink("deploy-prod.yml", join(copy, ".github/workflows/linked.yml"));
    });
    expect(result.exitCode).not.toBe(0);
    expect(result.output).toContain(".github/workflows/linked.yml is a symbolic link");
  }, 30_000);

  test("a non-regular workflow entry fails without being read", async () => {
    const result = await lintCopy(async (copy) => {
      expect(await Bun.spawn(["mkfifo", join(copy, ".github/workflows/pipe.yml")]).exited).toBe(0);
    });
    expect(result.exitCode).not.toBe(0);
    expect(result.output).toContain(".github/workflows/pipe.yml is a FIFO");
  }, 30_000);

  test("a symbolically linked Terraform file fails", async () => {
    const result = await lintCopy(async (copy) => {
      await symlink("main.tf", join(copy, "terraform/deployments/prod/linked.tf"));
    });
    expect(result.exitCode).not.toBe(0);
    expect(result.output).toContain("terraform/deployments/prod/linked.tf is a symbolic link");
  }, 30_000);

  // The fixture, and nothing else, must be what fails the copy: every line
  // of output has to be about the provider the fixture added.
  function expectOnlyFindingsAbout(output: string, subject: string): void {
    const lines = output.split("\n").filter((line) => line.trim() !== "");
    expect(lines.length).toBeGreaterThan(0);
    for (const line of lines) expect(line).toContain(subject);
  }

  // The demonstrated fail-opens: each of these providers carries the reviewed
  // exact clause beside a clause the inventory could not read, or beside one
  // that widens the trust without mentioning job_workflow_ref at all, and the
  // lint used to exit 0 for every one of them.
  const platformPath = "collinbentley1/platform/.github/workflows/";
  test.each([
    [
      "a widening clause with no job_workflow_ref",
      extraProvider(`"${trustLine("deploy-prod.yml")} || true"`),
      'admits a token from any workflow through the || operand "true"',
    ],
    [
      "a widening clause on another claim",
      extraProvider(`"${trustLine("deploy-prod.yml")} || assertion.repository == 'x'"`),
      "admits a token from any workflow through the || operand \"assertion.repository == 'x'\"",
    ],
    [
      "a prefix that stops short of a file name",
      extraProvider(`"${trustLine("deploy-prod.yml")} || assertion.job_workflow_ref.startsWith('${platformPath}')"`),
      "calls startsWith outside the legacy trust form",
    ],
    ["another repository", foreignProvider, "attacker-org/backdoor/.github/workflows/pwn.yml@"],
    [
      "an interpolated workflow name",
      extraProvider(
        `"assertion.job_workflow_ref == '${platformPath}$` + `{local.extra_name}.yml@' + assertion.job_workflow_sha"`,
        `locals {\n  extra_name = "deploy-prod"\n}\n`,
      ),
      "uses job_workflow_ref in a form the inventory does not read",
    ],
    [
      "a template directive",
      extraProvider(
        `"${trustLine("deploy-prod.yml")}%{ for w in local.extra_names } || assertion.job_workflow_ref.startsWith('${platformPath}$` +
          `{w}.yml@')%{ endfor }"`,
        `locals {\n  extra_names = ["deploy-prod"]\n}\n`,
      ),
      "contains the template directive",
    ],
    [
      "a variable spliced as a clause",
      extraProvider(`"${trustLine("deploy-prod.yml")} || ($` + `{var.extra_condition})"`),
      "interpolates ${var.extra_condition} where it cannot be bounded",
    ],
  ])("a second provider admitting %s beside a reviewed clause fails", async (_label, source, message) => {
    const result = await lintCopy(async (copy) => {
      await writeFile(join(copy, "terraform/deployments/prod/extra.tf"), source);
    });
    expect(result.exitCode).not.toBe(0);
    expect(result.output).toContain(message);
    expectOnlyFindingsAbout(result.output, "terraform/deployments/prod/extra.tf: google_iam_workload_identity_pool_provider.extra");
  }, 30_000);

  // A provider with no condition trusts every token the issuer signs, and
  // outside terraform/ it used to be invisible.
  test("a provider outside terraform/ is found", async () => {
    const result = await lintCopy(async (copy) => {
      await mkdir(join(copy, "infra"), { recursive: true });
      await writeFile(join(copy, "infra/wif.tf"), openProvider);
    });
    expect(result.exitCode).not.toBe(0);
    expect(result.output).toContain(
      "infra/wif.tf: google_iam_workload_identity_pool_provider.extra has no attribute_condition",
    );
    expectOnlyFindingsAbout(result.output, "infra/wif.tf: google_iam_workload_identity_pool_provider.extra");
  }, 30_000);

  // A stray entry used to suppress the authority check outright: the run
  // failed for the stray file and said nothing about the workflow beside it.
  test("a stray entry does not hide an authority finding about its neighbour", async () => {
    const result = await lintCopy(async (copy) => {
      await writeFile(join(copy, ".github/workflows/notes.txt"), "not a workflow\n");
      await writeFile(join(copy, ".github/workflows/hostile.yaml"), owner);
    });
    expect(result.exitCode).not.toBe(0);
    expect(result.output).toContain(".github/workflows/notes.txt is not a workflow");
    expect(result.output).toContain(".github/workflows/hostile.yaml is not declared in the workflow authority inventory");
    expect(result.output).toContain("its source shows owner-credential");
  }, 30_000);
});
