import { describe, expect, test } from "bun:test";
import { readFile, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  classifyWorkflowAuthority,
  declaredWorkflowAuthority,
  trustedWorkflowsFromTerraform,
  validateWorkflowAuthorityInventory,
} from "../tools/ci/workflow-authority-contract";

const root = resolve(import.meta.dir, "..");

async function liveWorkflows(): Promise<Map<string, string>> {
  const directory = join(root, ".github/workflows");
  const names = (await readdir(directory)).filter((name) => name.endsWith(".yml"));
  const sources = new Map<string, string>();
  for (const name of names) {
    sources.set(name, await readFile(join(directory, name), "utf8"));
  }
  return sources;
}

const terraform = await readFile(join(root, "terraform/modules/bootstrap/main.tf"), "utf8");

describe("the live inventory agrees with the declaration", () => {
  test("every workflow on disk classifies as declared", async () => {
    expect(validateWorkflowAuthorityInventory({
      bootstrapTerraform: terraform,
      workflows: await liveWorkflows(),
    })).toEqual([]);
  });

  test("Terraform trusts exactly the cloud-authority workflows", () => {
    expect([...trustedWorkflowsFromTerraform(terraform)].sort())
      .toEqual([...declaredWorkflowAuthority.cloudAuthority].sort());
  });

  // The whole point of the exercise: this workflow moves branches and opens
  // pull requests with GITHUB_TOKEN and holds no cloud or owner authority.
  test("bun-dependency-update.yml is outside the privileged set", async () => {
    const source = (await liveWorkflows()).get("bun-dependency-update.yml");
    expect(source).toBeString();
    expect(classifyWorkflowAuthority(source ?? "")).toBe("neither");
    expect(declaredWorkflowAuthority.neither).toContain("bun-dependency-update.yml");
  });
});

// A bare word "secrets" in a shell command is not a credential reference, and
// treating it as one would classify half the fleet as owner-credential.
describe("classification reads expressions, not text", () => {
  const base = (extra: string) =>
    `name: t\non: [push]\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n    steps:\n${extra}`;

  test("shell text mentioning secrets stays unprivileged", () => {
    expect(classifyWorkflowAuthority(base(
      "      - run: |\n          gcloud secrets versions list\n          secret_args=(--clear-secrets)\n",
    ))).toBe("neither");
  });

  test("an allowlisted literal secret does not imply owner authority", () => {
    expect(classifyWorkflowAuthority(base(
      "      - run: echo x\n        env:\n          T: ${{ secrets.DHI_PUBLIC_READ_TOKEN_20260822_098DCA9280B3 }}\n",
    ))).toBe("neither");
  });

  test.each([
    ["the owner token by name", "          T: ${{ secrets.OWNER_OAUTH_ACCESS_TOKEN }}\n"],
    ["an unlisted secret", "          T: ${{ secrets.SOMETHING_NEW }}\n"],
    ["dynamic indexing", "          T: ${{ secrets['OWNER_OAUTH_ACCESS_TOKEN'] }}\n"],
    ["whole-context serialisation", "          T: ${{ toJSON(secrets) }}\n"],
  ])("%s is owner-credential", (_label, env) => {
    expect(classifyWorkflowAuthority(base(`      - run: echo x\n        env:\n${env}`)))
      .toBe("owner-credential");
  });

  test("binding to the owner-token environment is authority on its own", () => {
    expect(classifyWorkflowAuthority(
      "name: t\non: [push]\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    environment: protected-bootstrap-owner-token\n    steps:\n      - run: echo x\n",
    )).toBe("owner-credential");
  });

  test("a secrets passthrough is owner-credential", () => {
    expect(classifyWorkflowAuthority(
      "name: t\non: [push]\npermissions: {}\njobs:\n  a:\n    uses: ./.github/workflows/x.yml\n    secrets: inherit\n",
    )).toBe("owner-credential");
  });

  test("unparseable YAML fails closed", () => {
    expect(classifyWorkflowAuthority("name: [unclosed\n  : :")).toBe("owner-credential");
  });
});

describe("cloud authority is detected by several independent signals", () => {
  test.each([
    ["id-token: write on a job", "    permissions:\n      id-token: write\n    steps:\n      - run: echo x\n"],
    ["a google-github-actions step", "    permissions:\n      contents: read\n    steps:\n      - uses: google-github-actions/auth@abc\n"],
    ["a hand-rolled STS exchange", "    permissions:\n      contents: read\n    steps:\n      - run: curl https://sts.googleapis.com/v1/token\n"],
    ["a credentials file", "    permissions:\n      contents: read\n    steps:\n      - run: echo\n        env:\n          X: create_credentials_file\n"],
  ])("%s is cloud-authority", (_label, job) => {
    expect(classifyWorkflowAuthority(
      `name: t\non: [push]\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-24.04\n${job}`,
    )).toBe("cloud-authority");
  });

  test("write-all counts as id-token", () => {
    expect(classifyWorkflowAuthority(
      "name: t\non: [push]\npermissions: write-all\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo x\n",
    )).toBe("cloud-authority");
  });
});

describe("the inventory fails closed on drift", () => {
  const neither = "name: t\non: [push]\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n    steps:\n      - run: echo x\n";
  const cloud = "name: t\non: [push]\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    permissions:\n      id-token: write\n    steps:\n      - run: echo x\n";
  const declared = { cloudAuthority: ["c.yml"], neither: ["n.yml"], ownerCredential: [] as string[] };
  const tf = "condition = \"assertion.job_workflow_ref == 'collinbentley1/platform/.github/workflows/c.yml@' + assertion.job_workflow_sha\"";

  test("a clean set passes", () => {
    expect(validateWorkflowAuthorityInventory({
      bootstrapTerraform: tf,
      declared,
      workflows: new Map([["c.yml", cloud], ["n.yml", neither]]),
    })).toEqual([]);
  });

  test("an undeclared new workflow fails", () => {
    const out = validateWorkflowAuthorityInventory({
      bootstrapTerraform: tf,
      declared,
      workflows: new Map([["c.yml", cloud], ["n.yml", neither], ["new.yml", neither]]),
    });
    expect(out.join(" ")).toContain("new.yml is not declared");
  });

  test("a workflow silently gaining cloud authority fails", () => {
    const out = validateWorkflowAuthorityInventory({
      bootstrapTerraform: tf,
      declared,
      workflows: new Map([["c.yml", cloud], ["n.yml", cloud]]),
    });
    expect(out.join(" ")).toContain("declared neither but its source shows cloud-authority");
  });

  test("cloud authority without a Terraform trust fails", () => {
    const out = validateWorkflowAuthorityInventory({
      bootstrapTerraform: "condition = \"assertion.job_workflow_ref == 'collinbentley1/platform/.github/workflows/other.yml@' + x\"",
      declared,
      workflows: new Map([["c.yml", cloud], ["n.yml", neither]]),
    });
    expect(out.join(" ")).toContain("without a Terraform trust condition");
  });

  test("a stale Terraform trust fails", () => {
    const out = validateWorkflowAuthorityInventory({
      bootstrapTerraform: tf + "\ncondition = \"assertion.job_workflow_ref == 'collinbentley1/platform/.github/workflows/gone.yml@' + x\"",
      declared,
      workflows: new Map([["c.yml", cloud], ["n.yml", neither]]),
    });
    expect(out.join(" ")).toContain("do not mint cloud credentials");
  });

  test("no trust conditions at all fails rather than agreeing with nothing", () => {
    const out = validateWorkflowAuthorityInventory({
      bootstrapTerraform: "no conditions here",
      declared,
      workflows: new Map([["c.yml", cloud], ["n.yml", neither]]),
    });
    expect(out.join(" ")).toContain("cannot be cross-checked");
  });

  test("an empty workflow set fails", () => {
    expect(validateWorkflowAuthorityInventory({
      bootstrapTerraform: tf, declared, workflows: new Map(),
    }).join(" ")).toContain("found no workflows");
  });

  test("a declared workflow that no longer exists fails", () => {
    expect(validateWorkflowAuthorityInventory({
      bootstrapTerraform: tf, declared, workflows: new Map([["c.yml", cloud]]),
    }).join(" ")).toContain("does not exist");
  });
});
