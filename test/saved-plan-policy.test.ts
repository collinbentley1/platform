import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { evaluateSavedPlanPolicy } from "../tools/ci/saved-plan-policy";
import { manifestPath, parseWorkflowAuthority } from "../tools/ci/workflow-authority";

const repoRoot = resolve(import.meta.dir, "..");
const activeSha = "a".repeat(40);
const transitionSha = "b".repeat(40);
const projectNumber = "882468538648";
const repositoryId = "1255553151";
const pool = `projects/${projectNumber}/locations/global/workloadIdentityPools/github-actions`;
const expectation = {
  activeSha,
  approvedModules: ["module.bootstrap"],
  projectNumber,
  repositoryId,
  transitionSha: null,
} as const;

type Change = {
  address: string;
  change: { actions: string[]; after: Record<string, unknown> | null; after_unknown: unknown; before: unknown };
  index?: string;
  mode: "managed";
  module_address?: string;
  name: string;
  provider_name: string;
  type: string;
};

type Plan = {
  configuration: Record<string, unknown>;
  format_version: string;
  planned_values: { root_module: { child_modules: Array<Record<string, unknown>> } };
  resource_changes: Change[];
};

function resource(type: string, name: string, after: Record<string, unknown>, options: { actions?: string[]; afterUnknown?: unknown; index?: string; module?: string | null } = {}): Change {
  const module = options.module === undefined ? "module.bootstrap" : options.module;
  const suffix = options.index === undefined ? "" : `[${JSON.stringify(options.index)}]`;
  return {
    address: `${module ? `${module}.` : ""}${type}.${name}${suffix}`,
    change: { actions: options.actions ?? ["no-op"], after, after_unknown: options.afterUnknown ?? {}, before: after },
    ...(options.index === undefined ? {} : { index: options.index }),
    mode: "managed",
    ...(module ? { module_address: module } : {}),
    name,
    provider_name: "registry.terraform.io/hashicorp/google",
    type,
  };
}

// Built by hand from the manifest: the fixture's member strings are template
// literals, not the policy's own expansion, so the exact-set comparison is a
// real cross-check rather than a tautology.
async function bindings(transition: string | null): Promise<Change[]> {
  const manifest = JSON.parse(await readFile(join(repoRoot, manifestPath), "utf8")) as Array<{
    authority: string;
    path: string;
    serviceAccounts: string[];
    transitionEligible: boolean;
  }>;
  const changes: Change[] = [];
  for (const entry of manifest) {
    if (entry.authority !== "cloud") continue;
    for (const account of entry.serviceAccounts) {
      for (const sha of [activeSha, ...(transition && entry.transitionEligible ? [transition] : [])]) {
        const key = `${account}/${entry.path}@${sha}`;
        changes.push(
          resource(
            "google_service_account_iam_member",
            "workflow_authority",
            {
              member: `principalSet://iam.googleapis.com/${pool}/attribute.job_workflow_ref/collinbentley1/platform/${entry.path}@${sha}`,
              role: "roles/iam.workloadIdentityUser",
              service_account_id: `projects/cdbentley/serviceAccounts/${account}@cdbentley.iam.gserviceaccount.com`,
            },
            { actions: ["create"], afterUnknown: { etag: true, id: true }, index: key },
          ),
        );
      }
    }
  }
  return changes;
}

function provider(): Change {
  return resource("google_iam_workload_identity_pool_provider", "github", {
    attribute_condition: `assertion.repository_owner_id == '16823277' && assertion.repository_id == '${repositoryId}'`,
    attribute_mapping: {
      "attribute.job_workflow_ref": "assertion.job_workflow_ref",
      "attribute.repository_id": "assertion.repository_id",
      "google.subject": "assertion.repository_owner_id + ':' + assertion.repository_id + ':' + assertion.run_id",
    },
    aws: [],
    disabled: false,
    oidc: [{ allowed_audiences: [], issuer_uri: "https://token.actions.githubusercontent.com/" }],
    saml: [],
    workload_identity_pool_id: "github-actions",
    workload_identity_pool_provider_id: "github",
    x509: [],
  }, { afterUnknown: { oidc: [{}] } });
}

async function plan(transition: string | null = null): Promise<Plan> {
  return {
    configuration: {
      root_module: {
        module_calls: {
          bootstrap: {
            module: {
              resources: [
                { address: "google_service_account_iam_member.workflow_authority", mode: "managed", type: "google_service_account_iam_member" },
              ],
            },
            source: "../../modules/bootstrap",
          },
        },
      },
    },
    format_version: "1.2",
    planned_values: { root_module: { child_modules: [{ address: "module.bootstrap", resources: [] }] } },
    resource_changes: [
      resource("google_iam_workload_identity_pool", "github", {
        disabled: false,
        name: pool,
        workload_identity_pool_id: "github-actions",
      }),
      provider(),
      ...(await bindings(transition)),
      resource("google_service_account_iam_member", "prod_deploy_uses_runtime", {
        member: "serviceAccount:gha-prod-deploy@cdbentley.iam.gserviceaccount.com",
        role: "roles/iam.serviceAccountUser",
        service_account_id: "projects/cdbentley/serviceAccounts/cloud-run-runtime@cdbentley.iam.gserviceaccount.com",
      }),
      resource("google_service_account_iam_member", "preview_deploy_uses_preview_runtime", {
        member: "serviceAccount:gha-preview-deploy@cdbentley.iam.gserviceaccount.com",
        role: "roles/iam.serviceAccountUser",
        service_account_id: "projects/cdbentley/serviceAccounts/cloud-run-preview@cdbentley.iam.gserviceaccount.com",
      }),
      resource("google_project_iam_member", "terraform_convergence_reader", {
        member: "serviceAccount:gha-terraform@cdbentley.iam.gserviceaccount.com",
        role: "projects/cdbentley/roles/terraformConvergenceReader",
      }),
      resource("google_project_iam_binding", "editor_absent", { members: [], role: "roles/editor" }),
      resource("google_storage_bucket_iam_member", "terraform_state_access_logs_writer", {
        member: "group:cloud-storage-analytics@google.com",
        role: "roles/storage.objectCreator",
      }),
      resource("google_service_account_iam_member", "terraform_wif_workflow_sha", null as never, {
        actions: ["delete"],
        index: "c".repeat(40),
      }),
    ],
  };
}

async function failuresOf(mutate: (plan: Plan) => void = () => {}, transition: string | null = null): Promise<string[]> {
  const fixture = await plan(transition);
  mutate(fixture);
  const entries = parseWorkflowAuthority(await readFile(join(repoRoot, manifestPath), "utf8")).entries;
  return evaluateSavedPlanPolicy(fixture, entries, { ...expectation, transitionSha: transition });
}

function binding(fixture: Plan, key: string): Change {
  const change = fixture.resource_changes.find((candidate) => candidate.index === key);
  expect(change, key).toBeDefined();
  return change!;
}

describe("saved plan policy", () => {
  test("the reviewed bootstrap plan passes at active-only and active-plus-transition cardinalities", async () => {
    expect(await failuresOf()).toEqual([]);
    expect(await failuresOf(() => {}, transitionSha)).toEqual([]);
    const fixture = await plan(transitionSha);
    expect(fixture.resource_changes.filter((change) => change.name === "workflow_authority")).toHaveLength(26);
  });

  test("a malformed plan is refused outright", async () => {
    const entries = parseWorkflowAuthority(await readFile(join(repoRoot, manifestPath), "utf8")).entries;
    expect(evaluateSavedPlanPolicy({ format_version: "1.2" }, entries, expectation)).toEqual([
      "plan: must be terraform show -json output with format_version, resource_changes, planned_values, and configuration.",
    ]);
  });

  test("a missing, duplicated, or extra federated binding fails the exact set match", async () => {
    const key = `gha-terraform/.github/workflows/infrastructure.yml@${activeSha}`;
    expect(await failuresOf((fixture) => {
      fixture.resource_changes = fixture.resource_changes.filter((change) => change.index !== key);
    })).toEqual([
      `${key}: expected exactly one binding of principalSet://iam.googleapis.com/${pool}/attribute.job_workflow_ref/collinbentley1/platform/.github/workflows/infrastructure.yml@${activeSha}, found 0.`,
    ]);
    expect(await failuresOf((fixture) => {
      fixture.resource_changes.push({ ...binding(fixture, key), address: "module.bootstrap.google_service_account_iam_member.twin" });
    })).toEqual([`${key}: expected exactly one binding of principalSet://iam.googleapis.com/${pool}/attribute.job_workflow_ref/collinbentley1/platform/.github/workflows/infrastructure.yml@${activeSha}, found 2.`]);
    const rogue = `gha-prod-deploy/.github/workflows/cleanup-preview.yml@${activeSha}`;
    expect(await failuresOf((fixture) => {
      fixture.resource_changes.push(resource("google_service_account_iam_member", "workflow_authority", {
        member: `principalSet://iam.googleapis.com/${pool}/attribute.job_workflow_ref/collinbentley1/platform/.github/workflows/cleanup-preview.yml@${activeSha}`,
        role: "roles/iam.workloadIdentityUser",
        service_account_id: "projects/cdbentley/serviceAccounts/gha-prod-deploy@cdbentley.iam.gserviceaccount.com",
      }, { actions: ["create"], index: rogue }));
    })).toEqual([
      `module.bootstrap.google_service_account_iam_member.workflow_authority["${rogue}"]: federated binding is not in the workflow authority manifest.`,
    ]);
  });

  test("a transition binding on a workflow that is not transition-eligible fails", async () => {
    const key = `gha-prod-deploy/.github/workflows/deploy-prod.yml@${transitionSha}`;
    expect(await failuresOf((fixture) => {
      fixture.resource_changes.push(resource("google_service_account_iam_member", "workflow_authority", {
        member: `principalSet://iam.googleapis.com/${pool}/attribute.job_workflow_ref/collinbentley1/platform/.github/workflows/deploy-prod.yml@${transitionSha}`,
        role: "roles/iam.workloadIdentityUser",
        service_account_id: "projects/cdbentley/serviceAccounts/gha-prod-deploy@cdbentley.iam.gserviceaccount.com",
      }, { actions: ["create"], index: key }));
    }, transitionSha)).toEqual([
      `module.bootstrap.google_service_account_iam_member.workflow_authority["${key}"]: federated binding is not in the workflow authority manifest.`,
    ]);
  });

  test("authorization values that are unknown until apply are refused", async () => {
    const key = `gha-wif-canary/.github/workflows/deploy-prod.yml@${activeSha}`;
    const address = `module.bootstrap.google_service_account_iam_member.workflow_authority["${key}"]`;
    expect(await failuresOf((fixture) => {
      binding(fixture, key).change.after_unknown = { member: true };
    })).toEqual([`${address}: member is unknown until apply.`]);
    expect(await failuresOf((fixture) => {
      const change = binding(fixture, key);
      delete change.change.after!.service_account_id;
      change.change.after_unknown = { service_account_id: true };
    })).toEqual([`${address}: service_account_id is unknown until apply.`]);
    expect(await failuresOf((fixture) => {
      const provider = fixture.resource_changes.find((change) => change.type === "google_iam_workload_identity_pool_provider")!;
      provider.change.after_unknown = { attribute_condition: true, attribute_mapping: { "attribute.repository_id": true } };
    })).toEqual([
      "module.bootstrap.google_iam_workload_identity_pool_provider.github: attribute_condition is unknown until apply.",
      "module.bootstrap.google_iam_workload_identity_pool_provider.github: attribute_mapping is unknown until apply.",
    ]);
  });

  test("a binding that targets a different service account than its key names fails", async () => {
    const key = `gha-prod-deploy/.github/workflows/deploy-prod.yml@${activeSha}`;
    expect(await failuresOf((fixture) => {
      binding(fixture, key).change.after!.service_account_id = "projects/cdbentley/serviceAccounts/gha-terraform@cdbentley.iam.gserviceaccount.com";
    })).toEqual([
      `module.bootstrap.google_service_account_iam_member.workflow_authority["${key}"]: must bind gha-prod-deploy, not projects/cdbentley/serviceAccounts/gha-terraform@cdbentley.iam.gserviceaccount.com.`,
    ]);
  });

  test("token creation, wildcards, direct federated resource grants, and authoritative policies are forbidden", async () => {
    const key = `gha-terraform/.github/workflows/infrastructure.yml@${activeSha}`;
    const address = `module.bootstrap.google_service_account_iam_member.workflow_authority["${key}"]`;
    expect(await failuresOf((fixture) => {
      binding(fixture, key).change.after!.role = "roles/iam.serviceAccountTokenCreator";
    })).toEqual([
      `${address}: roles/iam.serviceAccountTokenCreator is forbidden.`,
      `${address}: role must be roles/iam.workloadIdentityUser.`,
    ]);
    expect(await failuresOf((fixture) => {
      binding(fixture, key).change.after!.member = `principalSet://iam.googleapis.com/${pool}/*`;
    })).toEqual([
      `${address}: wildcard member principalSet://iam.googleapis.com/${pool}/* is forbidden.`,
      `${address}: member must be principalSet://iam.googleapis.com/${pool}/attribute.job_workflow_ref/collinbentley1/platform/.github/workflows/infrastructure.yml@${activeSha}.`,
    ]);
    expect(await failuresOf((fixture) => {
      fixture.resource_changes.push(resource("google_project_iam_member", "federated", {
        member: `principalSet://iam.googleapis.com/${pool}/attribute.repository_id/${repositoryId}`,
        role: "roles/viewer",
      }, { actions: ["create"] }));
    })).toEqual([
      `module.bootstrap.google_project_iam_member.federated: federated principal principalSet://iam.googleapis.com/${pool}/attribute.repository_id/${repositoryId} may only be bound to a service account.`,
    ]);
    expect(await failuresOf((fixture) => {
      fixture.resource_changes.push(resource("google_service_account_iam_policy", "authoritative", { policy_data: "{}" }, { actions: ["create"] }));
    })).toEqual(["module.bootstrap.google_service_account_iam_policy.authoritative: authoritative IAM policies are forbidden."]);
    expect(await failuresOf((fixture) => {
      fixture.resource_changes.push(resource("google_project_iam_member", "human", { member: "user:someone@example.com", role: "roles/viewer" }, { actions: ["create"] }));
    })).toEqual(["module.bootstrap.google_project_iam_member.human: unexpected member user:someone@example.com."]);
    expect(await failuresOf((fixture) => {
      fixture.resource_changes.push(resource("google_service_account_iam_member", "impersonation", {
        member: "serviceAccount:gha-terraform@cdbentley.iam.gserviceaccount.com",
        role: "roles/iam.serviceAccountTokenCreator",
        service_account_id: "projects/cdbentley/serviceAccounts/gha-prod-deploy@cdbentley.iam.gserviceaccount.com",
      }, { actions: ["create"] }));
    })).toEqual([
      "module.bootstrap.google_service_account_iam_member.impersonation: roles/iam.serviceAccountTokenCreator is forbidden.",
      "module.bootstrap.google_service_account_iam_member.impersonation: unexpected service account role roles/iam.serviceAccountTokenCreator.",
    ]);
  });

  test("the pool and provider must be exactly the reviewed pair with the literal condition and plain mapping", async () => {
    expect(await failuresOf((fixture) => {
      fixture.resource_changes.push({ ...provider(), address: "module.bootstrap.google_iam_workload_identity_pool_provider.second", name: "second" });
    })).toEqual(["workload identity providers: expected exactly 1, found 2."]);
    expect(await failuresOf((fixture) => {
      const change = fixture.resource_changes.find((candidate) => candidate.type === "google_iam_workload_identity_pool_provider")!;
      change.change.after!.attribute_condition = `assertion.repository_owner_id == '16823277' && assertion.repository_id == '${repositoryId}' || true`;
    })).toEqual([
      `module.bootstrap.google_iam_workload_identity_pool_provider.github: attribute_condition must be exactly "assertion.repository_owner_id == '16823277' && assertion.repository_id == '${repositoryId}'".`,
    ]);
    expect(await failuresOf((fixture) => {
      const change = fixture.resource_changes.find((candidate) => candidate.type === "google_iam_workload_identity_pool_provider")!;
      (change.change.after!.attribute_mapping as Record<string, string>)["attribute.environment"] = "assertion.environment";
    })).toEqual([
      'module.bootstrap.google_iam_workload_identity_pool_provider.github: attribute_mapping must be exactly [["attribute.job_workflow_ref","assertion.job_workflow_ref"],["attribute.repository_id","assertion.repository_id"],["google.subject","assertion.repository_owner_id + \':\' + assertion.repository_id + \':\' + assertion.run_id"]].',
    ]);
    expect(await failuresOf((fixture) => {
      const change = fixture.resource_changes.find((candidate) => candidate.type === "google_iam_workload_identity_pool_provider")!;
      change.change.after!.saml = [{ idp_metadata_xml: "<xml/>" }];
    })).toEqual(["module.bootstrap.google_iam_workload_identity_pool_provider.github: saml identity is forbidden."]);
    expect(await failuresOf((fixture) => {
      fixture.resource_changes.push(resource("google_iam_workload_identity_pool", "second", {
        disabled: false,
        name: `${pool}-2`,
        workload_identity_pool_id: "github-actions-2",
      }, { actions: ["create"] }));
    })).toEqual([
      "workload identity pools: expected exactly 1, found 2.",
      "module.bootstrap.google_iam_workload_identity_pool.second: pool id must be github-actions.",
      `module.bootstrap.google_iam_workload_identity_pool.second: pool name ${pool}-2 is not ${pool}.`,
    ]);
  });

  test("unapproved modules, root resources, provisioners, and provisioner vehicles fail", async () => {
    expect(await failuresOf((fixture) => {
      fixture.planned_values.root_module.child_modules.push({ address: "module.rogue", resources: [] });
      fixture.resource_changes.push(resource("google_project_service", "rogue", { service: "compute.googleapis.com" }, { actions: ["create"], module: "module.rogue" }));
    })).toEqual([
      "module.rogue: module is not approved.",
      "module.rogue.google_project_service.rogue: lives outside the approved modules.",
    ]);
    expect(await failuresOf((fixture) => {
      fixture.resource_changes.push(resource("google_project_service", "root", { service: "compute.googleapis.com" }, { actions: ["create"], module: null }));
    })).toEqual(["google_project_service.root: lives outside the approved modules."]);
    expect(await failuresOf((fixture) => {
      const bootstrap = (fixture.configuration.root_module as { module_calls: { bootstrap: { module: { resources: Array<Record<string, unknown>> } } } }).module_calls.bootstrap.module;
      bootstrap.resources[0]!.provisioners = [{ type: "local-exec", expressions: { command: { constant_value: "curl evil" } } }];
    })).toEqual(["configuration: provisioners are forbidden."]);
    expect(await failuresOf((fixture) => {
      fixture.resource_changes.push(resource("null_resource", "shell", { triggers: {} }, { actions: ["create"] }));
    })).toEqual(["module.bootstrap.null_resource.shell: null_resource is forbidden."]);
  });
});
