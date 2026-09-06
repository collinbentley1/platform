import { describe, expect, test } from "bun:test";
import { type DenyFlags, type LiveDenyPolicy, brokerAttachment, canaryTuples, classifyDenyState, consumerAttachment, denyCanaryPrincipal, denyFormFor, denyMatrix, deployPrincipals, invokerTuples, livePolicyFromJson, memberTuples, organizationAttachment, platformShasOf, steadyFlags } from "../src/deny";
import { activeSha, livePoliciesFromMatrix, organizationId, testAuthority, transitionSha } from "./support";

const coordinates = { platformShas: [activeSha] };
const bootstrapPrincipal = "principal://goog/subject/cloud-root@cdbentley.com";
const maintenancePrincipal = "principal://iam.googleapis.com/projects/-/serviceAccounts/gha-terraform@cdbentley.iam.gserviceaccount.com";

describe("the required Deny matrix", () => {
  test("steady: thirty-five broker rows, twenty-nine per consumer, ten at the organization, every row denying every principal with exactly the modeled exceptions", async () => {
    const authority = await testAuthority();
    const matrix = denyMatrix(authority, coordinates, steadyFlags);
    const broker = brokerAttachment(authority);
    const organization = organizationAttachment(authority);
    const rows = Object.values(matrix);
    expect(rows).toHaveLength(35 + 4 * 29 + 10);
    expect(rows.filter((row) => row.attachment === broker)).toHaveLength(35);
    expect(rows.filter((row) => row.attachment === organization)).toHaveLength(10);
    expect(rows.every((row) => row.denied.length === 1 && row.denied[0] === "principalSet://goog/public:all")).toBe(true);
    expect(Object.keys(matrix)).toEqual([...Object.keys(matrix)].sort());
    const brokerMember = "principal://iam.googleapis.com/projects/-/serviceAccounts/recovery-broker@recovery-test.iam.gserviceaccount.com";
    expect(matrix[`${broker}|datastore.googleapis.com/entities.get`]!.exceptions).toEqual([brokerMember]);
    expect(matrix[`${broker}|datastore.googleapis.com/entities.list`]!.exceptions).toEqual([brokerMember]);
    expect(matrix[`${broker}|iam.googleapis.com/serviceAccountKeys.create`]!.exceptions).toEqual([]);
    const invokers = invokerTuples(authority, coordinates);
    expect(invokers).toHaveLength(8);
    expect(invokers.every((tuple) => tuple.startsWith("principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-actions/attribute.authority/collinbentley1/platform/.github/workflows/protected-recovery-invoke.yml@refs/heads/main:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:recovery-"))).toBe(true);
    expect(canaryTuples(authority, coordinates)).toEqual(["principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-actions/attribute.authority/collinbentley1/platform/.github/workflows/protected-recovery-deny-canary.yml@refs/heads/main:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:protected-recovery-deny-canary:workflow_dispatch"]);
    expect(matrix[`${broker}|iam.googleapis.com/serviceAccounts.getAccessToken`]!.exceptions).toEqual([...invokers, ...canaryTuples(authority, coordinates)].sort());
    const members = memberTuples(authority);
    expect(members).toHaveLength(61);
    expect(matrix[`${broker}|iam.googleapis.com/serviceAccounts.getOpenIdToken`]!.exceptions).toEqual(["principal://iam.googleapis.com/projects/-/serviceAccounts/service-123456789012@gcp-sa-cloudscheduler.iam.gserviceaccount.com", ...invokers, ...members].sort());
    // The deployment rows of the broker project carry no standing exception: the bootstrap principal is a flag, never a default.
    expect(matrix[`${broker}|run.googleapis.com/services.update`]!.exceptions).toEqual([]);
    expect(matrix[`${broker}|cloudresourcemanager.googleapis.com/projects.setIamPolicy`]!.exceptions).toEqual([]);
    expect(matrix[`${broker}|artifactregistry.googleapis.com/repositories.uploadArtifacts`]!.exceptions).toEqual([]);
    const cdbentley = consumerAttachment(authority.consumers[0]!);
    expect(matrix[`${cdbentley}|iam.googleapis.com/serviceAccounts.setIamPolicy`]!.exceptions).toEqual([brokerMember]);
    expect(matrix[`${cdbentley}|cloudresourcemanager.googleapis.com/projects.setIamPolicy`]!.exceptions).toEqual([]);
    // Steady freezes the deploy path too: no deploy identity is excepted until the consumer is in deployment form.
    for (const permission of ["iam.googleapis.com/serviceAccounts.actAs", "run.googleapis.com/services.create", "run.googleapis.com/services.update", "run.googleapis.com/workerpools.create", "run.googleapis.com/workerpools.update", "run.googleapis.com/jobs.create", "cloudbuild.googleapis.com/builds.create", "compute.googleapis.com/instances.setServiceAccount", "serviceusage.googleapis.com/services.disable", "serviceusage.googleapis.com/services.enable", "iam.googleapis.com/serviceAccountKeys.create"]) {
      expect(matrix[`${cdbentley}|${permission}`]!.exceptions, permission).toEqual([]);
    }
    // Both organization-policy APIs and project movement are frozen at the organization.
    for (const permission of ["iam.googleapis.com/roles.create", "iam.googleapis.com/roles.delete", "iam.googleapis.com/roles.undelete", "iam.googleapis.com/roles.update", "orgpolicy.googleapis.com/policies.create", "orgpolicy.googleapis.com/policies.delete", "orgpolicy.googleapis.com/policies.update", "orgpolicy.googleapis.com/policy.set", "cloudresourcemanager.googleapis.com/projects.move", "cloudresourcemanager.googleapis.com/projects.update"]) {
      expect(matrix[`${organization}|${permission}`]!.exceptions, permission).toEqual([]);
    }
  });

  test("the deployment form excepts exactly the consumer's two deploy identities on exactly the Cloud Run deploy rows and actAs, per consumer", async () => {
    const authority = await testAuthority();
    const cdbentley = authority.consumers[0]!;
    const runsetta = authority.consumers[3]!;
    const steady = denyMatrix(authority, coordinates, steadyFlags);
    const matrix = denyMatrix(authority, coordinates, { ...steadyFlags, deployment: ["cdbentley"] });
    const expected = ["principal://iam.googleapis.com/projects/-/serviceAccounts/gha-preview-deploy@cdbentley.iam.gserviceaccount.com", "principal://iam.googleapis.com/projects/-/serviceAccounts/gha-prod-deploy@cdbentley.iam.gserviceaccount.com"];
    expect(deployPrincipals(cdbentley)).toEqual(expected);
    const changed = Object.keys(matrix).filter((key) => JSON.stringify(matrix[key]) !== JSON.stringify(steady[key]));
    expect(changed).toEqual([`${consumerAttachment(cdbentley)}|iam.googleapis.com/serviceAccounts.actAs`, `${consumerAttachment(cdbentley)}|run.googleapis.com/services.create`, `${consumerAttachment(cdbentley)}|run.googleapis.com/services.update`]);
    for (const key of changed) expect(matrix[key]!.exceptions).toEqual(expected);
    expect(matrix[`${consumerAttachment(runsetta)}|run.googleapis.com/services.update`]!.exceptions).toEqual([]);
  });

  test("the bootstrap form excepts the one bootstrap principal on exactly the rows the module's apply mutates, and never combines with maintenance", async () => {
    const authority = await testAuthority((document) => {
      document.bootstrapPrincipal = bootstrapPrincipal;
    });
    const steady = denyMatrix(authority, coordinates, steadyFlags);
    const matrix = denyMatrix(authority, coordinates, { ...steadyFlags, bootstrap: true });
    const changed = Object.keys(matrix).filter((key) => JSON.stringify(matrix[key]) !== JSON.stringify(steady[key]));
    const broker = brokerAttachment(authority);
    const organization = organizationAttachment(authority);
    expect(changed.filter((key) => key.startsWith(`${broker}|`))).toHaveLength(21);
    expect(changed.filter((key) => key.startsWith(`${organization}|`))).toEqual([`${organization}|iam.googleapis.com/roles.create`, `${organization}|iam.googleapis.com/roles.delete`, `${organization}|iam.googleapis.com/roles.update`]);
    for (const consumer of authority.consumers) {
      expect(changed.filter((key) => key.startsWith(`${consumerAttachment(consumer)}|`))).toEqual([`${consumerAttachment(consumer)}|cloudresourcemanager.googleapis.com/projects.setIamPolicy`, `${consumerAttachment(consumer)}|iam.googleapis.com/serviceAccounts.setIamPolicy`]);
    }
    for (const key of changed) expect(matrix[key]!.exceptions).toEqual([...steady[key]!.exceptions, bootstrapPrincipal].sort());
    // Without a declared bootstrap principal the bootstrap form is the steady form: nothing is excepted by default.
    const undeclared = await testAuthority();
    expect(denyMatrix(undeclared, coordinates, { ...steadyFlags, bootstrap: true })).toEqual(denyMatrix(undeclared, coordinates, steadyFlags));
    expect(() => denyMatrix(authority, coordinates, { ...steadyFlags, bootstrap: true, maintenance: true })).toThrow("never combine");
  });

  test("the maintenance form excepts the maintenance principals on the consumer IAM, federation, lifecycle, API, role, and organization-policy rows only", async () => {
    const authority = await testAuthority((document) => {
      document.maintenancePrincipals = [maintenancePrincipal];
    });
    const steady = denyMatrix(authority, coordinates, steadyFlags);
    const matrix = denyMatrix(authority, coordinates, { ...steadyFlags, maintenance: true });
    const changed = Object.keys(matrix).filter((key) => JSON.stringify(matrix[key]) !== JSON.stringify(steady[key]));
    const broker = brokerAttachment(authority);
    expect(changed.some((key) => key.startsWith(`${broker}|`))).toBe(false);
    // The four role rows and the four organization-policy rows; project movement stays frozen for everyone.
    expect(changed.filter((key) => key.startsWith(`${organizationAttachment(authority)}|`))).toHaveLength(8);
    expect(matrix[`${organizationAttachment(authority)}|cloudresourcemanager.googleapis.com/projects.move`]!.exceptions).toEqual([]);
    expect(matrix[`${organizationAttachment(authority)}|cloudresourcemanager.googleapis.com/projects.update`]!.exceptions).toEqual([]);
    const cdbentley = consumerAttachment(authority.consumers[0]!);
    const consumerRows = changed.filter((key) => key.startsWith(`${cdbentley}|`)).map((key) => key.slice(cdbentley.length + 1));
    expect(consumerRows).toEqual([
      "cloudresourcemanager.googleapis.com/projects.setIamPolicy",
      "iam.googleapis.com/serviceAccounts.create",
      "iam.googleapis.com/serviceAccounts.delete",
      "iam.googleapis.com/serviceAccounts.disable",
      "iam.googleapis.com/serviceAccounts.enable",
      "iam.googleapis.com/serviceAccounts.setIamPolicy",
      "iam.googleapis.com/serviceAccounts.undelete",
      "iam.googleapis.com/workloadIdentityPoolProviders.create",
      "iam.googleapis.com/workloadIdentityPoolProviders.delete",
      "iam.googleapis.com/workloadIdentityPoolProviders.undelete",
      "iam.googleapis.com/workloadIdentityPoolProviders.update",
      "iam.googleapis.com/workloadIdentityPools.create",
      "iam.googleapis.com/workloadIdentityPools.delete",
      "iam.googleapis.com/workloadIdentityPools.undelete",
      "iam.googleapis.com/workloadIdentityPools.update",
      "serviceusage.googleapis.com/services.disable",
      "serviceusage.googleapis.com/services.enable",
    ]);
    // Keys, the deploy path, and every other attachment path stay frozen for everyone under maintenance too.
    expect(matrix[`${cdbentley}|iam.googleapis.com/serviceAccountKeys.create`]!.exceptions).toEqual([]);
    expect(matrix[`${cdbentley}|iam.googleapis.com/serviceAccounts.actAs`]!.exceptions).toEqual([]);
    expect(matrix[`${cdbentley}|run.googleapis.com/jobs.create`]!.exceptions).toEqual([]);
  });

  test("the transition commit extends only the transition-eligible invoker tuples, and the matrix refuses an unrecorded broker or organization", async () => {
    const authority = await testAuthority();
    expect(invokerTuples(authority, { platformShas: [activeSha, transitionSha] })).toHaveLength(16);
    expect(canaryTuples(authority, { platformShas: [activeSha, transitionSha] })).toHaveLength(1);
    const unrecorded = await testAuthority((document) => {
      document.organizationId = null;
    });
    expect(() => denyMatrix(unrecorded, coordinates, steadyFlags)).toThrow("records no organization");
    const offline = await testAuthority((document) => {
      (document.broker as Record<string, unknown>).projectId = null;
      (document.broker as Record<string, unknown>).projectNumber = null;
    });
    expect(() => denyMatrix(offline, coordinates, steadyFlags)).toThrow("records no broker project");
  });
});

describe("classifying the live Deny state", () => {
  const attachmentsOf = async () => {
    const authority = await testAuthority((document) => {
      document.bootstrapPrincipal = bootstrapPrincipal;
      document.maintenancePrincipals = [maintenancePrincipal];
    });
    const cdbentley = authority.consumers[0]!;
    const attachments = [brokerAttachment(authority), organizationAttachment(authority), consumerAttachment(cdbentley)];
    const live = (flags: DenyFlags, shas = [activeSha]) => livePoliciesFromMatrix(denyMatrix(authority, { platformShas: shas }, flags)).policies.filter((policy) => attachments.includes(policy.attachment));
    return { attachments, authority, cdbentley, live };
  };

  test("each exact form is recognized, the deployment flag per consumer, and every widening is authority disabled for the consumer it touches", async () => {
    const { attachments, authority, cdbentley, live } = await attachmentsOf();
    expect(classifyDenyState(authority, live(steadyFlags), attachments)).toEqual({ kind: "classified", flags: steadyFlags });
    expect(denyFormFor(classifyDenyState(authority, live(steadyFlags), attachments), cdbentley)).toBe("steady");
    const deployment = classifyDenyState(authority, live({ ...steadyFlags, deployment: ["cdbentley"] }), attachments);
    expect(deployment).toEqual({ kind: "classified", flags: { ...steadyFlags, deployment: ["cdbentley"] } });
    expect(denyFormFor(deployment, cdbentley)).toBe("deployment");
    expect(denyFormFor(deployment, authority.consumers[3]!)).toBe("steady");
    const bootstrap = classifyDenyState(authority, live({ ...steadyFlags, bootstrap: true }), attachments);
    expect(bootstrap).toEqual({ kind: "classified", flags: { ...steadyFlags, bootstrap: true } });
    expect(denyFormFor(bootstrap, cdbentley)).toBe("bootstrap");
    const maintenance = classifyDenyState(authority, live({ ...steadyFlags, maintenance: true, deployment: ["cdbentley"] }), attachments);
    expect(maintenance).toEqual({ kind: "classified", flags: { ...steadyFlags, deployment: ["cdbentley"], maintenance: true } });
    expect(denyFormFor(maintenance, cdbentley)).toBe("maintenance");
    // The transition commit binds a second set of invoker tuples; the canary's commit names the active one.
    expect(platformShasOf(authority, live(steadyFlags, [activeSha, transitionSha]))).toEqual({ kind: "shas", shas: [activeSha, transitionSha] });
    expect(classifyDenyState(authority, live(steadyFlags, [activeSha, transitionSha]), attachments)).toEqual({ kind: "classified", flags: steadyFlags });
  });

  test("an exception outside every form, a missing row, a conditioned rule, a permission exception, or unbound invoker commits is drift", async () => {
    const { attachments, authority, cdbentley, live } = await attachmentsOf();
    const consumer = consumerAttachment(cdbentley);
    const edit = (policies: readonly LiveDenyPolicy[], attachment: string, mutate: (policy: LiveDenyPolicy) => LiveDenyPolicy) => policies.map((policy) => (policy.attachment === attachment ? mutate(policy) : policy));
    const widened = edit(live(steadyFlags), consumer, (policy) => ({ ...policy, rules: policy.rules.map((rule) => (rule.permissions.includes("iam.googleapis.com/serviceAccounts.actAs") ? { ...rule, exceptions: [...rule.exceptions, "principal://goog/subject/daily-human@cdbentley.com"] } : rule)) }));
    const verdict = classifyDenyState(authority, widened, attachments);
    expect(verdict.kind).toBe("drifted");
    if (verdict.kind !== "drifted") throw new Error();
    expect(verdict.reasons).toContain(`no live rule carries the row ${consumer}|iam.googleapis.com/serviceAccounts.actAs`);
    expect(denyFormFor(verdict, cdbentley)).toStartWith("drifted: ");
    const missing = edit(live(steadyFlags), consumer, (policy) => ({ ...policy, rules: policy.rules.map((rule) => ({ ...rule, permissions: rule.permissions.filter((permission) => permission !== "iam.googleapis.com/serviceAccountKeys.create") })) }));
    expect(classifyDenyState(authority, missing, attachments)).toMatchObject({ kind: "drifted", reasons: [`no live rule carries the row ${consumer}|iam.googleapis.com/serviceAccountKeys.create`] });
    const conditioned = edit(live(steadyFlags), consumer, (policy) => ({ ...policy, rules: policy.rules.map((rule) => ({ ...rule, condition: { expression: "resource.matchTag('1/env', 'canary')" } })) }));
    expect(classifyDenyState(authority, conditioned, attachments).kind).toBe("drifted");
    const excepted = edit(live(steadyFlags), consumer, (policy) => ({ ...policy, rules: policy.rules.map((rule) => ({ ...rule, exceptedPermissions: ["iam.googleapis.com/serviceAccounts.actAs"] })) }));
    expect(classifyDenyState(authority, excepted, attachments).kind).toBe("drifted");
    // A rule that denies fewer principals than everyone satisfies no row.
    const narrowed = edit(live(steadyFlags), consumer, (policy) => ({ ...policy, rules: policy.rules.map((rule) => ({ ...rule, denied: ["principalSet://goog/group/everyone@example.com"] })) }));
    expect(classifyDenyState(authority, narrowed, attachments).kind).toBe("drifted");
    // A broker rule without the canary tuple, or with invoker tuples at three commits, cannot name the active commit.
    const noCanary = edit(live(steadyFlags), brokerAttachment(authority), (policy) => ({ ...policy, rules: policy.rules.map((rule) => ({ ...rule, exceptions: rule.exceptions.filter((exception) => !exception.includes("protected-recovery-deny-canary.yml")) })) }));
    expect(classifyDenyState(authority, noCanary, attachments)).toEqual({ kind: "drifted", reasons: ["the live broker rules bind no Deny canary tuple"] });
    const third = "c".repeat(40);
    const extra = edit(live(steadyFlags, [activeSha, transitionSha]), brokerAttachment(authority), (policy) => ({ ...policy, rules: policy.rules.map((rule) => ({ ...rule, exceptions: rule.exceptions.flatMap((exception) => (exception.includes(`:${activeSha}:recovery-`) ? [exception, exception.replace(`:${activeSha}:`, `:${third}:`)] : [exception])) })) }));
    expect(classifyDenyState(authority, extra, attachments)).toMatchObject({ kind: "drifted", reasons: [expect.stringContaining("more than two commits")] });
    // Extra deny rules only narrow the state further and are never drift.
    const stricter = edit(live(steadyFlags), consumer, (policy) => ({ ...policy, rules: [...policy.rules, { condition: null, denied: ["principalSet://goog/public:all"], exceptedPermissions: [], exceptions: [], permissions: ["storage.googleapis.com/buckets.delete"] }] }));
    expect(classifyDenyState(authority, stricter, attachments)).toEqual({ kind: "classified", flags: steadyFlags });
    expect(denyCanaryPrincipal(authority)).toBe("principal://iam.googleapis.com/projects/-/serviceAccounts/gha-deny-canary@recovery-test.iam.gserviceaccount.com");
  });

  test("the IAM v2 policy document is projected strictly", () => {
    const attachment = `cloudresourcemanager.googleapis.com/organizations/${organizationId}`;
    const projected = livePolicyFromJson(attachment, { etag: "e1", name: "policies/x/denypolicies/y", rules: [{ denyRule: { deniedPermissions: ["iam.googleapis.com/roles.create"], deniedPrincipals: ["principalSet://goog/public:all"], exceptionPrincipals: [] } }, { description: "not a deny rule" }] });
    expect(projected).toEqual({ attachment, etag: "e1", name: "policies/x/denypolicies/y", rules: [{ condition: null, denied: ["principalSet://goog/public:all"], exceptedPermissions: [], exceptions: [], permissions: ["iam.googleapis.com/roles.create"] }] });
    expect(() => livePolicyFromJson(attachment, { name: "policies/x/denypolicies/y" })).toThrow("malformed");
    expect(() => livePolicyFromJson(attachment, { etag: "e", name: "n", rules: [{ denyRule: { deniedPermissions: "iam.googleapis.com/roles.create" } }] })).toThrow("malformed principal or permission list");
  });
});
