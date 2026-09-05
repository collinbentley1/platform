import { describe, expect, test } from "bun:test";
import { GoogleCredentialInventory, actuatorPermissions, actuatorRoleId, lifetimeExtensionConstraint } from "../src/inventory";
import { type Consumer, type RecoveryAuthority, type Target, brokerMember, managedRole, purposeForIdentity, scanReadiness, targetsFor } from "../src/model";
import { Clock, close, emulatorHost, invokerEmail, makeReady, quarantine, restore, seedTargets, testAuthority, world } from "./support";

// The inventory adapter against stand-ins of the six authoritative APIs it
// reads. Every adversarial case below is one real credential path the
// approved brief names; each must surface as a finding, and every answer the
// adapter cannot classify must make the inventory unavailable rather than
// clean. None of this proves the live APIs answer as modelled; the activation
// canary does.

type Fetcher = typeof fetch;

interface Policy {
  readonly bindings: unknown[];
  readonly etag: string;
}

interface Fixture {
  readonly calls: string[];
  identity: { email: string; uniqueId: string };
  saPolicy: Policy;
  projectPolicy: Policy;
  folderPolicy: Policy;
  orgPolicy: Policy;
  projectParent: string | undefined;
  folderParent: string;
  roles: Record<string, readonly string[] | { readonly status: number }>;
  keys: unknown[];
  lifetime: { status: number; body?: unknown };
  compute: { status: number; body?: unknown; instances: Record<string, unknown>; templates: Record<string, unknown> };
  run: { status: number; body?: unknown; pages: Array<{ services: unknown[]; nextPageToken?: string }>; jobs: unknown[] };
  build: { status: number; body?: unknown; triggers: unknown[] };
}

const endpoints = { cloudBuild: "https://cloudbuild.test", compute: "https://compute.test", iam: "https://iam.test", orgPolicy: "https://orgpolicy.test", resourceManager: "https://rm.test", run: "https://run.test" };
const organization = "organizations/100000000001";
const actuatorRole = `projects/cdbentley/roles/${actuatorRoleId}`;

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { headers: { "content-type": "application/json" }, status });
}

function disabled(service: string): unknown {
  return { error: { code: 403, details: [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo", domain: "googleapis.com", metadata: { service }, reason: "SERVICE_DISABLED" }], message: `${service} has not been used in project before or it is disabled.`, status: "PERMISSION_DENIED" } };
}

function clean(authority: RecoveryAuthority, target: Target): Fixture {
  return {
    build: { status: 200, triggers: [] },
    calls: [],
    compute: { status: 403, instances: {}, templates: {} },
    folderParent: organization,
    folderPolicy: { bindings: [{ members: ["group:everyone@example.com"], role: "roles/browser" }], etag: "f-1" },
    identity: { email: target.email, uniqueId: target.uniqueId },
    keys: [],
    lifetime: { status: 404 },
    orgPolicy: { bindings: [{ members: ["group:everyone@example.com"], role: "roles/resourcemanager.organizationViewer" }], etag: "o-1" },
    projectParent: "folders/500",
    projectPolicy: { bindings: [{ members: ["group:readers@example.com"], role: "roles/viewer" }, { members: ["user:ops@example.com"], role: "roles/logging.viewer" }], etag: "p-1" },
    roles: {
      [actuatorRole]: actuatorPermissions,
      "organizations/100000000001/roles/signer": ["iam.serviceAccounts.signJwt"],
      "projects/cdbentley/roles/credentialMinter": ["iam.serviceAccounts.getAccessToken"],
      "roles/browser": ["resourcemanager.projects.get"],
      "roles/iam.serviceAccountTokenCreator": ["iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.getOpenIdToken", "iam.serviceAccounts.implicitDelegation", "iam.serviceAccounts.signBlob", "iam.serviceAccounts.signJwt"],
      "roles/iam.serviceAccountViewer": ["iam.serviceAccounts.get", "iam.serviceAccounts.list"],
      "roles/iam.workloadIdentityUser": ["iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.getOpenIdToken"],
      "roles/logging.viewer": ["logging.logEntries.list"],
      "roles/owner": ["iam.serviceAccounts.setIamPolicy", "resourcemanager.projects.setIamPolicy", "storage.objects.get"],
      "roles/resourcemanager.organizationViewer": ["resourcemanager.organizations.get"],
      "roles/viewer": ["resourcemanager.projects.get", "storage.objects.get"],
    },
    run: { status: 200, jobs: [], pages: [{ services: [] }] },
    saPolicy: {
      bindings: [
        { members: [...target.members], role: managedRole },
        { members: ["serviceAccount:audit@recovery-test.iam.gserviceaccount.com"], role: "roles/iam.serviceAccountViewer" },
        { members: [brokerMember(authority)!], role: actuatorRole },
      ],
      etag: "sa-1",
    },
  };
}

function routes(f: Fixture, target: Target, consumer: Consumer): Fetcher {
  return Object.assign(async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    const path = url.pathname;
    f.calls.push(`${method} ${url.origin}${path}${url.search}`);
    if ((init?.headers as Record<string, string> | undefined)?.Authorization !== "Bearer broker-token") return json(401, { error: { status: "UNAUTHENTICATED" } });
    switch (url.origin) {
      case endpoints.iam: {
        if (path === `/v1/${target.resource}` && method === "GET") return json(200, { email: f.identity.email, name: target.resource, uniqueId: f.identity.uniqueId });
        if (path === `/v1/${target.resource}:getIamPolicy` && method === "POST") return json(200, { ...f.saPolicy, version: 3 });
        if (path === `/v1/${target.resource}/keys` && url.searchParams.get("keyTypes") === "USER_MANAGED") return json(200, f.keys.length === 0 ? {} : { keys: f.keys });
        const role = f.roles[path.slice("/v1/".length)];
        if (role === undefined) return json(404, { error: { status: "NOT_FOUND" } });
        if (!Array.isArray(role)) return json((role as { status: number }).status, { error: { status: "PERMISSION_DENIED" } });
        return json(200, { includedPermissions: role, name: path.slice("/v1/".length) });
      }
      case endpoints.resourceManager: {
        if (path === `/v3/projects/${consumer.projectNumber}` && method === "GET") return json(200, { name: `projects/${consumer.projectNumber}`, projectId: consumer.projectId, ...(f.projectParent === undefined ? {} : { parent: f.projectParent }) });
        if (path === `/v3/projects/${consumer.projectNumber}:getIamPolicy`) return json(200, { ...f.projectPolicy, version: 3 });
        if (path === "/v3/folders/500" && method === "GET") return json(200, { name: "folders/500", parent: f.folderParent });
        if (path === "/v3/folders/500:getIamPolicy") return json(200, { ...f.folderPolicy, version: 3 });
        if (path === `/v3/${organization}:getIamPolicy`) return json(200, { ...f.orgPolicy, version: 3 });
        return json(404, { error: { status: "NOT_FOUND" } });
      }
      case endpoints.orgPolicy:
        if (path !== `/v2/projects/${consumer.projectNumber}/policies/${lifetimeExtensionConstraint}:getEffectivePolicy`) return json(404, {});
        return f.lifetime.status === 200 ? json(200, f.lifetime.body) : json(f.lifetime.status, { error: { status: f.lifetime.status === 404 ? "NOT_FOUND" : "UNAVAILABLE" } });
      case endpoints.compute:
        if (f.compute.status !== 200) return json(f.compute.status, f.compute.body ?? disabled("compute.googleapis.com"));
        if (path === `/compute/v1/projects/${consumer.projectId}/aggregated/instances`) return json(200, { items: f.compute.instances });
        if (path === `/compute/v1/projects/${consumer.projectId}/aggregated/instanceTemplates`) return json(200, { items: f.compute.templates });
        return json(404, {});
      case endpoints.run: {
        if (f.run.status !== 200) return json(f.run.status, f.run.body ?? disabled("run.googleapis.com"));
        if (path === `/v2/projects/${consumer.projectId}/locations/-/services`) {
          const token = url.searchParams.get("pageToken");
          const page = f.run.pages[token === null ? 0 : Number(token)];
          return page ? json(200, page) : json(400, {});
        }
        if (path === `/v2/projects/${consumer.projectId}/locations/-/jobs`) return json(200, { jobs: f.run.jobs });
        return json(404, {});
      }
      case endpoints.cloudBuild:
        if (f.build.status !== 200) return json(f.build.status, f.build.body ?? disabled("cloudbuild.googleapis.com"));
        if (path === `/v1/projects/${consumer.projectId}/locations/-/triggers`) return json(200, { triggers: f.build.triggers });
        return json(404, {});
      default:
        return json(404, {});
    }
  }, { preconnect: fetch.preconnect });
}

async function harness() {
  const authority = await testAuthority();
  const consumer = authority.consumers.find((candidate) => candidate.repository === "cdbentley")!;
  const target = targetsFor(authority, consumer)![0]!;
  const fixture = clean(authority, target);
  const clock = new Clock();
  const inventory = new GoogleCredentialInventory({ authority, endpoints, fetch: routes(fixture, target, consumer), now: clock.read, token: async () => "broker-token" });
  const observe = async () => await inventory.inventory(target, consumer);
  const findingsOf = async () => {
    const outcome = await observe();
    if (outcome.kind !== "observed") throw new Error(outcome.reason);
    return outcome.inventory.findings;
  };
  return { authority, clock, consumer, findingsOf, fixture, inventory, observe, target };
}

describe("credential inventory", () => {
  test("a clean target: every ancestry policy with its etag, every role expanded exactly once, no keys, no lifetime extension, no attachment, a stable hash", async () => {
    const { clock, findingsOf, fixture, observe, target } = await harness();
    const first = await observe();
    if (first.kind !== "observed") throw new Error(first.reason);
    expect(first.inventory).toMatchObject({ account: target.account, email: target.email, findings: [], observedAt: clock.now.toISOString(), uniqueId: target.uniqueId });
    expect(first.inventory.summary).toEqual({
      ancestry: ["projects/882468538648", "folders/500", organization],
      attachments: [],
      grants: [],
      keys: [],
      lifetimeExtension: null,
      policies: [
        { etag: "f-1", resource: "folders/500" },
        { etag: "o-1", resource: organization },
        { etag: "p-1", resource: "projects/882468538648" },
        { etag: "sa-1", resource: target.resource },
      ],
      services: ["cloudbuild.googleapis.com:enabled", "compute.googleapis.com:disabled", "run.googleapis.com:enabled"],
    });
    const roleReads = fixture.calls.filter((call) => /GET https:\/\/iam\.test\/v1\/(?:roles|projects|organizations)\//.test(call) && !call.includes("/serviceAccounts/"));
    expect(new Set(roleReads).size).toBe(roleReads.length);
    expect(roleReads).toHaveLength(7);
    // The same world hashes the same; any moved etag hashes differently even with the same findings.
    const second = await observe();
    if (second.kind !== "observed") throw new Error(second.reason);
    expect(second.inventory.hash).toBe(first.inventory.hash);
    fixture.projectPolicy = { ...fixture.projectPolicy, etag: "p-2" };
    const moved = await observe();
    if (moved.kind !== "observed") throw new Error(moved.reason);
    expect(moved.inventory.hash).not.toBe(first.inventory.hash);
    expect(await findingsOf()).toEqual([]);
  });

  test("a custom role on the target that carries getAccessToken is a credential grant", async () => {
    const { findingsOf, fixture, target } = await harness();
    fixture.saPolicy = { ...fixture.saPolicy, bindings: [...fixture.saPolicy.bindings, { members: ["user:evil@example.com"], role: "projects/cdbentley/roles/credentialMinter" }] };
    expect(await findingsOf()).toEqual([`grant:${target.resource}|projects/cdbentley/roles/credentialMinter|user:evil@example.com`]);
  });

  test("inherited credential grants at the project, a folder, and the organization are found through role expansion", async () => {
    const { findingsOf, fixture } = await harness();
    fixture.projectPolicy = { ...fixture.projectPolicy, bindings: [...fixture.projectPolicy.bindings, { members: ["user:minter@example.com"], role: "roles/iam.serviceAccountTokenCreator" }] };
    fixture.folderPolicy = { ...fixture.folderPolicy, bindings: [...fixture.folderPolicy.bindings, { condition: { expression: "request.time < timestamp('2030-01-01T00:00:00Z')", title: "until_2030" }, members: ["group:signers@example.com"], role: "organizations/100000000001/roles/signer" }] };
    fixture.orgPolicy = { ...fixture.orgPolicy, bindings: [...fixture.orgPolicy.bindings, { members: ["user:root@example.com"], role: "roles/owner" }] };
    expect(await findingsOf()).toEqual([
      "grant:folders/500|organizations/100000000001/roles/signer[until_2030]|group:signers@example.com",
      `grant:${organization}|roles/owner|user:root@example.com`,
      "grant:projects/882468538648|roles/iam.serviceAccountTokenCreator|user:minter@example.com",
    ]);
  });

  test("user-managed keys are found, disabled or not", async () => {
    const { findingsOf, fixture, target } = await harness();
    fixture.keys = [{ keyType: "USER_MANAGED", name: `${target.resource}/keys/0a1b` }, { disabled: true, keyType: "USER_MANAGED", name: `${target.resource}/keys/2c3d` }];
    expect(await findingsOf()).toEqual([`key:${target.resource}/keys/0a1b`, `key:${target.resource}/keys/2c3d:disabled`]);
  });

  test("an effective credential-lifetime-extension policy that covers the target is found; one that covers only others is not", async () => {
    const { findingsOf, fixture, target } = await harness();
    fixture.lifetime = { status: 200, body: { name: `projects/882468538648/policies/${lifetimeExtensionConstraint}`, spec: { rules: [{ values: { allowedValues: ["other@cdbentley.iam.gserviceaccount.com"] } }] } } };
    expect(await findingsOf()).toEqual([]);
    fixture.lifetime = { status: 200, body: { spec: { rules: [{ values: { allowedValues: ["other@cdbentley.iam.gserviceaccount.com", target.email] } }] } } };
    expect(await findingsOf()).toEqual([`lifetime-extension:allowedValues:${target.email}`]);
    fixture.lifetime = { status: 200, body: { spec: { rules: [{ allowAll: true, condition: { expression: "resource.matchTag('123/env', 'prod')" } }] } } };
    expect(await findingsOf()).toEqual(["lifetime-extension:allowAll[conditional]"]);
  });

  test("direct federation: a pool principal granted anywhere in the ancestry, an unmodeled pool member on the target, or a conditional canonical member is found", async () => {
    const { findingsOf, fixture, target } = await harness();
    const foreign = `principalSet://iam.googleapis.com/${target.pool}/attribute.repository/collinbentley1/other`;
    fixture.projectPolicy = { ...fixture.projectPolicy, bindings: [...fixture.projectPolicy.bindings, { members: [foreign], role: "roles/viewer" }] };
    expect(await findingsOf()).toEqual([`grant:projects/882468538648|roles/viewer|${foreign}`]);
    fixture.projectPolicy = clean(await testAuthority(), target).projectPolicy;
    fixture.saPolicy = {
      ...fixture.saPolicy,
      bindings: [
        { members: [...target.members, foreign], role: managedRole },
        { condition: { expression: "request.time < timestamp('2030-01-01T00:00:00Z')", title: "expiring" }, members: [target.members[0]!], role: managedRole },
        ...fixture.saPolicy.bindings.slice(1),
      ],
    };
    expect(await findingsOf()).toEqual([`grant:${target.resource}|roles/iam.workloadIdentityUser[expiring]|${target.members[0]}`, `grant:${target.resource}|roles/iam.workloadIdentityUser|${foreign}`]);
  });

  test("Compute instances and templates, Cloud Run services and jobs across every page, and Cloud Build triggers that run as the target are found", async () => {
    const { findingsOf, fixture, observe, target } = await harness();
    fixture.compute = {
      status: 200,
      instances: { "zones/us-east4-a": { instances: [{ name: "vm-1", serviceAccounts: [{ email: target.email }] }, { name: "vm-2", serviceAccounts: [{ email: "other@cdbentley.iam.gserviceaccount.com" }] }] }, "zones/us-east4-b": { warning: { code: "NO_RESULTS_ON_PAGE" } } },
      templates: { global: { instanceTemplates: [{ name: "tpl-1", properties: { serviceAccounts: [{ email: target.email }] } }] }, "regions/us-east4": { instanceTemplates: [{ name: "tpl-2", properties: {} }] } },
    };
    fixture.run = {
      status: 200,
      jobs: [{ name: "projects/cdbentley/locations/us-east4/jobs/nightly", template: { template: { serviceAccount: target.email } } }],
      pages: [
        { nextPageToken: "1", services: [{ name: "projects/cdbentley/locations/us-east4/services/other", template: { serviceAccount: "other@cdbentley.iam.gserviceaccount.com" } }] },
        { services: [{ name: "projects/cdbentley/locations/us-east4/services/app", template: { serviceAccount: target.email } }] },
      ],
    };
    fixture.build = { status: 200, triggers: [{ resourceName: "projects/cdbentley/locations/global/triggers/deploy", serviceAccount: `projects/cdbentley/serviceAccounts/${target.email}` }, { id: "abc", serviceAccount: "projects/cdbentley/serviceAccounts/other@cdbentley.iam.gserviceaccount.com" }] };
    expect(await findingsOf()).toEqual([
      "attachment:cloudbuild.googleapis.com/projects/cdbentley/locations/global/triggers/deploy",
      "attachment:compute.googleapis.com/projects/cdbentley/global/instanceTemplates/tpl-1",
      "attachment:compute.googleapis.com/projects/cdbentley/zones/us-east4-a/instances/vm-1",
      "attachment:run.googleapis.com/projects/cdbentley/locations/us-east4/jobs/nightly",
      "attachment:run.googleapis.com/projects/cdbentley/locations/us-east4/services/app",
    ]);
    const outcome = await observe();
    if (outcome.kind !== "observed") throw new Error(outcome.reason);
    expect(outcome.inventory.summary.services).toEqual(["cloudbuild.googleapis.com:enabled", "compute.googleapis.com:enabled", "run.googleapis.com:enabled"]);
  });

  test("the broker's own actuator grant is exempt only while its role carries exactly the actuator permissions", async () => {
    const { authority, findingsOf, fixture, target } = await harness();
    fixture.roles = { ...fixture.roles, [actuatorRole]: [...actuatorPermissions, "iam.serviceAccounts.getAccessToken"] };
    expect(await findingsOf()).toEqual([`grant:${target.resource}|${actuatorRole}|${brokerMember(authority)}`]);
  });

  test("an answer the broker cannot classify makes the inventory unavailable, never clean", async () => {
    const { fixture, observe } = await harness();
    fixture.roles = { ...fixture.roles, "roles/viewer": { status: 403 } };
    expect(await observe()).toEqual({ kind: "unavailable", reason: "role roles/viewer: HTTP 403" });
    fixture.roles = { ...fixture.roles, "roles/viewer": ["resourcemanager.projects.get"] };
    fixture.run = { ...fixture.run, status: 403, body: { error: { code: 403, message: "The caller does not have permission", status: "PERMISSION_DENIED" } } };
    expect(await observe()).toMatchObject({ kind: "unavailable", reason: expect.stringContaining("run.test/v2/projects/cdbentley/locations/-/services: HTTP 403") });
    fixture.run = { ...fixture.run, status: 200 };
    fixture.lifetime = { status: 500 };
    expect(await observe()).toMatchObject({ kind: "unavailable", reason: expect.stringContaining(`${lifetimeExtensionConstraint} policy of projects/882468538648: HTTP 500`) });
    fixture.lifetime = { status: 404 };
    fixture.identity = { ...fixture.identity, uniqueId: "199990000000000000000" };
    expect(await observe()).toMatchObject({ kind: "unavailable", reason: expect.stringContaining("does not resolve to") });
  });
});

describe.skipIf(!emulatorHost)("inventory binds readiness (Firestore emulator)", () => {
  test("a finding refuses acceptance; a change during the interval voids the chain and blocks every gate until a new chain completes; an unavailable inventory blocks the gate", async () => {
    const w = await world();
    const { broker, clock, inventory, ledger } = w;
    const consumer = w.authority.consumers.find((candidate) => candidate.repository === "cdbentley")!;
    const targets = targetsFor(w.authority, consumer)!;
    seedTargets(w.iam, targets);
    const purpose = purposeForIdentity(w.authority, invokerEmail("cdbentley"))!;
    const first = targets[0]!;
    const finding = `grant:${first.resource}|projects/cdbentley/roles/credentialMinter|user:evil@example.com`;
    inventory.findings.set(first.uniqueId, [finding]);
    expect(await broker.handle(purpose, quarantine("q", "cdbentley", "k1"))).toEqual({ status: 409, body: { blockers: [`${first.account}: ${finding}`], error: "INVENTORY_BLOCKED" } });
    expect(await ledger.readShard("q")).toBeUndefined();
    expect(w.iam.writes).toHaveLength(0);
    inventory.findings.delete(first.uniqueId);
    expect((await broker.handle(purpose, quarantine("q", "cdbentley", "k1"))).status).toBe(201);
    await makeReady(w, "q");
    expect(scanReadiness((await ledger.readShard("q"))!, clock.now).ready).toBe(true);
    const baseline = (await ledger.readShard("q"))!.targets[first.account]!.chain.inventory!;
    // Something in the first target's inventory changes after readiness: the close is refused, the change is journaled,
    // the chain is voided, and readiness is rebuilt only by a new DENIED chain after the change.
    inventory.change(first.uniqueId);
    clock.advance(1);
    const refused = await broker.handle(purpose, close("q", "c1"));
    expect(refused).toEqual({ status: 409, body: { blockers: [`${first.account}: no DENIED impersonation probe after the quarantine acknowledgement`], error: "NOT_READY" } });
    const changed = (await ledger.readShard("q"))!.targets[first.account]!.chain;
    expect(changed).toMatchObject({ inventory: { changes: 1, observedAt: clock.now.toISOString() }, post: null, revocation: null });
    expect(changed.inventory!.hash).not.toBe(baseline.hash);
    const entries = await ledger.readEntries("q", (await ledger.readShard("q"))!.nextSequence - 1);
    expect(entries.at(-1)!.body).toMatchObject({ kind: "inventory", account: first.account, hash: changed.inventory!.hash });
    await makeReady(w, "q");
    expect(scanReadiness((await ledger.readShard("q"))!, clock.now).ready).toBe(true);
    // The inventory cannot be observed at the gate: the gate is refused.
    inventory.unavailable = 9;
    expect(await broker.handle(purpose, close("q", "c2"))).toMatchObject({ status: 409, body: { blockers: targets.map((target) => `${target.account}: credential inventory is unavailable at the gate`), error: "NOT_READY" } });
    expect((await ledger.readShard("q"))!.phase).toBe("OPEN");
    expect((await broker.handle(purpose, close("q", "c3"))).status).toBe(200);
    // A change between begin-close and finish-close keeps the shard CLOSING; the tainted interval is never certified.
    inventory.change(first.uniqueId);
    const view = await broker.reconcileShard("q");
    expect(view).toMatchObject({ phase: "CLOSING", terminal: null });
    expect((view as { notes: string[] }).notes).toEqual([expect.stringContaining(`close pending; not scan-ready: ${first.account}: credential inventory changed since`)]);
    expect(w.evidence.objects.has("shards/q/close.json")).toBe(false);
    // Restore admission re-observes the source: a CLOSED source whose inventory changed after its close is not restorable.
    const runsetta = w.authority.consumers.find((candidate) => candidate.repository === "runsetta")!;
    const runsettaTargets = targetsFor(w.authority, runsetta)!;
    seedTargets(w.iam, runsettaTargets);
    const isolate = purposeForIdentity(w.authority, invokerEmail("runsetta"))!;
    expect((await broker.handle(isolate, quarantine("rq", "runsetta", "k1"))).status).toBe(201);
    await makeReady(w, "rq");
    expect((await broker.handle(isolate, close("rq", "c"))).status).toBe(200);
    expect(await broker.reconcileShard("rq")).toMatchObject({ phase: "CLOSED" });
    const restorer = purposeForIdentity(w.authority, invokerEmail("runsetta", "RESTORE"))!;
    inventory.change(runsettaTargets[3]!.uniqueId);
    expect(await broker.handle(restorer, restore("rr", "runsetta", "k2", "rq"))).toMatchObject({ status: 409, body: { detail: expect.stringContaining(`${runsettaTargets[3]!.account}: credential inventory changed since`), error: "SOURCE_NOT_COMPLETE" } });
    expect(await ledger.readShard("rr")).toBeUndefined();
  }, 120_000);
});
