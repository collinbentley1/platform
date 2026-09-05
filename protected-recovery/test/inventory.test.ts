import { describe, expect, test } from "bun:test";
import { GoogleCredentialInventory, actuatorPermissions, actuatorRoleId, lifetimeExtensionConstraint } from "../src/inventory";
import { type Consumer, type RecoveryAuthority, type Target, brokerMember, managedRole, purposeForIdentity, scanReadiness, targetsFor } from "../src/model";
import { Clock, close, emulatorHost, invokerEmail, makeReady, quarantine, restore, seedTargets, testAuthority, world } from "./support";

// The inventory adapter against stand-ins of the authoritative APIs it
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

interface RunRegion {
  readonly executions: unknown[];
  readonly jobs: unknown[];
  readonly revisions: unknown[];
  // Services, split into pages when more than one is given.
  readonly services: unknown[][];
}

interface BuildRegion {
  readonly builds: unknown[];
  readonly triggers: unknown[];
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
  run: { status: number; body?: unknown; locations: unknown[] | { status: number }; regions: Record<string, RunRegion> };
  build: { status: number; body?: unknown; discovery: unknown | { status: number }; regions: Record<string, BuildRegion> };
}

const endpoints = { cloudBuild: "https://cloudbuild.test", compute: "https://compute.test", iam: "https://iam.test", orgPolicy: "https://orgpolicy.test", resourceManager: "https://rm.test", run: "https://run.test" };
const organization = "organizations/100000000001";
const actuatorRole = `projects/cdbentley/roles/${actuatorRoleId}`;
const location = (id: string) => ({ displayName: id, locationId: id, name: `projects/cdbentley/locations/${id}` });
const endpoint = (region: string) => ({ description: region, endpointUrl: `https://${region}-cloudbuild.googleapis.com/`, location: region });
const emptyRun: RunRegion = { executions: [], jobs: [], revisions: [], services: [[]] };
const emptyBuild: BuildRegion = { builds: [], triggers: [] };

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { headers: { "content-type": "application/json" }, status });
}

function disabled(service: string): unknown {
  return { error: { code: 403, details: [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo", domain: "googleapis.com", metadata: { service }, reason: "SERVICE_DISABLED" }], message: `${service} has not been used in project before or it is disabled.`, status: "PERMISSION_DENIED" } };
}

function clean(authority: RecoveryAuthority, target: Target): Fixture {
  return {
    build: { discovery: { endpoints: [endpoint("us-east4")] }, regions: { global: emptyBuild, "us-east4": emptyBuild }, status: 200 },
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
    run: { locations: [location("us-east4")], regions: { "us-east4": emptyRun }, status: 200 },
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

function routes(f: Fixture, target: Target, consumer: Consumer, others: readonly Target[] = []): Fetcher {
  const page = <T>(items: T[][], token: string | null, field: string): Response => {
    const index = token === null ? 0 : Number(token);
    const found = items[index];
    if (!found) return json(400, { error: { status: "INVALID_ARGUMENT" } });
    return json(200, { [field]: found, ...(index + 1 < items.length ? { nextPageToken: String(index + 1) } : {}) });
  };
  return Object.assign(async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    const path = url.pathname;
    f.calls.push(`${method} ${url.origin}${path}${url.search}`);
    const bearer = (init?.headers as Record<string, string> | undefined)?.Authorization;
    if (url.origin === endpoints.cloudBuild && path === "/$discovery/rest") {
      if (bearer !== undefined) return json(400, {});
      const discovery = f.build.discovery as { status?: number };
      return typeof discovery.status === "number" ? json(discovery.status, {}) : json(200, f.build.discovery);
    }
    if (bearer !== "Bearer broker-token") return json(401, { error: { status: "UNAUTHENTICATED" } });
    switch (url.origin) {
      case endpoints.iam: {
        if (path === `/v1/${target.resource}` && method === "GET") return json(200, { email: f.identity.email, name: target.resource, uniqueId: f.identity.uniqueId });
        if (path === `/v1/${target.resource}:getIamPolicy` && method === "POST") return json(200, { ...f.saPolicy, version: 3 });
        if (path === `/v1/${target.resource}/keys` && url.searchParams.get("keyTypes") === "USER_MANAGED") return json(200, f.keys.length === 0 ? {} : { keys: f.keys });
        // Every other target of the consumer is clean and answers for itself.
        const other = others.find((candidate) => path.startsWith(`/v1/${candidate.resource}`));
        if (other && path === `/v1/${other.resource}`) return json(200, { email: other.email, name: other.resource, uniqueId: other.uniqueId });
        if (other && path === `/v1/${other.resource}:getIamPolicy`) return json(200, { bindings: [{ members: [...other.members], role: managedRole }], etag: `sa-${other.account}`, version: 3 });
        if (other && path === `/v1/${other.resource}/keys`) return json(200, {});
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
        if (path === `/v1/projects/${consumer.projectId}/locations`) {
          const locations = f.run.locations as { status?: number };
          return typeof locations.status === "number" ? json(locations.status, { error: { status: "PERMISSION_DENIED" } }) : json(200, { locations: f.run.locations });
        }
        const match = new RegExp(`^/v2/projects/${consumer.projectId}/locations/([a-z0-9-]+)/(services|services/-/revisions|jobs|jobs/-/executions)$`).exec(path);
        const region = match ? f.run.regions[match[1]!] : undefined;
        if (!match || !region) return json(404, {});
        const token = url.searchParams.get("pageToken");
        switch (match[2]) {
          case "services":
            return page(region.services, token, "services");
          case "services/-/revisions":
            return page([region.revisions], token, "revisions");
          case "jobs":
            return page([region.jobs], token, "jobs");
          default:
            return page([region.executions], token, "executions");
        }
      }
      case endpoints.cloudBuild: {
        if (f.build.status !== 200) return json(f.build.status, f.build.body ?? disabled("cloudbuild.googleapis.com"));
        const match = new RegExp(`^/v1/projects/${consumer.projectId}/locations/([a-z0-9-]+)/(triggers|builds)$`).exec(path);
        const region = match ? f.build.regions[match[1]!] : undefined;
        if (!match || !region) return json(404, {});
        if (match[2] === "builds") {
          if (url.searchParams.get("filter") !== 'status="PENDING" OR status="QUEUED" OR status="WORKING"') return json(400, { error: { status: "INVALID_ARGUMENT" } });
          return json(200, { builds: region.builds });
        }
        return json(200, { triggers: region.triggers });
      }
      default:
        return json(404, {});
    }
  }, { preconnect: fetch.preconnect });
}

async function harness(account = 0) {
  const authority = await testAuthority();
  const consumer = authority.consumers.find((candidate) => candidate.repository === "cdbentley")!;
  const targets = targetsFor(authority, consumer)!;
  const target = targets[account]!;
  const fixture = clean(authority, target);
  const clock = new Clock();
  const inventory = new GoogleCredentialInventory({ authority, endpoints, fetch: routes(fixture, target, consumer, targets.filter((candidate) => candidate !== target)), now: clock.read, token: async () => "broker-token" });
  // A project snapshot serves the window after it was read; the next observation after this reads the world again.
  const fresh = () => clock.advance(61);
  const observe = async (of = target) => await inventory.inventory(of, consumer);
  const findingsOf = async () => {
    fresh();
    const outcome = await observe();
    if (outcome.kind !== "observed") throw new Error(outcome.reason);
    return outcome.inventory.findings;
  };
  return { authority, clock, consumer, findingsOf, fixture, fresh, inventory, observe, target };
}

describe("credential inventory", () => {
  test("a clean target: every ancestry policy with its etag, every role expanded exactly once, no keys, no lifetime extension, no attachment in any listed region, a stable hash", async () => {
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
    // Cloud Run was enumerated from its own location list and every region's four lists; Cloud Build from its discovery
    // document, the global location and every regional endpoint, each with triggers and current builds.
    expect(fixture.calls.filter((call) => call.startsWith("GET https://run.test/"))).toEqual([
      "GET https://run.test/v1/projects/cdbentley/locations",
      "GET https://run.test/v2/projects/cdbentley/locations/us-east4/services",
      "GET https://run.test/v2/projects/cdbentley/locations/us-east4/services/-/revisions",
      "GET https://run.test/v2/projects/cdbentley/locations/us-east4/jobs",
      "GET https://run.test/v2/projects/cdbentley/locations/us-east4/jobs/-/executions",
    ]);
    expect(fixture.calls.filter((call) => call.startsWith("GET https://cloudbuild.test/")).sort()).toEqual([
      "GET https://cloudbuild.test/$discovery/rest?version=v1",
      "GET https://cloudbuild.test/v1/projects/cdbentley/locations/global/builds?filter=status%3D%22PENDING%22%20OR%20status%3D%22QUEUED%22%20OR%20status%3D%22WORKING%22",
      "GET https://cloudbuild.test/v1/projects/cdbentley/locations/global/triggers",
      "GET https://cloudbuild.test/v1/projects/cdbentley/locations/global/triggers",
      "GET https://cloudbuild.test/v1/projects/cdbentley/locations/us-east4/builds?filter=status%3D%22PENDING%22%20OR%20status%3D%22QUEUED%22%20OR%20status%3D%22WORKING%22",
      "GET https://cloudbuild.test/v1/projects/cdbentley/locations/us-east4/triggers",
    ]);
    // The same world hashes the same; any moved etag hashes differently even with the same findings.
    clock.advance(120);
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

  test("Compute instances and templates, Cloud Run services, serving revisions, jobs, and in-flight executions in every region and page, and Cloud Build triggers and current builds in every region that run as the target are found", async () => {
    const { findingsOf, fixture, observe, target } = await harness();
    fixture.compute = {
      status: 200,
      instances: { "zones/us-east4-a": { instances: [{ name: "vm-1", serviceAccounts: [{ email: target.email }] }, { name: "vm-2", serviceAccounts: [{ email: "other@cdbentley.iam.gserviceaccount.com" }] }] }, "zones/us-east4-b": { warning: { code: "NO_RESULTS_ON_PAGE" } } },
      templates: { global: { instanceTemplates: [{ name: "tpl-1", properties: { serviceAccounts: [{ email: target.email }] } }] }, "regions/us-east4": { instanceTemplates: [{ name: "tpl-2", properties: {} }] } },
    };
    const service = (region: string, name: string) => `projects/cdbentley/locations/${region}/services/${name}`;
    const job = (region: string, name: string) => `projects/cdbentley/locations/${region}/jobs/${name}`;
    fixture.run = {
      locations: [location("us-east4"), location("europe-west1")],
      regions: {
        "europe-west1": {
          executions: [],
          jobs: [],
          revisions: [{ name: `${service("europe-west1", "far")}/revisions/far-00003-a`, serviceAccount: target.email }, { name: `${service("europe-west1", "far")}/revisions/far-00004-b`, serviceAccount: "other@cdbentley.iam.gserviceaccount.com" }],
          // The service moved to another identity; the old revision still serves by tag.
          services: [[{ latestReadyRevision: `${service("europe-west1", "far")}/revisions/far-00004-b`, name: service("europe-west1", "far"), template: { serviceAccount: "other@cdbentley.iam.gserviceaccount.com" }, trafficStatuses: [{ percent: 100, revision: "far-00004-b", type: "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION" }, { percent: 0, revision: "far-00003-a", tag: "old", type: "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION" }] }]],
        },
        "us-east4": {
          executions: [
            { completionTime: "2026-09-04T11:00:00Z", name: `${job("us-east4", "nightly")}/executions/nightly-done`, template: { serviceAccount: target.email } },
            { name: `${job("us-east4", "nightly")}/executions/nightly-live`, runningCount: 1, template: { serviceAccount: target.email } },
            { name: `${job("us-east4", "other")}/executions/other-live`, template: { serviceAccount: "other@cdbentley.iam.gserviceaccount.com" } },
          ],
          jobs: [{ name: job("us-east4", "nightly"), template: { template: { serviceAccount: target.email } } }, { name: job("us-east4", "other"), template: { template: { serviceAccount: "other@cdbentley.iam.gserviceaccount.com" } } }],
          revisions: [
            { name: `${service("us-east4", "other")}/revisions/other-00001-x`, serviceAccount: "other@cdbentley.iam.gserviceaccount.com" },
            { name: `${service("us-east4", "app")}/revisions/app-00002-y`, serviceAccount: target.email },
            { name: `${service("us-east4", "app")}/revisions/app-00001-z`, serviceAccount: target.email },
            { name: `${service("us-east4", "legacy")}/revisions/legacy-00007-q`, serviceAccount: target.email },
            { name: `${service("us-east4", "legacy")}/revisions/legacy-00008-r`, serviceAccount: "other@cdbentley.iam.gserviceaccount.com" },
          ],
          services: [
            [{ latestReadyRevision: `${service("us-east4", "other")}/revisions/other-00001-x`, name: service("us-east4", "other"), template: { serviceAccount: "other@cdbentley.iam.gserviceaccount.com" }, trafficStatuses: [{ percent: 100, revision: "other-00001-x", type: "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST" }] }],
            [
              { latestReadyRevision: `${service("us-east4", "app")}/revisions/app-00002-y`, name: service("us-east4", "app"), template: { serviceAccount: target.email }, trafficStatuses: [{ percent: 100, revision: "app-00002-y", type: "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST" }] },
              // The template moved to another identity, but the revision that still takes all the traffic is the target's.
              { latestReadyRevision: `${service("us-east4", "legacy")}/revisions/legacy-00008-r`, name: service("us-east4", "legacy"), template: { serviceAccount: "other@cdbentley.iam.gserviceaccount.com" }, trafficStatuses: [{ percent: 100, revision: "legacy-00007-q", type: "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION" }] },
            ],
          ],
        },
      },
      status: 200,
    };
    fixture.build = {
      discovery: { endpoints: [endpoint("us-east4"), endpoint("europe-west1")] },
      regions: {
        "europe-west1": { builds: [{ id: "b-far", serviceAccount: `projects/882468538648/serviceAccounts/${target.uniqueId}`, status: "QUEUED" }], triggers: [] },
        global: {
          builds: [{ id: "b-manual", serviceAccount: `projects/cdbentley/serviceAccounts/${target.email}`, status: "WORKING" }, { id: "b-done", serviceAccount: `projects/cdbentley/serviceAccounts/${target.email}`, status: "SUCCESS" }, { id: "b-other", serviceAccount: "projects/cdbentley/serviceAccounts/other@cdbentley.iam.gserviceaccount.com", status: "WORKING" }],
          triggers: [{ resourceName: "projects/cdbentley/locations/global/triggers/deploy", serviceAccount: `projects/cdbentley/serviceAccounts/${target.email}` }, { id: "abc", serviceAccount: "projects/cdbentley/serviceAccounts/other@cdbentley.iam.gserviceaccount.com" }],
        },
        "us-east4": { builds: [], triggers: [{ id: "regional", serviceAccount: `projects/882468538648/serviceAccounts/${target.email}` }] },
      },
      status: 200,
    };
    expect(await findingsOf()).toEqual([
      "attachment:cloudbuild.googleapis.com/projects/cdbentley/locations/europe-west1/builds/b-far",
      "attachment:cloudbuild.googleapis.com/projects/cdbentley/locations/global/builds/b-manual",
      "attachment:cloudbuild.googleapis.com/projects/cdbentley/locations/global/triggers/deploy",
      "attachment:cloudbuild.googleapis.com/projects/cdbentley/locations/us-east4/triggers/regional",
      "attachment:compute.googleapis.com/projects/cdbentley/global/instanceTemplates/tpl-1",
      "attachment:compute.googleapis.com/projects/cdbentley/zones/us-east4-a/instances/vm-1",
      `attachment:run.googleapis.com/${service("europe-west1", "far")}/revisions/far-00003-a`,
      `attachment:run.googleapis.com/${job("us-east4", "nightly")}`,
      `attachment:run.googleapis.com/${job("us-east4", "nightly")}/executions/nightly-live`,
      `attachment:run.googleapis.com/${service("us-east4", "app")}`,
      `attachment:run.googleapis.com/${service("us-east4", "app")}/revisions/app-00002-y`,
      `attachment:run.googleapis.com/${service("us-east4", "legacy")}/revisions/legacy-00007-q`,
    ]);
    const outcome = await observe();
    if (outcome.kind !== "observed") throw new Error(outcome.reason);
    expect(outcome.inventory.summary.services).toEqual(["cloudbuild.googleapis.com:enabled", "compute.googleapis.com:enabled", "run.googleapis.com:enabled"]);
    expect(fixture.calls.filter((call) => call.includes("/locations/us-east4/services?pageToken="))).toEqual(["GET https://run.test/v2/projects/cdbentley/locations/us-east4/services?pageToken=1"]);
  });

  test("a serving revision the region does not list, an incomplete page, an unlistable region set, or an unreadable Cloud Build discovery document makes the inventory unavailable, never clean", async () => {
    const { fixture, fresh, observe } = await harness();
    const app = "projects/cdbentley/locations/us-east4/services/app";
    fixture.run.regions = { "us-east4": { ...emptyRun, services: [[{ latestReadyRevision: `${app}/revisions/app-00001-a`, name: app, template: { serviceAccount: "other@cdbentley.iam.gserviceaccount.com" }, trafficStatuses: [] }]] } };
    expect(await observe()).toEqual({ kind: "unavailable", reason: `Cloud Run serves ${app}/revisions/app-00001-a but did not list it in us-east4` });
    fresh();
    // A page the region cannot complete.
    fixture.run.regions = { "us-east4": { ...emptyRun, services: [[{ name: `${app}-1`, template: {} }], undefined as unknown as unknown[]] } };
    expect(await observe()).toMatchObject({ kind: "unavailable", reason: expect.stringContaining("locations/us-east4/services: HTTP 400") });
    fresh();
    fixture.run.regions = { "us-east4": emptyRun };
    fixture.run.locations = [location("us-east4"), location("asia-east1")];
    expect(await observe()).toMatchObject({ kind: "unavailable", reason: expect.stringContaining("locations/asia-east1/services: HTTP 404") });
    fresh();
    fixture.run.locations = [];
    expect(await observe()).toEqual({ kind: "unavailable", reason: "Cloud Run listed no region for cdbentley" });
    fresh();
    fixture.run.locations = { status: 403 };
    expect(await observe()).toMatchObject({ kind: "unavailable", reason: expect.stringContaining("/v1/projects/cdbentley/locations: HTTP 403") });
    fresh();
    fixture.run.locations = [location("us-east4")];
    fixture.build.discovery = { status: 503 };
    expect(await observe()).toEqual({ kind: "unavailable", reason: "the Cloud Build discovery document: HTTP 503" });
    fresh();
    fixture.build.discovery = { endpoints: [] };
    expect(await observe()).toEqual({ kind: "unavailable", reason: "the Cloud Build discovery document lists no region" });
    fresh();
    fixture.build.discovery = { endpoints: [endpoint("us-east4"), endpoint("northamerica-northeast1")] };
    expect(await observe()).toMatchObject({ kind: "unavailable", reason: expect.stringContaining("locations/northamerica-northeast1/triggers: HTTP 404") });
  });

  test("one project snapshot serves every target of the project within its window, dated at the snapshot; a failed read is never reused", async () => {
    const { authority, clock, consumer, fixture, inventory, observe } = await harness();
    const other = targetsFor(authority, consumer)![1]!;
    const listings = () => fixture.calls.filter((call) => call.includes("/locations") || call.includes("$discovery")).length;
    const first = await observe();
    if (first.kind !== "observed") throw new Error(first.reason);
    const afterFirst = listings();
    clock.advance(30);
    const second = await observe(other);
    if (second.kind !== "observed") throw new Error(second.reason);
    expect(listings()).toBe(afterFirst);
    expect(second.inventory.observedAt).toBe(first.inventory.observedAt);
    clock.advance(31);
    const third = await observe();
    if (third.kind !== "observed") throw new Error(third.reason);
    expect(listings()).toBeGreaterThan(afterFirst);
    expect(third.inventory.observedAt).toBe(clock.now.toISOString());
    // A read that fails is not a snapshot: the next observation reads again.
    fixture.run.locations = { status: 403 };
    clock.advance(61);
    expect((await observe()).kind).toBe("unavailable");
    const afterFailure = listings();
    fixture.run.locations = [location("us-east4")];
    expect((await inventory.inventory(other, consumer)).kind).toBe("observed");
    expect(listings()).toBeGreaterThan(afterFailure);
  });

  test("the broker's own actuator grant is exempt only while its role carries exactly the actuator permissions", async () => {
    const { authority, findingsOf, fixture, target } = await harness();
    fixture.roles = { ...fixture.roles, [actuatorRole]: [...actuatorPermissions, "iam.serviceAccounts.getAccessToken"] };
    expect(await findingsOf()).toEqual([`grant:${target.resource}|${actuatorRole}|${brokerMember(authority)}`]);
  });

  test("an answer the broker cannot classify makes the inventory unavailable, never clean", async () => {
    const { fixture, fresh, observe } = await harness();
    fixture.roles = { ...fixture.roles, "roles/viewer": { status: 403 } };
    expect(await observe()).toEqual({ kind: "unavailable", reason: "role roles/viewer: HTTP 403" });
    fresh();
    fixture.roles = { ...fixture.roles, "roles/viewer": ["resourcemanager.projects.get"] };
    fixture.run = { ...fixture.run, status: 403, body: { error: { code: 403, message: "The caller does not have permission", status: "PERMISSION_DENIED" } } };
    expect(await observe()).toMatchObject({ kind: "unavailable", reason: expect.stringContaining("run.test/v1/projects/cdbentley/locations: HTTP 403") });
    fresh();
    fixture.run = { ...fixture.run, status: 200 };
    fixture.lifetime = { status: 500 };
    expect(await observe()).toMatchObject({ kind: "unavailable", reason: expect.stringContaining(`${lifetimeExtensionConstraint} policy of projects/882468538648: HTTP 500`) });
    fixture.lifetime = { status: 404 };
    fixture.identity = { ...fixture.identity, uniqueId: "199990000000000000000" };
    expect(await observe()).toMatchObject({ kind: "unavailable", reason: expect.stringContaining("does not resolve to") });
  });
});

describe.skipIf(!emulatorHost)("inventory binds readiness (Firestore emulator)", () => {
  test("a finding refuses acceptance; a change during the interval voids every member's chain and blocks every gate until a new chain completes; an unavailable inventory blocks the gate", async () => {
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
    // every member's chain is voided, and readiness is rebuilt only by new DENIED chains after the change.
    inventory.change(first.uniqueId);
    clock.advance(1);
    const refused = await broker.handle(purpose, close("q", "c1"));
    expect(refused).toEqual({ status: 409, body: { blockers: first.members.map((member) => `${first.account}: no DENIED impersonation probe of ${member} after the quarantine acknowledgement`), error: "NOT_READY" } });
    const changed = (await ledger.readShard("q"))!.targets[first.account]!.chain;
    expect(changed).toMatchObject({ inventory: { changes: 1, observedAt: clock.now.toISOString() } });
    for (const member of first.members) expect(changed.members[member]).toMatchObject({ post: null, revocation: null });
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
  }, 180_000);

  test("an attachment landing between an inventory observation and the transaction it gates is caught at the next gate: after begin-close the shard never finalizes, after finish-close the restore is refused", async () => {
    const w = await world();
    const { broker, clock, inventory, ledger } = w;
    const consumer = w.authority.consumers.find((candidate) => candidate.repository === "cdbentley")!;
    const targets = targetsFor(w.authority, consumer)!;
    seedTargets(w.iam, targets);
    const purpose = purposeForIdentity(w.authority, invokerEmail("cdbentley"))!;
    const first = targets[0]!;
    const attachment = "attachment:run.googleapis.com/projects/cdbentley/locations/us-east4/services/app/revisions/app-00009-k";
    const attach = () => inventory.findings.set(first.uniqueId, [attachment]);
    // Race at the begin-close boundary: the target is attached right after the gate's observation read it clean, before
    // the transaction commits. The close commits CLOSING on what it observed; the next reconcile re-observes, finds the
    // attachment, and the shard stays CLOSING with no terminal receipt; a restore is refused.
    expect((await broker.handle(purpose, quarantine("q1", "cdbentley", "k1"))).status).toBe(201);
    await makeReady(w, "q1");
    clock.advance(1);
    inventory.afterObserve = (target) => {
      if (target.uniqueId === first.uniqueId) attach();
    };
    expect((await broker.handle(purpose, close("q1", "c1"))).status).toBe(200);
    expect((await ledger.readShard("q1"))!.phase).toBe("CLOSING");
    const stuck = await broker.reconcileShard("q1");
    expect(stuck).toMatchObject({ phase: "CLOSING", terminal: null });
    expect((stuck as { notes: string[] }).notes).toEqual([expect.stringContaining(`close pending; not scan-ready: ${first.account}: alternate credential paths at the gate ${attachment}`)]);
    expect(w.evidence.objects.has("shards/q1/close.json")).toBe(false);
    expect(await broker.handle(purposeForIdentity(w.authority, invokerEmail("cdbentley", "RESTORE"))!, restore("r1", "cdbentley", "k2", "q1"))).toMatchObject({ status: 409, body: { error: "SOURCE_NOT_COMPLETE" } });
    inventory.findings.delete(first.uniqueId);
    // Race at the finish-close boundary, on another consumer whose members still stand: the attachment lands right
    // after the finishing observation read it clean. The close finalizes on what it observed and the shard is CLOSED
    // -- the interval this software cannot fence by itself, which the evidenced Deny matrix freezes (attachment
    // creation is denied while the matrix stands) -- and the very next gate, restore admission, re-observes and
    // refuses the attached target.
    const runsetta = w.authority.consumers.find((candidate) => candidate.repository === "runsetta")!;
    const runsettaTargets = targetsFor(w.authority, runsetta)!;
    seedTargets(w.iam, runsettaTargets);
    const isolate = purposeForIdentity(w.authority, invokerEmail("runsetta"))!;
    const attached = runsettaTargets[0]!;
    expect((await broker.handle(isolate, quarantine("q2", "runsetta", "k3"))).status).toBe(201);
    await makeReady(w, "q2");
    expect((await broker.handle(isolate, close("q2", "c2"))).status).toBe(200);
    inventory.afterObserve = (target) => {
      if (target.uniqueId === attached.uniqueId) inventory.findings.set(attached.uniqueId, [attachment]);
    };
    expect(await broker.reconcileShard("q2")).toMatchObject({ phase: "CLOSED", terminal: { state: "PROJECTED" } });
    expect(await broker.handle(purposeForIdentity(w.authority, invokerEmail("runsetta", "RESTORE"))!, restore("r2", "runsetta", "k4", "q2"))).toMatchObject({ status: 409, body: { detail: expect.stringContaining(`${attached.account}: alternate credential paths at the gate ${attachment}`), error: "SOURCE_NOT_COMPLETE" } });
    expect(await ledger.readShard("r2")).toBeUndefined();
  }, 180_000);
});
