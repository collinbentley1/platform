import { type JsonResponse, type Policy, policyFromJson, sendJson } from "./effects";
import {
  type Consumer,
  type InventoryRecord,
  type InventorySummary,
  type RecoveryAuthority,
  type Target,
  brokerMember,
  inventoryHash,
  isRecord,
  managedRole,
} from "./model";

// The credential inventory of one target: every path by which a principal
// other than the modeled federated members could mint, sign for, key,
// attach to, or re-grant the target's credentials. It is read from the
// authoritative APIs only -- never from an analysis service -- and any
// answer the broker cannot classify makes the whole inventory unavailable,
// which blocks readiness rather than passing as clean.
//
//   allow policies   the target's own policy, then its project's, each
//                    folder's, and the organization's, every role expanded
//                    through iam.roles.get so custom and basic roles count
//   keys             user-managed keys of the target
//   lifetime         the effective iam.allowServiceAccountCredentialLifetimeExtension
//                    policy of the project, which can stretch a token to 12 hours
//   federation       any principal of the consumer's pool granted anywhere in
//                    the ancestry, other than the managed members on the target
//   attachments      Compute instances and templates; Cloud Run services,
//                    their traffic-serving revisions, jobs, and in-flight
//                    executions in every region the project can use; and
//                    Cloud Build triggers and current builds in every Cloud
//                    Build region -- each region enumerated from the API
//                    itself and every page completed, or the inventory is
//                    unavailable
//
// Domain-wide delegation is not a resource the IAM API exposes; exercising it
// requires signing a JWT as the target, which needs a user-managed key or a
// signJwt/signBlob grant, both of which this inventory records.

export type InventoryOutcome =
  | { readonly kind: "observed"; readonly inventory: InventoryRecord }
  | { readonly kind: "unavailable"; readonly reason: string };

export interface CredentialInventory {
  inventory(target: Target, consumer: Consumer): Promise<InventoryOutcome>;
}

// Permissions that issue, sign for, key, attach, or re-grant a service
// account's credentials. A binding whose expanded role carries any of them
// is a credential-capable grant.
export const credentialPermissions: readonly string[] = [
  "iam.serviceAccountKeys.create",
  "iam.serviceAccounts.actAs",
  "iam.serviceAccounts.getAccessToken",
  "iam.serviceAccounts.getOpenIdToken",
  "iam.serviceAccounts.implicitDelegation",
  "iam.serviceAccounts.setIamPolicy",
  "iam.serviceAccounts.signBlob",
  "iam.serviceAccounts.signJwt",
  "resourcemanager.folders.setIamPolicy",
  "resourcemanager.organizations.setIamPolicy",
  "resourcemanager.projects.setIamPolicy",
];

// The one modeled grant besides the managed members: the broker's actuator
// role on the target itself, carrying exactly these permissions.
export const actuatorRoleId = "protectedRecoveryActuator";
export const actuatorPermissions: readonly string[] = ["iam.serviceAccountKeys.list", "iam.serviceAccounts.get", "iam.serviceAccounts.getIamPolicy", "iam.serviceAccounts.setIamPolicy"];
export const lifetimeExtensionConstraint = "iam.allowServiceAccountCredentialLifetimeExtension";

export function inventoryFindings(summary: InventorySummary): readonly string[] {
  return [
    ...summary.grants.map((grant) => `grant:${grant}`),
    ...summary.keys.map((key) => `key:${key}`),
    ...(summary.lifetimeExtension === null ? [] : [`lifetime-extension:${summary.lifetimeExtension}`]),
    ...summary.attachments.map((attachment) => `attachment:${attachment}`),
  ];
}

export interface InventoryDependencies {
  readonly authority: RecoveryAuthority;
  readonly endpoints?: { readonly cloudBuild?: string; readonly compute?: string; readonly iam?: string; readonly orgPolicy?: string; readonly resourceManager?: string; readonly run?: string };
  readonly fetch: typeof fetch;
  readonly now: () => Date;
  readonly token: () => Promise<string>;
}

class Unavailable extends Error {}

const maxPages = 100;
const maxAncestryDepth = 10;
// Attachment listings are per project, not per target: one snapshot of a
// consumer project's regions and workloads serves every target of that
// project observed within this window, and the record of each target is
// dated at the snapshot, never later.
const snapshotTtlMs = 60_000;
const regionConcurrency = 8;
// Cloud Build workloads that still run or are about to: a completed build
// holds no credential.
const currentBuildStatuses = ["PENDING", "QUEUED", "WORKING"];

interface RunRegion {
  readonly executions: readonly unknown[];
  readonly jobs: readonly unknown[];
  readonly region: string;
  readonly revisions: readonly unknown[];
  readonly services: readonly unknown[];
}

interface BuildRegion {
  readonly builds: readonly unknown[];
  readonly region: string;
  readonly triggers: readonly unknown[];
}

// Everything attachment-related the broker read from one consumer project,
// dated when the reads began.
interface Snapshot {
  readonly build: readonly BuildRegion[] | "disabled";
  readonly compute: { readonly instances: ReadonlyArray<readonly [string, unknown]>; readonly templates: ReadonlyArray<readonly [string, unknown]> } | "disabled";
  readonly observedAt: string;
  readonly run: readonly RunRegion[] | "disabled";
}

export class GoogleCredentialInventory implements CredentialInventory {
  readonly #deps: InventoryDependencies;
  readonly #snapshots = new Map<string, Promise<Snapshot>>();

  constructor(deps: InventoryDependencies) {
    this.#deps = deps;
  }

  async inventory(target: Target, consumer: Consumer): Promise<InventoryOutcome> {
    try {
      const bearer = await this.#deps.token();
      const snapshot = await this.#snapshot(consumer, bearer);
      const summary = await this.#summarize(target, consumer, bearer, snapshot);
      return { kind: "observed", inventory: { account: target.account, email: target.email, findings: inventoryFindings(summary), hash: inventoryHash(summary), observedAt: snapshot.observedAt, summary, uniqueId: target.uniqueId } };
    } catch (error) {
      if (error instanceof Unavailable) return { kind: "unavailable", reason: error.message };
      throw error;
    }
  }

  // The project snapshot in force, or a fresh one: a failed read is never
  // cached, and a snapshot older than its window is replaced.
  async #snapshot(consumer: Consumer, bearer: string): Promise<Snapshot> {
    const cached = this.#snapshots.get(consumer.projectId);
    if (cached) {
      const snapshot = await cached.catch(() => undefined);
      if (snapshot && this.#deps.now().getTime() - Date.parse(snapshot.observedAt) < snapshotTtlMs) return snapshot;
    }
    const pending = this.#read(consumer, bearer);
    this.#snapshots.set(consumer.projectId, pending);
    try {
      return await pending;
    } catch (error) {
      if (this.#snapshots.get(consumer.projectId) === pending) this.#snapshots.delete(consumer.projectId);
      throw error;
    }
  }

  async #read(consumer: Consumer, bearer: string): Promise<Snapshot> {
    const observedAt = this.#deps.now().toISOString();
    const compute = await this.#computeSnapshot(consumer, bearer);
    const run = await this.#runSnapshot(consumer, bearer);
    const build = await this.#buildSnapshot(consumer, bearer);
    return { build, compute, observedAt, run };
  }

  async #summarize(target: Target, consumer: Consumer, bearer: string, snapshot: Snapshot): Promise<InventorySummary> {
    const iam = this.#endpoint("iam");
    const identity = await this.#json("GET", `${iam}/v1/${target.resource}`, undefined, bearer, `identity of ${target.resource}`);
    if (!isRecord(identity) || identity.email !== target.email || identity.uniqueId !== target.uniqueId) {
      throw new Unavailable(`${target.resource} does not resolve to ${target.email} (${target.uniqueId})`);
    }
    const policies: Array<{ readonly policy: Policy; readonly resource: string }> = [{ policy: await this.#policy(`${iam}/v1/${target.resource}:getIamPolicy`, bearer, target.resource), resource: target.resource }];
    const ancestry = [`projects/${consumer.projectNumber}`];
    const resourceManager = this.#endpoint("resourceManager");
    const project = await this.#json("GET", `${resourceManager}/v3/projects/${consumer.projectNumber}`, undefined, bearer, `project ${consumer.projectNumber}`);
    if (!isRecord(project) || project.projectId !== consumer.projectId) throw new Unavailable(`projects/${consumer.projectNumber} is not ${consumer.projectId}`);
    policies.push({ policy: await this.#policy(`${resourceManager}/v3/projects/${consumer.projectNumber}:getIamPolicy`, bearer, `projects/${consumer.projectNumber}`), resource: `projects/${consumer.projectNumber}` });
    let parent = typeof project.parent === "string" ? project.parent : undefined;
    for (let depth = 0; parent !== undefined; depth += 1) {
      if (depth >= maxAncestryDepth) throw new Unavailable(`the ancestry of projects/${consumer.projectNumber} exceeds ${maxAncestryDepth} levels`);
      ancestry.push(parent);
      policies.push({ policy: await this.#policy(`${resourceManager}/v3/${parent}:getIamPolicy`, bearer, parent), resource: parent });
      if (parent.startsWith("organizations/")) break;
      if (!parent.startsWith("folders/")) throw new Unavailable(`${parent} is neither a folder nor an organization`);
      const folder = await this.#json("GET", `${resourceManager}/v3/${parent}`, undefined, bearer, parent);
      parent = isRecord(folder) && typeof folder.parent === "string" ? folder.parent : undefined;
    }
    const permissionsOf = new Map<string, readonly string[]>();
    for (const { policy } of policies) {
      for (const binding of policy.bindings) {
        if (permissionsOf.has(binding.role)) continue;
        permissionsOf.set(binding.role, await this.#rolePermissions(binding.role, bearer));
      }
    }
    const grants = new Set<string>();
    const poolPrefixes = [`principalSet://iam.googleapis.com/${target.pool}/`, `principal://iam.googleapis.com/${target.pool}/`];
    const broker = brokerMember(this.#deps.authority);
    const actuatorRole = `projects/${consumer.projectId}/roles/${actuatorRoleId}`;
    for (const { policy, resource } of policies) {
      for (const binding of policy.bindings) {
        const permissions = permissionsOf.get(binding.role) ?? [];
        const capable = permissions.some((permission) => credentialPermissions.includes(permission));
        const label = `${resource}|${binding.role}${binding.condition ? `[${binding.condition.title}]` : ""}`;
        for (const member of binding.members) {
          const federated = poolPrefixes.some((prefix) => member.startsWith(prefix));
          if (resource === target.resource && binding.condition === null && binding.role === managedRole && target.members.includes(member)) continue;
          if (resource === target.resource && binding.condition === null && binding.role === actuatorRole && member === broker && permissions.every((permission) => actuatorPermissions.includes(permission))) continue;
          if (capable || federated) grants.add(`${label}|${member}`);
        }
      }
    }
    const keys = await this.#keys(target, bearer);
    const lifetimeExtension = await this.#lifetimeExtension(target, consumer, bearer);
    const services = [
      `compute.googleapis.com:${snapshot.compute === "disabled" ? "disabled" : "enabled"}`,
      `run.googleapis.com:${snapshot.run === "disabled" ? "disabled" : "enabled"}`,
      `cloudbuild.googleapis.com:${snapshot.build === "disabled" ? "disabled" : "enabled"}`,
    ];
    const attachments = [...computeAttachments(target, consumer, snapshot), ...runAttachments(target, snapshot), ...buildAttachments(target, consumer, snapshot)];
    return {
      ancestry,
      attachments: [...new Set(attachments)].sort(),
      grants: [...grants].sort(),
      keys,
      lifetimeExtension,
      policies: policies.map(({ policy, resource }) => ({ etag: policy.etag, resource })).sort((left, right) => left.resource.localeCompare(right.resource)),
      services: services.sort(),
    };
  }

  async #policy(url: string, bearer: string, resource: string): Promise<Policy> {
    const body = await this.#json("POST", url, { options: { requestedPolicyVersion: 3 } }, bearer, `the allow policy of ${resource}`);
    try {
      return policyFromJson(body);
    } catch (error) {
      throw new Unavailable(`the allow policy of ${resource} is malformed: ${String(error instanceof Error ? error.message : error)}`);
    }
  }

  // Predefined, basic, and custom roles are all expanded through the same
  // API, so a custom role carrying getAccessToken counts exactly as
  // roles/iam.serviceAccountTokenCreator does.
  async #rolePermissions(role: string, bearer: string): Promise<readonly string[]> {
    if (!/^(?:roles\/[A-Za-z0-9._]+|(?:projects|organizations)\/[A-Za-z0-9._-]+\/roles\/[A-Za-z0-9._]+)$/.test(role)) throw new Unavailable(`${role} is not a role name`);
    const body = await this.#json("GET", `${this.#endpoint("iam")}/v1/${role}`, undefined, bearer, `role ${role}`);
    if (!isRecord(body)) throw new Unavailable(`role ${role} is malformed`);
    const permissions = body.includedPermissions === undefined ? [] : body.includedPermissions;
    if (!Array.isArray(permissions) || !permissions.every((permission): permission is string => typeof permission === "string")) throw new Unavailable(`role ${role} carries malformed permissions`);
    return permissions;
  }

  async #keys(target: Target, bearer: string): Promise<readonly string[]> {
    const body = await this.#json("GET", `${this.#endpoint("iam")}/v1/${target.resource}/keys?keyTypes=USER_MANAGED`, undefined, bearer, `the keys of ${target.resource}`);
    const keys = isRecord(body) && body.keys !== undefined ? body.keys : [];
    if (!Array.isArray(keys)) throw new Unavailable(`the keys of ${target.resource} are malformed`);
    return keys.map((key) => {
      if (!isRecord(key) || typeof key.name !== "string") throw new Unavailable(`a key of ${target.resource} is malformed`);
      return `${key.name}${key.disabled === true ? ":disabled" : ""}`;
    }).sort();
  }

  // The effective policy at the project decides whether any principal may
  // request a token for this account beyond one hour; 404 means the
  // constraint is unset and the default (no extension) applies.
  async #lifetimeExtension(target: Target, consumer: Consumer, bearer: string): Promise<string | null> {
    const response = await this.#send("GET", `${this.#endpoint("orgPolicy")}/v2/projects/${consumer.projectNumber}/policies/${lifetimeExtensionConstraint}:getEffectivePolicy`, undefined, bearer);
    if (response.kind === "response" && response.status === 404) return null;
    const body = this.#ok(response, `the effective ${lifetimeExtensionConstraint} policy of projects/${consumer.projectNumber}`);
    const spec = isRecord(body) && isRecord(body.spec) ? body.spec : {};
    const rules = spec.rules === undefined ? [] : spec.rules;
    if (!Array.isArray(rules)) throw new Unavailable(`the effective ${lifetimeExtensionConstraint} policy is malformed`);
    const covering: string[] = [];
    for (const rule of rules) {
      if (!isRecord(rule)) throw new Unavailable(`the effective ${lifetimeExtensionConstraint} policy is malformed`);
      const suffix = isRecord(rule.condition) ? `[conditional]` : "";
      if (rule.allowAll === true) covering.push(`allowAll${suffix}`);
      const allowed = isRecord(rule.values) && Array.isArray(rule.values.allowedValues) ? rule.values.allowedValues : [];
      if (allowed.some((value) => value === target.email || value === `serviceAccount:${target.email}` || value === target.resource)) covering.push(`allowedValues:${target.email}${suffix}`);
    }
    return covering.length === 0 ? null : covering.sort().join(",");
  }

  // Attachment reads are billed to the consumer project (X-Goog-User-Project),
  // whose own enablement of each attachment API is exactly what decides
  // whether that API can host an attachment; the broker project enables none
  // of them.
  async #computeSnapshot(consumer: Consumer, bearer: string): Promise<Snapshot["compute"]> {
    const compute = `${this.#endpoint("compute")}/compute/v1/projects/${consumer.projectId}`;
    const instances = await this.#aggregated(`${compute}/aggregated/instances`, "instances", bearer, consumer.projectId);
    if (instances.kind === "disabled") return "disabled";
    const templates = await this.#aggregated(`${compute}/aggregated/instanceTemplates`, "instanceTemplates", bearer, consumer.projectId);
    return { instances: instances.items, templates: templates.kind === "items" ? templates.items : [] };
  }

  // Cloud Run: the regions the project can use, from the API's own location
  // list (the v2 list contracts refuse the "-" wildcard for a location), and
  // in every one of them the services, every revision, the jobs, and every
  // execution, page by page.
  async #runSnapshot(consumer: Consumer, bearer: string): Promise<Snapshot["run"]> {
    const run = this.#endpoint("run");
    const locations = await this.#list(`${run}/v1/projects/${consumer.projectId}/locations`, "locations", bearer, consumer.projectId);
    if (locations.kind === "disabled") return "disabled";
    const regions = locations.items.map((location) => {
      if (!isRecord(location) || typeof location.locationId !== "string" || !/^[a-z]+-[a-z]+[0-9]$/.test(location.locationId)) throw new Unavailable(`Cloud Run listed a malformed location for ${consumer.projectId}`);
      return location.locationId;
    });
    if (regions.length === 0) throw new Unavailable(`Cloud Run listed no region for ${consumer.projectId}`);
    return await mapConcurrently([...new Set(regions)].sort(), regionConcurrency, async (region) => {
      const parent = `${run}/v2/projects/${consumer.projectId}/locations/${region}`;
      const [services, revisions, jobs, executions] = await Promise.all([
        this.#complete(`${parent}/services`, "services", bearer, consumer.projectId),
        this.#complete(`${parent}/services/-/revisions`, "revisions", bearer, consumer.projectId),
        this.#complete(`${parent}/jobs`, "jobs", bearer, consumer.projectId),
        this.#complete(`${parent}/jobs/-/executions`, "executions", bearer, consumer.projectId),
      ]);
      return { executions, jobs, region, revisions, services };
    });
  }

  // Cloud Build: every region the API publishes an endpoint for, plus the
  // global location, and in each the triggers and the current builds. There
  // is no location list to ask; the API's own discovery document is the
  // authoritative statement of its regions, and it must be complete or the
  // inventory is unavailable.
  async #buildSnapshot(consumer: Consumer, bearer: string): Promise<Snapshot["build"]> {
    const cloudBuild = this.#endpoint("cloudBuild");
    const first = await this.#send("GET", `${cloudBuild}/v1/projects/${consumer.projectId}/locations/global/triggers`, undefined, bearer, consumer.projectId);
    if (serviceDisabled(first)) return "disabled";
    this.#ok(first, `Cloud Build triggers of ${consumer.projectId}`);
    const discovery = await sendJson(this.#deps.fetch, "GET", `${cloudBuild}/$discovery/rest?version=v1`, undefined, undefined);
    const document = this.#ok(discovery, "the Cloud Build discovery document");
    const endpoints = isRecord(document) && Array.isArray(document.endpoints) ? document.endpoints : undefined;
    if (endpoints === undefined) throw new Unavailable("the Cloud Build discovery document lists no endpoints");
    const regions = endpoints.map((endpoint) => {
      if (!isRecord(endpoint) || typeof endpoint.location !== "string" || !/^[a-z]+-[a-z]+[0-9]$/.test(endpoint.location)) throw new Unavailable("the Cloud Build discovery document lists a malformed endpoint");
      return endpoint.location;
    });
    if (regions.length === 0) throw new Unavailable("the Cloud Build discovery document lists no region");
    const filter = encodeURIComponent(currentBuildStatuses.map((status) => `status="${status}"`).join(" OR "));
    return await mapConcurrently(["global", ...new Set(regions)].sort(), regionConcurrency, async (region) => {
      const parent = `${cloudBuild}/v1/projects/${consumer.projectId}/locations/${region}`;
      const [triggers, builds] = await Promise.all([
        this.#complete(`${parent}/triggers`, "triggers", bearer, consumer.projectId),
        this.#complete(`${parent}/builds?filter=${filter}`, "builds", bearer, consumer.projectId),
      ]);
      return { builds, region, triggers };
    });
  }

  // A list that must be complete: a disabled API here is not an answer,
  // because the project's enablement was already decided by the first read.
  async #complete(url: string, field: string, bearer: string, quotaProject: string): Promise<readonly unknown[]> {
    const listed = await this.#list(url, field, bearer, quotaProject);
    if (listed.kind === "disabled") throw new Unavailable(`${url}: the API answered disabled after it answered enabled`);
    return listed.items;
  }

  // A paginated list of one field, complete or not at all.
  async #list(url: string, field: string, bearer: string, quotaProject: string): Promise<{ readonly kind: "items"; readonly items: readonly unknown[] } | { readonly kind: "disabled" }> {
    const items: unknown[] = [];
    let pageToken: string | undefined;
    for (let page = 0; ; page += 1) {
      if (page >= maxPages) throw new Unavailable(`${url} exceeds ${maxPages} pages`);
      const response = await this.#send("GET", pageToken === undefined ? url : `${url}${url.includes("?") ? "&" : "?"}pageToken=${encodeURIComponent(pageToken)}`, undefined, bearer, quotaProject);
      if (serviceDisabled(response)) return { kind: "disabled" };
      const body = this.#ok(response, url);
      const found = isRecord(body) && body[field] !== undefined ? body[field] : [];
      if (!Array.isArray(found)) throw new Unavailable(`${url} returned a malformed ${field} list`);
      items.push(...found);
      const next = isRecord(body) ? body.nextPageToken : undefined;
      if (next === undefined || next === "") return { kind: "items", items };
      if (typeof next !== "string") throw new Unavailable(`${url} returned a malformed page token`);
      pageToken = next;
    }
  }

  // A Compute aggregated list: a map of scope (zones/x, regions/y, global)
  // to the items of that scope, paginated the same way.
  async #aggregated(url: string, field: string, bearer: string, quotaProject: string): Promise<{ readonly kind: "items"; readonly items: ReadonlyArray<readonly [string, unknown]> } | { readonly kind: "disabled" }> {
    const items: Array<readonly [string, unknown]> = [];
    let pageToken: string | undefined;
    for (let page = 0; ; page += 1) {
      if (page >= maxPages) throw new Unavailable(`${url} exceeds ${maxPages} pages`);
      const response = await this.#send("GET", pageToken === undefined ? url : `${url}?pageToken=${encodeURIComponent(pageToken)}`, undefined, bearer, quotaProject);
      if (serviceDisabled(response)) return { kind: "disabled" };
      const body = this.#ok(response, url);
      const scopes = isRecord(body) && isRecord(body.items) ? body.items : {};
      for (const [scope, scoped] of Object.entries(scopes)) {
        const found = isRecord(scoped) && scoped[field] !== undefined ? scoped[field] : [];
        if (!Array.isArray(found)) throw new Unavailable(`${url} returned a malformed ${field} list for ${scope}`);
        for (const item of found) items.push([scope, item]);
      }
      const next = isRecord(body) ? body.nextPageToken : undefined;
      if (next === undefined || next === "") return { kind: "items", items };
      if (typeof next !== "string") throw new Unavailable(`${url} returned a malformed page token`);
      pageToken = next;
    }
  }

  async #json(method: "GET" | "POST", url: string, body: unknown, bearer: string, what: string): Promise<unknown> {
    return this.#ok(await this.#send(method, url, body, bearer), what);
  }

  async #send(method: "GET" | "POST", url: string, body: unknown, bearer: string, quotaProject?: string): Promise<JsonResponse> {
    return await sendJson(this.#deps.fetch, method, url, body, bearer, quotaProject === undefined ? {} : { "X-Goog-User-Project": quotaProject });
  }

  #ok(response: JsonResponse, what: string): unknown {
    if (response.kind === "unreachable") throw new Unavailable(`${what}: ${response.reason}`);
    if (!response.ok) throw new Unavailable(`${what}: HTTP ${response.status}`);
    return response.body;
  }

  #endpoint(name: "cloudBuild" | "compute" | "iam" | "orgPolicy" | "resourceManager" | "run"): string {
    const defaults = {
      cloudBuild: "https://cloudbuild.googleapis.com",
      compute: "https://compute.googleapis.com",
      iam: "https://iam.googleapis.com",
      orgPolicy: "https://orgpolicy.googleapis.com",
      resourceManager: "https://cloudresourcemanager.googleapis.com",
      run: "https://run.googleapis.com",
    };
    return this.#deps.endpoints?.[name] ?? defaults[name];
  }
}

function computeAttachments(target: Target, consumer: Consumer, snapshot: Snapshot): readonly string[] {
  if (snapshot.compute === "disabled") return [];
  const runsAs = (accounts: unknown): boolean => Array.isArray(accounts) && accounts.some((account) => isRecord(account) && account.email === target.email);
  const attachments: string[] = [];
  for (const [scope, item] of snapshot.compute.instances) {
    if (isRecord(item) && runsAs(item.serviceAccounts) && typeof item.name === "string") attachments.push(`compute.googleapis.com/projects/${consumer.projectId}/${scope}/instances/${item.name}`);
  }
  for (const [scope, item] of snapshot.compute.templates) {
    if (isRecord(item) && isRecord(item.properties) && runsAs(item.properties.serviceAccounts) && typeof item.name === "string") attachments.push(`compute.googleapis.com/projects/${consumer.projectId}/${scope}/instanceTemplates/${item.name}`);
  }
  return attachments;
}

// Cloud Run workloads that run as the target: a service whose template names
// it, every revision of a service that serves traffic (by percent, by tag, or
// as the latest ready revision) and names it -- an older serving revision
// keeps its own identity after the template changes -- a job whose template
// names it, and every execution of a job that has not completed and names
// it. A serving revision the region's revision list does not carry makes the
// inventory unavailable rather than clean.
function runAttachments(target: Target, snapshot: Snapshot): readonly string[] {
  if (snapshot.run === "disabled") return [];
  const attachments: string[] = [];
  for (const { executions, jobs, region, revisions, services } of snapshot.run) {
    const revisionsByName = new Map<string, Record<string, unknown>>();
    for (const revision of revisions) {
      if (!isRecord(revision) || typeof revision.name !== "string") throw new Unavailable(`Cloud Run listed a malformed revision in ${region}`);
      revisionsByName.set(revision.name, revision);
    }
    for (const service of services) {
      if (!isRecord(service) || typeof service.name !== "string") throw new Unavailable(`Cloud Run listed a malformed service in ${region}`);
      if (isRecord(service.template) && service.template.serviceAccount === target.email) attachments.push(`run.googleapis.com/${service.name}`);
      const serving = new Set<string>();
      if (typeof service.latestReadyRevision === "string" && service.latestReadyRevision.length > 0) serving.add(service.latestReadyRevision);
      for (const status of Array.isArray(service.trafficStatuses) ? service.trafficStatuses : []) {
        if (!isRecord(status)) throw new Unavailable(`Cloud Run listed a malformed traffic status for ${service.name}`);
        const percent = typeof status.percent === "number" ? status.percent : 0;
        const tagged = typeof status.tag === "string" && status.tag.length > 0;
        if (typeof status.revision === "string" && status.revision.length > 0 && (percent > 0 || tagged)) serving.add(status.revision);
      }
      for (const named of serving) {
        const revisionName = named.includes("/") ? named : `${service.name}/revisions/${named}`;
        const revision = revisionsByName.get(revisionName);
        if (!revision) throw new Unavailable(`Cloud Run serves ${revisionName} but did not list it in ${region}`);
        if (revision.serviceAccount === target.email) attachments.push(`run.googleapis.com/${revisionName}`);
      }
    }
    for (const job of jobs) {
      if (!isRecord(job) || typeof job.name !== "string") throw new Unavailable(`Cloud Run listed a malformed job in ${region}`);
      if (isRecord(job.template) && isRecord(job.template.template) && job.template.template.serviceAccount === target.email) attachments.push(`run.googleapis.com/${job.name}`);
    }
    for (const execution of executions) {
      if (!isRecord(execution) || typeof execution.name !== "string") throw new Unavailable(`Cloud Run listed a malformed execution in ${region}`);
      const completed = typeof execution.completionTime === "string" && execution.completionTime.length > 0;
      if (!completed && isRecord(execution.template) && execution.template.serviceAccount === target.email) attachments.push(`run.googleapis.com/${execution.name}`);
    }
  }
  return attachments;
}

// Cloud Build triggers that run as the target, and current builds -- manual
// or triggered, in any region -- whose own service account is the target.
function buildAttachments(target: Target, consumer: Consumer, snapshot: Snapshot): readonly string[] {
  if (snapshot.build === "disabled") return [];
  const accounts = new Set([consumer.projectId, consumer.projectNumber].flatMap((project) => [`projects/${project}/serviceAccounts/${target.email}`, `projects/${project}/serviceAccounts/${target.uniqueId}`]));
  const attachments: string[] = [];
  for (const { builds, region, triggers } of snapshot.build) {
    for (const trigger of triggers) {
      if (!isRecord(trigger)) throw new Unavailable(`Cloud Build listed a malformed trigger in ${region}`);
      const name = typeof trigger.resourceName === "string" ? trigger.resourceName : typeof trigger.id === "string" ? `projects/${consumer.projectId}/locations/${region}/triggers/${trigger.id}` : undefined;
      if (name === undefined) throw new Unavailable(`Cloud Build listed a trigger without a name in ${region}`);
      if (typeof trigger.serviceAccount === "string" && accounts.has(trigger.serviceAccount)) attachments.push(`cloudbuild.googleapis.com/${name}`);
    }
    for (const build of builds) {
      if (!isRecord(build) || typeof build.id !== "string" || typeof build.status !== "string") throw new Unavailable(`Cloud Build listed a malformed build in ${region}`);
      if (!currentBuildStatuses.includes(build.status)) continue;
      if (typeof build.serviceAccount === "string" && accounts.has(build.serviceAccount)) attachments.push(`cloudbuild.googleapis.com/projects/${consumer.projectId}/locations/${region}/builds/${build.id}`);
    }
  }
  return attachments;
}

async function mapConcurrently<T, R>(items: readonly T[], limit: number, work: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const index = next;
      next += 1;
      if (index >= items.length) return;
      results[index] = await work(items[index]!);
    }
  });
  await Promise.all(workers);
  return results;
}

// An API that is not enabled in the consumer project hosts no resource of
// its kind; anything else that is not a page is unavailable.
function serviceDisabled(response: JsonResponse): boolean {
  if (response.kind !== "response" || response.status !== 403 || !isRecord(response.body) || !isRecord(response.body.error)) return false;
  const details = Array.isArray(response.body.error.details) ? response.body.error.details : [];
  return details.some((detail) => isRecord(detail) && detail.reason === "SERVICE_DISABLED");
}
