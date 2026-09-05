import { type DenyVerdict, type LiveDenyPolicy, brokerAttachment, classifyDenyState, consumerAttachment, denyFormFor, denyPoliciesUrl, livePolicyFromJson, organizationAttachment } from "./deny";
import { type JsonResponse, type Policy, policyFromJson, sendJson } from "./effects";
import {
  type Consumer,
  type DenyStateSummary,
  type InventoryRecord,
  type InventorySummary,
  type RecoveryAuthority,
  type Target,
  brokerMember,
  inventoryHash,
  isRecord,
  managedRole,
  regionId,
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
//                    through iam.roles.get so custom and basic roles count,
//                    and every role's definition version (etag) recorded so
//                    an edited-and-restored custom role still changes the hash
//   keys             user-managed keys of the target
//   lifetime         the effective iam.allowServiceAccountCredentialLifetimeExtension
//                    policy of the project, which can stretch a token to 12
//                    hours, and the policy resource set at the project and at
//                    every ancestor (etag and updateTime), so a policy set and
//                    restored between two reads still changes the hash
//   deny state       the live Deny policies at the broker project, the
//                    organization, and the consumer project, by name and
//                    etag, and the form they satisfy; any form but steady is a
//                    finding, which is how post-activation drift disables the
//                    broker's authority without any apply
//   federation       any principal of the consumer's pool granted anywhere in
//                    the ancestry, other than the managed members on the target
//   attachments      Compute instances and templates; Cloud Run services,
//                    their traffic-serving revisions, jobs, in-flight
//                    executions, and worker pools in every region the project
//                    can use; Cloud Build triggers and current builds in every
//                    Cloud Build region; and Cloud Scheduler jobs in every
//                    Scheduler region -- each region enumerated from the API
//                    itself and every page completed, or the inventory is
//                    unavailable
//   service agents   a Google-managed service agent bound its own predefined
//                    role at the project carries token permissions for every
//                    account in the project, but can exercise them only
//                    through a workload of its service attached to the
//                    account. That grant is neutralized -- recorded, not
//                    hidden -- exactly when the live Deny state is the steady
//                    form (every attachment path of that service frozen for
//                    every principal, service agents included) and this
//                    inventory found no attachment of that service running as
//                    the target; otherwise it is a grant finding
//
// One batch reads one consumer project's shared state once and every target
// against it; the record of each target spans the interval from the batch's
// first read to that target's last, and nothing is reused across batches.
//
// Domain-wide delegation is not a resource the IAM API exposes; exercising it
// requires signing a JWT as the target, which needs a user-managed key or a
// signJwt/signBlob grant, both of which this inventory records.

export type InventoryOutcome =
  | { readonly kind: "observed"; readonly inventory: InventoryRecord }
  | { readonly kind: "unavailable"; readonly reason: string };

export type DenyStateOutcome =
  | { readonly kind: "observed"; readonly state: DenyStateSummary; readonly verdict: DenyVerdict }
  | { readonly kind: "unavailable"; readonly reason: string };

export interface CredentialInventory {
  // Every target of one consumer against one uncached batch snapshot.
  inventoryAll(targets: readonly Target[], consumer: Consumer): Promise<readonly InventoryOutcome[]>;
  // The live Deny state alone, for gates that mutate nothing target-specific.
  denyState(consumer: Consumer): Promise<DenyStateOutcome>;
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

// The Google-managed service agents whose attachment kinds this inventory
// enumerates, each with the one predefined role Google binds it at the
// project and the attachment prefix its workloads are recorded under.
export const serviceAgents: ReadonlyArray<{ readonly domain: string; readonly prefix: string; readonly role: string; readonly service: string }> = [
  { domain: "serverless-robot-prod.iam.gserviceaccount.com", prefix: "run.googleapis.com/", role: "roles/run.serviceAgent", service: "run.googleapis.com" },
  { domain: "gcp-sa-cloudbuild.iam.gserviceaccount.com", prefix: "cloudbuild.googleapis.com/", role: "roles/cloudbuild.serviceAgent", service: "cloudbuild.googleapis.com" },
  { domain: "compute-system.iam.gserviceaccount.com", prefix: "compute.googleapis.com/", role: "roles/compute.serviceAgent", service: "compute.googleapis.com" },
  { domain: "gcp-sa-cloudscheduler.iam.gserviceaccount.com", prefix: "cloudscheduler.googleapis.com/", role: "roles/cloudscheduler.serviceAgent", service: "cloudscheduler.googleapis.com" },
];

export function inventoryFindings(summary: InventorySummary): readonly string[] {
  return [
    ...(summary.denyState.form === "steady" ? [] : [`deny-state:${summary.denyState.form}`]),
    ...summary.grants.map((grant) => `grant:${grant}`),
    ...summary.keys.map((key) => `key:${key}`),
    ...(summary.lifetimeExtension === null ? [] : [`lifetime-extension:${summary.lifetimeExtension}`]),
    ...summary.attachments.map((attachment) => `attachment:${attachment}`),
  ];
}

export interface InventoryDependencies {
  readonly authority: RecoveryAuthority;
  readonly endpoints?: { readonly cloudBuild?: string; readonly compute?: string; readonly iam?: string; readonly orgPolicy?: string; readonly resourceManager?: string; readonly run?: string; readonly scheduler?: string };
  readonly fetch: typeof fetch;
  readonly now: () => Date;
  readonly token: () => Promise<string>;
}

class Unavailable extends Error {}

const maxPages = 100;
const maxAncestryDepth = 10;
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
  readonly workerPools: readonly unknown[];
}

interface BuildRegion {
  readonly builds: readonly unknown[];
  readonly region: string;
  readonly triggers: readonly unknown[];
}

interface SchedulerRegion {
  readonly jobs: readonly unknown[];
  readonly region: string;
}

// Everything one batch read of a consumer project that is shared by every
// target of the project.
interface Snapshot {
  readonly ancestry: readonly string[];
  readonly build: readonly BuildRegion[] | "disabled";
  readonly compute: { readonly instances: ReadonlyArray<readonly [string, unknown]>; readonly templates: ReadonlyArray<readonly [string, unknown]> } | "disabled";
  readonly denyState: DenyStateSummary;
  readonly lifetimePolicies: readonly string[];
  readonly observedAt: string;
  readonly policies: ReadonlyArray<{ readonly policy: Policy; readonly resource: string }>;
  readonly roles: Map<string, { readonly etag: string; readonly permissions: readonly string[] }>;
  readonly run: readonly RunRegion[] | "disabled";
  readonly scheduler: readonly SchedulerRegion[] | "disabled";
}

export class GoogleCredentialInventory implements CredentialInventory {
  readonly #deps: InventoryDependencies;

  constructor(deps: InventoryDependencies) {
    this.#deps = deps;
  }

  async inventoryAll(targets: readonly Target[], consumer: Consumer): Promise<readonly InventoryOutcome[]> {
    let bearer: string;
    let snapshot: Snapshot;
    try {
      bearer = await this.#deps.token();
      snapshot = await this.#read(consumer, bearer);
    } catch (error) {
      if (error instanceof Unavailable) return targets.map(() => ({ kind: "unavailable", reason: error.message }));
      throw error;
    }
    const outcomes: InventoryOutcome[] = [];
    for (const target of targets) {
      try {
        const summary = await this.#summarize(target, consumer, bearer, snapshot);
        const observedUntil = this.#deps.now().toISOString();
        outcomes.push({ kind: "observed", inventory: { account: target.account, email: target.email, findings: inventoryFindings(summary), hash: inventoryHash(summary), observedAt: snapshot.observedAt, observedUntil, summary, uniqueId: target.uniqueId } });
      } catch (error) {
        if (!(error instanceof Unavailable)) throw error;
        outcomes.push({ kind: "unavailable", reason: error.message });
      }
    }
    return outcomes;
  }

  async denyState(consumer: Consumer): Promise<DenyStateOutcome> {
    try {
      const bearer = await this.#deps.token();
      return await this.#denyState(consumer, bearer);
    } catch (error) {
      if (error instanceof Unavailable) return { kind: "unavailable", reason: error.message };
      throw error;
    }
  }

  // The shared state of one consumer project, read once per batch, dated
  // when the first read began.
  async #read(consumer: Consumer, bearer: string): Promise<Snapshot> {
    const observedAt = this.#deps.now().toISOString();
    const resourceManager = this.#endpoint("resourceManager");
    const project = await this.#json("GET", `${resourceManager}/v3/projects/${consumer.projectNumber}`, undefined, bearer, `project ${consumer.projectNumber}`);
    if (!isRecord(project) || project.projectId !== consumer.projectId) throw new Unavailable(`projects/${consumer.projectNumber} is not ${consumer.projectId}`);
    const ancestry = [`projects/${consumer.projectNumber}`];
    const policies: Array<{ readonly policy: Policy; readonly resource: string }> = [{ policy: await this.#policy(`${resourceManager}/v3/projects/${consumer.projectNumber}:getIamPolicy`, bearer, `projects/${consumer.projectNumber}`), resource: `projects/${consumer.projectNumber}` }];
    let parent = typeof project.parent === "string" ? project.parent : undefined;
    for (let depth = 0; parent !== undefined; depth += 1) {
      if (depth >= maxAncestryDepth) throw new Unavailable(`the ancestry of projects/${consumer.projectNumber} exceeds ${maxAncestryDepth} levels`);
      // The recorded organization is the only one whose policy this inventory reads: a project under any other
      // organization is unavailable before a single read of that organization is made.
      if (parent.startsWith("organizations/") && this.#deps.authority.organizationId !== null && parent !== `organizations/${this.#deps.authority.organizationId}`) {
        throw new Unavailable(`projects/${consumer.projectNumber} sits under ${parent}, not the recorded organizations/${this.#deps.authority.organizationId}`);
      }
      ancestry.push(parent);
      policies.push({ policy: await this.#policy(`${resourceManager}/v3/${parent}:getIamPolicy`, bearer, parent), resource: parent });
      if (parent.startsWith("organizations/")) break;
      if (!parent.startsWith("folders/")) throw new Unavailable(`${parent} is neither a folder nor an organization`);
      const folder = await this.#json("GET", `${resourceManager}/v3/${parent}`, undefined, bearer, parent);
      parent = isRecord(folder) && typeof folder.parent === "string" ? folder.parent : undefined;
    }
    const organization = ancestry.at(-1);
    if (organization === undefined || !organization.startsWith("organizations/")) throw new Unavailable(`projects/${consumer.projectNumber} is not parented by an organization`);
    const roles = new Map<string, { readonly etag: string; readonly permissions: readonly string[] }>();
    for (const { policy } of policies) {
      for (const binding of policy.bindings) {
        if (roles.has(binding.role)) continue;
        roles.set(binding.role, await this.#role(binding.role, bearer));
      }
    }
    const lifetimePolicies = await Promise.all(ancestry.map((resource) => this.#lifetimePolicy(resource, bearer)));
    const denyState = await this.#denyState(consumer, bearer);
    if (denyState.kind === "unavailable") throw new Unavailable(denyState.reason);
    const compute = await this.#computeSnapshot(consumer, bearer);
    const run = await this.#runSnapshot(consumer, bearer);
    const build = await this.#buildSnapshot(consumer, bearer);
    const scheduler = await this.#schedulerSnapshot(consumer, bearer);
    return { ancestry, build, compute, denyState: denyState.state, lifetimePolicies: [...lifetimePolicies].sort(), observedAt, policies, roles, run, scheduler };
  }

  async #summarize(target: Target, consumer: Consumer, bearer: string, snapshot: Snapshot): Promise<InventorySummary> {
    const iam = this.#endpoint("iam");
    const identity = await this.#json("GET", `${iam}/v1/${target.resource}`, undefined, bearer, `identity of ${target.resource}`);
    if (!isRecord(identity) || identity.email !== target.email || identity.uniqueId !== target.uniqueId) {
      throw new Unavailable(`${target.resource} does not resolve to ${target.email} (${target.uniqueId})`);
    }
    const policies = [{ policy: await this.#policy(`${iam}/v1/${target.resource}:getIamPolicy`, bearer, target.resource), resource: target.resource }, ...snapshot.policies];
    const roles = new Map(snapshot.roles);
    for (const binding of policies[0]!.policy.bindings) {
      if (roles.has(binding.role)) continue;
      roles.set(binding.role, await this.#role(binding.role, bearer));
    }
    const attachments = [...new Set([...computeAttachments(target, consumer, snapshot), ...runAttachments(target, snapshot), ...buildAttachments(target, consumer, snapshot), ...schedulerAttachments(target, snapshot)])].sort();
    const grants = new Set<string>();
    const neutralized: string[] = [];
    const poolPrefixes = [`principalSet://iam.googleapis.com/${target.pool}/`, `principal://iam.googleapis.com/${target.pool}/`];
    const broker = brokerMember(this.#deps.authority);
    const actuatorRole = `projects/${consumer.projectId}/roles/${actuatorRoleId}`;
    const projectResource = `projects/${consumer.projectNumber}`;
    for (const { policy, resource } of policies) {
      for (const binding of policy.bindings) {
        const permissions = roles.get(binding.role)?.permissions ?? [];
        const capable = permissions.some((permission) => credentialPermissions.includes(permission));
        const label = `${resource}|${binding.role}${binding.condition ? `[${binding.condition.title}]` : ""}`;
        for (const member of binding.members) {
          const federated = poolPrefixes.some((prefix) => member.startsWith(prefix));
          if (resource === target.resource && binding.condition === null && binding.role === managedRole && target.members.includes(member)) continue;
          if (resource === target.resource && binding.condition === null && binding.role === actuatorRole && member === broker && permissions.every((permission) => actuatorPermissions.includes(permission))) continue;
          if (!capable && !federated) continue;
          const agent = serviceAgents.find((candidate) => candidate.role === binding.role && member === `serviceAccount:service-${consumer.projectNumber}@${candidate.domain}`);
          if (agent && resource === projectResource && binding.condition === null && snapshot.denyState.form === "steady" && !attachments.some((attachment) => attachment.startsWith(agent.prefix))) {
            neutralized.push(`${label}|${member}|frozen:${agent.service}`);
            continue;
          }
          grants.add(`${label}|${member}`);
        }
      }
    }
    const keys = await this.#keys(target, bearer);
    const lifetimeExtension = await this.#lifetimeExtension(target, consumer, bearer);
    const services = [
      `cloudbuild.googleapis.com:${snapshot.build === "disabled" ? "disabled" : "enabled"}`,
      `cloudscheduler.googleapis.com:${snapshot.scheduler === "disabled" ? "disabled" : "enabled"}`,
      `compute.googleapis.com:${snapshot.compute === "disabled" ? "disabled" : "enabled"}`,
      `run.googleapis.com:${snapshot.run === "disabled" ? "disabled" : "enabled"}`,
    ];
    return {
      ancestry: [...snapshot.ancestry],
      attachments,
      denyState: snapshot.denyState,
      grants: [...grants].sort(),
      keys,
      lifetimeExtension,
      lifetimePolicies: snapshot.lifetimePolicies,
      neutralized: neutralized.sort(),
      policies: policies.map(({ policy, resource }) => ({ etag: policy.etag, resource })).sort((left, right) => left.resource.localeCompare(right.resource)),
      roles: [...roles.entries()].map(([name, role]) => ({ etag: role.etag, name })).sort((left, right) => left.name.localeCompare(right.name)),
      services: services.sort(),
    };
  }

  // The live Deny policies at the broker project, the organization, and the
  // consumer project, each listed and read by name, and the form they satisfy.
  async #denyState(consumer: Consumer, bearer: string): Promise<DenyStateOutcome> {
    const authority = this.#deps.authority;
    const attachments = [brokerAttachment(authority), organizationAttachment(authority), consumerAttachment(consumer)];
    const live: LiveDenyPolicy[] = [];
    for (const attachment of attachments) {
      const listing = await this.#json("GET", denyPoliciesUrl(attachment).replace("https://iam.googleapis.com", this.#endpoint("iam")), undefined, bearer, `the deny policies of ${attachment}`);
      const names = isRecord(listing) && listing.policies !== undefined ? listing.policies : [];
      if (!Array.isArray(names)) throw new Unavailable(`the deny policies of ${attachment} are malformed`);
      for (const entry of names) {
        if (!isRecord(entry) || typeof entry.name !== "string") throw new Unavailable(`the deny policies of ${attachment} are malformed`);
        const document = await this.#json("GET", `${this.#endpoint("iam")}/v2/${entry.name}`, undefined, bearer, `the deny policy ${entry.name}`);
        try {
          live.push(livePolicyFromJson(attachment, document));
        } catch (error) {
          throw new Unavailable(String(error instanceof Error ? error.message : error));
        }
      }
    }
    const verdict = classifyDenyState(authority, live, attachments);
    const state: DenyStateSummary = { form: denyFormFor(verdict, consumer), policies: live.map((policy) => ({ attachment: policy.attachment, etag: policy.etag, name: policy.name })).sort((left, right) => left.name.localeCompare(right.name)) };
    return { kind: "observed", state, verdict };
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
  // roles/iam.serviceAccountTokenCreator does; the definition's etag is kept
  // so an edited-and-restored definition still changes the inventory.
  async #role(role: string, bearer: string): Promise<{ readonly etag: string; readonly permissions: readonly string[] }> {
    if (!/^(?:roles\/[A-Za-z0-9._]+|(?:projects|organizations)\/[A-Za-z0-9._-]+\/roles\/[A-Za-z0-9._]+)$/.test(role)) throw new Unavailable(`${role} is not a role name`);
    const body = await this.#json("GET", `${this.#endpoint("iam")}/v1/${role}`, undefined, bearer, `role ${role}`);
    if (!isRecord(body)) throw new Unavailable(`role ${role} is malformed`);
    const permissions = body.includedPermissions === undefined ? [] : body.includedPermissions;
    if (!Array.isArray(permissions) || !permissions.every((permission): permission is string => typeof permission === "string")) throw new Unavailable(`role ${role} carries malformed permissions`);
    if (typeof body.etag !== "string" || body.etag.length === 0) throw new Unavailable(`role ${role} carries no etag`);
    return { etag: body.etag, permissions };
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

  // The lifetime-extension policy resource set at one ancestor, versioned:
  // absent, or its etag and last update.
  async #lifetimePolicy(resource: string, bearer: string): Promise<string> {
    const response = await this.#send("GET", `${this.#endpoint("orgPolicy")}/v2/${resource}/policies/${lifetimeExtensionConstraint}`, undefined, bearer);
    if (response.kind === "response" && response.status === 404) return `${resource}|absent`;
    const body = this.#ok(response, `the ${lifetimeExtensionConstraint} policy of ${resource}`);
    const spec = isRecord(body) && isRecord(body.spec) ? body.spec : undefined;
    if (spec === undefined || typeof spec.etag !== "string" || typeof spec.updateTime !== "string") throw new Unavailable(`the ${lifetimeExtensionConstraint} policy of ${resource} carries no etag and update time`);
    return `${resource}|${spec.etag}|${spec.updateTime}`;
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
  // in every one of them the services, every revision, the jobs, every
  // execution, and the worker pools, page by page.
  async #runSnapshot(consumer: Consumer, bearer: string): Promise<Snapshot["run"]> {
    const run = this.#endpoint("run");
    const locations = await this.#list(`${run}/v1/projects/${consumer.projectId}/locations`, "locations", bearer, consumer.projectId);
    if (locations.kind === "disabled") return "disabled";
    const regions = locations.items.map((location) => {
      if (!isRecord(location) || typeof location.locationId !== "string" || !regionId.test(location.locationId)) throw new Unavailable(`Cloud Run listed a malformed location for ${consumer.projectId}`);
      return location.locationId;
    });
    if (regions.length === 0) throw new Unavailable(`Cloud Run listed no region for ${consumer.projectId}`);
    return await mapConcurrently([...new Set(regions)].sort(), regionConcurrency, async (region) => {
      const parent = `${run}/v2/projects/${consumer.projectId}/locations/${region}`;
      const [services, revisions, jobs, executions, workerPools] = await Promise.all([
        this.#complete(`${parent}/services`, "services", bearer, consumer.projectId),
        this.#complete(`${parent}/services/-/revisions`, "revisions", bearer, consumer.projectId),
        this.#complete(`${parent}/jobs`, "jobs", bearer, consumer.projectId),
        this.#complete(`${parent}/jobs/-/executions`, "executions", bearer, consumer.projectId),
        this.#complete(`${parent}/workerPools`, "workerPools", bearer, consumer.projectId),
      ]);
      return { executions, jobs, region, revisions, services, workerPools };
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
      if (!isRecord(endpoint) || typeof endpoint.location !== "string" || !regionId.test(endpoint.location)) throw new Unavailable("the Cloud Build discovery document lists a malformed endpoint");
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

  // Cloud Scheduler: every location the API lists for the project and in
  // each the jobs, whose HTTP targets can name a service account to mint
  // for.
  async #schedulerSnapshot(consumer: Consumer, bearer: string): Promise<Snapshot["scheduler"]> {
    const scheduler = this.#endpoint("scheduler");
    const locations = await this.#list(`${scheduler}/v1/projects/${consumer.projectId}/locations`, "locations", bearer, consumer.projectId);
    if (locations.kind === "disabled") return "disabled";
    const regions = locations.items.map((location) => {
      if (!isRecord(location) || typeof location.locationId !== "string" || !regionId.test(location.locationId)) throw new Unavailable(`Cloud Scheduler listed a malformed location for ${consumer.projectId}`);
      return location.locationId;
    });
    return await mapConcurrently([...new Set(regions)].sort(), regionConcurrency, async (region) => ({ jobs: await this.#complete(`${scheduler}/v1/projects/${consumer.projectId}/locations/${region}/jobs`, "jobs", bearer, consumer.projectId), region }));
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

  #endpoint(name: "cloudBuild" | "compute" | "iam" | "orgPolicy" | "resourceManager" | "run" | "scheduler"): string {
    const defaults = {
      cloudBuild: "https://cloudbuild.googleapis.com",
      compute: "https://compute.googleapis.com",
      iam: "https://iam.googleapis.com",
      orgPolicy: "https://orgpolicy.googleapis.com",
      resourceManager: "https://cloudresourcemanager.googleapis.com",
      run: "https://run.googleapis.com",
      scheduler: "https://cloudscheduler.googleapis.com",
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
// names it, every execution of a job that has not completed and names it, and
// a worker pool whose template names it. A serving revision the region's
// revision list does not carry makes the inventory unavailable rather than
// clean.
function runAttachments(target: Target, snapshot: Snapshot): readonly string[] {
  if (snapshot.run === "disabled") return [];
  const attachments: string[] = [];
  for (const { executions, jobs, region, revisions, services, workerPools } of snapshot.run) {
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
    for (const pool of workerPools) {
      if (!isRecord(pool) || typeof pool.name !== "string") throw new Unavailable(`Cloud Run listed a malformed worker pool in ${region}`);
      if (isRecord(pool.template) && pool.template.serviceAccount === target.email) attachments.push(`run.googleapis.com/${pool.name}`);
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

// Cloud Scheduler jobs whose HTTP target mints an OIDC or OAuth token as the
// target, in any state: a paused job is one update from running.
function schedulerAttachments(target: Target, snapshot: Snapshot): readonly string[] {
  if (snapshot.scheduler === "disabled") return [];
  const attachments: string[] = [];
  for (const { jobs, region } of snapshot.scheduler) {
    for (const job of jobs) {
      if (!isRecord(job) || typeof job.name !== "string") throw new Unavailable(`Cloud Scheduler listed a malformed job in ${region}`);
      const http = isRecord(job.httpTarget) ? job.httpTarget : {};
      const oidc = isRecord(http.oidcToken) ? http.oidcToken.serviceAccountEmail : undefined;
      const oauth = isRecord(http.oauthToken) ? http.oauthToken.serviceAccountEmail : undefined;
      if (oidc === target.email || oauth === target.email) attachments.push(`cloudscheduler.googleapis.com/${job.name}`);
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
