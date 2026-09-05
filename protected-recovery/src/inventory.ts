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
//   attachments      Compute instances and templates, Cloud Run services and
//                    jobs, and Cloud Build triggers that run as the target
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

export class GoogleCredentialInventory implements CredentialInventory {
  readonly #deps: InventoryDependencies;

  constructor(deps: InventoryDependencies) {
    this.#deps = deps;
  }

  async inventory(target: Target, consumer: Consumer): Promise<InventoryOutcome> {
    try {
      const bearer = await this.#deps.token();
      const summary = await this.#summarize(target, consumer, bearer);
      const observedAt = this.#deps.now().toISOString();
      return { kind: "observed", inventory: { account: target.account, email: target.email, findings: inventoryFindings(summary), hash: inventoryHash(summary), observedAt, summary, uniqueId: target.uniqueId } };
    } catch (error) {
      if (error instanceof Unavailable) return { kind: "unavailable", reason: error.message };
      throw error;
    }
  }

  async #summarize(target: Target, consumer: Consumer, bearer: string): Promise<InventorySummary> {
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
    const services: string[] = [];
    const attachments = [
      ...(await this.#computeAttachments(target, consumer, bearer, services)),
      ...(await this.#runAttachments(target, consumer, bearer, services)),
      ...(await this.#buildAttachments(target, consumer, bearer, services)),
    ];
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
  async #computeAttachments(target: Target, consumer: Consumer, bearer: string, services: string[]): Promise<readonly string[]> {
    const compute = `${this.#endpoint("compute")}/compute/v1/projects/${consumer.projectId}`;
    const instances = await this.#aggregated(`${compute}/aggregated/instances`, "instances", bearer, consumer.projectId);
    if (instances.kind === "disabled") {
      services.push("compute.googleapis.com:disabled");
      return [];
    }
    services.push("compute.googleapis.com:enabled");
    const templates = await this.#aggregated(`${compute}/aggregated/instanceTemplates`, "instanceTemplates", bearer, consumer.projectId);
    const runsAs = (accounts: unknown): boolean => Array.isArray(accounts) && accounts.some((account) => isRecord(account) && account.email === target.email);
    const attachments: string[] = [];
    for (const [scope, item] of instances.kind === "items" ? instances.items : []) {
      if (isRecord(item) && runsAs(item.serviceAccounts) && typeof item.name === "string") attachments.push(`compute.googleapis.com/projects/${consumer.projectId}/${scope}/instances/${item.name}`);
    }
    for (const [scope, item] of templates.kind === "items" ? templates.items : []) {
      if (isRecord(item) && isRecord(item.properties) && runsAs(item.properties.serviceAccounts) && typeof item.name === "string") attachments.push(`compute.googleapis.com/projects/${consumer.projectId}/${scope}/instanceTemplates/${item.name}`);
    }
    return attachments;
  }

  async #runAttachments(target: Target, consumer: Consumer, bearer: string, services: string[]): Promise<readonly string[]> {
    const run = `${this.#endpoint("run")}/v2/projects/${consumer.projectId}/locations/-`;
    const runServices = await this.#list(`${run}/services`, "services", bearer, consumer.projectId);
    if (runServices.kind === "disabled") {
      services.push("run.googleapis.com:disabled");
      return [];
    }
    services.push("run.googleapis.com:enabled");
    const jobs = await this.#list(`${run}/jobs`, "jobs", bearer, consumer.projectId);
    const attachments: string[] = [];
    for (const service of runServices.items) {
      if (isRecord(service) && isRecord(service.template) && service.template.serviceAccount === target.email && typeof service.name === "string") attachments.push(`run.googleapis.com/${service.name}`);
    }
    for (const job of jobs.kind === "items" ? jobs.items : []) {
      if (isRecord(job) && isRecord(job.template) && isRecord(job.template.template) && job.template.template.serviceAccount === target.email && typeof job.name === "string") attachments.push(`run.googleapis.com/${job.name}`);
    }
    return attachments;
  }

  async #buildAttachments(target: Target, consumer: Consumer, bearer: string, services: string[]): Promise<readonly string[]> {
    const triggers = await this.#list(`${this.#endpoint("cloudBuild")}/v1/projects/${consumer.projectId}/locations/-/triggers`, "triggers", bearer, consumer.projectId);
    if (triggers.kind === "disabled") {
      services.push("cloudbuild.googleapis.com:disabled");
      return [];
    }
    services.push("cloudbuild.googleapis.com:enabled");
    const attachments: string[] = [];
    for (const trigger of triggers.items) {
      if (!isRecord(trigger)) continue;
      const runsAs = trigger.serviceAccount === `projects/${consumer.projectId}/serviceAccounts/${target.email}` || trigger.serviceAccount === `projects/${consumer.projectNumber}/serviceAccounts/${target.email}`;
      const name = typeof trigger.resourceName === "string" ? trigger.resourceName : typeof trigger.id === "string" ? `projects/${consumer.projectId}/triggers/${trigger.id}` : undefined;
      if (runsAs && name !== undefined) attachments.push(`cloudbuild.googleapis.com/${name}`);
    }
    return attachments;
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

// An API that is not enabled in the consumer project hosts no resource of
// its kind; anything else that is not a page is unavailable.
function serviceDisabled(response: JsonResponse): boolean {
  if (response.kind !== "response" || response.status !== 403 || !isRecord(response.body) || !isRecord(response.body.error)) return false;
  const details = Array.isArray(response.body.error.details) ? response.body.error.details : [];
  return details.some((detail) => isRecord(detail) && detail.reason === "SERVICE_DISABLED");
}
