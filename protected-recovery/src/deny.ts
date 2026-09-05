import { authorityDelimiter, denyCanaryServiceAccount } from "../../tools/ci/workflow-authority";
import { type Consumer, type RecoveryAuthority, brokerServiceAccountId, canonicalJson, isRecord } from "./model";

// The required IAM Deny matrix, derived once from the canonical authority for
// the broker runtime and mirrored by terraform/modules/protected-recovery
// (tools/ci/protected-recovery-enabled-test.sh proves the two derivations
// equal). Every row is one attachment point, one permission, the denied
// principal set (every principal, service agents included), and the exact
// exception set. The matrix has one steady form and three exact,
// composable widenings, each named by a flag:
//
//   steady       no flag. The only state under which the broker exercises
//                authority over a consumer: every attachment, deployment,
//                IAM, federation, role, and organization-policy path frozen
//                for every principal but the modeled ones. The root enters it
//                for a consumer before a quarantine and the broker reads it
//                back, fresh, in the same batch as the inventory that admits
//                the quarantine.
//   deployment   per consumer. That consumer's two deploy identities excepted
//                from exactly run.services.create|update and actAs, so its
//                canonical deploy jobs run. It is the consumer's ordinary
//                state, and it is authority disabled for that consumer: a
//                deploy token stolen before a quarantine could otherwise
//                update the running service under the runtime identity and
//                keep refreshing credentials past every horizon. It cannot
//                overlap a quarantine: admission needs steady, and re-entering
//                it during one is a change of the inventory that voids every
//                chain and a finding that blocks readiness until steady
//                stands again.
//   bootstrap    the one bootstrap principal on exactly the rows the Terraform
//                module's own apply mutates. Authority disabled everywhere:
//                the exception must be retired before any quarantine is
//                accepted, prepared, or resumed.
//   maintenance  the maintenance principals on the consumer IAM, federation,
//                lifecycle, role, organization-policy, and API rows, for
//                infrastructure work under an open ticket. Authority disabled
//                everywhere; bootstrap and maintenance never combine. Project
//                movement and the key, deploy, and attachment paths stay
//                frozen for everyone under every form.
//
// Anything else the live state carries -- an exception outside these forms, a
// missing row, a conditioned or permission-excepted rule -- is drift, and
// drift is authority disabled as well.

export const allPrincipals = "principalSet://goog/public:all";

export interface DenyFlags {
  readonly bootstrap: boolean;
  // The consumers (by repository) whose deploy rows except their deploy identities.
  readonly deployment: readonly string[];
  readonly maintenance: boolean;
}

export const steadyFlags: DenyFlags = { bootstrap: false, deployment: [], maintenance: false };

export interface DenyRow {
  readonly attachment: string;
  readonly denied: readonly string[];
  readonly exceptions: readonly string[];
  readonly permission: string;
}

export type DenyMatrix = Readonly<Record<string, DenyRow>>;

export interface DenyCoordinates {
  // The platform commits whose protected-recovery-invoke tuples are bound:
  // the active commit first, then the optional transition commit.
  readonly platformShas: readonly string[];
}

// The consumer identities that run gcloud run deploy in the canonical deploy
// jobs; protected-recovery/test/authority.test.ts pins them to the workflows.
export const deployIdentities: readonly string[] = ["gha-preview-deploy", "gha-prod-deploy"];

const brokerLedgerPermissions = ["datastore.googleapis.com/entities.create", "datastore.googleapis.com/entities.delete", "datastore.googleapis.com/entities.get", "datastore.googleapis.com/entities.list", "datastore.googleapis.com/entities.update", "storage.googleapis.com/objects.create"];
const brokerSealedPermissions = ["iam.googleapis.com/serviceAccountKeys.create", "iam.googleapis.com/serviceAccounts.implicitDelegation", "iam.googleapis.com/serviceAccounts.signBlob", "iam.googleapis.com/serviceAccounts.signJwt", "storage.googleapis.com/objects.delete", "storage.googleapis.com/objects.update"];
const brokerDeploymentPermissions = [
  "artifactregistry.googleapis.com/repositories.uploadArtifacts",
  "cloudresourcemanager.googleapis.com/projects.setIamPolicy",
  "iam.googleapis.com/serviceAccounts.actAs",
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
  "run.googleapis.com/services.create",
  "run.googleapis.com/services.delete",
  "run.googleapis.com/services.setIamPolicy",
  "run.googleapis.com/services.update",
];
const consumerKeyPermissions = ["iam.googleapis.com/serviceAccountKeys.create"];
const consumerLifecyclePermissions = [
  "iam.googleapis.com/serviceAccounts.create",
  "iam.googleapis.com/serviceAccounts.delete",
  "iam.googleapis.com/serviceAccounts.disable",
  "iam.googleapis.com/serviceAccounts.enable",
  "iam.googleapis.com/serviceAccounts.undelete",
  "iam.googleapis.com/workloadIdentityPoolProviders.create",
  "iam.googleapis.com/workloadIdentityPoolProviders.delete",
  "iam.googleapis.com/workloadIdentityPoolProviders.undelete",
  "iam.googleapis.com/workloadIdentityPoolProviders.update",
  "iam.googleapis.com/workloadIdentityPools.create",
  "iam.googleapis.com/workloadIdentityPools.delete",
  "iam.googleapis.com/workloadIdentityPools.undelete",
  "iam.googleapis.com/workloadIdentityPools.update",
];
// The Cloud Run deploy path of the platform's own canonical jobs.
const consumerDeployPermissions = ["iam.googleapis.com/serviceAccounts.actAs", "run.googleapis.com/services.create", "run.googleapis.com/services.update"];
// Every other path that attaches a workload or disables an inventory API.
const consumerFreezePermissions = [
  "cloudbuild.googleapis.com/builds.create",
  "compute.googleapis.com/instanceTemplates.create",
  "compute.googleapis.com/instances.create",
  "compute.googleapis.com/instances.setServiceAccount",
  "run.googleapis.com/jobs.create",
  "run.googleapis.com/jobs.update",
  "run.googleapis.com/workerpools.create",
  "run.googleapis.com/workerpools.update",
];
// Disabling an inventory API hides its resources from the inventory; enabling
// one runs whatever was retained through a disable at once.
const consumerServiceUsagePermissions = ["serviceusage.googleapis.com/services.disable", "serviceusage.googleapis.com/services.enable"];
const organizationRolePermissions = ["iam.googleapis.com/roles.create", "iam.googleapis.com/roles.delete", "iam.googleapis.com/roles.undelete", "iam.googleapis.com/roles.update"];
const organizationBootstrapRolePermissions = ["iam.googleapis.com/roles.create", "iam.googleapis.com/roles.delete", "iam.googleapis.com/roles.update"];
// The organization-policy write paths of both APIs: policy.set governs the
// v1 API alone and does not stop the v2 API, whose write permissions are
// policies.create, policies.update, and policies.delete.
const organizationPolicyPermissions = ["orgpolicy.googleapis.com/policies.create", "orgpolicy.googleapis.com/policies.delete", "orgpolicy.googleapis.com/policies.update", "orgpolicy.googleapis.com/policy.set"];
// Moving a project changes which organization-level Deny and role policies
// it inherits, and the v1 update path can carry a parent as well; both are
// frozen for every principal in every form, at the organization that
// governs every consumer as a descendant.
const organizationMovementPermissions = ["cloudresourcemanager.googleapis.com/projects.move", "cloudresourcemanager.googleapis.com/projects.update"];

export function brokerAttachment(authority: RecoveryAuthority): string {
  return `cloudresourcemanager.googleapis.com/projects/${recorded(authority).projectId}`;
}

export function organizationAttachment(authority: RecoveryAuthority): string {
  const organizationId = authority.organizationId;
  if (organizationId === null) throw new Error("protected-recovery/authority.json records no organization; the Deny matrix has no organization attachment point.");
  return `cloudresourcemanager.googleapis.com/organizations/${organizationId}`;
}

export function consumerAttachment(consumer: Consumer): string {
  return `cloudresourcemanager.googleapis.com/projects/${consumer.projectId}`;
}

export function brokerPrincipal(authority: RecoveryAuthority): string {
  return `principal://iam.googleapis.com/projects/-/serviceAccounts/${brokerServiceAccountId}@${recorded(authority).projectId}.iam.gserviceaccount.com`;
}

export function schedulerAgentPrincipal(authority: RecoveryAuthority): string {
  return `principal://iam.googleapis.com/projects/-/serviceAccounts/service-${recorded(authority).projectNumber}@gcp-sa-cloudscheduler.iam.gserviceaccount.com`;
}

function serviceAccountPrincipal(account: string, projectId: string): string {
  return `principal://iam.googleapis.com/projects/-/serviceAccounts/${account}@${projectId}.iam.gserviceaccount.com`;
}

export function brokerPool(authority: RecoveryAuthority): string {
  return `projects/${recorded(authority).projectNumber}/locations/global/workloadIdentityPools/${authority.broker.workloadIdentityPoolId}`;
}

function recorded(authority: RecoveryAuthority): { readonly projectId: string; readonly projectNumber: string } {
  const { projectId, projectNumber } = authority.broker;
  if (projectId === null || projectNumber === null) throw new Error("protected-recovery/authority.json records no broker project; the Deny matrix cannot be derived.");
  return { projectId, projectNumber };
}

// The exact direct-dispatch tuples of the recovery invokers, bound through
// the broker pool at the active commit and, for transition-eligible entries,
// the transition commit.
export function invokerTuples(authority: RecoveryAuthority, coordinates: DenyCoordinates): readonly string[] {
  const pool = brokerPool(authority);
  const tuples = new Set<string>();
  for (const entry of authority.entries) {
    if (entry.trustDomain !== "recovery" || entry.purpose !== "recovery") continue;
    const shas = entry.transitionEligible ? coordinates.platformShas : coordinates.platformShas.slice(0, 1);
    for (const caller of entry.callers) {
      for (const event of caller.events) {
        for (const sha of shas) {
          tuples.add(`principalSet://iam.googleapis.com/${pool}/attribute.authority/${[`${authority.platformRepository}/${caller.workflow}@${caller.ref}`, sha, entry.environment, event].join(authorityDelimiter)}`);
        }
      }
    }
  }
  return [...tuples].sort();
}

// The Deny canary's own tuple, at the active commit only.
export function canaryTuples(authority: RecoveryAuthority, coordinates: DenyCoordinates): readonly string[] {
  const pool = brokerPool(authority);
  const active = coordinates.platformShas[0];
  const tuples = new Set<string>();
  for (const entry of authority.entries) {
    if (entry.purpose !== "deny-canary" || active === undefined) continue;
    for (const caller of entry.callers) {
      for (const event of caller.events) {
        tuples.add(`principalSet://iam.googleapis.com/${pool}/attribute.authority/${[`${authority.platformRepository}/${caller.workflow}@${caller.ref}`, active, entry.environment, event].join(authorityDelimiter)}`);
      }
    }
  }
  return [...tuples].sort();
}

// Every canonical consumer job tuple, through the member provider of the
// broker pool, at the commits each consumer records.
export function memberTuples(authority: RecoveryAuthority): readonly string[] {
  const pool = brokerPool(authority);
  const tuples = new Set<string>();
  for (const consumer of authority.consumers) {
    if (consumer.activeWorkflowSha === null) continue;
    for (const entry of authority.entries) {
      if (entry.trustDomain !== "consumer" || entry.purpose !== "gcp") continue;
      const shas = [consumer.activeWorkflowSha, ...(entry.transitionEligible && consumer.transitionWorkflowSha !== null ? [consumer.transitionWorkflowSha] : [])];
      for (const caller of entry.callers) {
        for (const event of caller.events) {
          for (const sha of shas) {
            tuples.add(`principalSet://iam.googleapis.com/${pool}/attribute.authority/${[`${authority.githubOwner}/${consumer.repository}/${caller.workflow}@${caller.ref}`, `${authority.platformRepository}/${entry.workflow}@${sha}`, sha, entry.environment, event].join(authorityDelimiter)}`);
          }
        }
      }
    }
  }
  return [...tuples].sort();
}

export function denyCanaryPrincipal(authority: RecoveryAuthority): string {
  return serviceAccountPrincipal(denyCanaryServiceAccount, recorded(authority).projectId);
}

export function deployPrincipals(consumer: Consumer): readonly string[] {
  return deployIdentities.map((account) => serviceAccountPrincipal(account, consumer.projectId)).sort();
}

export function denyMatrix(authority: RecoveryAuthority, coordinates: DenyCoordinates, flags: DenyFlags): DenyMatrix {
  if (flags.bootstrap && flags.maintenance) throw new Error("the bootstrap and maintenance forms never combine");
  const bootstrap = flags.bootstrap && authority.bootstrapPrincipal !== null ? [authority.bootstrapPrincipal] : [];
  const maintenance = flags.maintenance ? authority.maintenancePrincipals : [];
  const rows: Record<string, DenyRow> = {};
  const add = (attachment: string, permissions: readonly string[], exceptions: readonly string[]): void => {
    for (const permission of permissions) {
      rows[`${attachment}|${permission}`] = { attachment, denied: [allPrincipals], exceptions: [...new Set(exceptions)].sort(), permission };
    }
  };
  const broker = brokerAttachment(authority);
  const brokerMember = brokerPrincipal(authority);
  const invokers = invokerTuples(authority, coordinates);
  add(broker, brokerLedgerPermissions, [brokerMember]);
  add(broker, brokerSealedPermissions, []);
  add(broker, ["iam.googleapis.com/serviceAccounts.getAccessToken"], [...invokers, ...canaryTuples(authority, coordinates)]);
  add(broker, ["iam.googleapis.com/serviceAccounts.getOpenIdToken"], [schedulerAgentPrincipal(authority), ...invokers, ...memberTuples(authority)]);
  add(broker, brokerDeploymentPermissions, bootstrap);
  for (const consumer of authority.consumers) {
    const attachment = consumerAttachment(consumer);
    add(attachment, ["iam.googleapis.com/serviceAccounts.setIamPolicy"], [brokerMember, ...bootstrap, ...maintenance]);
    add(attachment, ["cloudresourcemanager.googleapis.com/projects.setIamPolicy"], [...bootstrap, ...maintenance]);
    add(attachment, consumerKeyPermissions, []);
    add(attachment, consumerLifecyclePermissions, maintenance);
    add(attachment, consumerDeployPermissions, flags.deployment.includes(consumer.repository) ? deployPrincipals(consumer) : []);
    add(attachment, consumerFreezePermissions, []);
    add(attachment, consumerServiceUsagePermissions, maintenance);
  }
  const organization = organizationAttachment(authority);
  add(organization, organizationRolePermissions, maintenance);
  add(organization, organizationBootstrapRolePermissions, [...bootstrap, ...maintenance]);
  add(organization, organizationPolicyPermissions, maintenance);
  add(organization, organizationMovementPermissions, []);
  return Object.fromEntries(Object.keys(rows).sort().map((key) => [key, rows[key]!]));
}

// The Deny state as the IAM v2 API answers it, projected to what the forms
// are judged on.
export interface LiveDenyRule {
  readonly condition: unknown;
  readonly denied: readonly string[];
  readonly exceptedPermissions: readonly string[];
  readonly exceptions: readonly string[];
  readonly permissions: readonly string[];
}

export interface LiveDenyPolicy {
  readonly attachment: string;
  readonly etag: string;
  readonly name: string;
  readonly rules: readonly LiveDenyRule[];
}

export type DenyVerdict =
  | { readonly kind: "classified"; readonly flags: DenyFlags }
  | { readonly kind: "drifted"; readonly reasons: readonly string[] };

// The label one consumer's inventory records for the live state: steady, or
// the widening that disables authority for that consumer.
export function denyFormFor(verdict: DenyVerdict, consumer: Consumer): string {
  if (verdict.kind === "drifted") return `drifted: ${verdict.reasons.join("; ")}`;
  if (verdict.flags.bootstrap) return "bootstrap";
  if (verdict.flags.maintenance) return "maintenance";
  return verdict.flags.deployment.includes(consumer.repository) ? "deployment" : "steady";
}

// The platform commits the live broker rules are bound at, read from the
// live invoker exceptions themselves: the module pins them as variables, the
// runtime does not know them, and what matters here is that every invoker
// exception is an exact protected-recovery-invoke tuple at one of at most two
// commits, the canary's commit being the active one.
export function platformShasOf(authority: RecoveryAuthority, live: readonly LiveDenyPolicy[]): { readonly kind: "shas"; readonly shas: readonly string[] } | { readonly kind: "unknown"; readonly reason: string } {
  const pool = brokerPool(authority);
  const invokePrefix = `principalSet://iam.googleapis.com/${pool}/attribute.authority/${authority.platformRepository}/.github/workflows/protected-recovery-invoke.yml@refs/heads/main${authorityDelimiter}`;
  const canaryPrefix = `principalSet://iam.googleapis.com/${pool}/attribute.authority/${authority.platformRepository}/.github/workflows/protected-recovery-deny-canary.yml@refs/heads/main${authorityDelimiter}`;
  const shas = new Set<string>();
  let active: string | undefined;
  const broker = brokerAttachment(authority);
  for (const policy of live) {
    if (policy.attachment !== broker) continue;
    for (const rule of policy.rules) {
      for (const exception of rule.exceptions) {
        const invoke = exception.startsWith(invokePrefix) ? exception.slice(invokePrefix.length).split(authorityDelimiter)[0] : undefined;
        const canary = exception.startsWith(canaryPrefix) ? exception.slice(canaryPrefix.length).split(authorityDelimiter)[0] : undefined;
        if (invoke !== undefined && /^[0-9a-f]{40}$/.test(invoke)) shas.add(invoke);
        if (canary !== undefined && /^[0-9a-f]{40}$/.test(canary)) {
          if (active !== undefined && active !== canary) return { kind: "unknown", reason: "the live broker rules bind the Deny canary at two commits" };
          active = canary;
        }
      }
    }
  }
  if (active === undefined) return { kind: "unknown", reason: "the live broker rules bind no Deny canary tuple" };
  shas.delete(active);
  if (shas.size > 1) return { kind: "unknown", reason: `the live broker rules bind invoker tuples at more than two commits: ${[active, ...shas].join(", ")}` };
  return { kind: "shas", shas: [active, ...shas] };
}

const consumerDeployRows = new Set(consumerDeployPermissions);

// Which form the live policies at the given attachment points satisfy: every
// row at those attachments must have an exactly matching live rule
// (unconditioned, no permission exceptions, every principal denied, the exact
// exception set) under one of the exact widenings -- no flag, bootstrap, or
// maintenance, each combined with any set of consumers in deployment form --
// or the state is drifted, naming the steady rows that fail.
export function classifyDenyState(authority: RecoveryAuthority, live: readonly LiveDenyPolicy[], attachments: readonly string[]): DenyVerdict {
  const shas = platformShasOf(authority, live);
  if (shas.kind === "unknown") return { kind: "drifted", reasons: [shas.reason] };
  const rules = live.flatMap((policy) => policy.rules.map((rule) => ({ ...rule, attachment: policy.attachment })));
  const satisfied = (row: DenyRow): boolean =>
    rules.some((rule) =>
      rule.attachment === row.attachment &&
      rule.condition === null &&
      rule.exceptedPermissions.length === 0 &&
      sameSet(rule.denied, row.denied) &&
      sameSet(rule.exceptions, row.exceptions) &&
      rule.permissions.includes(row.permission),
    );
  const coordinates = { platformShas: shas.shas };
  const consumers = authority.consumers.filter((consumer) => attachments.includes(consumerAttachment(consumer)));
  // Every consumer's deploy rows are judged on their own; every other row
  // decides the one overlay.
  const deployment = consumers.filter((consumer) => {
    const widened = denyMatrix(authority, coordinates, { ...steadyFlags, deployment: [consumer.repository] });
    const rows = Object.values(widened).filter((row) => row.attachment === consumerAttachment(consumer) && consumerDeployRows.has(row.permission));
    return rows.every(satisfied);
  }).map((consumer) => consumer.repository);
  let steadyFailures: string[] = [];
  for (const overlay of [steadyFlags, { ...steadyFlags, bootstrap: true }, { ...steadyFlags, maintenance: true }]) {
    const flags: DenyFlags = { ...overlay, deployment };
    const matrix = denyMatrix(authority, coordinates, flags);
    const rows = Object.values(matrix).filter((row) => attachments.includes(row.attachment));
    const failures = rows.filter((row) => !satisfied(row)).map((row) => `${row.attachment}|${row.permission}`);
    if (failures.length === 0) return { kind: "classified", flags };
    if (!overlay.bootstrap && !overlay.maintenance) steadyFailures = failures;
  }
  return { kind: "drifted", reasons: steadyFailures.slice(0, 8).map((row) => `no live rule carries the row ${row}`) };
}

// A deny policy carries one rule per exception set: every permission of one
// attachment point that shares an exception set sits in one rule, in sorted
// order. This is the shape the root installs and the IAM v2 API answers, and
// the shape the test stand-in and the enabled-path fixtures render a matrix
// into, so the classifier is judged against the same grouping live.
export interface GroupedRule {
  readonly exceptions: readonly string[];
  readonly permissions: readonly string[];
}

export function rulesByException(matrix: DenyMatrix): ReadonlyMap<string, readonly GroupedRule[]> {
  const byAttachment = new Map<string, Map<string, { readonly exceptions: readonly string[]; readonly permissions: string[] }>>();
  for (const row of Object.values(matrix)) {
    const rules = byAttachment.get(row.attachment) ?? new Map<string, { readonly exceptions: readonly string[]; readonly permissions: string[] }>();
    byAttachment.set(row.attachment, rules);
    const key = canonicalJson(row.exceptions);
    const rule = rules.get(key) ?? { exceptions: row.exceptions, permissions: [] };
    rules.set(key, rule);
    rule.permissions.push(row.permission);
  }
  return new Map([...byAttachment].map(([attachment, rules]) => [attachment, [...rules.values()].map((rule) => ({ exceptions: rule.exceptions, permissions: [...rule.permissions].sort() }))]));
}

// The IAM v2 listing and policy documents, projected; anything malformed is
// refused so the state is unread rather than misread.
export function livePolicyFromJson(attachment: string, value: unknown): LiveDenyPolicy {
  if (!isRecord(value) || typeof value.name !== "string" || typeof value.etag !== "string" || value.etag.length === 0) throw new Error(`the deny policy of ${attachment} is malformed`);
  const rawRules = value.rules === undefined ? [] : value.rules;
  if (!Array.isArray(rawRules)) throw new Error(`the deny policy ${value.name} carries malformed rules`);
  const rules: LiveDenyRule[] = [];
  for (const raw of rawRules) {
    if (!isRecord(raw)) throw new Error(`the deny policy ${value.name} carries a malformed rule`);
    if (raw.denyRule === undefined) continue;
    const denyRule = raw.denyRule;
    if (!isRecord(denyRule)) throw new Error(`the deny policy ${value.name} carries a malformed deny rule`);
    rules.push({
      condition: denyRule.denialCondition === undefined ? null : denyRule.denialCondition,
      denied: strings(denyRule.deniedPrincipals, value.name),
      exceptedPermissions: strings(denyRule.exceptionPermissions, value.name),
      exceptions: strings(denyRule.exceptionPrincipals, value.name),
      permissions: strings(denyRule.deniedPermissions, value.name),
    });
  }
  return { attachment, etag: value.etag, name: value.name, rules };
}

export function denyPoliciesUrl(attachment: string): string {
  return `https://iam.googleapis.com/v2/policies/${encodeURIComponent(attachment)}/denypolicies`;
}

function strings(value: unknown, policy: string): readonly string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || !value.every((item): item is string => typeof item === "string")) throw new Error(`the deny policy ${policy} carries a malformed principal or permission list`);
  return value;
}

function sameSet(left: readonly string[], right: readonly string[]): boolean {
  return canonicalJson([...new Set(left)].sort()) === canonicalJson([...new Set(right)].sort());
}
