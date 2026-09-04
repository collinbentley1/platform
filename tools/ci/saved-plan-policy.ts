import {
  expectedWorkloadIdentityBindings,
  isRecord,
  providerAttributeCondition,
  providerAttributeMapping,
  workloadIdentityPoolId,
  workloadIdentityUserRole,
  type WorkflowAuthorityEntry,
} from "./workflow-authority";

// Policy over `terraform show -json <plan>` for the protected bootstrap root.
// Pure JSON traversal: every decision reads planned values that Terraform has
// already resolved, and anything authorization-relevant that is still unknown
// at plan time is refused rather than trusted to resolve well during apply.
export interface SavedPlanExpectation {
  readonly activeSha: string;
  readonly approvedModules: readonly string[];
  readonly projectNumber: string;
  readonly repositoryId: string;
  readonly transitionSha: string | null;
}

interface ResourceChange {
  readonly address: string;
  readonly after: Record<string, unknown> | null;
  readonly afterUnknown: unknown;
  readonly index: unknown;
  readonly module: string;
  readonly type: string;
}

type PlannedResource = ResourceChange & { readonly after: Record<string, unknown> };

const iamResource = /_iam_(member|binding|policy)$/;
const provisionerVehicles = new Set(["null_resource", "terraform_data"]);
const tokenCreatorRole = "roles/iam.serviceAccountTokenCreator";
const serviceAccountMember = /^serviceAccount:[a-z][a-z0-9-]*@[a-z][a-z0-9-]*\.iam\.gserviceaccount\.com$/;
const storageLogDeliveryMember = "group:cloud-storage-analytics@google.com";
const githubIssuer = "https://token.actions.githubusercontent.com/";

export function evaluateSavedPlanPolicy(
  plan: unknown,
  entries: readonly WorkflowAuthorityEntry[],
  expectation: SavedPlanExpectation,
): string[] {
  const failures: string[] = [];
  if (!isRecord(plan) || typeof plan.format_version !== "string" || !Array.isArray(plan.resource_changes) || !isRecord(plan.planned_values) || !isRecord(plan.planned_values.root_module) || !isRecord(plan.configuration)) {
    return ["plan: must be terraform show -json output with format_version, resource_changes, planned_values, and configuration."];
  }
  const expectedBindings = expectedWorkloadIdentityBindings(entries, expectation.activeSha, expectation.transitionSha, expectation.projectNumber);
  const expectedPool = `projects/${expectation.projectNumber}/locations/global/workloadIdentityPools/${workloadIdentityPoolId}`;
  const approved = new Set(expectation.approvedModules);

  for (const address of moduleAddresses(plan.planned_values.root_module)) {
    if (!approved.has(address)) failures.push(`${address}: module is not approved.`);
  }
  if (hasProvisioners(plan.configuration)) failures.push("configuration: provisioners are forbidden.");

  const changes: PlannedResource[] = [];
  for (const [position, raw] of plan.resource_changes.entries()) {
    const change = resourceChange(raw);
    if (!change) {
      failures.push(`resource_changes[${position}]: malformed resource change.`);
      continue;
    }
    if (!approved.has(change.module)) failures.push(`${change.address}: lives outside the approved modules.`);
    if (provisionerVehicles.has(change.type)) failures.push(`${change.address}: ${change.type} is forbidden.`);
    if (isPlanned(change)) changes.push(change);
  }

  const pools = changes.filter((change) => change.type === "google_iam_workload_identity_pool");
  if (pools.length !== 1) failures.push(`workload identity pools: expected exactly 1, found ${pools.length}.`);
  for (const pool of pools) {
    if (pool.after.workload_identity_pool_id !== workloadIdentityPoolId) failures.push(`${pool.address}: pool id must be ${workloadIdentityPoolId}.`);
    if (typeof pool.after.name === "string" && pool.after.name !== expectedPool) failures.push(`${pool.address}: pool name ${pool.after.name} is not ${expectedPool}.`);
  }
  const providers = changes.filter((change) => change.type === "google_iam_workload_identity_pool_provider");
  if (providers.length !== 1) failures.push(`workload identity providers: expected exactly 1, found ${providers.length}.`);
  for (const provider of providers) checkProvider(provider, expectation.repositoryId, failures);

  const found = new Map<string, number>();
  for (const change of changes) {
    if (!iamResource.test(change.type)) continue;
    if (change.type.endsWith("_iam_policy")) {
      failures.push(`${change.address}: authoritative IAM policies are forbidden.`);
      continue;
    }
    for (const key of ["role", "member", "members", "condition"]) {
      if (unknown(change.afterUnknown, key)) failures.push(`${change.address}: ${key} is unknown until apply.`);
    }
    const role = change.after.role;
    if (role === tokenCreatorRole) failures.push(`${change.address}: ${tokenCreatorRole} is forbidden.`);
    const members = typeof change.after.member === "string" ? [change.after.member] : Array.isArray(change.after.members) ? change.after.members : [];
    for (const member of members) {
      if (typeof member !== "string") {
        failures.push(`${change.address}: member must be a string.`);
      } else if (member.includes("*")) {
        failures.push(`${change.address}: wildcard member ${member} is forbidden.`);
      } else if (member.startsWith("principal://") || member.startsWith("principalSet://")) {
        if (change.type !== "google_service_account_iam_member") failures.push(`${change.address}: federated principal ${member} may only be bound to a service account.`);
      } else if (!serviceAccountMember.test(member) && !(member === storageLogDeliveryMember && change.type === "google_storage_bucket_iam_member")) {
        failures.push(`${change.address}: unexpected member ${member}.`);
      }
    }
    if (change.type !== "google_service_account_iam_member") continue;
    const key = typeof change.index === "string" ? change.index : "";
    const binding = expectedBindings.get(key);
    if (!binding) {
      if (members.some((member) => typeof member === "string" && member.startsWith("principal"))) failures.push(`${change.address}: federated binding is not in the workflow authority manifest.`);
      else if (role !== "roles/iam.serviceAccountUser") failures.push(`${change.address}: unexpected service account role ${String(role)}.`);
      continue;
    }
    found.set(key, (found.get(key) ?? 0) + 1);
    if (role !== workloadIdentityUserRole) failures.push(`${change.address}: role must be ${workloadIdentityUserRole}.`);
    if (change.after.member !== binding.member) failures.push(`${change.address}: member must be ${binding.member}.`);
    const target = change.after.service_account_id;
    if (typeof target !== "string") failures.push(`${change.address}: service_account_id is unknown until apply.`);
    else if (target.match(/\/serviceAccounts\/([a-z][a-z0-9-]*)@/)?.[1] !== binding.account) failures.push(`${change.address}: must bind ${binding.account}, not ${target}.`);
  }
  for (const [key, binding] of expectedBindings) {
    const count = found.get(key) ?? 0;
    if (count !== 1) failures.push(`${key}: expected exactly one binding of ${binding.member}, found ${count}.`);
  }
  return failures;
}

function checkProvider(provider: PlannedResource, repositoryId: string, failures: string[]): void {
  const { address, after } = provider;
  for (const key of ["attribute_condition", "attribute_mapping", "disabled"]) {
    if (unknown(provider.afterUnknown, key)) failures.push(`${address}: ${key} is unknown until apply.`);
  }
  if (after.workload_identity_pool_provider_id !== "github") failures.push(`${address}: provider id must be github.`);
  if (after.workload_identity_pool_id !== workloadIdentityPoolId) failures.push(`${address}: pool id must be ${workloadIdentityPoolId}.`);
  const condition = providerAttributeCondition(repositoryId);
  if (after.attribute_condition !== condition) failures.push(`${address}: attribute_condition must be exactly ${JSON.stringify(condition)}.`);
  const mapping = isRecord(after.attribute_mapping) ? after.attribute_mapping : {};
  const expectedMapping = JSON.stringify(Object.entries(providerAttributeMapping).sort());
  if (JSON.stringify(Object.entries(mapping).sort()) !== expectedMapping) failures.push(`${address}: attribute_mapping must be exactly ${expectedMapping}.`);
  const oidc = Array.isArray(after.oidc) ? after.oidc : [];
  if (oidc.length !== 1 || !isRecord(oidc[0]) || oidc[0].issuer_uri !== githubIssuer) failures.push(`${address}: oidc issuer must be exactly ${githubIssuer}.`);
  for (const key of ["aws", "saml", "x509"]) {
    if (Array.isArray(after[key]) ? after[key].length > 0 : after[key] !== undefined && after[key] !== null) failures.push(`${address}: ${key} identity is forbidden.`);
  }
}

function resourceChange(raw: unknown): ResourceChange | undefined {
  if (!isRecord(raw) || typeof raw.address !== "string" || typeof raw.type !== "string" || !isRecord(raw.change) || !Array.isArray(raw.change.actions)) return undefined;
  const { after } = raw.change;
  const deleted = after === null && raw.change.actions.every((action) => action === "delete");
  if (!deleted && !isRecord(after)) return undefined;
  return {
    address: raw.address,
    after: isRecord(after) ? after : null,
    afterUnknown: raw.change.after_unknown,
    index: raw.index,
    module: typeof raw.module_address === "string" ? raw.module_address : "",
    type: raw.type,
  };
}

function isPlanned(change: ResourceChange): change is PlannedResource {
  return change.after !== null;
}

function moduleAddresses(module: Record<string, unknown>): string[] {
  const children = Array.isArray(module.child_modules) ? module.child_modules : [];
  return children.flatMap((child) => (isRecord(child) && typeof child.address === "string" ? [child.address, ...moduleAddresses(child)] : ["<malformed module>"]));
}

function hasProvisioners(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(hasProvisioners);
  if (!isRecord(value)) return false;
  return Object.entries(value).some(([key, item]) => (key === "provisioners" && Array.isArray(item) && item.length > 0) || hasProvisioners(item));
}

function unknown(afterUnknown: unknown, key: string): boolean {
  const value = isRecord(afterUnknown) ? afterUnknown[key] : undefined;
  const unresolved = (node: unknown): boolean =>
    node === true || (Array.isArray(node) ? node.some(unresolved) : isRecord(node) && Object.values(node).some(unresolved));
  return unresolved(value);
}
