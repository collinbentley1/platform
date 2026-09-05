import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { brokerAttachment, consumerAttachment, denyCanaryPrincipal, denyMatrix, organizationAttachment, rulesByException, steadyFlags } from "../../protected-recovery/src/deny";
import { type RecoveryAuthority, loadRecoveryAuthority } from "../../protected-recovery/src/model";
import { canaryBodySha256, canaryDigest } from "./protected-recovery-canary-digest";
import { manifestPath } from "./workflow-authority";

// Render the predicate one phase of the Deny canary attests
// (tools/ci/protected-recovery-deny-canary.sh, schema
// protected-recovery/deny-canary/v3, or deny-canary-cleanup/v3 for the
// cleanup phase) for one authority file, one platform commit set, and one
// control run, exactly as the producer shapes it: the live rules of every
// attachment point grouped by exception set (the canary principal added to
// each set in the control phase), the allow policies the phase recorded, and
// for every permission of every rule one observation of the request the
// producer makes for it -- its method, URL, content type, canonical body
// digest, required and observed pre-state, the permissions it needs, the
// operation it started, and the digest of all of that -- answered ALLOWED in
// the control phase and DENIED with an IAM permission denial naming the row's
// permission in the deny phase, or, for the consumer Compute and Cloud Build
// rows whose API the consumer projects do not enable, SERVICE_DISABLED in
// both. The enabled-path Terraform harness renders every phase with this and
// derives its adversarial variants from them, so the harness is judged
// against the producer's own shape.
//
//   bun run tools/ci/protected-recovery-canary-fixture.ts <authority.json> <active-sha>[,<transition-sha>] <control|deny|cleanup> <control-run-id> <run-id> <broker-image>

const [authorityPath, shas, phase, controlRunId, runId, brokerImage] = Bun.argv.slice(2);
if (!authorityPath || !shas || !phase || !controlRunId || !runId || !brokerImage) {
  throw new Error("Usage: protected-recovery-canary-fixture.ts <authority.json> <active-sha>[,<transition-sha>] <control|deny|cleanup> <control-run-id> <run-id> <broker-image>");
}
if (phase !== "control" && phase !== "deny" && phase !== "cleanup") throw new Error(`unknown phase ${phase}`);
if (!/^[1-9][0-9]*$/.test(controlRunId) || !/^[1-9][0-9]*$/.test(runId)) throw new Error("run IDs must be positive integers");
const root = join(import.meta.dir, "..", "..");
const authority: RecoveryAuthority = loadRecoveryAuthority(await readFile(authorityPath, "utf8"), await readFile(join(root, manifestPath), "utf8"));
const platformShas = shas.split(",").filter((sha) => sha.length > 0);
const active = platformShas[0];
if (active === undefined || !platformShas.every((sha) => /^[0-9a-f]{40}$/.test(sha))) throw new Error("every platform commit must be one full lowercase SHA");
const organizationId = authority.organizationId;
const brokerProject = authority.broker.projectId;
if (organizationId === null || brokerProject === null) throw new Error("the authority must record the organization and the broker project");

const region = authority.broker.region;
const zone = `${region}-a`;
const suffix = controlRunId.slice(-12);
const throwaway = `deny-canary-${suffix}`;
const throwawayNew = `${throwaway}-new`;
const throwawayGone = `${throwaway}-gone`;
const delegate = `${throwaway}-d`;
const roleId = `denyCanary${suffix}`;
const roleNew = `${roleId}New`;
const roleGone = `${roleId}Gone`;
const canaryProject = throwaway;
const folderId = "500100200300";
const constraintNew = "compute.skipDefaultNetworkCreation";
const constraintKept = "compute.requireOsLogin";
const constraintV1 = "compute.requireShieldedVm";
const canary = denyCanaryPrincipal(authority);
const canaryEmail = `gha-deny-canary@${brokerProject}.iam.gserviceaccount.com`;
const canaryMember = `serviceAccount:${canaryEmail}`;
const tokenCreator = "roles/iam.serviceAccountTokenCreator";
const ledgerDatabase = authority.broker.firestoreDatabase;
const evidenceBucket = `${brokerProject}-protected-recovery-evidence`;
const helloImage = "us-docker.pkg.dev/cloudrun/container/hello";
const endpoints = {
  cloudbuild: "https://cloudbuild.googleapis.com/v1",
  compute: "https://compute.googleapis.com/compute/v1",
  credentials: "https://iamcredentials.googleapis.com/v1",
  crm: "https://cloudresourcemanager.googleapis.com/v3",
  crmV1: "https://cloudresourcemanager.googleapis.com/v1",
  firestore: "https://firestore.googleapis.com/v1",
  gcs: "https://storage.googleapis.com",
  iam: "https://iam.googleapis.com/v1",
  orgpolicy: "https://orgpolicy.googleapis.com/v2",
  registry: "https://artifactregistry.googleapis.com",
  run: "https://run.googleapis.com/v2",
  scheduler: "https://cloudscheduler.googleapis.com/v1",
  serviceusage: "https://serviceusage.googleapis.com/v1",
};
// The consumer attachment rows the consumer projects cannot serve: their API
// is not enabled there (terraform/modules/protected-recovery/main.tf,
// unserviceable_permissions).
const unserviceable: Readonly<Record<string, string>> = {
  "cloudbuild.googleapis.com/builds.create": "cloudbuild.googleapis.com",
  "compute.googleapis.com/instanceTemplates.create": "compute.googleapis.com",
  "compute.googleapis.com/instances.create": "compute.googleapis.com",
  "compute.googleapis.com/instances.setServiceAccount": "compute.googleapis.com",
};
// The rows whose pre-state read is itself a denied row (datastore
// entities.get): the deny phase records unknown.
const unobservableInDeny = new Set(["datastore.googleapis.com/entities.create", "datastore.googleapis.com/entities.get", "datastore.googleapis.com/entities.update", "datastore.googleapis.com/entities.delete"]);
const actAs = "iam.googleapis.com/serviceAccounts.actAs";
const organization = `organizations/${organizationId}`;

type Scope = "broker" | "consumer" | "organization";

interface Exercise {
  readonly body: unknown | Uint8Array | null;
  readonly contentType: string;
  readonly detail: string;
  readonly expected: string;
  readonly lro: boolean;
  readonly method: string;
  readonly requires: readonly string[];
  readonly resource: string;
  readonly url: string;
}

const email = (id: string, project: string) => `${id}@${project}.iam.gserviceaccount.com`;
const accountBody = (id: string) => ({ accountId: id, serviceAccount: { displayName: "Protected recovery Deny canary throwaway" } });
const poolBody = { displayName: "Protected recovery Deny canary throwaway" };
const providerBody = { attributeCondition: "false", attributeMapping: { "google.subject": "assertion.sub" }, displayName: "Protected recovery Deny canary throwaway", oidc: { issuerUri: "https://token.actions.githubusercontent.com/" } };
const roleBody = (id: string) => ({ role: { includedPermissions: ["resourcemanager.projects.get"], stage: "DISABLED", title: "Protected recovery Deny canary throwaway" }, roleId: id });
const disk = { autoDelete: true, boot: true, initializeParams: { sourceImage: "projects/debian-cloud/global/images/family/debian-12" } };

function multipart(): Uint8Array {
  const boundary = "protected-recovery-deny-canary";
  const text = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify({ package_id: "deny-canary", version_id: suffix, filename: "canary.txt" })}\n\r\n--${boundary}\r\nContent-Type: text/plain\r\n\r\nprotected-recovery deny canary ${suffix}\r\n--${boundary}--\r\n`;
  return new TextEncoder().encode(text);
}

// The request the producer makes for one permission at one attachment scope.
function exercise(scope: Scope, project: string, permission: string): Exercise {
  const sa = `projects/-/serviceAccounts/${email(throwaway, project)}`;
  const saNew = `projects/-/serviceAccounts/${email(throwawayNew, project)}`;
  const saGone = `projects/-/serviceAccounts/${email(throwawayGone, project)}`;
  const saDelegate = `projects/-/serviceAccounts/${email(delegate, project)}`;
  const goneId = `1${project.length.toString().padStart(2, "0")}${suffix.padStart(18, "0")}`.slice(0, 21);
  const pool = `projects/${project}/locations/global/workloadIdentityPools/${throwaway}`;
  const poolNew = `projects/${project}/locations/global/workloadIdentityPools/${throwawayNew}`;
  const poolGone = `projects/${project}/locations/global/workloadIdentityPools/${throwawayGone}`;
  const provider = `${pool}/providers/${throwaway}`;
  const providerNew = `${pool}/providers/${throwawayNew}`;
  const providerGone = `${pool}/providers/${throwawayGone}`;
  const parent = `projects/${project}/locations/${region}`;
  const service = `${parent}/services/${throwaway}`;
  const serviceNew = `${parent}/services/${throwawayNew}`;
  const job = `${parent}/jobs/${throwaway}`;
  const jobNew = `${parent}/jobs/${throwawayNew}`;
  const workerPool = `${parent}/workerPools/${throwaway}`;
  const workerPoolNew = `${parent}/workerPools/${throwawayNew}`;
  const repository = `${parent}/repositories/${throwaway}`;
  const version = `${repository}/packages/deny-canary/versions/${suffix}`;
  const documents = `projects/${project}/databases/${ledgerDatabase}/documents`;
  const document = `${documents}/canary/${suffix}`;
  const documentNew = `${documents}/canary/${suffix}-new`;
  const bucket = `b/${evidenceBucket}`;
  const object = `canary%2F${suffix}`;
  const objectNew = `canary%2F${suffix}-new`;
  const instance = `projects/${project}/zones/${zone}/instances/${throwaway}`;
  const instanceNew = `projects/${project}/zones/${zone}/instances/${throwawayNew}`;
  const templateNew = `projects/${project}/global/instanceTemplates/${throwawayNew}`;
  const apiService = `projects/${project}/services/websecurityscanner.googleapis.com`;
  const role = `${organization}/roles/${roleId}`;
  const roleNewName = `${organization}/roles/${roleNew}`;
  const roleGoneName = `${organization}/roles/${roleGone}`;
  const policies = `projects/${brokerProject}/policies`;
  const runtime = email(throwaway, project);
  const serviceBody = { ingress: "INGRESS_TRAFFIC_INTERNAL_ONLY", template: { containers: [{ image: helloImage }], serviceAccount: runtime } };
  const jobBody = { template: { template: { containers: [{ image: helloImage }], serviceAccount: runtime } } };
  const workerPoolBody = { scaling: { manualInstanceCount: 0, scalingMode: "MANUAL" }, template: { containers: [{ image: helloImage }], serviceAccount: runtime } };
  const json = "application/json";
  const one = (method: string, url: string, body: unknown | Uint8Array | null, resource: string, expected: string, options: { readonly contentType?: string; readonly detail?: string; readonly lro?: boolean; readonly requires?: readonly string[] } = {}): Exercise => ({
    body,
    contentType: body === null ? "" : options.contentType ?? json,
    detail: options.detail ?? "",
    expected,
    lro: options.lro ?? false,
    method,
    requires: options.requires ?? [permission],
    resource,
    url,
  });
  const requests: Readonly<Record<string, () => Exercise>> = {
    "artifactregistry.googleapis.com/repositories.uploadArtifacts": () => one("POST", `${endpoints.registry}/upload/v1/${repository}/genericArtifacts:create?uploadType=multipart`, multipart(), version, "absent", { contentType: "multipart/related; boundary=protected-recovery-deny-canary", lro: true }),
    "cloudbuild.googleapis.com/builds.create": () => one("POST", `${endpoints.cloudbuild}/projects/${project}/locations/global/builds`, { options: { logging: "CLOUD_LOGGING_ONLY" }, steps: [{ args: ["version"], name: "gcr.io/cloud-builders/gcloud" }], tags: ["protected-recovery-deny-canary"] }, "-", "none"),
    "cloudresourcemanager.googleapis.com/projects.move": () => one("POST", `${endpoints.crm}/projects/${canaryProject}:move`, { destinationParent: `folders/${folderId}` }, `projects/${canaryProject}`, "present", { detail: organization, lro: true }),
    "cloudresourcemanager.googleapis.com/projects.setIamPolicy": () => one("POST", `${endpoints.crm}/projects/${project}:setIamPolicy`, { policy: { bindings: [], etag: `etag-${phase}`, version: 3 }, updateMask: "bindings,etag" }, `projects/${project}`, "present", { detail: organization }),
    "cloudresourcemanager.googleapis.com/projects.update": () => one("PATCH", `${endpoints.crm}/projects/${canaryProject}?updateMask=labels`, { labels: { "protected-recovery": "deny-canary" } }, `projects/${canaryProject}`, "present", { detail: organization, lro: true }),
    "compute.googleapis.com/instanceTemplates.create": () => one("POST", `${endpoints.compute}/projects/${project}/global/instanceTemplates`, { name: throwawayNew, properties: { disks: [disk], machineType: "e2-micro", networkInterfaces: [{ network: "global/networks/default" }] } }, templateNew, "absent", { lro: true }),
    "compute.googleapis.com/instances.create": () => one("POST", `${endpoints.compute}/projects/${project}/zones/${zone}/instances`, { disks: [disk], machineType: `zones/${zone}/machineTypes/e2-micro`, name: throwawayNew, networkInterfaces: [{ network: "global/networks/default" }] }, instanceNew, "absent", { lro: true }),
    "compute.googleapis.com/instances.setServiceAccount": () => one("POST", `${endpoints.compute}/${instance}/setServiceAccount`, {}, instance, "present", { lro: true }),
    "datastore.googleapis.com/entities.create": () => one("POST", `${endpoints.firestore}/${documents}:commit`, { writes: [{ currentDocument: { exists: false }, update: { fields: { run: { stringValue: "canary" } }, name: documentNew } }] }, documentNew, "absent"),
    "datastore.googleapis.com/entities.delete": () => one("POST", `${endpoints.firestore}/${documents}:commit`, { writes: [{ delete: document }] }, document, "present"),
    "datastore.googleapis.com/entities.get": () => one("GET", `${endpoints.firestore}/${document}`, null, document, "present"),
    "datastore.googleapis.com/entities.list": () => one("GET", `${endpoints.firestore}/${documents}/canary?pageSize=1`, null, "-", "none"),
    "datastore.googleapis.com/entities.update": () => one("POST", `${endpoints.firestore}/${documents}:commit`, { writes: [{ currentDocument: { exists: true }, update: { fields: { run: { stringValue: "canary" } }, name: document } }] }, document, "present"),
    "iam.googleapis.com/roles.create": () => one("POST", `${endpoints.iam}/organizations/${organizationId}/roles`, roleBody(roleNew), roleNewName, "inactive"),
    "iam.googleapis.com/roles.delete": () => one("DELETE", `${endpoints.iam}/${role}`, null, role, "present"),
    "iam.googleapis.com/roles.undelete": () => one("POST", `${endpoints.iam}/${roleGoneName}:undelete`, {}, roleGoneName, "deleted"),
    "iam.googleapis.com/roles.update": () => one("PATCH", `${endpoints.iam}/${role}?updateMask=description`, { description: "protected-recovery deny canary" }, role, "present"),
    "iam.googleapis.com/serviceAccountKeys.create": () => one("POST", `${endpoints.iam}/${sa}/keys`, { keyAlgorithm: "KEY_ALG_RSA_2048", privateKeyType: "TYPE_GOOGLE_CREDENTIALS_FILE" }, sa, "present"),
    "iam.googleapis.com/serviceAccounts.actAs": () => one("POST", `${endpoints.scheduler}/${parent}/jobs`, { httpTarget: { httpMethod: "GET", oidcToken: { serviceAccountEmail: runtime }, uri: "https://deny-canary.invalid/" }, name: `${parent}/jobs/${throwaway}`, schedule: "0 0 1 1 *", timeZone: "Etc/UTC" }, `${parent}/jobs/${throwaway}`, "absent"),
    "iam.googleapis.com/serviceAccounts.create": () => one("POST", `${endpoints.iam}/projects/${project}/serviceAccounts`, accountBody(throwawayNew), saNew, "absent"),
    "iam.googleapis.com/serviceAccounts.delete": () => one("DELETE", `${endpoints.iam}/${sa}`, null, sa, "present"),
    "iam.googleapis.com/serviceAccounts.disable": () => one("POST", `${endpoints.iam}/${sa}:disable`, {}, sa, "present"),
    "iam.googleapis.com/serviceAccounts.enable": () => one("POST", `${endpoints.iam}/${sa}:enable`, {}, sa, "present"),
    "iam.googleapis.com/serviceAccounts.getAccessToken": () => one("POST", `${endpoints.credentials}/${sa}:generateAccessToken`, { lifetime: "300s", scope: ["https://www.googleapis.com/auth/cloud-platform"] }, sa, "present"),
    "iam.googleapis.com/serviceAccounts.getOpenIdToken": () => one("POST", `${endpoints.credentials}/${sa}:generateIdToken`, { audience: "https://deny-canary.invalid", includeEmail: false }, sa, "present"),
    "iam.googleapis.com/serviceAccounts.implicitDelegation": () => one("POST", `${endpoints.credentials}/${sa}:generateAccessToken`, { delegates: [saDelegate], lifetime: "300s", scope: ["https://www.googleapis.com/auth/cloud-platform"] }, sa, "present", { requires: [permission, "iam.googleapis.com/serviceAccounts.getAccessToken"] }),
    "iam.googleapis.com/serviceAccounts.setIamPolicy": () => one("POST", `${endpoints.iam}/${sa}:setIamPolicy`, scope === "broker" ? { policy: { bindings: [{ members: [canaryMember, `serviceAccount:${email(delegate, project)}`], role: tokenCreator }], version: 3 }, updateMask: "bindings" } : { policy: { version: 3 }, updateMask: "bindings" }, sa, "present"),
    "iam.googleapis.com/serviceAccounts.signBlob": () => one("POST", `${endpoints.credentials}/${sa}:signBlob`, { payload: "ZGVueS1jYW5hcnk=" }, sa, "present"),
    "iam.googleapis.com/serviceAccounts.signJwt": () => one("POST", `${endpoints.credentials}/${sa}:signJwt`, { payload: '{"iss":"deny-canary"}' }, sa, "present"),
    "iam.googleapis.com/serviceAccounts.undelete": () => one("POST", `${endpoints.iam}/projects/-/serviceAccounts/${goneId}:undelete`, {}, saGone, "inactive"),
    "iam.googleapis.com/workloadIdentityPoolProviders.create": () => one("POST", `${endpoints.iam}/${pool}/providers?workloadIdentityPoolProviderId=${throwawayNew}`, providerBody, providerNew, "inactive", { lro: true }),
    "iam.googleapis.com/workloadIdentityPoolProviders.delete": () => one("DELETE", `${endpoints.iam}/${provider}`, null, provider, "present", { lro: true }),
    "iam.googleapis.com/workloadIdentityPoolProviders.undelete": () => one("POST", `${endpoints.iam}/${providerGone}:undelete`, {}, providerGone, "deleted", { lro: true }),
    "iam.googleapis.com/workloadIdentityPoolProviders.update": () => one("PATCH", `${endpoints.iam}/${provider}?updateMask=description`, { description: "protected-recovery deny canary" }, provider, "present", { lro: true }),
    "iam.googleapis.com/workloadIdentityPools.create": () => one("POST", `${endpoints.iam}/projects/${project}/locations/global/workloadIdentityPools?workloadIdentityPoolId=${throwawayNew}`, poolBody, poolNew, "inactive", { lro: true }),
    "iam.googleapis.com/workloadIdentityPools.delete": () => one("DELETE", `${endpoints.iam}/${pool}`, null, pool, "present", { lro: true }),
    "iam.googleapis.com/workloadIdentityPools.undelete": () => one("POST", `${endpoints.iam}/${poolGone}:undelete`, {}, poolGone, "deleted", { lro: true }),
    "iam.googleapis.com/workloadIdentityPools.update": () => one("PATCH", `${endpoints.iam}/${pool}?updateMask=description`, { description: "protected-recovery deny canary" }, pool, "present", { lro: true }),
    "orgpolicy.googleapis.com/policies.create": () => one("POST", `${endpoints.orgpolicy}/${policies}`, { name: `${policies}/${constraintNew}`, spec: { rules: [{ enforce: true }] } }, `${policies}/${constraintNew}`, "absent"),
    "orgpolicy.googleapis.com/policies.delete": () => one("DELETE", `${endpoints.orgpolicy}/${policies}/${constraintKept}`, null, `${policies}/${constraintKept}`, "present"),
    "orgpolicy.googleapis.com/policies.update": () => one("PATCH", `${endpoints.orgpolicy}/${policies}/${constraintKept}`, { name: `${policies}/${constraintKept}`, spec: { rules: [{ enforce: false }] } }, `${policies}/${constraintKept}`, "present"),
    "orgpolicy.googleapis.com/policy.set": () => one("POST", `${endpoints.crmV1}/projects/${brokerProject}:setOrgPolicy`, { policy: { booleanPolicy: { enforced: true }, constraint: `constraints/${constraintV1}` } }, `${policies}/${constraintV1}`, "absent"),
    "run.googleapis.com/jobs.create": () => one("POST", `${endpoints.run}/${parent}/jobs?jobId=${throwawayNew}`, jobBody, jobNew, "absent", { lro: true, requires: [permission, actAs] }),
    "run.googleapis.com/jobs.update": () => one("PATCH", `${endpoints.run}/${job}?updateMask=labels`, { labels: { "protected-recovery": "deny-canary" } }, job, "present", { lro: true, requires: [permission, actAs] }),
    "run.googleapis.com/services.create": () => one("POST", `${endpoints.run}/${parent}/services?serviceId=${throwawayNew}`, serviceBody, serviceNew, "absent", { lro: true, requires: [permission, actAs] }),
    "run.googleapis.com/services.delete": () => one("DELETE", `${endpoints.run}/${service}`, null, service, "present", { lro: true }),
    "run.googleapis.com/services.setIamPolicy": () => one("POST", `${endpoints.run}/${service}:setIamPolicy`, { policy: { version: 3 }, updateMask: "bindings" }, service, "present"),
    "run.googleapis.com/services.update": () => one("PATCH", `${endpoints.run}/${service}?updateMask=description`, { description: "protected-recovery deny canary" }, service, "present", { lro: true, requires: [permission, actAs] }),
    "run.googleapis.com/workerpools.create": () => one("POST", `${endpoints.run}/${parent}/workerPools?workerPoolId=${throwawayNew}`, workerPoolBody, workerPoolNew, "absent", { lro: true, requires: [permission, actAs] }),
    "run.googleapis.com/workerpools.update": () => one("PATCH", `${endpoints.run}/${workerPool}?updateMask=description`, { description: "protected-recovery deny canary" }, workerPool, "present", { lro: true, requires: [permission, actAs] }),
    "serviceusage.googleapis.com/services.disable": () => one("POST", `${endpoints.serviceusage}/${apiService}:disable`, { disableDependentServices: false }, apiService, "disabled", { lro: true }),
    "serviceusage.googleapis.com/services.enable": () => one("POST", `${endpoints.serviceusage}/${apiService}:enable`, {}, apiService, "disabled", { lro: true }),
    "storage.googleapis.com/objects.create": () => one("POST", `${endpoints.gcs}/upload/storage/v1/${bucket}/o?uploadType=media&name=${objectNew}&ifGenerationMatch=0`, { canary: true }, `${bucket}/o/${objectNew}`, "absent"),
    "storage.googleapis.com/objects.delete": () => one("DELETE", `${endpoints.gcs}/storage/v1/${bucket}/o/${object}`, null, `${bucket}/o/${object}`, "present"),
    "storage.googleapis.com/objects.update": () => one("PATCH", `${endpoints.gcs}/storage/v1/${bucket}/o/${object}`, { metadata: { "protected-recovery": "deny-canary" } }, `${bucket}/o/${object}`, "present"),
  };
  const found = requests[permission];
  if (!found) throw new Error(`no producer request is modelled for ${permission} (${scope})`);
  return found();
}

// The deny-policy permission in the form an IAM permission denial names it.
function rawPermission(permission: string): string {
  const [service, rest] = permission.split("/", 2) as [string, string];
  const prefix = service === "cloudresourcemanager.googleapis.com" ? "resourcemanager" : service.replace(/\.googleapis\.com$/, "");
  return `${prefix}.${rest}`;
}

function response(scope: Scope, permission: string): Record<string, string> {
  const api = unserviceable[permission];
  if (scope === "consumer" && api !== undefined) {
    return { message: `${api} has not been used in project before or it is disabled.`, permission: "", rawPermission: "", reason: "SERVICE_DISABLED", service: api, status: "403" };
  }
  if (phase === "control") return { message: "", permission: "", rawPermission: "", reason: "", service: "", status: "200" };
  const raw = rawPermission(permission);
  return { message: `Permission '${raw}' denied on resource (or it may not exist).`, permission, rawPermission: raw, reason: "IAM_PERMISSION_DENIED", service: "", status: "403" };
}

function outcome(scope: Scope, permission: string): string {
  if (scope === "consumer" && unserviceable[permission] !== undefined) return "UNSERVICEABLE";
  return phase === "control" ? "ALLOWED" : "DENIED";
}

// The pre-state each phase observes for a request: the required state, as
// the control phase leaves it; the soft-deleted residue of a create row's
// name in the deny phase; unknown where the API is disabled or the read is
// itself the denied get row.
function observed(scope: Scope, permission: string, request: Exercise): string {
  if (scope === "consumer" && unserviceable[permission] !== undefined) return request.expected === "none" ? "none" : "unknown";
  if (phase === "deny" && unobservableInDeny.has(permission)) return "unknown";
  if (request.expected === "inactive") return phase === "control" || request.resource.startsWith("projects/-/serviceAccounts/") ? "absent" : "deleted";
  return request.expected;
}

function operation(scope: Scope, permission: string, request: Exercise): Record<string, unknown> | null {
  if (!request.lro || outcome(scope, permission) !== "ALLOWED") return null;
  return { done: true, error: null, name: `operations/deny-canary-${suffix}-${permission.replace(/[^a-z]/gi, "-")}` };
}

const run = { attempt: 1, event: "workflow_dispatch", headSha: active, id: Number(runId), repositoryId: authority.platformRepositoryId, workflow: ".github/workflows/protected-recovery-deny-canary.yml" };
const throwaways = { delegate, folder: folderId, gone: throwawayGone, name: throwaway, new: throwawayNew, project: canaryProject, role: roleId };

if (phase === "cleanup") {
  const removed = [
    ...authority.consumers.flatMap((consumer) => [`Cloud Run service ${throwaway} of ${consumer.projectId}`, `pool ${throwaway} of ${consumer.projectId}`, `account ${throwaway} of ${consumer.projectId}`]),
    `Cloud Run service ${throwaway} of ${brokerProject}`,
    `registry repository of ${brokerProject}`,
    `account ${throwaway} of ${brokerProject}`,
    `account ${delegate} of ${brokerProject}`,
    `custom role ${roleId} of ${organization}`,
    `throwaway project ${canaryProject}`,
    `throwaway folder folders/${folderId}`,
  ];
  console.log(JSON.stringify({ schema: "protected-recovery/deny-canary-cleanup/v3", phase, controlRunId, brokerImage, organization, run, removed, leftovers: [] }, null, 2));
  process.exit(0);
}

const matrix = denyMatrix(authority, { platformShas }, steadyFlags);
const scopes = new Map<string, { readonly project: string; readonly scope: Scope }>([
  [brokerAttachment(authority), { project: brokerProject, scope: "broker" }],
  [organizationAttachment(authority), { project: brokerProject, scope: "organization" }],
  ...authority.consumers.map((consumer) => [consumerAttachment(consumer), { project: consumer.projectId, scope: "consumer" as const }] as const),
]);
const observedAt = "2026-09-05T00:00:00Z";
const policies = [...rulesByException(matrix)].map(([attachment, rules]) => {
  const scope = scopes.get(attachment);
  if (!scope) throw new Error(`no scope for ${attachment}`);
  return {
    attachmentPoint: attachment,
    etag: `deny-etag-${attachment.split("/").at(-1)}`,
    name: `policies/${encodeURIComponent(attachment)}/denypolicies/protected-recovery`,
    rules: rules.map((rule) => ({
      canary: rule.permissions.map((permission) => {
        const request = exercise(scope.scope, scope.project, permission);
        const bodySha256 = canaryBodySha256(request.body, request.contentType);
        return {
          observedAt,
          outcome: outcome(scope.scope, permission),
          permission,
          principal: canary,
          request: { method: request.method, url: request.url, contentType: request.contentType, bodySha256 },
          preState: { resource: request.resource, expected: request.expected, observed: observed(scope.scope, permission, request), detail: request.detail },
          requires: [...request.requires],
          operation: operation(scope.scope, permission, request),
          digest: canaryDigest(request.method, request.url, request.contentType, bodySha256, request.resource, request.expected, request.detail),
          response: response(scope.scope, permission),
        };
      }),
      denialCondition: null,
      deniedPermissions: [...rule.permissions],
      deniedPrincipals: ["principalSet://goog/public:all"],
      exceptionPermissions: [],
      exceptionPrincipals: phase === "control" ? [...new Set([...rule.exceptions, canary])].sort() : [...rule.exceptions],
    })),
  };
});

// The Allows both phases record: the roles the root granted the canary at
// every attachment point, and the token-creator edges on the throwaway
// accounts, unchanged between the end of the control phase and the start of
// the deny phase.
const attachmentRoles: Readonly<Record<Scope, readonly string[]>> = {
  broker: ["roles/artifactregistry.admin", "roles/cloudscheduler.admin", "roles/datastore.user", "roles/iam.serviceAccountAdmin", "roles/iam.workloadIdentityPoolAdmin", "roles/resourcemanager.projectIamAdmin", "roles/run.admin", "roles/storage.objectAdmin"],
  consumer: ["roles/cloudscheduler.admin", "roles/iam.serviceAccountAdmin", "roles/iam.workloadIdentityPoolAdmin", "roles/resourcemanager.projectIamAdmin", "roles/run.admin", "roles/serviceusage.serviceUsageAdmin"],
  organization: ["roles/iam.organizationRoleAdmin", "roles/orgpolicy.policyAdmin", "roles/resourcemanager.folderCreator", "roles/resourcemanager.projectCreator", "roles/resourcemanager.projectMover"],
};
const allowPolicies = [
  ...[...scopes].map(([attachment, scope]) => ({ resource: scope.scope === "organization" ? organization : `projects/${scope.project}`, etag: `allow-etag-${attachment.split("/").at(-1)}`, canaryRoles: [...attachmentRoles[scope.scope]], delegateRoles: [] as string[] })),
  { resource: `projects/${brokerProject}/serviceAccounts/${email(throwaway, brokerProject)}`, etag: "allow-etag-throwaway", canaryRoles: [tokenCreator], delegateRoles: [tokenCreator] },
  { resource: `projects/${brokerProject}/serviceAccounts/${email(delegate, brokerProject)}`, etag: "allow-etag-delegate", canaryRoles: [tokenCreator], delegateRoles: [] as string[] },
].sort((left, right) => left.resource.localeCompare(right.resource));

console.log(JSON.stringify({
  schema: "protected-recovery/deny-canary/v3",
  phase,
  controlRunId,
  brokerImage,
  organization,
  run,
  throwaways,
  allowPolicies,
  policies,
  unexercised: [],
  failures: [],
}, null, 2));
