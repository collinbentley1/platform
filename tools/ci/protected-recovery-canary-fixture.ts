import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { brokerAttachment, consumerAttachment, denyCanaryPrincipal, denyMatrix, organizationAttachment, rulesByException, steadyFlags } from "../../protected-recovery/src/deny";
import { type RecoveryAuthority, loadRecoveryAuthority } from "../../protected-recovery/src/model";
import { manifestPath } from "./workflow-authority";

// Render the predicate one phase of the Deny canary attests
// (tools/ci/protected-recovery-deny-canary.sh, schema
// protected-recovery/deny-canary/v2) for one authority file, one platform
// commit set, and one control run, exactly as the producer shapes it: the
// live rules of every attachment point grouped by exception set (the canary
// principal added to each set in the control phase), and for every permission
// of every rule one observation of the request the producer makes for it,
// answered ALLOWED in the control phase and DENIED with an IAM permission
// denial naming the row's permission in the deny phase -- or, for the
// consumer Compute and Cloud Build rows whose API the consumer projects do
// not enable, SERVICE_DISABLED in both. The enabled-path Terraform harness
// renders both phases with this and derives its adversarial variants from
// them, so the harness is judged against the producer's own shape.
//
//   bun run tools/ci/protected-recovery-canary-fixture.ts <authority.json> <active-sha>[,<transition-sha>] <control|deny> <control-run-id> <run-id> <broker-image>

const [authorityPath, shas, phase, controlRunId, runId, brokerImage] = Bun.argv.slice(2);
if (!authorityPath || !shas || !phase || !controlRunId || !runId || !brokerImage) {
  throw new Error("Usage: protected-recovery-canary-fixture.ts <authority.json> <active-sha>[,<transition-sha>] <control|deny> <control-run-id> <run-id> <broker-image>");
}
if (phase !== "control" && phase !== "deny") throw new Error(`unknown phase ${phase}`);
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
const roleId = `denyCanary${suffix}`;
const canary = denyCanaryPrincipal(authority);
const ledgerDatabase = authority.broker.firestoreDatabase;
const evidenceBucket = `${brokerProject}-protected-recovery-evidence`;
const endpoints = {
  cloudbuild: "https://cloudbuild.googleapis.com/v1",
  compute: "https://compute.googleapis.com/compute/v1",
  credentials: "https://iamcredentials.googleapis.com/v1",
  crm: "https://cloudresourcemanager.googleapis.com/v3",
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

interface Request {
  readonly method: string;
  readonly url: string;
}

// The request the producer makes for one permission at one attachment scope.
function request(scope: "broker" | "consumer" | "organization", project: string, permission: string): Request {
  const email = `${throwaway}@${project}.iam.gserviceaccount.com`;
  const sa = `projects/-/serviceAccounts/${email}`;
  const pool = `projects/${project}/locations/global/workloadIdentityPools/${throwaway}`;
  const provider = `${pool}/providers/${throwaway}`;
  const parent = `projects/${project}/locations/${region}`;
  const service = `${parent}/services/${throwaway}`;
  const documents = `projects/${project}/databases/${ledgerDatabase}/documents`;
  const object = `canary%2F${suffix}`;
  const role = `organizations/${organizationId}/roles/${roleId}`;
  const uniqueId = `1${project.length.toString().padStart(2, "0")}${suffix.padStart(18, "0")}`.slice(0, 21);
  const requests: Readonly<Record<string, Request>> = {
    "artifactregistry.googleapis.com/repositories.uploadArtifacts": { method: "POST", url: `${endpoints.registry}/upload/v1/${parent}/repositories/${throwaway}/genericArtifacts:create?uploadType=multipart` },
    "cloudbuild.googleapis.com/builds.create": { method: "POST", url: `${endpoints.cloudbuild}/projects/${project}/locations/global/builds` },
    "cloudresourcemanager.googleapis.com/projects.setIamPolicy": { method: "POST", url: `${endpoints.crm}/projects/${project}:setIamPolicy` },
    "compute.googleapis.com/instanceTemplates.create": { method: "POST", url: `${endpoints.compute}/projects/${project}/global/instanceTemplates` },
    "compute.googleapis.com/instances.create": { method: "POST", url: `${endpoints.compute}/projects/${project}/zones/${zone}/instances` },
    "compute.googleapis.com/instances.setServiceAccount": { method: "POST", url: `${endpoints.compute}/projects/${project}/zones/${zone}/instances/${throwaway}/setServiceAccount` },
    "datastore.googleapis.com/entities.create": { method: "POST", url: `${endpoints.firestore}/${documents}:commit` },
    "datastore.googleapis.com/entities.delete": { method: "POST", url: `${endpoints.firestore}/${documents}:commit` },
    "datastore.googleapis.com/entities.get": { method: "GET", url: `${endpoints.firestore}/${documents}/canary/${suffix}` },
    "datastore.googleapis.com/entities.list": { method: "GET", url: `${endpoints.firestore}/${documents}/canary?pageSize=1` },
    "datastore.googleapis.com/entities.update": { method: "POST", url: `${endpoints.firestore}/${documents}:commit` },
    "iam.googleapis.com/roles.create": { method: "POST", url: `${endpoints.iam}/organizations/${organizationId}/roles` },
    "iam.googleapis.com/roles.delete": { method: "DELETE", url: `${endpoints.iam}/${role}` },
    "iam.googleapis.com/roles.undelete": { method: "POST", url: `${endpoints.iam}/${role}:undelete` },
    "iam.googleapis.com/roles.update": { method: "PATCH", url: `${endpoints.iam}/${role}?updateMask=description` },
    "iam.googleapis.com/serviceAccountKeys.create": { method: "POST", url: `${endpoints.iam}/${sa}/keys` },
    "iam.googleapis.com/serviceAccounts.actAs": { method: "POST", url: `${endpoints.scheduler}/${parent}/jobs` },
    "iam.googleapis.com/serviceAccounts.create": { method: "POST", url: `${endpoints.iam}/projects/${project}/serviceAccounts` },
    "iam.googleapis.com/serviceAccounts.delete": { method: "DELETE", url: `${endpoints.iam}/${sa}` },
    "iam.googleapis.com/serviceAccounts.disable": { method: "POST", url: `${endpoints.iam}/${sa}:disable` },
    "iam.googleapis.com/serviceAccounts.enable": { method: "POST", url: `${endpoints.iam}/${sa}:enable` },
    "iam.googleapis.com/serviceAccounts.getAccessToken": { method: "POST", url: `${endpoints.credentials}/${sa}:generateAccessToken` },
    "iam.googleapis.com/serviceAccounts.getOpenIdToken": { method: "POST", url: `${endpoints.credentials}/${sa}:generateIdToken` },
    "iam.googleapis.com/serviceAccounts.implicitDelegation": { method: "POST", url: `${endpoints.credentials}/${sa}:generateAccessToken` },
    "iam.googleapis.com/serviceAccounts.setIamPolicy": { method: "POST", url: `${endpoints.iam}/${sa}:setIamPolicy` },
    "iam.googleapis.com/serviceAccounts.signBlob": { method: "POST", url: `${endpoints.credentials}/${sa}:signBlob` },
    "iam.googleapis.com/serviceAccounts.signJwt": { method: "POST", url: `${endpoints.credentials}/${sa}:signJwt` },
    "iam.googleapis.com/serviceAccounts.undelete": { method: "POST", url: `${endpoints.iam}/projects/-/serviceAccounts/${uniqueId}:undelete` },
    "iam.googleapis.com/workloadIdentityPoolProviders.create": { method: "POST", url: `${endpoints.iam}/${pool}/providers?workloadIdentityPoolProviderId=${throwaway}` },
    "iam.googleapis.com/workloadIdentityPoolProviders.delete": { method: "DELETE", url: `${endpoints.iam}/${provider}` },
    "iam.googleapis.com/workloadIdentityPoolProviders.undelete": { method: "POST", url: `${endpoints.iam}/${provider}:undelete` },
    "iam.googleapis.com/workloadIdentityPoolProviders.update": { method: "PATCH", url: `${endpoints.iam}/${provider}?updateMask=description` },
    "iam.googleapis.com/workloadIdentityPools.create": { method: "POST", url: `${endpoints.iam}/projects/${project}/locations/global/workloadIdentityPools?workloadIdentityPoolId=${throwaway}` },
    "iam.googleapis.com/workloadIdentityPools.delete": { method: "DELETE", url: `${endpoints.iam}/${pool}` },
    "iam.googleapis.com/workloadIdentityPools.undelete": { method: "POST", url: `${endpoints.iam}/${pool}:undelete` },
    "iam.googleapis.com/workloadIdentityPools.update": { method: "PATCH", url: `${endpoints.iam}/${pool}?updateMask=description` },
    "orgpolicy.googleapis.com/policy.set": { method: "POST", url: `${endpoints.orgpolicy}/projects/${brokerProject}/policies` },
    "run.googleapis.com/jobs.create": { method: "POST", url: `${endpoints.run}/${parent}/jobs?jobId=${throwaway}` },
    "run.googleapis.com/jobs.update": { method: "PATCH", url: `${endpoints.run}/${parent}/jobs/${throwaway}?updateMask=labels` },
    "run.googleapis.com/services.create": { method: "POST", url: `${endpoints.run}/${parent}/services?serviceId=${throwaway}` },
    "run.googleapis.com/services.delete": { method: "DELETE", url: `${endpoints.run}/${service}` },
    "run.googleapis.com/services.setIamPolicy": { method: "POST", url: `${endpoints.run}/${service}:setIamPolicy` },
    "run.googleapis.com/services.update": { method: "PATCH", url: `${endpoints.run}/${service}?updateMask=description` },
    "run.googleapis.com/workerpools.create": { method: "POST", url: `${endpoints.run}/${parent}/workerPools?workerPoolId=${throwaway}` },
    "run.googleapis.com/workerpools.update": { method: "PATCH", url: `${endpoints.run}/${parent}/workerPools/${throwaway}?updateMask=description` },
    "serviceusage.googleapis.com/services.disable": { method: "POST", url: `${endpoints.serviceusage}/projects/${project}/services/websecurityscanner.googleapis.com:disable` },
    "storage.googleapis.com/objects.create": { method: "POST", url: `${endpoints.gcs}/upload/storage/v1/b/${evidenceBucket}/o?uploadType=media&name=${object}&ifGenerationMatch=0` },
    "storage.googleapis.com/objects.delete": { method: "DELETE", url: `${endpoints.gcs}/storage/v1/b/${evidenceBucket}/o/${object}` },
    "storage.googleapis.com/objects.update": { method: "PATCH", url: `${endpoints.gcs}/storage/v1/b/${evidenceBucket}/o/${object}` },
  };
  const found = requests[permission];
  if (!found) throw new Error(`no producer request is modelled for ${permission} (${scope})`);
  return found;
}

// The deny-policy permission in the form an IAM permission denial names it.
function rawPermission(permission: string): string {
  const [service, rest] = permission.split("/", 2) as [string, string];
  const prefix = service === "cloudresourcemanager.googleapis.com" ? "resourcemanager" : service.replace(/\.googleapis\.com$/, "");
  return `${prefix}.${rest}`;
}

function response(scope: "broker" | "consumer" | "organization", permission: string): Record<string, string> {
  const api = unserviceable[permission];
  if (scope === "consumer" && api !== undefined) {
    return { message: `${api} has not been used in project before or it is disabled.`, permission: "", rawPermission: "", reason: "SERVICE_DISABLED", service: api, status: "403" };
  }
  if (phase === "control") return { message: "", permission: "", rawPermission: "", reason: "", service: "", status: "200" };
  const raw = rawPermission(permission);
  return { message: `Permission '${raw}' denied on resource (or it may not exist).`, permission, rawPermission: raw, reason: "IAM_PERMISSION_DENIED", service: "", status: "403" };
}

function outcome(scope: "broker" | "consumer" | "organization", permission: string): string {
  if (scope === "consumer" && unserviceable[permission] !== undefined) return "UNSERVICEABLE";
  return phase === "control" ? "ALLOWED" : "DENIED";
}

const matrix = denyMatrix(authority, { platformShas }, steadyFlags);
const scopes = new Map<string, { readonly project: string; readonly scope: "broker" | "consumer" | "organization" }>([
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
      canary: rule.permissions.map((permission) => ({
        observedAt,
        outcome: outcome(scope.scope, permission),
        permission,
        principal: canary,
        request: request(scope.scope, scope.project, permission),
        response: response(scope.scope, permission),
      })),
      denialCondition: null,
      deniedPermissions: [...rule.permissions],
      deniedPrincipals: ["principalSet://goog/public:all"],
      exceptionPermissions: [],
      exceptionPrincipals: phase === "control" ? [...new Set([...rule.exceptions, canary])].sort() : [...rule.exceptions],
    })),
  };
});

console.log(JSON.stringify({
  schema: "protected-recovery/deny-canary/v2",
  phase,
  controlRunId,
  brokerImage,
  organization: `organizations/${organizationId}`,
  run: { attempt: 1, event: "workflow_dispatch", headSha: active, id: Number(runId), repositoryId: authority.platformRepositoryId, workflow: ".github/workflows/protected-recovery-deny-canary.yml" },
  throwaways: { name: throwaway, role: roleId },
  policies,
  unexercised: [],
  failures: [],
}, null, 2));
