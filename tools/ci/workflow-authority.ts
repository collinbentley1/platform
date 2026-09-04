import { lstat, readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

// The one inventory of GitHub workflow authority. Terraform reads the same file
// through jsondecode(file(...)) to derive every Workload Identity User binding,
// so a workflow that is not declared here can mint nothing.
export const manifestPath = "terraform/modules/bootstrap/workflow-authority.json";
export const workflowDirectory = ".github/workflows";
export const platformRepository = "collinbentley1/platform";
export const githubOwnerId = "16823277";
export const workloadIdentityPoolId = "github-actions";
export const ownerSecretName = "OWNER_OAUTH_ACCESS_TOKEN";
export const workloadIdentityUserRole = "roles/iam.workloadIdentityUser";

export const authorities = ["cloud", "none", "owner-secret"] as const;
export type Authority = (typeof authorities)[number];

export const serviceAccountIds = [
  "gha-deploy-parity",
  "gha-preview-commit",
  "gha-preview-deploy",
  "gha-preview-operator",
  "gha-preview-publish",
  "gha-prod-deploy",
  "gha-prod-publish",
  "gha-terraform",
  "gha-wif-canary",
] as const;

export interface WorkflowAuthorityEntry {
  readonly authority: Authority;
  readonly environments: readonly string[];
  readonly events: readonly string[];
  readonly path: string;
  readonly serviceAccounts: readonly string[];
  readonly transitionEligible: boolean;
}

export interface WorkflowAuthorityCheck {
  readonly entries: readonly WorkflowAuthorityEntry[];
  readonly failures: readonly string[];
}

export interface WorkloadIdentityBinding {
  readonly account: string;
  readonly member: string;
  readonly path: string;
  readonly sha: string;
}

export const providerAttributeMapping: Readonly<Record<string, string>> = {
  "attribute.job_workflow_ref": "assertion.job_workflow_ref",
  "attribute.repository_id": "assertion.repository_id",
  "google.subject": "assertion.repository_owner_id + ':' + assertion.repository_id + ':' + assertion.run_id",
};

export function providerAttributeCondition(repositoryId: string): string {
  return `assertion.repository_owner_id == '${githubOwnerId}' && assertion.repository_id == '${repositoryId}'`;
}

export const commitSha = /^[0-9a-f]{40}$/;
const entryKeys = ["authority", "environments", "events", "path", "serviceAccounts", "transitionEligible"];
const workflowFile = /^[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$/;
const name = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const triggerEvent = /^[a-z_]+(?::[A-Za-z0-9./_*-]+(?:,[A-Za-z0-9./_*-]+)*)?$/;

export function parseWorkflowAuthority(text: string): WorkflowAuthorityCheck {
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch (error) {
    return { entries: [], failures: [`${manifestPath}: ${String(error)}`] };
  }
  if (!Array.isArray(document) || document.length === 0) {
    return { entries: [], failures: [`${manifestPath}: must be a non-empty array of workflow entries.`] };
  }
  const entries: WorkflowAuthorityEntry[] = [];
  const failures: string[] = [];
  const seen = new Set<string>();
  document.forEach((value, index) => {
    const label = `${manifestPath}[${index}]`;
    const entry = parseEntry(value, label, failures);
    if (!entry) return;
    if (seen.has(entry.path)) failures.push(`${label}: duplicate path ${entry.path}.`);
    seen.add(entry.path);
    entries.push(entry);
  });
  return { entries, failures };
}

function parseEntry(value: unknown, label: string, failures: string[]): WorkflowAuthorityEntry | undefined {
  const fail = (message: string): undefined => {
    failures.push(`${label}: ${message}.`);
    return undefined;
  };
  if (!isRecord(value)) return fail("must be an object");
  const keys = Object.keys(value).sort();
  if (keys.join(",") !== entryKeys.join(",")) {
    return fail(`keys must be exactly ${entryKeys.join(", ")}; found ${keys.join(", ") || "none"}`);
  }
  const { authority, environments, events, path, serviceAccounts, transitionEligible } = value;
  if (typeof path !== "string" || !path.startsWith(`${workflowDirectory}/`) || !workflowFile.test(path.slice(workflowDirectory.length + 1))) {
    return fail(`path must name a ${workflowDirectory}/*.yml or *.yaml file`);
  }
  if (!isAuthority(authority)) return fail(`authority must be one of ${authorities.join(", ")}`);
  const accounts = stringList(serviceAccounts, (id) => (serviceAccountIds as readonly string[]).includes(id));
  if (!accounts) return fail("serviceAccounts must be a sorted, unique list of known service account IDs");
  if ((authority === "cloud") !== accounts.length > 0) {
    return fail("serviceAccounts must be non-empty exactly when authority is cloud");
  }
  const environmentList = stringList(environments, (environment) => name.test(environment));
  if (!environmentList) return fail("environments must be a sorted, unique list of environment names");
  const eventList = stringList(events, (event) => triggerEvent.test(event));
  if (!eventList || eventList.length === 0) return fail("events must be a sorted, unique, non-empty list of trigger events");
  if (typeof transitionEligible !== "boolean") return fail("transitionEligible must be a boolean");
  if (transitionEligible && authority !== "cloud") return fail("transitionEligible requires authority cloud");
  return { authority, environments: environmentList, events: eventList, path, serviceAccounts: accounts, transitionEligible };
}

// Enumerates the manifest against every workflow on disk, then checks each
// workflow's own declarations against its manifest entry. Fails closed in both
// directions: an undeclared file and a declared-but-absent file are findings.
export async function checkWorkflowAuthority(root: string): Promise<WorkflowAuthorityCheck> {
  const manifestFile = join(root, manifestPath);
  const manifestStat = await lstat(manifestFile).catch(() => undefined);
  if (!manifestStat?.isFile()) return { entries: [], failures: [`${manifestPath}: must be a regular file.`] };
  const manifest = parseWorkflowAuthority(await readFile(manifestFile, "utf8"));
  const failures = [...manifest.failures];
  const names = await listWorkflows(root, failures);
  const declared = new Set(manifest.entries.map((entry) => entry.path));
  for (const file of names) {
    if (!declared.has(`${workflowDirectory}/${file}`)) failures.push(`${workflowDirectory}/${file}: not declared in ${manifestPath}.`);
  }
  for (const entry of manifest.entries) {
    if (!names.includes(entry.path.slice(workflowDirectory.length + 1))) {
      failures.push(`${entry.path}: declared in ${manifestPath} but is not a regular workflow file on disk.`);
      continue;
    }
    let document: unknown;
    try {
      document = Bun.YAML.parse(await readFile(join(root, entry.path), "utf8"));
    } catch (error) {
      failures.push(`${entry.path}: ${String(error)}`);
      continue;
    }
    checkWorkflow(entry, document, failures);
  }
  return { entries: manifest.entries, failures };
}

async function listWorkflows(root: string, failures: string[]): Promise<string[]> {
  const directory = join(root, workflowDirectory);
  const directoryStat = await lstat(directory).catch(() => undefined);
  if (!directoryStat?.isDirectory()) {
    failures.push(`${workflowDirectory}: must be a real directory.`);
    return [];
  }
  const names: string[] = [];
  for (const file of (await readdir(directory)).sort()) {
    const stat = await lstat(join(directory, file));
    if (!stat.isFile()) {
      failures.push(`${workflowDirectory}/${file}: must be a regular file, not a symbolic link or directory.`);
    } else if (!workflowFile.test(file)) {
      failures.push(`${workflowDirectory}/${file}: only .yml and .yaml workflow files are allowed here.`);
    } else {
      names.push(file);
    }
  }
  return names;
}

function checkWorkflow(entry: WorkflowAuthorityEntry, document: unknown, failures: string[]): void {
  const { path } = entry;
  if (!isRecord(document)) {
    failures.push(`${path}: workflow must be a YAML mapping.`);
    return;
  }
  const events = triggerEvents(document.on);
  if (!events) {
    failures.push(`${path}: on must be an event name, a list of event names, or a mapping of events.`);
  } else if (!sameList(events, entry.events)) {
    failures.push(`${path}: triggers [${events.join(", ")}] do not match the manifest events [${entry.events.join(", ")}].`);
  }
  const jobs = document.jobs;
  if (!isRecord(jobs) || Object.keys(jobs).length === 0) {
    failures.push(`${path}: jobs must be a non-empty mapping.`);
    return;
  }
  const environments = new Set<string>();
  let idTokenWrite = grantsIdTokenWrite(document.permissions);
  for (const [jobName, job] of Object.entries(jobs)) {
    if (!isRecord(job)) {
      failures.push(`${path}: job ${jobName} must be a mapping.`);
      continue;
    }
    if (job.permissions === undefined && document.permissions === undefined) {
      failures.push(`${path}: job ${jobName} declares no permissions and the workflow declares none.`);
    }
    if (grantsIdTokenWrite(job.permissions)) idTokenWrite = true;
    const environment = environmentName(job.environment);
    if (environment === null) failures.push(`${path}: job ${jobName} environment must be a name or a mapping with a name.`);
    else if (environment !== undefined) environments.add(environment);
    const steps = Array.isArray(job.steps) ? job.steps : [];
    for (const [where, uses] of [[`job ${jobName}`, job.uses], ...steps.map((step, index) => [`job ${jobName} step ${index}`, isRecord(step) ? step.uses : undefined])]) {
      if (uses === undefined) continue;
      if (typeof uses !== "string" || !isPinned(uses)) {
        failures.push(`${path}: ${where} uses ${JSON.stringify(uses)}, which is not pinned to a full 40-hex commit SHA or sha256 image digest.`);
      }
    }
  }
  if (!sameList([...environments].sort(), entry.environments)) {
    failures.push(`${path}: environments [${[...environments].sort().join(", ")}] do not match the manifest [${entry.environments.join(", ")}].`);
  }
  if (idTokenWrite !== (entry.authority === "cloud")) {
    failures.push(`${path}: id-token: write must appear exactly in workflows the manifest marks cloud; this one is ${entry.authority}.`);
  }
  const text = [...scalars(document)];
  const referencesOwnerSecret = text.some((scalar) => scalar.includes(ownerSecretName));
  if (referencesOwnerSecret !== (entry.authority === "owner-secret")) {
    failures.push(`${path}: ${ownerSecretName} must be referenced exactly by workflows the manifest marks owner-secret; this one is ${entry.authority}.`);
  }
  const mentioned = new Set(text.flatMap((scalar) => scalar.match(/gha-[a-z-]+(?=@)/g) ?? []));
  for (const account of entry.serviceAccounts) {
    if (!mentioned.has(account)) failures.push(`${path}: the manifest grants ${account}, which the workflow never names.`);
  }
}

export function expectedWorkloadIdentityBindings(
  entries: readonly WorkflowAuthorityEntry[],
  activeSha: string,
  transitionSha: string | null,
  projectNumber: string,
): Map<string, WorkloadIdentityBinding> {
  if (!commitSha.test(activeSha)) throw new Error(`active SHA ${activeSha} is not a full lowercase commit SHA.`);
  if (transitionSha !== null && (!commitSha.test(transitionSha) || transitionSha === activeSha)) {
    throw new Error(`transition SHA ${transitionSha} must be a distinct full lowercase commit SHA.`);
  }
  const pool = `projects/${projectNumber}/locations/global/workloadIdentityPools/${workloadIdentityPoolId}`;
  const bindings = new Map<string, WorkloadIdentityBinding>();
  for (const entry of entries) {
    if (entry.authority !== "cloud") continue;
    const shas = entry.transitionEligible && transitionSha !== null ? [activeSha, transitionSha] : [activeSha];
    for (const account of entry.serviceAccounts) {
      for (const sha of shas) {
        bindings.set(`${account}/${entry.path}@${sha}`, {
          account,
          member: `principalSet://iam.googleapis.com/${pool}/attribute.job_workflow_ref/${platformRepository}/${entry.path}@${sha}`,
          path: entry.path,
          sha,
        });
      }
    }
  }
  return bindings;
}

function triggerEvents(on: unknown): string[] | undefined {
  if (typeof on === "string") return [on];
  if (Array.isArray(on)) return on.every((event) => typeof event === "string") ? [...on].sort() : undefined;
  if (!isRecord(on)) return undefined;
  const events: string[] = [];
  for (const [event, config] of Object.entries(on)) {
    const branches = isRecord(config) ? config.branches : undefined;
    if (branches === undefined) events.push(event);
    else if (Array.isArray(branches) && branches.every((branch) => typeof branch === "string")) events.push(`${event}:${branches.join(",")}`);
    else return undefined;
  }
  return events.sort();
}

function grantsIdTokenWrite(permissions: unknown): boolean {
  return permissions === "write-all" || (isRecord(permissions) && permissions["id-token"] === "write");
}

function environmentName(environment: unknown): string | null | undefined {
  if (environment === undefined) return undefined;
  if (typeof environment === "string" && name.test(environment)) return environment;
  if (isRecord(environment) && typeof environment.name === "string" && name.test(environment.name)) return environment.name;
  return null;
}

function isPinned(uses: string): boolean {
  return uses.startsWith("docker://")
    ? /^docker:\/\/[^@\s]+@sha256:[0-9a-f]{64}$/.test(uses)
    : /^[^@\s]+@[0-9a-f]{40}$/.test(uses);
}

function* scalars(value: unknown, seen = new Set<object>()): Generator<string> {
  if (typeof value === "string") {
    yield value;
    return;
  }
  if (value === null || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  for (const [key, item] of Object.entries(value)) {
    if (!Array.isArray(value)) yield key;
    yield* scalars(item, seen);
  }
}

function stringList(value: unknown, valid: (item: string) => boolean): string[] | undefined {
  if (!Array.isArray(value) || !value.every((item): item is string => typeof item === "string" && valid(item))) return undefined;
  const sorted = [...value].sort();
  return new Set(value).size === value.length && sameList(value, sorted) ? sorted : undefined;
}

function sameList(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

function isAuthority(value: unknown): value is Authority {
  return (authorities as readonly unknown[]).includes(value);
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
