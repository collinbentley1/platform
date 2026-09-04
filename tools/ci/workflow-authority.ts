import { lstat, readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

// The one inventory of federated authority: one entry per job that requests
// id-token: write in a platform reusable workflow. Terraform reads the same
// file through jsondecode(file(...)) and binds each service account only to
// the exact job-level tuple -- consumer caller workflow_ref, reusable
// job_workflow_ref and job_workflow_sha, literal environment, event_name --
// of the entries that name it, so a job that is not declared here can mint
// nothing. The consumer identity (owner/repository) is the Terraform module
// instance's own; the caller facts recorded here are the ones every consumer
// shares through its byte-identical rendered caller template.
export const manifestPath = "terraform/modules/bootstrap/workflow-authority.json";
export const workflowDirectory = ".github/workflows";
const callerTemplateDirectory = "templates/app";
const platformRepository = "collinbentley1/platform";

// Reserved delimiter of the attribute.authority composite. Git refuses ':' in
// ref names and GitHub refuses it in owner and repository names, so no
// caller-controlled workflow_ref or job_workflow_ref can carry one, and the
// manifest is refused if any of its values does.
export const authorityDelimiter = ":";

export const purposes = ["attestation", "gcp"] as const;
type Purpose = (typeof purposes)[number];

const serviceAccountIds = [
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

interface AuthorityCaller {
  readonly events: readonly string[];
  readonly ref: string;
  readonly workflow: string;
}

export interface WorkflowAuthorityEntry {
  readonly callers: readonly AuthorityCaller[];
  readonly environment: string;
  readonly job: string;
  readonly purpose: Purpose;
  readonly serviceAccounts: readonly string[];
  readonly transitionEligible: boolean;
  readonly workflow: string;
}

interface WorkflowAuthorityCheck {
  readonly entries: readonly WorkflowAuthorityEntry[];
  readonly failures: readonly string[];
  readonly workflows: readonly string[];
}

const entryKeys = ["callers", "environment", "job", "purpose", "serviceAccounts", "transitionEligible", "workflow"];
const callerKeys = ["events", "ref", "workflow"];
const workflowFile = /^[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$/;
const workflowPath = /^\.github\/workflows\/[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$/;
const jobId = /^[A-Za-z_][A-Za-z0-9_-]*$/;
const environmentName = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const branchRef = /^refs\/heads\/[A-Za-z0-9][A-Za-z0-9._/-]*$/;
// push and pull_request_target run on the selected branch (pull_request_target
// on the base branch), schedule runs on the default branch, and a
// workflow_dispatch on any other branch yields a workflow_ref no binding names.
const branchEvents = ["pull_request_target", "push"];
const federatedEvents = [...branchEvents, "schedule", "workflow_dispatch"];
const outputReference = /^\$\{\{ steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+) \}\}$/;
const accountAssignment = /^echo "[A-Za-z0-9_]+=(gha-[a-z-]+)@\$\{project_id\}\.iam\.gserviceaccount\.com"$/;
const authAction = "google-github-actions/auth@";
const attestAction = "actions/attest@";

export function parseWorkflowAuthority(text: string): WorkflowAuthorityCheck {
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch (error) {
    return { entries: [], failures: [`${manifestPath}: ${String(error)}`], workflows: [] };
  }
  const failures = [...strings(document)]
    .filter((value) => value.includes(authorityDelimiter))
    .map((value) => `${manifestPath}: ${JSON.stringify(value)} contains the reserved delimiter ${JSON.stringify(authorityDelimiter)}.`);
  if (!Array.isArray(document) || document.length === 0) {
    return { entries: [], failures: [...failures, `${manifestPath}: must be a non-empty array of id-token job entries.`], workflows: [] };
  }
  const entries: WorkflowAuthorityEntry[] = [];
  document.forEach((value, index) => {
    const label = `${manifestPath}[${index}]`;
    const entry = parseEntry(value, label, failures);
    if (!entry) return;
    const previous = entries.at(-1);
    if (previous && `${previous.workflow} ${previous.job}` >= `${entry.workflow} ${entry.job}`) {
      failures.push(`${label}: entries must be unique and sorted by workflow, then job.`);
    }
    if (entries.some((other) => other.workflow === entry.workflow && other.environment === entry.environment)) {
      failures.push(`${label}: ${entry.workflow} job ${entry.job} shares environment ${entry.environment} with another id-token job, so their authority tuples would collide.`);
    }
    entries.push(entry);
  });
  return { entries, failures, workflows: [] };
}

function parseEntry(value: unknown, label: string, failures: string[]): WorkflowAuthorityEntry | undefined {
  const fail = (message: string): undefined => {
    failures.push(`${label}: ${message}.`);
    return undefined;
  };
  if (!isRecord(value)) return fail("must be an object");
  if (Object.keys(value).sort().join(",") !== entryKeys.join(",")) return fail(`keys must be exactly ${entryKeys.join(", ")}`);
  const { callers, environment, job, purpose, serviceAccounts, transitionEligible, workflow } = value;
  if (typeof workflow !== "string" || !workflowPath.test(workflow)) return fail("workflow must name a platform .github/workflows/*.yml or *.yaml file");
  if (typeof job !== "string" || !jobId.test(job)) return fail("job must be a GitHub job identifier");
  if (typeof environment !== "string" || !environmentName.test(environment)) return fail("environment must be one literal environment name");
  if (!isPurpose(purpose)) return fail(`purpose must be one of ${purposes.join(", ")}`);
  const accounts = stringList(serviceAccounts, (id) => (serviceAccountIds as readonly string[]).includes(id));
  if (!accounts) return fail("serviceAccounts must be a sorted, unique list of known service account IDs");
  if ((purpose === "gcp") !== accounts.length > 0) return fail("serviceAccounts must be non-empty exactly when purpose is gcp");
  if (typeof transitionEligible !== "boolean") return fail("transitionEligible must be a boolean");
  if (transitionEligible && purpose !== "gcp") return fail("transitionEligible requires purpose gcp");
  if (!Array.isArray(callers) || callers.length === 0) return fail("callers must be a non-empty list");
  const parsedCallers: AuthorityCaller[] = [];
  for (const caller of callers) {
    if (!isRecord(caller) || Object.keys(caller).sort().join(",") !== callerKeys.join(",")) {
      return fail(`each caller must have exactly the keys ${callerKeys.join(", ")}`);
    }
    const events = stringList(caller.events, (event) => federatedEvents.includes(event));
    if (typeof caller.workflow !== "string" || !workflowPath.test(caller.workflow)) return fail("caller workflow must name a consumer .github/workflows/*.yml or *.yaml file");
    if (typeof caller.ref !== "string" || !branchRef.test(caller.ref)) return fail("caller ref must be a refs/heads/ branch reference");
    if (!events || events.length === 0) return fail(`caller events must be a sorted, unique, non-empty list drawn from ${federatedEvents.join(", ")}`);
    const previous = parsedCallers.at(-1);
    if (previous && previous.workflow >= caller.workflow) return fail("callers must be unique and sorted by workflow");
    parsedCallers.push({ events, ref: caller.ref, workflow: caller.workflow });
  }
  return { callers: parsedCallers, environment, job, purpose, serviceAccounts: accounts, transitionEligible, workflow };
}

// Every id-token job on disk must be declared, every declaration must be such
// a job, each job must exchange for exactly the accounts its entry binds (or
// none, for attestation), and each declared caller must be a real trigger of
// the consumer caller template. Fails closed in every direction.
export async function checkWorkflowAuthority(root: string): Promise<WorkflowAuthorityCheck> {
  const manifestFile = join(root, manifestPath);
  const manifestStat = await lstat(manifestFile).catch(() => undefined);
  if (!manifestStat?.isFile()) return { entries: [], failures: [`${manifestPath}: must be a regular file.`], workflows: [] };
  const manifest = parseWorkflowAuthority(await readFile(manifestFile, "utf8"));
  const failures = [...manifest.failures];
  const workflows = await listWorkflows(root, failures);
  const covered = new Set<WorkflowAuthorityEntry>();
  for (const file of workflows) {
    const path = `${workflowDirectory}/${file}`;
    const document = await parseWorkflow(root, path, failures);
    if (!document) continue;
    const jobs = isRecord(document.jobs) ? document.jobs : {};
    for (const [id, job] of Object.entries(jobs)) {
      if (!isRecord(job)) {
        failures.push(`${path}: job ${id} must be a mapping.`);
        continue;
      }
      if (job.permissions === undefined && document.permissions === undefined) {
        failures.push(`${path}: job ${id} declares no permissions and the workflow declares none.`);
      }
      const permissions = job.permissions ?? document.permissions;
      if (!mintsIdToken(permissions)) continue;
      const entry = manifest.entries.find((candidate) => candidate.workflow === path && candidate.job === id);
      if (!entry) {
        failures.push(`${path}: job ${id} requests id-token: write but ${manifestPath} declares no authority for it.`);
        continue;
      }
      covered.add(entry);
      checkJob(entry, job, permissions, failures);
    }
  }
  for (const entry of manifest.entries) {
    if (!covered.has(entry)) failures.push(`${entry.workflow}: job ${entry.job} is declared in ${manifestPath} but is not an id-token: write job on disk.`);
    for (const caller of entry.callers) await checkCaller(root, entry, caller, failures);
  }
  return { entries: manifest.entries, failures, workflows };
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

async function parseWorkflow(root: string, path: string, failures: string[]): Promise<Record<string, unknown> | undefined> {
  const stat = await lstat(join(root, path)).catch(() => undefined);
  if (!stat?.isFile()) {
    failures.push(`${path}: must be a regular file.`);
    return undefined;
  }
  let document: unknown;
  try {
    document = Bun.YAML.parse(await readFile(join(root, path), "utf8"));
  } catch (error) {
    failures.push(`${path}: ${String(error)}`);
    return undefined;
  }
  if (isRecord(document)) return document;
  failures.push(`${path}: workflow must be a YAML mapping.`);
  return undefined;
}

function checkJob(entry: WorkflowAuthorityEntry, job: Record<string, unknown>, permissions: unknown, failures: string[]): void {
  const where = `${entry.workflow}: job ${entry.job}`;
  if (permissions === "write-all") failures.push(`${where} must declare an explicit permissions mapping, not write-all.`);
  const environment = literalEnvironment(job.environment);
  if (environment === undefined) failures.push(`${where} environment must be one literal environment name.`);
  else if (environment !== entry.environment) failures.push(`${where} environment ${environment} does not match the manifest environment ${entry.environment}.`);
  const steps: readonly unknown[] = Array.isArray(job.steps) ? job.steps : [];
  const minted = new Set<string>();
  let attests = false;
  steps.forEach((step, index) => {
    const uses = isRecord(step) ? step.uses : undefined;
    if (uses === undefined) return;
    if (typeof uses !== "string" || !isPinned(uses)) {
      failures.push(`${where} step ${index} uses ${JSON.stringify(uses)}, which is not pinned to a full 40-hex commit SHA or sha256 image digest.`);
    }
    if (typeof uses !== "string") return;
    if (uses.startsWith(attestAction)) attests = true;
    if (!uses.startsWith(authAction)) return;
    const account = resolvedServiceAccount(isRecord(step) && isRecord(step.with) ? step.with.service_account : undefined, steps);
    if (account === undefined) failures.push(`${where} step ${index} service_account must resolve to one known gha-* account through a same-job step output.`);
    else minted.add(account);
  });
  const exchanged = [...minted].sort();
  if (entry.purpose === "attestation") {
    if (!attests) failures.push(`${where} is declared attestation but never runs actions/attest.`);
    if (exchanged.length > 0) failures.push(`${where} is declared attestation but exchanges for [${exchanged.join(", ")}].`);
  } else if (!sameList(exchanged, entry.serviceAccounts)) {
    failures.push(`${where} exchanges for [${exchanged.join(", ")}] but the manifest binds [${entry.serviceAccounts.join(", ")}].`);
  }
}

// Caller facts are checked against the consumer caller template, which every
// consumer must mirror byte-for-byte once the platform SHA is rendered.
async function checkCaller(root: string, entry: WorkflowAuthorityEntry, caller: AuthorityCaller, failures: string[]): Promise<void> {
  const path = `${callerTemplateDirectory}/${caller.workflow}`;
  const document = await parseWorkflow(root, path, failures);
  if (!document) return;
  const triggers = isRecord(document.on) ? document.on : {};
  const events = Object.keys(triggers).sort();
  if (!sameList(events, caller.events)) {
    failures.push(`${path}: triggers [${events.join(", ")}] do not match the manifest caller events [${caller.events.join(", ")}] of ${entry.workflow} job ${entry.job}.`);
  }
  const branch = caller.ref.slice("refs/heads/".length);
  for (const event of caller.events.filter((candidate) => branchEvents.includes(candidate))) {
    const trigger = triggers[event];
    const branches = isRecord(trigger) ? trigger.branches : undefined;
    if (!Array.isArray(branches) || branches.length !== 1 || branches[0] !== branch) {
      failures.push(`${path}: ${event} must select only the ${branch} branch named by the manifest caller ref ${caller.ref}.`);
    }
  }
  const jobs = isRecord(document.jobs) ? Object.values(document.jobs) : [];
  const calls = jobs.filter((job) => isRecord(job) && job.uses === `${platformRepository}/${entry.workflow}@__PLATFORM_SHA__` && mintsIdToken(job.permissions ?? document.permissions));
  if (calls.length !== 1) {
    failures.push(`${path}: exactly one job must call ${platformRepository}/${entry.workflow}@__PLATFORM_SHA__ with id-token: write; found ${calls.length}.`);
  }
}

function resolvedServiceAccount(value: unknown, steps: readonly unknown[]): string | undefined {
  const reference = typeof value === "string" ? outputReference.exec(value) : null;
  if (!reference) return undefined;
  const producer = steps.find((step) => isRecord(step) && step.id === reference[1]);
  if (!isRecord(producer) || typeof producer.run !== "string") return undefined;
  const assignments = producer.run
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith(`echo "${reference[2]}=`));
  const account = assignments.length === 1 ? accountAssignment.exec(assignments[0]!)?.[1] : undefined;
  return account !== undefined && (serviceAccountIds as readonly string[]).includes(account) ? account : undefined;
}

function mintsIdToken(permissions: unknown): boolean {
  return permissions === "write-all" || (isRecord(permissions) && permissions["id-token"] === "write");
}

function literalEnvironment(environment: unknown): string | undefined {
  const name = isRecord(environment) ? environment.name : environment;
  return typeof name === "string" && environmentName.test(name) ? name : undefined;
}

function isPinned(uses: string): boolean {
  return uses.startsWith("docker://")
    ? /^docker:\/\/[^@\s]+@sha256:[0-9a-f]{64}$/.test(uses)
    : /^[^@\s]+@[0-9a-f]{40}$/.test(uses);
}

function* strings(value: unknown): Generator<string> {
  if (typeof value === "string") yield value;
  if (typeof value !== "object" || value === null) return;
  for (const [key, item] of Object.entries(value)) {
    if (!Array.isArray(value)) yield key;
    yield* strings(item);
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

function isPurpose(value: unknown): value is Purpose {
  return (purposes as readonly unknown[]).includes(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
