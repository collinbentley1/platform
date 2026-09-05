import { lstat, readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

// The one inventory of federated authority: one entry per job that requests
// id-token: write in a platform workflow, classified by trust domain. A
// consumer-domain entry is a job of a platform reusable workflow; Terraform
// reads the same file through jsondecode(file(...)) and binds each consumer
// service account only to the exact job-level tuple -- consumer caller
// workflow_ref, reusable job_workflow_ref and job_workflow_sha, literal
// environment, event_name -- of the entries that name it, so a job that is not
// declared here can mint nothing. The consumer identity (owner/repository) is
// the Terraform module instance's own; the caller facts recorded here are the
// ones every consumer shares through its byte-identical rendered caller
// template. A recovery-domain entry is a platform-local workflow_dispatch job
// declared directly (not a reusable-workflow call), so its token carries the
// direct-job claims workflow_ref and workflow_sha; GitHub documents
// job_workflow_ref and job_workflow_sha only for jobs that call a reusable
// workflow. The protected-recovery module binds that job, through the broker
// project's own pool and its own workflow_ref:workflow_sha:environment:event
// composite, to exactly one purpose-level invoker for one consumer and one
// effect direction.
export const manifestPath = "terraform/modules/bootstrap/workflow-authority.json";
export const workflowDirectory = ".github/workflows";
const callerTemplateDirectory = "templates/app";
const platformRepository = "collinbentley1/platform";

// Reserved delimiter of the attribute.authority composite. Git refuses ':' in
// ref names and GitHub refuses it in owner and repository names, so no
// caller-controlled workflow_ref or job_workflow_ref can carry one, and the
// manifest is refused if any of its values does.
export const authorityDelimiter = ":";

export const purposes = ["attestation", "deny-canary", "gcp", "recovery"] as const;
type Purpose = (typeof purposes)[number];
export const trustDomains = ["consumer", "recovery"] as const;
type TrustDomain = (typeof trustDomains)[number];
export const recoveryIntents = ["QUARANTINE", "RESTORE"] as const;
export type RecoveryIntent = (typeof recoveryIntents)[number];
// Every recovery invoker is named by its consumer and its one effect direction,
// so the manifest cannot bind one invoker to two consumers, two invokers to one
// direction, or both directions to one credential. Google limits a service
// account ID to 30 characters, which "gha-quarantine-critical-history" exceeds,
// so the QUARANTINE direction is named "isolate".
const recoveryInvokerPrefixes: Readonly<Record<RecoveryIntent, string>> = { QUARANTINE: "gha-isolate-", RESTORE: "gha-restore-" };

export function recoveryInvokerName(consumer: string, intent: RecoveryIntent): string {
  return `${recoveryInvokerPrefixes[intent]}${consumer}`;
}

// The member-delivery identity of one consumer in the broker project: the
// only account the consumer's canonical jobs may impersonate there, holding
// run.invoker on the broker alone, through which each job delivers its own
// credential (protected-recovery/deliver-member.sh).
export function memberDeliveryName(consumer: string): string {
  return `gha-member-${consumer}`;
}

// The Deny canary of the broker deployment: one direct workflow_dispatch job
// of the platform repository that exercises the broker's required Deny matrix
// and attests what it observed; its one identity holds no standing authority
// from this module.
export const denyCanaryServiceAccount = "gha-deny-canary";

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

interface AuthorityEntryBase {
  readonly callers: readonly AuthorityCaller[];
  readonly environment: string;
  readonly job: string;
  readonly serviceAccounts: readonly string[];
  readonly transitionEligible: boolean;
  readonly workflow: string;
}

export interface ConsumerAuthorityEntry extends AuthorityEntryBase {
  readonly purpose: "attestation" | "gcp";
  readonly trustDomain: "consumer";
}

export interface RecoveryAuthorityEntry extends AuthorityEntryBase {
  readonly consumer: string;
  readonly intent: RecoveryIntent;
  readonly purpose: "recovery";
  readonly trustDomain: "recovery";
}

// The one Deny canary job: a direct workflow_dispatch job of the platform
// repository that exchanges only for the canary identity and attests its
// observations (actions/attest), so the protected-recovery module can verify
// the attestation's signer against exactly this job.
export interface DenyCanaryAuthorityEntry extends AuthorityEntryBase {
  readonly purpose: "deny-canary";
  readonly trustDomain: "recovery";
}

export type WorkflowAuthorityEntry = ConsumerAuthorityEntry | RecoveryAuthorityEntry | DenyCanaryAuthorityEntry;

interface WorkflowAuthorityCheck {
  readonly entries: readonly WorkflowAuthorityEntry[];
  readonly failures: readonly string[];
  readonly workflows: readonly string[];
}

const consumerEntryKeys = ["callers", "environment", "job", "purpose", "serviceAccounts", "transitionEligible", "trustDomain", "workflow"];
const recoveryEntryKeys = ["callers", "consumer", "environment", "intent", "job", "purpose", "serviceAccounts", "transitionEligible", "trustDomain", "workflow"];
const callerKeys = ["events", "ref", "workflow"];
const workflowFile = /^[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$/;
const workflowPath = /^\.github\/workflows\/[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$/;
const jobId = /^[A-Za-z_][A-Za-z0-9_-]*$/;
const environmentName = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const repositoryName = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
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
const maxServiceAccountId = 30;

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
    if (entry.purpose === "recovery" && entries.some((other) => other.purpose === "recovery" && other.consumer === entry.consumer && other.intent === entry.intent)) {
      failures.push(`${label}: consumer ${entry.consumer} already has a ${entry.intent} invoker.`);
    }
    if (entry.purpose === "deny-canary" && entries.some((other) => other.purpose === "deny-canary")) {
      failures.push(`${label}: only one Deny canary job may be declared.`);
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
  const trustDomain = value.trustDomain;
  if (!isTrustDomain(trustDomain)) return fail(`trustDomain must be one of ${trustDomains.join(", ")}`);
  const entryKeys = trustDomain === "consumer" || value.purpose === "deny-canary" ? consumerEntryKeys : recoveryEntryKeys;
  if (Object.keys(value).sort().join(",") !== entryKeys.join(",")) return fail(`keys must be exactly ${entryKeys.join(", ")}`);
  const { callers, environment, job, purpose, serviceAccounts, transitionEligible, workflow } = value;
  if (typeof workflow !== "string" || !workflowPath.test(workflow)) return fail("workflow must name a platform .github/workflows/*.yml or *.yaml file");
  if (typeof job !== "string" || !jobId.test(job)) return fail("job must be a GitHub job identifier");
  if (typeof environment !== "string" || !environmentName.test(environment)) return fail("environment must be one literal environment name");
  if (!isPurpose(purpose)) return fail(`purpose must be one of ${purposes.join(", ")}`);
  if ((purpose === "recovery" || purpose === "deny-canary") !== (trustDomain === "recovery")) return fail("purposes recovery and deny-canary are exactly the recovery trust domain");
  if (typeof transitionEligible !== "boolean") return fail("transitionEligible must be a boolean");
  if (transitionEligible && purpose === "attestation") return fail("transitionEligible requires purpose gcp or recovery");
  if (transitionEligible && purpose === "deny-canary") return fail("the Deny canary runs only at the active platform commit");
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
  const base = { callers: parsedCallers, environment, job, transitionEligible, workflow };
  if (trustDomain === "consumer" && (purpose === "attestation" || purpose === "gcp")) {
    const accounts = stringList(serviceAccounts, (id) => (serviceAccountIds as readonly string[]).includes(id));
    if (!accounts) return fail("serviceAccounts must be a sorted, unique list of known service account IDs");
    if ((purpose === "gcp") !== accounts.length > 0) return fail("serviceAccounts must be non-empty exactly when purpose is gcp");
    return { ...base, purpose, serviceAccounts: accounts, trustDomain };
  }
  if (trustDomain !== "recovery") return fail("consumer entries have purpose attestation or gcp");
  if (purpose === "deny-canary") {
    const accounts = stringList(serviceAccounts, (id) => id === denyCanaryServiceAccount);
    if (!accounts || accounts.length !== 1) return fail(`serviceAccounts must be exactly the Deny canary identity ${denyCanaryServiceAccount}`);
    if (parsedCallers.length !== 1 || parsedCallers[0]!.workflow !== workflow) return fail("callers must name exactly this workflow, because the Deny canary is its own caller");
    return { ...base, purpose, serviceAccounts: accounts, trustDomain };
  }
  // A recovery job is a direct workflow_dispatch job and therefore its own
  // caller: its token's workflow_ref names this platform workflow and its
  // workflow_sha is the dispatched platform commit, so no consumer template and
  // no reusable-workflow claim is involved. One entry binds one direction.
  const { consumer, intent } = value;
  if (typeof consumer !== "string" || !repositoryName.test(consumer)) return fail("consumer must be one consumer repository name");
  if (!isRecoveryIntent(intent)) return fail(`intent must be one of ${recoveryIntents.join(", ")}`);
  const invoker = recoveryInvokerName(consumer, intent);
  const accounts = stringList(serviceAccounts, (id) => id === invoker);
  if (!accounts || accounts.length !== 1 || invoker.length > maxServiceAccountId) return fail(`serviceAccounts must be exactly the purpose-level invoker ${invoker}`);
  if (parsedCallers.length !== 1 || parsedCallers[0]!.workflow !== workflow) return fail("callers must name exactly this workflow, because a recovery job is its own caller");
  return { ...base, consumer, intent, purpose: "recovery", serviceAccounts: accounts, trustDomain: "recovery" };
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
  const allowedAccounts = entry.trustDomain === "recovery" ? entry.serviceAccounts : serviceAccountIds;
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
    const account = resolvedServiceAccount(isRecord(step) && isRecord(step.with) ? step.with.service_account : undefined, steps, allowedAccounts);
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
  if (entry.purpose === "deny-canary" && !attests) failures.push(`${where} is declared deny-canary but never runs actions/attest.`);
  if (entry.purpose !== "attestation" && entry.purpose !== "deny-canary" && attests) failures.push(`${where} runs actions/attest but is not declared attestation or deny-canary.`);
}

// Consumer caller facts are checked against the consumer caller template,
// which every consumer must mirror byte-for-byte once the platform SHA is
// rendered. A recovery job is its own caller, so its triggers are checked on
// the platform workflow itself and no reusable call is expected.
async function checkCaller(root: string, entry: WorkflowAuthorityEntry, caller: AuthorityCaller, failures: string[]): Promise<void> {
  const path = entry.trustDomain === "recovery" ? caller.workflow : `${callerTemplateDirectory}/${caller.workflow}`;
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
  if (entry.trustDomain === "recovery") return;
  const jobs = isRecord(document.jobs) ? Object.values(document.jobs) : [];
  const calls = jobs.filter((job) => isRecord(job) && job.uses === `${platformRepository}/${entry.workflow}@__PLATFORM_SHA__` && mintsIdToken(job.permissions ?? document.permissions));
  if (calls.length !== 1) {
    failures.push(`${path}: exactly one job must call ${platformRepository}/${entry.workflow}@__PLATFORM_SHA__ with id-token: write; found ${calls.length}.`);
  }
}

function resolvedServiceAccount(value: unknown, steps: readonly unknown[], allowed: readonly string[]): string | undefined {
  const reference = typeof value === "string" ? outputReference.exec(value) : null;
  if (!reference) return undefined;
  const producer = steps.find((step) => isRecord(step) && step.id === reference[1]);
  if (!isRecord(producer) || typeof producer.run !== "string") return undefined;
  const assignments = producer.run
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith(`echo "${reference[2]}=`));
  const account = assignments.length === 1 ? accountAssignment.exec(assignments[0]!)?.[1] : undefined;
  return account !== undefined && allowed.includes(account) ? account : undefined;
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

function isTrustDomain(value: unknown): value is TrustDomain {
  return (trustDomains as readonly unknown[]).includes(value);
}

function isRecoveryIntent(value: unknown): value is RecoveryIntent {
  return (recoveryIntents as readonly unknown[]).includes(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
