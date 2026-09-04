// Which workflows can actually reach a credential, derived rather than listed.
//
// Two authorities matter and they are not the same thing. A workflow may read
// the owner's Google OAuth token, or it may mint Google credentials for itself
// through Workload Identity Federation. Everything else holds only the
// per-run GITHUB_TOKEN, which can move branches and open pull requests but
// cannot touch cloud state.
//
// Each authority is derived from a workflow's source as its own flag, never as
// a single label, so a workflow that holds both is refused outright rather
// than recorded under whichever flag happened to be evaluated first. The
// derived flags are compared with the one hand-maintained declaration and
// cross-checked against the effective Terraform trust condition, so a workflow
// cannot acquire either authority by being added somewhere the reviewer forgot
// to look. A file that appears in neither the derived set nor the declared set
// is a failure, not a skip -- that is the drift this exists to catch. So is a
// file that cannot be read or parsed: authority that cannot be read cannot be
// bounded.

import { lstat, readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  type SecretContextReference,
  semanticSecretContextReferences,
} from "./workflow-secret-contract";

export type WorkflowAuthority =
  | "owner-credential"
  | "cloud-authority"
  | "owner-credential+cloud-authority"
  | "neither";

export interface DeclaredAuthorityInventory {
  readonly cloudAuthority: readonly string[];
  readonly neither: readonly string[];
  readonly ownerCredential: readonly string[];
}

// The one hand-maintained list. Changing it is the deliberate act that lets a
// workflow gain authority; the checks below refuse any drift from it.
export const declaredWorkflowAuthority: DeclaredAuthorityInventory = {
  cloudAuthority: [
    "cleanup-preview.yml",
    "deploy-preview.yml",
    "deploy-prod.yml",
    "infrastructure.yml",
    "reconcile-previews.yml",
  ],
  neither: [
    "application.yml",
    "bun-dependency-update.yml",
    "platform.yml",
    "refresh-grype-db.yml",
    "socket-firewall.yml",
  ],
  ownerCredential: ["protected-bootstrap-implementation.yml"],
};

export const ownerTokenSecretName = "OWNER_OAUTH_ACCESS_TOKEN";
export const ownerTokenEnvironment = "protected-bootstrap-owner-token";

// Secret names a workflow may name literally. Anything else reaching the
// secrets context -- including dynamic indexing -- is treated as capable of
// reading the owner token, because it cannot be shown otherwise. GitHub
// resolves context property names case-insensitively, so comparisons are made
// on the upper-cased spelling: `secrets.owner_oauth_access_token` is the owner
// token too.
const literalSecretAllowlist = new Set([
  "CONSUMER_ACTIONS_READ_TOKEN",
  "DHI_PUBLIC_READ_TOKEN_20260822_098DCA9280B3",
  ownerTokenSecretName,
]);

// Signals that a step is exchanging an OIDC token for Google credentials.
// Presence without `id-token: write` is itself inconsistent and fails.
const googleCredentialSignals = [
  "sts.googleapis.com",
  "iamcredentials.googleapis.com",
  "ACTIONS_ID_TOKEN_REQUEST_",
  "create_credentials_file",
  "gcloud auth login",
  "gcloud auth activate-service-account",
  "gcloud auth print-access-token",
];

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function sorted(values: Iterable<string>): string[] {
  return [...values].sort();
}

function describeList(values: Iterable<string>): string {
  const list = sorted(values);
  return list.length === 0 ? "(none)" : list.join(", ");
}

// ---------------------------------------------------------------------------
// The file universe
//
// One helper decides what counts as a workflow and what counts as Terraform
// source, and both the lint wiring and the contract go through it. The lint
// used to filter on `.endsWith(".yml")`, which let a `.yaml` workflow run on
// GitHub without ever being classified here.
// ---------------------------------------------------------------------------

// A rejected universe still carries every entry that did resolve. The lint
// used to skip the authority check whenever a universe was rejected, so one
// stray file in .github/workflows hid every finding about its neighbours: the
// run still failed, but for the stray file alone, and the findings were gone.
export type FileUniverse =
  | { readonly kind: "resolved"; readonly sources: ReadonlyMap<string, string> }
  | {
    readonly kind: "rejected";
    readonly failures: readonly string[];
    readonly sources: ReadonlyMap<string, string>;
  };

const workflowDirectory = ".github/workflows";
const workflowFileName = /\.ya?ml$/;
const terraformFileName = /\.tf$/;
const jsonTerraformFileName = /\.tf\.json$/;

// Directories the Terraform walk never enters: version-control internals,
// installed packages, and the provider binaries and fetched module copies
// that `terraform init` writes. The last is ignored by git, so its contents
// depend on what ran on this machine rather than on what was reviewed.
const unscannedDirectories = new Set([".git", ".terraform", "node_modules"]);

type EntryShape =
  | "regular file"
  | "symbolic link"
  | "directory"
  | "FIFO"
  | "socket"
  | "device"
  | "entry of unknown type";

// `lstat`, never `stat`: the question is what the entry itself is, not what a
// link happens to point at today.
async function entryShape(path: string): Promise<EntryShape> {
  const stats = await lstat(path);
  if (stats.isSymbolicLink()) return "symbolic link";
  if (stats.isFile()) return "regular file";
  if (stats.isDirectory()) return "directory";
  if (stats.isFIFO()) return "FIFO";
  if (stats.isSocket()) return "socket";
  if (stats.isBlockDevice() || stats.isCharacterDevice()) return "device";
  return "entry of unknown type";
}

async function entryNames(path: string, display: string, failures: string[]): Promise<string[]> {
  try {
    return (await readdir(path)).sort();
  } catch (error) {
    failures.push(`${display} could not be listed: ${errorMessage(error)}.`);
    return [];
  }
}

// A file that cannot be read is a failure naming the file, never an uncaught
// error: the run must say which authority it could not bound.
async function readSource(path: string, display: string, failures: string[]): Promise<string | undefined> {
  try {
    return await readFile(path, "utf8");
  } catch (error) {
    failures.push(`${display} could not be read: ${errorMessage(error)}.`);
    return undefined;
  }
}

// Every workflow GitHub would run: each entry of .github/workflows named *.yml
// or *.yaml. Anything else in the directory is refused with a message rather
// than skipped, because an entry the inventory did not read is authority it
// did not bound. That includes symbolic links -- the file a link resolves to
// is not the file that was reviewed -- and every other non-regular entry.
export async function workflowUniverse(root: string): Promise<FileUniverse> {
  const failures: string[] = [];
  const sources = new Map<string, string>();
  const directory = join(root, workflowDirectory);
  for (const name of await entryNames(directory, workflowDirectory, failures)) {
    const display = `${workflowDirectory}/${name}`;
    const shape = await entryShape(join(directory, name));
    if (shape !== "regular file") {
      failures.push(
        `${display} is a ${shape}; the workflow directory may hold only regular *.yml or *.yaml files.`,
      );
      continue;
    }
    if (!workflowFileName.test(name)) {
      failures.push(
        `${display} is not a workflow (*.yml or *.yaml); the workflow directory may hold nothing else.`,
      );
      continue;
    }
    const source = await readSource(join(directory, name), display, failures);
    if (source !== undefined) sources.set(name, source);
  }
  return failures.length > 0 ? { failures, kind: "rejected", sources } : { kind: "resolved", sources };
}

// Every Terraform source in the repository, keyed by its repository-relative
// path. The walk starts at the root rather than at terraform/ because
// Terraform reads whatever directory it is pointed at: a provider block in
// infra/wif.tf grants credentials exactly as one under terraform/ does, and a
// scan rooted in one directory never saw it. Symbolic links and other
// non-regular entries are refused as above; `*.tf.json` is refused because it
// is configuration this scan cannot read, and a provider block hidden in JSON
// would otherwise escape the cross-check.
export async function terraformUniverse(root: string): Promise<FileUniverse> {
  const failures: string[] = [];
  const sources = new Map<string, string>();
  await collectTerraform(root, "", failures, sources);
  return failures.length > 0 ? { failures, kind: "rejected", sources } : { kind: "resolved", sources };
}

async function collectTerraform(
  root: string,
  directory: string,
  failures: string[],
  sources: Map<string, string>,
): Promise<void> {
  const listing = directory === "" ? "the repository root" : directory;
  for (const name of await entryNames(join(root, directory), listing, failures)) {
    const display = directory === "" ? name : `${directory}/${name}`;
    const shape = await entryShape(join(root, display));
    if (shape === "directory") {
      if (!unscannedDirectories.has(name)) await collectTerraform(root, display, failures, sources);
      continue;
    }
    if (shape !== "regular file") {
      failures.push(`${display} is a ${shape}; Terraform sources must be regular files.`);
      continue;
    }
    if (jsonTerraformFileName.test(name)) {
      failures.push(
        `${display} is JSON Terraform configuration, which the authority scan cannot read; express it in HCL.`,
      );
      continue;
    }
    if (terraformFileName.test(name)) {
      const source = await readSource(join(root, display), display, failures);
      if (source !== undefined) sources.set(display, source);
    }
  }
}

// ---------------------------------------------------------------------------
// Workflow capabilities
// ---------------------------------------------------------------------------

export interface WorkflowCapabilities {
  readonly readsOwnerCredential: boolean;
  readonly mintsCloudCredentials: boolean;
  // GitHub-only effects -- `contents: write`, `pull-requests: write` and the
  // like. Recorded separately so a message never mistakes a branch push for
  // cloud authority, and never lets one hide the other.
  readonly writesGitHub: boolean;
  // Why each flag is set, in document-path terms. Empty when the flag is off.
  readonly ownerCredentialEvidence: readonly string[];
  readonly cloudCredentialEvidence: readonly string[];
  readonly gitHubWriteEvidence: readonly string[];
}

export type WorkflowAnalysis =
  | { readonly kind: "capabilities"; readonly capabilities: WorkflowCapabilities }
  | { readonly kind: "invalid"; readonly reasons: readonly string[] };

interface PermissionGrant {
  readonly idToken: boolean;
  readonly writes: readonly string[];
}

// The scopes a workflow may set. Anything else is refused rather than filed as
// a write: a scope this list does not know is an effect the inventory cannot
// describe. The list is the one actionlint accepts, so the two checks in this
// pipeline cannot disagree about a spelling.
const permissionScopes = new Set([
  "actions",
  "artifact-metadata",
  "attestations",
  "checks",
  "contents",
  "deployments",
  "discussions",
  "id-token",
  "issues",
  "models",
  "packages",
  "pages",
  "pull-requests",
  "repository-projects",
  "security-events",
  "statuses",
]);

// `write-all` is every scope at its highest level, and id-token has no level
// above write, so it is implied. Scope names are compared in lower case so a
// spelling such as `ID-TOKEN: write` is read as the id-token grant it may
// well be, never filed under the benign GitHub writes; every neighbouring
// shape check here fails closed on the unexpected, and this one used to be
// the exception.
function permissionGrant(
  value: unknown,
  where: string,
  reasons: string[],
): PermissionGrant | undefined {
  if (value === "write-all") return { idToken: true, writes: ["write-all"] };
  if (value === "read-all") return { idToken: false, writes: [] };
  const record = asRecord(value);
  if (record === undefined) {
    reasons.push(`${where} is not a permissions mapping, read-all or write-all`);
    return undefined;
  }
  const writes: string[] = [];
  let idToken = false;
  for (const [spelling, level] of Object.entries(record)) {
    const scope = spelling.toLowerCase();
    if (!permissionScopes.has(scope)) {
      reasons.push(`${where} grants ${JSON.stringify(spelling)}, which is not a GitHub permission scope`);
      continue;
    }
    if (level !== "read" && level !== "write" && level !== "none") {
      reasons.push(`${where} grants ${scope} an unrecognised level ${JSON.stringify(level)}`);
      continue;
    }
    if (level !== "write") continue;
    if (scope === "id-token") idToken = true;
    else writes.push(`${scope}: write`);
  }
  return { idToken, writes };
}

function usesOf(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function isGoogleAction(uses: string): boolean {
  return uses.split("@", 1)[0]?.startsWith("google-github-actions/") === true;
}

interface Scalar {
  readonly path: string;
  readonly value: string;
}

// Every scalar in the document with its path, so a signal cannot hide inside a
// run script, an env value, or a `with:` argument, and so a message can say
// where it was found.
function scalars(value: unknown, path: string, seen: Set<object>, out: Scalar[]): void {
  if (typeof value === "string") {
    out.push({ path, value });
    return;
  }
  if (typeof value !== "object" || value === null) return;
  if (seen.has(value)) return;
  seen.add(value);
  if (Array.isArray(value)) {
    value.forEach((item, index) => scalars(item, `${path}.${index}`, seen, out));
    return;
  }
  for (const [key, item] of Object.entries(value)) {
    scalars(item, path === "" ? key : `${path}.${key}`, seen, out);
  }
}

type SecretUsage =
  | { readonly kind: "literal"; readonly name: string; readonly spelling: string }
  | { readonly kind: "unbounded"; readonly detail: string };

// Splits a scalar into its `${{ ... }}` bodies with the same quote rules the
// secret scanner applies, so a `}}` inside a string literal does not end an
// expression early. An unterminated expression yields the rest of the scalar:
// GitHub would reject it, and a lint must not be more permissive than GitHub.
function expressionBodies(value: string): string[] {
  const bodies: string[] = [];
  let offset = 0;
  while (offset < value.length) {
    const start = value.indexOf("${{", offset);
    if (start < 0) break;
    let quote: "'" | '"' | undefined;
    let end = -1;
    for (let index = start + 3; index < value.length; index += 1) {
      const character = value.charAt(index);
      if (quote !== undefined) {
        if (character === quote) {
          if (quote === "'" && value.charAt(index + 1) === "'") index += 1;
          else quote = undefined;
        } else if (quote === '"' && character === "\\") {
          index += 1;
        }
        continue;
      }
      if (character === "'" || character === '"') {
        quote = character;
        continue;
      }
      if (character === "}" && value.charAt(index + 1) === "}") {
        end = index;
        break;
      }
    }
    if (end < 0) {
      bodies.push(value.slice(start + 3));
      break;
    }
    bodies.push(value.slice(start + 3, end));
    offset = end + 2;
  }
  return bodies;
}

interface QuotedLiteral {
  readonly end: number;
  readonly value: string;
}

// Reads the string literal opening at `start`. Expression syntax doubles a
// single quote to escape it; a double-quoted form is accepted with backslash
// escapes only so that it is classified rather than misread.
function quotedLiteral(body: string, start: number): QuotedLiteral | undefined {
  const quote = body.charAt(start);
  let value = "";
  for (let index = start + 1; index < body.length; index += 1) {
    const character = body.charAt(index);
    if (character === quote) {
      if (quote === "'" && body.charAt(index + 1) === "'") {
        value += "'";
        index += 1;
        continue;
      }
      return { end: index + 1, value };
    }
    if (quote === '"' && character === "\\") {
      value += body.charAt(index + 1);
      index += 1;
      continue;
    }
    value += character;
  }
  return undefined;
}

function skipSpaces(body: string, index: number): number {
  let cursor = index;
  while (cursor < body.length && /\s/.test(body.charAt(cursor))) cursor += 1;
  return cursor;
}

function previousSignificant(body: string, index: number): string {
  let cursor = index - 1;
  while (cursor >= 0 && /\s/.test(body.charAt(cursor))) cursor -= 1;
  return cursor >= 0 ? body.charAt(cursor) : "";
}

const identifierAt = /[A-Za-z_][A-Za-z0-9_-]*/y;

// Every use of the secrets context in one expression body, each either bound
// to a literal name -- `secrets.NAME`, `secrets['NAME']`, `secrets["NAME"]` --
// or unbounded. String literals are skipped so the word inside one is not
// mistaken for the context, and a use that cannot be bound is reported as
// such rather than ignored.
function secretUsages(body: string): SecretUsage[] {
  const usages: SecretUsage[] = [];
  let index = 0;
  while (index < body.length) {
    const character = body.charAt(index);
    if (character === "'" || character === '"') {
      index = quotedLiteral(body, index)?.end ?? body.length;
      continue;
    }
    identifierAt.lastIndex = index;
    const word = identifierAt.exec(body);
    if (word === null) {
      index += 1;
      continue;
    }
    const after = index + word[0].length;
    // `inputs.secrets` is a property of something else, but nothing here can
    // say what it carries, so it is reported as unbounded rather than skipped.
    if (word[0].toLowerCase() !== "secrets") {
      index = after;
      continue;
    }
    if (previousSignificant(body, index) === ".") {
      usages.push({ detail: "secrets is read as a property of another value", kind: "unbounded" });
      index = after;
      continue;
    }
    let cursor = skipSpaces(body, after);
    const next = body.charAt(cursor);
    if (next === ".") {
      cursor = skipSpaces(body, cursor + 1);
      identifierAt.lastIndex = cursor;
      const name = identifierAt.exec(body);
      if (name === null) {
        usages.push({ detail: "secrets is followed by a property access with no name", kind: "unbounded" });
        index = cursor;
        continue;
      }
      cursor += name[0].length;
      const trailing = body.charAt(skipSpaces(body, cursor));
      if (trailing === "." || trailing === "[") {
        usages.push({ detail: `secrets.${name[0]} is indexed further`, kind: "unbounded" });
      } else {
        usages.push({ kind: "literal", name: name[0], spelling: `secrets.${name[0]}` });
      }
      index = cursor;
      continue;
    }
    if (next === "[") {
      cursor = skipSpaces(body, cursor + 1);
      const quote = body.charAt(cursor);
      if (quote !== "'" && quote !== '"') {
        usages.push({ detail: "secrets is indexed by an expression, not a string literal", kind: "unbounded" });
        index = cursor;
        continue;
      }
      const literal = quotedLiteral(body, cursor);
      if (literal === undefined) {
        usages.push({ detail: "secrets is indexed by an unterminated string literal", kind: "unbounded" });
        index = body.length;
        continue;
      }
      cursor = skipSpaces(body, literal.end);
      if (body.charAt(cursor) !== "]") {
        usages.push({ detail: "secrets is indexed by more than a single string literal", kind: "unbounded" });
        index = cursor;
        continue;
      }
      cursor += 1;
      const spelling = `secrets[${quote}${literal.value}${quote}]`;
      const trailing = body.charAt(skipSpaces(body, cursor));
      if (trailing === "." || trailing === "[") {
        usages.push({ detail: `${spelling} is indexed further`, kind: "unbounded" });
      } else {
        usages.push({ kind: "literal", name: literal.value, spelling });
      }
      index = cursor;
      continue;
    }
    usages.push({ detail: "the whole secrets context is used", kind: "unbounded" });
    index = after;
  }
  return usages;
}

function ownerEvidenceFromReference(reference: SecretContextReference, evidence: string[]): void {
  // A plain key -- `secrets:` on a job or under workflow_call -- carries no
  // expression; those positions are judged structurally below.
  if (!reference.value.includes("${{")) return;
  let bounded = 0;
  for (const body of expressionBodies(reference.value)) {
    for (const usage of secretUsages(body)) {
      bounded += 1;
      if (usage.kind === "unbounded") {
        evidence.push(
          `${reference.path} references the secrets context in a form that cannot be bounded (${usage.detail})`,
        );
        continue;
      }
      const name = usage.name.toUpperCase();
      if (!literalSecretAllowlist.has(name)) {
        evidence.push(
          `${reference.path} references ${usage.spelling}, which is outside the reviewed literal allowlist`,
        );
      } else if (name === ownerTokenSecretName) {
        evidence.push(`${reference.path} references the owner token as ${usage.spelling}`);
      }
    }
  }
  // The scanner saw the secrets context here and nothing above could bind it.
  if (bounded === 0) {
    evidence.push(`${reference.path} mentions the secrets context where it cannot be bounded`);
  }
}

function environmentName(environment: unknown): string | undefined {
  if (typeof environment === "string") return environment;
  const named = asRecord(environment)?.name;
  return typeof named === "string" ? named : undefined;
}

// GitHub compares environment names case-insensitively, so the owner-token
// environment is matched the same way after trimming.
function isOwnerTokenEnvironment(name: string): boolean {
  return name.trim().toLowerCase() === ownerTokenEnvironment.toLowerCase();
}

// The two authorities as independent flags, each with its evidence, or an
// explicit account of why the workflow could not be analysed. A workflow that
// does not parse is invalid, never a classification: a lint that guesses at
// what GitHub would run is not bounding anything.
export function workflowCapabilities(source: string): WorkflowAnalysis {
  let parsed: unknown;
  let references: SecretContextReference[];
  try {
    parsed = Bun.YAML.parse(source);
    references = semanticSecretContextReferences(source);
  } catch (error) {
    return { kind: "invalid", reasons: [`does not parse as a workflow: ${errorMessage(error)}`] };
  }
  const document = asRecord(parsed);
  if (document === undefined) {
    return { kind: "invalid", reasons: ["is not a single YAML mapping"] };
  }
  const jobs = asRecord(document.jobs);
  if (jobs === undefined || Object.keys(jobs).length === 0) {
    return { kind: "invalid", reasons: ["declares no jobs, so it has nothing to classify"] };
  }

  const reasons: string[] = [];
  const owner: string[] = [];
  const cloud: string[] = [];
  const gitHubWrite: string[] = [];

  // Top-level permissions are the default for every job that declares none,
  // so an id-token grant there is authority the workflow holds even if every
  // job present today declines it.
  const topLevel = document.permissions === undefined
    ? undefined
    : permissionGrant(document.permissions, "top-level permissions", reasons);
  if (topLevel?.idToken === true) {
    cloud.push("top-level permissions grant id-token: write, the default for every job");
  }

  const workflowCall = asRecord(asRecord(document.on)?.workflow_call);
  if (workflowCall !== undefined && workflowCall.secrets !== undefined) {
    owner.push("on.workflow_call.secrets accepts whatever secrets a caller passes through");
  }

  for (const [jobName, jobValue] of Object.entries(jobs)) {
    const job = asRecord(jobValue);
    const where = `jobs.${jobName}`;
    if (job === undefined) {
      reasons.push(`${where} is not a mapping`);
      continue;
    }

    // Effective permissions: the job's own when present, otherwise the top
    // level. Absent at both levels means GitHub's repository default applies,
    // which this file cannot see, so that is refused rather than assumed.
    const effective = job.permissions === undefined
      ? topLevel
      : permissionGrant(job.permissions, `${where}.permissions`, reasons);
    if (job.permissions === undefined && document.permissions === undefined) {
      reasons.push(
        `${where} declares no permissions and neither does the top level; the token scope must be explicit`,
      );
    }
    if (effective?.idToken === true) {
      cloud.push(`${where} effective permissions grant id-token: write`);
    }
    if (effective !== undefined && effective.writes.length > 0) {
      gitHubWrite.push(`${where} effective permissions grant ${effective.writes.join(", ")}`);
    }

    // A `secrets:` passthrough hands the callee whatever the caller holds. An
    // explicit mapping is judged by its values, which the scanner sees.
    if (job.secrets !== undefined) {
      if (typeof job.secrets === "string" && job.secrets.trim().toLowerCase() === "inherit") {
        owner.push(`${where}.secrets: inherit passes every secret the caller holds`);
      } else if (asRecord(job.secrets) === undefined) {
        owner.push(`${where}.secrets is neither inherit nor a mapping and cannot be bounded`);
      }
    }

    if (job.environment !== undefined) {
      const name = environmentName(job.environment);
      if (name === undefined) {
        owner.push(`${where}.environment has no literal name and cannot be bounded`);
      } else if (name.includes("${{")) {
        owner.push(`${where}.environment is chosen at run time (${name}) and may be the owner-token environment`);
      } else if (isOwnerTokenEnvironment(name)) {
        owner.push(`${where}.environment binds ${name}, which holds the owner token`);
      }
    }

    const jobUses = usesOf(job.uses);
    if (jobUses !== undefined && isGoogleAction(jobUses)) cloud.push(`${where}.uses ${jobUses}`);
    // `steps` that is present but not a list is a job GitHub would refuse. It
    // is refused here too rather than scanned as empty: an empty scan reads
    // as "no Google action", and that is a claim, not an absence.
    if (job.steps !== undefined && !Array.isArray(job.steps)) {
      reasons.push(`${where}.steps is not a list, so its actions cannot be scanned`);
    }
    const steps = Array.isArray(job.steps) ? job.steps : [];
    steps.forEach((step, index) => {
      const uses = usesOf(asRecord(step)?.uses);
      if (uses !== undefined && isGoogleAction(uses)) cloud.push(`${where}.steps.${index}.uses ${uses}`);
    });
  }

  for (const reference of references) ownerEvidenceFromReference(reference, owner);

  const allScalars: Scalar[] = [];
  scalars(document, "", new Set<object>(), allScalars);
  for (const scalar of allScalars) {
    for (const signal of googleCredentialSignals) {
      if (scalar.value.includes(signal)) cloud.push(`${scalar.path} mentions ${signal}`);
    }
  }

  if (reasons.length > 0) return { kind: "invalid", reasons };
  return {
    capabilities: {
      cloudCredentialEvidence: cloud,
      gitHubWriteEvidence: gitHubWrite,
      mintsCloudCredentials: cloud.length > 0,
      ownerCredentialEvidence: owner,
      readsOwnerCredential: owner.length > 0,
      writesGitHub: gitHubWrite.length > 0,
    },
    kind: "capabilities",
  };
}

// A label for messages only. Every decision below reads the flags directly,
// because a label collapses the overlap that the flags exist to expose.
export function classifyWorkflowAuthority(capabilities: WorkflowCapabilities): WorkflowAuthority {
  if (capabilities.readsOwnerCredential && capabilities.mintsCloudCredentials) {
    return "owner-credential+cloud-authority";
  }
  if (capabilities.readsOwnerCredential) return "owner-credential";
  if (capabilities.mintsCloudCredentials) return "cloud-authority";
  return "neither";
}

function firstEvidence(evidence: readonly string[]): string {
  const first = evidence[0];
  if (first === undefined) return "";
  return evidence.length === 1 ? ` (${first})` : ` (${first}; ${evidence.length - 1} more)`;
}

function describeCapabilities(capabilities: WorkflowCapabilities): string {
  const yesNo = (flag: boolean, evidence: readonly string[]) =>
    flag ? `yes${firstEvidence(evidence)}` : "no";
  return (
    `reads owner credential: ${yesNo(capabilities.readsOwnerCredential, capabilities.ownerCredentialEvidence)}; ` +
    `mints cloud credentials: ${yesNo(capabilities.mintsCloudCredentials, capabilities.cloudCredentialEvidence)}; ` +
    `GitHub-only writes: ${yesNo(capabilities.writesGitHub, capabilities.gitHubWriteEvidence)}`
  );
}

// ---------------------------------------------------------------------------
// Terraform trust
//
// The provider's `attribute_condition` is the gate every federated token must
// pass, so it is the only place a workflow name counts. The text is read after
// comments are removed and only from inside provider blocks, then `local.*`
// references are followed through the locals of the same module until the
// effective condition is in hand. A decoy in a comment, a description, or an
// unrelated resource therefore proves nothing.
//
// The question asked of the effective condition is not "does it name a
// workflow" but "was every part of it read". A clause the patterns could not
// read used to contribute nothing and raise nothing, so one recognisable
// clause vouched for a condition that also admitted another repository. Now
// every mention of job_workflow_ref, every startsWith, every template
// interpolation and directive, and every reference or call outside a string
// must be one of the shapes listed below, or the provider is refused.
//
// Reading every token is still not reading the condition: `T || true` has
// no token to refuse and admits everything. So once the fragments are read,
// the condition they build is rendered into its CEL text and its boolean
// structure must bind job_workflow_ref on every path -- the two sections
// after the fragment scan.
// ---------------------------------------------------------------------------

// One rendering of a provider's condition: the CEL text Terraform would
// produce, with every conditional it passed through recorded as a choice.
export interface EffectiveCondition {
  readonly choices: readonly string[];
  readonly provider: string;
  readonly text: string;
}

export type TerraformTrust =
  | {
    readonly kind: "trusted";
    readonly conditions: readonly EffectiveCondition[];
    readonly providers: readonly string[];
    readonly workflows: ReadonlySet<string>;
  }
  | { readonly kind: "invalid"; readonly failures: readonly string[] };

const platformWorkflowPath = "collinbentley1/platform/.github/workflows/";

// The two ways a condition may bind job_workflow_ref to a workflow: the exact
// form, `== '<path>NAME.yml@' + assertion.job_workflow_sha`, and the legacy
// prefix form, `.startsWith('<path>NAME.yml@')`. Both end the literal at `@`,
// so a prefix that stops short of a file name matches neither.
const workflowTrustPattern =
  /assertion\.job_workflow_ref(?:\s*==\s*|\.startsWith\(\s*)'collinbentley1\/platform\/\.github\/workflows\/([\w.-]+\.ya?ml)@'/g;
// A presence check names no workflow and admits none.
const workflowRefPresencePattern = /\bhas\(\s*assertion\.job_workflow_ref\s*\)/g;
const workflowRefToken = /\bjob_workflow_ref\b/g;
const startsWithCall = /\bstartsWith\s*\(/g;

// One byte per source character: code, string text, or comment. Blanking
// comments and marking strings is what stops a brace inside a string from
// closing a block and a decoy inside a comment from matching anything.
const code = 0;
const text = 1;
const comment = 2;
const quote = 3;

// The opener each closing bracket pairs with.
const openerOf: Readonly<Record<string, string>> = { ")": "(", "]": "[", "}": "{" };

interface TemplateSpan {
  readonly close: number;
  readonly directive: boolean;
  readonly open: number;
}

interface HclFile {
  readonly mask: Uint8Array;
  readonly path: string;
  // Every `${ }` and `%{ }` in the file by the index of its opening sigil and
  // its closing brace, so the scan of one expression can see which template
  // sequences fall inside it.
  readonly templates: readonly TemplateSpan[];
  readonly text: string;
}

type HclFrame =
  | { readonly kind: "string" }
  | { readonly kind: "heredoc"; readonly marker: string }
  | { readonly kind: "template"; depth: number; readonly directive: boolean; readonly open: number };

const heredocMarker = /<<-?([A-Za-z_][A-Za-z0-9_-]*)[ \t]*\r?\n/y;

function lineOf(source: string, index: number): number {
  return source.slice(0, index).split("\n").length;
}

function lexHcl(
  path: string,
  source: string,
): { readonly kind: "lexed"; readonly file: HclFile } | { readonly kind: "invalid"; readonly failure: string } {
  const mask = new Uint8Array(source.length);
  const templates: TemplateSpan[] = [];
  const stack: HclFrame[] = [];
  let index = 0;
  while (index < source.length) {
    const frame = stack.at(-1);
    const character = source.charAt(index);
    const following = source.charAt(index + 1);
    if (frame === undefined || frame.kind === "template") {
      if (character === "#" || (character === "/" && following === "/")) {
        const newline = source.indexOf("\n", index);
        const stop = newline < 0 ? source.length : newline;
        mask.fill(comment, index, stop);
        index = stop;
        continue;
      }
      if (character === "/" && following === "*") {
        const close = source.indexOf("*/", index + 2);
        if (close < 0) {
          return { failure: `${path}: unterminated block comment at line ${lineOf(source, index)}.`, kind: "invalid" };
        }
        mask.fill(comment, index, close + 2);
        index = close + 2;
        continue;
      }
      if (character === '"') {
        mask[index] = quote;
        stack.push({ kind: "string" });
        index += 1;
        continue;
      }
      if (character === "<" && following === "<") {
        heredocMarker.lastIndex = index;
        const marker = heredocMarker.exec(source);
        if (marker !== null && marker[1] !== undefined) {
          mask.fill(text, index, index + marker[0].length);
          index += marker[0].length;
          stack.push({ kind: "heredoc", marker: marker[1] });
          continue;
        }
      }
      if (frame !== undefined) {
        if (character === "{") frame.depth += 1;
        else if (character === "}") {
          if (frame.depth === 0) {
            mask[index] = text;
            templates.push({ close: index, directive: frame.directive, open: frame.open });
            stack.pop();
            index += 1;
            continue;
          }
          frame.depth -= 1;
        }
      }
      index += 1;
      continue;
    }

    mask[index] = text;
    if (frame.kind === "string") {
      if (character === "\\") {
        if (index + 1 < source.length) mask[index + 1] = text;
        index += 2;
        continue;
      }
      if (character === '"') {
        mask[index] = quote;
        stack.pop();
        index += 1;
        continue;
      }
    } else if (index === 0 || source.charAt(index - 1) === "\n") {
      const newline = source.indexOf("\n", index);
      const stop = newline < 0 ? source.length : newline;
      if (source.slice(index, stop).trim() === frame.marker) {
        mask.fill(text, index, stop);
        index = stop;
        stack.pop();
        continue;
      }
    }
    // `$${` and `%%{` are the escapes for a literal `${` and `%{`.
    if ((character === "$" || character === "%") && following === character && source.charAt(index + 2) === "{") {
      mask.fill(text, index, index + 3);
      index += 3;
      continue;
    }
    if ((character === "$" || character === "%") && following === "{") {
      mask.fill(text, index, index + 2);
      stack.push({ depth: 0, directive: character === "%", kind: "template", open: index });
      index += 2;
      continue;
    }
    index += 1;
  }
  const open = stack.at(-1);
  if (open !== undefined) {
    return { failure: `${path}: unterminated ${open.kind} at end of file.`, kind: "invalid" };
  }
  const mismatch = bracketMismatch(path, source, mask);
  if (mismatch !== undefined) return { failure: mismatch, kind: "invalid" };
  return { file: { mask, path, templates, text: source }, kind: "lexed" };
}

// Every closing bracket that is code must close the bracket opened last. The
// scans below count depth over the three pairs as one, which is exact only
// once this holds; without it `(1]` read as balanced. An opener still open
// at the end of the file is left to the parse that runs into it, which names
// the block or expression it could not close.
function bracketMismatch(path: string, source: string, mask: Uint8Array): string | undefined {
  const open: Array<{ readonly bracket: string; readonly index: number }> = [];
  for (let index = 0; index < source.length; index += 1) {
    if (mask[index] !== code) continue;
    const character = source.charAt(index);
    if (character === "(" || character === "[" || character === "{") {
      open.push({ bracket: character, index });
      continue;
    }
    const opener = openerOf[character];
    if (opener === undefined) continue;
    const last = open.pop();
    if (last === undefined) {
      return `${path}: the ${character} at line ${lineOf(source, index)} closes nothing.`;
    }
    if (last.bracket !== opener) {
      return `${path}: the ${character} at line ${lineOf(source, index)} closes the ${last.bracket} opened at line ${lineOf(source, last.index)}.`;
    }
  }
  return undefined;
}

interface HclAttribute {
  readonly end: number;
  readonly line: number;
  readonly name: string;
  readonly start: number;
}

interface HclBlock {
  readonly bodyEnd: number;
  readonly bodyStart: number;
  readonly labels: readonly string[];
  readonly line: number;
  readonly type: string;
}

interface HclBody {
  readonly attributes: readonly HclAttribute[];
  readonly blocks: readonly HclBlock[];
}

function isCode(file: HclFile, index: number): boolean {
  return file.mask[index] === code;
}

function skipBlank(file: HclFile, from: number, end: number): number {
  let index = from;
  while (index < end && (file.mask[index] === comment || /\s/.test(file.text.charAt(index)))) index += 1;
  return index;
}

function skipInlineBlank(file: HclFile, from: number, end: number): number {
  let index = from;
  while (index < end && (file.mask[index] === comment || /[ \t]/.test(file.text.charAt(index)))) index += 1;
  return index;
}

// The index just past the bracket matching the one at `open`, counting only
// brackets of that pair that are code. This and every depth count after it
// rely on lexHcl having refused any closer that does not match the bracket
// opened last.
function closingBracket(file: HclFile, open: number, end: number): number | undefined {
  const opener = file.text.charAt(open);
  const closer = opener === "(" ? ")" : opener === "[" ? "]" : "}";
  let depth = 0;
  for (let index = open; index < end; index += 1) {
    if (!isCode(file, index)) continue;
    const character = file.text.charAt(index);
    if (character === opener) depth += 1;
    else if (character === closer) {
      depth -= 1;
      if (depth === 0) return index + 1;
    }
  }
  return undefined;
}

// An expression runs to the first newline that is code and outside every
// bracket. Newlines inside strings and heredocs are text, and newlines inside
// `(`, `[` or `{` continue the expression, which is how a multi-line `join(`
// stays whole.
function expressionEnd(file: HclFile, from: number, end: number): number {
  let depth = 0;
  for (let index = from; index < end; index += 1) {
    if (!isCode(file, index)) continue;
    const character = file.text.charAt(index);
    if (character === "(" || character === "[" || character === "{") depth += 1;
    else if (character === ")" || character === "]" || character === "}") depth -= 1;
    else if (character === "\n" && depth <= 0) return index;
  }
  return end;
}

function parseBody(
  file: HclFile,
  start: number,
  end: number,
): { readonly kind: "body"; readonly body: HclBody } | { readonly kind: "invalid"; readonly failure: string } {
  const attributes: HclAttribute[] = [];
  const blocks: HclBlock[] = [];
  let index = skipBlank(file, start, end);
  while (index < end) {
    const line = lineOf(file.text, index);
    identifierAt.lastIndex = index;
    const word = isCode(file, index) ? identifierAt.exec(file.text) : null;
    if (word === null) {
      return {
        failure: `${file.path}: expected an attribute or block at line ${line}, found ${JSON.stringify(file.text.charAt(index))}.`,
        kind: "invalid",
      };
    }
    const name = word[0];
    index = skipInlineBlank(file, index + name.length, end);
    if (file.text.charAt(index) === "=" && isCode(file, index)) {
      const valueStart = skipInlineBlank(file, index + 1, end);
      const valueEnd = expressionEnd(file, valueStart, end);
      attributes.push({ end: valueEnd, line, name, start: valueStart });
      index = skipBlank(file, valueEnd, end);
      continue;
    }
    const labels: string[] = [];
    while (file.text.charAt(index) === '"' && file.mask[index] === quote) {
      let close = index + 1;
      while (close < end && file.mask[close] !== quote) close += 1;
      labels.push(file.text.slice(index + 1, close));
      index = skipInlineBlank(file, close + 1, end);
    }
    if (file.text.charAt(index) !== "{" || !isCode(file, index)) {
      return {
        failure: `${file.path}: expected "=" or "{" after ${name} at line ${line}.`,
        kind: "invalid",
      };
    }
    const close = closingBracket(file, index, end);
    if (close === undefined) {
      return { failure: `${file.path}: unclosed block ${name} at line ${line}.`, kind: "invalid" };
    }
    blocks.push({ bodyEnd: close - 1, bodyStart: index + 1, labels, line, type: name });
    index = skipBlank(file, close, end);
  }
  return { body: { attributes, blocks }, kind: "body" };
}

// The expression with its comments blanked, so a trailing `# ...` on the same
// line cannot contribute a workflow name.
function visibleText(file: HclFile, start: number, end: number): string {
  let out = "";
  for (let index = start; index < end; index += 1) {
    out += file.mask[index] === comment ? " " : file.text.charAt(index);
  }
  return out;
}

const localReference = /\blocal\.([A-Za-z_][A-Za-z0-9_-]*)/g;

// The expression with everything but code blanked: the HCL around the
// strings, for scans that must not mistake prose for a reference.
function codeText(file: HclFile, start: number, end: number): string {
  let out = "";
  for (let index = start; index < end; index += 1) {
    out += isCode(file, index) ? file.text.charAt(index) : " ";
  }
  return out;
}

// `local.NAME` counts only where it is code: bare in the expression or inside
// a `${ }` interpolation. The same text inside plain string content is prose
// that Terraform would never evaluate.
function localReferences(file: HclFile, start: number, end: number): string[] {
  const names: string[] = [];
  for (const match of codeText(file, start, end).matchAll(localReference)) {
    if (match[1] !== undefined) names.push(match[1]);
  }
  return names;
}

interface LocalDefinition {
  readonly attribute: HclAttribute;
  readonly file: HclFile;
}

// ---------------------------------------------------------------------------
// Bounded holes
//
// A value that reaches the condition from outside the module cannot be read
// here, so it is admitted only where its shape proves it cannot carry a
// clause. A variable whose validation pins it to an anchored alphanumeric
// regex cannot hold the quote that would end a CEL string literal early, so
// `'${var.NAME}'` -- the interpolation as the whole of one literal -- can be
// compared but never evaluated. That is the one hole the scan accepts. It is
// accepted on the strength of the same validation block Terraform enforces at
// plan time, read as a top-level conjunct of the condition so that a `||` or
// a negation elsewhere in the formula cannot loosen it.
// ---------------------------------------------------------------------------

// A pinned collection is also `nonempty` when a validation conjunct requires
// at least one element, which is what spares a `for` over it the rendering
// in which it contributes nothing at all.
type VariablePin =
  | { readonly kind: "pinned"; readonly nonempty: boolean; readonly pattern: string }
  | { readonly kind: "unpinned"; readonly reason: string };

// The regex grammar the scan can vouch for: anchored at both ends and built
// from literal alphanumerics and same-case ranges inside classes, each with
// an optional `*`, `+` or `{n,m}` count. Anything richer -- a dot, an escape,
// an alternation, a negated class -- may admit a quote and is not a pin.
const pinnedPattern =
  /^\^(?:(?:\[(?:[0-9]-[0-9]|[a-z]-[a-z]|[A-Z]-[A-Z]|[A-Za-z0-9])+\]|[A-Za-z0-9])(?:[*+]|\{[0-9]+(?:,[0-9]*)?\})?)+\$$/;
// `can(regex("^...$", var.NAME))` pins a string; `alltrue([for X in var.NAME :
// can(regex("^...$", X))])` pins every element of a collection.
const directPin = /^can\(\s*regex\(\s*"([^"]*)"\s*,\s*var\.([A-Za-z_][A-Za-z0-9_-]*)\s*\)\s*\)$/;
const elementPin =
  /^alltrue\(\s*\[\s*for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+var\.([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*can\(\s*regex\(\s*"([^"]*)"\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\)\s*\]\s*\)$/;
// `length(var.NAME) > 0` as a conjunct of the same validation proves the
// collection is never empty.
const nonemptyPin = /^length\(\s*var\.([A-Za-z_][A-Za-z0-9_-]*)\s*\)\s*(?:>\s*0|>=\s*1)$/;

interface ParsedFile {
  readonly body: HclBody;
  readonly file: HclFile;
}

// [from, to) with leading and trailing blank and comment characters removed.
function trimmedRange(file: HclFile, start: number, end: number): [number, number] {
  const from = skipBlank(file, start, end);
  let to = end;
  while (to > from && (file.mask[to - 1] === comment || /\s/.test(file.text.charAt(to - 1)))) to -= 1;
  return [from, to];
}

// The top-level `&&` terms of an expression with enclosing parentheses
// unwrapped, so that a pin can be required to be a conjunct of the whole
// condition rather than a fragment of some looser formula.
function conjuncts(file: HclFile, start: number, end: number, out: Array<[number, number]>): void {
  const [from, to] = trimmedRange(file, start, end);
  if (from >= to) return;
  if (file.text.charAt(from) === "(" && isCode(file, from) && closingBracket(file, from, to) === to) {
    conjuncts(file, from + 1, to - 1, out);
    return;
  }
  const parts: Array<[number, number]> = [];
  let depth = 0;
  let partStart = from;
  for (let index = from; index < to; index += 1) {
    if (!isCode(file, index)) continue;
    const character = file.text.charAt(index);
    if (character === "(" || character === "[" || character === "{") depth += 1;
    else if (character === ")" || character === "]" || character === "}") depth -= 1;
    else if (depth === 0 && character === "&" && file.text.charAt(index + 1) === "&" && isCode(file, index + 1)) {
      parts.push([partStart, index]);
      partStart = index + 2;
      index += 1;
    }
  }
  if (parts.length === 0) {
    out.push([from, to]);
    return;
  }
  parts.push([partStart, to]);
  for (const [partFrom, partTo] of parts) conjuncts(file, partFrom, partTo, out);
}

function variablePin(file: HclFile, block: HclBlock, name: string): VariablePin {
  const inner = parseBody(file, block.bodyStart, block.bodyEnd);
  if (inner.kind === "invalid") {
    return { kind: "unpinned", reason: `var.${name} could not be read (${inner.failure})` };
  }
  let pattern: string | undefined;
  let nonempty = false;
  for (const validation of inner.body.blocks) {
    if (validation.type !== "validation") continue;
    const rules = parseBody(file, validation.bodyStart, validation.bodyEnd);
    if (rules.kind === "invalid") {
      return { kind: "unpinned", reason: `var.${name} could not be read (${rules.failure})` };
    }
    const condition = rules.body.attributes.find((attribute) => attribute.name === "condition");
    if (condition === undefined) continue;
    const terms: Array<[number, number]> = [];
    conjuncts(file, condition.start, condition.end, terms);
    for (const [from, to] of terms) {
      const term = visibleText(file, from, to).trim();
      const direct = directPin.exec(term);
      const element = elementPin.exec(term);
      const candidate = direct !== null && direct[2] === name
        ? direct[1]
        : element !== null && element[2] === name && element[1] === element[4]
        ? element[3]
        : undefined;
      if (pattern === undefined && candidate !== undefined && pinnedPattern.test(candidate)) pattern = candidate;
      if (nonemptyPin.exec(term)?.[1] === name) nonempty = true;
    }
  }
  if (pattern !== undefined) return { kind: "pinned", nonempty, pattern };
  return {
    kind: "unpinned",
    reason: `var.${name} has no validation that pins it to an anchored alphanumeric regex`,
  };
}

// The pins declared by the `variable` blocks of one module.
function variablePins(files: readonly ParsedFile[], directory: string): Map<string, VariablePin> {
  const pins = new Map<string, VariablePin>();
  for (const { body, file } of files) {
    for (const block of body.blocks) {
      if (block.type !== "variable") continue;
      const name = block.labels[0];
      if (name === undefined) continue;
      pins.set(
        name,
        pins.has(name)
          ? { kind: "unpinned", reason: `var.${name} is declared more than once in ${directory}` }
          : variablePin(file, block, name),
      );
    }
  }
  return pins;
}

// ---------------------------------------------------------------------------
// Reading one fragment of the effective condition
// ---------------------------------------------------------------------------

interface ConditionFragment {
  readonly attribute: HclAttribute;
  readonly file: HclFile;
  readonly label: string;
}

interface FragmentScan {
  readonly names: readonly string[];
  readonly residue: readonly string[];
}

// Functions that reshape or count a list without touching the text of any
// element. Anything else -- replace, format, substr, regex_replace -- can
// change the condition after it was read, and is refused.
const readableCalls = new Set([
  "compact",
  "concat",
  "distinct",
  "flatten",
  "join",
  "length",
  "sort",
  "tolist",
  "toset",
]);
const dottedReference = /\b[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)+/g;
const callSite = /\b([A-Za-z_][A-Za-z0-9_]*)\s*\(/g;
const forHeader = /\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+([^:]*?)\s*:/g;
// A collection can be read when it is one variable inside list-shaping calls.
const readableCollection =
  /^(?:(?:sort|tolist|toset|distinct|compact|flatten)\(\s*)*var\.([A-Za-z_][A-Za-z0-9_-]*)(?:\s*\))*$/;
const localHole = /^local\.[A-Za-z_][A-Za-z0-9_-]*$/;
const variableHole = /^var\.([A-Za-z_][A-Za-z0-9_-]*)$/;
const iteratorHole = /^[A-Za-z_][A-Za-z0-9_]*$/;
const templateSigil = /[$%]\{/g;

// Where a message points: the provider's own attribute, or the local that was
// followed to reach the text, with its file and line.
function fragmentWhere(fragment: ConditionFragment): string {
  return `${fragment.label} (${fragment.file.path} line ${fragment.attribute.line})`;
}

// The text around `index` on one line, for a message that has to show what
// the scan could not read.
function excerpt(text: string, index: number): string {
  const from = Math.max(0, index - 30);
  const to = Math.min(text.length, index + 60);
  const shown = text.slice(from, to).replace(/\s+/g, " ").trim();
  return JSON.stringify(`${from > 0 ? "..." : ""}${shown}${to < text.length ? "..." : ""}`);
}

// Why an interpolation other than `${local.NAME}` cannot be admitted, or
// undefined when it is a pinned value spliced as the whole of one literal.
function holeProblem(
  body: string,
  visible: string,
  open: number,
  close: number,
  pins: ReadonlyMap<string, VariablePin>,
  iterators: ReadonlyMap<string, VariablePin>,
): string | undefined {
  const variable = variableHole.exec(body)?.[1];
  let pin: VariablePin;
  if (variable !== undefined) {
    pin = pins.get(variable) ?? { kind: "unpinned", reason: `var.${variable} is not declared in this module` };
  } else if (iteratorHole.test(body)) {
    pin = iterators.get(body) ?? { kind: "unpinned", reason: `${body} is not bound by a for expression in this value` };
  } else {
    return "only local.* references, var.* values and for iterators are followed";
  }
  if (visible.charAt(open - 1) !== "'" || visible.charAt(close + 1) !== "'") {
    return "a value from outside the module is admitted only as the whole of a single-quoted CEL literal, where it can be compared but not evaluated";
  }
  return pin.kind === "pinned" ? undefined : pin.reason;
}

function scanFragment(fragment: ConditionFragment, pins: ReadonlyMap<string, VariablePin>): FragmentScan {
  const { attribute, file } = fragment;
  const visible = visibleText(file, attribute.start, attribute.end);
  const code = codeText(file, attribute.start, attribute.end);
  const where = fragmentWhere(fragment);
  const names: string[] = [];
  const residue: string[] = [];
  // Ranges of the fragment already accounted for; a token inside one is not
  // reported again.
  const consumed: Array<[number, number]> = [];
  const isConsumed = (index: number) => consumed.some(([from, to]) => index >= from && index < to);

  for (const match of visible.matchAll(workflowTrustPattern)) {
    if (match[1] !== undefined) names.push(match[1]);
    consumed.push([match.index, match.index + match[0].length]);
  }
  for (const match of visible.matchAll(workflowRefPresencePattern)) {
    consumed.push([match.index, match.index + match[0].length]);
  }

  // A `for` binds an iterator whose elements come from a variable; the
  // iterator inherits that variable's pin, or the reason it has none.
  const iterators = new Map<string, VariablePin>();
  for (const match of code.matchAll(forHeader)) {
    const iterator = match[1];
    const collection = (match[2] ?? "").trim();
    if (iterator === undefined) continue;
    consumed.push([match.index, match.index + match[0].length]);
    const source = readableCollection.exec(collection)?.[1];
    if (source === undefined) {
      residue.push(
        `${where} iterates over ${JSON.stringify(collection)}, which is not one variable inside list-shaping calls; its elements cannot be read.`,
      );
      iterators.set(iterator, { kind: "unpinned", reason: `${iterator} iterates over a collection the inventory cannot read` });
      continue;
    }
    const pin = pins.get(source) ?? { kind: "unpinned", reason: `var.${source} is not declared in this module` };
    iterators.set(
      iterator,
      pin.kind === "pinned" ? pin : { kind: "unpinned", reason: `${iterator} iterates over var.${source}, and ${pin.reason}` },
    );
  }

  for (const template of file.templates) {
    if (template.open < attribute.start || template.open >= attribute.end) continue;
    const open = template.open - attribute.start;
    const close = template.close - attribute.start;
    consumed.push([open, close + 1]);
    if (template.directive) {
      residue.push(
        `${where} contains the template directive ${excerpt(visible, open)}; Terraform expands it at plan time, so the condition it produces cannot be read here.`,
      );
      continue;
    }
    const body = visible.slice(open + 2, close).trim();
    if (localHole.test(body)) continue;
    const problem = holeProblem(body, visible, open, close, pins, iterators);
    if (problem !== undefined) {
      residue.push(`${where} interpolates \${${body}} where it cannot be bounded: ${problem}.`);
    }
  }
  // `$${` and `%%{` leave a literal sigil in the text, which CEL cannot parse.
  for (const match of visible.matchAll(templateSigil)) {
    if (isConsumed(match.index)) continue;
    residue.push(
      `${where} contains the escaped template sequence ${excerpt(visible, match.index)}, which is not a condition CEL can read.`,
    );
  }

  for (const match of visible.matchAll(workflowRefToken)) {
    if (isConsumed(match.index)) continue;
    residue.push(
      `${where} uses job_workflow_ref in a form the inventory does not read (${excerpt(visible, match.index)}); ` +
        `a workflow is trusted only through == '${platformWorkflowPath}NAME.yml@' + assertion.job_workflow_sha, ` +
        `the legacy startsWith of the same path, or has(assertion.job_workflow_ref).`,
    );
  }
  for (const match of visible.matchAll(startsWithCall)) {
    if (isConsumed(match.index)) continue;
    residue.push(
      `${where} calls startsWith outside the legacy trust form (${excerpt(visible, match.index)}); ` +
        `a prefix that is not a full ${platformWorkflowPath}NAME.yml@ path can admit another workflow or another repository.`,
    );
  }

  for (const match of code.matchAll(dottedReference)) {
    if (isConsumed(match.index)) continue;
    const reference = match[0];
    const [head, name, ...rest] = reference.split(".");
    if (head === "local") continue;
    if (head === "var" && name !== undefined && rest.length === 0) {
      // A variable that only chooses a branch or is only counted contributes
      // no text, and both branches of a choice are followed regardless.
      const before = code.slice(0, match.index);
      const after = code.slice(match.index + reference.length);
      if ((/\blength\(\s*$/.test(before) && /^\s*\)/.test(after)) || /^\s*\?/.test(after)) continue;
      residue.push(
        `${where} uses ${reference} where its value could reach the condition text (${excerpt(visible, match.index)}); ` +
          `a variable may only choose a branch (var.NAME ? a : b), be counted (length(var.NAME)), ` +
          `feed a for over a pinned collection, or be spliced as '\${var.NAME}' when pinned.`,
      );
      continue;
    }
    residue.push(`${where} references ${reference}, which the inventory cannot follow; only local.* values are read.`);
  }
  for (const match of code.matchAll(callSite)) {
    if (isConsumed(match.index)) continue;
    const called = match[1];
    if (called === undefined || readableCalls.has(called)) continue;
    residue.push(
      `${where} calls ${called}(...), which can change the condition after it was read; only ${describeList(readableCalls)} are followed.`,
    );
  }
  for (const iterator of iterators.keys()) {
    for (const match of code.matchAll(new RegExp(`\\b${iterator}\\b`, "g"))) {
      if (isConsumed(match.index)) continue;
      residue.push(
        `${where} uses the iterator ${iterator} outside a single-quoted CEL literal (${excerpt(visible, match.index)}); an element may be compared but not evaluated.`,
      );
    }
  }
  return { names, residue };
}

// ---------------------------------------------------------------------------
// The effective condition as text
//
// The fragment scan above reads every piece of the condition for a token it
// cannot account for. It does not say how the pieces fit together, and a
// clause that mentions nothing it refuses -- `|| true`, `|| assertion.
// repository == 'x'` -- fits beside a reviewed clause into a condition that
// admits every token the issuer signs. So the HCL that builds the condition
// is rendered into the CEL text Terraform would produce, and that text is
// read for its boolean structure in the section after this one.
//
// Only the shapes the bootstrap module uses are rendered: a string template
// or heredoc, join(SEPARATOR, [...]) over literal items or over a `for` whose
// collection is a pinned variable, a conditional with both branches followed,
// and a local.* reference. A pinned value spliced into a literal is rendered
// as the reference itself, so `'${var.github_owner_id}'` becomes
// `'var.github_owner_id'`: the pin bounds what it can hold, and a string's
// content is never read as structure. A `for` is rendered twice: as one
// element, and as two elements with the separator between them. Every
// element renders alike, so a third would add no operand of a new shape; the
// separator is text of the maintainer's choosing and the one place a join
// can introduce an operator, and it used to be dropped from the rendering,
// so `join(") || (assertion.repository_owner == 'x') || (", [for ...])` read
// as a single comparison. Over a collection that may be empty the `for`
// yields the empty text as well, because an empty join leaves a hole in the
// condition. Anything else refuses the provider.
// ---------------------------------------------------------------------------

interface RenderedBranch {
  readonly choices: readonly string[];
  readonly text: string;
}

// A rendering is text interleaved with choices, each choice a set of labelled
// alternatives, expanded into one branch per combination at the end.
type Piece = string | Choice;

interface ChoiceOption {
  readonly label: string;
  readonly pieces: readonly Piece[];
}

interface Choice {
  readonly options: readonly ChoiceOption[];
}

type PieceRender =
  | { readonly kind: "pieces"; readonly pieces: readonly Piece[] }
  | { readonly kind: "unreadable"; readonly reason: string };

type Expansion =
  | { readonly kind: "branches"; readonly branches: readonly RenderedBranch[] }
  | { readonly kind: "unreadable"; readonly reason: string };

interface RenderContext {
  readonly locals: ReadonlyMap<string, LocalDefinition>;
  readonly pins: ReadonlyMap<string, VariablePin>;
  // Locals already rendered, and those being rendered, so a local that
  // interpolates itself is refused rather than followed forever.
  readonly rendered: Map<string, PieceRender>;
  readonly rendering: Set<string>;
}

const noIterators: ReadonlySet<string> = new Set();
const joinCall = /^join\s*\(/;
const forExpression = /^\s*for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+([^:]*?)\s*:/;
const branchLimit = 64;

function unreadable(reason: string): PieceRender {
  return { kind: "unreadable", reason };
}

// The first code character equal to `wanted` at bracket depth zero.
function codeIndexOf(file: HclFile, from: number, to: number, wanted: string): number | undefined {
  let depth = 0;
  for (let index = from; index < to; index += 1) {
    if (!isCode(file, index)) continue;
    const character = file.text.charAt(index);
    if (character === "(" || character === "[" || character === "{") depth += 1;
    else if (character === ")" || character === "]" || character === "}") depth -= 1;
    else if (depth === 0 && character === wanted) return index;
  }
  return undefined;
}

// The `:` matching the `?` just before `from`, skipping nested conditionals.
function conditionalColon(file: HclFile, from: number, to: number): number | undefined {
  let depth = 0;
  let nested = 0;
  for (let index = from; index < to; index += 1) {
    if (!isCode(file, index)) continue;
    const character = file.text.charAt(index);
    if (character === "(" || character === "[" || character === "{") depth += 1;
    else if (character === ")" || character === "]" || character === "}") depth -= 1;
    else if (depth === 0 && character === "?") nested += 1;
    else if (depth === 0 && character === ":") {
      if (nested === 0) return index;
      nested -= 1;
    }
  }
  return undefined;
}

// The ranges between code commas at bracket depth zero, blank ones dropped so
// a trailing comma is not an argument.
function splitAtCommas(file: HclFile, from: number, to: number): Array<[number, number]> {
  const parts: Array<[number, number]> = [];
  let depth = 0;
  let start = from;
  for (let index = from; index < to; index += 1) {
    if (!isCode(file, index)) continue;
    const character = file.text.charAt(index);
    if (character === "(" || character === "[" || character === "{") depth += 1;
    else if (character === ")" || character === "]" || character === "}") depth -= 1;
    else if (depth === 0 && character === ",") {
      parts.push([start, index]);
      start = index + 1;
    }
  }
  parts.push([start, to]);
  return parts.filter(([partFrom, partTo]) => {
    const [trimmedFrom, trimmedTo] = trimmedRange(file, partFrom, partTo);
    return trimmedFrom < trimmedTo;
  });
}

// The closing quote of the string opening at `open`. An interpolation inside
// the string may hold strings of its own, so its span is stepped over.
function stringClose(file: HclFile, open: number, to: number): number | undefined {
  let index = open + 1;
  while (index < to) {
    const span = file.templates.find((candidate) => candidate.open === index);
    if (span !== undefined) {
      index = span.close + 1;
      continue;
    }
    if (file.mask[index] === quote) return index;
    index += 1;
  }
  return undefined;
}

// The literal text between interpolations, with backslash escapes resolved
// in a quoted string; a heredoc has none. An escape outside the few this
// module could plausibly use is refused rather than guessed at.
function literalText(
  file: HclFile,
  from: number,
  to: number,
  escapes: boolean,
): { readonly kind: "text"; readonly text: string } | { readonly kind: "unreadable"; readonly reason: string } {
  const raw = file.text.slice(from, to);
  if (!escapes) return { kind: "text", text: raw };
  let out = "";
  for (let index = 0; index < raw.length; index += 1) {
    const character = raw.charAt(index);
    if (character !== "\\") {
      out += character;
      continue;
    }
    const escaped = raw.charAt(index + 1);
    const resolved = escaped === '"'
      ? '"'
      : escaped === "\\"
      ? "\\"
      : escaped === "n"
      ? "\n"
      : escaped === "r"
      ? "\r"
      : escaped === "t"
      ? "\t"
      : undefined;
    if (resolved === undefined) return { kind: "unreadable", reason: `the escape sequence \\${escaped}` };
    out += resolved;
    index += 1;
  }
  return { kind: "text", text: out };
}

function renderTemplate(
  context: RenderContext,
  file: HclFile,
  from: number,
  to: number,
  escapes: boolean,
  iterators: ReadonlySet<string>,
  where: string,
): PieceRender {
  const pieces: Piece[] = [];
  let buffer = "";
  let cursor = from;
  const spans = file.templates
    .filter((span) => span.open >= from && span.open < to)
    .sort((left, right) => left.open - right.open);
  for (const span of spans) {
    // A span inside one already rendered belongs to that interpolation.
    if (span.open < cursor) continue;
    const literal = literalText(file, cursor, span.open, escapes);
    if (literal.kind === "unreadable") return unreadable(`${where} uses ${literal.reason}, which the inventory does not resolve.`);
    buffer += literal.text;
    cursor = span.close + 1;
    if (span.directive) {
      return unreadable(
        `${where} contains the template directive ${excerpt(file.text, span.open)}, which the inventory cannot expand.`,
      );
    }
    const body = file.text.slice(span.open + 2, span.close).trim();
    if (localHole.test(body)) {
      const inner = renderLocal(context, body.slice("local.".length));
      if (inner.kind === "unreadable") return inner;
      pieces.push(buffer, ...inner.pieces);
      buffer = "";
      continue;
    }
    const variable = variableHole.exec(body)?.[1];
    if (variable !== undefined) {
      if (context.pins.get(variable)?.kind !== "pinned") {
        return unreadable(`${where} interpolates \${${body}}, which no validation pins.`);
      }
    } else if (!iterators.has(body)) {
      return unreadable(`${where} interpolates \${${body}}, which the inventory cannot render.`);
    }
    // A pinned value is admitted only as the whole of one single-quoted CEL
    // literal, where the pin bounds its content; the reference stands in.
    if (file.text.charAt(span.open - 1) !== "'" || file.text.charAt(span.close + 1) !== "'") {
      return unreadable(`${where} interpolates \${${body}} outside a single-quoted CEL literal.`);
    }
    buffer += body;
  }
  const tail = literalText(file, cursor, to, escapes);
  if (tail.kind === "unreadable") return unreadable(`${where} uses ${tail.reason}, which the inventory does not resolve.`);
  pieces.push(buffer + tail.text);
  return { kind: "pieces", pieces };
}

function renderLocal(context: RenderContext, name: string): PieceRender {
  const memo = context.rendered.get(name);
  if (memo !== undefined) return memo;
  if (context.rendering.has(name)) {
    return unreadable(`local.${name} interpolates itself, so the effective condition has no finite text.`);
  }
  const definition = context.locals.get(name);
  if (definition === undefined) {
    return unreadable(`local.${name} is not defined beside the provider, so the effective condition cannot be rendered.`);
  }
  context.rendering.add(name);
  const result = renderExpression(
    context,
    definition.file,
    definition.attribute.start,
    definition.attribute.end,
    noIterators,
    `local.${name} (${definition.file.path} line ${definition.attribute.line})`,
  );
  context.rendering.delete(name);
  context.rendered.set(name, result);
  return result;
}

function renderFor(
  context: RenderContext,
  file: HclFile,
  from: number,
  to: number,
  iterators: ReadonlySet<string>,
  where: string,
  separator: string,
): PieceRender {
  const match = forExpression.exec(codeText(file, from, to));
  const iterator = match?.[1];
  const collection = match?.[2]?.trim();
  if (match === null || iterator === undefined || collection === undefined) {
    return unreadable(`${where} has a for expression the inventory cannot read.`);
  }
  const source = readableCollection.exec(collection)?.[1];
  if (source === undefined) {
    return unreadable(
      `${where} iterates over ${JSON.stringify(collection)}, which is not one variable inside list-shaping calls.`,
    );
  }
  const pin = context.pins.get(source);
  if (pin?.kind !== "pinned") return unreadable(`${where} iterates over var.${source}, which no validation pins.`);
  const body = renderExpression(context, file, from + match[0].length, to, new Set([...iterators, iterator]), where);
  if (body.kind === "unreadable") return body;
  const options: ChoiceOption[] = [
    { label: `var.${source} has one element`, pieces: body.pieces },
    { label: `var.${source} has more than one element`, pieces: [...body.pieces, separator, ...body.pieces] },
  ];
  if (!pin.nonempty) options.push({ label: `var.${source} is empty`, pieces: [] });
  return { kind: "pieces", pieces: [{ options }] };
}

function renderJoin(
  context: RenderContext,
  file: HclFile,
  from: number,
  to: number,
  iterators: ReadonlySet<string>,
  where: string,
): PieceRender {
  const visible = visibleText(file, from, to);
  const open = from + (joinCall.exec(codeText(file, from, to))?.[0].length ?? 1) - 1;
  if (closingBracket(file, open, to) !== to) {
    return unreadable(`${where} continues after join(...) (${excerpt(visible, 0)}), which the inventory does not render.`);
  }
  const [separatorArgument, listArgument, ...extra] = splitAtCommas(file, open + 1, to - 1);
  if (separatorArgument === undefined || listArgument === undefined || extra.length > 0) {
    return unreadable(`${where} calls join without exactly a separator and a list (${excerpt(visible, 0)}).`);
  }
  const separator = renderExpression(context, file, separatorArgument[0], separatorArgument[1], iterators, where);
  if (separator.kind === "unreadable") return separator;
  const separatorText = separator.pieces.length === 1 ? separator.pieces[0] : undefined;
  if (typeof separatorText !== "string") {
    return unreadable(`${where} joins with a separator that is not one literal string (${excerpt(visible, 0)}).`);
  }
  const [listFrom, listTo] = trimmedRange(file, listArgument[0], listArgument[1]);
  if (file.text.charAt(listFrom) !== "[" || !isCode(file, listFrom) || closingBracket(file, listFrom, listTo) !== listTo) {
    return unreadable(
      `${where} joins something other than a list literal (${excerpt(visible, 0)}); only [...] and [for ...] are rendered.`,
    );
  }
  if (forExpression.test(codeText(file, listFrom + 1, listTo - 1))) {
    return renderFor(context, file, listFrom + 1, listTo - 1, iterators, where, separatorText);
  }
  const items = splitAtCommas(file, listFrom + 1, listTo - 1);
  if (items.length === 0) return unreadable(`${where} joins an empty list, which renders as no condition at all.`);
  const pieces: Piece[] = [];
  for (const [index, [itemFrom, itemTo]] of items.entries()) {
    if (index > 0) pieces.push(separatorText);
    const item = renderExpression(context, file, itemFrom, itemTo, iterators, where);
    if (item.kind === "unreadable") return item;
    pieces.push(...item.pieces);
  }
  return { kind: "pieces", pieces };
}

function renderExpression(
  context: RenderContext,
  file: HclFile,
  start: number,
  end: number,
  iterators: ReadonlySet<string>,
  where: string,
): PieceRender {
  const [from, to] = trimmedRange(file, start, end);
  if (from >= to) return unreadable(`${where} is empty where a condition was expected.`);
  if (file.text.charAt(from) === "(" && isCode(file, from) && closingBracket(file, from, to) === to) {
    return renderExpression(context, file, from + 1, to - 1, iterators, where);
  }
  const question = codeIndexOf(file, from, to, "?");
  if (question !== undefined) {
    const colon = conditionalColon(file, question + 1, to);
    if (colon === undefined) {
      return unreadable(`${where} has a ? with no matching : (${excerpt(visibleText(file, from, to), 0)}).`);
    }
    const chooser = visibleText(file, from, question).replace(/\s+/g, " ").trim();
    const yes = renderExpression(context, file, question + 1, colon, iterators, where);
    if (yes.kind === "unreadable") return yes;
    const no = renderExpression(context, file, colon + 1, to, iterators, where);
    if (no.kind === "unreadable") return no;
    return {
      kind: "pieces",
      pieces: [{
        options: [
          { label: `${chooser} is true`, pieces: yes.pieces },
          { label: `${chooser} is false`, pieces: no.pieces },
        ],
      }],
    };
  }
  if (file.mask[from] === quote) {
    const close = stringClose(file, from, to);
    if (close !== to - 1) {
      return unreadable(
        `${where} is an expression around a string (${excerpt(visibleText(file, from, to), 0)}), not a string; only a whole string is rendered.`,
      );
    }
    return renderTemplate(context, file, from + 1, close, true, iterators, where);
  }
  if (file.text.startsWith("<<", from)) {
    heredocMarker.lastIndex = from;
    const marker = heredocMarker.exec(file.text);
    const terminator = file.text.lastIndexOf("\n", to - 1) + 1;
    if (marker === null || marker[1] === undefined || file.text.slice(terminator, to).trim() !== marker[1]) {
      return unreadable(`${where} is a heredoc the inventory cannot delimit.`);
    }
    return renderTemplate(context, file, from + marker[0].length, terminator, false, iterators, where);
  }
  const code = codeText(file, from, to).trim();
  if (localHole.test(code)) return renderLocal(context, code.slice("local.".length));
  if (joinCall.test(code)) return renderJoin(context, file, from, to, iterators, where);
  return unreadable(
    `${where} is not an expression the inventory can render into a condition (${excerpt(visibleText(file, from, to), 0)}); ` +
      `only a string, a heredoc, join(SEPARATOR, [...]), a conditional and a local.* reference are followed.`,
  );
}

// Every combination of choices, as one text each. A choice interpolated twice
// is expanded independently each time, which over-approximates: a branch
// that Terraform could not produce is still read, and reading more never
// admits more.
function expandPieces(pieces: readonly Piece[]): Expansion {
  let branches: RenderedBranch[] = [{ choices: [], text: "" }];
  for (const piece of pieces) {
    if (typeof piece === "string") {
      branches = branches.map((branch) => ({ choices: branch.choices, text: branch.text + piece }));
      continue;
    }
    const next: RenderedBranch[] = [];
    for (const option of piece.options) {
      const inner = expandPieces(option.pieces);
      if (inner.kind === "unreadable") return inner;
      for (const branch of branches) {
        for (const tail of inner.branches) {
          next.push({ choices: [...branch.choices, option.label, ...tail.choices], text: branch.text + tail.text });
        }
      }
    }
    if (next.length > branchLimit) {
      return {
        kind: "unreadable",
        reason: `the condition has more than ${branchLimit} conditional renderings, which the inventory does not read.`,
      };
    }
    branches = next;
  }
  return { branches, kind: "branches" };
}

function renderCondition(
  condition: HclAttribute,
  file: HclFile,
  locals: ReadonlyMap<string, LocalDefinition>,
  pins: ReadonlyMap<string, VariablePin>,
): Expansion {
  const context: RenderContext = { locals, pins, rendered: new Map(), rendering: new Set() };
  const pieces = renderExpression(
    context,
    file,
    condition.start,
    condition.end,
    noIterators,
    `attribute_condition (${file.path} line ${condition.line})`,
  );
  if (pieces.kind === "unreadable") return pieces;
  return expandPieces(pieces.pieces);
}

// ---------------------------------------------------------------------------
// The boolean structure of the effective condition
//
// A provider admits a token when its condition evaluates true, so the
// question is whether the condition can be true for a token whose
// job_workflow_ref is not a platform workflow. That is answered from the
// structure alone. A recognised trust form, read as the whole of one operand,
// binds job_workflow_ref; `A && B` binds it when either side does; `A || B`
// and `c ? A : B` bind it only when both sides do; a negation, a literal and
// any operand that is not a whole trust form bind nothing. The condition is
// refused unless the whole of it binds. `|| true` is refused because `true`
// binds nothing, and so is `T == false`, which CEL reads as `(T) == false`
// and which no whole-operand form matches. The live SHA disjunction passes
// because it stands as a conjunct beside a disjunction of trust forms, and a
// conjunct is never asked to bind on its own.
//
// Two further refusals keep the reading honest. A bare boolean literal is
// refused wherever it stands, since a condition is read only as comparisons
// of claims. And an operand the reader cannot decompose refuses the condition
// outright: a CEL comment, which hides the rest of the line from CEL but not
// from a naive split; a prefixed or triple-quoted string, which CEL delimits
// by other rules; a bracket unbalanced or closed by the wrong kind; a stray
// ? or :.
// ---------------------------------------------------------------------------

export type ConditionStructure =
  | { readonly kind: "bounded"; readonly names: ReadonlySet<string> }
  | { readonly kind: "unbounded"; readonly failures: readonly string[] };

type CelNode =
  | { readonly kind: "or"; readonly operands: readonly CelNode[]; readonly text: string }
  | { readonly kind: "and"; readonly operands: readonly CelNode[]; readonly text: string }
  | { readonly kind: "not"; readonly operand: CelNode; readonly text: string }
  | {
    readonly kind: "conditional";
    readonly condition: CelNode;
    readonly branches: readonly CelNode[];
    readonly text: string;
  }
  | { readonly kind: "trust"; readonly name: string; readonly text: string }
  | { readonly kind: "literal"; readonly text: string }
  | { readonly kind: "other"; readonly blanked: string; readonly text: string };

type CelParse =
  | { readonly kind: "node"; readonly node: CelNode }
  | { readonly kind: "problem"; readonly problem: string };

// The two trust forms as whole operands: nothing before, nothing after.
const exactTrustOperand =
  /^assertion\.job_workflow_ref\s*==\s*'collinbentley1\/platform\/\.github\/workflows\/([\w.-]+\.ya?ml)@'\s*\+\s*assertion\.job_workflow_sha$/;
const legacyTrustOperand =
  /^assertion\.job_workflow_ref\.startsWith\(\s*'collinbentley1\/platform\/\.github\/workflows\/([\w.-]+\.ya?ml)@'\s*\)$/;
// The fragment scan's pattern without its global flag, for a stateless test
// of whether a node mentions a trust form at all.
const trustMention = new RegExp(workflowTrustPattern.source);
const booleanLiteral = /\b(?:true|false)\b/g;
const identifierCharacter = /[A-Za-z0-9_]/;

function quoteOperand(text: string): string {
  const shown = text.replace(/\s+/g, " ").trim();
  return JSON.stringify(shown.length > 90 ? `${shown.slice(0, 87)}...` : shown);
}

// The text with every string literal's content replaced by spaces, so that
// operators and brackets are found only where CEL would find them.
function blankStrings(
  text: string,
): { readonly kind: "blanked"; readonly blanked: string } | { readonly kind: "problem"; readonly problem: string } {
  let out = "";
  let index = 0;
  while (index < text.length) {
    const character = text.charAt(index);
    if (character === "/" && text.charAt(index + 1) === "/") {
      return { kind: "problem", problem: `the CEL comment at ${excerpt(text, index)} hides the rest of the line from CEL` };
    }
    if (character !== "'" && character !== '"') {
      out += character;
      index += 1;
      continue;
    }
    if (identifierCharacter.test(text.charAt(index - 1))) {
      return { kind: "problem", problem: `the prefixed string literal at ${excerpt(text, index)} is not a plain string` };
    }
    if (text.charAt(index + 1) === character && text.charAt(index + 2) === character) {
      return { kind: "problem", problem: `the triple-quoted string literal at ${excerpt(text, index)} is not a plain string` };
    }
    out += character;
    let cursor = index + 1;
    while (cursor < text.length && text.charAt(cursor) !== character) {
      const width = text.charAt(cursor) === "\\" ? 2 : 1;
      out += " ".repeat(width);
      cursor += width;
    }
    if (cursor >= text.length) {
      return { kind: "problem", problem: `the string literal at ${excerpt(text, index)} is unterminated` };
    }
    out += character;
    const following = text.charAt(cursor + 1);
    if (following === "'" || following === '"') {
      return { kind: "problem", problem: `the string literal at ${excerpt(text, index)} is followed directly by another` };
    }
    index = cursor + 1;
  }
  return { blanked: out, kind: "blanked" };
}

// Every closing bracket must close the bracket opened last, or the depth
// counts that follow -- which treat the three pairs as one -- read `(T]` as
// a parenthesised trust form.
function bracketProblem(text: string, blanked: string): string | undefined {
  const open: string[] = [];
  for (let index = 0; index < blanked.length; index += 1) {
    const character = blanked.charAt(index);
    if (character === "(" || character === "[" || character === "{") {
      open.push(character);
      continue;
    }
    const opener = openerOf[character];
    if (opener === undefined) continue;
    const last = open.pop();
    if (last === undefined) return `the ${character} at ${excerpt(text, index)} closes nothing`;
    if (last !== opener) return `the ${character} at ${excerpt(text, index)} closes a ${last}, not a ${opener}`;
  }
  return open.length === 0 ? undefined : `the brackets of ${quoteOperand(text)} do not balance`;
}

// The index of the bracket closing the one at `open`; the brackets were
// checked to pair before the first call.
function matchingClose(blanked: string, open: number, to: number): number | undefined {
  let depth = 0;
  for (let index = open; index < to; index += 1) {
    const character = blanked.charAt(index);
    if (character === "(" || character === "[" || character === "{") depth += 1;
    else if (character === ")" || character === "]" || character === "}") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return undefined;
}

// CEL binds `?:` loosest, then `||`, then `&&`, then everything else, so the
// operators are looked for in that order at bracket depth zero. Whatever is
// left is one operand: a whole trust form, a literal, or something else. The
// brackets were checked to pair before the first call, so depth is counted
// over the three pairs as one.
function parseCel(text: string, blanked: string, start: number, end: number): CelParse {
  let from = start;
  let to = end;
  while (from < to && /\s/.test(blanked.charAt(from))) from += 1;
  while (to > from && /\s/.test(blanked.charAt(to - 1))) to -= 1;
  if (from >= to) return { kind: "problem", problem: "an operand is empty" };
  if (blanked.charAt(from) === "(" && matchingClose(blanked, from, to) === to - 1) {
    return parseCel(text, blanked, from + 1, to - 1);
  }
  const node = text.slice(from, to);
  const cuts: Array<{ readonly index: number; readonly operator: "||" | "&&" | "?" | ":" }> = [];
  let depth = 0;
  for (let index = from; index < to; index += 1) {
    const character = blanked.charAt(index);
    if (character === "(" || character === "[" || character === "{") {
      depth += 1;
    } else if (character === ")" || character === "]" || character === "}") {
      depth -= 1;
    } else if (depth > 0) {
      continue;
    } else if (character === "|" || character === "&") {
      if (blanked.charAt(index + 1) !== character) {
        return { kind: "problem", problem: `a single ${character} in ${quoteOperand(node)} is not a CEL operator` };
      }
      cuts.push({ index, operator: character === "|" ? "||" : "&&" });
      index += 1;
    } else if (character === "?" || character === ":") {
      cuts.push({ index, operator: character });
    }
  }

  const question = cuts.find((cut) => cut.operator === "?");
  if (question !== undefined) {
    let nested = 0;
    let colon: number | undefined;
    for (const cut of cuts) {
      if (cut.index <= question.index) continue;
      if (cut.operator === "?") nested += 1;
      else if (cut.operator === ":") {
        if (nested === 0) {
          colon = cut.index;
          break;
        }
        nested -= 1;
      }
    }
    if (colon === undefined) return { kind: "problem", problem: `the ? in ${quoteOperand(node)} has no matching :` };
    const condition = parseCel(text, blanked, from, question.index);
    if (condition.kind === "problem") return condition;
    const yes = parseCel(text, blanked, question.index + 1, colon);
    if (yes.kind === "problem") return yes;
    const no = parseCel(text, blanked, colon + 1, to);
    if (no.kind === "problem") return no;
    return {
      kind: "node",
      node: { branches: [yes.node, no.node], condition: condition.node, kind: "conditional", text: node },
    };
  }
  if (cuts.some((cut) => cut.operator === ":")) {
    return { kind: "problem", problem: `the : in ${quoteOperand(node)} has no ?` };
  }
  for (const operator of ["||", "&&"] as const) {
    const positions = cuts.filter((cut) => cut.operator === operator).map((cut) => cut.index);
    if (positions.length === 0) continue;
    const operands: CelNode[] = [];
    let cursor = from;
    for (const position of [...positions, to]) {
      const operand = parseCel(text, blanked, cursor, position);
      if (operand.kind === "problem") return operand;
      operands.push(operand.node);
      cursor = position + 2;
    }
    return { kind: "node", node: { kind: operator === "||" ? "or" : "and", operands, text: node } };
  }
  if (blanked.charAt(from) === "!") {
    const operand = parseCel(text, blanked, from + 1, to);
    if (operand.kind === "problem") return operand;
    return { kind: "node", node: { kind: "not", operand: operand.node, text: node } };
  }
  if (node === "true" || node === "false") return { kind: "node", node: { kind: "literal", text: node } };
  const name = exactTrustOperand.exec(node)?.[1] ?? legacyTrustOperand.exec(node)?.[1];
  if (name !== undefined) return { kind: "node", node: { kind: "trust", name, text: node } };
  return { kind: "node", node: { blanked: blanked.slice(from, to), kind: "other", text: node } };
}

// Whether every token the node admits has job_workflow_ref bound to a
// platform workflow.
function binds(node: CelNode): boolean {
  switch (node.kind) {
    case "trust":
      return true;
    case "and":
      return node.operands.some(binds);
    case "or":
      return node.operands.every(binds);
    case "conditional":
      return node.branches.every(binds);
    case "not":
    case "literal":
    case "other":
      return false;
  }
}

function trustNames(node: CelNode, out: Set<string>): void {
  switch (node.kind) {
    case "trust":
      out.add(node.name);
      return;
    case "and":
    case "or":
      for (const operand of node.operands) trustNames(operand, out);
      return;
    case "conditional":
      for (const branch of node.branches) trustNames(branch, out);
      return;
    case "not":
    case "literal":
    case "other":
      return;
  }
}

function refuseLiterals(node: CelNode, out: string[]): void {
  switch (node.kind) {
    case "literal":
      out.push(
        `the condition uses the boolean literal ${node.text} as an operand; a condition is read only as comparisons of assertion claims, ` +
          `and a bare literal can admit every token (|| true) or none (&& false).`,
      );
      return;
    case "other":
      for (const match of node.blanked.matchAll(booleanLiteral)) {
        out.push(
          `the condition uses the boolean literal ${match[0]} inside the operand ${quoteOperand(node.text)}, which the inventory does not decompose further.`,
        );
      }
      return;
    case "and":
    case "or":
      for (const operand of node.operands) refuseLiterals(operand, out);
      return;
    case "not":
      refuseLiterals(node.operand, out);
      return;
    case "conditional":
      refuseLiterals(node.condition, out);
      for (const branch of node.branches) refuseLiterals(branch, out);
      return;
    case "trust":
      return;
  }
}

// Why a node that does not bind does not: the operands that were relied on
// and failed, named as precisely as the structure allows.
function explainUnbound(node: CelNode, out: string[]): void {
  switch (node.kind) {
    case "or":
    case "conditional": {
      const parts = node.kind === "or" ? node.operands : node.branches;
      const role = node.kind === "or" ? "the || operand" : "the conditional branch";
      for (const part of parts) {
        if (binds(part)) continue;
        if ((part.kind === "and" || part.kind === "or" || part.kind === "conditional") && trustMention.test(part.text)) {
          explainUnbound(part, out);
          continue;
        }
        out.push(
          `the condition admits a token from any workflow through ${role} ${quoteOperand(part.text)}, which is not a recognised job_workflow_ref trust form; ` +
            `every operand of a || and every branch of a ?: must bind job_workflow_ref to a platform workflow.`,
        );
      }
      return;
    }
    case "and": {
      const candidates = node.operands.filter((operand) => trustMention.test(operand.text));
      if (candidates.length === 0) {
        out.push(`the condition binds job_workflow_ref to no platform workflow in any conjunct of ${quoteOperand(node.text)}.`);
        return;
      }
      for (const candidate of candidates) explainUnbound(candidate, out);
      return;
    }
    case "not":
      out.push(
        `the condition admits a token from any workflow through the negation ${quoteOperand(node.text)}; a negation binds job_workflow_ref to nothing.`,
      );
      return;
    case "literal":
    case "other":
      out.push(
        `the condition binds job_workflow_ref to no platform workflow: ${quoteOperand(node.text)} is not a recognised trust form read as a whole operand.`,
      );
      return;
    case "trust":
      return;
  }
}

// The structural reading of one effective condition: bounded, with the
// workflows its whole-operand trust forms name, or the reasons it is not.
export function conditionStructure(text: string): ConditionStructure {
  const blanked = blankStrings(text);
  if (blanked.kind === "problem") {
    return { failures: [`the condition cannot be decomposed: ${blanked.problem}.`], kind: "unbounded" };
  }
  const brackets = bracketProblem(text, blanked.blanked);
  if (brackets !== undefined) {
    return { failures: [`the condition cannot be decomposed: ${brackets}.`], kind: "unbounded" };
  }
  const parsed = parseCel(text, blanked.blanked, 0, text.length);
  if (parsed.kind === "problem") {
    return { failures: [`the condition cannot be decomposed: ${parsed.problem}.`], kind: "unbounded" };
  }
  const failures: string[] = [];
  refuseLiterals(parsed.node, failures);
  if (!binds(parsed.node)) explainUnbound(parsed.node, failures);
  if (failures.length > 0) return { failures: [...new Set(failures)], kind: "unbounded" };
  const names = new Set<string>();
  trustNames(parsed.node, names);
  return { kind: "bounded", names };
}

export function trustedWorkflowsFromTerraform(files: ReadonlyMap<string, string>): TerraformTrust {
  const failures: string[] = [];
  const parsed: ParsedFile[] = [];
  for (const [path, source] of files) {
    const lexed = lexHcl(path, source);
    if (lexed.kind === "invalid") {
      failures.push(lexed.failure);
      continue;
    }
    const body = parseBody(lexed.file, 0, source.length);
    if (body.kind === "invalid") {
      failures.push(body.failure);
      continue;
    }
    parsed.push({ body: body.body, file: lexed.file });
  }

  // Locals are module-scoped, so they are gathered per directory and a
  // provider only resolves against the locals beside it.
  const localsByDirectory = new Map<string, Map<string, LocalDefinition>>();
  for (const { body, file } of parsed) {
    const directory = dirname(file.path);
    const locals = localsByDirectory.get(directory) ?? new Map<string, LocalDefinition>();
    localsByDirectory.set(directory, locals);
    for (const block of body.blocks) {
      if (block.type !== "locals") continue;
      const inner = parseBody(file, block.bodyStart, block.bodyEnd);
      if (inner.kind === "invalid") {
        failures.push(inner.failure);
        continue;
      }
      for (const attribute of inner.body.attributes) {
        if (locals.has(attribute.name)) {
          failures.push(
            `${file.path}: local.${attribute.name} is defined more than once in ${directory}; the effective condition is ambiguous.`,
          );
          continue;
        }
        locals.set(attribute.name, { attribute, file });
      }
    }
  }

  // Variable pins are module-scoped like locals, and read only for a module
  // that holds a provider.
  const filesByDirectory = new Map<string, ParsedFile[]>();
  for (const entry of parsed) {
    const directory = dirname(entry.file.path);
    const list = filesByDirectory.get(directory) ?? [];
    list.push(entry);
    filesByDirectory.set(directory, list);
  }
  const pinsByDirectory = new Map<string, Map<string, VariablePin>>();

  const providers: string[] = [];
  const conditions: EffectiveCondition[] = [];
  const workflows = new Set<string>();
  for (const { body, file } of parsed) {
    for (const block of body.blocks) {
      if (block.type !== "resource" || block.labels[0] !== "google_iam_workload_identity_pool_provider") continue;
      const display = `${file.path}: google_iam_workload_identity_pool_provider.${block.labels[1] ?? "(unnamed)"}`;
      providers.push(display);
      const inner = parseBody(file, block.bodyStart, block.bodyEnd);
      if (inner.kind === "invalid") {
        failures.push(inner.failure);
        continue;
      }
      const condition = inner.body.attributes.find((attribute) => attribute.name === "attribute_condition");
      if (condition === undefined) {
        failures.push(
          `${display} has no attribute_condition; a provider without a condition trusts every token the issuer signs for this pool.`,
        );
        continue;
      }

      // Follow `local.*` through the module until the condition is literal.
      const directory = dirname(file.path);
      const locals = localsByDirectory.get(directory) ?? new Map<string, LocalDefinition>();
      const pending: ConditionFragment[] = [{ attribute: condition, file, label: "attribute_condition" }];
      const visited = new Set<string>();
      const fragments: ConditionFragment[] = [];
      let unresolved = false;
      while (pending.length > 0) {
        const current = pending.pop();
        if (current === undefined) break;
        fragments.push(current);
        for (const name of localReferences(current.file, current.attribute.start, current.attribute.end)) {
          if (visited.has(name)) continue;
          visited.add(name);
          const definition = locals.get(name);
          if (definition === undefined) {
            unresolved = true;
            failures.push(
              `${display} references local.${name}, which no locals block in ${directory} defines; the effective condition cannot be determined.`,
            );
            continue;
          }
          pending.push({ attribute: definition.attribute, file: definition.file, label: `local.${name}` });
        }
      }
      if (unresolved) continue;

      // Every fragment is read in full. A workflow name is collected only
      // from a recognised clause, and anything the scan could not account
      // for -- another mention of job_workflow_ref, a startsWith on some
      // other prefix, a template it cannot expand, a reference or call it
      // cannot follow -- refuses the provider, however many names sit beside
      // it. One readable clause used to vouch for the whole condition.
      const pins = pinsByDirectory.get(directory)
        ?? variablePins(filesByDirectory.get(directory) ?? [], directory);
      pinsByDirectory.set(directory, pins);
      const names = new Set<string>();
      let readable = true;
      for (const fragment of fragments) {
        const scan = scanFragment(fragment, pins);
        for (const name of scan.names) names.add(name);
        for (const problem of scan.residue) failures.push(`${display}: ${problem}`);
        if (scan.residue.length > 0) readable = false;
      }
      if (names.size === 0) {
        failures.push(
          `${display} has an attribute_condition that names no workflow through assertion.job_workflow_ref; the trust cannot be cross-checked.`,
        );
        continue;
      }
      if (!readable) continue;

      // Every fragment was read; now the condition they build is rendered
      // and its structure must bind job_workflow_ref on every path. A name
      // the fragment scan collected must also stand as a whole operand of
      // that structure, so that `T == false` -- the trust form inside a
      // larger comparison -- is refused even where another conjunct binds.
      const rendering = renderCondition(condition, file, locals, pins);
      if (rendering.kind === "unreadable") {
        failures.push(`${display}: ${rendering.reason}`);
        continue;
      }
      const anchored = new Set<string>();
      let bounded = true;
      for (const branch of rendering.branches) {
        const when = branch.choices.length > 0 ? `when ${branch.choices.join(" and ")}, ` : "";
        const structure = conditionStructure(branch.text);
        if (structure.kind === "unbounded") {
          bounded = false;
          for (const failure of structure.failures) failures.push(`${display}: ${when}${failure}`);
          continue;
        }
        for (const name of structure.names) anchored.add(name);
        conditions.push({ choices: branch.choices, provider: display, text: branch.text });
      }
      if (!bounded) continue;
      for (const name of sorted(names)) {
        if (anchored.has(name)) continue;
        bounded = false;
        failures.push(
          `${display} compares job_workflow_ref to ${name} only inside a larger operand; a trust form counts only as the whole of one || operand or && conjunct.`,
        );
      }
      if (!bounded) continue;
      for (const name of names) workflows.add(name);
    }
  }

  if (providers.length === 0) {
    failures.push(
      "no google_iam_workload_identity_pool_provider block was found in any Terraform file; the authority inventory cannot be cross-checked.",
    );
  }
  return failures.length > 0
    ? { failures, kind: "invalid" }
    : { conditions, kind: "trusted", providers, workflows };
}

// ---------------------------------------------------------------------------
// The inventory
// ---------------------------------------------------------------------------

export function validateWorkflowAuthorityInventory(input: {
  readonly declared?: DeclaredAuthorityInventory;
  readonly terraform: ReadonlyMap<string, string>;
  readonly workflows: ReadonlyMap<string, string>;
}): string[] {
  const failures: string[] = [];
  const declared = input.declared ?? declaredWorkflowAuthority;

  if (input.workflows.size === 0) {
    failures.push("workflow authority inventory found no workflows to classify.");
    return failures;
  }

  const declaredAll = [...declared.ownerCredential, ...declared.cloudAuthority, ...declared.neither];
  const declaredSet = new Set(declaredAll);
  for (const name of sorted(declaredSet)) {
    if (declaredAll.filter((candidate) => candidate === name).length > 1) {
      failures.push(`workflow authority inventory declares ${name} in more than one set.`);
    }
  }

  const derived = new Map<string, WorkflowCapabilities>();
  for (const [name, source] of input.workflows) {
    const analysis = workflowCapabilities(source);
    if (analysis.kind === "invalid") {
      for (const reason of analysis.reasons) {
        failures.push(`${workflowDirectory}/${name} ${reason}; it cannot be classified.`);
      }
      continue;
    }
    derived.set(name, analysis.capabilities);
  }

  // Every workflow on disk must be declared, and every declared workflow must
  // exist. A new file that nobody classified is the drift case.
  for (const name of sorted(input.workflows.keys())) {
    if (declaredSet.has(name)) continue;
    const capabilities = derived.get(name);
    const shown = capabilities === undefined
      ? ""
      : ` its source shows ${classifyWorkflowAuthority(capabilities)} (${describeCapabilities(capabilities)});`;
    failures.push(
      `${workflowDirectory}/${name} is not declared in the workflow authority inventory;${shown} ` +
        `classify it in tools/ci/workflow-authority-contract.ts.`,
    );
  }
  for (const name of sorted(declaredSet)) {
    if (!input.workflows.has(name)) {
      failures.push(`workflow authority inventory declares ${name}, which does not exist.`);
    }
  }

  const expected = new Map<string, { readonly owner: boolean; readonly cloud: boolean; readonly label: WorkflowAuthority }>();
  for (const name of declared.ownerCredential) expected.set(name, { cloud: false, label: "owner-credential", owner: true });
  for (const name of declared.cloudAuthority) expected.set(name, { cloud: true, label: "cloud-authority", owner: false });
  for (const name of declared.neither) expected.set(name, { cloud: false, label: "neither", owner: false });

  for (const name of sorted(derived.keys())) {
    const capabilities = derived.get(name);
    if (capabilities === undefined) continue;
    const file = `${workflowDirectory}/${name}`;

    // The owner credential and cloud authority must never meet in one
    // workflow, whatever the declaration says about it.
    if (capabilities.readsOwnerCredential && capabilities.mintsCloudCredentials) {
      failures.push(
        `${file} both reads the owner credential${firstEvidence(capabilities.ownerCredentialEvidence)} ` +
          `and mints cloud credentials${firstEvidence(capabilities.cloudCredentialEvidence)}; ` +
          `the two authorities must never meet in one workflow.`,
      );
    }

    const want = expected.get(name);
    if (want === undefined) continue;
    if (want.owner !== capabilities.readsOwnerCredential || want.cloud !== capabilities.mintsCloudCredentials) {
      failures.push(
        `${file} is declared ${want.label} but its source shows ${classifyWorkflowAuthority(capabilities)} ` +
          `(${describeCapabilities(capabilities)}); the declaration and the workflow disagree.`,
      );
    }
  }

  // Terraform must trust exactly the workflows that mint cloud credentials.
  // A trust with no auth step is a stale binding; an auth step with no trust
  // is a workflow reaching for authority nobody granted. The comparison uses
  // the derived flags, so an undeclared workflow reaching for credentials is
  // reported here as well as above.
  const trust = trustedWorkflowsFromTerraform(input.terraform);
  if (trust.kind === "invalid") {
    failures.push(...trust.failures);
    return failures;
  }
  const minting = new Set(
    [...derived].filter(([, capabilities]) => capabilities.mintsCloudCredentials).map(([name]) => name),
  );
  const missingTrust = [...minting].filter((name) => !trust.workflows.has(name));
  const staleTrust = [...trust.workflows].filter((name) => !minting.has(name));
  if (missingTrust.length > 0) {
    failures.push(
      `workflows mint cloud credentials without a Terraform trust condition: ${describeList(missingTrust)}.`,
    );
  }
  if (staleTrust.length > 0) {
    failures.push(
      `Terraform trusts workflows that do not mint cloud credentials: ${describeList(staleTrust)}.`,
    );
  }

  return failures;
}
