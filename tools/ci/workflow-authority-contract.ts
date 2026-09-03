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

export type FileUniverse =
  | { readonly kind: "resolved"; readonly sources: ReadonlyMap<string, string> }
  | { readonly kind: "rejected"; readonly failures: readonly string[] };

const workflowDirectory = ".github/workflows";
const terraformDirectory = "terraform";
const workflowFileName = /\.ya?ml$/;
const terraformFileName = /\.tf$/;
const jsonTerraformFileName = /\.tf\.json$/;

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
    sources.set(name, await readFile(join(directory, name), "utf8"));
  }
  return failures.length > 0 ? { failures, kind: "rejected" } : { kind: "resolved", sources };
}

// Every Terraform source under terraform/, keyed by its repository-relative
// path. Symbolic links and other non-regular entries are refused as above;
// `*.tf.json` is refused because it is configuration this scan cannot read,
// and a provider block hidden in JSON would otherwise escape the cross-check.
export async function terraformUniverse(root: string): Promise<FileUniverse> {
  const failures: string[] = [];
  const sources = new Map<string, string>();
  await collectTerraform(root, terraformDirectory, failures, sources);
  return failures.length > 0 ? { failures, kind: "rejected" } : { kind: "resolved", sources };
}

async function collectTerraform(
  root: string,
  directory: string,
  failures: string[],
  sources: Map<string, string>,
): Promise<void> {
  for (const name of await entryNames(join(root, directory), directory, failures)) {
    const display = `${directory}/${name}`;
    const shape = await entryShape(join(root, display));
    if (shape === "directory") {
      // `.terraform/` holds provider binaries and fetched module copies written
      // by `terraform init`. It is ignored by git, so its contents depend on
      // what ran on this machine rather than on what was reviewed.
      if (name !== ".terraform") await collectTerraform(root, display, failures, sources);
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
      sources.set(display, await readFile(join(root, display), "utf8"));
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

// `write-all` is every scope at its highest level, and id-token has no level
// above write, so it is implied.
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
  for (const [scope, level] of Object.entries(record)) {
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
// ---------------------------------------------------------------------------

export type TerraformTrust =
  | {
    readonly kind: "trusted";
    readonly providers: readonly string[];
    readonly workflows: ReadonlySet<string>;
  }
  | { readonly kind: "invalid"; readonly failures: readonly string[] };

// Both the `==` form and the legacy `startsWith(` form are matched.
const workflowTrustPattern =
  /assertion\.job_workflow_ref(?:\.startsWith\()?\s*(?:==\s*)?'collinbentley1\/platform\/\.github\/workflows\/([\w.-]+\.ya?ml)@/g;

// One byte per source character: code, string text, or comment. Blanking
// comments and marking strings is what stops a brace inside a string from
// closing a block and a decoy inside a comment from matching anything.
const code = 0;
const text = 1;
const comment = 2;
const quote = 3;

interface HclFile {
  readonly mask: Uint8Array;
  readonly path: string;
  readonly text: string;
}

type HclFrame =
  | { readonly kind: "string" }
  | { readonly kind: "heredoc"; readonly marker: string }
  | { readonly kind: "template"; depth: number };

const heredocMarker = /<<-?([A-Za-z_][A-Za-z0-9_-]*)[ \t]*\r?\n/y;

function lineOf(source: string, index: number): number {
  return source.slice(0, index).split("\n").length;
}

function lexHcl(
  path: string,
  source: string,
): { readonly kind: "lexed"; readonly file: HclFile } | { readonly kind: "invalid"; readonly failure: string } {
  const mask = new Uint8Array(source.length);
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
      index += 2;
      stack.push({ depth: 0, kind: "template" });
      continue;
    }
    index += 1;
  }
  const open = stack.at(-1);
  if (open !== undefined) {
    return { failure: `${path}: unterminated ${open.kind} at end of file.`, kind: "invalid" };
  }
  return { file: { mask, path, text: source }, kind: "lexed" };
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

// The index just past the `}` matching the `{` at `open`, counting only
// braces that are code.
function closingBrace(file: HclFile, open: number, end: number): number | undefined {
  let depth = 0;
  for (let index = open; index < end; index += 1) {
    if (!isCode(file, index)) continue;
    const character = file.text.charAt(index);
    if (character === "{") depth += 1;
    else if (character === "}") {
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
    const close = closingBrace(file, index, end);
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

// `local.NAME` counts only where it is code: bare in the expression or inside
// a `${ }` interpolation. The same text inside plain string content is prose
// that Terraform would never evaluate.
function localReferences(file: HclFile, start: number, end: number): string[] {
  let projected = "";
  for (let index = start; index < end; index += 1) {
    projected += isCode(file, index) ? file.text.charAt(index) : " ";
  }
  const names: string[] = [];
  for (const match of projected.matchAll(localReference)) {
    if (match[1] !== undefined) names.push(match[1]);
  }
  return names;
}

interface LocalDefinition {
  readonly attribute: HclAttribute;
  readonly file: HclFile;
}

export function trustedWorkflowsFromTerraform(files: ReadonlyMap<string, string>): TerraformTrust {
  const failures: string[] = [];
  const parsed: Array<{ readonly body: HclBody; readonly file: HclFile }> = [];
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

  const providers: string[] = [];
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
      const pending: LocalDefinition[] = [{ attribute: condition, file }];
      const visited = new Set<string>();
      const resolved: string[] = [];
      let unresolved = false;
      while (pending.length > 0) {
        const current = pending.pop();
        if (current === undefined) break;
        resolved.push(visibleText(current.file, current.attribute.start, current.attribute.end));
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
          pending.push(definition);
        }
      }
      if (unresolved) continue;

      const names = new Set<string>();
      for (const match of resolved.join("\n").matchAll(workflowTrustPattern)) {
        if (match[1] !== undefined) names.add(match[1]);
      }
      if (names.size === 0) {
        failures.push(
          `${display} has an attribute_condition that names no workflow through assertion.job_workflow_ref; the trust cannot be cross-checked.`,
        );
        continue;
      }
      for (const name of names) workflows.add(name);
    }
  }

  if (providers.length === 0) {
    failures.push(
      "no google_iam_workload_identity_pool_provider block was found in any Terraform file; the authority inventory cannot be cross-checked.",
    );
  }
  return failures.length > 0 ? { failures, kind: "invalid" } : { kind: "trusted", providers, workflows };
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
