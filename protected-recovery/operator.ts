import { lstat, mkdir, open, readFile, rename } from "node:fs/promises";
import { join } from "node:path";
import { canonicalJson, roundId, type RoundPhase, type RoundRuns } from "./src/model.ts";

export async function readJsonFile(path: string): Promise<unknown> {
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink() || info.size > 4 * 1024 * 1024) throw new Error("operator JSON must be a regular file of at most 4 MiB");
  const bytes = await readFile(path);
  if (bytes.byteLength > 4 * 1024 * 1024) throw new Error("operator JSON exceeds 4 MiB");
  return JSON.parse(bytes.toString("utf8"));
}

export function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("expected a JSON object");
  return value as Record<string, unknown>;
}
export function string(value: unknown): string {
  if (typeof value !== "string") throw new Error("expected a string");
  return value;
}
export function strings(value: unknown): string[] {
  if (!Array.isArray(value)) throw new Error("expected a string array");
  return value.map(string);
}
export function exact(actual: unknown, expected: unknown, label: string): void {
  if (canonicalJson(actual) !== canonicalJson(expected)) throw new Error(`${label} does not match the saved request`);
}
export function timestamp(value: unknown): number {
  const text = string(value);
  const epoch = Date.parse(text);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(text) || !Number.isFinite(epoch) || new Date(epoch).toISOString().replace(".000Z", "Z") !== text.replace(".000Z", "Z")) throw new Error("expected a canonical UTC timestamp");
  return epoch;
}

export interface Coordinates {
  readonly repository: string;
  readonly consumer: string;
  readonly phase: RoundPhase;
  readonly shard: string | null;
  readonly label: string;
  readonly round: string;
}
export function coordinates(args: readonly string[]): Coordinates {
  const [repository, phase, shard, label] = args;
  if (args.length !== 4 || !repository || !/^[\w.-]+\/[\w.-]+$/.test(repository) || !label || !/^[a-z0-9][a-z0-9-]{0,40}$/.test(label)) throw new Error("usage: orchestrate-deliveries.sh [--cleanup] owner/consumer CONTROL|REVOCATION|HORIZON shard|- label");
  if (phase !== "CONTROL" && phase !== "REVOCATION" && phase !== "HORIZON") throw new Error("invalid phase");
  if (!shard || !/^(-|[a-z0-9][a-z0-9-]{0,62})$/.test(shard) || (phase === "CONTROL") !== (shard === "-")) throw new Error("invalid phase/shard pair");
  const consumer = repository.slice(repository.indexOf("/") + 1);
  const boundShard = shard === "-" ? null : shard;
  return { repository, consumer, phase, shard: boundShard, label, round: roundId(consumer, phase, boundShard, label) };
}

export interface Invocation {
  readonly consumer: string;
  readonly direction: "quarantine";
  readonly operation: string;
  readonly shard: string;
  readonly argument: string;
}
export function replyEnvelope(value: unknown, nonce: string, runId: string, request: Invocation): Record<string, unknown> {
  const envelope = object(value);
  exact(envelope.nonce, nonce, "reply nonce");
  exact(envelope.runId, runId, "reply run");
  exact(envelope.runAttempt, "1", "reply attempt");
  exact(envelope.request, request, "reply request");
  return object(envelope.reply);
}
export function roundReply(value: unknown, expected: Coordinates): Record<string, unknown> {
  const round = object(object(value).round);
  for (const key of ["consumer", "phase", "shard", "label", "round"] as const) exact(round[key], expected[key], `round ${key}`);
  if (typeof round.complete !== "boolean" || typeof round.phaseReady !== "boolean") throw new Error("round has no authoritative readiness result");
  const expiresAt = timestamp(round.expiresAt);
  if (round.openedAt !== undefined && timestamp(round.openedAt) >= expiresAt) throw new Error("round validity interval is empty");
  if (round.expiredAt !== null || expiresAt <= Date.now()) throw new Error("round expired; retain its journal and use a new label");
  strings(round.members);
  return round;
}
export function completeRound(round: Record<string, unknown>, runs: RoundRuns): void {
  if (round.expiredAt !== null || timestamp(round.expiresAt) <= Date.now()) throw new Error("round expired before completion");
  exact(round.complete, true, "round completion");
  exact(round.phaseReady, true, "named phase readiness");
  exact(round.blockers, [], "current phase blockers");
  exact(round.owed, [], "delivery debt");
  exact(round.runs, runs, "broker trigger binding");
  const receipts = object(round.receipts);
  exact(Object.keys(receipts).sort(), Object.keys(runs).sort(), "receipt members");
  for (const [member, expected] of Object.entries(runs)) {
    const receipt = object(receipts[member]);
    exact(receipt.runId, expected.runId, "receipt run");
    exact(receipt.runAttempt, expected.runAttempt, "receipt attempt");
  }
}

export interface Run {
  readonly id: string;
  readonly attempt: string;
  readonly event: string;
  readonly head: string;
  readonly title: string;
  readonly created: string;
  readonly path: string;
}
export function parseRuns(value: unknown): Run[] {
  const raw = object(value).workflow_runs;
  if (!Array.isArray(raw) || raw.length > 100) throw new Error("GitHub did not return one bounded workflow run page");
  return raw.map((value) => {
    const r = object(value);
    if (!Number.isSafeInteger(r.id) || Number(r.id) < 1 || !Number.isSafeInteger(r.run_attempt) || Number(r.run_attempt) < 1) throw new Error("invalid workflow run identity");
    timestamp(r.created_at);
    if (!/^[0-9a-f]{40}$/.test(string(r.head_sha))) throw new Error("invalid workflow head SHA");
    return { id: String(r.id), attempt: String(r.run_attempt), event: string(r.event), head: string(r.head_sha), title: string(r.display_title), created: string(r.created_at), path: string(r.path).split("@")[0]! };
  });
}
export function selectRun(runs: readonly Run[], expected: { path: string; event: string; head: string; title: string | null; after: string }): Run | null {
  const after = timestamp(expected.after);
  const matches = runs.filter((r) => r.path === expected.path && r.event === expected.event && r.head === expected.head && (expected.title === null || r.title === expected.title) && timestamp(r.created) >= after);
  if (matches.length > 1) throw new Error(`ambiguous exact run set for ${expected.path}; retained journal requires reconciliation`);
  const run = matches[0] ?? null;
  if (run && run.attempt !== "1") throw new Error("a rerun cannot satisfy a fresh delivery trigger");
  return run;
}

export const callerUses: Readonly<Record<string, readonly string[]>> = {
  "deploy-prod.yml": ["deploy-prod.yml", "infrastructure.yml"],
  "deploy-preview.yml": ["cleanup-preview.yml", "deploy-preview.yml"],
  "cleanup-preview.yml": ["cleanup-preview.yml"],
  "reconcile-previews.yml": ["reconcile-previews.yml"],
};
const callerDhiSecretJobs: Readonly<Record<string, readonly string[]>> = {
  "deploy-prod.yml": ["deploy"],
  "deploy-preview.yml": ["invalidate", "deploy"],
  "cleanup-preview.yml": ["cleanup"],
  "reconcile-previews.yml": ["reconcile"],
};
const callerJobUses: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  "deploy-prod.yml": { infrastructure: "infrastructure.yml", deploy: "deploy-prod.yml" },
  "deploy-preview.yml": { invalidate: "cleanup-preview.yml", deploy: "deploy-preview.yml" },
  "cleanup-preview.yml": { cleanup: "cleanup-preview.yml" },
  "reconcile-previews.yml": { reconcile: "reconcile-previews.yml" },
};
const callerDhiSecretMapping: Readonly<Record<string, string>> = {
  DHI_PUBLIC_READ_TOKEN_20260822_098DCA9280B3:
    "${{ secrets.DHI_PUBLIC_READ_TOKEN_20260822_098DCA9280B3 }}",
};
export function callerPins(content: string, file: string, platform: string, pins: readonly string[]): Record<string, string> {
  const document = object(Bun.YAML.parse(content));
  const jobs = object(document.jobs);
  const calls = Object.values(jobs).flatMap((value) => {
    const use = object(value).uses;
    return typeof use === "string" && use.startsWith(`${platform}/.github/workflows/`) ? [use] : [];
  });
  const found: Record<string, string> = {};
  for (const use of calls) {
    const [path, sha] = use.split("@");
    if (!path || !sha || !/^[0-9a-f]{40}$/.test(sha) || !pins.includes(sha)) throw new Error(`unrecorded platform pin in ${file}`);
    const workflow = path.slice(`${platform}/.github/workflows/`.length);
    if (found[workflow]) throw new Error(`duplicate platform caller in ${file}`);
    found[workflow] = sha;
  }
  exact(Object.keys(found).sort(), [...(callerUses[file] ?? [])].sort(), `mandatory calls in ${file}`);
  const expectedJobUses = callerJobUses[file] ?? {};
  exact(Object.keys(jobs).sort(), Object.keys(expectedJobUses).sort(), `mandatory jobs in ${file}`);
  for (const [jobName, workflow] of Object.entries(expectedJobUses)) {
    exact(
      object(jobs[jobName]).uses,
      `${platform}/.github/workflows/${workflow}@${found[workflow]}`,
      `${file} ${jobName} reusable call`,
    );
  }
  const secretJobs = callerDhiSecretJobs[file] ?? [];
  for (const [jobName, value] of Object.entries(jobs)) {
    const job = object(value);
    if (secretJobs.includes(jobName)) {
      if (!("secrets" in job)) {
        throw new Error(`${file} ${jobName} DHI secret mapping is missing`);
      }
      exact(job.secrets, callerDhiSecretMapping, `${file} ${jobName} DHI secret mapping`);
    } else if ("secrets" in job) {
      throw new Error(`${file} ${jobName} must not forward secrets`);
    }
  }
  const events = object(document.on);
  if (file === "deploy-prod.yml" || file === "reconcile-previews.yml") {
    exact(events.push, { branches: ["main"] }, `${file} push trigger`);
  }
  if (file === "reconcile-previews.yml") {
    exact(Object.keys(document).sort(), ["jobs", "name", "on", "permissions", "run-name"], "reconcile top-level shape");
    exact(document.name, "Reconcile previews", "reconcile workflow name");
    exact(document.permissions, {}, "reconcile workflow permissions");
    exact(Object.keys(jobs), ["reconcile"], "reconcile job set");
    const reconcile = object(jobs.reconcile);
    exact(Object.keys(reconcile).sort(), ["permissions", "secrets", "uses"], "reconcile job shape");
    exact(reconcile.permissions, { actions: "read", "id-token": "write", "pull-requests": "read" }, "reconcile job permissions");
    exact(document["run-name"], "${{ inputs.delivery_nonce && format('recovery-dispatch-{0}', inputs.delivery_nonce) || github.workflow }}", "reconcile run-name");
    exact(Object.keys(events).sort(), ["push", "schedule", "workflow_dispatch"], "reconcile event set");
    const dispatch = object(events.workflow_dispatch);
    exact(Object.keys(dispatch), ["inputs"], "reconcile dispatch shape");
    const inputs = object(dispatch.inputs);
    exact(Object.keys(inputs), ["delivery_nonce"], "reconcile dispatch inputs");
    exact(object(inputs.delivery_nonce), {
      description: "Correlation nonce for a protected recovery delivery round.",
      required: false,
      type: "string",
    }, "reconcile delivery nonce input");
    const schedules = events.schedule;
    if (!Array.isArray(schedules) || schedules.length !== 1 || !/^[0-5]?[0-9] \* \* \* \*$/.test(string(object(schedules[0]).cron))) throw new Error("reconcile delivery requires one hourly schedule");
  }
  if (file === "deploy-preview.yml" || file === "cleanup-preview.yml") {
    exact(document["run-name"], "recovery-event-${{ github.event.action }}-${{ github.event.pull_request.number }}-${{ github.event.pull_request.head.sha }}", "preview run-name");
    const event = object(events.pull_request_target);
    exact(Object.keys(event).sort(), ["branches", "types"], "preview trigger filters");
    exact(event.branches, ["main"], "preview base branch");
    const types = strings(event.types);
    for (const required of file === "cleanup-preview.yml" ? ["closed"] : ["opened", "synchronize"]) if (!types.includes(required)) throw new Error(`${file} omits the ${required} lifecycle event`);
  }
  return found;
}
export function memberTrigger(member: string, repository: string, pins: Readonly<Record<string, Readonly<Record<string, string>>>>): string {
  const tuple = member.split("/attribute.authority/")[1]?.split(":");
  if (!tuple || tuple.length !== 5) throw new Error("unrecognized member tuple");
  const [caller, reusable, sha, , event] = tuple;
  const prefix = `${repository}/.github/workflows/`;
  if (!caller?.startsWith(prefix) || !caller.endsWith("@refs/heads/main")) throw new Error("member is not a main-branch caller of this consumer");
  const file = caller.slice(prefix.length).split("@")[0]!;
  const reusedFile = reusable?.split("/.github/workflows/")[1]?.split("@")[0];
  if (!reusedFile || pins[file]?.[reusedFile] !== sha) throw new Error("manifest member has no current caller at its exact platform pin; finish the pin transition first");
  if (event === "push") return `push-${file}`;
  if (event === "schedule" && file === "reconcile-previews.yml") return "schedule";
  if (event === "workflow_dispatch" && file === "reconcile-previews.yml") return "dispatch";
  if (event === "pull_request_target" && file === "cleanup-preview.yml") return "closed";
  if (event === "pull_request_target" && file === "deploy-preview.yml") return reusedFile === "cleanup-preview.yml" ? "synchronize" : "opened";
  throw new Error("no exact trigger for manifest member");
}

export function ownedPullRequest(value: unknown, expected: { repository: string; branch: string; title: string; heads: readonly string[] }): { number: number; state: string; head: string } {
  const pr = object(value);
  const head = object(pr.head);
  const base = object(pr.base);
  exact(pr.title, expected.title, "pull request title");
  exact(object(head.repo).full_name, expected.repository, "pull request head repository");
  exact(head.ref, expected.branch, "pull request head ref");
  exact(object(base.repo).full_name, expected.repository, "pull request base repository");
  exact(base.ref, "main", "pull request base ref");
  const sha = string(head.sha);
  if (!expected.heads.includes(sha)) throw new Error("recovery pull request head changed; preserve it for manual review");
  if (!Number.isSafeInteger(pr.number) || Number(pr.number) < 1 || (pr.state !== "open" && pr.state !== "closed")) throw new Error("invalid recovery pull request state");
  return { number: Number(pr.number), state: pr.state, head: sha };
}

// Each stage is immutable. Intent is fsynced before a remote mutation; ambiguous
// dispatches are reconciled by nonce and never sent a second time on restart.
export class Journal {
  constructor(readonly directory: string) {}
  async read(key: string): Promise<unknown | undefined> {
    try { return await readJsonFile(join(this.directory, `${key}.json`)); }
    catch (error) { if (error instanceof Error && "code" in error && error.code === "ENOENT") return undefined; throw error; }
  }
  async write(key: string, value: unknown): Promise<void> {
    if (!/^[a-z0-9-]+$/.test(key)) throw new Error("invalid journal stage");
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const existing = await this.read(key);
    if (existing !== undefined) { exact(existing, value, `immutable journal stage ${key}`); return; }
    const temporary = join(this.directory, `${key}.${process.pid}.tmp`);
    const file = await open(temporary, "wx", 0o600);
    try { await file.writeFile(`${canonicalJson(value)}\n`); await file.sync(); } finally { await file.close(); }
    await rename(temporary, join(this.directory, `${key}.json`));
    const directory = await open(this.directory, "r");
    try { await directory.sync(); } finally { await directory.close(); }
  }
}
