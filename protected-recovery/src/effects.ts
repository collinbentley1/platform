import type { Ledger } from "./ledger";
import {
  type Entry,
  type ExpectedSnapshot,
  type Intent,
  type ObservedSnapshot,
  type Target,
  canonicalJson,
  isRecord,
  managedRole,
  sha256Hex,
} from "./model";

// The one external effect: a compare-and-set of one target service account's
// IAM allow policy that adds or removes exactly the managed members of the
// managed role. The sequence is always PREPARE (Firestore) -> setIamPolicy
// with the prepared etag (IAM) -> ACK (Firestore). Every ambiguous answer is
// classified against the complete prepared before snapshot (bindings + etag)
// and the complete expected after snapshot; the operation is never recomputed
// against a newer policy.

export interface PolicyCondition {
  readonly description: string;
  readonly expression: string;
  readonly title: string;
}

export interface PolicyBinding {
  readonly condition: PolicyCondition | null;
  readonly members: readonly string[];
  readonly role: string;
}

export interface Policy {
  readonly bindings: readonly PolicyBinding[];
  readonly etag: string;
  readonly version: number;
}

export type ReadOutcome =
  | { readonly kind: "read"; readonly policy: Policy }
  | { readonly kind: "unavailable"; readonly reason: string };

export type WriteOutcome =
  | { readonly kind: "written"; readonly policy: Policy }
  | { readonly kind: "conflict"; readonly status: number }
  | { readonly kind: "lost"; readonly reason: string }
  | { readonly kind: "refused"; readonly status: number };

export interface ServiceAccountIam {
  getPolicy(resource: string): Promise<ReadOutcome>;
  setPolicy(resource: string, policy: Policy): Promise<WriteOutcome>;
}

export type DriveOutcome =
  | { readonly kind: "acked"; readonly entry: Entry }
  | { readonly kind: "diverged"; readonly entry: Entry; readonly reason: string }
  | { readonly kind: "pending"; readonly entry: Entry; readonly reason: string }
  // The recorded operation moved on without this actuator: nothing was written.
  | { readonly kind: "stale"; readonly entry: Entry }
  | { readonly kind: "terminal"; readonly entry: Entry };

// Roles on the target itself that issue or refresh its credentials by some
// path other than the modeled one. They are never touched, only reported.
const credentialRoles = [
  "roles/iam.serviceAccountAdmin",
  "roles/iam.serviceAccountKeyAdmin",
  "roles/iam.serviceAccountOpenIdTokenCreator",
  "roles/iam.serviceAccountTokenCreator",
  "roles/iam.serviceAccountUser",
];

export type Plan =
  | { readonly after: readonly PolicyBinding[]; readonly alternateIssuers: readonly string[] }
  | { readonly divergence: string };

// The exact managed members must be all present (QUARANTINE) or all absent
// (RESTORE); a member of the consumer's own pool that the inventory does not
// model is a divergence, and every other credential-issuing grant is preserved
// and reported as an alternate issuer.
export function planEffect(intent: Intent, policy: Policy, target: Target): Plan {
  const poolPrefixes = [`principalSet://iam.googleapis.com/${target.pool}/`, `principal://iam.googleapis.com/${target.pool}/`];
  const managed = policy.bindings.find((binding) => binding.role === managedRole && binding.condition === null);
  const current = managed?.members ?? [];
  const present = target.members.filter((member) => current.includes(member));
  const unmodeled = current.filter((member) => poolPrefixes.some((prefix) => member.startsWith(prefix)) && !target.members.includes(member));
  if (unmodeled.length > 0) return { divergence: `unmodeled federated members of the consumer pool: ${unmodeled.join(", ")}` };
  const alternateIssuers: string[] = [];
  for (const binding of policy.bindings) {
    const foreign = binding === managed
      ? binding.members.filter((member) => !target.members.includes(member))
      : binding.role === managedRole || credentialRoles.includes(binding.role)
        ? binding.members
        : [];
    alternateIssuers.push(...foreign.map((member) => `${binding.role}${binding.condition ? `[${binding.condition.title}]` : ""}:${member}`));
  }
  let members: readonly string[];
  if (intent === "QUARANTINE") {
    const missing = target.members.filter((member) => !current.includes(member));
    if (missing.length > 0) return { divergence: `managed members are not exactly present; missing ${missing.join(", ")}` };
    members = current.filter((member) => !target.members.includes(member));
  } else {
    if (present.length > 0) return { divergence: `managed members are already present: ${present.join(", ")}` };
    members = [...current, ...target.members];
  }
  const others = policy.bindings.filter((binding) => binding !== managed);
  const after = members.length > 0 ? [...others, { condition: null, members, role: managedRole }] : others;
  return { after: canonicalBindings(after), alternateIssuers: alternateIssuers.sort() };
}

export function observedSnapshot(policy: Policy): ObservedSnapshot {
  return { ...expectedSnapshot(policy.bindings), etag: policy.etag };
}

export function expectedSnapshot(bindings: readonly PolicyBinding[]): ExpectedSnapshot {
  const text = canonicalJson(bindingsJson(canonicalBindings(bindings)));
  return { hash: sha256Hex(text), policy: text };
}

// Drive one effect entry as far as the world allows. Nothing here runs inside
// a Firestore transaction; each ledger call is its own committed step, and
// each step is conditional on the recorded effect ID and actuator epoch.
export async function driveEffect(ledger: Ledger, iam: ServiceAccountIam, shard: string, initial: Entry, target: Target): Promise<DriveOutcome> {
  let entry = initial;
  if (entry.body.kind !== "effect" || entry.progress === null) return { kind: "terminal", entry };
  if (entry.progress.state === "ACKED" || entry.progress.state === "DIVERGED") return { kind: "terminal", entry };
  const intent = entry.body.intent;

  if (entry.progress.state === "RECORDED") {
    const reservation = await ledger.reserveActuator(shard, entry.sequence, target.email);
    if (reservation.kind === "held") return { kind: "pending", entry, reason: `actuator held by ${reservation.holder.shard}/${reservation.holder.sequence}` };
    if (reservation.kind === "unchanged") return { kind: "stale", entry: reservation.entry };
    const read = await iam.getPolicy(target.resource);
    if (read.kind === "unavailable") return { kind: "pending", entry, reason: read.reason };
    const plan = planEffect(intent, read.policy, target);
    const facts = { effectId: reservation.effectId, epoch: reservation.epoch };
    if ("divergence" in plan) {
      const diverged = await ledger.divergeEffect(shard, entry.sequence, { ...facts, observed: observedSnapshot(read.policy), reason: plan.divergence });
      return diverged.kind === "transitioned" ? { kind: "diverged", entry: diverged.entry, reason: plan.divergence } : { kind: "stale", entry: diverged.entry };
    }
    const prepared = await ledger.prepareEffect(shard, entry.sequence, { ...facts, after: expectedSnapshot(plan.after), alternateIssuers: plan.alternateIssuers, before: observedSnapshot(read.policy) });
    if (prepared.kind === "unchanged") return { kind: "stale", entry: prepared.entry };
    entry = prepared.entry;
  }

  const progress = entry.progress;
  if (progress === null || progress.state !== "PREPARED") return { kind: "terminal", entry };
  const facts = { effectId: progress.effectId, epoch: progress.epoch };
  const attempt = await ledger.recordAttempt(shard, entry.sequence, facts);
  if (attempt.kind === "unchanged") return { kind: "stale", entry: attempt.entry };
  entry = attempt.entry;
  const written = await iam.setPolicy(target.resource, { bindings: bindingsFromSnapshot(progress.after.policy), etag: progress.before.etag, version: 3 });
  if (written.kind === "written") {
    const observed = observedSnapshot(written.policy);
    if (observed.hash !== progress.after.hash) return await diverge(ledger, shard, entry, facts, observed, "the returned policy is not the expected after state");
    return await acknowledge(ledger, shard, entry, facts, observed, true);
  }
  if (written.kind === "refused") return { kind: "pending", entry, reason: `setIamPolicy refused with HTTP ${written.status}` };
  // Conflict or lost response: only the resource itself says what happened.
  const read = await iam.getPolicy(target.resource);
  if (read.kind === "unavailable") return { kind: "pending", entry, reason: `${written.kind}; ${read.reason}` };
  const observed = observedSnapshot(read.policy);
  if (observed.hash === progress.after.hash) return await acknowledge(ledger, shard, entry, facts, observed, written.kind === "lost");
  if (observed.hash === progress.before.hash && observed.etag === progress.before.etag) {
    return { kind: "pending", entry, reason: `${written.kind}; the policy is still exactly the prepared before state` };
  }
  return await diverge(ledger, shard, entry, facts, observed, `${written.kind}; the observed policy is neither the exact before nor the expected after state`);
}

async function acknowledge(ledger: Ledger, shard: string, entry: Entry, facts: { readonly effectId: string; readonly epoch: number }, observed: ObservedSnapshot, mutated: boolean): Promise<DriveOutcome> {
  const outcome = await ledger.acknowledgeEffect(shard, entry.sequence, { ...facts, mutated, observed });
  return outcome.kind === "transitioned" ? { kind: "acked", entry: outcome.entry } : { kind: "stale", entry: outcome.entry };
}

async function diverge(ledger: Ledger, shard: string, entry: Entry, facts: { readonly effectId: string; readonly epoch: number }, observed: ObservedSnapshot, reason: string): Promise<DriveOutcome> {
  const outcome = await ledger.divergeEffect(shard, entry.sequence, { ...facts, observed, reason });
  return outcome.kind === "transitioned" ? { kind: "diverged", entry: outcome.entry, reason } : { kind: "stale", entry: outcome.entry };
}

const policyKeys = ["bindings", "etag", "version"];
const bindingKeys = ["condition", "members", "role"];
const conditionKeys = ["description", "expression", "title"];

// A policy is parsed against a closed key set and put into canonical order so
// that equal policies hash equally regardless of the order IAM returns them.
export function policyFromJson(value: unknown): Policy {
  const policy = strictRecord(value, "policy", policyKeys);
  const etag = policy.etag;
  if (typeof etag !== "string" || etag.length === 0) throw new Error("policy.etag must be a non-empty string");
  const version = policy.version === undefined ? 1 : policy.version;
  if (typeof version !== "number" || ![1, 3].includes(version)) throw new Error("policy.version must be 1 or 3");
  const rawBindings = policy.bindings === undefined ? [] : policy.bindings;
  if (!Array.isArray(rawBindings)) throw new Error("policy.bindings must be a list");
  const bindings = rawBindings.map((raw, index) => {
    const binding = strictRecord(raw, `policy.bindings[${index}]`, bindingKeys);
    if (typeof binding.role !== "string" || !/^(?:roles|projects|organizations)\/[A-Za-z0-9._/-]+$/.test(binding.role)) throw new Error(`policy.bindings[${index}].role must be a role name`);
    const members = binding.members === undefined ? [] : binding.members;
    if (!Array.isArray(members) || !members.every((member): member is string => typeof member === "string" && member.length > 0)) {
      throw new Error(`policy.bindings[${index}].members must be a list of principals`);
    }
    let condition: PolicyCondition | null = null;
    if (binding.condition !== undefined && binding.condition !== null) {
      const raw = strictRecord(binding.condition, `policy.bindings[${index}].condition`, conditionKeys);
      if (typeof raw.expression !== "string" || typeof raw.title !== "string") throw new Error(`policy.bindings[${index}].condition must carry expression and title`);
      condition = { description: typeof raw.description === "string" ? raw.description : "", expression: raw.expression, title: raw.title };
    }
    return { condition, members, role: binding.role };
  });
  return { bindings: canonicalBindings(bindings), etag, version };
}

export function policyJson(policy: Policy): Record<string, unknown> {
  return { bindings: bindingsJson(policy.bindings), etag: policy.etag, version: policy.version };
}

function bindingsJson(bindings: readonly PolicyBinding[]): unknown[] {
  return bindings.map((binding) => ({
    ...(binding.condition ? { condition: { ...binding.condition } } : {}),
    members: [...binding.members],
    role: binding.role,
  }));
}

export function bindingsFromSnapshot(text: string): readonly PolicyBinding[] {
  return policyFromJson({ bindings: JSON.parse(text) as unknown, etag: "-", version: 3 }).bindings;
}

function canonicalBindings(bindings: readonly PolicyBinding[]): readonly PolicyBinding[] {
  return bindings
    .map((binding) => ({ ...binding, members: [...new Set(binding.members)].sort() }))
    .filter((binding) => binding.members.length > 0)
    .sort((left, right) => bindingOrder(left).localeCompare(bindingOrder(right)));
}

function bindingOrder(binding: PolicyBinding): string {
  return canonicalJson({ condition: binding.condition, role: binding.role });
}

function strictRecord(value: unknown, label: string, keys: readonly string[]): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (!keys.includes(key)) throw new Error(`${label}.${key} is not a known field`);
  }
  return value;
}

export interface GoogleIamDependencies {
  readonly baseUrl?: string;
  readonly fetch: typeof fetch;
  readonly token: () => Promise<string>;
}

const maxResourceBytes = 256 * 1024;
const conflictStatuses = [409, 412];

// The IAM API client: getIamPolicy at requested policy version 3, and
// setIamPolicy of the full version-3 policy with the prepared etag and the
// explicit update mask. Anything unexpected is unavailable, never a snapshot.
export class GoogleServiceAccountIam implements ServiceAccountIam {
  readonly #deps: GoogleIamDependencies;
  readonly #baseUrl: string;

  constructor(deps: GoogleIamDependencies) {
    this.#deps = deps;
    this.#baseUrl = deps.baseUrl ?? "https://iam.googleapis.com";
  }

  async getPolicy(resource: string): Promise<ReadOutcome> {
    const response = await this.#post(`${resource}:getIamPolicy`, { options: { requestedPolicyVersion: 3 } });
    if (response.kind === "unreachable") return { kind: "unavailable", reason: response.reason };
    if (!response.ok) return { kind: "unavailable", reason: `HTTP ${response.status}` };
    try {
      return { kind: "read", policy: policyFromJson(response.body) };
    } catch (error) {
      return { kind: "unavailable", reason: String(error instanceof Error ? error.message : error) };
    }
  }

  async setPolicy(resource: string, policy: Policy): Promise<WriteOutcome> {
    const response = await this.#post(`${resource}:setIamPolicy`, { policy: policyJson(policy), updateMask: "bindings,etag" });
    if (response.kind === "unreachable") return { kind: "lost", reason: response.reason };
    if (response.ok) {
      try {
        return { kind: "written", policy: policyFromJson(response.body) };
      } catch (error) {
        return { kind: "lost", reason: `written but the returned policy is malformed: ${String(error instanceof Error ? error.message : error)}` };
      }
    }
    if (conflictStatuses.includes(response.status)) return { kind: "conflict", status: response.status };
    if (response.status >= 500) return { kind: "lost", reason: `HTTP ${response.status}` };
    return { kind: "refused", status: response.status };
  }

  async #post(path: string, body: unknown): Promise<{ readonly kind: "response"; readonly ok: boolean; readonly status: number; readonly body: unknown } | { readonly kind: "unreachable"; readonly reason: string }> {
    let response: Response;
    try {
      response = await this.#deps.fetch(`${this.#baseUrl}/v1/${path}`, {
        body: JSON.stringify(body),
        headers: { Authorization: `Bearer ${await this.#deps.token()}`, "Content-Type": "application/json" },
        method: "POST",
        redirect: "error",
      });
    } catch (error) {
      return { kind: "unreachable", reason: String(error) };
    }
    let bytes: Uint8Array;
    try {
      bytes = new Uint8Array(await response.arrayBuffer());
    } catch (error) {
      return { kind: "unreachable", reason: `response body lost: ${String(error)}` };
    }
    if (bytes.byteLength > maxResourceBytes) return { kind: "response", ok: false, status: response.status, body: undefined };
    let parsed: unknown;
    try {
      parsed = bytes.byteLength === 0 ? undefined : (JSON.parse(new TextDecoder().decode(bytes)) as unknown);
    } catch {
      return { kind: "response", ok: false, status: response.status, body: undefined };
    }
    return { kind: "response", ok: response.ok, status: response.status, body: parsed };
  }
}
