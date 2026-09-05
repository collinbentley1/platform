import type { Ledger } from "./ledger";
import {
  type Consumer,
  type Entry,
  type ExpectedSnapshot,
  type Intent,
  type ObservedSnapshot,
  type ProbeOutcome,
  type RecoveryAuthority,
  type Target,
  canonicalJson,
  consumerPool,
  consumerProvider,
  isRecord,
  managedRole,
  probePermission,
  probePrerequisite,
  sha256Hex,
} from "./model";

// The one external effect: a compare-and-set of one target service account's
// IAM allow policy that adds or removes exactly the managed members of the
// managed role. The resource is addressed by the target's permanent unique
// ID, and before every read or write the identity IAM returns for it must be
// exactly the journaled email and unique ID. The sequence is always PREPARE
// (Firestore) -> setIamPolicy with the prepared etag (IAM) -> ACK (Firestore).
// Every ambiguous answer is classified against the complete prepared before
// snapshot (bindings + etag) and the complete expected after snapshot; the
// operation is never recomputed against a newer policy.

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

export type IdentityOutcome =
  | { readonly kind: "identity"; readonly email: string; readonly uniqueId: string }
  | { readonly kind: "unavailable"; readonly reason: string };

export interface ServiceAccountIam {
  getIdentity(resource: string): Promise<IdentityOutcome>;
  getPolicy(resource: string): Promise<ReadOutcome>;
  setPolicy(resource: string, policy: Policy): Promise<WriteOutcome>;
}

// A negative impersonation probe: an attempt of exactly the probe permission
// as the managed member against the exact target identity, performed by the
// broker itself, with the outcome observed by the broker. The result names
// the exact federated principal and the broker's observation time.
export interface ProbeRequest {
  readonly email: string;
  readonly member: string;
  readonly permission: typeof probePermission;
  readonly resource: string;
  readonly uniqueId: string;
}

export type ProbeResult =
  | { readonly kind: "observed"; readonly observedAt: string; readonly outcome: ProbeOutcome; readonly principal: string }
  | { readonly kind: "unavailable"; readonly reason: string };

// Whether the probe source can act as the managed member of every target
// right now: a positive control taken before a QUARANTINE is accepted and
// again before any of its effects is prepared, so that no binding is removed
// unless the observation that ends the quarantine can be made.
export type PreflightOutcome =
  | { readonly kind: "operational"; readonly principals: Readonly<Record<string, string>> }
  | { readonly kind: "unavailable"; readonly reason: string };

export interface ImpersonationProbe {
  preflight(targets: readonly Target[]): Promise<PreflightOutcome>;
  probe(request: ProbeRequest): Promise<ProbeResult>;
}

export type DriveOutcome =
  | { readonly kind: "acked"; readonly entry: Entry }
  | { readonly kind: "diverged"; readonly entry: Entry; readonly reason: string }
  | { readonly kind: "pending"; readonly entry: Entry; readonly reason: string }
  // The recorded operation moved on without this actuator: nothing was written.
  | { readonly kind: "stale"; readonly entry: Entry }
  | { readonly kind: "terminal"; readonly entry: Entry };

// Roles on the target itself that issue or refresh its credentials by some
// path other than the modeled one. They are never touched, only reported at
// PREPARE from the very policy the effect compare-and-sets; the credential
// inventory (inventory.ts) is the binding judgement, with role expansion.
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

// The identity IAM returns for the addressed resource must be exactly the
// journaled email and unique ID; anything else -- a recreated account at the
// same address, a misrecorded ID -- refuses the read and the write.
function identityMismatch(identity: IdentityOutcome & { readonly kind: "identity" }, target: Target): string | undefined {
  if (identity.uniqueId === target.uniqueId && identity.email === target.email) return undefined;
  return `the resource identity ${identity.email} (${identity.uniqueId}) is not the journaled target ${target.email} (${target.uniqueId})`;
}

// Drive one effect entry as far as the world allows. Nothing here runs inside
// a Firestore transaction; each ledger call is its own committed step, and
// each step is conditional on the recorded effect ID and actuator epoch.
export async function driveEffect(ledger: Ledger, iam: ServiceAccountIam, shard: string, initial: Entry, target: Target): Promise<DriveOutcome> {
  let entry = initial;
  if (entry.body.kind !== "effect" || entry.progress === null) return { kind: "terminal", entry };
  if (entry.progress.state === "ACKED" || entry.progress.state === "DIVERGED") return { kind: "terminal", entry };
  if (entry.body.uniqueId !== target.uniqueId || entry.body.email !== target.email || entry.body.resource !== target.resource) {
    throw new Error(`${shard}/${entry.sequence}: the journaled identity does not match the driven target.`);
  }
  const intent = entry.body.intent;

  if (entry.progress.state === "RECORDED") {
    const reservation = await ledger.reserveActuator(shard, entry.sequence, target.uniqueId);
    if (reservation.kind === "held") return { kind: "pending", entry, reason: `actuator held by ${reservation.holder.shard}/${reservation.holder.sequence}` };
    if (reservation.kind === "unchanged") return { kind: "stale", entry: reservation.entry };
    const facts = { effectId: reservation.effectId, epoch: reservation.epoch };
    const identity = await iam.getIdentity(target.resource);
    if (identity.kind === "unavailable") return { kind: "pending", entry, reason: identity.reason };
    const mismatch = identityMismatch(identity, target);
    if (mismatch !== undefined) {
      const diverged = await ledger.divergeEffect(shard, entry.sequence, { ...facts, observed: null, reason: mismatch });
      return diverged.kind === "transitioned" ? { kind: "diverged", entry: diverged.entry, reason: mismatch } : { kind: "stale", entry: diverged.entry };
    }
    const read = await iam.getPolicy(target.resource);
    if (read.kind === "unavailable") return { kind: "pending", entry, reason: read.reason };
    const plan = planEffect(intent, read.policy, target);
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
  // A takeover resumes here; the identity is verified again before the write.
  const identity = await iam.getIdentity(target.resource);
  if (identity.kind === "unavailable") return { kind: "pending", entry, reason: identity.reason };
  const mismatch = identityMismatch(identity, target);
  if (mismatch !== undefined) {
    const diverged = await ledger.divergeEffect(shard, entry.sequence, { ...facts, observed: null, reason: mismatch });
    return diverged.kind === "transitioned" ? { kind: "diverged", entry: diverged.entry, reason: mismatch } : { kind: "stale", entry: diverged.entry };
  }
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

export type JsonResponse =
  | { readonly kind: "response"; readonly ok: boolean; readonly status: number; readonly body: unknown }
  | { readonly kind: "unreachable"; readonly reason: string };

const maxResourceBytes = 4 * 1024 * 1024;

// One bounded JSON exchange with a Google API: a bearer token, an optional
// JSON body, and a parsed answer or an unreachable verdict. A body that is
// not JSON or exceeds the bound is a failed response, never a snapshot.
export async function sendJson(fetcher: typeof fetch, method: "GET" | "POST", url: string, body: unknown, bearer: string | undefined, headers: Readonly<Record<string, string>> = {}): Promise<JsonResponse> {
  let response: Response;
  try {
    response = await fetcher(url, {
      ...(method === "POST" ? { body: JSON.stringify(body) } : {}),
      headers: { ...headers, ...(bearer === undefined ? {} : { Authorization: `Bearer ${bearer}` }), ...(method === "POST" ? { "Content-Type": "application/json" } : {}) },
      method,
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

export interface GoogleIamDependencies {
  readonly baseUrl?: string;
  readonly fetch: typeof fetch;
  readonly token: () => Promise<string>;
}

const conflictStatuses = [409, 412];

// The IAM API client: serviceAccounts.get for the identity of the resource
// addressed by unique ID, getIamPolicy at requested policy version 3, and
// setIamPolicy of the full version-3 policy with the prepared etag and the
// explicit update mask. Anything unexpected is unavailable, never a snapshot.
export class GoogleServiceAccountIam implements ServiceAccountIam {
  readonly #deps: GoogleIamDependencies;
  readonly #baseUrl: string;

  constructor(deps: GoogleIamDependencies) {
    this.#deps = deps;
    this.#baseUrl = deps.baseUrl ?? "https://iam.googleapis.com";
  }

  async getIdentity(resource: string): Promise<IdentityOutcome> {
    const response = await sendJson(this.#deps.fetch, "GET", `${this.#baseUrl}/v1/${resource}`, undefined, await this.#deps.token());
    if (response.kind === "unreachable") return { kind: "unavailable", reason: response.reason };
    if (!response.ok) return { kind: "unavailable", reason: `HTTP ${response.status}` };
    const body = response.body;
    if (!isRecord(body) || typeof body.email !== "string" || typeof body.uniqueId !== "string" || !/^[1-9][0-9]*$/.test(body.uniqueId)) {
      return { kind: "unavailable", reason: "the service account response carries no email and unique ID" };
    }
    return { kind: "identity", email: body.email, uniqueId: body.uniqueId };
  }

  async getPolicy(resource: string): Promise<ReadOutcome> {
    const response = await sendJson(this.#deps.fetch, "POST", `${this.#baseUrl}/v1/${resource}:getIamPolicy`, { options: { requestedPolicyVersion: 3 } }, await this.#deps.token());
    if (response.kind === "unreachable") return { kind: "unavailable", reason: response.reason };
    if (!response.ok) return { kind: "unavailable", reason: `HTTP ${response.status}` };
    try {
      return { kind: "read", policy: policyFromJson(response.body) };
    } catch (error) {
      return { kind: "unavailable", reason: String(error instanceof Error ? error.message : error) };
    }
  }

  async setPolicy(resource: string, policy: Policy): Promise<WriteOutcome> {
    const response = await sendJson(this.#deps.fetch, "POST", `${this.#baseUrl}/v1/${resource}:setIamPolicy`, { policy: policyJson(policy), updateMask: "bindings,etag" }, await this.#deps.token());
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
}

// RS256 JSON Web Tokens verified against a JWKS: the shape every identity
// the broker trusts arrives in, from Google (its callers) and from GitHub
// (the canonical jobs whose credentials its probes act with).
export interface Jwk {
  readonly alg?: string;
  readonly e: string;
  readonly kid: string;
  readonly kty: string;
  readonly n: string;
  readonly use?: string;
}

export async function verifyRs256Jwt(token: string, jwks: readonly Jwk[]): Promise<Record<string, unknown> | undefined> {
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0 || part.length > 8192)) return undefined;
  const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];
  let header: unknown;
  let payload: unknown;
  try {
    header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString("utf8")) as unknown;
    payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8")) as unknown;
  } catch {
    return undefined;
  }
  if (!isRecord(header) || header.alg !== "RS256" || typeof header.kid !== "string") return undefined;
  const key = jwks.find((candidate) => candidate.kid === header.kid && candidate.kty === "RSA");
  if (!key) return undefined;
  let verified: boolean;
  try {
    const cryptoKey = await crypto.subtle.importKey("jwk", { e: key.e, kty: "RSA", n: key.n }, { hash: "SHA-256", name: "RSASSA-PKCS1-v1_5" }, false, ["verify"]);
    verified = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey, Buffer.from(encodedSignature, "base64url"), Buffer.from(`${encodedHeader}.${encodedPayload}`, "utf8"));
  } catch {
    return undefined;
  }
  return verified && isRecord(payload) ? payload : undefined;
}

export function cachedJwks(url: string, fetcher: typeof fetch, now: () => Date): () => Promise<readonly Jwk[]> {
  let cached: { readonly keys: readonly Jwk[]; readonly until: number } | undefined;
  return async () => {
    if (cached && cached.until > now().getTime()) return cached.keys;
    const response = await fetcher(url, { redirect: "error" });
    if (!response.ok) throw new Error(`JWKS fetch failed with HTTP ${response.status}.`);
    const body = JSON.parse(await response.text()) as unknown;
    const keys = isRecord(body) && Array.isArray(body.keys)
      ? body.keys.filter((key): key is Jwk => isRecord(key) && typeof key.kid === "string" && typeof key.n === "string" && typeof key.e === "string" && key.kty === "RSA")
      : [];
    const maxAge = /max-age=(\d+)/.exec(response.headers.get("cache-control") ?? "")?.[1];
    cached = { keys, until: now().getTime() + Math.min(Number(maxAge ?? "300"), 3600) * 1000 };
    return keys;
  };
}

export const githubIssuer = "https://token.actions.githubusercontent.com";
export const githubJwksUrl = `${githubIssuer}/.well-known/jwks`;
const clockSkewSeconds = 60;

// The credential of a managed member: the GitHub OIDC token of the one
// canonical job that is that member, minted for the consumer provider's
// audience. Only such a job can hold it, and only with it can the broker act
// as the member at STS and IAM Credentials.
export type MemberToken =
  | { readonly kind: "token"; readonly token: string }
  | { readonly kind: "unavailable"; readonly reason: string };

export interface MemberCredentialSource {
  oidcTokenFor(member: string): Promise<MemberToken>;
}

// The production binding until a consumer job delivers its token to the
// broker: every member's credential is unavailable, so every preflight fails
// and every QUARANTINE is refused before acceptance and before any mutation.
export const undeployedMemberCredentials: MemberCredentialSource = {
  oidcTokenFor: async () => ({ kind: "unavailable", reason: probePrerequisite }),
};

export interface IssuanceProbeDependencies {
  readonly authority: RecoveryAuthority;
  readonly credentials: MemberCredentialSource;
  readonly endpoints?: { readonly credentials?: string; readonly iam?: string; readonly sts?: string };
  readonly fetch: typeof fetch;
  // GitHub's JWKS, for the canonical jobs' OIDC tokens.
  readonly jwks: () => Promise<readonly Jwk[]>;
  readonly now: () => Date;
}

type Federated =
  | { readonly kind: "federated"; readonly accessToken: string; readonly principal: string }
  | { readonly kind: "unavailable"; readonly reason: string };

// The broker-verifiable issuance probe. For a managed member the broker
// verifies the canonical job's GitHub OIDC token against GitHub's JWKS,
// derives the member from the token's claims exactly as the consumer
// provider maps them and requires equality, exchanges the token at STS for
// the consumer pool, and then makes the IAM Credentials request itself
// against the target's permanent identity: generateAccessToken for a probe
// (ALLOWED on success, DENIED only on an IAM permission denial of exactly the
// probe permission, unavailable for anything else) and testIamPermissions
// for the preflight positive control. Every result is bound to the exact
// federated principal, the target unique ID, the member, the permission, the
// broker's clock, and the API's own answer; no analysis API stands in.
export class GoogleIssuanceProbe implements ImpersonationProbe {
  readonly #deps: IssuanceProbeDependencies;

  constructor(deps: IssuanceProbeDependencies) {
    this.#deps = deps;
  }

  async preflight(targets: readonly Target[]): Promise<PreflightOutcome> {
    const principals: Record<string, string> = {};
    const reasons: string[] = [];
    for (const target of targets) {
      const member = target.members[0];
      if (member === undefined) {
        reasons.push(`${target.account}: no managed member`);
        continue;
      }
      const federated = await this.#federated(target.resource, member);
      if (federated.kind === "unavailable") {
        reasons.push(`${target.account}: ${federated.reason}`);
        continue;
      }
      const response = await sendJson(this.#deps.fetch, "POST", `${this.#endpoint("iam")}/v1/projects/-/serviceAccounts/${target.uniqueId}:testIamPermissions`, { permissions: [probePermission] }, federated.accessToken);
      if (response.kind === "unreachable") {
        reasons.push(`${target.account}: ${response.reason}`);
        continue;
      }
      const granted = response.ok && isRecord(response.body) && Array.isArray(response.body.permissions) && response.body.permissions.includes(probePermission);
      if (!granted) {
        reasons.push(`${target.account}: the member is not affirmed for ${probePermission} on ${target.uniqueId} (HTTP ${response.status}); the probe cannot serve as a positive control`);
        continue;
      }
      principals[target.account] = federated.principal;
    }
    return reasons.length === 0 ? { kind: "operational", principals } : { kind: "unavailable", reason: reasons.join("; ") };
  }

  async probe(request: ProbeRequest): Promise<ProbeResult> {
    if (request.permission !== probePermission) return { kind: "unavailable", reason: `the probe permission is ${probePermission}` };
    const federated = await this.#federated(request.resource, request.member);
    if (federated.kind === "unavailable") return federated;
    const response = await sendJson(this.#deps.fetch, "POST", `${this.#endpoint("credentials")}/v1/projects/-/serviceAccounts/${request.uniqueId}:generateAccessToken`, { lifetime: "300s", scope: ["https://www.googleapis.com/auth/cloud-platform"] }, federated.accessToken);
    const observedAt = this.#deps.now().toISOString();
    if (response.kind === "unreachable") return { kind: "unavailable", reason: response.reason };
    // The minted token, if any, is never retained: the answer is the evidence.
    if (response.ok) return { kind: "observed", observedAt, outcome: "ALLOWED", principal: federated.principal };
    if (response.status === 403 && deniedForProbePermission(response.body)) return { kind: "observed", observedAt, outcome: "DENIED", principal: federated.principal };
    return { kind: "unavailable", reason: `generateAccessToken answered HTTP ${response.status} without an IAM denial of ${probePermission}` };
  }

  async #federated(resource: string, member: string): Promise<Federated> {
    const consumer = this.#consumerOf(resource);
    if (!consumer) return { kind: "unavailable", reason: `${resource} belongs to no declared consumer` };
    const pool = consumerPool(this.#deps.authority, consumer);
    const provider = consumerProvider(this.#deps.authority, consumer);
    const credential = await this.#deps.credentials.oidcTokenFor(member);
    if (credential.kind === "unavailable") return credential;
    const claims = await verifyRs256Jwt(credential.token, await this.#deps.jwks());
    if (!claims) return { kind: "unavailable", reason: "the member credential is not a GitHub-signed RS256 token" };
    const nowSeconds = Math.floor(this.#deps.now().getTime() / 1000);
    if (claims.iss !== githubIssuer) return { kind: "unavailable", reason: "the member credential was not issued by GitHub Actions" };
    if (claims.aud !== `https://iam.googleapis.com/${provider}`) return { kind: "unavailable", reason: "the member credential is not minted for the consumer provider audience" };
    if (typeof claims.exp !== "number" || claims.exp <= nowSeconds - clockSkewSeconds) return { kind: "unavailable", reason: "the member credential has expired" };
    if (typeof claims.iat !== "number" || claims.iat > nowSeconds + clockSkewSeconds) return { kind: "unavailable", reason: "the member credential is not yet valid" };
    if (claims.repository_owner_id !== this.#deps.authority.githubOwnerId || claims.repository_id !== consumer.repositoryId || claims.runner_environment !== "github-hosted") {
      return { kind: "unavailable", reason: "the member credential was minted outside the consumer repository on GitHub-hosted runners" };
    }
    const composite = ["workflow_ref", "job_workflow_ref", "job_workflow_sha", "environment", "event_name"].map((claim) => claims[claim]);
    if (typeof claims.sub !== "string" || claims.sub.length === 0 || !composite.every((value): value is string => typeof value === "string" && value.length > 0)) {
      return { kind: "unavailable", reason: "the member credential lacks the subject or the authority claims" };
    }
    const derived = `principalSet://iam.googleapis.com/${pool}/attribute.authority/${composite.join(":")}`;
    if (derived !== member) return { kind: "unavailable", reason: `the member credential is ${derived}, not the probed member` };
    const exchange = await sendJson(this.#deps.fetch, "POST", `${this.#endpoint("sts")}/v1/token`, {
      audience: `//iam.googleapis.com/${provider}`,
      grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
      requestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
      scope: "https://www.googleapis.com/auth/cloud-platform",
      subjectToken: credential.token,
      subjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
    }, undefined);
    if (exchange.kind === "unreachable") return { kind: "unavailable", reason: `STS is unreachable: ${exchange.reason}` };
    if (!exchange.ok || !isRecord(exchange.body) || typeof exchange.body.access_token !== "string" || exchange.body.access_token.length === 0) {
      return { kind: "unavailable", reason: `STS refused the member credential with HTTP ${exchange.status}` };
    }
    return { kind: "federated", accessToken: exchange.body.access_token, principal: `principal://iam.googleapis.com/${pool}/subject/${claims.sub}` };
  }

  #consumerOf(resource: string): Consumer | undefined {
    const match = /^projects\/([^/]+)\/serviceAccounts\/[1-9][0-9]*$/.exec(resource);
    return match ? this.#deps.authority.consumers.find((consumer) => consumer.projectId === match[1]) : undefined;
  }

  #endpoint(name: "credentials" | "iam" | "sts"): string {
    const defaults = { credentials: "https://iamcredentials.googleapis.com", iam: "https://iam.googleapis.com", sts: "https://sts.googleapis.com" };
    return this.#deps.endpoints?.[name] ?? defaults[name];
  }
}

// An IAM permission denial of exactly the probe permission: PERMISSION_DENIED
// with an ErrorInfo naming that permission, or the documented message form.
function deniedForProbePermission(body: unknown): boolean {
  if (!isRecord(body) || !isRecord(body.error) || body.error.status !== "PERMISSION_DENIED") return false;
  const details = Array.isArray(body.error.details) ? body.error.details : [];
  for (const detail of details) {
    if (isRecord(detail) && detail.reason === "IAM_PERMISSION_DENIED" && isRecord(detail.metadata) && detail.metadata.permission === probePermission) return true;
  }
  return typeof body.error.message === "string" && body.error.message.includes(`'${probePermission}'`);
}
