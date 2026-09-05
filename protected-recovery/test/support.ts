import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { type RecoveryIntent, manifestPath, recoveryInvokerName } from "../../tools/ci/workflow-authority";
import { type IdentityOutcome, type ImpersonationProbe, type Policy, type PolicyBinding, type PreflightOutcome, type ProbeRequest, type ProbeResult, type ReadOutcome, type ServiceAccountIam, type WriteOutcome } from "../src/effects";
import { Broker, type Deadlines, type Identity, type IdentityVerifier } from "../src/http";
import { type CredentialInventory, type InventoryOutcome, inventoryFindings } from "../src/inventory";
import { type Fresh, Ledger } from "../src/ledger";
import { type Consumer, type FreshInventory, type InventorySummary, type ProbeOutcome, type RecoveryAuthority, type Target, inventoryHash, loadRecoveryAuthority, managedRole, parseAppendBody, parseCloseBody, probesNeeded, targetOfEffect } from "../src/model";
import { type EvidenceStore, type GetOutcome, type PutOutcome } from "../src/outbox";

// Test support. The ledger is the real Firestore emulator (FIRESTORE_EMULATOR_HOST);
// the IAM API, the evidence bucket, the impersonation probe source, and the
// credential inventory are in-memory stand-ins with the exact etag,
// generation, identity, and hash semantics the broker relies on. None of the
// stand-ins is emulator coverage: the live canary must verify the actual
// returned etag behaviour of setIamPolicy, the ifGenerationMatch behaviour of
// GCS, the identity that serviceAccounts.get returns for a unique-ID resource,
// and the real answers of the inventory APIs; and no consumer job delivers a
// member credential to the production probe yet (see probePrerequisite), so
// the probe stand-in only exercises the broker's readiness logic over
// evidence it would record from the real source.

export const repoRoot = resolve(import.meta.dir, "..", "..");
export const emulatorHost = process.env.FIRESTORE_EMULATOR_HOST;
export const activeSha = "a".repeat(40);
export const transitionSha = "b".repeat(40);
export const proberPrincipal = "recovery-prober@recovery-test.iam.gserviceaccount.com";

export class Clock {
  now: Date;
  // Seconds the clock moves on every read, to make time budgets deterministic.
  secondsPerRead = 0;

  constructor(start = "2026-09-04T12:00:00.000Z") {
    this.now = new Date(start);
  }

  advance(seconds: number): void {
    this.now = new Date(this.now.getTime() + seconds * 1000);
  }

  read = (): Date => {
    if (this.secondsPerRead > 0) this.advance(this.secondsPerRead);
    return new Date(this.now.getTime());
  };
}

// The real repository authority with the broker project assigned, the
// consumer pins recorded, and a distinct test unique ID for every target, so
// purposes and targets derive exactly as in production.
export async function testAuthority(): Promise<RecoveryAuthority> {
  const authority = JSON.parse(await readFile(join(repoRoot, "protected-recovery/authority.json"), "utf8")) as Record<string, unknown>;
  const broker = authority.broker as Record<string, unknown>;
  broker.projectId = "recovery-test";
  broker.projectNumber = "123456789012";
  (authority.consumers as Array<Record<string, unknown>>).forEach((consumer, consumerIndex) => {
    consumer.activeWorkflowSha = activeSha;
    consumer.transitionWorkflowSha = consumer.repository === "runsetta" ? transitionSha : null;
    const ids = consumer.serviceAccountUniqueIds as Record<string, unknown>;
    Object.keys(ids).sort().forEach((account, accountIndex) => {
      ids[account] = testUniqueId(consumerIndex, accountIndex);
    });
  });
  return loadRecoveryAuthority(JSON.stringify(authority), await readFile(join(repoRoot, manifestPath), "utf8"));
}

export function testUniqueId(consumerIndex: number, accountIndex: number): string {
  return `1${String(consumerIndex + 1).padStart(2, "0")}${String(accountIndex + 1).padStart(2, "0")}${"0".repeat(16)}`;
}

export function invokerEmail(consumer: string, intent: RecoveryIntent = "QUARANTINE"): string {
  return `${recoveryInvokerName(consumer, intent)}@recovery-test.iam.gserviceaccount.com`;
}

export const reconcilerEmail = "recovery-reconciler@recovery-test.iam.gserviceaccount.com";

let projects = 0;

export function freshProject(): string {
  projects += 1;
  return `pr-${process.pid}-${Date.now()}-${projects}`;
}

// One Ledger is one service instance; two ledgers on the same project are two
// instances contending at the emulator.
export function emulatorLedger(clock: Clock, fetcher: typeof fetch = fetch, project = freshProject()): Ledger {
  if (!emulatorHost) throw new Error("FIRESTORE_EMULATOR_HOST is not set.");
  return new Ledger({
    fetch: fetcher,
    firestore: { baseUrl: `http://${emulatorHost}`, database: "(default)", project },
    now: clock.read,
    token: async () => "owner",
  });
}

export function quarantine(shard: string, consumer: string, key: string) {
  return parseAppendBody(shard, { consumer, intent: "QUARANTINE", key });
}

export function restore(shard: string, consumer: string, key: string, source: string) {
  return parseAppendBody(shard, { consumer, intent: "RESTORE", key, source });
}

export function close(shard: string, key: string) {
  return parseCloseBody(shard, { key });
}

// In-memory stand-in for the IAM service-account API. Every write bumps the
// etag; a write with any other etag is a 409 conflict unless the fence is
// deliberately switched off to show what a non-fencing API would do. The
// identity returned for a resource is the seeded one unless overridden to
// model a recreated account at the same address.
export class FakeIam implements ServiceAccountIam {
  readonly policies = new Map<string, Policy>();
  readonly identities = new Map<string, { readonly email: string; readonly uniqueId: string }>();
  readonly writes: Array<{ readonly bindings: readonly PolicyBinding[]; readonly etag: string; readonly resource: string }> = [];
  enforceEtag = true;
  // One-shot pauses and faults, each consumed by the first call that meets it,
  // so one worker can be held at an exact boundary while another takes over.
  beforeRead: (() => Promise<void>) | undefined;
  beforeWrite: (() => Promise<void>) | undefined;
  throwAfterWrite = false;
  dropResponses = 0;
  refuseOnce: number | undefined;
  unavailableReads = 0;
  unavailableIdentities = 0;
  // A hung API: an identity read that never settles for these resources, or
  // a write whose answer never arrives after it landed.
  readonly hangIdentities = new Set<string>();
  hangAfterWrite = false;
  #etags = 0;

  seed(resource: string, bindings: readonly PolicyBinding[]): Policy {
    const policy = { bindings, etag: this.#nextEtag(), version: 1 };
    this.policies.set(resource, policy);
    return policy;
  }

  async getIdentity(resource: string): Promise<IdentityOutcome> {
    if (this.hangIdentities.has(resource)) await new Promise<never>(() => {});
    if (this.unavailableIdentities > 0) {
      this.unavailableIdentities -= 1;
      return { kind: "unavailable", reason: "HTTP 503" };
    }
    const identity = this.identities.get(resource);
    return identity ? { kind: "identity", ...identity } : { kind: "unavailable", reason: "HTTP 404" };
  }

  async getPolicy(resource: string): Promise<ReadOutcome> {
    const gate = this.beforeRead;
    if (gate) {
      this.beforeRead = undefined;
      await gate();
    }
    if (this.unavailableReads > 0) {
      this.unavailableReads -= 1;
      return { kind: "unavailable", reason: "HTTP 503" };
    }
    const policy = this.policies.get(resource);
    return policy ? { kind: "read", policy } : { kind: "unavailable", reason: "HTTP 404" };
  }

  async setPolicy(resource: string, policy: Policy): Promise<WriteOutcome> {
    const gate = this.beforeWrite;
    if (gate) {
      this.beforeWrite = undefined;
      await gate();
    }
    if (this.refuseOnce !== undefined) {
      const status = this.refuseOnce;
      this.refuseOnce = undefined;
      return { kind: "refused", status };
    }
    const current = this.policies.get(resource);
    if (!current) return { kind: "refused", status: 404 };
    if (this.enforceEtag && policy.etag !== current.etag) return { kind: "conflict", status: 409 };
    const next = { bindings: policy.bindings, etag: this.#nextEtag(), version: 3 };
    this.policies.set(resource, next);
    this.writes.push({ bindings: policy.bindings, etag: policy.etag, resource });
    if (this.throwAfterWrite) {
      this.throwAfterWrite = false;
      throw new Error("the worker died after the write landed");
    }
    if (this.hangAfterWrite) {
      this.hangAfterWrite = false;
      await new Promise<never>(() => {});
    }
    if (this.dropResponses > 0) {
      this.dropResponses -= 1;
      return { kind: "lost", reason: "response dropped after the write landed" };
    }
    return { kind: "written", policy: next };
  }

  #nextEtag(): string {
    this.#etags += 1;
    return `etag-${this.#etags}`;
  }
}

// In-memory stand-in for the evidence bucket with ifGenerationMatch=0 semantics.
export class FakeEvidence implements EvidenceStore {
  readonly objects = new Map<string, { readonly bytes: Uint8Array; readonly generation: string }>();
  dropResponses = 0;
  unavailableReads = 0;
  #generations = 0;

  async create(name: string, bytes: Uint8Array): Promise<PutOutcome> {
    if (this.objects.has(name)) return { kind: "exists" };
    this.#generations += 1;
    const generation = String(this.#generations);
    this.objects.set(name, { bytes: new Uint8Array(bytes), generation });
    if (this.dropResponses > 0) {
      this.dropResponses -= 1;
      return { kind: "lost", reason: "response dropped after the object was created" };
    }
    return { kind: "created", generation };
  }

  async read(name: string): Promise<GetOutcome> {
    if (this.unavailableReads > 0) {
      this.unavailableReads -= 1;
      return { kind: "unavailable", reason: "HTTP 503" };
    }
    const object = this.objects.get(name);
    return object ? { kind: "found", bytes: object.bytes, generation: object.generation } : { kind: "missing" };
  }
}

// In-memory stand-in for the issuance probe source: every request and every
// preflight is logged, the preflight is operational unless made unavailable,
// the outcome is DENIED unless the target's unique ID is set to ALLOWED, and
// the observation time is the clock's. Production has no member credential
// source yet, so its real adapter refuses every preflight.
export class FakeProbe implements ImpersonationProbe {
  readonly requests: ProbeRequest[] = [];
  readonly preflights: Array<readonly Target[]> = [];
  readonly outcomes = new Map<string, ProbeOutcome>();
  unavailable = 0;
  preflightUnavailable = 0;
  readonly #clock: Clock;

  constructor(clock: Clock) {
    this.#clock = clock;
  }

  async preflight(targets: readonly Target[]): Promise<PreflightOutcome> {
    this.preflights.push(targets);
    if (this.preflightUnavailable > 0) {
      this.preflightUnavailable -= 1;
      return { kind: "unavailable", reason: "the probe source cannot act as the managed members" };
    }
    return { kind: "operational", principals: Object.fromEntries(targets.map((target) => [target.account, proberPrincipal])) };
  }

  async probe(request: ProbeRequest): Promise<ProbeResult> {
    this.requests.push(request);
    if (this.unavailable > 0) {
      this.unavailable -= 1;
      return { kind: "unavailable", reason: "the probe source is unreachable" };
    }
    return { kind: "observed", observedAt: this.#clock.now.toISOString(), outcome: this.outcomes.get(request.uniqueId) ?? "DENIED", principal: proberPrincipal };
  }
}

// In-memory stand-in for the credential inventory: every target is clean
// with a stable summary unless findings are set for its unique ID, the
// summary's etags move when a target is marked changed, and the observation
// time is the clock's.
export class FakeInventory implements CredentialInventory {
  readonly requests: Target[] = [];
  readonly findings = new Map<string, readonly string[]>();
  readonly versions = new Map<string, number>();
  unavailable = 0;
  readonly #clock: Clock;

  constructor(clock: Clock) {
    this.#clock = clock;
  }

  // Something in the target's credential inventory changed: a later
  // observation carries a different hash.
  change(uniqueId: string): void {
    this.versions.set(uniqueId, (this.versions.get(uniqueId) ?? 0) + 1);
  }

  summaryOf(target: Target): InventorySummary {
    const version = this.versions.get(target.uniqueId) ?? 0;
    const findings = this.findings.get(target.uniqueId) ?? [];
    return {
      ancestry: ["projects/882468538648", "organizations/100000000001"],
      attachments: findings.filter((finding) => finding.startsWith("attachment:")).map((finding) => finding.slice("attachment:".length)),
      grants: findings.filter((finding) => finding.startsWith("grant:")).map((finding) => finding.slice("grant:".length)),
      keys: findings.filter((finding) => finding.startsWith("key:")).map((finding) => finding.slice("key:".length)),
      lifetimeExtension: findings.find((finding) => finding.startsWith("lifetime-extension:"))?.slice("lifetime-extension:".length) ?? null,
      policies: [
        { etag: `sa-etag-${target.uniqueId}-${version}`, resource: target.resource },
        { etag: `project-etag-${version}`, resource: "projects/882468538648" },
      ],
      services: ["cloudbuild.googleapis.com:enabled", "compute.googleapis.com:disabled", "run.googleapis.com:enabled"],
    };
  }

  async inventory(target: Target, _consumer: Consumer): Promise<InventoryOutcome> {
    this.requests.push(target);
    if (this.unavailable > 0) {
      this.unavailable -= 1;
      return { kind: "unavailable", reason: "the inventory source is unreachable" };
    }
    const summary = this.summaryOf(target);
    return { kind: "observed", inventory: { account: target.account, email: target.email, findings: inventoryFindings(summary), hash: inventoryHash(summary), observedAt: this.#clock.now.toISOString(), summary, uniqueId: target.uniqueId } };
  }
}

// Bearer tokens map straight to identities; the real verifier is tested on its own.
export class FakeVerifier implements IdentityVerifier {
  async verify(authorization: string | null): Promise<Identity | undefined> {
    if (authorization === null || !authorization.startsWith("Bearer ")) return undefined;
    const email = authorization.slice("Bearer ".length);
    return email.includes("@") ? { email } : undefined;
  }
}

export interface World {
  readonly authority: RecoveryAuthority;
  readonly broker: Broker;
  readonly clock: Clock;
  readonly evidence: FakeEvidence;
  readonly iam: FakeIam;
  readonly inventory: FakeInventory;
  readonly ledger: Ledger;
  readonly probe: FakeProbe;
  // A second service instance sharing the ledger, IAM, evidence, probe, and inventory sources.
  readonly anotherInstance: () => { readonly broker: Broker; readonly ledger: Ledger };
}

export async function world(clock = new Clock(), fetcher: typeof fetch = fetch, deadlines?: Deadlines): Promise<World> {
  const authority = await testAuthority();
  const project = freshProject();
  const iam = new FakeIam();
  const evidence = new FakeEvidence();
  const probe = new FakeProbe(clock);
  const inventory = new FakeInventory(clock);
  const instance = () => {
    const ledger = emulatorLedger(clock, fetcher, project);
    return { broker: new Broker({ authority, ...(deadlines ? { deadlines } : {}), evidence, iam, inventory, ledger, now: clock.read, probe }), ledger };
  };
  const first = instance();
  return { authority, broker: first.broker, clock, evidence, iam, inventory, ledger: first.ledger, probe, anotherInstance: instance };
}

export const unrelatedBindings: readonly PolicyBinding[] = [
  { condition: null, members: ["serviceAccount:audit@recovery-test.iam.gserviceaccount.com"], role: "roles/iam.serviceAccountViewer" },
  {
    condition: { description: "", expression: "request.time < timestamp('2030-01-01T00:00:00Z')", title: "expiring_viewer" },
    members: ["group:viewers@example.com"],
    role: "roles/iam.serviceAccountViewer",
  },
];

export function seedTargets(iam: FakeIam, targets: readonly Target[], extra: readonly PolicyBinding[] = unrelatedBindings): void {
  for (const target of targets) {
    iam.seed(target.resource, [...extra, { condition: null, members: target.members, role: managedRole }]);
    iam.identities.set(target.resource, { email: target.email, uniqueId: target.uniqueId });
  }
}

// Drive an OPEN QUARANTINE shard to scan-ready through the broker's own
// observation recording: reconcile (acknowledges effects, records the
// inventory baselines and the revocation probes), drain the one-hour token
// horizon, reconcile again (records the post-horizon probes).
export async function makeReady(w: World, shard: string): Promise<void> {
  await w.broker.reconcileShard(shard);
  w.clock.advance(3600);
  await w.broker.reconcileShard(shard);
}

// The inventory of every acknowledged target of a shard as the broker would
// observe it immediately before a gate.
export async function freshOf(w: World, shardId: string): Promise<Fresh> {
  const shard = await w.ledger.readShard(shardId);
  if (!shard) return {};
  const consumer = w.authority.consumers.find((candidate) => candidate.repository === shard.consumer)!;
  const fresh: Record<string, FreshInventory> = {};
  for (const [account, state] of Object.entries(shard.targets)) {
    if (state.effect.state !== "ACKED") continue;
    const entry = await w.ledger.readEntry(shardId, state.sequence);
    if (!entry || entry.body.kind !== "effect") continue;
    const outcome = await w.inventory.inventory(targetOfEffect(w.authority, consumer, entry.body), consumer);
    if (outcome.kind === "observed") fresh[account] = { findings: outcome.inventory.findings, hash: outcome.inventory.hash, observedAt: outcome.inventory.observedAt };
  }
  return fresh;
}

// Begin a close exactly as the broker does for an invoker: with the fresh
// inventory of the shard's targets for a QUARANTINE shard.
export async function beginClose(w: World, shard: string, key: string, consumer = "cdbentley", intent: RecoveryIntent = "QUARANTINE") {
  return await w.ledger.beginClose(close(shard, key), consumer, intent, intent === "QUARANTINE" ? await freshOf(w, shard) : undefined);
}

export async function needsOf(w: World, shard: string, targets: readonly Target[]) {
  return probesNeeded((await w.ledger.readShard(shard))!, w.clock.now, (account) => targets.find((target) => target.account === account));
}

export function gate(): { readonly release: () => void; readonly wait: () => Promise<void> } {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { release, wait: () => promise };
}
