import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { manifestPath } from "../../tools/ci/workflow-authority";
import { type Policy, type PolicyBinding, type ReadOutcome, type ServiceAccountIam, type WriteOutcome } from "../src/effects";
import { Broker, type Identity, type IdentityVerifier } from "../src/http";
import { Ledger } from "../src/ledger";
import { type RecoveryAuthority, type Target, loadRecoveryAuthority, managedRole, parseAppendBody, parseCloseBody } from "../src/model";
import { type EvidenceStore, type GetOutcome, type PutOutcome } from "../src/outbox";

// Test support. The ledger is the real Firestore emulator (FIRESTORE_EMULATOR_HOST);
// the IAM API and the evidence bucket are in-memory stand-ins with the exact
// etag and generation semantics the broker relies on. Neither stand-in is
// emulator coverage: the live canary must verify the actual returned etag
// behaviour of setIamPolicy and the ifGenerationMatch behaviour of GCS.

export const repoRoot = resolve(import.meta.dir, "..", "..");
export const emulatorHost = process.env.FIRESTORE_EMULATOR_HOST;
export const activeSha = "a".repeat(40);
export const transitionSha = "b".repeat(40);

export class Clock {
  now: Date;

  constructor(start = "2026-09-04T12:00:00.000Z") {
    this.now = new Date(start);
  }

  advance(seconds: number): void {
    this.now = new Date(this.now.getTime() + seconds * 1000);
  }

  read = (): Date => new Date(this.now.getTime());
}

// The real repository authority with the broker project assigned and the
// consumer pins recorded, so purposes and targets derive exactly as in production.
export async function testAuthority(): Promise<RecoveryAuthority> {
  const authority = JSON.parse(await readFile(join(repoRoot, "protected-recovery/authority.json"), "utf8")) as Record<string, unknown>;
  const broker = authority.broker as Record<string, unknown>;
  broker.projectId = "recovery-test";
  broker.projectNumber = "123456789012";
  for (const consumer of authority.consumers as Array<Record<string, unknown>>) {
    consumer.activeWorkflowSha = activeSha;
    consumer.transitionWorkflowSha = consumer.repository === "runsetta" ? transitionSha : null;
  }
  return loadRecoveryAuthority(JSON.stringify(authority), await readFile(join(repoRoot, manifestPath), "utf8"));
}

export function invokerEmail(consumer: string): string {
  return `gha-recovery-${consumer}@recovery-test.iam.gserviceaccount.com`;
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

export function canary(shard: string, consumer: string, key: string, account: string, member: string, observedAt: string, failing: readonly string[] = []) {
  const checks = Object.fromEntries(["attachmentsAbsent", "impersonationDenied", "keysAbsent", "lifetimeExtensionAbsent", "tokenCreatorsAbsent", "wifDataPlaneAbsent"].map((check) => [check, !failing.includes(check)]));
  return parseAppendBody(shard, { canary: { account, checks, member, observedAt }, consumer, key });
}

export function close(shard: string, key: string) {
  return parseCloseBody(shard, { key });
}

// In-memory stand-in for the IAM service-account policy API. Every write
// bumps the etag; a write with any other etag is a 409 conflict unless the
// fence is deliberately switched off to show what a non-fencing API would do.
export class FakeIam implements ServiceAccountIam {
  readonly policies = new Map<string, Policy>();
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
  #etags = 0;

  seed(resource: string, bindings: readonly PolicyBinding[]): Policy {
    const policy = { bindings, etag: this.#nextEtag(), version: 1 };
    this.policies.set(resource, policy);
    return policy;
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
  readonly ledger: Ledger;
  // A second service instance sharing the ledger, IAM, and evidence.
  readonly anotherInstance: () => { readonly broker: Broker; readonly ledger: Ledger };
}

export async function world(clock = new Clock(), fetcher: typeof fetch = fetch): Promise<World> {
  const authority = await testAuthority();
  const project = freshProject();
  const iam = new FakeIam();
  const evidence = new FakeEvidence();
  const instance = () => {
    const ledger = emulatorLedger(clock, fetcher, project);
    return { broker: new Broker({ authority, evidence, iam, ledger, now: clock.read }), ledger };
  };
  const first = instance();
  return { authority, broker: first.broker, clock, evidence, iam, ledger: first.ledger, anotherInstance: instance };
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
  for (const target of targets) iam.seed(target.resource, [...extra, { condition: null, members: target.members, role: managedRole }]);
}

export function gate(): { readonly release: () => void; readonly wait: () => Promise<void> } {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { release, wait: () => promise };
}
