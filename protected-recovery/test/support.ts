import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { type RecoveryIntent, manifestPath, memberDeliveryName, recoveryInvokerName } from "../../tools/ci/workflow-authority";
import { type DenyFlags, type DenyMatrix, type DenyVerdict, type LiveDenyPolicy, brokerAttachment, consumerAttachment, organizationAttachment, rulesByException, steadyFlags } from "../src/deny";
import { type IdentityOutcome, type ImpersonationProbe, type Jwk, type MemberCredential, type MintOutcome, type MintResult, type Policy, type PolicyBinding, type ReadOutcome, type ServiceAccountIam, type WriteOutcome } from "../src/effects";
import { Broker, type BrokerResponse, type Deadlines, type Identity, type IdentityVerifier } from "../src/http";
import { type CredentialInventory, type DenyStateOutcome, type InventoryOutcome, inventoryFindings } from "../src/inventory";
import { type Fresh, Ledger } from "../src/ledger";
import { type Consumer, type FreshInventory, type InventorySummary, type ProbeOutcome, type RecoveryAuthority, type RoundPhase, type Target, consumerPool, inventoryHash, loadRecoveryAuthority, managedRole, parseAppendBody, parseCloseBody, parseRoundBody, probesNeeded, purposeForIdentity, targetOfEffect, targetsFor } from "../src/model";
import { type EvidenceStore, type GetOutcome, type PutOutcome } from "../src/outbox";

// Test support. The ledger is the real Firestore emulator (FIRESTORE_EMULATOR_HOST);
// the IAM API, the evidence bucket, the issuance probe, and the credential
// inventory are in-memory stand-ins with the exact etag, generation,
// identity, hash, and interval semantics the broker relies on. None of the
// stand-ins is emulator coverage: the live canary must verify the actual
// returned etag behaviour of setIamPolicy, the ifGenerationMatch behaviour of
// GCS, the identity that serviceAccounts.get returns for a unique-ID
// resource, and the real answers of the inventory, STS, and IAM Credentials
// APIs. Member credentials are minted here by a GitHub-style signer whose
// JWKS the broker is given, and delivered through the real request path
// (POST /v1/members), exactly as the canonical jobs deliver theirs.

export const repoRoot = resolve(import.meta.dir, "..", "..");
export const emulatorHost = process.env.FIRESTORE_EMULATOR_HOST;
export const activeSha = "a".repeat(40);
export const transitionSha = "b".repeat(40);
export const organizationId = "100000000001";
// A principal for observations tests record directly, outside any delivery.
export const proberPrincipal = "principal://iam.googleapis.com/projects/882468538648/locations/global/workloadIdentityPools/github-actions/subject/16823277:1255553151:github-hosted:1";

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

// The real repository authority with the broker project and organization
// assigned, the consumer pins recorded, and a distinct test unique ID for
// every target, so purposes, targets, and the Deny matrix derive exactly as
// in production.
export async function testAuthority(edit: (authority: Record<string, unknown>) => void = () => undefined): Promise<RecoveryAuthority> {
  const authority = JSON.parse(await readFile(join(repoRoot, "protected-recovery/authority.json"), "utf8")) as Record<string, unknown>;
  const broker = authority.broker as Record<string, unknown>;
  broker.projectId = "recovery-test";
  broker.projectNumber = "123456789012";
  authority.organizationId = organizationId;
  (authority.consumers as Array<Record<string, unknown>>).forEach((consumer, consumerIndex) => {
    consumer.activeWorkflowSha = activeSha;
    consumer.transitionWorkflowSha = consumer.repository === "runsetta" ? transitionSha : null;
    const ids = consumer.serviceAccountUniqueIds as Record<string, unknown>;
    Object.keys(ids).sort().forEach((account, accountIndex) => {
      ids[account] = testUniqueId(consumerIndex, accountIndex);
    });
  });
  edit(authority);
  return loadRecoveryAuthority(JSON.stringify(authority), await readFile(join(repoRoot, manifestPath), "utf8"));
}

export function testUniqueId(consumerIndex: number, accountIndex: number): string {
  return `1${String(consumerIndex + 1).padStart(2, "0")}${String(accountIndex + 1).padStart(2, "0")}${"0".repeat(16)}`;
}

export function invokerEmail(consumer: string, intent: RecoveryIntent = "QUARANTINE"): string {
  return `${recoveryInvokerName(consumer, intent)}@recovery-test.iam.gserviceaccount.com`;
}

export function memberEmail(consumer: string): string {
  return `${memberDeliveryName(consumer)}@recovery-test.iam.gserviceaccount.com`;
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

  // Whether the managed role on a resource currently carries a member: what
  // the issuance probe stand-in answers from.
  grants(resource: string, member: string): boolean {
    const policy = this.policies.get(resource);
    return policy?.bindings.some((binding) => binding.role === managedRole && binding.condition === null && binding.members.includes(member)) ?? false;
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

// In-memory stand-in for the issuance probe: every delivered credential is
// exchanged once and minted against each bound target, and the answer is what
// the IAM stand-in's managed binding says right now -- ALLOWED while the
// member is bound, DENIED once it is not -- unless an outcome is forced for
// the exact target and member (`${uniqueId}|${member}`) or the target. The
// observation time is the clock's.
export class FakeProbe implements ImpersonationProbe {
  readonly mints: Array<{ readonly member: string; readonly principal: string; readonly targets: readonly string[] }> = [];
  readonly outcomes = new Map<string, ProbeOutcome>();
  // Whole exchanges that fail, and targets whose mint answers with a failure.
  unavailable = 0;
  readonly unavailableTargets = new Set<string>();
  readonly #clock: Clock;
  readonly #iam: FakeIam;

  constructor(clock: Clock, iam: FakeIam) {
    this.#clock = clock;
    this.#iam = iam;
  }

  async mint(credential: MemberCredential, targets: readonly Target[]): Promise<MintOutcome> {
    this.mints.push({ member: credential.member, principal: credential.principal, targets: targets.map((target) => target.uniqueId) });
    if (this.unavailable > 0) {
      this.unavailable -= 1;
      return { kind: "unavailable", reason: "the probe source is unreachable" };
    }
    const results: MintResult[] = targets.map((target) => {
      if (this.unavailableTargets.has(target.uniqueId)) return { kind: "unavailable", reason: "generateAccessToken answered HTTP 503", target };
      const forced = this.outcomes.get(`${target.uniqueId}|${credential.member}`) ?? this.outcomes.get(target.uniqueId);
      const outcome: ProbeOutcome = forced ?? (this.#iam.grants(target.resource, credential.member) ? "ALLOWED" : "DENIED");
      return { kind: "observed", observedAt: this.#clock.now.toISOString(), outcome, target };
    });
    return { kind: "minted", principal: credential.principal, results };
  }
}

// In-memory stand-in for the credential inventory: every target is clean
// with a stable summary unless findings are set for its unique ID, the
// summary's etags move when a target is marked changed, the Deny state is
// steady unless the form is set, and every batch spans the clock's reads.
// A one-shot afterObserve hook runs after a read has produced its record, to
// model a change landing right after the read.
export class FakeInventory implements CredentialInventory {
  readonly requests: Target[] = [];
  readonly batches: Array<readonly string[]> = [];
  readonly findings = new Map<string, readonly string[]>();
  readonly versions = new Map<string, number>();
  unavailable = 0;
  afterObserve: ((target: Target) => void) | undefined;
  // The live Deny form the batch reads back, per consumer; steady by default.
  readonly forms = new Map<string, string>();
  denyVersion = 0;
  readonly #authority: RecoveryAuthority;
  readonly #clock: Clock;

  constructor(clock: Clock, authority: RecoveryAuthority) {
    this.#clock = clock;
    this.#authority = authority;
  }

  // Something in the target's credential inventory changed: a later
  // observation carries a different hash.
  change(uniqueId: string): void {
    this.versions.set(uniqueId, (this.versions.get(uniqueId) ?? 0) + 1);
  }

  // The live Deny state changed: every policy etag moves, into the given form.
  setDenyForm(consumer: string, form: string): void {
    this.forms.set(consumer, form);
    this.denyVersion += 1;
  }

  summaryOf(target: Target, consumer: Consumer): InventorySummary {
    const version = this.versions.get(target.uniqueId) ?? 0;
    const findings = this.findings.get(target.uniqueId) ?? [];
    const form = this.forms.get(consumer.repository) ?? "steady";
    return {
      ancestry: [`projects/${consumer.projectNumber}`, `organizations/${organizationId}`],
      attachments: findings.filter((finding) => finding.startsWith("attachment:")).map((finding) => finding.slice("attachment:".length)),
      denyState: {
        form,
        policies: [
          { attachment: brokerAttachment(this.#authority), etag: `deny-broker-${this.denyVersion}`, name: "policies/cloudresourcemanager.googleapis.com%2Fprojects%2Frecovery-test/denypolicies/protected-recovery-broker" },
          { attachment: consumerAttachment(consumer), etag: `deny-${consumer.repository}-${this.denyVersion}`, name: `policies/cloudresourcemanager.googleapis.com%2Fprojects%2F${consumer.projectId}/denypolicies/protected-recovery-consumer` },
          { attachment: organizationAttachment(this.#authority), etag: `deny-org-${this.denyVersion}`, name: `policies/cloudresourcemanager.googleapis.com%2Forganizations%2F${organizationId}/denypolicies/protected-recovery-organization` },
        ],
      },
      grants: findings.filter((finding) => finding.startsWith("grant:")).map((finding) => finding.slice("grant:".length)),
      keys: findings.filter((finding) => finding.startsWith("key:")).map((finding) => finding.slice("key:".length)),
      lifetimeExtension: findings.find((finding) => finding.startsWith("lifetime-extension:"))?.slice("lifetime-extension:".length) ?? null,
      lifetimePolicies: [`organizations/${organizationId}|absent`, `projects/${consumer.projectNumber}|absent`],
      neutralized: [],
      policies: [
        { etag: `sa-etag-${target.uniqueId}-${version}`, resource: target.resource },
        { etag: `project-etag-${version}`, resource: `projects/${consumer.projectNumber}` },
      ],
      roles: [{ etag: "role-etag-1", name: managedRole }],
      services: ["cloudbuild.googleapis.com:enabled", "cloudscheduler.googleapis.com:enabled", "compute.googleapis.com:disabled", "run.googleapis.com:enabled"],
    };
  }

  async inventory(target: Target, consumer: Consumer): Promise<InventoryOutcome> {
    return (await this.inventoryAll([target], consumer))[0]!;
  }

  async inventoryAll(targets: readonly Target[], consumer: Consumer): Promise<readonly InventoryOutcome[]> {
    this.batches.push(targets.map((target) => target.account));
    const observedAt = this.#clock.read().toISOString();
    const outcomes: InventoryOutcome[] = [];
    for (const target of targets) {
      this.requests.push(target);
      if (this.unavailable > 0) {
        this.unavailable -= 1;
        outcomes.push({ kind: "unavailable", reason: "the inventory source is unreachable" });
        continue;
      }
      const summary = this.summaryOf(target, consumer);
      const observedUntil = this.#clock.read().toISOString();
      outcomes.push({ kind: "observed", inventory: { account: target.account, email: target.email, findings: inventoryFindings(summary), hash: inventoryHash(summary), observedAt, observedUntil, summary, uniqueId: target.uniqueId } });
      const hook = this.afterObserve;
      if (hook) {
        this.afterObserve = undefined;
        hook(target);
      }
    }
    return outcomes;
  }

  async denyState(consumer: Consumer): Promise<DenyStateOutcome> {
    if (this.unavailable > 0) {
      this.unavailable -= 1;
      return { kind: "unavailable", reason: "the inventory source is unreachable" };
    }
    const summary = this.summaryOf({ account: "-", email: "-", members: [], pool: "-", resource: "-", uniqueId: "-" }, consumer);
    return { kind: "observed", state: summary.denyState, verdict: verdictOf(summary.denyState.form, consumer) };
  }
}

function verdictOf(form: string, consumer: Consumer): DenyVerdict {
  if (form.startsWith("drifted")) return { kind: "drifted", reasons: [form] };
  const flags: DenyFlags = { ...steadyFlags, bootstrap: form === "bootstrap", deployment: form === "deployment" ? [consumer.repository] : [], maintenance: form === "maintenance" };
  return { kind: "classified", flags };
}

// Bearer tokens map straight to identities; the real verifier is tested on its own.
export class FakeVerifier implements IdentityVerifier {
  async verify(authorization: string | null): Promise<Identity | undefined> {
    if (authorization === null || !authorization.startsWith("Bearer ")) return undefined;
    const email = authorization.slice("Bearer ".length);
    return email.includes("@") ? { email } : undefined;
  }
}

export interface Signer {
  readonly jwks: readonly Jwk[];
  readonly sign: (payload: Record<string, unknown>) => Promise<string>;
  readonly signWith: (payload: Record<string, unknown>, key: CryptoKey) => Promise<string>;
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
  // The GitHub-style signer whose JWKS the broker verifies member credentials against.
  readonly signer: Signer;
  // A second service instance sharing the ledger, IAM, evidence, probe, and inventory sources.
  readonly anotherInstance: () => { readonly broker: Broker; readonly ledger: Ledger };
}

export interface WorldOverrides {
  // The evidence store the broker projects to; the in-memory stand-in by default.
  readonly evidence?: EvidenceStore;
  // GitHub's JWKS as the broker sees it; the world's own signer by default.
  readonly jwks?: () => Promise<readonly Jwk[]>;
  // The ledger fetcher, distinct from the evidence store's own.
  readonly ledgerFetch?: typeof fetch;
}

export async function world(clock = new Clock(), fetcher: typeof fetch = fetch, deadlines?: Deadlines, overrides: WorldOverrides = {}): Promise<World> {
  const authority = await testAuthority();
  const project = freshProject();
  const iam = new FakeIam();
  const evidence = new FakeEvidence();
  const probe = new FakeProbe(clock, iam);
  const inventory = new FakeInventory(clock, authority);
  const signer = await githubSigner();
  const jwks = overrides.jwks ?? (async (): Promise<readonly Jwk[]> => signer.jwks);
  const instance = () => {
    const ledger = emulatorLedger(clock, overrides.ledgerFetch ?? fetcher, project);
    return { broker: new Broker({ authority, ...(deadlines ? { deadlines } : {}), evidence: overrides.evidence ?? evidence, iam, inventory, jwks, ledger, now: clock.read, probe }), ledger };
  };
  const first = instance();
  return { authority, broker: first.broker, clock, evidence, iam, inventory, ledger: first.ledger, probe, signer, anotherInstance: instance };
}

// A GitHub-style RS256 signer with its JWKS entry, for member credentials
// the tests mint themselves.
export async function githubSigner(kid = "gh1"): Promise<Signer> {
  const keys = await crypto.subtle.generateKey({ hash: "SHA-256", modulusLength: 2048, name: "RSASSA-PKCS1-v1_5", publicExponent: new Uint8Array([1, 0, 1]) }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const signWith = async (payload: Record<string, unknown>, key: CryptoKey): Promise<string> => {
    const signingInput = `${encode({ alg: "RS256", kid })}.${encode(payload)}`;
    const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, Buffer.from(signingInput));
    return `${signingInput}.${Buffer.from(signature).toString("base64url")}`;
  };
  return { jwks: [{ e: jwk.e!, kid, kty: "RSA", n: jwk.n! }], sign: (payload) => signWith(payload, keys.privateKey), signWith };
}

// The claims of the canonical job that is one managed member, minted for the
// consumer provider's audience: the five authority claims the provider
// composes, the numeric identity claims its subject mapping uses, and a
// normal GitHub subject, which the provider never uses as the principal.
export function memberClaims(authority: RecoveryAuthority, consumer: Consumer, member: string, nowSeconds: number, runId = "4242"): Record<string, unknown> {
  const pool = consumerPool(authority, consumer);
  const composite = member.slice(`principalSet://iam.googleapis.com/${pool}/attribute.authority/`.length).split(":");
  return {
    aud: `https://iam.googleapis.com/${pool}/providers/${authority.broker.workloadIdentityProviderId}`,
    environment: composite[3],
    event_name: composite[4],
    exp: nowSeconds + 300,
    iat: nowSeconds - 10,
    iss: "https://token.actions.githubusercontent.com",
    job_workflow_ref: composite[1],
    job_workflow_sha: composite[2],
    repository_id: consumer.repositoryId,
    repository_owner_id: authority.githubOwnerId,
    run_attempt: "1",
    run_id: runId,
    runner_environment: "github-hosted",
    sub: `repo:${authority.githubOwner}/${consumer.repository}:environment:${composite[3]}`,
    workflow_ref: composite[0],
  };
}

// The federated principal STS creates for a member credential minted in one run.
export function memberPrincipal(authority: RecoveryAuthority, consumer: Consumer, runId = "4242"): string {
  return `principal://iam.googleapis.com/${consumerPool(authority, consumer)}/subject/${authority.githubOwnerId}:${consumer.repositoryId}:github-hosted:${runId}`;
}

export function consumerOf(w: World, repository: string): Consumer {
  const consumer = w.authority.consumers.find((candidate) => candidate.repository === repository);
  if (!consumer) throw new Error(`no consumer ${repository}`);
  return consumer;
}

// One canonical job delivering its credential: a token of the exact member,
// minted now for the consumer provider's audience, through the consumer's
// member-delivery identity and the real request path.
export async function deliver(w: World, repository: string, member: string, runId = "4242"): Promise<BrokerResponse> {
  const consumer = consumerOf(w, repository);
  const token = await w.signer.sign(memberClaims(w.authority, consumer, member, Math.floor(w.clock.now.getTime() / 1000), runId));
  return await w.broker.handle(purposeForIdentity(w.authority, memberEmail(repository))!, { kind: "deliver", token });
}

// Every canonical job of a consumer delivering once, in member order: one
// delivery round.
export async function deliverAll(w: World, repository: string, runId = "4242"): Promise<readonly BrokerResponse[]> {
  const consumer = consumerOf(w, repository);
  const members = [...new Set((targetsFor(w.authority, consumer) ?? []).flatMap((target) => target.members))].sort();
  const responses: BrokerResponse[] = [];
  for (const member of members) responses.push(await deliver(w, repository, member, runId));
  return responses;
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

let roundCounter = 0;

// Open one delivery round through the consumer's QUARANTINE invoker and the
// real request path, at fresh coordinates; returns the round identifier.
export async function openRound(w: World, repository: string, phase: RoundPhase, shard: string | null): Promise<string> {
  roundCounter += 1;
  const label = `${phase.toLowerCase()}-${roundCounter}`;
  const request = parseRoundBody({ consumer: repository, key: `round/${label}`, label, phase, shard });
  const response = await w.broker.handle(purposeForIdentity(w.authority, invokerEmail(repository))!, request);
  if (response.status !== 201) throw new Error(`opening the ${phase} round answered ${response.status}: ${JSON.stringify(response.body)}`);
  return (response.body.round as { round: string }).round;
}

// One complete CONTROL round: opened, then every canonical job delivers once
// while the bindings stand. What a quarantine's admission needs.
export async function controlRound(w: World, repository: string): Promise<string> {
  const round = await openRound(w, repository, "CONTROL", null);
  for (const response of await deliverAll(w, repository)) {
    if (response.status !== 200) throw new Error(`the CONTROL delivery answered ${response.status}: ${JSON.stringify(response.body)}`);
  }
  const manifest = await w.ledger.readRound(round);
  if (!manifest || manifest.completedAt === null) throw new Error(`the CONTROL round ${round} did not complete`);
  return round;
}

// Seed a consumer's targets and complete one CONTROL round while the
// bindings stand: what admission needs.
export async function prime(w: World, repository: string): Promise<readonly Target[]> {
  const targets = targetsFor(w.authority, consumerOf(w, repository))!;
  seedTargets(w.iam, targets);
  await controlRound(w, repository);
  return targets;
}

// Drive an OPEN QUARANTINE shard to scan-ready through the broker's own
// observation recording: reconcile (acknowledges effects and records the
// inventory baselines), a REVOCATION round (the deliveries themselves record
// the revocation probe of every member), drain the one-hour token horizon, a
// HORIZON round (the post-horizon probes), then reconcile again to project
// the journaled probes.
export async function makeReady(w: World, shard: string): Promise<void> {
  await w.broker.reconcileShard(shard);
  const repository = (await w.ledger.readShard(shard))!.consumer;
  await openRound(w, repository, "REVOCATION", shard);
  await deliverAll(w, repository);
  w.clock.advance(3600);
  await openRound(w, repository, "HORIZON", shard);
  await deliverAll(w, repository);
  await w.broker.reconcileShard(shard);
}

// The inventory of every acknowledged target of a shard as the broker would
// observe it immediately before a gate.
export async function freshOf(w: World, shardId: string): Promise<Fresh> {
  const shard = await w.ledger.readShard(shardId);
  if (!shard) return {};
  const consumer = consumerOf(w, shard.consumer);
  const fresh: Record<string, FreshInventory> = {};
  const targets: Array<{ readonly account: string; readonly target: Target }> = [];
  for (const [account, state] of Object.entries(shard.targets)) {
    if (state.effect.state !== "ACKED") continue;
    const entry = await w.ledger.readEntry(shardId, state.sequence);
    if (!entry || entry.body.kind !== "effect") continue;
    targets.push({ account, target: targetOfEffect(w.authority, consumer, entry.body) });
  }
  const outcomes = targets.length === 0 ? [] : await w.inventory.inventoryAll(targets.map((entry) => entry.target), consumer);
  for (const [index, { account }] of targets.entries()) {
    const outcome = outcomes[index]!;
    if (outcome.kind === "observed") fresh[account] = { findings: outcome.inventory.findings, hash: outcome.inventory.hash, observedAt: outcome.inventory.observedAt, observedUntil: outcome.inventory.observedUntil };
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

// The live Deny policies the IAM v2 API would answer for a matrix: one policy
// per attachment point, one rule per exception set, each rule listing every
// permission that shares it, named and etagged deterministically. Both the
// projected form the classifier reads and the JSON documents the API stand-in
// serves.
export function livePoliciesFromMatrix(matrix: DenyMatrix, etag = (attachment: string) => `deny-etag-${attachment.split("/").at(-1)}`): { readonly documents: Readonly<Record<string, Record<string, unknown>>>; readonly policies: readonly LiveDenyPolicy[] } {
  const policies: LiveDenyPolicy[] = [];
  const documents: Record<string, Record<string, unknown>> = {};
  for (const [attachment, rules] of rulesByException(matrix)) {
    const name = `policies/${encodeURIComponent(attachment)}/denypolicies/protected-recovery`;
    const projected = rules.map((rule) => ({ condition: null, denied: ["principalSet://goog/public:all"], exceptedPermissions: [], exceptions: rule.exceptions, permissions: [...rule.permissions] }));
    policies.push({ attachment, etag: etag(attachment), name, rules: projected });
    documents[name] = { etag: etag(attachment), name, rules: projected.map((rule) => ({ denyRule: { deniedPermissions: rule.permissions, deniedPrincipals: rule.denied, exceptionPrincipals: rule.exceptions } })) };
  }
  return { documents, policies };
}
