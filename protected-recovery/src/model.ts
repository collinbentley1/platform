import { createHash } from "node:crypto";
import {
  type RecoveryAuthorityEntry,
  type RecoveryIntent,
  type WorkflowAuthorityEntry,
  memberDeliveryName,
  parseWorkflowAuthority,
  manifestPath,
  recoveryIntents,
} from "../../tools/ci/workflow-authority";

// The protected-recovery broker: one authenticated Cloud Run service whose
// ordering authority is Firestore transactions. Immutable GCS objects are only
// a projection of committed Firestore state, and the one external effect is a
// compare-and-set of a target service account's IAM allow policy.
//
// Caller usage (every request carries a Google-signed ID token for the broker
// audience; the purpose -- one consumer and exactly one effect direction, or
// the reconciler -- is derived from the authenticated service account, never
// from the body):
//
//   POST /v1/shards/{shard}/entries    the consumer's invoker for that direction
//     {"key", "consumer", "intent": "QUARANTINE"}                    one QUARANTINE effect per target account
//     {"key", "consumer", "intent": "RESTORE", "source": "<shard>"}  one RESTORE effect per effect of the scan-ready CLOSED source shard
//     201 accepted / 200 replayed     -> {"shard", "sequences", "key", "bodyHash", "acceptedAt"}
//     409 KEY_BODY_MISMATCH | SHARD_NOT_OPEN | SHARD_FULL | SHARD_MISMATCH | SOURCE_NOT_COMPLETE | PINS_UNRECORDED
//     409 PROBE_UNAVAILABLE | INVENTORY_BLOCKED   a QUARANTINE is refused before acceptance unless the broker's own
//                                                 issuance probe is operational against every target and the credential
//                                                 inventory of every target is observed and clean
//   POST /v1/shards/{shard}/close      the same invoker   {"key"}
//     200                             -> {"shard", "phase": "CLOSING", "closeHighWater", "closingAt"}
//     409 NOT_READY                   -> {"blockers": [...]}  a QUARANTINE shard closes only once scan-ready
//   POST /v1/shards/{shard}/reconcile  the same invoker, reconciler   {}
//   POST /v1/reconcile                 reconciler                     {}   (every shard with recorded pending work, paginated)
//     200                             -> {"shards": [ShardView], "next": cursor | null}
//   GET  /v1/shards/{shard}            the same invoker, reconciler
//     200                             -> {"shard": ShardView, "entries": [EntryView]}
//   400 INVALID_REQUEST, 401 UNAUTHENTICATED, 403 FORBIDDEN, 404 NOT_FOUND, 413 BODY_TOO_LARGE, 503 LEDGER_UNAVAILABLE
//
// No body carries evidence. Negative impersonation probes and credential
// inventories are recorded by the broker itself from its own sources, never
// from a caller, and a shard is scan-ready only on that recorded evidence.
// Retries are secured by the ledger: the same key with the same body returns
// the recorded result; the same key with a different body is refused. A shard
// is CLOSED only once its terminal receipt is verified in GCS; until then it
// is FINALIZING and no caller-facing completion exists.

export const authorityPath = "protected-recovery/authority.json";
export const intents = recoveryIntents;
export type Intent = RecoveryIntent;
export const managedRole = "roles/iam.workloadIdentityUser";
// The broker's own service account ID in the broker project; the Terraform
// module creates exactly this account and grants it the actuator role.
export const brokerServiceAccountId = "recovery-broker";
// Binding removal blocks new impersonation only. A holder of the managed role
// can mint a one-hour access token up to the moment removal propagates, so a
// protected scan waits this long after the last plausibly successful mint --
// bounded by the first negative probe after the last positive one -- and then
// needs another negative probe.
export const tokenHorizonSeconds = 3600;
// The journal ceiling of one shard. Effects need entries; observations are
// journaled while entries remain and otherwise folded into the shard's
// per-target chain state, so no number of observations can make the DENIED
// chain that reaches a terminal outcome unrecordable.
export const maxEntriesPerShard = 256;
export const maxBodyBytes = 8 * 1024;

// A probe attempts exactly this permission as the managed member against the
// exact target identity. The broker's own probe source performs it; no caller
// can submit a result.
export const probePermission = "iam.serviceAccounts.getAccessToken";
export const probePhases = ["REVOCATION", "HORIZON"] as const;
export type ProbePhase = (typeof probePhases)[number];
export const probeOutcomes = ["ALLOWED", "DENIED"] as const;
export type ProbeOutcome = (typeof probeOutcomes)[number];
// The issuance probe is a real IAM Credentials request as the exact managed
// member: the broker verifies the GitHub OIDC token of the one canonical job
// that is that member, exchanges it at STS for the consumer pool, and observes
// generateAccessToken against the target's permanent identity itself. No
// consumer job delivers such a token to the broker yet, so the production
// credential source reports every member unavailable and the broker refuses
// every QUARANTINE before acceptance, before PREPARE, and before any mutation.
export const probePrerequisite = "no canonical-member credential source is deployed: the issuance probe needs the GitHub OIDC token of the exact canonical job for each managed member, minted for the consumer pool's provider audience, and no consumer job delivers one to the broker; activation must supply that source before any QUARANTINE can be accepted";

export class AuthorityError extends Error {}
export class RequestError extends Error {}

export interface Consumer {
  readonly activeWorkflowSha: string | null;
  readonly projectId: string;
  readonly projectNumber: string;
  readonly repository: string;
  readonly repositoryId: string;
  // The permanent numeric identity of every target account, keyed by account
  // ID. Null until a reviewed change records the real one; nothing invents it.
  readonly serviceAccountUniqueIds: Readonly<Record<string, string | null>>;
  readonly transitionWorkflowSha: string | null;
}

export interface Broker {
  readonly firestoreDatabase: string;
  // The provider of the broker pool through which the consumers' canonical
  // jobs reach their member-delivery identity; distinct from the platform
  // repository's own provider.
  readonly memberWorkloadIdentityProviderId: string;
  readonly projectId: string | null;
  readonly projectNumber: string | null;
  readonly reconcilerServiceAccount: string;
  readonly region: string;
  readonly serviceName: string;
  readonly workloadIdentityPoolId: string;
  readonly workloadIdentityProviderId: string;
}

// Deployment and fixed-resource coordinates only. Who may invoke, for which
// consumer, in which direction, and which consumer accounts are bound to which
// exact tuples all come from the canonical workflow-authority manifest.
export interface RecoveryAuthority {
  readonly broker: Broker;
  readonly consumers: readonly Consumer[];
  readonly entries: readonly WorkflowAuthorityEntry[];
  readonly githubOwner: string;
  readonly githubOwnerId: string;
  readonly platformRepository: string;
  readonly platformRepositoryId: string;
  readonly targetAccounts: readonly string[];
}

export type Purpose =
  | { readonly kind: "recovery"; readonly consumer: Consumer; readonly intent: Intent; readonly serviceAccount: string }
  | { readonly kind: "reconciler"; readonly serviceAccount: string };

// One target service account of a consumer: its permanent numeric identity,
// the IAM resource addressed by that identity, and the exact managed members
// of the managed role, derived from the inventory.
export interface Target {
  readonly account: string;
  readonly email: string;
  readonly members: readonly string[];
  readonly pool: string;
  readonly resource: string;
  readonly uniqueId: string;
}

// A recorded probe: which principal tried which member and permission against
// which exact identity, when the broker observed it, and what happened.
export interface ProbeRecord {
  readonly account: string;
  readonly email: string;
  readonly member: string;
  readonly observedAt: string;
  readonly outcome: ProbeOutcome;
  readonly permission: typeof probePermission;
  readonly phase: ProbePhase;
  readonly principal: string;
  readonly uniqueId: string;
}

// The credential-relevant inventory of one target, exactly as the broker
// observed it: every allow-policy attachment point in the target's ancestry
// with its etag and every credential-capable grant found there after role
// expansion (excluding only the broker's own modeled actuator grant),
// user-managed keys, the effective credential-lifetime-extension policy, and
// Compute, Cloud Run, and Cloud Build attachments that run as the target.
// The hash is over this summary alone; any change to it is a change of the
// inventory.
export interface InventorySummary {
  readonly ancestry: readonly string[];
  readonly attachments: readonly string[];
  readonly grants: readonly string[];
  readonly keys: readonly string[];
  readonly lifetimeExtension: string | null;
  readonly policies: ReadonlyArray<{ readonly etag: string; readonly resource: string }>;
  // Which attachment APIs were enabled in the consumer project when read; a
  // disabled API hosts no attachment and is recorded as such, never assumed.
  readonly services: readonly string[];
}

export interface InventoryRecord {
  readonly account: string;
  readonly email: string;
  readonly findings: readonly string[];
  readonly hash: string;
  readonly observedAt: string;
  readonly summary: InventorySummary;
  readonly uniqueId: string;
}

export type EntryBody =
  | { readonly kind: "effect"; readonly account: string; readonly email: string; readonly intent: Intent; readonly members: readonly string[]; readonly resource: string; readonly uniqueId: string }
  | ({ readonly kind: "probe" } & ProbeRecord)
  | ({ readonly kind: "inventory" } & InventoryRecord);

// Complete policy snapshots: the canonical bindings and their content hash,
// plus the etag when the snapshot was observed rather than expected.
export interface ExpectedSnapshot {
  readonly hash: string;
  readonly policy: string;
}

export interface ObservedSnapshot extends ExpectedSnapshot {
  readonly etag: string;
}

export interface PreparedFacts {
  readonly after: ExpectedSnapshot;
  readonly alternateIssuers: readonly string[];
  readonly before: ObservedSnapshot;
  readonly effectId: string;
  readonly epoch: number;
  readonly preparedAt: string;
}

export type EffectProgress =
  | { readonly state: "RECORDED" }
  | ({ readonly state: "PREPARED"; readonly attempts: number } & PreparedFacts)
  | ({ readonly state: "ACKED"; readonly ackedAt: string; readonly attempts: number; readonly mutated: boolean; readonly observed: ObservedSnapshot } & PreparedFacts)
  | { readonly state: "DIVERGED"; readonly attempts: number; readonly divergedAt: string; readonly observed: ObservedSnapshot | null; readonly prepared: PreparedFacts | null; readonly reason: string };

export type EffectState = EffectProgress["state"];

export type OutboxProgress =
  | { readonly state: "PENDING" }
  | { readonly state: "PROJECTED"; readonly generation: string; readonly projectedAt: string; readonly sha256: string }
  | { readonly state: "DIVERGED"; readonly divergedAt: string; readonly reason: string };

export interface Entry {
  readonly acceptedAt: string;
  readonly body: EntryBody;
  readonly bodyHash: string;
  readonly key: string;
  readonly objectName: string;
  readonly outbox: OutboxProgress;
  readonly progress: EffectProgress | null;
  readonly sequence: number;
}

export interface TerminalOutbox {
  readonly objectName: string;
  readonly progress: OutboxProgress;
  readonly receipt: string;
  readonly sha256: string;
}

// The effect state of one target mirrored into the shard document by the
// same transactions that move the entry, so readiness never needs the entries.
export interface TargetEffect {
  readonly ackedAt: string | null;
  readonly alternateIssuers: readonly string[];
  readonly state: EffectState;
}

// The current inventory baseline of one target: the hash first observed at
// observedAt, re-verified unchanged at verifiedAt, after this many changes.
export interface ChainInventory {
  readonly changes: number;
  readonly findings: readonly string[];
  readonly hash: string;
  readonly observations: number;
  readonly observedAt: string;
  readonly verifiedAt: string;
}

// The probe chain of one target as committed state, not as a scan of entries:
// the revocation probe (the earliest DENIED observation after the quarantine
// acknowledgement, after the latest ALLOWED observation, and at or after the
// inventory baseline), the post-horizon probe (a DENIED observation at or
// after the token horizon), and the folded counts of every other observation.
// Observations are journaled as entries while the shard has room and
// otherwise counted as suppressed; the chain itself is always writable.
export interface TargetChain {
  readonly allowed: { readonly count: number; readonly lastObservedAt: string | null };
  readonly denied: number;
  readonly inventory: ChainInventory | null;
  readonly journaled: number;
  readonly post: ProbeRecord | null;
  readonly revocation: ProbeRecord | null;
  readonly suppressed: number;
}

export interface TargetState {
  readonly chain: TargetChain;
  readonly effect: TargetEffect;
  readonly sequence: number;
}

interface ShardBase {
  readonly consumer: string;
  readonly createdAt: string;
  readonly intent: Intent;
  readonly nextSequence: number;
  readonly pendingEffects: number;
  readonly pendingOutbox: number;
  readonly source: string | null;
  readonly targets: Readonly<Record<string, TargetState>>;
}

interface ClosingFacts {
  readonly closeHighWater: number;
  readonly closeKeyHash: string;
  readonly closingAt: string;
}

export type Shard =
  | (ShardBase & { readonly phase: "OPEN" })
  | (ShardBase & ClosingFacts & { readonly phase: "CLOSING" })
  | (ShardBase & ClosingFacts & { readonly phase: "FINALIZING"; readonly finalizingAt: string; readonly terminal: TerminalOutbox })
  | (ShardBase & ClosingFacts & { readonly phase: "CLOSED"; readonly closedAt: string; readonly finalizingAt: string; readonly pendingEffects: 0; readonly pendingOutbox: 0; readonly terminal: TerminalOutbox });

export type ShardPhase = Shard["phase"];

// One actuator per target identity orders every effect against it: PREPARE
// takes the actuator, ACK or DIVERGED releases it, and a takeover must finish
// the recorded operation before an opposite intent can take it.
export interface Actuator {
  readonly epoch: number;
  readonly holder: { readonly effectId: string; readonly sequence: number; readonly shard: string } | null;
  readonly lastEtag: string | null;
}

export interface KeyRecord {
  readonly bodyHash: string;
  readonly key: string;
  readonly operation: "append" | "close";
  readonly result: string;
}

export type AppendBody =
  | { readonly kind: "quarantine" }
  | { readonly kind: "restore"; readonly source: string };

export interface AppendRequest {
  readonly kind: "append";
  readonly body: AppendBody;
  readonly bodyHash: string;
  readonly consumer: string;
  readonly key: string;
  readonly shard: string;
}

export interface CloseRequest {
  readonly kind: "close";
  readonly bodyHash: string;
  readonly key: string;
  readonly shard: string;
}

export interface ReconcileRequest {
  readonly kind: "reconcile";
  readonly shard: string | null;
}

export interface ReadRequest {
  readonly kind: "read";
  readonly shard: string;
}

export type ParsedRequest = AppendRequest | CloseRequest | ReconcileRequest | ReadRequest;

export function intentOf(body: AppendBody): Intent {
  return body.kind === "restore" ? "RESTORE" : "QUARANTINE";
}

const shardId = /^[a-z0-9][a-z0-9-]{0,62}$/;
const idempotencyKey = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/;
const decimalId = /^[1-9][0-9]*$/;
const serviceAccountId = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const projectId = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const repositoryName = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const region = /^[a-z]+-[a-z]+[0-9]$/;
const commitSha = /^[0-9a-f]{40}$/;

export function loadRecoveryAuthority(authorityText: string, manifestText: string): RecoveryAuthority {
  let document: unknown;
  try {
    document = JSON.parse(authorityText);
  } catch (error) {
    throw new AuthorityError(`${authorityPath}: ${String(error)}`);
  }
  const root = record(document, authorityPath);
  exactKeys(root, ["broker", "consumers", "githubOwner", "githubOwnerId", "platformRepository", "platformRepositoryId"], authorityPath);
  const githubOwner = string(root.githubOwner, `${authorityPath}.githubOwner`);
  const githubOwnerId = string(root.githubOwnerId, `${authorityPath}.githubOwnerId`);
  const platformRepository = string(root.platformRepository, `${authorityPath}.platformRepository`);
  const platformRepositoryId = string(root.platformRepositoryId, `${authorityPath}.platformRepositoryId`);
  if (!repositoryName.test(githubOwner) || !decimalId.test(githubOwnerId) || !decimalId.test(platformRepositoryId)) {
    throw new AuthorityError(`${authorityPath}: githubOwner must be a GitHub owner and githubOwnerId and platformRepositoryId positive decimal IDs.`);
  }
  if (platformRepository !== `${githubOwner}/platform`) throw new AuthorityError(`${authorityPath}.platformRepository must be ${githubOwner}/platform.`);
  const manifest = parseWorkflowAuthority(manifestText);
  if (manifest.failures.length > 0) throw new AuthorityError(manifest.failures.join("\n"));
  const targetAccounts = [...new Set(manifest.entries.flatMap((entry) => (entry.trustDomain === "consumer" && entry.purpose === "gcp" ? entry.serviceAccounts : [])))].sort();
  const consumers = parseConsumers(root.consumers, targetAccounts);
  const broker = parseBroker(root.broker);
  for (const consumer of consumers) {
    for (const intent of intents) {
      const invokers = manifest.entries.filter((entry): entry is RecoveryAuthorityEntry => entry.purpose === "recovery" && entry.consumer === consumer.repository && entry.intent === intent);
      if (invokers.length !== 1) throw new AuthorityError(`${manifestPath}: consumer ${consumer.repository} must have exactly one ${intent} invoker; found ${invokers.length}.`);
    }
    if (manifest.entries.some((entry) => entry.serviceAccounts.includes(memberDeliveryName(consumer.repository)))) {
      throw new AuthorityError(`${manifestPath}: the member-delivery identity ${memberDeliveryName(consumer.repository)} is bound by this module alone and cannot be an entry's account.`);
    }
  }
  if (manifest.entries.filter((entry) => entry.purpose === "deny-canary").length !== 1) throw new AuthorityError(`${manifestPath}: exactly one Deny canary job must be declared.`);
  for (const entry of manifest.entries) {
    if (entry.purpose === "recovery" && !consumers.some((consumer) => consumer.repository === entry.consumer)) {
      throw new AuthorityError(`${manifestPath}: recovery invoker for ${entry.consumer} names no consumer declared in ${authorityPath}.`);
    }
    if (entry.trustDomain === "recovery" && entry.serviceAccounts[0] === broker.reconcilerServiceAccount) {
      throw new AuthorityError(`${manifestPath}: the reconciler ${broker.reconcilerServiceAccount} cannot also be a recovery invoker.`);
    }
  }
  return { broker, consumers, entries: manifest.entries, githubOwner, githubOwnerId, platformRepository, platformRepositoryId, targetAccounts };
}

function parseConsumers(value: unknown, targetAccounts: readonly string[]): readonly Consumer[] {
  const label = `${authorityPath}.consumers`;
  if (!Array.isArray(value) || value.length === 0) throw new AuthorityError(`${label} must be a non-empty array.`);
  const consumers: Consumer[] = [];
  value.forEach((raw, index) => {
    const where = `${label}[${index}]`;
    const entry = record(raw, where);
    exactKeys(entry, ["activeWorkflowSha", "projectId", "projectNumber", "repository", "repositoryId", "serviceAccountUniqueIds", "transitionWorkflowSha"], where);
    const consumer: Consumer = {
      activeWorkflowSha: nullableSha(entry.activeWorkflowSha, `${where}.activeWorkflowSha`),
      projectId: string(entry.projectId, `${where}.projectId`),
      projectNumber: string(entry.projectNumber, `${where}.projectNumber`),
      repository: string(entry.repository, `${where}.repository`),
      repositoryId: string(entry.repositoryId, `${where}.repositoryId`),
      serviceAccountUniqueIds: parseUniqueIds(entry.serviceAccountUniqueIds, `${where}.serviceAccountUniqueIds`, targetAccounts),
      transitionWorkflowSha: nullableSha(entry.transitionWorkflowSha, `${where}.transitionWorkflowSha`),
    };
    if (!repositoryName.test(consumer.repository)) throw new AuthorityError(`${where}.repository must be a GitHub repository name.`);
    if (!decimalId.test(consumer.repositoryId)) throw new AuthorityError(`${where}.repositoryId must be a positive decimal ID.`);
    if (!projectId.test(consumer.projectId)) throw new AuthorityError(`${where}.projectId must be a Google Cloud project ID.`);
    if (!decimalId.test(consumer.projectNumber)) throw new AuthorityError(`${where}.projectNumber must be a positive decimal project number.`);
    if (consumer.transitionWorkflowSha !== null && consumer.transitionWorkflowSha === consumer.activeWorkflowSha) {
      throw new AuthorityError(`${where}.transitionWorkflowSha must differ from activeWorkflowSha.`);
    }
    if (consumer.transitionWorkflowSha !== null && consumer.activeWorkflowSha === null) {
      throw new AuthorityError(`${where}.transitionWorkflowSha requires activeWorkflowSha.`);
    }
    for (const key of ["projectId", "projectNumber", "repository", "repositoryId"] as const) {
      if (consumers.some((other) => other[key] === consumer[key])) throw new AuthorityError(`${where}.${key} ${consumer[key]} is already declared.`);
    }
    for (const [account, uniqueId] of Object.entries(consumer.serviceAccountUniqueIds)) {
      if (uniqueId !== null && consumers.some((other) => Object.values(other.serviceAccountUniqueIds).includes(uniqueId))) {
        throw new AuthorityError(`${where}.serviceAccountUniqueIds.${account} ${uniqueId} is already declared.`);
      }
    }
    const previous = consumers.at(-1);
    if (previous && previous.repository >= consumer.repository) throw new AuthorityError(`${label} must be sorted by repository.`);
    consumers.push(consumer);
  });
  return consumers;
}

// Exactly one unique ID slot per target account the manifest binds, each null
// or one positive decimal ID; a slot that names no bound account, or a bound
// account without a slot, is refused so the inventory and the identities can
// never disagree about which accounts exist.
function parseUniqueIds(value: unknown, label: string, targetAccounts: readonly string[]): Readonly<Record<string, string | null>> {
  const ids = record(value, label);
  exactKeys(ids, targetAccounts, label);
  const parsed: Record<string, string | null> = {};
  for (const account of targetAccounts) {
    const uniqueId = ids[account];
    if (uniqueId === null) {
      parsed[account] = null;
      continue;
    }
    if (typeof uniqueId !== "string" || !decimalId.test(uniqueId)) throw new AuthorityError(`${label}.${account} must be null or one positive decimal unique ID.`);
    if (Object.values(parsed).includes(uniqueId)) throw new AuthorityError(`${label}.${account} ${uniqueId} is already declared.`);
    parsed[account] = uniqueId;
  }
  return parsed;
}

function parseBroker(value: unknown): Broker {
  const label = `${authorityPath}.broker`;
  const broker = record(value, label);
  exactKeys(broker, ["firestoreDatabase", "memberWorkloadIdentityProviderId", "projectId", "projectNumber", "reconcilerServiceAccount", "region", "serviceName", "workloadIdentityPoolId", "workloadIdentityProviderId"], label);
  const shared = {
    firestoreDatabase: string(broker.firestoreDatabase, `${label}.firestoreDatabase`),
    memberWorkloadIdentityProviderId: string(broker.memberWorkloadIdentityProviderId, `${label}.memberWorkloadIdentityProviderId`),
    reconcilerServiceAccount: string(broker.reconcilerServiceAccount, `${label}.reconcilerServiceAccount`),
    region: string(broker.region, `${label}.region`),
    serviceName: string(broker.serviceName, `${label}.serviceName`),
    workloadIdentityPoolId: string(broker.workloadIdentityPoolId, `${label}.workloadIdentityPoolId`),
    workloadIdentityProviderId: string(broker.workloadIdentityProviderId, `${label}.workloadIdentityProviderId`),
  };
  if (!region.test(shared.region)) throw new AuthorityError(`${label}.region must be a Google Cloud region.`);
  if (!/^[a-z][a-z0-9-]{0,48}$/.test(shared.serviceName)) throw new AuthorityError(`${label}.serviceName must be a Cloud Run service name.`);
  if (!/^[a-z][a-z0-9-]{0,61}[a-z0-9]$/.test(shared.firestoreDatabase)) throw new AuthorityError(`${label}.firestoreDatabase must be a Firestore database ID.`);
  if (!serviceAccountId.test(shared.reconcilerServiceAccount)) throw new AuthorityError(`${label}.reconcilerServiceAccount must be a service account ID.`);
  for (const id of [shared.workloadIdentityPoolId, shared.workloadIdentityProviderId, shared.memberWorkloadIdentityProviderId]) {
    if (!/^[a-z][a-z0-9-]{3,31}$/.test(id)) throw new AuthorityError(`${label}: pool and provider IDs must be workload identity IDs.`);
  }
  if (shared.memberWorkloadIdentityProviderId === shared.workloadIdentityProviderId) throw new AuthorityError(`${label}: the member provider must differ from the platform provider.`);
  // The security project does not exist yet. Its coordinates are null until a
  // reviewed change records the real ones; nothing here invents them.
  if (broker.projectId === null && broker.projectNumber === null) return { ...shared, projectId: null, projectNumber: null };
  if (broker.projectId === null || broker.projectNumber === null) throw new AuthorityError(`${label}: projectId and projectNumber must both be null or both be assigned.`);
  const assignedProjectId = string(broker.projectId, `${label}.projectId`);
  const assignedProjectNumber = string(broker.projectNumber, `${label}.projectNumber`);
  if (!projectId.test(assignedProjectId) || !decimalId.test(assignedProjectNumber)) {
    throw new AuthorityError(`${label}: projectId must be a Google Cloud project ID and projectNumber a positive decimal project number.`);
  }
  return { ...shared, projectId: assignedProjectId, projectNumber: assignedProjectNumber };
}

function nullableSha(value: unknown, label: string): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || !commitSha.test(value)) throw new AuthorityError(`${label} must be null or one full lowercase commit SHA.`);
  return value;
}

// Every consumer/account whose permanent identity is not yet recorded. The
// runtime refuses to start while any remains, exactly as it refuses null
// broker coordinates: an email-addressed effect could land on a recreated
// account with the same address and a different identity.
export function unrecordedIdentities(authority: RecoveryAuthority): readonly string[] {
  return authority.consumers.flatMap((consumer) =>
    Object.entries(consumer.serviceAccountUniqueIds)
      .filter(([, uniqueId]) => uniqueId === null)
      .map(([account]) => `${consumer.repository}/${account}`),
  );
}

// Purpose is derived only from the authenticated service-account identity in
// the broker project: one recovery entry of the manifest -- one consumer and
// one effect direction -- or the reconciler.
export function purposeForIdentity(authority: RecoveryAuthority, email: string): Purpose | undefined {
  const projectId = authority.broker.projectId;
  if (projectId === null) return undefined;
  const suffix = `@${projectId}.iam.gserviceaccount.com`;
  if (!email.endsWith(suffix)) return undefined;
  const account = email.slice(0, -suffix.length);
  if (account === authority.broker.reconcilerServiceAccount) return { kind: "reconciler", serviceAccount: account };
  for (const entry of authority.entries) {
    if (entry.trustDomain !== "recovery" || entry.purpose !== "recovery" || entry.serviceAccounts[0] !== account) continue;
    const consumer = authority.consumers.find((candidate) => candidate.repository === entry.consumer);
    if (!consumer) return undefined;
    return { kind: "recovery", consumer, intent: entry.intent, serviceAccount: account };
  }
  return undefined;
}

export function consumerNamed(authority: RecoveryAuthority, repository: string): Consumer | undefined {
  return authority.consumers.find((consumer) => consumer.repository === repository);
}

export function consumerPool(authority: RecoveryAuthority, consumer: Consumer): string {
  return `projects/${consumer.projectNumber}/locations/global/workloadIdentityPools/${authority.broker.workloadIdentityPoolId}`;
}

// The consumer's own provider inside its pool: the one a canonical job's
// GitHub OIDC token is minted for and exchanged through.
export function consumerProvider(authority: RecoveryAuthority, consumer: Consumer): string {
  return `${consumerPool(authority, consumer)}/providers/${authority.broker.workloadIdentityProviderId}`;
}

// The broker's own allow-policy member in the broker project, or undefined
// while the broker project is unrecorded.
export function brokerMember(authority: RecoveryAuthority): string | undefined {
  return authority.broker.projectId === null ? undefined : `serviceAccount:${brokerServiceAccountId}@${authority.broker.projectId}.iam.gserviceaccount.com`;
}

export function serviceAccountResource(consumer: Consumer, uniqueId: string): string {
  return `projects/${consumer.projectId}/serviceAccounts/${uniqueId}`;
}

// Every target of a consumer with its exact managed members: for each
// consumer-domain gcp entry that binds the account, each declared caller and
// event, the active SHA (plus the transition SHA only for transition-eligible
// entries), the attribute.authority principal set that the consumer's own
// bootstrap module binds. The IAM resource is addressed by the recorded
// permanent unique ID, never by the reusable email. Missing pins or missing
// identities refuse the derivation outright.
export function targetsFor(authority: RecoveryAuthority, consumer: Consumer): readonly Target[] | undefined {
  if (consumer.activeWorkflowSha === null) return undefined;
  const pool = consumerPool(authority, consumer);
  const members = new Map<string, Set<string>>();
  for (const entry of authority.entries) {
    if (entry.trustDomain !== "consumer" || entry.purpose !== "gcp") continue;
    const shas = [consumer.activeWorkflowSha, ...(entry.transitionEligible && consumer.transitionWorkflowSha !== null ? [consumer.transitionWorkflowSha] : [])];
    for (const account of entry.serviceAccounts) {
      const set = members.get(account) ?? new Set<string>();
      members.set(account, set);
      for (const caller of entry.callers) {
        for (const event of caller.events) {
          for (const sha of shas) {
            const tuple = [
              `${authority.githubOwner}/${consumer.repository}/${caller.workflow}@${caller.ref}`,
              `${authority.platformRepository}/${entry.workflow}@${sha}`,
              sha,
              entry.environment,
              event,
            ].join(":");
            set.add(`principalSet://iam.googleapis.com/${pool}/attribute.authority/${tuple}`);
          }
        }
      }
    }
  }
  const targets: Target[] = [];
  for (const account of [...members.keys()].sort()) {
    const uniqueId = consumer.serviceAccountUniqueIds[account];
    if (uniqueId === null || uniqueId === undefined) return undefined;
    targets.push({
      account,
      email: `${account}@${consumer.projectId}.iam.gserviceaccount.com`,
      members: [...members.get(account)!].sort(),
      pool,
      resource: serviceAccountResource(consumer, uniqueId),
      uniqueId,
    });
  }
  return targets;
}

// The target a journaled effect names, for a consumer of the authority.
export function targetOfEffect(authority: RecoveryAuthority, consumer: Consumer, body: EntryBody & { readonly kind: "effect" }): Target {
  return { account: body.account, email: body.email, members: body.members, pool: consumerPool(authority, consumer), resource: body.resource, uniqueId: body.uniqueId };
}

export function parseShardId(value: string): string {
  if (!shardId.test(value)) throw new RequestError("shard must match ^[a-z0-9][a-z0-9-]{0,62}$");
  return value;
}

// Every body is parsed exactly once, here, against a closed key set. A body
// that names a project, resource, role, member list, policy, object name, or
// any probe, inventory, or canary evidence is refused as an unknown field:
// those facts come from the identity, the inventory, and the broker's own
// sources only. The consumer and intent are repeated in the body so that the
// recorded request is self-describing; they must equal the purpose's binding.
export function parseAppendBody(shard: string, body: unknown): AppendRequest {
  const source = requestRecord(body, "body");
  const consumer = typeof source.consumer === "string" && repositoryName.test(source.consumer) ? source.consumer : undefined;
  if (consumer === undefined) throw new RequestError("consumer must be a consumer repository name");
  const key = requestKey(source.key);
  let parsed: AppendBody;
  if (source.intent === "RESTORE") {
    requestKeys(source, ["consumer", "intent", "key", "source"]);
    if (typeof source.source !== "string" || !shardId.test(source.source)) throw new RequestError("source must name the CLOSED quarantine shard to restore");
    parsed = { kind: "restore", source: source.source };
  } else {
    requestKeys(source, ["consumer", "intent", "key"]);
    if (source.intent !== "QUARANTINE") throw new RequestError(`intent must be one of ${intents.join(", ")}`);
    parsed = { kind: "quarantine" };
  }
  return { kind: "append", body: parsed, bodyHash: sha256Hex(canonicalJson({ consumer, key, ...appendBodyJson(parsed) })), consumer, key, shard: parseShardId(shard) };
}

export function appendBodyJson(body: AppendBody): Record<string, unknown> {
  switch (body.kind) {
    case "quarantine":
      return { intent: "QUARANTINE" };
    case "restore":
      return { intent: "RESTORE", source: body.source };
  }
}

export function parseCloseBody(shard: string, body: unknown): CloseRequest {
  const source = requestRecord(body, "body");
  requestKeys(source, ["key"]);
  const key = requestKey(source.key);
  return { kind: "close", bodyHash: sha256Hex(canonicalJson({ key })), key, shard: parseShardId(shard) };
}

export function parseReconcileBody(shard: string | null, body: unknown): ReconcileRequest {
  const source = requestRecord(body, "body");
  requestKeys(source, []);
  return { kind: "reconcile", shard: shard === null ? null : parseShardId(shard) };
}

export const emptyChain: TargetChain = { allowed: { count: 0, lastObservedAt: null }, denied: 0, inventory: null, journaled: 0, post: null, revocation: null, suppressed: 0 };

export function horizonOf(revocation: ProbeRecord): number {
  return Date.parse(revocation.observedAt) + tokenHorizonSeconds * 1000;
}

// The earliest instant a DENIED observation can start a chain for this
// target: the quarantine acknowledgement, then the inventory baseline.
export function chainFloor(state: TargetState): number {
  const acked = state.effect.ackedAt === null ? Number.NaN : Date.parse(state.effect.ackedAt);
  const baseline = state.chain.inventory === null ? Number.NaN : Date.parse(state.chain.inventory.observedAt);
  return Math.max(acked, baseline);
}

export type Observation =
  | { readonly kind: "probe"; readonly probe: ProbeRecord }
  | { readonly kind: "inventory"; readonly inventory: InventoryRecord };

// What an observation meant for the chain: it started it (REVOCATION), ended
// it (HORIZON), broke it (ALLOWED or CHANGE), established the inventory
// baseline (BASELINE), or repeated known facts (REDUNDANT).
export type ChainRole = "ALLOWED" | "BASELINE" | "CHANGE" | "HORIZON" | "REDUNDANT" | "REVOCATION";

// Apply one broker-recorded observation to a target's chain. Pure: the ledger
// commits the result with the shard document. A later ALLOWED observation or
// a changed inventory voids the revocation and post-horizon probes observed
// before it, so a timer alone never ends a chain; a DENIED observation counts
// as the revocation only after the acknowledgement, after the latest ALLOWED
// observation, and at or after the inventory baseline; a DENIED observation
// counts as the post-horizon probe only at or after the horizon.
export function applyObservation(state: TargetState, observation: Observation): { readonly chain: TargetChain; readonly role: ChainRole } {
  const chain = state.chain;
  if (observation.kind === "inventory") {
    const { findings, hash, observedAt } = observation.inventory;
    if (chain.inventory === null) {
      return { chain: { ...chain, inventory: { changes: 0, findings, hash, observations: 1, observedAt, verifiedAt: observedAt } }, role: "BASELINE" };
    }
    if (chain.inventory.hash === hash) {
      const verifiedAt = Date.parse(observedAt) > Date.parse(chain.inventory.verifiedAt) ? observedAt : chain.inventory.verifiedAt;
      return { chain: { ...chain, inventory: { ...chain.inventory, observations: chain.inventory.observations + 1, verifiedAt } }, role: "REDUNDANT" };
    }
    const changed = Date.parse(observedAt);
    const voided = chain.revocation !== null && Date.parse(chain.revocation.observedAt) < changed;
    return {
      chain: {
        ...chain,
        inventory: { changes: chain.inventory.changes + 1, findings, hash, observations: chain.inventory.observations + 1, observedAt, verifiedAt: observedAt },
        post: voided ? null : chain.post,
        revocation: voided ? null : chain.revocation,
      },
      role: "CHANGE",
    };
  }
  const probe = observation.probe;
  const observed = Date.parse(probe.observedAt);
  if (probe.outcome === "ALLOWED") {
    const last = chain.allowed.lastObservedAt;
    const lastObservedAt = last === null || observed > Date.parse(last) ? probe.observedAt : last;
    const voided = chain.revocation !== null && Date.parse(chain.revocation.observedAt) <= observed;
    return {
      chain: { ...chain, allowed: { count: chain.allowed.count + 1, lastObservedAt }, post: voided ? null : chain.post, revocation: voided ? null : chain.revocation },
      role: "ALLOWED",
    };
  }
  const counted = { ...chain, denied: chain.denied + 1 };
  if (chain.inventory === null) return { chain: counted, role: "REDUNDANT" };
  if (chain.revocation === null) {
    const afterAllowed = chain.allowed.lastObservedAt === null || observed > Date.parse(chain.allowed.lastObservedAt);
    if (observed >= chainFloor(state) && afterAllowed) return { chain: { ...counted, revocation: probe }, role: "REVOCATION" };
    return { chain: counted, role: "REDUNDANT" };
  }
  if (chain.post === null && observed >= horizonOf(chain.revocation)) return { chain: { ...counted, post: probe }, role: "HORIZON" };
  return { chain: counted, role: "REDUNDANT" };
}

export interface ScanReadiness {
  readonly blockers: readonly string[];
  // The instant the token horizon drains for the latest revocation probe --
  // the earliest a post-horizon probe can count -- once every target has one.
  readonly horizonAt: string | null;
  readonly ready: boolean;
}

// A probe the broker should record now: the phase, the exact target identity
// and member, and the earliest observation time the ledger will admit for it.
export interface ProbeNeed {
  readonly account: string;
  readonly email: string;
  readonly member: string;
  readonly notBefore: string;
  readonly phase: ProbePhase;
  readonly resource: string;
  readonly uniqueId: string;
}

function sortedTargets(shard: Shard): ReadonlyArray<readonly [string, TargetState]> {
  return Object.keys(shard.targets)
    .sort()
    .map((account) => [account, shard.targets[account]!] as const);
}

// Scan-ready is a pure judgement over the committed shard state: every target
// of a QUARANTINE shard acknowledged with no alternate issuer in its policy
// and no alternate credential path in its recorded inventory, a
// broker-recorded DENIED probe of a managed member against the exact target
// identity after that target's acknowledgement and inventory baseline, the
// one-hour token horizon drained since that probe, and another DENIED probe
// after the horizon. A fixed propagation timer alone never satisfies it, and
// nothing a caller submits contributes to it.
export function scanReadiness(shard: Shard, now: Date): ScanReadiness {
  const blockers: string[] = [];
  if (shard.intent !== "QUARANTINE") return { blockers: ["shard intent is RESTORE"], horizonAt: null, ready: false };
  const targets = sortedTargets(shard);
  if (targets.length === 0) blockers.push("no target has been journaled");
  let horizon = 0;
  let horizonKnown = true;
  for (const [account, state] of targets) {
    if (state.effect.state !== "ACKED") {
      blockers.push(`${account}: quarantine is ${state.effect.state}`);
      horizonKnown = false;
      continue;
    }
    if (state.effect.alternateIssuers.length > 0) blockers.push(`${account}: alternate credential issuers ${state.effect.alternateIssuers.join(", ")}`);
    const chain = state.chain;
    if (chain.inventory === null) {
      blockers.push(`${account}: no credential inventory since the quarantine acknowledgement`);
      horizonKnown = false;
      continue;
    }
    if (chain.inventory.findings.length > 0) blockers.push(`${account}: alternate credential paths ${chain.inventory.findings.join(", ")}`);
    if (chain.revocation === null) {
      blockers.push(`${account}: no DENIED impersonation probe after the quarantine acknowledgement`);
      horizonKnown = false;
      continue;
    }
    const targetHorizon = horizonOf(chain.revocation);
    horizon = Math.max(horizon, targetHorizon);
    if (now.getTime() < targetHorizon) {
      blockers.push(`${account}: token horizon drains at ${new Date(targetHorizon).toISOString()}`);
      continue;
    }
    if (chain.post === null) blockers.push(`${account}: no DENIED impersonation probe after the token horizon ${new Date(targetHorizon).toISOString()}`);
  }
  return { blockers, horizonAt: horizonKnown && horizon > 0 ? new Date(horizon).toISOString() : null, ready: blockers.length === 0 };
}

// The probes the broker should record for an OPEN QUARANTINE shard now: a
// revocation probe for every acknowledged, inventoried, clean target without
// one, and a post-horizon probe for every target whose horizon has drained
// without one. Targets with an alternate issuer or an alternate credential
// path are never ready in this shard, so they are not probed. The member
// tried is the target's first managed member.
export function probesNeeded(shard: Shard, now: Date, members: (account: string) => Target | undefined): readonly ProbeNeed[] {
  if (shard.phase !== "OPEN" || shard.intent !== "QUARANTINE") return [];
  const needs: ProbeNeed[] = [];
  for (const [account, state] of sortedTargets(shard)) {
    if (state.effect.state !== "ACKED" || state.effect.alternateIssuers.length > 0) continue;
    const chain = state.chain;
    if (chain.inventory === null || chain.inventory.findings.length > 0) continue;
    const target = members(account);
    const member = target?.members[0];
    if (!target || member === undefined) continue;
    const base = { account, email: target.email, member, resource: target.resource, uniqueId: target.uniqueId };
    if (chain.revocation === null) {
      const floor = Math.max(chainFloor(state), chain.allowed.lastObservedAt === null ? 0 : Date.parse(chain.allowed.lastObservedAt) + 1);
      needs.push({ ...base, notBefore: new Date(floor).toISOString(), phase: "REVOCATION" });
    } else if (chain.post === null && now.getTime() >= horizonOf(chain.revocation)) {
      needs.push({ ...base, notBefore: new Date(horizonOf(chain.revocation)).toISOString(), phase: "HORIZON" });
    }
  }
  return needs;
}

// A fresh inventory of one target as observed by the broker immediately
// before a gate; absent when the observation was unavailable.
export interface FreshInventory {
  readonly findings: readonly string[];
  readonly hash: string;
  readonly observedAt: string;
}

// The blockers a gate raises when the freshly observed inventory of a target
// is unavailable, dirty, or differs from the baseline the chain was built on:
// the quarantine/close interval is protected exactly by this equality.
export function inventoryDrift(shard: Shard, fresh: Readonly<Record<string, FreshInventory>>): readonly string[] {
  const blockers: string[] = [];
  for (const [account, state] of sortedTargets(shard)) {
    if (state.effect.state !== "ACKED" || state.chain.inventory === null) continue;
    const current = fresh[account];
    if (!current) {
      blockers.push(`${account}: credential inventory is unavailable at the gate`);
      continue;
    }
    if (current.findings.length > 0) blockers.push(`${account}: alternate credential paths at the gate ${current.findings.join(", ")}`);
    if (current.hash !== state.chain.inventory.hash) blockers.push(`${account}: credential inventory changed since ${state.chain.inventory.observedAt}`);
  }
  return blockers;
}

export function probeKey(probe: ProbeRecord): string {
  return `probe/${probe.account}/${probe.phase}/${probe.observedAt}`;
}

export function inventoryKey(inventory: InventoryRecord): string {
  return `inventory/${inventory.account}/${inventory.observedAt}`;
}

export function inventoryHash(summary: InventorySummary): string {
  return sha256Hex(canonicalJson(inventorySummaryJson(summary)));
}

export function inventorySummaryJson(summary: InventorySummary): Record<string, unknown> {
  return {
    ancestry: [...summary.ancestry],
    attachments: [...summary.attachments],
    grants: [...summary.grants],
    keys: [...summary.keys],
    lifetimeExtension: summary.lifetimeExtension,
    policies: summary.policies.map((policy) => ({ etag: policy.etag, resource: policy.resource })),
    services: [...summary.services],
  };
}

function requestKey(value: unknown): string {
  if (typeof value !== "string" || !idempotencyKey.test(value)) {
    throw new RequestError("key must match ^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$");
  }
  return value;
}

function requestRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new RequestError(`${label} must be a JSON object`);
  return value;
}

function requestKeys(value: Record<string, unknown>, keys: readonly string[]): void {
  const actual = Object.keys(value).sort();
  if (actual.join(",") !== [...keys].sort().join(",")) {
    throw new RequestError(`fields must be exactly [${keys.join(", ")}]; received [${actual.join(", ")}]`);
  }
}

// Canonical JSON: object keys sorted recursively, no whitespace. Every hash
// and every projected object is computed over these bytes.
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new TypeError("Canonical JSON admits only safe integers.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  throw new TypeError(`Canonical JSON cannot encode ${typeof value}.`);
}

export function sha256Hex(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}

export function entryObjectName(shard: string, sequence: number): string {
  return `shards/${shard}/entries/${String(sequence).padStart(6, "0")}.json`;
}

export function terminalObjectName(shard: string): string {
  return `shards/${shard}/close.json`;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new AuthorityError(`${label} must be an object.`);
  return value;
}

function string(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new AuthorityError(`${label} must be a non-empty string.`);
  return value;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  if (Object.keys(value).sort().join(",") !== [...keys].sort().join(",")) {
    throw new AuthorityError(`${label} keys must be exactly ${keys.join(", ")}.`);
  }
}
