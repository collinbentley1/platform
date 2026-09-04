import { createHash } from "node:crypto";
import {
  type RecoveryAuthorityEntry,
  type RecoveryIntent,
  type WorkflowAuthorityEntry,
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
// No body carries evidence. Negative impersonation probes are recorded by the
// broker itself from its probe source, never from a caller, and a shard is
// scan-ready only on that recorded evidence. Retries are secured by the ledger:
// the same key with the same body returns the recorded result; the same key
// with a different body is refused. A shard is CLOSED only once its terminal
// receipt is verified in GCS; until then it is FINALIZING and no caller-facing
// completion exists.

export const authorityPath = "protected-recovery/authority.json";
export const intents = recoveryIntents;
export type Intent = RecoveryIntent;
export const managedRole = "roles/iam.workloadIdentityUser";
// Binding removal blocks new impersonation only. A holder of the managed role
// can mint a one-hour access token up to the moment removal propagates, so a
// protected scan waits this long after the last plausibly successful mint --
// bounded by the first negative probe after the last positive one -- and then
// needs another negative probe.
export const tokenHorizonSeconds = 3600;
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
// No broker-verifiable negative-impersonation probe source exists yet. The
// broker cannot mint a GitHub OIDC token to try the federated member itself,
// a consumer-run attempt is an unverifiable assertion, and the broker's own
// authority is limited to the target policies; so the production binding
// reports every probe unavailable, readiness stays blocked, and this names the
// live prerequisite that activation must satisfy before any protected close.
export const probePrerequisite = "no broker-verifiable negative-impersonation probe source is deployed; activation must supply an approved source whose result binds the probe principal, the target unique ID, the attempted member and permission, a server-observed time, and an independently verifiable outcome";

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

export type EntryBody =
  | { readonly kind: "effect"; readonly account: string; readonly email: string; readonly intent: Intent; readonly members: readonly string[]; readonly resource: string; readonly uniqueId: string }
  | ({ readonly kind: "probe" } & ProbeRecord);

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

interface ShardBase {
  readonly consumer: string;
  readonly createdAt: string;
  readonly intent: Intent;
  readonly nextSequence: number;
  readonly pendingEffects: number;
  readonly pendingOutbox: number;
  readonly source: string | null;
  readonly targets: Readonly<Record<string, number>>;
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
      const invokers = manifest.entries.filter((entry): entry is RecoveryAuthorityEntry => entry.trustDomain === "recovery" && entry.consumer === consumer.repository && entry.intent === intent);
      if (invokers.length !== 1) throw new AuthorityError(`${manifestPath}: consumer ${consumer.repository} must have exactly one ${intent} invoker; found ${invokers.length}.`);
    }
  }
  for (const entry of manifest.entries) {
    if (entry.trustDomain === "recovery" && !consumers.some((consumer) => consumer.repository === entry.consumer)) {
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
  exactKeys(broker, ["firestoreDatabase", "projectId", "projectNumber", "reconcilerServiceAccount", "region", "serviceName", "workloadIdentityPoolId", "workloadIdentityProviderId"], label);
  const shared = {
    firestoreDatabase: string(broker.firestoreDatabase, `${label}.firestoreDatabase`),
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
  for (const id of [shared.workloadIdentityPoolId, shared.workloadIdentityProviderId]) {
    if (!/^[a-z][a-z0-9-]{3,31}$/.test(id)) throw new AuthorityError(`${label}: pool and provider IDs must be workload identity IDs.`);
  }
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
    if (entry.trustDomain !== "recovery" || entry.serviceAccounts[0] !== account) continue;
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

export function parseShardId(value: string): string {
  if (!shardId.test(value)) throw new RequestError("shard must match ^[a-z0-9][a-z0-9-]{0,62}$");
  return value;
}

// Every body is parsed exactly once, here, against a closed key set. A body
// that names a project, resource, role, member list, policy, object name, or
// any probe or canary evidence is refused as an unknown field: those facts
// come from the identity, the inventory, and the broker's own probes only. The
// consumer and intent are repeated in the body so that the recorded request is
// self-describing; they must equal the purpose's binding.
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

interface ProbeChain {
  readonly horizon: number | null;
  readonly post: Entry | undefined;
  readonly revocation: Entry | undefined;
}

// The probes that count for one acknowledged target, in two phases. The
// revocation probe is the earliest DENIED observation after the quarantine
// acknowledgement and after the latest ALLOWED observation: minting may have
// succeeded up to that moment, so the token horizon drains one hour after it.
// The post-horizon probe is a DENIED observation at or after that horizon.
// Any later ALLOWED observation restarts the chain; a timer alone never ends
// it. Only probes that name the target's exact identity and a managed member
// are considered.
function probeChain(effect: Entry, entries: readonly Entry[]): ProbeChain {
  const target = effect.body;
  if (target.kind !== "effect" || effect.progress?.state !== "ACKED") throw new TypeError(`Entry ${effect.sequence} is not an acknowledged effect.`);
  const ackedAt = Date.parse(effect.progress.ackedAt);
  const probes = entries
    .filter((entry): entry is Entry & { readonly body: { readonly kind: "probe" } & ProbeRecord } =>
      entry.body.kind === "probe" && entry.body.account === target.account && entry.body.uniqueId === target.uniqueId && target.members.includes(entry.body.member) && Date.parse(entry.body.observedAt) >= ackedAt,
    )
    .sort((left, right) => Date.parse(left.body.observedAt) - Date.parse(right.body.observedAt) || left.sequence - right.sequence);
  const lastAllowed = probes.filter((probe) => probe.body.outcome === "ALLOWED").at(-1);
  const denied = probes.filter((probe) => probe.body.outcome === "DENIED" && (!lastAllowed || Date.parse(probe.body.observedAt) > Date.parse(lastAllowed.body.observedAt)));
  const revocation = denied[0];
  if (!revocation) return { horizon: null, post: undefined, revocation: undefined };
  const horizon = Date.parse(revocation.body.observedAt) + tokenHorizonSeconds * 1000;
  return { horizon, post: denied.find((probe) => Date.parse(probe.body.observedAt) >= horizon), revocation };
}

function ackedEffects(shard: Shard, entries: readonly Entry[]): ReadonlyArray<{ readonly account: string; readonly effect: Entry | undefined }> {
  return Object.keys(shard.targets)
    .sort()
    .map((account) => ({ account, effect: entries.find((entry) => entry.sequence === shard.targets[account]) }));
}

// Scan-ready is a pure judgement over committed ledger facts: every target of
// a QUARANTINE shard acknowledged with no alternate issuer in its policy, a
// broker-recorded DENIED probe of a managed member against the exact target
// identity after that target's acknowledgement, the one-hour token horizon
// drained since that probe, and another DENIED probe after the horizon. A
// fixed propagation timer alone never satisfies it, and nothing a caller
// submits contributes to it.
export function scanReadiness(shard: Shard, entries: readonly Entry[], now: Date): ScanReadiness {
  const blockers: string[] = [];
  if (shard.intent !== "QUARANTINE") return { blockers: ["shard intent is RESTORE"], horizonAt: null, ready: false };
  const targets = ackedEffects(shard, entries);
  if (targets.length === 0) blockers.push("no target has been journaled");
  let horizon = 0;
  let horizonKnown = true;
  for (const { account, effect } of targets) {
    if (!effect || effect.body.kind !== "effect" || effect.progress === null) {
      blockers.push(`${account}: effect entry is missing`);
      horizonKnown = false;
      continue;
    }
    if (effect.progress.state !== "ACKED") {
      blockers.push(`${account}: quarantine is ${effect.progress.state}`);
      horizonKnown = false;
      continue;
    }
    if (effect.progress.alternateIssuers.length > 0) blockers.push(`${account}: alternate credential issuers ${effect.progress.alternateIssuers.join(", ")}`);
    const chain = probeChain(effect, entries);
    if (!chain.revocation || chain.horizon === null) {
      blockers.push(`${account}: no DENIED impersonation probe after the quarantine acknowledgement`);
      horizonKnown = false;
      continue;
    }
    horizon = Math.max(horizon, chain.horizon);
    if (now.getTime() < chain.horizon) {
      blockers.push(`${account}: token horizon drains at ${new Date(chain.horizon).toISOString()}`);
      continue;
    }
    if (!chain.post) blockers.push(`${account}: no DENIED impersonation probe after the token horizon ${new Date(chain.horizon).toISOString()}`);
  }
  return { blockers, horizonAt: horizonKnown && horizon > 0 ? new Date(horizon).toISOString() : null, ready: blockers.length === 0 };
}

// The probes the broker should record for an OPEN QUARANTINE shard now: a
// revocation probe for every acknowledged target without one, and a
// post-horizon probe for every target whose horizon has drained without one.
// Targets with an alternate issuer are never ready in this shard, so they are
// not probed. The member tried is the target's first managed member.
export function probesNeeded(shard: Shard, entries: readonly Entry[], now: Date): readonly ProbeNeed[] {
  if (shard.phase !== "OPEN" || shard.intent !== "QUARANTINE") return [];
  const needs: ProbeNeed[] = [];
  for (const { effect } of ackedEffects(shard, entries)) {
    if (!effect || effect.body.kind !== "effect" || effect.progress?.state !== "ACKED" || effect.progress.alternateIssuers.length > 0) continue;
    const member = effect.body.members[0];
    if (member === undefined) continue;
    const base = { account: effect.body.account, email: effect.body.email, member, resource: effect.body.resource, uniqueId: effect.body.uniqueId };
    const chain = probeChain(effect, entries);
    if (!chain.revocation || chain.horizon === null) needs.push({ ...base, notBefore: effect.progress.ackedAt, phase: "REVOCATION" });
    else if (!chain.post && now.getTime() >= chain.horizon) needs.push({ ...base, notBefore: new Date(chain.horizon).toISOString(), phase: "HORIZON" });
  }
  return needs;
}

export function probeKey(probe: ProbeRecord): string {
  return `probe/${probe.account}/${probe.phase}/${probe.observedAt}`;
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
