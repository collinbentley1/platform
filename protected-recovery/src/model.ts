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
//     409 PROBE_UNAVAILABLE | ROUND_STALE | INVENTORY_BLOCKED   a QUARANTINE is refused before acceptance unless one complete
//                                                 CONTROL round -- a receipt from every exact member, minted ALLOWED against
//                                                 every target it is bound to -- exists, its binding still holds against the
//                                                 credential inventory observed now, and that inventory is clean
//   POST /v1/shards/{shard}/close      the same invoker   {"key"}
//     200                             -> {"shard", "phase": "CLOSING", "closeHighWater", "closingAt"}
//     409 NOT_READY                   -> {"blockers": [...]}  a QUARANTINE shard closes only once scan-ready
//   POST /v1/shards/{shard}/reconcile  the same invoker, reconciler   {}
//   POST /v1/reconcile                 reconciler                     {}   (every shard with recorded pending work, paginated)
//     200                             -> {"shards": [ShardView], "next": cursor | null}
//   GET  /v1/shards/{shard}            the same invoker, reconciler
//     200                             -> {"shard": ShardView, "entries": [EntryView]}
//   POST /v1/rounds                    the consumer's QUARANTINE invoker
//     {"key", "consumer", "phase": "CONTROL", "shard": null, "label"}           the positive-control round before a quarantine
//     {"key", "consumer", "phase": "REVOCATION" | "HORIZON", "shard", "label"}  the probe rounds of one OPEN quarantine shard
//     201 opened / 200 replayed       -> {"round": RoundView}   the round manifest, bound at opening to every exact member,
//                                        the platform pins, every target's permanent identity, policy etag, and inventory
//                                        hash, and the live Deny state by policy etag and form; idempotent on its coordinates
//     409 PINS_UNRECORDED | INVENTORY_BLOCKED | SHARD_NOT_OPEN, 404 NOT_FOUND
//   GET  /v1/rounds/{round}            either invoker of the consumer, reconciler
//     200                             -> {"round": RoundView}   the receipts recorded so far and every delivery still owed
//   POST /v1/members                   the consumer's member-delivery identity   {"token": "<GitHub OIDC token>"}
//     200                             -> {"member", "controls", "probes", "rounds"}   the canonical job's own credential,
//                                        verified, exchanged at STS, and used at once to mint as the member against every
//                                        target it is bound to; the outcomes are recorded (a receipt in every open round of
//                                        the consumer whose binding the delivery satisfies, the revocation or post-horizon
//                                        probe of every OPEN quarantine that needs it) and the bearer is discarded -- it is
//                                        never stored
//     409 MEMBER_UNVERIFIED | MEMBER_EXPIRING   refused before any exchange
//   POST /v1/maintenance               a RESTORE invoker   {"key", "action": "open" | "close"}
//     200                             -> {"ticket": {...} | null}   the maintenance ticket under which the root may widen the
//                                        Deny matrix to its maintenance form; refused (409 QUARANTINE_ACTIVE) while any
//                                        QUARANTINE shard is not CLOSED, and while a ticket is open no QUARANTINE is accepted
//   400 INVALID_REQUEST, 401 UNAUTHENTICATED, 403 FORBIDDEN, 404 NOT_FOUND, 413 BODY_TOO_LARGE, 503 LEDGER_UNAVAILABLE |
//   503 DEPENDENCY_UNAVAILABLE (an external dependency of the request answered with a failure)
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
// The horizon when the token-lifetime path was ambiguous during the interval:
// constraints/iam.allowServiceAccountCredentialLifetimeExtension can extend an
// access token to twelve hours, so a chain rebuilt after a change of the Deny
// form, of a bound role's definition, or of a lifetime-extension policy waits
// the maximum lifetime such a change could have granted.
export const extendedTokenHorizonSeconds = 43_200;
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
// generateAccessToken against the target's permanent identity itself, at the
// moment the job delivers the token through POST /v1/members (see
// protected-recovery/deliver-member.sh). The bearer is never stored: what the
// ledger keeps is the outcome. A member whose canonical job has never
// delivered and minted (the positive control) cannot be quarantined, so every
// QUARANTINE that needs it is refused before acceptance, before PREPARE, and
// before any mutation; a member that has not delivered again after the effect
// owes the delivery its negative probe needs.
export function probePrerequisite(member: string): string {
  return `no positive control for ${member}: the canonical job that is this member must deliver its GitHub OIDC token, minted for the consumer provider's audience, to POST /v1/members so the broker can mint as it once before any quarantine`;
}

export function deliveryOwed(member: string, phase: ProbePhase): string {
  return `${phase} probe of ${member} awaits a delivery: the canonical job that is this member must run again and deliver its credential to POST /v1/members`;
}

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
  // The one principal the Deny matrix's bootstrap form excepts on exactly the
  // rows the module's own apply mutates; null until the offline root is named.
  readonly bootstrapPrincipal: string | null;
  readonly broker: Broker;
  readonly consumers: readonly Consumer[];
  readonly entries: readonly WorkflowAuthorityEntry[];
  readonly githubOwner: string;
  readonly githubOwnerId: string;
  // The principals the matrix's maintenance form excepts on the consumer IAM,
  // federation, role, and organization-policy rows under an open ticket.
  readonly maintenancePrincipals: readonly string[];
  // The organization every consumer project and the broker project sit under;
  // the third Deny attachment point. Null until the organization exists.
  readonly organizationId: string | null;
  readonly platformRepository: string;
  readonly platformRepositoryId: string;
  readonly targetAccounts: readonly string[];
}

export type Purpose =
  | { readonly kind: "recovery"; readonly consumer: Consumer; readonly intent: Intent; readonly serviceAccount: string }
  | { readonly kind: "reconciler"; readonly serviceAccount: string }
  // The member-delivery identity of one consumer: the canonical jobs of that
  // consumer reach it through the broker pool and may only deliver their own
  // credential (POST /v1/members).
  | { readonly kind: "member"; readonly consumer: Consumer; readonly serviceAccount: string };

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
// The live Deny state the inventory read in the same batch: the deny policies
// at the broker project, the organization, and the consumer project, by name
// and etag, and the form they satisfy (steady, bootstrap, maintenance, or
// drifted). Any change of a policy changes the hash; any form but steady is a
// finding, so authority is disabled by the state itself, never by an apply.
export interface DenyStateSummary {
  readonly form: string;
  readonly policies: ReadonlyArray<{ readonly attachment: string; readonly etag: string; readonly name: string }>;
}

export interface InventorySummary {
  readonly ancestry: readonly string[];
  readonly attachments: readonly string[];
  readonly denyState: DenyStateSummary;
  readonly grants: readonly string[];
  readonly keys: readonly string[];
  readonly lifetimeExtension: string | null;
  // The lifetime-extension policy resource set at the project and at every
  // ancestor, each as "<resource>|absent" or "<resource>|<etag>|<updateTime>":
  // a policy set and restored between two reads still moves its updateTime.
  readonly lifetimePolicies: readonly string[];
  // Service-agent grants the frozen attachment model neutralized, with the
  // proof each rested on; recorded so the receipt carries the reasoning.
  readonly neutralized: readonly string[];
  readonly policies: ReadonlyArray<{ readonly etag: string; readonly resource: string }>;
  // The definition version (etag) of every role bound in the ancestry: a
  // custom role edited and restored still moves its etag.
  readonly roles: ReadonlyArray<{ readonly etag: string; readonly name: string }>;
  // Which attachment APIs were enabled in the consumer project when read; a
  // disabled API hosts no attachment and is recorded as such, never assumed.
  readonly services: readonly string[];
}

// An inventory is observed over an interval: observedAt is when the earliest
// of its component reads began and observedUntil when the last one completed.
// Folding orders inventories by observedUntil, and a change voids every chain
// built before the read that detected it, because the change could have
// landed at any instant up to that read.
export interface InventoryRecord {
  readonly account: string;
  readonly email: string;
  readonly findings: readonly string[];
  readonly hash: string;
  readonly observedAt: string;
  readonly observedUntil: string;
  readonly summary: InventorySummary;
  readonly uniqueId: string;
}

// What the broker keeps of a delivered member credential: never the bearer,
// only the member it proved, the consumer whose provider it was minted for,
// the federated principal STS created for it, when it was delivered and
// expired, and the outcome of minting as it against every target it is bound
// to -- the positive control that admits a quarantine of those targets.
export interface MemberControl {
  readonly observedAt: string;
  readonly outcome: ProbeOutcome;
  readonly uniqueId: string;
}

export interface MemberControlRecord {
  readonly consumer: string;
  readonly deliveredAt: string;
  readonly expiresAt: string;
  readonly member: string;
  readonly principal: string;
  readonly targets: Readonly<Record<string, MemberControl>>;
}

// The one maintenance ticket: while it is open the root may widen the Deny
// matrix to its maintenance form for infrastructure work, no QUARANTINE is
// accepted, and once it expires a still-widened matrix is drift. It cannot be
// opened while any QUARANTINE shard is not CLOSED.
export const maintenanceTicketSeconds = 4 * 3600;

// How recent the complete CONTROL round a quarantine rests on must be for the
// quarantine to be accepted, prepared, or resumed: every canonical job must
// have delivered and minted within this window, so admission rests on a
// channel proven to exist in its current form, not on a round from jobs that
// may since have gone.
export const controlValiditySeconds = 24 * 3600;

// A delivery round: one complete pass of every canonical job of a consumer
// through POST /v1/members, represented as one manifest the broker binds at
// opening and completes only from receipts that satisfy the binding.
//
//   CONTROL      before a quarantine, with the bindings standing: every member
//                mints against every target it is bound to. A quarantine
//                target is accepted, prepared, or resumed only against one
//                complete CONTROL round whose binding still holds and whose
//                receipt from every member of that target is ALLOWED.
//   REVOCATION   after the quarantine is acknowledged: every member mints
//                again, the revocation probe of its chain, DENIED once the
//                binding is gone.
//   HORIZON      after the token horizon: every member mints once more.
//
// The binding: the exact members, the platform commits the consumer records
// (which every delivery's job_workflow_sha must be one of), every target's
// permanent identity, allow-policy etag, and inventory hash, and the live
// Deny state by policy etag and form. A receipt records the delivering run
// and attempt, the federated principal, and the outcome against each target.
export const roundPhases = ["CONTROL", "HORIZON", "REVOCATION"] as const;
export type RoundPhase = (typeof roundPhases)[number];

export interface RoundTarget {
  readonly inventoryHash: string;
  readonly members: readonly string[];
  readonly policyEtag: string;
  readonly uniqueId: string;
}

export interface RoundReceipt {
  readonly controls: Readonly<Record<string, MemberControl>>;
  readonly deliveredAt: string;
  readonly platformSha: string;
  readonly principal: string;
  readonly runAttempt: string;
  readonly runId: string;
}

export interface RoundBinding {
  readonly denyState: DenyStateSummary;
  readonly members: readonly string[];
  readonly platformShas: readonly string[];
  readonly targets: Readonly<Record<string, RoundTarget>>;
}

export interface RoundManifest extends RoundBinding {
  readonly completedAt: string | null;
  readonly consumer: string;
  readonly key: string;
  readonly label: string;
  readonly openedAt: string;
  readonly openedBy: string;
  readonly phase: RoundPhase;
  readonly receipts: Readonly<Record<string, RoundReceipt>>;
  readonly shard: string | null;
  readonly version: number;
}

// One consumer's rounds: the latest complete CONTROL round, which admits its
// quarantines, and every round still open to receipts.
export interface RoundPointer {
  readonly control: string | null;
  readonly open: readonly string[];
}

// A round is identified by its coordinates alone, so a retried opening
// reuses it.
export function roundId(consumer: string, phase: RoundPhase, shard: string | null, label: string): string {
  return sha256Hex(canonicalJson({ consumer, label, phase, shard }));
}

export interface RoundDebt {
  readonly account: string;
  readonly member: string;
  readonly reason: string;
}

// What a round still owes: for every member and every target it is bound
// to, a receipt whose control was minted against that target's exact
// identity. The outcome is judged where it matters -- admission needs
// ALLOWED in the CONTROL round for each target it admits; a shard's chains
// need DENIED after its acknowledgement -- so a round is complete when every
// expected delivery has happened, whatever each mint answered.
export function roundOwed(round: RoundManifest): readonly RoundDebt[] {
  const owed: RoundDebt[] = [];
  for (const member of round.members) {
    const receipt = round.receipts[member];
    for (const account of Object.keys(round.targets).sort()) {
      const target = round.targets[account]!;
      if (!target.members.includes(member)) continue;
      if (!receipt) {
        owed.push({ account, member, reason: "the canonical job that is this member has not delivered to this round" });
        continue;
      }
      const control = receipt.controls[account];
      if (!control) owed.push({ account, member, reason: "the delivery did not mint against this target" });
      else if (control.uniqueId !== target.uniqueId) owed.push({ account, member, reason: `the delivery minted against ${control.uniqueId}, not the bound identity ${target.uniqueId}` });
    }
  }
  return owed;
}

export function roundComplete(round: RoundManifest): boolean {
  return roundOwed(round).length === 0;
}

export interface MaintenanceTicket {
  readonly expiresAt: string;
  readonly key: string;
  readonly openedAt: string;
  readonly openedBy: string;
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
// The summary is the preimage of the hash, kept in the committed state so the
// terminal receipt carries it even when the observation that set it could not
// be journaled as an entry.
export interface ChainInventory {
  readonly changes: number;
  readonly findings: readonly string[];
  readonly hash: string;
  // The waiting horizon of every chain built on this baseline: the one-hour
  // token lifetime, or twelve hours when the lifetime path was ambiguous
  // before this baseline (see extendedTokenHorizonSeconds).
  readonly horizonSeconds: number;
  readonly observations: number;
  readonly observedAt: string;
  // When the observation that set this baseline completed: the earliest a
  // DENIED probe can start a chain, and the instant later reads are ordered by.
  readonly observedUntil: string;
  readonly summary: InventorySummary;
  readonly verifiedAt: string;
}

// The probe chain of one managed member of one target: the revocation probe
// (the earliest DENIED observation of that member after the quarantine
// acknowledgement, after the member's latest ALLOWED observation, and at or
// after the inventory baseline), the post-horizon probe (a DENIED observation
// of that member at or after its token horizon), and the folded counts of
// every other observation of it.
export interface MemberChain {
  readonly allowed: { readonly count: number; readonly lastObservedAt: string | null };
  readonly denied: number;
  readonly post: ProbeRecord | null;
  readonly revocation: ProbeRecord | null;
}

// The chains of one target as committed state, not as a scan of entries: one
// chain per exact managed member, keyed by the member, created when the
// target is journaled so the set of members that must complete both phases
// is fixed by the effect and can never shrink with the journal. Observations
// are journaled as entries while the shard has room and otherwise counted as
// suppressed; the chains themselves are always writable.
export interface TargetChain {
  readonly inventory: ChainInventory | null;
  readonly journaled: number;
  readonly members: Readonly<Record<string, MemberChain>>;
  readonly suppressed: number;
}

export interface TargetState {
  readonly chain: TargetChain;
  readonly effect: TargetEffect;
  readonly sequence: number;
}

interface ShardBase {
  readonly consumer: string;
  // The complete CONTROL round that admitted a QUARANTINE shard; null for a
  // RESTORE shard.
  readonly controlRound: string | null;
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

// A canonical job delivering its own credential: the GitHub OIDC token it
// minted for the consumer provider's audience. Nothing else is in the body;
// the member it proves is derived from the token's verified claims.
export interface DeliverRequest {
  readonly kind: "deliver";
  readonly token: string;
}

export const maintenanceActions = ["close", "open"] as const;
export type MaintenanceAction = (typeof maintenanceActions)[number];

export interface MaintenanceRequest {
  readonly kind: "maintenance";
  readonly action: MaintenanceAction;
  readonly bodyHash: string;
  readonly key: string;
}

export interface RoundRequest {
  readonly kind: "round";
  readonly body: { readonly consumer: string; readonly label: string; readonly phase: RoundPhase; readonly shard: string | null };
  readonly bodyHash: string;
  readonly key: string;
}

export interface RoundReadRequest {
  readonly kind: "round-read";
  readonly round: string;
}

export type ParsedRequest = AppendRequest | CloseRequest | ReconcileRequest | ReadRequest | DeliverRequest | MaintenanceRequest | RoundRequest | RoundReadRequest;

export function intentOf(body: AppendBody): Intent {
  return body.kind === "restore" ? "RESTORE" : "QUARANTINE";
}

const shardId = /^[a-z0-9][a-z0-9-]{0,62}$/;
const roundLabel = /^[a-z0-9][a-z0-9-]{0,40}$/;
const roundDocumentId = /^[0-9a-f]{64}$/;
const idempotencyKey = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/;
const decimalId = /^[1-9][0-9]*$/;
const serviceAccountId = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const projectId = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const repositoryName = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
// A Google Cloud location identifier as the location APIs publish them:
// continent, hyphen, area, then a one-or-more-digit ordinal (europe-west1,
// europe-west10, northamerica-northeast2). Nothing assumes a single digit.
export const regionId = /^[a-z]+-[a-z]+[1-9][0-9]*$/;
const region = regionId;
const commitSha = /^[0-9a-f]{40}$/;
// A v2 principal identifier of the two kinds the Deny forms name outside the
// broker's own derivations: a Google Account or a service account.
export const principalId = /^principal:\/\/(?:goog\/subject\/[^/\s]+@[^/\s]+|iam\.googleapis\.com\/projects\/-\/serviceAccounts\/[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com)$/;

export function loadRecoveryAuthority(authorityText: string, manifestText: string): RecoveryAuthority {
  let document: unknown;
  try {
    document = JSON.parse(authorityText);
  } catch (error) {
    throw new AuthorityError(`${authorityPath}: ${String(error)}`);
  }
  const root = record(document, authorityPath);
  exactKeys(root, ["bootstrapPrincipal", "broker", "consumers", "githubOwner", "githubOwnerId", "maintenancePrincipals", "organizationId", "platformRepository", "platformRepositoryId"], authorityPath);
  const organizationId = root.organizationId;
  if (organizationId !== null && (typeof organizationId !== "string" || !decimalId.test(organizationId))) throw new AuthorityError(`${authorityPath}.organizationId must be null or one positive decimal organization ID.`);
  const bootstrapPrincipal = root.bootstrapPrincipal;
  if (bootstrapPrincipal !== null && (typeof bootstrapPrincipal !== "string" || !principalId.test(bootstrapPrincipal))) throw new AuthorityError(`${authorityPath}.bootstrapPrincipal must be null or one v2 principal identifier.`);
  const maintenancePrincipals = root.maintenancePrincipals;
  if (!Array.isArray(maintenancePrincipals) || !maintenancePrincipals.every((principal): principal is string => typeof principal === "string" && principalId.test(principal))) {
    throw new AuthorityError(`${authorityPath}.maintenancePrincipals must be a list of v2 principal identifiers.`);
  }
  if (new Set(maintenancePrincipals).size !== maintenancePrincipals.length || [...maintenancePrincipals].sort().join(",") !== maintenancePrincipals.join(",")) {
    throw new AuthorityError(`${authorityPath}.maintenancePrincipals must be sorted and unique.`);
  }
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
  return { bootstrapPrincipal, broker, consumers, entries: manifest.entries, githubOwner, githubOwnerId, maintenancePrincipals, organizationId, platformRepository, platformRepositoryId, targetAccounts };
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
// one effect direction -- the reconciler, or one consumer's member-delivery
// identity.
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
  const member = authority.consumers.find((candidate) => memberDeliveryName(candidate.repository) === account);
  if (member) return { kind: "member", consumer: member, serviceAccount: account };
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

const memberToken = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

export function parseDeliverBody(body: unknown): DeliverRequest {
  const source = requestRecord(body, "body");
  requestKeys(source, ["token"]);
  if (typeof source.token !== "string" || source.token.length > 6 * 1024 || !memberToken.test(source.token)) throw new RequestError("token must be one compact JWS");
  return { kind: "deliver", token: source.token };
}

// A round is opened by its coordinates: the consumer, the phase, the OPEN
// quarantine shard it probes (none for CONTROL), and an operator label.
export function parseRoundBody(body: unknown): RoundRequest {
  const source = requestRecord(body, "body");
  requestKeys(source, ["consumer", "key", "label", "phase", "shard"]);
  const consumer = typeof source.consumer === "string" && repositoryName.test(source.consumer) ? source.consumer : undefined;
  if (consumer === undefined) throw new RequestError("consumer must be a consumer repository name");
  const key = requestKey(source.key);
  if (typeof source.label !== "string" || !roundLabel.test(source.label)) throw new RequestError("label must match ^[a-z0-9][a-z0-9-]{0,40}$");
  if (typeof source.phase !== "string" || !(roundPhases as readonly string[]).includes(source.phase)) throw new RequestError(`phase must be one of ${roundPhases.join(", ")}`);
  const phase = source.phase as RoundPhase;
  if (source.shard !== null && (typeof source.shard !== "string" || !shardId.test(source.shard))) throw new RequestError("shard must be null or match ^[a-z0-9][a-z0-9-]{0,62}$");
  const shard = source.shard as string | null;
  if (phase === "CONTROL" && shard !== null) throw new RequestError("a CONTROL round binds no shard");
  if (phase !== "CONTROL" && shard === null) throw new RequestError(`a ${phase} round names the OPEN quarantine shard it probes`);
  return { kind: "round", body: { consumer, label: source.label, phase, shard }, bodyHash: sha256Hex(canonicalJson({ consumer, key, label: source.label, phase, shard })), key };
}

export function parseRoundId(value: string): string {
  if (!roundDocumentId.test(value)) throw new RequestError("round must be one round identifier");
  return value;
}

export function parseMaintenanceBody(body: unknown): MaintenanceRequest {
  const source = requestRecord(body, "body");
  requestKeys(source, ["action", "key"]);
  const key = requestKey(source.key);
  if (typeof source.action !== "string" || !(maintenanceActions as readonly string[]).includes(source.action)) throw new RequestError(`action must be one of ${maintenanceActions.join(", ")}`);
  return { kind: "maintenance", action: source.action as MaintenanceAction, bodyHash: sha256Hex(canonicalJson({ action: source.action, key })), key };
}

export const emptyMemberChain: MemberChain = { allowed: { count: 0, lastObservedAt: null }, denied: 0, post: null, revocation: null };

// The chains of a target at journaling: one empty chain per exact managed
// member of the journaled effect.
export function emptyChain(members: readonly string[]): TargetChain {
  return { inventory: null, journaled: 0, members: Object.fromEntries([...members].sort().map((member) => [member, emptyMemberChain])), suppressed: 0 };
}

export function horizonOf(revocation: ProbeRecord, horizonSeconds: number): number {
  return Date.parse(revocation.observedAt) + horizonSeconds * 1000;
}

// The earliest instant a DENIED observation can start a chain for this
// target: the quarantine acknowledgement, then the completion of the
// inventory baseline's observation.
export function chainFloor(state: TargetState): number {
  const acked = state.effect.ackedAt === null ? Number.NaN : Date.parse(state.effect.ackedAt);
  const baseline = state.chain.inventory === null ? Number.NaN : Date.parse(state.chain.inventory.observedUntil);
  return Math.max(acked, baseline);
}

// Whether the token-lifetime path was ambiguous between two inventories: the
// Deny form was not steady in either, or a bound role's definition or a
// lifetime-extension policy resource moved. Chains rebuilt after such a
// change wait the maximum lifetime the path could have granted.
export function lifetimeAmbiguous(previous: InventorySummary, next: InventorySummary): boolean {
  if (previous.denyState.form !== "steady" || next.denyState.form !== "steady") return true;
  if (canonicalJson(previous.lifetimePolicies) !== canonicalJson(next.lifetimePolicies)) return true;
  if (canonicalJson(previous.roles) !== canonicalJson(next.roles)) return true;
  return previous.lifetimeExtension !== next.lifetimeExtension;
}

export type Observation =
  | { readonly kind: "probe"; readonly probe: ProbeRecord }
  | { readonly kind: "inventory"; readonly inventory: InventoryRecord };

// What an observation meant for the chain: it started a member's chain
// (REVOCATION), ended it (HORIZON), broke it (ALLOWED), established the
// inventory baseline (BASELINE), changed the inventory and voided the chains
// built before the change (CHANGE), contradicted an inventory observed at the
// same instant (CONFLICT), was older than the inventory already recorded
// (STALE, never folded), or repeated known facts (REDUNDANT).
export type ChainRole = "ALLOWED" | "BASELINE" | "CHANGE" | "CONFLICT" | "HORIZON" | "REDUNDANT" | "REVOCATION" | "STALE";

function voidBefore(members: Readonly<Record<string, MemberChain>>, instant: number): Readonly<Record<string, MemberChain>> {
  return Object.fromEntries(Object.entries(members).map(([member, chain]) => {
    const voided = chain.revocation !== null && Date.parse(chain.revocation.observedAt) < instant;
    return [member, voided ? { ...chain, post: null, revocation: null } : chain];
  }));
}

// Apply one broker-recorded observation to a target's chains. Pure: the
// ledger commits the result with the shard document. Inventory observations
// fold monotonically by their observation time: an observation older than
// the latest one recorded is STALE and changes nothing, an equal-time
// observation with another hash is a CONFLICT that voids every member's
// chain and marks the inventory dirty until a strictly later observation
// settles it, and a later observation with another hash is a CHANGE that
// voids every member's chain built before it. A member's ALLOWED observation
// voids that member's chain, so a timer alone never ends one; a DENIED
// observation counts as the member's revocation only after the
// acknowledgement, after the member's latest ALLOWED observation, and at or
// after the inventory baseline; it counts as the post-horizon probe only at
// or after that member's horizon.
export function applyObservation(state: TargetState, observation: Observation): { readonly chain: TargetChain; readonly role: ChainRole } {
  const chain = state.chain;
  if (observation.kind === "inventory") {
    const { findings, hash, observedAt, observedUntil, summary } = observation.inventory;
    if (chain.inventory === null) {
      const horizonSeconds = summary.denyState.form === "steady" ? tokenHorizonSeconds : extendedTokenHorizonSeconds;
      return { chain: { ...chain, inventory: { changes: 0, findings, hash, horizonSeconds, observations: 1, observedAt, observedUntil, summary, verifiedAt: observedUntil } }, role: "BASELINE" };
    }
    // Inventories are ordered by the completion of their reads: an
    // observation that completed before the latest recorded one is stale.
    const observed = Date.parse(observedUntil);
    const latest = Date.parse(chain.inventory.verifiedAt);
    if (observed < latest) return { chain, role: "STALE" };
    if (chain.inventory.hash === hash) {
      // A strictly later confirmation of the same hash settles any conflict marker.
      const settled = observed > latest ? findings : chain.inventory.findings;
      return { chain: { ...chain, inventory: { ...chain.inventory, findings: settled, observations: chain.inventory.observations + 1, verifiedAt: observedUntil } }, role: "REDUNDANT" };
    }
    // A change could have landed at any instant up to the read that detected
    // it: every chain whose revocation was observed before that read is void.
    const horizonSeconds = lifetimeAmbiguous(chain.inventory.summary, summary) ? extendedTokenHorizonSeconds : tokenHorizonSeconds;
    if (observed === latest) {
      const conflict = `conflict:${chain.inventory.hash}!=${hash}@${observedUntil}`;
      const merged = [...new Set([...chain.inventory.findings, ...findings, conflict])].sort();
      return {
        chain: {
          ...chain,
          inventory: { changes: chain.inventory.changes + 1, findings: merged, hash, horizonSeconds, observations: chain.inventory.observations + 1, observedAt, observedUntil, summary, verifiedAt: observedUntil },
          members: voidBefore(chain.members, observed + 1),
        },
        role: "CONFLICT",
      };
    }
    return {
      chain: {
        ...chain,
        inventory: { changes: chain.inventory.changes + 1, findings, hash, horizonSeconds, observations: chain.inventory.observations + 1, observedAt, observedUntil, summary, verifiedAt: observedUntil },
        members: voidBefore(chain.members, observed + 1),
      },
      role: "CHANGE",
    };
  }
  const probe = observation.probe;
  const member = chain.members[probe.member];
  if (member === undefined) return { chain, role: "REDUNDANT" };
  const observed = Date.parse(probe.observedAt);
  const withMember = (next: MemberChain): TargetChain => ({ ...chain, members: { ...chain.members, [probe.member]: next } });
  if (probe.outcome === "ALLOWED") {
    const last = member.allowed.lastObservedAt;
    const lastObservedAt = last === null || observed > Date.parse(last) ? probe.observedAt : last;
    const voided = member.revocation !== null && Date.parse(member.revocation.observedAt) <= observed;
    return {
      chain: withMember({ ...member, allowed: { count: member.allowed.count + 1, lastObservedAt }, post: voided ? null : member.post, revocation: voided ? null : member.revocation }),
      role: "ALLOWED",
    };
  }
  const counted = { ...member, denied: member.denied + 1 };
  if (chain.inventory === null) return { chain: withMember(counted), role: "REDUNDANT" };
  if (member.revocation === null) {
    const afterAllowed = member.allowed.lastObservedAt === null || observed > Date.parse(member.allowed.lastObservedAt);
    if (observed >= chainFloor(state) && afterAllowed) return { chain: withMember({ ...counted, revocation: probe }), role: "REVOCATION" };
    return { chain: withMember(counted), role: "REDUNDANT" };
  }
  if (member.post === null && observed >= horizonOf(member.revocation, chain.inventory.horizonSeconds)) return { chain: withMember({ ...counted, post: probe }), role: "HORIZON" };
  return { chain: withMember(counted), role: "REDUNDANT" };
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

function sortedMembers(chain: TargetChain): ReadonlyArray<readonly [string, MemberChain]> {
  return Object.keys(chain.members)
    .sort()
    .map((member) => [member, chain.members[member]!] as const);
}

// Scan-ready is a pure judgement over the committed shard state: every target
// of a QUARANTINE shard acknowledged with no alternate issuer in its policy
// and no alternate credential path in its recorded inventory, and for every
// exact managed member of every target a broker-recorded DENIED probe of that
// member against the exact target identity after the target's
// acknowledgement and inventory baseline, the one-hour token horizon drained
// since that probe, and another DENIED probe of the same member after the
// horizon. A fixed propagation timer alone never satisfies it, and nothing a
// caller submits contributes to it.
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
    const members = sortedMembers(chain);
    if (members.length === 0) {
      blockers.push(`${account}: no managed member is journaled`);
      horizonKnown = false;
      continue;
    }
    for (const [member, memberChain] of members) {
      if (memberChain.revocation === null) {
        blockers.push(`${account}: no DENIED impersonation probe of ${member} after the quarantine acknowledgement`);
        horizonKnown = false;
        continue;
      }
      const memberHorizon = horizonOf(memberChain.revocation, chain.inventory.horizonSeconds);
      horizon = Math.max(horizon, memberHorizon);
      if (now.getTime() < memberHorizon) {
        blockers.push(`${account}: token horizon of ${member} drains at ${new Date(memberHorizon).toISOString()}`);
        continue;
      }
      if (memberChain.post === null) blockers.push(`${account}: no DENIED impersonation probe of ${member} after the token horizon ${new Date(memberHorizon).toISOString()}`);
    }
  }
  return { blockers, horizonAt: horizonKnown && horizon > 0 ? new Date(horizon).toISOString() : null, ready: blockers.length === 0 };
}

// The probes the broker should record for an OPEN QUARANTINE shard now: for
// every exact managed member of every acknowledged, inventoried, clean
// target, a revocation probe while that member has none, and a post-horizon
// probe once that member's horizon has drained without one. Targets with an
// alternate issuer or an alternate credential path are never ready in this
// shard, so they are not probed.
export function probesNeeded(shard: Shard, now: Date, members: (account: string) => Target | undefined): readonly ProbeNeed[] {
  if (shard.phase !== "OPEN" || shard.intent !== "QUARANTINE") return [];
  const needs: ProbeNeed[] = [];
  for (const [account, state] of sortedTargets(shard)) {
    if (state.effect.state !== "ACKED" || state.effect.alternateIssuers.length > 0) continue;
    const chain = state.chain;
    if (chain.inventory === null || chain.inventory.findings.length > 0) continue;
    const target = members(account);
    if (!target) continue;
    for (const [member, memberChain] of sortedMembers(chain)) {
      if (!target.members.includes(member)) continue;
      const base = { account, email: target.email, member, resource: target.resource, uniqueId: target.uniqueId };
      if (memberChain.revocation === null) {
        const floor = Math.max(chainFloor(state), memberChain.allowed.lastObservedAt === null ? 0 : Date.parse(memberChain.allowed.lastObservedAt) + 1);
        needs.push({ ...base, notBefore: new Date(floor).toISOString(), phase: "REVOCATION" });
      } else if (memberChain.post === null && now.getTime() >= horizonOf(memberChain.revocation, chain.inventory.horizonSeconds)) {
        needs.push({ ...base, notBefore: new Date(horizonOf(memberChain.revocation, chain.inventory.horizonSeconds)).toISOString(), phase: "HORIZON" });
      }
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
  readonly observedUntil: string;
}

// The blockers a gate raises when the freshly observed inventory of a target
// is unavailable, dirty, older than the inventory already recorded, or
// differs from the baseline the chain was built on: the quarantine/close
// interval is protected exactly by this equality.
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
    if (Date.parse(current.observedUntil) < Date.parse(state.chain.inventory.verifiedAt)) blockers.push(`${account}: the credential inventory observed at the gate is older than the inventory recorded at ${state.chain.inventory.verifiedAt}`);
    if (current.hash !== state.chain.inventory.hash) blockers.push(`${account}: credential inventory changed since ${state.chain.inventory.observedAt}`);
  }
  return blockers;
}

export function probeKey(probe: ProbeRecord): string {
  return `probe/${probe.account}/${probe.phase}/${sha256Hex(probe.member).slice(0, 16)}/${probe.observedAt}`;
}

export function inventoryKey(inventory: InventoryRecord): string {
  return `inventory/${inventory.account}/${inventory.observedUntil}`;
}

export function inventoryHash(summary: InventorySummary): string {
  return sha256Hex(canonicalJson(inventorySummaryJson(summary)));
}

export function inventorySummaryJson(summary: InventorySummary): Record<string, unknown> {
  return {
    ancestry: [...summary.ancestry],
    attachments: [...summary.attachments],
    denyState: { form: summary.denyState.form, policies: summary.denyState.policies.map((policy) => ({ attachment: policy.attachment, etag: policy.etag, name: policy.name })) },
    grants: [...summary.grants],
    keys: [...summary.keys],
    lifetimeExtension: summary.lifetimeExtension,
    lifetimePolicies: [...summary.lifetimePolicies],
    neutralized: [...summary.neutralized],
    policies: summary.policies.map((policy) => ({ etag: policy.etag, resource: policy.resource })),
    roles: summary.roles.map((role) => ({ etag: role.etag, name: role.name })),
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
