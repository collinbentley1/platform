import { AsyncLocalStorage } from "node:async_hooks";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { manifestPath } from "../../tools/ci/workflow-authority";
import {
  type ImpersonationProbe,
  type Jwk,
  type ServiceAccountIam,
  ExternalUnavailable,
  GoogleIssuanceProbe,
  GoogleServiceAccountIam,
  cachedJwks,
  deliveryBudgetSeconds,
  driveEffect,
  classifyPreparedEffect,
  githubJwksUrl,
  verifyMemberCredential,
  verifyRs256Jwt,
} from "./effects";
import { type CredentialInventory, GoogleCredentialInventory } from "./inventory";
import { type FirestoreTarget, type Fresh, type Rejection, Ledger, LedgerError, LedgerUnavailable, targetsToJson } from "./ledger";
import {
  type Consumer,
  type Entry,
  type InventoryRecord,
  type MemberControl,
  type ParsedRequest,
  type Purpose,
  type RecoveryAuthority,
  type RoundBinding,
  type RoundManifest,
  type RoundRequest,
  type Shard,
  type Target,
  RequestError,
  consumerNamed,
  controlValiditySeconds,
  controlRoundFresh,
  roundComplete,
  roundPhaseBlockers,
  roundProbeDigest,
  canonicalJson,
  deliveryOwed,
  intentOf,
  loadRecoveryAuthority,
  maxBodyBytes,
  parseAppendBody,
  parseCloseBody,
  parseDeliverBody,
  parseMaintenanceBody,
  parseProtectedApplyBody,
  parseReconcileBody,
  parseRoundBody,
  parseRoundId,
  parseRoundRunsBody,
  parseShardId,
  probePermission,
  probesNeeded,
  purposeForIdentity,
  roundId,
  roundOwed,
  scanReadiness,
  targetOfEffect,
  targetsFor,
  unrecordedIdentities,
} from "./model";
import { type EvidenceStore, GoogleEvidenceStore, entryEvidence, project } from "./outbox";

// The thin HTTP service. Identity is verified first and purpose is derived from
// it; the body is parsed once against a closed grammar; the purpose's binding
// to its consumer and its one effect direction is enforced; then the ledger,
// effects, probe, inventory, and outbox modules do the work.

export interface Identity {
  readonly email: string;
}

export interface IdentityVerifier {
  verify(authorization: string | null): Promise<Identity | undefined>;
}

export interface Deadlines {
  // One caller request: the inventory reads a close or restore admission
  // makes, then its transaction. Under Cloud Run's 120-second request timeout.
  readonly requestMs: number;
  // One shard's reconciliation within the fleet sweep or the per-shard route.
  readonly shardMs: number;
}

export interface BrokerDependencies {
  readonly authority: RecoveryAuthority;
  readonly deadlines?: Deadlines;
  readonly evidence: EvidenceStore;
  readonly iam: ServiceAccountIam;
  readonly inventory: CredentialInventory;
  // GitHub's JWKS, against which a delivered member credential is verified.
  readonly jwks: () => Promise<readonly Jwk[]>;
  readonly ledger: Ledger;
  readonly now: () => Date;
  // The issuance probe a delivered credential is exercised through, at once.
  readonly probe: ImpersonationProbe;
}

export interface BrokerResponse {
  readonly body: Record<string, unknown>;
  readonly status: number;
}

// Every outbound call carries its own deadline, and every unit of work the
// broker performs for one shard or one request runs under a deadline of its
// own, so a call that never settles can neither hold a request past Cloud
// Run's timeout nor hold the fleet sweep on one shard. Work interrupted by a
// deadline leaves only PREPARE/effect/ACK states the next pass classifies
// exactly, because every ledger transition is conditional and every lost
// IAM answer is reconciled against the prepared before and after snapshots.
export const outboundCallMs = 15_000;
export const defaultDeadlines: Deadlines = { requestMs: 100_000, shardMs: 30_000 };
const deadlines = new AsyncLocalStorage<AbortSignal>();

export class DeadlineExceeded extends Error {}

export function boundedFetch(fetcher: typeof fetch, timeoutMs = outboundCallMs): typeof fetch {
  const bounded = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const signals = [AbortSignal.timeout(timeoutMs)];
    const enclosing = deadlines.getStore();
    if (enclosing) signals.push(enclosing);
    if (init?.signal) signals.push(init.signal);
    return await fetcher(input, { ...init, signal: AbortSignal.any(signals) });
  };
  return Object.assign(bounded, { preconnect: fetcher.preconnect });
}

// Run work under a deadline: every outbound call made within it aborts at
// the deadline, and the work's result is refused at the deadline even if some
// call ignores its signal.
export async function withDeadline<T>(ms: number, work: () => Promise<T>): Promise<T> {
  const controller = new AbortController();
  const enclosing = deadlines.getStore();
  const signal = enclosing ? AbortSignal.any([enclosing, controller.signal]) : controller.signal;
  const timer = setTimeout(() => controller.abort(new DeadlineExceeded(`the deadline of ${ms}ms was exceeded`)), ms);
  try {
    return await Promise.race([
      deadlines.run(signal, work),
      new Promise<never>((_, reject) => signal.addEventListener("abort", () => reject(signal.reason instanceof Error ? signal.reason : new DeadlineExceeded(String(signal.reason))), { once: true })),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

// One page of the fleet sweep, and the time the sweep may spend in one
// invocation: Cloud Run allows the request 120 seconds and Scheduler waits
// 180, so the sweep stops early, records where it stopped, and the next
// invocation continues from there. Shards that can make no progress are
// visited and passed, never allowed to hold the front of the queue.
const reconcileBatch = 64;
const reconcileBudgetMs = 90_000;

interface Observed {
  readonly fresh: Fresh;
  readonly records: readonly InventoryRecord[];
  readonly unavailable: readonly string[];
}

export class Broker {
  readonly #deps: BrokerDependencies;
  readonly #deadlines: Deadlines;

  constructor(deps: BrokerDependencies) {
    this.#deps = deps;
    this.#deadlines = deps.deadlines ?? defaultDeadlines;
  }

  async handle(purpose: Purpose, request: ParsedRequest): Promise<BrokerResponse> {
    try {
      return await withDeadline(this.#deadlines.requestMs, () => this.#handle(purpose, request));
    } catch (error) {
      if (error instanceof DeadlineExceeded) return { status: 503, body: { detail: error.message, error: "DEADLINE_EXCEEDED" } };
      throw error;
    }
  }

  async #handle(purpose: Purpose, request: ParsedRequest): Promise<BrokerResponse> {
    const { authority, ledger } = this.#deps;
    switch (request.kind) {
      case "append": {
        if (purpose.kind !== "recovery" || purpose.consumer.repository !== request.consumer || purpose.intent !== intentOf(request.body)) return forbidden();
        // A replay of a recorded key is answered by the ledger alone; a new
        // QUARANTINE is admitted only once the probe source is operational
        // against every target and every target's inventory is clean, and a
        // new RESTORE only against the source's freshly observed inventory.
        const recorded = await ledger.readKey(request.shard, request.key);
        let outcome;
        if (request.body.kind === "quarantine") {
          const targets = targetsFor(authority, purpose.consumer);
          let controlRound: string | undefined;
          if (targets && !recorded) {
            const admission = await this.#admissible(purpose.consumer, targets);
            if (admission.kind === "refused") return admission.response;
            controlRound = admission.round;
          }
          outcome = await ledger.append(request, targets, undefined, controlRound);
        } else {
          const source = recorded ? undefined : await ledger.readShard(request.body.source);
          const fresh = source && source.consumer === purpose.consumer.repository ? (await this.#observe(request.body.source, source, purpose.consumer)).fresh : undefined;
          outcome = await ledger.append(request, undefined, fresh);
        }
        switch (outcome.kind) {
          case "accepted":
            return { status: 201, body: JSON.parse(outcome.result) as Record<string, unknown> };
          case "replayed":
            return { status: 200, body: JSON.parse(outcome.result) as Record<string, unknown> };
          case "conflict":
            return { status: 409, body: { error: "KEY_BODY_MISMATCH" } };
          case "rejected":
            return rejected(outcome.rejection);
        }
      }
      // eslint-disable-next-line no-fallthrough
      case "close": {
        if (purpose.kind !== "recovery") return forbidden();
        let fresh: Fresh | undefined;
        if (purpose.intent === "QUARANTINE") {
          const shard = await ledger.readShard(request.shard);
          if (shard && shard.phase === "OPEN" && shard.intent === "QUARANTINE" && shard.consumer === purpose.consumer.repository) {
            const observed = await this.#observe(request.shard, shard, purpose.consumer);
            // A changed inventory is recorded, voiding the chain, before the gate judges it.
            for (const record of observed.records) await ledger.recordInventory(request.shard, record);
            fresh = observed.fresh;
          }
        }
        const outcome = await ledger.beginClose(request, purpose.consumer.repository, purpose.intent, fresh);
        switch (outcome.kind) {
          case "closing":
          case "replayed":
            return { status: 200, body: JSON.parse(outcome.result) as Record<string, unknown> };
          case "conflict":
            return { status: 409, body: { error: "KEY_BODY_MISMATCH" } };
          case "rejected":
            return rejected(outcome.rejection);
        }
      }
      // eslint-disable-next-line no-fallthrough
      case "reconcile": {
        if (request.shard === null) {
          // A fleet-wide reconcile is the reconciler's alone.
          if (purpose.kind !== "reconciler") return forbidden();
          return { status: 200, body: await this.reconcileFleet() };
        }
        const shard = await ledger.readShard(request.shard);
        if (!shard) return notFound();
        if (!allowed(purpose, shard)) return forbidden();
        const view = await this.#reconcileBounded(request.shard);
        return view ? { status: 200, body: { shard: view } } : notFound();
      }
      case "read": {
        const shard = await ledger.readShard(request.shard);
        if (!shard) return notFound();
        if (!allowed(purpose, shard)) return forbidden();
        const entries = await ledger.readEntries(request.shard, shard.nextSequence - 1);
        const consumer = consumerNamed(authority, shard.consumer);
        const owed = consumer ? probesNeeded(shard, this.#deps.now(), targetLookup(authority, consumer, entries)).map((need) => ({ account: need.account, member: need.member, notBefore: need.notBefore, phase: need.phase })) : [];
        return { status: 200, body: { entries: entries.map((entry) => entryView(entry)), shard: { ...shardView(request.shard, shard), deliveriesOwed: owed, scanReady: scanReadiness(shard, this.#deps.now()) } } };
      }
      case "deliver":
        return await this.#deliver(purpose, request.token);
      case "round":
        return await this.#openRound(purpose, request);
      case "round-runs": {
        const round = await ledger.readRound(request.round);
        if (!round) return notFound();
        if (purpose.kind !== "recovery" || purpose.intent !== "QUARANTINE" || purpose.consumer.repository !== round.consumer) return forbidden();
        const bound = await ledger.bindRoundRuns(request.round, request.runs);
        if (bound.kind === "refused") return { status: 409, body: { error: "ROUND_RUNS_REFUSED", detail: bound.reason } };
        return { status: 200, body: { round: await this.#refreshRound(request.round, bound.round) } };
      }
      case "round-read": {
        const round = await ledger.readRound(request.round);
        if (!round) return notFound();
        if (!(purpose.kind === "reconciler" || (purpose.kind === "recovery" && purpose.consumer.repository === round.consumer))) return forbidden();
        return { status: 200, body: { round: await this.#refreshRound(request.round, round) } };
      }
      case "protected-apply-read": {
        if (purpose.kind !== "recovery" || purpose.intent !== "RESTORE") return forbidden();
        const owner = `${purpose.serviceAccount}@${authority.broker.projectId}.iam.gserviceaccount.com`;
        const lease = await ledger.readProtectedApply();
        if (lease && lease.openedBy !== owner) return forbidden();
        return { status: 200, body: { lease } };
      }
      case "protected-apply": {
        if (purpose.kind !== "recovery" || purpose.intent !== "RESTORE") return forbidden();
        const owner = `${purpose.serviceAccount}@${authority.broker.projectId}.iam.gserviceaccount.com`;
        const outcome = request.action === "acquire"
          ? await ledger.acquireProtectedApply(request.key, request.planSha256, owner)
          : await ledger.releaseProtectedApply(request.key, request.planSha256, owner);
        if (outcome.kind === "refused") return { status: 409, body: { error: outcome.reason } };
        return { status: outcome.kind === "acquired" ? 201 : 200, body: { lease: outcome.lease } };
      }
      case "maintenance": {
        // The maintenance ticket is the RESTORE direction's: it is the
        // return to ordinary operation that infrastructure work belongs to.
        if (purpose.kind !== "recovery" || purpose.intent !== "RESTORE") return forbidden();
        const outcome = request.action === "open" ? await ledger.openMaintenance(request.key, purpose.serviceAccount) : await ledger.closeMaintenance(request.key);
        if (outcome.kind === "refused") return { status: 409, body: { detail: outcome.detail, error: outcome.reason } };
        return { status: 200, body: { action: request.action, ticket: outcome.ticket } };
      }
    }
  }

  // A round is opened by the consumer's QUARANTINE invoker at exact
  // coordinates and bound, at that moment, to every member, the platform
  // commits the consumer records, every target's identity, policy etag, and
  // inventory hash from one fresh batch inventory, and the live Deny state.
  // A round with a dirty or unavailable inventory is refused; a round that
  // exists is replayed.
  async #openRound(purpose: Purpose, request: RoundRequest): Promise<BrokerResponse> {
    const { authority, inventory, ledger } = this.#deps;
    if (purpose.kind !== "recovery" || purpose.intent !== "QUARANTINE" || purpose.consumer.repository !== request.body.consumer) return forbidden();
    const consumer = purpose.consumer;
    const id = roundId(consumer.repository, request.body.phase, request.body.shard, request.body.label);
    const existing = await ledger.readRound(id);
    if (existing) return { status: 200, body: { round: await this.#refreshRound(id, existing) } };
    let targets: readonly Target[] | undefined;
    if (request.body.shard === null) {
      targets = targetsFor(authority, consumer);
      if (!targets) return { status: 409, body: { detail: "the consumer's workflow SHA pins or target identities are not recorded", error: "PINS_UNRECORDED" } };
    } else {
      const shard = await ledger.readShard(request.body.shard);
      if (!shard) return notFound();
      if (!allowed(purpose, shard)) return forbidden();
      if (shard.phase !== "OPEN") return { status: 409, body: { error: "SHARD_NOT_OPEN", phase: shard.phase } };
      const entries = await ledger.readEntries(request.body.shard, shard.nextSequence - 1);
      if (shard.pendingEffects !== 0 || Object.values(shard.targets).some((state) => state.effect.state !== "ACKED" || state.chain.inventory === null)) return { status: 409, body: { error: "NOT_READY", blockers: ["all shard effects and their inventory baselines must be committed before opening a phase round"] } };
      targets = entries.flatMap((entry) => (entry.body.kind === "effect" ? [targetOfEffect(authority, consumer, entry.body)] : []));
      if (targets.length === 0) return { status: 409, body: { detail: "the shard has no acknowledged target to probe", error: "SHARD_NOT_OPEN", phase: shard.phase } };
    }
    const outcomes = await inventory.inventoryAll(targets, consumer);
    const blockers: string[] = [];
    const bound: Record<string, RoundBinding["targets"][string]> = {};
    let denyState: RoundBinding["denyState"] | undefined;
    for (const [index, target] of targets.entries()) {
      const outcome = outcomes[index];
      if (!outcome || outcome.kind === "unavailable") {
        blockers.push(`${target.account}: credential inventory unavailable; ${outcome?.reason ?? "no outcome"}`);
        continue;
      }
      if (outcome.inventory.findings.length > 0) blockers.push(`${target.account}: ${outcome.inventory.findings.join(", ")}`);
      const policy = outcome.inventory.summary.policies.find((candidate) => candidate.resource === target.resource);
      if (!policy) blockers.push(`${target.account}: the inventory carries no allow policy etag for ${target.resource}`);
      bound[target.account] = { inventoryHash: outcome.inventory.hash, members: target.members, policyEtag: policy?.etag ?? "", uniqueId: target.uniqueId };
      denyState ??= outcome.inventory.summary.denyState;
    }
    if (blockers.length > 0 || denyState === undefined) return { status: 409, body: { blockers, error: "INVENTORY_BLOCKED" } };
    const platformShas = [consumer.activeWorkflowSha, ...(consumer.transitionWorkflowSha === null ? [] : [consumer.transitionWorkflowSha])].filter((sha): sha is string => sha !== null);
    const members = [...new Set(targets.flatMap((target) => target.members))].sort();
    const opened = await ledger.openRound(request, purpose.serviceAccount, { denyState, members, platformShas, targets: bound });
    if (opened.kind === "rejected") return rejected(opened.rejection);
    return { status: opened.kind === "opened" ? 201 : 200, body: { round: roundView(opened.id, opened.round) } };
  }

  // A canonical job delivers its own credential through its consumer's
  // member-delivery identity. The broker verifies it exactly as the consumer
  // provider would, binds it to that consumer, requires enough remaining life
  // for the whole delivery, exchanges it at STS once, and mints as the member
  // against every bound target now. Its outcomes can count in one current
  // round, for the exact registered run and named phase. Successful mints
  // invalidate every affected open chain. No bearer survives the request.
  async #deliver(purpose: Purpose, token: string): Promise<BrokerResponse> {
    const { authority, ledger, now, probe } = this.#deps;
    if (purpose.kind !== "member") return forbidden();
    const verified = await verifyMemberCredential({ authority, jwks: this.#deps.jwks, now }, token, purpose.consumer);
    if (verified.kind === "unavailable") return { status: 409, body: { detail: verified.reason, error: "MEMBER_UNVERIFIED" } };
    const bound = targetsFor(authority, verified.consumer);
    if (!bound) return { status: 409, body: { detail: "the consumer's workflow SHA pins or target identities are not recorded", error: "PINS_UNRECORDED" } };
    const targets = bound.filter((target) => target.members.includes(verified.member));
    const remaining = Math.floor((Date.parse(verified.expiresAt) - now().getTime()) / 1000);
    const budget = deliveryBudgetSeconds(targets.length);
    if (remaining < budget) return { status: 409, body: { detail: `the member credential expires in ${remaining}s; a delivery to ${targets.length} targets needs ${budget}s`, error: "MEMBER_EXPIRING" } };
    const minted = await probe.mint({ consumer: verified.consumer, member: verified.member, principal: verified.principal, token }, targets);
    if (minted.kind === "unavailable") return { status: 409, body: { detail: minted.reason, error: "MINT_UNAVAILABLE" } };
    const controls: Record<string, MemberControl> = {};
    const unavailable: string[] = [];
    for (const result of minted.results) {
      if (result.kind === "observed") controls[result.target.account] = { observedAt: result.observedAt, outcome: result.outcome, uniqueId: result.target.uniqueId };
      else unavailable.push(`${result.target.account}: ${result.reason}`);
    }
    const deliveredAt = now().toISOString();
    await ledger.putMemberControl({ consumer: verified.consumer.repository, deliveredAt, expiresAt: verified.expiresAt, member: verified.member, principal: minted.principal, targets: controls });
    // The bounded consumer pointer identifies at most one receiving round.
    // Receipts count only after its exact trigger run mapping is registered.
    const rounds: Record<string, unknown>[] = [];
    const probes: Record<string, unknown>[] = [];
    // A successful mint invalidates every affected recovery chain, even
    // when its run was not selected for a round. It can never satisfy debt.
    if (Object.values(controls).some((control) => control.outcome === "ALLOWED")) {
      for (const shardId of await ledger.listOpenQuarantines(verified.consumer.repository)) {
        for (const target of targets) {
          const control = controls[target.account];
          if (control?.outcome !== "ALLOWED") continue;
          await ledger.recordProbe(shardId, { account: target.account, email: target.email, member: verified.member, observedAt: control.observedAt, outcome: "ALLOWED", permission: probePermission, phase: "REVOCATION", principal: minted.principal, uniqueId: target.uniqueId });
        }
      }
    }
    for (const id of (await ledger.readRoundPointer(verified.consumer.repository)).open) {
      const recorded = await ledger.recordReceipt(id, verified.member, { controls, deliveredAt, platformSha: verified.platformSha, principal: minted.principal, runAttempt: verified.runAttempt, runId: verified.runId });
      if (recorded.kind === "recorded") {
        const view = await this.#refreshRound(id, recorded.round);
        rounds.push({ round: id, complete: view.complete, phase: recorded.round.phase, recorded: true });
      } else rounds.push({ round: id, recorded: false, refused: recorded.reason });
    }
    return { status: 200, body: { controls: Object.fromEntries(Object.keys(controls).sort().map((account) => [account, controls[account]!.outcome])), member: verified.member, probes, rounds, unavailable } };
  }

  async #refreshRound(id: string, initial: RoundManifest): Promise<Record<string, unknown>> {
    const { authority, inventory, ledger, now } = this.#deps;
    let round = initial;
    const blockers: string[] = [];
    if (round.expiredAt !== null || Date.parse(round.expiresAt) <= now().getTime()) return roundView(id, round, ["the round expired"]);
    if (round.runs === null) return roundView(id, round, ["the round awaits an exact trigger run mapping"]);
    const consumer = consumerNamed(authority, round.consumer);
    const canonical = consumer ? targetsFor(authority, consumer) : undefined;
    if (!consumer || !canonical) return roundView(id, round, ["the consumer authority is unavailable"]);
    const targets = canonical.filter((target) => round.targets[target.account] !== undefined);
    const outcomes = await inventory.inventoryAll(targets, consumer);
    const bound: Record<string, RoundBinding["targets"][string]> = {};
    let denyState: RoundBinding["denyState"] | undefined;
    for (const [index, target] of targets.entries()) {
      const outcome = outcomes[index];
      if (!outcome || outcome.kind !== "observed") { blockers.push(`${target.account}: current inventory unavailable`); continue; }
      const record = outcome.inventory;
      if (round.shard !== null && round.completedAt === null) await ledger.recordInventory(round.shard, record);
      if (record.findings.length > 0) blockers.push(`${target.account}: ${record.findings.join(", ")}`);
      const policy = record.summary.policies.find((candidate) => candidate.resource === target.resource);
      if (!policy) blockers.push(`${target.account}: target policy unavailable`);
      bound[target.account] = { inventoryHash: record.hash, members: target.members, policyEtag: policy?.etag ?? "", uniqueId: target.uniqueId };
      denyState ??= record.summary.denyState;
    }
    const binding: RoundBinding = { denyState: denyState ?? { form: "unavailable", policies: [] }, members: [...new Set(targets.flatMap((target) => target.members))].sort(), platformShas: [consumer.activeWorkflowSha, consumer.transitionWorkflowSha].filter((sha): sha is string => sha !== null), targets: bound };
    if (canonicalJson(binding) !== canonicalJson({ denyState: round.denyState, members: round.members, platformShas: round.platformShas, targets: round.targets })) blockers.push("the current inventory, identity, policy or platform binding changed");
    if (blockers.length > 0) return roundView(id, round, blockers);
    if (round.shard !== null) {
      let shard = await ledger.readShard(round.shard);
      if (!shard) return roundView(id, round, ["the shard does not exist"]);
      blockers.push(...roundPhaseBlockers(round, shard, now()));
      if (blockers.length === 0 && round.completedAt === null) {
        for (const member of round.members) {
          const receipt = round.receipts[member];
          if (!receipt) continue;
          for (const target of targets) {
            const control = receipt.controls[target.account];
            if (!control || control.outcome !== "DENIED" || !target.members.includes(member)) continue;
            const existing = round.phase === "REVOCATION" ? shard.targets[target.account]?.chain.members[member]?.revocation : shard.targets[target.account]?.chain.members[member]?.post;
            if (existing && round.committed[member]?.[target.account] === roundProbeDigest(round.phase, target.account, member, receipt)) continue;
            const recorded = await ledger.recordProbe(round.shard, { account: target.account, email: target.email, member, observedAt: control.observedAt, outcome: control.outcome, permission: probePermission, phase: round.phase === "REVOCATION" ? "REVOCATION" : "HORIZON", principal: receipt.principal, uniqueId: target.uniqueId }, id);
            if (recorded.kind === "refused") blockers.push(`${target.account}/${member}: ${recorded.reason}`);
          }
        }
        shard = await ledger.readShard(round.shard);
        round = await ledger.readRound(id) ?? round;
      }
      if (shard) blockers.push(...roundPhaseBlockers(round, shard, now(), round.receipts, round.committed));
      else blockers.push("the shard does not exist");
    }
    if (!roundComplete(round)) blockers.push("the round still owes successful phase receipts");
    if (blockers.length === 0 && round.completedAt === null) {
      const completed = await ledger.completeRound(id, round.version, binding);
      if (completed.kind === "recorded") round = completed.round;
      else blockers.push(completed.reason);
    }
    return roundView(id, round, blockers);
  }

  // Sweep the complete reconcilable set in document-name order, one page at a
  // time, from where the previous sweep stopped. Every shard runs under its
  // own deadline and the cursor is persisted after every shard, so a shard
  // whose calls never settle is passed, recorded as passed, and cannot keep
  // a later shard from being visited by this or the next invocation. When
  // the budget runs out the cursor records the last shard reached; when the
  // end is reached the cursor clears so the next sweep restarts. A cursor
  // left past the end of a set that has since shrunk restarts within the
  // same sweep.
  async reconcileFleet(): Promise<Record<string, unknown>> {
    const { ledger, now } = this.#deps;
    const started = now().getTime();
    const views: Record<string, unknown>[] = [];
    let after = await ledger.readReconcileCursor();
    let restarted = after === null;
    let exhausted = false;
    for (;;) {
      const page = await ledger.listReconcilable(reconcileBatch, after);
      if (page.length === 0) {
        if (!restarted && views.length === 0) {
          after = null;
          restarted = true;
          continue;
        }
        exhausted = true;
        break;
      }
      let processed = 0;
      for (const shard of page) {
        if (now().getTime() - started + this.#deadlines.shardMs > reconcileBudgetMs) break;
        const view = await this.#reconcileBounded(shard);
        if (view) views.push(view);
        after = shard;
        processed += 1;
        await ledger.writeReconcileCursor(after);
      }
      if (processed < page.length) break;
      if (page.length < reconcileBatch) {
        exhausted = true;
        break;
      }
    }
    const next = exhausted ? null : after;
    await ledger.writeReconcileCursor(next);
    return { next, shards: views };
  }

  // One shard under its deadline: a shard whose work exceeds it, whose
  // ledger is unavailable or malformed, or whose bounded external
  // dependency answered with a failure, is reported and passed; anything
  // else is a broker defect and propagates.
  async #reconcileBounded(shardId: string): Promise<Record<string, unknown> | undefined> {
    try {
      return await withDeadline(this.#deadlines.shardMs, () => this.reconcileShard(shardId));
    } catch (error) {
      if (error instanceof DeadlineExceeded) return { deadline: true, notes: [`passed; ${error.message}`], shard: shardId };
      if (error instanceof LedgerUnavailable || error instanceof LedgerError || error instanceof ExternalUnavailable) return { deadline: false, notes: [`passed; ${error.message}`], shard: shardId };
      throw error;
    }
  }

  // Drive every recorded pending step of one shard and finish the close only
  // when nothing remains. Every step is idempotent and conditional, so any
  // number of instances (or zero, followed by one) reaches the same state.
  // A QUARANTINE effect is prepared, and a PREPARED one resumed to its write,
  // only while admission holds right now: the live Deny state is the steady
  // form, every managed member of every pending target has a recorded
  // positive control, and every such target's inventory is clean. A RESTORE
  // effect is written only under the steady form. For an OPEN QUARANTINE
  // shard the broker then records the inventories its targets need from its
  // own source and names every delivery its probes still await.
  async reconcileShard(shardId: string): Promise<Record<string, unknown> | undefined> {
    const { authority, evidence, iam, inventory, ledger, now } = this.#deps;
    let shard = await ledger.readShard(shardId);
    if (!shard) return undefined;
    const notes: string[] = [];
    const projectEntry = async (entry: Entry): Promise<void> => {
      const projected = await project(evidence, entry.objectName, entryEvidence(shardId, entry));
      if (projected.kind === "projected") await ledger.markEntryProjected(shardId, entry.sequence, projected.generation, projected.sha256);
      else if (projected.kind === "diverged") await ledger.divergeEntryOutbox(shardId, entry.sequence, projected.reason);
      else notes.push(`${entry.sequence}: outbox pending; ${projected.reason}`);
    };
    if (shard.phase === "OPEN" || shard.phase === "CLOSING") {
      const consumer = consumerNamed(authority, shard.consumer);
      const entries = await ledger.readEntries(shardId, shard.nextSequence - 1);
      let admission: string | undefined;
      const pending = entries.flatMap((entry) => (entry.body.kind === "effect" && (entry.progress?.state === "RECORDED" || entry.progress?.state === "PREPARED") && consumer ? [targetOfEffect(authority, consumer, entry.body)] : []));
      if (pending.length > 0 && consumer) {
        if (shard.intent === "QUARANTINE") {
          const verdict = await this.#admissible(consumer, pending, shard.controlRound);
          if (verdict.kind === "refused") admission = `${String(verdict.response.body.error)}; ${describe(verdict.response.body)}`;
        } else {
          const deny = await inventory.denyState(consumer);
          if (deny.kind === "unavailable") admission = `DENY_STATE_UNAVAILABLE; ${deny.reason}`;
          else if (deny.state.form !== "steady") admission = `DENY_STATE_NOT_STEADY; ${deny.state.form}`;
        }
      }
      for (const initial of entries) {
        let entry = initial;
        if (entry.body.kind === "effect" && entry.progress !== null && (entry.progress.state === "RECORDED" || entry.progress.state === "PREPARED")) {
          if (!consumer) {
            notes.push(`${entry.sequence}: pending; consumer ${shard.consumer} is not declared`);
            continue;
          }
          if (admission !== undefined && entry.progress.state === "RECORDED") {
            notes.push(`${entry.sequence}: pending; not prepared because ${admission}`);
            continue;
          }
          const driven = admission === undefined
            ? await driveEffect(ledger, iam, shardId, entry, targetOfEffect(authority, consumer, entry.body))
            : await classifyPreparedEffect(ledger, iam, shardId, entry, targetOfEffect(authority, consumer, entry.body));
          if (admission !== undefined && driven.kind === "pending") {
            notes.push(`${entry.sequence}: pending; not resumed because ${admission}`);
            continue;
          }
          entry = driven.entry;
          if (driven.kind === "pending") notes.push(`${entry.sequence}: pending; ${driven.reason}`);
          else if (driven.kind === "stale") notes.push(`${entry.sequence}: stale actuator; nothing written`);
        }
        if ((entry.progress === null || entry.progress.state === "ACKED") && entry.outbox.state === "PENDING") {
          await projectEntry(entry);
        } else if (entry.progress?.state === "DIVERGED") {
          notes.push(`${entry.sequence}: diverged; ${entry.progress.reason}`);
        }
      }
      shard = await ledger.readShard(shardId);
      if (!shard) return undefined;
      if (shard.phase === "OPEN" && shard.intent === "QUARANTINE" && consumer) {
        const observed = await this.#observe(shardId, shard, consumer, entries);
        notes.push(...observed.unavailable.map((reason) => `credential inventory unavailable; ${reason}`));
        for (const record of observed.records) {
          const recorded = await ledger.recordInventory(shardId, record);
          if (recorded.kind === "refused") notes.push(`${record.account}: inventory refused; ${recorded.reason}`);
          else if (recorded.entry) await projectEntry(recorded.entry);
        }
        shard = await ledger.readShard(shardId);
        if (!shard) return undefined;
        // Probes are recorded when the member's canonical job delivers its
        // credential (POST /v1/members); the sweep names what is still owed.
        for (const need of probesNeeded(shard, now(), targetLookup(authority, consumer, entries))) notes.push(`${need.account}: ${deliveryOwed(need.member, need.phase)}`);
      }
      if (shard.phase === "CLOSING") {
        const fresh = shard.intent === "QUARANTINE" && consumer ? (await this.#observe(shardId, shard, consumer, entries)).fresh : undefined;
        const finished = await ledger.finishClose(shardId, fresh);
        if (finished.kind === "finalizing") shard = finished.shard;
        else notes.push(`close pending; ${finished.reason}`);
      }
    }
    if (shard.phase === "FINALIZING" && shard.terminal.progress.state === "PENDING") {
      const projected = await project(evidence, shard.terminal.objectName, new TextEncoder().encode(shard.terminal.receipt));
      if (projected.kind === "projected") shard = (await ledger.markTerminalProjected(shardId, projected.generation)) ?? shard;
      else if (projected.kind === "diverged") shard = (await ledger.divergeTerminal(shardId, projected.reason)) ?? shard;
      else notes.push(`terminal: outbox pending; ${projected.reason}`);
    }
    return { ...shardView(shardId, shard), notes };
  }

  // Whether a QUARANTINE of these targets may be accepted, prepared, or
  // resumed right now: no maintenance ticket is open; the consumer has one
  // complete CONTROL round, recent enough, bound to the current platform
  // pins, that carries a receipt from every managed member of every target
  // minted ALLOWED against that target's exact identity; every target's
  // inventory -- the live Deny state included -- is observed and clean; and
  // that inventory still equals the round's binding -- the same inventory
  // hash and allow-policy etag per target, the same Deny policies by etag
  // and the same form -- so the positive controls were established under
  // exactly the state the quarantine would act on. Otherwise the refusal
  // names exactly what is missing, and nothing has been mutated.
  async #admissible(consumer: Consumer, targets: readonly Target[], admittingRound?: string | null): Promise<{ readonly kind: "admitted"; readonly round: string } | { readonly kind: "refused"; readonly response: BrokerResponse }> {
    const { inventory, ledger } = this.#deps;
    const refuse = (response: BrokerResponse): { readonly kind: "refused"; readonly response: BrokerResponse } => ({ kind: "refused", response });
    const ticket = await ledger.readMaintenance();
    if (ticket) return refuse({ status: 409, body: { detail: `a maintenance ticket opened at ${ticket.openedAt} by ${ticket.openedBy} is open until ${ticket.expiresAt}`, error: "MAINTENANCE_OPEN" } });
    const pointer = admittingRound === undefined ? await ledger.readRoundPointer(consumer.repository) : { control: admittingRound };
    const round = pointer.control === null ? undefined : await ledger.readRound(pointer.control);
    if (!pointer.control || !round || round.completedAt === null) return refuse({ status: 409, body: { detail: `no complete CONTROL round of ${consumer.repository}: every canonical job that is a managed member must deliver its credential to POST /v1/members into one round opened at POST /v1/rounds, and mint ALLOWED against every target it is bound to, before any quarantine`, error: "PROBE_UNAVAILABLE" } });
    const missing: string[] = [];
    if (!controlRoundFresh(round, this.#deps.now())) missing.push(`the CONTROL round ${pointer.control} contains an expired, unbound or unsuccessful delivery outside its ${controlValiditySeconds}s validity window`);
    const pins = [consumer.activeWorkflowSha, ...(consumer.transitionWorkflowSha === null ? [] : [consumer.transitionWorkflowSha])].filter((sha): sha is string => sha !== null);
    if (pins.join(",") !== [...round.platformShas].join(",")) missing.push(`the CONTROL round ${pointer.control} bound the platform at ${round.platformShas.join(", ")}, not the recorded ${pins.join(", ")}`);
    for (const target of targets) {
      if (target.members.length === 0) missing.push(`${target.account}: no managed member`);
      const bound = round.targets[target.account];
      if (!bound || bound.uniqueId !== target.uniqueId) {
        missing.push(`${target.account}: the CONTROL round ${pointer.control} does not bind identity ${target.uniqueId}`);
        continue;
      }
      for (const member of target.members) {
        const control = round.receipts[member]?.controls[target.account];
        if (!bound.members.includes(member)) missing.push(`${target.account}/${member}: the CONTROL round ${pointer.control} does not bind this member`);
        else if (!control || control.outcome !== "ALLOWED" || control.uniqueId !== target.uniqueId) missing.push(`${target.account}/${member}: no ALLOWED receipt in the CONTROL round ${pointer.control}`);
      }
    }
    if (missing.length > 0) return refuse({ status: 409, body: { detail: missing.join("; "), error: "PROBE_UNAVAILABLE" } });
    const blockers: string[] = [];
    const stale: string[] = [];
    const outcomes = await inventory.inventoryAll(targets, consumer);
    for (const [index, target] of targets.entries()) {
      const outcome = outcomes[index];
      if (!outcome || outcome.kind === "unavailable") {
        blockers.push(`${target.account}: credential inventory unavailable; ${outcome?.reason ?? "no outcome"}`);
        continue;
      }
      if (outcome.inventory.findings.length > 0) blockers.push(`${target.account}: ${outcome.inventory.findings.join(", ")}`);
      const bound = round.targets[target.account]!;
      const policy = outcome.inventory.summary.policies.find((candidate) => candidate.resource === target.resource);
      if (outcome.inventory.hash !== bound.inventoryHash) stale.push(`${target.account}: the credential inventory changed since the CONTROL round ${pointer.control} bound it`);
      if (policy?.etag !== bound.policyEtag) stale.push(`${target.account}: the allow policy of ${target.resource} moved since the CONTROL round ${pointer.control} bound it`);
      const live = outcome.inventory.summary.denyState;
      if (live.form !== round.denyState.form || canonicalPolicies(live.policies) !== canonicalPolicies(round.denyState.policies)) stale.push(`${target.account}: the live Deny state (${live.form}) is not the state the CONTROL round ${pointer.control} bound (${round.denyState.form})`);
    }
    if (blockers.length > 0) return refuse({ status: 409, body: { blockers, error: "INVENTORY_BLOCKED" } });
    if (stale.length > 0) return refuse({ status: 409, body: { blockers: [...new Set(stale)], error: "ROUND_STALE" } });
    return { kind: "admitted", round: pointer.control };
  }

  // The freshly observed inventory of every acknowledged target of a shard,
  // from one batch snapshot.
  async #observe(shardId: string, shard: Shard, consumer: Consumer, entries?: readonly Entry[]): Promise<Observed> {
    const targets: Array<{ readonly account: string; readonly target: Target }> = [];
    for (const account of Object.keys(shard.targets).sort()) {
      const state = shard.targets[account]!;
      if (state.effect.state !== "ACKED") continue;
      const entry = entries?.find((candidate) => candidate.sequence === state.sequence) ?? (await this.#deps.ledger.readEntry(shardId, state.sequence));
      if (!entry || entry.body.kind !== "effect") continue;
      targets.push({ account, target: targetOfEffect(this.#deps.authority, consumer, entry.body) });
    }
    const fresh: Record<string, InventoryRecord> = {};
    const records: InventoryRecord[] = [];
    const unavailable: string[] = [];
    const outcomes = targets.length === 0 ? [] : await this.#deps.inventory.inventoryAll(targets.map((entry) => entry.target), consumer);
    for (const [index, { account }] of targets.entries()) {
      const outcome = outcomes[index];
      if (!outcome || outcome.kind === "unavailable") {
        unavailable.push(`${account}: ${outcome?.reason ?? "no outcome"}`);
        continue;
      }
      records.push(outcome.inventory);
      fresh[account] = outcome.inventory;
    }
    return { fresh: Object.fromEntries(Object.entries(fresh).map(([account, record]) => [account, { findings: record.findings, hash: record.hash, observedAt: record.observedAt, observedUntil: record.observedUntil }])), records, unavailable };
  }
}

function canonicalPolicies(policies: ReadonlyArray<{ readonly attachment: string; readonly etag: string; readonly name: string }>): string {
  return JSON.stringify([...policies].map((policy) => [policy.attachment, policy.name, policy.etag]).sort());
}

// The journaled target of every effect entry of a shard, by account.
function targetLookup(authority: RecoveryAuthority, consumer: Consumer, entries: readonly Entry[]): (account: string) => Target | undefined {
  const targets = new Map(entries.flatMap((entry) => (entry.body.kind === "effect" ? [[entry.body.account, targetOfEffect(authority, consumer, entry.body)] as const] : [])));
  return (account) => targets.get(account);
}

function describe(body: Record<string, unknown>): string {
  if (typeof body.detail === "string") return body.detail;
  if (Array.isArray(body.blockers)) return body.blockers.map((blocker) => String(blocker)).join("; ");
  return "";
}

// A purpose may touch only the shards of its own consumer and its own
// direction; the reconciler may touch any recorded shard; a member-delivery
// identity touches no shard at all.
function allowed(purpose: Purpose, shard: Shard): boolean {
  return purpose.kind === "reconciler" || (purpose.kind === "recovery" && purpose.consumer.repository === shard.consumer && purpose.intent === shard.intent);
}

function forbidden(): BrokerResponse {
  return { status: 403, body: { error: "FORBIDDEN" } };
}

function notFound(): BrokerResponse {
  return { status: 404, body: { error: "NOT_FOUND" } };
}

function rejected(rejection: Rejection): BrokerResponse {
  if (rejection.reason === "NOT_FOUND") return notFound();
  if (rejection.reason === "SHARD_NOT_OPEN") return { status: 409, body: { error: rejection.reason, phase: rejection.phase } };
  if (rejection.reason === "NOT_READY") return { status: 409, body: { blockers: [...rejection.blockers], error: rejection.reason } };
  return { status: rejection.reason === "SHARD_MISMATCH" ? 403 : 409, body: { detail: rejection.detail, error: rejection.reason } };
}

// The round as its invoker and the orchestrator see it: the binding, every
// receipt's outcomes (never a bearer), and every delivery still owed.
function roundView(id: string, round: RoundManifest, blockers: readonly string[] = []): Record<string, unknown> {
  return {
    complete: round.completedAt !== null && blockers.length === 0,
    phaseReady: round.completedAt !== null && blockers.length === 0,
    blockers,
    expiredAt: round.expiredAt,
    expiresAt: round.expiresAt,
    runs: round.runs,
    completedAt: round.completedAt,
    consumer: round.consumer,
    denyState: round.denyState,
    label: round.label,
    members: [...round.members],
    openedAt: round.openedAt,
    openedBy: round.openedBy,
    owed: roundOwed(round),
    phase: round.phase,
    platformShas: [...round.platformShas],
    receipts: Object.fromEntries(Object.keys(round.receipts).sort().map((member) => {
      const receipt = round.receipts[member]!;
      return [member, { controls: Object.fromEntries(Object.keys(receipt.controls).sort().map((account) => [account, receipt.controls[account]!.outcome])), deliveredAt: receipt.deliveredAt, platformSha: receipt.platformSha, principal: receipt.principal, runAttempt: receipt.runAttempt, runId: receipt.runId }];
    })),
    round: id,
    shard: round.shard,
    targets: Object.fromEntries(Object.keys(round.targets).sort().map((account) => [account, { ...round.targets[account]!, members: [...round.targets[account]!.members] }])),
    version: round.version,
  };
}

function shardView(shardId: string, shard: Shard): Record<string, unknown> {
  const terminal = shard.phase === "FINALIZING" || shard.phase === "CLOSED"
    ? { generation: shard.terminal.progress.state === "PROJECTED" ? shard.terminal.progress.generation : null, objectName: shard.terminal.objectName, sha256: shard.terminal.sha256, state: shard.terminal.progress.state }
    : null;
  return {
    closeHighWater: shard.phase === "OPEN" ? null : shard.closeHighWater,
    consumer: shard.consumer,
    controlRound: shard.controlRound,
    intent: shard.intent,
    nextSequence: shard.nextSequence,
    pendingEffects: shard.pendingEffects,
    pendingOutbox: shard.pendingOutbox,
    phase: shard.phase,
    shard: shardId,
    source: shard.source,
    targets: targetsToJson(shard.targets),
    terminal,
  };
}

function entryView(entry: Entry): Record<string, unknown> {
  return {
    acceptedAt: entry.acceptedAt,
    body: entry.body,
    bodyHash: entry.bodyHash,
    key: entry.key,
    objectName: entry.objectName,
    outbox: entry.outbox,
    progress: entry.progress,
    sequence: entry.sequence,
  };
}

const routes = {
  append: /^\/v1\/shards\/([^/]+)\/entries$/,
  close: /^\/v1\/shards\/([^/]+)\/close$/,
  maintenance: /^\/v1\/maintenance$/,
  protectedApply: /^\/v1\/protected-apply$/,
  members: /^\/v1\/members$/,
  read: /^\/v1\/shards\/([^/]+)$/,
  reconcileAll: /^\/v1\/reconcile$/,
  reconcileShard: /^\/v1\/shards\/([^/]+)\/reconcile$/,
  round: /^\/v1\/rounds\/([^/]+)$/,
  rounds: /^\/v1\/rounds$/,
  roundRuns: /^\/v1\/rounds\/([^/]+)\/runs$/,
} as const;

export interface ServiceDependencies {
  readonly authority: RecoveryAuthority;
  readonly broker: Broker;
  readonly verifier: IdentityVerifier;
}

// One request, in order: identity, purpose, grammar, permission, work.
export async function handleRequest(deps: ServiceDependencies, request: Request): Promise<Response> {
  let identity: Identity | undefined;
  try {
    identity = await deps.verifier.verify(request.headers.get("authorization"));
  } catch (error) {
    if (error instanceof ExternalUnavailable) return json(503, { detail: error.message, error: "DEPENDENCY_UNAVAILABLE" });
    throw error;
  }
  if (!identity) return json(401, { error: "UNAUTHENTICATED" });
  const purpose = purposeForIdentity(deps.authority, identity.email);
  if (!purpose) return json(403, { error: "FORBIDDEN" });
  let parsed: ParsedRequest;
  try {
    parsed = await parseRequest(request);
  } catch (error) {
    if (error instanceof RequestError) return json(400, { detail: error.message, error: "INVALID_REQUEST" });
    if (error instanceof BodyTooLarge) return json(413, { error: "BODY_TOO_LARGE" });
    if (error instanceof NotFound) return json(404, { error: "NOT_FOUND" });
    throw error;
  }
  try {
    const response = await deps.broker.handle(purpose, parsed);
    return json(response.status, response.body);
  } catch (error) {
    if (error instanceof LedgerUnavailable) return json(503, { error: "LEDGER_UNAVAILABLE" });
    if (error instanceof ExternalUnavailable) return json(503, { detail: error.message, error: "DEPENDENCY_UNAVAILABLE" });
    throw error;
  }
}

class BodyTooLarge extends Error {}
class NotFound extends Error {}

async function parseRequest(request: Request): Promise<ParsedRequest> {
  const path = new URL(request.url).pathname;
  const decode = (raw: string): string => {
    try {
      return parseShardId(decodeURIComponent(raw));
    } catch {
      throw new NotFound();
    }
  };
  if (request.method === "GET") {
    if (routes.protectedApply.test(path)) return { kind: "protected-apply-read" };
    const round = routes.round.exec(path);
    if (round) {
      try {
        return { kind: "round-read", round: parseRoundId(decodeURIComponent(round[1]!)) };
      } catch {
        throw new NotFound();
      }
    }
    const match = routes.read.exec(path);
    if (!match) throw new NotFound();
    return { kind: "read", shard: decode(match[1]!) };
  }
  if (request.method !== "POST") throw new NotFound();
  // The full transition-enabled runsetta mapping exceeds 8 KiB. Only this
  // bounded 32-member registration route accepts a 16 KiB request.
  const body = await readJsonBody(request, routes.roundRuns.test(path) ? 16 * 1024 : maxBodyBytes);
  let match = routes.append.exec(path);
  if (match) return parseAppendBody(decode(match[1]!), body);
  match = routes.close.exec(path);
  if (match) return parseCloseBody(decode(match[1]!), body);
  match = routes.reconcileShard.exec(path);
  if (match) return parseReconcileBody(decode(match[1]!), body);
  if (routes.reconcileAll.test(path)) return parseReconcileBody(null, body);
  if (routes.members.test(path)) return parseDeliverBody(body);
  if (routes.maintenance.test(path)) return parseMaintenanceBody(body);
  if (routes.protectedApply.test(path)) return parseProtectedApplyBody(body);
  if (routes.rounds.test(path)) return parseRoundBody(body);
  match = routes.roundRuns.exec(path);
  if (match) return parseRoundRunsBody(decodeURIComponent(match[1]!), body);
  throw new NotFound();
}

async function readJsonBody(request: Request, limit = maxBodyBytes): Promise<unknown> {
  const declared = request.headers.get("content-length");
  if (declared !== null && !/^[0-9]+$/.test(declared)) {
    void request.body?.cancel().catch(() => undefined);
    throw new RequestError("content-length must be a nonnegative integer");
  }
  if (Number(declared) > limit) {
    void request.body?.cancel().catch(() => undefined);
    throw new BodyTooLarge();
  }
  if (!request.body) return {};
  const reader = request.body.getReader();
  const bytes = new Uint8Array(limit);
  let length = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      if (chunk.value.byteLength > limit - length) {
        void reader.cancel().catch(() => undefined);
        throw new BodyTooLarge();
      }
      bytes.set(chunk.value, length);
      length += chunk.value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
  if (length === 0) return {};
  try {
    return JSON.parse(new TextDecoder().decode(bytes.subarray(0, length))) as unknown;
  } catch {
    throw new RequestError("body must be JSON");
  }
}

function json(status: number, body: Record<string, unknown>): Response {
  return new Response(`${JSON.stringify(body)}\n`, {
    headers: { "Cache-Control": "no-store", "Content-Type": "application/json" },
    status,
  });
}

export interface GoogleIdentityDependencies {
  readonly audience: string;
  readonly jwks: () => Promise<readonly Jwk[]>;
  readonly now: () => Date;
}

const issuers = ["accounts.google.com", "https://accounts.google.com"];
const clockSkewSeconds = 60;

// Cloud Run enforces roles/run.invoker at its edge, then forwards the bearer.
// The broker verifies the Google-signed ID token itself so that the purpose is
// derived from a proven service-account identity and the exact audience.
//
// The token travels in the Authorization header only: invoke.sh sends it
// there, and this verifier reads it there. Google documents that Cloud Run
// removes the token signature only from the X-Serverless-Authorization
// header, which this service neither sends nor reads. No test in this
// repository exercises the Cloud Run edge, so the live forwarded-header
// behaviour -- that a request authenticated at the edge with Authorization
// reaches the container with a signature this verifier accepts -- is a
// mandatory ACTIVATION canary before any purpose can be exercised.
export class GoogleIdentityVerifier implements IdentityVerifier {
  readonly #deps: GoogleIdentityDependencies;

  constructor(deps: GoogleIdentityDependencies) {
    this.#deps = deps;
  }

  async verify(authorization: string | null): Promise<Identity | undefined> {
    if (authorization === null || !authorization.startsWith("Bearer ")) return undefined;
    const payload = await verifyRs256Jwt(authorization.slice("Bearer ".length).trim(), await this.#deps.jwks());
    if (!payload) return undefined;
    const nowSeconds = Math.floor(this.#deps.now().getTime() / 1000);
    if (typeof payload.iss !== "string" || !issuers.includes(payload.iss)) return undefined;
    if (payload.aud !== this.#deps.audience) return undefined;
    if (typeof payload.exp !== "number" || payload.exp <= nowSeconds - clockSkewSeconds) return undefined;
    if (typeof payload.iat !== "number" || payload.iat > nowSeconds + clockSkewSeconds) return undefined;
    if (payload.email_verified !== true || typeof payload.email !== "string" || !/^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/.test(payload.email)) {
      return undefined;
    }
    return { email: payload.email };
  }
}

export const googleJwksUrl = "https://www.googleapis.com/oauth2/v3/certs";

// The runtime service-account token from the metadata server, cached to its
// expiry. Only the broker identity ever calls Google APIs.
export function metadataToken(fetcher: typeof fetch, now: () => Date): () => Promise<string> {
  let cached: { readonly token: string; readonly until: number } | undefined;
  return async () => {
    if (cached && cached.until > now().getTime()) return cached.token;
    let response: Response;
    try {
      response = await fetcher("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", {
        headers: { "Metadata-Flavor": "Google" },
        redirect: "error",
      });
    } catch (error) {
      throw new ExternalUnavailable(`the metadata server is unreachable: ${String(error)}`);
    }
    if (!response.ok) throw new ExternalUnavailable(`the metadata server answered HTTP ${response.status}`);
    let body: unknown;
    try {
      body = JSON.parse(await response.text()) as unknown;
    } catch (error) {
      throw new ExternalUnavailable(`the metadata server answered malformed JSON: ${String(error)}`);
    }
    if (typeof body !== "object" || body === null || Array.isArray(body) || typeof (body as Record<string, unknown>).access_token !== "string" || typeof (body as Record<string, unknown>).expires_in !== "number") {
      throw new ExternalUnavailable("the metadata server answered a malformed token");
    }
    const { access_token: token, expires_in: expiresIn } = body as { access_token: string; expires_in: number };
    cached = { token, until: now().getTime() + Math.max(0, expiresIn - 120) * 1000 };
    return cached.token;
  };
}

export interface RuntimeConfiguration {
  readonly audience: string;
  readonly evidenceBucket: string;
  readonly firestore: FirestoreTarget;
  readonly firestoreEmulator: boolean;
  readonly port: number;
}

// The service refuses to start on null broker coordinates and on any target
// whose permanent unique ID is not recorded: an email-addressed effect could
// otherwise land on a recreated account with the same address.
export function configurationFromEnvironment(env: Readonly<Record<string, string | undefined>>, authority: RecoveryAuthority): RuntimeConfiguration {
  if (authority.broker.projectId === null) {
    throw new Error("protected-recovery/authority.json records no broker project; the service refuses to start.");
  }
  const unrecorded = unrecordedIdentities(authority);
  if (unrecorded.length > 0) {
    throw new Error(`protected-recovery/authority.json records no unique ID for ${unrecorded.join(", ")}; the service refuses to start.`);
  }
  if (authority.organizationId === null) {
    throw new Error("protected-recovery/authority.json records no organization; the service refuses to start.");
  }
  const required = (name: string): string => {
    const value = env[name];
    if (value === undefined || value === "") throw new Error(`${name} is required.`);
    return value;
  };
  const emulator = env.FIRESTORE_EMULATOR_HOST;
  const project = required("FIRESTORE_PROJECT_ID");
  if (emulator === undefined && project !== authority.broker.projectId) {
    throw new Error("FIRESTORE_PROJECT_ID must be the broker project recorded in the authority.");
  }
  const database = required("FIRESTORE_DATABASE_ID");
  if (database !== authority.broker.firestoreDatabase) throw new Error("FIRESTORE_DATABASE_ID must be the ledger database recorded in the authority.");
  const port = Number(env.PORT ?? "8080");
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("PORT must be a TCP port.");
  return {
    audience: required("BROKER_AUDIENCE"),
    evidenceBucket: required("EVIDENCE_BUCKET"),
    firestore: { baseUrl: emulator === undefined ? "https://firestore.googleapis.com" : `http://${emulator}`, database, project },
    firestoreEmulator: emulator !== undefined,
    port,
  };
}

if (import.meta.main) {
  const root = join(import.meta.dir, "..", "..");
  const authority = loadRecoveryAuthority(await readFile(join(root, "protected-recovery", "authority.json"), "utf8"), await readFile(join(root, manifestPath), "utf8"));
  const configuration = configurationFromEnvironment(Bun.env, authority);
  const now = (): Date => new Date();
  // Every outbound call of the service is bounded, and every shard and
  // request runs under its own deadline (see boundedFetch and withDeadline).
  const fetcher = boundedFetch(fetch);
  const token = configuration.firestoreEmulator ? async (): Promise<string> => "owner" : metadataToken(fetcher, now);
  const ledger = new Ledger({ fetch: fetcher, firestore: configuration.firestore, now, token });
  const githubJwks = cachedJwks(githubJwksUrl, fetcher, now);
  const broker = new Broker({
    authority,
    evidence: new GoogleEvidenceStore({ bucket: configuration.evidenceBucket, fetch: fetcher, token }),
    iam: new GoogleServiceAccountIam({ fetch: fetcher, token }),
    inventory: new GoogleCredentialInventory({ authority, fetch: fetcher, now, token }),
    jwks: githubJwks,
    ledger,
    now,
    // The real issuance probe, exercised at once with each credential a
    // canonical job delivers through POST /v1/members: a member whose job has
    // never delivered and minted has no positive control, so every QUARANTINE
    // that needs it is refused before acceptance and before any effect is
    // prepared or resumed.
    probe: new GoogleIssuanceProbe({ authority, fetch: fetcher, now }),
  });
  const verifier = new GoogleIdentityVerifier({ audience: configuration.audience, jwks: cachedJwks(googleJwksUrl, fetcher, now), now });
  const server = Bun.serve({
    fetch: (request) => handleRequest({ authority, broker, verifier }, request),
    hostname: "0.0.0.0",
    port: configuration.port,
  });
  console.log(`protected-recovery listening on ${server.port}`);
}
