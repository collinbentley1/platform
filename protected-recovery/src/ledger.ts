import {
  type Actuator,
  type AppendRequest,
  type CloseRequest,
  type EffectProgress,
  type Entry,
  type EntryBody,
  type ExpectedSnapshot,
  type KeyRecord,
  type ObservedSnapshot,
  type OutboxProgress,
  type PreparedFacts,
  type Shard,
  type Target,
  type TerminalOutbox,
  appendBodyJson,
  canaryChecks,
  canonicalJson,
  entryObjectName,
  intentOf,
  intents,
  isRecord,
  maxEntriesPerShard,
  sha256Hex,
  terminalObjectName,
} from "./model";

// The ledger is Firestore, spoken through its REST API so the broker carries no
// dependencies. Every state change is one transaction over the shard document
// and the documents it orders; nothing here calls any other API. Effects are
// additionally ordered per target service account by an actuator document:
// PREPARE takes it, ACK or DIVERGED releases it, and every effect transition is
// conditional on the recorded effect ID and actuator epoch.

export class LedgerUnavailable extends Error {}
export class LedgerError extends Error {}

export interface FirestoreTarget {
  readonly baseUrl: string;
  readonly database: string;
  readonly project: string;
}

export interface LedgerDependencies {
  readonly fetch: typeof fetch;
  readonly firestore: FirestoreTarget;
  readonly now: () => Date;
  readonly token: () => Promise<string>;
}

export type Rejection =
  | { readonly reason: "SHARD_NOT_OPEN"; readonly phase: Shard["phase"] }
  | { readonly reason: "CANARY_PREMATURE" | "NOT_FOUND" | "PINS_UNRECORDED" | "SHARD_FULL" | "SHARD_MISMATCH" | "SOURCE_NOT_COMPLETE"; readonly detail: string };

export type AppendOutcome =
  | { readonly kind: "accepted"; readonly entries: readonly Entry[]; readonly result: string }
  | { readonly kind: "replayed"; readonly result: string }
  | { readonly kind: "conflict" }
  | { readonly kind: "rejected"; readonly rejection: Rejection };

export type CloseOutcome =
  | { readonly kind: "closing"; readonly shard: Shard; readonly result: string }
  | { readonly kind: "replayed"; readonly result: string }
  | { readonly kind: "conflict" }
  | { readonly kind: "rejected"; readonly rejection: Rejection };

export type TransitionOutcome =
  | { readonly kind: "transitioned"; readonly entry: Entry }
  | { readonly kind: "unchanged"; readonly entry: Entry };

export type ReservationOutcome =
  | { readonly kind: "reserved"; readonly effectId: string; readonly epoch: number }
  | { readonly kind: "held"; readonly holder: NonNullable<Actuator["holder"]> }
  | { readonly kind: "unchanged"; readonly entry: Entry };

export type FinishCloseOutcome =
  | { readonly kind: "finalizing"; readonly shard: Shard }
  | { readonly kind: "not-ready"; readonly shard: Shard | undefined };

interface EffectFacts {
  readonly effectId: string;
  readonly epoch: number;
}

interface FirestoreValue {
  readonly arrayValue?: { readonly values?: readonly FirestoreValue[] };
  readonly booleanValue?: boolean;
  readonly integerValue?: string;
  readonly mapValue?: { readonly fields?: Readonly<Record<string, FirestoreValue>> };
  readonly nullValue?: null;
  readonly stringValue?: string;
}

interface StoredDocument {
  readonly fields: Readonly<Record<string, FirestoreValue>>;
  readonly name: string;
  readonly updateTime: string;
}

interface Write {
  readonly currentDocument: { readonly exists: false } | { readonly updateTime: string };
  readonly update: { readonly fields: Readonly<Record<string, FirestoreValue>>; readonly name: string };
}

type Json = string | number | boolean | null | readonly Json[] | { readonly [key: string]: Json };

const maxTransactionAttempts = 128;
const maxResponseBytes = 4 * 1024 * 1024;

export class Ledger {
  readonly #deps: LedgerDependencies;
  readonly #documents: string;
  readonly #queues = new Map<string, Promise<unknown>>();

  constructor(deps: LedgerDependencies) {
    this.#deps = deps;
    this.#documents = `projects/${deps.firestore.project}/databases/${deps.firestore.database}/documents`;
  }

  // Append succeeds only in OPEN. The shard document is read and rewritten in
  // the same transaction as the entry and key documents, so every concurrent
  // append is ordered before a close or refused after it. A QUARANTINE request
  // journals one effect per inventory target; a RESTORE request journals one
  // effect per acknowledged effect of its CLOSED source shard; a canary
  // request journals evidence for one acknowledged target.
  async append(request: AppendRequest, targets: readonly Target[] | undefined): Promise<AppendOutcome> {
    return await this.#transact(request.shard, async (tx) => {
      const shardName = this.#shardName(request.shard);
      const keyName = this.#keyName(request.shard, request.key);
      const [shardDoc, keyDoc] = await tx.get([shardName, keyName]);
      if (keyDoc) {
        const recorded = keyFromDocument(keyDoc);
        if (recorded.operation !== "append" || recorded.bodyHash !== request.bodyHash) return { kind: "conflict" };
        return { kind: "replayed", result: recorded.result };
      }
      const now = this.#deps.now().toISOString();
      const intent = intentOf(request.body);
      const reject = (rejection: Rejection): AppendOutcome => ({ kind: "rejected", rejection });
      let shard: Shard;
      if (shardDoc) {
        shard = shardFromDocument(shardDoc);
        if (shard.consumer !== request.consumer || shard.intent !== intent) return reject({ reason: "SHARD_MISMATCH", detail: `shard is ${shard.consumer} ${shard.intent}` });
        if (shard.phase !== "OPEN") return reject({ reason: "SHARD_NOT_OPEN", phase: shard.phase });
      } else {
        if (request.body.kind === "canary") return reject({ reason: "CANARY_PREMATURE", detail: "no quarantine shard exists" });
        shard = { phase: "OPEN", consumer: request.consumer, createdAt: now, intent, nextSequence: 1, pendingEffects: 0, pendingOutbox: 0, source: request.body.kind === "restore" ? request.body.source : null, targets: {} };
      }
      let bodies: EntryBody[];
      if (request.body.kind === "quarantine") {
        if (!targets) return reject({ reason: "PINS_UNRECORDED", detail: "the consumer's workflow SHA pins are not recorded" });
        if (Object.keys(shard.targets).length > 0) return reject({ reason: "SHARD_MISMATCH", detail: "targets are already journaled in this shard" });
        bodies = targets.map((target) => ({ kind: "effect", account: target.account, intent: "QUARANTINE", members: target.members, resource: target.resource }));
      } else if (request.body.kind === "restore") {
        if (Object.keys(shard.targets).length > 0) return reject({ reason: "SHARD_MISMATCH", detail: "targets are already journaled in this shard" });
        if (shard.source !== request.body.source) return reject({ reason: "SHARD_MISMATCH", detail: `shard restores ${shard.source}` });
        const [sourceDoc] = await tx.get([this.#shardName(request.body.source)]);
        if (!sourceDoc) return reject({ reason: "SOURCE_NOT_COMPLETE", detail: "the source shard does not exist" });
        const source = shardFromDocument(sourceDoc);
        if (source.consumer !== request.consumer || source.intent !== "QUARANTINE") return reject({ reason: "SOURCE_NOT_COMPLETE", detail: `the source shard is ${source.consumer} ${source.intent}` });
        if (source.phase !== "CLOSED" || source.terminal.progress.state !== "PROJECTED") return reject({ reason: "SOURCE_NOT_COMPLETE", detail: `the source shard is ${source.phase} without a projected completeness receipt` });
        const sequences = Object.values(source.targets).sort((left, right) => left - right);
        const docs = sequences.length === 0 ? [] : await tx.get(sequences.map((sequence) => this.#entryName(request.body.kind === "restore" ? request.body.source : "", sequence)));
        bodies = docs.map((doc, index) => {
          if (!doc) throw new LedgerError(`${source.consumer}: source entry ${sequences[index]} is missing.`);
          const entry = entryFromDocument(doc);
          if (entry.body.kind !== "effect" || entry.progress?.state !== "ACKED") throw new LedgerError(`${request.body.kind}: source entry ${entry.sequence} is not an acknowledged effect.`);
          return { kind: "effect", account: entry.body.account, intent: "RESTORE", members: entry.body.members, resource: entry.body.resource };
        });
      } else {
        const canary = request.body;
        const sequence = shard.targets[canary.account];
        if (sequence === undefined) return reject({ reason: "CANARY_PREMATURE", detail: `${canary.account} is not a journaled target` });
        const [effectDoc] = await tx.get([this.#entryName(request.shard, sequence)]);
        if (!effectDoc) throw new LedgerError(`${request.shard}: target entry ${sequence} is missing.`);
        const effect = entryFromDocument(effectDoc);
        if (effect.body.kind !== "effect" || effect.progress === null) throw new LedgerError(`${request.shard}: entry ${sequence} is not an effect.`);
        if (effect.progress.state !== "ACKED") return reject({ reason: "CANARY_PREMATURE", detail: `${canary.account} quarantine is ${effect.progress.state}` });
        if (!effect.body.members.includes(canary.member)) return reject({ reason: "CANARY_PREMATURE", detail: "member is not a managed member of the target" });
        if (Date.parse(canary.observedAt) < Date.parse(effect.progress.ackedAt)) return reject({ reason: "CANARY_PREMATURE", detail: "observedAt precedes the quarantine acknowledgement" });
        bodies = [{ kind: "canary", account: canary.account, checks: canary.checks, member: canary.member, observedAt: canary.observedAt }];
      }
      if (bodies.length === 0) return reject({ reason: "SHARD_MISMATCH", detail: "the request journals no target" });
      if (shard.nextSequence + bodies.length - 1 > maxEntriesPerShard) return reject({ reason: "SHARD_FULL", detail: `${maxEntriesPerShard} entries` });
      const targetsJournaled: Record<string, number> = { ...shard.targets };
      const entries: Entry[] = bodies.map((body, index) => {
        const sequence = shard.nextSequence + index;
        if (body.kind === "effect") targetsJournaled[body.account] = sequence;
        return {
          acceptedAt: now,
          body,
          bodyHash: request.bodyHash,
          key: request.key,
          objectName: entryObjectName(request.shard, sequence),
          outbox: { state: "PENDING" },
          progress: body.kind === "effect" ? { state: "RECORDED" } : null,
          sequence,
        };
      });
      const effects = entries.filter((entry) => entry.progress !== null).length;
      const next: Shard = {
        ...shard,
        nextSequence: shard.nextSequence + entries.length,
        pendingEffects: shard.pendingEffects + effects,
        pendingOutbox: shard.pendingOutbox + entries.length,
        targets: targetsJournaled,
      };
      const result = canonicalJson({ acceptedAt: now, bodyHash: request.bodyHash, key: request.key, sequences: entries.map((entry) => entry.sequence), shard: request.shard });
      tx.put(shardName, shardToJson(next), shardDoc);
      for (const entry of entries) tx.put(this.#entryName(request.shard, entry.sequence), entryToJson(entry), null);
      tx.put(keyName, keyToJson({ bodyHash: request.bodyHash, key: request.key, operation: "append", result }), null);
      return { kind: "accepted", entries, result };
    });
  }

  // Begin-close atomically moves OPEN to CLOSING and fixes closeHighWater at
  // the last accepted sequence, for the shard of the calling purpose only.
  async beginClose(request: CloseRequest, consumer: string): Promise<CloseOutcome> {
    return await this.#transact(request.shard, async (tx) => {
      const shardName = this.#shardName(request.shard);
      const keyName = this.#keyName(request.shard, request.key);
      const [shardDoc, keyDoc] = await tx.get([shardName, keyName]);
      if (!shardDoc) return { kind: "rejected", rejection: { reason: "NOT_FOUND", detail: "the shard does not exist" } };
      const shard = shardFromDocument(shardDoc);
      if (shard.consumer !== consumer) return { kind: "rejected", rejection: { reason: "SHARD_MISMATCH", detail: `shard belongs to ${shard.consumer}` } };
      if (keyDoc) {
        const recorded = keyFromDocument(keyDoc);
        if (recorded.operation !== "close" || recorded.bodyHash !== request.bodyHash) return { kind: "conflict" };
        return { kind: "replayed", result: recorded.result };
      }
      if (shard.phase !== "OPEN") return { kind: "rejected", rejection: { reason: "SHARD_NOT_OPEN", phase: shard.phase } };
      const now = this.#deps.now().toISOString();
      const closing: Shard = { ...shard, phase: "CLOSING", closeHighWater: shard.nextSequence - 1, closeKeyHash: sha256Hex(request.key), closingAt: now };
      const result = canonicalJson({ closeHighWater: closing.closeHighWater, closingAt: now, phase: "CLOSING", shard: request.shard });
      tx.put(shardName, shardToJson(closing), shardDoc);
      tx.put(keyName, keyToJson({ bodyHash: request.bodyHash, key: request.key, operation: "close", result }), null);
      return { kind: "closing", shard: closing, result };
    });
  }

  // Reservation takes the target's actuator for one RECORDED effect before any
  // policy is read, so a takeover always continues the same operation and an
  // opposite intent waits until it is acknowledged or diverged.
  async reserveActuator(shardId: string, sequence: number, email: string): Promise<ReservationOutcome> {
    return await this.#transact(shardId, async (tx) => {
      const entryName = this.#entryName(shardId, sequence);
      const actuatorName = this.#actuatorName(email);
      const [entryDoc, actuatorDoc] = await tx.get([entryName, actuatorName]);
      if (!entryDoc) throw new LedgerError(`${shardId}: entry ${sequence} is missing.`);
      const entry = entryFromDocument(entryDoc);
      if (entry.progress?.state !== "RECORDED") return { kind: "unchanged", entry };
      const actuator = actuatorDoc ? actuatorFromDocument(actuatorDoc) : { epoch: 0, holder: null, lastEtag: null };
      if (actuator.holder) {
        if (actuator.holder.shard === shardId && actuator.holder.sequence === sequence) return { kind: "reserved", effectId: actuator.holder.effectId, epoch: actuator.epoch };
        return { kind: "held", holder: actuator.holder };
      }
      const next: Actuator = { epoch: actuator.epoch + 1, holder: { effectId: `${shardId}/${sequence}`, sequence, shard: shardId }, lastEtag: actuator.lastEtag };
      tx.put(actuatorName, actuatorToJson(next), actuatorDoc);
      return { kind: "reserved", effectId: next.holder!.effectId, epoch: next.epoch };
    });
  }

  // PREPARE records the complete before snapshot with its etag and the
  // complete expected after snapshot before any external write is made.
  async prepareEffect(shardId: string, sequence: number, facts: EffectFacts & { readonly after: ExpectedSnapshot; readonly alternateIssuers: readonly string[]; readonly before: ObservedSnapshot }): Promise<TransitionOutcome> {
    return await this.#transitionEffect(shardId, sequence, facts, (entry, now) => {
      if (entry.progress?.state !== "RECORDED") return undefined;
      return { ...entry, progress: { state: "PREPARED", after: facts.after, alternateIssuers: facts.alternateIssuers, attempts: 0, before: facts.before, effectId: facts.effectId, epoch: facts.epoch, preparedAt: now } };
    });
  }

  // Every external apply attempt is recorded before it is made.
  async recordAttempt(shardId: string, sequence: number, facts: EffectFacts): Promise<TransitionOutcome> {
    return await this.#transitionEffect(shardId, sequence, facts, (entry) => {
      if (entry.progress?.state !== "PREPARED" || !samePreparation(entry.progress, facts)) return undefined;
      return { ...entry, progress: { ...entry.progress, attempts: entry.progress.attempts + 1 } };
    });
  }

  async acknowledgeEffect(shardId: string, sequence: number, facts: EffectFacts & { readonly mutated: boolean; readonly observed: ObservedSnapshot }): Promise<TransitionOutcome> {
    return await this.#transitionEffect(shardId, sequence, facts, (entry, now) => {
      if (entry.progress?.state !== "PREPARED" || !samePreparation(entry.progress, facts)) return undefined;
      const { attempts, state: _state, ...prepared } = entry.progress;
      return { ...entry, progress: { state: "ACKED", ...prepared, ackedAt: now, attempts, mutated: facts.mutated, observed: facts.observed } };
    }, (shard) => countPending(shard, -1, 0), (actuator) => ({ ...actuator, holder: null, lastEtag: facts.observed.etag }));
  }

  async divergeEffect(shardId: string, sequence: number, facts: EffectFacts & { readonly observed: ObservedSnapshot | null; readonly reason: string }): Promise<TransitionOutcome> {
    return await this.#transitionEffect(shardId, sequence, facts, (entry, now) => {
      const progress = entry.progress;
      if (progress === null || (progress.state !== "RECORDED" && progress.state !== "PREPARED")) return undefined;
      if (progress.state === "PREPARED" && !samePreparation(progress, facts)) return undefined;
      const prepared: PreparedFacts | null = progress.state === "PREPARED"
        ? { after: progress.after, alternateIssuers: progress.alternateIssuers, before: progress.before, effectId: progress.effectId, epoch: progress.epoch, preparedAt: progress.preparedAt }
        : null;
      return { ...entry, progress: { state: "DIVERGED", attempts: progress.state === "PREPARED" ? progress.attempts : 0, divergedAt: now, observed: facts.observed, prepared, reason: facts.reason } };
    }, (shard) => countPending(shard, -1, 0), (actuator) => ({ ...actuator, holder: null, lastEtag: facts.observed?.etag ?? actuator.lastEtag }));
  }

  async markEntryProjected(shardId: string, sequence: number, generation: string, sha256: string): Promise<TransitionOutcome> {
    return await this.#transitionEntry(shardId, sequence, (entry, now) => {
      if (entry.outbox.state !== "PENDING") return undefined;
      return { ...entry, outbox: { state: "PROJECTED", generation, projectedAt: now, sha256 } };
    }, (shard) => countPending(shard, 0, -1));
  }

  async divergeEntryOutbox(shardId: string, sequence: number, reason: string): Promise<TransitionOutcome> {
    return await this.#transitionEntry(shardId, sequence, (entry, now) => {
      if (entry.outbox.state !== "PENDING") return undefined;
      return { ...entry, outbox: { state: "DIVERGED", divergedAt: now, reason } };
    });
  }

  // The final close transaction: only a CLOSING shard with no pending or
  // diverged effect and no pending outbox item may finalize. The terminal
  // outbox entry is created here from the committed entries; the shard is
  // FINALIZING, not CLOSED, until that entry is verified in GCS.
  async finishClose(shardId: string): Promise<FinishCloseOutcome> {
    return await this.#transact(shardId, async (tx) => {
      const shardName = this.#shardName(shardId);
      const [shardDoc] = await tx.get([shardName]);
      if (!shardDoc) return { kind: "not-ready", shard: undefined };
      const shard = shardFromDocument(shardDoc);
      if (shard.phase !== "CLOSING" || shard.pendingEffects !== 0 || shard.pendingOutbox !== 0) return { kind: "not-ready", shard };
      const names = sequences(shard.closeHighWater).map((sequence) => this.#entryName(shardId, sequence));
      const docs = names.length === 0 ? [] : await tx.get(names);
      const entries = docs.map((doc, index) => {
        if (!doc) throw new LedgerError(`${shardId}: entry ${index + 1} is missing at close.`);
        const entry = entryFromDocument(doc);
        if (entry.outbox.state !== "PROJECTED" || (entry.progress !== null && entry.progress.state !== "ACKED")) {
          return undefined;
        }
        return {
          body: entry.body,
          bodyHash: entry.bodyHash,
          key: entry.key,
          outbox: { generation: entry.outbox.generation, objectName: entry.objectName, sha256: entry.outbox.sha256 },
          progress: entry.progress === null ? null : {
            ackedAt: entry.progress.ackedAt,
            after: entry.progress.after.hash,
            alternateIssuers: entry.progress.alternateIssuers,
            attempts: entry.progress.attempts,
            before: { etag: entry.progress.before.etag, hash: entry.progress.before.hash },
            effectId: entry.progress.effectId,
            epoch: entry.progress.epoch,
            mutated: entry.progress.mutated,
            observed: { etag: entry.progress.observed.etag, hash: entry.progress.observed.hash },
          },
          sequence: entry.sequence,
        };
      });
      if (entries.some((entry) => entry === undefined)) return { kind: "not-ready", shard };
      const now = this.#deps.now().toISOString();
      const receipt = `${canonicalJson({
        closeHighWater: shard.closeHighWater,
        closingAt: shard.closingAt,
        consumer: shard.consumer,
        entries,
        finalizingAt: now,
        intent: shard.intent,
        shard: shardId,
        source: shard.source,
        targets: shard.targets,
      })}\n`;
      const terminal: TerminalOutbox = { objectName: terminalObjectName(shardId), progress: { state: "PENDING" }, receipt, sha256: sha256Hex(receipt) };
      const finalizing: Shard = { ...shard, phase: "FINALIZING", finalizingAt: now, terminal };
      tx.put(shardName, shardToJson(finalizing), shardDoc);
      return { kind: "finalizing", shard: finalizing };
    });
  }

  async markTerminalProjected(shardId: string, generation: string): Promise<Shard | undefined> {
    return await this.#transact(shardId, async (tx) => {
      const shardName = this.#shardName(shardId);
      const [shardDoc] = await tx.get([shardName]);
      if (!shardDoc) return undefined;
      const shard = shardFromDocument(shardDoc);
      if (shard.phase !== "FINALIZING" || shard.terminal.progress.state !== "PENDING") return shard;
      const now = this.#deps.now().toISOString();
      const closed: Shard = {
        ...shard,
        phase: "CLOSED",
        closedAt: now,
        pendingEffects: 0,
        pendingOutbox: 0,
        terminal: { ...shard.terminal, progress: { state: "PROJECTED", generation, projectedAt: now, sha256: shard.terminal.sha256 } },
      };
      tx.put(shardName, shardToJson(closed), shardDoc);
      return closed;
    });
  }

  async divergeTerminal(shardId: string, reason: string): Promise<Shard | undefined> {
    return await this.#transact(shardId, async (tx) => {
      const shardName = this.#shardName(shardId);
      const [shardDoc] = await tx.get([shardName]);
      if (!shardDoc) return undefined;
      const shard = shardFromDocument(shardDoc);
      if (shard.phase !== "FINALIZING" || shard.terminal.progress.state !== "PENDING") return shard;
      const next: Shard = { ...shard, terminal: { ...shard.terminal, progress: { state: "DIVERGED", divergedAt: this.#deps.now().toISOString(), reason } } };
      tx.put(shardName, shardToJson(next), shardDoc);
      return next;
    });
  }

  async readShard(shardId: string): Promise<Shard | undefined> {
    const [doc] = await this.#batchGet([this.#shardName(shardId)], undefined);
    return doc ? shardFromDocument(doc) : undefined;
  }

  async readEntries(shardId: string, upTo: number): Promise<readonly Entry[]> {
    const names = sequences(upTo).map((sequence) => this.#entryName(shardId, sequence));
    if (names.length === 0) return [];
    const docs = await this.#batchGet(names, undefined);
    return docs.map((doc, index) => {
      if (!doc) throw new LedgerError(`${shardId}: entry ${index + 1} is missing.`);
      return entryFromDocument(doc);
    });
  }

  async readEntry(shardId: string, sequence: number): Promise<Entry | undefined> {
    const [doc] = await this.#batchGet([this.#entryName(shardId, sequence)], undefined);
    return doc ? entryFromDocument(doc) : undefined;
  }

  async readActuator(email: string): Promise<Actuator | undefined> {
    const [doc] = await this.#batchGet([this.#actuatorName(email)], undefined);
    return doc ? actuatorFromDocument(doc) : undefined;
  }

  // Shards with recorded pending work. The reconciler may act only on what
  // this returns; the equality filter needs no composite index.
  async listReconcilable(limit: number): Promise<readonly string[]> {
    const body = await this.#call("runQuery", {
      structuredQuery: {
        from: [{ collectionId: "shards" }],
        limit,
        where: { fieldFilter: { field: { fieldPath: "reconcile" }, op: "EQUAL", value: { booleanValue: true } } },
      },
    });
    if (!Array.isArray(body)) throw new LedgerError("runQuery returned a non-array.");
    const ids: string[] = [];
    for (const item of body) {
      if (!isRecord(item) || !isRecord(item.document) || typeof item.document.name !== "string") continue;
      ids.push(item.document.name.slice(item.document.name.lastIndexOf("/") + 1));
    }
    return ids;
  }

  // An effect transition is conditional on the entry, on the shard, and on the
  // target's actuator naming this very operation at this very epoch.
  async #transitionEffect(
    shardId: string,
    sequence: number,
    facts: EffectFacts,
    transition: (entry: Entry, now: string) => Entry | undefined,
    shardTransition?: (shard: Shard) => Shard,
    actuatorTransition?: (actuator: Actuator) => Actuator,
  ): Promise<TransitionOutcome> {
    return await this.#transact(shardId, async (tx) => {
      const shardName = this.#shardName(shardId);
      const entryName = this.#entryName(shardId, sequence);
      const [shardDoc, entryDoc] = await tx.get([shardName, entryName]);
      if (!shardDoc || !entryDoc) throw new LedgerError(`${shardId}: entry ${sequence} or its shard is missing.`);
      const entry = entryFromDocument(entryDoc);
      if (entry.body.kind !== "effect") return { kind: "unchanged", entry };
      const actuatorName = this.#actuatorName(emailOf(entry.body.resource));
      const [actuatorDoc] = await tx.get([actuatorName]);
      const actuator = actuatorDoc ? actuatorFromDocument(actuatorDoc) : undefined;
      if (!actuator?.holder || actuator.holder.effectId !== facts.effectId || actuator.epoch !== facts.epoch) return { kind: "unchanged", entry };
      const next = transition(entry, this.#deps.now().toISOString());
      if (!next) return { kind: "unchanged", entry };
      tx.put(entryName, entryToJson(next), entryDoc);
      if (shardTransition) tx.put(shardName, shardToJson(shardTransition(shardFromDocument(shardDoc))), shardDoc);
      if (actuatorTransition) tx.put(actuatorName, actuatorToJson(actuatorTransition(actuator)), actuatorDoc!);
      return { kind: "transitioned", entry: next };
    });
  }

  async #transitionEntry(
    shardId: string,
    sequence: number,
    transition: (entry: Entry, now: string) => Entry | undefined,
    shardTransition?: (shard: Shard) => Shard,
  ): Promise<TransitionOutcome> {
    return await this.#transact(shardId, async (tx) => {
      const shardName = this.#shardName(shardId);
      const entryName = this.#entryName(shardId, sequence);
      const [shardDoc, entryDoc] = await tx.get([shardName, entryName]);
      if (!shardDoc || !entryDoc) throw new LedgerError(`${shardId}: entry ${sequence} or its shard is missing.`);
      const entry = entryFromDocument(entryDoc);
      const next = transition(entry, this.#deps.now().toISOString());
      if (!next) return { kind: "unchanged", entry };
      tx.put(entryName, entryToJson(next), entryDoc);
      if (shardTransition) tx.put(shardName, shardToJson(shardTransition(shardFromDocument(shardDoc))), shardDoc);
      return { kind: "transitioned", entry: next };
    });
  }

  // Transactions on one shard are serialized within an instance: Cloud Run
  // admits several concurrent requests per instance, and contending them at
  // Firestore would only trade throughput for aborts. Ordering across
  // instances, and with zero instances followed by one, is Firestore's alone.
  async #transact<T>(shardId: string, body: (tx: Transaction) => Promise<T>): Promise<T> {
    const previous = this.#queues.get(shardId) ?? Promise.resolve();
    const run = previous.then(() => this.#transactNow(body), () => this.#transactNow(body));
    const settled = run.then(() => undefined, () => undefined);
    this.#queues.set(shardId, settled);
    void settled.then(() => {
      if (this.#queues.get(shardId) === settled) this.#queues.delete(shardId);
    });
    return await run;
  }

  async #transactNow<T>(body: (tx: Transaction) => Promise<T>): Promise<T> {
    let previous: string | undefined;
    for (let attempt = 1; attempt <= maxTransactionAttempts; attempt += 1) {
      const begin = await this.#call("beginTransaction", { options: { readWrite: previous === undefined ? {} : { retryTransaction: previous } } });
      if (!isRecord(begin) || typeof begin.transaction !== "string") throw new LedgerError("beginTransaction returned no transaction.");
      const transaction = begin.transaction;
      const tx = new Transaction(transaction, (names) => this.#batchGet(names, transaction));
      let result: T;
      try {
        result = await body(tx);
      } catch (error) {
        await this.#rollback(tx.id);
        throw error;
      }
      if (tx.writes.length === 0) {
        await this.#rollback(tx.id);
        return result;
      }
      const commit = await this.#request("commit", { transaction: tx.id, writes: tx.writes });
      if (commit.ok) return result;
      if (commit.status === "ABORTED" || commit.status === "FAILED_PRECONDITION") {
        previous = tx.id;
        await Bun.sleep(Math.min(200, 10 + attempt * 5) + Math.random() * 30);
        continue;
      }
      throw new LedgerError(`commit failed: ${commit.status}`);
    }
    throw new LedgerUnavailable("The ledger transaction did not commit within its contention bound.");
  }

  async #rollback(transaction: string): Promise<void> {
    try {
      await this.#request("rollback", { transaction });
    } catch {
      // A rollback that fails leaves an expiring transaction; nothing was written.
    }
  }

  async #batchGet(names: readonly string[], transaction: string | undefined): Promise<ReadonlyArray<StoredDocument | null>> {
    const body = await this.#call("batchGet", transaction === undefined ? { documents: names } : { documents: names, transaction });
    if (!Array.isArray(body)) throw new LedgerError("batchGet returned a non-array.");
    const found = new Map<string, StoredDocument>();
    const missing = new Set<string>();
    for (const item of body) {
      if (!isRecord(item)) throw new LedgerError("batchGet returned a malformed item.");
      if (typeof item.missing === "string") {
        missing.add(item.missing);
      } else if (isRecord(item.found) && typeof item.found.name === "string" && typeof item.found.updateTime === "string") {
        found.set(item.found.name, { fields: isRecord(item.found.fields) ? (item.found.fields as Record<string, FirestoreValue>) : {}, name: item.found.name, updateTime: item.found.updateTime });
      } else {
        throw new LedgerError("batchGet returned a malformed document.");
      }
    }
    return names.map((name) => {
      const doc = found.get(name);
      if (doc) return doc;
      if (missing.has(name)) return null;
      throw new LedgerError(`batchGet did not answer for ${name}.`);
    });
  }

  async #call(method: string, body: unknown): Promise<unknown> {
    const response = await this.#request(method, body);
    if (!response.ok) throw new LedgerError(`${method} failed: ${response.status}`);
    return response.body;
  }

  async #request(method: string, body: unknown): Promise<{ readonly ok: true; readonly body: unknown } | { readonly ok: false; readonly status: string }> {
    const url = `${this.#deps.firestore.baseUrl}/v1/${this.#documents}:${method}`;
    let response: Response;
    try {
      response = await this.#deps.fetch(url, {
        body: JSON.stringify(body),
        headers: { Authorization: `Bearer ${await this.#deps.token()}`, "Content-Type": "application/json" },
        method: "POST",
        redirect: "error",
      });
    } catch (error) {
      throw new LedgerUnavailable(`Firestore ${method} is unreachable: ${String(error)}`);
    }
    const text = await boundedText(response);
    if (response.ok) {
      try {
        return { ok: true, body: JSON.parse(text) as unknown };
      } catch {
        throw new LedgerError(`Firestore ${method} returned malformed JSON.`);
      }
    }
    if (response.status >= 500 || response.status === 429) throw new LedgerUnavailable(`Firestore ${method} returned HTTP ${response.status}.`);
    let status = `HTTP_${response.status}`;
    try {
      const parsed = JSON.parse(text) as unknown;
      if (isRecord(parsed) && isRecord(parsed.error) && typeof parsed.error.status === "string") status = parsed.error.status;
    } catch {
      // Keep the HTTP status.
    }
    return { ok: false, status };
  }

  #shardName(shard: string): string {
    return `${this.#documents}/shards/${shard}`;
  }

  #entryName(shard: string, sequence: number): string {
    return `${this.#shardName(shard)}/entries/${String(sequence).padStart(6, "0")}`;
  }

  #keyName(shard: string, key: string): string {
    return `${this.#shardName(shard)}/keys/${sha256Hex(key)}`;
  }

  #actuatorName(email: string): string {
    return `${this.#documents}/actuators/${email}`;
  }
}

class Transaction {
  readonly id: string;
  readonly writes: Write[] = [];
  readonly #read: (names: readonly string[]) => Promise<ReadonlyArray<StoredDocument | null>>;

  constructor(id: string, read: (names: readonly string[]) => Promise<ReadonlyArray<StoredDocument | null>>) {
    this.id = id;
    this.#read = read;
  }

  async get(names: readonly string[]): Promise<ReadonlyArray<StoredDocument | null>> {
    return await this.#read(names);
  }

  put(name: string, value: Record<string, Json>, current: StoredDocument | null | undefined): void {
    this.writes.push({
      currentDocument: current ? { updateTime: current.updateTime } : { exists: false },
      update: { fields: encodeFields(value), name },
    });
  }
}

async function boundedText(response: Response): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxResponseBytes) {
      await reader.cancel();
      throw new LedgerError("Firestore response exceeded its size bound.");
    }
    chunks.push(value);
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

// Pending counts move only while a shard is OPEN or CLOSING; FINALIZING and
// CLOSED shards were created with nothing pending.
function countPending(shard: Shard, effects: number, outbox: number): Shard {
  if (shard.phase !== "OPEN" && shard.phase !== "CLOSING") throw new LedgerError(`A ${shard.phase} shard cannot change its pending counts.`);
  return { ...shard, pendingEffects: shard.pendingEffects + effects, pendingOutbox: shard.pendingOutbox + outbox };
}

function sequences(upTo: number): number[] {
  return Array.from({ length: upTo }, (_, index) => index + 1);
}

function samePreparation(progress: PreparedFacts, facts: EffectFacts): boolean {
  return progress.effectId === facts.effectId && progress.epoch === facts.epoch;
}

export function emailOf(resource: string): string {
  return resource.slice(resource.lastIndexOf("/") + 1);
}

// Documents are plain JSON records; the shard carries one derived field,
// reconcile, so the reconciler can find pending work with an equality query.
export function shardToJson(shard: Shard): Record<string, Json> {
  const base: Record<string, Json> = {
    consumer: shard.consumer,
    createdAt: shard.createdAt,
    intent: shard.intent,
    nextSequence: shard.nextSequence,
    pendingEffects: shard.pendingEffects,
    pendingOutbox: shard.pendingOutbox,
    phase: shard.phase,
    reconcile: shard.phase === "CLOSING" || (shard.phase === "FINALIZING" ? shard.terminal.progress.state === "PENDING" : shard.phase === "OPEN" && (shard.pendingEffects > 0 || shard.pendingOutbox > 0)),
    source: shard.source,
    targets: { ...shard.targets },
  };
  if (shard.phase === "OPEN") return base;
  const closing = { ...base, closeHighWater: shard.closeHighWater, closeKeyHash: shard.closeKeyHash, closingAt: shard.closingAt };
  if (shard.phase === "CLOSING") return closing;
  const terminal = { objectName: shard.terminal.objectName, progress: outboxToJson(shard.terminal.progress), receipt: shard.terminal.receipt, sha256: shard.terminal.sha256 };
  if (shard.phase === "FINALIZING") return { ...closing, finalizingAt: shard.finalizingAt, terminal };
  return { ...closing, closedAt: shard.closedAt, finalizingAt: shard.finalizingAt, terminal };
}

export function shardFromDocument(doc: StoredDocument): Shard {
  const json = decodeFields(doc.fields);
  const phase = str(json, "phase");
  const intent = str(json, "intent");
  if (!(intents as readonly string[]).includes(intent)) throw new LedgerError(`Unknown shard intent ${intent}.`);
  const source = json.source;
  if (source !== null && typeof source !== "string") throw new LedgerError("Shard source is malformed.");
  const targets = obj(json, "targets");
  const base = {
    consumer: str(json, "consumer"),
    createdAt: str(json, "createdAt"),
    intent: intent as Shard["intent"],
    nextSequence: int(json, "nextSequence"),
    pendingEffects: int(json, "pendingEffects"),
    pendingOutbox: int(json, "pendingOutbox"),
    source,
    targets: Object.fromEntries(Object.keys(targets).sort().map((account) => [account, int(targets, account)])),
  };
  if (phase === "OPEN") return { phase, ...base };
  const closing = { closeHighWater: int(json, "closeHighWater"), closeKeyHash: str(json, "closeKeyHash"), closingAt: str(json, "closingAt") };
  if (phase === "CLOSING") return { phase, ...base, ...closing };
  const rawTerminal = obj(json, "terminal");
  const terminal: TerminalOutbox = { objectName: str(rawTerminal, "objectName"), progress: outboxFromJson(obj(rawTerminal, "progress")), receipt: str(rawTerminal, "receipt"), sha256: str(rawTerminal, "sha256") };
  if (phase === "FINALIZING") return { phase, ...base, ...closing, finalizingAt: str(json, "finalizingAt"), terminal };
  if (phase === "CLOSED") {
    if (base.pendingEffects !== 0 || base.pendingOutbox !== 0 || terminal.progress.state !== "PROJECTED") throw new LedgerError("A CLOSED shard records pending work.");
    return { phase, ...base, ...closing, closedAt: str(json, "closedAt"), finalizingAt: str(json, "finalizingAt"), pendingEffects: 0, pendingOutbox: 0, terminal };
  }
  throw new LedgerError(`Unknown shard phase ${phase}.`);
}

export function entryToJson(entry: Entry): Record<string, Json> {
  return {
    acceptedAt: entry.acceptedAt,
    body: bodyToJson(entry.body),
    bodyHash: entry.bodyHash,
    key: entry.key,
    objectName: entry.objectName,
    outbox: outboxToJson(entry.outbox),
    progress: entry.progress === null ? null : progressToJson(entry.progress),
    sequence: entry.sequence,
  };
}

export function entryFromDocument(doc: StoredDocument): Entry {
  const json = decodeFields(doc.fields);
  const progress = json.progress;
  return {
    acceptedAt: str(json, "acceptedAt"),
    body: bodyFromJson(obj(json, "body")),
    bodyHash: str(json, "bodyHash"),
    key: str(json, "key"),
    objectName: str(json, "objectName"),
    outbox: outboxFromJson(obj(json, "outbox")),
    progress: progress === null ? null : progressFromJson(obj(json, "progress")),
    sequence: int(json, "sequence"),
  };
}

function bodyToJson(body: EntryBody): Record<string, Json> {
  if (body.kind === "effect") return { account: body.account, intent: body.intent, kind: "effect", members: [...body.members], resource: body.resource };
  return { account: body.account, checks: { ...body.checks }, kind: "canary", member: body.member, observedAt: body.observedAt };
}

function bodyFromJson(json: Record<string, Json>): EntryBody {
  const kind = str(json, "kind");
  if (kind === "effect") {
    const intent = str(json, "intent");
    if (!(intents as readonly string[]).includes(intent)) throw new LedgerError(`Unknown effect intent ${intent}.`);
    return { kind, account: str(json, "account"), intent: intent as EntryBody & { kind: "effect" } extends { intent: infer I } ? I : never, members: strings(json, "members"), resource: str(json, "resource") };
  }
  if (kind === "canary") {
    const checks = obj(json, "checks");
    return {
      kind,
      account: str(json, "account"),
      checks: Object.fromEntries(canaryChecks.map((check) => [check, bool(checks, check)])) as Record<(typeof canaryChecks)[number], boolean>,
      member: str(json, "member"),
      observedAt: str(json, "observedAt"),
    };
  }
  throw new LedgerError(`Unknown entry kind ${kind}.`);
}

function progressToJson(progress: EffectProgress): Record<string, Json> {
  switch (progress.state) {
    case "RECORDED":
      return { state: progress.state };
    case "PREPARED":
      return { state: progress.state, attempts: progress.attempts, ...preparedToJson(progress) };
    case "ACKED":
      return { state: progress.state, ackedAt: progress.ackedAt, attempts: progress.attempts, mutated: progress.mutated, observed: { ...progress.observed }, ...preparedToJson(progress) };
    case "DIVERGED":
      return { state: progress.state, attempts: progress.attempts, divergedAt: progress.divergedAt, observed: progress.observed === null ? null : { ...progress.observed }, prepared: progress.prepared === null ? null : preparedToJson(progress.prepared), reason: progress.reason };
  }
}

function preparedToJson(prepared: PreparedFacts): Record<string, Json> {
  return { after: { ...prepared.after }, alternateIssuers: [...prepared.alternateIssuers], before: { ...prepared.before }, effectId: prepared.effectId, epoch: prepared.epoch, preparedAt: prepared.preparedAt };
}

function preparedFromJson(json: Record<string, Json>): PreparedFacts {
  const after = obj(json, "after");
  return { after: { hash: str(after, "hash"), policy: str(after, "policy") }, alternateIssuers: strings(json, "alternateIssuers"), before: observedFromJson(obj(json, "before")), effectId: str(json, "effectId"), epoch: int(json, "epoch"), preparedAt: str(json, "preparedAt") };
}

function observedFromJson(json: Record<string, Json>): ObservedSnapshot {
  return { etag: str(json, "etag"), hash: str(json, "hash"), policy: str(json, "policy") };
}

function progressFromJson(json: Record<string, Json>): EffectProgress {
  const state = str(json, "state");
  switch (state) {
    case "RECORDED":
      return { state };
    case "PREPARED":
      return { state, attempts: int(json, "attempts"), ...preparedFromJson(json) };
    case "ACKED":
      return { state, ackedAt: str(json, "ackedAt"), attempts: int(json, "attempts"), mutated: bool(json, "mutated"), observed: observedFromJson(obj(json, "observed")), ...preparedFromJson(json) };
    case "DIVERGED":
      return {
        state,
        attempts: int(json, "attempts"),
        divergedAt: str(json, "divergedAt"),
        observed: json.observed === null ? null : observedFromJson(obj(json, "observed")),
        prepared: json.prepared === null ? null : preparedFromJson(obj(json, "prepared")),
        reason: str(json, "reason"),
      };
    default:
      throw new LedgerError(`Unknown effect state ${state}.`);
  }
}

function outboxToJson(progress: OutboxProgress): Record<string, Json> {
  return { ...progress };
}

function outboxFromJson(json: Record<string, Json>): OutboxProgress {
  const state = str(json, "state");
  switch (state) {
    case "PENDING":
      return { state };
    case "PROJECTED":
      return { state, generation: str(json, "generation"), projectedAt: str(json, "projectedAt"), sha256: str(json, "sha256") };
    case "DIVERGED":
      return { state, divergedAt: str(json, "divergedAt"), reason: str(json, "reason") };
    default:
      throw new LedgerError(`Unknown outbox state ${state}.`);
  }
}

function actuatorToJson(actuator: Actuator): Record<string, Json> {
  return { epoch: actuator.epoch, holder: actuator.holder === null ? null : { ...actuator.holder }, lastEtag: actuator.lastEtag };
}

function actuatorFromDocument(doc: StoredDocument): Actuator {
  const json = decodeFields(doc.fields);
  const holder = json.holder === null ? null : obj(json, "holder");
  const lastEtag = json.lastEtag;
  if (lastEtag !== null && typeof lastEtag !== "string") throw new LedgerError("Actuator lastEtag is malformed.");
  return { epoch: int(json, "epoch"), holder: holder === null ? null : { effectId: str(holder, "effectId"), sequence: int(holder, "sequence"), shard: str(holder, "shard") }, lastEtag };
}

function keyToJson(record: KeyRecord): Record<string, Json> {
  return { bodyHash: record.bodyHash, key: record.key, operation: record.operation, result: record.result };
}

function keyFromDocument(doc: StoredDocument): KeyRecord {
  const json = decodeFields(doc.fields);
  const operation = str(json, "operation");
  if (operation !== "append" && operation !== "close") throw new LedgerError(`Unknown key operation ${operation}.`);
  return { bodyHash: str(json, "bodyHash"), key: str(json, "key"), operation, result: str(json, "result") };
}

function str(json: Record<string, Json>, key: string): string {
  const value = json[key];
  if (typeof value !== "string") throw new LedgerError(`Document field ${key} is not a string.`);
  return value;
}

function strings(json: Record<string, Json>, key: string): string[] {
  const value = json[key];
  if (!Array.isArray(value) || !value.every((item): item is string => typeof item === "string")) throw new LedgerError(`Document field ${key} is not a list of strings.`);
  return value;
}

function int(json: Record<string, Json>, key: string): number {
  const value = json[key];
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new LedgerError(`Document field ${key} is not a non-negative integer.`);
  return value;
}

function bool(json: Record<string, Json>, key: string): boolean {
  const value = json[key];
  if (typeof value !== "boolean") throw new LedgerError(`Document field ${key} is not a boolean.`);
  return value;
}

function obj(json: Record<string, Json>, key: string): Record<string, Json> {
  const value = json[key];
  if (!isRecord(value)) throw new LedgerError(`Document field ${key} is not an object.`);
  return value as Record<string, Json>;
}

function encodeFields(value: Record<string, Json>): Record<string, FirestoreValue> {
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, encodeValue(item)]));
}

function encodeValue(value: Json): FirestoreValue {
  if (value === null) return { nullValue: null };
  if (typeof value === "string") return { stringValue: value };
  if (typeof value === "boolean") return { booleanValue: value };
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new LedgerError("Only safe integers are stored.");
    return { integerValue: String(value) };
  }
  if (Array.isArray(value)) return { arrayValue: { values: value.map((item) => encodeValue(item)) } };
  return { mapValue: { fields: encodeFields(value as Record<string, Json>) } };
}

function decodeFields(fields: Readonly<Record<string, FirestoreValue>>): Record<string, Json> {
  return Object.fromEntries(Object.entries(fields).map(([key, item]) => [key, decodeValue(item)]));
}

function decodeValue(value: FirestoreValue): Json {
  if (value.nullValue === null) return null;
  if (typeof value.stringValue === "string") return value.stringValue;
  if (typeof value.booleanValue === "boolean") return value.booleanValue;
  if (typeof value.integerValue === "string") {
    const parsed = Number(value.integerValue);
    if (!Number.isSafeInteger(parsed)) throw new LedgerError("Stored integer is not a safe integer.");
    return parsed;
  }
  if (value.arrayValue) return (value.arrayValue.values ?? []).map((item) => decodeValue(item));
  if (value.mapValue) return decodeFields(value.mapValue.fields ?? {});
  throw new LedgerError("Stored value has an unsupported type.");
}

export { appendBodyJson };
