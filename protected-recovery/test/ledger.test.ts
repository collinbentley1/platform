import { describe, expect, test } from "bun:test";
import { driveEffect } from "../src/effects";
import { boundedFetch } from "../src/http";
import { LedgerUnavailable } from "../src/ledger";
import { type InventoryRecord, type ProbeRecord, type Target, emptyChain, inventoryHash, maxEntriesPerShard, probeKey, probePermission, scanReadiness, targetsFor } from "../src/model";
import { inventoryFindings } from "../src/inventory";
import { Clock, beginClose, close, consumerOf, deliver, deliverAll, emulatorHost, emulatorLedger, freshOf, makeReady, memberPrincipal, prime, proberPrincipal, quarantine, restore, seedTargets, testAuthority, world } from "./support";

const membersOf = (targets: readonly Target[]) => targets.flatMap((target) => target.members.map((member) => [target, member] as const));

const cdbentley = async (clock = new Clock(), fetcher: typeof fetch = fetch, deadlines?: { readonly requestMs: number; readonly shardMs: number }) => {
  const w = await world(clock, fetcher, deadlines);
  const consumer = w.authority.consumers.find((candidate) => candidate.repository === "cdbentley")!;
  const targets = await prime(w, "cdbentley");
  return { ...w, consumer, targets };
};

describe.skipIf(!emulatorHost)("ledger (Firestore emulator)", () => {
  test("a quarantine append journals every target separately by identity and replays the same key and body", async () => {
    const { ledger, targets } = await cdbentley();
    const first = await ledger.append(quarantine("q", "cdbentley", "k1"), targets);
    expect(first.kind).toBe("accepted");
    if (first.kind !== "accepted") throw new Error();
    expect(first.entries.map((entry) => entry.body.kind === "effect" && entry.body.account)).toEqual(targets.map((target) => target.account));
    expect(first.entries.map((entry) => entry.body.kind === "effect" && [entry.body.email, entry.body.uniqueId, entry.body.resource])).toEqual(targets.map((target) => [target.email, target.uniqueId, `projects/cdbentley/serviceAccounts/${target.uniqueId}`]));
    expect(first.entries.every((entry) => entry.progress?.state === "RECORDED" && entry.outbox.state === "PENDING")).toBe(true);
    const shard = (await ledger.readShard("q"))!;
    expect(shard).toMatchObject({ consumer: "cdbentley", intent: "QUARANTINE", nextSequence: 10, pendingEffects: 9, pendingOutbox: 9, phase: "OPEN", source: null });
    expect(Object.keys(shard.targets)).toHaveLength(9);
    // Every managed member of the target gets its own empty chain at journaling: the members that must complete are fixed here.
    expect(shard.targets[targets[0]!.account]).toEqual({ chain: emptyChain(targets[0]!.members), effect: { ackedAt: null, alternateIssuers: [], state: "RECORDED" }, sequence: 1 });
    expect(Object.keys(shard.targets[targets[0]!.account]!.chain.members).sort()).toEqual([...targets[0]!.members].sort());
    expect(targets[0]!.members.length).toBeGreaterThan(1);
    const replay = await ledger.append(quarantine("q", "cdbentley", "k1"), targets);
    expect(replay).toEqual({ kind: "replayed", result: first.result });
    expect((await ledger.readShard("q"))!.nextSequence).toBe(10);
    expect(await ledger.readKey("q", "k1")).toMatchObject({ key: "k1", operation: "append", result: first.result });
    expect(await ledger.readKey("q", "k9")).toBeUndefined();
    // A second quarantine of the same shard under a new key would journal duplicates and is refused.
    expect(await ledger.append(quarantine("q", "cdbentley", "k2"), targets)).toMatchObject({ kind: "rejected", rejection: { reason: "SHARD_MISMATCH" } });
    // Unrecorded pins or identities refuse the derivation outright.
    expect(await ledger.append(quarantine("q2", "cdbentley", "k3"), undefined)).toMatchObject({ kind: "rejected", rejection: { reason: "PINS_UNRECORDED" } });
  });

  test("the same key with a different body is refused, reordered duplicates converge, and a close binds the shard's consumer and direction", async () => {
    const w = await cdbentley();
    const { ledger, targets } = w;
    const requests = [quarantine("q", "cdbentley", "k1"), quarantine("q", "cdbentley", "k1"), quarantine("q", "cdbentley", "k1")];
    const outcomes = await Promise.all(requests.map((request) => ledger.append(request, targets)));
    expect(outcomes.filter((outcome) => outcome.kind === "accepted")).toHaveLength(1);
    expect(outcomes.filter((outcome) => outcome.kind === "replayed")).toHaveLength(2);
    expect(await ledger.append(restore("q", "cdbentley", "k1", "other"), targets)).toEqual({ kind: "conflict" });
    expect(await ledger.append({ ...quarantine("q", "cdbentley", "k1"), bodyHash: "0".repeat(64) }, targets)).toEqual({ kind: "conflict" });
    // A close needs readiness; a not-ready shard is refused and stays OPEN.
    expect(await beginClose(w, "q", "c1")).toMatchObject({ kind: "rejected", rejection: { reason: "NOT_READY" } });
    expect((await ledger.readShard("q"))!.phase).toBe("OPEN");
    await makeReady(w, "q");
    expect(await beginClose(w, "q", "c1", "runsetta")).toMatchObject({ kind: "rejected", rejection: { reason: "SHARD_MISMATCH" } });
    expect(await beginClose(w, "q", "c1", "cdbentley", "RESTORE")).toMatchObject({ kind: "rejected", rejection: { reason: "SHARD_MISMATCH" } });
    // A ready shard whose inventory is not re-observed at the gate does not close.
    expect(await ledger.beginClose(close("q", "c1"), "cdbentley", "QUARANTINE")).toMatchObject({ kind: "rejected", rejection: { blockers: targets.map((target) => `${target.account}: credential inventory is unavailable at the gate`), reason: "NOT_READY" } });
    const closing = await beginClose(w, "q", "c1");
    expect(closing.kind).toBe("closing");
    expect(await beginClose(w, "q", "c1")).toEqual({ kind: "replayed", result: closing.kind === "closing" ? closing.result : "" });
    expect(await ledger.beginClose({ ...close("q", "c1"), bodyHash: "0".repeat(64) }, "cdbentley", "QUARANTINE")).toEqual({ kind: "conflict" });
    expect(await beginClose(w, "q", "c2")).toMatchObject({ kind: "rejected", rejection: { phase: "CLOSING", reason: "SHARD_NOT_OPEN" } });
    expect(await beginClose(w, "missing", "c4")).toMatchObject({ kind: "rejected", rejection: { reason: "NOT_FOUND" } });
  }, 60_000);

  test("one hundred concurrent probe records race a close from another instance: every accepted record is at or below closeHighWater and every later record is refused", async () => {
    const w = await cdbentley();
    const { clock, ledger, targets } = w;
    const other = w.anotherInstance().ledger;
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    await makeReady(w, "q");
    const before = (await ledger.readShard("q"))!.nextSequence - 1;
    const fresh = await freshOf(w, "q");
    const target = targets[0]!;
    const probe: ProbeRecord = { account: target.account, email: target.email, member: target.members[0]!, observedAt: clock.now.toISOString(), outcome: "DENIED", permission: probePermission, phase: "HORIZON", principal: proberPrincipal, uniqueId: target.uniqueId };
    // A broker instance whose record is answered 503 retries; the ledger admits or refuses it exactly as if it had waited.
    const recordWithRetries = async () => {
      for (let attempt = 1; ; attempt += 1) {
        try {
          return await ledger.recordProbe("q", probe);
        } catch (error) {
          if (!(error instanceof LedgerUnavailable) || attempt === 20) throw error;
        }
      }
    };
    const started = Date.now();
    const records = Array.from({ length: 100 }, () => recordWithRetries());
    const closing = (async () => {
      await Bun.sleep(25);
      return await other.beginClose(close("q", "close"), "cdbentley", "QUARANTINE", fresh);
    })();
    const [outcomes, closed] = await Promise.all([Promise.all(records), closing]);
    expect(closed.kind).toBe("closing");
    if (closed.kind !== "closing" || closed.shard.phase !== "CLOSING") throw new Error();
    const highWater = closed.shard.closeHighWater;
    const accepted = outcomes.filter((outcome) => outcome.kind === "recorded");
    const refused = outcomes.filter((outcome) => outcome.kind === "refused");
    expect(accepted.length + refused.length).toBe(100);
    expect(refused.every((outcome) => outcome.kind === "refused" && outcome.reason === "the shard is CLOSING")).toBe(true);
    const sequences = accepted.flatMap((outcome) => (outcome.kind === "recorded" && outcome.entry ? [outcome.entry.sequence] : [])).sort((left, right) => left - right);
    expect(sequences).toHaveLength(accepted.length);
    expect(sequences.every((sequence) => sequence <= highWater)).toBe(true);
    expect(sequences).toEqual(Array.from({ length: sequences.length }, (_, index) => before + 1 + index));
    expect(highWater).toBe(before + sequences.length);
    const entries = await ledger.readEntries("q", highWater);
    expect(entries).toHaveLength(highWater);
    expect(await ledger.recordProbe("q", probe)).toEqual({ kind: "refused", reason: "the shard is CLOSING" });
    expect(await other.recordProbe("q", probe)).toEqual({ kind: "refused", reason: "the shard is CLOSING" });
    console.log(`100 concurrent probe records against close: ${accepted.length} accepted, ${refused.length} refused, closeHighWater ${highWater}, ${Date.now() - started}ms`);
  }, 300_000);

  test("a shard admits only its consumer and intent, and an observation only an acknowledged target's exact identity, managed member, permission, and admissible observation", async () => {
    const { authority, clock, consumer, iam, inventory, ledger, targets } = await cdbentley();
    const runsetta = authority.consumers.find((candidate) => candidate.repository === "runsetta")!;
    const runsettaTargets = targetsFor(authority, runsetta)!;
    seedTargets(iam, runsettaTargets);
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    expect(await ledger.append(quarantine("q", "runsetta", "k2"), runsettaTargets)).toMatchObject({ kind: "rejected", rejection: { reason: "SHARD_MISMATCH" } });
    expect(await ledger.append(restore("q", "cdbentley", "k3", "q0"), targets)).toMatchObject({ kind: "rejected", rejection: { reason: "SHARD_MISMATCH" } });
    const target = targets[0]!;
    const probe = (overrides: Partial<ProbeRecord> = {}): ProbeRecord => ({ account: target.account, email: target.email, member: target.members[0]!, observedAt: clock.now.toISOString(), outcome: "DENIED", permission: probePermission, phase: "REVOCATION", principal: proberPrincipal, uniqueId: target.uniqueId, ...overrides });
    // Evidence before the acknowledgement is refused.
    expect(await ledger.recordProbe("q", probe())).toEqual({ kind: "refused", reason: `${target.account} quarantine is RECORDED` });
    expect((await driveEffect(ledger, iam, "q", (await ledger.readEntry("q", 1))!, target)).kind).toBe("acked");
    clock.advance(1);
    expect(await ledger.recordProbe("q", probe({ account: "gha-nobody" }))).toEqual({ kind: "refused", reason: "gha-nobody is not a journaled target" });
    expect(await ledger.recordProbe("q", probe({ account: targets[1]!.account, email: targets[1]!.email, uniqueId: targets[1]!.uniqueId }))).toEqual({ kind: "refused", reason: `${targets[1]!.account} quarantine is RECORDED` });
    expect(await ledger.recordProbe("q", probe({ uniqueId: "199990000000000000000" }))).toEqual({ kind: "refused", reason: "the observation names a different identity than the journaled target" });
    expect(await ledger.recordProbe("q", probe({ email: "other@cdbentley.iam.gserviceaccount.com" }))).toEqual({ kind: "refused", reason: "the observation names a different identity than the journaled target" });
    expect(await ledger.recordProbe("q", probe({ member: "principalSet://iam.googleapis.com/other" }))).toEqual({ kind: "refused", reason: "the probed member is not a managed member of the target" });
    expect(await ledger.recordProbe("q", probe({ permission: "iam.serviceAccounts.actAs" as typeof probePermission }))).toEqual({ kind: "refused", reason: `the probed permission is not ${probePermission}` });
    expect(await ledger.recordProbe("q", probe({ principal: "" }))).toEqual({ kind: "refused", reason: "the probe names no principal" });
    expect(await ledger.recordProbe("q", probe({ phase: "LATER" as ProbeRecord["phase"] }))).toEqual({ kind: "refused", reason: "unknown probe phase or outcome" });
    expect(await ledger.recordProbe("q", probe({ observedAt: "2020-01-01T00:00:00.000Z" }))).toEqual({ kind: "refused", reason: "the observation precedes the quarantine acknowledgement" });
    expect(await ledger.recordProbe("q", probe({ observedAt: "yesterday" }))).toEqual({ kind: "refused", reason: "observedAt must be an ISO-8601 UTC instant" });
    expect(await ledger.recordProbe("q", probe({ observedAt: new Date(clock.now.getTime() + 1000).toISOString() }))).toEqual({ kind: "refused", reason: "the observation is in the ledger's future" });
    expect(await ledger.recordProbe("missing", probe())).toEqual({ kind: "refused", reason: "the shard does not exist" });
    // Without an inventory baseline a DENIED observation is journaled but starts no chain; it counts for its member alone.
    const recorded = await ledger.recordProbe("q", probe());
    expect(recorded).toMatchObject({ kind: "recorded", entry: { key: probeKey(probe()), progress: null, sequence: 10 }, role: "REDUNDANT" });
    expect(probeKey(probe())).toMatch(/^probe\/gha-deploy-parity\/REVOCATION\/[0-9a-f]{16}\/2026-/);
    expect(probeKey(probe())).not.toBe(probeKey(probe({ member: target.members[1]! })));
    expect((await ledger.readShard("q"))!).toMatchObject({ nextSequence: 11, pendingEffects: 8, pendingOutbox: 10 });
    expect((await ledger.readShard("q"))!.targets[target.account]!.chain).toMatchObject({ journaled: 1, members: { [target.members[0]!]: { denied: 1, revocation: null }, [target.members[1]!]: { denied: 0, revocation: null } } });
    // An inventory whose hash does not match its summary, or another identity's inventory, is refused.
    const summary = inventory.summaryOf(target, consumer);
    expect(await ledger.recordInventory("q", { account: target.account, email: target.email, findings: [], hash: "0".repeat(64), observedAt: clock.now.toISOString(), observedUntil: clock.now.toISOString(), summary, uniqueId: target.uniqueId })).toEqual({ kind: "refused", reason: "the inventory hash does not match its summary" });
    // An inventory whose interval ends before it begins, or ends in the future, is refused.
    const valid = { account: target.account, email: target.email, findings: [] as readonly string[], hash: inventoryHash(summary), summary, uniqueId: target.uniqueId };
    expect(await ledger.recordInventory("q", { ...valid, observedAt: clock.now.toISOString(), observedUntil: new Date(clock.now.getTime() - 1000).toISOString() })).toEqual({ kind: "refused", reason: "the inventory interval ends before it begins" });
    expect(await ledger.recordInventory("q", { ...valid, observedAt: clock.now.toISOString(), observedUntil: new Date(clock.now.getTime() + 1000).toISOString() })).toEqual({ kind: "refused", reason: "the observation is in the ledger's future" });
    // Another consumer's shard journals the same account names under other identities; this target's probe names none of them.
    expect((await ledger.append(quarantine("q2", "runsetta", "k4"), runsettaTargets)).kind).toBe("accepted");
    expect((await driveEffect(ledger, iam, "q2", (await ledger.readEntry("q2", 1))!, runsettaTargets[0]!)).kind).toBe("acked");
    expect(await ledger.recordProbe("q2", probe())).toEqual({ kind: "refused", reason: "the observation names a different identity than the journaled target" });
  }, 60_000);

  test("restore needs the source's projected completeness receipt on a scan-ready close, a fresh equal inventory, and copies exactly the captured identities and members", async () => {
    const w = await cdbentley();
    const { broker, ledger, targets } = w;
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    expect(await ledger.append(restore("r", "cdbentley", "k2", "q"), targets)).toMatchObject({ kind: "rejected", rejection: { reason: "SOURCE_NOT_COMPLETE" } });
    await broker.reconcileShard("q");
    expect(await beginClose(w, "q", "c")).toMatchObject({ kind: "rejected", rejection: { reason: "NOT_READY" } });
    await makeReady(w, "q");
    expect((await beginClose(w, "q", "c")).kind).toBe("closing");
    expect(await ledger.append(restore("r", "cdbentley", "k2", "q"), targets, await freshOf(w, "q"))).toMatchObject({ kind: "rejected", rejection: { reason: "SOURCE_NOT_COMPLETE" } });
    await broker.reconcileShard("q");
    expect((await ledger.readShard("q"))!.phase).toBe("CLOSED");
    expect(await ledger.append(restore("r", "cdbentley", "k2", "missing"), targets)).toMatchObject({ kind: "rejected", rejection: { reason: "SOURCE_NOT_COMPLETE" } });
    expect(await ledger.append(restore("r", "runsetta", "k2", "q"), targets)).toMatchObject({ kind: "rejected", rejection: { reason: "SOURCE_NOT_COMPLETE" } });
    // Without the source's fresh inventory, or with one that differs from the baseline, the restore is refused.
    expect(await ledger.append(restore("r", "cdbentley", "k2", "q"), targets)).toMatchObject({ kind: "rejected", rejection: { detail: expect.stringContaining("credential inventory is unavailable at the gate"), reason: "SOURCE_NOT_COMPLETE" } });
    const fresh = await freshOf(w, "q");
    const drifted = { ...fresh, [targets[0]!.account]: { ...fresh[targets[0]!.account]!, hash: "f".repeat(64) } };
    expect(await ledger.append(restore("r", "cdbentley", "k2", "q"), targets, drifted)).toMatchObject({ kind: "rejected", rejection: { detail: expect.stringContaining(`${targets[0]!.account}: credential inventory changed since`), reason: "SOURCE_NOT_COMPLETE" } });
    const restored = await ledger.append(restore("r", "cdbentley", "k2", "q"), targets, fresh);
    expect(restored.kind).toBe("accepted");
    if (restored.kind !== "accepted") throw new Error();
    const source = await ledger.readShard("q");
    if (source?.phase !== "CLOSED") throw new Error();
    const quarantined = (await ledger.readEntries("q", source.closeHighWater)).filter((entry) => entry.body.kind === "effect");
    expect(quarantined).toHaveLength(9);
    expect(restored.entries.map((entry) => entry.body)).toEqual(quarantined.map((entry) => (entry.body.kind === "effect" ? { ...entry.body, intent: "RESTORE" } : entry.body)));
    expect((await ledger.readShard("r"))!).toMatchObject({ intent: "RESTORE", source: "q" });
  }, 60_000);

  test("the actuator orders effects per identity: reserved once, held against others, released on acknowledgement, and mirrored into the shard", async () => {
    const { ledger, targets } = await cdbentley();
    expect((await ledger.append(quarantine("q1", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    expect((await ledger.append(quarantine("q2", "cdbentley", "k2"), targets)).kind).toBe("accepted");
    const uniqueId = targets[0]!.uniqueId;
    expect(await ledger.readActuator(uniqueId)).toBeUndefined();
    expect(await ledger.reserveActuator("q1", 1, uniqueId)).toEqual({ kind: "reserved", effectId: "q1/1", epoch: 1 });
    expect(await ledger.reserveActuator("q1", 1, uniqueId)).toEqual({ kind: "reserved", effectId: "q1/1", epoch: 1 });
    expect(await ledger.reserveActuator("q2", 1, uniqueId)).toEqual({ kind: "held", holder: { effectId: "q1/1", sequence: 1, shard: "q1" } });
    await expect(ledger.reserveActuator("q1", 2, uniqueId)).rejects.toThrow(`is not an effect on ${uniqueId}`);
    const facts = { effectId: "q1/1", epoch: 1 };
    const wrong = { effectId: "q1/1", epoch: 2 };
    const snapshot = { etag: "e", hash: "h", policy: "[]" };
    expect((await ledger.prepareEffect("q1", 1, { ...wrong, after: snapshot, alternateIssuers: [], before: snapshot })).kind).toBe("unchanged");
    expect((await ledger.prepareEffect("q1", 1, { ...facts, after: snapshot, alternateIssuers: ["roles/x:user:y"], before: snapshot })).kind).toBe("transitioned");
    expect((await ledger.readShard("q1"))!.targets[targets[0]!.account]!.effect).toEqual({ ackedAt: null, alternateIssuers: ["roles/x:user:y"], state: "PREPARED" });
    expect((await ledger.recordAttempt("q1", 1, wrong)).kind).toBe("unchanged");
    expect((await ledger.recordAttempt("q1", 1, facts)).kind).toBe("transitioned");
    expect((await ledger.acknowledgeEffect("q1", 1, { ...wrong, mutated: true, observed: { ...snapshot, etag: "e2" } })).kind).toBe("unchanged");
    expect((await ledger.acknowledgeEffect("q1", 1, { ...facts, mutated: true, observed: { ...snapshot, etag: "e2" } })).kind).toBe("transitioned");
    expect((await ledger.readShard("q1"))!.targets[targets[0]!.account]!.effect).toMatchObject({ alternateIssuers: ["roles/x:user:y"], state: "ACKED" });
    expect(await ledger.readActuator(uniqueId)).toEqual({ epoch: 1, holder: null, lastEtag: "e2" });
    expect((await ledger.acknowledgeEffect("q1", 1, { ...facts, mutated: true, observed: snapshot })).kind).toBe("unchanged");
    expect(await ledger.reserveActuator("q2", 1, uniqueId)).toEqual({ kind: "reserved", effectId: "q2/1", epoch: 2 });
    expect((await ledger.divergeEffect("q2", 1, { effectId: "q2/1", epoch: 2, observed: null, reason: "test" })).kind).toBe("transitioned");
    expect(await ledger.readActuator(uniqueId)).toEqual({ epoch: 2, holder: null, lastEtag: "e2" });
    expect((await ledger.readShard("q2"))!).toMatchObject({ pendingEffects: 8 });
    expect((await ledger.readShard("q2"))!.targets[targets[0]!.account]!.effect.state).toBe("DIVERGED");
  });

  test("an unavailable ledger before acceptance mutates nothing; after restoration the same key succeeds exactly once", async () => {
    const clock = new Clock();
    let failing = true;
    const fetcher: typeof fetch = Object.assign(async (input: string | URL | Request, init?: RequestInit) => {
      if (failing) throw new TypeError("connect ECONNREFUSED");
      return await fetch(input, init);
    }, { preconnect: fetch.preconnect });
    const ledger = emulatorLedger(clock, fetcher);
    const authority = await testAuthority();
    const targets = targetsFor(authority, authority.consumers[0]!)!;
    await expect(ledger.append(quarantine("q", "cdbentley", "k1"), targets)).rejects.toBeInstanceOf(LedgerUnavailable);
    await expect(ledger.beginClose(close("q", "c1"), "cdbentley", "QUARANTINE")).rejects.toBeInstanceOf(LedgerUnavailable);
    await expect(ledger.readShard("q")).rejects.toBeInstanceOf(LedgerUnavailable);
    failing = false;
    expect(await ledger.readShard("q")).toBeUndefined();
    expect(await ledger.readEntry("q", 1)).toBeUndefined();
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("replayed");
    expect((await ledger.readShard("q"))!.nextSequence).toBe(10);
  });

  test("a shard at its journal ceiling still records every member's DENIED chain and a changed inventory with its summary, closes, and is restorable: observations beyond capacity fold into the chains and the receipt keeps the audit", async () => {
    const w = await cdbentley();
    const { broker, clock, consumer, evidence, inventory, ledger, probe, targets } = w;
    const principal = memberPrincipal(w.authority, consumer);
    const members = membersOf(targets);
    const [first, second] = [targets[0]!, targets[1]!];
    const lingering = first.members[0]!;
    probe.outcomes.set(`${first.uniqueId}|${lingering}`, "ALLOWED");
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    const firstPassAt = clock.now.getTime();
    await broker.reconcileShard("q");
    await deliverAll(w, "cdbentley");
    expect((await ledger.readShard("q"))!.nextSequence).toBe(19 + members.length);
    // The lingering member keeps being ALLOWED until the journal is full.
    const allowed = (observedAt: string): ProbeRecord => ({ account: first.account, email: first.email, member: lingering, observedAt, outcome: "ALLOWED", permission: probePermission, phase: "REVOCATION", principal: proberPrincipal, uniqueId: first.uniqueId });
    let spam = 0;
    while ((await ledger.readShard("q"))!.nextSequence <= maxEntriesPerShard) {
      clock.advance(1);
      const recorded = await ledger.recordProbe("q", allowed(clock.now.toISOString()));
      expect(recorded).toMatchObject({ kind: "recorded", role: "ALLOWED" });
      expect(recorded.kind === "recorded" && recorded.entry !== null).toBe(true);
      spam += 1;
    }
    expect(spam).toBe(maxEntriesPerShard - 18 - members.length);
    const full = (await ledger.readShard("q"))!;
    expect(full.nextSequence).toBe(maxEntriesPerShard + 1);
    expect(full.targets[first.account]!.chain).toMatchObject({ members: { [lingering]: { allowed: { count: spam + 1, lastObservedAt: clock.now.toISOString() }, revocation: null }, [first.members[1]!]: { allowed: { count: 0 }, revocation: { outcome: "DENIED" } } }, suppressed: 0 });
    // Revocation of the lingering member is finally observed by its job's next delivery: no entry remains, its chain
    // records it anyway.
    probe.outcomes.delete(`${first.uniqueId}|${lingering}`);
    clock.advance(1);
    expect((await deliver(w, "cdbentley", lingering)).status).toBe(200);
    const revoked = (await ledger.readShard("q"))!;
    expect(revoked.nextSequence).toBe(maxEntriesPerShard + 1);
    expect(revoked.targets[first.account]!.chain).toMatchObject({ members: { [lingering]: { post: null, revocation: { member: lingering, observedAt: clock.now.toISOString(), outcome: "DENIED", phase: "REVOCATION", principal } } }, suppressed: 1 });
    const lateHorizon = new Date(clock.now.getTime() + 3600 * 1000).toISOString();
    expect(scanReadiness(revoked, clock.now).blockers).toEqual(members.map(([target, member]) => `${target.account}: token horizon of ${member} drains at ${target === first && member === lingering ? lateHorizon : new Date(firstPassAt + 3600 * 1000).toISOString()}`));
    // The second target's inventory changes while no entry can be written: the change folds into its chain with the
    // complete new summary, voids its members' chains, and a new baseline starts.
    const baseline = revoked.targets[second.account]!.chain.inventory!;
    inventory.change(second.uniqueId);
    clock.advance(1);
    await broker.reconcileShard("q");
    const changed = (await ledger.readShard("q"))!;
    expect(changed.nextSequence).toBe(maxEntriesPerShard + 1);
    const changedSummary = inventory.summaryOf(second, consumer);
    expect(changed.targets[second.account]!.chain.inventory).toMatchObject({ changes: 1, findings: [], hash: inventoryHash(changedSummary), horizonSeconds: 3600, observedAt: clock.now.toISOString(), summary: changedSummary });
    expect(changed.targets[second.account]!.chain.inventory!.hash).not.toBe(baseline.hash);
    for (const member of second.members) expect(changed.targets[second.account]!.chain.members[member]).toMatchObject({ post: null, revocation: null });
    // The second target's members deliver again after the change and rebuild their chains; then the post-horizon
    // probes of every member are likewise folded in, and the shard is ready, closes, and restores.
    clock.advance(1);
    for (const member of second.members) expect((await deliver(w, "cdbentley", member)).status).toBe(200);
    for (const member of second.members) expect((await ledger.readShard("q"))!.targets[second.account]!.chain.members[member]).toMatchObject({ post: null, revocation: { observedAt: clock.now.toISOString(), outcome: "DENIED" } });
    clock.advance(3600);
    await deliverAll(w, "cdbentley");
    await broker.reconcileShard("q");
    const ready = (await ledger.readShard("q"))!;
    expect(ready.nextSequence).toBe(maxEntriesPerShard + 1);
    expect(scanReadiness(ready, clock.now)).toEqual({ blockers: [], horizonAt: clock.now.toISOString(), ready: true });
    expect(ready.targets[first.account]!.chain).toMatchObject({ members: { [lingering]: { post: { member: lingering, outcome: "DENIED", phase: "HORIZON" } } }, suppressed: 1 + first.members.length });
    expect(ready.targets[second.account]!.chain.suppressed).toBe(1 + 2 * second.members.length);
    expect(ready.targets[second.account]!.chain.members[second.members[0]!]!.revocation!.principal).toBe(principal);
    expect(targets.slice(2).every((target) => ready.targets[target.account]!.chain.suppressed === target.members.length)).toBe(true);
    expect(await beginClose(w, "q", "c")).toMatchObject({ kind: "closing", shard: { closeHighWater: maxEntriesPerShard } });
    expect(await broker.reconcileShard("q")).toMatchObject({ phase: "CLOSED", terminal: { state: "PROJECTED" } });
    const closed = await ledger.readShard("q");
    if (closed?.phase !== "CLOSED") throw new Error();
    const receipt = JSON.parse(closed.terminal.receipt) as { closeHighWater: number; entries: Array<{ body: { kind: string; account?: string } }>; targets: Record<string, { chain: { inventory: { changes: number; hash: string; summary: unknown }; journaled: number; members: Record<string, { allowed: { count: number }; denied: number; post: { principal: string }; revocation: { principal: string } }>; suppressed: number } }> };
    expect(receipt.closeHighWater).toBe(maxEntriesPerShard);
    expect(receipt.entries).toHaveLength(maxEntriesPerShard);
    expect(receipt.targets[first.account]!.chain).toMatchObject({ journaled: 1 + first.members.length + spam, members: { [lingering]: { allowed: { count: spam + 1 }, denied: 2, post: { principal }, revocation: { principal } } }, suppressed: 1 + first.members.length });
    // No entry carries the second target's changed inventory, so the receipt itself carries the preimage of the hash
    // that authorized its close: the complete summary, equal to the folded chain state.
    expect(receipt.entries.filter((entry) => entry.body.kind === "inventory" && entry.body.account === second.account)).toHaveLength(1);
    expect(receipt.targets[second.account]!.chain.inventory).toEqual({ ...ready.targets[second.account]!.chain.inventory!, summary: changedSummary });
    expect(inventoryHash(receipt.targets[second.account]!.chain.inventory.summary as InventoryRecord["summary"])).toBe(receipt.targets[second.account]!.chain.inventory.hash);
    expect(inventoryFindings(receipt.targets[second.account]!.chain.inventory.summary as InventoryRecord["summary"])).toEqual([]);
    expect(evidence.objects.size).toBe(maxEntriesPerShard + 1);
    expect((await ledger.append(restore("r", "cdbentley", "k2", "q"), targets, await freshOf(w, "q"))).kind).toBe("accepted");
  }, 180_000);

  test("inventory folding is monotonic by observation time: an older observation never replaces newer state, an equal-time conflict fails closed, and a strictly later confirmation settles it", async () => {
    const { clock, consumer, iam, inventory, ledger, targets } = await cdbentley();
    const target = targets[0]!;
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    expect((await driveEffect(ledger, iam, "q", (await ledger.readEntry("q", 1))!, target)).kind).toBe("acked");
    const at = (minutes: number, seconds = 0) => new Date(clock.now.getTime() + minutes * 60_000 + seconds * 1000).toISOString();
    const summaryAt = (findings: readonly string[]): InventoryRecord["summary"] => ({ ...inventory.summaryOf(target, consumer), keys: findings.filter((finding) => finding.startsWith("key:")).map((finding) => finding.slice(4)) });
    const record = (observedAt: string, findings: readonly string[] = [], observedUntil = observedAt): InventoryRecord => {
      const summary = summaryAt(findings);
      return { account: target.account, email: target.email, findings: inventoryFindings(summary), hash: inventoryHash(summary), observedAt, observedUntil, summary, uniqueId: target.uniqueId };
    };
    const probe = (member: string, phase: ProbeRecord["phase"], observedAt: string): ProbeRecord => ({ account: target.account, email: target.email, member, observedAt, outcome: "DENIED", permission: probePermission, phase, principal: proberPrincipal, uniqueId: target.uniqueId });
    const blockersOf = async () => scanReadiness((await ledger.readShard("q"))!, clock.now).blockers.filter((blocker) => blocker.startsWith(`${target.account}:`));
    // The exact reproduction: clean at +10, DENIED at +60 and +120 for every member, then a dirty observation from +50.
    const clean = record(at(10));
    clock.advance(3 * 3600);
    expect(await ledger.recordInventory("q", clean)).toMatchObject({ kind: "recorded", role: "BASELINE" });
    for (const member of target.members) expect(await ledger.recordProbe("q", probe(member, "REVOCATION", at(-120)))).toMatchObject({ kind: "recorded", role: "REVOCATION" });
    for (const member of target.members) expect(await ledger.recordProbe("q", probe(member, "HORIZON", at(-60)))).toMatchObject({ kind: "recorded", role: "HORIZON" });
    expect(await blockersOf()).toEqual([]);
    const dirty = record(at(-130), ["key:leaked"]);
    expect(await ledger.recordInventory("q", dirty)).toMatchObject({ kind: "recorded", role: "CHANGE" });
    expect(await blockersOf()).toEqual([`${target.account}: alternate credential paths key:leaked`]);
    // A delayed clean observation from one second before the dirty one is refused; it replaces nothing.
    const delayed = record(new Date(Date.parse(dirty.observedAt) - 1000).toISOString());
    expect(await ledger.recordInventory("q", delayed)).toEqual({ kind: "refused", reason: `the observation at ${delayed.observedAt} is older than the inventory recorded at ${dirty.observedAt}` });
    let chain = (await ledger.readShard("q"))!.targets[target.account]!.chain;
    expect(chain.inventory).toMatchObject({ changes: 1, findings: ["key:leaked"], hash: dirty.hash, observedAt: dirty.observedAt, verifiedAt: dirty.observedAt });
    for (const member of target.members) expect(chain.members[member]).toMatchObject({ post: { phase: "HORIZON" }, revocation: { phase: "REVOCATION" } });
    expect(await blockersOf()).toEqual([`${target.account}: alternate credential paths key:leaked`]);
    // A clean observation at exactly the dirty one's instant contradicts it: the conflict is recorded, marked, and every
    // chain built at or before it is voided; readiness fails closed until a strictly later observation settles the fact.
    const conflicting = record(dirty.observedAt);
    expect(await ledger.recordInventory("q", conflicting)).toMatchObject({ kind: "recorded", role: "CONFLICT" });
    chain = (await ledger.readShard("q"))!.targets[target.account]!.chain;
    expect(chain.inventory).toMatchObject({ changes: 2, findings: [`conflict:${dirty.hash}!=${conflicting.hash}@${dirty.observedAt}`, "key:leaked"], hash: conflicting.hash, observedAt: dirty.observedAt });
    expect((await blockersOf())[0]).toContain("conflict:");
    const later = record(at(-30));
    expect(await ledger.recordInventory("q", later)).toMatchObject({ kind: "recorded", role: "REDUNDANT" });
    chain = (await ledger.readShard("q"))!.targets[target.account]!.chain;
    expect(chain.inventory).toMatchObject({ changes: 2, findings: [], hash: later.hash, observations: 4, verifiedAt: later.observedAt });
    expect(await blockersOf()).toEqual([]);
    // A gate whose fresh observation is older than the recorded inventory is refused as well.
    const stale = { [target.account]: { findings: [], hash: later.hash, observedAt: at(-46), observedUntil: at(-45) } };
    expect((await ledger.beginClose(close("q", "c"), "cdbentley", "QUARANTINE", stale)).kind === "rejected").toBe(true);
    const rejection = await ledger.beginClose(close("q", "c2"), "cdbentley", "QUARANTINE", stale);
    expect(rejection).toMatchObject({ kind: "rejected", rejection: { blockers: expect.arrayContaining([`${target.account}: the credential inventory observed at the gate is older than the inventory recorded at ${later.observedAt}`]), reason: "NOT_READY" } });
  }, 120_000);

  test("an inventory read after a member's revocation voids that member's chain when it detects a change, whatever cached component it began with: the exact cached-timestamp reproduction", async () => {
    const { clock, consumer, iam, inventory, ledger, targets } = await cdbentley();
    const target = targets[0]!;
    const member = target.members[0]!;
    const at = (time: string) => `2026-09-04T${time}.000Z`;
    clock.now = new Date(at("12:00:00"));
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    expect((await driveEffect(ledger, iam, "q", (await ledger.readEntry("q", 1))!, target)).kind).toBe("acked");
    const record = (observedAt: string, observedUntil: string, findings: readonly string[] = []): InventoryRecord => {
      const summary = { ...inventory.summaryOf(target, consumer), keys: findings };
      return { account: target.account, email: target.email, findings: inventoryFindings(summary), hash: inventoryHash(summary), observedAt, observedUntil, summary, uniqueId: target.uniqueId };
    };
    const probe = (observedAt: string): ProbeRecord => ({ account: target.account, email: target.email, member, observedAt, outcome: "DENIED", permission: probePermission, phase: "REVOCATION", principal: proberPrincipal, uniqueId: target.uniqueId });
    const chainOf = async () => (await ledger.readShard("q"))!.targets[target.account]!.chain;
    clock.now = new Date(at("13:00:10"));
    // Clean A observed at 12:00:00; the member's revocation at 12:00:10.
    expect(await ledger.recordInventory("q", record(at("12:00:00"), at("12:00:00")))).toMatchObject({ kind: "recorded", role: "BASELINE" });
    expect(await ledger.recordProbe("q", probe(at("12:00:10")))).toMatchObject({ kind: "recorded", role: "REVOCATION" });
    // Dirty B: a batch that began at 12:00:00 with a cached attachment component and completed its fresh IAM reads at
    // 12:00:20. It is ordered by its completion, so it is a change, and the revocation observed before that completion
    // is void: the mint that B's grant permitted could have happened after 12:00:10.
    expect(await ledger.recordInventory("q", record(at("12:00:00"), at("12:00:20"), ["projects/cdbentley/serviceAccounts/x/keys/leaked"]))).toMatchObject({ kind: "recorded", role: "CHANGE" });
    expect((await chainOf()).members[member]).toMatchObject({ post: null, revocation: null });
    // The benign definition is restored and read back clean at 12:00:40, then confirmed at 12:01:00: a new baseline,
    // never the old chain.
    expect(await ledger.recordInventory("q", record(at("12:00:30"), at("12:00:40")))).toMatchObject({ kind: "recorded", role: "CHANGE" });
    expect(await ledger.recordInventory("q", record(at("12:01:00"), at("12:01:00")))).toMatchObject({ kind: "recorded", role: "REDUNDANT" });
    expect((await chainOf()).inventory).toMatchObject({ changes: 2, findings: [], observedUntil: at("12:00:40"), verifiedAt: at("12:01:00") });
    expect((await chainOf()).members[member]).toMatchObject({ post: null, revocation: null });
    // At 13:00:10 nothing is ready: the member owes a fresh revocation probe after the baseline's completion, and its
    // hour has not begun. A DENIED probe from before that completion counts for nothing; one at the completion starts
    // the member's hour, which drains at 13:00:40.
    expect(scanReadiness((await ledger.readShard("q"))!, clock.now).blockers).toContain(`${target.account}: no DENIED impersonation probe of ${member} after the quarantine acknowledgement`);
    expect(await ledger.recordProbe("q", probe(at("12:00:35")))).toMatchObject({ kind: "recorded", role: "REDUNDANT" });
    expect((await chainOf()).members[member]!.revocation).toBeNull();
    expect(await ledger.recordProbe("q", probe(at("12:00:40")))).toMatchObject({ kind: "recorded", role: "REVOCATION" });
    expect(scanReadiness((await ledger.readShard("q"))!, clock.now).blockers).toContain(`${target.account}: token horizon of ${member} drains at ${at("13:00:40")}`);
    // A record whose interval ends before the inventory recorded is stale, whatever its start.
    expect(await ledger.recordInventory("q", record(at("12:00:50"), at("12:00:59")))).toMatchObject({ kind: "refused", reason: expect.stringContaining("older than the inventory recorded at") });
  }, 60_000);

  test("the fleet sweep pages through the complete reconcilable set across invocations even when the first shards are terminally stuck", async () => {
    const w = await cdbentley();
    const { broker, clock, iam, ledger, targets } = w;
    const shards = Array.from({ length: 70 }, (_, index) => `s-${String(index).padStart(2, "0")}`);
    for (const shard of shards) expect((await ledger.append(quarantine(shard, "cdbentley", `k-${shard}`), targets)).kind).toBe("accepted");
    // Pages are in document-name order and continue after the named shard; the cursor persists between sweeps.
    expect(await ledger.listReconcilable(64, null)).toEqual(shards.slice(0, 64));
    expect(await ledger.listReconcilable(64, shards[63]!)).toEqual(shards.slice(64));
    expect(await ledger.listReconcilable(64, shards[69]!)).toEqual([]);
    expect(await ledger.readReconcileCursor()).toBeNull();
    await ledger.writeReconcileCursor("s-10");
    expect(await ledger.readReconcileCursor()).toBe("s-10");
    await ledger.writeReconcileCursor(null);
    expect(await ledger.readReconcileCursor()).toBeNull();
    // Every shard is stuck: IAM never answers for any identity, so all seventy keep reconcile: true forever.
    iam.unavailableIdentities = Number.MAX_SAFE_INTEGER;
    // Each look at the clock costs twenty seconds, so a sweep's ninety-second budget covers only a few shards.
    clock.secondsPerRead = 20;
    const visited: string[] = [];
    let sweeps = 0;
    for (;;) {
      sweeps += 1;
      const result = await broker.reconcileFleet();
      const ids = (result.shards as Array<{ shard: string }>).map((view) => view.shard);
      expect(ids.length).toBeGreaterThan(0);
      expect(ids.length).toBeLessThan(shards.length);
      visited.push(...ids);
      if (result.next === null) break;
      expect(result.next).toBe(ids.at(-1)!);
      expect(await ledger.readReconcileCursor()).toBe(result.next as string);
      expect(sweeps).toBeLessThan(shards.length);
    }
    expect(sweeps).toBeGreaterThan(1);
    expect(visited).toEqual(shards);
    expect(await ledger.readReconcileCursor()).toBeNull();
    // The next sweep starts over from the first shard, and a cursor left past the end restarts within one sweep.
    expect((((await broker.reconcileFleet()).shards as Array<{ shard: string }>)[0]!).shard).toBe(shards[0]!);
    await ledger.writeReconcileCursor("zz-past-the-end");
    expect((((await broker.reconcileFleet()).shards as Array<{ shard: string }>)[0]!).shard).toBe(shards[0]!);
  }, 300_000);

  test("a shard whose ledger read never settles is passed at its deadline with its cursor progress persisted, and the next shard is visited in this and every later invocation", async () => {
    const clock = new Clock();
    let armed = false;
    let hung = 0;
    // The exact review reproduction: the first shard's readShard never settles. The hung read honours the abort signal
    // the broker attaches to every outbound call, exactly as a real fetch does.
    const hanging: typeof fetch = Object.assign(async (input: string | URL | Request, init?: RequestInit) => {
      const body = typeof init?.body === "string" ? (JSON.parse(init.body) as { documents?: string[] }) : {};
      const documents = body.documents ?? [];
      if (armed && String(input).endsWith(":batchGet") && documents.length === 1 && documents[0]!.endsWith("/shards/a-stuck")) {
        hung += 1;
        return await new Promise<Response>((_, reject) => init?.signal?.addEventListener("abort", () => reject(new Error("the hung read was aborted")), { once: true }));
      }
      return await fetch(input, init);
    }, { preconnect: fetch.preconnect });
    // The shard deadline must outlast a shard's real work on a slow emulator while still bounding a hung one.
    const w = await cdbentley(clock, boundedFetch(hanging, 30_000), { requestMs: 30_000, shardMs: 8000 });
    const { broker, ledger, targets } = w;
    for (const shard of ["a-stuck", "b-ready"]) expect((await ledger.append(quarantine(shard, "cdbentley", `k-${shard}`), targets)).kind).toBe("accepted");
    const cursorWrites: Array<string | null> = [];
    const write = ledger.writeReconcileCursor.bind(ledger);
    ledger.writeReconcileCursor = async (after) => {
      cursorWrites.push(after);
      await write(after);
    };
    armed = true;
    const started = Date.now();
    const first = await broker.reconcileFleet();
    expect(Date.now() - started).toBeLessThan(25_000);
    expect(hung).toBe(1);
    expect(first.shards).toEqual([
      expect.objectContaining({ deadline: true, notes: [expect.stringContaining("passed; ")], shard: "a-stuck" }),
      expect.objectContaining({ pendingEffects: 0, phase: "OPEN", shard: "b-ready" }),
    ]);
    expect(cursorWrites).toEqual(["a-stuck", "b-ready", null]);
    expect(first.next).toBeNull();
    expect(w.iam.writes.map((entry) => entry.resource)).toEqual(targets.map((target) => target.resource));
    // The next invocation visits the later shard again while the first is still hung.
    const second = await broker.reconcileFleet();
    expect(hung).toBe(2);
    expect((second.shards as Array<{ shard: string }>).map((view) => view.shard)).toEqual(["a-stuck", "b-ready"]);
    // A call that never settles and ignores its signal is passed just the same: another consumer's shard whose first
    // identity read hangs in the IAM stand-in. The consumer is primed first, because admission needs its positive
    // controls before the effect reaches that read.
    armed = false;
    const runsetta = w.authority.consumers.find((candidate) => candidate.repository === "runsetta")!;
    const runsettaTargets = targetsFor(w.authority, runsetta)!;
    await prime(w, "runsetta");
    w.iam.hangIdentities.add(runsettaTargets[0]!.resource);
    expect((await ledger.append(quarantine("c-hung-iam", "runsetta", "k-c"), runsettaTargets)).kind).toBe("accepted");
    const third = await broker.reconcileFleet();
    expect((third.shards as Array<{ deadline?: boolean; shard: string }>).find((view) => view.shard === "c-hung-iam")).toMatchObject({ deadline: true });
    expect((third.shards as Array<{ shard: string }>).map((view) => view.shard)).toEqual(["a-stuck", "b-ready", "c-hung-iam"]);
  }, 120_000);

  test("an effect interrupted by the deadline after its write landed is classified exactly on the next pass without a second write", async () => {
    const w = await cdbentley(new Clock(), fetch, { requestMs: 30_000, shardMs: 3000 });
    const { broker, iam, ledger, targets } = w;
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    iam.hangAfterWrite = true;
    const interrupted = await broker.handle({ kind: "reconciler", serviceAccount: "recovery-reconciler" }, { kind: "reconcile", shard: "q" });
    expect(interrupted).toMatchObject({ status: 200, body: { shard: { deadline: true, shard: "q" } } });
    expect(iam.writes).toHaveLength(1);
    expect((await ledger.readEntry("q", 1))!.progress).toMatchObject({ state: "PREPARED", attempts: 1 });
    expect(await ledger.readActuator(targets[0]!.uniqueId)).toMatchObject({ holder: { effectId: "q/1" } });
    // The next pass finds the landed write as the exact after state: acknowledged, not rewritten.
    await broker.reconcileShard("q");
    expect((await ledger.readEntry("q", 1))!.progress).toMatchObject({ state: "ACKED", attempts: 2, mutated: false });
    expect(iam.writes.filter((write) => write.resource === targets[0]!.resource)).toHaveLength(1);
    expect(iam.writes).toHaveLength(9);
  }, 60_000);
});
