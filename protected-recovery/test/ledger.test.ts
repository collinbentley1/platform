import { describe, expect, test } from "bun:test";
import { driveEffect } from "../src/effects";
import { LedgerUnavailable } from "../src/ledger";
import { type ProbeRecord, probePermission, targetsFor } from "../src/model";
import { Clock, close, emulatorHost, emulatorLedger, makeReady, proberPrincipal, quarantine, restore, seedTargets, testAuthority, world } from "./support";

const cdbentley = async () => {
  const w = await world();
  const consumer = w.authority.consumers.find((candidate) => candidate.repository === "cdbentley")!;
  const targets = targetsFor(w.authority, consumer)!;
  seedTargets(w.iam, targets);
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
    const replay = await ledger.append(quarantine("q", "cdbentley", "k1"), targets);
    expect(replay).toEqual({ kind: "replayed", result: first.result });
    expect((await ledger.readShard("q"))!.nextSequence).toBe(10);
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
    expect(await ledger.beginClose(close("q", "c1"), "cdbentley", "QUARANTINE")).toMatchObject({ kind: "rejected", rejection: { reason: "NOT_READY" } });
    expect((await ledger.readShard("q"))!.phase).toBe("OPEN");
    await makeReady(w, "q");
    expect(await ledger.beginClose(close("q", "c1"), "runsetta", "QUARANTINE")).toMatchObject({ kind: "rejected", rejection: { reason: "SHARD_MISMATCH" } });
    expect(await ledger.beginClose(close("q", "c1"), "cdbentley", "RESTORE")).toMatchObject({ kind: "rejected", rejection: { reason: "SHARD_MISMATCH" } });
    const closing = await ledger.beginClose(close("q", "c1"), "cdbentley", "QUARANTINE");
    expect(closing.kind).toBe("closing");
    expect(await ledger.beginClose(close("q", "c1"), "cdbentley", "QUARANTINE")).toEqual({ kind: "replayed", result: closing.kind === "closing" ? closing.result : "" });
    expect(await ledger.beginClose({ ...close("q", "c1"), bodyHash: "0".repeat(64) }, "cdbentley", "QUARANTINE")).toEqual({ kind: "conflict" });
    expect(await ledger.beginClose(close("q", "c2"), "cdbentley", "QUARANTINE")).toMatchObject({ kind: "rejected", rejection: { phase: "CLOSING", reason: "SHARD_NOT_OPEN" } });
    expect(await ledger.beginClose(close("missing", "c4"), "cdbentley", "QUARANTINE")).toMatchObject({ kind: "rejected", rejection: { reason: "NOT_FOUND" } });
  }, 60_000);

  test("one hundred concurrent probe records race a close from another instance: every accepted record is at or below closeHighWater and every later record is refused", async () => {
    const w = await cdbentley();
    const { clock, ledger, targets } = w;
    const other = w.anotherInstance().ledger;
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    await makeReady(w, "q");
    const before = (await ledger.readShard("q"))!.nextSequence - 1;
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
      return await other.beginClose(close("q", "close"), "cdbentley", "QUARANTINE");
    })();
    const [outcomes, closed] = await Promise.all([Promise.all(records), closing]);
    expect(closed.kind).toBe("closing");
    if (closed.kind !== "closing" || closed.shard.phase !== "CLOSING") throw new Error();
    const highWater = closed.shard.closeHighWater;
    const accepted = outcomes.filter((outcome) => outcome.kind === "recorded");
    const refused = outcomes.filter((outcome) => outcome.kind === "refused");
    expect(accepted.length + refused.length).toBe(100);
    expect(refused.every((outcome) => outcome.kind === "refused" && outcome.reason === "the shard is CLOSING")).toBe(true);
    const sequences = accepted.flatMap((outcome) => (outcome.kind === "recorded" ? [outcome.entry.sequence] : [])).sort((left, right) => left - right);
    expect(sequences.every((sequence) => sequence <= highWater)).toBe(true);
    expect(sequences).toEqual(Array.from({ length: sequences.length }, (_, index) => before + 1 + index));
    expect(highWater).toBe(before + sequences.length);
    const entries = await ledger.readEntries("q", highWater);
    expect(entries).toHaveLength(highWater);
    expect(await ledger.recordProbe("q", probe)).toEqual({ kind: "refused", reason: "the shard is CLOSING" });
    expect(await other.recordProbe("q", probe)).toEqual({ kind: "refused", reason: "the shard is CLOSING" });
    console.log(`100 concurrent probe records against close: ${accepted.length} accepted, ${refused.length} refused, closeHighWater ${highWater}, ${Date.now() - started}ms`);
  }, 300_000);

  test("a shard admits only its consumer and intent, and a probe only an acknowledged target's exact identity, managed member, permission, and admissible observation", async () => {
    const { authority, clock, iam, ledger, targets } = await cdbentley();
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
    expect(await ledger.recordProbe("q", probe({ uniqueId: "199990000000000000000" }))).toEqual({ kind: "refused", reason: "the probe names a different identity than the journaled target" });
    expect(await ledger.recordProbe("q", probe({ email: "other@cdbentley.iam.gserviceaccount.com" }))).toEqual({ kind: "refused", reason: "the probe names a different identity than the journaled target" });
    expect(await ledger.recordProbe("q", probe({ member: "principalSet://iam.googleapis.com/other" }))).toEqual({ kind: "refused", reason: "the probed member is not a managed member of the target" });
    expect(await ledger.recordProbe("q", probe({ permission: "iam.serviceAccounts.actAs" as typeof probePermission }))).toEqual({ kind: "refused", reason: `the probed permission is not ${probePermission}` });
    expect(await ledger.recordProbe("q", probe({ principal: "" }))).toEqual({ kind: "refused", reason: "the probe names no principal" });
    expect(await ledger.recordProbe("q", probe({ phase: "LATER" as ProbeRecord["phase"] }))).toEqual({ kind: "refused", reason: "unknown probe phase or outcome" });
    expect(await ledger.recordProbe("q", probe({ observedAt: "2020-01-01T00:00:00.000Z" }))).toEqual({ kind: "refused", reason: "the observation precedes the quarantine acknowledgement" });
    expect(await ledger.recordProbe("q", probe({ observedAt: "yesterday" }))).toEqual({ kind: "refused", reason: "observedAt must be an ISO-8601 UTC instant" });
    expect(await ledger.recordProbe("q", probe({ observedAt: new Date(clock.now.getTime() + 1000).toISOString() }))).toEqual({ kind: "refused", reason: "the observation is in the ledger's future" });
    expect(await ledger.recordProbe("missing", probe())).toEqual({ kind: "refused", reason: "the shard does not exist" });
    const recorded = await ledger.recordProbe("q", probe());
    expect(recorded).toMatchObject({ kind: "recorded", entry: { key: `probe/${target.account}/REVOCATION/${clock.now.toISOString()}`, progress: null, sequence: 10 } });
    expect((await ledger.readShard("q"))!).toMatchObject({ nextSequence: 11, pendingEffects: 8, pendingOutbox: 10 });
    // Another consumer's shard journals the same account names under other identities; this target's probe names none of them.
    expect((await ledger.append(quarantine("q2", "runsetta", "k4"), runsettaTargets)).kind).toBe("accepted");
    expect((await driveEffect(ledger, iam, "q2", (await ledger.readEntry("q2", 1))!, runsettaTargets[0]!)).kind).toBe("acked");
    expect(await ledger.recordProbe("q2", probe())).toEqual({ kind: "refused", reason: "the probe names a different identity than the journaled target" });
  }, 60_000);

  test("restore needs the source's projected completeness receipt on a scan-ready close and copies exactly the captured identities and members", async () => {
    const w = await cdbentley();
    const { broker, ledger, targets } = w;
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    expect(await ledger.append(restore("r", "cdbentley", "k2", "q"), targets)).toMatchObject({ kind: "rejected", rejection: { reason: "SOURCE_NOT_COMPLETE" } });
    await broker.reconcileShard("q");
    expect(await ledger.beginClose(close("q", "c"), "cdbentley", "QUARANTINE")).toMatchObject({ kind: "rejected", rejection: { reason: "NOT_READY" } });
    await makeReady(w, "q");
    expect((await ledger.beginClose(close("q", "c"), "cdbentley", "QUARANTINE")).kind).toBe("closing");
    expect(await ledger.append(restore("r", "cdbentley", "k2", "q"), targets)).toMatchObject({ kind: "rejected", rejection: { reason: "SOURCE_NOT_COMPLETE" } });
    await broker.reconcileShard("q");
    expect((await ledger.readShard("q"))!.phase).toBe("CLOSED");
    expect(await ledger.append(restore("r", "cdbentley", "k2", "missing"), targets)).toMatchObject({ kind: "rejected", rejection: { reason: "SOURCE_NOT_COMPLETE" } });
    expect(await ledger.append(restore("r", "runsetta", "k2", "q"), targets)).toMatchObject({ kind: "rejected", rejection: { reason: "SOURCE_NOT_COMPLETE" } });
    const restored = await ledger.append(restore("r", "cdbentley", "k2", "q"), targets);
    expect(restored.kind).toBe("accepted");
    if (restored.kind !== "accepted") throw new Error();
    const quarantined = (await ledger.readEntries("q", 27)).filter((entry) => entry.body.kind === "effect");
    expect(quarantined).toHaveLength(9);
    expect(restored.entries.map((entry) => entry.body)).toEqual(quarantined.map((entry) => (entry.body.kind === "effect" ? { ...entry.body, intent: "RESTORE" } : entry.body)));
    expect((await ledger.readShard("r"))!).toMatchObject({ intent: "RESTORE", source: "q" });
  }, 60_000);

  test("the actuator orders effects per identity: reserved once, held against others, released on acknowledgement", async () => {
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
    expect((await ledger.prepareEffect("q1", 1, { ...facts, after: snapshot, alternateIssuers: [], before: snapshot })).kind).toBe("transitioned");
    expect((await ledger.recordAttempt("q1", 1, wrong)).kind).toBe("unchanged");
    expect((await ledger.recordAttempt("q1", 1, facts)).kind).toBe("transitioned");
    expect((await ledger.acknowledgeEffect("q1", 1, { ...wrong, mutated: true, observed: { ...snapshot, etag: "e2" } })).kind).toBe("unchanged");
    expect((await ledger.acknowledgeEffect("q1", 1, { ...facts, mutated: true, observed: { ...snapshot, etag: "e2" } })).kind).toBe("transitioned");
    expect(await ledger.readActuator(uniqueId)).toEqual({ epoch: 1, holder: null, lastEtag: "e2" });
    expect((await ledger.acknowledgeEffect("q1", 1, { ...facts, mutated: true, observed: snapshot })).kind).toBe("unchanged");
    expect(await ledger.reserveActuator("q2", 1, uniqueId)).toEqual({ kind: "reserved", effectId: "q2/1", epoch: 2 });
    expect((await ledger.divergeEffect("q2", 1, { effectId: "q2/1", epoch: 2, observed: null, reason: "test" })).kind).toBe("transitioned");
    expect(await ledger.readActuator(uniqueId)).toEqual({ epoch: 2, holder: null, lastEtag: "e2" });
    expect((await ledger.readShard("q2"))!).toMatchObject({ pendingEffects: 8 });
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
});
