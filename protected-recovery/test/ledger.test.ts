import { describe, expect, test } from "bun:test";
import { LedgerUnavailable } from "../src/ledger";
import { targetsFor } from "../src/model";
import { Clock, canary, close, emulatorHost, emulatorLedger, quarantine, restore, seedTargets, testAuthority, world } from "./support";

const cdbentley = async () => {
  const w = await world();
  const consumer = w.authority.consumers.find((candidate) => candidate.repository === "cdbentley")!;
  const targets = targetsFor(w.authority, consumer)!;
  seedTargets(w.iam, targets);
  return { ...w, consumer, targets };
};

describe.skipIf(!emulatorHost)("ledger (Firestore emulator)", () => {
  test("a quarantine append journals every target separately and replays the same key and body", async () => {
    const { ledger, targets } = await cdbentley();
    const first = await ledger.append(quarantine("q", "cdbentley", "k1"), targets);
    expect(first.kind).toBe("accepted");
    if (first.kind !== "accepted") throw new Error();
    expect(first.entries.map((entry) => entry.body.kind === "effect" && entry.body.account)).toEqual(targets.map((target) => target.account));
    expect(first.entries.every((entry) => entry.progress?.state === "RECORDED" && entry.outbox.state === "PENDING")).toBe(true);
    const shard = (await ledger.readShard("q"))!;
    expect(shard).toMatchObject({ consumer: "cdbentley", intent: "QUARANTINE", nextSequence: 10, pendingEffects: 9, pendingOutbox: 9, phase: "OPEN", source: null });
    expect(Object.keys(shard.targets)).toHaveLength(9);
    const replay = await ledger.append(quarantine("q", "cdbentley", "k1"), targets);
    expect(replay).toEqual({ kind: "replayed", result: first.result });
    expect((await ledger.readShard("q"))!.nextSequence).toBe(10);
    // A second quarantine of the same shard under a new key would journal duplicates and is refused.
    expect(await ledger.append(quarantine("q", "cdbentley", "k2"), targets)).toMatchObject({ kind: "rejected", rejection: { reason: "SHARD_MISMATCH" } });
    // Unrecorded pins refuse the derivation outright.
    expect(await ledger.append(quarantine("q2", "cdbentley", "k3"), undefined)).toMatchObject({ kind: "rejected", rejection: { reason: "PINS_UNRECORDED" } });
  });

  test("the same key with a different body is refused and reordered duplicates converge", async () => {
    const { ledger, targets } = await cdbentley();
    const requests = [quarantine("q", "cdbentley", "k1"), quarantine("q", "cdbentley", "k1"), quarantine("q", "cdbentley", "k1")];
    const outcomes = await Promise.all(requests.map((request) => ledger.append(request, targets)));
    expect(outcomes.filter((outcome) => outcome.kind === "accepted")).toHaveLength(1);
    expect(outcomes.filter((outcome) => outcome.kind === "replayed")).toHaveLength(2);
    expect(await ledger.append(restore("q", "cdbentley", "k1", "other"), targets)).toEqual({ kind: "conflict" });
    expect(await ledger.append({ ...quarantine("q", "cdbentley", "k1"), bodyHash: "0".repeat(64) }, targets)).toEqual({ kind: "conflict" });
    const closing = await ledger.beginClose(close("q", "c1"), "cdbentley");
    expect(closing.kind).toBe("closing");
    expect(await ledger.beginClose(close("q", "c1"), "cdbentley")).toEqual({ kind: "replayed", result: closing.kind === "closing" ? closing.result : "" });
    expect(await ledger.beginClose({ ...close("q", "c1"), bodyHash: "0".repeat(64) }, "cdbentley")).toEqual({ kind: "conflict" });
    expect(await ledger.beginClose(close("q", "c2"), "cdbentley")).toMatchObject({ kind: "rejected", rejection: { phase: "CLOSING", reason: "SHARD_NOT_OPEN" } });
    expect(await ledger.beginClose(close("q", "c3"), "runsetta")).toMatchObject({ kind: "rejected", rejection: { reason: "SHARD_MISMATCH" } });
    expect(await ledger.beginClose(close("missing", "c4"), "cdbentley")).toMatchObject({ kind: "rejected", rejection: { reason: "NOT_FOUND" } });
  });

  test("one hundred concurrent appends race a close from another instance: every accepted append is at or below closeHighWater and every later append is rejected", async () => {
    const w = await cdbentley();
    const { broker, clock, ledger, targets } = w;
    const other = w.anotherInstance().ledger;
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    await broker.reconcileShard("q");
    clock.advance(1);
    const target = targets[0]!;
    const observedAt = clock.now.toISOString();
    // A caller whose append is answered 503 retries the same key; the ledger replays or rejects it exactly as if it had waited.
    const appendWithRetries = async (index: number) => {
      for (let attempt = 1; ; attempt += 1) {
        try {
          return await ledger.append(canary("q", "cdbentley", `c-${index}`, target.account, target.members[0]!, observedAt), undefined);
        } catch (error) {
          if (!(error instanceof LedgerUnavailable) || attempt === 20) throw error;
        }
      }
    };
    const started = Date.now();
    const appends = Array.from({ length: 100 }, (_, index) => appendWithRetries(index));
    const closing = (async () => {
      await Bun.sleep(25);
      return await other.beginClose(close("q", "close"), "cdbentley");
    })();
    const [outcomes, closed] = await Promise.all([Promise.all(appends), closing]);
    expect(closed.kind).toBe("closing");
    if (closed.kind !== "closing" || closed.shard.phase !== "CLOSING") throw new Error();
    const highWater = closed.shard.closeHighWater;
    const accepted = outcomes.filter((outcome) => outcome.kind === "accepted");
    const rejected = outcomes.filter((outcome) => outcome.kind === "rejected");
    expect(accepted.length + rejected.length).toBe(100);
    expect(rejected.every((outcome) => outcome.kind === "rejected" && outcome.rejection.reason === "SHARD_NOT_OPEN")).toBe(true);
    const sequences = accepted.flatMap((outcome) => (outcome.kind === "accepted" ? outcome.entries.map((entry) => entry.sequence) : [])).sort((left, right) => left - right);
    expect(sequences.every((sequence) => sequence <= highWater)).toBe(true);
    expect(sequences).toEqual(Array.from({ length: sequences.length }, (_, index) => 10 + index));
    expect(highWater).toBe(9 + sequences.length);
    const entries = await ledger.readEntries("q", highWater);
    expect(entries).toHaveLength(highWater);
    expect(await ledger.append(canary("q", "cdbentley", "late", target.account, target.members[0]!, observedAt), undefined)).toMatchObject({ kind: "rejected", rejection: { phase: "CLOSING", reason: "SHARD_NOT_OPEN" } });
    expect(await other.append(canary("q", "cdbentley", "late-2", target.account, target.members[0]!, observedAt), undefined)).toMatchObject({ kind: "rejected", rejection: { phase: "CLOSING", reason: "SHARD_NOT_OPEN" } });
    console.log(`100 concurrent appends against close: ${accepted.length} accepted, ${rejected.length} rejected, closeHighWater ${highWater}, ${Date.now() - started}ms`);
  }, 300_000);

  test("a shard admits only its consumer and intent, and a canary only an acknowledged managed member", async () => {
    const { authority, broker, clock, iam, ledger, targets } = await cdbentley();
    const runsetta = authority.consumers.find((candidate) => candidate.repository === "runsetta")!;
    const runsettaTargets = targetsFor(authority, runsetta)!;
    seedTargets(iam, runsettaTargets);
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    expect(await ledger.append(quarantine("q", "runsetta", "k2"), runsettaTargets)).toMatchObject({ kind: "rejected", rejection: { reason: "SHARD_MISMATCH" } });
    expect(await ledger.append(restore("q", "cdbentley", "k3", "q0"), targets)).toMatchObject({ kind: "rejected", rejection: { reason: "SHARD_MISMATCH" } });
    const target = targets[0]!;
    const member = target.members[0]!;
    // Evidence before the acknowledgement, for an unknown target, or for a foreign member is premature.
    expect(await ledger.append(canary("q", "cdbentley", "c1", target.account, member, clock.now.toISOString()), undefined)).toMatchObject({ kind: "rejected", rejection: { reason: "CANARY_PREMATURE" } });
    await broker.reconcileShard("q");
    expect(await ledger.append(canary("q", "cdbentley", "c2", "gha-nobody", member, clock.now.toISOString()), undefined)).toMatchObject({ kind: "rejected", rejection: { reason: "CANARY_PREMATURE" } });
    expect(await ledger.append(canary("q", "cdbentley", "c3", target.account, "principalSet://iam.googleapis.com/other", clock.now.toISOString()), undefined)).toMatchObject({ kind: "rejected", rejection: { reason: "CANARY_PREMATURE" } });
    expect(await ledger.append(canary("q", "cdbentley", "c4", target.account, member, "2020-01-01T00:00:00Z"), undefined)).toMatchObject({ kind: "rejected", rejection: { reason: "CANARY_PREMATURE" } });
    expect(await ledger.append(canary("missing", "cdbentley", "c5", target.account, member, clock.now.toISOString()), undefined)).toMatchObject({ kind: "rejected", rejection: { reason: "CANARY_PREMATURE" } });
    clock.advance(1);
    expect((await ledger.append(canary("q", "cdbentley", "c6", target.account, member, clock.now.toISOString()), undefined)).kind).toBe("accepted");
  });

  test("restore needs the source's projected completeness receipt and copies exactly the captured members", async () => {
    const { broker, ledger, targets } = await cdbentley();
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    expect(await ledger.append(restore("r", "cdbentley", "k2", "q"), targets)).toMatchObject({ kind: "rejected", rejection: { reason: "SOURCE_NOT_COMPLETE" } });
    await broker.reconcileShard("q");
    expect((await ledger.beginClose(close("q", "c"), "cdbentley")).kind).toBe("closing");
    expect(await ledger.append(restore("r", "cdbentley", "k2", "q"), targets)).toMatchObject({ kind: "rejected", rejection: { reason: "SOURCE_NOT_COMPLETE" } });
    await broker.reconcileShard("q");
    expect((await ledger.readShard("q"))!.phase).toBe("CLOSED");
    expect(await ledger.append(restore("r", "cdbentley", "k2", "missing"), targets)).toMatchObject({ kind: "rejected", rejection: { reason: "SOURCE_NOT_COMPLETE" } });
    expect(await ledger.append(restore("r", "runsetta", "k2", "q"), targets)).toMatchObject({ kind: "rejected", rejection: { reason: "SOURCE_NOT_COMPLETE" } });
    const restored = await ledger.append(restore("r", "cdbentley", "k2", "q"), targets);
    expect(restored.kind).toBe("accepted");
    if (restored.kind !== "accepted") throw new Error();
    const quarantined = await ledger.readEntries("q", 9);
    expect(restored.entries.map((entry) => entry.body)).toEqual(quarantined.map((entry) => (entry.body.kind === "effect" ? { ...entry.body, intent: "RESTORE" } : entry.body)));
    expect((await ledger.readShard("r"))!).toMatchObject({ intent: "RESTORE", source: "q" });
  });

  test("the actuator orders effects per target: reserved once, held against others, released on acknowledgement", async () => {
    const { ledger, targets } = await cdbentley();
    expect((await ledger.append(quarantine("q1", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    expect((await ledger.append(quarantine("q2", "cdbentley", "k2"), targets)).kind).toBe("accepted");
    const email = targets[0]!.email;
    expect(await ledger.readActuator(email)).toBeUndefined();
    expect(await ledger.reserveActuator("q1", 1, email)).toEqual({ kind: "reserved", effectId: "q1/1", epoch: 1 });
    expect(await ledger.reserveActuator("q1", 1, email)).toEqual({ kind: "reserved", effectId: "q1/1", epoch: 1 });
    expect(await ledger.reserveActuator("q2", 1, email)).toEqual({ kind: "held", holder: { effectId: "q1/1", sequence: 1, shard: "q1" } });
    const facts = { effectId: "q1/1", epoch: 1 };
    const wrong = { effectId: "q1/1", epoch: 2 };
    const snapshot = { etag: "e", hash: "h", policy: "[]" };
    expect((await ledger.prepareEffect("q1", 1, { ...wrong, after: snapshot, alternateIssuers: [], before: snapshot })).kind).toBe("unchanged");
    expect((await ledger.prepareEffect("q1", 1, { ...facts, after: snapshot, alternateIssuers: [], before: snapshot })).kind).toBe("transitioned");
    expect((await ledger.recordAttempt("q1", 1, wrong)).kind).toBe("unchanged");
    expect((await ledger.recordAttempt("q1", 1, facts)).kind).toBe("transitioned");
    expect((await ledger.acknowledgeEffect("q1", 1, { ...wrong, mutated: true, observed: { ...snapshot, etag: "e2" } })).kind).toBe("unchanged");
    expect((await ledger.acknowledgeEffect("q1", 1, { ...facts, mutated: true, observed: { ...snapshot, etag: "e2" } })).kind).toBe("transitioned");
    expect(await ledger.readActuator(email)).toEqual({ epoch: 1, holder: null, lastEtag: "e2" });
    expect((await ledger.acknowledgeEffect("q1", 1, { ...facts, mutated: true, observed: snapshot })).kind).toBe("unchanged");
    expect(await ledger.reserveActuator("q2", 1, email)).toEqual({ kind: "reserved", effectId: "q2/1", epoch: 2 });
    expect((await ledger.divergeEffect("q2", 1, { effectId: "q2/1", epoch: 2, observed: null, reason: "test" })).kind).toBe("transitioned");
    expect(await ledger.readActuator(email)).toEqual({ epoch: 2, holder: null, lastEtag: "e2" });
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
    await expect(ledger.beginClose(close("q", "c1"), "cdbentley")).rejects.toBeInstanceOf(LedgerUnavailable);
    await expect(ledger.readShard("q")).rejects.toBeInstanceOf(LedgerUnavailable);
    failing = false;
    expect(await ledger.readShard("q")).toBeUndefined();
    expect(await ledger.readEntry("q", 1)).toBeUndefined();
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("replayed");
    expect((await ledger.readShard("q"))!.nextSequence).toBe(10);
  });
});
