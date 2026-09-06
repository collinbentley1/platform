import { describe, expect, test } from "bun:test";
import { handleRequest } from "../src/http";
import { driveEffect } from "../src/effects";
import { type RoundManifest, type RoundPhase, maxEntriesPerShard, probePermission, parseRoundBody, parseRoundRunsBody, purposeForIdentity, roundComplete, scanReadiness, targetsFor } from "../src/model";
import { type World, FakeVerifier, consumerOf, controlRound, deliver, deliverAll, emulatorHost, invokerEmail, openRound, prime, quarantine, seedTargets, world } from "./support";

const purpose = (w: World) => purposeForIdentity(w.authority, invokerEmail("cdbentley"))!;
const create = (w: World, label: string, phase: RoundPhase = "CONTROL", shard: string | null = null) => w.broker.handle(purpose(w), parseRoundBody({ consumer: "cdbentley", key: `round/${label}`, label, phase, shard }));
const status = async (w: World, id: string) => (await w.broker.handle(purpose(w), { kind: "round-read", round: id })).body.round as { complete: boolean; phaseReady: boolean; blockers: string[]; expiredAt: string | null };
async function manifest(w: World, id: string): Promise<RoundManifest> {
  const round = await w.ledger.readRound(id);
  if (!round) throw new Error("round missing");
  return round;
}
async function bind(w: World, id: string, runId: string) {
  const round = await manifest(w, id);
  return await w.broker.handle(purpose(w), parseRoundRunsBody(id, { runs: Object.fromEntries(round.members.map((member) => [member, { runId, runAttempt: "1" }])) }));
}

// These tests exercise defensive state contracts on the real Firestore
// emulator; the identity signer, IAM and inventory remain local stand-ins.
describe.skipIf(!emulatorHost)("phase delivery rounds (Firestore emulator)", () => {
  test("the complete runsetta transition mapping fits its route-specific request cap", async () => {
    const w = await world();
    const consumer = consumerOf(w, "runsetta");
    seedTargets(w.iam, targetsFor(w.authority, consumer)!);
    const opened = await w.broker.handle(purposeForIdentity(w.authority, invokerEmail("runsetta"))!, parseRoundBody({ consumer: "runsetta", key: "round/size", label: "size", phase: "CONTROL", shard: null }));
    expect(opened.status).toBe(201);
    const id = (opened.body.round as { round: string }).round;
    const members = (await manifest(w, id)).members;
    expect(members).toHaveLength(19);
    const body = JSON.stringify({ runs: Object.fromEntries(members.map((member) => [member, { runId: "9".repeat(20), runAttempt: "9".repeat(10) }])) });
    expect(new TextEncoder().encode(body).length).toBeGreaterThan(8 * 1024);
    const request = (path: string, text = body) => new Request(`https://broker.test${path}`, { method: "POST", headers: { authorization: `Bearer ${invokerEmail("runsetta")}`, "content-type": "application/json" }, body: text });
    const service = { authority: w.authority, broker: w.broker, verifier: new FakeVerifier() };
    expect((await handleRequest(service, request(`/v1/rounds/${id}/runs`))).status).toBe(200);
    expect((await handleRequest(service, request(`/v1/rounds/${id}/runs`, " ".repeat(16 * 1024) + body))).status).toBe(413);
    expect((await handleRequest(service, request("/v1/members"))).status).toBe(413);
  }, 180_000);

  test("early deliveries are bounded, count only exact registered runs and cannot be claimed by a second round", async () => {
    const w = await world();
    seedTargets(w.iam, targetsFor(w.authority, consumerOf(w, "cdbentley"))!);
    const opened = await create(w, "early");
    expect(opened.status).toBe(201);
    const id = (opened.body.round as { round: string }).round;
    for (const response of await deliverAll(w, "cdbentley", "8001")) expect(response.status).toBe(200);
    expect((await manifest(w, id)).receipts).toEqual({});
    expect((await status(w, id)).complete).toBe(false);
    expect((await bind(w, id, "8001")).status).toBe(200);
    expect(await status(w, id)).toMatchObject({ complete: true, phaseReady: true });
    expect((await bind(w, id, "8001")).status).toBe(200);
    expect((await bind(w, id, "8002")).status).toBe(409);
    const next = await create(w, "second");
    const nextId = (next.body.round as { round: string }).round;
    expect((await bind(w, nextId, "8001")).status).toBe(409);
    const member = (await manifest(w, nextId)).members[0]!;
    for (let run = 8010; run < 8018; run += 1) await deliver(w, "cdbentley", member, String(run));
    expect((await manifest(w, nextId)).pending.filter((pending) => pending.member === member)).toHaveLength(4);
    expect((await create(w, "another-live")).status).toBe(409);
  }, 180_000);

  test("a partial CONTROL round expires without becoming fresh when its last member arrives", async () => {
    const w = await world();
    seedTargets(w.iam, targetsFor(w.authority, consumerOf(w, "cdbentley"))!);
    const id = await openRound(w, "cdbentley", "CONTROL", null);
    const round = await manifest(w, id);
    for (const member of round.members.slice(0, -1)) await deliver(w, "cdbentley", member);
    w.clock.advance(24 * 3600 + 1);
    await deliver(w, "cdbentley", round.members.at(-1)!);
    expect(await status(w, id)).toMatchObject({ complete: false, phaseReady: false, expiredAt: w.clock.now.toISOString() });
    expect(await w.ledger.readRoundPointer("cdbentley")).toEqual({ control: null, open: [] });
    expect((await w.broker.handle(purpose(w), quarantine("q", "cdbentley", "q"))).status).toBe(409);
    expect((await create(w, "replacement")).status).toBe(201);
  }, 180_000);

  test("phase opening requires every acknowledgement, committed baseline and due horizon", async () => {
    const w = await world();
    const targets = await prime(w, "cdbentley");
    expect((await w.broker.handle(purpose(w), quarantine("q", "cdbentley", "q"))).status).toBe(201);
    expect((await create(w, "partial", "REVOCATION", "q")).status).toBe(409);
    for (const [index, target] of targets.entries()) await driveEffect(w.ledger, w.iam, "q", (await w.ledger.readEntry("q", index + 1))!, target);
    expect((await create(w, "no-baseline", "REVOCATION", "q")).status).toBe(409);
    await w.broker.reconcileShard("q");
    expect((await create(w, "not-due", "HORIZON", "q")).status).toBe(409);
    const revocation = await openRound(w, "cdbentley", "REVOCATION", "q");
    await deliverAll(w, "cdbentley");
    expect(await status(w, revocation)).toMatchObject({ complete: true, phaseReady: true });
    expect((await create(w, "too-soon", "HORIZON", "q")).status).toBe(409);
    w.clock.advance(3600);
    const horizon = await openRound(w, "cdbentley", "HORIZON", "q");
    await deliverAll(w, "cdbentley");
    expect(await status(w, horizon)).toMatchObject({ complete: true, phaseReady: true });
    expect(scanReadiness((await w.ledger.readShard("q"))!, w.clock.now).ready).toBe(true);
  }, 180_000);

  test("ALLOWED phase receipts cannot complete a round and any successful mint invalidates its chain", async () => {
    const w = await world();
    const targets = await prime(w, "cdbentley");
    await w.broker.handle(purpose(w), quarantine("q", "cdbentley", "q"));
    await w.broker.reconcileShard("q");
    const id = await openRound(w, "cdbentley", "REVOCATION", "q");
    const target = targets[0]!;
    w.probe.outcomes.set(target.uniqueId, "ALLOWED");
    await deliverAll(w, "cdbentley");
    expect(roundComplete(await manifest(w, id))).toBe(false);
    expect(await status(w, id)).toMatchObject({ complete: false, phaseReady: false });
    expect((await w.ledger.readShard("q"))!.targets[target.account]!.chain.members[target.members[0]!]!.revocation).toBeNull();
    w.probe.outcomes.delete(target.uniqueId);
    w.clock.advance(1);
    await deliverAll(w, "cdbentley");
    expect(await status(w, id)).toMatchObject({ complete: true });
    w.clock.advance(1);
    w.probe.outcomes.set(target.uniqueId, "ALLOWED");
    await deliver(w, "cdbentley", target.members[0]!, "9999");
    expect(await status(w, id)).toMatchObject({ complete: false, phaseReady: false });
  }, 180_000);

  test("receipt persistence cannot complete a phase if probe commit or current binding verification fails", async () => {
    const w = await world();
    const targets = await prime(w, "cdbentley");
    await w.broker.handle(purpose(w), quarantine("q", "cdbentley", "q"));
    await w.broker.reconcileShard("q");
    const id = await openRound(w, "cdbentley", "REVOCATION", "q");
    const original = w.ledger.recordProbe.bind(w.ledger);
    w.ledger.recordProbe = async () => ({ kind: "refused", reason: "local test dependency unavailable" });
    await deliverAll(w, "cdbentley");
    expect(roundComplete(await manifest(w, id))).toBe(true);
    expect((await manifest(w, id)).completedAt).toBeNull();
    expect(await status(w, id)).toMatchObject({ complete: false, phaseReady: false });
    w.ledger.recordProbe = original;
    w.clock.advance(1);
    w.inventory.change(targets[0]!.uniqueId);
    expect(await status(w, id)).toMatchObject({ complete: false, phaseReady: false });
    expect((await manifest(w, id)).completedAt).toBeNull();
  }, 180_000);

  test("phase proof commits remain available after the shard journal reaches capacity", async () => {
    const w = await world();
    const targets = await prime(w, "cdbentley");
    await w.broker.handle(purpose(w), quarantine("q", "cdbentley", "q"));
    await w.broker.reconcileShard("q");
    const target = targets[0]!;
    while ((await w.ledger.readShard("q"))!.nextSequence <= maxEntriesPerShard) {
      await w.ledger.recordProbe("q", { account: target.account, email: target.email, member: target.members[0]!, observedAt: w.clock.now.toISOString(), outcome: "ALLOWED", permission: probePermission, phase: "REVOCATION", principal: "local-test-source", uniqueId: target.uniqueId });
    }
    w.clock.advance(1);
    const revocation = await openRound(w, "cdbentley", "REVOCATION", "q");
    await deliverAll(w, "cdbentley");
    expect(await status(w, revocation)).toMatchObject({ complete: true, phaseReady: true });
    expect(Object.keys((await manifest(w, revocation)).committed)).toHaveLength(14);
    expect((await w.ledger.readShard("q"))!.nextSequence).toBe(maxEntriesPerShard + 1);
    w.clock.advance(3600);
    const horizon = await openRound(w, "cdbentley", "HORIZON", "q");
    await deliverAll(w, "cdbentley");
    expect(await status(w, horizon)).toMatchObject({ complete: true, phaseReady: true });
    expect(scanReadiness((await w.ledger.readShard("q"))!, w.clock.now).ready).toBe(true);
  }, 180_000);

  test("PREPARED resume keeps its recorded CONTROL round and read-only classification settles a landed write after expiry", async () => {
    const w = await world();
    const targets = await prime(w, "cdbentley");
    await w.broker.handle(purpose(w), quarantine("q", "cdbentley", "q"));
    const admitting = (await w.ledger.readShard("q"))!.controlRound;
    w.iam.beforeWrite = async () => { throw new Error("paused before CAS"); };
    await expect(driveEffect(w.ledger, w.iam, "q", (await w.ledger.readEntry("q", 1))!, targets[0]!)).rejects.toThrow("paused");
    // A complete newer CONTROL cannot replace the admitting round of q.
    await controlRound(w, "cdbentley");
    expect((await w.ledger.readRoundPointer("cdbentley")).control).not.toBe(admitting);
    expect((await w.ledger.readShard("q"))!.controlRound).toBe(admitting);
    const ack = w.ledger.acknowledgeEffect.bind(w.ledger);
    w.ledger.acknowledgeEffect = async () => { throw new Error("lost ACK"); };
    await expect(driveEffect(w.ledger, w.iam, "q", (await w.ledger.readEntry("q", 1))!, targets[0]!)).rejects.toThrow("lost ACK");
    w.ledger.acknowledgeEffect = ack;
    const writes = w.iam.writes.length;
    w.clock.advance(24 * 3600 + 1);
    await w.broker.reconcileShard("q");
    expect((await w.ledger.readEntry("q", 1))!.progress?.state).toBe("ACKED");
    expect(w.iam.writes).toHaveLength(writes);
    expect((await w.ledger.readEntry("q", 2))!.progress?.state).toBe("RECORDED");
  }, 180_000);
});
