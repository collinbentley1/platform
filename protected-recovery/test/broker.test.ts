import { describe, expect, test } from "bun:test";
import { ExternalUnavailable, cachedJwks, driveEffect } from "../src/effects";
import { Broker, boundedFetch, handleRequest, metadataToken } from "../src/http";
import { type CredentialInventory, GoogleCredentialInventory } from "../src/inventory";
import { maintenanceTicketSeconds, purposeForIdentity, targetsFor } from "../src/model";
import { Clock, FakeVerifier, beginClose, consumerOf, deliver, emulatorHost, freshOf, invokerEmail, makeReady, memberClaims, memberEmail, prime, quarantine, reconcilerEmail, restore, world } from "./support";

// The broker's boundaries beyond one shard's effects: the maintenance ticket
// that keeps infrastructure work and quarantines apart, the Deny fence on the
// restore direction, and the normalization of every bounded external
// dependency failure -- GitHub's JWKS, the metadata server -- into a refused
// request or a passed shard rather than an escaped error that starves the
// fleet.

const failing = (status: number): typeof fetch => Object.assign(async () => new Response(JSON.stringify({ error: "unavailable" }), { headers: { "content-type": "application/json" }, status }), { preconnect: fetch.preconnect });

describe.skipIf(!emulatorHost)("maintenance, the restore fence, and external dependency failures (Firestore emulator)", () => {
  test("a maintenance ticket cannot open while any QUARANTINE shard is not CLOSED, no QUARANTINE is accepted while one is open, the same key replays, and an expired ticket holds nothing", async () => {
    const w = await world();
    const { broker, clock, ledger } = w;
    const targets = await prime(w, "cdbentley");
    const isolate = purposeForIdentity(w.authority, invokerEmail("cdbentley"))!;
    const restorer = purposeForIdentity(w.authority, invokerEmail("cdbentley", "RESTORE"))!;
    const runsettaRestorer = purposeForIdentity(w.authority, invokerEmail("runsetta", "RESTORE"))!;
    // Open, replay, refuse a second key, refuse a quarantine, close.
    const opened = await broker.handle(restorer, { kind: "maintenance", action: "open", bodyHash: "h", key: "m1" });
    expect(opened).toMatchObject({ status: 200, body: { action: "open", ticket: { expiresAt: new Date(clock.now.getTime() + maintenanceTicketSeconds * 1000).toISOString(), key: "m1", openedAt: clock.now.toISOString(), openedBy: "gha-restore-cdbentley" } } });
    expect(await broker.handle(restorer, { kind: "maintenance", action: "open", bodyHash: "h", key: "m1" })).toEqual(opened);
    expect(await broker.handle(runsettaRestorer, { kind: "maintenance", action: "open", bodyHash: "h", key: "m2" })).toMatchObject({ status: 409, body: { error: "MAINTENANCE_OPEN" } });
    expect(await broker.handle(isolate, quarantine("q", "cdbentley", "k1"))).toMatchObject({ status: 409, body: { detail: expect.stringContaining("maintenance ticket opened at"), error: "MAINTENANCE_OPEN" } });
    expect(await ledger.readShard("q")).toBeUndefined();
    // The ledger itself refuses the quarantine inside its transaction, whatever route journals it.
    expect(await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).toMatchObject({ kind: "rejected", rejection: { reason: "MAINTENANCE_OPEN" } });
    expect(await broker.handle(restorer, { kind: "maintenance", action: "close", bodyHash: "h", key: "other" })).toMatchObject({ status: 409, body: { error: "MAINTENANCE_OPEN" } });
    expect(await broker.handle(runsettaRestorer, { kind: "maintenance", action: "close", bodyHash: "h", key: "m1" })).toMatchObject({ status: 200, body: { action: "close", ticket: { key: "m1" } } });
    expect(await broker.handle(restorer, { kind: "maintenance", action: "close", bodyHash: "h", key: "m1" })).toEqual({ status: 200, body: { action: "close", ticket: null } });
    expect(await ledger.readMaintenance()).toBeNull();
    // With a quarantine OPEN no ticket opens; once it is CLOSED one does; and an expired ticket blocks nothing.
    expect((await broker.handle(isolate, quarantine("q", "cdbentley", "k1"))).status).toBe(201);
    expect(await broker.handle(restorer, { kind: "maintenance", action: "open", bodyHash: "h", key: "m3" })).toEqual({ status: 409, body: { detail: "QUARANTINE shards not CLOSED: q", error: "QUARANTINE_ACTIVE" } });
    await makeReady(w, "q");
    expect((await beginClose(w, "q", "c")).kind).toBe("closing");
    expect(await broker.handle(restorer, { kind: "maintenance", action: "open", bodyHash: "h", key: "m3" })).toMatchObject({ status: 409, body: { error: "QUARANTINE_ACTIVE" } });
    await broker.reconcileShard("q");
    expect((await ledger.readShard("q"))!.phase).toBe("CLOSED");
    expect((await broker.handle(restorer, { kind: "maintenance", action: "open", bodyHash: "h", key: "m3" })).status).toBe(200);
    clock.advance(maintenanceTicketSeconds + 1);
    expect(await ledger.readMaintenance()).toBeNull();
    // The bindings are back and a fresh delivery round records ALLOWED controls: a second quarantine is admitted.
    await prime(w, "cdbentley");
    expect((await broker.handle(isolate, quarantine("q2", "cdbentley", "k2"))).status).toBe(201);
  }, 180_000);

  test("a RESTORE effect is prepared and written only under the steady Deny form, and a PREPARED one is re-admitted before it resumes", async () => {
    const w = await world();
    const { broker, iam, inventory, ledger } = w;
    const targets = await prime(w, "cdbentley");
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    await makeReady(w, "q");
    expect((await beginClose(w, "q", "c")).kind).toBe("closing");
    await broker.reconcileShard("q");
    expect((await ledger.append(restore("r", "cdbentley", "k2", "q"), targets, await freshOf(w, "q"))).kind).toBe("accepted");
    const writes = iam.writes.length;
    // The Deny state is not steady: nothing is prepared or written in the restore direction either.
    inventory.setDenyForm("cdbentley", "maintenance");
    expect(((await broker.reconcileShard("r")) as { notes: string[] }).notes).toEqual(targets.map((_, index) => `${index + 1}: pending; not prepared because DENY_STATE_NOT_STEADY; maintenance`));
    expect(iam.writes).toHaveLength(writes);
    inventory.unavailable = 1;
    expect(((await broker.reconcileShard("r")) as { notes: string[] }).notes[0]).toBe("1: pending; not prepared because DENY_STATE_UNAVAILABLE; the inventory source is unreachable");
    expect(iam.writes).toHaveLength(writes);
    // Steady: the first effect is prepared, then its worker dies; drift; the resume is refused; steady; resumed.
    inventory.setDenyForm("cdbentley", "steady");
    iam.beforeWrite = async () => {
      throw new Error("the worker died before the write");
    };
    await expect(driveEffect(ledger, iam, "r", (await ledger.readEntry("r", 1))!, targets[0]!)).rejects.toThrow("died before the write");
    expect((await ledger.readEntry("r", 1))!.progress).toMatchObject({ state: "PREPARED" });
    inventory.setDenyForm("cdbentley", "deployment");
    expect(((await broker.reconcileShard("r")) as { notes: string[] }).notes[0]).toBe("1: pending; not resumed because DENY_STATE_NOT_STEADY; deployment");
    expect(iam.writes).toHaveLength(writes);
    inventory.setDenyForm("cdbentley", "steady");
    await broker.reconcileShard("r");
    expect(iam.writes).toHaveLength(writes + targets.length);
    expect((await ledger.readEntry("r", 1))!.progress).toMatchObject({ state: "ACKED" });
  }, 180_000);

  test("a GitHub JWKS or metadata-server failure is a refused request or a passed shard, never an escaped error: two sweeps visit both shards and persist the cursor with a real cachedJwks 503 and a real metadataToken 503", async () => {
    const clock = new Clock();
    const authority = (await world()).authority;
    // The real inventory adapter over the real metadata token source, whose server answers 503; the real JWKS cache
    // over a server that answers 503.
    const inventory: CredentialInventory = new GoogleCredentialInventory({ authority, fetch: boundedFetch(failing(503)), now: clock.read, token: metadataToken(failing(503), clock.read) });
    const jwks = cachedJwks("https://token.actions.githubusercontent.com/.well-known/jwks", boundedFetch(failing(503)), clock.read);
    const base = await world(clock);
    const broker = new Broker({ authority, evidence: base.evidence, iam: base.iam, inventory, jwks, ledger: base.ledger, now: clock.read, probe: base.probe });
    for (const [shard, repository] of [["a-quarantine", "cdbentley"], ["b-restore", "runsetta"]] as const) {
      const targets = await prime(base, repository);
      expect((await base.ledger.append(quarantine(shard, repository, `k-${shard}`), targets)).kind).toBe("accepted");
    }
    const cursorWrites: Array<string | null> = [];
    const write = base.ledger.writeReconcileCursor.bind(base.ledger);
    base.ledger.writeReconcileCursor = async (after) => {
      cursorWrites.push(after);
      await write(after);
    };
    // The exact reproduction: two consecutive sweeps. Each shard's admission read reaches the metadata server,
    // whose failure is classified inside the shard boundary; the later shard is visited each time and the cursor
    // persisted after every shard.
    const sweeps = [await broker.reconcileFleet(), await broker.reconcileFleet()];
    for (const sweep of sweeps) {
      const views = sweep.shards as Array<{ deadline?: boolean; notes: string[]; shard: string }>;
      expect(views.map((view) => view.shard)).toEqual(["a-quarantine", "b-restore"]);
      for (const view of views) {
        expect(view.deadline).toBe(false);
        expect(view.notes).toEqual([expect.stringMatching(/^passed; the metadata server answered HTTP 503$/)]);
      }
      expect(sweep.next).toBeNull();
    }
    expect(cursorWrites).toEqual(["a-quarantine", "b-restore", null, "a-quarantine", "b-restore", null]);
    expect(base.iam.writes).toHaveLength(0);
    // The same failure at the request boundary is a 503, for the identity verifier's JWKS and for a delivery's.
    const deps = { authority, broker, verifier: new FakeVerifier() };
    const consumer = consumerOf(base, "cdbentley");
    const token = await base.signer.sign(memberClaims(authority, consumer, targetsFor(authority, consumer)![0]!.members[0]!, Math.floor(clock.now.getTime() / 1000)));
    const delivery = await handleRequest(deps, new Request("http://broker/v1/members", { body: JSON.stringify({ token }), headers: { authorization: `Bearer ${memberEmail("cdbentley")}` }, method: "POST" }));
    expect(delivery.status).toBe(503);
    expect(await delivery.json()).toEqual({ detail: "JWKS https://token.actions.githubusercontent.com/.well-known/jwks answered HTTP 503", error: "DEPENDENCY_UNAVAILABLE" });
    const unverifiable = { authority, broker, verifier: { verify: async () => { throw new ExternalUnavailable("JWKS https://www.googleapis.com/oauth2/v3/certs answered HTTP 503"); } } };
    const refused = await handleRequest(unverifiable, new Request("http://broker/v1/reconcile", { body: "{}", headers: { authorization: `Bearer ${reconcilerEmail}` }, method: "POST" }));
    expect(refused.status).toBe(503);
    expect(await refused.json()).toEqual({ detail: "JWKS https://www.googleapis.com/oauth2/v3/certs answered HTTP 503", error: "DEPENDENCY_UNAVAILABLE" });
    // Once the JWKS answers, the same delivery verifies and is exercised.
    const healthy = new Broker({ authority, evidence: base.evidence, iam: base.iam, inventory: base.inventory, jwks: async () => base.signer.jwks, ledger: base.ledger, now: clock.read, probe: base.probe });
    expect((await deliver({ ...base, broker: healthy }, "cdbentley", targetsFor(authority, consumer)![0]!.members[0]!)).status).toBe(200);
  }, 180_000);
});
