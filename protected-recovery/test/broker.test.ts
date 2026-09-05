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

  test("quarantine acceptance and maintenance opening are ordered by one coordination document -- written by the transactions that accept a quarantine and close it, read by the one that opens a ticket -- so concurrent attempts across two instances never both succeed and the document is exactly the set of quarantines not CLOSED", async () => {
    // Every Firestore read made inside a transaction, and every commit, observed.
    const reads: Array<{ readonly documents: readonly string[]; readonly transaction: string | undefined }> = [];
    const commits: Array<readonly string[]> = [];
    const observing: typeof fetch = Object.assign(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      const body = typeof init?.body === "string" ? (JSON.parse(init.body) as { documents?: string[]; transaction?: string; writes?: Array<{ update?: { name: string } }> }) : {};
      if (url.endsWith(":batchGet")) reads.push({ documents: body.documents ?? [], transaction: body.transaction });
      if (url.endsWith(":commit")) commits.push((body.writes ?? []).flatMap((write) => (write.update ? [write.update.name] : [])));
      return await fetch(input, init);
    }, { preconnect: fetch.preconnect });
    const w = await world(new Clock(), observing);
    const { broker, ledger } = w;
    const other = w.anotherInstance().ledger;
    const targets = await prime(w, "cdbentley");
    const coordination = (name: string) => name.endsWith("/coordination/quarantines");
    expect(await ledger.readCoordination()).toEqual({ active: [], version: 0 });
    // From a clean state -- no ticket, no quarantine -- acceptance and opening race on two instances. Exactly one
    // wins each time, and after every race the committed state satisfies the invariant: an open ticket never
    // stands beside a quarantine that is not CLOSED, and the coordination document names exactly those quarantines.
    let accepted = 0;
    let opened = 0;
    for (let race = 0; race < 4; race += 1) {
      const shard = `q-${race}`;
      const before = reads.length;
      const [appended, ticket] = await Promise.all([ledger.append(quarantine(shard, "cdbentley", `k-${race}`), targets), other.openMaintenance(`m-${race}`, "gha-restore-cdbentley")]);
      const won = [appended.kind === "accepted", ticket.kind === "opened"];
      expect(won.filter(Boolean)).toHaveLength(1);
      // Both transactions read the coordination document inside their own transaction.
      const transactional = reads.slice(before).filter((read) => read.transaction !== undefined && read.documents.some(coordination));
      expect(transactional.length).toBeGreaterThanOrEqual(2);
      const state = await ledger.readCoordination();
      const maintenance = await ledger.readMaintenance();
      if (ticket.kind === "opened") {
        opened += 1;
        expect(appended).toMatchObject({ kind: "rejected", rejection: { reason: "MAINTENANCE_OPEN" } });
        expect(await ledger.readShard(shard)).toBeUndefined();
        expect(state.active).toEqual([]);
        expect(maintenance).toMatchObject({ key: `m-${race}` });
        expect((await other.closeMaintenance(`m-${race}`)).kind).toBe("closed");
      } else {
        accepted += 1;
        expect(ticket).toEqual({ kind: "refused", reason: "QUARANTINE_ACTIVE", detail: `QUARANTINE shards not CLOSED: ${shard}` });
        expect(maintenance).toBeNull();
        expect(state.active).toEqual([shard]);
        // The acceptance commit wrote the shard into the coordination document in the same commit as the shard.
        expect(commits.some((names) => names.some(coordination) && names.some((name) => name.endsWith(`/shards/${shard}`)))).toBe(true);
        // Opening stays refused through CLOSING and FINALIZING, and the terminal close writes the shard out.
        await makeReady(w, shard);
        expect((await beginClose(w, shard, `c-${race}`)).kind).toBe("closing");
        expect(await other.openMaintenance(`m-${race}-closing`, "gha-restore-cdbentley")).toMatchObject({ kind: "refused", reason: "QUARANTINE_ACTIVE" });
        expect((await broker.reconcileShard(shard) as { phase: string }).phase).toBe("CLOSED");
        expect((await ledger.readCoordination()).active).toEqual([]);
        // The quarantine removed the managed bindings: they are put back and a fresh delivery round records the
        // ALLOWED controls the next race's quarantine needs.
        await prime(w, "cdbentley");
      }
      // Every transition advanced the version.
      expect((await ledger.readCoordination()).version).toBeGreaterThan(state.version - 1);
    }
    expect(accepted + opened).toBe(4);
    // Two quarantines of two consumers are both named until each is CLOSED, in sorted order.
    const runsettaTargets = await prime(w, "runsetta");
    expect((await ledger.append(quarantine("zz", "runsetta", "k-zz"), runsettaTargets)).kind).toBe("accepted");
    expect((await other.append(quarantine("aa", "cdbentley", "k-aa"), targets)).kind).toBe("accepted");
    expect((await ledger.readCoordination()).active).toEqual(["aa", "zz"]);
    // Twenty concurrent openings across both instances while quarantines stand: every one refused, none opened.
    const attempts = await Promise.all(Array.from({ length: 20 }, (_, index) => (index % 2 === 0 ? ledger : other).openMaintenance(`burst-${index}`, "gha-restore-cdbentley")));
    expect(attempts.every((attempt) => attempt.kind === "refused" && attempt.reason === "QUARANTINE_ACTIVE")).toBe(true);
    expect(await ledger.readMaintenance()).toBeNull();
    // A RESTORE shard is not a quarantine and never enters the document.
    await makeReady(w, "aa");
    expect((await beginClose(w, "aa", "c-aa")).kind).toBe("closing");
    expect((await broker.reconcileShard("aa") as { phase: string }).phase).toBe("CLOSED");
    expect((await ledger.readCoordination()).active).toEqual(["zz"]);
    expect((await ledger.append(restore("ra", "cdbentley", "k-ra", "aa"), targets, await freshOf(w, "aa"))).kind).toBe("accepted");
    expect((await ledger.readCoordination()).active).toEqual(["zz"]);
  }, 300_000);

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
