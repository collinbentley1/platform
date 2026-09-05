import { describe, expect, test } from "bun:test";
import { boundedFetch } from "../src/http";
import { type EntryBody, probePermission, targetsFor } from "../src/model";
import { GoogleEvidenceStore, entryEvidence, project } from "../src/outbox";
import { Clock, FakeEvidence, emulatorHost, quarantine, seedTargets, world } from "./support";

describe("outbox projection", () => {
  const bytes = new TextEncoder().encode('{"a":1}\n');

  test("creates the deterministic object once and accepts only exact bytes afterwards", async () => {
    const store = new FakeEvidence();
    expect(await project(store, "shards/s/close.json", bytes)).toEqual({ kind: "projected", generation: "1", sha256: expect.any(String) });
    expect(await project(store, "shards/s/close.json", bytes)).toEqual({ kind: "projected", generation: "1", sha256: expect.any(String) });
    expect(await project(store, "shards/s/close.json", new TextEncoder().encode('{"a":2}\n'))).toEqual({ kind: "diverged", reason: "shards/s/close.json exists with different bytes" });
    expect(store.objects.size).toBe(1);
  });

  test("a lost upload response is settled by the object itself", async () => {
    const store = new FakeEvidence();
    store.dropResponses = 1;
    expect(await project(store, "o", bytes)).toEqual({ kind: "projected", generation: "1", sha256: expect.any(String) });
    store.unavailableReads = 1;
    store.dropResponses = 1;
    expect(await project(store, "p", bytes)).toMatchObject({ kind: "pending" });
    expect(await project(store, "p", bytes)).toEqual({ kind: "projected", generation: "2", sha256: expect.any(String) });
  });

  test("entry evidence is the committed body and outcome, never a pending effect", () => {
    const base = { acceptedAt: "2026-09-04T12:00:00.000Z", bodyHash: "h", key: "k", objectName: "shards/s/entries/000001.json", outbox: { state: "PENDING" as const }, sequence: 1 };
    const effect = { kind: "effect" as const, account: "gha-terraform", email: "gha-terraform@p.iam.gserviceaccount.com", intent: "QUARANTINE" as const, members: ["principalSet://x"], resource: "projects/p/serviceAccounts/101080000000000000000", uniqueId: "101080000000000000000" };
    expect(() => entryEvidence("s", { ...base, body: effect, progress: { state: "RECORDED" } })).toThrow("not acknowledged");
    const probe: EntryBody = { kind: "probe", account: "gha-terraform", email: effect.email, member: "principalSet://x", observedAt: "2026-09-04T12:00:00.000Z", outcome: "DENIED", permission: probePermission, phase: "REVOCATION", principal: "prober@p.iam.gserviceaccount.com", uniqueId: effect.uniqueId };
    const text = new TextDecoder().decode(entryEvidence("s", { ...base, body: probe, progress: null }));
    expect(text.endsWith("\n")).toBe(true);
    expect(JSON.parse(text)).toMatchObject({ body: probe, progress: null, sequence: 1, shard: "s" });
  });
});

// A GCS JSON API stand-in over fetch with the exact ifGenerationMatch=0
// semantics: upload creates or answers 412, metadata answers the generation,
// media answers the bytes. While stalling is armed, every answer for an
// object under the stalled prefix carries 200 headers and a body that never
// ends until the request is aborted -- the upload's answer as well as the
// reads the store settles a lost answer with.
function gcs(stalledPrefix: string) {
  const objects = new Map<string, { readonly bytes: Uint8Array; readonly generation: string }>();
  let generations = 0;
  let stalled = 0;
  let stalling = true;
  const fetcher: typeof fetch = Object.assign(async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    const stall = (): Response => {
      stalled += 1;
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          init?.signal?.addEventListener("abort", () => controller.error(init.signal?.reason ?? new Error("aborted")), { once: true });
        },
      });
      return new Response(stream, { headers: { "content-type": "application/json" }, status: 200 });
    };
    if (url.pathname.startsWith("/upload/storage/v1/b/") && init?.method === "POST") {
      const name = url.searchParams.get("name")!;
      if (objects.has(name)) return new Response("{}", { status: 412 });
      generations += 1;
      const generation = String(generations);
      objects.set(name, { bytes: new Uint8Array(init.body as Uint8Array), generation });
      if (stalling && name.startsWith(stalledPrefix)) return stall();
      return Response.json({ generation, name });
    }
    const object = /^\/storage\/v1\/b\/[^/]+\/o\/(.+)$/.exec(url.pathname);
    if (object && (init?.method ?? "GET") === "GET") {
      const name = decodeURIComponent(object[1]!);
      const found = objects.get(name);
      if (!found) return new Response("{}", { status: 404 });
      if (stalling && name.startsWith(stalledPrefix)) return stall();
      if (url.searchParams.get("alt") === "media") return new Response(found.bytes, { status: 200 });
      return Response.json({ generation: found.generation, name });
    }
    return new Response("{}", { status: 404 });
  }, { preconnect: fetch.preconnect });
  return { fetcher, objects, settle: () => (stalling = false), stalled: () => stalled };
}

describe.skipIf(!emulatorHost)("stalled evidence bodies (Firestore emulator; GCS stand-in over the real store and bounded fetch)", () => {
  test("a GCS body that stalls after the headers is a lost answer of that shard's projection: the sweep visits the later shard and persists its cursor, on this and the next invocation", async () => {
    const bucket = gcs("shards/a-hung/");
    // The real store over the real bounded fetch, whose body timeout is short here; the ledger keeps its own fetch.
    // The shard deadline outlasts every stalled answer of the shard's fifty-odd projections, so what is proven is the
    // store's classification, not the deadline.
    const evidence = new GoogleEvidenceStore({ bucket: "evidence", fetch: boundedFetch(bucket.fetcher, 120), token: async () => "broker" });
    const clock = new Clock();
    const w = await world(clock, fetch, { requestMs: 120_000, shardMs: 80_000 }, { evidence, ledgerFetch: fetch });
    // Two consumers' quarantines: the hung shard's targets are quarantined for real, so the later shard must be another
    // consumer's for its own effects to have members to remove.
    for (const [shard, repository] of [["a-hung", "cdbentley"], ["b-ready", "runsetta"]] as const) {
      const consumer = w.authority.consumers.find((candidate) => candidate.repository === repository)!;
      const targets = targetsFor(w.authority, consumer)!;
      seedTargets(w.iam, targets);
      expect((await w.ledger.append(quarantine(shard, repository, `k-${shard}`), targets)).kind).toBe("accepted");
    }
    const cursorWrites: Array<string | null> = [];
    const write = w.ledger.writeReconcileCursor.bind(w.ledger);
    w.ledger.writeReconcileCursor = async (after) => {
      cursorWrites.push(after);
      await write(after);
    };
    // The exact reproduction: the hung shard's every evidence answer stalls; two consecutive sweeps.
    const sweeps = [await w.broker.reconcileFleet(), await w.broker.reconcileFleet()];
    expect(bucket.stalled()).toBeGreaterThan(0);
    for (const sweep of sweeps) {
      const views = sweep.shards as Array<{ deadline?: boolean; notes: string[]; pendingOutbox: number; shard: string }>;
      expect(views.map((view) => view.shard)).toEqual(["a-hung", "b-ready"]);
      // The hung shard's projections are pending lost answers, classified inside the store; nothing escaped the sweep
      // and nothing was passed at a deadline.
      expect(views[0]!.deadline).toBeUndefined();
      expect(views[0]!.notes.length).toBeGreaterThan(0);
      // A stalled upload answer is a lost put and a stalled read is a lost object body, each classified inside the
      // store as the bounded fetch's timeout, so the projection is pending rather than an escaped error.
      expect(views[0]!.notes.every((note) => /: outbox pending; (lost|exists); object body lost: .*TimeoutError/.test(note))).toBe(true);
      expect(views[0]!.pendingOutbox).toBeGreaterThan(0);
      expect(views[1]).toMatchObject({ notes: [], pendingEffects: 0, pendingOutbox: 0 });
      expect(sweep.next).toBeNull();
    }
    expect(cursorWrites).toEqual(["a-hung", "b-ready", null, "a-hung", "b-ready", null]);
    // Once the bucket answers, the objects the hung shard uploaded settle its projections from the object itself.
    bucket.settle();
    const third = await w.broker.reconcileFleet();
    expect((third.shards as Array<{ pendingOutbox: number; shard: string }>).find((view) => view.shard === "a-hung")).toMatchObject({ pendingOutbox: 0 });
  }, 300_000);
});
