import { describe, expect, test } from "bun:test";
import { entryEvidence, project } from "../src/outbox";
import { FakeEvidence } from "./support";

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
    const effect = { kind: "effect" as const, account: "gha-terraform", intent: "QUARANTINE" as const, members: ["principalSet://x"], resource: "projects/p/serviceAccounts/e" };
    expect(() => entryEvidence("s", { ...base, body: effect, progress: { state: "RECORDED" } })).toThrow("not acknowledged");
    const canary = { kind: "canary" as const, account: "gha-terraform", checks: { attachmentsAbsent: true, impersonationDenied: true, keysAbsent: true, lifetimeExtensionAbsent: true, tokenCreatorsAbsent: true, wifDataPlaneAbsent: true }, member: "principalSet://x", observedAt: "2026-09-04T12:00:00.000Z" };
    const text = new TextDecoder().decode(entryEvidence("s", { ...base, body: canary, progress: null }));
    expect(text.endsWith("\n")).toBe(true);
    expect(JSON.parse(text)).toMatchObject({ body: canary, progress: null, sequence: 1, shard: "s" });
  });
});
