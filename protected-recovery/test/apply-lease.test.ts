import { describe, expect, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { handleRequest } from "../src/http";
import { parseProtectedApplyBody, purposeForIdentity, targetsFor } from "../src/model";
import { Clock, FakeVerifier, beginClose, consumerOf, emulatorHost, freshOf, invokerEmail, makeReady, prime, quarantine, restore, world } from "./support";

const key = () => `apply-${randomUUID()}`;
const digest = "a".repeat(64);
const owner = invokerEmail("cdbentley", "RESTORE");

describe("protected apply grammar", () => {
  test("requires an exact unique key and saved plan digest", () => {
    const body = { action: "acquire", key: key(), planSha256: digest };
    expect(parseProtectedApplyBody(body)).toMatchObject({ kind: "protected-apply", ...body });
    for (const change of [{ action: "renew" }, { key: "same" }, { planSha256: "short" }, { expiresAt: "tomorrow" }]) expect(() => parseProtectedApplyBody({ ...body, ...change })).toThrow();
  });
});

describe.skipIf(!emulatorHost)("exclusive protected apply (Firestore emulator)", () => {
  test("one acquisition wins across service instances; clock advance and repeated acquisition cannot take ownership", async () => {
    const w = await world();
    const other = w.anotherInstance().ledger;
    const candidates = [key(), key()];
    const results = await Promise.all(candidates.map((candidate, index) => (index === 0 ? w.ledger : other).acquireProtectedApply(candidate, digest, owner)));
    expect(results.filter((result) => result.kind === "acquired")).toHaveLength(1);
    const held = await w.ledger.readProtectedApply();
    expect(held).not.toBeNull();
    if (!held) throw new Error("missing lease");
    w.clock.advance(365 * 24 * 3600);
    expect(await other.acquireProtectedApply(held.key, digest, owner)).toEqual({ kind: "refused", reason: "PROTECTED_APPLY_ACTIVE" });
    expect(await other.readProtectedApply()).toEqual(held);
    for (const [wrongKey, wrongDigest, wrongOwner] of [[key(), digest, owner], [held.key, "b".repeat(64), owner], [held.key, digest, invokerEmail("runsetta", "RESTORE")]]) {
      expect(await other.releaseProtectedApply(wrongKey!, wrongDigest!, wrongOwner!)).toEqual({ kind: "refused", reason: "PROTECTED_APPLY_MISMATCH" });
    }
    expect(await other.releaseProtectedApply(held.key, digest, owner)).toEqual({ kind: "released", lease: null });
    expect(await other.acquireProtectedApply(held.key, digest, owner)).toEqual({ kind: "refused", reason: "PROTECTED_APPLY_KEY_USED" });
    expect((await other.acquireProtectedApply(key(), digest, owner)).kind).toBe("acquired");
  }, 120_000);

  test("apply acquisition and recovery append or maintenance open are transactionally exclusive", async () => {
    for (const rival of ["append", "maintenance"] as const) {
      const w = await world();
      const other = w.anotherInstance().ledger;
      const targets = targetsFor(w.authority, consumerOf(w, "cdbentley"))!;
      const [lease, work] = await Promise.all([
        w.ledger.acquireProtectedApply(key(), digest, owner),
        rival === "append" ? other.append(quarantine("q", "cdbentley", "q"), targets) : other.openMaintenance("m", owner),
      ]);
      expect([lease.kind === "acquired", work.kind === "accepted" || work.kind === "opened"].filter(Boolean)).toHaveLength(1);
      if (lease.kind === "acquired") {
        expect(await other.openMaintenance("blocked", owner)).toMatchObject({ kind: "refused", reason: "PROTECTED_APPLY_ACTIVE" });
        expect(await other.append(quarantine("blocked", "cdbentley", "b"), targets)).toMatchObject({ kind: "rejected", rejection: { reason: "PROTECTED_APPLY_ACTIVE" } });
      } else expect(lease).toMatchObject({ kind: "refused", reason: rival === "append" ? "RECOVERY_ACTIVE" : "MAINTENANCE_OPEN" });
    }
  }, 120_000);

  test("unclosed restoration also prevents protected apply until its terminal receipt is projected", async () => {
    const w = await world(new Clock());
    const targets = await prime(w, "cdbentley");
    expect((await w.ledger.append(quarantine("q", "cdbentley", "q"), targets)).kind).toBe("accepted");
    await makeReady(w, "q");
    expect((await beginClose(w, "q", "close-q")).kind).toBe("closing");
    await w.broker.reconcileShard("q");
    expect((await w.ledger.append(restore("r", "cdbentley", "r", "q"), targets, await freshOf(w, "q"))).kind).toBe("accepted");
    expect((await w.ledger.readCoordination()).active).toEqual(["r"]);
    expect(await w.ledger.acquireProtectedApply(key(), digest, owner)).toEqual({ kind: "refused", reason: "RECOVERY_ACTIVE" });
    await w.broker.reconcileShard("r");
    expect((await beginClose(w, "r", "close-r", "cdbentley", "RESTORE")).kind).toBe("closing");
    expect(await w.ledger.acquireProtectedApply(key(), digest, owner)).toEqual({ kind: "refused", reason: "RECOVERY_ACTIVE" });
    await w.broker.reconcileShard("r");
    expect((await w.ledger.readCoordination()).active).toEqual([]);
    expect((await w.ledger.acquireProtectedApply(key(), digest, owner)).kind).toBe("acquired");
  }, 180_000);

  test("RESTORE admission and maintenance opening cannot both succeed across instances", async () => {
    const w = await world();
    const targets = await prime(w, "cdbentley");
    expect((await w.ledger.append(quarantine("q", "cdbentley", "q"), targets)).kind).toBe("accepted");
    await makeReady(w, "q");
    expect((await beginClose(w, "q", "close")).kind).toBe("closing");
    await w.broker.reconcileShard("q");
    const fresh = await freshOf(w, "q");
    const [appended, maintenance] = await Promise.all([
      w.ledger.append(restore("r", "cdbentley", "r", "q"), targets, fresh),
      w.anotherInstance().ledger.openMaintenance("maintenance", owner),
    ]);
    expect([appended.kind === "accepted", maintenance.kind === "opened"].filter(Boolean)).toHaveLength(1);
    if (maintenance.kind === "opened") expect(appended).toMatchObject({ kind: "rejected", rejection: { reason: "MAINTENANCE_OPEN" } });
    else expect(maintenance).toMatchObject({ kind: "refused", reason: "QUARANTINE_ACTIVE" });
  }, 180_000);

  test("HTTP derives full owner identity and permits reads/releases only to that RESTORE invoker", async () => {
    const w = await world();
    const restorer = purposeForIdentity(w.authority, owner)!;
    const body = { action: "acquire", key: key(), planSha256: digest };
    const verifier = new FakeVerifier();
    const service = { authority: w.authority, broker: w.broker, verifier };
    const opened = await handleRequest(service, new Request("https://broker.test/v1/protected-apply", { method: "POST", headers: { authorization: `Bearer ${owner}` }, body: JSON.stringify(body) }));
    expect(opened.status).toBe(201);
    expect(await opened.json()).toMatchObject({ lease: { openedBy: owner, key: body.key, planSha256: digest } });
    expect((await w.broker.handle(restorer, { kind: "protected-apply-read" })).status).toBe(200);
    for (const email of [invokerEmail("cdbentley"), invokerEmail("runsetta", "RESTORE")]) {
      expect((await handleRequest(service, new Request("https://broker.test/v1/protected-apply", { headers: { authorization: `Bearer ${email}` } }))).status).toBe(403);
      expect((await handleRequest(service, new Request("https://broker.test/v1/protected-apply", { method: "POST", headers: { authorization: `Bearer ${email}` }, body: JSON.stringify({ ...body, action: "release" }) }))).status).toBe(email === invokerEmail("cdbentley") ? 403 : 409);
    }
    expect((await handleRequest(service, new Request("https://broker.test/v1/protected-apply", { method: "POST", headers: { authorization: `Bearer ${owner}` }, body: JSON.stringify({ ...body, action: "release" }) }))).status).toBe(200);
  }, 120_000);
});
