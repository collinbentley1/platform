import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { manifestPath } from "../../tools/ci/workflow-authority";
import { GoogleIdentityVerifier, configurationFromEnvironment, handleRequest } from "../src/http";
import { loadRecoveryAuthority, parseAppendBody, purposeForIdentity, targetsFor, unrecordedIdentities } from "../src/model";
import { FakeVerifier, activeSha, emulatorHost, invokerEmail, reconcilerEmail, repoRoot, testAuthority, testUniqueId, transitionSha, world } from "./support";

const authorityText = () => readFile(join(repoRoot, "protected-recovery/authority.json"), "utf8");
const manifestText = () => readFile(join(repoRoot, manifestPath), "utf8");

describe("recovery authority", () => {
  test("the committed authority holds only coordinates: the broker project and every target identity are not yet assigned", async () => {
    const authority = loadRecoveryAuthority(await authorityText(), await manifestText());
    expect(authority.broker.projectId).toBeNull();
    expect(authority.broker.projectNumber).toBeNull();
    expect(authority.consumers.map((consumer) => consumer.repository)).toEqual(["cdbentley", "critical-history", "healthmcp", "runsetta"]);
    expect(authority.consumers.every((consumer) => consumer.activeWorkflowSha === null && consumer.transitionWorkflowSha === null)).toBe(true);
    expect(authority.targetAccounts).toEqual(["gha-deploy-parity", "gha-preview-commit", "gha-preview-deploy", "gha-preview-operator", "gha-preview-publish", "gha-prod-deploy", "gha-prod-publish", "gha-terraform", "gha-wif-canary"]);
    expect(authority.consumers.every((consumer) => Object.values(consumer.serviceAccountUniqueIds).every((uniqueId) => uniqueId === null))).toBe(true);
    expect(unrecordedIdentities(authority)).toHaveLength(36);
    expect(authority.entries.filter((entry) => entry.purpose === "recovery")).toHaveLength(8);
    expect(authority.entries.filter((entry) => entry.purpose === "deny-canary").map((entry) => `${entry.workflow}#${entry.job}`)).toEqual([".github/workflows/protected-recovery-deny-canary.yml#exercise"]);
    // No identity can hold a purpose until the broker project is recorded, and no target derives without its identity.
    expect(purposeForIdentity(authority, "gha-isolate-cdbentley@anything.iam.gserviceaccount.com")).toBeUndefined();
    expect(targetsFor(authority, { ...authority.consumers[0]!, activeWorkflowSha: activeSha })).toBeUndefined();
    expect(() => configurationFromEnvironment({}, authority)).toThrow("records no broker project");
    // With the broker recorded but any identity unrecorded, the service still refuses to start.
    const assigned = JSON.parse(await authorityText()) as Record<string, unknown>;
    (assigned.broker as Record<string, unknown>).projectId = "recovery-test";
    (assigned.broker as Record<string, unknown>).projectNumber = "123456789012";
    const assignedAuthority = loadRecoveryAuthority(JSON.stringify(assigned), await manifestText());
    expect(() => configurationFromEnvironment({}, assignedAuthority)).toThrow("records no unique ID for cdbentley/gha-deploy-parity, cdbentley/gha-preview-commit");
  });

  test("consumer coordinates agree with the production deploy registry", async () => {
    const authority = loadRecoveryAuthority(await authorityText(), await manifestText());
    const deployProd = await readFile(join(repoRoot, ".github/workflows/deploy-prod.yml"), "utf8");
    for (const consumer of authority.consumers) {
      expect(deployProd).toContain(`${consumer.repositoryId}) project_id="${consumer.projectId}"; project_number="${consumer.projectNumber}" ;;`);
    }
    const bootstrap = await readFile(join(repoRoot, "terraform/deployments/bootstrap/main.tf"), "utf8");
    for (const consumer of authority.consumers) {
      expect(bootstrap).toContain(`github_repo                 = "${consumer.repository}"\n      github_repository_id        = "${consumer.repositoryId}"`);
    }
  });

  test("the authority refuses coordinates that do not match the manifest or each other", async () => {
    const manifest = await manifestText();
    const base = JSON.parse(await authorityText()) as Record<string, unknown>;
    const consumers = (authority: Record<string, unknown>) => authority.consumers as Array<Record<string, unknown>>;
    const edit = (mutate: (authority: Record<string, unknown>) => void) => {
      const copy = structuredClone(base);
      mutate(copy);
      return () => loadRecoveryAuthority(JSON.stringify(copy), manifest);
    };
    expect(edit((authority) => consumers(authority).pop())).toThrow("recovery invoker for runsetta names no consumer");
    expect(edit((authority) => (consumers(authority)[0]!.repository = "cdbentley-two"))).toThrow("must have exactly one QUARANTINE invoker");
    expect(edit((authority) => (consumers(authority)[0]!.projectNumber = "422714632513"))).toThrow("already declared");
    expect(edit((authority) => (consumers(authority)[0]!.activeWorkflowSha = "abc"))).toThrow("one full lowercase commit SHA");
    expect(edit((authority) => (consumers(authority)[0]!.transitionWorkflowSha = activeSha))).toThrow("requires activeWorkflowSha");
    expect(edit((authority) => (authority.broker as Record<string, unknown>).projectId = "recovery-test")).toThrow("both be null or both be assigned");
    expect(edit((authority) => (authority.broker as Record<string, unknown>).reconcilerServiceAccount = "gha-isolate-cdbentley")).toThrow("cannot also be a recovery invoker");
    expect(edit((authority) => (authority.broker as Record<string, unknown>).reconcilerServiceAccount = "gha-deny-canary")).toThrow("cannot also be a recovery invoker");
    expect(edit((authority) => (authority.broker as Record<string, unknown>).evidenceBucket = "bucket")).toThrow("keys must be exactly");
    expect(edit((authority) => (authority.platformRepository = "evil/platform"))).toThrow("must be collinbentley1/platform");
    // Target identities: exactly the manifest's bound accounts, each null or one positive decimal ID, never shared.
    const ids = (authority: Record<string, unknown>, index: number) => consumers(authority)[index]!.serviceAccountUniqueIds as Record<string, unknown>;
    expect(edit((authority) => delete ids(authority, 0)["gha-terraform"])).toThrow("serviceAccountUniqueIds keys must be exactly");
    expect(edit((authority) => (ids(authority, 0)["gha-owner"] = null))).toThrow("serviceAccountUniqueIds keys must be exactly");
    expect(edit((authority) => (ids(authority, 0)["gha-terraform"] = "not-an-id"))).toThrow("must be null or one positive decimal unique ID");
    expect(edit((authority) => (ids(authority, 0)["gha-terraform"] = "0123"))).toThrow("must be null or one positive decimal unique ID");
    expect(edit((authority) => (ids(authority, 0)["gha-terraform"] = 123))).toThrow("must be null or one positive decimal unique ID");
    expect(edit((authority) => {
      ids(authority, 0)["gha-terraform"] = "101080000000000000000";
      ids(authority, 0)["gha-wif-canary"] = "101080000000000000000";
    })).toThrow("gha-wif-canary 101080000000000000000 is already declared");
    expect(edit((authority) => {
      ids(authority, 0)["gha-terraform"] = "101080000000000000000";
      ids(authority, 1)["gha-terraform"] = "101080000000000000000";
    })).toThrow("gha-terraform 101080000000000000000 is already declared");
    expect(edit((authority) => (ids(authority, 0)["gha-terraform"] = "101080000000000000000"))).not.toThrow();
    expect(() => loadRecoveryAuthority(JSON.stringify(base), "[]")).toThrow("must be a non-empty array");
    // A manifest that binds both directions to one credential, or only one direction, is refused.
    const entries = JSON.parse(manifest) as Array<Record<string, unknown>>;
    const withoutRestore = entries.filter((entry) => !(entry.trustDomain === "recovery" && entry.consumer === "cdbentley" && entry.intent === "RESTORE"));
    expect(() => loadRecoveryAuthority(JSON.stringify(base), JSON.stringify(withoutRestore))).toThrow("consumer cdbentley must have exactly one RESTORE invoker; found 0");
    // Exactly one Deny canary job, and no entry may bind a member-delivery identity: the module binds those alone.
    const withoutCanary = entries.filter((entry) => entry.purpose !== "deny-canary");
    expect(() => loadRecoveryAuthority(JSON.stringify(base), JSON.stringify(withoutCanary))).toThrow("exactly one Deny canary job must be declared");
    const bindingMember = entries.map((entry) => (entry.purpose === "deny-canary" ? { ...entry, serviceAccounts: ["gha-member-cdbentley"] } : entry));
    expect(() => loadRecoveryAuthority(JSON.stringify(base), JSON.stringify(bindingMember))).toThrow(/Deny canary identity|member-delivery identity/);
  });

  test("purpose is derived only from the invoker identity in the broker project, one consumer and one direction each", async () => {
    const authority = await testAuthority();
    const isolate = purposeForIdentity(authority, invokerEmail("cdbentley", "QUARANTINE"));
    expect(isolate?.kind).toBe("recovery");
    if (isolate?.kind !== "recovery") throw new Error("expected a recovery purpose");
    expect(isolate.consumer.repository).toBe("cdbentley");
    expect(isolate.intent).toBe("QUARANTINE");
    expect(isolate.serviceAccount).toBe("gha-isolate-cdbentley");
    const restorer = purposeForIdentity(authority, invokerEmail("cdbentley", "RESTORE"));
    expect(restorer).toMatchObject({ kind: "recovery", intent: "RESTORE", serviceAccount: "gha-restore-cdbentley" });
    expect(purposeForIdentity(authority, reconcilerEmail)).toEqual({ kind: "reconciler", serviceAccount: "recovery-reconciler" });
    for (const forged of [
      "gha-isolate-cdbentley@cdbentley.iam.gserviceaccount.com",
      "gha-recovery-cdbentley@recovery-test.iam.gserviceaccount.com",
      "gha-terraform@recovery-test.iam.gserviceaccount.com",
      "gha-isolate-other@recovery-test.iam.gserviceaccount.com",
      "gha-deny-canary@recovery-test.iam.gserviceaccount.com",
      "recovery-broker@recovery-test.iam.gserviceaccount.com",
      "collin@example.com",
    ]) {
      expect(purposeForIdentity(authority, forged), forged).toBeUndefined();
    }
  });

  test("targets and managed members derive exactly from the canonical inventory, addressed by permanent identity", async () => {
    const authority = await testAuthority();
    const cdbentley = authority.consumers.find((consumer) => consumer.repository === "cdbentley")!;
    const targets = targetsFor(authority, cdbentley)!;
    expect(targets.map((target) => target.account)).toEqual([
      "gha-deploy-parity",
      "gha-preview-commit",
      "gha-preview-deploy",
      "gha-preview-operator",
      "gha-preview-publish",
      "gha-prod-deploy",
      "gha-prod-publish",
      "gha-terraform",
      "gha-wif-canary",
    ]);
    const pool = "projects/882468538648/locations/global/workloadIdentityPools/github-actions";
    const terraform = targets.find((target) => target.account === "gha-terraform")!;
    expect(terraform.email).toBe("gha-terraform@cdbentley.iam.gserviceaccount.com");
    expect(terraform.uniqueId).toBe(testUniqueId(0, 7));
    expect(terraform.resource).toBe(`projects/cdbentley/serviceAccounts/${testUniqueId(0, 7)}`);
    expect(terraform.resource).not.toContain("@");
    expect(terraform.pool).toBe(pool);
    expect(terraform.members).toEqual([
      `principalSet://iam.googleapis.com/${pool}/attribute.authority/collinbentley1/cdbentley/.github/workflows/deploy-prod.yml@refs/heads/main:collinbentley1/platform/.github/workflows/infrastructure.yml@${activeSha}:${activeSha}:production:push`,
    ]);
    expect(new Set(targets.map((target) => target.uniqueId)).size).toBe(9);
    // Thirty-five active tuples in total, exactly the bootstrap module's matrix.
    expect(targets.reduce((count, target) => count + target.members.length, 0)).toBe(35);
    // The transition SHA extends only transition-eligible entries, and only for a consumer that records one.
    const runsetta = authority.consumers.find((consumer) => consumer.repository === "runsetta")!;
    const runsettaTargets = targetsFor(authority, runsetta)!;
    expect(runsettaTargets.reduce((count, target) => count + target.members.length, 0)).toBe(50);
    const operator = runsettaTargets.find((target) => target.account === "gha-preview-operator")!;
    expect(operator.members.filter((member) => member.includes(transitionSha))).toHaveLength(5);
    expect(runsettaTargets.find((target) => target.account === "gha-prod-deploy")!.members.some((member) => member.includes(transitionSha))).toBe(false);
    // Unpinned consumers and unrecorded identities derive nothing.
    expect(targetsFor(authority, { ...cdbentley, activeWorkflowSha: null })).toBeUndefined();
    expect(targetsFor(authority, { ...cdbentley, serviceAccountUniqueIds: { ...cdbentley.serviceAccountUniqueIds, "gha-terraform": null } })).toBeUndefined();
  });

  test("forged purpose, project, resource, role, member, policy, object-name, and evidence fields are refused", () => {
    const valid = { consumer: "cdbentley", intent: "QUARANTINE", key: "k" };
    expect(parseAppendBody("s", valid).body).toEqual({ kind: "quarantine" });
    const checks = { attachmentsAbsent: true, impersonationDenied: true, keysAbsent: true, lifetimeExtensionAbsent: true, tokenCreatorsAbsent: true, wifDataPlaneAbsent: true };
    for (const forged of [
      { ...valid, purpose: "reconciler" },
      { ...valid, project: "cdbentley" },
      { ...valid, resource: "projects/cdbentley/serviceAccounts/x" },
      { ...valid, role: "roles/owner" },
      { ...valid, members: ["user:evil@example.com"] },
      { ...valid, policy: { bindings: [] } },
      { ...valid, objectName: "shards/x/close.json" },
      { ...valid, intent: "DISABLE" },
      { ...valid, intent: "RESTORE" },
      { ...valid, uniqueId: "101080000000000000000" },
      { consumer: "cdbentley", intent: "RESTORE", key: "k", source: "../other" },
      { consumer: "cdbentley/../runsetta", intent: "QUARANTINE", key: "k" },
      { consumer: "cdbentley", intent: "QUARANTINE", key: "k:" + "x".repeat(300) },
      // No caller may submit canary or probe evidence in any shape.
      { consumer: "cdbentley", key: "k", canary: { account: "gha-terraform", checks, member: "principalSet://iam.googleapis.com/x", observedAt: "2026-09-04T12:00:00Z" } },
      { ...valid, canary: { account: "gha-terraform", checks, member: "principalSet://iam.googleapis.com/x", observedAt: "2026-09-04T12:00:00Z" } },
      { consumer: "cdbentley", key: "k", probe: { account: "gha-terraform", outcome: "DENIED", phase: "REVOCATION" } },
      { ...valid, probe: { outcome: "DENIED" } },
      { ...valid, scanReady: true },
    ]) {
      expect(() => parseAppendBody("s", forged), JSON.stringify(forged)).toThrow();
    }
    expect(() => parseAppendBody("Shard", valid)).toThrow("shard must match");
  });
});

describe.skipIf(!emulatorHost)("request boundary (Firestore emulator)", () => {
  test("identity, purpose, grammar, permission, and direction are enforced in order", async () => {
    const { authority, broker } = await world();
    const deps = { authority, broker, verifier: new FakeVerifier() };
    const call = (method: string, path: string, token: string | undefined, body?: unknown) =>
      handleRequest(deps, new Request(`http://broker${path}`, { body: body === undefined ? undefined : JSON.stringify(body), headers: token === undefined ? {} : { authorization: `Bearer ${token}` }, method }));
    const isolate = invokerEmail("cdbentley", "QUARANTINE");
    const restorer = invokerEmail("cdbentley", "RESTORE");
    expect((await call("POST", "/v1/shards/s/entries", undefined, {})).status).toBe(401);
    expect((await call("POST", "/v1/shards/s/entries", "gha-terraform@cdbentley.iam.gserviceaccount.com", {})).status).toBe(403);
    expect((await call("POST", "/v1/shards/s/entries", isolate, { consumer: "cdbentley", intent: "QUARANTINE", key: "k", role: "roles/owner" })).status).toBe(400);
    expect((await call("POST", "/v1/shards/s/entries", isolate, "not json")).status).toBe(400);
    expect((await call("POST", "/v1/shards/s/entries", isolate, { consumer: "runsetta", intent: "QUARANTINE", key: "k" })).status).toBe(403);
    expect((await call("POST", "/v1/shards/s/entries", reconcilerEmail, { consumer: "cdbentley", intent: "QUARANTINE", key: "k" })).status).toBe(403);
    // One credential, one direction: the isolate invoker cannot journal a restore and the restore invoker cannot journal a quarantine.
    expect((await call("POST", "/v1/shards/s/entries", isolate, { consumer: "cdbentley", intent: "RESTORE", key: "k", source: "q" })).status).toBe(403);
    expect((await call("POST", "/v1/shards/s/entries", restorer, { consumer: "cdbentley", intent: "QUARANTINE", key: "k" })).status).toBe(403);
    expect((await call("POST", "/v1/reconcile", isolate, {})).status).toBe(403);
    expect((await call("POST", "/v1/shards/s/close", isolate, { key: "k" })).status).toBe(404);
    expect((await call("GET", "/v1/shards/s", isolate)).status).toBe(404);
    expect((await call("GET", "/v1/shards/Bad", isolate)).status).toBe(404);
    expect((await call("DELETE", "/v1/shards/s", isolate)).status).toBe(404);
    const large = await handleRequest(deps, new Request("http://broker/v1/shards/s/entries", { body: JSON.stringify({ key: "x".repeat(9000) }), headers: { authorization: `Bearer ${isolate}` }, method: "POST" }));
    expect(large.status).toBe(413);
    const accepted = await call("POST", "/v1/shards/s/entries", isolate, { consumer: "cdbentley", intent: "QUARANTINE", key: "k" });
    expect(accepted.status).toBe(201);
    expect((await accepted.json() as { sequences: number[] }).sequences).toHaveLength(9);
    // Another consumer's invoker, and this consumer's other-direction invoker, can neither read, reconcile, nor close this shard; the reconciler can read and reconcile it.
    expect((await call("GET", "/v1/shards/s", invokerEmail("runsetta"))).status).toBe(403);
    expect((await call("POST", "/v1/shards/s/close", invokerEmail("runsetta"), { key: "c" })).status).toBe(403);
    expect((await call("GET", "/v1/shards/s", restorer)).status).toBe(403);
    expect((await call("POST", "/v1/shards/s/reconcile", restorer, {})).status).toBe(403);
    expect((await call("POST", "/v1/shards/s/close", restorer, { key: "c" })).status).toBe(403);
    expect((await call("GET", "/v1/shards/s", reconcilerEmail)).status).toBe(200);
    const sweep = await call("POST", "/v1/reconcile", reconcilerEmail, {});
    expect(sweep.status).toBe(200);
    expect(await sweep.json()).toMatchObject({ next: null, shards: [{ shard: "s" }] });
    // A close before readiness is refused with the blockers, and the shard stays OPEN.
    const notReady = await call("POST", "/v1/shards/s/close", isolate, { key: "c" });
    expect(notReady.status).toBe(409);
    expect(await notReady.json()).toMatchObject({ blockers: expect.arrayContaining([expect.stringContaining("quarantine is RECORDED")]), error: "NOT_READY" });
    expect((await (await call("GET", "/v1/shards/s", isolate)).json() as { shard: { phase: string; scanReady: { ready: boolean } } }).shard).toMatchObject({ phase: "OPEN", scanReady: { ready: false } });
  });
});

describe("Google identity verifier", () => {
  test("accepts only a Google-signed RS256 token for the exact audience and a service-account email", async () => {
    const keys = await crypto.subtle.generateKey({ hash: "SHA-256", modulusLength: 2048, name: "RSASSA-PKCS1-v1_5", publicExponent: new Uint8Array([1, 0, 1]) }, true, ["sign", "verify"]);
    const jwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
    const now = () => new Date("2026-09-04T12:00:00Z");
    const nowSeconds = Math.floor(now().getTime() / 1000);
    const verifier = new GoogleIdentityVerifier({ audience: "https://broker", jwks: async () => [{ e: jwk.e!, kid: "k1", kty: "RSA", n: jwk.n! }], now });
    const sign = async (payload: Record<string, unknown>, header: Record<string, unknown> = { alg: "RS256", kid: "k1" }) => {
      const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
      const signingInput = `${encode(header)}.${encode(payload)}`;
      const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", keys.privateKey, Buffer.from(signingInput));
      return `Bearer ${signingInput}.${Buffer.from(signature).toString("base64url")}`;
    };
    const claims = { aud: "https://broker", email: "gha-isolate-cdbentley@recovery-test.iam.gserviceaccount.com", email_verified: true, exp: nowSeconds + 3600, iat: nowSeconds - 60, iss: "https://accounts.google.com" };
    expect(await verifier.verify(await sign(claims))).toEqual({ email: claims.email });
    expect(await verifier.verify(await sign({ ...claims, aud: "https://other" }))).toBeUndefined();
    expect(await verifier.verify(await sign({ ...claims, iss: "https://evil.example" }))).toBeUndefined();
    expect(await verifier.verify(await sign({ ...claims, exp: nowSeconds - 3600 }))).toBeUndefined();
    expect(await verifier.verify(await sign({ ...claims, iat: nowSeconds + 3600 }))).toBeUndefined();
    expect(await verifier.verify(await sign({ ...claims, email: "collin@example.com" }))).toBeUndefined();
    expect(await verifier.verify(await sign({ ...claims, email_verified: false }))).toBeUndefined();
    expect(await verifier.verify(await sign(claims, { alg: "none", kid: "k1" }))).toBeUndefined();
    expect(await verifier.verify(await sign(claims, { alg: "RS256", kid: "k2" }))).toBeUndefined();
    const tampered = (await sign(claims)).replace(/\.[^.]+$/, ".AAAA");
    expect(await verifier.verify(tampered)).toBeUndefined();
    expect(await verifier.verify(null)).toBeUndefined();
    expect(await verifier.verify("Basic abc")).toBeUndefined();
  });
});
