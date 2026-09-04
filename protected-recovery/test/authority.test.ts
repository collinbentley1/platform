import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { manifestPath } from "../../tools/ci/workflow-authority";
import { GoogleIdentityVerifier, configurationFromEnvironment, handleRequest } from "../src/http";
import { loadRecoveryAuthority, parseAppendBody, purposeForIdentity, targetsFor } from "../src/model";
import { FakeVerifier, activeSha, emulatorHost, invokerEmail, reconcilerEmail, repoRoot, testAuthority, transitionSha, world } from "./support";

const authorityText = () => readFile(join(repoRoot, "protected-recovery/authority.json"), "utf8");
const manifestText = () => readFile(join(repoRoot, manifestPath), "utf8");

describe("recovery authority", () => {
  test("the committed authority holds only coordinates, and the broker project is not yet assigned", async () => {
    const authority = loadRecoveryAuthority(await authorityText(), await manifestText());
    expect(authority.broker.projectId).toBeNull();
    expect(authority.broker.projectNumber).toBeNull();
    expect(authority.consumers.map((consumer) => consumer.repository)).toEqual(["cdbentley", "critical-history", "healthmcp", "runsetta"]);
    expect(authority.consumers.every((consumer) => consumer.activeWorkflowSha === null && consumer.transitionWorkflowSha === null)).toBe(true);
    expect(authority.entries.filter((entry) => entry.trustDomain === "recovery")).toHaveLength(4);
    // No identity can hold a purpose until the broker project is recorded.
    expect(purposeForIdentity(authority, "gha-recovery-cdbentley@anything.iam.gserviceaccount.com")).toBeUndefined();
    expect(() => configurationFromEnvironment({}, authority)).toThrow("records no broker project");
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
    const edit = (mutate: (authority: Record<string, unknown>) => void) => {
      const copy = structuredClone(base);
      mutate(copy);
      return () => loadRecoveryAuthority(JSON.stringify(copy), manifest);
    };
    expect(edit((authority) => (authority.consumers as unknown[]).pop())).toThrow("recovery invoker for runsetta names no consumer");
    expect(edit((authority) => (authority.consumers as Array<Record<string, unknown>>)[0]!.repository = "cdbentley-two")).toThrow("must have exactly one recovery invoker");
    expect(edit((authority) => (authority.consumers as Array<Record<string, unknown>>)[0]!.projectNumber = "422714632513")).toThrow("already declared");
    expect(edit((authority) => (authority.consumers as Array<Record<string, unknown>>)[0]!.activeWorkflowSha = "abc")).toThrow("one full lowercase commit SHA");
    expect(edit((authority) => (authority.consumers as Array<Record<string, unknown>>)[0]!.transitionWorkflowSha = activeSha)).toThrow("requires activeWorkflowSha");
    expect(edit((authority) => (authority.broker as Record<string, unknown>).projectId = "recovery-test")).toThrow("both be null or both be assigned");
    expect(edit((authority) => (authority.broker as Record<string, unknown>).reconcilerServiceAccount = "gha-recovery-cdbentley")).toThrow("cannot also be a recovery invoker");
    expect(edit((authority) => (authority.broker as Record<string, unknown>).evidenceBucket = "bucket")).toThrow("keys must be exactly");
    expect(edit((authority) => (authority.platformRepository = "evil/platform"))).toThrow("must be collinbentley1/platform");
    expect(() => loadRecoveryAuthority(JSON.stringify(base), "[]")).toThrow("must be a non-empty array");
  });

  test("purpose is derived only from the invoker identity in the broker project", async () => {
    const authority = await testAuthority();
    const purpose = purposeForIdentity(authority, invokerEmail("cdbentley"));
    expect(purpose?.kind).toBe("recovery");
    if (purpose?.kind !== "recovery") throw new Error("expected a recovery purpose");
    expect(purpose.consumer.repository).toBe("cdbentley");
    expect(purpose.intents).toEqual(["QUARANTINE", "RESTORE"]);
    expect(purposeForIdentity(authority, reconcilerEmail)).toEqual({ kind: "reconciler", serviceAccount: "recovery-reconciler" });
    for (const forged of [
      "gha-recovery-cdbentley@cdbentley.iam.gserviceaccount.com",
      "gha-terraform@recovery-test.iam.gserviceaccount.com",
      "gha-recovery-other@recovery-test.iam.gserviceaccount.com",
      "recovery-broker@recovery-test.iam.gserviceaccount.com",
      "collin@example.com",
    ]) {
      expect(purposeForIdentity(authority, forged), forged).toBeUndefined();
    }
  });

  test("targets and managed members derive exactly from the canonical inventory", async () => {
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
    expect(terraform.resource).toBe("projects/cdbentley/serviceAccounts/gha-terraform@cdbentley.iam.gserviceaccount.com");
    expect(terraform.pool).toBe(pool);
    expect(terraform.members).toEqual([
      `principalSet://iam.googleapis.com/${pool}/attribute.authority/collinbentley1/cdbentley/.github/workflows/deploy-prod.yml@refs/heads/main:collinbentley1/platform/.github/workflows/infrastructure.yml@${activeSha}:${activeSha}:production:push`,
    ]);
    // Thirty-five active tuples in total, exactly the bootstrap module's matrix.
    expect(targets.reduce((count, target) => count + target.members.length, 0)).toBe(35);
    // The transition SHA extends only transition-eligible entries, and only for a consumer that records one.
    const runsetta = authority.consumers.find((consumer) => consumer.repository === "runsetta")!;
    const runsettaTargets = targetsFor(authority, runsetta)!;
    expect(runsettaTargets.reduce((count, target) => count + target.members.length, 0)).toBe(50);
    const operator = runsettaTargets.find((target) => target.account === "gha-preview-operator")!;
    expect(operator.members.filter((member) => member.includes(transitionSha))).toHaveLength(5);
    expect(runsettaTargets.find((target) => target.account === "gha-prod-deploy")!.members.some((member) => member.includes(transitionSha))).toBe(false);
    // Unpinned consumers derive nothing.
    expect(targetsFor(authority, { ...cdbentley, activeWorkflowSha: null })).toBeUndefined();
  });

  test("forged purpose, project, resource, role, member, policy, and object-name fields are refused", () => {
    const valid = { consumer: "cdbentley", intent: "QUARANTINE", key: "k" };
    expect(parseAppendBody("s", valid).body).toEqual({ kind: "quarantine" });
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
      { consumer: "cdbentley", intent: "RESTORE", key: "k", source: "../other" },
      { consumer: "cdbentley/../runsetta", intent: "QUARANTINE", key: "k" },
      { consumer: "cdbentley", intent: "QUARANTINE", key: "k:" + "x".repeat(300) },
      { consumer: "cdbentley", key: "k", canary: { account: "gha-terraform", member: "user:evil@example.com", observedAt: "2026-09-04T12:00:00Z", checks: {} } },
      { consumer: "cdbentley", key: "k", canary: { account: "gha-terraform", member: "principalSet://iam.googleapis.com/x", observedAt: "yesterday", checks: {} } },
    ]) {
      expect(() => parseAppendBody("s", forged), JSON.stringify(forged)).toThrow();
    }
    expect(() => parseAppendBody("Shard", valid)).toThrow("shard must match");
  });
});

describe.skipIf(!emulatorHost)("request boundary (Firestore emulator)", () => {
  test("identity, purpose, grammar, and permission are enforced in order", async () => {
    const { authority, broker } = await world();
    const deps = { authority, broker, verifier: new FakeVerifier() };
    const call = (method: string, path: string, token: string | undefined, body?: unknown) =>
      handleRequest(deps, new Request(`http://broker${path}`, { body: body === undefined ? undefined : JSON.stringify(body), headers: token === undefined ? {} : { authorization: `Bearer ${token}` }, method }));
    expect((await call("POST", "/v1/shards/s/entries", undefined, {})).status).toBe(401);
    expect((await call("POST", "/v1/shards/s/entries", "gha-terraform@cdbentley.iam.gserviceaccount.com", {})).status).toBe(403);
    expect((await call("POST", "/v1/shards/s/entries", invokerEmail("cdbentley"), { consumer: "cdbentley", intent: "QUARANTINE", key: "k", role: "roles/owner" })).status).toBe(400);
    expect((await call("POST", "/v1/shards/s/entries", invokerEmail("cdbentley"), "not json")).status).toBe(400);
    expect((await call("POST", "/v1/shards/s/entries", invokerEmail("cdbentley"), { consumer: "runsetta", intent: "QUARANTINE", key: "k" })).status).toBe(403);
    expect((await call("POST", "/v1/shards/s/entries", reconcilerEmail, { consumer: "cdbentley", intent: "QUARANTINE", key: "k" })).status).toBe(403);
    expect((await call("POST", "/v1/reconcile", invokerEmail("cdbentley"), {})).status).toBe(403);
    expect((await call("POST", "/v1/shards/s/close", invokerEmail("cdbentley"), { key: "k" })).status).toBe(404);
    expect((await call("GET", "/v1/shards/s", invokerEmail("cdbentley"))).status).toBe(404);
    expect((await call("GET", "/v1/shards/Bad", invokerEmail("cdbentley"))).status).toBe(404);
    expect((await call("DELETE", "/v1/shards/s", invokerEmail("cdbentley"))).status).toBe(404);
    const large = await handleRequest(deps, new Request("http://broker/v1/shards/s/entries", { body: JSON.stringify({ key: "x".repeat(9000) }), headers: { authorization: `Bearer ${invokerEmail("cdbentley")}` }, method: "POST" }));
    expect(large.status).toBe(413);
    const accepted = await call("POST", "/v1/shards/s/entries", invokerEmail("cdbentley"), { consumer: "cdbentley", intent: "QUARANTINE", key: "k" });
    expect(accepted.status).toBe(201);
    expect((await accepted.json() as { sequences: number[] }).sequences).toHaveLength(9);
    // Another consumer's invoker can neither read nor close this shard; the reconciler can read it.
    expect((await call("GET", "/v1/shards/s", invokerEmail("runsetta"))).status).toBe(403);
    expect((await call("POST", "/v1/shards/s/close", invokerEmail("runsetta"), { key: "c" })).status).toBe(403);
    expect((await call("GET", "/v1/shards/s", reconcilerEmail)).status).toBe(200);
    expect((await call("POST", "/v1/reconcile", reconcilerEmail, {})).status).toBe(200);
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
    const claims = { aud: "https://broker", email: "gha-recovery-cdbentley@recovery-test.iam.gserviceaccount.com", email_verified: true, exp: nowSeconds + 3600, iat: nowSeconds - 60, iss: "https://accounts.google.com" };
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
