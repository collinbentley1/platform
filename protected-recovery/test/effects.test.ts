import { describe, expect, test } from "bun:test";
import { type MemberCredentialSource, type Policy, type ProbeRequest, GoogleIssuanceProbe, driveEffect, expectedSnapshot, githubIssuer, observedSnapshot, planEffect, policyFromJson, undeployedMemberCredentials } from "../src/effects";
import { Broker } from "../src/http";
import { type Target, consumerProvider, managedRole, probePermission, probePrerequisite, purposeForIdentity, scanReadiness, targetsFor } from "../src/model";
import { entryEvidence } from "../src/outbox";
import { type World, Clock, beginClose, close, emulatorHost, freshOf, gate, invokerEmail, makeReady, needsOf, proberPrincipal, quarantine, restore, seedTargets, testAuthority, unrelatedBindings, world } from "./support";

const pool = "projects/882468538648/locations/global/workloadIdentityPools/github-actions";
const member = (sha: string) => `principalSet://iam.googleapis.com/${pool}/attribute.authority/collinbentley1/cdbentley/.github/workflows/deploy-prod.yml@refs/heads/main:collinbentley1/platform/.github/workflows/infrastructure.yml@${sha}:${sha}:production:push`;
const target: Target = { account: "gha-terraform", email: "gha-terraform@cdbentley.iam.gserviceaccount.com", members: [member("a".repeat(40)), member("b".repeat(40))], pool, resource: "projects/cdbentley/serviceAccounts/101080000000000000000", uniqueId: "101080000000000000000" };
const policy = (bindings: Policy["bindings"], etag = "e1"): Policy => policyFromJson({ bindings, etag, version: 1 });

describe("policy plan", () => {
  test("removes or adds exactly the managed members and preserves every unrelated binding and condition", () => {
    const before = policy([...unrelatedBindings, { condition: null, members: [...target.members, "serviceAccount:other@cdbentley.iam.gserviceaccount.com"], role: managedRole }]);
    const quarantined = planEffect("QUARANTINE", before, target);
    if ("divergence" in quarantined) throw new Error(quarantined.divergence);
    expect(quarantined.after).toEqual(policy([...unrelatedBindings, { condition: null, members: ["serviceAccount:other@cdbentley.iam.gserviceaccount.com"], role: managedRole }]).bindings);
    expect(quarantined.alternateIssuers).toEqual(["roles/iam.workloadIdentityUser:serviceAccount:other@cdbentley.iam.gserviceaccount.com"]);
    const restored = planEffect("RESTORE", policy(quarantined.after), target);
    if ("divergence" in restored) throw new Error(restored.divergence);
    expect(expectedSnapshot(restored.after).hash).toBe(observedSnapshot(before).hash);
    // A binding emptied by the quarantine disappears and returns on restore.
    const only = policy([...unrelatedBindings, { condition: null, members: [...target.members], role: managedRole }]);
    const emptied = planEffect("QUARANTINE", only, target);
    if ("divergence" in emptied) throw new Error(emptied.divergence);
    expect(emptied.after).toEqual(policy(unrelatedBindings).bindings);
    expect(emptied.alternateIssuers).toEqual([]);
    const back = planEffect("RESTORE", policy(emptied.after), target);
    if ("divergence" in back) throw new Error(back.divergence);
    expect(expectedSnapshot(back.after).hash).toBe(observedSnapshot(only).hash);
  });

  test("reports every alternate credential issuer without touching it", () => {
    const before = policy([
      { condition: null, members: [...target.members], role: managedRole },
      { condition: { description: "", expression: "true", title: "cond" }, members: ["user:evil@example.com"], role: managedRole },
      { condition: null, members: ["serviceAccount:minter@cdbentley.iam.gserviceaccount.com"], role: "roles/iam.serviceAccountTokenCreator" },
      { condition: null, members: ["group:ops@example.com"], role: "roles/iam.serviceAccountKeyAdmin" },
      { condition: null, members: ["serviceAccount:deploy@cdbentley.iam.gserviceaccount.com"], role: "roles/iam.serviceAccountUser" },
    ]);
    const plan = planEffect("QUARANTINE", before, target);
    if ("divergence" in plan) throw new Error(plan.divergence);
    expect(plan.alternateIssuers).toEqual([
      "roles/iam.serviceAccountKeyAdmin:group:ops@example.com",
      "roles/iam.serviceAccountTokenCreator:serviceAccount:minter@cdbentley.iam.gserviceaccount.com",
      "roles/iam.serviceAccountUser:serviceAccount:deploy@cdbentley.iam.gserviceaccount.com",
      "roles/iam.workloadIdentityUser[cond]:user:evil@example.com",
    ]);
    expect(plan.after).toHaveLength(4);
  });

  test("diverges on a missing managed member, an unmodeled pool member, or a member already present on restore", () => {
    expect(planEffect("QUARANTINE", policy([{ condition: null, members: [target.members[0]!], role: managedRole }]), target)).toEqual({ divergence: `managed members are not exactly present; missing ${target.members[1]}` });
    expect(planEffect("QUARANTINE", policy([{ condition: null, members: [...target.members, member("c".repeat(40))], role: managedRole }]), target)).toEqual({ divergence: `unmodeled federated members of the consumer pool: ${member("c".repeat(40))}` });
    expect(planEffect("RESTORE", policy([{ condition: null, members: [target.members[1]!], role: managedRole }]), target)).toEqual({ divergence: `managed members are already present: ${target.members[1]}` });
    expect(planEffect("QUARANTINE", policy([]), target)).toMatchObject({ divergence: expect.stringContaining("missing") });
  });

  test("policies are parsed strictly and canonically", () => {
    expect(() => policyFromJson({ bindings: [], etag: "e", version: 1, auditConfigs: [] })).toThrow("not a known field");
    expect(() => policyFromJson({ bindings: [], version: 1 })).toThrow("etag");
    expect(() => policyFromJson({ bindings: [{ members: ["x"] }], etag: "e" })).toThrow("role");
    const a = policyFromJson({ bindings: [{ members: ["user:b@x", "user:a@x", "user:a@x"], role: "roles/viewer" }, { members: ["user:c@x"], role: "roles/editor" }], etag: "e" });
    const b = policyFromJson({ bindings: [{ members: ["user:c@x"], role: "roles/editor" }, { members: ["user:a@x", "user:b@x"], role: "roles/viewer" }], etag: "e" });
    expect(observedSnapshot(a)).toEqual(observedSnapshot(b));
    expect(a.version).toBe(1);
  });
});

type Fetcher = typeof fetch;

function router(handle: (url: string, init: RequestInit) => Promise<Response> | Response): Fetcher {
  return Object.assign(async (input: string | URL | Request, init?: RequestInit) => await handle(String(input), init ?? {}), { preconnect: fetch.preconnect });
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { headers: { "content-type": "application/json" }, status });
}

describe("issuance probe", () => {
  test("acts as the exact canonical member through STS and IAM Credentials, binding principal, member, unique ID, permission, clock, and answer; anything else is unavailable, never DENIED", async () => {
    const authority = await testAuthority();
    const consumer = authority.consumers.find((candidate) => candidate.repository === "cdbentley")!;
    const probed = targetsFor(authority, consumer)![0]!;
    const canonical = probed.members[0]!;
    const provider = consumerProvider(authority, consumer);
    const composite = canonical.slice(`principalSet://iam.googleapis.com/${probed.pool}/attribute.authority/`.length).split(":");
    const keys = await crypto.subtle.generateKey({ hash: "SHA-256", modulusLength: 2048, name: "RSASSA-PKCS1-v1_5", publicExponent: new Uint8Array([1, 0, 1]) }, true, ["sign", "verify"]);
    const jwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
    const clock = new Clock();
    const nowSeconds = Math.floor(clock.now.getTime() / 1000);
    const sign = async (payload: Record<string, unknown>, signer = keys.privateKey, kid = "gh1"): Promise<string> => {
      const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
      const signingInput = `${encode({ alg: "RS256", kid })}.${encode(payload)}`;
      const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", signer, Buffer.from(signingInput));
      return `${signingInput}.${Buffer.from(signature).toString("base64url")}`;
    };
    const claims = {
      aud: `https://iam.googleapis.com/${provider}`,
      environment: composite[3],
      event_name: composite[4],
      exp: nowSeconds + 300,
      iat: nowSeconds - 10,
      iss: githubIssuer,
      job_workflow_ref: composite[1],
      job_workflow_sha: composite[2],
      repository_id: consumer.repositoryId,
      repository_owner_id: authority.githubOwnerId,
      runner_environment: "github-hosted",
      sub: `${authority.githubOwnerId}:${consumer.repositoryId}:github-hosted:4242`,
      workflow_ref: composite[0],
    };
    let token = await sign(claims);
    const credentials: MemberCredentialSource = { oidcTokenFor: async (requested) => (requested === canonical ? { kind: "token", token } : { kind: "unavailable", reason: `no job holds ${requested}` }) };
    const calls: Array<{ readonly bearer: string | undefined; readonly url: string }> = [];
    let allowed = true;
    let affirmed = true;
    let stsStatus = 200;
    let denial: unknown = { error: { code: 403, details: [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo", domain: "iam.googleapis.com", metadata: { permission: probePermission }, reason: "IAM_PERMISSION_DENIED" }], message: `Permission '${probePermission}' denied on resource (or it may not exist).`, status: "PERMISSION_DENIED" } };
    const fetcher = router((url, init) => {
      const headers = init.headers as Record<string, string> | undefined;
      calls.push({ bearer: headers?.Authorization, url });
      if (url === "https://sts.test/v1/token") {
        const body = JSON.parse(String(init.body)) as Record<string, unknown>;
        if (body.subjectToken !== token || body.audience !== `//iam.googleapis.com/${provider}` || body.grantType !== "urn:ietf:params:oauth:grant-type:token-exchange") return json(400, { error: "invalid_request" });
        return json(stsStatus, stsStatus === 200 ? { access_token: "federated-token", expires_in: 3599, issued_token_type: "urn:ietf:params:oauth:token-type:access_token", token_type: "Bearer" } : { error: "invalid_grant" });
      }
      if (headers?.Authorization !== "Bearer federated-token") return json(401, { error: { status: "UNAUTHENTICATED" } });
      if (url === `https://iam.test/v1/projects/-/serviceAccounts/${probed.uniqueId}:testIamPermissions`) return json(200, affirmed ? { permissions: [probePermission] } : {});
      if (url === `https://credentials.test/v1/projects/-/serviceAccounts/${probed.uniqueId}:generateAccessToken`) return allowed ? json(200, { accessToken: "never-retained", expireTime: "2026-09-04T12:05:00Z" }) : json(403, denial);
      return json(404, { error: { status: "NOT_FOUND" } });
    });
    const probe = new GoogleIssuanceProbe({ authority, credentials, endpoints: { credentials: "https://credentials.test", iam: "https://iam.test", sts: "https://sts.test" }, fetch: fetcher, jwks: async () => [{ e: jwk.e!, kid: "gh1", kty: "RSA", n: jwk.n! }], now: clock.read });
    const principal = `principal://iam.googleapis.com/${probed.pool}/subject/${claims.sub}`;
    const request: ProbeRequest = { email: probed.email, member: canonical, permission: probePermission, resource: probed.resource, uniqueId: probed.uniqueId };
    // The positive control affirms the member on the exact unique-ID resource with the federated token.
    expect(await probe.preflight([probed])).toEqual({ kind: "operational", principals: { [probed.account]: principal } });
    expect(calls.map((call) => call.url)).toEqual(["https://sts.test/v1/token", `https://iam.test/v1/projects/-/serviceAccounts/${probed.uniqueId}:testIamPermissions`]);
    // Issuance is ALLOWED while the binding stands and DENIED once IAM refuses exactly the probe permission.
    expect(await probe.probe(request)).toEqual({ kind: "observed", observedAt: clock.now.toISOString(), outcome: "ALLOWED", principal });
    allowed = false;
    clock.advance(5);
    expect(await probe.probe(request)).toEqual({ kind: "observed", observedAt: clock.now.toISOString(), outcome: "DENIED", principal });
    expect(calls.at(-1)!.url).toBe(`https://credentials.test/v1/projects/-/serviceAccounts/${probed.uniqueId}:generateAccessToken`);
    // A denial of another permission, a denial without an IAM reason, or any other failure is unavailable.
    denial = { error: { code: 403, details: [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo", domain: "iam.googleapis.com", metadata: { permission: "iam.serviceAccounts.actAs" }, reason: "IAM_PERMISSION_DENIED" }], message: "Permission 'iam.serviceAccounts.actAs' denied on resource.", status: "PERMISSION_DENIED" } };
    expect(await probe.probe(request)).toMatchObject({ kind: "unavailable", reason: expect.stringContaining("without an IAM denial") });
    denial = { error: { code: 403, message: "The caller does not have permission", status: "PERMISSION_DENIED" } };
    expect(await probe.probe(request)).toMatchObject({ kind: "unavailable" });
    denial = { error: { code: 403, message: "Permission 'iam.serviceAccounts.getAccessToken' denied on resource (or it may not exist).", status: "PERMISSION_DENIED" } };
    expect(await probe.probe(request)).toMatchObject({ kind: "observed", outcome: "DENIED" });
    affirmed = false;
    expect(await probe.preflight([probed])).toMatchObject({ kind: "unavailable", reason: expect.stringContaining("cannot serve as a positive control") });
    affirmed = true;
    stsStatus = 400;
    expect(await probe.probe(request)).toMatchObject({ kind: "unavailable", reason: "STS refused the member credential with HTTP 400" });
    stsStatus = 200;
    // A credential that is any other identity is refused before STS is ever called: another environment, another
    // repository, another audience, an expired token, another issuer, or a signature GitHub's keys do not verify.
    const before = calls.length;
    const refusals: Array<[Record<string, unknown> | undefined, CryptoKey, string]> = [
      [{ ...claims, environment: "production" }, keys.privateKey, "not the probed member"],
      [{ ...claims, repository_id: "999" }, keys.privateKey, "outside the consumer repository"],
      [{ ...claims, runner_environment: "self-hosted" }, keys.privateKey, "outside the consumer repository"],
      [{ ...claims, aud: "https://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/other/providers/github" }, keys.privateKey, "not minted for the consumer provider audience"],
      [{ ...claims, exp: nowSeconds - 3600 }, keys.privateKey, "has expired"],
      [{ ...claims, iss: "https://evil.example" }, keys.privateKey, "not issued by GitHub Actions"],
      [{ ...claims, sub: "" }, keys.privateKey, "lacks the subject"],
    ];
    for (const [payload, signer, reason] of refusals) {
      token = await sign(payload!, signer);
      expect(await probe.probe(request), reason).toMatchObject({ kind: "unavailable", reason: expect.stringContaining(reason) });
      expect(await probe.preflight([probed]), reason).toMatchObject({ kind: "unavailable" });
    }
    const foreign = await crypto.subtle.generateKey({ hash: "SHA-256", modulusLength: 2048, name: "RSASSA-PKCS1-v1_5", publicExponent: new Uint8Array([1, 0, 1]) }, true, ["sign", "verify"]);
    token = await sign(claims, foreign.privateKey);
    expect(await probe.probe(request)).toMatchObject({ kind: "unavailable", reason: "the member credential is not a GitHub-signed RS256 token" });
    expect(calls.length).toBe(before);
    // The production binding has no member credential source: every preflight and probe is unavailable, naming the prerequisite.
    const undeployed = new GoogleIssuanceProbe({ authority, credentials: undeployedMemberCredentials, endpoints: { credentials: "https://credentials.test", iam: "https://iam.test", sts: "https://sts.test" }, fetch: fetcher, jwks: async () => [], now: clock.read });
    expect(await undeployed.preflight([probed])).toEqual({ kind: "unavailable", reason: `${probed.account}: ${probePrerequisite}` });
    expect(await undeployed.probe(request)).toEqual({ kind: "unavailable", reason: probePrerequisite });
    expect(calls.length).toBe(before);
  });
});

async function setup(): Promise<World & { readonly targets: readonly Target[] }> {
  const w = await world();
  const consumer = w.authority.consumers.find((candidate) => candidate.repository === "cdbentley")!;
  const targets = targetsFor(w.authority, consumer)!;
  seedTargets(w.iam, targets);
  return { ...w, targets };
}

const entriesOf = (w: World, shard: string) => w.ledger.readShard(shard).then((doc) => w.ledger.readEntries(shard, doc!.nextSequence - 1));
const contentOf = (w: World, resource: string) => observedSnapshot(w.iam.policies.get(resource)!);
const readinessOf = async (w: World, shard: string) => scanReadiness((await w.ledger.readShard(shard))!, w.clock.now);
const isolate = (w: World) => purposeForIdentity(w.authority, invokerEmail("cdbentley"))!;

async function quarantineAndClose(w: World & { readonly targets: readonly Target[] }, shard: string): Promise<void> {
  expect((await w.ledger.append(quarantine(shard, "cdbentley", `${shard}-q`), w.targets)).kind).toBe("accepted");
  await makeReady(w, shard);
  expect((await beginClose(w, shard, `${shard}-c`)).kind).toBe("closing");
  await w.broker.reconcileShard(shard);
  expect((await w.ledger.readShard(shard))!.phase).toBe("CLOSED");
}

describe.skipIf(!emulatorHost)("effects and closure (Firestore emulator; in-memory IAM, evidence, probe, and inventory stand-ins)", () => {
  test("an exact policy A -> B -> A cycle: quarantine, inventory baseline, two probe phases, protected close, terminal projection, then a separately journaled restore", async () => {
    const w = await setup();
    const { broker, evidence, iam, ledger, probe, targets } = w;
    const before = new Map(targets.map((target) => [target.resource, contentOf(w, target.resource)]));
    expect((await ledger.append(quarantine("q1", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    const view = await broker.reconcileShard("q1");
    expect(view).toMatchObject({ notes: [], pendingEffects: 0, pendingOutbox: 0, phase: "OPEN" });
    const acked = await entriesOf(w, "q1");
    expect(acked).toHaveLength(27);
    for (const [index, target] of targets.entries()) {
      const entry = acked[index]!;
      if (entry.progress?.state !== "ACKED") throw new Error(`${target.account} is ${entry.progress?.state}`);
      expect(entry.body).toMatchObject({ email: target.email, resource: `projects/cdbentley/serviceAccounts/${target.uniqueId}`, uniqueId: target.uniqueId });
      expect(entry.progress.before).toEqual(before.get(target.resource)!);
      expect(entry.progress.observed.hash).toBe(entry.progress.after.hash);
      expect(entry.progress.observed.etag).not.toBe(entry.progress.before.etag);
      expect(entry.progress).toMatchObject({ alternateIssuers: [], attempts: 1, effectId: `q1/${index + 1}`, epoch: 1, mutated: true });
      expect(iam.policies.get(target.resource)!.bindings).toEqual(policyFromJson({ bindings: unrelatedBindings, etag: "x" }).bindings);
      expect(entry.outbox.state).toBe("PROJECTED");
      expect(evidence.objects.get(entry.objectName)!.bytes).toEqual(entryEvidence("q1", entry));
      expect(await ledger.readActuator(target.uniqueId)).toEqual({ epoch: 1, holder: null, lastEtag: entry.progress.observed.etag });
    }
    expect(iam.writes).toHaveLength(9);
    // The same reconcile recorded the inventory baseline of every target and then one revocation probe per target from the
    // probe source, bound to the exact identity and first managed member; the shard mirrors each target's chain.
    expect(probe.requests).toHaveLength(9);
    expect(probe.requests.map((request) => request.uniqueId)).toEqual(targets.map((target) => target.uniqueId));
    expect(probe.requests[0]).toEqual({ email: targets[0]!.email, member: targets[0]!.members[0]!, permission: probePermission, resource: targets[0]!.resource, uniqueId: targets[0]!.uniqueId });
    const shardAfterFirstPass = (await ledger.readShard("q1"))!;
    for (const [index, target] of targets.entries()) {
      const inventory = acked[9 + index]!;
      expect(inventory.body).toMatchObject({ kind: "inventory", account: target.account, email: target.email, findings: [], observedAt: w.clock.now.toISOString(), uniqueId: target.uniqueId });
      expect(inventory.outbox.state).toBe("PROJECTED");
      expect(acked[18 + index]!.body).toEqual({ kind: "probe", account: target.account, email: target.email, member: target.members[0]!, observedAt: w.clock.now.toISOString(), outcome: "DENIED", permission: probePermission, phase: "REVOCATION", principal: proberPrincipal, uniqueId: target.uniqueId });
      expect(acked[18 + index]!.outbox.state).toBe("PROJECTED");
      const state = shardAfterFirstPass.targets[target.account]!;
      expect(state).toMatchObject({ effect: { ackedAt: w.clock.now.toISOString(), alternateIssuers: [], state: "ACKED" }, sequence: index + 1 });
      expect(state.chain).toMatchObject({ allowed: { count: 0, lastObservedAt: null }, denied: 1, inventory: { changes: 0, findings: [], hash: inventory.body.kind === "inventory" ? inventory.body.hash : "", observations: 1 }, journaled: 2, post: null, revocation: { outcome: "DENIED", phase: "REVOCATION" }, suppressed: 0 });
    }
    // Not ready until the horizon drains and the post-horizon probes are recorded; close is refused until then.
    const horizonAt = new Date(w.clock.now.getTime() + 3600 * 1000).toISOString();
    expect(await readinessOf(w, "q1")).toEqual({ blockers: targets.map((target) => `${target.account}: token horizon drains at ${horizonAt}`), horizonAt, ready: false });
    expect(await beginClose(w, "q1", "c0")).toMatchObject({ kind: "rejected", rejection: { reason: "NOT_READY" } });
    w.clock.advance(3600);
    await broker.reconcileShard("q1");
    expect(probe.requests).toHaveLength(18);
    expect(await readinessOf(w, "q1")).toEqual({ blockers: [], horizonAt, ready: true });
    // The re-observed inventory was equal: no entry, the baseline re-verified.
    expect((await ledger.readShard("q1"))!.targets[targets[0]!.account]!.chain.inventory).toMatchObject({ changes: 0, observations: 2, verifiedAt: w.clock.now.toISOString() });
    // Managed bindings stay absent through the protected close and the terminal projection.
    expect((await beginClose(w, "q1", "c1")).kind).toBe("closing");
    const closed = await broker.reconcileShard("q1");
    expect(closed).toMatchObject({ phase: "CLOSED", terminal: { generation: "37", state: "PROJECTED" } });
    const shard = (await ledger.readShard("q1"))!;
    if (shard.phase !== "CLOSED") throw new Error();
    expect(new TextDecoder().decode(evidence.objects.get(shard.terminal.objectName)!.bytes)).toBe(shard.terminal.receipt);
    const receipt = JSON.parse(shard.terminal.receipt) as { targets: Record<string, { chain: { post: unknown; revocation: unknown; suppressed: number } }> };
    expect(receipt).toMatchObject({ closeHighWater: 36, consumer: "cdbentley", intent: "QUARANTINE", readiness: { blockers: [], horizonAt, ready: true }, shard: "q1" });
    expect(receipt.targets[targets[0]!.account]!.chain).toMatchObject({ post: { phase: "HORIZON" }, revocation: { phase: "REVOCATION" }, suppressed: 0 });
    expect(iam.writes).toHaveLength(9);
    expect(probe.requests).toHaveLength(18);
    // Restore is its own journal with its own receipt, restoring exactly the captured members on exactly the captured
    // identities, admitted only against the source's freshly observed inventory; it admits no probe.
    expect((await ledger.append(restore("r1", "cdbentley", "k2", "q1"), targets, await freshOf(w, "q1"))).kind).toBe("accepted");
    expect(await ledger.recordProbe("r1", { account: targets[0]!.account, email: targets[0]!.email, member: targets[0]!.members[0]!, observedAt: w.clock.now.toISOString(), outcome: "DENIED", permission: probePermission, phase: "REVOCATION", principal: proberPrincipal, uniqueId: targets[0]!.uniqueId })).toEqual({ kind: "refused", reason: "probes belong to QUARANTINE shards only" });
    await broker.reconcileShard("r1");
    const restored = await entriesOf(w, "r1");
    expect(restored).toHaveLength(9);
    for (const [index, target] of targets.entries()) {
      const entry = restored[index]!;
      if (entry.progress?.state !== "ACKED") throw new Error(`${target.account} restore is ${entry.progress?.state}`);
      expect(entry.body).toMatchObject({ email: target.email, intent: "RESTORE", resource: target.resource, uniqueId: target.uniqueId });
      const original = before.get(target.resource)!;
      expect(entry.progress.after.hash).toBe(original.hash);
      expect(entry.progress.observed.hash).toBe(original.hash);
      expect(entry.progress.observed.etag).not.toBe(original.etag);
      expect(entry.progress.before.etag).toBe(acked[index]!.progress!.state === "ACKED" ? (acked[index]!.progress as { observed: { etag: string } }).observed.etag : "");
      expect(entry.progress.epoch).toBe(2);
      expect(contentOf(w, target.resource).policy).toBe(original.policy);
    }
    expect(iam.writes).toHaveLength(18);
    expect((await beginClose(w, "r1", "c2", "cdbentley", "RESTORE")).kind).toBe("closing");
    expect(await broker.reconcileShard("r1")).toMatchObject({ phase: "CLOSED", source: "q1", terminal: { state: "PROJECTED" } });
    expect(JSON.parse((await ledger.readShard("r1") as { terminal: { receipt: string } }).terminal.receipt)).toMatchObject({ intent: "RESTORE", readiness: null });
    // A second restore of the same receipt finds the members present and diverges without writing.
    expect((await ledger.append(restore("r2", "cdbentley", "k3", "q1"), targets, await freshOf(w, "q1"))).kind).toBe("accepted");
    const again = await broker.reconcileShard("r2");
    expect((again as { notes: string[] }).notes.every((note) => note.includes("already present"))).toBe(true);
    expect(iam.writes).toHaveLength(18);
  }, 60_000);

  test("scan-ready needs an inventory baseline and a DENIED probe per exact target after acknowledgement, a drained one-hour horizon, and another DENIED probe after it", async () => {
    const w = await setup();
    const { broker, clock, ledger, probe, targets } = w;
    // A one-hour token minted one second before the quarantine lands must keep the shard unready until it expires.
    const mintedAt = clock.now.getTime();
    clock.advance(1);
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    expect(await readinessOf(w, "q")).toMatchObject({ horizonAt: null, ready: false });
    expect((await readinessOf(w, "q")).blockers).toEqual(targets.map((target) => `${target.account}: quarantine is RECORDED`));
    await broker.reconcileShard("q");
    const tokenExpiry = mintedAt + 3600 * 1000;
    const horizon = clock.now.getTime() + 3600 * 1000;
    const horizonAt = new Date(horizon).toISOString();
    expect(horizon).toBeGreaterThanOrEqual(tokenExpiry);
    expect(probe.requests).toHaveLength(9);
    expect(await readinessOf(w, "q")).toEqual({ blockers: targets.map((target) => `${target.account}: token horizon drains at ${horizonAt}`), horizonAt, ready: false });
    // Before the horizon no post-horizon probe is taken, and none would be admitted as one.
    clock.now = new Date(tokenExpiry - 1000);
    await broker.reconcileShard("q");
    expect(probe.requests).toHaveLength(9);
    expect((await readinessOf(w, "q")).ready).toBe(false);
    clock.now = new Date(horizon - 1000);
    await broker.reconcileShard("q");
    expect(probe.requests).toHaveLength(9);
    expect(await needsOf(w, "q", targets)).toEqual([]);
    expect((await readinessOf(w, "q")).ready).toBe(false);
    const early = targets[0]!;
    expect(await ledger.recordProbe("q", { account: early.account, email: early.email, member: early.members[0]!, observedAt: new Date(horizon).toISOString(), outcome: "DENIED", permission: probePermission, phase: "HORIZON", principal: proberPrincipal, uniqueId: early.uniqueId })).toMatchObject({ kind: "refused", reason: "the observation is in the ledger's future" });
    // A DENIED observation before the horizon is journaled but counts for nothing.
    expect(await ledger.recordProbe("q", { account: early.account, email: early.email, member: early.members[0]!, observedAt: clock.now.toISOString(), outcome: "DENIED", permission: probePermission, phase: "HORIZON", principal: proberPrincipal, uniqueId: early.uniqueId })).toMatchObject({ kind: "recorded", role: "REDUNDANT" });
    expect((await ledger.readShard("q"))!.targets[early.account]!.chain).toMatchObject({ denied: 2, post: null });
    // At the horizon the broker records the post-horizon probes and the shard is ready; time alone never made it so.
    clock.now = new Date(horizon);
    expect(await needsOf(w, "q", targets)).toEqual(targets.map((target) => ({ account: target.account, email: target.email, member: target.members[0]!, notBefore: horizonAt, phase: "HORIZON", resource: target.resource, uniqueId: target.uniqueId })));
    expect(await readinessOf(w, "q")).toEqual({ blockers: targets.map((target) => `${target.account}: no DENIED impersonation probe after the token horizon ${horizonAt}`), horizonAt, ready: false });
    await broker.reconcileShard("q");
    expect(probe.requests).toHaveLength(18);
    expect(await readinessOf(w, "q")).toEqual({ blockers: [], horizonAt, ready: true });
    // The readiness is reported on the caller-facing view.
    const view = await broker.handle({ kind: "reconciler", serviceAccount: "recovery-reconciler" }, { kind: "read", shard: "q" });
    expect((view.body.shard as { scanReady: unknown }).scanReady).toEqual({ blockers: [], horizonAt, ready: true });
  }, 60_000);

  test("an ALLOWED observation restarts a target's chain, and an unreachable source records nothing", async () => {
    const w = await setup();
    const { broker, clock, ledger, probe, targets } = w;
    const [first, second] = [targets[0]!, targets[1]!];
    probe.outcomes.set(first.uniqueId, "ALLOWED");
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    await broker.reconcileShard("q");
    expect(probe.requests).toHaveLength(9);
    let readiness = await readinessOf(w, "q");
    expect(readiness.horizonAt).toBeNull();
    expect(readiness.blockers).toContain(`${first.account}: no DENIED impersonation probe after the quarantine acknowledgement`);
    expect((await ledger.readShard("q"))!.targets[first.account]!.chain).toMatchObject({ allowed: { count: 1, lastObservedAt: clock.now.toISOString() }, revocation: null });
    // Still allowed ten minutes later: probed again, still blocked; the others wait for their horizon and are not probed.
    clock.advance(600);
    await broker.reconcileShard("q");
    expect(probe.requests).toHaveLength(10);
    expect(probe.requests[9]!.uniqueId).toBe(first.uniqueId);
    // Denied at T+1200: the horizon of the first target is one hour after that, later than every other target's.
    probe.outcomes.delete(first.uniqueId);
    clock.advance(600);
    await broker.reconcileShard("q");
    expect(probe.requests).toHaveLength(11);
    const firstHorizon = clock.now.getTime() + 3600 * 1000;
    readiness = await readinessOf(w, "q");
    expect(readiness.horizonAt).toBe(new Date(firstHorizon).toISOString());
    expect(readiness.ready).toBe(false);
    // The other eight targets drain first and get their post-horizon probes; the first still blocks.
    clock.advance(2400);
    await broker.reconcileShard("q");
    expect(probe.requests).toHaveLength(19);
    readiness = await readinessOf(w, "q");
    expect(readiness.blockers).toEqual([`${first.account}: token horizon drains at ${new Date(firstHorizon).toISOString()}`]);
    expect(await beginClose(w, "q", "c0")).toMatchObject({ kind: "rejected", rejection: { blockers: readiness.blockers, reason: "NOT_READY" } });
    clock.advance(1200);
    await broker.reconcileShard("q");
    expect(probe.requests).toHaveLength(20);
    expect((await readinessOf(w, "q")).ready).toBe(true);
    // A later ALLOWED observation on a ready target restarts its chain: a fresh DENIED probe and a fresh hour are required again.
    expect(await ledger.recordProbe("q", { account: second.account, email: second.email, member: second.members[0]!, observedAt: clock.now.toISOString(), outcome: "ALLOWED", permission: probePermission, phase: "HORIZON", principal: proberPrincipal, uniqueId: second.uniqueId })).toMatchObject({ kind: "recorded", role: "ALLOWED" });
    readiness = await readinessOf(w, "q");
    expect(readiness).toMatchObject({ blockers: [`${second.account}: no DENIED impersonation probe after the quarantine acknowledgement`], horizonAt: null, ready: false });
    expect(await beginClose(w, "q", "c1")).toMatchObject({ kind: "rejected", rejection: { reason: "NOT_READY" } });
    clock.advance(1);
    await broker.reconcileShard("q");
    expect(probe.requests).toHaveLength(21);
    expect((await readinessOf(w, "q")).blockers).toEqual([`${second.account}: token horizon drains at ${new Date(clock.now.getTime() + 3600 * 1000).toISOString()}`]);
    // An unreachable source records nothing.
    const u = await setup();
    expect((await u.ledger.append(quarantine("q", "cdbentley", "k1"), u.targets)).kind).toBe("accepted");
    u.probe.unavailable = 9;
    const unavailable = await u.broker.reconcileShard("q");
    expect((unavailable as { notes: string[] }).notes).toEqual(u.targets.map((target) => `${target.account}: REVOCATION probe unavailable; the probe source is unreachable`));
    expect((await entriesOf(u, "q")).filter((entry) => entry.body.kind === "probe")).toHaveLength(0);
    expect((await readinessOf(u, "q")).blockers).toEqual(u.targets.map((target) => `${target.account}: no DENIED impersonation probe after the quarantine acknowledgement`));
  }, 60_000);

  test("a QUARANTINE is refused before acceptance and before any effect is prepared while the probe source cannot act as the members or an inventory is not clean", async () => {
    const w = await setup();
    const { broker, iam, inventory, ledger, probe, targets } = w;
    const purpose = isolate(w);
    // The positive control fails: refused before acceptance, nothing journaled, nothing read or written.
    probe.preflightUnavailable = 1;
    expect(await broker.handle(purpose, quarantine("q", "cdbentley", "k1"))).toEqual({ status: 409, body: { detail: "the probe source cannot act as the managed members", error: "PROBE_UNAVAILABLE" } });
    expect(await ledger.readShard("q")).toBeUndefined();
    expect(probe.preflights.at(-1)!.map((target) => target.uniqueId)).toEqual(targets.map((target) => target.uniqueId));
    expect(inventory.requests).toHaveLength(0);
    expect(iam.writes).toHaveLength(0);
    // A target with an alternate credential path: refused before acceptance, naming the path.
    inventory.findings.set(targets[2]!.uniqueId, ["key:projects/cdbentley/serviceAccounts/x/keys/k1"]);
    expect(await broker.handle(purpose, quarantine("q", "cdbentley", "k1"))).toEqual({ status: 409, body: { blockers: [`${targets[2]!.account}: key:projects/cdbentley/serviceAccounts/x/keys/k1`], error: "INVENTORY_BLOCKED" } });
    expect(await ledger.readShard("q")).toBeUndefined();
    inventory.findings.delete(targets[2]!.uniqueId);
    // Operational and clean: accepted.
    expect((await broker.handle(purpose, quarantine("q", "cdbentley", "k1"))).status).toBe(201);
    expect((await ledger.readShard("q"))!.nextSequence).toBe(10);
    // The source becomes unavailable after acceptance: no RECORDED effect is prepared, no actuator taken, nothing written.
    probe.preflightUnavailable = 1;
    const held = await broker.reconcileShard("q");
    expect((held as { notes: string[] }).notes).toEqual(targets.map((_, index) => `${index + 1}: pending; not prepared because PROBE_UNAVAILABLE; the probe source cannot act as the managed members`));
    expect(iam.writes).toHaveLength(0);
    expect((await entriesOf(w, "q")).every((entry) => entry.progress?.state === "RECORDED")).toBe(true);
    expect(await ledger.readActuator(targets[0]!.uniqueId)).toBeUndefined();
    expect(iam.policies.get(targets[0]!.resource)!.bindings.some((binding) => binding.role === managedRole)).toBe(true);
    // A replay of the accepted key is answered by the ledger without another positive control.
    probe.preflightUnavailable = 1;
    expect((await broker.handle(purpose, quarantine("q", "cdbentley", "k1"))).status).toBe(200);
    expect(probe.preflightUnavailable).toBe(1);
    // Operational again: prepared, written, acknowledged.
    probe.preflightUnavailable = 0;
    await broker.reconcileShard("q");
    expect(iam.writes).toHaveLength(9);
    // The production binding has no member credential source: refused before acceptance, and a shard journaled by any other
    // route stays RECORDED and unwritten under it, naming the prerequisite.
    const p = await setup();
    const production = new GoogleIssuanceProbe({ authority: p.authority, credentials: undeployedMemberCredentials, fetch, jwks: async () => [], now: p.clock.read });
    const inert = new Broker({ authority: p.authority, evidence: p.evidence, iam: p.iam, inventory: p.inventory, ledger: p.ledger, now: p.clock.read, probe: production });
    const detail = p.targets.map((target) => `${target.account}: ${probePrerequisite}`).join("; ");
    expect(await inert.handle(isolate(p), quarantine("q", "cdbentley", "k1"))).toEqual({ status: 409, body: { detail, error: "PROBE_UNAVAILABLE" } });
    expect(await p.ledger.readShard("q")).toBeUndefined();
    expect((await p.ledger.append(quarantine("q", "cdbentley", "k1"), p.targets)).kind).toBe("accepted");
    const view = await inert.reconcileShard("q");
    expect((view as { notes: string[] }).notes).toEqual(p.targets.map((_, index) => `${index + 1}: pending; not prepared because PROBE_UNAVAILABLE; ${detail}`));
    expect(p.iam.writes).toHaveLength(0);
    p.clock.advance(7200);
    await inert.reconcileShard("q");
    expect(await readinessOf(p, "q")).toEqual({ blockers: p.targets.map((target) => `${target.account}: quarantine is RECORDED`), horizonAt: null, ready: false });
    expect(await beginClose(p, "q", "c")).toMatchObject({ kind: "rejected", rejection: { reason: "NOT_READY" } });
  }, 60_000);

  test("a partial quarantine, an alternate issuer, or a pre-prepare divergence is never scan-ready, is not probed, and refuses to close", async () => {
    const w = await setup();
    const { broker, clock, evidence, iam, ledger, probe, targets } = w;
    // Target 1 carries an extra token creator; target 2 lost one managed member out of band.
    iam.seed(targets[1]!.resource, [{ condition: null, members: ["serviceAccount:minter@cdbentley.iam.gserviceaccount.com"], role: "roles/iam.serviceAccountTokenCreator" }, { condition: null, members: [...targets[1]!.members], role: managedRole }]);
    iam.seed(targets[2]!.resource, [{ condition: null, members: targets[2]!.members.slice(1), role: managedRole }]);
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    const view = await broker.reconcileShard("q");
    expect((view as { notes: string[] }).notes).toEqual([`3: diverged; managed members are not exactly present; missing ${targets[2]!.members[0]}`]);
    const entries = await entriesOf(w, "q");
    expect(entries[1]!.progress).toMatchObject({ state: "ACKED", alternateIssuers: ["roles/iam.serviceAccountTokenCreator:serviceAccount:minter@cdbentley.iam.gserviceaccount.com"] });
    expect(iam.policies.get(targets[1]!.resource)!.bindings).toEqual([{ condition: null, members: ["serviceAccount:minter@cdbentley.iam.gserviceaccount.com"], role: "roles/iam.serviceAccountTokenCreator" }]);
    expect(entries[2]!.progress).toMatchObject({ state: "DIVERGED", attempts: 0, prepared: null });
    expect((await ledger.readShard("q"))!.targets[targets[2]!.account]!.effect).toEqual({ ackedAt: null, alternateIssuers: [], state: "DIVERGED" });
    expect(iam.writes.map((write) => write.resource)).not.toContain(targets[2]!.resource);
    expect(evidence.objects.has(entries[2]!.objectName)).toBe(false);
    expect(await ledger.readActuator(targets[2]!.uniqueId)).toEqual({ epoch: 1, holder: null, lastEtag: (entries[2]!.progress as { observed: { etag: string } }).observed.etag });
    // Neither the alternate-issuer target nor the diverged target is probed; the other seven are.
    expect(probe.requests.map((request) => request.uniqueId)).toEqual(targets.filter((_, index) => index !== 1 && index !== 2).map((target) => target.uniqueId));
    clock.advance(3600);
    await broker.reconcileShard("q");
    const readiness = await readinessOf(w, "q");
    expect(readiness.ready).toBe(false);
    expect(readiness.blockers).toContain(`${targets[1]!.account}: alternate credential issuers roles/iam.serviceAccountTokenCreator:serviceAccount:minter@cdbentley.iam.gserviceaccount.com`);
    expect(readiness.blockers).toContain(`${targets[2]!.account}: quarantine is DIVERGED`);
    expect(await beginClose(w, "q", "c")).toMatchObject({ kind: "rejected", rejection: { blockers: readiness.blockers, reason: "NOT_READY" } });
    await broker.reconcileShard("q");
    expect((await ledger.readShard("q"))!.phase).toBe("OPEN");
    expect(evidence.objects.has("shards/q/close.json")).toBe(false);
    expect(await ledger.append(restore("r", "cdbentley", "k2", "q"), targets, await freshOf(w, "q"))).toMatchObject({ kind: "rejected", rejection: { reason: "SOURCE_NOT_COMPLETE" } });
  });

  test("a resource whose returned identity is not the journaled unique ID and email is refused before any read or write", async () => {
    const w = await setup();
    const { broker, iam, ledger, targets } = w;
    const [recreated, prepared, unavailable] = [targets[0]!, targets[1]!, targets[2]!];
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    // Driving a journaled effect with any other target identity is refused before the actuator is even reserved.
    await expect(driveEffect(ledger, iam, "q", (await ledger.readEntry("q", 4))!, unavailable)).rejects.toThrow("the journaled identity does not match the driven target");
    expect((await ledger.readEntry("q", 4))!.progress).toEqual({ state: "RECORDED" });
    expect(await ledger.readActuator(targets[3]!.uniqueId)).toBeUndefined();
    // A takeover resuming a PREPARED effect verifies the identity again before its write.
    iam.beforeWrite = async () => {
      throw new Error("the worker died before the write");
    };
    await expect(driveEffect(ledger, iam, "q", (await ledger.readEntry("q", 2))!, prepared)).rejects.toThrow("died before the write");
    expect((await ledger.readEntry("q", 2))!.progress).toMatchObject({ state: "PREPARED", attempts: 1 });
    expect((await ledger.readShard("q"))!.targets[prepared.account]!.effect.state).toBe("PREPARED");
    // The account at the first target's address was deleted and recreated: same email, different permanent identity.
    iam.identities.set(recreated.resource, { email: recreated.email, uniqueId: "199990000000000000000" });
    iam.identities.set(prepared.resource, { email: "someone-else@cdbentley.iam.gserviceaccount.com", uniqueId: prepared.uniqueId });
    // The third target's identity cannot be read at all: nothing is written for it either.
    iam.identities.delete(unavailable.resource);
    const writesBefore = iam.writes.length;
    const view = await broker.reconcileShard("q");
    const notes = (view as { notes: string[] }).notes;
    expect(notes).toContain(`1: diverged; the resource identity ${recreated.email} (199990000000000000000) is not the journaled target ${recreated.email} (${recreated.uniqueId})`);
    expect(notes).toContain(`2: diverged; the resource identity someone-else@cdbentley.iam.gserviceaccount.com (${prepared.uniqueId}) is not the journaled target ${prepared.email} (${prepared.uniqueId})`);
    expect(notes).toContain("3: pending; HTTP 404");
    const entries = await entriesOf(w, "q");
    expect(entries[0]!.progress).toMatchObject({ state: "DIVERGED", observed: null, prepared: null });
    expect(entries[1]!.progress).toMatchObject({ state: "DIVERGED", observed: null, attempts: 1 });
    expect(entries[2]!.progress).toMatchObject({ state: "RECORDED" });
    expect(iam.writes.slice(writesBefore).map((write) => write.resource)).not.toContain(recreated.resource);
    expect(iam.writes.slice(writesBefore).map((write) => write.resource)).not.toContain(prepared.resource);
    expect(iam.policies.get(recreated.resource)!.bindings.some((binding) => binding.role === managedRole)).toBe(true);
    expect(iam.policies.get(prepared.resource)!.bindings.some((binding) => binding.role === managedRole)).toBe(true);
    // Actuators are keyed by identity, and both diverged targets released theirs.
    expect(await ledger.readActuator(recreated.uniqueId)).toMatchObject({ epoch: 1, holder: null });
    expect(await ledger.readActuator(prepared.uniqueId)).toMatchObject({ epoch: 1, holder: null });
    expect(await ledger.readActuator(recreated.email)).toBeUndefined();
    expect(iam.writes.slice(writesBefore).map((write) => write.resource)).not.toContain(unavailable.resource);
    // The transient identity failure resolves on the next pass, and only then is the third target written.
    iam.identities.set(unavailable.resource, { email: unavailable.email, uniqueId: unavailable.uniqueId });
    await broker.reconcileShard("q");
    expect((await ledger.readEntry("q", 3))!.progress).toMatchObject({ state: "ACKED", attempts: 1 });
    expect((await entriesOf(w, "q")).filter((entry) => entry.progress?.state === "ACKED")).toHaveLength(7);
  }, 60_000);

  test("termination at each boundary reconciles to one exact outcome: reservation, PREPARE, landed write, ACK, entry outbox, terminal outbox", async () => {
    const w = await setup();
    const { broker, evidence, iam, ledger, targets } = w;
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    const entry = (sequence: number) => ledger.readEntry("q", sequence).then((found) => found!);
    const target = (sequence: number) => targets[sequence - 1]!;
    // 1: died after reserving the actuator.
    expect(await ledger.reserveActuator("q", 1, target(1).uniqueId)).toEqual({ kind: "reserved", effectId: "q/1", epoch: 1 });
    // 2: died after PREPARE, before any write (the read is real, the write never happens).
    iam.beforeWrite = async () => {
      throw new Error("the worker died before the write");
    };
    await expect(driveEffect(ledger, iam, "q", await entry(2), target(2))).rejects.toThrow("died before the write");
    expect((await entry(2)).progress).toMatchObject({ state: "PREPARED", attempts: 1, epoch: 1 });
    // 3: died after the write landed, before reading the answer.
    iam.throwAfterWrite = true;
    await expect(driveEffect(ledger, iam, "q", await entry(3), target(3))).rejects.toThrow("died after the write landed");
    expect((await entry(3)).progress).toMatchObject({ state: "PREPARED", attempts: 1 });
    // 4: acknowledged, died before the outbox projection.
    expect((await driveEffect(ledger, iam, "q", await entry(4), target(4))).kind).toBe("acked");
    // 5: acknowledged and the evidence object created, died before recording it.
    expect((await driveEffect(ledger, iam, "q", await entry(5), target(5))).kind).toBe("acked");
    const fifth = await entry(5);
    expect((await evidence.create(fifth.objectName, entryEvidence("q", fifth))).kind).toBe("created");
    const writesBefore = iam.writes.length;
    const view = await broker.reconcileShard("q");
    expect(view).toMatchObject({ notes: [], pendingEffects: 0, pendingOutbox: 0 });
    const entries = await entriesOf(w, "q");
    expect(entries.every((candidate) => (candidate.progress === null || candidate.progress.state === "ACKED") && candidate.outbox.state === "PROJECTED")).toBe(true);
    expect(entries[0]!.progress).toMatchObject({ attempts: 1, effectId: "q/1", epoch: 1 });
    expect(entries[1]!.progress).toMatchObject({ attempts: 2, effectId: "q/2", epoch: 1, mutated: true });
    // The landed write was classified as the exact after state without a second write.
    expect(entries[2]!.progress).toMatchObject({ attempts: 2, effectId: "q/3", epoch: 1, mutated: false });
    // Three writes landed before the reconcile (boundaries 3, 4, 5); the other six targets are written exactly once.
    expect(iam.writes.length - writesBefore).toBe(6);
    expect(iam.writes.filter((write) => write.resource === target(3).resource)).toHaveLength(1);
    expect(entries[4]!.outbox).toMatchObject({ state: "PROJECTED", generation: evidence.objects.get(fifth.objectName)!.generation });
    // 6: ready, close, then the terminal projection's answer is lost and the bucket is unreadable: FINALIZING, not CLOSED.
    w.clock.advance(3600);
    await broker.reconcileShard("q");
    expect((await beginClose(w, "q", "c")).kind).toBe("closing");
    evidence.dropResponses = 1;
    evidence.unavailableReads = 1;
    const finalizing = await broker.reconcileShard("q");
    expect(finalizing).toMatchObject({ phase: "FINALIZING", terminal: { generation: null, state: "PENDING" } });
    expect(await broker.reconcileShard("q")).toMatchObject({ phase: "CLOSED", terminal: { state: "PROJECTED" } });
    const shard = (await ledger.readShard("q"))!;
    if (shard.phase !== "CLOSED") throw new Error();
    expect(evidence.objects.get(shard.terminal.objectName)!.generation).toBe(shard.terminal.progress.state === "PROJECTED" ? shard.terminal.progress.generation : "");
  }, 60_000);

  test("close stays CLOSING with no terminal receipt until pending work resolves, and a diverged terminal never becomes CLOSED", async () => {
    const w = await setup();
    const { broker, evidence, iam, ledger, targets } = w;
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    // Nothing acknowledged yet: not ready, so the close is refused outright and nothing is written or projected.
    iam.unavailableReads = 9;
    expect(await broker.reconcileShard("q")).toMatchObject({ pendingEffects: 9, phase: "OPEN", terminal: null });
    expect(await beginClose(w, "q", "c")).toMatchObject({ kind: "rejected", rejection: { reason: "NOT_READY" } });
    expect(evidence.objects.size).toBe(0);
    expect(iam.writes).toHaveLength(0);
    // Ready, but the post-horizon probe entries could not be projected: the close begins and stays CLOSING.
    await broker.reconcileShard("q");
    w.clock.advance(3600);
    evidence.dropResponses = 9;
    evidence.unavailableReads = 9;
    await broker.reconcileShard("q");
    expect((await ledger.readShard("q"))!).toMatchObject({ pendingEffects: 0, pendingOutbox: 9 });
    expect((await beginClose(w, "q", "c")).kind).toBe("closing");
    evidence.unavailableReads = 9;
    expect(await broker.reconcileShard("q")).toMatchObject({ pendingOutbox: 9, phase: "CLOSING", terminal: null });
    expect(evidence.objects.has("shards/q/close.json")).toBe(false);
    // Pre-create the terminal object with foreign bytes: the close diverges and is never labelled CLOSED.
    expect((await evidence.create("shards/q/close.json", new TextEncoder().encode("forged\n"))).kind).toBe("created");
    expect(await broker.reconcileShard("q")).toMatchObject({ pendingOutbox: 0, phase: "FINALIZING", terminal: { generation: null, state: "DIVERGED" } });
    expect(await broker.reconcileShard("q")).toMatchObject({ phase: "FINALIZING", terminal: { state: "DIVERGED" } });
    expect(await ledger.append(restore("r", "cdbentley", "k2", "q"), targets, await freshOf(w, "q"))).toMatchObject({ kind: "rejected", rejection: { reason: "SOURCE_NOT_COMPLETE" } });
  }, 60_000);

  test("a lost response is taken over exactly once, whether the first worker survives or dies", async () => {
    const w = await setup();
    const { broker, iam, ledger, targets } = w;
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    iam.dropResponses = 1;
    const survived = await driveEffect(ledger, iam, "q", (await ledger.readEntry("q", 1))!, targets[0]!);
    expect(survived.kind).toBe("acked");
    expect(survived.entry.progress).toMatchObject({ attempts: 1, mutated: true });
    iam.throwAfterWrite = true;
    await expect(driveEffect(ledger, iam, "q", (await ledger.readEntry("q", 2))!, targets[1]!)).rejects.toThrow();
    const takeover = await driveEffect(ledger, iam, "q", (await ledger.readEntry("q", 2))!, targets[1]!);
    expect(takeover.kind).toBe("acked");
    expect(takeover.entry.progress).toMatchObject({ attempts: 2, mutated: false });
    expect(iam.writes.filter((write) => write.resource === targets[1]!.resource)).toHaveLength(1);
    // A refused write records the attempt and changes nothing.
    iam.refuseOnce = 403;
    const refused = await driveEffect(ledger, iam, "q", (await ledger.readEntry("q", 3))!, targets[2]!);
    expect(refused).toMatchObject({ kind: "pending", reason: "setIamPolicy refused with HTTP 403" });
    expect(refused.entry.progress).toMatchObject({ state: "PREPARED", attempts: 1 });
    expect(iam.writes.filter((write) => write.resource === targets[2]!.resource)).toHaveLength(0);
    await broker.reconcileShard("q");
    expect((await ledger.readEntry("q", 3))!.progress).toMatchObject({ state: "ACKED", attempts: 2 });
    // Two instances reconciling the same shard land exactly one write per target and record each observation once per instance at most.
    expect((await ledger.append(quarantine("q2", "cdbentley", "k2"), targets)).kind).toBe("accepted");
    seedTargets(iam, targets);
    const writesBefore = iam.writes.length;
    await Promise.all([broker.reconcileShard("q2"), w.anotherInstance().broker.reconcileShard("q2")]);
    expect(iam.writes.length - writesBefore).toBe(9);
    expect((await entriesOf(w, "q2")).filter((entry) => entry.body.kind === "effect").every((entry) => entry.progress?.state === "ACKED")).toBe(true);
  }, 60_000);

  test("a paused QUARANTINE actuator that resumes after a takeover and a RESTORE is stale and changes nothing", async () => {
    const w = await setup();
    const { broker, iam, ledger, targets } = w;
    const target = targets[0]!;
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    const paused = gate();
    iam.beforeWrite = paused.wait;
    const stale = driveEffect(ledger, iam, "q", (await ledger.readEntry("q", 1))!, target);
    await Bun.sleep(200);
    expect((await ledger.readEntry("q", 1))!.progress).toMatchObject({ state: "PREPARED", attempts: 1 });
    // The takeover finishes the same prepared operation, the shard becomes ready and closes, and a restore returns the policy to its original content.
    await makeReady(w, "q");
    expect((await beginClose(w, "q", "c")).kind).toBe("closing");
    await broker.reconcileShard("q");
    expect((await ledger.append(restore("r", "cdbentley", "k2", "q"), targets, await freshOf(w, "q"))).kind).toBe("accepted");
    await broker.reconcileShard("r");
    const restoredPolicy = iam.policies.get(target.resource)!;
    const writesBefore = iam.writes.length;
    const actuatorBefore = await ledger.readActuator(target.uniqueId);
    paused.release();
    const outcome = await stale;
    expect(outcome.kind).toBe("stale");
    expect(iam.policies.get(target.resource)).toBe(restoredPolicy);
    expect(iam.writes).toHaveLength(writesBefore);
    expect(await ledger.readActuator(target.uniqueId)).toEqual(actuatorBefore);
    expect((await ledger.readEntry("q", 1))!.progress).toMatchObject({ state: "ACKED", attempts: 2 });
    expect((await ledger.readEntry("r", 1))!.progress).toMatchObject({ state: "ACKED", epoch: 2 });
    // A worker paused between its read and its PREPARE is equally stale.
    expect((await ledger.append(quarantine("q2", "cdbentley", "k3"), targets)).kind).toBe("accepted");
    const pausedRead = gate();
    iam.beforeRead = pausedRead.wait;
    const slow = driveEffect(ledger, iam, "q2", (await ledger.readEntry("q2", 1))!, target);
    await Bun.sleep(200);
    await broker.reconcileShard("q2");
    pausedRead.release();
    expect((await slow).kind).toBe("stale");
    expect(iam.writes.filter((write) => write.resource === target.resource)).toHaveLength(3);
  }, 60_000);

  test("the stale actuator is fenced by the etag alone: a non-fencing API would let the stale write land, which the live canary must rule out", async () => {
    const w = await setup();
    const { broker, iam, ledger, targets } = w;
    const target = targets[0]!;
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    const paused = gate();
    iam.beforeWrite = paused.wait;
    const stale = driveEffect(ledger, iam, "q", (await ledger.readEntry("q", 1))!, target);
    await Bun.sleep(200);
    await makeReady(w, "q");
    expect((await beginClose(w, "q", "c")).kind).toBe("closing");
    await broker.reconcileShard("q");
    expect((await ledger.append(restore("r", "cdbentley", "k2", "q"), targets, await freshOf(w, "q"))).kind).toBe("accepted");
    await broker.reconcileShard("r");
    const restoredContent = contentOf(w, target.resource);
    iam.enforceEtag = false;
    paused.release();
    expect((await stale).kind).toBe("stale");
    // The ledger recorded nothing for the stale actuator, but the resource silently regressed.
    expect((await ledger.readEntry("r", 1))!.progress).toMatchObject({ state: "ACKED" });
    expect(contentOf(w, target.resource).hash).not.toBe(restoredContent.hash);
  }, 60_000);

  test("opposite-direction contention: a QUARANTINE waits until the prepared RESTORE on the same identity is reconciled", async () => {
    const w = await setup();
    const { broker, iam, ledger, targets } = w;
    const target = targets[0]!;
    await quarantineAndClose(w, "q0");
    expect((await ledger.append(restore("r0", "cdbentley", "r0-k", "q0"), targets, await freshOf(w, "q0"))).kind).toBe("accepted");
    const paused = gate();
    iam.beforeWrite = paused.wait;
    const restoring = driveEffect(ledger, iam, "r0", (await ledger.readEntry("r0", 1))!, target);
    await Bun.sleep(200);
    expect((await ledger.append(quarantine("q1", "cdbentley", "q1-k"), targets)).kind).toBe("accepted");
    const contended = await driveEffect(ledger, iam, "q1", (await ledger.readEntry("q1", 1))!, target);
    expect(contended).toMatchObject({ kind: "pending", reason: "actuator held by r0/1" });
    expect((await ledger.readEntry("q1", 1))!.progress).toEqual({ state: "RECORDED" });
    expect(iam.writes.filter((write) => write.resource === target.resource)).toHaveLength(1);
    paused.release();
    expect((await restoring).kind).toBe("acked");
    expect((await driveEffect(ledger, iam, "q1", (await ledger.readEntry("q1", 1))!, target)).kind).toBe("acked");
    const writes = iam.writes.filter((write) => write.resource === target.resource);
    expect(writes).toHaveLength(3);
    expect(writes.map((write) => write.bindings.some((binding) => binding.role === managedRole))).toEqual([false, true, false]);
    expect((await ledger.readEntry("q1", 1))!.progress).toMatchObject({ state: "ACKED", epoch: 3 });
    // The rest of q1 completes and the second restore is refused until q1 closes.
    await broker.reconcileShard("r0");
    await broker.reconcileShard("q1");
    expect((await entriesOf(w, "q1")).filter((entry) => entry.body.kind === "effect").every((entry) => entry.progress?.state === "ACKED")).toBe(true);
  }, 60_000);
});
