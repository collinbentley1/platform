import { describe, expect, test } from "bun:test";
import { type MemberCredentialSource, type Policy, type ProbeRequest, GoogleIssuanceProbe, LedgerMemberCredentials, driveEffect, expectedSnapshot, observedSnapshot, planEffect, policyFromJson, verifyMemberCredential } from "../src/effects";
import { Broker } from "../src/http";
import { type Target, consumerPool, managedRole, probePermission, probePrerequisite, purposeForIdentity, scanReadiness, targetsFor } from "../src/model";
import { entryEvidence } from "../src/outbox";
import { type World, Clock, beginClose, close, emulatorHost, freshOf, gate, githubSigner, invokerEmail, makeReady, memberClaims, needsOf, proberPrincipal, quarantine, restore, seedTargets, testAuthority, unrelatedBindings, world } from "./support";

const pool = "projects/882468538648/locations/global/workloadIdentityPools/github-actions";
const member = (sha: string) => `principalSet://iam.googleapis.com/${pool}/attribute.authority/collinbentley1/cdbentley/.github/workflows/deploy-prod.yml@refs/heads/main:collinbentley1/platform/.github/workflows/infrastructure.yml@${sha}:${sha}:production:push`;
const target: Target = { account: "gha-terraform", email: "gha-terraform@cdbentley.iam.gserviceaccount.com", members: [member("a".repeat(40)), member("b".repeat(40))], pool, resource: "projects/cdbentley/serviceAccounts/101080000000000000000", uniqueId: "101080000000000000000" };
const policy = (bindings: Policy["bindings"], etag = "e1"): Policy => policyFromJson({ bindings, etag, version: 1 });
// Every managed member of every target, in the order the broker probes them.
const membersOf = (targets: readonly Target[]) => targets.flatMap((candidate) => candidate.members.map((managed) => [candidate, managed] as const));

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

const endpoints = { credentials: "https://credentials.test", sts: "https://sts.test" };
const iamDenial = { error: { code: 403, details: [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo", domain: "iam.googleapis.com", metadata: { permission: probePermission }, reason: "IAM_PERMISSION_DENIED" }], message: `Permission '${probePermission}' denied on resource (or it may not exist).`, status: "PERMISSION_DENIED" } };

// Stand-ins for STS and IAM Credentials: STS exchanges exactly the tokens it
// knows for a federated token naming the member; generateAccessToken answers
// per unique ID, ALLOWED unless the identity is set to deny or fail.
function googleIssuance(tokens: () => ReadonlyMap<string, string>, provider: string) {
  const calls: Array<{ readonly bearer: string | undefined; readonly url: string }> = [];
  const denied = new Set<string>();
  const failing = new Map<string, number>();
  let stsStatus = 200;
  let denial: unknown = iamDenial;
  const fetcher = router((url, init) => {
    const headers = init.headers as Record<string, string> | undefined;
    calls.push({ bearer: headers?.Authorization, url });
    if (url === `${endpoints.sts}/v1/token`) {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      const owner = [...tokens().entries()].find(([, token]) => token === body.subjectToken)?.[0];
      if (owner === undefined || body.audience !== `//iam.googleapis.com/${provider}` || body.grantType !== "urn:ietf:params:oauth:grant-type:token-exchange") return json(400, { error: "invalid_request" });
      return json(stsStatus, stsStatus === 200 ? { access_token: `federated:${owner}`, expires_in: 3599, issued_token_type: "urn:ietf:params:oauth:token-type:access_token", token_type: "Bearer" } : { error: "invalid_grant" });
    }
    if (!headers?.Authorization?.startsWith("Bearer federated:")) return json(401, { error: { status: "UNAUTHENTICATED" } });
    const mint = /^https:\/\/credentials\.test\/v1\/projects\/-\/serviceAccounts\/([0-9]+):generateAccessToken$/.exec(url);
    if (!mint) return json(404, { error: { status: "NOT_FOUND" } });
    const uniqueId = mint[1]!;
    const fails = failing.get(uniqueId) ?? 0;
    if (fails > 0) {
      failing.set(uniqueId, fails - 1);
      return json(503, { error: { status: "UNAVAILABLE" } });
    }
    return denied.has(uniqueId) ? json(403, denial) : json(200, { accessToken: "never-retained", expireTime: "2026-09-04T12:05:00Z" });
  });
  return { calls, denied, failing, fetcher, setDenial: (value: unknown) => (denial = value), setSts: (status: number) => (stsStatus = status) };
}

describe("issuance probe", () => {
  test("the positive control mints as every managed member through STS and IAM Credentials and discards the token; the probe uses the same endpoint; the principal is the provider's mapped subject", async () => {
    const authority = await testAuthority();
    const consumer = authority.consumers.find((candidate) => candidate.repository === "cdbentley")!;
    const probed = targetsFor(authority, consumer)![0]!;
    expect(probed.members.length).toBeGreaterThan(1);
    const provider = `${consumerPool(authority, consumer)}/providers/${authority.broker.workloadIdentityProviderId}`;
    const signer = await githubSigner();
    const clock = new Clock();
    const nowSeconds = Math.floor(clock.now.getTime() / 1000);
    const tokens = new Map<string, string>();
    for (const [index, managed] of probed.members.entries()) tokens.set(managed, await signer.sign(memberClaims(authority, consumer, managed, nowSeconds, String(1000 + index))));
    const credentials: MemberCredentialSource = { oidcTokenFor: async (requested) => (tokens.has(requested) ? { kind: "token", token: tokens.get(requested)! } : { kind: "unavailable", reason: probePrerequisite(requested) }) };
    const issuance = googleIssuance(() => tokens, provider);
    const probe = new GoogleIssuanceProbe({ authority, credentials, endpoints, fetch: issuance.fetcher, jwks: async () => signer.jwks, now: clock.read });
    const principalOf = (index: number) => `principal://iam.googleapis.com/${probed.pool}/subject/${authority.githubOwnerId}:${consumer.repositoryId}:github-hosted:${1000 + index}`;
    // The positive control: one STS exchange and one actual generateAccessToken per member, all of them minting.
    expect(await probe.preflight([probed])).toEqual({ kind: "operational", principals: { [probed.account]: Object.fromEntries(probed.members.map((managed, index) => [managed, principalOf(index)])) } });
    expect(issuance.calls.map((call) => call.url)).toEqual(probed.members.flatMap(() => [`${endpoints.sts}/v1/token`, `${endpoints.credentials}/v1/projects/-/serviceAccounts/${probed.uniqueId}:generateAccessToken`]));
    // The recorded principal is never the raw GitHub subject; it is the provider's numeric subject mapping.
    const verified = await verifyMemberCredential({ authority, jwks: async () => signer.jwks, now: clock.read }, tokens.get(probed.members[0]!)!);
    expect(verified).toEqual({ kind: "verified", consumer, expiresAt: new Date((nowSeconds + 300) * 1000).toISOString(), member: probed.members[0]!, principal: principalOf(0) });
    expect(principalOf(0)).not.toContain("repo:");
    // A member that cannot mint, or whose endpoint fails, makes the positive control unavailable, naming that member.
    issuance.denied.add(probed.uniqueId);
    expect(await probe.preflight([probed])).toMatchObject({ kind: "unavailable", reason: expect.stringContaining(`${probed.account}/${probed.members[0]}: generateAccessToken answered HTTP 403; the member cannot mint for ${probed.uniqueId}`) });
    issuance.denied.delete(probed.uniqueId);
    issuance.failing.set(probed.uniqueId, 1);
    expect(await probe.preflight([probed])).toMatchObject({ kind: "unavailable", reason: expect.stringContaining("generateAccessToken answered HTTP 503") });
    // Issuance is ALLOWED while the binding stands and DENIED once IAM refuses exactly the probe permission, for any member.
    const request: ProbeRequest = { email: probed.email, member: probed.members[1]!, permission: probePermission, resource: probed.resource, uniqueId: probed.uniqueId };
    expect(await probe.probe(request)).toEqual({ kind: "observed", observedAt: clock.now.toISOString(), outcome: "ALLOWED", principal: principalOf(1) });
    issuance.denied.add(probed.uniqueId);
    clock.advance(5);
    expect(await probe.probe(request)).toEqual({ kind: "observed", observedAt: clock.now.toISOString(), outcome: "DENIED", principal: principalOf(1) });
    expect(issuance.calls.at(-1)!.url).toBe(`${endpoints.credentials}/v1/projects/-/serviceAccounts/${probed.uniqueId}:generateAccessToken`);
    // A denial of another permission, a denial without an IAM reason, or any other failure is unavailable.
    issuance.setDenial({ error: { code: 403, details: [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo", domain: "iam.googleapis.com", metadata: { permission: "iam.serviceAccounts.actAs" }, reason: "IAM_PERMISSION_DENIED" }], message: "Permission 'iam.serviceAccounts.actAs' denied on resource.", status: "PERMISSION_DENIED" } });
    expect(await probe.probe(request)).toMatchObject({ kind: "unavailable", reason: expect.stringContaining("without an IAM denial") });
    issuance.setDenial({ error: { code: 403, message: "The caller does not have permission", status: "PERMISSION_DENIED" } });
    expect(await probe.probe(request)).toMatchObject({ kind: "unavailable" });
    issuance.setDenial({ error: { code: 403, message: "Permission 'iam.serviceAccounts.getAccessToken' denied on resource (or it may not exist).", status: "PERMISSION_DENIED" } });
    expect(await probe.probe(request)).toMatchObject({ kind: "observed", outcome: "DENIED" });
    issuance.setSts(400);
    expect(await probe.probe(request)).toMatchObject({ kind: "unavailable", reason: "STS refused the member credential with HTTP 400" });
    issuance.setSts(200);
    // A credential that is any other identity is refused before STS is ever called for it: another environment,
    // another repository, another audience, an expired token, another issuer, no run, or a signature GitHub's keys do
    // not verify. The positive control still mints as the other, valid member and is unavailable as a whole.
    const claims = memberClaims(authority, consumer, probed.members[1]!, nowSeconds, "1001");
    const refusals: Array<[Record<string, unknown>, string]> = [
      [{ ...claims, environment: "elsewhere" }, "binds to no target"],
      [{ ...claims, repository_id: "999" }, "outside the consumer repository"],
      [{ ...claims, runner_environment: "self-hosted" }, "outside the consumer repository"],
      [{ ...claims, aud: "https://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/other/providers/github" }, "not minted for the consumer provider audience"],
      [{ ...claims, exp: nowSeconds - 3600 }, "has expired"],
      [{ ...claims, iss: "https://evil.example" }, "not issued by GitHub Actions"],
      [{ ...claims, run_id: undefined }, "lacks the run or the authority claims"],
    ];
    for (const [payload, reason] of refusals) {
      tokens.set(probed.members[1]!, await signer.sign(payload));
      const at = issuance.calls.length;
      expect(await probe.probe(request), reason).toMatchObject({ kind: "unavailable", reason: expect.stringContaining(reason) });
      expect(issuance.calls.length, reason).toBe(at);
      expect(await probe.preflight([probed]), reason).toMatchObject({ kind: "unavailable", reason: expect.stringContaining(`${probed.account}/${probed.members[1]}: `) });
      expect(issuance.calls.slice(at).every((call) => call.bearer === undefined || call.bearer === `Bearer federated:${probed.members[0]}`), reason).toBe(true);
    }
    // A credential of another member of the same consumer is refused for this member, and a signature GitHub's keys
    // do not verify is refused before anything is called.
    const before = issuance.calls.length;
    tokens.set(probed.members[1]!, tokens.get(probed.members[0]!)!);
    expect(await probe.probe(request)).toMatchObject({ kind: "unavailable", reason: expect.stringContaining("not the probed member") });
    const foreign = await crypto.subtle.generateKey({ hash: "SHA-256", modulusLength: 2048, name: "RSASSA-PKCS1-v1_5", publicExponent: new Uint8Array([1, 0, 1]) }, true, ["sign", "verify"]);
    tokens.set(probed.members[1]!, await signer.signWith(claims, foreign.privateKey));
    expect(await probe.probe(request)).toMatchObject({ kind: "unavailable", reason: "the member credential is not a GitHub-signed RS256 token" });
    expect(issuance.calls.length).toBe(before);
    // Without a delivered credential every preflight and probe is unavailable, naming the member and the channel.
    const undelivered = new GoogleIssuanceProbe({ authority, credentials: { oidcTokenFor: async (requested) => ({ kind: "unavailable", reason: probePrerequisite(requested) }) }, endpoints, fetch: issuance.fetcher, jwks: async () => [], now: clock.read });
    expect(await undelivered.preflight([probed])).toEqual({ kind: "unavailable", reason: probed.members.map((managed) => `${probed.account}/${managed}: ${probePrerequisite(managed)}`).join("; ") });
    expect(await undelivered.probe(request)).toEqual({ kind: "unavailable", reason: probePrerequisite(request.member) });
    expect(issuance.calls.length).toBe(before);
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
  test("an exact policy A -> B -> A cycle: quarantine, inventory baseline, two probe phases for every managed member, protected close, terminal projection, then a separately journaled restore", async () => {
    const w = await setup();
    const { broker, evidence, iam, ledger, probe, targets } = w;
    const members = membersOf(targets);
    expect(members.length).toBe(35);
    const before = new Map(targets.map((candidate) => [candidate.resource, contentOf(w, candidate.resource)]));
    expect((await ledger.append(quarantine("q1", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    const view = await broker.reconcileShard("q1");
    expect(view).toMatchObject({ notes: [], pendingEffects: 0, pendingOutbox: 0, phase: "OPEN" });
    const acked = await entriesOf(w, "q1");
    expect(acked).toHaveLength(18 + members.length);
    for (const [index, candidate] of targets.entries()) {
      const entry = acked[index]!;
      if (entry.progress?.state !== "ACKED") throw new Error(`${candidate.account} is ${entry.progress?.state}`);
      expect(entry.body).toMatchObject({ email: candidate.email, resource: `projects/cdbentley/serviceAccounts/${candidate.uniqueId}`, uniqueId: candidate.uniqueId });
      expect(entry.progress.before).toEqual(before.get(candidate.resource)!);
      expect(entry.progress.observed.hash).toBe(entry.progress.after.hash);
      expect(entry.progress.observed.etag).not.toBe(entry.progress.before.etag);
      expect(entry.progress).toMatchObject({ alternateIssuers: [], attempts: 1, effectId: `q1/${index + 1}`, epoch: 1, mutated: true });
      expect(iam.policies.get(candidate.resource)!.bindings).toEqual(policyFromJson({ bindings: unrelatedBindings, etag: "x" }).bindings);
      expect(entry.outbox.state).toBe("PROJECTED");
      expect(evidence.objects.get(entry.objectName)!.bytes).toEqual(entryEvidence("q1", entry));
      expect(await ledger.readActuator(candidate.uniqueId)).toEqual({ epoch: 1, holder: null, lastEtag: entry.progress.observed.etag });
    }
    expect(iam.writes).toHaveLength(9);
    // The same reconcile recorded the inventory baseline of every target and then one revocation probe per managed
    // member of every target from the probe source, each bound to the exact identity and member; the shard mirrors
    // every member's chain.
    expect(probe.requests).toHaveLength(members.length);
    expect(probe.requests.map((request) => [request.uniqueId, request.member])).toEqual(members.map(([candidate, managed]) => [candidate.uniqueId, managed]));
    expect(probe.requests[0]).toEqual({ email: targets[0]!.email, member: targets[0]!.members[0]!, permission: probePermission, resource: targets[0]!.resource, uniqueId: targets[0]!.uniqueId });
    const shardAfterFirstPass = (await ledger.readShard("q1"))!;
    for (const [index, candidate] of targets.entries()) {
      const inventory = acked[9 + index]!;
      expect(inventory.body).toMatchObject({ kind: "inventory", account: candidate.account, email: candidate.email, findings: [], observedAt: w.clock.now.toISOString(), uniqueId: candidate.uniqueId });
      expect(inventory.outbox.state).toBe("PROJECTED");
      const state = shardAfterFirstPass.targets[candidate.account]!;
      expect(state).toMatchObject({ effect: { ackedAt: w.clock.now.toISOString(), alternateIssuers: [], state: "ACKED" }, sequence: index + 1 });
      expect(state.chain).toMatchObject({ inventory: { changes: 0, findings: [], hash: inventory.body.kind === "inventory" ? inventory.body.hash : "", observations: 1 }, journaled: 1 + candidate.members.length, suppressed: 0 });
      expect(Object.keys(state.chain.members).sort()).toEqual([...candidate.members].sort());
      for (const managed of candidate.members) expect(state.chain.members[managed]).toMatchObject({ allowed: { count: 0, lastObservedAt: null }, denied: 1, post: null, revocation: { member: managed, outcome: "DENIED", phase: "REVOCATION" } });
    }
    for (const [index, [candidate, managed]] of members.entries()) {
      expect(acked[18 + index]!.body).toEqual({ kind: "probe", account: candidate.account, email: candidate.email, member: managed, observedAt: w.clock.now.toISOString(), outcome: "DENIED", permission: probePermission, phase: "REVOCATION", principal: proberPrincipal, uniqueId: candidate.uniqueId });
      expect(acked[18 + index]!.outbox.state).toBe("PROJECTED");
    }
    // Not ready until every member's horizon drains and its post-horizon probe is recorded; close is refused until then.
    const horizonAt = new Date(w.clock.now.getTime() + 3600 * 1000).toISOString();
    expect(await readinessOf(w, "q1")).toEqual({ blockers: members.map(([candidate, managed]) => `${candidate.account}: token horizon of ${managed} drains at ${horizonAt}`), horizonAt, ready: false });
    expect(await beginClose(w, "q1", "c0")).toMatchObject({ kind: "rejected", rejection: { reason: "NOT_READY" } });
    w.clock.advance(3600);
    await broker.reconcileShard("q1");
    expect(probe.requests).toHaveLength(2 * members.length);
    expect(await readinessOf(w, "q1")).toEqual({ blockers: [], horizonAt, ready: true });
    // The re-observed inventory was equal: no entry, the baseline re-verified.
    expect((await ledger.readShard("q1"))!.targets[targets[0]!.account]!.chain.inventory).toMatchObject({ changes: 0, observations: 2, verifiedAt: w.clock.now.toISOString() });
    // Managed bindings stay absent through the protected close and the terminal projection.
    expect((await beginClose(w, "q1", "c1")).kind).toBe("closing");
    const closed = await broker.reconcileShard("q1");
    const highWater = 18 + 2 * members.length;
    expect(closed).toMatchObject({ phase: "CLOSED", terminal: { generation: String(highWater + 1), state: "PROJECTED" } });
    const shard = (await ledger.readShard("q1"))!;
    if (shard.phase !== "CLOSED") throw new Error();
    expect(new TextDecoder().decode(evidence.objects.get(shard.terminal.objectName)!.bytes)).toBe(shard.terminal.receipt);
    const receipt = JSON.parse(shard.terminal.receipt) as { targets: Record<string, { chain: { inventory: { hash: string; summary: unknown }; members: Record<string, { post: unknown; revocation: unknown }>; suppressed: number } }> };
    expect(receipt).toMatchObject({ closeHighWater: highWater, consumer: "cdbentley", intent: "QUARANTINE", readiness: { blockers: [], horizonAt, ready: true }, shard: "q1" });
    for (const [candidate, managed] of members) {
      expect(receipt.targets[candidate.account]!.chain.members[managed]).toMatchObject({ post: { member: managed, phase: "HORIZON" }, revocation: { member: managed, phase: "REVOCATION" } });
    }
    // The receipt carries the preimage of every target's readiness hash: the inventory summary itself.
    expect(receipt.targets[targets[0]!.account]!.chain).toMatchObject({ inventory: { hash: (acked[9]!.body as { hash: string }).hash, summary: (acked[9]!.body as { summary: unknown }).summary }, suppressed: 0 });
    expect(iam.writes).toHaveLength(9);
    expect(probe.requests).toHaveLength(2 * members.length);
    // Restore is its own journal with its own receipt, restoring exactly the captured members on exactly the captured
    // identities, admitted only against the source's freshly observed inventory; it admits no probe.
    expect((await ledger.append(restore("r1", "cdbentley", "k2", "q1"), targets, await freshOf(w, "q1"))).kind).toBe("accepted");
    expect(await ledger.recordProbe("r1", { account: targets[0]!.account, email: targets[0]!.email, member: targets[0]!.members[0]!, observedAt: w.clock.now.toISOString(), outcome: "DENIED", permission: probePermission, phase: "REVOCATION", principal: proberPrincipal, uniqueId: targets[0]!.uniqueId })).toEqual({ kind: "refused", reason: "probes belong to QUARANTINE shards only" });
    await broker.reconcileShard("r1");
    const restored = await entriesOf(w, "r1");
    expect(restored).toHaveLength(9);
    for (const [index, candidate] of targets.entries()) {
      const entry = restored[index]!;
      if (entry.progress?.state !== "ACKED") throw new Error(`${candidate.account} restore is ${entry.progress?.state}`);
      expect(entry.body).toMatchObject({ email: candidate.email, intent: "RESTORE", resource: candidate.resource, uniqueId: candidate.uniqueId });
      const original = before.get(candidate.resource)!;
      expect(entry.progress.after.hash).toBe(original.hash);
      expect(entry.progress.observed.hash).toBe(original.hash);
      expect(entry.progress.observed.etag).not.toBe(original.etag);
      expect(entry.progress.before.etag).toBe(acked[index]!.progress!.state === "ACKED" ? (acked[index]!.progress as { observed: { etag: string } }).observed.etag : "");
      expect(entry.progress.epoch).toBe(2);
      expect(contentOf(w, candidate.resource).policy).toBe(original.policy);
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
  }, 120_000);

  test("scan-ready needs an inventory baseline and, for every managed member of every target, a DENIED probe after acknowledgement, a drained one-hour horizon, and another DENIED probe after it", async () => {
    const w = await setup();
    const { broker, clock, ledger, probe, targets } = w;
    const members = membersOf(targets);
    // A one-hour token minted one second before the quarantine lands must keep the shard unready until it expires.
    const mintedAt = clock.now.getTime();
    clock.advance(1);
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    expect(await readinessOf(w, "q")).toMatchObject({ horizonAt: null, ready: false });
    expect((await readinessOf(w, "q")).blockers).toEqual(targets.map((candidate) => `${candidate.account}: quarantine is RECORDED`));
    await broker.reconcileShard("q");
    const tokenExpiry = mintedAt + 3600 * 1000;
    const horizon = clock.now.getTime() + 3600 * 1000;
    const horizonAt = new Date(horizon).toISOString();
    expect(horizon).toBeGreaterThanOrEqual(tokenExpiry);
    expect(probe.requests).toHaveLength(members.length);
    expect(await readinessOf(w, "q")).toEqual({ blockers: members.map(([candidate, managed]) => `${candidate.account}: token horizon of ${managed} drains at ${horizonAt}`), horizonAt, ready: false });
    // Before the horizon no post-horizon probe is taken, and none would be admitted as one.
    clock.now = new Date(tokenExpiry - 1000);
    await broker.reconcileShard("q");
    expect(probe.requests).toHaveLength(members.length);
    expect((await readinessOf(w, "q")).ready).toBe(false);
    clock.now = new Date(horizon - 1000);
    await broker.reconcileShard("q");
    expect(probe.requests).toHaveLength(members.length);
    expect(await needsOf(w, "q", targets)).toEqual([]);
    expect((await readinessOf(w, "q")).ready).toBe(false);
    const early = targets[0]!;
    expect(await ledger.recordProbe("q", { account: early.account, email: early.email, member: early.members[0]!, observedAt: new Date(horizon).toISOString(), outcome: "DENIED", permission: probePermission, phase: "HORIZON", principal: proberPrincipal, uniqueId: early.uniqueId })).toMatchObject({ kind: "refused", reason: "the observation is in the ledger's future" });
    // A DENIED observation before the horizon is journaled but counts for nothing.
    expect(await ledger.recordProbe("q", { account: early.account, email: early.email, member: early.members[0]!, observedAt: clock.now.toISOString(), outcome: "DENIED", permission: probePermission, phase: "HORIZON", principal: proberPrincipal, uniqueId: early.uniqueId })).toMatchObject({ kind: "recorded", role: "REDUNDANT" });
    expect((await ledger.readShard("q"))!.targets[early.account]!.chain.members[early.members[0]!]).toMatchObject({ denied: 2, post: null });
    // A member's post-horizon probe is admitted only for that member; the other members still need theirs.
    clock.now = new Date(horizon);
    expect(await needsOf(w, "q", targets)).toEqual(members.map(([candidate, managed]) => ({ account: candidate.account, email: candidate.email, member: managed, notBefore: horizonAt, phase: "HORIZON", resource: candidate.resource, uniqueId: candidate.uniqueId })));
    expect(await readinessOf(w, "q")).toEqual({ blockers: members.map(([candidate, managed]) => `${candidate.account}: no DENIED impersonation probe of ${managed} after the token horizon ${horizonAt}`), horizonAt, ready: false });
    expect(await ledger.recordProbe("q", { account: early.account, email: early.email, member: early.members[0]!, observedAt: clock.now.toISOString(), outcome: "DENIED", permission: probePermission, phase: "HORIZON", principal: proberPrincipal, uniqueId: early.uniqueId })).toMatchObject({ kind: "recorded", role: "HORIZON" });
    expect((await readinessOf(w, "q")).blockers).toEqual(members.filter(([candidate, managed]) => !(candidate === early && managed === early.members[0])).map(([candidate, managed]) => `${candidate.account}: no DENIED impersonation probe of ${managed} after the token horizon ${horizonAt}`));
    // At the horizon the broker records every remaining member's post-horizon probe and the shard is ready; time alone never made it so.
    await broker.reconcileShard("q");
    expect(probe.requests).toHaveLength(2 * members.length - 1);
    expect(await readinessOf(w, "q")).toEqual({ blockers: [], horizonAt, ready: true });
    // The readiness is reported on the caller-facing view.
    const view = await broker.handle({ kind: "reconciler", serviceAccount: "recovery-reconciler" }, { kind: "read", shard: "q" });
    expect((view.body.shard as { scanReady: unknown }).scanReady).toEqual({ blockers: [], horizonAt, ready: true });
  }, 120_000);

  test("an ALLOWED observation restarts only that member's chain, and an unreachable source records nothing", async () => {
    const w = await setup();
    const { broker, clock, ledger, probe, targets } = w;
    const members = membersOf(targets);
    const [first, second] = [targets[0]!, targets[1]!];
    expect(first.members.length).toBeGreaterThan(1);
    // Only the first member of the first target keeps minting; the same tuple is a member of other targets too, and
    // those chains are untouched.
    const lingering = first.members[0]!;
    expect(targets.filter((candidate) => candidate.members.includes(lingering)).length).toBeGreaterThan(1);
    probe.outcomes.set(`${first.uniqueId}|${lingering}`, "ALLOWED");
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    await broker.reconcileShard("q");
    expect(probe.requests).toHaveLength(members.length);
    let readiness = await readinessOf(w, "q");
    expect(readiness.horizonAt).toBeNull();
    expect(readiness.blockers).toEqual([`${first.account}: no DENIED impersonation probe of ${lingering} after the quarantine acknowledgement`, ...members.filter(([candidate, managed]) => !(candidate === first && managed === lingering)).map(([candidate, managed]) => `${candidate.account}: token horizon of ${managed} drains at ${new Date(clock.now.getTime() + 3600 * 1000).toISOString()}`)]);
    expect((await ledger.readShard("q"))!.targets[first.account]!.chain.members[lingering]).toMatchObject({ allowed: { count: 1, lastObservedAt: clock.now.toISOString() }, revocation: null });
    expect((await ledger.readShard("q"))!.targets[first.account]!.chain.members[first.members[1]!]).toMatchObject({ allowed: { count: 0 }, revocation: { outcome: "DENIED" } });
    // Still allowed ten minutes later: only that member is probed again, still blocked; every other member waits for its horizon.
    clock.advance(600);
    await broker.reconcileShard("q");
    expect(probe.requests).toHaveLength(members.length + 1);
    expect(probe.requests.at(-1)).toMatchObject({ member: lingering, uniqueId: first.uniqueId });
    // Denied at T+1200: the horizon of that member is one hour after that, later than every other member's.
    probe.outcomes.delete(`${first.uniqueId}|${lingering}`);
    clock.advance(600);
    await broker.reconcileShard("q");
    expect(probe.requests).toHaveLength(members.length + 2);
    const lateHorizon = clock.now.getTime() + 3600 * 1000;
    readiness = await readinessOf(w, "q");
    expect(readiness.horizonAt).toBe(new Date(lateHorizon).toISOString());
    expect(readiness.ready).toBe(false);
    // Every other member drains first and gets its post-horizon probe; the lingering member still blocks.
    clock.advance(2400);
    await broker.reconcileShard("q");
    expect(probe.requests).toHaveLength(2 * members.length + 1);
    readiness = await readinessOf(w, "q");
    expect(readiness.blockers).toEqual([`${first.account}: token horizon of ${lingering} drains at ${new Date(lateHorizon).toISOString()}`]);
    expect(await beginClose(w, "q", "c0")).toMatchObject({ kind: "rejected", rejection: { blockers: readiness.blockers, reason: "NOT_READY" } });
    clock.advance(1200);
    await broker.reconcileShard("q");
    expect(probe.requests).toHaveLength(2 * members.length + 2);
    expect((await readinessOf(w, "q")).ready).toBe(true);
    // A later ALLOWED observation of one member of a ready target restarts that member's chain alone: a fresh DENIED
    // probe and a fresh hour are required again for it, and the other members keep their completed chains.
    const restarted = second.members[0]!;
    expect(await ledger.recordProbe("q", { account: second.account, email: second.email, member: restarted, observedAt: clock.now.toISOString(), outcome: "ALLOWED", permission: probePermission, phase: "HORIZON", principal: proberPrincipal, uniqueId: second.uniqueId })).toMatchObject({ kind: "recorded", role: "ALLOWED" });
    readiness = await readinessOf(w, "q");
    expect(readiness).toMatchObject({ blockers: [`${second.account}: no DENIED impersonation probe of ${restarted} after the quarantine acknowledgement`], horizonAt: null, ready: false });
    expect(await beginClose(w, "q", "c1")).toMatchObject({ kind: "rejected", rejection: { reason: "NOT_READY" } });
    clock.advance(1);
    await broker.reconcileShard("q");
    expect(probe.requests).toHaveLength(2 * members.length + 3);
    expect(probe.requests.at(-1)).toMatchObject({ member: restarted, uniqueId: second.uniqueId });
    expect((await readinessOf(w, "q")).blockers).toEqual([`${second.account}: token horizon of ${restarted} drains at ${new Date(clock.now.getTime() + 3600 * 1000).toISOString()}`]);
    // An unreachable source records nothing, for any member.
    const u = await setup();
    expect((await u.ledger.append(quarantine("q", "cdbentley", "k1"), u.targets)).kind).toBe("accepted");
    u.probe.unavailable = members.length;
    const unavailable = await u.broker.reconcileShard("q");
    expect((unavailable as { notes: string[] }).notes).toEqual(members.map(([candidate]) => `${candidate.account}: REVOCATION probe unavailable; the probe source is unreachable`));
    expect((await entriesOf(u, "q")).filter((entry) => entry.body.kind === "probe")).toHaveLength(0);
    expect((await readinessOf(u, "q")).blockers).toEqual(members.map(([candidate, managed]) => `${candidate.account}: no DENIED impersonation probe of ${managed} after the quarantine acknowledgement`));
  }, 120_000);

  test("a QUARANTINE is refused before acceptance and before any effect is prepared while the probe source cannot mint as every member or an inventory is not clean; the delivered credentials of the canonical jobs are what make it operational", async () => {
    const w = await setup();
    const { broker, iam, inventory, ledger, probe, targets } = w;
    const purpose = isolate(w);
    // The positive control fails: refused before acceptance, nothing journaled, nothing read or written.
    probe.preflightUnavailable = 1;
    expect(await broker.handle(purpose, quarantine("q", "cdbentley", "k1"))).toEqual({ status: 409, body: { detail: "the probe source cannot act as the managed members", error: "PROBE_UNAVAILABLE" } });
    expect(await ledger.readShard("q")).toBeUndefined();
    expect(probe.preflights.at(-1)!.map((candidate) => candidate.uniqueId)).toEqual(targets.map((candidate) => candidate.uniqueId));
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
    // The production binding: the real issuance probe over the credentials the canonical jobs deliver. With none
    // delivered every member is unavailable, naming the channel: refused before acceptance, and a shard journaled by
    // any other route stays RECORDED and unwritten.
    const p = await setup();
    const consumer = p.authority.consumers.find((candidate) => candidate.repository === "cdbentley")!;
    const provider = `${consumerPool(p.authority, consumer)}/providers/${p.authority.broker.workloadIdentityProviderId}`;
    const signer = await githubSigner();
    const tokens = new Map<string, string>();
    const issuance = googleIssuance(() => tokens, provider);
    const production = new GoogleIssuanceProbe({ authority: p.authority, credentials: new LedgerMemberCredentials(p.ledger, p.clock.read), endpoints, fetch: issuance.fetcher, jwks: async () => signer.jwks, now: p.clock.read });
    const live = new Broker({ authority: p.authority, evidence: p.evidence, iam: p.iam, inventory: p.inventory, jwks: async () => signer.jwks, ledger: p.ledger, now: p.clock.read, probe: production });
    const members = membersOf(p.targets);
    const detail = members.map(([candidate, managed]) => `${candidate.account}/${managed}: ${probePrerequisite(managed)}`).join("; ");
    expect(await live.handle(isolate(p), quarantine("q", "cdbentley", "k1"))).toEqual({ status: 409, body: { detail, error: "PROBE_UNAVAILABLE" } });
    expect(await p.ledger.readShard("q")).toBeUndefined();
    expect((await p.ledger.append(quarantine("q", "cdbentley", "k1"), p.targets)).kind).toBe("accepted");
    const view = await live.reconcileShard("q");
    expect((view as { notes: string[] }).notes).toEqual(p.targets.map((_, index) => `${index + 1}: pending; not prepared because PROBE_UNAVAILABLE; ${detail}`));
    expect(p.iam.writes).toHaveLength(0);
    p.clock.advance(7200);
    await live.reconcileShard("q");
    expect(await readinessOf(p, "q")).toEqual({ blockers: p.targets.map((candidate) => `${candidate.account}: quarantine is RECORDED`), horizonAt: null, ready: false });
    expect(await beginClose(p, "q", "c")).toMatchObject({ kind: "rejected", rejection: { reason: "NOT_READY" } });
    // Every canonical job delivers its own credential through the consumer's member-delivery identity; another
    // consumer's identity cannot deliver it, and a credential of a member bound to no target is refused.
    const deliverer = purposeForIdentity(p.authority, "gha-member-cdbentley@recovery-test.iam.gserviceaccount.com")!;
    const other = purposeForIdentity(p.authority, "gha-member-runsetta@recovery-test.iam.gserviceaccount.com")!;
    const nowSeconds = Math.floor(p.clock.now.getTime() / 1000);
    for (const [index, [, managed]] of members.entries()) {
      const token = await signer.sign(memberClaims(p.authority, consumer, managed, nowSeconds, String(2000 + index)));
      if (index === 0) expect(await live.handle(other, { kind: "deliver", token })).toEqual({ status: 409, body: { detail: "the member credential is not minted for the consumer provider audience", error: "MEMBER_UNVERIFIED" } });
      expect(await live.handle(deliverer, { kind: "deliver", token })).toEqual({ status: 200, body: { expiresAt: new Date((nowSeconds + 300) * 1000).toISOString(), member: managed } });
      tokens.set(managed, token);
    }
    const unbound = await signer.sign({ ...memberClaims(p.authority, consumer, members[0]![1], nowSeconds), environment: "elsewhere" });
    expect(await live.handle(deliverer, { kind: "deliver", token: unbound })).toMatchObject({ status: 409, body: { detail: expect.stringContaining("binds to no target"), error: "MEMBER_UNVERIFIED" } });
    expect(await p.ledger.readMemberCredential(members[0]![1])).toMatchObject({ consumer: "cdbentley", member: members[0]![1], token: tokens.get(members[0]![1]) });
    // With every member's live credential the positive control mints as each of them: the RECORDED effects are prepared,
    // written, and acknowledged, and the revocation probes go through the same endpoint as every member.
    const mintCalls = () => issuance.calls.filter((call) => call.url.endsWith(":generateAccessToken")).length;
    await live.reconcileShard("q");
    expect(p.iam.writes).toHaveLength(9);
    expect(mintCalls()).toBe(2 * members.length);
    expect((await readinessOf(p, "q")).blockers.every((blocker) => blocker.includes("drains at"))).toBe(false);
    // The probes minted as every member after removal: ALLOWED, because the IAM stand-in keeps issuing; nothing is ready.
    expect((await p.ledger.readShard("q"))!.targets[p.targets[0]!.account]!.chain.members[p.targets[0]!.members[0]!]).toMatchObject({ allowed: { count: 1 }, revocation: null });
    // Once the credential expires the member is unavailable again, naming the channel.
    p.clock.advance(600);
    const expired = await live.reconcileShard("q");
    expect((expired as { notes: string[] }).notes).toContain(`${p.targets[0]!.account}: REVOCATION probe unavailable; ${probePrerequisite(p.targets[0]!.members[0]!)}`);
  }, 180_000);

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
    // Neither the alternate-issuer target nor the diverged target is probed; every member of the other seven is.
    expect(probe.requests.map((request) => request.uniqueId)).toEqual(membersOf(targets.filter((_, index) => index !== 1 && index !== 2)).map(([candidate]) => candidate.uniqueId));
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
  }, 120_000);

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
  }, 120_000);

  test("termination at each boundary reconciles to one exact outcome: reservation, PREPARE, landed write, ACK, entry outbox, terminal outbox", async () => {
    const w = await setup();
    const { broker, evidence, iam, ledger, targets } = w;
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    const entry = (sequence: number) => ledger.readEntry("q", sequence).then((found) => found!);
    const targetAt = (sequence: number) => targets[sequence - 1]!;
    // 1: died after reserving the actuator.
    expect(await ledger.reserveActuator("q", 1, targetAt(1).uniqueId)).toEqual({ kind: "reserved", effectId: "q/1", epoch: 1 });
    // 2: died after PREPARE, before any write (the read is real, the write never happens).
    iam.beforeWrite = async () => {
      throw new Error("the worker died before the write");
    };
    await expect(driveEffect(ledger, iam, "q", await entry(2), targetAt(2))).rejects.toThrow("died before the write");
    expect((await entry(2)).progress).toMatchObject({ state: "PREPARED", attempts: 1, epoch: 1 });
    // 3: died after the write landed, before reading the answer.
    iam.throwAfterWrite = true;
    await expect(driveEffect(ledger, iam, "q", await entry(3), targetAt(3))).rejects.toThrow("died after the write landed");
    expect((await entry(3)).progress).toMatchObject({ state: "PREPARED", attempts: 1 });
    // 4: acknowledged, died before the outbox projection.
    expect((await driveEffect(ledger, iam, "q", await entry(4), targetAt(4))).kind).toBe("acked");
    // 5: acknowledged and the evidence object created, died before recording it.
    expect((await driveEffect(ledger, iam, "q", await entry(5), targetAt(5))).kind).toBe("acked");
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
    expect(iam.writes.filter((write) => write.resource === targetAt(3).resource)).toHaveLength(1);
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
  }, 120_000);

  test("close stays CLOSING with no terminal receipt until pending work resolves, and a diverged terminal never becomes CLOSED", async () => {
    const w = await setup();
    const { broker, evidence, iam, ledger, targets } = w;
    const members = membersOf(targets);
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
    evidence.dropResponses = members.length;
    evidence.unavailableReads = members.length;
    await broker.reconcileShard("q");
    expect((await ledger.readShard("q"))!).toMatchObject({ pendingEffects: 0, pendingOutbox: members.length });
    expect((await beginClose(w, "q", "c")).kind).toBe("closing");
    evidence.unavailableReads = members.length;
    expect(await broker.reconcileShard("q")).toMatchObject({ pendingOutbox: members.length, phase: "CLOSING", terminal: null });
    expect(evidence.objects.has("shards/q/close.json")).toBe(false);
    // Pre-create the terminal object with foreign bytes: the close diverges and is never labelled CLOSED.
    expect((await evidence.create("shards/q/close.json", new TextEncoder().encode("forged\n"))).kind).toBe("created");
    expect(await broker.reconcileShard("q")).toMatchObject({ pendingOutbox: 0, phase: "FINALIZING", terminal: { generation: null, state: "DIVERGED" } });
    expect(await broker.reconcileShard("q")).toMatchObject({ phase: "FINALIZING", terminal: { state: "DIVERGED" } });
    expect(await ledger.append(restore("r", "cdbentley", "k2", "q"), targets, await freshOf(w, "q"))).toMatchObject({ kind: "rejected", rejection: { reason: "SOURCE_NOT_COMPLETE" } });
  }, 120_000);

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
  }, 120_000);

  test("a paused QUARANTINE actuator that resumes after a takeover and a RESTORE is stale and changes nothing", async () => {
    const w = await setup();
    const { broker, iam, ledger, targets } = w;
    const first = targets[0]!;
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    const paused = gate();
    iam.beforeWrite = paused.wait;
    const stale = driveEffect(ledger, iam, "q", (await ledger.readEntry("q", 1))!, first);
    await Bun.sleep(200);
    expect((await ledger.readEntry("q", 1))!.progress).toMatchObject({ state: "PREPARED", attempts: 1 });
    // The takeover finishes the same prepared operation, the shard becomes ready and closes, and a restore returns the policy to its original content.
    await makeReady(w, "q");
    expect((await beginClose(w, "q", "c")).kind).toBe("closing");
    await broker.reconcileShard("q");
    expect((await ledger.append(restore("r", "cdbentley", "k2", "q"), targets, await freshOf(w, "q"))).kind).toBe("accepted");
    await broker.reconcileShard("r");
    const restoredPolicy = iam.policies.get(first.resource)!;
    const writesBefore = iam.writes.length;
    const actuatorBefore = await ledger.readActuator(first.uniqueId);
    paused.release();
    const outcome = await stale;
    expect(outcome.kind).toBe("stale");
    expect(iam.policies.get(first.resource)).toBe(restoredPolicy);
    expect(iam.writes).toHaveLength(writesBefore);
    expect(await ledger.readActuator(first.uniqueId)).toEqual(actuatorBefore);
    expect((await ledger.readEntry("q", 1))!.progress).toMatchObject({ state: "ACKED", attempts: 2 });
    expect((await ledger.readEntry("r", 1))!.progress).toMatchObject({ state: "ACKED", epoch: 2 });
    // A worker paused between its read and its PREPARE is equally stale.
    expect((await ledger.append(quarantine("q2", "cdbentley", "k3"), targets)).kind).toBe("accepted");
    const pausedRead = gate();
    iam.beforeRead = pausedRead.wait;
    const slow = driveEffect(ledger, iam, "q2", (await ledger.readEntry("q2", 1))!, first);
    await Bun.sleep(200);
    await broker.reconcileShard("q2");
    pausedRead.release();
    expect((await slow).kind).toBe("stale");
    expect(iam.writes.filter((write) => write.resource === first.resource)).toHaveLength(3);
  }, 120_000);

  test("the stale actuator is fenced by the etag alone: a non-fencing API would let the stale write land, which the live canary must rule out", async () => {
    const w = await setup();
    const { broker, iam, ledger, targets } = w;
    const first = targets[0]!;
    expect((await ledger.append(quarantine("q", "cdbentley", "k1"), targets)).kind).toBe("accepted");
    const paused = gate();
    iam.beforeWrite = paused.wait;
    const stale = driveEffect(ledger, iam, "q", (await ledger.readEntry("q", 1))!, first);
    await Bun.sleep(200);
    await makeReady(w, "q");
    expect((await beginClose(w, "q", "c")).kind).toBe("closing");
    await broker.reconcileShard("q");
    expect((await ledger.append(restore("r", "cdbentley", "k2", "q"), targets, await freshOf(w, "q"))).kind).toBe("accepted");
    await broker.reconcileShard("r");
    const restoredContent = contentOf(w, first.resource);
    iam.enforceEtag = false;
    paused.release();
    expect((await stale).kind).toBe("stale");
    // The ledger recorded nothing for the stale actuator, but the resource silently regressed.
    expect((await ledger.readEntry("r", 1))!.progress).toMatchObject({ state: "ACKED" });
    expect(contentOf(w, first.resource).hash).not.toBe(restoredContent.hash);
  }, 120_000);

  test("opposite-direction contention: a QUARANTINE waits until the prepared RESTORE on the same identity is reconciled", async () => {
    const w = await setup();
    const { broker, iam, ledger, targets } = w;
    const first = targets[0]!;
    await quarantineAndClose(w, "q0");
    expect((await ledger.append(restore("r0", "cdbentley", "r0-k", "q0"), targets, await freshOf(w, "q0"))).kind).toBe("accepted");
    const paused = gate();
    iam.beforeWrite = paused.wait;
    const restoring = driveEffect(ledger, iam, "r0", (await ledger.readEntry("r0", 1))!, first);
    await Bun.sleep(200);
    expect((await ledger.append(quarantine("q1", "cdbentley", "q1-k"), targets)).kind).toBe("accepted");
    const contended = await driveEffect(ledger, iam, "q1", (await ledger.readEntry("q1", 1))!, first);
    expect(contended).toMatchObject({ kind: "pending", reason: "actuator held by r0/1" });
    expect((await ledger.readEntry("q1", 1))!.progress).toEqual({ state: "RECORDED" });
    expect(iam.writes.filter((write) => write.resource === first.resource)).toHaveLength(1);
    paused.release();
    expect((await restoring).kind).toBe("acked");
    expect((await driveEffect(ledger, iam, "q1", (await ledger.readEntry("q1", 1))!, first)).kind).toBe("acked");
    const writes = iam.writes.filter((write) => write.resource === first.resource);
    expect(writes).toHaveLength(3);
    expect(writes.map((write) => write.bindings.some((binding) => binding.role === managedRole))).toEqual([false, true, false]);
    expect((await ledger.readEntry("q1", 1))!.progress).toMatchObject({ state: "ACKED", epoch: 3 });
    // The rest of q1 completes and the second restore is refused until q1 closes.
    await broker.reconcileShard("r0");
    await broker.reconcileShard("q1");
    expect((await entriesOf(w, "q1")).filter((entry) => entry.body.kind === "effect").every((entry) => entry.progress?.state === "ACKED")).toBe(true);
  }, 120_000);
});
