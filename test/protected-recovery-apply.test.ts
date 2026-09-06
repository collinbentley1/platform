import { describe, expect, test } from "bun:test";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { denyMatrix, steadyFlags } from "../protected-recovery/src/deny";
import { type RecoveryAuthority, canonicalJson, sha256Hex } from "../protected-recovery/src/model";
import { activeSha, livePoliciesFromMatrix, testAuthority } from "../protected-recovery/test/support";
import { type ApplyDependencies, type ApplyLease, applyUnderLease, deploymentSnapshot, parseLease, readLeaseEvidence } from "../tools/ci/protected-recovery-apply";

const lease: ApplyLease = { key: "apply-11111111-1111-4111-8111-111111111111", planSha256: "a".repeat(64), openedAt: "2026-09-05T12:00:00.000Z", openedBy: "gha-restore-cdbentley@recovery-test.iam.gserviceaccount.com" };

function controller(edit: Partial<ApplyDependencies> = {}) {
  const events: string[] = [];
  const deps: ApplyDependencies = {
    acquire: async () => { events.push("acquire"); return lease; },
    read: async () => { events.push("read"); return lease; },
    release: async () => { events.push("release"); },
    snapshot: async () => { events.push("snapshot"); return "unchanged"; },
    apply: async () => { events.push("apply"); },
    ...edit,
  };
  return { events, run: () => applyUnderLease(deps, lease.key, lease.planSha256, lease.openedBy) };
}

describe("protected apply controller", () => {
  test("the durable lease encloses all reads, apply, and final verification", async () => {
    const session = controller();
    expect((await session.run()).lease).toEqual(lease);
    expect(session.events).toEqual(["acquire", "snapshot", "read", "apply", "read", "snapshot", "read", "release"]);
  });

  test("acquisition refusal or ambiguous response never starts an apply or releases", async () => {
    const session = controller({ acquire: async () => { throw new Error("conflict or lost response"); } });
    await expect(session.run()).rejects.toThrow();
    expect(session.events).toEqual([]);
  });

  test("another owner, key, or saved plan cannot authorize the apply", async () => {
    for (const changed of [{ ...lease, openedBy: "another-controller" }, { ...lease, key: "another-key" }, { ...lease, planSha256: "b".repeat(64) }]) {
      const session = controller({ acquire: async () => changed });
      await expect(session.run()).rejects.toThrow("does not bind");
      expect(session.events).toEqual([]);
    }
  });

  test("a missing or changed lease before the apply refuses all grants", async () => {
    for (const changed of [null, { ...lease, openedAt: "2026-09-05T13:00:00.000Z" }]) {
      const session = controller({ read: async () => changed });
      await expect(session.run()).rejects.toThrow("no longer owns");
      expect(session.events).toEqual(["acquire", "snapshot"]);
    }
  });

  test("failed apply, failed reread, and final drift leave the durable lease held", async () => {
    const applyFailure = controller({ apply: async () => { throw new Error("apply failed"); } });
    await expect(applyFailure.run()).rejects.toThrow("apply failed");
    expect(applyFailure.events).not.toContain("release");
    for (const outcome of ["drift", "unreadable"]) {
      let reads = 0;
      const session = controller({ snapshot: async () => {
        if (++reads === 1) return "unchanged";
        if (outcome === "unreadable") throw new Error("reread failed");
        return "changed";
      } });
      await expect(session.run()).rejects.toThrow();
      expect(session.events).toContain("apply");
      expect(session.events).not.toContain("release");
    }
  });

  test("a lost lease during either final check cannot report completion", async () => {
    for (const failAt of [2, 3]) {
      let reads = 0;
      const session = controller({ read: async () => ++reads === failAt ? null : lease });
      await expect(session.run()).rejects.toThrow("no longer owns");
      expect(session.events).toContain("apply");
      expect(session.events).not.toContain("release");
    }
  });

  test("lease parsing requires a server response and exact key and digest shapes", () => {
    expect(parseLease({ lease })).toEqual(lease);
    expect(parseLease({ lease: null })).toBeNull();
    for (const malformed of [{}, { lease: true }, { lease: { ...lease, planSha256: "short" } }, { lease: { ...lease, key: "held" } }, { lease: { ...lease, openedAt: "never" } }]) expect(() => parseLease(malformed)).toThrow();
  });

  test("the Terraform reader hashes the saved plan and requires the matching server lease", async () => {
    const authority = await testAuthority((value) => { value.bootstrapPrincipal = "principal://goog/subject/cloud-root@cdbentley.com"; });
    const work = await mkdtemp(join(tmpdir(), "protected-apply-reader-test-"));
    try {
      const plan = join(work, "saved.tfplan");
      const contextPath = join(work, "context.json");
      const savedLease = { ...lease, planSha256: sha256Hex("reviewed saved plan bytes") };
      const brokerUrl = `https://${authority.broker.serviceName}-${authority.broker.projectNumber}.${authority.broker.region}.run.app`;
      const query = { broker_url: brokerUrl, project_id: authority.broker.projectId };
      await writeFile(plan, "reviewed saved plan bytes", { mode: 0o600 });
      await writeFile(contextPath, JSON.stringify({ lease: savedLease, plan, brokerUrl, tokenFile: join(work, "token") }), { mode: 0o600 });
      const read = (live: ApplyLease | null = savedLease) => readLeaseEvidence(authority, query, contextPath, async () => live);
      expect(await read()).toEqual({ status: "200", key: lease.key, plan_sha256: savedLease.planSha256, owner: lease.openedBy, reason: "" });
      await expect(read(null)).rejects.toThrow("no longer owns");
      await expect(read({ ...savedLease, openedBy: "another-owner" })).rejects.toThrow("no longer owns");
      await expect(readLeaseEvidence(authority, query, undefined, async () => savedLease)).rejects.toThrow("wrapper context");
      await chmod(contextPath, 0o644);
      await expect(read()).rejects.toThrow("owner-only");
      await chmod(contextPath, 0o600);
      await writeFile(plan, "different saved plan bytes");
      let serverRead = false;
      await expect(readLeaseEvidence(authority, query, contextPath, async () => { serverRead = true; return savedLease; })).rejects.toThrow("differs from its lease");
      expect(serverRead).toBe(false);
    } finally {
      await rm(work, { recursive: true, force: true });
    }
  });
});

function snapshotReplies(authority: RecoveryAuthority): Map<string, unknown> {
  const responses = new Map<string, unknown>();
  responses.set("https://openidconnect.googleapis.com/v1/userinfo", { email: "cloud-root@cdbentley.com" });
  for (const project of [{ projectId: authority.broker.projectId, projectNumber: authority.broker.projectNumber }, ...authority.consumers]) {
    responses.set(`https://cloudresourcemanager.googleapis.com/v3/projects/${project.projectNumber}`, { name: `projects/${project.projectNumber}`, projectId: project.projectId, parent: `organizations/${authority.organizationId}`, state: "ACTIVE", etag: "project-etag", updateTime: "2026-09-05T12:00:00.000Z" });
  }
  const { documents, policies } = livePoliciesFromMatrix(denyMatrix(authority, { platformShas: [activeSha] }, steadyFlags));
  for (const policy of policies) {
    responses.set(`https://iam.googleapis.com/v2/policies/${encodeURIComponent(policy.attachment)}/denypolicies`, { policies: [{ name: policy.name }] });
    responses.set(`https://iam.googleapis.com/v2/${policy.name}`, documents[policy.name]);
  }
  for (const consumer of authority.consumers) {
    for (const account of authority.targetAccounts) {
      const email = `${account}@${consumer.projectId}.iam.gserviceaccount.com`;
      responses.set(`https://iam.googleapis.com/v1/projects/${consumer.projectId}/serviceAccounts/${email}`, { email, uniqueId: consumer.serviceAccountUniqueIds[account] });
    }
  }
  return responses;
}

describe("protected apply final reads", () => {
  test("all five project versions, six Deny attachments, and 36 exact targets are reread", async () => {
    const authority = await testAuthority((value) => { value.bootstrapPrincipal = "principal://goog/subject/cloud-root@cdbentley.com"; });
    const responses = snapshotReplies(authority);
    const reads: string[] = [];
    const snapshot = await deploymentSnapshot(authority, async (url) => { reads.push(url); return responses.get(url); });
    expect(reads.length).toBe(54);
    expect(snapshot).toContain("project-etag");
    expect(snapshot).toContain("deny-etag");
    expect(new Set(reads).size).toBe(reads.length);
  });

  test("broker movement, deployer change, unreadable or recreated targets stop a repair apply", async () => {
    const authority = await testAuthority((value) => { value.bootstrapPrincipal = "principal://goog/subject/cloud-root@cdbentley.com"; });
    const originals = snapshotReplies(authority);
    const broker = `https://cloudresourcemanager.googleapis.com/v3/projects/${authority.broker.projectNumber}`;
    const target = [...originals.keys()].find((url) => url.includes("/serviceAccounts/"));
    if (!target) throw new Error("Fixture target missing");
    for (const [url, changed] of new Map<string, unknown>([
      ["https://openidconnect.googleapis.com/v1/userinfo", { email: "different@example.com" }],
      [broker, { name: `projects/${authority.broker.projectNumber}`, projectId: authority.broker.projectId, parent: "organizations/999", state: "ACTIVE", etag: "moved", updateTime: "2026-09-05T12:01:00.000Z" }],
      [target, { uniqueId: "999", email: "recreated@example.com" }],
    ])) {
      const responses = new Map(originals).set(url, changed);
      const session = controller({ snapshot: () => deploymentSnapshot(authority, async (requested) => responses.get(requested)) });
      await expect(session.run()).rejects.toThrow();
      expect(session.events).not.toContain("apply");
      expect(session.events).not.toContain("release");
    }
    await expect(deploymentSnapshot(authority, async () => undefined)).rejects.toThrow();
  });

  test("a paginated or missing Deny policy inventory never counts as a final read", async () => {
    const authority = await testAuthority((value) => { value.bootstrapPrincipal = "principal://goog/subject/cloud-root@cdbentley.com"; });
    const originals = snapshotReplies(authority);
    const listing = [...originals.keys()].find((url) => url.endsWith("/denypolicies"));
    if (!listing) throw new Error("Fixture listing missing");
    for (const changed of [{ policies: [], nextPageToken: "more" }, { policies: [] }, {}]) {
      const responses = new Map(originals).set(listing, changed);
      await expect(deploymentSnapshot(authority, async (requested) => responses.get(requested))).rejects.toThrow("Deny policy listing");
    }
  });

  test("same final ancestry with a changed project version invalidates the readback", async () => {
    const authority = await testAuthority((value) => { value.bootstrapPrincipal = "principal://goog/subject/cloud-root@cdbentley.com"; });
    const responses = snapshotReplies(authority);
    const before = await deploymentSnapshot(authority, async (url) => responses.get(url));
    const broker = `https://cloudresourcemanager.googleapis.com/v3/projects/${authority.broker.projectNumber}`;
    responses.set(broker, { name: `projects/${authority.broker.projectNumber}`, projectId: authority.broker.projectId, parent: `organizations/${authority.organizationId}`, state: "ACTIVE", etag: "new-version", updateTime: "2026-09-05T12:01:00.000Z" });
    const after = await deploymentSnapshot(authority, async (url) => responses.get(url));
    expect(canonicalJson(after)).not.toBe(canonicalJson(before));
  });
});
