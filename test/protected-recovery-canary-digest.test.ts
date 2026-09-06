import { describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canaryBodySha256, canaryCreateComparison, canaryDigest, canarySnapshotSha256 } from "../tools/ci/protected-recovery-canary-digest";

// The Deny canary's request digest has two derivations -- the producer's
// (bash, tools/ci/protected-recovery-canary-digest.sh) and the fixture
// renderer's (TypeScript, tools/ci/protected-recovery-canary-digest.ts) --
// and the enabled-path harness is judged against the renderer's. They must
// agree byte for byte on the same inputs, including the one normalization
// (a top-level policy.etag is not part of the canonical body).

const root = join(import.meta.dir, "..");

async function bash(script: string): Promise<string> {
  const process = Bun.spawn(["bash", "-c", `. "${root}/tools/ci/protected-recovery-canary-digest.sh"; ${script}`], { stderr: "pipe", stdout: "pipe" });
  const [stdout, stderr] = await Promise.all([new Response(process.stdout).text(), new Response(process.stderr).text()]);
  expect(await process.exited, stderr).toBe(0);
  return stdout.trim();
}

describe("Deny canary request digest", () => {
  test("the bash producer and the TypeScript renderer derive the same body digest and observation digest, and a policy etag never enters either", async () => {
    const directory = await mkdtemp(join(tmpdir(), "canary-digest-"));
    try {
      const policyBody = { updateMask: "bindings,etag", policy: { version: 3, etag: "ACAB=", bindings: [{ role: "roles/viewer", members: ["user:b@example.com", "user:a@example.com"] }] } };
      const policyBodyOtherEtag = { policy: { bindings: [{ members: ["user:b@example.com", "user:a@example.com"], role: "roles/viewer" }], etag: "BQAB=", version: 3 }, updateMask: "bindings,etag" };
      const plainBody = { scope: ["https://www.googleapis.com/auth/cloud-platform"], lifetime: "300s", delegates: ["projects/-/serviceAccounts/d@p.iam.gserviceaccount.com"] };
      const bytes = new TextEncoder().encode("--b\r\nContent-Type: text/plain\r\n\r\nprotected-recovery deny canary 000000000001\r\n--b--\r\n");
      await writeFile(join(directory, "policy.json"), JSON.stringify(policyBody));
      await writeFile(join(directory, "policy-other.json"), JSON.stringify(policyBodyOtherEtag));
      await writeFile(join(directory, "plain.json"), JSON.stringify(plainBody));
      await writeFile(join(directory, "upload.body"), bytes);
      const policySha = await bash(`canary_body_sha256 "${directory}/policy.json" application/json`);
      expect(policySha).toMatch(/^[0-9a-f]{64}$/);
      expect(canaryBodySha256(policyBody, "application/json")).toBe(policySha);
      // The etag and the key order are not part of the canonical body.
      expect(await bash(`canary_body_sha256 "${directory}/policy-other.json" application/json`)).toBe(policySha);
      expect(canaryBodySha256(policyBodyOtherEtag, "application/json")).toBe(policySha);
      // Every other byte is.
      const plainSha = await bash(`canary_body_sha256 "${directory}/plain.json" application/json`);
      expect(canaryBodySha256(plainBody, "application/json")).toBe(plainSha);
      expect(plainSha).not.toBe(policySha);
      expect(canaryBodySha256({ ...plainBody, lifetime: "301s" }, "application/json")).not.toBe(plainSha);
      // A non-JSON body is its bytes; no body is the empty string.
      const bytesSha = await bash(`canary_body_sha256 "${directory}/upload.body" "multipart/related; boundary=b"`);
      expect(canaryBodySha256(bytes, "multipart/related; boundary=b")).toBe(bytesSha);
      expect(await bash('canary_body_sha256 "" ""')).toBe("");
      expect(canaryBodySha256(null, "")).toBe("");
      // The observation digest binds method, URL, content type, body digest, and the required pre-state.
      const digest = await bash(`canary_digest POST "https://iam.googleapis.com/v1/projects/-/serviceAccounts/t@p.iam.gserviceaccount.com:setIamPolicy" application/json "${policySha}" "projects/-/serviceAccounts/t@p.iam.gserviceaccount.com" present "" present`);
      expect(digest).toMatch(/^[0-9a-f]{64}$/);
      expect(canaryDigest("POST", "https://iam.googleapis.com/v1/projects/-/serviceAccounts/t@p.iam.gserviceaccount.com:setIamPolicy", "application/json", policySha, "projects/-/serviceAccounts/t@p.iam.gserviceaccount.com", "present", "", "present")).toBe(digest);
      const moved = await bash(`canary_digest POST "https://cloudresourcemanager.googleapis.com/v3/projects/x:move" application/json "${plainSha}" "projects/x" present "organizations/1" present`);
      expect(canaryDigest("POST", "https://cloudresourcemanager.googleapis.com/v3/projects/x:move", "application/json", plainSha, "projects/x", "present", "organizations/1", "present")).toBe(moved);
      for (const [method, url, contentType, body, resource, expected, detail] of [
        ["PATCH", "https://iam.googleapis.com/v1/projects/-/serviceAccounts/t@p.iam.gserviceaccount.com:setIamPolicy", "application/json", policySha, "projects/-/serviceAccounts/t@p.iam.gserviceaccount.com", "present", ""],
        ["POST", "https://iam.googleapis.com/v1/projects/-/serviceAccounts/t@p.iam.gserviceaccount.com:setIamPolicy?x=1", "application/json", policySha, "projects/-/serviceAccounts/t@p.iam.gserviceaccount.com", "present", ""],
        ["POST", "https://iam.googleapis.com/v1/projects/-/serviceAccounts/t@p.iam.gserviceaccount.com:setIamPolicy", "text/plain", policySha, "projects/-/serviceAccounts/t@p.iam.gserviceaccount.com", "present", ""],
        ["POST", "https://iam.googleapis.com/v1/projects/-/serviceAccounts/t@p.iam.gserviceaccount.com:setIamPolicy", "application/json", plainSha, "projects/-/serviceAccounts/t@p.iam.gserviceaccount.com", "present", ""],
        ["POST", "https://iam.googleapis.com/v1/projects/-/serviceAccounts/t@p.iam.gserviceaccount.com:setIamPolicy", "application/json", policySha, "projects/-/serviceAccounts/u@p.iam.gserviceaccount.com", "present", ""],
        ["POST", "https://iam.googleapis.com/v1/projects/-/serviceAccounts/t@p.iam.gserviceaccount.com:setIamPolicy", "application/json", policySha, "projects/-/serviceAccounts/t@p.iam.gserviceaccount.com", "absent", ""],
        ["POST", "https://iam.googleapis.com/v1/projects/-/serviceAccounts/t@p.iam.gserviceaccount.com:setIamPolicy", "application/json", policySha, "projects/-/serviceAccounts/t@p.iam.gserviceaccount.com", "present", "folders/1"],
      ] as const) {
        expect(canaryDigest(method, url, contentType, body, resource, expected, detail, "present")).not.toBe(digest);
      }
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });
});

test("actual observed states enter the digest without absent/deleted or enabled/disabled collapsing", async () => {
  const digest = (observed: string, detail: string) => canaryDigest("POST", "https://iam.googleapis.com/v1/projects/example/serviceAccounts", "application/json", "body", "projects/example/serviceAccounts/example", "absent", detail, observed);
  expect(digest("absent", "")).not.toBe(digest("deleted", ""));
  expect(digest("present", "enabled")).not.toBe(digest("present", "disabled"));
  expect(digest("absent", "")).not.toBe(digest("unknown", ""));
  expect(await bash('canary_digest POST https://iam.googleapis.com/v1/projects/example/serviceAccounts application/json body projects/example/serviceAccounts/example absent "" deleted')).toBe(digest("deleted", ""));
});

test("only each create API's documented identifier is compared across fresh names; raw digests stay distinct", async () => {
  const directory = await mkdtemp(join(tmpdir(), "canary-pairs-"));
  try {
    const cases = [
      { permission: "iam.googleapis.com/serviceAccounts.create", url: "https://iam.googleapis.com/v1/projects/example/serviceAccounts", resource: "projects/-/serviceAccounts/fresh-c@example.iam.gserviceaccount.com", body: { accountId: "fresh-c", serviceAccount: { displayName: "fresh-c is literal content" } } },
      { permission: "iam.googleapis.com/roles.create", url: "https://iam.googleapis.com/v1/organizations/1/roles", resource: "organizations/1/roles/fresh-c", body: { roleId: "fresh-c", role: { title: "fresh-c is literal content" } } },
      { permission: "iam.googleapis.com/workloadIdentityPools.create", url: "https://iam.googleapis.com/v1/projects/example/locations/global/workloadIdentityPools?workloadIdentityPoolId=fresh-c", resource: "projects/example/locations/global/workloadIdentityPools/fresh-c", body: { displayName: "fresh-c is literal content" } },
      { permission: "iam.googleapis.com/workloadIdentityPoolProviders.create", url: "https://iam.googleapis.com/v1/projects/example/locations/global/workloadIdentityPools/parent/providers?workloadIdentityPoolProviderId=fresh-c", resource: "projects/example/locations/global/workloadIdentityPools/parent/providers/fresh-c", body: { displayName: "fresh-c is literal content" } },
    ];
    for (const input of cases) {
      const path = join(directory, "body.json");
      await writeFile(path, JSON.stringify(input.body));
      const comparison = canaryCreateComparison({ ...input, current: "fresh-c", canonical: "fresh", expected: "absent", detail: "", observed: "absent" });
      expect(JSON.parse(await bash(`canary_create_comparison '${input.permission}' '${input.url}' '${path}' '${input.resource}' fresh-c fresh absent '' absent`))).toEqual(comparison);
      expect(comparison.digest).not.toBe(canaryDigest("POST", input.url, "application/json", canaryBodySha256(input.body, "application/json"), input.resource, "absent", "", "absent"));
      expect(() => canaryCreateComparison({ ...input, current: "other", canonical: "fresh", expected: "absent", detail: "", observed: "absent" })).toThrow();
      const changedBody = { ...input.body, unrelated: "different" };
      expect(canaryCreateComparison({ ...input, body: changedBody, current: "fresh-c", canonical: "fresh", expected: "absent", detail: "", observed: "absent" }).digest).not.toBe(comparison.digest);
    }
    const first = cases[0];
    if (first === undefined) throw new Error("missing create fixture");
    expect(() => canaryCreateComparison({ ...first, permission: "iam.googleapis.com/serviceAccounts.delete", current: "fresh-c", canonical: "fresh", expected: "absent", detail: "", observed: "absent" })).toThrow();
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

test("Allow snapshot hashing preserves Terraform JSON escaping", async () => {
  const directory = await mkdtemp(join(tmpdir(), "canary-snapshot-"));
  try {
    const snapshot = { expression: "a < b && c > d", title: "\u2028\u2029", roles: ["roles/viewer"] };
    const path = join(directory, "snapshot.json");
    await writeFile(path, JSON.stringify(snapshot));
    expect(await bash(`canary_snapshot_sha256 '${path}'`)).toBe(canarySnapshotSha256(snapshot));
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});
