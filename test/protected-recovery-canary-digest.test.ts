import { describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canaryBodySha256, canaryDigest } from "../tools/ci/protected-recovery-canary-digest";

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
      const digest = await bash(`canary_digest POST "https://iam.googleapis.com/v1/projects/-/serviceAccounts/t@p.iam.gserviceaccount.com:setIamPolicy" application/json "${policySha}" "projects/-/serviceAccounts/t@p.iam.gserviceaccount.com" present ""`);
      expect(digest).toMatch(/^[0-9a-f]{64}$/);
      expect(canaryDigest("POST", "https://iam.googleapis.com/v1/projects/-/serviceAccounts/t@p.iam.gserviceaccount.com:setIamPolicy", "application/json", policySha, "projects/-/serviceAccounts/t@p.iam.gserviceaccount.com", "present", "")).toBe(digest);
      const moved = await bash(`canary_digest POST "https://cloudresourcemanager.googleapis.com/v3/projects/x:move" application/json "${plainSha}" "projects/x" present "organizations/1"`);
      expect(canaryDigest("POST", "https://cloudresourcemanager.googleapis.com/v3/projects/x:move", "application/json", plainSha, "projects/x", "present", "organizations/1")).toBe(moved);
      for (const [method, url, contentType, body, resource, expected, detail] of [
        ["PATCH", "https://iam.googleapis.com/v1/projects/-/serviceAccounts/t@p.iam.gserviceaccount.com:setIamPolicy", "application/json", policySha, "projects/-/serviceAccounts/t@p.iam.gserviceaccount.com", "present", ""],
        ["POST", "https://iam.googleapis.com/v1/projects/-/serviceAccounts/t@p.iam.gserviceaccount.com:setIamPolicy?x=1", "application/json", policySha, "projects/-/serviceAccounts/t@p.iam.gserviceaccount.com", "present", ""],
        ["POST", "https://iam.googleapis.com/v1/projects/-/serviceAccounts/t@p.iam.gserviceaccount.com:setIamPolicy", "text/plain", policySha, "projects/-/serviceAccounts/t@p.iam.gserviceaccount.com", "present", ""],
        ["POST", "https://iam.googleapis.com/v1/projects/-/serviceAccounts/t@p.iam.gserviceaccount.com:setIamPolicy", "application/json", plainSha, "projects/-/serviceAccounts/t@p.iam.gserviceaccount.com", "present", ""],
        ["POST", "https://iam.googleapis.com/v1/projects/-/serviceAccounts/t@p.iam.gserviceaccount.com:setIamPolicy", "application/json", policySha, "projects/-/serviceAccounts/u@p.iam.gserviceaccount.com", "present", ""],
        ["POST", "https://iam.googleapis.com/v1/projects/-/serviceAccounts/t@p.iam.gserviceaccount.com:setIamPolicy", "application/json", policySha, "projects/-/serviceAccounts/t@p.iam.gserviceaccount.com", "absent", ""],
        ["POST", "https://iam.googleapis.com/v1/projects/-/serviceAccounts/t@p.iam.gserviceaccount.com:setIamPolicy", "application/json", policySha, "projects/-/serviceAccounts/t@p.iam.gserviceaccount.com", "present", "folders/1"],
      ] as const) {
        expect(canaryDigest(method, url, contentType, body, resource, expected, detail)).not.toBe(digest);
      }
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });
});
