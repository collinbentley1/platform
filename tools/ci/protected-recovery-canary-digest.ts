import { canonicalJson, sha256Hex } from "../../protected-recovery/src/model";

// The canonical request digest of one Deny canary observation, derived
// exactly as tools/ci/protected-recovery-canary-digest.sh derives it for the
// producer: the fixture renderer uses these, and test/protected-recovery-
// canary-digest.test.ts requires the two derivations to agree on the same
// inputs. A JSON body is canonical JSON with a top-level policy.etag removed;
// any other body is its bytes; no body is the empty string.

export function canaryBodySha256(body: unknown | Uint8Array | null, contentType: string): string {
  if (body === null) return "";
  if (body instanceof Uint8Array) return sha256Hex(body);
  if (!contentType.startsWith("application/json")) throw new Error("a non-JSON body must be given as bytes");
  return sha256Hex(canonicalJson(withoutPolicyEtag(body)));
}

export function canaryDigest(method: string, url: string, contentType: string, bodySha256: string, resource: string, expected: string, detail: string): string {
  return sha256Hex(canonicalJson({ bodySha256, contentType, method, preState: { detail, expected, resource }, url }));
}

function withoutPolicyEtag(body: unknown): unknown {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return body;
  const record = body as Record<string, unknown>;
  const policy = record.policy;
  if (typeof policy !== "object" || policy === null || Array.isArray(policy)) return body;
  const { etag: _etag, ...rest } = policy as Record<string, unknown>;
  return { ...record, policy: rest };
}
