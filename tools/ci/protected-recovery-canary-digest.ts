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

export function canaryDigest(method: string, url: string, contentType: string, bodySha256: string, resource: string, expected: string, detail: string, observed: string): string {
  return sha256Hex(canonicalJson({ bodySha256, contentType, method, preState: { detail, expected, observed, resource }, url }));
}

function withoutPolicyEtag(body: unknown): unknown {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return body;
  const record = body as Record<string, unknown>;
  const policy = record.policy;
  if (typeof policy !== "object" || policy === null || Array.isArray(policy)) return body;
  const { etag: _etag, ...rest } = policy as Record<string, unknown>;
  return { ...record, policy: rest };
}

export function canaryCreateComparison(input: {
  readonly permission: string;
  readonly url: string;
  readonly body: unknown;
  readonly resource: string;
  readonly current: string;
  readonly canonical: string;
  readonly expected: string;
  readonly detail: string;
  readonly observed: string;
}): { readonly request: { readonly method: string; readonly url: string; readonly contentType: string; readonly bodySha256: string }; readonly resource: string; readonly digest: string } {
  let url = input.url;
  let resource: string;
  let body = input.body;
  switch (input.permission) {
    case "iam.googleapis.com/serviceAccounts.create": {
      if (!input.resource.includes(`/serviceAccounts/${input.current}@`)) throw new Error("the paired account resource differs");
      if (typeof body !== "object" || body === null || !("accountId" in body) || body.accountId !== input.current) throw new Error("the paired account identifier differs");
      body = { ...body, accountId: input.canonical };
      resource = input.resource.replace(`/serviceAccounts/${input.current}@`, `/serviceAccounts/${input.canonical}@`);
      break;
    }
    case "iam.googleapis.com/roles.create": {
      if (!input.resource.endsWith(`/roles/${input.current}`)) throw new Error("the paired role resource differs");
      if (typeof body !== "object" || body === null || !("roleId" in body) || body.roleId !== input.current) throw new Error("the paired role identifier differs");
      body = { ...body, roleId: input.canonical };
      resource = `${input.resource.slice(0, -input.current.length)}${input.canonical}`;
      break;
    }
    case "iam.googleapis.com/workloadIdentityPools.create":
    case "iam.googleapis.com/workloadIdentityPoolProviders.create": {
      const provider = input.permission === "iam.googleapis.com/workloadIdentityPoolProviders.create";
      const field = provider ? "workloadIdentityPoolProviderId" : "workloadIdentityPoolId";
      const segment = provider ? "providers" : "workloadIdentityPools";
      if (!url.endsWith(`?${field}=${input.current}`) || !input.resource.endsWith(`/${segment}/${input.current}`)) throw new Error("the paired pool or provider identifier differs");
      url = `${url.slice(0, -input.current.length)}${input.canonical}`;
      resource = `${input.resource.slice(0, -input.current.length)}${input.canonical}`;
      break;
    }
    default: throw new Error("this API has no paired create identifier");
  }
  const request = { method: "POST", url, contentType: "application/json", bodySha256: canaryBodySha256(body, "application/json") };
  return { request, resource, digest: canaryDigest(request.method, url, request.contentType, request.bodySha256, resource, input.expected, input.detail, input.observed) };
}

export function canarySnapshotSha256(snapshot: unknown): string {
  const escaped = canonicalJson(snapshot).replace(/[<>&\u2028\u2029]/g, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);
  return sha256Hex(escaped);
}
