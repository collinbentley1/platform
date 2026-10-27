import { describe, test, expect, spyOn } from "bun:test";
import { generateKeyPair, SignJWT } from "jose";
import { mkdtemp, rm, writeFile, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { HttpError, json, readJson, secureHandler, serveStatic, requireOrigin } from "../runtime/http.ts";
import { identityVerifier, sessionCookie, sessionToken } from "../runtime/auth.ts";
import { sqliteStore, firestoreStore, memoryStore, cachedReadiness } from "../runtime/data.ts";

describe("shared application boundaries", () => {
  test("bounds streamed input without trusting content length and rejects malformed UTF-8", async () => {
    const request = new Request("https://app.example/api", { method: "POST", headers: { "content-type": "application/json" }, body: new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode('{"large":"')); c.enqueue(new Uint8Array(100)); c.close(); } }), duplex: "half" } as RequestInit);
    await expect(readJson(request, 32)).rejects.toMatchObject({ status: 413 });
    await expect(readJson(new Request("https://app.example", { method: "POST", headers: { "content-type": "application/json" }, body: new Uint8Array([255]) }))).rejects.toMatchObject({ status: 400 });
  });
  test("neutralizes unexpected errors and logs no paths, credentials, or bodies", async () => {
    const logs: unknown[] = [];
    const handler = secureHandler(() => { throw new Error("secret-private-value"); }, { log: entry => logs.push(entry) });
    const response = await handler(new Request("https://app.example/token?secret=private", { headers: { authorization: "Bearer secret" } }));
    expect(response.status).toBe(500); expect(await response.text()).not.toContain("secret");
    expect(JSON.stringify(logs)).not.toContain("secret"); expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("x-request-id")).toMatch(/^[a-f0-9-]{36}$/);
  });
  test("rejects cross-site writes even from sibling origins", () => {
    expect(() => requireOrigin(new Request("https://app.example/api", { method: "POST", headers: { origin: "https://preview.app.example" } }), "https://app.example")).toThrow(HttpError);
  });
  test("confines static paths including symlinks", async () => {
    const root = await mkdtemp(join(tmpdir(), "platform-static-"));
    try {
      await writeFile(join(root, "index.html"), "hello"); await symlink("/etc/passwd", join(root, "escape"));
      expect(await (await serveStatic(root, "/")).text()).toBe("hello");
      await expect(serveStatic(root, "/escape")).rejects.toMatchObject({ status: 404 });
      await expect(serveStatic(root, "/%2e%2e/passwd")).rejects.toMatchObject({ status: 400 });
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});

describe("identity and sessions", () => {
  test("verifies signature, audience, issuer and authentication time", async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const verify = identityVerifier("example-project", async () => publicKey);
    const issue = (audience: string, authTime: number) => new SignJWT({ auth_time: authTime }).setProtectedHeader({ alg: "RS256", kid: "test" }).setIssuer("https://securetoken.google.com/example-project").setAudience(audience).setSubject("user-one").setIssuedAt().setExpirationTime("1h").sign(privateKey);
    expect((await verify(await issue("example-project", Math.floor(Date.now() / 1000)))).id).toBe("user-one");
    await expect(verify(await issue("other-project", 1))).rejects.toMatchObject({ status: 401 });
    await expect(verify(await issue("example-project", Math.floor(Date.now() / 1000) + 300))).rejects.toMatchObject({ status: 401 });
  });
  test("uses host-only secure cookies and rejects ambiguous cookie values", () => {
    const cookie = sessionCookie("https://app.example", "abc.def.ghi", 3600);
    expect(cookie).toContain("__Host-platform-session="); expect(cookie).toContain("HttpOnly"); expect(cookie).toContain("Secure"); expect(cookie).not.toContain("Domain=");
    expect(() => sessionCookie("http://app.example", "abc", 3600)).toThrow();
    expect(sessionToken(new Request("https://app.example", { headers: { cookie: "__Host-platform-session=a; __Host-platform-session=b" } }))).toBeUndefined();
  });
});

test("durable records isolate users and make repeated creates idempotent", async () => {
  const root = await mkdtemp(join(tmpdir(), "platform-data-")); const path = join(root, "data.sqlite");
  const id = crypto.randomUUID(); const record = { id, title: "A note", createdAt: new Date().toISOString() };
  let store = await sqliteStore(path);
  try {
    await store.put("alice", record); expect(await store.put("alice", record)).toEqual(record);
    await expect(store.put("alice", { ...record, title: "Changed" })).rejects.toMatchObject({ status: 409 });
    expect(await store.list("bob")).toEqual([]); await store.remove("bob", id); expect((await store.list("alice")).length).toBe(1);
    store.close(); store = await sqliteStore(path); expect(await store.list("alice")).toEqual([record]);
  } finally { store.close(); await rm(root, { recursive: true, force: true }); }
});

test("Cloud Run TLS termination keeps HSTS without trusting forwarded request headers",async()=>{
  const previous=Bun.env.K_SERVICE;
  try{
    Bun.env.K_SERVICE="synthetic-cloud-run";
    const response=await secureHandler(()=>new Response("ok"))(new Request("http://app.example/"));
    expect(response.headers.get("Strict-Transport-Security")).toBe("max-age=31536000");
  }finally{if(previous===undefined)delete Bun.env.K_SERVICE;else Bun.env.K_SERVICE=previous;}
});

test("Firestore readiness requires a successful database operation, including on an empty store",async()=>{
  const original=globalThis.fetch;let status=404;
  globalThis.fetch=(async(input:unknown)=>{
    const url=new URL(String(input));
    expect(url.pathname).toBe("/v1/projects/demo-project/databases/(default)/documents/platform_records");
    expect(url.searchParams.get("pageSize")).toBe("1");
    return Response.json(status===200?{documents:[]}:{error:{status:"NOT_FOUND"}},{status});
  }) as typeof fetch;
  try{
    const store=()=>firestoreStore("demo-project","platform_records",async()=>"synthetic-test-identity");
    await expect(store().ready()).rejects.toThrow("Datastore unavailable");
    status=403;await expect(store().ready()).rejects.toThrow("Datastore unavailable");
    status=200;await expect(store().ready()).resolves.toBeUndefined();
  }finally{globalThis.fetch=original;}
});

test("readiness coalesces requests, caches failures and retries after the bounded interval", async () => {
  let now=0,calls=0,fail=true;
  const clock=spyOn(performance,"now").mockImplementation(()=>now);
  const ready=cachedReadiness(async()=>{calls++;if(fail)throw new Error("private database details");});
  try {
    const results=await Promise.allSettled(Array.from({length:20},()=>ready()));
    expect(calls).toBe(1);expect(results.every(result=>result.status==="rejected" && result.reason.message==="Datastore unavailable.")).toBe(true);
    fail=false;await expect(ready()).rejects.toThrow("Datastore unavailable");expect(calls).toBe(1);
    now=5000;await Promise.all(Array.from({length:20},()=>ready()));expect(calls).toBe(2);
    await ready();expect(calls).toBe(2);
    now=10000;await ready();expect(calls).toBe(3);
  } finally {clock.mockRestore();}
});

 test("Firestore retains empty string values consistently with the other stores",async()=>{
 const original=globalThis.fetch;const id=crypto.randomUUID();
 globalThis.fetch=(async(_input:unknown)=>Response.json({name:`projects/demo/databases/(default)/documents/records/${id}`,fields:{title:{stringValue:""},createdAt:{stringValue:""}}})) as typeof fetch;
 try { const store=firestoreStore("demo-project","platform_records",async()=>"synthetic"); await expect(store.put("alice",{id,title:"",createdAt:""})).resolves.toEqual({id,title:"",createdAt:""}); } finally {globalThis.fetch=original;}
 });

test("memory previews sort by creation time before selecting the newest 100",async()=>{const store=memoryStore();const newer={id:crypto.randomUUID(),title:"new",createdAt:"2030-01-01"};await store.put("alice",newer);for(let i=0;i<100;i++)await store.put("alice",{id:crypto.randomUUID(),title:"older",createdAt:"2020-01-01"});const listed=await store.list("alice");expect(listed).toHaveLength(100);expect(listed[0]).toEqual(newer);});

test("oversized records are rejected before a Firestore write and equal timestamps sort consistently",async()=>{const original=globalThis.fetch;let calls=0;globalThis.fetch=(async(_input:unknown)=>{calls++;return Response.json({});}) as typeof fetch;try{const store=firestoreStore("demo-project","platform_records",async()=>"synthetic");await expect(store.put("alice",{id:crypto.randomUUID(),title:"x".repeat(4096),createdAt:new Date().toISOString()})).rejects.toMatchObject({status:400});expect(calls).toBe(0);const memory=memoryStore();const ids=["00000000-0000-0000-0000-000000000001","00000000-0000-0000-0000-000000000002"];for(const id of ids)await memory.put("alice",{id,title:"same",createdAt:"2030-01-01"});expect((await memory.list("alice")).map(value=>value.id)).toEqual(ids.toReversed());}finally{globalThis.fetch=original;}});

test("HEAD preserves the UTF-8 JSON representation length",async()=>{const handler=secureHandler(()=>json({value:"é"}));const get=await handler(new Request("https://app.example/"));const head=await handler(new Request("https://app.example/",{method:"HEAD"}));expect(head.headers.get("Content-Length")).toBe(String((await get.arrayBuffer()).byteLength));expect(await head.text()).toBe("");});

test("JSON framing uses one serialization even for stateful values",async()=>{let calls=0;const response=json({toJSON(){calls++;return{value:"é".repeat(calls)};}},200,{"Cache-Control":"max-age=300"});const body=await response.arrayBuffer();expect(calls).toBe(1);expect(response.headers.get("Content-Length")).toBe(String(body.byteLength));expect(response.headers.get("Cache-Control")).toBe("max-age=300");});

test("account data deletion removes only its owner's records", async () => {
  const root=await mkdtemp(join(tmpdir(),"platform-account-cleanup-")); const store=await sqliteStore(join(root,"data.sqlite"));
  try {
    for(const owner of ["alice","bob"]) await store.put(owner,{id:crypto.randomUUID(),title:owner,createdAt:new Date().toISOString()});
    await store.removeAll("alice"); await store.removeAll("alice");
    expect(await store.list("alice")).toEqual([]); expect((await store.list("bob"))[0]?.title).toBe("bob");
    await expect(store.put("alice",{id:crypto.randomUUID(),title:"late write",createdAt:new Date().toISOString()})).rejects.toMatchObject({status:410});
  } finally {store.close();await rm(root,{recursive:true,force:true});}
});

test("account recovery hides missing accounts but surfaces provider outages", async () => {
  const {managedIdentity}=await import("../runtime/identity.ts");
  const fetcher=globalThis.fetch;let status=400;let code="EMAIL_NOT_FOUND";
  globalThis.fetch=(async()=>Response.json({error:{message:code}},{status})) as typeof fetch;
  try {
    const provider=managedIdentity("demo-recovery-test","synthetic-key");
    await expect(provider.sendReset("synthetic@example.invalid")).resolves.toBeUndefined();
    status=503;code="UNAVAILABLE";await expect(provider.sendReset("synthetic@example.invalid")).rejects.toMatchObject({status:503});
    status=400;code="API_KEY_INVALID";await expect(provider.sendReset("synthetic@example.invalid")).rejects.toMatchObject({status:400});
  } finally {globalThis.fetch=fetcher;}
});
