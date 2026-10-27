import { expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { IdentityProvider } from "../.platform/runtime/identity.ts";
import { createHandler } from "../src/server.ts";
import { sqliteStore, memoryStore } from "../.platform/runtime/data.ts";

const identity = (id?: string): IdentityProvider => ({ verify: async token => ({ id: token, emailVerified: true, authenticatedAt: Math.floor(Date.now()/1000) }), signIn: async () => id ?? "alice", signUp: async () => "new-user", sendVerification: async () => {}, sendReset: async () => {}, confirm: async () => {}, revoke: async () => {}, remove: async () => {} });

test("a signed-in user can save, retry, and delete a durable note without exposing another user's records", async () => {
  const root = await mkdtemp(join(tmpdir(), "application-test-")); const store = await sqliteStore(join(root, "notes.sqlite"));
  const origin = "https://application.example";
  const handler = createHandler({ origin, publicDirectory: "./public", development: false, nonce: "test-deployment" }, {
    store, identity: identity(),
  });
  const request = (path: string, method = "GET", body?: unknown, user = "alice") => new Request(origin + path, {
    method, headers: { origin, "content-type": "application/json", cookie: `__Host-platform-session=${user}` }, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  try {
    expect((await handler(new Request(origin + "/api/notes"))).status).toBe(401);
    const note = { id: crypto.randomUUID(), title: "A saved note" };
    expect((await handler(request("/api/notes", "POST", note))).status).toBe(201);
    expect((await handler(request("/api/notes", "POST", note))).status).toBe(201);
    const saved = await (await handler(request("/api/notes"))).json() as { notes: unknown[] }; expect(saved.notes).toHaveLength(1);
    const other = await (await handler(request("/api/notes", "GET", undefined, "bob"))).json() as { notes: unknown[] }; expect(other.notes).toHaveLength(0);
    await handler(request(`/api/notes/${note.id}`, "DELETE", undefined, "bob"));
    expect((await (await handler(request("/api/notes"))).json() as { notes: unknown[] }).notes).toHaveLength(1);
    expect((await handler(new Request(origin + "/api/notes", { method: "POST", headers: { origin: "https://evil.example", cookie: "__Host-platform-session=alice", "content-type": "application/json" }, body: JSON.stringify(note) }))).status).toBe(403);
    await handler(request(`/api/notes/${note.id}`, "DELETE"));
    expect((await (await handler(request("/api/notes"))).json() as { notes: unknown[] }).notes).toHaveLength(0);
    expect(await (await handler(request("/livez"))).json()).toEqual({ ok: true, deployment: "test-deployment" });
  } finally { store.close(); await rm(root, { recursive: true, force: true }); }
});

test("development authentication cannot be exposed on a public origin", () => {
  expect(() => createHandler({ origin: "https://application.example", publicDirectory: "./public", development: true }, {} as never)).toThrow("loopback");
});

test("TLS termination retains secure host-only sessions and rejects forged hosts and cross-site origins", async () => {
  const origin = "https://application.example";
  const handler = createHandler({origin,publicDirectory:"./public",development:false}, {
    store:memoryStore(),identity:identity("verified-identity"),
  });
  const login = await handler(new Request("http://application.example/api/session",{method:"POST",headers:{Origin:origin,"Content-Type":"application/json"},body:JSON.stringify({email:"test@example.invalid",password:"synthetic"})}));
  expect(login.status).toBe(200);
  expect(login.headers.get("Set-Cookie")).toContain("__Host-platform-session=verified-identity");
  expect(login.headers.get("Set-Cookie")).toContain("Secure");
  expect(login.headers.get("Strict-Transport-Security")).toBeTruthy();
  const session = await handler(new Request("http://application.example/api/session",{headers:{Cookie:"__Host-platform-session=verified-identity"}}));
  expect(session.status).toBe(200);
  expect((await handler(new Request("http://forged.example/api/session"))).status).toBe(403);
  expect((await handler(new Request("http://application.example/api/session",{method:"DELETE",headers:{Origin:"https://sibling.example"}}))).status).toBe(403);
});
