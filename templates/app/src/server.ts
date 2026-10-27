import { resolve } from "node:path";
import { HttpError, json, readJson, requireOrigin, secureHandler, serveStatic } from "../.platform/runtime/http.ts";
import { identityVerifier, passwordSignIn, sessionCookie, sessionToken, type Identity } from "../.platform/runtime/auth.ts";
import { firestoreStore, memoryStore, sqliteStore, type RecordStore } from "../.platform/runtime/data.ts";

type Config = { origin: string; publicDirectory: string; development: boolean; preview?: boolean; nonce?: string };
type Dependencies = { store: RecordStore; verify: (token: string) => Promise<Identity>; signIn: (email: string, password: string) => Promise<string> };

export function createHandler(config: Config, dependencies: Dependencies) {
  const origin = new URL(config.origin).origin;
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(new URL(origin).hostname);
  if (config.development && !loopback) throw new Error("Development authentication requires a loopback origin.");
  const identify = async (request: Request): Promise<Identity> => {
    if (config.preview) return { id: "synthetic-preview" };
    const token = sessionToken(request);
    if (!token) throw new HttpError(401, "Sign in required.");
    if (config.development && token === "development") return { id: "local-developer", email: "developer@example.invalid" };
    return dependencies.verify(token);
  };
  return secureHandler(async request => {
    const url = new URL(request.url);
    if (url.pathname === "/livez") return json(config.nonce ? { ok: true, deployment: config.nonce } : { ok: true });
    if (url.pathname === "/readyz") {
      try { await dependencies.store.ready(); return json({ ok: true }); } catch { return json({ ok: false }, 503); }
    }
    if (url.origin !== origin) throw new HttpError(403, "Host is not allowed.");
    if (!["GET", "HEAD"].includes(request.method)) requireOrigin(request, origin);
    if (url.pathname === "/api/session") {
      if (request.method === "GET") return json({ user: await identify(request), development: config.development, preview: Boolean(config.preview) });
      if (request.method === "DELETE") return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(origin, "", 0) });
      if (request.method === "POST") {
        const body = await readJson(request, 4096);
        if (!isObject(body) || typeof body.email !== "string" || typeof body.password !== "string" || Object.keys(body).some(key => !["email", "password"].includes(key))) throw new HttpError(400, "Invalid credentials.");
        const token = config.development ? "development" : await dependencies.signIn(body.email, body.password);
        if (!config.development) await dependencies.verify(token);
        return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(origin, token, 3600) });
      }
    }
    if (url.pathname === "/api/notes") {
      const user = await identify(request);
      if (request.method === "GET") return json({ notes: await dependencies.store.list(user.id) });
      if (request.method === "POST") {
        const body = await readJson(request, 4096);
        if (!isObject(body) || Object.keys(body).some(key => !["id", "title"].includes(key)) || typeof body.id !== "string" || typeof body.title !== "string" || body.title.trim().length < 1 || body.title.length > 200) throw new HttpError(400, "Enter a title of 1 to 200 characters.");
        return json(await dependencies.store.put(user.id, { id: body.id, title: body.title.trim(), createdAt: new Date().toISOString() }), 201);
      }
    }
    const note = /^\/api\/notes\/([a-f0-9-]+)$/.exec(url.pathname);
    if (note && request.method === "DELETE") { const user = await identify(request); await dependencies.store.remove(user.id, note[1]!); return json({ ok: true }); }
    if (url.pathname.startsWith("/api/")) throw new HttpError(404, "Not found.");
    if (request.method !== "GET" && request.method !== "HEAD") throw new HttpError(405, "Method not allowed.");
    return serveStatic(config.publicDirectory, url.pathname);
  }, { log: entry => console.info(JSON.stringify(entry)) });
}

function isObject(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value); }

if (import.meta.main) {
  const production = Bun.env.NODE_ENV === "production" || Boolean(Bun.env.K_SERVICE);
  const preview = Bun.env.PLATFORM_PREVIEW === "1";
  if (Bun.env.PLATFORM_PREVIEW && !preview) throw new Error("Invalid preview mode.");
  const project = Bun.env.IDENTITY_PROJECT_ID;
  const apiKey = Bun.env.IDENTITY_API_KEY;
  const origin = Bun.env.PUBLIC_ORIGIN ?? (production ? "" : "http://127.0.0.1:8080");
  if (production && !origin.startsWith("https://")) throw new Error("Production requires an HTTPS origin.");
  if (production && !preview && (!project || !apiKey || !Bun.env.FIRESTORE_PROJECT_ID)) throw new Error("Production identity and data configuration is required.");
  if (preview && (project || apiKey || Bun.env.FIRESTORE_PROJECT_ID)) throw new Error("Previews may not receive production identity or data configuration.");
  const store = preview ? memoryStore() : production ? firestoreStore(Bun.env.FIRESTORE_PROJECT_ID!) : await sqliteStore(Bun.env.DATABASE_PATH ?? "./.local/application.sqlite");
  const verify = project ? identityVerifier(project) : async (): Promise<Identity> => { throw new HttpError(401, "Sign in required."); };
  const handler = createHandler({ origin, development: !production, preview, publicDirectory: resolve(import.meta.dir, "public"), ...(Bun.env.PLATFORM_DEPLOY_NONCE ? { nonce: Bun.env.PLATFORM_DEPLOY_NONCE } : {}) }, {
    store, verify, signIn: (email, password) => passwordSignIn(apiKey ?? "", email, password),
  });
  const server = Bun.serve({ hostname: production ? "0.0.0.0" : "127.0.0.1", port: Number(Bun.env.PORT ?? 8080), maxRequestBodySize: 65_536, idleTimeout: 30, fetch: handler });
  console.info(JSON.stringify({ event: "listening", origin }));
  process.on("SIGTERM", () => { void server.stop().then(() => { store.close(); process.exit(0); }); });
}
