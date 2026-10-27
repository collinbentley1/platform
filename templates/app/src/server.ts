import { resolve } from "node:path";
import { application, type ApplicationConfig, type ApplicationDependencies } from "../.platform/runtime/application.ts";
import { HttpError, json, readJson } from "../.platform/runtime/http.ts";
import { managedIdentity } from "../.platform/runtime/identity.ts";
import { firestoreStore, memoryStore, sqliteStore } from "../.platform/runtime/data.ts";

export function createHandler(config: ApplicationConfig, dependencies: ApplicationDependencies) {
  return application(config, dependencies, async (request, identify) => {
    const path = new URL(request.url).pathname;
    if (path === "/api/notes") {
      const user = await identify();
      if (request.method === "GET") return json({ notes: await dependencies.store.list(user.id) });
      if (request.method === "POST") {
        const body = await readJson(request, 4096) as Record<string, unknown> | null;
        if (!body || Array.isArray(body) || Object.keys(body).some(key => !["id", "title"].includes(key)) || typeof body.id !== "string" || typeof body.title !== "string" || !body.title.trim() || body.title.length > 200) throw new HttpError(400, "Enter a title of 1 to 200 characters.");
        return json(await dependencies.store.put(user.id, { id: body.id, title: body.title.trim(), createdAt: new Date().toISOString() }), 201);
      }
    }
    const note = /^\/api\/notes\/([a-f0-9-]+)$/.exec(path);
    if (note && request.method === "DELETE") { const user = await identify(); await dependencies.store.remove(user.id, note[1]!); return json({ ok: true }); }
    return undefined;
  });
}

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
  const handler = createHandler({ origin, development: !production && !Bun.env.FIREBASE_AUTH_EMULATOR_HOST, preview, publicDirectory: resolve(import.meta.dir, "public"), ...(Bun.env.PLATFORM_DEPLOY_NONCE ? { nonce: Bun.env.PLATFORM_DEPLOY_NONCE } : {}) }, { store, ...(project && apiKey ? { identity: managedIdentity(project, apiKey, origin) } : {}) });
  const server = Bun.serve({ hostname: production ? "0.0.0.0" : "127.0.0.1", port: Number(Bun.env.PORT ?? 8080), maxRequestBodySize: 65_536, idleTimeout: 30, fetch: handler });
  console.info(JSON.stringify({ event: "listening", origin }));
  process.on("SIGTERM", () => { void server.stop().then(() => { store.close(); process.exit(0); }); });
}
