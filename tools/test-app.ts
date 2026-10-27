import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { command } from "../delivery/process.ts";
const root = join(import.meta.dir, ".."); const directory = await mkdtemp(join(tmpdir(), "platform-browser-"));
const app = join(directory, "application"); let server: ReturnType<typeof Bun.spawn> | undefined;
const cleanup = async () => { server?.kill(); if (server) await server.exited; await rm(directory, { recursive: true, force: true }); };
process.on("SIGTERM", () => { void cleanup().then(() => process.exit(0)); });
try {
  await command([process.execPath, "tools/platform.ts", "init", "browser-test", app], { cwd: root });
  await command([process.execPath, "install", "--ignore-scripts", "--no-env-file"], { cwd: app });
  await command([process.execPath, "run", "verify:ci"], { cwd: app });
  server = Bun.spawn([process.execPath, "dist/server.js"], { cwd: app, stdout: "inherit", stderr: "inherit", env: { ...process.env, NODE_ENV: "development", PORT: "8089", PUBLIC_ORIGIN: "http://127.0.0.1:8089", IDENTITY_PROJECT_ID: "demo-platform-tests", IDENTITY_API_KEY: "emulator-public-key", FIREBASE_AUTH_EMULATOR_HOST: "127.0.0.1:9099" } });
  await server.exited;
} finally { await cleanup(); }
