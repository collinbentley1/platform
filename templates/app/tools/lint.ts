import { readFile } from "node:fs/promises";
import { join } from "node:path";

const server = await readFile(join(import.meta.dir, "..", "src/server.ts"), "utf8");
if (!server.includes('url.pathname === "/livez"')) {
  throw new Error("The server must retain the platform-standard /livez endpoint.");
}
if (!server.includes("Bun.env.PLATFORM_DEPLOY_NONCE")) {
  throw new Error("Preview health must echo the platform deployment nonce.");
}
