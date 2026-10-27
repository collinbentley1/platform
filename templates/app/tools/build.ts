import { cp, mkdir, rm, stat } from "node:fs/promises";
import { join } from "node:path";

const root = join(import.meta.dir, "..");
const dist = join(root, "dist");
const publicDirectory = join(root, "public");

await rm(dist, { force: true, recursive: true });
await mkdir(dist, { recursive: true });

const result = await Bun.build({
  entrypoints: [join(root, "src/server.ts")],
  minify: false,
  outdir: dist,
  target: "bun",
});
if (!result.success) {
  for (const message of result.logs) {
    console.error(message);
  }
  throw new Error("Server build failed.");
}

if ((await stat(publicDirectory).catch(() => undefined))?.isDirectory()) {
  await cp(publicDirectory, join(dist, "public"), { recursive: true });
}

const client = await Bun.build({ entrypoints: [join(root, "src/client.ts")], target: "browser", minify: true, outdir: join(dist, "public") });
if (!client.success) throw new Error("Client build failed.");
