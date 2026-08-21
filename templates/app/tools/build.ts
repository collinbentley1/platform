import { cp, mkdir, rm } from "node:fs/promises";
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

if (await Bun.file(publicDirectory).exists()) {
  await cp(publicDirectory, join(dist, "public"), { recursive: true });
}
