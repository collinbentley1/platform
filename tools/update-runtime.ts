import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { command, github } from "../delivery/process.ts";
const root = join(import.meta.dir, ".."); const version = Bun.argv[2];
if (!version || !/^\d+\.\d+\.\d+$/.test(version)) throw new Error("Usage: bun tools/update-runtime.ts <stable-bun-version>");
const release = await github<{ draft: boolean; prerelease: boolean; published_at: string; assets: Array<{ name: string; digest: string }> }>(`repos/oven-sh/bun/releases/tags/bun-v${version}`);
if (release.draft || release.prerelease) throw new Error("Bun updates require a stable vendor release.");
const hash = (name: string) => { const digest = release.assets.find(asset => asset.name === name)?.digest; if (!digest || !/^sha256:[a-f0-9]{64}$/.test(digest)) throw new Error("Vendor release checksum is unavailable."); return digest.slice(7); };
const build = await command(["regctl", "image", "digest", `oven/bun:${version}`]);
const runtime = await command(["regctl", "image", "digest", `oven/bun:${version}-distroless`]);
if (![build, runtime].every(value => /^sha256:[a-f0-9]{64}$/.test(value))) throw new Error("Immutable Bun images are required.");
await writeFile(join(root, "delivery/bun.json"), JSON.stringify({ version, linuxX64: hash("bun-linux-x64.zip"), darwinArm64: hash("bun-darwin-aarch64.zip") }, null, 2) + "\n");
for (const file of ["package.json", "templates/app/package.json"]) { const path = join(root, file); const value = JSON.parse(await readFile(path, "utf8")); value.packageManager = `bun@${version}`; await writeFile(path, JSON.stringify(value, null, 2) + "\n"); }
const docker = join(root, "delivery/Dockerfile");
await writeFile(docker, (await readFile(docker, "utf8")).replace(/oven\/bun:\d+\.\d+\.\d+(-distroless)?@sha256:[a-f0-9]{64}/g, (_, suffix: string | undefined) => `oven/bun:${version}${suffix ?? ""}@${suffix ? runtime : build}`));
console.log(`Updated coordinated Bun build, CI and runtime pins to ${version}. Run bun install and the normal tests before publishing.`);
