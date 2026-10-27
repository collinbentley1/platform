#!/usr/bin/env bun
import { cp, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import { doctor, upgrade, requireSha } from "../delivery/consumer.ts";
import { verifyApplication } from "../delivery/verify.ts";

const source = resolve(import.meta.dir, "..");
const [command, ...args] = Bun.argv.slice(2);
const flag = (name: string) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const sha = flag("--sha") ?? Bun.env.PLATFORM_WORKFLOW_SHA ?? (await new Response(Bun.spawn(["git", "rev-parse", "HEAD"], { cwd: source, stdout: "pipe" }).stdout).text()).trim();
const target = resolve(args[0] ?? ".");
switch (command) {
  case "create": { const { create } = await import("../delivery/create.ts"); await create(args[0] ?? "", args.slice(1)); break; }
  case "init":
  case "scaffold": {
    const name = args[0]; const destination = resolve(args[1] ?? name ?? "");
    if (!name || !/^[a-z][a-z0-9-]{0,39}$/.test(name)) throw new Error("Usage: platform init <name> [directory] --sha <release>");
    await mkdir(destination, { recursive: false });
    await cp(join(source, "templates/app"), destination, { recursive: true, filter: path => !path.split("/").some(part => ["node_modules", "dist", ".local", "infra", ".github", ".platform"].includes(part)) });
    for await (const path of walk(destination)) { const content = await readFile(path, "utf8"); await writeFile(path, content.replaceAll("__APP_NAME__", name)); }
    await upgrade(destination, source, requireSha(sha), { adopt: true });
    console.log(destination); break;
  }
  case "upgrade": {
    const changed = await upgrade(target, source, requireSha(sha), { adopt: args.includes("--adopt"), check: args.includes("--check") });
    console.log(JSON.stringify({ changed, sha })); break;
  }
  case "doctor": {
    const failures = await doctor(target, source, requireSha(sha));
    if (failures.length) { console.error(failures.join("\n")); process.exit(1); }
    console.log("Platform contract verified."); break;
  }
  case "verify": await verifyApplication(target); break;
  case "enroll": {
    const { provision } = await import("../delivery/provision.ts");
    await provision(args[0] ?? "", args.includes("--apply")); break;
  }
  case "budget": { const { budget } = await import("../delivery/operations.ts"); await budget(Number(args[0] ?? 30)); break; }
  case "status": { const { status } = await import("../delivery/operations.ts"); status(); break; }
  case "repository-settings": {
    const { settings } = await import("../delivery/settings.ts");
    await settings(args[0] ?? ""); break;
  }
  case "help":
  case undefined:
    console.log("platform create <name> --project <id> [--billing-account <id>] --apply\nplatform init <name> [directory] --sha <release>\nplatform budget [total-monthly-USD]\nplatform status\nplatform verify [directory]\nplatform doctor [directory] --sha <release>\nplatform upgrade [directory] --sha <release> [--check] [--adopt]\nplatform enroll <registered-google-project> [--apply]\nplatform repository-settings <registered-repository>\n\nThe complete starter includes local SQLite and production Identity Platform + Firestore.\nPublished platform releases propose managed consumer PRs; all checks and current-head automated review must pass before automatic merge.\nCloud publishing and deployment run only in the protected platform repository. Each application owns its frontend and product code."); break;
  default: throw new Error("Unknown command; run platform help.");
}

async function* walk(directory: string): AsyncGenerator<string> {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) yield* walk(path); else if (entry.isFile()) yield path;
  }
}
