import { command } from "../delivery/process.ts";
import { project, imageName } from "../delivery/catalog.ts";
import { google } from "../delivery/google.ts";
import { service, deploy, routingState, productionOrigin } from "../delivery/deploy.ts";
import { servingSource } from "../delivery/serving.ts";
if (Bun.env.GITHUB_ACTIONS || !Bun.argv.includes("--apply")) throw new Error("Owner rollback drill: bun tools/rollback-drill.ts <registered-app> --apply");
const app = project(Bun.argv[2] ?? "");
Bun.env.GOOGLE_OAUTH_ACCESS_TOKEN = await command(["gcloud", "auth", "print-access-token"], { quiet: true });
if (app.identity) Bun.env.IDENTITY_API_KEY = await command(["gh", "variable", "get", "IDENTITY_API_KEY", "--repo", "collinbentley1/platform", "--env", `deploy-${app.name}`], { quiet: true });
const before = await service(app); const routed = (before.trafficStatuses ?? []).filter(item => (item.percent ?? 0) > 0);
if (routed.length !== 1 || routed[0]!.percent !== 100) throw new Error("A rollback drill requires one stable production revision.");
const revision = await google<{containers:Array<{image:string;env:Array<{name:string;value?:string}>}>}>(`https://run.googleapis.com/v2/${before.name}/revisions/${routed[0]!.revision!.split("/").at(-1)}`);
const image = revision.containers[0]!.image; const source = servingSource(revision.containers[0]!.env);
if (!image.startsWith(`${imageName(app)}@sha256:`)) throw new Error("Serving image is outside the application's registry.");
const digest = image.split("@")[1]!; const fetcher = globalThis.fetch;
try {
  globalThis.fetch = (async (input: unknown, init?: RequestInit) => { const url = new URL(String(input)); return url.origin === productionOrigin(app,before.uri) && url.pathname === "/" ? new Response("Synthetic rollback failure", { status: 503 }) : fetcher(input as RequestInfo, init); }) as typeof fetch;
  try { await deploy(app, { schemaVersion: 1, digest, runnableDigest: digest, sourceSha: source.source, platformSha: source.release }); throw new Error("Injected failure was accepted."); }
  catch(error) { if (!String(error).includes("entry route failed")) throw error; }
  if (routingState((await service(app)).trafficStatuses ?? []) !== routingState(before.trafficStatuses ?? [])) throw new Error("The original production route was not restored.");
  console.log(JSON.stringify({ event: "rollback-drill-passed", app: app.name }));
} finally { globalThis.fetch = fetcher; }
