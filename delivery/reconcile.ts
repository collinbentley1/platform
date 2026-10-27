import { projects, imageName } from "./catalog.ts";
import { service, runtimeIdentity } from "./deploy.ts";
import { google } from "./google.ts";
import { scanImage } from "./scan.ts";

const app = projects.find(app => app.name === Bun.env.PLATFORM_APP);
if (!app) throw new Error("Unknown application.");
const current = await service(app);
const revisions = new Set((current.trafficStatuses ?? []).filter(item => (item.percent ?? 0) > 0 || item.tag).map(item => item.revision));
if (!revisions.size || revisions.has(undefined)) throw new Error("Production has no resolved serving revision.");
for (const name of revisions) {
  if (!name || !name.startsWith(app.service + "-") || !/^[a-z0-9-]+$/.test(name)) throw new Error("Serving revision is outside the registered service.");
  const revision = await google<{ serviceAccount: string; containers: Array<{image:string}> }>(`https://run.googleapis.com/v2/${current.name}/revisions/${name}`);
  const prefix = `${imageName(app)}@`;
  if (revision.serviceAccount !== runtimeIdentity(app) || !revision.containers[0]?.image.startsWith(prefix)) throw new Error("Serving runtime identity or registry drifted.");
  await scanImage(app, revision.containers[0].image.slice(prefix.length), 60_000);
}
const preview = await service(app, true);
if (preview.template.serviceAccount !== runtimeIdentity(app, true)) throw new Error("Preview runtime identity drifted.");
const response = await fetch(new URL("/livez", preview.uri), {redirect:"error",signal:AbortSignal.timeout(15_000)});
if (![401,403].includes(response.status)) throw new Error("Preview accepts anonymous requests.");
const health = await fetch(new URL("/livez", app.env.PUBLIC_ORIGIN ?? current.uri), {redirect:"error",signal:AbortSignal.timeout(20_000)});
if (!health.ok || !(await health.json() as {ok?:boolean}).ok) throw new Error("Production health failed.");
console.log(JSON.stringify({event:"serving-application-verified",app:app.name,revisions:[...revisions]}));
