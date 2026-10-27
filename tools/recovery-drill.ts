import { command } from "../delivery/process.ts";
import { project } from "../delivery/catalog.ts";
import { google, GoogleError } from "../delivery/google.ts";

if (Bun.env.GITHUB_ACTIONS || !Bun.argv.includes("--apply")) throw new Error("Owner recovery drill: bun tools/recovery-drill.ts <registered-app> --apply");
const app = project(Bun.argv[2] ?? ""); if (!app.data) throw new Error("Application has no managed datastore.");
Bun.env.GOOGLE_OAUTH_ACCESS_TOKEN = await command(["gcloud", "auth", "print-access-token"], { quiet: true });
const database = `projects/${app.project}/databases/(default)`;
const base = `https://firestore.googleapis.com/v1/${database}`;
const name = `${database}/documents/platform_recovery_proof/${crypto.randomUUID()}`;
const url = `https://firestore.googleapis.com/v1/${name}`;
const fixture = { fields: { title: { stringValue: "Synthetic platform recovery proof" } } };
const missing = (error: unknown) => error instanceof GoogleError && error.status === 404;
if ((await google<{pointInTimeRecoveryEnablement:string}>(base)).pointInTimeRecoveryEnablement !== "POINT_IN_TIME_RECOVERY_ENABLED") throw new Error("PITR is not enabled.");
try {
  const created = await google<{updateTime:string}>(url, "PATCH", fixture);
  const snapshot = new Date((Math.floor(Date.parse(created.updateTime) / 60000) + 1) * 60000).toISOString();
  console.log(JSON.stringify({ event: "recovery-drill-started", app: app.name, snapshot }));
  while (Date.now() < Date.parse(snapshot) + 5000) await Bun.sleep(Math.min(5000, Date.parse(snapshot) + 5000 - Date.now()));
  await google(url, "DELETE");
  try { await google(url); throw new Error("The synthetic deletion did not take effect."); } catch(error) { if (!missing(error)) throw error; }
  const history = await google<Array<{found?:{name:string;fields:typeof fixture.fields}}>>(`${base}/documents:batchGet`, "POST", {documents:[name],readTime:snapshot});
  const restored = history.find(value=>value.found?.name===name)?.found;
  if (!restored || JSON.stringify(restored.fields) !== JSON.stringify(fixture.fields)) throw new Error("Historical fixture content differs.");
  await google(url, "PATCH", {fields:restored.fields});
  if (JSON.stringify((await google<typeof fixture>(url)).fields) !== JSON.stringify(restored.fields)) throw new Error("Restored fixture content differs.");
  console.log(JSON.stringify({ event: "recovery-drill-passed", app: app.name, method:"historical-read-and-restore" }));
} finally {
  try { await google(url, "DELETE"); } catch(error) { if (!missing(error)) throw error; }
  console.log(JSON.stringify({ event: "recovery-fixture-removed", app: app.name }));
}
