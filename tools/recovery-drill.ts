import { command, gcloud } from "../delivery/process.ts";
import { project } from "../delivery/catalog.ts";
import { google, GoogleError, operation } from "../delivery/google.ts";
if (Bun.env.GITHUB_ACTIONS || !Bun.argv.includes("--apply")) throw new Error("Owner recovery drill: bun tools/recovery-drill.ts <registered-app> --apply (temporary Firestore clone).");
const app = project(Bun.argv[2] ?? ""); if (!app.data) throw new Error("Application has no managed datastore.");
Bun.env.GOOGLE_OAUTH_ACCESS_TOKEN = await command(["gcloud", "auth", "print-access-token"], { quiet: true });
const base = "https://firestore.googleapis.com/v1"; const source = `projects/${app.project}/databases/(default)`;
const id = `platform-recovery-${crypto.randomUUID().slice(0, 8)}`; const doc = `platform_recovery_proof/${crypto.randomUUID()}`;
const fixture = { fields: { title: { stringValue: "Synthetic platform recovery proof" } } };
const missing = (error: unknown) => error instanceof GoogleError && error.status === 404;
if ((await google<{pointInTimeRecoveryEnablement:string}>(`${base}/${source}`)).pointInTimeRecoveryEnablement !== "POINT_IN_TIME_RECOVERY_ENABLED") throw new Error("PITR is not enabled.");
try { await google(`${base}/projects/${app.project}/databases/${id}`); throw new Error("Reserved recovery database already exists."); } catch (error) { if (!missing(error)) throw error; }
const created = await google<{updateTime:string}>(`${base}/${source}/documents/${doc}`, "PATCH", fixture);
const snapshot = new Date((Math.floor(Date.parse(created.updateTime) / 60000) + 1) * 60000).toISOString();
let cloneRequested = false;
let cloning: string | undefined;
console.log(JSON.stringify({ event: "recovery-drill-started", app: app.name, database: id, snapshot }));
try {
  while (Date.now() < Date.parse(snapshot) + 5000) await Bun.sleep(Math.min(5000, Date.parse(snapshot) + 5000 - Date.now()));
  await google(`${base}/${source}/documents/${doc}`, "DELETE");
  cloneRequested = true;
  cloning = (await google<{name:string}>(`${base}/projects/${app.project}/databases:clone`,"POST",{databaseId:id,pitrSnapshot:{database:source,snapshotTime:snapshot}})).name;
  await operation(cloning,30*60_000);
  const restored = await google<typeof fixture>(`${base}/projects/${app.project}/databases/${id}/documents/${doc}`);
  if (JSON.stringify(restored.fields) !== JSON.stringify(fixture.fields)) throw new Error("Restored fixture content differs.");
  console.log(JSON.stringify({ event: "recovery-drill-passed", app: app.name }));
} catch (error) { console.error("Recovery drill failed before cleanup:", error); throw error; }
finally {
  try { await google(`${base}/${source}/documents/${doc}`, "DELETE"); } catch (error) { if (!missing(error)) throw error; }
  finally {
    if (cloneRequested) {
      if (cloning) await operation(cloning,30*60_000);
      const name = `projects/${app.project}/databases/${id}`;
      let exists = true;
      try { await google(`${base}/${name}`); } catch (error) { if (!missing(error)) throw error; exists = false; }
      if (exists) {
        const unlock = await gcloud<{name:string}>(["firestore","databases","update",`--database=${id}`,`--project=${app.project}`,"--no-delete-protection"]);
        if(unlock.name.includes("/operations/")) await operation(unlock.name);
        const removal = await gcloud<{name:string}>(["firestore","databases","delete",`--database=${id}`,`--project=${app.project}`]); await operation(removal.name);
      }
      console.log(JSON.stringify({ event: "recovery-clone-removed", database: id }));
    }
  }
}
