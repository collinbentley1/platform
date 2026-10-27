import { command } from "../delivery/process.ts";
import { project } from "../delivery/catalog.ts";
import { google, GoogleError, operation } from "../delivery/google.ts";
if (Bun.env.GITHUB_ACTIONS || !Bun.argv.includes("--apply")) throw new Error("Owner recovery drill: bun tools/recovery-drill.ts <registered-app> --apply (temporary Firestore clone).");
const app = project(Bun.argv[2] ?? ""); if (!app.data) throw new Error("Application has no managed datastore.");
Bun.env.GOOGLE_OAUTH_ACCESS_TOKEN = await command(["gcloud", "auth", "print-access-token"], { quiet: true });
const base = "https://firestore.googleapis.com/v1"; const source = `projects/${app.project}/databases/(default)`;
const id = `platform-recovery-${crypto.randomUUID().slice(0, 8)}`; const doc = `platform_recovery_proof/${crypto.randomUUID()}`;
const fixture = { fields: { title: { stringValue: "Synthetic platform recovery proof" } } };
const missing = (error: unknown) => error instanceof GoogleError && error.status === 404;
// Firestore can briefly reject reads/updates after its clone LRO completes.
async function ready<T>(action: () => Promise<T>): Promise<T> {
  const deadline = Date.now() + 10 * 60_000;
  for (;;) {
    try { return await action(); }
    catch (error) { if (!(error instanceof GoogleError && error.code === "FAILED_PRECONDITION") || Date.now() >= deadline) throw error; }
    await Bun.sleep(3000);
  }
}
if ((await google<{pointInTimeRecoveryEnablement:string}>(`${base}/${source}`)).pointInTimeRecoveryEnablement !== "POINT_IN_TIME_RECOVERY_ENABLED") throw new Error("PITR is not enabled.");
try { await google(`${base}/projects/${app.project}/databases/${id}`); throw new Error("Reserved recovery database already exists."); } catch (error) { if (!missing(error)) throw error; }
const created = await google<{updateTime:string}>(`${base}/${source}/documents/${doc}`, "PATCH", fixture);
const snapshot = new Date((Math.floor(Date.parse(created.updateTime) / 60000) + 1) * 60000).toISOString();
let cloneRequested = false;
let cloning: Parameters<typeof operation>[0] | undefined;
console.log(JSON.stringify({ event: "recovery-drill-started", app: app.name, database: id, snapshot }));
try {
  while (Date.now() < Date.parse(snapshot) + 5000) await Bun.sleep(Math.min(5000, Date.parse(snapshot) + 5000 - Date.now()));
  await google(`${base}/${source}/documents/${doc}`, "DELETE");
  cloneRequested = true;
  cloning = await google<{name:string}>(`${base}/projects/${app.project}/databases:clone`,"POST",{databaseId:id,pitrSnapshot:{database:source,snapshotTime:snapshot}});
  await operation(cloning,30*60_000);
  const restored = await ready(() => google<typeof fixture>(`${base}/projects/${app.project}/databases/${id}/documents/${doc}`));
  if (JSON.stringify(restored.fields) !== JSON.stringify(fixture.fields)) throw new Error("Restored fixture content differs.");
  console.log(JSON.stringify({ event: "recovery-drill-passed", app: app.name }));
} catch (error) { console.error("Recovery drill failed before cleanup:", error); throw error; }
finally {
  try { await google(`${base}/${source}/documents/${doc}`, "DELETE"); } catch (error) { if (!missing(error)) throw error; }
  finally {
    if (cloneRequested) {
      const name = `projects/${app.project}/databases/${id}`;
      let exists = true;
      try { const state = await google<{sourceInfo?:{operation?:string}}>(`${base}/${name}`); cloning ??= state.sourceInfo?.operation; } catch (error) { if (!missing(error)) throw error; exists = false; }
      if (exists) {
        if (cloning) { try { await operation(cloning,30*60_000); } catch(error) { console.error("Clone operation failed; attempting reserved-database cleanup:",error); } }
        const unlock = await ready(() => google<{name:string}>(`${base}/${name}?updateMask=deleteProtectionState`,"PATCH",{name,deleteProtectionState:"DELETE_PROTECTION_DISABLED"}));
        await operation(unlock);
        await google(`${base}/${name}`,"DELETE");
        const deadline = Date.now() + 10 * 60_000;
        for (;;) {
          try { await google(`${base}/${name}`); } catch(error) { if (missing(error)) break; throw error; }
          if (Date.now() >= deadline) throw new Error("Recovery clone deletion has not settled.");
          await Bun.sleep(3000);
        }
      }
      console.log(JSON.stringify({ event: "recovery-clone-removed", database: id }));
    }
  }
}
