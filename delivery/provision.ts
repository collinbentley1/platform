import { mkdtemp, readFile, writeFile, mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { projects } from "./catalog.ts";
import { command, gcloud } from "./process.ts";
import { google, GoogleError } from "./google.ts";

const bootstrap = "us-docker.pkg.dev/cloudrun/container/hello@sha256:d5dbac4a196296d8d517f8bdc302ad967deb9d83accf8bdbe491d3479e86a5e5";

export async function provision(projectId: string, apply = false): Promise<void> {
  if (Bun.env.GITHUB_ACTIONS) throw new Error("Infrastructure enrollment uses the owner's local Google session, never an application build identity.");
  const apps = projects.filter(app => app.project === projectId);
  if (!apps.length) throw new Error("Project is not registered.");
  const metadata = await gcloud<{ projectNumber: string }>(["projects", "describe", projectId]);
  if (apps.some(app => app.number !== metadata.projectNumber)) throw new Error("Project numeric identity differs from the reviewed catalog.");
  const inspectionApis=["cloudresourcemanager.googleapis.com","iam.googleapis.com","run.googleapis.com","artifactregistry.googleapis.com","storage.googleapis.com",...(apps.some(app=>app.data)?["firestore.googleapis.com"]:[]),...(apps.some(app=>app.identity || app.name==="healthmcp")?["identitytoolkit.googleapis.com","apikeys.googleapis.com"]:[]),...(apps.some(app=>app.name==="healthmcp")?["recaptchaenterprise.googleapis.com"]:[])];
  if(inspectionApis.length) await command(["gcloud","services","enable",...inspectionApis,`--project=${projectId}`,"--quiet"]);
  const directory = resolve(import.meta.dir, "terraform");
  const artifacts = await mkdtemp(join(tmpdir(), "platform-enrollment-"));
  const bucket = `${projectId}-platform-state`;
  let exists = true;
  try {
    const value = await google<{ projectNumber: string }>(`https://storage.googleapis.com/storage/v1/b/${bucket}`);
    if (String(value.projectNumber) !== apps[0]!.number) throw new Error("State bucket belongs to a different project.");
  } catch (error) { if (error instanceof GoogleError && error.status === 404) exists = false; else throw error; }
  if (!exists) await command(["gcloud", "storage", "buckets", "create", `gs://${bucket}`, `--project=${projectId}`, "--location=us-east4", "--uniform-bucket-level-access", "--public-access-prevention", "--quiet"]);
  await command(["gcloud", "storage", "buckets", "update", `gs://${bucket}`, "--versioning", "--public-access-prevention", "--quiet"]);
  const images: Record<string, string> = {};
  const existing = new Set<string>();
  for (const app of apps) {
    try {
      const current = await google<{ latestReadyRevision?: string }>(`https://run.googleapis.com/v2/projects/${app.project}/locations/${app.region}/services/${app.service}`);
      const revision = current.latestReadyRevision;
      if (!revision) throw new Error("The existing service has no ready revision.");
      const value = await google<{containers:Array<{image:string}>}>(`https://run.googleapis.com/v2/${revision}`);
      const image = value.containers[0]?.image;
      if (!image || !/@sha256:[a-f0-9]{64}$/.test(image)) throw new Error("Existing revision does not resolve to an immutable image.");
      images[app.name] = image;
      existing.add(app.name);
    } catch (error) { if (error instanceof GoogleError && error.status === 404) images[app.name] = bootstrap; else throw error; }
  }
  const variables = join(artifacts, "enrollment.tfvars.json");
  await writeFile(variables, JSON.stringify({ project_id: projectId, initial_images: images }), { mode: 0o600 });
  const env = { ...process.env, TF_DATA_DIR:join(artifacts,"terraform-data"), GOOGLE_OAUTH_ACCESS_TOKEN: await command(["gcloud", "auth", "print-access-token"], { quiet: true }) };
  const terraform = (args: string[]) => command(["terraform", `-chdir=${directory}`, ...args], { env });
  await terraform(["init", "-input=false", "-reconfigure", `-backend-config=bucket=${bucket}`, "-backend-config=prefix=delivery/v1"]);
  const state = await terraform(["state", "list"]);
  for (const registry of new Set(apps.map(app=>app.registry))) {
    const address = `google_artifact_registry_repository.images[${JSON.stringify(registry)}]`;
    if (!state.split("\n").includes(address)) {
      const id = `projects/${projectId}/locations/us-east4/repositories/${registry}`;
      try { await google(`https://artifactregistry.googleapis.com/v1/${id}`); await terraform(["import","-input=false",`-var-file=${variables}`,address,id]); }
      catch(error) { if (!(error instanceof GoogleError && error.status===404)) throw error; }
    }
  }
  for (const app of apps) {
    const address = `google_cloud_run_v2_service.app[${JSON.stringify(app.name)}]`;
    if (existing.has(app.name) && !state.split("\n").includes(address)) await terraform(["import", "-input=false", `-var-file=${variables}`, address, `projects/${app.project}/locations/${app.region}/services/${app.service}`]);
  }
  if (apps.some(app => app.data) && !state.split("\n").includes("google_firestore_database.application[0]")) {
    try {
      await google(`https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)`);
      await terraform(["import", "-input=false", `-var-file=${variables}`, "google_firestore_database.application[0]", `projects/${projectId}/databases/(default)`]);
    } catch (error) { if (!(error instanceof GoogleError && error.status === 404)) throw error; }
  }
  const importPresent=async(address:string,id:string,url:string):Promise<void>=>{
    if(state.split("\n").includes(address)) return;
    try { await google(url,"GET",undefined,projectId); await terraform(["import","-input=false",`-var-file=${variables}`,address,id]); }
    catch(error) {if(!(error instanceof GoogleError && error.status===404)) throw error;}
  };
  if(apps.some(app=>app.identity)) {
    await importPresent("google_identity_platform_config.identity[0]",`projects/${projectId}/config`,`https://identitytoolkit.googleapis.com/v2/projects/${projectId}/config`);
    if(!state.split("\n").includes("google_apikeys_key.identity[0]")) {
      const keys=await google<{keys?:Array<{name:string;displayName:string}>;nextPageToken?:string}>(`https://apikeys.googleapis.com/v2/projects/${projectId}/locations/global/keys?pageSize=100`,"GET",undefined,projectId);
      const selected=keys.keys?.filter(key=>key.displayName==="Public Identity Platform client")??[];
      if(keys.nextPageToken || selected.length>1) throw new Error("Existing identity key inventory is ambiguous.");
      if(selected[0]) await terraform(["import","-input=false",`-var-file=${variables}`,"google_apikeys_key.identity[0]",selected[0].name]);
    }
  }
  if(apps.some(app=>app.name==="healthmcp")) {
    await importPresent("google_identity_platform_config.waitlist[0]",`projects/${projectId}/config`,`https://identitytoolkit.googleapis.com/v2/projects/${projectId}/config`);
    for(const collection of ["waitlist","waitlist_quota"]) {const id=`projects/${projectId}/databases/(default)/collectionGroups/${collection}/fields/expiresAt`;await importPresent(`google_firestore_field.waitlist_expiry["${collection}"]`,id,`https://firestore.googleapis.com/v1/${id}`);}
    if(!state.split("\n").includes("google_recaptcha_enterprise_key.waitlist[0]")) {
      const keys=await google<{keys?:Array<{name:string;displayName:string}>;nextPageToken?:string}>(`https://recaptchaenterprise.googleapis.com/v1/projects/${projectId}/keys?pageSize=100`,"GET",undefined,projectId);
      const selected=keys.keys?.filter(key=>key.displayName==="Medlock waitlist ownership")??[];
      if(keys.nextPageToken || selected.length>1) throw new Error("Existing reCAPTCHA key inventory is ambiguous.");
      if(selected[0]) await terraform(["import","-input=false",`-var-file=${variables}`,"google_recaptcha_enterprise_key.waitlist[0]",selected[0].name]);
    }
  }
  if(apps.some(app=>app.name==="virtual-care-mcp")) {const id=`projects/${projectId}/databases/(default)/collectionGroups/visits/fields/expiresAt`;await importPresent("google_firestore_field.visits_expiry[0]",id,`https://firestore.googleapis.com/v1/${id}`);}
  const planFile = join(artifacts, "enrollment.tfplan");
  await terraform(["plan", "-input=false", `-var-file=${variables}`, `-out=${planFile}`]);
  const plan = JSON.parse(await terraform(["show", "-json", planFile])) as { resource_changes?: Array<{ address: string; change: { actions: string[] } }> };
  if (plan.resource_changes?.some(change => change.change.actions.includes("delete"))) throw new Error("Enrollment refuses deletion or replacement of existing infrastructure.");
  const changes = plan.resource_changes?.filter(change => change.change.actions.some(action => action !== "no-op")) ?? [];
  console.log(JSON.stringify({ project: projectId, changes: changes.map(change => ({ address: change.address, actions: change.change.actions })), artifacts }));
  if (apply) {
    await terraform(["apply", "-input=false", "-auto-approve", planFile]);
    const { environments } = await import("./environments.ts");
    await environments(apps);
    console.log(JSON.stringify({ event: "enrollment-applied", project: projectId }));
  }
  // Keep private plans for owner inspection; never place state or plans in the repository.
}

if (import.meta.main) await provision(Bun.argv[2] ?? "", Bun.argv.includes("--apply"));
