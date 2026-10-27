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
  if (apps.some(app => app.data)) await command(["gcloud", "services", "enable", "firestore.googleapis.com", `--project=${projectId}`, "--quiet"]);
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
      const value = await gcloud<{ status: { imageDigest: string } }>(["run", "revisions", "describe", revision.split("/").at(-1)!, `--project=${app.project}`, `--region=${app.region}`]);
      images[app.name] = value.status.imageDigest;
      existing.add(app.name);
    } catch (error) { if (error instanceof GoogleError && error.status === 404) images[app.name] = bootstrap; else throw error; }
  }
  const variables = join(artifacts, "enrollment.tfvars.json");
  await writeFile(variables, JSON.stringify({ project_id: projectId, initial_images: images }), { mode: 0o600 });
  const env = { ...process.env, GOOGLE_OAUTH_ACCESS_TOKEN: await command(["gcloud", "auth", "print-access-token"], { quiet: true }) };
  const terraform = (args: string[]) => command(["terraform", `-chdir=${directory}`, ...args], { env });
  await terraform(["init", "-input=false", "-reconfigure", `-backend-config=bucket=${bucket}`, "-backend-config=prefix=delivery/v1"]);
  const state = await terraform(["state", "list"]);
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
  const planFile = join(artifacts, "enrollment.tfplan");
  await terraform(["plan", "-input=false", `-var-file=${variables}`, `-out=${planFile}`]);
  const plan = JSON.parse(await terraform(["show", "-json", planFile])) as { resource_changes?: Array<{ address: string; change: { actions: string[] } }> };
  if (plan.resource_changes?.some(change => change.change.actions.includes("delete"))) throw new Error("Enrollment refuses deletion or replacement of existing infrastructure.");
  const changes = plan.resource_changes?.filter(change => change.change.actions.some(action => action !== "no-op")) ?? [];
  console.log(JSON.stringify({ project: projectId, changes: changes.map(change => ({ address: change.address, actions: change.change.actions })), artifacts }));
  if (apply) {
    await terraform(["apply", "-input=false", "-auto-approve", planFile]);
    console.log(JSON.stringify({ event: "enrollment-applied", project: projectId }));
  }
  // Keep private plans for owner inspection; never place state or plans in the repository.
}

if (import.meta.main) await provision(Bun.argv[2] ?? "", Bun.argv.includes("--apply"));
