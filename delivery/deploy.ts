import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { imageName, type Project } from "./catalog.ts";
import { command, gcloud } from "./process.ts";
import { google, operation } from "./google.ts";
import { scanImage } from "./scan.ts";
import { api } from "./github.ts";
import type { ImageEvidence } from "./oci.ts";

type Traffic = { revision?: string; percent?: number; tag?: string; type?: string };
type Service = { name: string; etag: string; uri: string; traffic?: Traffic[]; trafficStatuses?: Traffic[]; template: { serviceAccount: string }; latestReadyRevision?: string };
type Revision = { name: string; serviceAccount: string; containers: Array<{ image: string }>; conditions: Array<{ type: string; state: string }>; labels?: Record<string, string> };

export function runtimeIdentity(app: Project, preview = false): string { return `${preview ? "preview" : "runtime"}-${app.service.slice(0, 20)}@${app.project}.iam.gserviceaccount.com`; }
export function servicePath(app: Project, preview = false): string { return `projects/${app.project}/locations/${app.region}/services/${app.service}${preview ? "-preview-v1" : ""}`; }
export async function service(app: Project, preview = false): Promise<Service> { return google<Service>(`https://run.googleapis.com/v2/${servicePath(app, preview)}`); }

export async function requireCurrentSource(app: Project, evidence: ImageEvidence, pr?: string): Promise<void> {
  if (Bun.env.GITHUB_ACTIONS !== "true") return; // Owner CLI supports testing an exact unmerged checkout.
  const platform = await api<{ sha: string }>("/repos/collinbentley1/platform/commits/main");
  if (platform.sha !== evidence.platformSha) throw new Error("Platform authority changed while this deployment was running.");
  const repo = app.repository ?? app.name;
  const identity = await api<{ id: number }>(`/repos/collinbentley1/${repo}`);
  if (String(identity.id) !== app.repositoryId) throw new Error("Repository identity changed.");
  if (pr) {
    if (!/^[1-9][0-9]*$/.test(pr)) throw new Error("Invalid preview number.");
    const value = await api<{ state: string; draft: boolean; head: { sha: string; repo: { id: number } }; base: { ref: string } }>(`/repos/collinbentley1/${repo}/pulls/${pr}`);
    if (value.state !== "open" || value.draft || value.base.ref !== "main" || String(value.head.repo.id) !== app.repositoryId || value.head.sha !== evidence.sourceSha) throw new Error("Preview head is stale or no longer eligible.");
  } else {
    const head = await api<{ sha: string }>(`/repos/collinbentley1/${repo}/commits/main`);
    if (head.sha !== evidence.sourceSha) throw new Error("Application head changed while this deployment was running.");
  }
}

export function previewEnvironment(app: Project): Record<string, string> {
  if (app.name === "healthmcp") return { WAITLIST_BACKEND: "memory", WAITLIST_ACTIVATION_ENABLED: "false" };
  if (app.name === "runsetta") return { RUNSETTA_OFFLINE: "1" };
  if (app.name === "virtual-care-mcp") return { VISIT_STORE: "memory" };
  if (app.identity) return { PLATFORM_PREVIEW: "1" };
  return {};
}

async function probe(url: string, nonce: string, token?: string): Promise<void> {
  const response = await fetch(new URL("/livez", url), { redirect: "error", signal: AbortSignal.timeout(20_000), ...(token ? { headers: { Authorization: `Bearer ${token}` } } : {}) });
  if (!response.ok) throw new Error("Deployment health request failed.");
  const value = await response.json() as { deployment?: unknown };
  if (value.deployment !== nonce) throw new Error("Health response belongs to a different revision.");
}

function routed(traffic: readonly Traffic[]): string {
  return JSON.stringify(traffic.filter(target => (target.percent ?? 0) > 0).map(target => ({ revision: target.revision?.split("/").at(-1), percent: target.percent })).sort((a, b) => (a.revision ?? "").localeCompare(b.revision ?? "")));
}

export async function deploy(app: Project, evidence: ImageEvidence, previewPr?: string): Promise<{ url: string; revision: string }> {
  const preview = Boolean(previewPr); const name = servicePath(app, preview);
  await requireCurrentSource(app, evidence, previewPr);
  await scanImage(app, evidence.runnableDigest);
  const before = await service(app, preview);
  const previousTraffic = before.trafficStatuses ?? [];
  const nonce = crypto.randomUUID(); const suffix = `p${nonce.replaceAll("-", "").slice(0, 18)}`;
  const revisionName = `${app.service}${preview ? "-preview-v1" : ""}-${suffix}`;
  const tag = previewPr ? `pr-${previewPr}` : "candidate";
  const directory = await mkdtemp(join(tmpdir(), "platform-deploy-"));
  const environment: Record<string, string> = {
    ...(preview ? previewEnvironment(app) : app.env), NODE_ENV: "production", PLATFORM_DEPLOY_NONCE: nonce,
  };
  if (app.identity) {
    if (preview) environment.PUBLIC_ORIGIN = before.uri;
    else { const key = Bun.env.IDENTITY_API_KEY; if (!key) throw new Error("Identity client configuration is missing."); environment.IDENTITY_API_KEY = key; }
  }
  const secrets = preview ? [] : Object.entries(app.secrets).map(([key, value]) => `${key}=${value}`);
  await writeFile(join(directory, "environment.json"), JSON.stringify(environment), { mode: 0o600 });
  try {
    await requireCurrentSource(app, evidence, previewPr);
    await gcloud(["run", "deploy", `${app.service}${preview ? "-preview-v1" : ""}`, `--project=${app.project}`, `--region=${app.region}`, `--image=${imageName(app)}@${evidence.digest}`, `--service-account=${runtimeIdentity(app, preview)}`, `--env-vars-file=${join(directory, "environment.json")}`, ...(secrets.length ? [`--set-secrets=${secrets.join(",")}`] : ["--clear-secrets"]), "--no-traffic", `--tag=${tag}`, `--revision-suffix=${suffix}`, "--min-instances=0", `--max-instances=${preview ? 2 : 10}`, "--memory=512Mi", "--cpu=1", "--concurrency=80", "--timeout=60s", "--ingress=all", preview ? "--invoker-iam-check" : "--no-invoker-iam-check", `--labels=platform-managed=v1,platform-source=${evidence.sourceSha},platform-release=${evidence.platformSha}`]);
    const revision = await google<Revision>(`https://run.googleapis.com/v2/projects/${app.project}/locations/${app.region}/services/${app.service}${preview ? "-preview-v1" : ""}/revisions/${revisionName}`);
    if (revision.serviceAccount !== runtimeIdentity(app, preview) || !revision.conditions.some(condition => condition.type === "Ready" && condition.state === "CONDITION_SUCCEEDED") || ![`${imageName(app)}@${evidence.runnableDigest}`, `${imageName(app)}@${evidence.digest}`].includes(revision.containers[0]?.image ?? "")) throw new Error("Staged runtime identity, image, or readiness differs.");
    const staged = await service(app, preview);
    const target = staged.trafficStatuses?.find(item => item.tag === tag && item.revision?.split("/").at(-1) === revisionName) as Traffic & { uri?: string } | undefined;
    const token = preview ? Bun.env.PLATFORM_PREVIEW_TOKEN ?? await command(["gcloud", "auth", "print-identity-token"], { quiet: true }) : undefined;
    if (!target?.uri) throw new Error("The exact staged revision has no health route.");
    await probe(target.uri, nonce, token);
    if (preview) {
      const anonymous = await fetch(new URL("/livez", target.uri), { redirect: "error", signal: AbortSignal.timeout(15_000) });
      if (![401, 403].includes(anonymous.status)) throw new Error("Private preview accepts anonymous requests.");
      return { url: target.uri, revision: revisionName };
    }
    if (routed(staged.trafficStatuses ?? []) !== routed(previousTraffic)) throw new Error("Production traffic changed during staging.");
    await requireCurrentSource(app, evidence);
    // The etag protects against an overlapping operator or a stale deployment run.
    const result = await google<{ name: string }>(`https://run.googleapis.com/v2/${name}?updateMask=traffic`, "PATCH", { name, etag: staged.etag, traffic: [{ type: "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION", revision: revisionName, percent: 100 }] });
    await operation(result.name);
    const current = await service(app);
    if (routed(current.trafficStatuses ?? []) !== routed([{ revision: revisionName, percent: 100 }])) throw new Error("Production route did not converge to the verified revision.");
    await probe(app.env.PUBLIC_ORIGIN ?? current.uri, nonce);
    console.info(JSON.stringify({ event: "deployment-verified", app: app.name, revision: revisionName, source: evidence.sourceSha, platform: evidence.platformSha }));
    return { url: app.env.PUBLIC_ORIGIN ?? current.uri, revision: revisionName };
  } finally { await rm(directory, { recursive: true, force: true }); }
}
