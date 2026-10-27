import { projects, imageName, type Project } from "./catalog.ts";
import { service, servicePath, runtimeIdentity } from "./deploy.ts";
import { api } from "./github.ts";
import { google, operation } from "./google.ts";

export type Target = {revision?:string;percent?:number;tag?:string;type?:string};
export function removeClosedTags(traffic: readonly Target[], closed: ReadonlySet<string>): Target[] {
  if (!traffic.some(item => (item.percent ?? 0) > 0)) throw new Error("Preview has no resolved base route.");
  return traffic.filter(item => {
    if (!item.tag || !closed.has(item.tag)) return true;
    if ((item.percent ?? 0) > 0) throw new Error("A closed preview tag also receives base-service traffic; operator review is required.");
    return false;
  }).map(item => { if (!item.revision) throw new Error("Preview traffic target is unresolved."); return ({type:"TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION",revision:item.revision,...(item.percent === undefined?{}:{percent:item.percent}),...(item.tag?{tag:item.tag}:{})}); });
}

export async function cleanupPreviews(app: Project): Promise<void> {
  const repo = app.repository ?? app.name;
  const metadata = await api<{id:number}>(`/repos/collinbentley1/${repo}`);
  if (String(metadata.id) !== app.repositoryId) throw new Error("Preview repository identity changed.");
  const current = await service(app,true); const targets = current.trafficStatuses ?? [];
  const closed = new Set<string>();
  for (const target of targets) {
    const match = /^pr-([1-9][0-9]*)$/.exec(target.tag ?? ""); if (!match) continue;
    const pr = await api<{state:string}>(`/repos/collinbentley1/${repo}/pulls/${match[1]}`);
    if (pr.state !== "closed") continue;
    if (!target.revision || !target.revision.startsWith(`${app.service}-preview-v1-`) || !/^[a-z0-9-]+$/.test(target.revision)) throw new Error("Closed preview target is not resolved to this preview service.");
    const revision = await google<{serviceAccount:string;containers:Array<{image:string;env?:Array<{name:string;value?:string}>}>}>(`https://run.googleapis.com/v2/${servicePath(app,true)}/revisions/${target.revision}`);
    const source = revision.containers[0]?.env?.find(item=>item.name==="PLATFORM_SOURCE_SHA")?.value;
    if (revision.serviceAccount !== runtimeIdentity(app,true) || !revision.containers[0]?.image.startsWith(`${imageName(app)}@sha256:`) || !/^[a-f0-9]{40}$/.test(source ?? "")) throw new Error("Closed preview identity or source evidence differs.");
    closed.add(target.tag!);
  }
  if (!closed.size) return;
  const traffic = removeClosedTags(targets,closed);
  // Re-read PR state before the etag-guarded update; a reopened PR keeps its tag.
  for (const tag of closed) if ((await api<{state:string}>(`/repos/collinbentley1/${repo}/pulls/${tag.slice(3)}`)).state !== "closed") throw new Error("Preview was reopened during cleanup.");
  const result = await google<{name:string}>(`https://run.googleapis.com/v2/${servicePath(app,true)}?updateMask=traffic`,"PATCH",{name:current.name,etag:current.etag,traffic});
  await operation(result.name);
  const after = await service(app,true);
  if (after.trafficStatuses?.some(item=>item.tag&&closed.has(item.tag))) throw new Error("Preview tag cleanup did not converge.");
  console.log(JSON.stringify({event:"closed-preview-tags-removed",app:app.name,tags:[...closed]}));
}
if (import.meta.main) {
  const app=projects.find(app=>app.name===Bun.env.PLATFORM_APP);if(!app)throw new Error("Unknown application.");
  await cleanupPreviews(app);
}
