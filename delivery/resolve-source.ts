import { pullRequest, output, type PullRequest } from "./github.ts";
import { requireSha } from "./consumer.ts";

export async function resolveSource(requested: string, fallback: string, read: (number: string) => Promise<PullRequest> = pullRequest): Promise<{sha:string;pr:string;reviewable:string}> {
  if (!requested) return {sha:requireSha(fallback),pr:"",reviewable:"false"};
  if (!/^[1-9][0-9]*$/.test(requested)) throw new Error("Invalid requested pull request.");
  const pr = await read(requested);
  return {sha:requireSha(pr.head.sha),pr:requested,reviewable:String(!pr.draft)};
}
if (import.meta.main) await output(await resolveSource(Bun.env.REQUESTED_PR ?? "",Bun.env.DEFAULT_SHA ?? ""));
