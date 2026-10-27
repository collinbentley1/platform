import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { api, graphql, pages, GitHubError, repository, pullRequest, type PullRequest } from "./github.ts";
import { upgrade, requireSha } from "./consumer.ts";
import { command } from "./process.ts";
import { automatedReview, requestReview, consumerReviewCheck } from "./review.ts";

type Check = { name: string; status: string; conclusion: string | null; app: { id: number }; id: number };
export function checksPassed(checks: readonly Check[], required: readonly { context: string; app_id: number | null }[]): boolean {
  const latest = new Map<string, Check>();
  for (const check of checks) { const key = `${check.app.id}:${check.name}`; if ((latest.get(key)?.id ?? 0) < check.id) latest.set(key, check); }
  if ([...latest.values()].some(check => check.status !== "completed" || !["success", "neutral", "skipped"].includes(check.conclusion ?? ""))) return false;
  return required.every(rule => [...latest.values()].some(check => check.name === rule.context && (rule.app_id === null || rule.app_id === check.app.id) && check.conclusion === "success"));
}

export async function latestRelease(read: <T>(path:string)=>Promise<T> = api): Promise<{ sha: string; tag: string }> {
  const release = await read<{ tag_name: string; draft: boolean; prerelease: boolean }>("/repos/collinbentley1/platform/releases/latest");
  if (release.draft || release.prerelease || !/^v[0-9]+\.[0-9]+\.[0-9]+$/.test(release.tag_name)) throw new Error("Invalid platform release.");
  let object = (await read<{ object: { type: string; sha: string } }>(`/repos/collinbentley1/platform/git/ref/tags/${release.tag_name}`)).object;
  for (let i = 0; object.type === "tag" && i < 3; i++) object = (await read<{ object: { type: string; sha: string } }>(`/repos/collinbentley1/platform/git/tags/${requireSha(object.sha)}`)).object;
  if (object.type !== "commit") throw new Error("Release does not resolve to a commit.");
  const sha = requireSha(object.sha);
  const ancestry = await read<{ status: string }>(`/repos/collinbentley1/platform/compare/${sha}...main`);
  if (!["ahead", "identical"].includes(ancestry.status)) throw new Error("Release is not from protected platform main.");
  return { sha, tag: release.tag_name };
}

export async function proposeUpgrade(source: string, release: { sha: string; tag: string }, adopt = false): Promise<PullRequest | undefined> {
  const repo = repository(); const branch = `platform/upgrade-${requireSha(release.sha).slice(0, 12)}`;
  const existing = await api<PullRequest[]>(`/repos/${repo}/pulls?state=open&head=collinbentley1:${branch}`);
  if (existing.length === 1) return existing[0];
  if (existing.length > 1) throw new Error("Ambiguous upgrade proposal.");
  const base = await api<{ sha: string }>(`/repos/${repo}/commits/main`);
  const references=await api<Array<{ref:string;object:{sha:string}}>>(`/repos/${repo}/git/matching-refs/heads/${branch}`);
  const reference=references.find(value=>value.ref===`refs/heads/${branch}`);
  let baseline=base.sha; let completedTree:string|undefined;
  if(reference) {
    const declined=await api<Array<{merged_at:string|null}>>(`/repos/${repo}/pulls?state=closed&head=collinbentley1:${branch}`);
    if(declined.some(pr=>!pr.merged_at)) return undefined;
    const ancestry=await api<{status:string}>(`/repos/${repo}/compare/${requireSha(reference.object.sha)}...${base.sha}`);
    if(["ahead","identical"].includes(ancestry.status)) baseline=reference.object.sha;
    else {
      const commit=await api<{parents:Array<{sha:string}>;tree:{sha:string}}>(`/repos/${repo}/git/commits/${reference.object.sha}`);
      if(commit.parents.length!==1) throw new Error("An interrupted upgrade branch has unexpected history.");
      baseline=requireSha(commit.parents[0]!.sha); completedTree=commit.tree.sha;
      const parent=await api<{status:string}>(`/repos/${repo}/compare/${baseline}...${base.sha}`);
      if(!["ahead","identical"].includes(parent.status)) throw new Error("Interrupted upgrade is not based on protected main history.");
    }
  }
  const directory = await mkdtemp(join(tmpdir(), "platform-upgrade-"));
  try {
    const token = Bun.env.GH_TOKEN; if (!token) throw new Error("Upgrade installation token is missing.");
    const env = { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "http.https://github.com/.extraheader", GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic ${Buffer.from(`x-access-token:${token}`).toString("base64")}` };
    const git = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "filter.lfs.smudge=", "-c", "filter.lfs.required=false", "-c", "submodule.recurse=false", "-c", "protocol.file.allow=never"];
    await command([...git, "init", directory], { env });
    await command([...git, "remote", "add", "origin", `https://github.com/${repo}.git`], { cwd: directory, env });
    await command([...git, "fetch", "--depth=1", "origin", requireSha(baseline)], { cwd: directory, env });
    await command([...git, "checkout", "--detach", "FETCH_HEAD"], { cwd: directory, env });
    const changed = await upgrade(directory, source, release.sha, { adopt });
    if (!changed.length) return undefined;
    const additions: Array<{path:string;contents:string}> = []; const deletions: Array<{path:string}> = [];
    for (const path of changed) { const content = await readFile(join(directory, path)).catch(error => { if(error.code === "ENOENT") return undefined; throw error; }); if(content) additions.push({path,contents:content.toString("base64")}); else deletions.push({path}); }
    if(completedTree) {
      await command([...git,"add","--all","--",...changed],{cwd:directory,env});
      const expectedTree=await command([...git,"write-tree"],{cwd:directory,env});
      if(expectedTree!==completedTree) throw new Error("Interrupted upgrade branch differs from the exact managed upgrade.");
    } else {
      if(!reference) await api(`/repos/${repo}/git/refs`, "POST", { ref: `refs/heads/${branch}`, sha: baseline });
      await graphql(`mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid}}}`, { input: { branch: { repositoryNameWithOwner: repo, branchName: branch }, expectedHeadOid: baseline, message: { headline: `Update platform to ${release.tag}` }, fileChanges: { additions, deletions } } });
    }
    return await api<PullRequest>(`/repos/${repo}/pulls`, "POST", { title: `Update platform to ${release.tag}`, head: branch, base: "main", body: `Updates the managed platform contract to ${release.tag}.` });
  } finally { await rm(directory, { recursive: true, force: true }); }
}

export async function enableVerifiedMerge(prNumber: string, timeoutMs = 20 * 60_000): Promise<void> {
  const pr = await pullRequest(prNumber); let head = pr.head.sha;
  // Allow the PR-open automatic review webhook to establish its current-head summary.
  await Bun.sleep(30_000);
  await requestReview(prNumber, head);
  const rules = await api<{ required_status_checks?: { checks: Array<{ context: string; app_id: number | null }> } }>(`/repos/${repository()}/branches/main/protection`);
  const required = rules.required_status_checks?.checks ?? [];
  if (!required.some(rule => [consumerReviewCheck,"Automated review"].includes(rule.context) && rule.app_id === 15368)) throw new Error("Automatic upgrades require the trusted automated-review check.");
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const current = await pullRequest(prNumber); if (current.head.sha !== head) throw new Error("Upgrade head changed.");
    if (current.mergeable_state === "behind") {
      await api(`/repos/${repository()}/pulls/${prNumber}/update-branch`, "PUT", {expected_head_sha:head});
      let refreshed = await pullRequest(prNumber);
      for (let attempt=0; refreshed.head.sha===head && attempt<12; attempt++) { await Bun.sleep(2000); refreshed=await pullRequest(prNumber); }
      if (refreshed.head.sha===head) throw new Error("Branch refresh did not complete; the upgrade remains open.");
      head = refreshed.head.sha;
      await requestReview(prNumber, head);
      continue;
    }
    const checks: Check[] = [];
    for (let page = 1; page <= 50; page++) {
      const result = await api<{ check_runs: Check[] }>(`/repos/${repository()}/commits/${head}/check-runs?filter=latest&per_page=100&page=${page}`);
      checks.push(...result.check_runs); if (result.check_runs.length < 100) break;
      if (page === 50) throw new Error("Check inventory exceeds bounds.");
    }
    if (checksPassed(checks, required) && await automatedReview(prNumber, head)) {
      const latest = await pullRequest(prNumber); if (latest.head.sha !== head) throw new Error("Upgrade head changed before merge admission.");
      let merged:{merged:boolean};
      try { merged=await api<{merged:boolean}>(`/repos/${repository()}/pulls/${prNumber}/merge`,"PUT",{sha:head,merge_method:"squash"}); }
      catch(error) {
        // GitHub can lag the completed checks while recalculating protected-branch admission.
        if(error instanceof GitHubError && [405,409].includes(error.status)) {await Bun.sleep(20_000);continue;}
        throw error;
      }
      if(!merged.merged) throw new Error("Verified automatic merge did not complete.");
      console.log(JSON.stringify({ event: "upgrade-auto-merged", repository: repository(), pullRequest: prNumber, head })); return;
    }
    await Bun.sleep(20_000);
  }
  throw new Error("Upgrade remains open because checks or automated review have not passed.");
}

if (import.meta.main) {
  const release = await latestRelease();
  const source = resolve(Bun.argv[2] ?? ".");
  const current = (await command(["git", "rev-parse", "HEAD"], { cwd: source })).trim();
  if (current !== release.sha) throw new Error("Upgrade source must be the exact published release.");
  const pr = await proposeUpgrade(source, release, Bun.argv.includes("--adopt"));
  if (pr) await enableVerifiedMerge(String(pr.number));
}
