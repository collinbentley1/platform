import {latestRelease} from "./upgrade.ts";
import {tmpdir} from "node:os";
import { resolve, join } from "node:path";
import { readFile, writeFile, mkdtemp } from "node:fs/promises";
import { command, github, gcloud } from "./process.ts";
import { validateCatalog } from "./catalog.ts";

const root = resolve(import.meta.dir, "..");
const owner = "collinbentley1";
const installationUrls = ["https://github.com/settings/installations/175658023", "https://github.com/settings/installations/67956186", "https://github.com/settings/installations/137315361", "https://chatgpt.com/codex/cloud/settings/code-review"];
export async function create(name: string, args: string[]): Promise<void> {
  const option = (key: string) => { const at = args.indexOf(key); return at < 0 ? undefined : args[at + 1]; };
  const projectId = option("--project");
  if (!/^[a-z][a-z0-9-]{0,17}$/.test(name) || !projectId || !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(projectId)) throw new Error("Usage: platform create <name> --project <id> [--billing-account <id>] [--origin <https-origin>] [--directory <path>] --apply");
  const directory = resolve(option("--directory") ?? join(root, "..", name));
  const apply = args.includes("--apply");
  console.log(JSON.stringify({ name, directory, project: projectId, repository: `${owner}/${name}`, steps: ["scaffold", "repository", "catalog PR", "infrastructure", "application checks", "delivery"], apply }));
  if (!apply) return;
  if (Bun.env.GITHUB_ACTIONS) throw new Error("Project creation requires the owner's local session.");
  if ((await command(["git", "branch", "--show-current"], { cwd: root })) !== "main" || await command(["git", "status", "--porcelain", "--untracked-files=no"], { cwd: root })) throw new Error("Start project creation from a clean platform main checkout.");
  await command(["git","pull","--ff-only"],{cwd:root});
  let cloud: { projectNumber: string; labels?:Record<string,string> };
  try { cloud = await gcloud(["projects", "describe", projectId]); }
  catch {
    const billing = option("--billing-account");
    if (!billing || !/^[A-F0-9]{6}-[A-F0-9]{6}-[A-F0-9]{6}$/.test(billing)) throw new Error("A new Google project requires an explicit --billing-account. No project was created.");
    await command(["gcloud", "projects", "create", projectId, `--name=${name}`, `--labels=platform-onboarding=${name},platform-owner=16823277`, "--quiet"]);
    await command(["gcloud", "billing", "projects", "link", projectId, `--billing-account=${billing}`, "--quiet"]);
    cloud = await gcloud(["projects", "describe", projectId]);
  }
  if(cloud.labels?.["platform-onboarding"]!==name || cloud.labels?.["platform-owner"]!=="16823277")throw new Error("Create uses a dedicated project labeled by this onboarding command. Use enroll to adopt existing projects.");
  const billingState=await gcloud<{billingEnabled:boolean}>(["billing","projects","describe",projectId]);
  if(!billingState.billingEnabled){const billing=option("--billing-account");if(!billing)throw new Error("Resume with --billing-account to enable project billing.");await command(["gcloud","billing","projects","link",projectId,`--billing-account=${billing}`,"--quiet"]);}
  // Start core API activation before source checks and catalog review, allowing
  // Google's project-level permissions to propagate before Terraform runs.
  await command(["gcloud","services","enable","cloudresourcemanager.googleapis.com","iam.googleapis.com",`--project=${projectId}`,"--quiet"]);
  const origin = option("--origin") ?? `https://${name}-${cloud.projectNumber}.us-east4.run.app`;
  if (new URL(origin).origin !== origin || !origin.startsWith("https://")) throw new Error("Use an exact HTTPS origin, without a path.");
  const marker = join(directory, ".platform/onboarding.json");
  const prior = await readFile(marker, "utf8").catch(() => undefined);
  if (prior && JSON.parse(prior).project !== projectId) throw new Error("The local project belongs to another onboarding request.");
  if (!prior) {
    const release=await latestRelease(<T>(path:string)=>github<T>(path.replace(/^\//,"")));
    const revision={sha:release.sha};
    await command(["git","fetch","origin",`refs/tags/${release.tag}:refs/tags/${release.tag}`],{cwd:root});
    const temporary=await mkdtemp(join(tmpdir(),"platform-create-source-"));const source=join(temporary,"release");
    await command(["git","worktree","add","--detach",source,revision.sha],{cwd:root});
    try{await command([process.execPath, "tools/platform.ts", "init", name, directory,"--sha",revision.sha], { cwd: source });}
    finally{await command(["git","worktree","remove",source],{cwd:root});}
    await writeFile(marker, JSON.stringify({ name, project: projectId }) + "\n");
    await command(["git", "init", "-b", "main"], { cwd: directory });
  }
  let repo: { id: number; private: boolean; owner: { login: string } };
  try { repo = await github(`repos/${owner}/${name}`); }
  catch { await command(["gh", "repo", "create", `${owner}/${name}`, "--public", "--description", "Application built on the managed platform"]); repo = await github(`repos/${owner}/${name}`); }
  if (repo.private || repo.owner.login !== owner) throw new Error("Repository authority or visibility differs.");
  if (!await command(["git", "remote"], { cwd: directory })) await command(["git", "remote", "add", "origin", `git@github.com:${owner}/${name}.git`], { cwd: directory });
  if ((await command(["git", "remote", "get-url", "origin"], { cwd: directory })) !== `git@github.com:${owner}/${name}.git`) throw new Error("Unexpected onboarding remote.");
  if(await command(["git","ls-remote","--heads","origin","refs/heads/main"],{cwd:directory}))await command(["git","pull","--ff-only","origin","main"],{cwd:directory});
  if (await command(["git", "status", "--porcelain"], { cwd: directory })) {
    await command([process.execPath, "install", "--ignore-scripts", "--no-env-file"], { cwd: directory });
    await command(["git", "add", "--all"], { cwd: directory });
    await command(["git", "commit", "-m", "Create application"], { cwd: directory });
  }
  await command(["git", "push", "-u", "origin", "main"], { cwd: directory });
  await catalogChange(`register-${name}`,`Register ${name}`, catalog=>{
    const existing=catalog.projects.find(app=>app.name===name);
    if(existing){if(existing.repositoryId!==String(repo.id)||existing.project!==projectId||existing.env.PUBLIC_ORIGIN!==origin)throw new Error("A different project is registered under this name.");return false;}
    if(catalog.projects.some(app=>app.project===projectId && (app.data||app.identity)))throw new Error("Data-backed apps need dedicated Google projects.");
    catalog.projects.push({name,repositoryId:String(repo.id),project:projectId,number:cloud.projectNumber,region:"us-east4",registry:"site",service:name,data:true,identity:true,env:{PUBLIC_ORIGIN:origin,IDENTITY_PROJECT_ID:projectId,FIRESTORE_PROJECT_ID:projectId},secrets:{}});return true;
  });
  await command(["git", "pull", "--ff-only"], { cwd: root });
  // New process reads the newly reviewed catalog, not this process's old import.
  await command([process.execPath,"tools/platform.ts","budget"],{cwd:root});
  await command([process.execPath, "tools/platform.ts", "repository-settings", name], { cwd: root });
  await command([process.execPath, "tools/platform.ts", "enroll", projectId, "--apply"], { cwd: root });
  await workflow("upgrade-consumers.yml", `${owner}/platform`, ["-f", `repository=${name}`]);
  await workflow("application.yml", `${owner}/${name}`);
  await deliver(name);
  console.log(JSON.stringify({ event: "project-deployed", origin, installationUrls }));
}

export async function catalogChange(change:string,title:string,mutate:(catalog:Parameters<typeof validateCatalog>[0])=>boolean):Promise<void>{
  if(Bun.env.GITHUB_ACTIONS || !/^[a-z][a-z0-9-]{0,60}$/.test(change))throw new Error("Catalog updates require an owner session and a scoped branch name.");
  const main=await github<{sha:string}>(`repos/${owner}/platform/commits/main`);
  const file=await github<{content:string}>(`repos/${owner}/platform/contents/delivery/projects.json?ref=${main.sha}`);
  const catalog=JSON.parse(Buffer.from(file.content,"base64").toString("utf8")) as Parameters<typeof validateCatalog>[0];
  if(!mutate(catalog))return;validateCatalog(catalog);
    const branch = `platform/${change}`;
    const pulls = await github<Array<{ number: number; head: { ref: string } }>>(`repos/${owner}/platform/pulls?state=open&head=${owner}:${branch}`);
    let number = pulls[0]?.number;
    if (!number) {
      let parent=main.sha;
      try { await github(`repos/${owner}/platform/git/refs`, ["--method", "POST", "-f", `ref=refs/heads/${branch}`, "-f", `sha=${main.sha}`]); }
      catch {parent=(await github<{object:{sha:string}}>(`repos/${owner}/platform/git/ref/heads/${branch}`)).object.sha;}
      const input = { branch: { repositoryNameWithOwner: `${owner}/platform`, branchName: branch }, expectedHeadOid: parent, message: { headline: title }, fileChanges: { additions: [{ path: "delivery/projects.json", contents: Buffer.from(JSON.stringify(catalog, null, 2) + "\n").toString("base64") }] } };
      const query = "mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid}}}";
      await command(["gh", "api", "graphql", "--input", "-"], { stdin: JSON.stringify({ query, variables: { input } }) });
      const created = await github<{ number: number }>(`repos/${owner}/platform/pulls`, ["--method", "POST", "-f", `head=${branch}`, "-f", "base=main", "-f", `title=${title}`, "-f", `body=${title}.`]); number = created.number;
    }
    console.log(JSON.stringify({ event: "catalog-review", pullRequest: `https://github.com/${owner}/platform/pull/${number}`, installationUrls }));
    const refresh = () => command(["gh", "pr", "update-branch", String(number), "--repo", `${owner}/platform`]);
    await refresh();
    await command(["gh", "pr", "merge", String(number), "--repo", `${owner}/platform`, "--auto", "--squash"]);
    const deadline = Date.now() + 30 * 60_000;
    for (;;) {
      const pull = await github<{ merged: boolean; state: string; mergeable_state?: string }>(`repos/${owner}/platform/pulls/${number}`);
      if (pull.merged) break;
      if (pull.state === "closed" || Date.now() > deadline) throw new Error("Registration is awaiting review. Resolve its checks and rerun this command.");
      if (pull.mergeable_state === "behind") await refresh();
      await Bun.sleep(15_000);
    }

}

export async function deliver(name:string,options:{force?:boolean}={}):Promise<void>{
  await workflow("deliver.yml",`${owner}/platform`,["-f",`application=${name}`,...(options.force?["-f","force=true"]:[])]);
}
async function workflow(file:string,repository:string,fields:string[]=[]):Promise<void>{
  const result=await command(["gh","workflow","run",file,"--repo",repository,"--ref","main",...fields]);
  const run=/actions\/runs\/([0-9]+)/.exec(result)?.[1];
  console.log(JSON.stringify({event:"workflow-started",workflow:file,repository,result,installationUrls}));
  if(!run)throw new Error("Workflow was dispatched; use gh run list to follow it before claiming completion.");
  await command(["gh","run","watch",run,"--repo",repository,"--exit-status"]);
}
