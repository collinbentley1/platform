import { resolve, join } from "node:path";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { command, github, gcloud } from "./process.ts";
import { validateCatalog, type Project } from "./catalog.ts";

const root = resolve(import.meta.dir, "..");
const owner = "collinbentley1";
const installationUrls = ["https://github.com/settings/installations/175658023", "https://chatgpt.com/settings/code-review"];
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
  let cloud: { projectNumber: string };
  try { cloud = await gcloud(["projects", "describe", projectId]); }
  catch {
    const billing = option("--billing-account");
    if (!billing || !/^[A-F0-9]{6}-[A-F0-9]{6}-[A-F0-9]{6}$/.test(billing)) throw new Error("A new Google project requires an explicit --billing-account. No project was created.");
    await command(["gcloud", "projects", "create", projectId, `--name=${name}`, "--quiet"]);
    await command(["gcloud", "billing", "projects", "link", projectId, `--billing-account=${billing}`, "--quiet"]);
    cloud = await gcloud(["projects", "describe", projectId]);
  }
  const origin = option("--origin") ?? `https://${name}-${cloud.projectNumber}.us-east4.run.app`;
  if (new URL(origin).origin !== origin || !origin.startsWith("https://")) throw new Error("Use an exact HTTPS origin, without a path.");
  const marker = join(directory, ".platform/onboarding.json");
  const prior = await readFile(marker, "utf8").catch(() => undefined);
  if (prior && JSON.parse(prior).project !== projectId) throw new Error("The local project belongs to another onboarding request.");
  if (!prior) {
    await command([process.execPath, "tools/platform.ts", "init", name, directory], { cwd: root });
    await writeFile(marker, JSON.stringify({ name, project: projectId }) + "\n");
    await command(["git", "init", "-b", "main"], { cwd: directory });
  }
  let repo: { id: number; private: boolean; owner: { login: string } };
  try { repo = await github(`repos/${owner}/${name}`); }
  catch { await command(["gh", "repo", "create", `${owner}/${name}`, "--public", "--description", "Application built on the managed platform"]); repo = await github(`repos/${owner}/${name}`); }
  if (repo.private || repo.owner.login !== owner) throw new Error("Repository authority or visibility differs.");
  if (!await command(["git", "remote"], { cwd: directory })) await command(["git", "remote", "add", "origin", `git@github.com:${owner}/${name}.git`], { cwd: directory });
  if ((await command(["git", "remote", "get-url", "origin"], { cwd: directory })) !== `git@github.com:${owner}/${name}.git`) throw new Error("Unexpected onboarding remote.");
  if (await command(["git", "status", "--porcelain"], { cwd: directory })) {
    await command([process.execPath, "install", "--ignore-scripts", "--no-env-file"], { cwd: directory });
    await command(["git", "add", "--all"], { cwd: directory });
    await command(["git", "commit", "-m", "Create application"], { cwd: directory });
  }
  await command(["git", "push", "-u", "origin", "main"], { cwd: directory });
  const main = await github<{ sha: string }>(`repos/${owner}/platform/commits/main`);
  const file = await github<{ content: string; sha: string }>(`repos/${owner}/platform/contents/delivery/projects.json?ref=${main.sha}`);
  const catalog = JSON.parse(Buffer.from(file.content, "base64").toString("utf8")) as { schemaVersion: number; owner: string; platformRepositoryId: string; projects: Project[] };
  const existing = catalog.projects.find(app => app.name === name);
  if (existing && (existing.repositoryId !== String(repo.id) || existing.project !== projectId)) throw new Error("A different project is registered under this name.");
  if (!existing) {
    catalog.projects.push({ name, repositoryId: String(repo.id), project: projectId, number: cloud.projectNumber, region: "us-east4", registry: "site", service: name, data: true, identity: true, env: { PUBLIC_ORIGIN: origin, IDENTITY_PROJECT_ID: projectId, FIRESTORE_PROJECT_ID: projectId }, secrets: {} });
    validateCatalog(catalog);
    const branch = `platform/register-${name}`;
    const pulls = await github<Array<{ number: number; head: { ref: string } }>>(`repos/${owner}/platform/pulls?state=open&head=${owner}:${branch}`);
    let number = pulls[0]?.number;
    if (!number) {
      try { await github(`repos/${owner}/platform/git/refs`, ["--method", "POST", "-f", `ref=refs/heads/${branch}`, "-f", `sha=${main.sha}`]); } catch { throw new Error("Reserved registration branch already exists; inspect it before resuming."); }
      const input = { branch: { repositoryNameWithOwner: `${owner}/platform`, branchName: branch }, expectedHeadOid: main.sha, message: { headline: `Register ${name}` }, fileChanges: { additions: [{ path: "delivery/projects.json", contents: Buffer.from(JSON.stringify(catalog, null, 2) + "\n").toString("base64") }] } };
      const query = "mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid}}}";
      await command(["gh", "api", "graphql", "--input", "-"], { stdin: JSON.stringify({ query, variables: { input } }) });
      const created = await github<{ number: number }>(`repos/${owner}/platform/pulls`, ["--method", "POST", "-f", `head=${branch}`, "-f", "base=main", "-f", `title=Register ${name}`, "-f", `body=Register ${name} for managed delivery.`]); number = created.number;
    }
    console.log(JSON.stringify({ event: "registration-review", pullRequest: `https://github.com/${owner}/platform/pull/${number}`, installationUrls }));
    await command(["gh", "pr", "merge", String(number), "--repo", `${owner}/platform`, "--auto", "--squash"]);
    const deadline = Date.now() + 30 * 60_000;
    for (;;) {
      const pull = await github<{ merged: boolean; state: string }>(`repos/${owner}/platform/pulls/${number}`);
      if (pull.merged) break;
      if (pull.state === "closed" || Date.now() > deadline) throw new Error("Registration is awaiting review. Resolve its checks and rerun this command.");
      await Bun.sleep(15_000);
    }
  }
  await command(["git", "pull", "--ff-only"], { cwd: root });
  // New process reads the newly reviewed catalog, not this process's old import.
  await command([process.execPath, "tools/platform.ts", "repository-settings", name], { cwd: root });
  await command([process.execPath, "tools/platform.ts", "enroll", projectId, "--apply"], { cwd: root });
  await command(["gh", "workflow", "run", "upgrade-consumers.yml", "--repo", `${owner}/platform`, "--ref", "main"]);
  await command(["gh", "workflow", "run", "deliver.yml", "--repo", `${owner}/platform`, "--ref", "main", "-f", `application=${name}`]);
  console.log(JSON.stringify({ event: "project-enrolled", origin, installationUrls, note: "Selected-repository Apps still require their owner authorization. Enable Codex and Socket for the new repo, then rerun if an App check reports missing access." }));
}
