import { resolve, join } from "node:path";
import { mkdir, cp } from "node:fs/promises";
import { projects, type Project } from "./catalog.ts";
import { api, output } from "./github.ts";
import { requireSha, doctor } from "./consumer.ts";
import { command } from "./process.ts";
import { checksPassed, latestRelease } from "./upgrade.ts";

type Item = { app: string; sha: string; release: string; project: string; number: string; pr: string };
async function eligible(app: Project, sha: string): Promise<boolean> {
  const repo = app.repository ?? app.name;
  const result = await api<{ check_runs: Parameters<typeof checksPassed>[0] }>(`/repos/collinbentley1/${repo}/commits/${sha}/check-runs?filter=latest&per_page=100`);
  if (result.check_runs.length >= 100) throw new Error("Check inventory exceeds the delivery bound.");
  const required = [{ context: repo === "platform" ? "Complete starter and container" : "Bun verify / Bun verify", app_id: 15368 }];
  return checksPassed(result.check_runs, required);
}
async function plan(): Promise<void> {
  const release = await latestRelease(); const selected = Bun.env.PLATFORM_APP;
  if (selected && !projects.some(app => app.name === selected)) throw new Error("Application is not registered.");
  const items: Item[] = [];
  for (const app of projects.filter(app => !selected || app.name === selected)) {
    const repo = app.repository ?? app.name;
    const metadata = await api<{ id: number; private: boolean }>(`/repos/collinbentley1/${repo}`);
    if (String(metadata.id) !== app.repositoryId || metadata.private) throw new Error("Application source identity or visibility changed.");
    const pr = Bun.env.PLATFORM_PR ?? "";
    let sha: string;
    if (pr) {
      if (!selected || !/^[1-9][0-9]*$/.test(pr)) throw new Error("Select one application for a preview.");
      const pull = await api<{ state: string; draft: boolean; head: { sha: string; repo: { id: number } }; base: { ref: string } }>(`/repos/collinbentley1/${repo}/pulls/${pr}`);
      if (pull.state !== "open" || pull.draft || pull.base.ref !== "main" || String(pull.head.repo.id) !== app.repositoryId) throw new Error("Preview is not an eligible same-repository pull request.");
      sha = requireSha(pull.head.sha);
    } else sha = requireSha((await api<{ sha: string }>(`/repos/collinbentley1/${repo}/commits/main`)).sha);
    if (!await eligible(app, sha)) { if (selected) throw new Error("Application checks have not passed."); continue; }
    items.push({ app: app.name, sha, release: release.sha, project: app.project, number: app.number, pr });
  }
  await output({ matrix: JSON.stringify({ include: items }), ready: String(items.length > 0) });
}
async function source(): Promise<void> {
  const app = projects.find(value => value.name === Bun.env.PLATFORM_APP); if (!app) throw new Error("Unknown application.");
  const sha = requireSha(Bun.env.SOURCE_SHA ?? ""); const release = requireSha(Bun.env.RELEASE_SHA ?? "");
  const directory = resolve(Bun.env.APPLICATION_DIRECTORY ?? "application");
  if (app.sourceDirectory) {
    await command(["bun", "tools/platform-v1.ts", "init", "platform-reference", directory, "--sha", release], { cwd: resolve("release") });
  } else {
    await mkdir(directory, { recursive: false });
    const git = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "filter.lfs.smudge=", "-c", "filter.lfs.required=false", "-c", "submodule.recurse=false", "-c", "protocol.file.allow=never"];
    const env = { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" };
    await command([...git, "init", directory], { env });
    await command([...git, "fetch", "--depth=1", `https://github.com/collinbentley1/${app.name}.git`, sha], { cwd: directory, env });
    await command([...git, "checkout", "--detach", "FETCH_HEAD"], { cwd: directory, env });
  }
  const failures = await doctor(directory, resolve("release"), release);
  if (failures.length) throw new Error(`Application has not consumed the selected release: ${failures.join(", ")}`);
  // Build receives data only, no checkout hooks or repository credentials.
}
if (import.meta.main) {
  if (Bun.argv[2] === "plan") await plan();
  else if (Bun.argv[2] === "source") await source();
  else throw new Error("Expected plan or source.");
}
