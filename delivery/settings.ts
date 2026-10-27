import { command, github } from "./process.ts";
import { projects, platformRepositoryId } from "./catalog.ts";

const actions = [
  "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
  "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
  "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
  "actions/create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349",
  "google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093",
  "google-github-actions/setup-gcloud@aa5489c8933f4cc7a4f7d45035b3b1440c9c10db",
  "collinbentley1/platform/.github/workflows/*@*",
];
export async function settings(name: string): Promise<void> {
  if (Bun.env.GITHUB_ACTIONS) throw new Error("Repository enrollment requires the owner's GitHub session.");
  const expectedId = name === "platform" ? platformRepositoryId : projects.find(app => app.name === name)?.repositoryId;
  if (!expectedId) throw new Error("Repository is not registered.");
  const path = `repos/collinbentley1/${name}`;
  const metadata = await github<{ id: number }>(path);
  if (String(metadata.id) !== expectedId) throw new Error("Repository numeric identity changed.");
  const write = (endpoint: string, value?: unknown, method = "PUT") => command(["gh", "api", "--method", method, endpoint, ...(value === undefined ? [] : ["--input", "-"])], value === undefined ? {} : {stdin:JSON.stringify(value)});
  await write(`${path}/actions/permissions`, {enabled:true,allowed_actions:"selected",sha_pinning_required:true});
  await write(`${path}/actions/permissions/selected-actions`, {github_owned_allowed:false,verified_allowed:false,patterns_allowed:actions});
  await write(`${path}/actions/permissions/workflow`, {default_workflow_permissions:"read",can_approve_pull_request_reviews:false});
  await write(path, {allow_auto_merge:true,delete_branch_on_merge:true,security_and_analysis:{secret_scanning:{status:"enabled"},secret_scanning_push_protection:{status:"enabled"}}}, "PATCH");
  await write(`${path}/vulnerability-alerts`);
  await write(`${path}/automated-security-fixes`);
  console.log(JSON.stringify({repository:name,actions:"sha-only",nativeSecurity:true,autoMerge:true}));
}
if (import.meta.main) for (const name of Bun.argv.slice(2)) await settings(name);
