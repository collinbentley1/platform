import { command, github } from "./process.ts";
import { projects, platformRepositoryId } from "./catalog.ts";

const actions = [
  "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
  "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
  "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
  "actions/create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349",
  "google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093",
  "google-github-actions/setup-gcloud@aa5489c8933f4cc7a4f7d45035b3b1440c9c10db",
  "github/codeql-action/init@793b778da9c9275a0f276522b27cb5fc14bba279",
  "github/codeql-action/analyze@793b778da9c9275a0f276522b27cb5fc14bba279",
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
  // GitHub enforces full SHA pins. Trust stays limited to these repositories;
  // routine reviewed action updates no longer need an owner allowlist mutation.
  await write(`${path}/actions/permissions/selected-actions`, {github_owned_allowed:false,verified_allowed:false,patterns_allowed:actions.map(action => action.slice(0,action.lastIndexOf("@"))+"@*")});
  await write(`${path}/actions/permissions/workflow`, {default_workflow_permissions:"read",can_approve_pull_request_reviews:false});
  await write(path, {allow_auto_merge:true,delete_branch_on_merge:true,security_and_analysis:{secret_scanning:{status:"enabled"},secret_scanning_push_protection:{status:"enabled"}}}, "PATCH");
  await write(`${path}/vulnerability-alerts`);
  await write(`${path}/automated-security-fixes`);
  if (name === "platform") {
    const current=await github<{required_status_checks:{checks:Array<{context:string;app_id:number|null}>}}>(`${path}/branches/main/protection`);
    const checks=[...current.required_status_checks.checks.filter(check=>!["Browser application","CodeQL"].includes(check.context)),{context:"Browser application",app_id:15368},{context:"CodeQL",app_id:57789}];
    await write(`${path}/branches/main/protection/required_status_checks`,{strict:true,checks},"PATCH");
  }
  if (name !== "platform") {
    let existing: {required_status_checks:{checks:Array<{context:string;app_id:number|null}>}};
    try { existing = await github(`${path}/branches/main/protection`); }
    catch {
      // A freshly created application has no branch protection yet.
      await write(`${path}/branches/main/protection`,{required_status_checks:{strict:true,checks:[]},enforce_admins:true,required_pull_request_reviews:null,restrictions:null,allow_force_pushes:false,allow_deletions:false});
      existing = await github(`${path}/branches/main/protection`);
    }
    const replaced = new Set(["CodeQL","Bun verify / Bun verify","Automated review","infrastructure / Terraform validate","infrastructure / Checkov","Socket Firewall / Socket Firewall","Socket Security: Project Report","Socket Security: Pull Request Alerts"]);
    const checks = [...existing.required_status_checks.checks.filter(check=>!replaced.has(check.context)),{context:"CodeQL",app_id:57789},{context:"Bun verify / Bun verify",app_id:15368},{context:"Automated review",app_id:15368},{context:"Socket Security: Project Report",app_id:156372},{context:"Socket Security: Pull Request Alerts",app_id:156372}];
    await write(`${path}/branches/main/protection/required_status_checks`,{strict:true,checks},"PATCH");
    const rulesets=await github<Array<{id:number;name:string}>>(`${path}/rulesets`);
    for(const entry of rulesets.filter(entry=>entry.name==="Require trusted review for non-owner pull requests")) {
      const ruleset=await github<{name:string;target:string;enforcement:string;conditions:unknown;rules:unknown[];bypass_actors:Array<{actor_id:number;actor_type:string;bypass_mode:string}>}>(`${path}/rulesets/${entry.id}`);
      if(!ruleset.bypass_actors.some(actor=>actor.actor_type==="Integration" && actor.actor_id===5488696)) {
        const {name,target,enforcement,conditions,rules,bypass_actors}=ruleset;
        await write(`${path}/rulesets/${entry.id}`,{name,target,enforcement,conditions,rules,bypass_actors:[...bypass_actors,{actor_id:5488696,actor_type:"Integration",bypass_mode:"pull_request"}]});
      }
    }
  }
  console.log(JSON.stringify({repository:name,actions:"sha-only",nativeSecurity:true,autoMerge:true}));
}
if (import.meta.main) for (const name of Bun.argv.slice(2)) await settings(name);
