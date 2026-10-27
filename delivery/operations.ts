import { projects } from "./catalog.ts";
import { command, gcloud } from "./process.ts";

// Owner-only setup. Billing email alerts are free; no Pub/Sub, metric alert
// policies, uptime-check resources, log exports or resident monitoring service.
export async function budget(total: number): Promise<void> {
  if (Bun.env.GITHUB_ACTIONS || !Number.isFinite(total) || total <= 0 || total > 30) throw new Error("Owner budget must be between zero and 30 USD.");
  const accounts = new Set<string>();
  for (const project of new Set(projects.map(app => app.project))) {
    const value = await gcloud<{ billingAccountName: string; billingEnabled: boolean }>(["billing", "projects", "describe", project]);
    if (!value.billingEnabled) throw new Error("An enrolled project's billing is disabled.");
    accounts.add(value.billingAccountName);
  }
  const share = Math.floor(total / accounts.size * 100) / 100;
  for (const account of accounts) {
    const existing = await gcloud<Array<{ name: string; displayName: string }>>(["billing", "budgets", "list", `--billing-account=${account}`]);
    const matches = existing.filter(item => ["Collin all GCP 30 USD monthly alert", "Platform share of combined 30 USD monthly budget"].includes(item.displayName));
    if (matches.length > 1) throw new Error("Budget inventory is ambiguous.");
    await command(["gcloud", "billing", "budgets", matches[0] ? "update" : "create", ...(matches[0] ? [matches[0].name] : []), `--billing-account=${account}`, `--budget-amount=${share}`, "--calendar-period=month", "--display-name=Platform share of combined 30 USD monthly budget", ...(matches[0] ? ["--clear-threshold-rules"] : []), "--add-threshold-rule=percent=0.5,basis=current-spend", "--add-threshold-rule=percent=0.8,basis=current-spend", "--add-threshold-rule=percent=1,basis=current-spend", "--add-threshold-rule=percent=0.9,basis=forecasted-spend", "--quiet"]);
    console.log(JSON.stringify({ event: "budget-email-alert-configured", account, monthlyUSD: share, combinedMonthlyUSD: total, hardCap: false }));
  }
}

export function status(): void {
  for (const app of projects) console.log(JSON.stringify({ app: app.name, production: app.env.PUBLIC_ORIGIN ?? app.env.PUBLIC_BASE_URL ?? `https://${app.service}-${app.number}.${app.region}.run.app`, logs: `https://console.cloud.google.com/run/detail/${app.region}/${app.service}/logs?project=${app.project}`, metrics: `https://console.cloud.google.com/run/detail/${app.region}/${app.service}/metrics?project=${app.project}` }));
}
