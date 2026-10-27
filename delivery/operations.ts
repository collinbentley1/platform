import { projects, defaults, type Project } from "./catalog.ts";
import { command, gcloud } from "./process.ts";

type NativeBudget = {
  name: string;
  budgetFilter?: { projects?: string[]; services?: string[] };
  amount?: { specifiedAmount?: { currencyCode: string; units?: string; nanos?: number } };
  spendCap?: { outputState: string };
};
type BudgetRequest = <T>(path: string, body?: unknown) => Promise<T>;
const cloudRunService = "services/152E-C115-5142";

export async function ensureCloudRunCap(app: Pick<Project, "project" | "number">, account: string, request: BudgetRequest): Promise<NativeBudget> {
  const inventory = await request<{ budgets?: NativeBudget[]; nextPageToken?: string }>(`${account}/budgets?pageSize=1000`);
  if (inventory.nextPageToken) throw new Error("Budget inventory is incomplete; no cap was created.");
  const matches = (inventory.budgets ?? []).filter(budget => budget.spendCap && budget.budgetFilter?.projects?.includes(`projects/${app.number}`) && budget.budgetFilter?.services?.includes(cloudRunService));
  if (matches.length > 1) throw new Error(`Cloud Run cap is ambiguous for ${app.project}.`);
  const cap = matches[0] ?? await request<NativeBudget>(`${account}/budgets`, {
    displayName: `Platform Cloud Run cap - ${app.project}`,
    budgetFilter: { projects: [`projects/${app.number}`], services: [cloudRunService], creditTypesTreatment: "EXCLUDE_ALL_CREDITS", calendarPeriod: "MONTH" },
    amount: { specifiedAmount: { currencyCode: "USD", units: "4", nanos: 0 } },
    thresholdRules: [0.5, 0.8, 1].map(thresholdPercent => ({ thresholdPercent })),
    notificationsRule: { enableProjectLevelRecipients: true },
    ownershipScope: "ALL_USERS",
    spendCap: { inputState: "CONFIGURED" },
  });
  const money = cap.amount?.specifiedAmount;
  const amount = Number(money?.units ?? 0) + (money?.nanos ?? 0) / 1e9;
  // Keep stricter caps and enforcement intact; setup never raises or lifts them.
  if (money?.currencyCode !== "USD" || !(amount > 0 && amount <= 4) || !["CONFIGURED", "ENFORCED"].includes(cap.spendCap?.outputState ?? "")) throw new Error(`Cloud Run cap for ${app.project} needs owner attention; it was not changed.`);
  return cap;
}

// Owner-only native billing controls; no resident monitoring service.
export async function budget(total: number): Promise<void> {
  if (Bun.env.GITHUB_ACTIONS || !Number.isFinite(total) || total <= 0 || total > defaults.monthlyBudgetUSD) throw new Error("Owner budget must be between zero and 30 USD.");
  const accounts = new Set<string>();
  const enrolled = [...new Map(projects.map(app => [app.project, app])).values()];
  const billing = new Map<string, string>();
  for (const { project } of enrolled) {
    const value = await gcloud<{ billingAccountName: string; billingEnabled: boolean }>(["billing", "projects", "describe", project]);
    if (!value.billingEnabled) throw new Error("An enrolled project's billing is disabled.");
    accounts.add(value.billingAccountName);
    billing.set(project, value.billingAccountName);
  }
  const share = Math.floor(total / accounts.size * 100) / 100;
  for (const account of accounts) {
    const existing = await gcloud<Array<{ name: string; displayName: string }>>(["billing", "budgets", "list", `--billing-account=${account}`]);
    const matches = existing.filter(item => ["Collin all GCP 30 USD monthly alert", "Platform share of combined 30 USD monthly budget"].includes(item.displayName));
    if (matches.length > 1) throw new Error("Budget inventory is ambiguous.");
    await command(["gcloud", "billing", "budgets", matches[0] ? "update" : "create", ...(matches[0] ? [matches[0].name] : []), `--billing-account=${account}`, `--budget-amount=${share}`, "--calendar-period=month", "--display-name=Platform share of combined 30 USD monthly budget", ...(matches[0] ? ["--clear-threshold-rules"] : []), "--add-threshold-rule=percent=0.5,basis=current-spend", "--add-threshold-rule=percent=0.8,basis=current-spend", "--add-threshold-rule=percent=1,basis=current-spend", "--add-threshold-rule=percent=0.9,basis=forecasted-spend", "--quiet"]);
    console.log(JSON.stringify({ event: "budget-email-alert-configured", account, monthlyUSD: share, combinedMonthlyUSD: total, hardCap: false }));
  }
  const quotaProject = enrolled[0]?.project;
  if (!quotaProject) throw new Error("No enrolled project is available for budget setup.");
  await command(["gcloud", "services", "enable", "billingbudgets.googleapis.com", `--project=${quotaProject}`, "--quiet"]);
  const token = await command(["gcloud", "auth", "print-access-token"], { quiet: true });
  const request: BudgetRequest = async <T>(path: string, body?: unknown): Promise<T> => {
    const response = await fetch(`https://billingbudgets.googleapis.com/v1/${path}`, { method: body ? "POST" : "GET", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", "X-Goog-User-Project": quotaProject }, ...(body ? { body: JSON.stringify(body) } : {}), redirect: "error", signal: AbortSignal.timeout(30_000) });
    if (!response.ok) throw new Error(`Native budget API failed (${response.status}). Rerun budget setup after resolving access.`);
    return await response.json() as T;
  };
  for (const app of enrolled) {
    const cap = await ensureCloudRunCap(app, billing.get(app.project)!, request);
    console.log(JSON.stringify({ event: "cloud-run-cap-configured", project: app.project, amount: cap.amount, state: cap.spendCap?.outputState }));
  }
}

export function status(): void {
  for (const app of projects) console.log(JSON.stringify({ app: app.name, production: app.env.PUBLIC_ORIGIN ?? app.env.PUBLIC_BASE_URL ?? `https://${app.service}-${app.number}.${app.region}.run.app`, logs: `https://console.cloud.google.com/run/detail/${app.region}/${app.service}/logs?project=${app.project}`, metrics: `https://console.cloud.google.com/run/detail/${app.region}/${app.service}/metrics?project=${app.project}` }));
}
