import { appendFile } from "node:fs/promises";

export function repository(): string {
  const name = Bun.env.PLATFORM_TARGET_REPOSITORY ?? Bun.env.GITHUB_REPOSITORY ?? "";
  if (!/^collinbentley1\/[a-zA-Z0-9._-]+$/.test(name)) throw new Error("Unexpected GitHub repository.");
  return name;
}
export class GitHubError extends Error { constructor(readonly status:number){super(`GitHub request failed (${status}).`);} }
export async function api<T>(path: string, method = "GET", body?: unknown): Promise<T> {
  if (!path.startsWith("/") || path.startsWith("//") || !Bun.env.GH_TOKEN) throw new Error("Invalid GitHub request.");
  const response = await fetch(`https://api.github.com${path}`, { method, headers: { Authorization: `Bearer ${Bun.env.GH_TOKEN}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(30_000), redirect: "error" });
  if (!response.ok) throw new GitHubError(response.status);
  return response.status === 204 ? undefined as T : await response.json() as T;
}
export async function pages<T>(path: string): Promise<T[]> {
  const rows: T[] = [];
  for (let page = 1; page <= 50; page++) {
    const result = await api<T[]>(`${path}${path.includes("?") ? "&" : "?"}per_page=100&page=${page}`);
    if (!Array.isArray(result)) throw new Error("Invalid paginated GitHub result.");
    rows.push(...result); if (result.length < 100) return rows;
  }
  throw new Error("GitHub inventory exceeds its pagination bound.");
}
export async function output(values: Record<string, string>): Promise<void> {
  for (const [name, value] of Object.entries(values)) if (!/^[a-z_]+$/.test(name) || /[\r\n]/.test(value)) throw new Error("Invalid workflow output.");
  if (Bun.env.GITHUB_OUTPUT) await appendFile(Bun.env.GITHUB_OUTPUT, Object.entries(values).map(([name, value]) => `${name}=${value}\n`).join(""));
  else console.log(JSON.stringify(values));
}
export type PullRequest = { number: number; state: string; draft: boolean; mergeable_state?: string; head: { sha: string; repo: { id: number; full_name: string } }; base: { ref: string; repo: { id: number } }; node_id: string };
export async function pullRequest(number: string): Promise<PullRequest> {
  if (!/^[1-9][0-9]*$/.test(number)) throw new Error("Invalid pull request number.");
  const pr = await api<PullRequest>(`/repos/${repository()}/pulls/${number}`);
  if (pr.state !== "open" || pr.base.ref !== "main" || pr.head.repo.id !== pr.base.repo.id || !/^[a-f0-9]{40}$/.test(pr.head.sha)) throw new Error("Pull request is not an eligible same-repository head.");
  return pr;
}
export async function graphql<T>(query: string, variables: Record<string, unknown>): Promise<T> {
  const result = await api<{ data: T; errors?: unknown }>("/graphql", "POST", { query, variables });
  if (result.errors) throw new Error("GitHub GraphQL request failed.");
  return result.data;
}
