import { api, graphql, pages, pullRequest, repository } from "./github.ts";

const codexId = 199175422;
export function reviewedCommit(body: string): string | undefined {
  if (!body.includes("<!-- codex-pull-request-review-summary -->")) return undefined;
  return /\|[^|\n]*Code Review[^|\n]*\|[^|\n]*Completed[^|\n]*\|\s*`([a-f0-9]{7,40})`/.exec(body)?.[1];
}

export async function automatedReview(number: string, expectedHead: string): Promise<boolean> {
  const pr = await pullRequest(number); if (pr.head.sha !== expectedHead || pr.draft) return false;
  const comments = await pages<{ user: { id: number }; body: string }>(`/repos/${repository()}/issues/${number}/comments`);
  const summary = comments.filter(comment => comment.user.id === codexId).map(comment => reviewedCommit(comment.body)).filter(Boolean).at(-1);
  if (!summary) return false;
  const commit = await api<{ sha: string }>(`/repos/${repository()}/commits/${summary}`);
  if (commit.sha !== expectedHead) return false;
  let cursor: string | null = null;
  const [owner, name] = repository().split("/");
  for (let page = 0; page < 50; page++) {
    const data: { repository: { pullRequest: { reviewThreads: { nodes: Array<{ isResolved: boolean }>; pageInfo: { hasNextPage: boolean; endCursor: string | null } } } } } = await graphql(`query($owner:String!,$name:String!,$number:Int!,$cursor:String){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewThreads(first:100,after:$cursor){nodes{isResolved}pageInfo{hasNextPage endCursor}}}}}`, { owner, name, number: Number(number), cursor });
    const threads = data.repository.pullRequest.reviewThreads;
    if (threads.nodes.some(thread => !thread.isResolved)) return false;
    if (!threads.pageInfo.hasNextPage) break;
    if (page === 49) throw new Error("Review thread pagination bound exceeded.");
    cursor = threads.pageInfo.endCursor;
  }
  const reviews = await pages<{ user: { id: number }; state: string; commit_id: string }>(`/repos/${repository()}/pulls/${number}/reviews`);
  const latest = new Map<number, string>();
  for (const review of reviews) if (["APPROVED", "CHANGES_REQUESTED", "DISMISSED"].includes(review.state)) latest.set(review.user.id, review.state);
  return ![...latest.values()].includes("CHANGES_REQUESTED");
}

export async function requestReview(number: string, head: string): Promise<void> {
  const comments = await pages<{ body: string }>(`/repos/${repository()}/issues/${number}/comments`);
  const marker = `<!-- platform-review-head:${head} -->`;
  if (!comments.some(comment => comment.body.includes(marker))) await api(`/repos/${repository()}/issues/${number}/comments`, "POST", { body: `@codex review\n\n${marker}` });
}

export async function reviewGate(number: string, timeoutMs = 15 * 60_000): Promise<void> {
  const pr = await pullRequest(number); if (pr.draft) return; const head = pr.head.sha;
  const check = await api<{ id: number }>(`/repos/${repository()}/check-runs`, "POST", { name: "Automated review", head_sha: head, status: "in_progress" });
  const deadline = Date.now() + timeoutMs;
  let success = false;
  try {
    // The platform upgrade producer requests a review; the generic read-only gate does not post comments.
    while (Date.now() < deadline) {
      const current = await pullRequest(number); if (current.head.sha !== head) throw new Error("Review head changed.");
      if (await automatedReview(number, head)) { success = true; return; }
      await Bun.sleep(20_000);
    }
    throw new Error("Automated review has not completed, or feedback remains unresolved.");
  } finally { await api(`/repos/${repository()}/check-runs/${check.id}`, "PATCH", { status: "completed", conclusion: success ? "success" : "failure", completed_at: new Date().toISOString() }); }
}

if (import.meta.main) await reviewGate(Bun.argv[2] ?? "");
