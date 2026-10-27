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

export function reviewRequestDue(comments: readonly {body:string;created_at:string;user:{id:number}}[],head:string,now=Date.now()): boolean {
  const marker=`<!-- platform-review-head:${head} -->`;
  const previous=comments.filter(comment=>comment.body.includes(marker)).at(-1);
  const summary=comments.filter(comment=>comment.user.id===codexId && comment.body.includes("<!-- codex-pull-request-review-summary -->")).at(-1);
  const completed=summary?reviewedCommit(summary.body):undefined;
  if(completed && head.startsWith(completed)) return false;
  if(summary?.body.includes(head) && /\"status\":\"running\"/.test(summary.body)) return false;
  return !previous || now-Date.parse(previous.created_at)>=4*60*60_000;
}

type RefreshComment = {id:number;body:string;created_at:string;user:{id:number};performed_via_github_app?:{id:number}|null};
export function recoverableReviewDraft(comments: readonly RefreshComment[], head:string, draftActor:number|undefined): RefreshComment|undefined {
  return comments.filter(comment=>comment.performed_via_github_app?.id===5488696 && comment.user.id===draftActor && comment.body.includes(`<!-- platform-review-pending:${head} -->`)).at(-1);
}

export async function requestReview(number: string, head: string): Promise<void> {
  const comments = await pages<RefreshComment>(`/repos/${repository()}/issues/${number}/comments`);
  const pr=await pullRequest(number);
  if(pr.head.sha!==head) throw new Error("Review refresh requires the unchanged upgrade PR.");
  let pending:RefreshComment|undefined;
  if(pr.draft) {
    const events=await pages<{event:string;actor:{id:number}}>(`/repos/${repository()}/issues/${number}/events`);
    pending=recoverableReviewDraft(comments,head,events.filter(event=>event.event==="converted_to_draft").at(-1)?.actor.id);
    if(!pending)throw new Error("A manually drafted upgrade requires owner review.");
  } else {
    if (!reviewRequestDue(comments,head)) return;
    pending=await api<RefreshComment>(`/repos/${repository()}/issues/${number}/comments`, "POST", {body:`Refreshing automatic review.\n\n<!-- platform-review-pending:${head} -->`});
    await graphql(`mutation($id:ID!){convertPullRequestToDraft(input:{pullRequestId:$id}){pullRequest{id}}}`,{id:pr.node_id});
  }
  // Repository-wide automatic reviews use the configured owner's review allowance.
  // A bot-authored @mention can resolve a different billing identity.
  if((await pullRequest(number)).head.sha!==head) throw new Error("Upgrade head changed during review refresh.");
  const markReady=()=>graphql(`mutation($id:ID!){markPullRequestReadyForReview(input:{pullRequestId:$id}){pullRequest{id}}}`,{id:pr.node_id});
  try {await markReady();} catch(error) {
    const current=await pullRequest(number);if(current.head.sha!==head)throw error;
    if(current.draft)await markReady(); // Pending provenance lets the next producer run retry another failure.
  }
  // Start the cooldown only after the ready-for-review transition succeeded.
  await api(`/repos/${repository()}/issues/comments/${pending.id}`,"PATCH",{body:`Refresh automatic review.\n\n<!-- platform-review-head:${head} -->`});
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
    // The published check remains unsuccessful. A later review event can refresh it
    // without leaving a failed polling-worker job on the same commit forever.
    console.info(JSON.stringify({event:"automated-review-pending",repository:repository(),pullRequest:number,head}));
  } finally { await api(`/repos/${repository()}/check-runs/${check.id}`, "PATCH", { status: "completed", conclusion: success ? "success" : "failure", completed_at: new Date().toISOString() }); }
}

export async function reviewSweep():Promise<void> {
  const pulls=await pages<{number:number;draft:boolean;head:{sha:string;repo:{id:number}|null};base:{ref:string;repo:{id:number}}}>(`/repos/${repository()}/pulls?state=open`);
  for(const pr of pulls.filter(pr=>!pr.draft && pr.base.ref==="main" && pr.head.repo?.id===pr.base.repo.id)) {
    const head=pr.head.sha;
    const admitted=await automatedReview(String(pr.number),head);
    const result=await api<{check_runs:Array<{id:number;name:string;app:{id:number};status:string;conclusion:string|null}>}>(`/repos/${repository()}/commits/${head}/check-runs?check_name=Automated%20review&filter=latest&per_page=100`);
    if(result.check_runs.length>=100)throw new Error("Review check inventory exceeds its bound.");
    const previous=result.check_runs.filter(check=>check.name==="Automated review" && check.app.id===15368).sort((a,b)=>b.id-a.id)[0];
    if(admitted ? previous?.status==="completed" && previous.conclusion==="success" : previous?.conclusion!=="success")continue;
    const current=await pullRequest(String(pr.number));if(current.head.sha!==head || current.draft)continue;
    await api(`/repos/${repository()}/check-runs`,"POST",{name:"Automated review",head_sha:head,status:"completed",conclusion:admitted?"success":"failure",completed_at:new Date().toISOString()});
    console.log(JSON.stringify({event:"review-admission-refreshed",repository:repository(),pullRequest:pr.number,head,admitted}));
  }
}

if (import.meta.main) {
  if(Bun.argv[2]==="sweep")await reviewSweep();
  else await reviewGate(Bun.argv[2] ?? "");
}
