import { test, expect } from "bun:test";
import { reviewedCommit, reviewRequestDue, recoverableReviewDraft } from "../delivery/review.ts";

test("recognizes a completed source-bound Codex summary without treating a running or failed review as approval", () => {
  const body = '<!-- codex-pull-request-review-summary -->\n| Review | Status | Commit | Review trigger |\n| 📝 **Code Review** | ✅ **Completed** <relative-time datetime="2026-10-26T12:00:00Z">now</relative-time> | `abc1234` | PR opened |';
  expect(reviewedCommit(body)).toBe("abc1234");
  expect(reviewedCommit(body.replace("Completed", "Running"))).toBeUndefined();
  expect(reviewedCommit(body.replace("Completed", "Failed"))).toBeUndefined();
  expect(reviewedCommit(body.replace("<!-- codex-pull-request-review-summary -->", ""))).toBeUndefined();
});

test("failed reviews can be retried on the upgrade schedule without spamming a running review",()=>{const head="a".repeat(40);const previous={body:`@codex review\n<!-- platform-review-head:${head} -->`,created_at:"2030-01-01T00:00:00Z",user:{id:1}};expect(reviewRequestDue([previous],head,Date.parse("2030-01-01T03:59:00Z"))).toBe(false);expect(reviewRequestDue([previous],head,Date.parse("2030-01-01T04:00:00Z"))).toBe(true);expect(reviewRequestDue([previous,{body:`<!-- codex-pull-request-review-summary --> {"commit_sha":"${head}","status":"running"}`,created_at:previous.created_at,user:{id:199175422}}],head,Date.parse("2030-01-01T05:00:00Z"))).toBe(false);});

 test("a completed review for an older head does not suppress a retry for the current head",()=>{
 const head="a".repeat(40),created_at="2030-01-01T00:00:00Z";
 const comments=[{body:`@codex review\n<!-- platform-review-head:${head} -->`,created_at,user:{id:1}},{body:'<!-- codex-pull-request-review-summary -->\n| 📝 **Code Review** | ✅ **Completed** | `bbbbbbb` |',created_at,user:{id:199175422}}];
 expect(reviewRequestDue(comments,head,Date.parse("2030-01-01T05:00:00Z"))).toBe(true);
 });

test("an automatic review needs no duplicate manual request marker",()=>{const head="a".repeat(40);const comments=[{body:`<!-- codex-pull-request-review-summary --> {"commit_sha":"${head}","status":"running"}`,created_at:"2030-01-01T00:00:00Z",user:{id:199175422}}];expect(reviewRequestDue(comments,head)).toBe(false);});

test("interrupted review refreshes remain recoverable without taking over a human draft",()=>{
  const head="a".repeat(40),pending={id:1,body:`<!-- platform-review-pending:${head} -->`,created_at:"2030-01-01T00:00:00Z",user:{id:123},performed_via_github_app:{id:5488696}};
  expect(reviewRequestDue([pending],head,Date.parse("2030-01-01T00:01:00Z"))).toBe(true);
  expect(recoverableReviewDraft([pending],head,123)).toEqual(pending);
  expect(recoverableReviewDraft([pending],head,456)).toBeUndefined();
  expect(recoverableReviewDraft([{...pending,performed_via_github_app:null}],head,123)).toBeUndefined();
  expect(recoverableReviewDraft([pending],"b".repeat(40),123)).toBeUndefined();
  expect(recoverableReviewDraft([{...pending,body:`<!-- platform-review-head:${head} -->`}],head,123)).toBeUndefined();
});
