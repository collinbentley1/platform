import { test, expect } from "bun:test";
import { reviewedCommit, reviewRequestDue } from "../delivery/review.ts";

test("recognizes a completed source-bound Codex summary without treating a running or failed review as approval", () => {
  const body = '<!-- codex-pull-request-review-summary -->\n| Review | Status | Commit | Review trigger |\n| 📝 **Code Review** | ✅ **Completed** <relative-time datetime="2026-10-26T12:00:00Z">now</relative-time> | `abc1234` | PR opened |';
  expect(reviewedCommit(body)).toBe("abc1234");
  expect(reviewedCommit(body.replace("Completed", "Running"))).toBeUndefined();
  expect(reviewedCommit(body.replace("Completed", "Failed"))).toBeUndefined();
  expect(reviewedCommit(body.replace("<!-- codex-pull-request-review-summary -->", ""))).toBeUndefined();
});

test("failed reviews can be retried on the upgrade schedule without spamming a running review",()=>{const head="a".repeat(40);const previous={body:`@codex review\n<!-- platform-review-head:${head} -->`,created_at:"2030-01-01T00:00:00Z",user:{id:1}};expect(reviewRequestDue([previous],head,Date.parse("2030-01-01T03:59:00Z"))).toBe(false);expect(reviewRequestDue([previous],head,Date.parse("2030-01-01T04:00:00Z"))).toBe(true);expect(reviewRequestDue([previous,{body:`<!-- codex-pull-request-review-summary --> {"commit_sha":"${head}","status":"running"}`,created_at:previous.created_at,user:{id:199175422}}],head,Date.parse("2030-01-01T05:00:00Z"))).toBe(false);});
