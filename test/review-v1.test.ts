import { test, expect } from "bun:test";
import { reviewedCommit } from "../delivery/review.ts";

test("recognizes a completed source-bound Codex summary without treating a running or failed review as approval", () => {
  const body = '<!-- codex-pull-request-review-summary -->\n| Review | Status | Commit | Review trigger |\n| 📝 **Code Review** | ✅ **Completed** <relative-time datetime="2026-10-26T12:00:00Z">now</relative-time> | `abc1234` | PR opened |';
  expect(reviewedCommit(body)).toBe("abc1234");
  expect(reviewedCommit(body.replace("Completed", "Running"))).toBeUndefined();
  expect(reviewedCommit(body.replace("Completed", "Failed"))).toBeUndefined();
  expect(reviewedCommit(body.replace("<!-- codex-pull-request-review-summary -->", ""))).toBeUndefined();
});
