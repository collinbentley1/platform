import { test, expect } from "bun:test";
import { checksPassed } from "../delivery/upgrade.ts";
test("automatic merge requires every configured check from its expected app and waits for other running checks", () => {
  const required = [{ context: "Verification", app_id: 15368 }];
  const pass = { name: "Verification", status: "completed", conclusion: "success", app: { id: 15368 }, id: 1 };
  expect(checksPassed([pass], required)).toBe(true);
  expect(checksPassed([{ ...pass, app: { id: 123 } }], required)).toBe(false);
  expect(checksPassed([pass, { ...pass, id: 2, status: "in_progress", conclusion: null }], required)).toBe(false);
  expect(checksPassed([pass, { ...pass, id: 2, name: "Other check", conclusion: "failure" }], required)).toBe(false);
  expect(checksPassed([], required)).toBe(false);
});
