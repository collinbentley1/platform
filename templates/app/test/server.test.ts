import { expect, test } from "bun:test";

test("template has a test harness", () => {
  expect("__APP_NAME__").toBeTruthy();
});
