import { test, expect, type APIRequestContext } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
const password = "Synthetic-test-password-123!";
async function actionLink(email: string, requestType: string, request: APIRequestContext) {
  const response = await request.get("http://127.0.0.1:9099/emulator/v1/projects/demo-platform-tests/oobCodes");
  const body = await response.json() as { oobCodes: Array<{ email: string; requestType: string; oobLink: string }> };
  const action = body.oobCodes.filter(action => action.email === email && action.requestType === requestType).at(-1);
  expect(action).toBeTruthy(); return action!.oobLink;
}

test("managed signup, verification, durable CRUD, recovery, revocation, isolation and account deletion", async ({ page, context, browser }) => {
  const email = `platform-${crypto.randomUUID()}@example.invalid`;
  await page.goto("/");
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Create account", exact: true }).click();
  await expect(page.getByText("Verify your email, then sign in again.", { exact: false })).toBeVisible();
  expect((await context.request.get("/api/notes")).status()).toBe(403);
  await page.goto(await actionLink(email, "VERIFY_EMAIL", context.request));
  await expect(page).toHaveURL("http://127.0.0.1:8089/");
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByLabel("New note").fill("Browser recovery proof");
  await page.getByRole("button", { name: "Add note", exact: true }).click();
  await expect(page.getByText("Browser recovery proof", { exact: true })).toBeVisible();
  await page.reload(); await expect(page.getByText("Browser recovery proof", { exact: true })).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  const notes = await (await context.request.get("/api/notes")).json();
  expect(notes.notes).toHaveLength(1);
  expect((await context.request.post("/api/notes", { headers: { Origin: "https://untrusted.invalid" }, data: { id: crypto.randomUUID(), title: "forged" } })).status()).toBe(403);
  const oldSession = await browser.newContext({ storageState: await context.storageState() });
  const sessionSecond = Math.floor(Date.now() / 1000);
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByRole("button", { name: "Forgot password", exact: true }).click();
  await expect(page.getByText("If the account exists, a recovery email is on its way.")).toBeVisible();
  const reset = new URL(await actionLink(email, "PASSWORD_RESET", context.request)); const newPassword = password + "-changed";
  // Google's hosted reset revokes sessions using a whole-second cutoff.
  await expect.poll(() => Math.floor(Date.now() / 1000)).toBeGreaterThan(sessionSecond);
  // The official emulator's hosted handler accepts this test-only query field.
  reset.searchParams.set("newPassword", newPassword);
  await page.goto(reset.href);
  await expect(page).toHaveURL("http://127.0.0.1:8089/");
  await expect.poll(async () => (await oldSession.request.get("http://127.0.0.1:8089/api/notes")).status()).toBe(401);
  await oldSession.close();
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(newPassword);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByText("Browser recovery proof", { exact: true })).toBeVisible();
  const other = await browser.newContext();
  const otherEmail = `platform-${crypto.randomUUID()}@example.invalid`;
  const headers = { Origin: "http://127.0.0.1:8089" };
  expect((await other.request.post("http://127.0.0.1:8089/api/account", { headers, data: { email: otherEmail, password } })).ok()).toBe(true);
  expect((await other.request.get(await actionLink(otherEmail, "VERIFY_EMAIL", context.request))).ok()).toBe(true);
  await other.request.post("http://127.0.0.1:8089/api/session", { headers, data: { email: otherEmail, password } });
  expect((await (await other.request.get("http://127.0.0.1:8089/api/notes")).json()).notes).toEqual([]);
  await other.request.delete(`http://127.0.0.1:8089/api/notes/${notes.notes[0].id}`, { headers });
  expect((await (await context.request.get("/api/notes")).json()).notes).toHaveLength(1);
  await other.request.delete("http://127.0.0.1:8089/api/account", { headers }); await other.close();
  const peer = await browser.newContext({ storageState: await context.storageState() });
  await page.getByRole("button", { name: "Sign out all devices", exact: true }).click();
  await expect.poll(async () => (await peer.request.get("http://127.0.0.1:8089/api/notes")).status()).toBe(401); await peer.close();
  await page.getByLabel("Email", { exact: true }).fill(email); await page.getByLabel("Password", { exact: true }).fill(newPassword);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByText("Browser recovery proof", { exact: true })).toBeVisible();
  page.on("dialog", dialog => dialog.accept());
  await page.getByRole("button", { name: "Delete account and notes", exact: true }).click();
  await expect(page.getByText("Account and notes deleted.")).toBeVisible();
  expect((await context.request.get("/api/notes")).status()).toBe(401);
});

test("untrusted origins, anonymous writes and excessive login attempts are rejected", async ({ request }) => {
  expect((await request.post("/api/notes", { headers: { Origin: "http://127.0.0.1:8089" }, data: { id: crypto.randomUUID(), title: "anonymous" } })).status()).toBe(401);
  const email = `rate-${crypto.randomUUID()}@example.invalid`;
  let last = 0;
  for(let attempt=0;attempt<6;attempt++) last=(await request.post("/api/session", { headers: { Origin: "http://127.0.0.1:8089" }, data: { email, password } })).status();
  expect(last).toBe(429);
  const burst = await Promise.all(Array.from({ length: 20 }, () => request.get("/livez")));
  expect(burst.every(response => response.ok())).toBe(true);
});
