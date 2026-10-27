import { test, expect } from "@playwright/test";

test("production sign-in and durable owner-scoped CRUD", async ({ page, context }) => {
  test.skip(!process.env.PLATFORM_TEST_ORIGIN, "Runs only against the protected synthetic production account.");
  const email = process.env.PLATFORM_TEST_EMAIL; const password = process.env.PLATFORM_TEST_PASSWORD;
  if (!email || !password) throw new Error("Protected synthetic account configuration is required.");
  const title = `Synthetic smoke ${crypto.randomUUID()}`; let id: string | undefined;
  try {
    await page.goto("/"); await page.getByLabel("Email", { exact: true }).fill(email); await page.getByLabel("Password", { exact: true }).fill(password);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.getByLabel("New note").fill(title); await page.getByRole("button", { name: "Add note", exact: true }).click();
    await expect(page.getByText(title, { exact: true })).toBeVisible();
    const notes = (await (await context.request.get("/api/notes")).json()).notes as Array<{ id: string; title: string }>;
    id = notes.find(note => note.title === title)?.id; expect(id).toBeTruthy();
    await page.reload(); await expect(page.getByText(title, { exact: true })).toBeVisible();
    await page.getByRole("button", { name: `Delete ${title}`, exact: true }).click(); await expect(page.getByText(title, { exact: true })).toHaveCount(0);
    await page.getByRole("button", { name: "Sign out", exact: true }).click(); expect((await context.request.get("/api/notes")).status()).toBe(401);
  } finally { if (id) await context.request.delete(`/api/notes/${id}`, { headers: { Origin: process.env.PLATFORM_TEST_ORIGIN! } }); }
});
