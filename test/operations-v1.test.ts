import { test, expect } from "bun:test";
import { ensureCloudRunCap } from "../delivery/operations.ts";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";

const app = { project: "test-project", number: "123456789" };
const account = "billingAccounts/000000-111111-222222";
const cap = (state = "CONFIGURED", units = "4") => ({
  name: `${account}/budgets/existing-cap`,
  budgetFilter: { projects: [`projects/${app.number}`], services: ["services/152E-C115-5142"] },
  amount: { specifiedAmount: { currencyCode: "USD", units } },
  spendCap: { outputState: state },
});

test("a new project gets a monthly native Cloud Run cap and rerunning creates no duplicate", async () => {
  const budgets: ReturnType<typeof cap>[] = [];
  const writes: unknown[] = [];
  const request = async <T>(path: string, body?: unknown): Promise<T> => {
    if (body) {
      expect(path).toBe(`${account}/budgets`);
      writes.push(body); budgets.push(cap());
      return structuredClone(budgets[0]) as T;
    }
    const query = new URL(`https://billing.test/${path}`).searchParams;
    expect(query.get("scope")).toBe(`projects/${app.number}`);
    expect(query.get("pageSize")).toBe("100");
    return structuredClone({ budgets }) as T;
  };
  await ensureCloudRunCap(app, account, request);
  await ensureCloudRunCap(app, account, request);
  expect(writes).toHaveLength(1);
  expect(writes[0]).toMatchObject({
    budgetFilter: { projects: [`projects/${app.number}`], services: ["services/152E-C115-5142"], calendarPeriod: "MONTH", creditTypesTreatment: "EXCLUDE_ALL_CREDITS" },
    amount: { specifiedAmount: { currencyCode: "USD", units: "4", nanos: 0 } },
    spendCap: { inputState: "CONFIGURED" },
  });
});

test("setup preserves stricter and enforced caps without raising or lifting them", async () => {
  for (const existing of [cap("CONFIGURED", "2"), cap("ENFORCED")]) {
    const request = async <T>(_path: string, body?: unknown): Promise<T> => {
      expect(body).toBeUndefined();
      return structuredClone({ budgets: [existing] }) as T;
    };
    expect(await ensureCloudRunCap(app, account, request)).toEqual(existing);
  }
});

test("a lifted or excessive existing cap needs owner attention rather than a duplicate", async () => {
  for (const existing of [cap("AWAITING_NEXT_PERIOD"), cap("CONFIGURED", "8")]) {
    const request = async <T>(_path: string, body?: unknown): Promise<T> => {
      expect(body).toBeUndefined();
      return structuredClone({ budgets: [existing] }) as T;
    };
    await expect(ensureCloudRunCap(app, account, request)).rejects.toThrow("owner attention");
  }
});

test("a cap on a later page is reused instead of duplicated", async () => {
  const pages: string[] = [];
  const request = async <T>(path: string, body?: unknown): Promise<T> => {
    expect(body).toBeUndefined();
    const query = new URL(`https://billing.test/${path}`).searchParams;
    expect(query.get("scope")).toBe(`projects/${app.number}`);
    const token = query.get("pageToken") ?? ""; pages.push(token);
    return structuredClone(token === "" ? { budgets: [], nextPageToken: "next/+?" } : { budgets: [cap()] }) as T;
  };
  expect(await ensureCloudRunCap(app, account, request)).toEqual(cap());
  expect(pages).toEqual(["", "next/+?"]);
});

test("duplicate caps across pages cannot create another cap", async () => {
  const request = async <T>(path: string, body?: unknown): Promise<T> => {
    expect(body).toBeUndefined();
    const token = new URL(`https://billing.test/${path}`).searchParams.get("pageToken");
    return structuredClone({ budgets: [cap()], ...(!token ? { nextPageToken: "next" } : {}) }) as T;
  };
  await expect(ensureCloudRunCap(app, account, request)).rejects.toThrow("ambiguous");
});

test("onboarding uses normal delivery while credential changes can explicitly force it", async () => {
  const directory = await mkdtemp(join(tmpdir(), "platform-delivery-arguments-"));
  const calls = join(directory, "calls.jsonl");
  try {
    await writeFile(join(directory, "gh"), '#!/usr/bin/env bun\nimport {appendFileSync} from "node:fs";\nappendFileSync(Bun.env.PLATFORM_TEST_GH_CALLS,JSON.stringify(Bun.argv.slice(2))+"\\n");\nif(Bun.argv[2]==="workflow")console.log("https://github.com/collinbentley1/platform/actions/runs/123");\n', { mode: 0o700 });
    for (const force of [false, true]) {
      await writeFile(calls, "");
      const script = `import {deliver} from ${JSON.stringify(resolve(import.meta.dir, "../delivery/create.ts"))}; await deliver("test-app"${force ? ",{force:true}" : ""});`;
      const child = Bun.spawn([process.execPath, "-e", script], { env: { ...process.env, PATH: `${directory}:${process.env.PATH}`, PLATFORM_TEST_GH_CALLS: calls }, stdout: "pipe", stderr: "pipe" });
      const [status, output, error] = await Promise.all([child.exited, new Response(child.stdout).text(), new Response(child.stderr).text()]);
      expect({ status, error }).toEqual({ status: 0, error: "" });
      expect(output).toContain("workflow-started");
      const recorded = (await readFile(calls, "utf8")).trim().split("\n").map(line => JSON.parse(line) as string[]);
      expect(recorded).toHaveLength(2);
      expect(recorded[0]!.slice(0, 3)).toEqual(["workflow", "run", "deliver.yml"]);
      expect(recorded[0]).toContain("application=test-app");
      expect(recorded[0]!.includes("force=true")).toBe(force);
      expect(recorded[1]!.slice(0, 3)).toEqual(["run", "watch", "123"]);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});
