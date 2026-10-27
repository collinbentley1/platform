import { test, expect } from "bun:test";
import { ensureCloudRunCap } from "../delivery/operations.ts";

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
    expect(path).toBe(`${account}/budgets?pageSize=1000`);
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

test("incomplete or ambiguous inventory cannot create another cap", async () => {
  for (const inventory of [{ budgets: [], nextPageToken: "next" }, { budgets: [cap(), cap()] }]) {
    const request = async <T>(_path: string, body?: unknown): Promise<T> => {
      expect(body).toBeUndefined();
      return structuredClone(inventory) as T;
    };
    await expect(ensureCloudRunCap(app, account, request)).rejects.toThrow();
  }
});
