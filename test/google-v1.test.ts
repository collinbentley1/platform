import { expect, test } from "bun:test";
import { operation } from "../delivery/google.ts";

test("Firestore operations completed inline do not poll an absent operation resource", async () => {
  const original = globalThis.fetch; let requests = 0;
  globalThis.fetch = (async (_input: unknown) => { requests++; return new Response("Completed operation was not persisted.", {status:404}); }) as typeof fetch;
  const name = "projects/demo-platform/databases/recovery/operations/inline-operation";
  try {
    await expect(operation({name, done:true})).resolves.toBeUndefined();
    await expect(operation({name, done:true, error:{code:9}})).rejects.toThrow("Google operation failed.");
    expect(requests).toBe(0);
  } finally { globalThis.fetch = original; }
});
