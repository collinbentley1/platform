import { describe, test, expect } from "bun:test";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { doctor, upgrade } from "../delivery/consumer.ts";

const source = resolve(import.meta.dir, "..");
const first = "a".repeat(40); const second = "b".repeat(40);
describe("managed platform upgrades", () => {
  test("upgrades the complete contract without changing product files, and repeated runs make no changes", async () => {
    const root = await mkdtemp(join(tmpdir(), "platform-upgrade-"));
    try {
      await writeFile(join(root, "product.ts"), "custom frontend and product code");
      await mkdir(join(root, "src"));
      await writeFile(join(root, "src/server.ts"), 'import {secureHandler} from "../.platform/runtime/http.ts";\nexport const handler = secureHandler(() => new Response("custom"));\n');
      await upgrade(root, source, first, { adopt: true }); expect(await doctor(root, source, first)).toEqual([]);
      const planned = await upgrade(root, source, second, { check: true }); expect(planned).toContain(".platform/release.json");
      expect(JSON.parse(await readFile(join(root, ".platform/release.json"), "utf8")).sha).toBe(first);
      await upgrade(root, source, second); expect(await doctor(root, source, second)).toEqual([]);
      expect(await upgrade(root, source, second)).toEqual([]);
      expect(await readFile(join(root, "product.ts"), "utf8")).toBe("custom frontend and product code");
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  test("refuses to overwrite managed edits before writing any file", async () => {
    const root = await mkdtemp(join(tmpdir(), "platform-upgrade-"));
    try {
      await upgrade(root, source, first, { adopt: true }); const lock = await readFile(join(root, ".platform/release.json"), "utf8");
      await writeFile(join(root, ".platform/runtime/http.ts"), "a local change");
      await expect(upgrade(root, source, second)).rejects.toThrow("local managed-file change");
      expect(await readFile(join(root, ".platform/release.json"), "utf8")).toBe(lock);
      expect(await readFile(join(root, ".platform/runtime/http.ts"), "utf8")).toBe("a local change");
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});
