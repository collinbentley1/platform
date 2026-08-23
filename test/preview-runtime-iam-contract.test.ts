import { afterEach, describe, expect, test } from "bun:test";
import { chmod, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const helper = join(root, "tools/ci/preview-runtime-iam-contract.sh");
const mock = join(root, "test/fixtures/preview-runtime-iam-mock-curl.ts");
const temporary: string[] = [];

afterEach(async () => Promise.all(temporary.splice(0).map((path) => rm(path, { recursive: true, force: true }))));

describe("preview runtime effective IAM admission", () => {
  test("admits only after 16 complete empty cross-project analyses", async () => {
    const result = await run("clean");
    expect(result.code, result.stderr).toBe(0);
    expect(result.stdout).toContain("preview_runtime_iam_admitted=true");
    expect(result.log.match(/:analyzeIamPolicy/g)?.length).toBe(16);
    expect(result.log.match(/:getIamPolicy/g)?.length).toBe(8);
    expect(result.log.match(/cloudresourcemanager\.googleapis\.com\/v1\/projects\/[^:]+$/gm)?.length).toBe(8);
    expect(result.log).not.toContain("expandGroups");
  });

  for (const mode of [
    "binding",
    "group-binding",
    "direct-binding",
    "broad-principal",
    "project-service-accounts",
    "parent",
    "project-drift",
    "partial",
    "warning",
    "impersonation",
    "malformed",
    "etag-drift",
  ]) {
    test(`fails closed for ${mode}`, async () => {
      const result = await run(mode);
      expect(result.code).not.toBe(0);
      expect(result.stdout).not.toContain("admitted=true");
    });
  }
});

async function run(mode: string) {
  const dir = await mkdtemp(join(tmpdir(), "preview-runtime-iam-"));
  temporary.push(dir);
  const bin = join(dir, "bin");
  await mkdir(bin);
  const wrapper = join(bin, "curl");
  await writeFile(wrapper, `#!/bin/sh\nexec bun "${mock}" "$@"\n`);
  await chmod(wrapper, 0o755);
  const log = join(dir, "calls.log");
  const counts = join(dir, "counts.json");
  await writeFile(log, "");
  await writeFile(counts, "{}");
  const child = Bun.spawn(["/bin/bash", helper, "verify"], {
    cwd: root,
    env: { ...process.env, ACCESS_TOKEN: "mock-token", MOCK_COUNTS: counts, MOCK_LOG: log, MOCK_MODE: mode, PATH: `${bin}:${process.env.PATH}`, RUNNER_TEMP: dir },
    stdout: "pipe", stderr: "pipe",
  });
  const [stdout, stderr, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
  return { code, stdout, stderr, log: await Bun.file(log).text() };
}
