import { expect, test } from "bun:test";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

async function readAllows(options: { readonly inherited: boolean; readonly ancestorReadable: boolean; readonly cleanupStatus?: number }): Promise<unknown> {
  const directory = await mkdtemp(join(tmpdir(), "canary-allows-"));
  const member = "serviceAccount:gha-deny-canary@fixture-test.iam.gserviceaccount.com";
  const calls: string[] = [];
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      const path = new URL(request.url).pathname;
      calls.push(`${request.method} ${path}`);
      if (path.endsWith(":getIamPolicy")) {
        const inherited = options.inherited && path === "/v3/folders/12345:getIamPolicy";
        return Response.json({ etag: "fixture-etag", version: 3, bindings: inherited ? [{ role: "roles/viewer", members: [member] }] : [] });
      }
      if (path === "/v3/projects/fixture-test") return Response.json({ parent: "folders/12345" });
      if (path === "/v3/folders/12345" && options.ancestorReadable) return Response.json({ parent: "organizations/99999" });
      if (path === "/v3/folders/54321" || path === "/v3/projects/deny-canary-11111") return Response.json({}, { status: options.cleanupStatus ?? 404 });
      return Response.json({}, { status: 403 });
    },
  });
  try {
    await mkdir(join(directory, "bin"));
    await writeFile(join(directory, "bin/gcloud"), "#!/bin/sh\nprintf 'fixture-credential'\n", { mode: 0o700 });
    const process = Bun.spawn(["bash", join(import.meta.dir, "../tools/ci/protected-recovery-allow-state.sh")], {
      stdin: "pipe", stdout: "pipe", stderr: "pipe",
      env: { PATH: `${directory}/bin:${Bun.env.PATH ?? "/usr/bin:/bin"}`, PROTECTED_RECOVERY_RESOURCEMANAGER_ENDPOINT: `http://127.0.0.1:${server.port}` },
    });
    process.stdin.write(JSON.stringify({ principal: member.slice("serviceAccount:".length), resource: options.cleanupStatus === undefined ? "projects/fixture-test" : "organizations/99999", ...(options.cleanupStatus === undefined ? {} : { folder_id: "54321", canary_project: "deny-canary-11111", expected_display: "deny-canary-11111" }) }));
    process.stdin.end();
    const [stdout, stderr] = await Promise.all([new Response(process.stdout).text(), new Response(process.stderr).text()]);
    expect(await process.exited, stderr).toBe(0);
    expect(calls.every((call) => call.startsWith("GET ") || call.endsWith(":getIamPolicy"))).toBe(true);
    expect(stdout).not.toContain("fixture-credential");
    return JSON.parse(stdout);
  } finally {
    server.stop(true);
    await rm(directory, { force: true, recursive: true });
  }
}

test("retirement reads every inherited Allow attachment", async () => {
  expect(await readAllows({ inherited: true, ancestorReadable: true })).toMatchObject({ status: "200", roles: '["roles/viewer"]' });
  expect(await readAllows({ inherited: false, ancestorReadable: true })).toMatchObject({ status: "200", roles: "[]" });
  expect(await readAllows({ inherited: false, ancestorReadable: false })).toMatchObject({ status: "403", cleanup_status: "UNREAD" });
});

test("cleanup identities are reread after retirement and authorization failure is unresolved", async () => {
  expect(await readAllows({ inherited: false, ancestorReadable: true, cleanupStatus: 404 })).toMatchObject({ status: "200", cleanup_status: "CLEAN" });
  expect(await readAllows({ inherited: false, ancestorReadable: true, cleanupStatus: 403 })).toMatchObject({ status: "403", cleanup_status: "UNREAD" });
  expect(await readAllows({ inherited: false, ancestorReadable: true, cleanupStatus: 200 })).toMatchObject({ status: "200", cleanup_status: "RETAINED" });
});
