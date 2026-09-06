import { expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const source = await readFile(join(import.meta.dir, "../tools/ci/protected-recovery-deny-canary.sh"), "utf8");
function functionSource(name: string): string {
  const found = source.match(new RegExp(`^${name}\\(\\) \\{[\\s\\S]*?^\\}`, "m"));
  if (!found) throw new Error(`missing shell function ${name}`);
  return found[0];
}

async function cleanup(command: string, answers: readonly { readonly status: number; readonly body: unknown }[]): Promise<{ readonly failures: string; readonly calls: string }> {
  const directory = await mkdtemp(join(tmpdir(), "canary-cleanup-"));
  try {
    await writeFile(join(directory, "answers.json"), JSON.stringify(answers));
    const script = `set -euo pipefail
workdir="$1"
failures="$workdir/failures"
removed="$workdir/removed"
: > "$failures"
: > "$removed"
: > "$workdir/calls"
crm=https://cloudresourcemanager.googleapis.com/v3
PHASE=cleanup
folder_id=12345
ORGANIZATION_ID=99999
throwaway=deny-canary-test
index=0
call() {
  printf '%s %s\\n' "$1" "$2" >> "$workdir/calls"
  last_status="$(jq -r --argjson index "$index" '.[$index].status' "$workdir/answers.json")"
  jq --argjson index "$index" '.[$index].body' "$workdir/answers.json" > "$workdir/body"
  index=$((index + 1))
}
wait_operation() { return 0; }
${["fail", "remove", "remove_unless_deleted", "cleanup_folder"].map(functionSource).join("\n")}
${command}
`;
    const path = join(directory, "test.sh");
    await writeFile(path, script);
    const process = Bun.spawn(["bash", path, directory], { stdout: "pipe", stderr: "pipe" });
    const stderr = await new Response(process.stderr).text();
    expect(await process.exited, stderr).toBe(0);
    return { failures: await readFile(join(directory, "failures"), "utf8"), calls: await readFile(join(directory, "calls"), "utf8") };
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
}

const active = { name: "folders/12345", parent: "organizations/99999", displayName: "deny-canary-test", state: "ACTIVE" };
test("cleanup records disabled APIs and unread resources as unresolved", async () => {
  for (const status of [403, 500]) {
    const answer = { status, body: { error: { message: "unread", details: [{ reason: "SERVICE_DISABLED" }] } } };
    expect((await cleanup("remove DELETE https://example.invalid/resource resource", [answer])).failures).toContain(`HTTP ${status}`);
    const read = await cleanup("remove_unless_deleted https://example.invalid/resource resource", [answer]);
    expect(read.failures).toContain("state unread before cleanup");
    expect(read.calls.trim().split("\n")).toHaveLength(1);
  }
});

test("folder cleanup addresses its exact numeric identity and verifies terminal deletion", async () => {
  const result = await cleanup("cleanup_folder", [{ status: 200, body: active }, { status: 200, body: {} }, { status: 200, body: { ...active, state: "DELETE_REQUESTED" } }]);
  expect(result.failures).toBe("");
  expect(result.calls.trim().split("\n")).toEqual(["GET https://cloudresourcemanager.googleapis.com/v3/folders/12345", "DELETE https://cloudresourcemanager.googleapis.com/v3/folders/12345", "GET https://cloudresourcemanager.googleapis.com/v3/folders/12345"]);
  for (const body of [{ ...active, parent: "organizations/22222" }, { ...active, name: "folders/54321" }, { ...active, displayName: "different" }]) {
    const mismatch = await cleanup("cleanup_folder", [{ status: 200, body }]);
    expect(mismatch.failures).toContain("differs from the control manifest");
    expect(mismatch.calls).not.toContain("DELETE");
  }
  const retained = await cleanup("cleanup_folder", [{ status: 200, body: active }, { status: 200, body: {} }, { status: 200, body: active }]);
  expect(retained.failures).toContain("terminal deletion state is not readable");
  const unread = await cleanup("cleanup_folder", [{ status: 403, body: {} }]);
  expect(unread.failures).toContain("state unread before cleanup");
});
