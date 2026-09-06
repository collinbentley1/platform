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

const instanceResource = "projects/consumer-project/zones/us-east4-a/instances/deny-canary-123-new";
const validManifest = {
  schema: "protected-recovery/deny-canary/v3", phase: "control", controlRunId: "123", run: { id: 123, attempt: 1, headSha: "reviewed" }, brokerImage: "image", witnessServiceAccount: "witness",
  resourceCreation: [{ resource: instanceResource, service: "compute.googleapis.com", state: "NEVER_CREATED", reason: "SERVICE_DISABLED", tag: "" }],
};
async function cleanup(command: string, answers: readonly { readonly status: number; readonly body: unknown }[]): Promise<{ readonly failures: string; readonly calls: string; readonly observations: string; readonly creation: string }> {
  const directory = await mkdtemp(join(tmpdir(), "canary-cleanup-"));
  try {
    await writeFile(join(directory, "answers.json"), JSON.stringify(answers));
    await writeFile(join(directory, "predicate.json"), JSON.stringify(validManifest));
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
CONTROL_RUN_ID=123
GITHUB_RUN_ID=456
GITHUB_RUN_ATTEMPT=1
GITHUB_SHA=reviewed
BROKER_IMAGE=image
CANARY_WITNESS_SERVICE_ACCOUNT=witness
CONTROL_PREDICATE="$workdir/predicate.json"
CURRENT_PREDICATE="$workdir/predicate.json"
compute=https://compute.googleapis.com/compute/v1
cloudbuild=https://cloudbuild.googleapis.com/v1
zone=us-east4-a
resource_creation="$workdir/creation.json"
printf '[]' > "$resource_creation"
observations="$workdir/observations"
: > "$observations"
canary_principal=canary
record_allow_boundary() { :; }
pre_state() { pre_observed=unknown; pre_detail=fixture; }
canary_body_sha256() { printf bodysha; }
canary_digest() { printf digest; }
witness_call() { call "$@"; }
index=0
call() {
  printf '%s %s\\n' "$1" "$2" >> "$workdir/calls"
  last_status="$(jq -r --argjson index "$index" '.[$index].status' "$workdir/answers.json")"
  jq --argjson index "$index" '.[$index].body' "$workdir/answers.json" > "$workdir/body"
  index=$((index + 1))
}
wait_operation() { return 0; }
${["fail", "remove", "remove_unless_deleted", "cleanup_folder", "creation_record", "creation_answer", "service_disabled_exact", "never_created", "build_filter", "capability_url", "skip_never_created", "classify", "observe", "transient_builds"].map(functionSource).join("\n")}
${command}
`;
    const path = join(directory, "test.sh");
    await writeFile(path, script);
    const process = Bun.spawn(["bash", path, directory], { stdout: "pipe", stderr: "pipe" });
    const stderr = await new Response(process.stderr).text();
    expect(await process.exited, stderr).toBe(0);
    return { failures: await readFile(join(directory, "failures"), "utf8"), calls: await readFile(join(directory, "calls"), "utf8"), observations: await readFile(join(directory, "observations"), "utf8"), creation: await readFile(join(directory, "creation.json"), "utf8") };
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

const disabled = { status: 403, body: { error: { details: [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo", reason: "SERVICE_DISABLED", metadata: { service: "compute.googleapis.com" } }] } } };
const skip = `if ! skip_never_created ${instanceResource} compute.googleapis.com; then fail missing-proof; fi`;
const observeNeverCreated = `PHASE=deny
observe attachment compute.googleapis.com/instances.create POST https://compute.googleapis.com/compute/v1/projects/consumer-project/zones/us-east4-a/instances "" "" compute ${instanceResource} absent compute.googleapis.com/instances.create`;

test("never-created cleanup requires exact control identity and authoritative API-disabled read", async () => {
  const result = await cleanup(skip, [disabled]);
  expect(result.failures).toBe("");
  expect(result.calls.trim()).toBe("GET https://compute.googleapis.com/compute/v1/projects/consumer-project/zones/us-east4-a");
  for (const alteration of [".run.attempt = 2", '.run.headSha = "other"', '.resourceCreation[0].state = "UNKNOWN"', '.resourceCreation[0].state = "CREATED"', '.resourceCreation[0].resource = "other"', '.resourceCreation[0].service = "other.googleapis.com"', '.resourceCreation += .resourceCreation']) {
    const mismatch = await cleanup(`jq '${alteration}' "$CONTROL_PREDICATE" > "$workdir/changed"
mv "$workdir/changed" "$CONTROL_PREDICATE"
${skip}`, [disabled]);
    expect(mismatch.failures).toContain("missing-proof");
    expect(mismatch.calls).toBe("");
  }
  for (const answer of [{ status: 200, body: {} }, { status: 500, body: {} }, { status: 403, body: {} }]) {
    const unread = await cleanup(skip, [answer]);
    expect(unread.failures).toContain("requires the authoritative API to remain disabled");
    expect(unread.calls).not.toContain("DELETE");
  }
});

test("deny never issues the mutation for a control-proven never-created resource, even when enabled or unreadable", async () => {
  for (const answer of [disabled, { status: 200, body: {} }, { status: 500, body: {} }]) {
    const result = await cleanup(observeNeverCreated, [answer]);
    expect(result.calls.trim()).toBe("GET https://compute.googleapis.com/compute/v1/projects/consumer-project/zones/us-east4-a");
    const row = JSON.parse(result.observations);
    expect(row.request.method).toBe("POST");
    expect(row.response.skippedMutation).toBe(true);
    expect(row.response.observedRequest.method).toBe("GET");
    expect(row.outcome).toBe(answer.status === 403 ? "UNSERVICEABLE" : "ERROR");
  }
});

test("created and ambiguous resources cannot become never-created through a later disabled response", async () => {
  for (const state of ["CREATED", "UNKNOWN"]) {
    const result = await cleanup(`creation_record ${instanceResource} compute.googleapis.com ${state}
creation_record ${instanceResource} compute.googleapis.com NEVER_CREATED SERVICE_DISABLED`, []);
    expect(JSON.parse(result.creation)[0].state).toBe(state);
  }
  const timeout = await cleanup(`last_outcome=ERROR
last_status=000
creation_answer ${instanceResource} compute.googleapis.com
creation_record ${instanceResource} compute.googleapis.com NEVER_CREATED SERVICE_DISABLED`, []);
  expect(JSON.parse(timeout.creation)[0].state).toBe("UNKNOWN");
});

test("control transient proof is bound to its own current run and attempt", async () => {
  const valid = await cleanup(`PHASE=control
GITHUB_RUN_ID=123
${skip}`, [disabled]);
  expect(valid.failures).toBe("");
  const retry = await cleanup(`PHASE=control
GITHUB_RUN_ID=123
GITHUB_RUN_ATTEMPT=2
${skip}`, [disabled]);
  expect(retry.failures).toContain("missing-proof");
  const matchedRetry = await cleanup(`PHASE=control\nGITHUB_RUN_ID=123\nGITHUB_RUN_ATTEMPT=2\njq '.run.attempt = 2' "$CONTROL_PREDICATE" > "$workdir/changed"\nmv "$workdir/changed" "$CONTROL_PREDICATE"\n${skip}`, [disabled]);
  expect(matchedRetry.failures).toContain("missing-proof");
  const missing = await cleanup(`PHASE=control
GITHUB_RUN_ID=123
CURRENT_PREDICATE=
${skip}`, [disabled]);
  expect(missing.failures).toContain("missing-proof");
});

test("Cloud Build cleanup and deny preflight bind this control's exact project and tag", async () => {
  const buildResource = "projects/consumer-project/locations/global/builds";
  const setup = `jq '.resourceCreation = [{resource: "${buildResource}", service: "cloudbuild.googleapis.com", state: "NEVER_CREATED", reason: "SERVICE_DISABLED", tag: "protected-recovery-deny-canary-123"}]' "$CONTROL_PREDICATE" > "$workdir/changed"
mv "$workdir/changed" "$CONTROL_PREDICATE"`;
  const answer = { status: 403, body: { error: { details: [{ "@type": "type.googleapis.com/google.rpc.ErrorInfo", reason: "SERVICE_DISABLED", metadata: { service: "cloudbuild.googleapis.com" } }] } } };
  const result = await cleanup(`${setup}
transient_builds consumer-project`, [answer]);
  expect(result.failures).toBe("");
  expect(decodeURIComponent(result.calls)).toContain('tags="protected-recovery-deny-canary-123"');
  expect(result.calls).not.toContain("POST");
  const observation = await cleanup(`${setup}
PHASE=deny
observe attachment cloudbuild.googleapis.com/builds.create POST https://cloudbuild.googleapis.com/v1/${buildResource} "" "" none ${buildResource} none cloudbuild.googleapis.com/builds.create`, [answer]);
  expect(JSON.parse(observation.observations).response.skippedMutation).toBe(true);
  expect(observation.calls).not.toContain("POST");
  const wrongTag = await cleanup(`${setup}
jq '.resourceCreation[0].tag = "another-run"' "$CONTROL_PREDICATE" > "$workdir/changed"
mv "$workdir/changed" "$CONTROL_PREDICATE"
transient_builds consumer-project`, [answer]);
  expect(wrongTag.failures).toContain("could not be listed");
  const unread = await cleanup(`${setup}
transient_builds consumer-project`, [{ status: 500, body: {} }]);
  expect(unread.failures).toContain("requires the authoritative API to remain disabled");
});
