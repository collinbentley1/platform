import { expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const bash = Bun.which("bash");
if (!bash || Bun.spawnSync([bash, "-c", 'test "${BASH_VERSINFO[0]}" -ge 4'], { stdout: "ignore", stderr: "ignore" }).exitCode !== 0) {
  throw new Error("Canary cleanup fixtures require Bash 4 or newer. Put its bin directory first in PATH before running bun test; macOS /bin/bash is version 3.2.");
}

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
    await writeFile(join(directory, "authority.json"), JSON.stringify({ consumers: [{ projectId: "consumer-project" }] }));
    const script = `set -euo pipefail
workdir="$1"
failures="$workdir/failures"
removed="$workdir/removed"
: > "$failures"
: > "$removed"
: > "$workdir/calls"
crm=https://cloudresourcemanager.googleapis.com/v3
PHASE=cleanup
transient_cleanup=1
recovery_proof=0
operation_json=null
last_status=000
declare -A mutation_ready=()
declare -A manifest_gone=()
broker_project=broker-project
authority="$workdir/authority.json"
iam=https://iam.googleapis.com/v1
retained_carriers="$workdir/carriers.json"
printf '[]' > "$retained_carriers"
manifest_ids="$workdir/manifest-ids"
: > "$manifest_ids"
cleanup_skips="$workdir/cleanup-skips"
: > "$cleanup_skips"
folder_id=12345
ORGANIZATION_ID=99999
throwaway=deny-canary-test
throwaway_new=deny-canary-test-new
canary_project=deny-canary-test
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
manifest_write() { cp "$resource_creation" "$workdir/durable-creation.json"; }
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
${["fail", "remove", "remove_unless_deleted", "cleanup_folder", "creation_record", "creation_answer", "creation_persist", "creation_resources", "creation_initialize", "creation_vector", "creation_restore", "service_account_email", "carrier_read", "carrier_projects", "consumer_projects", "checkpoint_read", "collect_carriers", "retire_carriers", "json_body", "provision", "manifest_description", "service_disabled_exact", "never_created", "build_filter", "capability_url", "skip_never_created", "classify", "observe", "transient_builds"].map(functionSource).join("\n")}
${command}
`;
    const path = join(directory, "test.sh");
    await writeFile(path, script);
    const process = Bun.spawn([bash, path, directory], { stdout: "pipe", stderr: "pipe" });
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

const carrierEmail = "deny-canary-test@broker-project.iam.gserviceaccount.com";
const carrierDescription = (freeze: string) => JSON.stringify({ gone: "222", folder: "12345", controlRunId: "123", headSha: "reviewed", freeze });

test("failed controls recover P and N only through exact durable metadata and a fresh disabled read", async () => {
  const resource = "projects/consumer-project/zones/us-east4-a/instances/deny-canary-test-new";
  for (const state of ["PPPP", "NNNN", "UUUU", "CCCC"]) {
    const result = await cleanup(`CONTROL_PREDICATE=
carrier_read broker-project
if ! skip_never_created ${resource} compute.googleapis.com; then fail unresolved-creation; fi`, [
      { status: 200, body: { email: carrierEmail, uniqueId: "222", description: carrierDescription(state) } }, disabled,
    ]);
    expect(result.failures).toBe(state === "PPPP" || state === "NNNN" ? "" : "unresolved-creation\n");
    expect(result.calls.trim().split("\n")).toHaveLength(state === "PPPP" || state === "NNNN" ? 2 : 1);
  }
  const mismatch = await cleanup("if ! carrier_read broker-project; then fail rejected-carrier; fi", [
    { status: 200, body: { email: carrierEmail, uniqueId: "222", description: carrierDescription("PPPP").replace("reviewed", "different") } },
  ]);
  expect(mismatch.failures).toContain("rejected-carrier");
});

test("control persists U before an enabled create and a failed durable write suppresses the mutation", async () => {
  const observeControl = observeNeverCreated.replace("PHASE=deny", "PHASE=control\ntransient_cleanup=0");
  const setup = `creation_record ${instanceResource} compute.googleapis.com NOT_ATTEMPTED
mutation_ready[${instanceResource}]=1`;
  const result = await cleanup(`${setup}
manifest_write() { printf 'PERSIST U\\n' >> "$workdir/calls"; }
${observeControl}`, [{ status: 200, body: {} }]);
  expect(result.calls.trim().split("\n")).toEqual(["PERSIST U", "POST https://compute.googleapis.com/compute/v1/projects/consumer-project/zones/us-east4-a/instances"]);
  expect(JSON.parse(result.creation)[0].state).toBe("UNKNOWN");
  const failedWrite = await cleanup(`${setup}
manifest_write() { return 1; }
if ${observeControl}; then fail unexpected-mutation; fi`, []);
  expect(failedWrite.calls).toBe("");
  expect(failedWrite.failures).toBe("");
  const disabledControl = await cleanup(`creation_record ${instanceResource} compute.googleapis.com NEVER_CREATED SERVICE_DISABLED
${observeControl}`, [disabled]);
  expect(disabledControl.calls).not.toContain("POST");
  expect(JSON.parse(disabledControl.observations).response.skippedMutation).toBe(true);
});

test("durable carrier writes verify exact readback and reject oversized descriptions before any write", async () => {
  const command = `${functionSource("manifest_write")}
creation_initialize
manifest_gone[broker-project]=222
if ! manifest_write broker-project; then fail carrier-write-rejected; fi`;
  const valid = await cleanup(command, [
    { status: 200, body: {} },
    { status: 200, body: { email: carrierEmail, uniqueId: "222", description: carrierDescription("PPPP") } },
  ]);
  expect(valid.failures).toBe("");
  expect(valid.calls).toContain("PATCH");
  const changed = await cleanup(command, [{ status: 200, body: {} }, { status: 200, body: { email: carrierEmail, uniqueId: "222", description: "changed" } }]);
  expect(changed.failures).toContain("carrier-write-rejected");
  const oversized = await cleanup(`GITHUB_SHA=${"a".repeat(300)}
${command}`, []);
  expect(oversized.failures).toContain("256-byte description bound");
  expect(oversized.calls).toBe("");
});

const retainedCarriers = [
  { project: "consumer-project", email: "deny-canary-test@consumer-project.iam.gserviceaccount.com", uniqueId: "111" },
  { project: "broker-project", email: carrierEmail, uniqueId: "222" },
];
const carrierSetup = `printf '%s' '${JSON.stringify(retainedCarriers)}' > "$retained_carriers"`;

test("carrier retirement uses permanent IDs, verifies absence, and preserves the broker after any earlier failure", async () => {
  const answers = retainedCarriers.flatMap((carrier) => [
    { status: 200, body: { email: carrier.email, uniqueId: carrier.uniqueId } },
    { status: 204, body: {} }, { status: 404, body: {} }, { status: 404, body: {} },
  ]);
  const success = await cleanup(`${carrierSetup}
retire_carriers`, answers);
  expect(success.failures).toBe("");
  expect(success.calls.split("\n").filter((line) => line.startsWith("DELETE"))).toEqual([
    "DELETE https://iam.googleapis.com/v1/projects/-/serviceAccounts/111",
    "DELETE https://iam.googleapis.com/v1/projects/-/serviceAccounts/222",
  ]);
  const incomplete = await cleanup(`${carrierSetup}
retire_carriers`, [{ status: 200, body: { email: "deny-canary-test@consumer-project.iam.gserviceaccount.com", uniqueId: "111" } }, { status: 403, body: {} }, { status: 200, body: {} }, { status: 200, body: {} }]);
  expect(incomplete.failures).toContain("final carrier absence is not readable");
  expect(incomplete.calls).not.toContain(carrierEmail);
  const recreated = await cleanup(`${carrierSetup}
retire_carriers`, [{ status: 200, body: { email: "deny-canary-test@consumer-project.iam.gserviceaccount.com", uniqueId: "999" } }]);
  expect(recreated.failures).toContain("carrier identity changed");
  expect(recreated.calls).not.toContain("DELETE");
});

test("verified checkpoint recovery retains missing carrier IDs and repeats enabled or disabled resource checks", async () => {
  const checkpointSetup = `${carrierSetup}
creation_initialize
jq -n --slurpfile carriers "$retained_carriers" --slurpfile creation "$resource_creation" '{schema:"protected-recovery/deny-canary-cleanup-checkpoint/v3",phase:"cleanup",controlRunId:"123",run:{headSha:"reviewed",id:400,attempt:1},brokerImage:"image",organization:"organizations/99999",witnessServiceAccount:"witness",throwaways:{project:"deny-canary-test",folder:"12345",goneUniqueIds:{"broker-project":"222"}},leftovers:[],removed:[],cleanupSkips:[],creationVector:"PPPP",resourceCreation:$creation[0],retainedCarriers:$carriers[0]}' > "$workdir/checkpoint.json"
CLEANUP_CHECKPOINT="$workdir/checkpoint.json"
checkpoint_read
collect_carriers
if ! skip_never_created projects/consumer-project/zones/us-east4-a/instances/deny-canary-test-new compute.googleapis.com; then remove DELETE https://compute.googleapis.com/compute/v1/projects/consumer-project/zones/us-east4-a/instances/deny-canary-test-new instance compute; fi`;
  const result = await cleanup(checkpointSetup, [{ status: 404, body: {} }, { status: 404, body: {} }, disabled]);
  expect(result.failures).toBe("");
  expect(result.calls.trim().split("\n")).toHaveLength(3);
  expect(result.calls).not.toContain("DELETE");
  const enabled = await cleanup(checkpointSetup, [{ status: 404, body: {} }, { status: 404, body: {} }, { status: 200, body: {} }, { status: 404, body: {} }]);
  expect(enabled.failures).toBe("");
  expect(enabled.calls.trim().split("\n").at(-1)).toBe("DELETE https://compute.googleapis.com/compute/v1/projects/consumer-project/zones/us-east4-a/instances/deny-canary-test-new");
  for (const answer of [{ status: 500, body: {} }, { status: 200, body: { error: {} } }, { status: 200, body: [] }, { status: 200, body: "invalid" }]) {
    const unread = await cleanup(checkpointSetup, [{ status: 404, body: {} }, { status: 404, body: {} }, answer]);
    expect(unread.failures).toContain("requires the authoritative API to remain disabled");
    expect(unread.calls).not.toContain("DELETE");
  }
  const build = await cleanup(`CONTROL_PREDICATE=
carrier_read broker-project
transient_builds consumer-project`, [
    { status: 200, body: { email: carrierEmail, uniqueId: "222", description: carrierDescription("PPPP") } },
    { status: 200, body: { builds: [] } }, { status: 200, body: { builds: [] } },
  ]);
  expect(build.failures).toBe("");
  expect(build.calls.trim().split("\n")).toHaveLength(3);
  expect(decodeURIComponent(build.calls)).toContain('tags="protected-recovery-deny-canary-123"');
});

test("the carrier create itself contains durable P metadata before any later provisioning", async () => {
  const result = await cleanup(`${functionSource("identity_rows")}
creation_initialize
folder_id=
create_new=deny-canary-test-new-c
throwaway_gone=deny-canary-test-gone
delegate=deny-canary-test-d
preparing() { return 0; }
provision() { cp "$3" "$observations"; printf 'CREATE %s\\n' "$2" >> "$workdir/calls"; return 1; }
if identity_rows attachment broker-project broker; then fail unexpectedly-continued; fi`, []);
  const request = JSON.parse(result.observations);
  expect(request.accountId).toBe("deny-canary-test");
  expect(JSON.parse(request.serviceAccount.description)).toEqual({ gone: "", folder: "", controlRunId: "123", headSha: "reviewed", freeze: "PPPP" });
  expect(result.calls.trim().split("\n")).toHaveLength(1);
  expect(result.failures).toBe("");
});
