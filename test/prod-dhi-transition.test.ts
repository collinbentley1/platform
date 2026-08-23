import { afterEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "..");
const helper = join(repoRoot, "tools/ci/cloud-run-prod-dhi-transition.sh");
const mockCli = join(repoRoot, "test/fixtures/preview-controller-mock-cli.ts");
const parityId = "1a4cho1elzg84pavos8mbanvvpmkieiht7kyhpjdofzpivf3k8";
const workflowSha = "1".repeat(40);
const productionHead = "2".repeat(40);
const projectId = "cdbentley";
const projectNumber = "882468538648";
const region = "us-east4";
const productionService = "cdbentley";
const previewService = "cdbentley-preview";
const productionImage = "us-east4-docker.pkg.dev/cdbentley/site/cdbentley";
const previewImage = "us-east4-docker.pkg.dev/cdbentley/site-preview/cdbentley";
const runtimeServiceAccount = "cloud-run-preview@cdbentley.iam.gserviceaccount.com";
const productionRevision = "cdbentley-production-current";
const oldBaseline = "cdbentley-preview-old-baseline";
const newBaseline = "cdbentley-preview-new-baseline";
const prRevision = "cdbentley-preview-pr31";
const temporaryRoots: string[] = [];

setDefaultTimeout(30_000);

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("production DHI epoch transaction", () => {
  test("same-DHI production with an admitted preview takes the mutation-free fast path", async () => {
    const fixture = await setup("open");
    const result = await run(fixture, "prepare", true, true);
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.output).toContain("epoch-required=false");
    expect(result.log).not.toContain("transition-prod-dhi-transition");
    expect(result.log).not.toContain("patch-attempt");
    expect(result.state.exposure).toBe("open");
  });

  test("legacy adoption prunes every tag SEALED, installs a proven baseline, and releases only after final proof", async () => {
    const fixture = await setup("open");
    const prepared = await run(fixture, "prepare", false, false);
    expect(prepared.exitCode, prepared.stderr).toBe(0);
    expect(prepared.output).toContain("epoch-required=true");
    expect(prepared.state.exposure).toBe("sealed");
    expect(prepared.state.traffic.map((target: any) => target.tag ?? "baseline")).toEqual(["baseline"]);
    expect(prepared.state.transitionMetadata.state).toBe("prod-dhi-transition");

    const state = prepared.state;
    state.revisions[newBaseline] = baselineRevision(newBaseline);
    await writeFile(fixture.state, JSON.stringify(state));
    const finalized = await run(fixture, "finalize", true, false);
    expect(finalized.exitCode, finalized.stderr).toBe(0);
    expect(finalized.output).toContain("epoch-finalized=true");
    expect(finalized.state.exposure).toBe("sealed");
    expect(finalized.state.traffic).toEqual([target(newBaseline, 100)]);
    expect(finalized.state.transitionMetadata).toEqual({
      "repository-id": "1255553151",
      state: "clear",
      version: "1",
    });
    expect(finalized.state.iamBindings).toEqual(exactIamBindings());
    expect(finalized.log).toContain("production-graph-proof");
    expect(finalized.log).toContain("graph-proof");
  });

  test("a retry can rekey only the same candidate prod epoch from zero-tag SEALED state", async () => {
    const fixture = await setup("sealed", {
      "dhi-parity-id": parityId,
      "github-run-attempt": "1",
      "github-run-id": "9",
      nonce: "a".repeat(64),
      "platform-workflow-sha": workflowSha,
      "repository-id": "1255553151",
      state: "prod-dhi-transition",
      version: "1",
    });
    const state = JSON.parse(await readFile(fixture.state, "utf8"));
    state.traffic = [target(oldBaseline, 100)];
    await writeFile(fixture.state, JSON.stringify(state));
    const resumed = await run(fixture, "prepare", true, false);
    expect(resumed.exitCode, resumed.stderr).toBe(0);
    expect(resumed.output).toContain("epoch-required=true");
    expect(resumed.state.transitionMetadata.state).toBe("prod-dhi-transition");
    expect(resumed.state.transitionMetadata["github-run-id"]).toBe("123456789");
    expect(resumed.state.transitionMetadata.nonce).not.toBe("a".repeat(64));
  });

  test("first-adoption retry rekeys the exact epoch before prod changes and atomically prunes an OPEN legacy graph", async () => {
    const fixture = await setup("open", {
      "dhi-parity-id": parityId,
      "github-run-attempt": "1",
      "github-run-id": "9",
      nonce: "c".repeat(64),
      "platform-workflow-sha": workflowSha,
      "repository-id": "1255553151",
      state: "prod-dhi-transition",
      version: "1",
    });
    const resumed = await run(fixture, "prepare", false, false);
    expect(resumed.exitCode, resumed.stderr).toBe(0);
    expect(resumed.state.exposure).toBe("sealed");
    expect(resumed.state.traffic.map((route: any) => route.tag ?? "baseline")).toEqual(["baseline"]);
    expect(resumed.state.transitionMetadata.state).toBe("prod-dhi-transition");
    expect(resumed.state.transitionMetadata["github-run-id"]).toBe("123456789");
  });

  test("a lost exact-policy response remains poisoned until authoritative policy readback", async () => {
    const fixture = await setup("open");
    const state = JSON.parse(await readFile(fixture.state, "utf8"));
    state.iamSetTransportLoss = true;
    await writeFile(fixture.state, JSON.stringify(state));
    const prepared = await run(fixture, "prepare", false, false);
    expect(prepared.exitCode, prepared.stderr).toBe(0);
    expect(prepared.state.iamBindings).toEqual(exactIamBindings());
    expect(prepared.log).toContain("iam-policy-sanitize-response-lost");
    expect(prepared.state.transitionMetadata.state).toBe("prod-dhi-transition");
  });

  test("finalize detects a same-DHI production app flip and retains the poison", async () => {
    const fixture = await setup("open");
    const prepared = await run(fixture, "prepare", false, false);
    expect(prepared.exitCode, prepared.stderr).toBe(0);
    const state = prepared.state;
    state.revisions[newBaseline] = baselineRevision(newBaseline);
    state.productionFlipAfterServiceRead = 2;
    state.productionReadCount = 0;
    await writeFile(fixture.state, JSON.stringify(state));
    const finalized = await run(fixture, "finalize", true, false);
    expect(finalized.exitCode, JSON.stringify({ log: finalized.log, state: finalized.state, stderr: finalized.stderr })).not.toBe(0);
    expect(finalized.stderr).toContain("Production changed while the sanitized candidate-DHI baseline was proven");
    expect(finalized.state.transitionMetadata.state).toBe("prod-dhi-transition");
    expect(finalized.log).toContain("production-same-dhi-app-flip");
  });
});

type Fixture = { bin: string; lease: string; log: string; output: string; policy: string; root: string; state: string };

async function setup(exposure: "open" | "sealed", transitionMetadata?: Record<string, string>): Promise<Fixture> {
  const root = await mkdtemp(join(tmpdir(), "platform-prod-dhi-transition-"));
  temporaryRoots.push(root);
  const bin = join(root, "bin");
  const policy = join(root, "policy", "tools", "ci");
  const state = join(root, "state.json");
  const log = join(root, "events.log");
  const output = join(root, "outputs");
  const lease = join(root, "prod-dhi-transition-lease.json");
  await mkdir(bin, { recursive: true });
  await mkdir(policy, { recursive: true });
  await writeFile(log, "");
  await writeFile(output, "");
  for (const command of ["curl", "gcloud", "gh"]) {
    const wrapper = join(bin, command);
    await writeFile(wrapper, `#!/bin/sh\nMOCK_COMMAND=${command} exec bun "$MOCK_CLI" "$@"\n`);
    await chmod(wrapper, 0o755);
  }
  const sleep = join(bin, "sleep");
  await writeFile(sleep, "#!/bin/sh\nexit 0\n");
  await chmod(sleep, 0o755);

  await writeFile(join(policy, "cloud-run-dhi-parity.sh"), [
    "#!/bin/bash", "set -euo pipefail", "case \"$1\" in",
    "prove-production)",
    "  [ \"${MOCK_PRODUCTION_CANDIDATE:-false}\" = true ]",
    "  head=$(jq -er '.metadata.labels[\"git-head-sha\"]' \"$PARITY_REVISION_JSON\")",
    "  index=$(jq -er '[.spec.containers[0].env[] | select(.name == \"PLATFORM_IMAGE_INDEX_DIGEST\") | .value][0]' \"$PARITY_REVISION_JSON\")",
    "  runnable=$(jq -er '[.spec.containers[0].env[] | select(.name == \"PLATFORM_IMAGE_RUNNABLE_DIGEST\") | .value][0]' \"$PARITY_REVISION_JSON\")",
    `  echo dhi_parity_id=${parityId} >> \"$GITHUB_OUTPUT\"`,
    "  echo live_production_head_sha=$head >> \"$GITHUB_OUTPUT\"",
    "  echo live_production_index_image=${EXPECTED_PRODUCTION_IMAGE_NAME}@$index >> \"$GITHUB_OUTPUT\"",
    "  echo live_production_runnable_image=${EXPECTED_PRODUCTION_IMAGE_NAME}@$runnable >> \"$GITHUB_OUTPUT\"",
    "  ;;",
    "prove-preview-routes)",
    "  echo active_preview_count=0 >> \"$GITHUB_OUTPUT\"",
    "  echo all_routes_candidate_parity=true >> \"$GITHUB_OUTPUT\"",
    `  echo dhi_parity_id=${parityId} >> \"$GITHUB_OUTPUT\"`,
    "  ;;", "*) exit 97 ;;", "esac", "",
  ].join("\n"));
  await chmod(join(policy, "cloud-run-dhi-parity.sh"), 0o755);
  await writeFile(join(policy, "container-artifact-contract.sh"), [
    "#!/bin/bash", "set -euo pipefail", "case \"$1\" in",
    "verify-live-production) echo production-graph-proof >> \"$MOCK_LOG\" ;;",
    "verify-live-images) jq -e 'length == 1' \"$LIVE_IMAGE_SET_FILE\" >/dev/null; echo graph-proof >> \"$MOCK_LOG\" ;;",
    "*) exit 98 ;;", "esac", `echo dhi_parity_id=${parityId} >> \"$GITHUB_OUTPUT\"`, "",
  ].join("\n"));
  await chmod(join(policy, "container-artifact-contract.sh"), 0o755);
  await writeFile(join(policy, "deployment-parity-transition.sh"), await readFile(join(repoRoot, "tools/ci/deployment-parity-transition.sh")));
  await chmod(join(policy, "deployment-parity-transition.sh"), 0o755);

  const revisions = {
    [oldBaseline]: baselineRevision(oldBaseline),
    [newBaseline]: baselineRevision(newBaseline),
    [prRevision]: previewRevision(prRevision),
  };
  await writeFile(state, JSON.stringify({
    etag: 1,
    exposure,
    generation: 7,
    ghHeads: { "31": "3".repeat(40) },
    iamBindings: transitionMetadata ? exactIamBindings() : [{ members: ["user:legacy@example.com"], role: "roles/run.invoker" }],
    iamEtag: 1,
    operation: 0,
    previewService,
    productionRevision: productionRevisionFixture(),
    productionService,
    projectId,
    projectNumber,
    region,
    revisions,
    traffic: exposure === "open"
      ? [target(oldBaseline, 100), target(prRevision, 0, "pr-31")]
      : [target(oldBaseline, 100)],
    transitionGeneration: "17",
    transitionMetadata: transitionMetadata ?? { "repository-id": "1255553151", state: "clear", version: "1" },
    transitionMetageneration: transitionMetadata ? "8" : "1",
  }));
  return { bin, lease, log, output, policy: resolve(policy, "..", ".."), root, state };
}

async function run(fixture: Fixture, command: "prepare" | "finalize", candidate: boolean, previewAdmitted: boolean) {
  await writeFile(fixture.output, "");
  const child = Bun.spawn(["/bin/bash", helper, command], {
    cwd: repoRoot,
    env: {
      ...process.env,
      ACCESS_TOKEN: "fixture-token",
      BASE_CONTENT_SHA256: "6".repeat(64),
      BASE_DOWNLOAD_DIR: fixture.root,
      BASE_MANIFEST_SHA256: "7".repeat(64),
      BASELINE_REVISION: newBaseline,
      DHI_PARITY_ID: parityId,
      EXPECTED_BASELINE_PRODUCTION_HEAD_SHA: productionHead,
      EXPECTED_BASELINE_PRODUCTION_INDEX_IMAGE: `${productionImage}@sha256:${"a".repeat(64)}`,
      EXPECTED_BASELINE_PRODUCTION_RUNNABLE_IMAGE: `${productionImage}@sha256:${"b".repeat(64)}`,
      EXPECTED_PLATFORM_WORKFLOW_SHA: workflowSha,
      EXPECTED_PREVIEW_IMAGE_NAME: previewImage,
      EXPECTED_PREVIEW_RUNTIME_SERVICE_ACCOUNT: runtimeServiceAccount,
      EXPECTED_PRODUCTION_IMAGE_NAME: productionImage,
      EXPECTED_PROJECT_NUMBER: projectNumber,
      GITHUB_OUTPUT: fixture.output,
      GITHUB_RUN_ATTEMPT: "1",
      GITHUB_RUN_ID: "123456789",
      MOCK_CLI: mockCli,
      MOCK_LOG: fixture.log,
      MOCK_PRODUCTION_CANDIDATE: candidate ? "true" : "false",
      MOCK_STATE: fixture.state,
      PARITY_POLICY_ROOT: fixture.policy,
      PATH: `${fixture.bin}:${process.env.PATH ?? "/usr/bin:/bin"}`,
      PREVIEW_PARITY_ADMITTED: previewAdmitted ? "true" : "false",
      PREVIEW_SERVICE: previewService,
      PROJECT_ID: projectId,
      REGION: region,
      REPOSITORY_ID: "1255553151",
      RUNNER_TEMP: fixture.root,
      SERVICE_NAME: productionService,
      TRANSITION_LEASE_FILE: fixture.lease,
    },
    stdout: "ignore",
    stderr: "pipe",
  });
  const [exitCode, stderr] = await Promise.all([child.exited, new Response(child.stderr).text()]);
  return {
    exitCode,
    log: await readFile(fixture.log, "utf8"),
    output: await readFile(fixture.output, "utf8"),
    state: JSON.parse(await readFile(fixture.state, "utf8")),
    stderr,
  };
}

function target(revision: string, percent: number, tag?: string) {
  return { percent, revision, ...(tag ? { tag } : {}), type: "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION" };
}

function exactIamBindings() {
  return [
    { members: ["serviceAccount:gha-preview-deploy@cdbentley.iam.gserviceaccount.com"], role: "projects/cdbentley/roles/cloudRunRevisionDeployer" },
    { members: ["serviceAccount:gha-deploy-parity@cdbentley.iam.gserviceaccount.com"], role: "projects/cdbentley/roles/deploymentParityCloudRunReader" },
    { members: ["serviceAccount:gha-preview-commit@cdbentley.iam.gserviceaccount.com"], role: "projects/cdbentley/roles/previewTrafficCommitter" },
  ];
}

function baselineRevision(name: string) {
  const index = `sha256:${"a".repeat(64)}`;
  const runnable = `sha256:${"b".repeat(64)}`;
  const env = [
    { name: "PLATFORM_DEPLOY_ENVIRONMENT", value: "preview-baseline" },
    { name: "PLATFORM_IMAGE_INDEX_DIGEST", value: index },
    { name: "PLATFORM_IMAGE_RUNNABLE_DIGEST", value: runnable },
  ];
  const labels = {
    "dhi-parity-id": parityId,
    environment: "preview",
    "git-head-sha": productionHead,
    "github-repository-id": "1255553151",
    "managed-by": "github-actions",
    "platform-workflow-sha": workflowSha,
    "preview-role": "baseline",
  };
  const container = {
    args: ["-e", "Bun.serve({port:+process.env.PORT,fetch(){return new Response(null,{status:404})}})"],
    command: ["bun"], env, image: `${productionImage}@${runnable}`,
  };
  return {
    v1: {
      metadata: { generation: 1, labels, name, namespace: projectNumber },
      spec: { containers: [container], serviceAccountName: runtimeServiceAccount },
      status: { conditions: [{ status: "True", type: "Ready" }], imageDigest: `${productionImage}@${runnable}`, observedGeneration: 1 },
    },
    v2: {
      conditions: [{ state: "CONDITION_SUCCEEDED", type: "Ready" }],
      containers: [container], generation: "1", labels,
      name: `projects/${projectId}/locations/${region}/services/${previewService}/revisions/${name}`,
      serviceAccount: runtimeServiceAccount,
    },
  };
}

function previewRevision(name: string) {
  const fixture = baselineRevision(name);
  fixture.v1.metadata.labels["preview-role"] = "pr";
  fixture.v1.metadata.labels["github-pr"] = "31";
  fixture.v2.labels["preview-role"] = "pr";
  fixture.v2.labels["github-pr"] = "31";
  return fixture;
}

function productionRevisionFixture() {
  const index = `sha256:${"a".repeat(64)}`;
  const runnable = `sha256:${"b".repeat(64)}`;
  const env = [
    { name: "PLATFORM_IMAGE_INDEX_DIGEST", value: index },
    { name: "PLATFORM_IMAGE_RUNNABLE_DIGEST", value: runnable },
  ];
  const labels = { "dhi-parity-id": parityId, "git-head-sha": productionHead, "platform-workflow-sha": workflowSha };
  const container = { env, image: `${productionImage}@${runnable}` };
  return {
    v1: {
      metadata: { generation: 1, labels, name: productionRevision, namespace: projectNumber },
      spec: { containers: [container] },
      status: { conditions: [{ status: "True", type: "Ready" }], observedGeneration: 1 },
    },
    v2: {
      conditions: [{ state: "CONDITION_SUCCEEDED", type: "Ready" }], containers: [container], labels,
      name: `projects/${projectId}/locations/${region}/services/${productionService}/revisions/${productionRevision}`,
    },
  };
}
