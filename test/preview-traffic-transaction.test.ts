import { afterEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "..");
const helper = join(repoRoot, "tools/ci/cloud-run-preview-traffic.sh");
const mockCli = join(repoRoot, "test/fixtures/preview-traffic-mock-cli.ts");
const parityId = "1a4cho1elzg84pavos8mbanvvpmkieiht7kyhpjdofzpivf3k8";
const workflowSha = "1".repeat(40);
const productionHead = "2".repeat(40);
const candidateHead = "3".repeat(40);
const survivorHead = "4".repeat(40);
const oldHead = "5".repeat(40);
const projectId = "cdbentley";
const projectNumber = "882468538648";
const region = "us-east4";
const service = "cdbentley-preview";
const productionService = "cdbentley";
const productionRevision = "cdbentley-production-current";
const productionImage = "us-east4-docker.pkg.dev/cdbentley/site/cdbentley";
const previewImage = "us-east4-docker.pkg.dev/cdbentley/site-preview/cdbentley";
const runtimeServiceAccount = "cloud-run-preview@cdbentley.iam.gserviceaccount.com";
const exactPreviewIamBindings = [
  {
    members: ["serviceAccount:gha-preview-deploy@cdbentley.iam.gserviceaccount.com"],
    role: "projects/cdbentley/roles/cloudRunRevisionDeployer",
  },
  {
    members: ["serviceAccount:gha-deploy-parity@cdbentley.iam.gserviceaccount.com"],
    role: "projects/cdbentley/roles/deploymentParityCloudRunReader",
  },
  {
    members: ["serviceAccount:gha-preview-commit@cdbentley.iam.gserviceaccount.com"],
    role: "projects/cdbentley/roles/previewTrafficCommitter",
  },
];
const baselineRevision = "cdbentley-preview-baseline-new";
const candidateRevision = "cdbentley-preview-p31-candidate";
const oldBaselineRevision = "cdbentley-preview-baseline-old";
const oldTargetRevision = "cdbentley-preview-p31-old";
const survivorRevision = "cdbentley-preview-p44-current";
const bootstrapRevision = "cdbentley-preview-bootstrap";
const temporaryRoots: string[] = [];

setDefaultTimeout(20_000);

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("etag-bound preview traffic transaction", () => {
  test("a deploy preflight failure before exposure classification performs no Cloud Run mutation", async () => {
    const result = await runDeployPreflightFailure();
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("Critical History requires a protected MAPBOX_PUBLIC_TOKEN");
    expect(result.mutations).toBe("");
  });

  test("an OPEN synchronize replaces only its old target after proposed OCI/lifecycle proof", async () => {
    const result = await runTransaction({ exposure: "open" });
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.output).toContain("admitted=true");
    expect(result.state.exposure).toBe("open");
    expect(routeRevision(result.state, "pr-31")).toBe(candidateRevision);
    expect(routeRevision(result.state, "pr-44")).toBe(survivorRevision);
    expect(JSON.stringify(result.state.traffic)).not.toContain(oldTargetRevision);
    expect(result.log).not.toContain("seal");
    expect(result.log.indexOf("graph-proof")).toBeLessThan(result.log.indexOf("traffic-commit"));
    expect(result.log.trim().split("\n")).toContain("lifecycle-31");
    expect(result.log.lastIndexOf("health-pr-31")).toBeLessThan(result.log.lastIndexOf("lifecycle-31"));
  });

  test("a SEALED converted bootstrap admits explicit revisions with omitted false protobuf fields", async () => {
    const result = await runTransaction({ exposure: "sealed" });
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.state.exposure).toBe("open");
    expect(result.log).toContain("traffic-commit");
    expect(result.log.trim().split("\n")).toContain("open");
    expect(result.state.transitionMetadata.state).toBe("clear");
    expect(routeRevision(result.state, undefined)).toBe(baselineRevision);
    expect(routeRevision(result.state, "pr-31")).toBe(candidateRevision);
  });

  test("a raw LATEST target after staging is rejected without mutation", async () => {
    const result = await runTransaction({ exposure: "sealed", rawLatest: true });
    expect(result.exitCode).not.toBe(0);
    expect(result.log).not.toContain("traffic-commit");
    expect(result.log).not.toContain("open");
    expect(result.state.exposure).toBe("sealed");
    expect(result.state.traffic).toEqual([
      { percent: 100, type: "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST" },
    ]);
  });

  test("a v2 automatic base image binding is rejected before traffic mutation", async () => {
    const result = await runTransaction({ candidateBaseImage: true, exposure: "sealed" });
    expect(result.exitCode).not.toBe(0);
    expect(result.log).not.toContain("traffic-commit");
    expect(result.state.exposure).toBe("sealed");
  });

  test("a v2 service buildConfig is rejected before traffic mutation", async () => {
    const result = await runTransaction({ exposure: "sealed", serviceBuildConfig: true });
    expect(result.exitCode).not.toBe(0);
    expect(result.log).not.toContain("traffic-commit");
    expect(result.state.exposure).toBe("sealed");
  });

  test("quoted opaque v2 etags are preserved and missing or malformed etags fail before mutation", async () => {
    const accepted = await runTransaction({ exposure: "sealed" });
    expect(accepted.exitCode, accepted.stderr).toBe(0);
    for (const etagMode of ["missing", "malformed"] as const) {
      const rejected = await runTransaction({ etagMode, exposure: "sealed" });
      expect(rejected.exitCode).not.toBe(0);
      expect(rejected.log).not.toContain("traffic-commit");
      expect(rejected.state.exposure).toBe("sealed");
    }
  });

  test("an etag conflict leaves the admitted OPEN graph untouched", async () => {
    const result = await runTransaction({ exposure: "open", patchMode: "conflict" });
    expect(result.exitCode).not.toBe(0);
    expect(result.log).toContain("traffic-conflict");
    expect(result.log).not.toContain("traffic-commit");
    expect(routeRevision(result.state, "pr-31")).toBe(oldTargetRevision);
    expect(routeRevision(result.state, "pr-44")).toBe(survivorRevision);
    expect(result.state.exposure).toBe("open");
  });

  test("an asynchronous operation error leaves the prior graph untouched", async () => {
    const result = await runTransaction({ exposure: "open", patchMode: "operation-error" });
    expect(result.exitCode).not.toBe(0);
    expect(result.log).toContain("traffic-operation-error");
    expect(routeRevision(result.state, "pr-31")).toBe(oldTargetRevision);
    expect(result.state.exposure).toBe("open");
  });

  test("a response-lost PATCH retains durable poison and performs no inferential follow-up mutation", async () => {
    const result = await runTransaction({ exposure: "sealed", patchMode: "accepted-transport-loss" });
    expect(result.exitCode).not.toBe(0);
    expect(result.log, result.stderr).toContain("traffic-transport-loss");
    expect(result.log).not.toContain("traffic-commit-delayed");
    expect(result.log).not.toContain("traffic-restore");
    expect(result.state.exposure).toBe("sealed");
    expect(routeRevision(result.state, undefined)).toBe(bootstrapRevision);
    expect(routeRevision(result.state, "pr-31")).toBeUndefined();
    expect(result.state.transitionMetadata.state).toBe("preview-admission");
    expect(result.state.pendingPatch).toBeDefined();
    expect(result.stderr).toContain("retaining the durable parity poison");
  });

  test("failure after an OPEN commit restores the exact prior traffic without sealing siblings", async () => {
    const result = await runTransaction({ exposure: "open", healthFailure: true });
    expect(result.exitCode).not.toBe(0);
    expect(routeRevision(result.state, "pr-31")).toBe(oldTargetRevision);
    expect(routeRevision(result.state, "pr-44")).toBe(survivorRevision);
    expect(result.state.exposure).toBe("open");
    expect(result.log).toContain("traffic-commit");
    expect(result.log).toContain("traffic-restore");
    expect(result.log).not.toContain("seal");
  });

  test("failure after SEALED exposure opens reseals before restoring bootstrap traffic", async () => {
    const result = await runTransaction({ exposure: "sealed", healthFailure: true });
    expect(result.exitCode).not.toBe(0);
    expect(result.state.exposure).toBe("sealed");
    expect(routeRevision(result.state, undefined)).toBe(bootstrapRevision);
    expect(result.log).toContain("traffic-commit");
    expect(result.log.trim().split("\n")).toContain("open");
    expect(result.log).toContain("traffic-restore-sealed");
    expect(result.log.trim().split("\n")).not.toContain("seal");
    expect(result.state.transitionMetadata.state).toBe("preview-admission");
  });

  test("post-health control-plane drift is detected while exact rollback is still armed", async () => {
    const result = await runTransaction({ exposure: "open", driftAfterHealth: true });
    expect(result.exitCode).not.toBe(0);
    expect(result.log).toContain("health-drift");
    expect(result.log).toContain("traffic-restore");
    expect(routeRevision(result.state, "pr-31")).toBe(oldTargetRevision);
    expect(result.state.exposure).toBe("open");
  });

  test("production changing immediately before CAS causes no traffic mutation and seals exposure", async () => {
    const result = await runTransaction({ exposure: "open", productionFlipBeforePatch: true });
    expect(result.exitCode).not.toBe(0);
    expect(result.log).not.toContain("traffic-commit");
    expect(routeRevision(result.state, "pr-31")).toBe(oldTargetRevision);
    expect(result.state.exposure).toBe("sealed");
    expect(result.log).toContain("seal-cas");
    expect(result.state.transitionMetadata.state).toBe("preview-admission");
  });

  test("production changing after CAS restores exact prior traffic and seals exposure", async () => {
    const result = await runTransaction({ exposure: "open", productionFlipAfterPatch: true });
    expect(result.exitCode).not.toBe(0);
    expect(result.log).toContain("traffic-commit");
    expect(result.log).toContain("traffic-restore-sealed");
    expect(routeRevision(result.state, "pr-31")).toBe(oldTargetRevision);
    expect(routeRevision(result.state, "pr-44")).toBe(survivorRevision);
    expect(result.state.exposure).toBe("sealed");
    expect(result.state.transitionMetadata.state).toBe("preview-admission");
  });
});

type RunOptions = {
  candidateBaseImage?: boolean;
  driftAfterHealth?: boolean;
  etagMode?: "malformed" | "missing";
  exposure: "open" | "sealed";
  healthFailure?: boolean;
  patchMode?: "accepted-transport-loss" | "conflict" | "operation-error";
  productionFlipAfterPatch?: boolean;
  productionFlipBeforePatch?: boolean;
  rawLatest?: boolean;
  serviceBuildConfig?: boolean;
};

async function runDeployPreflightFailure(): Promise<{
  exitCode: number;
  mutations: string;
  stderr: string;
}> {
  const root = await mkdtemp(join(tmpdir(), "platform-preview-preflight-"));
  temporaryRoots.push(root);
  const bin = join(root, "bin");
  const output = join(root, "github-output");
  const mutations = join(root, "mutations");
  await mkdir(bin, { recursive: true });
  await writeFile(output, "");
  await writeFile(mutations, "");
  const gcloud = join(bin, "gcloud");
  await writeFile(
    gcloud,
    [
      "#!/bin/sh",
      "set -eu",
      "if [ \"$*\" = 'auth print-access-token' ]; then printf 'fixture-token\\n'; exit 0; fi",
      "printf '%s\\n' \"$*\" >> \"$FAKE_MUTATIONS\"",
      "exit 99",
      "",
    ].join("\n"),
  );
  await chmod(gcloud, 0o755);
  const workflow = Bun.YAML.parse(
    await readFile(join(repoRoot, ".github/workflows/deploy-preview.yml"), "utf8"),
  ) as { jobs: { deploy: { steps: Array<{ name?: string; run?: string }> } } };
  const run = workflow.jobs.deploy.steps.find((step) => step.name === "Deploy preview to Cloud Run")?.run;
  expect(run).toBeDefined();
  const child = Bun.spawn(["/bin/bash", "--noprofile", "--norc", "-c", run!], {
    cwd: repoRoot,
    env: {
      ...process.env,
      DHI_PARITY_ID: parityId,
      EXPECTED_HEAD_SHA: candidateHead,
      EXPECTED_PREVIEW_IMAGE_NAME:
        "us-east4-docker.pkg.dev/critical-history-16823277/site-preview/critical-history",
      EXPECTED_PRODUCTION_IMAGE_NAME:
        "us-east4-docker.pkg.dev/critical-history-16823277/site/critical-history",
      FAKE_MUTATIONS: mutations,
      GITHUB_OUTPUT: output,
      GITHUB_RUN_ATTEMPT: "1",
      GITHUB_RUN_ID: "123456789",
      IMAGE_DIGEST: `sha256:${"a".repeat(64)}`,
      IMAGE_NAME:
        "us-east4-docker.pkg.dev/critical-history-16823277/site-preview/critical-history",
      LIVE_PRODUCTION_HEAD_SHA: productionHead,
      LIVE_PRODUCTION_INDEX_IMAGE:
        `us-east4-docker.pkg.dev/critical-history-16823277/site/critical-history@sha256:${"b".repeat(64)}`,
      LIVE_PRODUCTION_RUNNABLE_IMAGE:
        `us-east4-docker.pkg.dev/critical-history-16823277/site/critical-history@sha256:${"c".repeat(64)}`,
      MAPBOX_PUBLIC_TOKEN: "",
      PATH: `${bin}:${process.env.PATH ?? "/usr/bin:/bin"}`,
      PLATFORM_WORKFLOW_SHA: workflowSha,
      PREVIEW_INGRESS: "internal-and-cloud-load-balancing",
      PREVIEW_SERVICE: "critical-history-preview",
      PR_NUMBER: "31",
      PROJECT_ID: "critical-history-16823277",
      PROJECT_NUMBER: "229383559510",
      REGION: region,
      REPOSITORY_ID: "280932482",
      RUNNABLE_DIGEST: `sha256:${"d".repeat(64)}`,
      RUNNER_TEMP: root,
      RUNTIME_SERVICE_ACCOUNT:
        "cloud-run-preview@critical-history-16823277.iam.gserviceaccount.com",
      STABLE_PREVIEW_DOMAIN: "preview.ycriticalhistory.org",
    },
    stdout: "ignore",
    stderr: "pipe",
  });
  const [exitCode, stderr] = await Promise.all([
    child.exited,
    new Response(child.stderr).text(),
  ]);
  return { exitCode, mutations: await readFile(mutations, "utf8"), stderr };
}

async function runTransaction(options: RunOptions): Promise<{
  exitCode: number;
  log: string;
  output: string;
  state: any;
  stderr: string;
}> {
  const root = await mkdtemp(join(tmpdir(), "platform-preview-transaction-"));
  temporaryRoots.push(root);
  const bin = join(root, "bin");
  const policy = join(root, "policy/tools/ci");
  const statePath = join(root, "state.json");
  const logPath = join(root, "events.log");
  const outputPath = join(root, "github-output");
  await mkdir(bin, { recursive: true });
  await mkdir(policy, { recursive: true });
  await writeFile(logPath, "");
  await writeFile(outputPath, "");

  const wrapper = (command: string) => [
    "#!/bin/sh",
    "set -eu",
    `MOCK_COMMAND=${command} exec bun "$MOCK_CLI" "$@"`,
    "",
  ].join("\n");
  for (const command of ["curl", "gcloud", "gh"]) {
    const path = join(bin, command);
    await writeFile(path, wrapper(command));
    await chmod(path, 0o755);
  }
  const sleep = join(bin, "sleep");
  await writeFile(sleep, "#!/bin/sh\nexit 0\n");
  await chmod(sleep, 0o755);

  const parityPolicy = join(policy, "cloud-run-dhi-parity.sh");
  await writeFile(parityPolicy, [
    "#!/bin/bash",
    "set -euo pipefail",
    "case \"$1\" in",
    "  prove-preview-routes)",
    "    tag=pr-${PR_NUMBER}",
    "    jq -e --arg baseline \"$BASELINE_REVISION\" --arg candidate \"$EXPECTED_REVISION\" --arg forbidden \"${MOCK_FORBIDDEN_REVISION:-}\" --arg tag \"$tag\" '",
    "      ([.status.traffic[]? | select((.tag // \"\") == \"\") | .revisionName] == [$baseline]) and",
    "      ([.status.traffic[]? | select(.tag == $tag) | .revisionName] == [$candidate]) and",
    "      ($forbidden == \"\" or ([.status.traffic[]?.revisionName] | index($forbidden) == null))",
    "    ' \"$PARITY_SERVICE_JSON\" >/dev/null",
    "    echo parity-proof >> \"$MOCK_LOG\"",
    "    echo all_routes_candidate_parity=true >> \"$GITHUB_OUTPUT\"",
    `    echo dhi_parity_id=${parityId} >> \"$GITHUB_OUTPUT\"`,
    "    ;;",
    "  prove-production)",
    "    head=$(jq -er '.metadata.labels[\"git-head-sha\"]' \"$PARITY_REVISION_JSON\")",
    "    index=$(jq -er '[.spec.containers[0].env[] | select(.name == \"PLATFORM_IMAGE_INDEX_DIGEST\") | .value][0]' \"$PARITY_REVISION_JSON\")",
    "    runnable=$(jq -er '[.spec.containers[0].env[] | select(.name == \"PLATFORM_IMAGE_RUNNABLE_DIGEST\") | .value][0]' \"$PARITY_REVISION_JSON\")",
    `    echo dhi_parity_id=${parityId} >> \"$GITHUB_OUTPUT\"`,
    "    echo live_production_head_sha=$head >> \"$GITHUB_OUTPUT\"",
    "    echo live_production_index_digest=$index >> \"$GITHUB_OUTPUT\"",
    "    echo live_production_index_image=${EXPECTED_PRODUCTION_IMAGE_NAME}@$index >> \"$GITHUB_OUTPUT\"",
    "    echo live_production_runnable_digest=$runnable >> \"$GITHUB_OUTPUT\"",
    "    echo live_production_runnable_image=${EXPECTED_PRODUCTION_IMAGE_NAME}@$runnable >> \"$GITHUB_OUTPUT\"",
    "    echo production_revision=$(jq -r .metadata.name \"$PARITY_REVISION_JSON\") >> \"$GITHUB_OUTPUT\"",
    "    ;;",
    "  *) exit 97 ;;",
    "esac",
    "",
  ].join("\n"));
  await chmod(parityPolicy, 0o755);
  const graphPolicy = join(policy, "container-artifact-contract.sh");
  await writeFile(graphPolicy, [
    "#!/bin/bash",
    "set -euo pipefail",
    "case \"$1\" in",
    "  verify-live-images) jq -e 'length >= 2' \"$LIVE_IMAGE_SET_FILE\" >/dev/null; echo graph-proof >> \"$MOCK_LOG\" ;;",
    "  verify-live-production) echo production-graph-proof >> \"$MOCK_LOG\" ;;",
    "  *) exit 98 ;;",
    "esac",
    `echo dhi_parity_id=${parityId} >> \"$GITHUB_OUTPUT\"`,
    "",
  ].join("\n"));
  await chmod(graphPolicy, 0o755);
  const transitionPolicy = join(policy, "deployment-parity-transition.sh");
  await writeFile(transitionPolicy, await readFile(join(repoRoot, "tools/ci/deployment-parity-transition.sh")));
  await chmod(transitionPolicy, 0o755);

  const revisions = Object.fromEntries([
    revision(baselineRevision, "baseline", productionHead, undefined, "a"),
    revision(candidateRevision, "pr", candidateHead, "31", "b"),
    revision(oldBaselineRevision, "baseline", productionHead, undefined, "c"),
    revision(oldTargetRevision, "pr", oldHead, "31", "d"),
    revision(survivorRevision, "pr", survivorHead, "44", "e"),
    revision(bootstrapRevision, "baseline", productionHead, undefined, "f"),
  ].map((pair) => [pair.v1.metadata.name, pair]));
  if (options.candidateBaseImage) {
    revisions[candidateRevision].v2.containers[0].baseImageUri =
      "us-east4-docker.pkg.dev/serverless-runtimes/google-24/runtimes/nodejs24";
  }
  const traffic = options.rawLatest
    ? [{ percent: 100, type: "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST" }]
    : options.exposure === "open"
    ? [
        target(oldBaselineRevision, 100),
        target(oldTargetRevision, 0, "pr-31"),
        target(survivorRevision, 0, "pr-44"),
      ]
    : [target(bootstrapRevision, 100)];
  const initialState = {
    candidateRevision,
    etag: 1,
    etagMode: options.etagMode,
    exposure: options.exposure,
    generation: 7,
    ghHeads: { "31": candidateHead, "44": survivorHead },
    iamBindings: exactPreviewIamBindings,
    iamEtag: 1,
    latestResolution: bootstrapRevision,
    latestRevision: candidateRevision,
    patchMode: options.patchMode,
    projectId,
    projectNumber,
    productionFlipAfterPatch: options.productionFlipAfterPatch,
    productionFlipBeforePatch: options.productionFlipBeforePatch,
    productionGeneration: 9,
    productionHead,
    productionIndex: `sha256:${"8".repeat(64)}`,
    productionReadCount: 0,
    productionRevision,
    productionRunnable: `sha256:${"9".repeat(64)}`,
    productionService,
    region,
    revisions,
    service,
    serviceBuildConfig: options.serviceBuildConfig,
    traffic,
    transitionGeneration: "17",
    transitionMetadata: { "repository-id": "1255553151", state: "clear", version: "1" },
    transitionMetageneration: "1",
  };
  await writeFile(statePath, JSON.stringify(initialState));

  const child = Bun.spawn(["/bin/bash", helper, "commit"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      BASE_CONTENT_SHA256: "6".repeat(64),
      BASE_DOWNLOAD_DIR: root,
      BASE_MANIFEST_SHA256: "7".repeat(64),
      BASELINE_REVISION: baselineRevision,
      DHI_PARITY_ID: parityId,
      EXPECTED_BASELINE_PRODUCTION_HEAD_SHA: productionHead,
      EXPECTED_BASELINE_PRODUCTION_INDEX_IMAGE: `${productionImage}@sha256:${"8".repeat(64)}`,
      EXPECTED_BASELINE_PRODUCTION_RUNNABLE_IMAGE: `${productionImage}@sha256:${"9".repeat(64)}`,
      EXPECTED_PLATFORM_WORKFLOW_SHA: workflowSha,
      EXPECTED_PREVIEW_IMAGE_NAME: previewImage,
      EXPECTED_PREVIEW_RUNTIME_SERVICE_ACCOUNT: runtimeServiceAccount,
      EXPECTED_PRODUCTION_IMAGE_NAME: productionImage,
      EXPECTED_PROJECT_NUMBER: projectNumber,
      EXPECTED_REPOSITORY: "collinbentley1/cdbentley",
      EXPECTED_REPOSITORY_ID: "1255553151",
      EXPECTED_REVISION: candidateRevision,
      GH_TOKEN: "test-token",
      GITHUB_OUTPUT: outputPath,
      GITHUB_REPOSITORY: "collinbentley1/cdbentley",
      GITHUB_RUN_ATTEMPT: "1",
      GITHUB_RUN_ID: "123456789",
      GITHUB_WORKSPACE: root,
      INITIAL_EXPOSURE: options.exposure,
      MOCK_CLI: mockCli,
      MOCK_DRIFT_AFTER_HEALTH: options.driftAfterHealth ? "1" : "0",
      MOCK_FORBIDDEN_REVISION: oldTargetRevision,
      MOCK_HEALTH_FAILURE: options.healthFailure ? "1" : "0",
      MOCK_LOG: logPath,
      MOCK_STATE: statePath,
      PARITY_POLICY_ROOT: join(root, "policy"),
      PATH: `${bin}:${process.env.PATH ?? "/usr/bin:/bin"}`,
      PREVIEW_INGRESS: "all",
      PREVIEW_SERVICE: service,
      PREVIEW_URL: `https://pr-31---${service}-${projectNumber}.${region}.run.app`,
      PR_NUMBER: "31",
      PROJECT_ID: projectId,
      REGION: region,
      RUNNER_TEMP: root,
      SERVICE_NAME: productionService,
      STABLE_PREVIEW_DOMAIN: "",
    },
    stdout: "ignore",
    stderr: "pipe",
  });
  const [exitCode, stderr] = await Promise.all([
    child.exited,
    new Response(child.stderr).text(),
  ]);
  return {
    exitCode,
    log: await readFile(logPath, "utf8"),
    output: await readFile(outputPath, "utf8"),
    state: JSON.parse(await readFile(statePath, "utf8")),
    stderr,
  };
}

function target(revision: string, percent: number, tag?: string): Record<string, unknown> {
  return {
    percent,
    revision,
    ...(tag ? { tag } : {}),
    type: "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION",
  };
}

function routeRevision(state: any, tag: string | undefined): string | undefined {
  return state.traffic.find((target: any) => target.tag === tag)?.revision;
}

function revision(
  name: string,
  role: "baseline" | "pr",
  head: string,
  pull: string | undefined,
  nonceCharacter: string,
): { v1: any; v2: any } {
  const baseline = role === "baseline";
  const imageName = baseline ? productionImage : previewImage;
  const index = `sha256:${nonceCharacter.repeat(64)}`;
  const runnable = `sha256:${nonceCharacter.toUpperCase().repeat(64).toLowerCase()}`;
  const env = baseline
    ? [
        { name: "PLATFORM_DEPLOY_ENVIRONMENT", value: "preview-baseline" },
        { name: "PLATFORM_IMAGE_INDEX_DIGEST", value: index },
        { name: "PLATFORM_IMAGE_RUNNABLE_DIGEST", value: runnable },
      ]
    : [
        { name: "PLATFORM_DEPLOY_ENVIRONMENT", value: "preview" },
        { name: "PLATFORM_DEPLOY_NONCE", value: nonceCharacter.repeat(64) },
        { name: "PLATFORM_IMAGE_INDEX_DIGEST", value: index },
        { name: "PLATFORM_IMAGE_RUNNABLE_DIGEST", value: runnable },
        { name: "PLATFORM_PREVIEW_NUMBER", value: pull },
      ];
  const command = baseline ? ["bun"] : [];
  const args = baseline
    ? ["-e", "Bun.serve({port:+process.env.PORT,fetch(){return new Response(null,{status:404})}})"]
    : [];
  const labels = {
    "dhi-parity-id": parityId,
    "git-head-sha": head,
    "github-repository-id": "1255553151",
    "managed-by": "github-actions",
    "platform-workflow-sha": workflowSha,
    "preview-role": role,
    ...(pull ? { "github-pr": pull } : {}),
  };
  const container = { args, command, env, image: `${imageName}@${runnable}` };
  return {
    v1: {
      metadata: { generation: 1, labels, name, namespace: projectNumber },
      spec: { containers: [container], serviceAccountName: runtimeServiceAccount },
      status: {
        conditions: [{ status: "True", type: "Ready" }],
        imageDigest: `${imageName}@${runnable}`,
        observedGeneration: 1,
      },
    },
    v2: {
      conditions: [{ state: "CONDITION_SUCCEEDED", type: "Ready" }],
      containers: [container],
      generation: "1",
      labels,
      name: `projects/${projectId}/locations/${region}/services/${service}/revisions/${name}`,
      serviceAccount: runtimeServiceAccount,
    },
  };
}
