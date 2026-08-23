import { appendFileSync, readFileSync, writeFileSync } from "node:fs";

type TrafficTarget = {
  percent: number;
  revision?: string;
  tag?: string;
  type: string;
};

type RevisionPair = { v1: Record<string, unknown>; v2: Record<string, unknown> };

type State = {
  candidateRevision: string;
  etag: number;
  etagMode?: "malformed" | "missing";
  exposure: "open" | "sealed";
  generation: number;
  ghHeads: Record<string, string>;
  healthDrifted?: boolean;
  iamBindings: Array<{ members: string[]; role: string }>;
  iamEtag: number;
  latestRevision: string;
  latestResolution: string;
  operationError?: boolean;
  patchMode?: "accepted-transport-loss" | "conflict" | "operation-error";
  pendingPatch?: {
    body: { ingress?: string; invokerIamDisabled?: boolean; traffic?: TrafficTarget[] };
    updateMask: string;
  };
  pendingReads?: number;
  productionFlipAfterPatch?: boolean;
  productionFlipBeforePatch?: boolean;
  productionGeneration: number;
  productionHead: string;
  productionIndex: string;
  productionReadCount: number;
  productionRevision: string;
  productionRunnable: string;
  productionService: string;
  projectId: string;
  projectNumber: string;
  region: string;
  revisions: Record<string, RevisionPair>;
  service: string;
  serviceBuildConfig?: boolean;
  traffic: TrafficTarget[];
  transitionGeneration: string;
  transitionMetadata: Record<string, string>;
  transitionMetageneration: string;
};

const command = process.env.MOCK_COMMAND;
const statePath = process.env.MOCK_STATE!;
const logPath = process.env.MOCK_LOG!;
const args = Bun.argv.slice(2);

function readState(): State {
  return JSON.parse(readFileSync(statePath, "utf8")) as State;
}

function writeState(state: State): void {
  writeFileSync(statePath, JSON.stringify(state));
}

function log(event: string): void {
  appendFileSync(logPath, `${event}\n`);
}

function shortRevision(target: TrafficTarget, state: State): string {
  return target.revision?.split("/").at(-1) ?? state.latestResolution;
}

function tagUrl(target: TrafficTarget, state: State): string {
  if (!target.tag) {
    return `https://${state.service}-${state.projectNumber}.${state.region}.run.app`;
  }
  return `https://${target.tag}---${state.service}-${state.projectNumber}.${state.region}.run.app`;
}

function serviceV2(state: State): Record<string, unknown> {
  const trafficStatuses = state.traffic.map((target) => ({
    percent: target.percent,
    revision: shortRevision(target, state),
    ...(target.tag ? { tag: target.tag } : {}),
    uri: tagUrl(target, state),
  }));
  return {
    name: `projects/${state.projectId}/locations/${state.region}/services/${state.service}`,
    generation: String(state.generation),
    observedGeneration: String(state.generation),
    ...(state.etagMode === "missing"
      ? {}
      : { etag: state.etagMode === "malformed" ? "bad\netag" : `\"etag-${state.etag}\"` }),
    ingress: state.exposure === "open"
      ? "INGRESS_TRAFFIC_ALL"
      : "INGRESS_TRAFFIC_INTERNAL_ONLY",
    ...(state.exposure === "open" ? { invokerIamDisabled: true } : {}),
    traffic: state.traffic,
    trafficStatuses,
    latestReadyRevision: state.latestRevision,
    terminalCondition: { state: "CONDITION_SUCCEEDED", type: "Ready" },
    urls: [`https://${state.service}-${state.projectNumber}.${state.region}.run.app`],
    uri: `https://${state.service}-${state.projectNumber}.${state.region}.run.app`,
    ...(state.serviceBuildConfig
      ? { buildConfig: { baseImage: "us-east4-docker.pkg.dev/serverless-runtimes/google-24/runtimes/nodejs24" } }
      : {}),
    template: { revision: state.latestRevision },
  };
}

function serviceV1(state: State): Record<string, unknown> {
  const specTraffic = state.traffic.map((target) => ({
    latestRevision: target.type === "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST",
    percent: target.percent,
    ...(target.revision ? { revisionName: shortRevision(target, state) } : {}),
    ...(target.tag ? { tag: target.tag } : {}),
  }));
  const statusTraffic = state.traffic.map((target) => ({
    latestRevision: target.type === "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST",
    percent: target.percent,
    revisionName: shortRevision(target, state),
    ...(target.tag ? { tag: target.tag } : {}),
    url: tagUrl(target, state),
  }));
  return {
    metadata: {
      annotations: {
        "run.googleapis.com/ingress": state.exposure === "open" ? "all" : "internal",
      },
      generation: state.generation,
      labels: { environment: "preview" },
      name: state.service,
      namespace: state.projectNumber,
    },
    spec: {
      template: { metadata: { name: state.latestRevision } },
      traffic: specTraffic,
    },
    status: {
      conditions: [{ status: "True", type: "Ready" }],
      latestCreatedRevisionName: state.latestRevision,
      latestReadyRevisionName: state.latestRevision,
      observedGeneration: state.generation,
      traffic: statusTraffic,
    },
  };
}

function productionServiceV1(state: State): Record<string, unknown> {
  return {
    apiVersion: "serving.knative.dev/v1",
    kind: "Service",
    metadata: {
      generation: state.productionGeneration,
      labels: {
        "dhi-parity-id": "1a4cho1elzg84pavos8mbanvvpmkieiht7kyhpjdofzpivf3k8",
        environment: "production",
        "managed-by": "github-actions",
      },
      name: state.productionService,
      namespace: state.projectNumber,
    },
    spec: { traffic: [{ latestRevision: true, percent: 100 }] },
    status: {
      conditions: [
        { status: "True", type: "Ready" },
        { status: "True", type: "ConfigurationsReady" },
        { status: "True", type: "RoutesReady" },
      ],
      latestCreatedRevisionName: state.productionRevision,
      latestReadyRevisionName: state.productionRevision,
      observedGeneration: state.productionGeneration,
      traffic: [{
        latestRevision: true,
        percent: 100,
        revisionName: state.productionRevision,
      }],
    },
  };
}

function productionRevisionV1(state: State): Record<string, unknown> {
  const image = `us-east4-docker.pkg.dev/${state.projectId}/site/${state.productionService}@${state.productionRunnable}`;
  return {
    apiVersion: "serving.knative.dev/v1",
    kind: "Revision",
    metadata: {
      generation: 1,
      labels: {
        "dhi-parity-id": "1a4cho1elzg84pavos8mbanvvpmkieiht7kyhpjdofzpivf3k8",
        environment: "production",
        "git-head-sha": state.productionHead,
        "github-repository-id": "1255553151",
        "managed-by": "github-actions",
        "platform-workflow-sha": "1".repeat(40),
        "serving.knative.dev/service": state.productionService,
      },
      name: state.productionRevision,
      namespace: state.projectNumber,
    },
    spec: {
      containers: [{
        env: [
          { name: "PLATFORM_IMAGE_INDEX_DIGEST", value: state.productionIndex },
          { name: "PLATFORM_IMAGE_RUNNABLE_DIGEST", value: state.productionRunnable },
        ],
        image,
      }],
    },
    status: {
      conditions: [{ status: "True", type: "Ready" }],
      imageDigest: image,
      observedGeneration: 1,
    },
  };
}

function productionServiceV2(state: State): Record<string, unknown> {
  return {
    etag: `\"production-etag-${state.productionGeneration}\"`,
    generation: String(state.productionGeneration),
    ingress: "INGRESS_TRAFFIC_ALL",
    invokerIamDisabled: true,
    latestReadyRevision: state.productionRevision,
    name: `projects/${state.projectId}/locations/${state.region}/services/${state.productionService}`,
    observedGeneration: String(state.productionGeneration),
    template: { containers: [{}], revision: state.productionRevision },
    terminalCondition: { state: "CONDITION_SUCCEEDED", type: "Ready" },
    traffic: [{ percent: 100, type: "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST" }],
    trafficStatuses: [{ percent: 100, type: "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST" }],
    uri: `https://${state.productionService}-${state.projectNumber}.${state.region}.run.app`,
    urls: [`https://${state.productionService}-${state.projectNumber}.${state.region}.run.app`],
  };
}

function productionRevisionV2(state: State): Record<string, unknown> {
  const image = `us-east4-docker.pkg.dev/${state.projectId}/site/${state.productionService}@${state.productionRunnable}`;
  return {
    conditions: [{ state: "CONDITION_SUCCEEDED", type: "Ready" }],
    containers: [{
      env: [
        { name: "PLATFORM_IMAGE_INDEX_DIGEST", value: state.productionIndex },
        { name: "PLATFORM_IMAGE_RUNNABLE_DIGEST", value: state.productionRunnable },
      ],
      image,
    }],
    generation: "1",
    labels: { "git-head-sha": state.productionHead },
    name:
      `projects/${state.projectId}/locations/${state.region}/services/${state.productionService}/revisions/${state.productionRevision}`,
  };
}

function flipProduction(state: State): void {
  state.productionGeneration += 1;
  state.productionHead = "f".repeat(40);
  state.productionIndex = `sha256:${"6".repeat(64)}`;
  state.productionRunnable = `sha256:${"7".repeat(64)}`;
  state.productionRevision = `${state.productionService}-production-changed`;
  log("production-flip");
}

function outputPath(): string | undefined {
  const index = args.indexOf("--output");
  if (index >= 0) return args[index + 1];
  return args.find((argument) => argument.startsWith("--output="))?.slice(9);
}

function writeOutput(value: unknown): void {
  const destination = outputPath();
  if (!destination) throw new Error(`mock curl missing --output: ${args.join(" ")}`);
  if (typeof value === "string") writeFileSync(destination, value);
  else writeFileSync(destination, JSON.stringify(value));
}

function mutate(state: State, event: string): void {
  state.etag += 1;
  state.generation += 1;
  writeState(state);
  log(event);
}

if (command === "gcloud") {
  const state = readState();
  if (args[0] === "auth" && args[1] === "print-access-token") {
    process.stdout.write("mock-access-token\n");
  } else if (args[0] === "run" && args[1] === "services" && args[2] === "describe") {
    if (args[3] === state.productionService) {
      state.productionReadCount += 1;
      if (state.productionFlipBeforePatch && state.productionReadCount === 2) {
        flipProduction(state);
      }
      writeState(state);
      process.stdout.write(JSON.stringify(productionServiceV1(state)));
    } else {
      process.stdout.write(JSON.stringify(serviceV1(state)));
    }
  } else if (args[0] === "run" && args[1] === "revisions" && args[2] === "describe") {
    const revision = args[3]!;
    if (revision === state.productionRevision) {
      process.stdout.write(JSON.stringify(productionRevisionV1(state)));
    } else {
      const fixture = state.revisions[revision];
      if (!fixture) process.exit(4);
      process.stdout.write(JSON.stringify(fixture.v1));
    }
  } else if (args[0] === "run" && args[1] === "services" && args[2] === "update") {
    state.exposure = "sealed";
    mutate(state, "seal");
    process.stdout.write(JSON.stringify(serviceV1(state)));
  } else {
    throw new Error(`unexpected gcloud invocation: ${args.join(" ")}`);
  }
  process.exit(0);
}

if (command === "gh") {
  const state = readState();
  const endpoint = args.at(-1)!;
  const pull = endpoint.match(/\/pulls\/([1-9][0-9]*)$/)?.[1];
  const head = pull ? state.ghHeads[pull] : undefined;
  if (!pull || !head) process.exit(1);
  log(`lifecycle-${pull}`);
  process.stdout.write(JSON.stringify({
    base: { ref: "main" },
    draft: false,
    head: {
      repo: { full_name: "collinbentley1/cdbentley", id: 1255553151 },
      sha: head,
    },
    state: "open",
  }));
  process.exit(0);
}

if (command !== "curl") throw new Error(`unexpected mock command: ${command}`);

const state = readState();
const url = args.at(-1)!;
const requestIndex = args.indexOf("--request");
const method = requestIndex >= 0 ? args[requestIndex + 1] : "GET";

if (url.includes("storage.googleapis.com/storage/v1/b/")) {
  if (method === "GET") {
    writeOutput({
      bucket: `${state.projectId}-deployment-parity-state`,
      generation: state.transitionGeneration,
      metadata: state.transitionMetadata,
      metageneration: state.transitionMetageneration,
      name: "deployment-parity-transition",
    });
    process.stdout.write("200");
    process.exit(0);
  }
  if (method !== "PATCH") throw new Error(`unexpected storage method: ${method}`);
  const query = new URL(url).searchParams;
  if (query.get("ifGenerationMatch") !== state.transitionGeneration ||
      query.get("ifMetagenerationMatch") !== state.transitionMetageneration) {
    writeOutput({ error: { code: 412 } });
    process.stdout.write("412");
    process.exit(0);
  }
  const dataArgument = args[args.indexOf("--data-binary") + 1]!;
  const request = JSON.parse(readFileSync(dataArgument.slice(1), "utf8")) as {
    metadata: Record<string, string | null>;
  };
  for (const [key, value] of Object.entries(request.metadata)) {
    if (value === null) delete state.transitionMetadata[key];
    else state.transitionMetadata[key] = value;
  }
  state.transitionMetageneration = String(Number(state.transitionMetageneration) + 1);
  writeState(state);
  log(`transition-${state.transitionMetadata.state}`);
  writeOutput({
    bucket: `${state.projectId}-deployment-parity-state`,
    generation: state.transitionGeneration,
    metadata: state.transitionMetadata,
    metageneration: state.transitionMetageneration,
    name: "deployment-parity-transition",
  });
  process.stdout.write("200");
  process.exit(0);
}

if (url.includes(":getIamPolicy")) {
  writeOutput({ bindings: state.iamBindings, etag: `\"iam-etag-${state.iamEtag}\"`, version: 3 });
  process.exit(0);
}

if (url.includes(":setIamPolicy") && method === "POST") {
  const dataArgument = args[args.indexOf("--data-binary") + 1]!;
  const request = JSON.parse(readFileSync(dataArgument.slice(1), "utf8")) as {
    policy: { bindings?: Array<{ members: string[]; role: string }>; etag: string };
  };
  if (request.policy.etag !== `\"iam-etag-${state.iamEtag}\"`) {
    process.stdout.write("409");
    process.exit(0);
  }
  state.iamBindings = request.policy.bindings ?? [];
  state.iamEtag += 1;
  writeState(state);
  log("iam-policy-sanitize");
  writeOutput({ bindings: state.iamBindings, etag: `\"iam-etag-${state.iamEtag}\"`, version: 3 });
  process.stdout.write("200");
  process.exit(0);
}

if (url.includes("run.googleapis.com/v2/") && url.includes("/operations/")) {
  if (state.operationError) {
    writeOutput({ done: true, error: { code: 9, message: "mock operation error" } });
    state.operationError = false;
    writeState(state);
  } else {
    writeOutput({ done: true, response: { name: serviceV2(state).name } });
  }
  process.exit(0);
}

if (url.includes("run.googleapis.com/v2/projects/") && url.includes("/revisions/")) {
  const revision = url.split("/").at(-1)!;
  if (url.includes(`/services/${state.productionService}/revisions/`) && revision === state.productionRevision) {
    writeOutput(productionRevisionV2(state));
  } else {
    const fixture = state.revisions[revision];
    if (!fixture) process.exit(22);
    writeOutput(fixture.v2);
  }
  process.exit(0);
}

if (url.includes("run.googleapis.com/v2/projects/") && method === "PATCH") {
  const dataArgument = args[args.indexOf("--data-binary") + 1]!;
  const body = JSON.parse(readFileSync(dataArgument.slice(1), "utf8")) as {
    etag: string;
    ingress?: string;
    invokerIamDisabled?: boolean;
    traffic?: TrafficTarget[];
  };
  const updateMask = new URL(url).searchParams.get("updateMask") ?? "";
  if (body.etag !== `\"etag-${state.etag}\"`) process.exit(22);
  if (url.includes("updateMask=traffic")) {
    if (state.patchMode === "conflict") {
      log("traffic-conflict");
      process.exit(22);
    }
    if (state.patchMode === "operation-error") {
      state.operationError = true;
      state.patchMode = undefined;
      writeState(state);
      log("traffic-operation-error");
    } else if (state.patchMode === "accepted-transport-loss") {
      state.patchMode = undefined;
      state.pendingPatch = { body, updateMask };
      state.pendingReads = 2;
      writeState(state);
      log("traffic-transport-loss");
      process.exit(18);
    } else {
      state.traffic = body.traffic!;
      const commit = state.traffic.some((target) => shortRevision(target, state) === state.candidateRevision);
      if (url.includes("ingress,invokerIamDisabled")) {
        state.exposure = body.invokerIamDisabled === true ? "open" : "sealed";
      }
      const event = commit
        ? (state.exposure === "open" && url.includes("ingress,invokerIamDisabled")
          ? "traffic-commit-open"
          : "traffic-commit")
        : (state.exposure === "sealed" && url.includes("ingress,invokerIamDisabled")
          ? "traffic-restore-sealed"
          : "traffic-restore");
      mutate(state, event);
      if (commit && state.productionFlipAfterPatch) {
        flipProduction(state);
        state.productionFlipAfterPatch = false;
        writeState(state);
      }
    }
  } else if (url.includes("updateMask=ingress,invokerIamDisabled")) {
    state.exposure = body.invokerIamDisabled === true ? "open" : "sealed";
    mutate(state, state.exposure === "open" ? "open" : "seal-cas");
  } else {
    throw new Error(`unexpected PATCH: ${url}`);
  }
  writeOutput({ name: `projects/${state.projectId}/locations/${state.region}/operations/op-${state.etag}` });
  process.exit(0);
}

if (url.includes("run.googleapis.com/v2/projects/")) {
  if (!url.endsWith(`/services/${state.productionService}`) && state.pendingPatch) {
    if ((state.pendingReads ?? 0) > 0) {
      state.pendingReads = (state.pendingReads ?? 0) - 1;
      writeState(state);
    } else {
      const pending = state.pendingPatch;
      if (pending.body.traffic) state.traffic = pending.body.traffic;
      if (pending.updateMask.includes("ingress")) {
        state.exposure = pending.body.invokerIamDisabled === true ? "open" : "sealed";
      }
      const commit = state.traffic.some((target) => shortRevision(target, state) === state.candidateRevision);
      delete state.pendingPatch;
      delete state.pendingReads;
      mutate(state, commit ? "traffic-commit-delayed" : "traffic-restore-delayed");
    }
  }
  writeOutput(url.endsWith(`/services/${state.productionService}`)
    ? productionServiceV2(state)
    : serviceV2(state));
  process.exit(0);
}

const statusOutput = args.includes("--write-out");
if (!statusOutput) throw new Error(`unexpected external curl: ${args.join(" ")}`);
const destination = outputPath()!;
if (url.endsWith("/livez")) {
  const tag = url.match(/https:\/\/(pr-[1-9][0-9]*)---/)?.[1];
  const target = state.traffic.find((entry) => entry.tag === tag);
  const revision = target ? state.revisions[shortRevision(target, state)] : undefined;
  const nonce = (revision?.v1 as any)?.spec?.containers?.[0]?.env?.find(
    (entry: { name: string }) => entry.name === "PLATFORM_DEPLOY_NONCE",
  )?.value;
  if (state.exposure === "open" && nonce && process.env.MOCK_HEALTH_FAILURE !== "1") {
    writeFileSync(destination, JSON.stringify({ deployment: nonce, ok: true }));
    process.stdout.write("200");
    log(`health-${tag}`);
    if (process.env.MOCK_DRIFT_AFTER_HEALTH === "1" && !state.healthDrifted) {
      state.healthDrifted = true;
      mutate(state, "health-drift");
    }
  } else {
    writeFileSync(destination, "{}");
    process.stdout.write("503");
  }
} else {
  writeFileSync(destination, "");
  process.stdout.write(state.exposure === "open" ? "404" : "403");
  log("baseline-probe");
}
