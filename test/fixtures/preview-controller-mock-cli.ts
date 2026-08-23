import { appendFileSync, readFileSync, writeFileSync } from "node:fs";

type TrafficTarget = {
  percent: number;
  revision: string;
  tag?: string;
  type: "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION";
};

type RevisionPair = { v1: Record<string, unknown>; v2: Record<string, unknown> };

type State = {
  etag: number;
  exposure: "open" | "sealed";
  generation: number;
  ghHeads: Record<string, string>;
  initialReadFailure?: boolean;
  iamBindings: Array<{ members: string[]; role: string }>;
  iamEtag: number;
  iamSetTransportLoss?: boolean;
  labels: Record<string, string>;
  operation: number;
  patchAttemptCount?: number;
  patchConflict?: boolean;
  patchConflictsRemaining?: number;
  patchDoesNotAdvanceEtagOnAttempt?: number;
  patchTransportLoss?: boolean;
  patchTransportLossOnAttempt?: number;
  pendingPatch?: {
    body: {
      ingress?: string;
      invokerIamDisabled?: boolean;
      labels?: Record<string, string>;
      traffic?: TrafficTarget[];
    };
    updateMask: string;
  };
  pendingReads?: number;
  previewService: string;
  previewServiceAbsent?: boolean;
  productionRevision: RevisionPair;
  productionReadCount?: number;
  productionFlipAfterServiceRead?: number;
  productionService: string;
  projectId: string;
  projectNumber: string;
  region: string;
  revisions: Record<string, RevisionPair>;
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

function etag(state: State): string {
  return `\"controller-etag-${state.etag}\"`;
}

function tagUrl(tag: string | undefined, state: State): string {
  return tag
    ? `https://${tag}---${state.previewService}-${state.projectNumber}.${state.region}.run.app`
    : `https://${state.previewService}-${state.projectNumber}.${state.region}.run.app`;
}

function previewServiceV1(state: State): Record<string, unknown> {
  return {
    metadata: {
      annotations: {
        "run.googleapis.com/ingress": state.exposure === "open" ? "all" : "internal",
      },
      generation: state.generation,
      labels: { environment: "preview" },
      name: state.previewService,
      namespace: state.projectNumber,
    },
    spec: {
      template: { metadata: { name: state.traffic[0]?.revision } },
      traffic: state.traffic.map((target) => ({
        latestRevision: false,
        percent: target.percent,
        revisionName: target.revision,
        ...(target.tag ? { tag: target.tag } : {}),
      })),
    },
    status: {
      conditions: [{ status: "True", type: "Ready" }],
      latestCreatedRevisionName: state.traffic[0]?.revision,
      latestReadyRevisionName: state.traffic[0]?.revision,
      observedGeneration: state.generation,
      traffic: state.traffic.map((target) => ({
        latestRevision: false,
        percent: target.percent,
        revisionName: target.revision,
        ...(target.tag ? { tag: target.tag } : {}),
        url: tagUrl(target.tag, state),
      })),
    },
  };
}

function previewServiceV2(state: State): Record<string, unknown> {
  const traffic = state.traffic.map((target) => ({ ...target }));
  return {
    etag: etag(state),
    generation: String(state.generation),
    ingress: state.exposure === "open"
      ? "INGRESS_TRAFFIC_ALL"
      : "INGRESS_TRAFFIC_INTERNAL_ONLY",
    ...(state.exposure === "open" ? { invokerIamDisabled: true } : {}),
    latestReadyRevision: state.traffic[0]?.revision,
    labels: state.labels,
    name:
      `projects/${state.projectId}/locations/${state.region}/services/${state.previewService}`,
    observedGeneration: String(state.generation),
    terminalCondition: { state: "CONDITION_SUCCEEDED", type: "Ready" },
    template: { containers: [{}], revision: state.traffic[0]?.revision },
    traffic,
    trafficStatuses: state.traffic.map((target) => ({
      ...target,
      uri: tagUrl(target.tag, state),
    })),
    uri: tagUrl(undefined, state),
    urls: [tagUrl(undefined, state)],
  };
}

function applyPendingPatch(state: State): void {
  const pending = state.pendingPatch;
  if (!pending) return;
  if (pending.body.traffic) state.traffic = pending.body.traffic;
  if (pending.body.labels) state.labels = pending.body.labels;
  if (pending.updateMask.includes("ingress")) {
    state.exposure = pending.body.invokerIamDisabled === true ? "open" : "sealed";
  }
  if (state.patchDoesNotAdvanceEtagOnAttempt !== state.patchAttemptCount) {
    state.etag += 1;
    state.generation += 1;
  }
  state.operation += 1;
  log(
    `patch-commit mask=${pending.updateMask} exposure=${state.exposure} tags=${state.traffic
      .map((target) => target.tag ?? "baseline")
      .join(",")}`,
  );
  delete state.pendingPatch;
  delete state.pendingReads;
}

function productionServiceV1(state: State): Record<string, unknown> {
  const revision = (state.productionRevision.v1 as any).metadata.name;
  return {
    metadata: {
      generation: 9,
      labels: { environment: "production" },
      name: state.productionService,
      namespace: state.projectNumber,
    },
    spec: { traffic: [{ latestRevision: true, percent: 100 }] },
    status: {
      conditions: [{ status: "True", type: "Ready" }],
      latestCreatedRevisionName: revision,
      latestReadyRevisionName: revision,
      observedGeneration: 9,
      traffic: [{ latestRevision: true, percent: 100, revisionName: revision }],
    },
  };
}

function productionServiceV2(state: State): Record<string, unknown> {
  const revision = (state.productionRevision.v1 as any).metadata.name;
  return {
    generation: "9",
    ingress: "INGRESS_TRAFFIC_ALL",
    invokerIamDisabled: true,
    latestReadyRevision: revision,
    name:
      `projects/${state.projectId}/locations/${state.region}/services/${state.productionService}`,
    observedGeneration: "9",
    terminalCondition: { state: "CONDITION_SUCCEEDED", type: "Ready" },
    template: { containers: [{}], revision },
    traffic: [{ percent: 100, type: "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST" }],
    trafficStatuses: [{ percent: 100, type: "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST" }],
  };
}

function outputPath(): string | undefined {
  const index = args.indexOf("--output");
  if (index >= 0) return args[index + 1];
  return args.find((argument) => argument.startsWith("--output="))?.slice(9);
}

function writeOutput(value: unknown): void {
  const destination = outputPath();
  if (!destination) throw new Error(`mock curl missing --output: ${args.join(" ")}`);
  if (destination === "/dev/null") return;
  writeFileSync(destination, typeof value === "string" ? value : JSON.stringify(value));
}

if (command === "gcloud") {
  const state = readState();
  const gcloudArgs = args[0]?.startsWith("--access-token-file=") ? args.slice(1) : args;
  if (gcloudArgs[0] === "auth" && gcloudArgs[1] === "print-access-token") {
    process.stdout.write("mock-access-token\n");
  } else if (gcloudArgs[0] === "run" && gcloudArgs[1] === "services" && gcloudArgs[2] === "describe") {
    const service = gcloudArgs[3];
    if (service === state.previewService && state.initialReadFailure) {
      process.stderr.write("mock transient preview read failure\n");
      process.exit(17);
    }
    process.stdout.write(JSON.stringify(
      service === state.productionService ? productionServiceV1(state) : previewServiceV1(state),
    ));
  } else if (gcloudArgs[0] === "run" && gcloudArgs[1] === "revisions" && gcloudArgs[2] === "describe") {
    const revision = gcloudArgs[3]!;
    const fixture = revision === (state.productionRevision.v1 as any).metadata.name
      ? state.productionRevision
      : state.revisions[revision];
    if (!fixture) process.exit(4);
    process.stdout.write(JSON.stringify(fixture.v1));
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
  const query = new URL(url).searchParams;
  if (method !== "PATCH" || query.get("ifGenerationMatch") !== state.transitionGeneration ||
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
  writeOutput({
    bindings: state.iamBindings,
    etag: `\"iam-etag-${state.iamEtag}\"`,
    version: 3,
  });
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
  if (state.iamSetTransportLoss) {
    state.iamSetTransportLoss = false;
    writeState(state);
    log("iam-policy-sanitize-response-lost");
    process.exit(18);
  }
  writeState(state);
  log("iam-policy-sanitize");
  writeOutput({ bindings: state.iamBindings, etag: `\"iam-etag-${state.iamEtag}\"`, version: 3 });
  process.stdout.write("200");
  process.exit(0);
}

if (url.includes("run.googleapis.com/v2/") && url.includes("/operations/")) {
  writeOutput({
    done: true,
    response: { name: previewServiceV2(state).name },
  });
  process.exit(0);
}

if (url.includes("run.googleapis.com/v2/projects/") && url.includes("/revisions/")) {
  const revision = url.split("/").at(-1)!;
  const fixture = revision === (state.productionRevision.v1 as any).metadata.name
    ? state.productionRevision
    : state.revisions[revision];
  if (!fixture) process.exit(22);
  writeOutput(fixture.v2);
  process.exit(0);
}

if (url.includes("run.googleapis.com/v2/projects/") && method === "PATCH") {
  const dataArgument = args[args.indexOf("--data-binary") + 1]!;
  const body = JSON.parse(readFileSync(dataArgument.slice(1), "utf8")) as {
    etag: string;
    ingress?: string;
    invokerIamDisabled?: boolean;
    labels?: Record<string, string>;
    traffic?: TrafficTarget[];
  };
  const updateMask = new URL(url).searchParams.get("updateMask") ?? "";
  state.patchAttemptCount = (state.patchAttemptCount ?? 0) + 1;
  log(`patch-attempt mask=${updateMask} etag=${JSON.stringify(body.etag)}`);
  if (body.etag !== etag(state)) {
    log("patch-stale-etag");
    process.exit(22);
  }
  if (state.patchConflict) {
    log("patch-conflict");
    process.stdout.write("409");
    process.exit(0);
  }
  if ((state.patchConflictsRemaining ?? 0) > 0) {
    state.patchConflictsRemaining = (state.patchConflictsRemaining ?? 0) - 1;
    state.etag += 1;
    state.generation += 1;
    writeState(state);
    log("patch-conflict-once");
    writeOutput({ error: { code: 409 } });
    process.stdout.write("409");
    process.exit(0);
  }
  if (state.patchTransportLoss || state.patchTransportLossOnAttempt === state.patchAttemptCount) {
    state.patchTransportLoss = false;
    state.pendingPatch = { body, updateMask };
    state.pendingReads = 2;
    writeState(state);
    log("patch-transport-loss");
    process.exit(18);
  }
  if (body.traffic) state.traffic = body.traffic;
  if (body.labels) state.labels = body.labels;
  if (updateMask.includes("ingress")) {
    state.exposure = body.invokerIamDisabled === true ? "open" : "sealed";
  }
  if (state.patchDoesNotAdvanceEtagOnAttempt !== state.patchAttemptCount) {
    state.etag += 1;
    state.generation += 1;
  }
  state.operation += 1;
  writeState(state);
  log(
    `patch-commit mask=${updateMask} exposure=${state.exposure} tags=${state.traffic
      .map((target) => target.tag ?? "baseline")
      .join(",")}`,
  );
  writeOutput({
    name:
      `projects/${state.projectId}/locations/${state.region}/operations/op-${state.operation}`,
  });
  if (args.includes("--write-out")) process.stdout.write("200");
  process.exit(0);
}

if (url.includes("run.googleapis.com/v2/projects/")) {
  const production = url.endsWith(`/services/${state.productionService}`);
  if (!production && state.previewServiceAbsent) {
    writeOutput({ error: { code: 404 } });
    if (args.includes("--write-out")) {
      process.stdout.write("404");
      process.exit(0);
    }
    process.exit(22);
  }
  if (production) {
    state.productionReadCount = (state.productionReadCount ?? 0) + 1;
    if (state.productionFlipAfterServiceRead === state.productionReadCount) {
      const replacement = "4".repeat(40);
      (state.productionRevision.v1 as any).metadata.labels["git-head-sha"] = replacement;
      (state.productionRevision.v2 as any).labels["git-head-sha"] = replacement;
      log("production-same-dhi-app-flip");
    }
    writeState(state);
  }
  if (!production && state.pendingPatch) {
    if ((state.pendingReads ?? 0) > 0) {
      state.pendingReads = (state.pendingReads ?? 0) - 1;
    } else {
      applyPendingPatch(state);
    }
    writeState(state);
  }
  writeOutput(production ? productionServiceV2(state) : previewServiceV2(state));
  if (args.includes("--write-out")) process.stdout.write("200");
  process.exit(0);
}

if (!args.includes("--write-out")) {
  throw new Error(`unexpected external curl: ${args.join(" ")}`);
}

const destination = outputPath();
const tag = url.match(/https:\/\/(pr-[1-9][0-9]*)---/)?.[1];
const target = state.traffic.find((entry) => entry.tag === tag);
if (url.endsWith("/livez") && tag && target && state.exposure === "open") {
  const revision = state.revisions[target.revision];
  const nonce = (revision?.v1 as any)?.spec?.containers?.[0]?.env?.find(
    (entry: { name: string }) => entry.name === "PLATFORM_DEPLOY_NONCE",
  )?.value;
  if (destination && destination !== "/dev/null") {
    writeFileSync(destination, JSON.stringify({ deployment: nonce, ok: true }));
  }
  process.stdout.write("200");
  log(`health-${tag}`);
} else if (url.endsWith("/livez") && tag) {
  if (destination && destination !== "/dev/null") writeFileSync(destination, "");
  process.stdout.write("404");
  log(`removed-${tag}`);
} else {
  if (destination && destination !== "/dev/null") writeFileSync(destination, "");
  process.stdout.write(state.exposure === "open" ? "404" : "403");
  log("baseline-probe");
}
