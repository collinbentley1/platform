import { appendFileSync, readFileSync, writeFileSync } from "node:fs";

const args = process.argv.slice(2);
const output = valueAfter("--output");
if (!output) process.exit(64);
const url = args.at(-1) ?? "";
appendFileSync(process.env.MOCK_LOG!, `${url}\n`);

if (/\/v1\/projects\/[^:]+$/.test(url)) {
  const project = /projects\/([^/]+)$/.exec(url)?.[1] ?? "unknown";
  const counts = JSON.parse(readFileSync(process.env.MOCK_COUNTS!, "utf8"));
  const key = `project-${project}`;
  counts[key] = (counts[key] ?? 0) + 1;
  writeFileSync(process.env.MOCK_COUNTS!, JSON.stringify(counts));
  const projectNumber = {
    cdbentley: "882468538648",
    runsetta: "601124730704",
    "medlock-1025243085": "229383559510",
    "critical-history-16823277": "422714632513",
  }[project] ?? "1";
  const response: any = { lifecycleState: "ACTIVE", projectId: project, projectNumber };
  if (process.env.MOCK_MODE === "parent") {
    response.parent = { id: "123456789", type: "organization" };
  }
  if (process.env.MOCK_MODE === "project-drift" && counts[key] > 1) {
    response.lifecycleState = "DELETE_REQUESTED";
  }
  writeFileSync(output, JSON.stringify(response));
  process.exit(0);
}

if (url.includes(":getIamPolicy")) {
  const project = /projects\/([^:]+):/.exec(url)?.[1] ?? "unknown";
  const counts = JSON.parse(readFileSync(process.env.MOCK_COUNTS!, "utf8"));
  counts[project] = (counts[project] ?? 0) + 1;
  writeFileSync(process.env.MOCK_COUNTS!, JSON.stringify(counts));
  const drift = process.env.MOCK_MODE === "etag-drift" && counts[project] > 1;
  const bindings: any[] = [];
  if (process.env.MOCK_MODE === "direct-binding" && project === "runsetta") {
    bindings.push({
      members: ["serviceAccount:cloud-run-preview@cdbentley.iam.gserviceaccount.com"],
      role: "roles/viewer",
    });
  }
  if (process.env.MOCK_MODE === "broad-principal" && project === "runsetta") {
    bindings.push({ members: ["group:developers@example.com"], role: "roles/viewer" });
  }
  if (process.env.MOCK_MODE === "project-service-accounts" && project === "runsetta") {
    bindings.push({
      members: ["principalSet://cloudresourcemanager.googleapis.com/projects/601124730704/type/ServiceAccount"],
      role: "roles/viewer",
    });
  }
  writeFileSync(output, JSON.stringify({ bindings, etag: drift ? `after-${project}` : `stable-${project}`, version: 3 }));
  process.exit(0);
}

const identityArg = args.find((arg) => arg.startsWith("analysisQuery.identitySelector.identity="));
const identity = identityArg?.split("=").slice(1).join("=") ?? "";
if (args.includes("analysisQuery.options.expandGroups=true")) process.exit(65);
if (!args.includes("analysisQuery.options.outputGroupEdges=true")) process.exit(66);
const project = /projects\/([^:]+):/.exec(url)?.[1] ?? "unknown";
const mode = process.env.MOCK_MODE ?? "clean";
const main: any = {
  analysisQuery: { scope: `projects/${project}`, identitySelector: { identity } },
  analysisResults: [], fullyExplored: true, nonCriticalErrors: [],
};
const response: any = {
  mainAnalysis: main,
  serviceAccountImpersonationAnalysis: [],
  fullyExplored: true,
};
if (mode === "binding" && project === "runsetta") main.analysisResults.push({ iamBinding: { role: "roles/viewer" } });
if (mode === "group-binding" && project === "runsetta") {
  main.analysisResults.push({
    iamBinding: { members: ["group:preview-runtime@example.com"], role: "roles/viewer" },
  });
  main.identityList = {
    groupEdges: [{ group: "group:preview-runtime@example.com", members: [identity] }],
  };
}
if (mode === "partial") response.fullyExplored = false;
if (mode === "warning") main.nonCriticalErrors.push({ code: "PERMISSION_DENIED" });
if (mode === "impersonation") response.serviceAccountImpersonationAnalysis.push({ analysisResults: [{}], fullyExplored: true });
if (mode === "malformed") delete main.analysisQuery;
writeFileSync(output, JSON.stringify(response));

function valueAfter(flag: string): string | undefined {
  const index = args.indexOf(flag);
  return index < 0 ? undefined : args[index + 1];
}
