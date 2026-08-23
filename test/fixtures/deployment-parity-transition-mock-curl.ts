import { appendFileSync, readFileSync, writeFileSync } from "node:fs";

type State = {
  bucket: string;
  generation: string;
  metadata: Record<string, string>;
  metageneration: string;
  mode?: "acquire-conflict" | "acquire-transport-loss" | "release-transport-loss";
  name: string;
};

const statePath = process.env.MOCK_STATE!;
const logPath = process.env.MOCK_LOG!;
const args = Bun.argv.slice(2);
const url = args.at(-1)!;
const outputIndex = args.indexOf("--output");
const output = outputIndex >= 0 ? args[outputIndex + 1] : undefined;
const requestIndex = args.indexOf("--request");
const method = requestIndex >= 0 ? args[requestIndex + 1] : "GET";

const state = JSON.parse(readFileSync(statePath, "utf8")) as State;

function emit(value: unknown, status: string): never {
  if (output) writeFileSync(output, JSON.stringify(value));
  if (args.includes("--write-out")) process.stdout.write(status);
  process.exit(0);
}

function log(line: string): void {
  appendFileSync(logPath, `${line}\n`);
}

if (method === "GET") {
  log("get");
  emit(state, "200");
}

if (method !== "PATCH") throw new Error(`unexpected method: ${method}`);
const query = new URL(url).searchParams;
const expectedGeneration = query.get("ifGenerationMatch");
const expectedMetageneration = query.get("ifMetagenerationMatch");
log(`patch generation=${expectedGeneration} metageneration=${expectedMetageneration}`);
if (expectedGeneration !== state.generation || expectedMetageneration !== state.metageneration) {
  emit({ error: { code: 412 } }, "412");
}
const dataArgument = args[args.indexOf("--data-binary") + 1]!;
const request = JSON.parse(readFileSync(dataArgument.slice(1), "utf8")) as {
  metadata: Record<string, string | null>;
};
const acquiring = request.metadata.state !== "clear";
if (acquiring && state.mode === "acquire-conflict") {
  state.metageneration = String(Number(state.metageneration) + 1);
  state.metadata = { ...state.metadata, state: "external-poison" };
  writeFileSync(statePath, JSON.stringify(state));
  emit({ error: { code: 412 } }, "412");
}
for (const [key, value] of Object.entries(request.metadata)) {
  if (value === null) delete state.metadata[key];
  else state.metadata[key] = value;
}
state.metageneration = String(Number(state.metageneration) + 1);
writeFileSync(statePath, JSON.stringify(state));
if (acquiring && state.mode === "acquire-transport-loss") {
  log("acquire-applied-response-lost");
  process.exit(18);
}
if (!acquiring && state.mode === "release-transport-loss") {
  log("release-applied-response-lost");
  process.exit(18);
}
emit(state, "200");
