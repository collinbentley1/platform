#!/usr/bin/env bun
// Refresh the reviewed Grype vulnerability database pin.
//
// The pin lives in four coupled places and every one of them must move
// together or `bun run lint` fails in a way that reads like an unrelated
// problem:
//
//   1. tools/ci/grype-db.json                  the manifest itself
//   2. tools/lint.ts                           lint's independent assertion of
//                                              the reviewed snapshot
//   3. tools/lint.ts                           the manifest file's own sha256
//   4. tools/ci/container-artifact-contract.sh the same manifest sha256
//   5. platform-capabilities/preview-deployment-parity-v1.json
//                                              which hashes (4)'s file
//
// Items 4 and 5 both postdate the previous refresh commit (b6a68bb), which
// touched only 1 and 2. Following that commit as a template half-refreshes the
// pin and fails later in `bun test` on a capability digest, a long way from the
// actual cause. This script is the procedure.
//
// It only ever moves the pin forward to a snapshot Anchore currently publishes,
// and it refuses anything it cannot fully validate. Run it, read the diff, then
// commit -- the reviewed pin is still promoted by a human merging a PR.
import { createHash } from "node:crypto";

const LATEST = "https://grype.anchore.io/databases/v6/latest.json";
const BASE = "https://grype.anchore.io/databases/v6/";
const MANIFEST = "tools/ci/grype-db.json";
const LINT = "tools/lint.ts";
const CONTRACT = "tools/ci/container-artifact-contract.sh";
const CAPABILITY = "platform-capabilities/preview-deployment-parity-v1.json";

function fail(message: string): never {
  console.error(`refresh-grype-db: ${message}`);
  process.exit(1);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const response = await fetch(LATEST, { redirect: "error" });
if (!response.ok) fail(`${LATEST} answered HTTP ${response.status}.`);
const body = await response.text();
if (body.length > 4096) fail("latest.json is implausibly large.");

let listing: unknown;
try {
  listing = JSON.parse(body);
} catch {
  fail("latest.json is not valid JSON.");
}
if (!isRecord(listing)) fail("latest.json is not an object.");

const { built, checksum, path, schemaVersion, status } = listing;
if (status !== "active") fail(`published database status is ${String(status)}, not active.`);
if (typeof schemaVersion !== "string" || !/^v6\.\d+\.\d+$/.test(schemaVersion)) {
  fail("published schemaVersion is not a v6 release.");
}
if (typeof checksum !== "string" || !/^sha256:[0-9a-f]{64}$/.test(checksum)) {
  fail("published checksum is not a sha256 digest.");
}
if (typeof path !== "string" ||
  path !== `vulnerability-db_${schemaVersion}_${path.split("_")[2] ?? ""}_${path.split("_")[3] ?? ""}` ||
  !/^vulnerability-db_v6\.\d+\.\d+_[0-9T:Z-]+_\d+\.tar\.zst$/.test(path)) {
  fail("published path is not an exact v6 database filename.");
}
if (typeof built !== "string" || new Date(built).toISOString().replace(/\.\d{3}Z$/, "Z") !== built) {
  fail("published build timestamp is not a round-tripping ISO-8601 instant.");
}

const builtAtMs = Date.parse(built);
if (builtAtMs > Date.now() + 60 * 60 * 1000) fail("published database is built in the future.");

const current = JSON.parse(await Bun.file(MANIFEST).text()) as Record<string, string>;
if (Date.parse(current.built!) > builtAtMs) {
  fail("published database is older than the pinned one; refusing to move the pin backwards.");
}
const snapshotMoved = current.built !== built;
if (snapshotMoved && schemaVersion !== current.schemaVersion) {
  fail(
    `schema moved ${current.schemaVersion} -> ${schemaVersion}; the scanner contract pins the ` +
      "schema, so this needs a human, not a refresh.",
  );
}

const sha = checksum.slice("sha256:".length);
const oldManifestText = await Bun.file(MANIFEST).text();
const oldManifestSha = createHash("sha256").update(oldManifestText).digest("hex");
const oldPath = current.url!.slice(BASE.length).split("?")[0]!;

if (snapshotMoved) {
  const url = `${BASE}${path}?checksum=sha256%3A${sha}`;
  const head = await fetch(url, { method: "HEAD", redirect: "error" });
  if (!head.ok) fail(`published database URL answered HTTP ${head.status}.`);
  const manifestText = oldManifestText
    .replace(current.built!, built)
    .replace(oldPath, path)
    .replaceAll(current.sha256!, sha);
  await Bun.write(MANIFEST, manifestText);
  let lintText = await Bun.file(LINT).text();
  const replacements = [
    [oldPath, path],
    [current.sha256!, sha],
    [current.built!, built],
  ] as const;
  for (const [from, to] of replacements) {
    if (!lintText.includes(from)) fail(`${LINT} does not contain the expected value ${from}.`);
    lintText = lintText.replaceAll(from, to);
  }
  await Bun.write(LINT, lintText);
}

// Derived digests are reconciled unconditionally, so a half-applied refresh is
// repaired rather than reported as already current.
const manifestSha = createHash("sha256")
  .update(await Bun.file(MANIFEST).text())
  .digest("hex");
for (const file of [LINT, CONTRACT] as const) {
  const text = await Bun.file(file).text();
  if (text.includes(manifestSha)) continue;
  if (!text.includes(oldManifestSha)) {
    fail(`${file} pins neither the current nor the previous manifest digest.`);
  }
  await Bun.write(file, text.replaceAll(oldManifestSha, manifestSha));
}

// The capability manifest hashes the contract script, so it moves with it.
const capabilityText = await Bun.file(CAPABILITY).text();
const capability = JSON.parse(capabilityText) as {
  requiredFiles: Record<string, string>;
};
const oldContractDigest = capability.requiredFiles[CONTRACT];
if (typeof oldContractDigest !== "string") {
  fail(`${CAPABILITY} does not pin ${CONTRACT}.`);
}
const newContractDigest = "sha256:" +
  createHash("sha256").update(new Uint8Array(await Bun.file(CONTRACT).arrayBuffer())).digest("hex");
if (!capabilityText.includes(oldContractDigest)) {
  fail(`${CAPABILITY} does not contain the expected digest ${oldContractDigest}.`);
}
await Bun.write(CAPABILITY, capabilityText.replace(oldContractDigest, newContractDigest));

console.log(
  snapshotMoved ? `refreshed ${current.built} -> ${built}` : `snapshot already current: ${built}`,
);
console.log(`  database sha256 ${sha}`);
console.log(`  manifest sha256 ${manifestSha}`);
console.log(`  capability pin  ${newContractDigest}`);
