import { lstat, readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";

type Descriptor = { mediaType: string; digest: string; size: number };
type Index = { schemaVersion: number; manifests: Descriptor[] };
type Manifest = { schemaVersion: number; config: Descriptor; layers: Descriptor[] };
export type ImageEvidence = { schemaVersion: 1; digest: string; runnableDigest: string; sourceSha: string; platformSha: string };
const hash = (value: Uint8Array) => `sha256:${createHash("sha256").update(value).digest("hex")}`;
const imageTypes = new Set(["application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"]);
const indexTypes = new Set(["application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"]);

export async function verifyImage(directory: string, sourceSha: string, platformSha: string, architecture = "amd64"): Promise<ImageEvidence> {
  if (![sourceSha, platformSha].every(value => /^[a-f0-9]{40}$/.test(value))) throw new Error("Invalid source identity.");
  if (!(await lstat(directory)).isDirectory() || (await lstat(directory)).isSymbolicLink()) throw new Error("Invalid OCI directory.");
  const rootNames = (await readdir(directory)).sort();
  if (rootNames.join(",") !== "blobs,index.json,oci-layout") throw new Error("Unexpected OCI files.");
  const regular = async (path: string, limit: number): Promise<Buffer> => {
    const metadata = await lstat(path);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > limit) throw new Error("Invalid OCI regular file.");
    return readFile(path);
  };
  const parse = (bytes: Uint8Array): any => {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const value = JSON.parse(text); let count = 0;
    const visit = (node: unknown, depth = 0): void => { if (depth > 32 || ++count > 100_000) throw new Error("OCI metadata exceeds bounds."); if (node && typeof node === "object") for (const item of Object.values(node)) visit(item, depth + 1); };
    visit(value); return value;
  };
  if (parse(await regular(join(directory, "oci-layout"), 4096)).imageLayoutVersion !== "1.0.0") throw new Error("Invalid OCI layout.");
  const index = parse(await regular(join(directory, "index.json"), 1_048_576)) as Index;
  if (index.schemaVersion !== 2 || !Array.isArray(index.manifests) || index.manifests.length !== 1) throw new Error("Expected one published OCI image.");
  const blobs = join(directory, "blobs"); const algorithm = join(blobs, "sha256");
  for (const path of [blobs, algorithm]) if (!(await lstat(path)).isDirectory() || (await lstat(path)).isSymbolicLink()) throw new Error("Invalid OCI blob directory.");
  if ((await readdir(blobs)).join(",") !== "sha256") throw new Error("Invalid OCI digest algorithm.");
  const names = await readdir(algorithm); if (names.length > 512) throw new Error("OCI graph exceeds its blob bound.");
  const closure = new Set<string>(); let total = 0;
  const readBlob = async (descriptor: Descriptor, metadata = false): Promise<Buffer> => {
    if (!descriptor || !/^sha256:[a-f0-9]{64}$/.test(descriptor.digest) || !Number.isSafeInteger(descriptor.size) || descriptor.size < 1 || descriptor.size > 536_870_912) throw new Error("Invalid OCI descriptor.");
    const bytes = await regular(join(algorithm, descriptor.digest.slice(7)), metadata ? 4_194_304 : 536_870_912);
    if (bytes.length !== descriptor.size || hash(bytes) !== descriptor.digest) throw new Error("OCI content digest differs.");
    if (!closure.has(descriptor.digest)) { total += bytes.length; closure.add(descriptor.digest); }
    if (total > 1_610_612_736) throw new Error("OCI image exceeds its byte bound.");
    return bytes;
  };
  const published = index.manifests[0]!; let runnable = published;
  if (indexTypes.has(published.mediaType)) {
    const nested = parse(await readBlob(published, true)) as Index;
    if (nested.schemaVersion !== 2 || !Array.isArray(nested.manifests) || nested.manifests.length !== 1) throw new Error("Expected exactly one runnable platform.");
    runnable = nested.manifests[0]!;
  }
  if (!imageTypes.has(runnable.mediaType)) throw new Error("Unsupported runnable image.");
  const manifest = parse(await readBlob(runnable, true)) as Manifest;
  if (manifest.schemaVersion !== 2 || !Array.isArray(manifest.layers) || manifest.layers.length > 256) throw new Error("Invalid OCI manifest.");
  const config = parse(await readBlob(manifest.config, true));
  if (config.os !== "linux" || config.architecture !== architecture || config.config?.User !== "1000:1000") throw new Error("Runtime architecture or non-root identity differs.");
  if (config.config?.Labels?.["org.opencontainers.image.revision"] !== sourceSha || config.config?.Labels?.["io.collinbentley.platform.revision"] !== platformSha) throw new Error("Runtime source labels differ.");
  for (const layer of manifest.layers) {
    if (!["application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+zstd", "application/vnd.docker.image.rootfs.diff.tar.gzip"].includes(layer.mediaType)) throw new Error("Unsupported OCI layer type.");
    // Hash compressed layers as opaque bytes. A credentialed runner never extracts app files.
    await readBlob(layer);
  }
  if (names.some(name => !/^[a-f0-9]{64}$/.test(name) || !closure.has(`sha256:${name}`)) || names.length !== closure.size) throw new Error("OCI graph contains unreferenced content.");
  return { schemaVersion: 1, digest: published.digest, runnableDigest: runnable.digest, sourceSha, platformSha };
}
