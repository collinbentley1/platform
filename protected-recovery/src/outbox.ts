import { type Entry, canonicalJson, isRecord, sha256Hex } from "./model";

// Outbox projection: committed Firestore state is written to its deterministic
// GCS name with ifGenerationMatch=0. An object that already exists is accepted
// only when its bytes and hash match exactly; anything else is a divergence.

export type PutOutcome =
  | { readonly kind: "created"; readonly generation: string }
  | { readonly kind: "exists" }
  | { readonly kind: "lost"; readonly reason: string };

export type GetOutcome =
  | { readonly kind: "found"; readonly bytes: Uint8Array; readonly generation: string }
  | { readonly kind: "missing" }
  | { readonly kind: "unavailable"; readonly reason: string };

export interface EvidenceStore {
  create(name: string, bytes: Uint8Array): Promise<PutOutcome>;
  read(name: string): Promise<GetOutcome>;
}

export type ProjectOutcome =
  | { readonly kind: "projected"; readonly generation: string; readonly sha256: string }
  | { readonly kind: "pending"; readonly reason: string }
  | { readonly kind: "diverged"; readonly reason: string };

export async function project(store: EvidenceStore, name: string, bytes: Uint8Array): Promise<ProjectOutcome> {
  const sha256 = sha256Hex(bytes);
  const put = await store.create(name, bytes);
  if (put.kind === "created") return { kind: "projected", generation: put.generation, sha256 };
  // The object exists (412) or the answer was lost: the object itself decides.
  const existing = await store.read(name);
  if (existing.kind === "unavailable") return { kind: "pending", reason: `${put.kind}; ${existing.reason}` };
  if (existing.kind === "missing") {
    return put.kind === "exists"
      ? { kind: "pending", reason: "the object was reported existing and is now missing" }
      : { kind: "pending", reason: `${put.reason}; the object does not exist` };
  }
  if (existing.bytes.byteLength === bytes.byteLength && Buffer.compare(existing.bytes, bytes) === 0 && sha256Hex(existing.bytes) === sha256) {
    return { kind: "projected", generation: existing.generation, sha256 };
  }
  return { kind: "diverged", reason: `${name} exists with different bytes` };
}

// The evidence bytes of one committed entry: its body and, for an effect, the
// complete acknowledged outcome, and nothing that changes after it.
export function entryEvidence(shard: string, entry: Entry): Uint8Array {
  if (entry.progress !== null && entry.progress.state !== "ACKED") throw new Error(`Entry ${entry.sequence} is ${entry.progress.state}, not acknowledged.`);
  return new TextEncoder().encode(`${canonicalJson({
    acceptedAt: entry.acceptedAt,
    body: entry.body,
    bodyHash: entry.bodyHash,
    key: entry.key,
    progress: entry.progress,
    sequence: entry.sequence,
    shard,
  })}\n`);
}

export interface GoogleEvidenceDependencies {
  readonly baseUrl?: string;
  readonly bucket: string;
  readonly fetch: typeof fetch;
  readonly token: () => Promise<string>;
}

const maxObjectBytes = 1024 * 1024;

export class GoogleEvidenceStore implements EvidenceStore {
  readonly #deps: GoogleEvidenceDependencies;
  readonly #baseUrl: string;

  constructor(deps: GoogleEvidenceDependencies) {
    this.#deps = deps;
    this.#baseUrl = deps.baseUrl ?? "https://storage.googleapis.com";
  }

  async create(name: string, bytes: Uint8Array): Promise<PutOutcome> {
    const url = `${this.#baseUrl}/upload/storage/v1/b/${encodeURIComponent(this.#deps.bucket)}/o?uploadType=media&name=${encodeURIComponent(name)}&ifGenerationMatch=0`;
    let response: Response;
    try {
      response = await this.#deps.fetch(url, {
        body: bytes,
        headers: { Authorization: `Bearer ${await this.#deps.token()}`, "Content-Type": "application/json" },
        method: "POST",
        redirect: "error",
      });
    } catch (error) {
      return { kind: "lost", reason: String(error) };
    }
    // A body that stalls after the headers arrived is aborted by the bounded
    // fetch; that abort is a lost answer of this call, never an error that
    // escapes the caller's classification.
    let text: string;
    try {
      text = await response.text();
    } catch (error) {
      return { kind: "lost", reason: `upload response body lost: ${String(error)}` };
    }
    if (response.status === 412) return { kind: "exists" };
    if (!response.ok) return { kind: "lost", reason: `HTTP ${response.status}` };
    let body: unknown;
    try {
      body = JSON.parse(text) as unknown;
    } catch {
      return { kind: "lost", reason: "upload response is not JSON" };
    }
    if (!isRecord(body) || typeof body.generation !== "string" || !/^[1-9][0-9]*$/.test(body.generation)) {
      return { kind: "lost", reason: "upload response carries no generation" };
    }
    return { kind: "created", generation: body.generation };
  }

  async read(name: string): Promise<GetOutcome> {
    const object = `${this.#baseUrl}/storage/v1/b/${encodeURIComponent(this.#deps.bucket)}/o/${encodeURIComponent(name)}`;
    const metadata = await this.#get(object);
    if (metadata.kind !== "ok") return metadata;
    let generation: string;
    try {
      const parsed = JSON.parse(new TextDecoder().decode(metadata.bytes)) as unknown;
      if (!isRecord(parsed) || typeof parsed.generation !== "string" || !/^[1-9][0-9]*$/.test(parsed.generation)) throw new Error("no generation");
      generation = parsed.generation;
    } catch {
      return { kind: "unavailable", reason: "object metadata carries no generation" };
    }
    const media = await this.#get(`${object}?alt=media&generation=${generation}`);
    if (media.kind !== "ok") return media;
    return { kind: "found", bytes: media.bytes, generation };
  }

  async #get(url: string): Promise<{ readonly kind: "ok"; readonly bytes: Uint8Array } | { readonly kind: "missing" } | { readonly kind: "unavailable"; readonly reason: string }> {
    let response: Response;
    try {
      response = await this.#deps.fetch(url, {
        headers: { Authorization: `Bearer ${await this.#deps.token()}` },
        method: "GET",
        redirect: "error",
      });
    } catch (error) {
      return { kind: "unavailable", reason: String(error) };
    }
    let bytes: Uint8Array;
    try {
      bytes = new Uint8Array(await response.arrayBuffer());
    } catch (error) {
      return { kind: "unavailable", reason: `object body lost: ${String(error)}` };
    }
    if (response.status === 404) return { kind: "missing" };
    if (!response.ok) return { kind: "unavailable", reason: `HTTP ${response.status}` };
    if (bytes.byteLength > maxObjectBytes) return { kind: "unavailable", reason: "object exceeded its size bound" };
    return { kind: "ok", bytes };
  }
}
