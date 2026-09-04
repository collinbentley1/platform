import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { manifestPath } from "../../tools/ci/workflow-authority";
import { type ServiceAccountIam, GoogleServiceAccountIam, driveEffect } from "./effects";
import { type FirestoreTarget, type Rejection, Ledger, LedgerUnavailable, emailOf } from "./ledger";
import {
  type Entry,
  type ParsedRequest,
  type Purpose,
  type RecoveryAuthority,
  type Shard,
  type Target,
  RequestError,
  consumerNamed,
  consumerPool,
  intentOf,
  loadRecoveryAuthority,
  maxBodyBytes,
  parseAppendBody,
  parseCloseBody,
  parseReconcileBody,
  parseShardId,
  purposeForIdentity,
  scanReadiness,
  targetsFor,
} from "./model";
import { type EvidenceStore, GoogleEvidenceStore, entryEvidence, project } from "./outbox";

// The thin HTTP service. Identity is verified first and purpose is derived from
// it; the body is parsed once against a closed grammar; the purpose's binding
// to its consumer and effect directions is enforced; then the ledger, effects,
// and outbox modules do the work.

export interface Identity {
  readonly email: string;
}

export interface IdentityVerifier {
  verify(authorization: string | null): Promise<Identity | undefined>;
}

export interface BrokerDependencies {
  readonly authority: RecoveryAuthority;
  readonly evidence: EvidenceStore;
  readonly iam: ServiceAccountIam;
  readonly ledger: Ledger;
  readonly now: () => Date;
}

export interface BrokerResponse {
  readonly body: Record<string, unknown>;
  readonly status: number;
}

const reconcileBatch = 64;

export class Broker {
  readonly #deps: BrokerDependencies;

  constructor(deps: BrokerDependencies) {
    this.#deps = deps;
  }

  async handle(purpose: Purpose, request: ParsedRequest): Promise<BrokerResponse> {
    const { ledger } = this.#deps;
    switch (request.kind) {
      case "append": {
        if (purpose.kind !== "recovery" || purpose.consumer.repository !== request.consumer || !purpose.intents.includes(intentOf(request.body))) return forbidden();
        const targets = request.body.kind === "quarantine" ? targetsFor(this.#deps.authority, purpose.consumer) : undefined;
        const outcome = await ledger.append(request, targets);
        switch (outcome.kind) {
          case "accepted":
            return { status: 201, body: JSON.parse(outcome.result) as Record<string, unknown> };
          case "replayed":
            return { status: 200, body: JSON.parse(outcome.result) as Record<string, unknown> };
          case "conflict":
            return { status: 409, body: { error: "KEY_BODY_MISMATCH" } };
          case "rejected":
            return rejected(outcome.rejection);
        }
      }
      // eslint-disable-next-line no-fallthrough
      case "close": {
        if (purpose.kind !== "recovery") return forbidden();
        const outcome = await ledger.beginClose(request, purpose.consumer.repository);
        switch (outcome.kind) {
          case "closing":
          case "replayed":
            return { status: 200, body: JSON.parse(outcome.result) as Record<string, unknown> };
          case "conflict":
            return { status: 409, body: { error: "KEY_BODY_MISMATCH" } };
          case "rejected":
            return rejected(outcome.rejection);
        }
      }
      // eslint-disable-next-line no-fallthrough
      case "reconcile": {
        if (request.shard === null) {
          // A fleet-wide reconcile is the reconciler's alone.
          if (purpose.kind !== "reconciler") return forbidden();
          const views: Record<string, unknown>[] = [];
          for (const shard of await ledger.listReconcilable(reconcileBatch)) {
            const view = await this.reconcileShard(shard);
            if (view) views.push(view);
          }
          return { status: 200, body: { shards: views } };
        }
        const shard = await ledger.readShard(request.shard);
        if (!shard) return notFound();
        if (!allowed(purpose, shard)) return forbidden();
        const view = await this.reconcileShard(request.shard);
        return view ? { status: 200, body: { shard: view } } : notFound();
      }
      case "read": {
        const shard = await ledger.readShard(request.shard);
        if (!shard) return notFound();
        if (!allowed(purpose, shard)) return forbidden();
        const entries = await ledger.readEntries(request.shard, shard.nextSequence - 1);
        return { status: 200, body: { entries: entries.map((entry) => entryView(entry)), shard: { ...shardView(request.shard, shard), scanReady: scanReadiness(shard, entries, this.#deps.now()) } } };
      }
    }
  }

  // Drive every recorded pending step of one shard and finish the close only
  // when nothing remains. Every step is idempotent and conditional, so any
  // number of instances (or zero, followed by one) reaches the same state.
  async reconcileShard(shardId: string): Promise<Record<string, unknown> | undefined> {
    const { authority, evidence, iam, ledger } = this.#deps;
    let shard = await ledger.readShard(shardId);
    if (!shard) return undefined;
    const notes: string[] = [];
    if (shard.phase === "OPEN" || shard.phase === "CLOSING") {
      const consumer = consumerNamed(authority, shard.consumer);
      for (const initial of await ledger.readEntries(shardId, shard.nextSequence - 1)) {
        let entry = initial;
        if (entry.body.kind === "effect" && entry.progress !== null && (entry.progress.state === "RECORDED" || entry.progress.state === "PREPARED")) {
          if (!consumer) {
            notes.push(`${entry.sequence}: pending; consumer ${shard.consumer} is not declared`);
            continue;
          }
          const target: Target = { account: entry.body.account, email: emailOf(entry.body.resource), members: entry.body.members, pool: consumerPool(authority, consumer), resource: entry.body.resource };
          const driven = await driveEffect(ledger, iam, shardId, entry, target);
          entry = driven.entry;
          if (driven.kind === "pending") notes.push(`${entry.sequence}: pending; ${driven.reason}`);
          else if (driven.kind === "stale") notes.push(`${entry.sequence}: stale actuator; nothing written`);
        }
        if ((entry.progress === null || entry.progress.state === "ACKED") && entry.outbox.state === "PENDING") {
          const projected = await project(evidence, entry.objectName, entryEvidence(shardId, entry));
          if (projected.kind === "projected") await ledger.markEntryProjected(shardId, entry.sequence, projected.generation, projected.sha256);
          else if (projected.kind === "diverged") await ledger.divergeEntryOutbox(shardId, entry.sequence, projected.reason);
          else notes.push(`${entry.sequence}: outbox pending; ${projected.reason}`);
        } else if (entry.progress?.state === "DIVERGED") {
          notes.push(`${entry.sequence}: diverged; ${entry.progress.reason}`);
        }
      }
      shard = await ledger.readShard(shardId);
      if (!shard) return undefined;
      if (shard.phase === "CLOSING") {
        const finished = await ledger.finishClose(shardId);
        if (finished.kind === "finalizing") shard = finished.shard;
      }
    }
    if (shard.phase === "FINALIZING" && shard.terminal.progress.state === "PENDING") {
      const projected = await project(evidence, shard.terminal.objectName, new TextEncoder().encode(shard.terminal.receipt));
      if (projected.kind === "projected") shard = (await ledger.markTerminalProjected(shardId, projected.generation)) ?? shard;
      else if (projected.kind === "diverged") shard = (await ledger.divergeTerminal(shardId, projected.reason)) ?? shard;
      else notes.push(`terminal: outbox pending; ${projected.reason}`);
    }
    return { ...shardView(shardId, shard), notes };
  }
}

function allowed(purpose: Purpose, shard: Shard): boolean {
  return purpose.kind === "reconciler" || (purpose.consumer.repository === shard.consumer && purpose.intents.includes(shard.intent));
}

function forbidden(): BrokerResponse {
  return { status: 403, body: { error: "FORBIDDEN" } };
}

function notFound(): BrokerResponse {
  return { status: 404, body: { error: "NOT_FOUND" } };
}

function rejected(rejection: Rejection): BrokerResponse {
  if (rejection.reason === "NOT_FOUND") return notFound();
  if (rejection.reason === "SHARD_NOT_OPEN") return { status: 409, body: { error: rejection.reason, phase: rejection.phase } };
  return { status: rejection.reason === "SHARD_MISMATCH" ? 403 : 409, body: { detail: rejection.detail, error: rejection.reason } };
}

function shardView(shardId: string, shard: Shard): Record<string, unknown> {
  const terminal = shard.phase === "FINALIZING" || shard.phase === "CLOSED"
    ? { generation: shard.terminal.progress.state === "PROJECTED" ? shard.terminal.progress.generation : null, objectName: shard.terminal.objectName, sha256: shard.terminal.sha256, state: shard.terminal.progress.state }
    : null;
  return {
    closeHighWater: shard.phase === "OPEN" ? null : shard.closeHighWater,
    consumer: shard.consumer,
    intent: shard.intent,
    nextSequence: shard.nextSequence,
    pendingEffects: shard.pendingEffects,
    pendingOutbox: shard.pendingOutbox,
    phase: shard.phase,
    shard: shardId,
    source: shard.source,
    targets: shard.targets,
    terminal,
  };
}

function entryView(entry: Entry): Record<string, unknown> {
  return {
    acceptedAt: entry.acceptedAt,
    body: entry.body,
    bodyHash: entry.bodyHash,
    key: entry.key,
    objectName: entry.objectName,
    outbox: entry.outbox,
    progress: entry.progress,
    sequence: entry.sequence,
  };
}

const routes = {
  append: /^\/v1\/shards\/([^/]+)\/entries$/,
  close: /^\/v1\/shards\/([^/]+)\/close$/,
  read: /^\/v1\/shards\/([^/]+)$/,
  reconcileAll: /^\/v1\/reconcile$/,
  reconcileShard: /^\/v1\/shards\/([^/]+)\/reconcile$/,
} as const;

export interface ServiceDependencies {
  readonly authority: RecoveryAuthority;
  readonly broker: Broker;
  readonly verifier: IdentityVerifier;
}

// One request, in order: identity, purpose, grammar, permission, work.
export async function handleRequest(deps: ServiceDependencies, request: Request): Promise<Response> {
  const identity = await deps.verifier.verify(request.headers.get("authorization"));
  if (!identity) return json(401, { error: "UNAUTHENTICATED" });
  const purpose = purposeForIdentity(deps.authority, identity.email);
  if (!purpose) return json(403, { error: "FORBIDDEN" });
  let parsed: ParsedRequest;
  try {
    parsed = await parseRequest(request);
  } catch (error) {
    if (error instanceof RequestError) return json(400, { detail: error.message, error: "INVALID_REQUEST" });
    if (error instanceof BodyTooLarge) return json(413, { error: "BODY_TOO_LARGE" });
    if (error instanceof NotFound) return json(404, { error: "NOT_FOUND" });
    throw error;
  }
  try {
    const response = await deps.broker.handle(purpose, parsed);
    return json(response.status, response.body);
  } catch (error) {
    if (error instanceof LedgerUnavailable) return json(503, { error: "LEDGER_UNAVAILABLE" });
    throw error;
  }
}

class BodyTooLarge extends Error {}
class NotFound extends Error {}

async function parseRequest(request: Request): Promise<ParsedRequest> {
  const path = new URL(request.url).pathname;
  const decode = (raw: string): string => {
    try {
      return parseShardId(decodeURIComponent(raw));
    } catch {
      throw new NotFound();
    }
  };
  if (request.method === "GET") {
    const match = routes.read.exec(path);
    if (!match) throw new NotFound();
    return { kind: "read", shard: decode(match[1]!) };
  }
  if (request.method !== "POST") throw new NotFound();
  const body = await readJsonBody(request);
  let match = routes.append.exec(path);
  if (match) return parseAppendBody(decode(match[1]!), body);
  match = routes.close.exec(path);
  if (match) return parseCloseBody(decode(match[1]!), body);
  match = routes.reconcileShard.exec(path);
  if (match) return parseReconcileBody(decode(match[1]!), body);
  if (routes.reconcileAll.test(path)) return parseReconcileBody(null, body);
  throw new NotFound();
}

async function readJsonBody(request: Request): Promise<unknown> {
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (declared > maxBodyBytes) throw new BodyTooLarge();
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength > maxBodyBytes) throw new BodyTooLarge();
  if (bytes.byteLength === 0) return {};
  try {
    return JSON.parse(new TextDecoder().decode(bytes)) as unknown;
  } catch {
    throw new RequestError("body must be JSON");
  }
}

function json(status: number, body: Record<string, unknown>): Response {
  return new Response(`${JSON.stringify(body)}\n`, {
    headers: { "Cache-Control": "no-store", "Content-Type": "application/json" },
    status,
  });
}

export interface Jwk {
  readonly alg?: string;
  readonly e: string;
  readonly kid: string;
  readonly kty: string;
  readonly n: string;
  readonly use?: string;
}

export interface GoogleIdentityDependencies {
  readonly audience: string;
  readonly jwks: () => Promise<readonly Jwk[]>;
  readonly now: () => Date;
}

const issuers = ["accounts.google.com", "https://accounts.google.com"];
const clockSkewSeconds = 60;

// Cloud Run enforces roles/run.invoker at its edge, then forwards the bearer.
// The broker verifies the Google-signed ID token itself so that the purpose is
// derived from a proven service-account identity and the exact audience.
export class GoogleIdentityVerifier implements IdentityVerifier {
  readonly #deps: GoogleIdentityDependencies;

  constructor(deps: GoogleIdentityDependencies) {
    this.#deps = deps;
  }

  async verify(authorization: string | null): Promise<Identity | undefined> {
    if (authorization === null || !authorization.startsWith("Bearer ")) return undefined;
    const token = authorization.slice("Bearer ".length).trim();
    const parts = token.split(".");
    if (parts.length !== 3 || parts.some((part) => part.length === 0 || part.length > 8192)) return undefined;
    const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];
    let header: unknown;
    let payload: unknown;
    try {
      header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString("utf8")) as unknown;
      payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8")) as unknown;
    } catch {
      return undefined;
    }
    if (!isPlainObject(header) || header.alg !== "RS256" || typeof header.kid !== "string") return undefined;
    const key = (await this.#deps.jwks()).find((candidate) => candidate.kid === header.kid && candidate.kty === "RSA");
    if (!key) return undefined;
    let verified: boolean;
    try {
      const cryptoKey = await crypto.subtle.importKey("jwk", { e: key.e, kty: "RSA", n: key.n }, { hash: "SHA-256", name: "RSASSA-PKCS1-v1_5" }, false, ["verify"]);
      verified = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey, Buffer.from(encodedSignature, "base64url"), Buffer.from(`${encodedHeader}.${encodedPayload}`, "utf8"));
    } catch {
      return undefined;
    }
    if (!verified || !isPlainObject(payload)) return undefined;
    const nowSeconds = Math.floor(this.#deps.now().getTime() / 1000);
    if (typeof payload.iss !== "string" || !issuers.includes(payload.iss)) return undefined;
    if (payload.aud !== this.#deps.audience) return undefined;
    if (typeof payload.exp !== "number" || payload.exp <= nowSeconds - clockSkewSeconds) return undefined;
    if (typeof payload.iat !== "number" || payload.iat > nowSeconds + clockSkewSeconds) return undefined;
    if (payload.email_verified !== true || typeof payload.email !== "string" || !/^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/.test(payload.email)) {
      return undefined;
    }
    return { email: payload.email };
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const jwksUrl = "https://www.googleapis.com/oauth2/v3/certs";

export function googleJwks(fetcher: typeof fetch, now: () => Date): () => Promise<readonly Jwk[]> {
  let cached: { readonly keys: readonly Jwk[]; readonly until: number } | undefined;
  return async () => {
    if (cached && cached.until > now().getTime()) return cached.keys;
    const response = await fetcher(jwksUrl, { redirect: "error" });
    if (!response.ok) throw new Error(`JWKS fetch failed with HTTP ${response.status}.`);
    const body = JSON.parse(await response.text()) as unknown;
    const keys = isPlainObject(body) && Array.isArray(body.keys)
      ? body.keys.filter((key): key is Jwk => isPlainObject(key) && typeof key.kid === "string" && typeof key.n === "string" && typeof key.e === "string" && key.kty === "RSA")
      : [];
    const maxAge = /max-age=(\d+)/.exec(response.headers.get("cache-control") ?? "")?.[1];
    cached = { keys, until: now().getTime() + Math.min(Number(maxAge ?? "300"), 3600) * 1000 };
    return keys;
  };
}

// The runtime service-account token from the metadata server, cached to its
// expiry. Only the broker identity ever calls Google APIs.
export function metadataToken(fetcher: typeof fetch, now: () => Date): () => Promise<string> {
  let cached: { readonly token: string; readonly until: number } | undefined;
  return async () => {
    if (cached && cached.until > now().getTime()) return cached.token;
    const response = await fetcher("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", {
      headers: { "Metadata-Flavor": "Google" },
      redirect: "error",
    });
    if (!response.ok) throw new Error(`Metadata token request failed with HTTP ${response.status}.`);
    const body = JSON.parse(await response.text()) as unknown;
    if (!isPlainObject(body) || typeof body.access_token !== "string" || typeof body.expires_in !== "number") {
      throw new Error("Metadata token response is malformed.");
    }
    cached = { token: body.access_token, until: now().getTime() + Math.max(0, body.expires_in - 120) * 1000 };
    return cached.token;
  };
}

export interface RuntimeConfiguration {
  readonly audience: string;
  readonly evidenceBucket: string;
  readonly firestore: FirestoreTarget;
  readonly firestoreEmulator: boolean;
  readonly port: number;
}

export function configurationFromEnvironment(env: Readonly<Record<string, string | undefined>>, authority: RecoveryAuthority): RuntimeConfiguration {
  if (authority.broker.projectId === null) {
    throw new Error("protected-recovery/authority.json records no broker project; the service refuses to start.");
  }
  const required = (name: string): string => {
    const value = env[name];
    if (value === undefined || value === "") throw new Error(`${name} is required.`);
    return value;
  };
  const emulator = env.FIRESTORE_EMULATOR_HOST;
  const project = required("FIRESTORE_PROJECT_ID");
  if (emulator === undefined && project !== authority.broker.projectId) {
    throw new Error("FIRESTORE_PROJECT_ID must be the broker project recorded in the authority.");
  }
  const database = required("FIRESTORE_DATABASE_ID");
  if (database !== authority.broker.firestoreDatabase) throw new Error("FIRESTORE_DATABASE_ID must be the ledger database recorded in the authority.");
  const port = Number(env.PORT ?? "8080");
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("PORT must be a TCP port.");
  return {
    audience: required("BROKER_AUDIENCE"),
    evidenceBucket: required("EVIDENCE_BUCKET"),
    firestore: { baseUrl: emulator === undefined ? "https://firestore.googleapis.com" : `http://${emulator}`, database, project },
    firestoreEmulator: emulator !== undefined,
    port,
  };
}

if (import.meta.main) {
  const root = join(import.meta.dir, "..", "..");
  const authority = loadRecoveryAuthority(await readFile(join(root, "protected-recovery", "authority.json"), "utf8"), await readFile(join(root, manifestPath), "utf8"));
  const configuration = configurationFromEnvironment(Bun.env, authority);
  const now = (): Date => new Date();
  const token = configuration.firestoreEmulator ? async (): Promise<string> => "owner" : metadataToken(fetch, now);
  const ledger = new Ledger({ fetch, firestore: configuration.firestore, now, token });
  const broker = new Broker({
    authority,
    evidence: new GoogleEvidenceStore({ bucket: configuration.evidenceBucket, fetch, token }),
    iam: new GoogleServiceAccountIam({ fetch, token }),
    ledger,
    now,
  });
  const verifier = new GoogleIdentityVerifier({ audience: configuration.audience, jwks: googleJwks(fetch, now), now });
  const server = Bun.serve({
    fetch: (request) => handleRequest({ authority, broker, verifier }, request),
    hostname: "0.0.0.0",
    port: configuration.port,
  });
  console.log(`protected-recovery listening on ${server.port}`);
}
