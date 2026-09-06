import { randomUUID } from "node:crypto";
import { chmod, lstat, mkdtemp, readFile, realpath, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { brokerAttachment, consumerAttachment, denyPoliciesUrl, livePolicyFromJson, organizationAttachment } from "../../protected-recovery/src/deny";
import { type RecoveryAuthority, type ProtectedApplyLease, canonicalJson, isRecord, loadRecoveryAuthority, sha256Hex } from "../../protected-recovery/src/model";
import { manifestPath } from "./workflow-authority";

export type ApplyLease = ProtectedApplyLease;

export interface ApplyDependencies {
  readonly acquire: (key: string, planSha256: string) => Promise<ApplyLease>;
  readonly read: () => Promise<ApplyLease | null>;
  readonly release: (lease: ApplyLease) => Promise<void>;
  readonly snapshot: () => Promise<string>;
  readonly apply: (lease: ApplyLease) => Promise<void>;
}

export function requireLease(actual: ApplyLease | null, expected: ApplyLease): void {
  if (actual === null || canonicalJson(actual) !== canonicalJson(expected)) throw new Error("The protected apply no longer owns its exact durable lease");
}

export async function applyUnderLease(deps: ApplyDependencies, key: string, planSha256: string, owner: string): Promise<{ lease: ApplyLease; snapshotSha256: string }> {
  const lease = await deps.acquire(key, planSha256);
  if (lease.key !== key || lease.planSha256 !== planSha256 || lease.openedBy !== owner) throw new Error("The acquired lease does not bind this controller and saved plan");
  const before = await deps.snapshot();
  requireLease(await deps.read(), lease);
  await deps.apply(lease);
  requireLease(await deps.read(), lease);
  const after = await deps.snapshot();
  if (after !== before) throw new Error("Deny, ancestry, applying identity, or target identity changed during the protected apply; its lease remains held");
  requireLease(await deps.read(), lease);
  await deps.release(lease);
  return { lease, snapshotSha256: sha256Hex(after) };
}

type Fetcher = (url: string, options: RequestInit) => Promise<Response>;

async function json(fetcher: Fetcher, url: string, token: string, body?: unknown): Promise<unknown> {
  const response = await fetcher(url, {
    method: body === undefined ? "GET" : "POST",
    headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    redirect: "error",
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok || response.body === null) throw new Error(`Protected apply read or lease request failed with HTTP ${response.status}`);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > 4 * 1024 * 1024) throw new Error("Protected apply response exceeds 4 MiB");
      chunks.push(next.value);
    }
  } finally {
    await reader.cancel();
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

export function parseLease(value: unknown): ApplyLease | null {
  if (!isRecord(value) || !("lease" in value)) throw new Error("Missing protected apply lease response");
  const lease = value.lease;
  if (lease === null) return null;
  if (!isRecord(lease) || typeof lease.key !== "string" || !/^apply-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(lease.key) || typeof lease.planSha256 !== "string" || !/^[0-9a-f]{64}$/.test(lease.planSha256) || typeof lease.openedAt !== "string" || !Number.isFinite(Date.parse(lease.openedAt)) || typeof lease.openedBy !== "string") throw new Error("Malformed protected apply lease");
  return { key: lease.key, planSha256: lease.planSha256, openedAt: lease.openedAt, openedBy: lease.openedBy };
}

function brokerUrl(authority: RecoveryAuthority): string {
  if (authority.broker.projectId === null || authority.broker.projectNumber === null || authority.organizationId === null || authority.bootstrapPrincipal === null) throw new Error("Protected recovery activation coordinates are incomplete");
  return `https://${authority.broker.serviceName}-${authority.broker.projectNumber}.${authority.broker.region}.run.app`;
}

async function privateFile(path: string, maximumBytes: number): Promise<Buffer> {
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o077) !== 0 || info.uid !== process.getuid?.() || info.size > maximumBytes) throw new Error("Protected apply context and token files must be bounded owner-only regular files");
  const bytes = await readFile(path);
  if (bytes.byteLength > maximumBytes) throw new Error("Protected apply file exceeds its bound");
  return bytes;
}

function leaseClient(url: string, tokenFile: string) {
  const request = async (body?: unknown) => {
    const token = (await privateFile(tokenFile, 16 * 1024)).toString("utf8").trim();
    if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) throw new Error("Controller token file must contain one ID token");
    return parseLease(await json(fetch, `${url}/v1/protected-apply`, token, body));
  };
  return {
    read: () => request(),
    acquire: async (key: string, planSha256: string) => {
      const lease = await request({ action: "acquire", key, planSha256 });
      if (lease === null) throw new Error("Broker did not acquire a protected apply lease");
      return lease;
    },
    release: async (lease: ApplyLease) => {
      if (await request({ action: "release", key: lease.key, planSha256: lease.planSha256 }) !== null) throw new Error("Broker did not release the protected apply lease");
    },
  };
}

export async function deploymentSnapshot(authority: RecoveryAuthority, get: (url: string) => Promise<unknown>): Promise<string> {
  brokerUrl(authority);
  const identity = await get("https://openidconnect.googleapis.com/v1/userinfo");
  if (!isRecord(identity) || typeof identity.email !== "string") throw new Error("Applying identity is unreadable");
  const principal = identity.email.endsWith(".gserviceaccount.com") ? `principal://iam.googleapis.com/projects/-/serviceAccounts/${identity.email}` : `principal://goog/subject/${identity.email}`;
  if (principal !== authority.bootstrapPrincipal) throw new Error("Applying identity is not the reviewed bootstrap principal");
  const projects = [{ projectId: authority.broker.projectId, projectNumber: authority.broker.projectNumber }, ...authority.consumers];
  const ancestry = [];
  for (const project of projects) {
    const live = await get(`https://cloudresourcemanager.googleapis.com/v3/projects/${project.projectNumber}`);
    if (!isRecord(live) || live.name !== `projects/${project.projectNumber}` || live.projectId !== project.projectId || live.parent !== `organizations/${authority.organizationId}` || live.state !== "ACTIVE" || typeof live.etag !== "string" || live.etag.length === 0 || typeof live.updateTime !== "string") throw new Error(`The live ancestry of ${project.projectId} is not the reviewed active organization attachment`);
    ancestry.push({ name: live.name, projectId: live.projectId, parent: live.parent, etag: live.etag, updateTime: live.updateTime });
  }
  const policies = [];
  for (const attachment of [brokerAttachment(authority), organizationAttachment(authority), ...authority.consumers.map(consumerAttachment)]) {
    const listing = await get(denyPoliciesUrl(attachment));
    if (!isRecord(listing) || !Array.isArray(listing.policies) || listing.policies.length === 0 || listing.policies.length > 100 || listing.nextPageToken) throw new Error(`The Deny policy listing of ${attachment} is missing, paginated, or too large`);
    const prefix = `policies/${encodeURIComponent(attachment)}/denypolicies/`;
    for (const entry of listing.policies) {
      if (!isRecord(entry) || typeof entry.name !== "string" || !entry.name.startsWith(prefix) || !/^[A-Za-z0-9._-]+$/.test(entry.name.slice(prefix.length))) throw new Error("Malformed or foreign Deny policy name");
      const policy = livePolicyFromJson(attachment, await get(`https://iam.googleapis.com/v2/${entry.name}`));
      if (policy.name !== entry.name) throw new Error("Deny policy read returned a different policy");
      policies.push(policy);
    }
  }
  const targets = [];
  for (const consumer of authority.consumers) {
    for (const account of authority.targetAccounts) {
      const uniqueId = consumer.serviceAccountUniqueIds[account];
      if (uniqueId === null || uniqueId === undefined) throw new Error("Target identity is unrecorded");
      const email = `${account}@${consumer.projectId}.iam.gserviceaccount.com`;
      const live = await get(`https://iam.googleapis.com/v1/projects/${consumer.projectId}/serviceAccounts/${email}`);
      if (!isRecord(live) || live.uniqueId !== uniqueId || live.email !== email || live.disabled === true) throw new Error(`The live target ${email} differs from the reviewed identity`);
      targets.push({ email, uniqueId });
    }
  }
  policies.sort((left, right) => left.name.localeCompare(right.name));
  return canonicalJson({ ancestry, policies, principal, targets });
}

interface ApplyContext {
  readonly lease: ApplyLease;
  readonly plan: string;
  readonly tokenFile: string;
  readonly brokerUrl: string;
}

async function readContext(path: string): Promise<ApplyContext> {
  const value: unknown = JSON.parse((await privateFile(path, 64 * 1024)).toString("utf8"));
  if (!isRecord(value) || typeof value.plan !== "string" || typeof value.tokenFile !== "string" || typeof value.brokerUrl !== "string") throw new Error("Malformed protected apply context");
  const lease = parseLease({ lease: value.lease });
  if (lease === null || sha256Hex(await privateFile(value.plan, 256 * 1024 * 1024)) !== lease.planSha256) throw new Error("Protected apply saved plan differs from its lease");
  return { lease, plan: value.plan, tokenFile: value.tokenFile, brokerUrl: value.brokerUrl };
}

export async function readLeaseEvidence(authority: RecoveryAuthority, query: unknown, contextPath: string | undefined, read: (context: ApplyContext) => Promise<ApplyLease | null>): Promise<Record<string, string>> {
  const url = brokerUrl(authority);
  if (!contextPath || !isRecord(query) || query.broker_url !== url || query.project_id !== authority.broker.projectId) throw new Error("Protected authority grants require the reviewed apply wrapper context");
  const context = await readContext(contextPath);
  if (context.brokerUrl !== url || !authority.consumers.some((entry) => context.lease.openedBy === `gha-restore-${entry.repository}@${authority.broker.projectId}.iam.gserviceaccount.com`)) throw new Error("The lease names a different broker or controller");
  requireLease(await read(context), context.lease);
  return { status: "200", key: context.lease.key, plan_sha256: context.lease.planSha256, owner: context.lease.openedBy, reason: "" };
}

async function main(): Promise<void> {
  const root = resolve(import.meta.dir, "../..");
  const authority = loadRecoveryAuthority(await readFile(join(root, "protected-recovery/authority.json"), "utf8"), await readFile(join(root, manifestPath), "utf8"));
  const url = brokerUrl(authority);
  const [mode, directory, savedPlan, consumer, controllerToken] = Bun.argv.slice(2);
  if (mode === "read-lease") {
    const query: unknown = JSON.parse(await Bun.stdin.text());
    const evidence = await readLeaseEvidence(authority, query, process.env.PROTECTED_RECOVERY_APPLY_CONTEXT, (context) => leaseClient(url, context.tokenFile).read());
    console.log(JSON.stringify(evidence));
    return;
  }
  if (mode !== "apply" || !directory || !savedPlan || !consumer || !controllerToken || !authority.consumers.some((entry) => entry.repository === consumer)) throw new Error("Usage: protected-recovery-apply.ts apply <Terraform root> <saved plan> <consumer RESTORE controller> <owner-only ID-token file>");
  const work = await mkdtemp(join(tmpdir(), "protected-recovery-apply-"));
  await chmod(work, 0o700);
  const plan = join(work, "reviewed.tfplan");
  const planBytes = await privateFile(await realpath(savedPlan), 256 * 1024 * 1024);
  await writeFile(plan, planBytes, { mode: 0o600, flag: "wx" });
  const tokenFile = await realpath(controllerToken);
  const contextPath = join(work, "context.json");
  const client = leaseClient(url, tokenFile);
  const snapshot = async () => {
    const credential = Bun.spawn(["gcloud", "auth", "application-default", "print-access-token"], { stdout: "pipe", stderr: "ignore" });
    const token = (await new Response(credential.stdout).text()).trim();
    if (await credential.exited !== 0 || !token) throw new Error("Applying ADC identity is unavailable");
    return deploymentSnapshot(authority, (target) => json(fetch, target, token));
  };
  const result = await applyUnderLease({
    ...client,
    acquire: async (key, planSha256) => {
      const lease = await client.acquire(key, planSha256);
      await writeFile(contextPath, JSON.stringify({ lease, plan, tokenFile, brokerUrl: url }), { mode: 0o600, flag: "wx" });
      console.error(`Protected apply lease ${lease.key}; local context: ${contextPath}`);
      return lease;
    },
    snapshot,
    apply: async (lease) => {
      requireLease((await readContext(contextPath)).lease, lease);
      const child = Bun.spawn(["terraform", `-chdir=${await realpath(directory)}`, "apply", "-input=false", "-lock=true", plan], {
        env: { ...Bun.env, PROTECTED_RECOVERY_APPLY_CONTEXT: contextPath },
        stdin: "ignore", stdout: "inherit", stderr: "inherit",
      });
      if (await child.exited !== 0) throw new Error("Terraform apply failed; the durable protected apply lease remains held");
    },
  }, `apply-${randomUUID()}`, sha256Hex(planBytes), `gha-restore-${consumer}@${authority.broker.projectId}.iam.gserviceaccount.com`);
  await writeFile(join(work, "verified.json"), JSON.stringify(result), { mode: 0o600, flag: "wx" });
  console.log(`Protected apply and final rereads succeeded; lease released. Local evidence: ${work}`);
}

if (import.meta.main) {
  await main().catch(() => {
    // API and credential errors may carry sensitive bytes. Keep diagnostics
    // generic and leave every acquired lease held for explicit reconciliation.
    console.error("Protected apply or lease verification failed. Inspect and reconcile the broker lease before retrying; no automatic cleanup was attempted.");
    process.exitCode = 1;
  });
}
