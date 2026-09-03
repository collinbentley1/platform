// Which workflows can actually reach a credential, derived rather than listed.
//
// Two authorities matter and they are not the same thing. A workflow may read
// the owner's Google OAuth token, or it may mint Google credentials for itself
// through Workload Identity Federation. Everything else holds only the
// per-run GITHUB_TOKEN, which can move branches and open pull requests but
// cannot touch cloud state.
//
// The set is derived from the workflows on disk and cross-checked against the
// Terraform trust conditions, so a workflow cannot acquire either authority by
// being added somewhere the reviewer forgot to look. A file that appears in
// neither the derived set nor the declared set is a failure, not a skip --
// that is the drift this exists to catch.

export type WorkflowAuthority = "owner-credential" | "cloud-authority" | "neither";

export interface DeclaredAuthorityInventory {
  readonly cloudAuthority: readonly string[];
  readonly neither: readonly string[];
  readonly ownerCredential: readonly string[];
}

// The one hand-maintained list. Changing it is the deliberate act that lets a
// workflow gain authority; the checks below refuse any drift from it.
export const declaredWorkflowAuthority: DeclaredAuthorityInventory = {
  cloudAuthority: [
    "cleanup-preview.yml",
    "deploy-preview.yml",
    "deploy-prod.yml",
    "infrastructure.yml",
    "reconcile-previews.yml",
  ],
  neither: [
    "application.yml",
    "bun-dependency-update.yml",
    "platform.yml",
    "refresh-grype-db.yml",
    "socket-firewall.yml",
  ],
  ownerCredential: ["protected-bootstrap-implementation.yml"],
};

export const ownerTokenSecretName = "OWNER_OAUTH_ACCESS_TOKEN";
export const ownerTokenEnvironment = "protected-bootstrap-owner-token";

// Secret names a workflow may name literally. Anything else reaching the
// secrets context -- including dynamic indexing -- is treated as capable of
// reading the owner token, because it cannot be shown otherwise.
const literalSecretAllowlist = new Set([
  "CONSUMER_ACTIONS_READ_TOKEN",
  "DHI_PUBLIC_READ_TOKEN_20260822_098DCA9280B3",
  ownerTokenSecretName,
]);

// The secrets context is only reachable through an expression delimiter, so
// only `${{ ... }}` bodies are examined. A bare word "secrets" in a run script
// -- `gcloud secrets versions list` -- is shell, not a credential reference.
const expressionBody = /\$\{\{([\s\S]*?)\}\}/g;
const secretsContextToken = /(^|[^A-Za-z0-9_-])secrets(?=[^A-Za-z0-9_-]|$)/i;
const literalSecretReference = /^\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*$/;

// Signals that a step is exchanging an OIDC token for Google credentials.
// Presence without `id-token: write` is itself inconsistent and fails.
const googleCredentialSignals = [
  "sts.googleapis.com",
  "iamcredentials.googleapis.com",
  "ACTIONS_ID_TOKEN_REQUEST_",
  "create_credentials_file",
  "gcloud auth login",
  "gcloud auth activate-service-account",
  "gcloud auth print-access-token",
];

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function jobsOf(parsed: unknown): Record<string, unknown> {
  return asRecord(asRecord(parsed)?.jobs) ?? {};
}

// Every scalar in the document, so a signal cannot hide inside a run script,
// an env value, or a `with:` argument.
function scalars(value: unknown, seen: Set<object>, out: string[]): void {
  if (typeof value === "string") {
    out.push(value);
    return;
  }
  if (typeof value !== "object" || value === null) return;
  if (seen.has(value)) return;
  seen.add(value);
  for (const child of Array.isArray(value) ? value : Object.values(value)) {
    scalars(child, seen, out);
  }
}

function permissionGrantsIdToken(permissions: unknown): boolean {
  if (permissions === "write-all") return true;
  const record = asRecord(permissions);
  return record?.["id-token"] === "write";
}

function environmentNames(job: unknown): string[] {
  const environment = asRecord(job)?.environment;
  if (typeof environment === "string") return [environment];
  const named = asRecord(environment)?.name;
  return typeof named === "string" ? [named] : [];
}

function stepUses(parsed: unknown): string[] {
  const uses: string[] = [];
  for (const job of Object.values(jobsOf(parsed))) {
    const steps = asRecord(job)?.steps;
    if (!Array.isArray(steps)) continue;
    for (const step of steps) {
      const value = asRecord(step)?.uses;
      if (typeof value === "string") uses.push(value);
    }
  }
  return uses;
}

export function readsOwnerCredential(parsed: unknown, allScalars: readonly string[]): boolean {
  const document = asRecord(parsed);
  if (document === undefined) return true;

  // A `secrets:` passthrough hands the callee whatever the caller holds.
  const workflowCall = asRecord(asRecord(document.on)?.workflow_call);
  if (workflowCall !== undefined && workflowCall.secrets !== undefined) return true;
  for (const job of Object.values(jobsOf(parsed))) {
    if (asRecord(job)?.secrets !== undefined) return true;
    if (environmentNames(job).includes(ownerTokenEnvironment)) return true;
  }

  for (const scalar of allScalars) {
    for (const expression of scalar.matchAll(expressionBody)) {
      const body = expression[1] ?? "";
      if (!secretsContextToken.test(body)) continue;
      const literal = literalSecretReference.exec(body);
      // Anything but a single literal `secrets.NAME` -- indexing, toJSON, a
      // compound expression -- cannot be shown to exclude the owner token.
      if (literal === null) return true;
      const name = literal[1] ?? "";
      if (!literalSecretAllowlist.has(name)) return true;
      if (name === ownerTokenSecretName) return true;
    }
  }
  return false;
}

export function mintsCloudCredentials(parsed: unknown, allScalars: readonly string[]): boolean {
  const document = asRecord(parsed);
  if (document === undefined) return true;
  if (permissionGrantsIdToken(document.permissions)) return true;
  for (const job of Object.values(jobsOf(parsed))) {
    if (permissionGrantsIdToken(asRecord(job)?.permissions)) return true;
  }
  for (const uses of stepUses(parsed)) {
    if (uses.split("@", 1)[0]?.startsWith("google-github-actions/") === true) return true;
  }
  for (const scalar of allScalars) {
    if (googleCredentialSignals.some((signal) => scalar.includes(signal))) return true;
  }
  return false;
}

export function classifyWorkflowAuthority(source: string): WorkflowAuthority {
  let parsed: unknown;
  try {
    parsed = Bun.YAML.parse(source);
  } catch {
    // Unparseable is not benign; it is authority that cannot be bounded.
    return "owner-credential";
  }
  const allScalars: string[] = [];
  scalars(parsed, new Set<object>(), allScalars);
  if (readsOwnerCredential(parsed, allScalars)) return "owner-credential";
  if (mintsCloudCredentials(parsed, allScalars)) return "cloud-authority";
  return "neither";
}

// Workflows named by a Terraform WIF trust condition. Both the `==` form and
// the legacy `startsWith(` form are matched; zero matches fails rather than
// silently agreeing with an empty derived set.
export function trustedWorkflowsFromTerraform(terraform: string): Set<string> {
  const pattern =
    /assertion\.job_workflow_ref(?:\.startsWith\()?\s*(?:==\s*)?'collinbentley1\/platform\/\.github\/workflows\/([\w.-]+\.yml)@/g;
  const names = new Set<string>();
  for (const match of terraform.matchAll(pattern)) {
    const name = match[1];
    if (name !== undefined) names.add(name);
  }
  return names;
}

function sorted(values: Iterable<string>): string[] {
  return [...values].sort();
}

function describe(values: Iterable<string>): string {
  const list = sorted(values);
  return list.length === 0 ? "(none)" : list.join(", ");
}

export function validateWorkflowAuthorityInventory(input: {
  readonly bootstrapTerraform: string;
  readonly declared?: DeclaredAuthorityInventory;
  readonly workflows: ReadonlyMap<string, string>;
}): string[] {
  const failures: string[] = [];
  const declared = input.declared ?? declaredWorkflowAuthority;

  if (input.workflows.size === 0) {
    failures.push("workflow authority inventory found no workflows to classify.");
    return failures;
  }

  const declaredAll = [...declared.ownerCredential, ...declared.cloudAuthority, ...declared.neither];
  const declaredSet = new Set(declaredAll);
  if (declaredSet.size !== declaredAll.length) {
    failures.push("workflow authority inventory declares a workflow in more than one set.");
  }

  const derived = new Map<string, WorkflowAuthority>();
  for (const [name, source] of input.workflows) {
    derived.set(name, classifyWorkflowAuthority(source));
  }

  // Every workflow on disk must be declared, and every declared workflow must
  // exist. A new file that nobody classified is the drift case.
  for (const name of sorted(derived.keys())) {
    if (!declaredSet.has(name)) {
      failures.push(
        `.github/workflows/${name} is not declared in the workflow authority inventory; ` +
          `classify it in tools/ci/workflow-authority-contract.ts.`,
      );
    }
  }
  for (const name of sorted(declaredSet)) {
    if (!derived.has(name)) {
      failures.push(`workflow authority inventory declares ${name}, which does not exist.`);
    }
  }

  const expected = new Map<string, WorkflowAuthority>();
  for (const name of declared.ownerCredential) expected.set(name, "owner-credential");
  for (const name of declared.cloudAuthority) expected.set(name, "cloud-authority");
  for (const name of declared.neither) expected.set(name, "neither");

  for (const name of sorted(derived.keys())) {
    const actual = derived.get(name);
    const want = expected.get(name);
    if (want !== undefined && actual !== want) {
      failures.push(
        `.github/workflows/${name} is declared ${want} but its source shows ${actual}; ` +
          `the declaration and the workflow disagree.`,
      );
    }
  }

  // The owner credential and cloud authority must never meet in one workflow.
  for (const name of declared.ownerCredential) {
    if (declared.cloudAuthority.includes(name)) {
      failures.push(`${name} may not hold both the owner credential and cloud authority.`);
    }
  }

  // Terraform must trust exactly the workflows that mint cloud credentials.
  // A trust with no auth step is a stale binding; an auth step with no trust
  // is a workflow reaching for authority nobody granted.
  const trusted = trustedWorkflowsFromTerraform(input.bootstrapTerraform);
  if (trusted.size === 0) {
    failures.push(
      "no workflow trust conditions were found in the bootstrap Terraform; " +
        "the authority inventory cannot be cross-checked.",
    );
  } else {
    const cloud = new Set(declared.cloudAuthority);
    const missingTrust = sorted([...cloud].filter((name) => !trusted.has(name)));
    const staleTrust = sorted([...trusted].filter((name) => !cloud.has(name)));
    if (missingTrust.length > 0) {
      failures.push(
        `workflows mint cloud credentials without a Terraform trust condition: ${describe(missingTrust)}.`,
      );
    }
    if (staleTrust.length > 0) {
      failures.push(
        `Terraform trusts workflows that do not mint cloud credentials: ${describe(staleTrust)}.`,
      );
    }
  }

  return failures;
}
