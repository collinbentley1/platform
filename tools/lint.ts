import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import {
  validateRegistryOnlyDependencySpecs,
  validateRegistryOnlyLock,
  validateTypeScriptLock,
} from "./ci/app-contract";
import {
  type SecretContextReference,
  semanticSecretContextReferences,
} from "./ci/workflow-secret-contract";
import { validateWorkflowAuthorityInventory } from "./ci/workflow-authority-contract";

const root = join(import.meta.dir, "..");
const failures: string[] = [];
const reusableWorkflows = [
  "application.yml",
  "bun-dependency-update.yml",
  "socket-firewall.yml",
  "infrastructure.yml",
  "deploy-prod.yml",
  "deploy-preview.yml",
  "cleanup-preview.yml",
  "reconcile-previews.yml",
];
const platformWorkflows = [
  ...reusableWorkflows,
  "platform.yml",
  "protected-bootstrap-implementation.yml",
  "refresh-grype-db.yml",
];

// Derived, not listed. `platformWorkflows` above is a hand-maintained set that
// has drifted before -- refresh-grype-db.yml existed for weeks without any rule
// keyed on that list ever seeing it. Everything below enumerates the directory
// instead, so a new workflow is classified or the lint fails.
const workflowDirectory = join(root, ".github/workflows");
const derivedPlatformWorkflows = (await readdir(workflowDirectory))
  .filter((name) => name.endsWith(".yml"))
  .sort();
for (const name of derivedPlatformWorkflows) {
  if (!platformWorkflows.includes(name)) {
    failures.push(
      `.github/workflows/${name} is not covered by the platform workflow lint set.`,
    );
  }
}
const workflowSources = new Map<string, string>();
for (const name of derivedPlatformWorkflows) {
  workflowSources.set(name, await readFile(join(workflowDirectory, name), "utf8"));
}
failures.push(
  ...validateWorkflowAuthorityInventory({
    bootstrapTerraform: await readFile(join(root, "terraform/modules/bootstrap/main.tf"), "utf8"),
    workflows: workflowSources,
  }),
);
const declaredEnvironmentSecrets = [
  "DHI_PUBLIC_READ_TOKEN_20260822_098DCA9280B3",
];
const expectedPreviewSecretContextReferences: SecretContextReference[] = [
  {
    job: "prefetch-bases",
    path: "jobs.prefetch-bases.steps.2.env.DHI_PUBLIC_READ_TOKEN",
    value: "${{ secrets.DHI_PUBLIC_READ_TOKEN_20260822_098DCA9280B3 }}",
  },
];
const expectedProductionSecretContextReferences: SecretContextReference[] =
  expectedPreviewSecretContextReferences;
const requiredCheckEventGuard = `set -euo pipefail
if [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then
  jq -e '
    if .action == "edited" then
      (.changes | type == "object") and
      ((.changes | keys) == ["body"]) and
      (.changes.body | type == "object") and
      ((.changes.body | keys) == ["from"]) and
      ((.changes.body.from | type) == "string" or .changes.body.from == null)
    else
      .action == "opened" or
      .action == "reopened" or
      .action == "synchronize"
    end
  ' "$GITHUB_EVENT_PATH" >/dev/null
  exit 0
fi
test "$GITHUB_EVENT_NAME" = "push"
test "$GITHUB_REF" = "refs/heads/main"
`;

for (const workflow of reusableWorkflows) {
  const path = `.github/workflows/${workflow}`;
  const text = await read(path);
  requireContains(path, text, "workflow_call:", "Reusable workflow must expose workflow_call.");
}

for (const workflow of platformWorkflows) {
  const path = `.github/workflows/${workflow}`;
  const text = await read(path);
  checkActionPins(path, text, false);
  if (/\brg\b/.test(text)) {
    failures.push(
      `${path}: Hosted-runner workflows must use baseline grep instead of assuming ambient ripgrep.`,
    );
  }
  if (/\bgrep\s+-[A-Za-z]*I/.test(text) || text.includes("--binary-files=without-match")) {
    failures.push(
      `${path}: Security searches must force binary-classified files to text instead of skipping them with grep -I.`,
    );
  }
  const allowedVariables = path.endsWith("deploy-preview.yml") || path.endsWith("deploy-prod.yml")
    ? [
        "${{ vars.DHI_USERNAME }}",
        "${{ vars.MAPBOX_PUBLIC_TOKEN }}",
      ]
    : path.endsWith("cleanup-preview.yml") || path.endsWith("reconcile-previews.yml")
    ? ["${{ vars.DHI_USERNAME }}"]
    : [];
  let unreviewedVariables = text;
  for (const variable of allowedVariables) {
    if (unreviewedVariables.split(variable).length !== 2) {
      failures.push(`${path}: ${variable} must appear exactly once in its reviewed non-secret slot.`);
    }
    unreviewedVariables = unreviewedVariables.replace(variable, "");
  }
  if (unreviewedVariables.includes("${{ vars.")) {
    failures.push(`${path}: unreviewed repository or environment variable reference.`);
  }
}

const bunDependencyUpdateWorkflow = await read(".github/workflows/bun-dependency-update.yml");
const bunResolveJob = sectionBetween(
  bunDependencyUpdateWorkflow,
  "  resolve:\n",
  "\n  verify:\n",
);
const bunVerifyJob = sectionBetween(
  bunDependencyUpdateWorkflow,
  "  verify:\n",
  "\n  propose:\n",
);
const bunProposeJob = bunDependencyUpdateWorkflow.slice(
  bunDependencyUpdateWorkflow.indexOf("\n  propose:\n"),
);
for (const [job, section] of [
  ["resolve", bunResolveJob],
  ["verify", bunVerifyJob],
] as const) {
  requireContains(
    ".github/workflows/bun-dependency-update.yml",
    section,
    "contents: read",
    `Bun ${job} job must remain read-only.`,
  );
  rejectContains(
    ".github/workflows/bun-dependency-update.yml",
    section,
    "contents: write",
    `Bun ${job} job must never receive repository write authority.`,
  );
  rejectContains(
    ".github/workflows/bun-dependency-update.yml",
    section,
    "pull-requests: write",
    `Bun ${job} job must never receive pull-request write authority.`,
  );
}
for (const boundary of [
  "needs: [resolve, verify]",
  "needs.verify.result == 'success'",
  "contents: write",
  "pull-requests: write",
  "Revalidate the artifact in the fresh privileged runner",
  'test "$digest" = "$RESOLVED_DIGEST"',
  'test "$digest" = "$VERIFIED_DIGEST"',
  'test "$current_main" = "$GITHUB_SHA"',
  "GIT_CONFIG_NOSYSTEM: \"1\"",
  "GIT_CONFIG_GLOBAL: /dev/null",
  "credential.helper=",
]) {
  requireContains(
    ".github/workflows/bun-dependency-update.yml",
    bunProposeJob,
    boundary,
    `Fresh Bun proposal boundary is missing ${boundary}.`,
  );
}
for (const boundary of [
  "--registry=https://registry.npmjs.org",
  "--ignore-scripts",
  "--validate-proposal",
  "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
  "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
  "bun-dependency-proposal-${{ github.run_id }}",
  'test "$GITHUB_RUN_ATTEMPT" = "1"',
  'test "$GITHUB_REF" = "refs/heads/main"',
  'test "$WORKFLOW_REPOSITORY" = "collinbentley1/platform"',
]) {
  requireContains(
    ".github/workflows/bun-dependency-update.yml",
    bunDependencyUpdateWorkflow,
    boundary,
    `Bun updater is missing fail-closed boundary ${boundary}.`,
  );
}
const bunDependencyUpdater = await read("tools/ci/update-bun-dependencies.ts");
for (const boundary of [
  'const OFFICIAL_REGISTRY = "https://registry.npmjs.org"',
  "const MINIMUM_RELEASE_AGE_SECONDS = 7 * 24 * 60 * 60",
  '`--minimum-release-age=${MINIMUM_RELEASE_AGE_SECONDS}`',
  '`--registry=${OFFICIAL_REGISTRY}`',
  '"--ignore-scripts"',
  '"--lockfile-only"',
  "validateBunDependencyProposal",
  'canonical(["bun.lock", "package.json"])',
  "base and proposal roots must be distinct",
  "package.json and bun.lock must move together",
  "coordinated TypeScript lock entries",
  "the updater retargeted dependency ${name}",
  "the updater did not strictly upgrade dependency ${name}",
  "Bun.semver.order",
  'stderr: "ignore"',
  'stdout: "ignore"',
]) {
  requireContains(
    "tools/ci/update-bun-dependencies.ts",
    bunDependencyUpdater,
    boundary,
    `Bun resolver is missing fail-closed boundary ${boundary}.`,
  );
}
for (const forbidden of ["registry?:", "minimumReleaseAgeSeconds?:", "bunExecutable?:"]) {
  rejectContains(
    "tools/ci/update-bun-dependencies.ts",
    bunDependencyUpdater,
    forbidden,
    `Bun resolver must not expose production-policy override ${forbidden}.`,
  );
}
if (bunDependencyUpdateWorkflow.split("contents: write").length !== 2) {
  failures.push(
    ".github/workflows/bun-dependency-update.yml: exactly one fresh job may receive contents: write.",
  );
}
for (const forbidden of [
  "--force",
  "environment:",
  "id-token: write",
  "pull_request_target:",
  "secrets.",
]) {
  rejectContains(
    ".github/workflows/bun-dependency-update.yml",
    bunDependencyUpdateWorkflow,
    forbidden,
    `Bun dependency proposals must not contain privileged escape ${forbidden}.`,
  );
}

const deployProd = await read(".github/workflows/deploy-prod.yml");
requireContains(
  ".github/workflows/deploy-prod.yml",
  deployProd,
  "if: github.event_name == 'push' && github.ref == 'refs/heads/main'",
  "Production deploys must fail closed outside a main-branch push.",
);
requireContains(
  ".github/workflows/deploy-prod.yml",
  deployProd,
  "deffdbe82ca6e3d19ffb291d063a651488e04e1b33799b5a238e4b5c6784e3c6",
  "Production deploys must verify the reviewed Cloud SDK archive.",
);

const deployPreview = await read(".github/workflows/deploy-preview.yml");
const previewTrafficTransaction = await read("tools/ci/cloud-run-preview-traffic.sh");

for (const [path, workflow] of [
  [".github/workflows/deploy-preview.yml", deployPreview],
  [".github/workflows/deploy-prod.yml", deployProd],
] as const) {
  const workflowCall = sectionBetween(workflow, "  workflow_call:\n", "\npermissions:");
  if (workflowCall.trim() !== "workflow_call:") {
    failures.push(`${path}: reusable deploy workflows must not declare caller-provided secrets or inputs.`);
  }
}

rejectContains(
  ".github/workflows/deploy-preview.yml",
  deployPreview,
  "runtime-config-script",
  "Preview workflows must not execute caller-controlled runtime scripts.",
);
rejectContains(
  ".github/workflows/deploy-preview.yml",
  sectionBetween(deployPreview, "  build:\n", "\n  canary:\n"),
  "id-token: write",
  "The untrusted preview build job must not receive an OIDC token.",
);
for (const needle of [
  "Enforce the trusted application and container contract",
  "environment: dhi-base-prefetch-20260822-098dca9280b3",
  "environment: preview-cloud",
  "environment: preview-publish",
  "environment: supply-chain",
  "48af8a397ebd60178778bf63611dbcebe5f5e7a9be90eb9147b24b9587455778",
  "image=moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8",
  "builder: ${{ steps.buildx.outputs.name }}",
  "needs.canary.result == 'success'",
  "actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d",
  "preview-env.json",
]) {
  requireContains(
    ".github/workflows/deploy-preview.yml",
    deployPreview,
    needle,
    `Preview workflow is missing required boundary: ${needle}`,
  );
}
requireContains(
  ".github/workflows/deploy-preview.yml",
  deployPreview,
  "deffdbe82ca6e3d19ffb291d063a651488e04e1b33799b5a238e4b5c6784e3c6",
  "Preview deploys must verify the reviewed Cloud SDK archive.",
);
for (const needle of [
  "github.event.pull_request.user.type == 'User'",
  "github.actor != 'dependabot[bot]'",
  '--revision-suffix="$revision_suffix"',
  "EXPECTED_HEAD_SHA",
]) {
  requireContains(
    ".github/workflows/deploy-preview.yml",
    deployPreview,
    needle,
    `Preview identity/lifecycle policy is missing: ${needle}`,
  );
}
const previewDeployJob = sectionBetween(deployPreview, "  deploy:\n", "\n  invalidate:\n");
for (const [path, workflow, expectedReferences] of [
  [
    ".github/workflows/deploy-preview.yml",
    deployPreview,
    expectedPreviewSecretContextReferences,
  ],
  [
    ".github/workflows/deploy-prod.yml",
    deployProd,
    expectedProductionSecretContextReferences,
  ],
] as const) {
  let references: SecretContextReference[];
  try {
    references = semanticSecretContextReferences(workflow);
  } catch (error) {
    failures.push(`${path}: semantic YAML inspection failed: ${String(error)}`);
    references = [];
  }
  if (JSON.stringify(references) !== JSON.stringify(expectedReferences)) {
    failures.push(`${path}: decoded secret-context references must exactly match the reviewed job paths.`);
  }
  for (const forbidden of [
    "DHI_ACCESS_TOKEN",
    "DHI_ACCESS_TOKEN_20260822",
    "SOCKET_API_TOKEN",
    "SOCKET_API_TOKEN_20260822",
    "WAITLIST_IDENTITY_KEYSET",
    "WAITLIST_IDENTITY_KEYSET_20260822",
  ]) {
    if (workflow.includes(`\${{ secrets.${forbidden} }}`)) {
      failures.push(`${path}: obsolete or replayable secret ${forbidden} is forbidden.`);
    }
  }
}
for (const needle of [
  'stable_preview_domain="preview.ycriticalhistory.org"',
  'preview_ingress="internal-and-cloud-load-balancing"',
  'echo "project_number=$project_number"',
  'deterministic_url="https://pr-${PR_NUMBER}---${PREVIEW_SERVICE}-${PROJECT_NUMBER}.${REGION}.run.app"',
  'public_preview_url="https://pr-${PR_NUMBER}.${STABLE_PREVIEW_DOMAIN}"',
  "PLATFORM_DEPLOY_NONCE: $deploy_nonce",
  'preview_nonce="$(openssl rand -hex 32)"',
  '"${public_preview_url}/livez"',
  "--max-filesize 1024",
  'jq -e -s --arg nonce "$preview_nonce"',
  "--no-traffic",
  '--command=""',
  'steps.traffic-commit.outputs.admitted == \'true\'',
]) {
  requireContains(
    ".github/workflows/deploy-preview.yml",
    previewDeployJob,
    needle,
    `Stable Critical History preview routing is missing: ${needle}`,
  );
}
rejectContains(
  ".github/workflows/deploy-preview.yml",
  previewDeployJob,
  '--tag="pr-${PR_NUMBER}"',
  "A preview candidate must remain unrouted until the etag-bound transaction proves its complete graph.",
);
requireBefore(
  "tools/ci/cloud-run-preview-traffic.sh",
  sectionBetween(
    previewTrafficTransaction,
    "# Prove the complete proposed graph",
    "trap - EXIT",
  ),
  "capture_snapshot before true",
  "patched=true",
  "The proposed route graph must be remotely proven before rollback is armed for the traffic CAS.",
);
requireContains(
  "tools/ci/cloud-run-preview-traffic.sh",
  sectionBetween(previewTrafficTransaction, "patched=true", "patched=false"),
  "capture_snapshot health-after false",
  "The exact rollback must remain armed through post-health route and lifecycle revalidation.",
);
for (const needle of [
  "capture_snapshot before true",
  "capture_snapshot after false",
  "preview-traffic-before-full.sha256",
  "preview-traffic-after-full.sha256",
  "etag:.etag",
  "commit_update_mask=traffic",
  "commit_update_mask=traffic,ingress,invokerIamDisabled",
  "rollback_update_mask=traffic,ingress,invokerIamDisabled",
  "?updateMask=${commit_update_mask}&allowMissing=false",
  "rollback_exact_traffic",
  "capture_snapshot sealed-admitted true",
  "capture_snapshot sealed-admitted-after false",
  "capture_snapshot final false",
  "length == 1 and .[0] == {deployment:$nonce,ok:true}",
  "capture_snapshot health-after false",
  '[ "$live_url" = "$PREVIEW_URL" ]',
  "patched=false",
]) {
  requireContains(
    "tools/ci/cloud-run-preview-traffic.sh",
    previewTrafficTransaction,
    needle,
    `Preview traffic transaction is missing: ${needle}`,
  );
}
requireBefore(
  "tools/ci/cloud-run-preview-traffic.sh",
  sectionBetween(
    previewTrafficTransaction,
    "# Prove the complete proposed graph",
    "trap - EXIT",
  ),
  "patched=true",
  "?updateMask=${commit_update_mask}&allowMissing=false",
  "Preview rollback must arm before the etag-bound traffic mutation.",
);
requireBefore(
  "tools/ci/cloud-run-preview-traffic.sh",
  sectionBetween(
    previewTrafficTransaction,
    "# Prove the complete proposed graph",
    "trap - EXIT",
  ),
  "capture_snapshot health-after false",
  "patched=false",
  "Preview rollback must remain armed until stable health and lifecycle are revalidated.",
);
rejectContains(
  ".github/workflows/deploy-preview.yml",
  previewDeployJob,
  "--ingress=all",
  "Preview ingress must come only from the immutable numeric-repository-ID map.",
);
rejectContains(
  ".github/workflows/deploy-preview.yml",
  previewDeployJob,
  "*.preview.ycriticalhistory.org",
  "Mapbox and workflow URL policy must use the stable parent origin, not unsupported wildcard syntax.",
);

const grypeConfig = await read("tools/ci/grype.yaml");
requireContains("tools/ci/grype.yaml", grypeConfig, "auto-update: false", "Grype must not trust a mutable database listing.");
requireContains("tools/ci/grype.yaml", grypeConfig, "max-allowed-built-age: 48h", "The reviewed vulnerability DB must expire closed.");
const grypeBlockingPolicy = await read("tools/ci/grype-blocking.jq");
requireContains(
  "$CONTRACT_ROOT/grype-blocking.jq",
  grypeBlockingPolicy,
  '.vulnerability.severity == "High"',
  "Every High vulnerability must block publication even when no upstream fix exists.",
);
rejectContains(
  "grype-blocking.jq",
  grypeBlockingPolicy,
  ".vulnerability.fix.state ==",
  "Vulnerability blocking must not depend on upstream fix availability.",
);
try {
  const manifest = JSON.parse(await read("tools/ci/grype-db.json")) as {
    built?: unknown;
    schemaVersion?: unknown;
    sha256?: unknown;
    url?: unknown;
  };
  if (
    typeof manifest.sha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(manifest.sha256) ||
    typeof manifest.url !== "string" ||
    manifest.url !==
      `https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.9_2026-09-03T00:34:04Z_1788417055.tar.zst?checksum=sha256%3A${manifest.sha256}` ||
    manifest.sha256 !== "3574269f1e15cc771bd8ea11a31f2e198c5e4cc546ae7d3187919c8f4822cb7a" ||
    manifest.schemaVersion !== "v6.1.9" ||
    manifest.built !== "2026-09-03T06:30:55Z"
  ) {
    failures.push("tools/ci/grype-db.json: vulnerability DB identity must match the reviewed checksum-qualified snapshot.");
  }
  const builtAt = typeof manifest.built === "string" ? Date.parse(manifest.built) : Number.NaN;
  const databaseAgeMs = Date.now() - builtAt;
  if (!Number.isFinite(builtAt) || databaseAgeMs < -60 * 60 * 1000 || databaseAgeMs > 48 * 60 * 60 * 1000) {
    failures.push("tools/ci/grype-db.json: reviewed vulnerability DB must be between zero and 48 hours old.");
  }
} catch {
  failures.push("tools/ci/grype-db.json: vulnerability DB manifest must be valid JSON.");
}

for (const [path, workflow] of [
  [".github/workflows/deploy-prod.yml", deployProd],
  [".github/workflows/deploy-preview.yml", deployPreview],
] as const) {
  rejectContains(
    path,
    workflow,
    "GRYPE_DB_MANIFEST_JSON",
    "The credentialless promoter must load the vulnerability DB manifest only from immutable platform policy.",
  );
  rejectContains(
    path,
    workflow,
    "DB_MANIFEST_JSON:",
    "The credentialless promoter must reject mutable manifest injection from every GitHub variable scope.",
  );
  requireContains(
    path,
    workflow,
    "bun pm scan must not mutate package.json or bun.lock.",
    "The free Socket scan must prove it is non-mutating.",
  );
  rejectContains(
    path,
    workflow,
    "SOCKET_API_TOKEN:",
    "The workflow must not receive a Socket token; the installed GitHub App owns the external gate.",
  );
  requireContains(path, workflow, "Socket Security Scanner free mode", "The local lock scan must remain credentialless.");
  requireContains(path, workflow, "github-token: \"\"", "BuildKit must not receive an implicit GitHub token.");
  requireContains(path, workflow, "archive: false", "OCI handoffs must use one raw artifact with explicit content hashing.");
  requireContains(path, workflow, "digest-mismatch: error", "Every artifact download must reject an API digest mismatch.");
  requireContains(path, workflow, "skip-decompress: true", "Raw artifact downloads must never be implicitly extracted.");
  for (const boundary of [
    "Disable workflow commands for untrusted build output",
    "Restore workflow commands after untrusted build output",
    'token_file="$RUNNER_TEMP/platform-build-command-token"',
    "cat /proc/sys/kernel/random/uuid",
    "(umask 077;",
    "::stop-commands::%s",
    "if: always()",
    'unlink "$token_file"',
    "printf '::%s::\\n'",
    'DOCKER_BUILD_RECORD_UPLOAD: "false"',
    'DOCKER_BUILD_SUMMARY: "false"',
    'DOCKER_BUILD_CHECKS_ANNOTATIONS: "false"',
  ]) {
    requireContains(
      path,
      workflow,
      boundary,
      `The untrusted container build is missing the runner-command boundary: ${boundary}`,
    );
  }
  const buildName = path.endsWith("deploy-preview.yml")
    ? "Build untrusted preview image into a local OCI archive"
    : "Build production image into a local OCI archive";
  requireBefore(
    path,
    workflow,
    "Disable workflow commands for untrusted build output",
    buildName,
    "Runner commands must be disabled before PR-controlled Docker output is relayed.",
  );
  requireBefore(
    path,
    workflow,
    buildName,
    "Restore workflow commands after untrusted build output",
    "Runner commands must remain disabled throughout the PR-controlled Docker build.",
  );
  rejectContains(
    path,
    sectionBetween(
      workflow,
      `      - name: ${buildName}\n`,
      "      - name: Restore workflow commands after untrusted build output\n",
    ),
    "platform-build-command-token",
    "The random runner-command resume token must not be passed to the container build action.",
  );
}
const artifactContract = await read("tools/ci/container-artifact-contract.sh");
for (const boundary of [
  "GRYPE_DB_MANIFEST_SHA256=cf47c247ca2b93ba67d5c47d8b8a16820d12259dbf3e686fcaa5a1f09ad2fac2",
  'test -z "${DB_MANIFEST_JSON:-}" && test -z "${GRYPE_DB_MANIFEST_JSON:-}"',
  'test -f "$GRYPE_DB_MANIFEST" && test ! -L "$GRYPE_DB_MANIFEST"',
  'verify_sha256 "$GRYPE_DB_MANIFEST_SHA256" "$GRYPE_DB_MANIFEST"',
  'db import /database/grype-db.tar.zst',
  '"$scanner_policy/grype-blocking.jq"',
  "jq -e 'length == 0'",
  "/tools/syft",
  "--config /policy/syft.yaml oci-dir:/input",
  "DHI_ATTESTATION_POLICY_IMPLEMENTED=true",
  "COSIGN_SHA256=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71",
  "sha256:58a392f5dec3be5cb20a2495baca84ac785f237a2d2904c5b9cad7ba11f3e475",
  "sha256:0f9e5f506d653e0f87e44bb5c24fece19f9fb7253016f6e49d7a4783026f876d",
]) {
  requireContains(
    "tools/ci/container-artifact-contract.sh",
    artifactContract,
    boundary,
    `The shared container artifact contract is missing ${boundary}.`,
  );
}
rejectContains(
  "tools/ci/container-artifact-contract.sh",
  artifactContract,
  "db update",
  "The credentialless promoter must not trust mutable vulnerability metadata.",
);
const syftConfig = await read("tools/ci/syft.yaml");
if (syftConfig.trim() !== "{}") {
  failures.push("tools/ci/syft.yaml: trusted Syft policy must retain complete default cataloging without caller exclusions.");
}

const deployProduction = await read(".github/workflows/deploy-prod.yml");
requireContains(
  ".github/workflows/deploy-prod.yml",
  deployProduction,
  "--clear-secrets",
  "The current immutable runtime map must authoritatively clear undeclared secret mappings.",
);
requireContains(
  ".github/workflows/deploy-prod.yml",
  deployProduction,
  '--set-secrets="WAITLIST_IDENTITY_KEYSET=waitlist-identity-keyset:${secret_version}"',
  "Medlock must bind Cloud Run to the exact Secret Manager version created by the trusted deploy.",
);
rejectContains(
  ".github/workflows/deploy-prod.yml",
  deployProduction,
  "--update-secrets",
  "Production secret mappings must replace the complete map rather than preserve undeclared entries.",
);
rejectContains(
  ".github/workflows/deploy-prod.yml",
  sectionBetween(deployProduction, "  build:\n", "\n  canary:\n"),
  "id-token: write",
  "The production image build job must not receive an OIDC token.",
);
for (const needle of [
  "Enforce the trusted application and container contract",
  "environment: dhi-base-prefetch-20260822-098dca9280b3",
  "environment: production",
  "environment: production-publish",
  "environment: supply-chain",
  "48af8a397ebd60178778bf63611dbcebe5f5e7a9be90eb9147b24b9587455778",
  "image=moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8",
  "builder: ${{ steps.buildx.outputs.name }}",
  "needs.canary.result == 'success'",
  "actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d",
  "production-env.json",
]) {
  requireContains(
    ".github/workflows/deploy-prod.yml",
    deployProduction,
    needle,
    `Production workflow is missing required boundary: ${needle}`,
  );
}
for (const needle of [
  "MAPBOX_PUBLIC_TOKEN: ${{ vars.MAPBOX_PUBLIC_TOKEN }}",
  "gcloud run services describe",
  'select(.name == "WAITLIST_IDENTITY_KEYSET")',
  "gcloud secrets versions list",
  "gcloud secrets versions add waitlist-identity-keyset",
  "--data-file=-",
  "--format='value(name)'",
  "^projects/(229383559510|medlock-1025243085)/secrets/waitlist-identity-keyset/versions/([1-9][0-9]*)$",
  'secret_args=(--set-secrets="WAITLIST_IDENTITY_KEYSET=waitlist-identity-keyset:${secret_version}")',
  'PLATFORM_DEPLOY_ENVIRONMENT: "production"',
  '[[ ! "$MAPBOX_PUBLIC_TOKEN" =~ ^pk\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$ ]]',
  ". + {MAPBOX_PUBLIC_TOKEN: $token}",
  'RUNSETTA_OFFLINE: "1"',
  'WAITLIST_BACKEND: "firestore"',
  'FIRESTORE_PROJECT_ID: "medlock-1025243085"',
  'gcloud recaptcha keys describe "$recaptcha_site_key"',
  'IDENTITY_PLATFORM_AUDIENCE: "medlock-1025243085"',
  'IDENTITY_PLATFORM_CONTINUE_URL: "https://medlock.ai/api/waitlist/confirm"',
  'RECAPTCHA_PROJECT_ID: "medlock-1025243085"',
  "RECAPTCHA_SITE_KEY: $recaptcha_site_key",
  "The served Medlock revision did not preserve the verified ownership configuration.",
]) {
  requireContains(
    ".github/workflows/deploy-prod.yml",
    deployProduction,
    needle,
    `Immutable production runtime configuration is missing: ${needle}`,
  );
}
rejectContains(
  ".github/workflows/deploy-prod.yml",
  deployProduction,
  "secrets.WAITLIST_IDENTITY_KEYSET",
  "The Medlock signing key must never transit GitHub Actions secrets.",
);
if (deployProduction.split("--set-secrets").length - 1 !== 1) {
  failures.push(".github/workflows/deploy-prod.yml: Exactly one reviewed Secret Manager mapping is permitted.");
}
requireBefore(
  ".github/workflows/deploy-prod.yml",
  deployProduction,
  "gcloud secrets versions list",
  "gcloud secrets versions add waitlist-identity-keyset",
  "The trusted deploy must prove there is no enabled unbound version before creating the first key.",
);
for (const needle of ["PROD_ENV_VARS", "PROD_SECRETS", "GCP_PROD_ENV_VARS", "GCP_PROD_SECRETS"]) {
  rejectContains(
    ".github/workflows/deploy-prod.yml",
    deployProduction,
    needle,
    `Production runtime configuration must not accept generic caller-controlled ${needle}.`,
  );
}
for (const needle of [
  "MAPBOX_PUBLIC_TOKEN: ${{ vars.MAPBOX_PUBLIC_TOKEN }}",
  "openssl rand -base64 32",
  '[[ ! "$waitlist_identity_keyset" =~ ^[A-Za-z0-9_-]{43}$ ]]',
  'WAITLIST_IDENTITY_KEYSET: $waitlist_identity_keyset',
  '[[ ! "$MAPBOX_PUBLIC_TOKEN" =~ ^pk\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$ ]]',
  ". + {MAPBOX_PUBLIC_TOKEN: $token}",
  'RUNSETTA_OFFLINE: "1"',
  'WAITLIST_BACKEND: "memory"',
]) {
  requireContains(
    ".github/workflows/deploy-preview.yml",
    deployPreview,
    needle,
    `Immutable preview runtime configuration is missing: ${needle}`,
  );
}
for (const needle of ["EXTRA_ENV_VARS", "GCP_PREVIEW_ENV_VARS", "GCP_CLOUD_PREVIEW_ENABLED"]) {
  rejectContains(
    ".github/workflows/deploy-preview.yml",
    deployPreview,
    needle,
    `Preview runtime/deployment policy must not accept repository-controlled ${needle}.`,
  );
}

for (const [path, workflow, publishEnvironment, publisherAccount, deployAccount, publisherCanary] of [
  [
    ".github/workflows/deploy-prod.yml",
    deployProduction,
    "environment: production-publish",
    "gha-prod-publish@",
    "gha-prod-deploy@",
    "Prove exact production publisher workflow-SHA WIF trust",
  ],
  [
    ".github/workflows/deploy-preview.yml",
    deployPreview,
    "environment: preview-publish",
    "gha-preview-publish@",
    "gha-preview-deploy@",
    "Prove exact preview publisher workflow-SHA WIF trust",
  ],
] as const) {
  const publish = sectionBetween(workflow, "  publish:\n", "\n  attest:\n");
  const build = sectionBetween(workflow, "  build:\n", "\n  verify-image:\n");
  const promoter = sectionBetween(workflow, "  verify-image:\n", "\n  canary:\n");
  const deploy = path.endsWith("deploy-preview.yml")
    ? sectionBetween(workflow, "  deploy:\n", "\n  invalidate:\n")
    : sectionFrom(workflow, "  deploy:\n");
  requireContains(path, publish, publishEnvironment, "Image publication must use its distinct protected environment claim.");
  requireContains(path, publish, publisherAccount, "Image publication must use the dedicated publisher service account.");
  requireContains(path, publish, publisherCanary, "Each publisher claim must have an independent no-role canary exchange.");
  rejectContains(path, publish, deployAccount, "An image publisher job must not authenticate the Cloud Run operator.");
  requireContains(path, deploy, deployAccount, "Cloud Run mutation must use the dedicated deploy/operator service account.");
  rejectContains(path, deploy, publisherAccount, "A Cloud Run deploy job must not authenticate the Artifact Registry publisher.");
  for (const [jobName, job] of [["build", build], ["promoter", promoter]] as const) {
    rejectContains(path, job, "id-token: write", `The credentialless ${jobName} job must not mint cloud credentials.`);
    rejectContains(path, job, "packages: write", `The credentialless ${jobName} job must not write GitHub packages.`);
  }
  rejectContains(path, workflow, "ghcr.io", "The container pipeline must not use a public GHCR staging package.");
  rejectContains(path, workflow, "packages: write", "The container pipeline must not retain GitHub Packages write access.");
  for (const boundary of [
    '[[ "$ARTIFACT_DIGEST" =~ ^[0-9a-f]{64}$ ]]',
    '--arg digest "sha256:${digest}"',
    "artifact-ids: ${{ needs.verify-image.outputs.artifact-id }}",
    "digest-mismatch: error",
    "skip-decompress: true",
    'container-artifact-contract.sh" validate-promoted',
    'container-artifact-contract.sh" prepare-publisher',
    'container-artifact-contract.sh" publish',
    "Verify publisher credentials were retired",
  ]) {
    requireContains(path, publish, boundary, `The fixed promoted-artifact publisher is missing ${boundary}.`);
  }
  requireBefore(path, publish, "validate-promoted", "prepare-publisher", "The canonical OCI graph must be validated before the publisher tool is prepared.");
  requireBefore(path, publish, "prepare-publisher", publisherCanary, "All non-credential tooling must be checksum-pinned before OIDC.");
  requireBefore(path, publish, "validate-promoted", "Authenticate", "The promoted graph must be revalidated before any registry access token is requested.");
  rejectContains(path, publish, "actions/checkout@", "The privileged publisher must never checkout caller code.");
  rejectContains(path, publish, "docker load", "The privileged publisher must not extract or execute image layers.");
}
const previewInvalidation = sectionFrom(deployPreview, "  invalidate:\n");
const previewDeploy = sectionBetween(deployPreview, "  deploy:\n", "\n  invalidate:\n");
requireContains(
  ".github/workflows/deploy-preview.yml",
  previewDeploy,
  'gh pr comment "$PR_NUMBER" --repo "$GITHUB_REPOSITORY" --body',
  "Preview comments must identify the repository when the deploy job has no checkout.",
);
rejectContains(
  ".github/workflows/deploy-preview.yml",
  previewDeploy,
  'gh pr comment "$PR_NUMBER" --body',
  "Preview comments must not rely on a local Git repository.",
);
const previewPublishCanary = sectionBetween(deployPreview, "  publish-canary:\n", "\n  publish:\n");
requireContains(
  ".github/workflows/deploy-preview.yml",
  previewPublishCanary,
  "environment: preview-publish",
  "Preview publisher trust must have an independent publish-environment canary.",
);
rejectContains(
  ".github/workflows/deploy-preview.yml",
  previewPublishCanary,
  "GCP_EXACT_WIF_CANARY_ENABLED",
  "The preview publisher canary must not have a repository-variable bypass.",
);
requireContains(
  ".github/workflows/deploy-preview.yml",
  sectionBetween(deployPreview, "  publish:\n", "\n  attest:\n"),
  "needs.publish-canary.result == 'success'",
  "Preview publication must fail closed unless the independent publisher canary succeeds.",
);
requireContains(
  ".github/workflows/deploy-preview.yml",
  previewInvalidation,
  "environment: preview-operations",
  "Stale-preview invalidation must use the traffic-only environment claim.",
);
requireContains(
  ".github/workflows/deploy-preview.yml",
  previewInvalidation,
  "gha-preview-commit@",
  "Stale-preview invalidation must authenticate the dedicated preview transaction committer.",
);
for (const boundary of [
  "deployed-revision: ${{ steps.deploy.outputs.revision }}",
  "EXPECTED_TARGET_REVISION: ${{ needs.deploy.outputs.deployed-revision }}",
  'cloud-run-preview-controller.sh" remove',
]) {
  requireContains(
    ".github/workflows/deploy-preview.yml",
    deployPreview,
    boundary,
    `Stale-preview invalidation must preserve a newer queued deployment: ${boundary}`,
  );
}
rejectContains(
  ".github/workflows/deploy-preview.yml",
  previewInvalidation,
  "actions/checkout@",
  "Privileged stale-preview invalidation must not checkout or execute PR-controlled code.",
);
for (const needle of ["cloud-run-preview-controller.sh", "deployment-parity-transition.sh"]) {
  requireContains(
    ".github/workflows/deploy-preview.yml",
    previewInvalidation,
    needle,
    `Stale-preview invalidation must verify stable data-plane teardown: ${needle}`,
  );
}
for (const workflowName of ["cleanup-preview.yml", "reconcile-previews.yml"]) {
  const path = `.github/workflows/${workflowName}`;
  const workflow = await read(path);
  requireContains(path, workflow, "gha-preview-commit@", "Preview traffic operations must authenticate the dedicated preview transaction committer.");
  rejectContains(path, workflow, "gha-preview-publish@", "Preview traffic operations must not authenticate the publisher identity.");
  rejectContains(
    path,
    workflow,
    "actions/checkout@",
    "Privileged preview traffic operations must not checkout or execute repository code.",
  );
  requireContains(path, workflow, "cloud-run-preview-controller.sh", "Preview traffic operations must use the shared proven etag controller.");
}
for (const boundary of [
  'removed_url="https://${removed_tag}.${STABLE_PREVIEW_DOMAIN}"',
  '[ "$status" = 404 ]',
]) {
  requireContains(
    "tools/ci/cloud-run-preview-controller.sh",
    await read("tools/ci/cloud-run-preview-controller.sh"),
    boundary,
    `The shared controller must prove exact stable-route teardown: ${boundary}`,
  );
}
rejectContains(
  "tools/ci/cloud-run-preview-controller.sh",
  sectionFrom(await read("tools/ci/cloud-run-preview-controller.sh"), "removed_checks="),
  "--location",
  "Stable preview teardown probes must not follow redirects.",
);
const cleanupPreview = await read(".github/workflows/cleanup-preview.yml");
for (const boundary of [
  "github.event.pull_request.head.repo.full_name == github.repository",
  "PR_NUMBER: ${{ github.event.pull_request.number }}",
  'export TARGET_TAG="pr-${{ github.event.pull_request.number }}"',
]) {
  requireContains(
    ".github/workflows/cleanup-preview.yml",
    cleanupPreview,
    boundary,
    `Preview cleanup must derive its exact target from the trusted event: ${boundary}`,
  );
}
const reconcilePreviews = await read(".github/workflows/reconcile-previews.yml");
for (const boundary of [
  "(github.event_name == 'push' || github.event_name == 'schedule' || github.event_name == 'workflow_dispatch')",
  "github.ref == 'refs/heads/main'",
  'cloud-run-preview-controller.sh" reconcile',
]) {
  requireContains(
    ".github/workflows/reconcile-previews.yml",
    reconcilePreviews,
    boundary,
    `Preview reconciliation must derive its decisions from trusted default-branch state: ${boundary}`,
  );
}
for (const [path, workflow] of [
  [".github/workflows/deploy-preview.yml", deployPreview],
  [".github/workflows/deploy-prod.yml", deployProduction],
] as const) {
  rejectContains(path, workflow, "Login to Docker Hardened Images", "Only the isolated prefetch helper may receive the DHI token.");
  rejectContains(path, workflow, "secrets.SOCKET_API_TOKEN", "Socket GitHub App checks replace all workflow Socket credentials.");
  requireBefore(path, workflow, "Fetch, verify, and close the exact public base graph", "Checkout", "DHI credentials must be retired before any application checkout.");
}

for (const workflow of ["application.yml", "socket-firewall.yml", "platform.yml"]) {
  const path = `.github/workflows/${workflow}`;
  const text = await read(path);
  rejectContains(path, text, "oven-sh/setup-bun@", "Bun must be installed from a checksum-pinned archive.");
  requireContains(
    path,
    text,
    "2d03fb5fb83ac8b567aca0a281b2ce1a1a19d488f56c2968d88c3f25e92fe452",
    "Bun 1.4.0 archive checksum must be pinned.",
  );
}

const application = await read(".github/workflows/application.yml");
for (const forbidden of ["install-command", "verify-command", "inputs.bun-version"]) {
  rejectContains(
    ".github/workflows/application.yml",
    application,
    forbidden,
    `Application verification must not accept caller-controlled ${forbidden}.`,
  );
}
for (const [path, workflow] of [
  [".github/workflows/application.yml", application],
  [".github/workflows/socket-firewall.yml", await read(".github/workflows/socket-firewall.yml")],
] as const) {
  rejectContains(path, workflow, "environment: dependency-scan", "Duplicate verification jobs must not unlock the paid Socket token.");
  rejectContains(path, workflow, "secrets.SOCKET_API_TOKEN", "Duplicate verification jobs must remain credential-free.");
  requireContains(path, workflow, "unset SOCKET_API_TOKEN SOCKET_API_KEY", "Credential-free Socket checks must scrub token aliases.");
  requireContains(path, workflow, "Socket Security Scanner free mode", "Credential-free Socket checks must prove public-policy execution.");
  rejectContains(
    path,
    workflow,
    "ALLOW_SOCKET_FREE_MODE",
    "Credential-free verification must not have a branch-dependent secret mode.",
  );
}
for (const path of [
  ".github/workflows/application.yml",
  ".github/workflows/socket-firewall.yml",
  ".github/workflows/deploy-preview.yml",
  ".github/workflows/deploy-prod.yml",
  ".github/workflows/platform.yml",
]) {
  const workflow = await read(path);
  for (const boundary of [
    "print_untrusted_output()",
    "/proc/sys/kernel/random/uuid",
    "::stop-commands::%s",
    "printf '::%s::\\n'",
  ]) {
    requireContains(
      path,
      workflow,
      boundary,
      "Captured dependency-tool output must disable GitHub workflow-command parsing while it is re-emitted.",
    );
  }
  for (const variable of ["scan_output", "install_output"]) {
    rejectContains(
      path,
      workflow,
      `printf '%s\\n' \"$${variable}\"`,
      "Remote dependency-tool output must not be re-emitted while runner commands are active.",
    );
  }
}
const platformDependencyWorkflow = await read(".github/workflows/platform.yml");
rejectContains(
  ".github/workflows/platform.yml",
  platformDependencyWorkflow,
  "environment:",
  "Platform verification is credentialless and must not enter a secret-bearing environment.",
);
rejectContains(
  ".github/workflows/platform.yml",
  platformDependencyWorkflow,
  "secrets.SOCKET_API_TOKEN",
  "The Socket GitHub App gate replaces every platform workflow token.",
);
rejectContains(
  ".github/workflows/platform.yml",
  platformDependencyWorkflow,
  "workflow_dispatch:",
  "Platform dependency credentials must never be reachable from an off-main manual dispatch.",
);
for (const boundary of [
  "PLATFORM_BUN=",
  "Reject scanner substitution before any Socket credential exists",
  'Object.hasOwn(packageJson, "patchedDependencies")',
  'Object.hasOwn(lock, "patchedDependencies")',
  'Object.hasOwn(packageJson, "workspaces")',
  "must use an exact npm registry version or npm alias",
  "must be a sha512-pinned npm registry resolution",
  "bun.lock must contain only the root workspace",
  'Object.keys(lock.packages ?? {}).length > 128',
  '--config="$GITHUB_WORKSPACE/bunfig.toml" pm scan',
  "bun pm scan must not mutate package.json or bun.lock.",
  'tools/ci/verify-platform.ts "$GITHUB_WORKSPACE"',
]) {
  requireContains(
    ".github/workflows/platform.yml",
    platformDependencyWorkflow,
    boundary,
    `Platform verification must bypass dependency-installed executable shims: ${boundary}`,
  );
}
const trustedPlatformRunner = await read("tools/ci/verify-platform.ts");
for (const boundary of [
  'process.platform !== "linux"',
  "`/proc/${process.pid}/exe`",
  "node_modules/.bin/bun",
  '"typecheck"',
  "tools/format.ts",
  "tools/lint.ts",
  '"test"',
]) {
  requireContains(
    "tools/ci/verify-platform.ts",
    trustedPlatformRunner,
    boundary,
    `Platform verification runner is missing immutable execution boundary: ${boundary}`,
  );
}
rejectContains(
  ".github/workflows/platform.yml",
  platformDependencyWorkflow,
  "run: bun run verify",
  "Platform CI must not execute dependency-shadowable package-script orchestration.",
);
for (const workflow of ["application.yml", "socket-firewall.yml"]) {
  const path = `.github/workflows/${workflow}`;
  const text = await read(path);
  requireContains(path, text, "repository: ${{ job.workflow_repository }}", "Policy source must be the reusable workflow repository.");
  requireContains(path, text, "ref: ${{ job.workflow_sha }}", "Policy source must use the exact resolved reusable workflow SHA.");
  requireContains(path, text, "path: _platform_policy", "Policy source must be isolated from the caller checkout.");
  requireContains(path, text, "enforce-app-contract.ts", "Workflow must run the immutable platform contract checker.");
  requireContains(
    path,
    text,
    '"${{ github.event.repository.id }}"',
    "Immutable app policy must bind to the caller repository's numeric GitHub ID.",
  );
  requireContains(
    path,
    text,
    '"${{ github.event.repository.id }}" \\\n              "${{ job.workflow_sha }}"',
    "Immutable app policy must bind Terraform mirrors to the resolved reusable workflow SHA.",
  );
  requireContains(
    path,
    text,
    "--no-env-file --no-orphans",
    "Trusted Bun commands must disable env files and kill descendants.",
  );
  rejectContains(path, text, "declare -A stages", "Untrusted Docker tokens must never enter Bash associative arrays.");
}
for (const workflow of ["deploy-preview.yml", "deploy-prod.yml"]) {
  const path = `.github/workflows/${workflow}`;
  const text = await read(path);
  for (const boundary of [
    "WORKFLOW_REPOSITORY: ${{ job.workflow_repository }}",
    "WORKFLOW_SHA: ${{ job.workflow_sha }}",
    'test "$WORKFLOW_REPOSITORY" = "collinbentley1/platform"',
    "GIT_CONFIG_NOSYSTEM=1",
    "core.hooksPath=/dev/null",
    "protocol.ext.allow=never",
    "container-artifact-contract.sh",
    "enforce-app-contract.ts",
    '"${{ github.event.repository.id }}"',
    '"${{ job.workflow_sha }}"',
    "--no-env-file --no-orphans",
  ]) {
    requireContains(path, text, boundary, `Exact reusable-workflow policy materialization is missing ${boundary}.`);
  }
  rejectContains(path, text, "declare -A stages", "Untrusted Docker tokens must never enter Bash associative arrays.");
}

const appPolicy = await read("tools/ci/enforce-app-contract.ts");
for (const boundary of [
  "canonicalFiles",
  "Bun.JSONC.parse",
  "bun.lock must not resolve the quota-exhausting published Socket scanner",
  "bun.lock exceeds the reviewed",
  '"tools/socket-security-scanner.ts"',
  "must exactly match the immutable platform template",
  'name !== ".env.example"',
  "validateAppScripts",
  "validateTerraformGitignore",
  "isForbiddenTerraformArtifact",
  "trusted-repository-id",
  "validateTypeScriptLock",
  "validateRegistryOnlyDependencySpecs",
  "validateRegistryOnlyLock",
  "package.json patchedDependencies are forbidden",
  "bun.lock patchedDependencies are forbidden",
  "tools/platform-verify.ts",
]) {
  requireContains(
    "tools/ci/enforce-app-contract.ts",
    appPolicy,
    boundary,
    `Immutable app policy is missing boundary: ${boundary}`,
  );
}
const sharedAppContract = await read("tools/ci/app-contract.ts");
for (const boundary of [
  "bun ci --no-env-file --ignore-scripts --registry=https://registry.npmjs.org && bun --no-env-file run verify:ci",
  "bun run format:check && bun run lint && bun run typecheck && bun run test && bun run build",
  "package.json script ${name} must exactly match the immutable platform command",
  "**/.terraform/",
  "*.tfstate.*",
  "*.tfplan",
  "*.tfvars.json",
  ".terraformrc",
  "terraformGitignoreSafetyBlock",
  "# BEGIN platform-managed Terraform safety rules",
  "@typescript/typescript-",
  "bun.lock does not resolve the reviewed TypeScript integrity for ${name}",
  "package.json workspaces are forbidden by the registry-only dependency policy",
  "must use an exact npm registry version or npm alias",
  "must be a sha512-pinned npm registry resolution",
  "bun.lock must contain only the root workspace",
]) {
  requireContains(
    "tools/ci/app-contract.ts",
    sharedAppContract,
    boundary,
    `Shared app contract is missing required boundary: ${boundary}`,
  );
}
const trustedVerificationRunner = await read("templates/app/tools/platform-verify.ts");
for (const boundary of [
  "process.execPath",
  'process.platform !== "linux"',
  "`/proc/${process.pid}/exe`",
  "node_modules/.bin/bun",
  "node_modules/typescript/bin/tsc",
  'verificationEnvironment.PATH = [dirname(bunExecutable), "/usr/local/bin", "/usr/bin", "/bin"]',
  '"typecheck"',
  "tools/format.ts",
  "tools/lint.ts",
  "tools/build.ts",
]) {
  requireContains(
    "templates/app/tools/platform-verify.ts",
    trustedVerificationRunner,
    boundary,
    `Trusted application verification runner is missing boundary: ${boundary}`,
  );
}
const applicationWorkflow = await read(".github/workflows/application.yml");
for (const boundary of ["PLATFORM_BUN=", "templates/app/tools/platform-verify.ts"]) {
  requireContains(
    ".github/workflows/application.yml",
    applicationWorkflow,
    boundary,
    `Application verification must use the checksum-pinned absolute Bun runner: ${boundary}`,
  );
}
rejectContains(
  ".github/workflows/application.yml",
  applicationWorkflow,
  "run verify:ci",
  "Application CI must not execute dependency-shadowable package-script orchestration.",
);
const templateDockerfile = await read("templates/app/Dockerfile");
for (const boundary of [
  "COPY tools ./tools",
  "/usr/local/bin/bun --no-env-file --no-orphans",
  "/app/tools/platform-verify.ts /app",
]) {
  requireContains(
    "templates/app/Dockerfile",
    templateDockerfile,
    boundary,
    `Container verification must bypass dependency-installed executable shims: ${boundary}`,
  );
}
rejectContains(
  "templates/app/Dockerfile",
  templateDockerfile,
  "run verify:ci",
  "The container build must not execute dependency-shadowable package-script orchestration.",
);
const templateGitignore = await read("templates/app/.gitignore");
for (const boundary of [
  "**/.terraform/",
  "*.tfstate",
  "*.tfstate.*",
  "*.tfplan",
  "*.plan",
  "*.tflock",
  "*.tfvars",
  "*.auto.tfvars",
  ".terraformrc",
  "terraform.rc",
]) {
  requireContains(
    "templates/app/.gitignore",
    templateGitignore,
    boundary,
    `Scaffold must ignore Terraform state/config artifact: ${boundary}`,
  );
}
const templateBootstrapOutputs = await read("templates/app/infra/terraform/bootstrap/outputs.tf");
const templateProductionMain = await read("templates/app/infra/terraform/prod/main.tf");
const templateProductionVariables = await read("templates/app/infra/terraform/prod/variables.tf");
requireContains(
  "templates/app/infra/terraform/prod/main.tf",
  templateProductionMain,
  "runtime_secret_version_adder_ids               = var.runtime_secret_version_adder_ids",
  "The scaffold must pass the declared exact-secret version-adder set.",
);
requireContains(
  "templates/app/infra/terraform/prod/variables.tf",
  templateProductionVariables,
  "setsubtract(var.runtime_secret_version_adder_ids, var.runtime_secret_ids)",
  "The scaffold version-adder set must be a subset of retained secret containers.",
);
rejectContains(
  "templates/app/infra/terraform/bootstrap/outputs.tf",
  templateBootstrapOutputs,
  "Terraform apply workflow",
  "The routine Terraform identity is metadata-only and must never be described as an apply identity.",
);
const runsettaAppleWorkflow = await read("templates/additional-workflows/runsetta/apple.yml");
checkActionPins(
  "templates/additional-workflows/runsetta/apple.yml",
  runsettaAppleWorkflow,
  false,
);
requireContains(
  "templates/additional-workflows/runsetta/apple.yml",
  runsettaAppleWorkflow,
  "persist-credentials: false",
  "Runsetta's untrusted Swift build must not receive the checkout credential.",
);
rejectContains(
  "templates/additional-workflows/runsetta/apple.yml",
  runsettaAppleWorkflow,
  "secrets.",
  "Runsetta's additional pull-request workflow must remain credential-free.",
);
rejectContains(
  "templates/additional-workflows/runsetta/apple.yml",
  runsettaAppleWorkflow,
  "workflow_dispatch:",
  "Runsetta's required Swift check must not be manually dispatchable on a pull-request head.",
);
for (const boundary of ["- edited", "- opened", "- reopened", "- synchronize"]) {
  requireContains(
    "templates/additional-workflows/runsetta/apple.yml",
    runsettaAppleWorkflow,
    boundary,
    "Runsetta's required Swift check must rerun when a pull request opens, changes head, reopens, or changes base.",
  );
}
for (const boundary of [
  'test "$GITHUB_RUN_ATTEMPT" = "1"',
  'if [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then',
  'test "$GITHUB_EVENT_NAME" = "push"',
  'test "$GITHUB_REF" = "refs/heads/main"',
]) {
  requireContains(
    "templates/additional-workflows/runsetta/apple.yml",
    runsettaAppleWorkflow,
    boundary,
    "Runsetta's required Swift check must reject reruns and alternate event aliases.",
  );
}
requireBefore(
  "templates/additional-workflows/runsetta/apple.yml",
  runsettaAppleWorkflow,
  "Reject workflow reruns before any required check",
  "Reject alternate required-check event paths",
  "Runsetta must reject reruns before evaluating the triggering event.",
);
requireBefore(
  "templates/additional-workflows/runsetta/apple.yml",
  runsettaAppleWorkflow,
  "Reject alternate required-check event paths",
  "Checkout",
  "Runsetta must reject alternate events before executing pull-request code.",
);
rejectContains(
  "templates/additional-workflows/runsetta/apple.yml",
  runsettaAppleWorkflow,
  "continue-on-error:",
  "Runsetta's required check guards must fail closed.",
);
requireContains(
  "templates/app/infra/terraform/bootstrap/outputs.tf",
  templateBootstrapOutputs,
  "Metadata-only service account used by the immutable Terraform convergence workflow.",
  "The scaffold must document the routine Terraform identity's metadata-only boundary.",
);
const trustedCiBunfig = await read("tools/ci/bunfig.toml");
requireContains(
  "tools/ci/bunfig.toml",
  trustedCiBunfig,
  'registry = "https://registry.npmjs.org"',
  "Trusted Bun execution must pin the official registry.",
);
const platformBunfig = await read("bunfig.toml");
for (const boundary of [
  "env = false",
  "telemetry = false",
  "minimumReleaseAge = 604800",
  'registry = "https://registry.npmjs.org"',
  'scanner = "./tools/socket-security-scanner.ts"',
]) {
  requireContains("bunfig.toml", platformBunfig, boundary, `The platform Bun policy is missing boundary: ${boundary}`);
}
requireContains(
  "tools/ci/bunfig.toml",
  trustedCiBunfig,
  'scanner = "./tools/socket-security-scanner.ts"',
  "Trusted Bun execution must use the canonical local Socket scanner.",
);
const socketScanner = await read("tools/socket-security-scanner.ts");
const templateSocketScanner = await read("templates/app/tools/socket-security-scanner.ts");
if (socketScanner !== templateSocketScanner) {
  failures.push(
    "templates/app/tools/socket-security-scanner.ts: scanner must byte-match the reviewed platform implementation.",
  );
}
for (const boundary of [
  'const socketFirewallBase = "https://firewall-api.socket.dev/purl"',
  "const reviewedPackageLimit = 128",
  "const publicConcurrency = 10",
  "const maxAlertsPerArtifact = 256",
  '`${socketFirewallBase}/${encodeURIComponent(purl)}`',
  'headers: { Accept: "application/x-ndjson", "User-Agent": userAgent }',
  'logger("Socket Security Scanner free mode.")',
  'redirect: "error"',
  'parsed._type === "purlError"',
  'parsed._type === "summary"',
  'rawAlert.action !== "error" && rawAlert.action !== "warn"',
  "/^[A-Za-z][A-Za-z0-9_-]{0,127}$/",
  'rawAlert.type === "pendingScan"',
  'rawAlert.type === "notFound"',
  '.replaceAll("::", ": :")',
  '.replaceAll("##[", "# #[")',
]) {
  requireContains(
    "tools/socket-security-scanner.ts",
    socketScanner,
    boundary,
    `The local Socket scanner is missing fail-closed boundary: ${boundary}`,
  );
}
rejectContains(
  "tools/socket-security-scanner.ts",
  socketScanner,
  "SOCKET_API_KEY",
  "The local Socket scanner must remain credentialless.",
);
rejectContains(
  "tools/socket-security-scanner.ts",
  socketScanner,
  "SOCKET_API_TOKEN",
  "The local Socket scanner must remain credentialless.",
);
rejectContains(
  "tools/socket-security-scanner.ts",
  socketScanner,
  "Promise.all(flights)",
  "The local scanner must not reintroduce the released scanner's shared-array race.",
);

const socketFirewall = await read(".github/workflows/socket-firewall.yml");
rejectContains(
  ".github/workflows/socket-firewall.yml",
  socketFirewall,
  "socket-config-command",
  "Socket verification must not accept a caller-controlled command.",
);
rejectContains(
  ".github/workflows/socket-firewall.yml",
  socketFirewall,
  "socketdev/action@",
  "The Bun-only platform must not download the mutable Socket Firewall wrapper.",
);

const infrastructure = await read(".github/workflows/infrastructure.yml");

// Every Google credential this platform mints must be bounded to the mutator
// lifetime the capability manifest declares. The protected bridge's freeze proof
// waits out the longest token a consumer could hold before it mutates IAM, and
// GCP offers no way to cap that centrally: no organization policy reduces the
// 1-hour default, and an already-issued token cannot be revoked short of
// disabling the service account. The bound is therefore only as good as what
// these workflows request, so it is asserted here rather than assumed.
//
// This includes the steps whose token is discarded (`create_credentials_file`
// and `export_environment_variables` both false, used only to prove WIF trust
// resolves). An unused 1-hour token still widens the drain the bridge must wait
// out, because the freeze proof bounds what a consumer *could* hold, not what it
// chose to use.
for (
  const [path, workflow] of [
    [".github/workflows/cleanup-preview.yml", cleanupPreview],
    [".github/workflows/deploy-preview.yml", deployPreview],
    [".github/workflows/deploy-prod.yml", deployProd],
    [".github/workflows/infrastructure.yml", infrastructure],
    [".github/workflows/reconcile-previews.yml", reconcilePreviews],
  ] as const
) {
  const lines = workflow.split("\n");
  for (const [index, line] of lines.entries()) {
    if (!line.includes("google-github-actions/auth@")) continue;
    const step = lines.slice(index, index + 14).join("\n");
    if (!/\n\s+access_token_lifetime: 300s(\n|$)/.test(step)) {
      failures.push(
        `${path}: the google-github-actions/auth step at line ${
          index + 1
        } must declare \`access_token_lifetime: 300s\`; an unbounded token widens the protected freeze drain.`,
      );
    }
  }
}
checkRequiredCheckEventGuards([
  {
    jobs: ["verify"],
    path: ".github/workflows/application.yml",
    source: application,
  },
  {
    jobs: ["rerun-guard", "terraform-validate", "checkov", "terraform-convergence"],
    path: ".github/workflows/infrastructure.yml",
    source: infrastructure,
  },
  {
    jobs: ["firewall"],
    path: ".github/workflows/socket-firewall.yml",
    source: socketFirewall,
  },
  {
    jobs: ["swift-package"],
    path: "templates/additional-workflows/runsetta/apple.yml",
    source: runsettaAppleWorkflow,
  },
]);
for (const boundary of [
  "infra/terraform >/dev/null; then",
  "grep -rahcE --include='*.tf'",
  "grep -rahcE 'collinbentley1/platform",
  "' . >/dev/null; then",
]) {
  requireContains(
    ".github/workflows/infrastructure.yml",
    infrastructure,
    boundary,
    `Infrastructure policy search must suppress attacker-controlled match output: ${boundary}`,
  );
}
rejectContains(
  ".github/workflows/infrastructure.yml",
  infrastructure,
  'printf \'%s\\n\' "$platform_refs"',
  "Infrastructure validation must never replay attacker-controlled grep output to the runner command channel.",
);
requireContains(
  ".github/workflows/infrastructure.yml",
  infrastructure,
  "ac21c2b9dcd115711f540cbd27ead0596bb4288a917cb56dfa9b25edb3eb6280",
  "Terraform must be installed from the reviewed checksum-pinned archive.",
);
rejectContains(
  ".github/workflows/infrastructure.yml",
  infrastructure,
  "hashicorp/setup-terraform@",
  "Terraform tool-cache downloads do not verify the release archive checksum.",
);
rejectContains(
  ".github/workflows/infrastructure.yml",
  infrastructure,
  "config_file: .checkov.yml",
  "Checkov policy must not come from the caller checkout.",
);
requireContains(
  ".github/workflows/infrastructure.yml",
  infrastructure,
  "CHECKOV_IMAGE: ghcr.io/bridgecrewio/checkov@sha256:f4c7c5bde21df03432ca8d9d1305ffe21b7205ea752c3d4e65559abae67ead4a",
  "Checkov container must be digest pinned.",
);
for (const configName of [".checkov.yml", ".checkov.yaml", "checkov.yml", "checkov.yaml"]) {
  requireContains(
    ".github/workflows/infrastructure.yml",
    infrastructure,
    configName,
    `Infrastructure verification must reject caller-controlled ${configName}.`,
  );
}
requireContains(
  ".github/workflows/infrastructure.yml",
  infrastructure,
  "--config-file /policy.yml",
  "Checkov must use a trusted fail-closed configuration written by the reusable workflow.",
);
requireContains(
  ".github/workflows/infrastructure.yml",
  infrastructure,
  "printf '%s\\n' 'soft-fail: false' > \"$policy_file\"",
  "The trusted Checkov configuration must fail closed.",
);
requireContains(
  ".github/workflows/infrastructure.yml",
  infrastructure,
  'chmod 0444 "$policy_file"',
  "The non-root Checkov container must be able to read the generated non-secret policy.",
);
for (const boundary of [
  'policy_file="$RUNNER_TEMP/platform-checkov.yml"',
  "docker run --rm --pull=never",
  "--network=none",
  "--read-only",
  "--cap-drop=ALL",
  "--security-opt no-new-privileges=true",
  "--user 65532:65532",
  "--workdir /tmp",
  '--mount "type=bind,src=${scan_root},dst=/scan,readonly"',
  '--mount "type=bind,src=${policy_file},dst=/policy.yml,readonly"',
  "--entrypoint /usr/local/bin/checkov",
  "--skip-download",
  "--skip-path '(^|/)\\.terraform(/|$)'",
  "--skip-path '(^|/)outputs(/|$)'",
  "--skip-path '(^|/)work(/|$)'",
]) {
  requireContains(
    ".github/workflows/infrastructure.yml",
    infrastructure,
    boundary,
    `Infrastructure Checkov isolation is missing ${boundary}.`,
  );
}
rejectContains(
  ".github/workflows/infrastructure.yml",
  infrastructure,
  "uses: docker://ghcr.io/bridgecrewio/checkov@",
  "The Checkov GitHub Action entrypoint ignores raw args and must not wrap the trusted scan.",
);
for (const boundary of [
  "validate_root infra/terraform/bootstrap bootstrap terraform/modules/bootstrap",
  "validate_root infra/terraform/prod site terraform/modules/cloud-run-service",
  "Consumer roots may contain only the exact reviewed Terraform mirror",
  "platform.ts\" doctor",
  "Committed Terraform caches and substituted modules/providers are forbidden",
  "Checkout only the exact trusted platform source",
  "platform-source/terraform/deployments/prod",
]) {
  requireContains(
    ".github/workflows/infrastructure.yml",
    infrastructure,
    boundary,
    `Infrastructure workflow is missing trusted module boundary: ${boundary}`,
  );
}
rejectContains(
  ".github/workflows/infrastructure.yml",
  infrastructure,
  '(resource|data)[[:space:]]+"',
  "The fail-fast shell scan must not reject direct resources before the immutable doctor authenticates the exact reviewed consumer mirror.",
);
rejectContains(
  ".github/workflows/infrastructure.yml",
  sectionFrom(infrastructure, "  terraform-convergence:\n"),
  "terraform -chdir=infra/terraform/prod",
  "Authenticated Terraform convergence must never execute the consumer root.",
);

for (const workflow of [
  "deploy-prod.yml",
  "deploy-preview.yml",
  "cleanup-preview.yml",
  "reconcile-previews.yml",
  "infrastructure.yml",
]) {
  const path = `.github/workflows/${workflow}`;
  const text = await read(path);
  requireContains(path, text, "queue: max", "Cloud mutations must retain a FIFO pending queue.");
  requireContains(
    path,
    text,
    "github.event.repository.id",
    "Cloud mutation locks must survive repository renames via numeric ID.",
  );
}

for (const workflow of ["deploy-prod.yml", "deploy-preview.yml", "cleanup-preview.yml", "reconcile-previews.yml"]) {
  const path = `.github/workflows/${workflow}`;
  const text = await read(path);
  requireContains(
    path,
    text,
    "https://storage.googleapis.com/cloud-sdk-release/google-cloud-cli-581.0.0-linux-x86_64.tar.gz?generation=1787059661116797",
    "Cloud operations must use the reviewed Cloud SDK archive.",
  );
  requireContains(
    path,
    text,
    "deffdbe82ca6e3d19ffb291d063a651488e04e1b33799b5a238e4b5c6784e3c6",
    "Cloud operations must verify the reviewed Cloud SDK archive checksum.",
  );
  requireContains(path, text, '.["Google Cloud SDK"] == "581.0.0"', "Cloud operations must verify the extracted SDK version.");
  requireContains(
    path,
    text,
    "export CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK=true",
    "The Cloud SDK update check must be disabled before its first execution.",
  );
  requireContains(
    path,
    text,
    "export CLOUDSDK_CORE_DISABLE_USAGE_REPORTING=true",
    "Cloud SDK usage reporting must be disabled before its first execution.",
  );
  rejectContains(path, text, "google-github-actions/setup-gcloud@", "Cloud SDK tool-cache downloads are not independently verified.");
  rejectContains(path, text, "google-github-actions/deploy-cloudrun@", "Cloud Run deploys must use the checksum-verified SDK.");
  rejectContains(path, text, "install.sh", "The Cloud SDK installer script must not execute in privileged jobs.");
}

requireBefore(
  ".github/workflows/cleanup-preview.yml",
  await read(".github/workflows/cleanup-preview.yml"),
  "Install checksum-pinned Google Cloud CLI",
  "Prove exact workflow-SHA WIF trust",
  "Preview cleanup must verify gcloud before any OIDC exchange.",
);
requireBefore(
  ".github/workflows/reconcile-previews.yml",
  await read(".github/workflows/reconcile-previews.yml"),
  "Install checksum-pinned Google Cloud CLI",
  "Prove exact workflow-SHA WIF trust",
  "Preview reconciliation must verify gcloud before any OIDC exchange.",
);
requireBefore(
  ".github/workflows/deploy-preview.yml",
  sectionFrom(deployPreview, "  deploy:\n"),
  "Install checksum-pinned Google Cloud CLI",
  "Authenticate preview deployer",
  "Preview deploys must verify gcloud before OIDC authentication.",
);
requireBefore(
  ".github/workflows/deploy-prod.yml",
  sectionFrom(deployProduction, "  deploy:\n"),
  "Install checksum-pinned Google Cloud CLI",
  "Authenticate production deployer",
  "Production deploys must verify gcloud before OIDC authentication.",
);

for (const workflow of [...reusableWorkflows, "application.yml", "socket-firewall.yml"]) {
  const path = `templates/app/.github/workflows/${workflow}`;
  const text = await read(path);
  requireContains(path, text, "@__PLATFORM_SHA__", "Template workflows must use the scaffolded platform SHA.");
  rejectContains(path, text, "secrets: inherit", "Template workflows must pass only named secrets.");
  checkActionPins(path, text, true);
}

for (const workflow of ["application.yml", "infrastructure.yml", "socket-firewall.yml"]) {
  const path = `templates/app/.github/workflows/${workflow}`;
  const text = await read(path);
  rejectContains(
    path,
    text,
    "workflow_dispatch:",
    "A required check must not be manually dispatchable on a pull-request head.",
  );
  for (const boundary of ["- edited", "- opened", "- reopened", "- synchronize"]) {
    requireContains(
      path,
      text,
      boundary,
      "Required checks must rerun when a pull request opens, changes head, reopens, or changes base.",
    );
  }
}

for (const workflow of ["deploy-preview.yml", "deploy-prod.yml"]) {
  const path = `templates/app/.github/workflows/${workflow}`;
  const text = await read(path);
  rejectContains(path, text, "    secrets:", "Deploy callers must not forward any secret map to a reusable workflow.");
}
requireContains(
  "templates/app/.github/workflows/deploy-preview.yml",
  await read("templates/app/.github/workflows/deploy-preview.yml"),
  "github.event.pull_request.draft == false",
  "Preview callers must not deploy draft pull requests.",
);
for (const boundary of [
  "pull_request_target:",
  "branches:",
  "- main",
  "- opened",
  "- synchronize",
  "- reopened",
  "- ready_for_review",
  "- converted_to_draft",
]) {
  requireContains(
    "templates/app/.github/workflows/deploy-preview.yml",
    await read("templates/app/.github/workflows/deploy-preview.yml"),
    boundary,
    `Preview callers must use the trusted default-branch definition and include ${boundary}.`,
  );
}

const dockerfile = await read("templates/app/Dockerfile");
const bunfig = await read("templates/app/bunfig.toml");
const templateLock = await read("templates/app/bun.lock");
const platformLock = await read("bun.lock");
const platformPackage = JSON.parse(await read("package.json")) as Record<string, unknown>;
const parsedTemplateLock = Bun.JSONC.parse(templateLock) as {
  packages?: Record<string, unknown>;
  workspaces?: unknown;
};
const parsedPlatformLock = Bun.JSONC.parse(platformLock) as {
  packages?: Record<string, unknown>;
  patchedDependencies?: unknown;
  workspaces?: unknown;
};
for (const failure of validateRegistryOnlyDependencySpecs(platformPackage)) {
  failures.push(`package.json: ${failure}`);
}
for (const failure of validateRegistryOnlyLock(parsedPlatformLock)) {
  failures.push(`bun.lock: ${failure}`);
}
for (const failure of validateRegistryOnlyLock(parsedTemplateLock)) {
  failures.push(`templates/app/bun.lock: ${failure}`);
}
if (Object.hasOwn(platformPackage, "patchedDependencies")) {
  failures.push("package.json: patchedDependencies are forbidden for trusted CI dependencies.");
}
if ((await read("package.json")).includes("@socketsecurity/bun-security-scanner")) {
  failures.push("package.json: the quota-exhausting published Socket scanner is forbidden.");
}
if (Object.hasOwn(parsedPlatformLock, "patchedDependencies")) {
  failures.push("bun.lock: patchedDependencies are forbidden for trusted CI dependencies.");
}
if (Object.hasOwn(parsedPlatformLock.packages ?? {}, "@socketsecurity/bun-security-scanner")) {
  failures.push("bun.lock: the quota-exhausting published Socket scanner is forbidden.");
}
if (Object.keys(parsedPlatformLock.packages ?? {}).length > 128) {
  failures.push("bun.lock: exceeds the reviewed 128-package Socket request limit.");
}
for (const failure of validateTypeScriptLock(
  parsedPlatformLock.packages,
  parsedTemplateLock.packages,
)) {
  failures.push(`bun.lock: ${failure}`);
}
rejectContains(
  "templates/app/bunfig.toml",
  bunfig,
  "[install.scopes]",
  "The scaffold must not contain a package scope override section.",
);
for (const boundary of ["env = false", "telemetry = false", "minimumReleaseAge = 604800"]) {
  requireContains(
    "templates/app/bunfig.toml",
    bunfig,
    boundary,
    `The scaffold Bun policy is missing boundary: ${boundary}`,
  );
}
rejectContains(
  "templates/app/bun.lock",
  templateLock,
  "@socketsecurity/bun-security-scanner",
  "The scaffold lockfile must not include the quota-exhausting published Socket scanner.",
);
requireContains(
  "templates/app/bun.lock",
  templateLock,
  '"@typescript/typescript-linux-x64@7.0.2", "", { "os": "linux", "cpu": "x64" }, "sha512-EYdf2cNg7rgCWJnxCdJ+F3V39O8ihb37eHAu1LK8oAFizgTQbPOK7zHHXbPt8rX24COqODXeI3sIf0fCXG7H/A=="',
  "The scaffold lockfile must retain the reviewed Linux TypeScript compiler integrity.",
);
rejectContains("templates/app/Dockerfile", dockerfile, "curl -fsSL https://bun.com/install", "Bun installers must not execute curl-piped shell code.");
requireContains(
  "templates/app/Dockerfile",
  dockerfile,
  "FROM platform.invalid/bun-release AS bun-release",
  "The Bun binary stage must use only the platform-supplied closed OCI context.",
);
if (dockerfile.split("34cbb9a40b4bd1bd767d134a7065e66c2432a676").length !== 3) {
  failures.push(
    "templates/app/Dockerfile: both executable stages must verify the exact Bun revision.",
  );
}
rejectContains("templates/app/Dockerfile", dockerfile, "apt-get", "Container builds must not execute mutable package-manager downloads.");
rejectContains("templates/app/Dockerfile", dockerfile, "curl ", "Container builds must not download executable build inputs over the network.");
requireContains("templates/app/Dockerfile", dockerfile, "--ignore-scripts", "Docker dependency installs must disable lifecycle scripts.");
requireContains("templates/app/Dockerfile", dockerfile, "--no-env-file", "Docker dependency installs must disable environment-file loading.");
rejectContains(
  "templates/app/Dockerfile",
  dockerfile,
  "--mount=type=secret,id=socket_api_token,required=true",
  "Docker dependency installs must never receive the Socket organization token.",
);
requireContains(
  "templates/app/Dockerfile",
  dockerfile,
  "Socket Security Scanner free mode",
  "Docker dependency installs must prove the scanner ran without credentials.",
);
requireContains(
  "templates/app/Dockerfile",
  dockerfile,
  "COPY tools/socket-security-scanner.ts ./tools/socket-security-scanner.ts",
  "Docker dependency installs must receive the reviewed local scanner before package extraction.",
);
requireContains(
  "templates/app/Dockerfile",
  dockerfile,
  "--registry=https://registry.npmjs.org",
  "Docker dependency installs must pin the official registry.",
);
requireContains("templates/app/Dockerfile", dockerfile, "FROM platform.invalid/dhi-bun-dev AS deps", "Builds must use only the exact verified DHI dev context.");
requireContains("templates/app/Dockerfile", dockerfile, "FROM platform.invalid/dhi-bun-runtime AS runtime", "Runtime must use only the exact verified DHI runtime context.");
rejectContains(
  "templates/app/Dockerfile",
  dockerfile,
  "# syntax=",
  "Dockerfile syntax frontends must not be fetched through mutable directives.",
);
checkDockerPins("templates/app/Dockerfile", dockerfile);

const readme = await read("README.md");
requireContains("README.md", readme, "0.5.0", "README should document the current release.");
const securityRollout = await read("docs/security-rollout.md");
for (const boundary of [
  "The WIF predecessor `P` is not a recovery root.",
  "separate recovery root `R` from `S`",
  "transition exact WIF trust from `{P, S}` to `{S, R}`",
]) {
  requireContains(
    "docs/security-rollout.md",
    securityRollout,
    boundary,
    `Stable-preview rollback documentation is missing boundary: ${boundary}`,
  );
}
rejectContains(
  "docs/security-rollout.md",
  securityRollout,
  "with the exact reviewed `P` production root",
  "The WIF predecessor must never be presented as a public-ingress recovery root.",
);
const templateServer = await read("templates/app/src/server.ts");
requireContains(
  "templates/app/src/server.ts",
  templateServer,
  "Bun.env.PLATFORM_DEPLOY_NONCE",
  "The standard preview health response must bind the data plane to this deployment.",
);

const moduleMain = await read("terraform/modules/cloud-run-service/main.tf");
const moduleVariables = await read("terraform/modules/cloud-run-service/variables.tf");
const moduleVersions = await read("terraform/modules/cloud-run-service/versions.tf");
if (
  createHash("sha256").update(moduleMain).digest("hex") !==
  "349780e0b92a85bbf4e6d1f330bfecadbb887c5183cca9a35729bdfec518dbab"
) {
  failures.push(
    "terraform/modules/cloud-run-service/main.tf: Security-critical module content changed; review it and both independent hash contracts together.",
  );
}
const productionServiceBlock = sectionBetween(
  moduleMain,
  'resource "google_cloud_run_v2_service" "site"',
  'resource "google_cloud_run_v2_service_iam_member" "prod_deploy"',
);
const previewServiceBlock = sectionBetween(
  moduleMain,
  'resource "google_cloud_run_v2_service" "preview"',
  'resource "google_cloud_run_v2_service_iam_member" "preview_deploy"',
);
const previewLifecycleBlock = sectionBetween(
  previewServiceBlock,
  "  lifecycle {\n",
  "\n  depends_on",
);
if (productionServiceBlock.includes("template[0].revision")) {
  failures.push(
    "terraform/modules/cloud-run-service/main.tf: Production must not ignore revision names it does not own.",
  );
}
if (
  !previewLifecycleBlock.includes(
    "# deploy-preview owns deterministic revision names. Land preview template\n" +
      "      # changes through that workflow first to avoid immutable-name conflicts.",
  )
) {
  failures.push(
    "terraform/modules/cloud-run-service/main.tf: Document the workflow-owned preview revision-name invariant.",
  );
}
if (
  previewServiceBlock.split("template[0].revision").length - 1 !== 1 ||
  previewLifecycleBlock.split("      template[0].revision,\n").length - 1 !== 1
) {
  failures.push(
    "terraform/modules/cloud-run-service/main.tf: Preview must ignore exactly one workflow-owned revision name.",
  );
}
const approvedModuleFiles = ["main.tf", "outputs.tf", "variables.tf", "versions.tf"];
for (const moduleName of ["cloud-run-service", "bootstrap"]) {
  const moduleDirectory = join(root, "terraform/modules", moduleName);
  const approvedEntries = moduleName === "bootstrap"
    ? [...approvedModuleFiles, ".terraform.lock.hcl", "tests"].sort()
    : approvedModuleFiles;
  const moduleEntries = (await readdir(moduleDirectory)).sort();
  if (JSON.stringify(moduleEntries) !== JSON.stringify(approvedEntries)) {
    failures.push(
      `terraform/modules/${moduleName}: entries must be exactly ${approvedEntries.join(", ")}; found ${moduleEntries.join(", ")}.`,
    );
  }
  for (const name of approvedModuleFiles.filter((file) => file !== "main.tf")) {
    const content = await readFile(join(moduleDirectory, name), "utf8");
    if (/^\s*(?:resource|data|module|locals|provider)\s+(?:"|\{)/m.test(content)) {
      failures.push(
        `terraform/modules/${moduleName}/${name}: Executable Terraform blocks belong only in the reviewed main.tf.`,
      );
    }
  }
}
const bootstrapModuleTests = join(root, "terraform/modules/bootstrap/tests");
const bootstrapTestFiles = (await readdir(bootstrapModuleTests)).sort();
if (JSON.stringify(bootstrapTestFiles) !== JSON.stringify(["transition_cardinality.tftest.hcl"])) {
  failures.push("terraform/modules/bootstrap/tests: only the reviewed transition-cardinality test is allowed.");
}
const transitionCardinalityTest = await readFile(
  join(bootstrapModuleTests, "transition_cardinality.tftest.hcl"),
  "utf8",
);
for (const boundary of [
  'run "reject_multiple_preview_operator_transition_shas"',
  "expect_failures = [var.preview_operator_transition_workflow_shas]",
  '"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"',
  '"cccccccccccccccccccccccccccccccccccccccc"',
]) {
  if (!transitionCardinalityTest.includes(boundary)) {
    failures.push(`terraform/modules/bootstrap/tests/transition_cardinality.tftest.hcl: missing ${boundary}`);
  }
}
const bootstrapModuleLock = await readFile(
  join(root, "terraform/modules/bootstrap/.terraform.lock.hcl"),
  "utf8",
);
for (const boundary of ['version     = "7.45.0"', 'constraints = ">= 7.34.0"']) {
  if (!bootstrapModuleLock.includes(boundary)) {
    failures.push(`terraform/modules/bootstrap/.terraform.lock.hcl: missing ${boundary}`);
  }
}
const allServiceModuleTerraform = (
  await Promise.all(
    approvedModuleFiles.map((name) => read(`terraform/modules/cloud-run-service/${name}`)),
  )
).join("\n");
for (const [path, content] of [
  ["terraform/modules/cloud-run-service/main.tf", moduleMain],
  ["terraform/modules/bootstrap/main.tf", await read("terraform/modules/bootstrap/main.tf")],
] as const) {
  if (/^\s*module\s+"/m.test(content)) {
    failures.push(`${path}: Trusted Terraform modules must not delegate to child modules.`);
  }
  if (/<<|\/\*|^\s*\/\//m.test(content)) {
    failures.push(
      `${path}: Trusted Terraform module entrypoints must not use heredocs or block-style comments that can disguise structural delimiters.`,
    );
  }
}
requireContains(
  "terraform/modules/cloud-run-service/versions.tf",
  moduleVersions,
  "configuration_aliases = [google.no_attribution]",
  "The no-destroy domain migration must retain its historical provider address until state is relinquished.",
);
rejectContains(
  "terraform/modules/cloud-run-service/main.tf",
  moduleMain,
  "provider = google.no_attribution",
  "Routine production resources must not use the protected domain-mapping provider alias.",
);
requireContains(
  "terraform/modules/cloud-run-service/main.tf",
  moduleMain,
  "from = google_cloud_run_domain_mapping.site",
  "Routine production state must relinquish legacy domain mappings without destroying them.",
);
requireContains(
  "terraform/modules/cloud-run-service/main.tf",
  moduleMain,
  "template[0].containers[0].env",
  "Cloud Run service must ignore deploy-owned runtime environment drift.",
);
requireContains(
  "terraform/modules/cloud-run-service/main.tf",
  moduleMain,
  "for_each = var.runtime_secret_accessor_ids",
  "Secret containers must not implicitly grant runtime payload access.",
);
requireContains(
  "terraform/modules/cloud-run-service/main.tf",
  moduleMain,
  "for_each = var.runtime_secret_version_adder_ids",
  "Production deployers must receive version-add permission only through the declared exact-secret set.",
);
requireContains(
  "terraform/modules/cloud-run-service/variables.tf",
  sectionFrom(moduleVariables, 'variable "runtime_secret_accessor_ids"'),
  "default     = []",
  "Runtime secret payload access must default to empty.",
);
requireContains(
  "terraform/modules/cloud-run-service/variables.tf",
  sectionFrom(moduleVariables, 'variable "runtime_secret_accessor_ids"'),
  "setsubtract(var.runtime_secret_accessor_ids, var.runtime_secret_ids)",
  "Runtime accessor IDs must be validated as a subset of retained secret containers.",
);
requireContains(
  "terraform/modules/cloud-run-service/variables.tf",
  sectionFrom(moduleVariables, 'variable "runtime_secret_version_adder_ids"'),
  "default     = []",
  "Production deploy secret-version addition must default to empty.",
);
requireContains(
  "terraform/modules/cloud-run-service/variables.tf",
  sectionFrom(moduleVariables, 'variable "runtime_secret_version_adder_ids"'),
  "setsubtract(var.runtime_secret_version_adder_ids, var.runtime_secret_ids)",
  "Production deploy version-adder IDs must be validated as a subset of retained secret containers.",
);
const productionDeployment = await read("terraform/deployments/prod/main.tf");
const bootstrapDeploymentRoot = await read("terraform/deployments/bootstrap/main.tf");
const exposureDeployment = await read("terraform/deployments/exposure/main.tf");
const exposureOutputs = await read("terraform/deployments/exposure/outputs.tf");
const previewDomainMain = await read("terraform/modules/cloud-run-preview-domain/main.tf");
const previewDomainOutputs = await read("terraform/modules/cloud-run-preview-domain/outputs.tf");
const previewDomainVariables = await read("terraform/modules/cloud-run-preview-domain/variables.tf");
for (const needle of [
  'network_endpoint_type = "SERVERLESS"',
  "service  = var.preview_service_name",
  'url_mask = "<tag>.${var.preview_domain}"',
  'load_balancing_scheme = "EXTERNAL_MANAGED"',
  'min_tls_version = "TLS_1_2"',
  'profile         = "MODERN"',
  'type            = "PER_PROJECT_RECORD"',
  "domains            = [local.wildcard_domain]",
  'port_range            = "443"',
]) {
  requireContains(
    "terraform/modules/cloud-run-preview-domain/main.tf",
    previewDomainMain,
    needle,
    `Stable preview-domain module is missing security boundary: ${needle}`,
  );
}
for (const forbidden of ["allUsers", "allAuthenticatedUsers", "google_cloud_run_v2_service", "http_forwarding_rule"] ) {
  rejectContains(
    "terraform/modules/cloud-run-preview-domain/main.tf",
    previewDomainMain,
    forbidden,
    `Preview routing must not create or publicly bind a Cloud Run service: ${forbidden}`,
  );
}
if ([...previewDomainMain.matchAll(/deletion_policy\s*=\s*"PREVENT"/g)].length !== 11) {
  failures.push(
    "terraform/modules/cloud-run-preview-domain/main.tf: every preview frontend resource must retain provider-level deletion prevention.",
  );
}
rejectContains(
  "terraform/modules/cloud-run-preview-domain/variables.tf",
  previewDomainVariables,
  "url_mask",
  "The serverless NEG URL mask must remain fixed in trusted module code.",
);
for (const needle of [
  'var.repository_id == "280932482"',
  'toset(["preview.ycriticalhistory.org"])',
  'preview_service_name = "${local.deployment.service_name}-preview"',
]) {
  requireContains(
    "terraform/deployments/exposure/main.tf",
    exposureDeployment,
    needle,
    `Protected exposure root is missing the Critical-only preview boundary: ${needle}`,
  );
}
requireContains(
  "terraform/modules/cloud-run-preview-domain/outputs.tf",
  previewDomainOutputs,
  'value       = "https://pr-N.${var.preview_domain}"',
  "The operator-facing preview URL pattern must stay tied to workflow-created pr-N tags.",
);
requireContains(
  "terraform/deployments/exposure/outputs.tf",
  exposureOutputs,
  'module.preview_domain["preview.ycriticalhistory.org"].dns_records',
  "The protected exposure plan must emit the exact DNS changes for owner review.",
);
rejectContains(
  "terraform/deployments/exposure/outputs.tf",
  exposureOutputs,
  "try(",
  "Critical preview output evaluation errors must fail the protected plan instead of becoming null.",
);
requireContains(
  "terraform/deployments/prod/main.tf",
  productionDeployment,
  'preview_ingress                          = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"',
  "Critical History previews must reject direct public run.app ingress after the frontend exists.",
);
for (const needle of [
  'alias                           = "no_attribution"',
  "google.no_attribution = google.no_attribution",
]) {
  requireContains(
    "terraform/deployments/prod/main.tf",
    productionDeployment,
    needle,
    "The trusted production root must preserve the historical domain-mapping provider address during migration.",
  );
}
for (const needle of [
  'medlock_ownership_enabled = var.repository_id == "1025243085"',
  "RECAPTCHA_SITE_KEY = one(google_recaptcha_enterprise_key.waitlist[*].name)",
  'resource "google_firestore_field" "waitlist_entry_ttl"',
  'resource "google_firestore_field" "waitlist_quota_ttl"',
  'resource "google_identity_platform_config" "default"',
  'resource "google_recaptcha_enterprise_key" "waitlist"',
]) {
  requireContains(
    "terraform/deployments/prod/main.tf",
    productionDeployment,
    needle,
    `The trusted production root is missing the Medlock ownership resource: ${needle}`,
  );
}
rejectContains(
  "terraform/deployments/prod/main.tf",
  productionDeployment,
  'resource "google_project_service"',
  "API enablement must have one Terraform owner in bootstrap state, never a second owner in production state.",
);
for (const needle of [
  "runtime_secret_accessor_ids              = []",
  'RUNSETTA_OFFLINE   = "1"',
  'RUNSETTA_TTS_MODEL = "gpt-4o-mini-tts"',
  'RUNSETTA_TTS_VOICE = "marin"',
]) {
  requireContains(
    "terraform/deployments/prod/main.tf",
    productionDeployment,
    needle,
    `The immutable Runsetta offline boundary is missing: ${needle}`,
  );
}
for (const needle of [
  '"waitlist-identity-keyset"',
  "runtime_secret_version_adder_ids = [",
  "runtime_secret_version_adder_ids               = local.deployment.runtime_secret_version_adder_ids",
]) {
  requireContains(
    "terraform/deployments/prod/main.tf",
    productionDeployment,
    needle,
    `The exact Medlock Secret Manager deployment boundary is missing: ${needle}`,
  );
}
const medlockBootstrapDeployment = sectionBetween(
  bootstrapDeploymentRoot,
  '    "1025243085" = {',
  '    "280932482" = {',
);
requireContains(
  "terraform/deployments/bootstrap/main.tf",
  medlockBootstrapDeployment,
  '"secretmanager.googleapis.com"',
  "Medlock must enable Secret Manager before the exact-version runtime binding is applied.",
);
if (productionDeployment.split("runtime_secret_version_adder_ids         = []").length - 1 !== 3) {
  failures.push(
    "terraform/deployments/prod/main.tf: Every non-Medlock production deploy identity must retain an empty secret-version-adder set.",
  );
}
for (const [publisherResource, publisherVariable, formerDeployResource] of [
  ["prod_publisher_writer", "prod_publisher_service_account_email", "prod_deploy_writer"],
  ["preview_publisher_writer", "preview_publisher_service_account_email", "preview_deploy_writer"],
] as const) {
  requireContains(
    "terraform/modules/cloud-run-service/main.tf",
    moduleMain,
    `resource "google_artifact_registry_repository_iam_member" "${publisherResource}"`,
    "Artifact Registry Writer must be repository-scoped to a dedicated publisher resource.",
  );
  requireContains(
    "terraform/modules/cloud-run-service/main.tf",
    moduleMain,
    `member     = "serviceAccount:${"${var."}${publisherVariable}}"`,
    "Artifact Registry Writer must belong only to the publisher identity.",
  );
  rejectContains(
    "terraform/modules/cloud-run-service/main.tf",
    moduleMain,
    `resource "google_artifact_registry_repository_iam_member" "${formerDeployResource}" {`,
    "Deploy/operator identities must not retain Artifact Registry Writer resources.",
  );
}
for (const [readerResource, readerVariable, repositoryResource] of [
  ["prod_deploy_reader", "prod_deploy_service_account_email", "site"],
  ["preview_deploy_reader", "preview_deploy_service_account_email", "preview"],
] as const) {
  const reader = sectionBetween(
    moduleMain,
    `resource "google_artifact_registry_repository_iam_member" "${readerResource}"`,
    "\n}\n",
  );
  requireContains(
    "terraform/modules/cloud-run-service/main.tf",
    reader,
    'role       = "roles/artifactregistry.reader"',
    "Cloud Run deployers need only the documented repository-scoped Artifact Registry Reader role.",
  );
  requireContains(
    "terraform/modules/cloud-run-service/main.tf",
    reader,
    `member     = "serviceAccount:${"${var."}${readerVariable}}"`,
    "Artifact Registry Reader must belong only to the matching deploy identity.",
  );
  requireContains(
    "terraform/modules/cloud-run-service/main.tf",
    reader,
    `repository = google_artifact_registry_repository.${repositoryResource}.repository_id`,
    "Artifact Registry Reader must remain scoped to the matching image repository.",
  );
  rejectContains(
    "terraform/modules/cloud-run-service/main.tf",
    reader,
    'roles/artifactregistry.writer',
    "Deploy identities must not receive Artifact Registry upload or delete permissions.",
  );
}
const repositoryIamMembers = [
  ...allServiceModuleTerraform.matchAll(
    /resource\s+"google_artifact_registry_repository_iam_member"\s+"([^"]+)"/g,
  ),
]
  .map((match) => match[1])
  .sort();
const approvedRepositoryIamMembers = [
  "deployment_parity_preview_image_reader",
  "deployment_parity_prod_image_reader",
  "preview_commit_preview_image_reader",
  "preview_commit_prod_image_reader",
  "preview_deploy_prod_image_reader",
  "preview_deploy_reader",
  "preview_publisher_writer",
  "prod_deploy_reader",
  "prod_publisher_writer",
].sort();
if (JSON.stringify(repositoryIamMembers) !== JSON.stringify(approvedRepositoryIamMembers)) {
  failures.push(
    `terraform/modules/cloud-run-service/main.tf: Repository IAM resources must be exactly ${approvedRepositoryIamMembers.join(", ")}; found ${repositoryIamMembers.join(", ")}.`,
  );
}
for (const forbiddenResource of [
  /resource\s+"google_artifact_registry_repository_iam_(?:binding|policy)"/,
  /resource\s+"google_project_iam_(?:member|binding|policy)"/,
]) {
  if (forbiddenResource.test(allServiceModuleTerraform)) {
    failures.push(
      `terraform/modules/cloud-run-service/main.tf: ${forbiddenResource.source} is forbidden; IAM must remain in the enumerated exact-resource grants.`,
    );
  }
}
const allIamResources = [
  ...allServiceModuleTerraform.matchAll(
    /resource\s+"(google_[^"]+_iam_(?:member|binding|policy))"\s+"([^"]+)"/g,
  ),
]
  .map((match) => `${match[1]}.${match[2]}`)
  .sort();
const approvedIamResources = [
  "google_artifact_registry_repository_iam_member.deployment_parity_preview_image_reader",
  "google_artifact_registry_repository_iam_member.deployment_parity_prod_image_reader",
  "google_artifact_registry_repository_iam_member.preview_commit_preview_image_reader",
  "google_artifact_registry_repository_iam_member.preview_commit_prod_image_reader",
  "google_artifact_registry_repository_iam_member.preview_deploy_prod_image_reader",
  "google_artifact_registry_repository_iam_member.preview_deploy_reader",
  "google_artifact_registry_repository_iam_member.preview_publisher_writer",
  "google_artifact_registry_repository_iam_member.prod_deploy_reader",
  "google_artifact_registry_repository_iam_member.prod_publisher_writer",
  "google_cloud_run_v2_service_iam_member.deployment_parity_preview_reader",
  "google_cloud_run_v2_service_iam_member.deployment_parity_prod_reader",
  "google_cloud_run_v2_service_iam_member.preview_commit",
  "google_cloud_run_v2_service_iam_member.preview_commit_prod_reader",
  "google_cloud_run_v2_service_iam_member.preview_deploy",
  "google_cloud_run_v2_service_iam_member.prod_deploy",
  "google_secret_manager_secret_iam_member.prod_deploy_version_adder",
  "google_secret_manager_secret_iam_member.prod_deploy_version_metadata_reader",
  "google_secret_manager_secret_iam_member.runtime_accessor",
].sort();
if (JSON.stringify(allIamResources) !== JSON.stringify(approvedIamResources)) {
  failures.push(
    `terraform/modules/cloud-run-service: IAM resources must be exactly ${approvedIamResources.join(", ")}; found ${allIamResources.join(", ")}.`,
  );
}
const exactIamBlocks = [
  [
    'resource "google_artifact_registry_repository_iam_member" "prod_publisher_writer" {',
    "  project    = var.project_id",
    "  location   = google_artifact_registry_repository.site.location",
    "  repository = google_artifact_registry_repository.site.repository_id",
    '  role       = "roles/artifactregistry.writer"',
    '  member     = "serviceAccount:${var.prod_publisher_service_account_email}"',
    "}",
  ].join("\n"),
  [
    'resource "google_artifact_registry_repository_iam_member" "preview_publisher_writer" {',
    "  project    = var.project_id",
    "  location   = google_artifact_registry_repository.preview.location",
    "  repository = google_artifact_registry_repository.preview.repository_id",
    '  role       = "roles/artifactregistry.writer"',
    '  member     = "serviceAccount:${var.preview_publisher_service_account_email}"',
    "}",
  ].join("\n"),
  [
    'resource "google_artifact_registry_repository_iam_member" "prod_deploy_reader" {',
    "  project    = var.project_id",
    "  location   = google_artifact_registry_repository.site.location",
    "  repository = google_artifact_registry_repository.site.repository_id",
    '  role       = "roles/artifactregistry.reader"',
    '  member     = "serviceAccount:${var.prod_deploy_service_account_email}"',
    "}",
  ].join("\n"),
  [
    'resource "google_artifact_registry_repository_iam_member" "preview_deploy_reader" {',
    "  project    = var.project_id",
    "  location   = google_artifact_registry_repository.preview.location",
    "  repository = google_artifact_registry_repository.preview.repository_id",
    '  role       = "roles/artifactregistry.reader"',
    '  member     = "serviceAccount:${var.preview_deploy_service_account_email}"',
    "}",
  ].join("\n"),
  [
    'resource "google_artifact_registry_repository_iam_member" "deployment_parity_prod_image_reader" {',
    "  project    = var.project_id",
    "  location   = google_artifact_registry_repository.site.location",
    "  repository = google_artifact_registry_repository.site.repository_id",
    '  role       = "projects/${var.project_id}/roles/deploymentParityImageDownloader"',
    '  member     = "serviceAccount:${var.deployment_parity_reader_service_account_email}"',
    "}",
  ].join("\n"),
  [
    'resource "google_artifact_registry_repository_iam_member" "deployment_parity_preview_image_reader" {',
    "  project    = var.project_id",
    "  location   = google_artifact_registry_repository.preview.location",
    "  repository = google_artifact_registry_repository.preview.repository_id",
    '  role       = "projects/${var.project_id}/roles/deploymentParityImageDownloader"',
    '  member     = "serviceAccount:${var.deployment_parity_reader_service_account_email}"',
    "}",
  ].join("\n"),
  [
    'resource "google_artifact_registry_repository_iam_member" "preview_commit_prod_image_reader" {',
    "  project    = var.project_id",
    "  location   = google_artifact_registry_repository.site.location",
    "  repository = google_artifact_registry_repository.site.repository_id",
    '  role       = "projects/${var.project_id}/roles/deploymentParityImageDownloader"',
    '  member     = "serviceAccount:${var.preview_commit_service_account_email}"',
    "}",
  ].join("\n"),
  [
    'resource "google_artifact_registry_repository_iam_member" "preview_commit_preview_image_reader" {',
    "  project    = var.project_id",
    "  location   = google_artifact_registry_repository.preview.location",
    "  repository = google_artifact_registry_repository.preview.repository_id",
    '  role       = "projects/${var.project_id}/roles/deploymentParityImageDownloader"',
    '  member     = "serviceAccount:${var.preview_commit_service_account_email}"',
    "}",
  ].join("\n"),
  [
    'resource "google_secret_manager_secret_iam_member" "runtime_accessor" {',
    "  for_each = var.runtime_secret_accessor_ids",
    "",
    "  project   = var.project_id",
    "  secret_id = google_secret_manager_secret.runtime[each.value].secret_id",
    '  role      = "roles/secretmanager.secretAccessor"',
    '  member    = "serviceAccount:${var.runtime_service_account_email}"',
    "}",
  ].join("\n"),
  [
    'resource "google_secret_manager_secret_iam_member" "prod_deploy_version_adder" {',
    "  for_each = var.runtime_secret_version_adder_ids",
    "",
    "  project   = var.project_id",
    "  secret_id = google_secret_manager_secret.runtime[each.value].secret_id",
    '  role      = "roles/secretmanager.secretVersionAdder"',
    '  member    = "serviceAccount:${var.prod_deploy_service_account_email}"',
    "}",
  ].join("\n"),
  [
    'resource "google_cloud_run_v2_service_iam_member" "prod_deploy" {',
    "  project  = var.project_id",
    "  location = google_cloud_run_v2_service.site.location",
    "  name     = google_cloud_run_v2_service.site.name",
    '  role     = "projects/${var.project_id}/roles/cloudRunRevisionDeployer"',
    '  member   = "serviceAccount:${var.prod_deploy_service_account_email}"',
    "}",
  ].join("\n"),
  [
    'resource "google_cloud_run_v2_service_iam_member" "preview_deploy" {',
    "  project  = var.project_id",
    "  location = google_cloud_run_v2_service.preview.location",
    "  name     = google_cloud_run_v2_service.preview.name",
    '  role     = "projects/${var.project_id}/roles/cloudRunRevisionDeployer"',
    '  member   = "serviceAccount:${var.preview_deploy_service_account_email}"',
    "}",
  ].join("\n"),
  [
    'resource "google_cloud_run_v2_service_iam_member" "preview_commit" {',
    "  project  = var.project_id",
    "  location = google_cloud_run_v2_service.preview.location",
    "  name     = google_cloud_run_v2_service.preview.name",
    '  role     = "projects/${var.project_id}/roles/previewTrafficCommitter"',
    '  member   = "serviceAccount:${var.preview_commit_service_account_email}"',
    "}",
  ].join("\n"),
  [
    'resource "google_cloud_run_v2_service_iam_member" "deployment_parity_prod_reader" {',
    "  project  = var.project_id",
    "  location = google_cloud_run_v2_service.site.location",
    "  name     = google_cloud_run_v2_service.site.name",
    '  role     = "projects/${var.project_id}/roles/deploymentParityCloudRunReader"',
    '  member   = "serviceAccount:${var.deployment_parity_reader_service_account_email}"',
    "}",
  ].join("\n"),
  [
    'resource "google_cloud_run_v2_service_iam_member" "deployment_parity_preview_reader" {',
    "  project  = var.project_id",
    "  location = google_cloud_run_v2_service.preview.location",
    "  name     = google_cloud_run_v2_service.preview.name",
    '  role     = "projects/${var.project_id}/roles/deploymentParityCloudRunReader"',
    '  member   = "serviceAccount:${var.deployment_parity_reader_service_account_email}"',
    "}",
  ].join("\n"),
];
for (const exactIamBlock of exactIamBlocks) {
  if (moduleMain.split(exactIamBlock).length - 1 !== 1) {
    failures.push(
      `terraform/modules/cloud-run-service/main.tf: IAM block must match its exact canonical contract: ${exactIamBlock.split("\n")[0]}`,
    );
  }
}
for (const [resource, identity, service] of [
  ["prod_deploy", "prod_deploy_service_account_email", "site"],
  ["preview_deploy", "preview_deploy_service_account_email", "preview"],
] as const) {
  const serviceGrant = sectionBetween(
    moduleMain,
    `resource "google_cloud_run_v2_service_iam_member" "${resource}"`,
    "\n}\n",
  );
  for (const needle of [
    'role     = "projects/${var.project_id}/roles/cloudRunRevisionDeployer"',
    `member   = "serviceAccount:${"${var."}${identity}}"`,
    `name     = google_cloud_run_v2_service.${service}.name`,
  ]) {
    requireContains(
      "terraform/modules/cloud-run-service/main.tf",
      serviceGrant,
      needle,
      `The exact ${resource} service grant is missing: ${needle}`,
    );
  }
}
const runtimeAccessor = sectionBetween(
  moduleMain,
  'resource "google_secret_manager_secret_iam_member" "runtime_accessor"',
  "\n}\n",
);
for (const needle of [
  'role      = "roles/secretmanager.secretAccessor"',
  'member    = "serviceAccount:${var.runtime_service_account_email}"',
]) {
  requireContains(
    "terraform/modules/cloud-run-service/main.tf",
    runtimeAccessor,
    needle,
    `The runtime-only secret grant is missing: ${needle}`,
  );
}
const prodDeployVersionAdder = sectionBetween(
  moduleMain,
  'resource "google_secret_manager_secret_iam_member" "prod_deploy_version_adder"',
  "\n}\n",
);
for (const needle of [
  'role      = "roles/secretmanager.secretVersionAdder"',
  'member    = "serviceAccount:${var.prod_deploy_service_account_email}"',
]) {
  requireContains(
    "terraform/modules/cloud-run-service/main.tf",
    prodDeployVersionAdder,
    needle,
    `The production deploy version-adder grant is missing: ${needle}`,
  );
}
if (allServiceModuleTerraform.split("preview_operator_service_account_email").length - 1 !== 1) {
  failures.push(
    "terraform/modules/cloud-run-service: The deprecated preview operator input must remain declared exactly once and receive no IAM grant.",
  );
}
rejectContains(
  "terraform/modules/cloud-run-service/main.tf",
  moduleMain,
  "preview_operator_service_account_email",
  "The retired preview operator must receive no Cloud Run or Artifact Registry grant.",
);
for (const publisherVariable of [
  "prod_publisher_service_account_email",
  "preview_publisher_service_account_email",
]) {
  rejectContains(
    "terraform/modules/cloud-run-service/main.tf",
    sectionFrom(moduleMain, 'resource "google_cloud_run_v2_service_iam_member" "prod_deploy"'),
    publisherVariable,
    "Artifact Registry publishers must have zero Cloud Run role grants.",
  );
}

// The protected apply disables every consumer workload identity pool for the
// length of its window. Two concurrent runs against different targets would
// therefore capture and restore each other's pool state, and the first to finish
// would re-open federation while the second still held privilege. The group must
// stay fleet-global and must not interpolate the target.
requireContains(
  ".github/workflows/protected-bootstrap-implementation.yml",
  await read(".github/workflows/protected-bootstrap-implementation.yml"),
  "group: protected-owner-terraform-federation",
  "Protected runs must serialise across the whole fleet while federation is quarantined.",
);
rejectContains(
  ".github/workflows/protected-bootstrap-implementation.yml",
  await read(".github/workflows/protected-bootstrap-implementation.yml"),
  "group: protected-owner-terraform-${{ inputs.target_repository }}",
  "A per-target concurrency group lets two protected runs restore each other's federation state.",
);

const bootstrapMain = await read("terraform/modules/bootstrap/main.tf");
const bootstrapVariables = await read("terraform/modules/bootstrap/variables.tf");
if (
  createHash("sha256").update(bootstrapMain).digest("hex") !==
  "912f75489dfd4e11bc645c706655d4d27d72f7d02838759435833855fc0d1801"
) {
  failures.push(
    "terraform/modules/bootstrap/main.tf: Privileged bootstrap content changed; review it and both independent hash contracts together.",
  );
}
const bootstrapIamResources = [
  ...bootstrapMain.matchAll(
    /^resource\s+"(google_[^"]+_iam_(?:member|binding|policy))"\s+"([^"]+)"/gm,
  ),
]
  .map((match) => `${match[1]}.${match[2]}`)
  .sort();
const approvedBootstrapIamResources = [
  "google_project_iam_binding.editor_absent",
  "google_project_iam_member.preview_iam_auditors",
  "google_project_iam_member.prod_deploy_waitlist_recaptcha_key_reader",
  "google_project_iam_member.runtime_project_roles",
  "google_project_iam_member.runtime_waitlist_challenge_sender",
  "google_project_iam_member.terraform_convergence_reader",
  "google_service_account_iam_member.canary_wif_preview_deploy_workflow_sha",
  "google_service_account_iam_member.canary_wif_preview_operator_workflow_sha",
  "google_service_account_iam_member.canary_wif_preview_publish_workflow_sha",
  "google_service_account_iam_member.canary_wif_prod_publish_workflow_sha",
  "google_service_account_iam_member.canary_wif_prod_workflow_sha",
  "google_service_account_iam_member.canary_wif_terraform_workflow_sha",
  "google_service_account_iam_member.deployment_parity_wif_preview_workflow_sha",
  "google_service_account_iam_member.deployment_parity_wif_prod_workflow_sha",
  "google_service_account_iam_member.preview_commit_wif_preview_operations_workflow_sha",
  "google_service_account_iam_member.preview_commit_wif_prod_workflow_sha",
  "google_service_account_iam_member.preview_commit_wif_workflow_sha",
  "google_service_account_iam_member.preview_deploy_uses_preview_runtime",
  "google_service_account_iam_member.preview_deploy_wif_repo",
  "google_service_account_iam_member.preview_deploy_wif_prod_workflow_sha",
  "google_service_account_iam_member.preview_deploy_wif_workflow_sha",
  "google_service_account_iam_member.preview_operator_wif_repo",
  "google_service_account_iam_member.preview_operator_wif_workflow_sha",
  "google_service_account_iam_member.preview_iam_audit_wif_preview_operations_workflow_sha",
  "google_service_account_iam_member.preview_iam_audit_wif_workflow_sha",
  "google_service_account_iam_member.preview_publisher_wif_workflow_sha",
  "google_service_account_iam_member.prod_deploy_uses_runtime",
  "google_service_account_iam_member.prod_deploy_wif_prod_env",
  "google_service_account_iam_member.prod_deploy_wif_workflow_sha",
  "google_service_account_iam_member.prod_publisher_wif_workflow_sha",
  "google_service_account_iam_member.terraform_wif_prod_env",
  "google_service_account_iam_member.terraform_wif_workflow_sha",
  "google_storage_bucket_iam_binding.bootstrap_state_no_legacy_access",
  "google_storage_bucket_iam_binding.deployment_parity_transition_no_legacy_access",
  "google_storage_bucket_iam_binding.terraform_state_logs_no_legacy_access",
  "google_storage_bucket_iam_binding.terraform_state_no_legacy_access",
  "google_storage_bucket_iam_member.terraform_state_access_logs_writer",
  "google_storage_bucket_iam_member.preview_commit_transition_coordinator",
  "google_storage_bucket_iam_member.terraform_state_reader",
].sort();
if (
  JSON.stringify(bootstrapIamResources) !== JSON.stringify(approvedBootstrapIamResources)
) {
  failures.push(
    `terraform/modules/bootstrap/main.tf: IAM resources must be exactly ${approvedBootstrapIamResources.join(", ")}; found ${bootstrapIamResources.join(", ")}.`,
  );
}
for (const exactProjectIamBlock of [
  [
    'resource "google_project_iam_member" "terraform_convergence_reader" {',
    "  project = var.project_id",
    "  role    = google_project_iam_custom_role.terraform_convergence_reader.name",
    '  member  = "serviceAccount:${google_service_account.terraform.email}"',
    "}",
  ].join("\n"),
  [
    'resource "google_project_iam_member" "runtime_project_roles" {',
    "  for_each = var.runtime_project_roles",
    "",
    "  project = var.project_id",
    "  role    = each.value",
    '  member  = "serviceAccount:${google_service_account.runtime.email}"',
    "}",
  ].join("\n"),
  [
    'resource "google_project_iam_binding" "editor_absent" {',
    "  #checkov:skip=CKV_GCP_49:An authoritative empty binding removes impersonation-capable basic-role members; it grants no principal access.",
    "  #checkov:skip=CKV_GCP_117:An authoritative empty Editor binding removes the basic role and prevents drift; it grants no principal access.",
    "  project = var.project_id",
    '  role    = "roles/editor"',
    "  members = []",
    "",
    "  depends_on = [google_project_service.required]",
    "}",
  ].join("\n"),
]) {
  if (bootstrapMain.split(exactProjectIamBlock).length - 1 !== 1) {
    failures.push(
      `terraform/modules/bootstrap/main.tf: Project IAM block must match its exact canonical contract: ${exactProjectIamBlock.split("\n")[0]}`,
    );
  }
}
if (/roles\/artifactregistry\.(?:admin|reader|writer)/.test(bootstrapMain)) {
  failures.push(
    "terraform/modules/bootstrap/main.tf: Bootstrap must not grant predefined Artifact Registry roles.",
  );
}
requireContains(
  "terraform/modules/bootstrap/main.tf",
  sectionBetween(
    bootstrapMain,
    'resource "google_project_iam_member" "preview_iam_auditors"',
    '\n}\n',
  ),
  "role    = google_project_iam_custom_role.preview_iam_auditor.name",
  "The migration-stable preview operator may receive only the dedicated read-only IAM-auditor project role.",
);
const previewTrafficImageDownloaderRole = sectionBetween(
  bootstrapMain,
  'resource "google_project_iam_custom_role" "preview_traffic_image_downloader"',
  "\n}\n",
);
const expectedPreviewTrafficImageDownloaderRole = [
  'resource "google_project_iam_custom_role" "preview_traffic_image_downloader" {',
  "  project     = var.project_id",
  '  role_id     = "previewTrafficImageDownloader"',
  '  title       = "Legacy Preview Traffic Image Downloader"',
  '  description = "Transition-only role definition retained until the retired preview operator repository binding converges away."',
  "  permissions = [",
  '    "artifactregistry.repositories.downloadArtifacts",',
  "  ]",
  "",
  "  depends_on = [google_project_service.required]",
  "}",
].join("\n");
if (
  bootstrapMain.split(expectedPreviewTrafficImageDownloaderRole).length - 1 !== 1 ||
  [...bootstrapMain.matchAll(
    /^resource\s+"google_project_iam_custom_role"\s+"preview_traffic_image_downloader"\s*\{/gm,
  )].length !== 1
) {
  failures.push(
    "terraform/modules/bootstrap/main.tf: previewTrafficImageDownloader must match its one exact canonical resource block.",
  );
}
for (const needle of [
  'role_id     = "previewTrafficImageDownloader"',
  'description = "Transition-only role definition retained until the retired preview operator repository binding converges away."',
  '"artifactregistry.repositories.downloadArtifacts",',
]) {
  requireContains(
    "terraform/modules/bootstrap/main.tf",
    previewTrafficImageDownloaderRole,
    needle,
    `The preview traffic image downloader role is missing: ${needle}`,
  );
}
rejectContains(
  "terraform/modules/bootstrap/main.tf",
  previewTrafficImageDownloaderRole,
  "ignore_changes",
  "The one-permission preview role must converge out-of-band permission drift.",
);
const previewTrafficPermissions = [
  ...previewTrafficImageDownloaderRole.matchAll(/"([a-z]+\.[A-Za-z]+\.[A-Za-z]+)",/g),
].map((match) => match[1]);
if (
  previewTrafficImageDownloaderRole.split("permissions =").length - 1 !== 1 ||
  !/permissions\s*=\s*\[\s*"artifactregistry\.repositories\.downloadArtifacts",?\s*\]/.test(
    previewTrafficImageDownloaderRole,
  )
) {
  failures.push(
    "terraform/modules/bootstrap/main.tf: previewTrafficImageDownloader permissions must be one literal singleton list.",
  );
}
if (
  JSON.stringify(previewTrafficPermissions) !==
  JSON.stringify(["artifactregistry.repositories.downloadArtifacts"])
) {
  failures.push(
    `terraform/modules/bootstrap/main.tf: previewTrafficImageDownloader must contain exactly artifactregistry.repositories.downloadArtifacts; found ${previewTrafficPermissions.join(", ")}.`,
  );
}
requireContains(
  "terraform/modules/bootstrap/variables.tf",
  bootstrapVariables,
  "Retired preview traffic identity retained only for an explicitly declared workflow-SHA transition; receives no steady-state operational grants.",
  "The retired preview operator description must disclose its transition-only boundary.",
);
requireContains(
  "README.md",
  readme,
  "active SHA binds the distinct",
  "The identity overview must disclose the active and transition preview-operations split.",
);
requireContains(
  "docs/security-rollout.md",
  securityRollout,
  "active/new SHA's distinct preview-operator workflow attribute",
  "The rollout guide must disclose the active and transition preview-operations split.",
);
for (const outputPath of [
  "terraform/modules/bootstrap/outputs.tf",
  "terraform/deployments/bootstrap/outputs.tf",
  "templates/app/infra/terraform/bootstrap/outputs.tf",
]) {
  const output = await read(outputPath);
  requireContains(
    outputPath,
    output,
    "Retired transition-only preview operator service account; receives no steady-state operational grants.",
    "The preview operator output must disclose its retired transition-only status.",
  );
  requireContains(
    outputPath,
    output,
    "only declared exact-secret version-add grants.",
    "The production deploy output must disclose its exact-secret version-add boundary.",
  );
}
const activePreviewOperationsShas = sectionBetween(
  bootstrapVariables,
  'variable "preview_operations_active_workflow_shas"',
  "\n}\n",
);
for (const boundary of [
  "length(var.preview_operations_active_workflow_shas) > 0",
  "setintersection(var.preview_operations_active_workflow_shas, var.preview_operator_transition_workflow_shas)",
  "setunion(var.preview_operations_active_workflow_shas, var.preview_operator_transition_workflow_shas) == var.trusted_platform_workflow_shas",
]) {
  requireContains(
    "terraform/modules/bootstrap/variables.tf",
    activePreviewOperationsShas,
    boundary,
    `Active preview-operations SHA partition validation is missing: ${boundary}`,
  );
}
const transitionPreviewOperatorShas = sectionBetween(
  bootstrapVariables,
  'variable "preview_operator_transition_workflow_shas"',
  "\n}\n",
);
for (const boundary of [
  "default     = []",
  "length(var.preview_operator_transition_workflow_shas) <= 1",
  "setsubtract(var.preview_operator_transition_workflow_shas, var.trusted_platform_workflow_shas)",
]) {
  requireContains(
    "terraform/modules/bootstrap/variables.tf",
    transitionPreviewOperatorShas,
    boundary,
    `Transition preview-operator SHA validation is missing: ${boundary}`,
  );
}
requireContains(
  "terraform/modules/bootstrap/variables.tf",
  bootstrapVariables,
  'variable "manage_automatic_default_service_account_grants_policy"',
  "Organization-policy management must be an explicit protected bootstrap decision.",
);
const organizationPolicyVariableBlock = sectionBetween(
  bootstrapVariables,
  'variable "manage_automatic_default_service_account_grants_policy"',
  "\n}\n",
);
if (/^\s*default\s*=/m.test(organizationPolicyVariableBlock)) {
  failures.push(
    "terraform/modules/bootstrap/variables.tf: Organization-policy management must be an explicit decision at every protected module call.",
  );
}
requireContains(
  "terraform/modules/bootstrap/main.tf",
  sectionBetween(
    bootstrapMain,
    'resource "google_org_policy_policy" "disable_automatic_default_service_account_grants"',
    "\n}\n",
  ),
  "count = var.manage_automatic_default_service_account_grants_policy ? 1 : 0",
  "The organization policy must not be planned for a standalone project.",
);
requireContains(
  "terraform/modules/bootstrap/main.tf",
  bootstrapMain,
  "effective_required_services = setunion(",
  "The Org Policy API must follow the explicit organization-policy management decision.",
);
requireContains(
  "terraform/modules/bootstrap/main.tf",
  bootstrapMain,
  "from = google_org_policy_policy.disable_automatic_default_service_account_grants",
  "Existing organization-backed state must migrate to the counted policy address without replacement.",
);
requireContains(
  "terraform/modules/bootstrap/main.tf",
  bootstrapMain,
  "to   = google_org_policy_policy.disable_automatic_default_service_account_grants[0]",
  "Existing organization-backed state must migrate to the counted policy address without replacement.",
);
requireContains(
  "terraform/modules/bootstrap/main.tf",
  bootstrapMain,
  '"(${local.trusted_workflow_sha_condition})",',
  "The WIF provider itself must reject unapproved workflow SHAs.",
);
for (const attemptGuard of [
  '"has(assertion.run_attempt)",',
  '"assertion.run_attempt == \'1\'",',
  "has(assertion.run_attempt) && assertion.run_attempt == '1' && assertion.runner_environment == 'github-hosted'",
]) {
  requireContains(
    "terraform/modules/bootstrap/main.tf",
    bootstrapMain,
    attemptGuard,
    "Both exact and legacy WIF provider paths must reject workflow reruns.",
  );
}
for (const boundary of [
  'account_id   = "gha-prod-publish"',
  'account_id   = "gha-preview-publish"',
  'account_id   = "gha-preview-operator"',
  'account_id   = "gha-preview-commit"',
  '"attribute.preview_deploy_workflow_sha"',
  '"attribute.preview_operator_workflow_sha"',
  '"attribute.prod_publish_workflow_sha"',
  '"attribute.preview_publish_workflow_sha"',
  '"attribute.legacy_preview_deploy"',
  '"attribute.legacy_preview_operator"',
  '"attribute.legacy_prod_deploy"',
  '"attribute.legacy_terraform"',
  'resource "google_service_account_iam_member" "prod_publisher_wif_workflow_sha"',
  'resource "google_service_account_iam_member" "preview_publisher_wif_workflow_sha"',
  'resource "google_service_account_iam_member" "preview_commit_wif_workflow_sha"',
  'resource "google_service_account_iam_member" "preview_commit_wif_preview_operations_workflow_sha"',
  'resource "google_service_account_iam_member" "preview_operator_wif_workflow_sha"',
  'resource "google_service_account_iam_member" "canary_wif_preview_deploy_workflow_sha"',
  'resource "google_service_account_iam_member" "canary_wif_preview_operator_workflow_sha"',
  'resource "google_service_account_iam_member" "canary_wif_prod_publish_workflow_sha"',
  'resource "google_service_account_iam_member" "canary_wif_preview_publish_workflow_sha"',
]) {
  requireContains(
    "terraform/modules/bootstrap/main.tf",
    bootstrapMain,
    boundary,
    `Publisher/deployer WIF isolation is missing boundary: ${boundary}`,
  );
}
for (const forbiddenMapping of ['"attribute.environment"', '"attribute.repository_id"']) {
  rejectContains(
    "terraform/modules/bootstrap/main.tf",
    bootstrapMain,
    forbiddenMapping,
    `Compatibility WIF must not expose aggregate cross-identity mapping ${forbiddenMapping}.`,
  );
}
for (const boundary of [
  'preview_operator_transition_workflow_sha_condition = length(var.preview_operator_transition_workflow_shas) == 0 ? "false"',
  "for sha in sort(tolist(var.preview_operator_transition_workflow_shas))",
  '"attribute.legacy_preview_operator"       = "(${local.legacy_preview_operator_attribute_condition}) ? assertion.repository_id : \'denied\'"',
]) {
  requireContains(
    "terraform/modules/bootstrap/main.tf",
    bootstrapMain,
    boundary,
    `Retired preview-operator compatibility trust must be restricted to the declared transition SHA set: ${boundary}`,
  );
}
for (const [binding, serviceAccount, attribute] of [
  ["prod_deploy_wif_workflow_sha", "prod_deploy", "prod_workflow_sha"],
  ["prod_publisher_wif_workflow_sha", "prod_publisher", "prod_publish_workflow_sha"],
  ["preview_deploy_wif_workflow_sha", "preview_deploy", "preview_deploy_workflow_sha"],
  [
    "preview_commit_wif_workflow_sha",
    "preview_commit",
    "preview_deploy_workflow_sha",
  ],
  [
    "preview_commit_wif_preview_operations_workflow_sha",
    "preview_commit",
    "preview_operator_workflow_sha",
  ],
  ["preview_operator_wif_workflow_sha", "preview_operator", "preview_operator_workflow_sha"],
  ["preview_publisher_wif_workflow_sha", "preview_publisher", "preview_publish_workflow_sha"],
  ["terraform_wif_workflow_sha", "terraform", "terraform_workflow_sha"],
] as const) {
  const block = sectionBetween(
    bootstrapMain,
    `resource "google_service_account_iam_member" "${binding}"`,
    "\n}\n",
  );
  requireContains(
    "terraform/modules/bootstrap/main.tf",
    block,
    `service_account_id = google_service_account.${serviceAccount}.name`,
    `Exact WIF binding ${binding} must target only ${serviceAccount}.`,
  );
  requireContains(
    "terraform/modules/bootstrap/main.tf",
    block,
    `/attribute.${attribute}/`,
    `Exact WIF binding ${binding} must use only ${attribute}.`,
  );
}
for (const [binding, forEach] of [
  [
    "preview_commit_wif_preview_operations_workflow_sha",
    "var.preview_operations_active_workflow_shas",
  ],
  ["preview_operator_wif_workflow_sha", "var.preview_operator_transition_workflow_shas"],
] as const) {
  requireContains(
    "terraform/modules/bootstrap/main.tf",
    sectionBetween(
      bootstrapMain,
      `resource "google_service_account_iam_member" "${binding}"`,
      "\n}\n",
    ),
    `for_each = ${forEach}`,
    `Preview-operations WIF binding ${binding} must use only ${forEach}.`,
  );
}
for (const [binding, serviceAccount, principal] of [
  ["prod_deploy_wif_prod_env", "prod_deploy", "legacy_prod_deploy_principal_set"],
  ["preview_deploy_wif_repo", "preview_deploy", "legacy_preview_deploy_principal_set"],
  ["preview_operator_wif_repo", "preview_operator", "legacy_preview_operator_principal_set"],
  ["terraform_wif_prod_env", "terraform", "legacy_terraform_principal_set"],
] as const) {
  const block = sectionBetween(
    bootstrapMain,
    `resource "google_service_account_iam_member" "${binding}"`,
    "\n}\n",
  );
  requireContains(
    "terraform/modules/bootstrap/main.tf",
    block,
    `service_account_id = google_service_account.${serviceAccount}.name`,
    `Legacy WIF binding ${binding} must target only ${serviceAccount}.`,
  );
  requireContains(
    "terraform/modules/bootstrap/main.tf",
    block,
    `member             = local.${principal}`,
    `Legacy WIF binding ${binding} must use only ${principal}.`,
  );
}
for (const forbiddenPublisherFallback of ["legacy_prod_publish", "legacy_preview_publish"]) {
  rejectContains(
    "terraform/modules/bootstrap/main.tf",
    bootstrapMain,
    forbiddenPublisherFallback,
    "Publisher identities must never receive a generic compatibility WIF attribute.",
  );
}
for (const publisher of ["prod_publisher", "preview_publisher"]) {
  rejectContains(
    "terraform/modules/bootstrap/main.tf",
    bootstrapMain,
    `member             = "serviceAccount:${"${google_service_account."}${publisher}.email}"`,
    "Publisher identities must not receive project roles or runtime service-account actAs.",
  );
}
rejectContains(
  "terraform/modules/bootstrap/main.tf",
  bootstrapMain,
  'member             = "serviceAccount:${google_service_account.preview_operator.email}"',
  "The preview traffic operator must not receive project roles or runtime service-account actAs.",
);
for (const forbidden of [
  "roles/artifactregistry.admin",
  "roles/run.admin",
  "roles/secretmanager.admin",
  "roles/datastore.owner",
  "roles/iam.serviceAccountTokenCreator",
  '"terraform_uses_runtime"',
  '"terraform_uses_preview_runtime"',
  '"terraform_uses_bootstrap_runtime"',
  '"preview_deploy_uses_runtime"',
]) {
  rejectContains(
    "terraform/modules/bootstrap/main.tf",
    bootstrapMain,
    forbidden,
    `The first protected bootstrap apply must remove legacy privilege: ${forbidden}`,
  );
}
const bootstrapDeployment = await read("terraform/deployments/bootstrap/main.tf");
requireContains(
  "terraform/deployments/bootstrap/main.tf",
  bootstrapDeployment,
  "manage_automatic_default_service_account_grants_policy = false",
  "The four registered standalone projects must not request organization-only authority.",
);
for (const boundary of [
  "preview_operations_active_workflow_shas   = local.preview_operations_active_workflow_shas",
  "preview_operator_transition_workflow_shas = local.preview_operator_transition_workflow_shas",
]) {
  requireContains(
    "terraform/deployments/bootstrap/main.tf",
    bootstrapDeployment,
    boundary,
    `The protected bootstrap root is missing the exact preview-operations transition partition: ${boundary}`,
  );
}
const templateBootstrapMain = await read("templates/app/infra/terraform/bootstrap/main.tf");
const templateBootstrapVariables = await read("templates/app/infra/terraform/bootstrap/variables.tf");
requireContains(
  "templates/app/infra/terraform/bootstrap/main.tf",
  templateBootstrapMain,
  "manage_automatic_default_service_account_grants_policy = var.manage_automatic_default_service_account_grants_policy",
  "Generic scaffolds must require an explicit organization-policy capability decision.",
);
for (const boundary of [
  "preview_operations_active_workflow_shas = [",
  "preview_operator_transition_workflow_shas              = []",
]) {
  requireContains(
    "templates/app/infra/terraform/bootstrap/main.tf",
    templateBootstrapMain,
    boundary,
    `Generic scaffolds must render the steady-state preview-operations partition: ${boundary}`,
  );
}
requireContains(
  "templates/app/infra/terraform/bootstrap/variables.tf",
  templateBootstrapVariables,
  'variable "manage_automatic_default_service_account_grants_policy"',
  "Generic scaffolds must expose the explicit organization-policy capability decision.",
);
const templateOrganizationPolicyVariableBlock = sectionBetween(
  templateBootstrapVariables,
  'variable "manage_automatic_default_service_account_grants_policy"',
  "\n}\n",
);
if (/^\s*default\s*=/m.test(templateOrganizationPolicyVariableBlock)) {
  failures.push(
    "templates/app/infra/terraform/bootstrap/variables.tf: A generic scaffold must not silently choose a standalone or organization-backed policy mode.",
  );
}
const forbiddenPreMigrationWorkflowShas = [
  "734d0cd02187f88c6e91263f127dc3f4c0709feb",
  "1378a3e81a5e74c71f2adfd5548b430bb008490e",
  "37bd4b1beea8802ec85c38d69ea08d5992c75a50",
  "42435a3c4c5c063a342765ef7c85047224217fe2",
  "7f01d9f008a7757df12f13ac8fa0f261600cf21a",
  "4f032955477c26b942fdd4f1b01f5272380390ea",
  "92c73184bc527388b5e10ccb5e4f0222a84e68b5",
  "33ab9b9a5f3d8a0553372980c22540cad001f776",
];
const platformTool = await read("tools/platform.ts");
for (const sha of forbiddenPreMigrationWorkflowShas) {
  if (bootstrapDeployment.split(sha).length - 1 !== 2) {
    failures.push(
      `terraform/deployments/bootstrap/main.tf: pre-migration SHA ${sha} must be denied for both active and transition trust.`,
    );
  }
  requireContains(
    "tools/platform.ts",
    platformTool,
    sha,
    `Doctor must reject pre-migration workflow SHA ${sha}.`,
  );
}
for (const forbidden of [
  "roles/artifactregistry.admin",
  "roles/run.admin",
  "roles/secretmanager.admin",
  "roles/datastore.owner",
  "terraform_project_roles",
]) {
  rejectContains(
    "terraform/deployments/bootstrap/main.tf",
    bootstrapDeployment,
    forbidden,
    `The trusted bootstrap map must never restore a legacy routine/deployer privilege: ${forbidden}`,
  );
}

for (const rootPath of [
  "terraform/deployments/bootstrap/main.tf",
  "terraform/deployments/exposure/main.tf",
  "terraform/deployments/prod/main.tf",
]) {
  const deployment = await read(rootPath);
  requireContains(rootPath, deployment, 'source = "../../modules/', "Trusted deployment roots must use local platform modules.");
  rejectContains(rootPath, deployment, "github.com/", "Trusted deployment roots must not download caller-selected modules.");
}
const expectedTerraformPlatformHashes = [
  '"h1:5bwzwKa/bvJmUkVMkrF18v9AfFeJ/wjR230oY+4LHrc="',
  '"h1:EYsKCMfXi6gtv3fE6XgNpsKrt7qFNrGFwenhlTkrrRM="',
  '"h1:FGFsRBzfeyq56BUAcb/WT676NieMX3NRfR4DBj2eEqk="',
  '"h1:snI9jfT+CtL8dH099NZCe79ciOSTuL74nPB7KaCf9pM="',
].sort();
for (const lockPath of [
  "terraform/deployments/bootstrap/.terraform.lock.hcl",
  "terraform/deployments/exposure/.terraform.lock.hcl",
  "terraform/deployments/prod/.terraform.lock.hcl",
  "terraform/examples/bootstrap/.terraform.lock.hcl",
  "terraform/examples/cloud-run-service/.terraform.lock.hcl",
  "templates/app/infra/terraform/bootstrap/.terraform.lock.hcl",
  "templates/app/infra/terraform/prod/.terraform.lock.hcl",
]) {
  const lock = await read(lockPath);
  const actualPlatformHashes = [...lock.matchAll(/"h1:[^"]+"/g)].map(([hash]) => hash).sort();
  if (JSON.stringify(actualPlatformHashes) !== JSON.stringify(expectedTerraformPlatformHashes)) {
    failures.push(
      `${lockPath}: Google provider lockfile must include the reviewed Darwin/Linux amd64+arm64 package hashes.`,
    );
  }
}
const platformWorkflow = await read(".github/workflows/platform.yml");
requireContains(
  ".github/workflows/platform.yml",
  platformWorkflow,
  "Committed node_modules content is forbidden before the Socket credential is released.",
  "Platform CI must reject checkout-controlled node_modules before releasing the Socket token.",
);
requireContains(
  ".github/workflows/platform.yml",
  platformWorkflow,
  "terraform/deployments/*",
  "Platform CI must validate every privileged deployment root.",
);
requireContains(
  ".github/workflows/platform.yml",
  platformWorkflow,
  "terraform -chdir=terraform/deployments/bootstrap test -no-color",
  "Platform CI must execute protected bootstrap variable-validation regressions.",
);
requireContains(
  ".github/workflows/platform.yml",
  platformWorkflow,
  "terraform -chdir=terraform/deployments/exposure test -no-color",
  "Platform CI must execute stable preview-domain selection regressions.",
);
requireContains(
  ".github/workflows/platform.yml",
  platformWorkflow,
  "CHECKOV_IMAGE: ghcr.io/bridgecrewio/checkov@sha256:f4c7c5bde21df03432ca8d9d1305ffe21b7205ea752c3d4e65559abae67ead4a",
  "Platform Terraform must be scanned by the reviewed digest-pinned Checkov image.",
);
requireContains(
  ".github/workflows/platform.yml",
  platformWorkflow,
  'docker pull "$CHECKOV_IMAGE"',
  "Platform CI must explicitly pull the reviewed Checkov digest before disabling network access.",
);
for (const boundary of [
  "docker run --rm --pull=never",
  "--network=none",
  "--read-only",
  "--cap-drop=ALL",
  "--security-opt no-new-privileges=true",
  "--user 65532:65532",
  "--workdir /tmp",
  '--mount "type=bind,src=${terraform_root},dst=/scan,readonly"',
  '--mount "type=bind,src=${policy_file},dst=/policy.yml,readonly"',
  "--entrypoint /usr/local/bin/checkov",
  "--skip-download",
  "--skip-path '(^|/)\\.terraform(/|$)'",
]) {
  requireContains(
    ".github/workflows/platform.yml",
    platformWorkflow,
    boundary,
    `Platform Checkov isolation is missing ${boundary}.`,
  );
}
rejectContains(
  ".github/workflows/platform.yml",
  platformWorkflow,
  '--mount "type=bind,src=${GITHUB_WORKSPACE},dst=/scan,readonly"',
  "Platform Checkov must never receive the caller-controlled repository root.",
);
for (const configName of [".checkov.yml", ".checkov.yaml", "checkov.yml", "checkov.yaml"]) {
  requireContains(
    ".github/workflows/platform.yml",
    platformWorkflow,
    configName,
    `Platform Terraform verification must reject ambient ${configName}.`,
  );
}
requireContains(
  ".github/workflows/platform.yml",
  platformWorkflow,
  "--directory /scan",
  "Platform Checkov must scan the trusted modules and deployment roots.",
);
requireContains(
  ".github/workflows/platform.yml",
  platformWorkflow,
  "--config-file /policy.yml",
  "Platform Checkov must ignore ambient user configuration and use the reviewed fail-closed policy.",
);
const platformCheckov = await read("tools/ci/checkov-platform.yml");
if (platformCheckov !== "soft-fail: false\n") {
  failures.push("tools/ci/checkov-platform.yml: Platform Checkov policy must contain only soft-fail: false.");
}
requireContains(
  ".github/workflows/platform.yml",
  platformWorkflow,
  "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
  "Platform CI must checksum-pin actionlint.",
);
requireContains(
  ".github/workflows/platform.yml",
  platformWorkflow,
  "actionlint .github/workflows/*.yml templates/app/.github/workflows/*.yml templates/additional-workflows/runsetta/apple.yml",
  "Platform CI must lint reusable and caller workflow syntax.",
);
const actionlintConfig = await read(".github/actionlint.yaml");
for (const knownSchemaLag of [
  'property "workflow_(repository|sha)" is not defined in object type',
  'unexpected key "queue" for "concurrency" section',
]) {
  requireContains(
    ".github/actionlint.yaml",
    actionlintConfig,
    knownSchemaLag,
    `actionlint may ignore only the documented schema lag: ${knownSchemaLag}`,
  );
}
rejectContains(
  ".github/actionlint.yaml",
  actionlintConfig,
  "- '.*'",
  "actionlint configuration must not suppress all findings.",
);

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exit(1);
}

async function read(path: string): Promise<string> {
  return await readFile(join(root, path), "utf8");
}

function requireContains(path: string, text: string, needle: string, message: string): void {
  if (!text.includes(needle)) {
    failures.push(`${path}: ${message}`);
  }
}

function rejectContains(path: string, text: string, needle: string, message: string): void {
  if (text.includes(needle)) {
    failures.push(`${path}: ${message}`);
  }
}

function sectionBetween(text: string, start: string, end: string): string {
  const startIndex = text.indexOf(start);
  const endIndex = text.indexOf(end, startIndex + start.length);
  if (startIndex === -1 || endIndex === -1) {
    return text;
  }
  return text.slice(startIndex, endIndex);
}

function sectionFrom(text: string, start: string): string {
  const startIndex = text.indexOf(start);
  return startIndex === -1 ? text : text.slice(startIndex);
}

function requireBefore(
  path: string,
  text: string,
  first: string,
  second: string,
  message: string,
): void {
  const firstIndex = text.indexOf(first);
  const secondIndex = text.indexOf(second);
  if (firstIndex === -1 || secondIndex === -1 || firstIndex >= secondIndex) {
    failures.push(`${path}: ${message}`);
  }
}

function checkRequiredCheckEventGuards(
  specifications: readonly {
    readonly jobs: readonly string[];
    readonly path: string;
    readonly source: string;
  }[],
): void {
  for (const specification of specifications) {
    let workflow: {
      readonly jobs?: Readonly<
        Record<
          string,
          {
            readonly steps?: readonly {
              readonly name?: unknown;
              readonly run?: unknown;
              readonly shell?: unknown;
            }[];
          }
        >
      >;
    };
    try {
      workflow = Bun.YAML.parse(specification.source) as typeof workflow;
    } catch (error) {
      failures.push(`${specification.path}: required-check guard YAML is invalid: ${String(error)}`);
      continue;
    }
    for (const jobName of specification.jobs) {
      const steps = workflow.jobs?.[jobName]?.steps;
      if (!Array.isArray(steps)) {
        failures.push(`${specification.path}:${jobName}: required-check job must have steps.`);
        continue;
      }
      const guardIndexes = steps.flatMap((step, index) =>
        step.name === "Reject alternate required-check event paths" ? [index] : []
      );
      if (guardIndexes.length !== 1) {
        failures.push(
          `${specification.path}:${jobName}: required-check job must have exactly one event guard.`,
        );
        continue;
      }
      const guardIndex = guardIndexes[0]!;
      const guard = steps[guardIndex]!;
      if (guardIndex !== 1 || typeof steps[0]?.name !== "string" ||
        !steps[0].name.startsWith("Reject workflow reruns before any ")) {
        failures.push(
          `${specification.path}:${jobName}: required-check event guard must immediately follow the rerun guard.`,
        );
      }
      if (guard.shell !== "/bin/bash --noprofile --norc -euo pipefail {0}") {
        failures.push(
          `${specification.path}:${jobName}: required-check event guard must use the hardened Bash shell.`,
        );
      }
      if (guard.run !== requiredCheckEventGuard) {
        failures.push(
          `${specification.path}:${jobName}: required-check event guard must use the shared exact payload contract.`,
        );
      }
    }
  }
}

function checkActionPins(path: string, text: string, allowPlatformPlaceholder: boolean): void {
  for (const match of text.matchAll(
    /^\s*uses:\s*(?:"([^"]+)"|'([^']+)'|([^\s#]+))(?:\s+#.*)?$/gm,
  )) {
    const spec = match[1] ?? match[2] ?? match[3]!;
    if (spec.startsWith("./")) {
      failures.push(`${path}: local action ${spec} is not allowed in platform workflows.`);
      continue;
    }
    if (spec.startsWith("docker://")) {
      if (!/^docker:\/\/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$/.test(spec)) {
        failures.push(`${path}: container action ${spec} must use a full sha256 image digest.`);
      }
      continue;
    }

    const separator = spec.lastIndexOf("@");
    const action = separator === -1 ? spec : spec.slice(0, separator);
    const ref = separator === -1 ? "" : spec.slice(separator + 1);
    const allowedPlaceholder =
      allowPlatformPlaceholder &&
      action.startsWith("collinbentley1/platform/.github/workflows/") &&
      ref === "__PLATFORM_SHA__";

    if (!allowedPlaceholder && !/^[0-9a-f]{40}$/.test(ref)) {
      failures.push(`${path}: action ${spec} must use a full lowercase 40-character commit SHA.`);
    }
  }
}

function checkDockerPins(path: string, text: string): void {
  const stages = new Set<string>();
  const exactNamedContexts = new Set([
    "platform.invalid/bun-release",
    "platform.invalid/dhi-bun-dev",
    "platform.invalid/dhi-bun-runtime",
  ]);

  for (const match of text.matchAll(/^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$/gim)) {
    const image = match[1]!;
    const alias = match[2]?.toLowerCase();
    if (
      !stages.has(image.toLowerCase()) &&
      !exactNamedContexts.has(image.toLowerCase()) &&
      !/@sha256:[0-9a-f]{64}$/.test(image)
    ) {
      failures.push(`${path}: external base image ${image} must be pinned to a sha256 digest.`);
    }
    if (alias) {
      stages.add(alias);
    }
  }
}
