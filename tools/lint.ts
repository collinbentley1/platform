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

const root = join(import.meta.dir, "..");
const failures: string[] = [];
const reusableWorkflows = [
  "application.yml",
  "socket-firewall.yml",
  "infrastructure.yml",
  "deploy-prod.yml",
  "deploy-preview.yml",
  "cleanup-preview.yml",
  "reconcile-previews.yml",
];
const platformWorkflows = [...reusableWorkflows, "platform.yml"];
const declaredEnvironmentSecrets = [
  "DHI_ACCESS_TOKEN",
  "DHI_USERNAME",
  "GRYPE_DB_MANIFEST_JSON",
  "MAPBOX_PUBLIC_TOKEN",
  "SOCKET_API_TOKEN",
  "WAITLIST_IDENTITY_KEYSET",
];
const expectedPreviewEnvironmentSecretDeclarations = [
  "    secrets:",
  "      DHI_ACCESS_TOKEN:",
  "        required: true",
  "      DHI_USERNAME:",
  "        required: true",
  "      GRYPE_DB_MANIFEST_JSON:",
  "        required: true",
  "      MAPBOX_PUBLIC_TOKEN:",
  "        required: false",
  "      SOCKET_API_TOKEN:",
  "        required: true",
].join("\n");
const expectedProductionEnvironmentSecretDeclarations = [
  expectedPreviewEnvironmentSecretDeclarations,
  "      WAITLIST_IDENTITY_KEYSET:",
  "        required: false",
].join("\n");
const expectedPreviewCallerSecretMap = [
  "    secrets:",
  "      DHI_ACCESS_TOKEN: ${{ secrets.DHI_ACCESS_TOKEN }}",
  "      DHI_USERNAME: ${{ secrets.DHI_USERNAME }}",
  "      GRYPE_DB_MANIFEST_JSON: ${{ secrets.GRYPE_DB_MANIFEST_JSON }}",
  "      MAPBOX_PUBLIC_TOKEN: ${{ secrets.MAPBOX_PUBLIC_TOKEN }}",
  "      SOCKET_API_TOKEN: ${{ secrets.SOCKET_API_TOKEN }}",
].join("\n");
const expectedProductionCallerSecretMap = [
  expectedPreviewCallerSecretMap,
  "      WAITLIST_IDENTITY_KEYSET: ${{ secrets.WAITLIST_IDENTITY_KEYSET }}",
].join("\n");
const expectedPreviewSecretContextReferences: SecretContextReference[] = [
  { job: null, path: "on.workflow_call.<key:secrets>", value: "secrets" },
  {
    job: "build",
    path: "jobs.build.steps.7.env.SOCKET_API_TOKEN",
    value: "${{ secrets.SOCKET_API_TOKEN }}",
  },
  {
    job: "build",
    path: "jobs.build.steps.9.with.username",
    value: "${{ secrets.DHI_USERNAME }}",
  },
  {
    job: "build",
    path: "jobs.build.steps.9.with.password",
    value: "${{ secrets.DHI_ACCESS_TOKEN }}",
  },
  {
    job: "build",
    path: "jobs.build.steps.17.env.DB_MANIFEST_JSON",
    value: "${{ secrets.GRYPE_DB_MANIFEST_JSON }}",
  },
  {
    job: "deploy",
    path: "jobs.deploy.steps.4.env.MAPBOX_PUBLIC_TOKEN",
    value: "${{ secrets.MAPBOX_PUBLIC_TOKEN }}",
  },
];
const expectedProductionSecretContextReferences: SecretContextReference[] = [
  ...expectedPreviewSecretContextReferences,
  {
    job: "deploy",
    path: "jobs.deploy.steps.4.env.WAITLIST_IDENTITY_KEYSET",
    value: "${{ secrets.WAITLIST_IDENTITY_KEYSET }}",
  },
];

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
  rejectContains(
    path,
    text,
    "${{ vars.",
    "Security-sensitive workflow policy must never be controlled by a repository or environment variable.",
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

for (const [path, workflow, expectedDeclarations, count] of [
  [".github/workflows/deploy-preview.yml", deployPreview, expectedPreviewEnvironmentSecretDeclarations, "five"],
  [".github/workflows/deploy-prod.yml", deployProd, expectedProductionEnvironmentSecretDeclarations, "six"],
] as const) {
  const workflowCall = sectionBetween(workflow, "  workflow_call:\n", "\npermissions:");
  const declarationBlock = sectionFrom(workflowCall, "    secrets:\n").trimEnd();
  if (declarationBlock !== expectedDeclarations) {
    failures.push(`${path}: workflow_call secrets must exactly match the reviewed ${count}-name contract.`);
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
  "environment: preview-build",
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
for (const [path, workflow, buildJob, deployJob, expectedReferences] of [
  [
    ".github/workflows/deploy-preview.yml",
    deployPreview,
    sectionBetween(deployPreview, "  build:\n", "\n  canary:\n"),
    previewDeployJob,
    expectedPreviewSecretContextReferences,
  ],
  [
    ".github/workflows/deploy-prod.yml",
    deployProd,
    sectionBetween(deployProd, "  build:\n", "\n  canary:\n"),
    sectionFrom(deployProd, "  deploy:\n"),
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
  for (const secret of [
    "DHI_ACCESS_TOKEN",
    "DHI_USERNAME",
    "GRYPE_DB_MANIFEST_JSON",
    "SOCKET_API_TOKEN",
  ]) {
    const reference = `\${{ secrets.${secret} }}`;
    if (workflow.split(reference).length !== 2 || !buildJob.includes(reference)) {
      failures.push(`${path}: ${secret} must be referenced exactly once and only by the build job.`);
    }
  }
  const deploySecrets = path.endsWith("deploy-prod.yml")
    ? ["MAPBOX_PUBLIC_TOKEN", "WAITLIST_IDENTITY_KEYSET"]
    : ["MAPBOX_PUBLIC_TOKEN"];
  for (const secret of deploySecrets) {
    const reference = `\${{ secrets.${secret} }}`;
    if (workflow.split(reference).length !== 2 || !deployJob.includes(reference)) {
      failures.push(`${path}: ${secret} must be referenced exactly once and only by the deploy job.`);
    }
  }
}
for (const needle of [
  'stable_preview_domain="preview.ycriticalhistory.org"',
  'preview_ingress="internal-and-cloud-load-balancing"',
  'echo "project_number=$project_number"',
  '--ingress="$PREVIEW_INGRESS"',
  'deterministic_url="https://pr-${PR_NUMBER}---${PREVIEW_SERVICE}-${PROJECT_NUMBER}.${REGION}.run.app"',
  '[a-z0-9.-]+\\.run\\.app',
  'public_preview_url="https://pr-${PR_NUMBER}.${STABLE_PREVIEW_DOMAIN}"',
  "PLATFORM_DEPLOY_NONCE: $deploy_nonce",
  'preview_nonce="$(openssl rand -hex 32)"',
  '"${public_preview_url}/livez"',
  "--max-filesize 1024",
  'if health_status="$(curl --silent --show-error',
  'jq -e -s --arg nonce "$preview_nonce"',
  'length == 1 and .[0] == {deployment: $nonce, ok: true}',
  "rollback_tag=true",
  'if [ "$current_revision" = "$expected_revision" ]',
  '--remove-tags="$tag"',
  "rollback_tag=false",
]) {
  requireContains(
    ".github/workflows/deploy-preview.yml",
    previewDeployJob,
    needle,
    `Stable Critical History preview routing is missing: ${needle}`,
  );
}
requireBefore(
  ".github/workflows/deploy-preview.yml",
  previewDeployJob,
  "rollback_tag=true",
  'gcloud run deploy "$PREVIEW_SERVICE"',
  "Preview rollback must arm before Cloud Run can mutate the shared service.",
);
requireContains(
  ".github/workflows/deploy-preview.yml",
  sectionBetween(
    previewDeployJob,
    'jq -e -s --arg nonce "$preview_nonce"',
    'echo "url=$public_preview_url"',
  ),
  "rollback_tag=false",
  "Preview rollback must remain armed until the stable health response is validated.",
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
  "tools/ci/grype-blocking.jq",
  grypeBlockingPolicy,
  '.vulnerability.severity == "High"',
  "Every High vulnerability must block publication even when no upstream fix exists.",
);
rejectContains(
  "tools/ci/grype-blocking.jq",
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
      `https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.9_2026-08-20T16:14:23Z_1787293044.tar.zst?checksum=sha256%3A${manifest.sha256}` ||
    manifest.sha256 !== "dca26dd65bd0c4ba626af404a2e60d983d9302863eabdd8a7e7d42008fb4da3c" ||
    manifest.schemaVersion !== "v6.1.9" ||
    manifest.built !== "2026-08-21T06:17:24Z"
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
  requireContains(
    path,
    workflow,
    "DB_MANIFEST_JSON: ${{ secrets.GRYPE_DB_MANIFEST_JSON }}",
    "Image scanning must use the owner-controlled build-environment vulnerability DB manifest secret.",
  );
  requireContains(path, workflow, '<<< "$DB_MANIFEST_JSON"', "The vulnerability DB manifest must be parsed as inert JSON.");
  requireContains(path, workflow, 'db import "$db_url"', "Image scanning must import the exact checksum-qualified DB archive.");
  rejectContains(path, workflow, "db update", "Image scanning must not trust mutable database metadata.");
  requireContains(
    path,
    workflow,
    "tools/ci/grype-blocking.jq",
    "Image publication must use the reviewed High-and-Critical blocking policy.",
  );
  requireContains(path, workflow, "jq -e 'length == 0'", "Image publication must fail when the blocking policy finds a vulnerability.");
  requireContains(
    path,
    workflow,
    '--config "$config" "docker:${LOCAL_IMAGE}"',
    "SBOM generation must use the trusted platform-owned Syft configuration.",
  );
  requireContains(
    path,
    workflow,
    "syft-empty-docker-config",
    "SBOM generation must not inherit registry credentials from the build.",
  );
  requireContains(
    path,
    workflow,
    "SOCKET_API_TOKEN: ${{ secrets.SOCKET_API_TOKEN }}",
    "The pre-extraction lock scan must receive the protected Socket organization token.",
  );
  requireContains(
    path,
    workflow,
    '--config="$GITHUB_WORKSPACE/_platform_policy/tools/ci/bunfig.toml" pm scan',
    "The protected Socket scan must use the exact checked-out platform policy.",
  );
  requireContains(
    path,
    workflow,
    "bun pm scan must not mutate package.json or bun.lock.",
    "The protected Socket scan must prove it is non-mutating.",
  );
  rejectContains(
    path,
    workflow,
    "socket_api_token=",
    "The Socket organization token must never enter BuildKit or an image layer.",
  );
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
  ]) {
    requireContains(
      path,
      workflow,
      boundary,
      `The untrusted container build is missing the runner-command boundary: ${boundary}`,
    );
  }
  const buildName = path.endsWith("deploy-preview.yml")
    ? "Build untrusted preview image without cloud credentials"
    : "Build production image without cloud credentials";
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
  "environment: production-build",
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
  "MAPBOX_PUBLIC_TOKEN: ${{ secrets.MAPBOX_PUBLIC_TOKEN }}",
  "WAITLIST_IDENTITY_KEYSET: ${{ secrets.WAITLIST_IDENTITY_KEYSET }}",
  '[[ ! "$WAITLIST_IDENTITY_KEYSET" =~ ^[A-Za-z0-9_-]{43}(,[A-Za-z0-9_-]{43})?$ ]]',
  "canonical_base64url_32",
  "base64 --decode",
  "base64 --wrap=0",
  'waitlist_fingerprint="$(printf',
  "gcloud run services describe",
  'waitlist-keyset-fingerprint',
  'select(.name == "waitlist-identity-keyset")',
  "gcloud secrets versions add waitlist-identity-keyset",
  "env -u WAITLIST_IDENTITY_KEYSET",
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
  "jq --arg waitlist_identity_keyset",
  "The Medlock signing payload must never enter the literal Cloud Run environment JSON.",
);
if (deployProduction.split("--set-secrets").length - 1 !== 1) {
  failures.push(
    ".github/workflows/deploy-prod.yml: Exactly one reviewed Secret Manager mapping is permitted.",
  );
}
requireBefore(
  ".github/workflows/deploy-prod.yml",
  deployProduction,
  'if ! canonical_base64url_32 "$waitlist_primary"',
  "gcloud secrets versions add waitlist-identity-keyset",
  "Canonical key validation must finish before any immutable secret version is created.",
);
requireBefore(
  ".github/workflows/deploy-prod.yml",
  deployProduction,
  "gcloud run services describe",
  "gcloud secrets versions add waitlist-identity-keyset",
  "The trusted deploy must reuse the exact current version when the keyset fingerprint is unchanged.",
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
  "MAPBOX_PUBLIC_TOKEN: ${{ secrets.MAPBOX_PUBLIC_TOKEN }}",
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
  const stagingKind = path === ".github/workflows/deploy-preview.yml" ? "preview" : "production";
  const publish = sectionBetween(workflow, "  publish:\n", "\n  attest:\n");
  const deploy =
    path === ".github/workflows/deploy-preview.yml"
      ? sectionBetween(workflow, "  deploy:\n", "\n  invalidate:\n")
      : sectionFrom(workflow, "  deploy:\n");
  requireContains(path, publish, publishEnvironment, "Image publication must use its distinct protected environment claim.");
  requireContains(path, publish, publisherAccount, "Image publication must use the dedicated publisher service account.");
  requireContains(path, publish, publisherCanary, "Each publisher claim must have an independent no-role canary exchange.");
  rejectContains(path, publish, deployAccount, "An image publisher job must not authenticate the Cloud Run operator.");
  requireContains(
    path,
    workflow,
    `platform-${"${repository}"}-${stagingKind}-staging-${"${GITHUB_RUN_ID}"}-${"${GITHUB_RUN_ATTEMPT}"}:run-${"${GITHUB_RUN_ID}"}-${"${GITHUB_RUN_ATTEMPT}"}`,
    "The build must create a run-and-attempt-unique GHCR package and tag.",
  );
  requireContains(
    path,
    workflow,
    'staging-image: ${{ steps.metadata.outputs.staging_image }}',
    "The build must export its exact staging image identity.",
  );
  rejectContains(
    path,
    publish,
    `staging_image=ghcr.io/${"${source_owner}"}/platform-${"${source_repository}"}-${stagingKind}-staging-${"${GITHUB_RUN_ID}"}-${"${GITHUB_RUN_ATTEMPT}"}`,
    "A rerun must not reconstruct the producer attempt from the current attempt.",
  );
  for (const needle of [
    'BUILD_STAGING_IMAGE: ${{ needs.build.outputs.staging-image }}',
    `platform-${"${source_repository}"}-${stagingKind}-staging-${"${GITHUB_RUN_ID}"}-([1-9][0-9]*):run-${"${GITHUB_RUN_ID}"}-([1-9][0-9]*)`,
    '[[ ! "$BUILD_STAGING_IMAGE" =~ $staging_pattern ]]',
    '[[ "${BASH_REMATCH[1]}" != "${BASH_REMATCH[2]}" ]]',
    'echo "staging_image=$BUILD_STAGING_IMAGE"',
  ]) {
    requireContains(path, publish, needle, `Publisher staging identity handoff is missing: ${needle}`);
  }
  rejectContains(
    path,
    workflow,
    `-${stagingKind}-staging:run-${"${GITHUB_RUN_ID}"}-${"${GITHUB_RUN_ATTEMPT}"}`,
    "A shared staging package permits cross-run manifest-version races.",
  );
  const copy = sectionBetween(
    publish,
    "      - name: Copy the opaque image by digest\n",
    "\n      - name: Verify registry credentials were retired\n",
  );
  const credentialVerification = sectionFrom(
    publish,
    "      - name: Verify registry credentials were retired\n",
  );
  const cleanup = sectionBetween(
    workflow,
    "  cleanup-staging:\n",
    "\n  attest:\n",
  );
  for (const needle of [
    "set -euo pipefail",
    'docker_config="$RUNNER_TEMP/platform-publisher-docker"',
    'trap retire_registry_credentials EXIT',
    'export DOCKER_CONFIG="$docker_config"',
    'rm -f -- "$docker_config/config.json"',
    '"$crane" copy "${STAGING_IMAGE}@${STAGING_DIGEST}" "$REMOTE_IMAGE"',
    'remote_digest="$("$crane" digest "$REMOTE_IMAGE")"',
    'if [ "$remote_digest" != "$STAGING_DIGEST" ]',
    'echo "digest=$remote_digest" >> "$GITHUB_OUTPUT"',
  ]) {
    requireContains(path, copy, needle, `Verified registry copy transaction is missing: ${needle}`);
  }
  requireBefore(
    path,
    copy,
    '"$crane" copy "${STAGING_IMAGE}@${STAGING_DIGEST}" "$REMOTE_IMAGE"',
    'remote_digest="$("$crane" digest "$REMOTE_IMAGE")"',
    "The registry digest must be read only after the opaque copy completes.",
  );
  requireBefore(
    path,
    copy,
    'if [ "$remote_digest" != "$STAGING_DIGEST" ]',
    'echo "digest=$remote_digest" >> "$GITHUB_OUTPUT"',
    "The publisher must reject a changed digest before exporting it.",
  );
  rejectContains(path, copy, "continue-on-error", "The verified registry copy transaction must fail closed.");
  rejectContains(path, copy, "|| true", "The verified registry copy transaction must not suppress failures.");
  rejectContains(path, publish, '"$crane" delete', "GHCR does not support distribution-spec manifest deletion.");
  for (const needle of [
    "set -euo pipefail",
    'credential_file="$RUNNER_TEMP/platform-publisher-docker/config.json"',
    '[ -e "$credential_file" ] || [ -L "$credential_file" ]',
  ]) {
    requireContains(path, credentialVerification, needle, `Registry credential retirement proof is missing: ${needle}`);
  }
  for (const needle of [
    "needs:\n      - build\n      - publish",
    "if: always() && needs.publish.result == 'success'",
    "timeout-minutes: 5",
    "permissions:\n      packages: write",
    "timeout-minutes: 2",
    'STAGING_IMAGE: ${{ needs.build.outputs.staging-image }}',
    `staging_pattern="^ghcr\\\\.io/${"${owner}"}/(platform-${"${repository}"}-${stagingKind}-staging-${"${GITHUB_RUN_ID}"}-([1-9][0-9]*)):(run-${"${GITHUB_RUN_ID}"}-([1-9][0-9]*))$"`,
    '[[ ! "$STAGING_IMAGE" =~ $staging_pattern ]]',
    '[[ "${BASH_REMATCH[2]}" != "${BASH_REMATCH[4]}" ]]',
    'package="${BASH_REMATCH[1]}"',
    'tag="${BASH_REMATCH[3]}"',
    '[[ ! "$GITHUB_RUN_ID" =~ ^[1-9][0-9]*$ ]]',
    'for candidate_root in user "users/${owner}"; do',
    '/${candidate_root}/packages/container/${package}/versions?state=active&per_page=100',
    '.name == $digest',
    '.metadata.package_type == "container"',
    '.metadata.container.tags == [$tag]',
    'if type == "array" and',
    'length == 1 and',
    'else error("expected one exact isolated staging version")',
    '[[ "$candidate_id" =~ ^[1-9][0-9]*$ ]]',
    '/packages/container/${package}',
    "X-GitHub-Api-Version: 2022-11-28",
  ]) {
    requireContains(path, cleanup, needle, `Staging package cleanup is missing: ${needle}`);
  }
  rejectContains(path, cleanup, "AR_ACCESS_TOKEN", "Post-copy staging cleanup must not retain Artifact Registry credentials.");
  rejectContains(path, cleanup, "DOCKER_CONFIG", "Post-copy staging cleanup must run outside the publisher credential directory.");
  rejectContains(path, cleanup, "id-token", "Post-copy staging cleanup must not be able to mint cloud credentials.");
  rejectContains(path, cleanup, "environment:", "Post-copy staging cleanup must not enter a protected cloud environment.");
  rejectContains(path, cleanup, "--paginate", "Post-copy staging cleanup must bound GitHub package enumeration.");
  rejectContains(path, cleanup, '"$crane" copy', "Post-copy staging cleanup must not recopy the image.");
  rejectContains(path, cleanup, "continue-on-error", "Staging package cleanup failures must remain visible.");
  rejectContains(path, cleanup, "|| true", "Staging package cleanup must use explicit fallback branches.");
  rejectContains(
    path,
    cleanup,
    'package="platform-${repository}',
    "Cleanup must use the producer-exported package rather than the current rerun attempt.",
  );
  requireBefore(
    path,
    workflow,
    'echo "digest=$remote_digest" >> "$GITHUB_OUTPUT"',
    "  cleanup-staging:",
    "Staging cleanup must occur only after a verified copy exports its digest.",
  );
  requireContains(path, deploy, deployAccount, "Cloud Run mutation must use the dedicated deploy/operator service account.");
  rejectContains(path, deploy, publisherAccount, "A Cloud Run deploy job must not authenticate the Artifact Registry publisher.");
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
  "gha-preview-deploy@",
  "Stale-preview invalidation must authenticate the existing preview deploy identity.",
);
for (const boundary of [
  "deployed-revision: ${{ steps.deploy.outputs.revision }}",
  "EXPECTED_REVISION: ${{ needs.deploy.outputs.deployed-revision }}",
  'if [ "$current_revision" != "$EXPECTED_REVISION" ]',
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
  "gha-preview-operator@",
  "Active stale-preview invalidation must not authenticate the retired preview operator.",
);
rejectContains(
  ".github/workflows/deploy-preview.yml",
  previewInvalidation,
  "actions/checkout@",
  "Privileged stale-preview invalidation must not checkout or execute PR-controlled code.",
);
for (const needle of [
  "verify_stable_preview_absent",
  'preview.ycriticalhistory.org"',
  '[ "$status" = "404" ]',
]) {
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
  requireContains(path, workflow, "gha-preview-deploy@", "Preview traffic operations must authenticate the existing preview deploy identity.");
  rejectContains(path, workflow, "gha-preview-operator@", "Active preview traffic operations must not authenticate the retired operator identity.");
  rejectContains(path, workflow, "gha-preview-publish@", "Preview traffic operations must not authenticate the publisher identity.");
  rejectContains(
    path,
    workflow,
    "actions/checkout@",
    "Privileged preview traffic operations must not checkout or execute repository code.",
  );
  requireContains(
    path,
    workflow,
    "verify_stable_preview_absent",
    "Preview traffic operations must verify the stable Critical History URL is unroutable.",
  );
  requireContains(path, workflow, '[ "$status" = "404" ]', "Stable preview cleanup must require an exact 404 without redirects.");
  rejectContains(
    path,
    sectionFrom(workflow, "verify_stable_preview_absent()"),
    "--location",
    "Stable preview teardown probes must not follow redirects.",
  );
}
const cleanupPreview = await read(".github/workflows/cleanup-preview.yml");
for (const boundary of [
  "github.event.pull_request.head.repo.full_name == github.repository",
  "PR_NUMBER: ${{ github.event.pull_request.number }}",
  'preview_tag="pr-${PR_NUMBER}"',
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
  "(github.event_name == 'schedule' || github.event_name == 'workflow_dispatch')",
  "github.ref == 'refs/heads/main'",
  'gh api "repos/${GITHUB_REPOSITORY}/pulls/${pr_number}"',
]) {
  requireContains(
    ".github/workflows/reconcile-previews.yml",
    reconcilePreviews,
    boundary,
    `Preview reconciliation must derive its decisions from trusted default-branch state: ${boundary}`,
  );
}
requireBefore(
  ".github/workflows/deploy-preview.yml",
  deployPreview,
  "Enforce the trusted application and container contract",
  "Enforce the organization Socket policy before package extraction",
  "Preview contract validation must finish before the Socket token is exposed.",
);
requireBefore(
  ".github/workflows/deploy-preview.yml",
  deployPreview,
  "Enforce the organization Socket policy before package extraction",
  "Login to Docker Hardened Images",
  "Preview Socket policy must finish before registry credentials are exposed.",
);
requireBefore(
  ".github/workflows/deploy-prod.yml",
  deployProduction,
  "Enforce the trusted application and container contract",
  "Enforce the organization Socket policy before package extraction",
  "Production contract validation must finish before the Socket token is exposed.",
);
requireBefore(
  ".github/workflows/deploy-prod.yml",
  deployProduction,
  "Enforce the organization Socket policy before package extraction",
  "Login to Docker Hardened Images",
  "Production Socket policy must finish before registry credentials are exposed.",
);

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
requireContains(
  ".github/workflows/platform.yml",
  platformDependencyWorkflow,
  "environment: ${{ github.event_name == 'push' && 'dependency-scan' || 'platform-pull-request' }}",
  "Platform pull requests must use a secretless environment distinct from trusted main.",
);
requireContains(
  ".github/workflows/platform.yml",
  platformDependencyWorkflow,
  "SOCKET_API_TOKEN: ${{ github.event_name == 'push' && secrets.SOCKET_API_TOKEN || '' }}",
  "The Socket organization token must be unavailable to platform pull requests.",
);
rejectContains(
  ".github/workflows/platform.yml",
  platformDependencyWorkflow,
  "SOCKET_API_TOKEN: ${{ secrets.SOCKET_API_TOKEN }}",
  "Platform pull requests must never receive the Socket token through an unconditional mapping.",
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
for (const workflow of ["application.yml", "socket-firewall.yml", "deploy-preview.yml", "deploy-prod.yml"]) {
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
  "runtime_secret_version_adder_ids        = var.runtime_secret_version_adder_ids",
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
  'const socketOrganization = "collinbentley1"',
  'const authenticatedPackageLimit = 128',
  'const authenticatedBatchCost = 100',
  "const maxAlertsPerArtifact = 256",
  '`${socketApiBase}/quota`',
  '/orgs/${encodeURIComponent(socketOrganization)}/purl?',
  'alerts: "true"',
  'actions: "error,warn"',
  'poll: "true"',
  'purlErrors: "true"',
  'summary: "true"',
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
  "The local Socket scanner must accept only the canonical least-scope token variable.",
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
  "Consumer roots may configure only the reviewed platform modules",
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

for (const [workflow, expectedSecretMap, count] of [
  ["deploy-preview.yml", expectedPreviewCallerSecretMap, "five"],
  ["deploy-prod.yml", expectedProductionCallerSecretMap, "six"],
] as const) {
  const path = `templates/app/.github/workflows/${workflow}`;
  const text = await read(path);
  const secretMap = sectionFrom(text, "    secrets:\n").trimEnd();
  if (secretMap !== expectedSecretMap) {
    failures.push(`${path}: deploy caller secret map must exactly match the reviewed ${count}-name contract.`);
  }
}
requireContains(
  "templates/app/.github/workflows/deploy-preview.yml",
  await read("templates/app/.github/workflows/deploy-preview.yml"),
  "github.event.pull_request.draft == false",
  "Preview callers must not deploy draft pull requests.",
);

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
  "oven/bun:1.4.0-alpine@sha256:07235578f79ef8c6f97d94aee7938e76f5cdba5f21ae5dbfdd3d3d38058437eb",
  "The exact Bun binary source image must be digest pinned.",
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
requireContains(
  "templates/app/Dockerfile",
  dockerfile,
  "dhi.io/bun:1-alpine-dev@sha256:d364f4eb6d20f8e906bdb9d12726995f8335878f46e0c1c69c910df9d92df5d8",
  "The reviewed zero-High/Critical build base image must stay digest pinned.",
);
requireContains(
  "templates/app/Dockerfile",
  dockerfile,
  "dhi.io/bun:1-alpine@sha256:b169efde3cf30151d66f3d7988cad69b4d08833cc4cfaeca7da6bda2bd0a89b3",
  "The reviewed zero-vulnerability runtime base image must stay digest pinned.",
);
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
  "bb0be7c548794254309371db48e4800770cad59a72c7457b028bbeff1f6c7682"
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
  'preview_ingress                   = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"',
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
  "runtime_secret_accessor_ids       = []",
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
  "runtime_secret_version_adder_ids        = local.deployment.runtime_secret_version_adder_ids",
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
if (productionDeployment.split("runtime_secret_version_adder_ids  = []").length - 1 !== 3) {
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
  "google_artifact_registry_repository_iam_member.preview_deploy_reader",
  "google_artifact_registry_repository_iam_member.preview_publisher_writer",
  "google_artifact_registry_repository_iam_member.prod_deploy_reader",
  "google_artifact_registry_repository_iam_member.prod_publisher_writer",
  "google_cloud_run_v2_service_iam_member.preview_deploy",
  "google_cloud_run_v2_service_iam_member.prod_deploy",
  "google_secret_manager_secret_iam_member.prod_deploy_version_adder",
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

const bootstrapMain = await read("terraform/modules/bootstrap/main.tf");
const bootstrapVariables = await read("terraform/modules/bootstrap/variables.tf");
if (
  createHash("sha256").update(bootstrapMain).digest("hex") !==
  "42b12bb7f5eda9ac0f2131660e54d44fed4174db8a7e4735c48c0f3b995ab7f1"
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
  "google_project_iam_member.runtime_project_roles",
  "google_project_iam_member.terraform_convergence_reader",
  "google_service_account_iam_member.canary_wif_preview_deploy_workflow_sha",
  "google_service_account_iam_member.canary_wif_preview_operator_workflow_sha",
  "google_service_account_iam_member.canary_wif_preview_publish_workflow_sha",
  "google_service_account_iam_member.canary_wif_prod_publish_workflow_sha",
  "google_service_account_iam_member.canary_wif_prod_workflow_sha",
  "google_service_account_iam_member.canary_wif_terraform_workflow_sha",
  "google_service_account_iam_member.preview_deploy_uses_preview_runtime",
  "google_service_account_iam_member.preview_deploy_wif_repo",
  "google_service_account_iam_member.preview_deploy_wif_preview_operations_workflow_sha",
  "google_service_account_iam_member.preview_deploy_wif_workflow_sha",
  "google_service_account_iam_member.preview_operator_wif_repo",
  "google_service_account_iam_member.preview_operator_wif_workflow_sha",
  "google_service_account_iam_member.preview_publisher_wif_workflow_sha",
  "google_service_account_iam_member.prod_deploy_uses_runtime",
  "google_service_account_iam_member.prod_deploy_wif_prod_env",
  "google_service_account_iam_member.prod_deploy_wif_workflow_sha",
  "google_service_account_iam_member.prod_publisher_wif_workflow_sha",
  "google_service_account_iam_member.terraform_wif_prod_env",
  "google_service_account_iam_member.terraform_wif_workflow_sha",
  "google_storage_bucket_iam_binding.bootstrap_state_no_legacy_access",
  "google_storage_bucket_iam_binding.terraform_state_logs_no_legacy_access",
  "google_storage_bucket_iam_binding.terraform_state_no_legacy_access",
  "google_storage_bucket_iam_member.terraform_state_access_logs_writer",
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
if (
  /google_service_account\.preview_operator\.(?:email|member)/.test(bootstrapMain) ||
  bootstrapMain.includes("serviceAccount:gha-preview-operator@")
) {
  failures.push(
    "terraform/modules/bootstrap/main.tf: The preview operator must not receive direct project, registry, state, secret, or runtime grants.",
  );
}
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
for (const boundary of [
  'account_id   = "gha-prod-publish"',
  'account_id   = "gha-preview-publish"',
  'account_id   = "gha-preview-operator"',
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
  'resource "google_service_account_iam_member" "preview_deploy_wif_preview_operations_workflow_sha"',
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
    "preview_deploy_wif_preview_operations_workflow_sha",
    "preview_deploy",
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
    "preview_deploy_wif_preview_operations_workflow_sha",
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
  "actionlint .github/workflows/*.yml templates/app/.github/workflows/*.yml",
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

  for (const match of text.matchAll(/^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$/gim)) {
    const image = match[1]!;
    const alias = match[2]?.toLowerCase();
    if (!stages.has(image.toLowerCase()) && !/@sha256:[0-9a-f]{64}$/.test(image)) {
      failures.push(`${path}: external base image ${image} must be pinned to a sha256 digest.`);
    }
    if (alias) {
      stages.add(alias);
    }
  }
}
