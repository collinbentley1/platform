import { createHash, randomBytes } from "node:crypto";
import { closeSync, readFileSync, readSync } from "node:fs";
import {
  appendFile,
  chmod,
  lstat,
  mkdir,
  readFile,
  readdir,
  rm,
} from "node:fs/promises";
import { join, resolve } from "node:path";

const PLATFORM_OWNER = "collinbentley1";
const PLATFORM_OWNER_ID = "16823277";
const PLATFORM_REPOSITORY = "collinbentley1/platform";
const PLATFORM_REPOSITORY_ID = "1255856466";
const OWNER_MEMBER = "user:CollinBentley1@gmail.com";
const EXECUTOR_ACCOUNT_PREFIX = "gha-pbt-";
const EXECUTOR_ROLE_PREFIX = "pbt_";
const EXECUTOR_DISPLAY_NAME = "Protected Terraform Executor";
const EXECUTOR_DESCRIPTION_VERSION = "pbt-v1";
const TERRAFORM_SANDBOX_IMAGE =
  "docker.io/oven/bun@sha256:8aac45197595035f697ea6b11cd73ce2401d82503fcb2540b5fac606973b242b";
const TERRAFORM_VERSION = "1.14.5";
const GOOGLE_PROVIDER_VERSION = "7.45.0";
const GOOGLE_PROVIDER_LINUX_AMD64_ZH =
  "fb1b9d1ea7bc79b7409f02aa7c19ba39afa22dbead69e83ae7eb2691ac5c2426";
const GOOGLE_PROVIDER_BINARY = "terraform-provider-google_v7.45.0_x5";
const PLAN_FORMAT_VERSION = "1.2";
const JOB_TIMEOUT_MINUTES = 35;
const MAIN_STEP_TIMEOUT_MINUTES = 26;
const LEASE_MINUTES = 47;
const INTERNAL_OPERATION_MINUTES = 24;
const RECOVERY_OPERATION_MINUTES = 6;
const EXECUTOR_TOKEN_MINUTES = 30;
// Reserve seven minutes for the mandatory 300s+120s post-WIF drain and eight
// more for the bounded apply, zero-diff readback, marker proof, and receipt.
const MINIMUM_PRE_APPLY_MINUTES = 15;
const APPROVAL_FRESHNESS_MINUTES = 6 * 60;
const MAX_PLAN_FILE_BYTES = 64 * 1024 * 1024;
const MAX_PLAN_JSON_BYTES = 32 * 1024 * 1024;
const MAX_REVIEW_MANIFEST_BYTES = 800 * 1024;
const MAX_GITHUB_RUNS_PER_STATUS = 10_000;
const MAX_API_RESPONSE_BYTES = 4 * 1024 * 1024;
const CLEANUP_RETRY_INTERVAL_MS = 2_000;
const IAM_CONSISTENCY_MAX_WAIT_MS = 5 * 60_000;
const IAM_RETRY_INITIAL_MS = 1_000;
const IAM_RETRY_MAX_MS = 32_000;
const IAM_RETRY_MAX_ATTEMPTS = 16;
const IAM_FENCE_EXPIRED_AT = "2000-01-01T00:00:00.000Z";
const CLEANUP_FENCE_DESCRIPTION =
  "Expired inert binding used only to advance the cleanup CAS generation.";
const ORPHAN_FENCE_DESCRIPTION =
  "Expired inert binding used only to advance the orphan-recovery CAS generation.";
const MAX_SECRET_BUNDLE_BYTES = 16 * 1024;
const BRIDGE_TELEMETRY_INTERVAL_MS = 15_000;
// Google documents that a newly created service account can take 60 seconds or
// more to become visible, and its CI retry guidance allows a 300-second 404
// convergence deadline. Six scans 60 seconds apart establish that full
// five-minute stable-empty observation span without multiplying IAM reads.
const RECOVERY_STABLE_EMPTY_MS = 300_000;
const RECOVERY_STABLE_EMPTY_INTERVAL_MS = 60_000;
const LEGACY_MUTATOR_TOKEN_SECONDS = 3_600;
const TOKEN_DRAIN_SKEW_SECONDS = 120;
const POST_MUTATION_DRAIN_SECONDS = 300 + TOKEN_DRAIN_SKEW_SECONDS;
const CAPABILITY_MANIFEST_PATH = "platform-capabilities/preview-deployment-parity-v1.json";
const DEPLOYMENT_PARITY_MARKER_OBJECT = "deployment-parity-transition";
const DEPLOYMENT_PARITY_BUCKET_SUFFIX = "-deployment-parity-state";
const SANDBOX_OWNER_LABEL = "io.collinbentley1.platform.protected-bootstrap";
const SANDBOX_RUN_LABEL = "io.collinbentley1.platform.github-run-id";
const SANDBOX_PLATFORM_REPOSITORY_LABEL = "io.collinbentley1.platform.repository-id";
const SANDBOX_TARGET_REPOSITORY_LABEL = "io.collinbentley1.platform.target-repository-id";
const CAPABILITY_REQUIRED_FILES = [
  ".github/workflows/cleanup-preview.yml",
  ".github/workflows/deploy-preview.yml",
  ".github/workflows/deploy-prod.yml",
  ".github/workflows/infrastructure.yml",
  ".github/workflows/reconcile-previews.yml",
  "terraform/modules/bootstrap/main.tf",
  "terraform/modules/bootstrap/preview-runtime-deny.tf",
  "terraform/modules/bootstrap/variables.tf",
  "terraform/modules/cloud-run-service/main.tf",
  "tools/ci/cloud-run-dhi-parity.sh",
  "tools/ci/cloud-run-prod-dhi-transition.sh",
  "tools/ci/cloud-run-preview-controller.sh",
  "tools/ci/cloud-run-preview-traffic.sh",
  "tools/ci/container-artifact-contract.sh",
  "tools/ci/deployment-parity-transition.sh",
  "tools/ci/preview-runtime-iam-contract.sh",
] as const;
const CONSUMER_WORKFLOW_CALLS: Readonly<Record<string, readonly string[]>> = {
  "application.yml": ["application.yml"],
  "cleanup-preview.yml": ["cleanup-preview.yml"],
  "deploy-preview.yml": ["deploy-preview.yml"],
  "deploy-prod.yml": ["infrastructure.yml", "deploy-prod.yml"],
  "infrastructure.yml": ["infrastructure.yml"],
  "reconcile-previews.yml": ["reconcile-previews.yml"],
  "socket-firewall.yml": ["socket-firewall.yml"],
};
const FORBIDDEN_PRE_MIGRATION_WORKFLOW_SHAS = new Set([
  "734d0cd02187f88c6e91263f127dc3f4c0709feb",
  "1378a3e81a5e74c71f2adfd5548b430bb008490e",
  "37bd4b1beea8802ec85c38d69ea08d5992c75a50",
  "42435a3c4c5c063a342765ef7c85047224217fe2",
  "7f01d9f008a7757df12f13ac8fa0f261600cf21a",
  "4f032955477c26b942fdd4f1b01f5272380390ea",
  "92c73184bc527388b5e10ccb5e4f0222a84e68b5",
  "33ab9b9a5f3d8a0553372980c22540cad001f776",
]);

const BRIDGE_PHASES = [
  "controller.start",
  "controller.prepare",
  "controller.acquire",
  "controller.proof",
  "controller.terraform-init",
  "controller.terraform-plan",
  "controller.plan-read",
  "controller.plan-publish",
  "controller.apply-authorize",
  "controller.apply",
  "controller.apply-audit",
  "controller.apply-drain",
  "controller.apply-publish",
  "controller.cleanup",
  "controller.complete",
  "controller.failed",
  "executor.inventory",
  "executor.account-create",
  "executor.role-create",
  "executor.policy",
  "executor.enable",
  "executor.token-mint",
  "executor.baseline-proof",
  "executor.disable",
  "executor.project-leases",
  "executor.marker-leases",
  "executor.final-enable",
  "executor.permission-proof",
  "executor.ready",
  "recovery.start",
  "recovery.source-proof",
  "recovery.inventory",
  "recovery.complete",
  "recovery.failed",
] as const;
const BRIDGE_PHASE_SET = new Set<string>(BRIDGE_PHASES);

export type BridgePhase = (typeof BRIDGE_PHASES)[number];

export interface BridgeTelemetry {
  readonly phase: (phase: BridgePhase) => void;
  readonly stop: () => void;
}

interface CgroupMemorySnapshot {
  readonly currentBytes?: number;
  readonly oom?: number;
  readonly oomKill?: number;
  readonly peakBytes?: number;
}

const NOOP_BRIDGE_TELEMETRY: BridgeTelemetry = {
  phase: () => undefined,
  stop: () => undefined,
};


if (LEASE_MINUTES <= JOB_TIMEOUT_MINUTES + 10) {
  throw new Error("The emergency IAM expiry must remain safely beyond the job timeout.");
}
if (
  MINIMUM_PRE_APPLY_MINUTES >= INTERNAL_OPERATION_MINUTES ||
  INTERNAL_OPERATION_MINUTES > JOB_TIMEOUT_MINUTES - 10
) {
  throw new Error("The operation and pre-apply deadlines must reserve unconditional cleanup.");
}
if (MAIN_STEP_TIMEOUT_MINUTES > JOB_TIMEOUT_MINUTES - 9) {
  throw new Error("The crash-recovery deadline escaped the main job's reserved tail.");
}

export const REPOSITORY_NAMES = [
  "cdbentley",
  "runsetta",
  "healthmcp",
  "critical-history",
] as const;

export type RepositoryName = (typeof REPOSITORY_NAMES)[number];
export type TerraformRoot = "bootstrap" | "prod";
export type ExecutionMode = "plan" | "apply";

export interface RepositoryContract {
  readonly projectId: string;
  readonly repositoryId: string;
  readonly state: {
    readonly bootstrap: { readonly bucket: string; readonly prefix: string };
    readonly prod: { readonly bucket: string; readonly prefix: string };
  };
}

export const REPOSITORIES: Readonly<Record<RepositoryName, RepositoryContract>> = {
  cdbentley: {
    projectId: "cdbentley",
    repositoryId: "1255553151",
    state: {
      bootstrap: {
        bucket: "cdbentley-tfstate-882468538648-bootstrap",
        prefix: "cdbentley/bootstrap",
      },
      prod: { bucket: "cdbentley-tfstate-882468538648", prefix: "cdbentley/prod" },
    },
  },
  runsetta: {
    projectId: "runsetta",
    repositoryId: "711292980",
    state: {
      bootstrap: {
        bucket: "runsetta-tfstate-601124730704-bootstrap",
        prefix: "runsetta/bootstrap",
      },
      prod: { bucket: "runsetta-tfstate-601124730704", prefix: "runsetta/prod" },
    },
  },
  healthmcp: {
    projectId: "medlock-1025243085",
    repositoryId: "1025243085",
    state: {
      bootstrap: {
        bucket: "medlock-tfstate-1025243085-bootstrap",
        prefix: "medlock/bootstrap",
      },
      prod: { bucket: "medlock-tfstate-1025243085", prefix: "medlock/prod" },
    },
  },
  "critical-history": {
    projectId: "critical-history-16823277",
    repositoryId: "280932482",
    state: {
      bootstrap: {
        bucket: "critical-history-tfstate-422714632513-bootstrap",
        prefix: "critical-history/bootstrap",
      },
      prod: {
        bucket: "critical-history-tfstate-422714632513",
        prefix: "critical-history/prod",
      },
    },
  },
};

const BOOTSTRAP_RESOURCE_TYPES = new Set([
  "google_iam_deny_policy",
  "google_iam_workload_identity_pool",
  "google_iam_workload_identity_pool_provider",
  "google_project_iam_binding",
  "google_project_iam_custom_role",
  "google_project_iam_member",
  "google_project_service",
  "google_service_account",
  "google_service_account_iam_member",
  "google_storage_bucket",
  "google_storage_bucket_object",
  "google_storage_bucket_iam_binding",
  "google_storage_bucket_iam_member",
]);

const PROD_RESOURCE_TYPES = new Set([
  "google_artifact_registry_repository",
  "google_artifact_registry_repository_iam_member",
  "google_cloud_run_v2_service",
  "google_cloud_run_v2_service_iam_member",
  "google_firestore_database",
  "google_secret_manager_secret",
  "google_secret_manager_secret_iam_member",
]);

const PROD_FORGET_ONLY_ADDRESSES = [
  /^module\.site\.google_cloud_run_domain_mapping\.site\["[a-z0-9.-]+"\]$/,
  /^module\.site\.google_project_iam_member\.runtime_firestore_user\[0\]$/,
] as const;

type JsonPrimitive = boolean | null | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export interface Invocation {
  readonly approvedManifestSha256: string;
  readonly approvedPlanRunId: string;
  readonly operationBudgetSeconds: number;
  readonly consumerRoot: string;
  readonly consumerSha: string;
  readonly githubActionsToken: string;
  readonly githubRunId: string;
  readonly legacyCompatibilityMode: boolean;
  readonly mode: ExecutionMode;
  readonly ownerAccessToken: string;
  readonly platformActionsToken: string;
  readonly platformRoot: string;
  readonly platformSha: string;
  readonly repository: RepositoryName;
  readonly runnerTemp: string;
  readonly stepSummary: string;
  readonly terraformBinary: string;
  readonly terraformProviderArchive: string;
  readonly terraformProviderDirectory: string;
  readonly terraformRoot: TerraformRoot;
  readonly terraformSandboxImage: string;
  readonly transitionPlatformRoot: string;
  readonly transitionWorkflowSha: string;
}

export interface ControllerSecrets {
  readonly consumerActionsToken: string;
  readonly ownerAccessToken: string;
  readonly platformActionsToken: string;
}

export interface RecoveryInvocation {
  readonly githubRunId: string;
  readonly ownerAccessToken: string;
  readonly platformRoot: string;
  readonly platformSha: string;
  readonly repository: RepositoryName;
  readonly runnerTemp: string;
}

export interface StorageLease {
  readonly condition: {
    readonly description: string;
    readonly expression: string;
    readonly title: string;
  };
  readonly members: readonly [string];
  readonly role: string;
}

export interface ServiceAccount {
  readonly description: string;
  readonly disabled: boolean;
  readonly displayName: string;
  readonly email: string;
  readonly etag: string;
  readonly name: string;
  readonly projectId: string;
  readonly uniqueId: string;
}

interface ServiceAccountIdentity {
  readonly disabled: boolean;
  readonly email: string;
  readonly name: string;
  readonly projectId: string;
  readonly uniqueId: string;
}

interface ServiceAccountListEntry {
  readonly email: string;
  readonly value: Record<string, unknown>;
}

interface ExecutorProvenance {
  readonly approvedPlanRunId: string;
  readonly expiresAt: Date;
  readonly mode: ExecutionMode;
  readonly repository: RepositoryName;
  readonly root: TerraformRoot;
  readonly runId: string;
}

export interface ProjectCustomRole {
  readonly deleted: boolean;
  readonly description: string;
  readonly etag: string;
  readonly includedPermissions: readonly string[];
  readonly name: string;
  readonly stage: "GA";
  readonly title: string;
}

type EphemeralRoleIntent = Omit<ProjectCustomRole, "deleted" | "etag">;

export interface ExecutorSession {
  readonly accessToken: string;
  readonly executorEmail: string;
  readonly executorUniqueId: string;
  readonly tokenExpiresAtMs: number;
}

export interface IamBinding {
  readonly condition?: {
    readonly description?: string;
    readonly expression: string;
    readonly location?: string;
    readonly title: string;
  };
  readonly members: readonly string[];
  readonly role: string;
}

export interface IamPolicy {
  readonly auditConfigs?: readonly JsonValue[];
  readonly bindings: readonly IamBinding[];
  readonly etag: string;
  readonly version: number;
}

export interface PlanIdentity {
  readonly consumerSha: string;
  readonly consumerTreeSha: string;
  readonly dhiParityId: string;
  readonly legacyCompatibilityMode: boolean;
  readonly maxMutatorTokenLifetimeSeconds: number;
  readonly markerProof: readonly MarkerStateProof[];
  readonly platformSha: string;
  readonly projectId: string;
  readonly repository: RepositoryName;
  readonly repositoryId: string;
  readonly terraformRoot: TerraformRoot;
  readonly tokenDrainSeconds: number;
  readonly transitionWorkflowSha: string;
}

export interface PlatformCapability {
  readonly dhiParityId: string;
  readonly maxMutatorTokenLifetimeSeconds: number;
}

export interface PreparationResult extends PlatformCapability {
  readonly consumerTreeSha: string;
  readonly tokenDrainSeconds: number;
}

export interface MarkerStateProof {
  readonly bucket: string;
  readonly generation: string | null;
  readonly metadata: {
    readonly "repository-id": string;
    readonly state: "clear";
    readonly version: "1";
  } | null;
  readonly metageneration: string | null;
  readonly repository: RepositoryName;
  readonly repositoryId: string;
  readonly state: "absent" | "clear";
}

export interface ExecutionProof extends PreparationResult {
  readonly freezeProof: ConsumerFreezeProof;
  readonly markerProof: readonly MarkerStateProof[];
}

export interface ConsumerFreezeProof {
  readonly observedAt: string;
  readonly repositories: readonly {
    readonly actionsEnabled: false;
    readonly activeRunCount: 0;
    readonly latestPossibleTokenIssuance: string | null;
    readonly repository: RepositoryName;
    readonly repositoryId: string;
  }[];
  readonly tokenDrainSeconds: number;
}

export interface ReviewManifestResult {
  readonly canonical: string;
  readonly sha256: string;
}

export type Fetcher = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface CommandRequest {
  readonly argv: readonly string[];
  readonly capture?: boolean;
  readonly cwd: string;
  readonly deadlineMs: number;
  readonly env: Readonly<Record<string, string>>;
  readonly ignoreFailure?: boolean;
  readonly stdin?: string;
  readonly label: string;
}

export interface BridgeDependencies {
  readonly acquireExecutor: (
    invocation: Invocation,
    leaseExpiresAt: Date,
    operationDeadlineMs: number,
  ) => Promise<ExecutorSession>;
  readonly appendSummary: (invocation: Invocation, value: string) => Promise<void>;
  readonly consumeApproval: (
    invocation: Invocation,
    session: ExecutorSession,
    review: ReviewManifestResult,
    proof: ExecutionProof,
    nowMs: number,
  ) => Promise<void>;
  readonly elevateExecutor: (
    invocation: Invocation,
    session: ExecutorSession,
    leaseExpiresAt: Date,
    operationDeadlineMs: number,
  ) => Promise<void>;
  readonly inspectPlan: (path: string) => Promise<void>;
  readonly now: () => number;
  readonly prepare: (
    invocation: Invocation,
    operationDeadlineMs: number,
  ) => Promise<PreparationResult>;
  readonly proveFreeze: (
    invocation: Invocation,
    tokenDrainSeconds: number,
  ) => Promise<ConsumerFreezeProof>;
  readonly proveMarkers: (
    invocation: Invocation,
    session: ExecutorSession,
    requireTargetClear: boolean,
  ) => Promise<readonly MarkerStateProof[]>;
  readonly publishPlanReceipt: (
    invocation: Invocation,
    session: ExecutorSession,
    review: ReviewManifestResult,
    proof: ExecutionProof,
    nowMs: number,
  ) => Promise<void>;
  readonly publishPostApplyReceipt: (
    invocation: Invocation,
    session: ExecutorSession,
    review: ReviewManifestResult,
    proof: ExecutionProof,
    nowMs: number,
  ) => Promise<void>;
  readonly readPlanJson: (
    invocation: Invocation,
    session: ExecutorSession,
    terraformDirectory: string,
    planPath: string,
    operationDeadlineMs: number,
  ) => Promise<string>;
  readonly releaseExecutor: (
    invocation: Invocation,
    session: ExecutorSession | undefined,
    operationDeadlineMs: number,
  ) => Promise<void>;
  readonly removePrivatePath: (path: string) => Promise<void>;
  readonly runTerraform: (
    invocation: Invocation,
    session: ExecutorSession,
    terraformDirectory: string,
    args: readonly string[],
    operationDeadlineMs: number,
  ) => Promise<void>;
  readonly verifyApproval: (
    invocation: Invocation,
    session: ExecutorSession,
    proof: ExecutionProof,
    nowMs: number,
  ) => Promise<ReviewManifestResult>;
  readonly waitForPostMutationDrain: (
    invocation: Invocation,
    mutationCompletedAtMs: number,
    operationDeadlineMs: number,
  ) => Promise<void>;
}

export interface RecoveryDependencies {
  readonly now: () => number;
  readonly recoverArtifacts: (
    invocation: RecoveryInvocation,
    recoveryDeadlineMs: number,
  ) => Promise<void>;
  readonly verifySource: (invocation: RecoveryInvocation) => Promise<void>;
}

function validateProtectedRoute(source: NodeJS.ProcessEnv): void {
  exact(source.GITHUB_EVENT_NAME_EXACT, "workflow_dispatch", "GitHub event");
  exact(source.GITHUB_REF_EXACT, "refs/heads/main", "GitHub ref");
  exact(source.GITHUB_REPOSITORY_EXACT, PLATFORM_REPOSITORY, "GitHub repository");
  exact(source.GITHUB_REPOSITORY_ID_EXACT, PLATFORM_REPOSITORY_ID, "GitHub repository ID");
  exact(source.GITHUB_REPOSITORY_OWNER_ID_EXACT, PLATFORM_OWNER_ID, "GitHub owner ID");
  exact(source.GITHUB_ACTOR_ID_EXACT, PLATFORM_OWNER_ID, "GitHub actor ID");
  exact(source.GITHUB_RUN_ATTEMPT_EXACT, "1", "GitHub run attempt");
  exact(source.RUNNER_ENVIRONMENT_EXACT, "github-hosted", "runner environment");
  exact(source.RUNNER_OS_EXACT, "Linux", "runner OS");
  exact(source.RUNNER_ARCH_EXACT, "X64", "runner architecture");
  exact(
    source.GITHUB_WORKFLOW_REF_EXACT,
    `${PLATFORM_REPOSITORY}/.github/workflows/protected-bootstrap-implementation.yml@refs/heads/main`,
    "workflow ref",
  );
}

export function validateRecoveryInvocation(
  source: NodeJS.ProcessEnv = process.env,
): RecoveryInvocation {
  validateProtectedRoute(source);
  rejectRecoveryCapabilities(source);
  return {
    githubRunId: numeric(required(source, "GITHUB_RUN_ID_EXACT"), "GitHub run ID"),
    ownerAccessToken: secret(source, "OWNER_OAUTH_ACCESS_TOKEN"),
    platformRoot: safeAbsoluteDirectory(required(source, "PLATFORM_ROOT"), "platform root"),
    platformSha: sha(required(source, "GITHUB_SHA_EXACT"), "platform SHA"),
    repository: repositoryName(required(source, "TARGET_REPOSITORY")),
    runnerTemp: safeAbsoluteDirectory(required(source, "RUNNER_TEMP_EXACT"), "runner temp"),
  };
}

function rejectRecoveryCapabilities(source: NodeJS.ProcessEnv): void {
  for (const name of [
    "APPROVED_MANIFEST_SHA256",
    "APPROVED_PLAN_RUN_ID",
    "BRIDGE_OPERATION_BUDGET_SECONDS_EXACT",
    "CONSUMER_ACTIONS_READ_TOKEN",
    "CONSUMER_ROOT",
    "CONSUMER_SHA",
    "EXECUTION_MODE",
    "LEGACY_COMPATIBILITY_MODE",
    "PLATFORM_ACTIONS_READ_TOKEN",
    "TERRAFORM_BINARY",
    "TERRAFORM_PROVIDER_ARCHIVE",
    "TERRAFORM_PROVIDER_DIRECTORY",
    "TERRAFORM_ROOT",
    "TERRAFORM_SANDBOX_IMAGE",
    "TRANSITION_PLATFORM_ROOT",
    "TRANSITION_WORKFLOW_SHA",
  ]) {
    if (source[name] !== undefined) {
      throw new Error("Recovery-only execution received a normal-operation capability.");
    }
  }
}

export function validateInvocation(source: NodeJS.ProcessEnv = process.env): Invocation {
  validateProtectedRoute(source);

  const repository = repositoryName(required(source, "TARGET_REPOSITORY"));
  const terraformRoot = rootName(required(source, "TERRAFORM_ROOT"));
  const mode = executionMode(required(source, "EXECUTION_MODE"));
  const platformSha = sha(required(source, "GITHUB_SHA_EXACT"), "platform SHA");
  const consumerSha = sha(required(source, "CONSUMER_SHA"), "consumer SHA");
  const githubRunId = numeric(required(source, "GITHUB_RUN_ID_EXACT"), "GitHub run ID");
  const operationBudgetSeconds = Number(numeric(
    required(source, "BRIDGE_OPERATION_BUDGET_SECONDS_EXACT"),
    "bridge operation budget seconds",
  ));
  if (operationBudgetSeconds < 420 || operationBudgetSeconds > 26 * 60) {
    throw new Error("Bridge operation budget escaped its reviewed 420..1560 second range.");
  }
  const legacyCompatibilityMode = booleanString(
    required(source, "LEGACY_COMPATIBILITY_MODE"),
    "legacy compatibility mode",
  );
  const transitionWorkflowSha = source.TRANSITION_WORKFLOW_SHA ?? "";
  if (transitionWorkflowSha !== "") sha(transitionWorkflowSha, "transition workflow SHA");
  if (terraformRoot === "prod" && (legacyCompatibilityMode || transitionWorkflowSha !== "")) {
    throw new Error("Production mode forbids bootstrap migration controls.");
  }
  if (legacyCompatibilityMode && transitionWorkflowSha !== "") {
    throw new Error("Legacy compatibility is allowed only for the initial migration without a transition SHA.");
  }
  if (transitionWorkflowSha === platformSha) {
    throw new Error("The transition workflow SHA must differ from the active platform SHA.");
  }
  const approvedManifestSha256 = source.APPROVED_MANIFEST_SHA256 ?? "";
  const approvedPlanRunId = source.APPROVED_PLAN_RUN_ID ?? "";
  if (mode === "plan" && (approvedManifestSha256 !== "" || approvedPlanRunId !== "")) {
    throw new Error("Plan mode forbids an approved plan run or manifest digest.");
  }
  if (mode === "apply") {
    hash(approvedManifestSha256, "approved manifest digest");
    numeric(approvedPlanRunId, "approved plan run ID");
    if (approvedPlanRunId === githubRunId) {
      throw new Error("An apply run cannot approve itself.");
    }
  }

  const ownerAccessToken = secret(source, "OWNER_OAUTH_ACCESS_TOKEN");
  const githubActionsToken = secret(source, "CONSUMER_ACTIONS_READ_TOKEN");
  const platformActionsToken = secret(source, "PLATFORM_ACTIONS_READ_TOKEN");
  if (
    new Set([ownerAccessToken, githubActionsToken, platformActionsToken]).size !== 3
  ) {
    throw new Error("The Google, consumer-GitHub, and platform-GitHub credentials must differ.");
  }

  exact(
    required(source, "TERRAFORM_SANDBOX_IMAGE"),
    TERRAFORM_SANDBOX_IMAGE,
    "Terraform sandbox image",
  );
  return {
    approvedManifestSha256,
    approvedPlanRunId,
    consumerRoot: safeAbsoluteDirectory(required(source, "CONSUMER_ROOT"), "consumer root"),
    consumerSha,
    githubActionsToken,
    githubRunId,
    legacyCompatibilityMode,
    mode,
    operationBudgetSeconds,
    ownerAccessToken,
    platformActionsToken,
    platformRoot: safeAbsoluteDirectory(required(source, "PLATFORM_ROOT"), "platform root"),
    platformSha,
    repository,
    runnerTemp: safeAbsoluteDirectory(required(source, "RUNNER_TEMP_EXACT"), "runner temp"),
    stepSummary: safeAbsolutePath(required(source, "GITHUB_STEP_SUMMARY_EXACT"), "step summary"),
    terraformBinary: safeAbsolutePath(
      required(source, "TERRAFORM_BINARY"),
      "Terraform binary",
    ),
    terraformProviderArchive: safeAbsolutePath(
      required(source, "TERRAFORM_PROVIDER_ARCHIVE"),
      "Terraform provider archive",
    ),
    terraformProviderDirectory: safeAbsoluteDirectory(
      required(source, "TERRAFORM_PROVIDER_DIRECTORY"),
      "Terraform provider directory",
    ),
    terraformRoot,
    terraformSandboxImage: TERRAFORM_SANDBOX_IMAGE,
    transitionPlatformRoot: safeAbsoluteDirectory(
      required(source, "TRANSITION_PLATFORM_ROOT"),
      "transition platform root",
    ),
    transitionWorkflowSha,
  };
}

export function buildStorageLease(
  repository: RepositoryName,
  root: TerraformRoot,
  runId: string,
  expiresAt: Date,
  executorServiceAccountEmail: string,
  mode: ExecutionMode = "plan",
  approvedPlanRunId = "",
): StorageLease {
  numeric(runId, "GitHub run ID");
  if (mode === "apply") numeric(approvedPlanRunId, "approved plan run ID");
  if (mode === "plan" && approvedPlanRunId !== "") {
    throw new Error("Plan storage scope cannot name an approved run.");
  }
  if (!Number.isFinite(expiresAt.getTime())) throw new Error("Lease expiration is invalid.");
  const contract = REPOSITORIES[repository];
  const backend = contract.state[root];
  const bucketResources =
    root === "bootstrap"
      ? [
          contract.state.bootstrap.bucket,
          contract.state.prod.bucket,
          `${contract.state.prod.bucket}-access-logs`,
        ]
      : [contract.state.prod.bucket];
  const resourceNames = [
    ...bucketResources.map((bucket) => `projects/_/buckets/${bucket}`),
    `projects/_/buckets/${backend.bucket}/objects/${backend.prefix}/default.tfstate`,
    ...(mode === "apply"
      ? [`projects/_/buckets/${backend.bucket}/objects/${backend.prefix}/default.tflock`]
      : []),
  ].toSorted();
  const expression = [
    `request.time < timestamp('${expiresAt.toISOString()}')`,
    `(${resourceNames.map((name) => `resource.name == '${name}'`).join(" || ")})`,
  ].join(" && ");
  return {
    condition: {
      description: `Temporary ${root} state lease for ${repository}; expires automatically.`,
      expression,
      title: `codex-executor-storage-${mode}-${runId}`,
    },
    members: [executorMember(contract.projectId, executorServiceAccountEmail)],
    role: mode === "plan"
      ? "roles/storage.viewer"
      : root === "bootstrap"
      ? "roles/storage.admin"
      : "roles/storage.objectAdmin",
  };
}

export function buildReceiptLeases(
  repository: RepositoryName,
  root: TerraformRoot,
  runId: string,
  expiresAt: Date,
  mode: ExecutionMode,
  approvedPlanRunId: string,
  executorServiceAccountEmail: string,
): readonly IamBinding[] {
  numeric(runId, "GitHub run ID");
  if (mode === "apply") numeric(approvedPlanRunId, "approved plan run ID");
  if (mode === "plan" && approvedPlanRunId !== "") {
    throw new Error("Plan receipt scope cannot name an approved run.");
  }
  const contract = REPOSITORIES[repository];
  const state = contract.state[root];
  const planRunId = mode === "plan" ? runId : approvedPlanRunId;
  const planResource =
    `projects/_/buckets/${state.bucket}/objects/${receiptObjectName(state, "plans", planRunId)}`;
  const consumedResource = mode === "apply"
    ? `projects/_/buckets/${state.bucket}/objects/${receiptObjectName(state, "consumed", approvedPlanRunId)}`
    : undefined;
  const resultResource = mode === "apply"
    ? `projects/_/buckets/${state.bucket}/objects/${receiptObjectName(state, "results", runId)}`
    : undefined;
  const member = executorMember(contract.projectId, executorServiceAccountEmail);
  const viewerResources = [
    planResource,
    ...(consumedResource === undefined ? [] : [consumedResource]),
    ...(resultResource === undefined ? [] : [resultResource]),
  ];
  const creatorResources = consumedResource === undefined
    ? [planResource]
    : [consumedResource, resultResource!];
  return [
    {
      condition: {
        ...expiringCondition(
          `codex-receipt-create-${runId}`,
          `Create-only immutable receipt scope for ${repository} ${root}.`,
          expiresAt,
        ),
        expression: [
          `request.time < timestamp('${expiresAt.toISOString()}')`,
          `(${creatorResources.map((resource) => `resource.name == '${resource}'`).join(" || ")})`,
        ].join(" && "),
      },
      members: [member],
      role: "roles/storage.objectCreator",
    },
    {
      condition: {
        ...expiringCondition(
          `codex-receipt-read-${runId}`,
          `Read-only immutable receipt scope for ${repository} ${root}.`,
          expiresAt,
        ),
        expression: [
          `request.time < timestamp('${expiresAt.toISOString()}')`,
          `(${viewerResources.map((resource) => `resource.name == '${resource}'`).join(" || ")})`,
        ].join(" && "),
      },
      members: [member],
      role: "roles/storage.objectViewer",
    },
  ];
}

export function buildMarkerReadLease(
  markerRepository: RepositoryName,
  runId: string,
  expiresAt: Date,
  executorProjectId: string,
  executorServiceAccountEmail: string,
): IamBinding {
  numeric(runId, "GitHub run ID");
  const markerResource = deploymentParityMarkerResource(markerRepository);
  return {
    condition: {
      ...expiringCondition(
        `codex-marker-read-${runId}-${REPOSITORY_NAMES.indexOf(markerRepository)}`,
        `Read only the ${markerRepository} deployment-parity marker.`,
        expiresAt,
      ),
      expression: [
        `request.time < timestamp('${expiresAt.toISOString()}')`,
        "resource.type == 'storage.googleapis.com/Object'",
        `resource.name == '${markerResource}'`,
      ].join(" && "),
    },
    members: [executorMember(executorProjectId, executorServiceAccountEmail)],
    role: "roles/storage.objectViewer",
  };
}

export function buildMarkerMutationLease(
  repository: RepositoryName,
  runId: string,
  expiresAt: Date,
  executorServiceAccountEmail: string,
): IamBinding {
  numeric(runId, "GitHub run ID");
  const contract = REPOSITORIES[repository];
  return {
    condition: {
      ...expiringCondition(
        `codex-marker-mutation-${runId}`,
        `Mutate only the ${repository} deployment-parity marker.`,
        expiresAt,
      ),
      expression: [
        `request.time < timestamp('${expiresAt.toISOString()}')`,
        "resource.type == 'storage.googleapis.com/Object'",
        `resource.name == '${deploymentParityMarkerResource(repository)}'`,
      ].join(" && "),
    },
    members: [executorMember(contract.projectId, executorServiceAccountEmail)],
    role: "roles/storage.objectAdmin",
  };
}

function deploymentParityMarkerResource(repository: RepositoryName): string {
  const projectId = REPOSITORIES[repository].projectId;
  return `projects/_/buckets/${projectId}${DEPLOYMENT_PARITY_BUCKET_SUFFIX}/objects/${DEPLOYMENT_PARITY_MARKER_OBJECT}`;
}

export function buildExecutorProjectLeases(
  repository: RepositoryName,
  runId: string,
  expiresAt: Date,
  executorServiceAccountEmail: string,
  ephemeralRoleName: string,
  phase: "mutation" | "read",
): readonly IamBinding[] {
  numeric(runId, "GitHub run ID");
  const contract = REPOSITORIES[repository];
  exact(
    ephemeralRoleName.startsWith(`projects/${contract.projectId}/roles/${EXECUTOR_ROLE_PREFIX}`),
    true,
    "ephemeral executor role project and prefix",
  );
  return [{
    condition: expiringCondition(
      `codex-executor-${phase}-${runId}`,
      `Temporary ${phase} custom-role lease for ${repository}.`,
      expiresAt,
    ),
    members: [executorMember(contract.projectId, executorServiceAccountEmail)],
    role: ephemeralRoleName,
  }];
}

export function executorControlPermissions(
  repository: RepositoryName,
  root: TerraformRoot,
  phase: "mutation" | "read",
): readonly string[] {
  const bootstrapRead = [
    "iam.denypolicies.get",
    "iam.denypolicies.list",
    "iam.roles.get",
    "iam.roles.list",
    "iam.serviceAccounts.get",
    "iam.serviceAccounts.getIamPolicy",
    "iam.serviceAccounts.list",
    "iam.workloadIdentityPools.get",
    "iam.workloadIdentityPools.list",
    "iam.workloadIdentityPoolProviders.get",
    "iam.workloadIdentityPoolProviders.list",
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "serviceusage.services.get",
    "serviceusage.services.list",
    "serviceusage.services.use",
    "storage.buckets.get",
    "storage.buckets.getIamPolicy",
    "storage.buckets.list",
  ];
  const prodRead = [
    "artifactregistry.locations.get",
    "artifactregistry.locations.list",
    "artifactregistry.repositories.get",
    "artifactregistry.repositories.getIamPolicy",
    "artifactregistry.repositories.list",
    "artifactregistry.repositories.listEffectiveTags",
    "artifactregistry.repositories.listTagBindings",
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "run.locations.list",
    "run.operations.get",
    "run.operations.list",
    "run.services.get",
    "run.services.getIamPolicy",
    "run.services.list",
    "run.services.listEffectiveTags",
    "run.services.listTagBindings",
    "serviceusage.services.get",
    "serviceusage.services.list",
    "serviceusage.services.use",
    ...(repository === "runsetta" || repository === "healthmcp"
      ? [
          "secretmanager.locations.get",
          "secretmanager.locations.list",
          "secretmanager.secrets.get",
          "secretmanager.secrets.getIamPolicy",
          "secretmanager.secrets.list",
          "secretmanager.secrets.listEffectiveTags",
          "secretmanager.secrets.listTagBindings",
        ]
      : []),
    ...(repository === "healthmcp"
      ? [
          "datastore.databases.get",
          "datastore.databases.getMetadata",
          "datastore.databases.list",
        ]
      : []),
  ];
  const mutation = root === "bootstrap"
    ? [
        "iam.denypolicies.create",
        "iam.denypolicies.delete",
        "iam.denypolicies.update",
        "iam.roles.create",
        "iam.roles.delete",
        "iam.roles.undelete",
        "iam.roles.update",
        "iam.serviceAccounts.create",
        "iam.serviceAccounts.delete",
        "iam.serviceAccounts.disable",
        "iam.serviceAccounts.enable",
        "iam.serviceAccounts.setIamPolicy",
        "iam.serviceAccounts.update",
        "iam.workloadIdentityPools.create",
        "iam.workloadIdentityPools.delete",
        "iam.workloadIdentityPools.undelete",
        "iam.workloadIdentityPools.update",
        "iam.workloadIdentityPoolProviders.create",
        "iam.workloadIdentityPoolProviders.delete",
        "iam.workloadIdentityPoolProviders.undelete",
        "iam.workloadIdentityPoolProviders.update",
        "resourcemanager.projects.setIamPolicy",
        "serviceusage.services.disable",
        "serviceusage.services.enable",
        "storage.buckets.create",
        "storage.buckets.delete",
        "storage.buckets.setIamPolicy",
        "storage.buckets.update",
      ]
    : [
        "artifactregistry.repositories.create",
        "artifactregistry.repositories.delete",
        "artifactregistry.repositories.setIamPolicy",
        "artifactregistry.repositories.update",
        "run.services.create",
        "run.services.delete",
        "run.services.setIamPolicy",
        "run.services.update",
        ...(repository === "runsetta" || repository === "healthmcp"
          ? [
              "secretmanager.secrets.create",
              "secretmanager.secrets.delete",
              "secretmanager.secrets.setIamPolicy",
              "secretmanager.secrets.update",
            ]
          : []),
        ...(repository === "healthmcp"
          ? [
              "datastore.databases.create",
              "datastore.databases.delete",
              "datastore.databases.update",
              "datastore.operations.get",
              "datastore.operations.list",
            ]
          : []),
      ];
  return [...new Set(phase === "read"
    ? root === "bootstrap" ? bootstrapRead : prodRead
    : [...(root === "bootstrap" ? bootstrapRead : prodRead), ...mutation])].toSorted();
}

export function buildTokenCreatorLease(
  repository: RepositoryName,
  runId: string,
  expiresAt: Date,
): IamBinding {
  return {
    condition: expiringCondition(
      `codex-owner-mint-${runId}`,
      `Owner may mint only the disabled-at-rest executor for ${repository}.`,
      expiresAt,
    ),
    members: [OWNER_MEMBER],
    role: "roles/iam.serviceAccountTokenCreator",
  };
}

export function buildRuntimeActAsLeases(
  repository: RepositoryName,
  runId: string,
  expiresAt: Date,
  executorServiceAccountEmail: string,
): Readonly<Record<string, IamBinding>> {
  const projectId = REPOSITORIES[repository].projectId;
  const member = executorMember(projectId, executorServiceAccountEmail);
  return Object.fromEntries(
    runtimeServiceAccountEmails(repository).map((email, index) => [
      email,
      {
        condition: expiringCondition(
          `codex-executor-actas-${runId}-${index}`,
          `Temporary exact-runtime actAs lease for ${repository}.`,
          expiresAt,
        ),
        members: [member],
        role: "roles/iam.serviceAccountUser",
      } satisfies IamBinding,
    ]),
  );
}

function runtimeServiceAccountEmails(repository: RepositoryName): readonly string[] {
  const projectId = REPOSITORIES[repository].projectId;
  return ["cloud-run-bootstrap", "cloud-run-preview", "cloud-run-runtime"].map(
    (account) => `${account}@${projectId}.iam.gserviceaccount.com`,
  );
}

function expiringCondition(
  title: string,
  description: string,
  expiresAt: Date,
): NonNullable<IamBinding["condition"]> {
  if (!Number.isFinite(expiresAt.getTime())) throw new Error("Lease expiration is invalid.");
  return {
    description,
    expression: `request.time < timestamp('${expiresAt.toISOString()}')`,
    title,
  };
}

export function addExactLease(policy: IamPolicy, lease: IamBinding): IamPolicy {
  const leaseCondition = lease.condition;
  if (leaseCondition === undefined) throw new Error("Every temporary IAM lease needs a condition.");
  const collisions = policy.bindings.filter(
    (binding) => binding.condition?.title === leaseCondition.title,
  );
  if (collisions.length > 0) {
    if (collisions.length === 1 && bindingEqualsLease(collisions[0]!, lease)) return policy;
    throw new Error("An IAM condition-title collision prevents adding the temporary lease.");
  }
  return {
    ...(policy.auditConfigs === undefined ? {} : { auditConfigs: policy.auditConfigs }),
    bindings: [...policy.bindings, lease],
    etag: policy.etag,
    version: 3,
  };
}

export function removeExactLease(policy: IamPolicy, lease: IamBinding): IamPolicy {
  const leaseCondition = lease.condition;
  if (leaseCondition === undefined) throw new Error("Every temporary IAM lease needs a condition.");
  const matches = policy.bindings.filter((binding) => bindingEqualsLease(binding, lease));
  if (matches.length === 0) {
    if (policy.bindings.some((binding) => binding.condition?.title === leaseCondition.title)) {
      throw new Error("The temporary IAM lease was changed and cannot be safely removed.");
    }
    return policy;
  }
  if (matches.length !== 1) throw new Error("The exact temporary IAM lease is duplicated.");
  return {
    ...(policy.auditConfigs === undefined ? {} : { auditConfigs: policy.auditConfigs }),
    bindings: policy.bindings.filter((binding) => !bindingEqualsLease(binding, lease)),
    etag: policy.etag,
    version: policy.version,
  };
}

export function buildReviewManifest(raw: unknown, identity: PlanIdentity): ReviewManifestResult {
  if (typeof identity.legacyCompatibilityMode !== "boolean") {
    throw new Error("Review identity compatibility mode must be boolean.");
  }
  if (identity.transitionWorkflowSha !== "") {
    sha(identity.transitionWorkflowSha, "transition workflow SHA");
  }
  if (
    identity.terraformRoot === "prod" &&
    (identity.legacyCompatibilityMode || identity.transitionWorkflowSha !== "")
  ) {
    throw new Error("Production review identity contains bootstrap migration controls.");
  }
  if (identity.legacyCompatibilityMode && identity.transitionWorkflowSha !== "") {
    throw new Error("Review identity cannot combine legacy compatibility with a transition SHA.");
  }
  if (!/^[0-9a-z]{50}$/.test(identity.dhiParityId)) {
    throw new Error("Review identity DHI parity ID is malformed.");
  }
  if (identity.maxMutatorTokenLifetimeSeconds !== 300) {
    throw new Error("Review identity mutator-token lifetime drifted.");
  }
  if (
    ![300, LEGACY_MUTATOR_TOKEN_SECONDS].includes(identity.tokenDrainSeconds) ||
    identity.tokenDrainSeconds < identity.maxMutatorTokenLifetimeSeconds
  ) {
    throw new Error("Review identity token-drain window drifted.");
  }
  const markerProof = normalizeMarkerProof(
    identity.markerProof,
    identity.legacyCompatibilityMode,
  );
  const plan = record(raw, "Terraform plan");
  exactKeys(
    plan,
    new Set([
      "applyable",
      "checks",
      "complete",
      "configuration",
      "errored",
      "format_version",
      "output_changes",
      "planned_values",
      "prior_state",
      "relevant_attributes",
      "resource_changes",
      "resource_drift",
      "terraform_version",
      "timestamp",
      "variables",
    ]),
    "Terraform plan",
  );
  exact(plan.format_version, PLAN_FORMAT_VERSION, "Terraform plan format version");
  exact(plan.terraform_version, TERRAFORM_VERSION, "Terraform version");
  if (plan.errored !== false || typeof plan.applyable !== "boolean" || plan.complete !== true) {
    throw new Error("Terraform produced an errored, incomplete, or malformed plan.");
  }
  const changes = normalizeChanges(plan.resource_changes, identity, "resource change");
  const drift = normalizeChanges(plan.resource_drift, identity, "resource drift");
  const outputChanges = normalizeOutputChanges(plan.output_changes);
  const checks = json(plan.checks ?? [], "Terraform checks");
  const relevantAttributes = json(
    plan.relevant_attributes ?? [],
    "Terraform relevant attributes",
  );
  const variables = normalizeNamedHashes(plan.variables ?? {}, "Terraform variable");
  const manifest: JsonValue = {
    plan: {
      applyable: plan.applyable,
      changes,
      checksCount: Array.isArray(checks) ? checks.length : 0,
      checksSha256: hashJson(checks),
      complete: true,
      drift,
      outputChanges,
      relevantAttributesSha256: hashJson(relevantAttributes),
      semanticSha256: hashJson({
        checks,
        outputChanges,
        relevantAttributes,
        resourceChanges: changes,
        resourceDrift: drift,
        variables,
      }),
      variables,
    },
    schemaVersion: 2,
    source: {
      approvalMode: "plan",
      consumerSha: sha(identity.consumerSha, "consumer SHA"),
      consumerTreeSha: sha(identity.consumerTreeSha, "consumer tree SHA"),
      dhiParityId: identity.dhiParityId,
      legacyCompatibilityMode: identity.legacyCompatibilityMode,
      maxMutatorTokenLifetimeSeconds: identity.maxMutatorTokenLifetimeSeconds,
      markerProof,
      platformSha: sha(identity.platformSha, "platform SHA"),
      projectId: identity.projectId,
      repository: identity.repository,
      repositoryId: identity.repositoryId,
      terraformRoot: identity.terraformRoot,
      tokenDrainSeconds: identity.tokenDrainSeconds,
      transitionWorkflowSha: identity.transitionWorkflowSha === ""
        ? null
        : sha(identity.transitionWorkflowSha, "transition workflow SHA"),
    },
  };
  const canonical = `${canonicalJson(manifest)}\n`;
  if (Buffer.byteLength(canonical) > MAX_REVIEW_MANIFEST_BYTES) {
    throw new Error("The sanitized review manifest exceeds the reviewed size ceiling.");
  }
  return {
    canonical,
    sha256: createHash("sha256").update(canonical).digest("hex"),
  };
}

export function canonicalJson(value: JsonValue): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .toSorted()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key]!)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function normalizeMarkerProof(
  proof: readonly MarkerStateProof[],
  allowAbsent: boolean,
): JsonValue[] {
  if (proof.length !== REPOSITORY_NAMES.length) {
    throw new Error("The deployment-parity marker proof is incomplete.");
  }
  return proof.map((marker, index) => {
    const repository = REPOSITORY_NAMES[index]!;
    const contract = REPOSITORIES[repository];
    exact(marker.repository, repository, "marker proof repository order");
    exact(marker.repositoryId, contract.repositoryId, "marker proof repository ID");
    exact(
      marker.bucket,
      `${contract.projectId}-deployment-parity-state`,
      "marker proof bucket",
    );
    if (marker.state === "absent") {
      if (
        !allowAbsent ||
        marker.generation !== null ||
        marker.metadata !== null ||
        marker.metageneration !== null
      ) {
        throw new Error("A deployment-parity marker is absent outside initial migration.");
      }
    } else if (marker.state === "clear") {
      numeric(requiredString(marker.generation, "marker generation"), "marker generation");
      numeric(
        requiredString(marker.metageneration, "marker metageneration"),
        "marker metageneration",
      );
      const metadata = record(marker.metadata, "marker metadata");
      exactKeys(
        metadata,
        new Set(["repository-id", "state", "version"]),
        "marker metadata",
      );
      exact(metadata.version, "1", "marker metadata version");
      exact(metadata["repository-id"], contract.repositoryId, "marker metadata repository ID");
      exact(metadata.state, "clear", "marker metadata state");
    } else {
      throw new Error("A deployment-parity marker has an unreviewed state.");
    }
    return {
      bucket: marker.bucket,
      generation: marker.generation,
      metadata: marker.metadata === null
        ? null
        : {
            "repository-id": contract.repositoryId,
            state: "clear",
            version: "1",
          },
      metageneration: marker.metageneration,
      repository,
      repositoryId: contract.repositoryId,
      state: marker.state,
    };
  });
}

function markerProofForReceipt(
  proof: readonly MarkerStateProof[],
  invocation: Pick<
    Invocation,
    "legacyCompatibilityMode" | "terraformRoot" | "transitionWorkflowSha"
  >,
): readonly MarkerStateProof[] {
  const allowAbsent = invocation.terraformRoot === "bootstrap" &&
    invocation.legacyCompatibilityMode && invocation.transitionWorkflowSha === "";
  normalizeMarkerProof(proof, allowAbsent);
  return proof.map((marker) => ({
    ...marker,
    metadata: marker.metadata === null ? null : { ...marker.metadata },
  }));
}

function markerProofFromJson(value: unknown, allowAbsent: boolean): readonly MarkerStateProof[] {
  const proof = array(value, "plan receipt marker proof").map((entry, index) => {
    const marker = record(entry, `plan receipt marker proof ${index}`);
    exactKeys(
      marker,
      new Set([
        "bucket",
        "generation",
        "metadata",
        "metageneration",
        "repository",
        "repositoryId",
        "state",
      ]),
      `plan receipt marker proof ${index}`,
    );
    const state = requiredString(marker.state, "plan receipt marker state");
    if (state !== "absent" && state !== "clear") {
      throw new Error("Plan receipt marker state escaped the reviewed values.");
    }
    let metadata: MarkerStateProof["metadata"] = null;
    if (marker.metadata !== null) {
      const parsed = record(marker.metadata, "plan receipt marker metadata");
      exactKeys(
        parsed,
        new Set(["repository-id", "state", "version"]),
        "plan receipt marker metadata",
      );
      metadata = {
        "repository-id": requiredString(
          parsed["repository-id"],
          "plan receipt marker metadata repository ID",
        ),
        state: (() => {
          exact(parsed.state, "clear", "plan receipt marker metadata state");
          return "clear" as const;
        })(),
        version: (() => {
          exact(parsed.version, "1", "plan receipt marker metadata version");
          return "1" as const;
        })(),
      };
    }
    return {
      bucket: requiredString(marker.bucket, "plan receipt marker bucket"),
      generation: marker.generation === null
        ? null
        : requiredString(marker.generation, "plan receipt marker generation"),
      metadata,
      metageneration: marker.metageneration === null
        ? null
        : requiredString(marker.metageneration, "plan receipt marker metageneration"),
      repository: repositoryName(
        requiredString(marker.repository, "plan receipt marker repository"),
      ),
      repositoryId: numeric(
        requiredString(marker.repositoryId, "plan receipt marker repository ID"),
        "plan receipt marker repository ID",
      ),
      state,
    } satisfies MarkerStateProof;
  });
  normalizeMarkerProof(proof, allowAbsent);
  return proof;
}

function normalizedFreezeProof(
  proof: ConsumerFreezeProof,
  expectedDrainSeconds: number,
): ConsumerFreezeProof {
  exact(proof.tokenDrainSeconds, expectedDrainSeconds, "freeze-proof token-drain window");
  if (![300, LEGACY_MUTATOR_TOKEN_SECONDS].includes(proof.tokenDrainSeconds)) {
    throw new Error("Freeze proof token-drain window escaped the reviewed values.");
  }
  const observedAtMs = Date.parse(proof.observedAt);
  if (!Number.isFinite(observedAtMs) || new Date(observedAtMs).toISOString() !== proof.observedAt) {
    throw new Error("Freeze proof observation time is malformed.");
  }
  if (proof.repositories.length !== REPOSITORY_NAMES.length) {
    throw new Error("Freeze proof repository inventory is incomplete.");
  }
  const repositories = proof.repositories.map((entry, index) => {
    const repository = REPOSITORY_NAMES[index]!;
    const contract = REPOSITORIES[repository];
    exact(entry.repository, repository, "freeze-proof repository order");
    exact(entry.repositoryId, contract.repositoryId, "freeze-proof repository ID");
    exact(entry.actionsEnabled, false, "freeze-proof Actions state");
    exact(entry.activeRunCount, 0, "freeze-proof active-run count");
    if (entry.latestPossibleTokenIssuance !== null) {
      const issuanceMs = Date.parse(entry.latestPossibleTokenIssuance);
      if (
        !Number.isFinite(issuanceMs) ||
        new Date(issuanceMs).toISOString() !== entry.latestPossibleTokenIssuance ||
        observedAtMs - issuanceMs <
          (proof.tokenDrainSeconds + TOKEN_DRAIN_SKEW_SECONDS) * 1_000
      ) {
        throw new Error("Freeze proof contains an undrained or malformed token issuance.");
      }
    }
    return { ...entry };
  });
  return { observedAt: proof.observedAt, repositories, tokenDrainSeconds: proof.tokenDrainSeconds };
}

function freezeProofFromJson(value: unknown, expectedDrainSeconds: number): ConsumerFreezeProof {
  const proof = record(value, "freeze proof");
  exactKeys(
    proof,
    new Set(["observedAt", "repositories", "tokenDrainSeconds"]),
    "freeze proof",
  );
  const repositories = array(proof.repositories, "freeze proof repositories").map(
    (raw, index) => {
      const entry = record(raw, `freeze proof repository ${index}`);
      exactKeys(
        entry,
        new Set([
          "actionsEnabled",
          "activeRunCount",
          "latestPossibleTokenIssuance",
          "repository",
          "repositoryId",
        ]),
        `freeze proof repository ${index}`,
      );
      exact(entry.actionsEnabled, false, "freeze proof Actions state");
      exact(entry.activeRunCount, 0, "freeze proof active-run count");
      return {
        actionsEnabled: false,
        activeRunCount: 0,
        latestPossibleTokenIssuance: entry.latestPossibleTokenIssuance === null
          ? null
          : requiredString(
              entry.latestPossibleTokenIssuance,
              "freeze proof latest token issuance",
            ),
        repository: repositoryName(
          requiredString(entry.repository, "freeze proof repository"),
        ),
        repositoryId: numeric(
          requiredString(entry.repositoryId, "freeze proof repository ID"),
          "freeze proof repository ID",
        ),
      } as const;
    },
  );
  return normalizedFreezeProof(
    {
      observedAt: requiredString(proof.observedAt, "freeze proof observation time"),
      repositories,
      tokenDrainSeconds: boundedInteger(
        proof.tokenDrainSeconds,
        "freeze proof token-drain window",
        1,
        LEGACY_MUTATOR_TOKEN_SECONDS,
      ),
    },
    expectedDrainSeconds,
  );
}

export function formatBridgeBreadcrumb(
  phase: BridgePhase,
  rssBytes: number,
  cgroup: CgroupMemorySnapshot = {},
): string {
  if (!BRIDGE_PHASE_SET.has(phase)) {
    throw new Error("Protected bridge telemetry phase escaped its closed vocabulary.");
  }
  if (!Number.isSafeInteger(rssBytes) || rssBytes < 0) {
    throw new Error("Protected bridge telemetry RSS escaped its integer bound.");
  }
  const fields = [
    `Protected bridge telemetry phase=${phase}`,
    `rss_kib=${Math.ceil(rssBytes / 1_024)}`,
  ];
  for (const [label, value] of [
    ["cgroup_current_kib", cgroup.currentBytes === undefined
      ? undefined
      : Math.ceil(cgroup.currentBytes / 1_024)],
    ["cgroup_peak_kib", cgroup.peakBytes === undefined
      ? undefined
      : Math.ceil(cgroup.peakBytes / 1_024)],
    ["cgroup_oom", cgroup.oom],
    ["cgroup_oom_kill", cgroup.oomKill],
  ] as const) {
    if (value === undefined) continue;
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error("Protected bridge cgroup telemetry escaped its integer bound.");
    }
    fields.push(`${label}=${value}`);
  }
  return fields.join(" ");
}

function readCgroupMemorySnapshot(): CgroupMemorySnapshot {
  const numericFile = (path: string): number | undefined => {
    try {
      const value = readFileSync(path, "utf8").trim();
      if (!/^(?:0|[1-9][0-9]*)$/.test(value)) return undefined;
      const parsed = Number(value);
      return Number.isSafeInteger(parsed) ? parsed : undefined;
    } catch {
      return undefined;
    }
  };
  let oom: number | undefined;
  let oomKill: number | undefined;
  try {
    for (const line of readFileSync("/sys/fs/cgroup/memory.events", "utf8").split("\n")) {
      const match = /^(oom|oom_kill) (0|[1-9][0-9]*)$/.exec(line);
      if (match === null) continue;
      const parsed = Number(match[2]);
      if (!Number.isSafeInteger(parsed)) continue;
      if (match[1] === "oom") oom = parsed;
      if (match[1] === "oom_kill") oomKill = parsed;
    }
  } catch {
    // cgroup v2 is optional. Do not inspect any other process or environment state.
  }
  const currentBytes = numericFile("/sys/fs/cgroup/memory.current");
  const peakBytes = numericFile("/sys/fs/cgroup/memory.peak");
  return {
    ...(currentBytes === undefined ? {} : { currentBytes }),
    ...(oom === undefined ? {} : { oom }),
    ...(oomKill === undefined ? {} : { oomKill }),
    ...(peakBytes === undefined ? {} : { peakBytes }),
  };
}

function bestEffortTelemetry(telemetry: BridgeTelemetry): BridgeTelemetry {
  return {
    phase: (phase) => {
      try {
        telemetry.phase(phase);
      } catch {
        // Breadcrumbs are diagnostic only and may never alter privileged control flow.
      }
    },
    stop: () => {
      try {
        telemetry.stop();
      } catch {
        // Breadcrumbs are diagnostic only and may never alter privileged control flow.
      }
    },
  };
}

function startBridgeTelemetry(
  initialPhase: BridgePhase,
  sink: (value: string) => void = (value) => console.error(value),
  readRss: () => number = () => process.memoryUsage().rss,
): BridgeTelemetry {
  let currentPhase = initialPhase;
  const emit = () => {
    try {
      sink(formatBridgeBreadcrumb(currentPhase, readRss(), readCgroupMemorySnapshot()));
    } catch {
      // Sink, RSS, formatting, and cgroup failures are all strictly best effort.
    }
  };
  emit();
  let timer: ReturnType<typeof setInterval> | undefined;
  try {
    timer = setInterval(emit, BRIDGE_TELEMETRY_INTERVAL_MS);
    timer.unref();
  } catch {
    timer = undefined;
  }
  return {
    phase: (phase) => {
      currentPhase = phase;
      emit();
    },
    stop: () => {
      if (timer !== undefined) clearInterval(timer);
    },
  };
}

export async function runProtectedBootstrap(
  invocation: Invocation,
  dependencies: BridgeDependencies = defaultBridgeDependencies(),
  telemetry: BridgeTelemetry = NOOP_BRIDGE_TELEMETRY,
): Promise<void> {
  telemetry = bestEffortTelemetry(telemetry);
  const startedAtMs = dependencies.now();
  const wrapperDeadlineMs = startedAtMs + invocation.operationBudgetSeconds * 1_000;
  const cleanupDeadlineMs = wrapperDeadlineMs - 60_000;
  const operationDeadlineMs = Math.min(
    startedAtMs + INTERNAL_OPERATION_MINUTES * 60_000,
    cleanupDeadlineMs - 5 * 60_000,
  );
  if (operationDeadlineMs <= startedAtMs) {
    throw new Error("Bridge operation budget cannot cover primary work plus exact cleanup.");
  }
  const leaseExpiresAt = new Date(startedAtMs + LEASE_MINUTES * 60_000);
  const contract = REPOSITORIES[invocation.repository];
  const sandboxPath = resolve(
    invocation.runnerTemp,
    `protected-bootstrap-${invocation.githubRunId}.sandbox`,
  );
  const planPath = resolve(
    sandboxPath,
    "plan.tfplan",
  );
  const tfDataPath = resolve(
    sandboxPath,
    "tfdata",
  );
  let session: ExecutorSession | undefined;
  let primaryFailure: unknown;
  try {
    telemetry.phase("controller.prepare");
    const preparation = await dependencies.prepare(invocation, operationDeadlineMs);
    const consumerTreeSha = preparation.consumerTreeSha;
    assertBeforeDeadline(dependencies.now(), operationDeadlineMs, "protected preparation");
    telemetry.phase("controller.acquire");
    session = await dependencies.acquireExecutor(
      invocation,
      leaseExpiresAt,
      operationDeadlineMs,
    );
    assertSession(session, dependencies.now(), operationDeadlineMs);
    telemetry.phase("controller.proof");
    const proof: ExecutionProof = {
      ...preparation,
      freezeProof: await dependencies.proveFreeze(invocation, preparation.tokenDrainSeconds),
      markerProof: await dependencies.proveMarkers(invocation, session, false),
    };

    const approved = invocation.mode === "apply"
      ? await dependencies.verifyApproval(invocation, session, proof, dependencies.now())
      : undefined;
    const terraformDirectory = resolve(
      invocation.platformRoot,
      "terraform",
      "deployments",
      invocation.terraformRoot,
    );
    telemetry.phase("controller.terraform-init");
    await dependencies.runTerraform(
      invocation,
      session,
      terraformDirectory,
      [
        "init",
        "-input=false",
        "-lockfile=readonly",
        "-no-color",
        "-plugin-dir=/plugins",
        `-backend-config=bucket=${contract.state[invocation.terraformRoot].bucket}`,
        `-backend-config=prefix=${contract.state[invocation.terraformRoot].prefix}`,
      ],
      operationDeadlineMs,
    );
    telemetry.phase("controller.terraform-plan");
    await dependencies.runTerraform(
      invocation,
      session,
      terraformDirectory,
      [
        "plan",
        "-input=false",
        "-lock=false",
        "-no-color",
        "-out=/work/plan.tfplan",
        `-var=repository_id=${contract.repositoryId}`,
        ...(invocation.terraformRoot === "bootstrap"
          ? [
              `-var=active_workflow_sha=${invocation.platformSha}`,
              `-var=legacy_compatibility_mode=${invocation.legacyCompatibilityMode}`,
              `-var=transition_workflow_sha=${invocation.transitionWorkflowSha}`,
            ]
          : []),
      ],
      operationDeadlineMs,
    );
    telemetry.phase("controller.plan-read");
    await dependencies.inspectPlan(planPath);
    const planJson = await dependencies.readPlanJson(
      invocation,
      session,
      terraformDirectory,
      planPath,
      operationDeadlineMs,
    );
    if (Buffer.byteLength(planJson) > MAX_PLAN_JSON_BYTES) {
      throw new Error("Terraform plan JSON exceeds the reviewed size ceiling.");
    }
    let rawPlan: unknown;
    try {
      rawPlan = JSON.parse(planJson) as unknown;
    } catch {
      throw new Error("Terraform emitted malformed plan JSON.");
    }
    const review = buildReviewManifest(rawPlan, {
      consumerSha: invocation.consumerSha,
      consumerTreeSha,
      dhiParityId: preparation.dhiParityId,
      legacyCompatibilityMode: invocation.legacyCompatibilityMode,
      maxMutatorTokenLifetimeSeconds: preparation.maxMutatorTokenLifetimeSeconds,
      markerProof: proof.markerProof,
      platformSha: invocation.platformSha,
      projectId: contract.projectId,
      repository: invocation.repository,
      repositoryId: contract.repositoryId,
      terraformRoot: invocation.terraformRoot,
      tokenDrainSeconds: preparation.tokenDrainSeconds,
      transitionWorkflowSha: invocation.transitionWorkflowSha,
    });
    if (invocation.mode === "plan") {
      telemetry.phase("controller.plan-publish");
      await dependencies.publishPlanReceipt(
        invocation,
        session,
        review,
        proof,
        dependencies.now(),
      );
      await dependencies.appendSummary(invocation, reviewSummary(invocation, review, undefined));
      console.log(`Protected Terraform review digest: ${review.sha256}`);
      return;
    }

    telemetry.phase("controller.apply-authorize");
    if (
      approved === undefined ||
      approved.sha256 !== review.sha256 ||
      review.sha256 !== invocation.approvedManifestSha256
    ) {
      throw new Error("The recomputed plan does not match the fresh approved plan receipt.");
    }
    assertPreApplyTime(
      dependencies.now(),
      operationDeadlineMs,
      leaseExpiresAt.getTime(),
      session.tokenExpiresAtMs,
    );
    const preApplyProof: ExecutionProof = {
      ...preparation,
      freezeProof: await dependencies.proveFreeze(invocation, preparation.tokenDrainSeconds),
      markerProof: await dependencies.proveMarkers(invocation, session, false),
    };
    exact(
      canonicalJson(json(preApplyProof.markerProof, "fresh pre-apply markers")),
      canonicalJson(json(proof.markerProof, "approved pre-apply markers")),
      "fresh pre-apply marker proof",
    );
    await dependencies.consumeApproval(
      invocation,
      session,
      review,
      preApplyProof,
      dependencies.now(),
    );
    await dependencies.elevateExecutor(
      invocation,
      session,
      leaseExpiresAt,
      operationDeadlineMs,
    );
    assertPreApplyTime(
      dependencies.now(),
      operationDeadlineMs,
      leaseExpiresAt.getTime(),
      session.tokenExpiresAtMs,
    );
    await dependencies.proveFreeze(invocation, preparation.tokenDrainSeconds);
    telemetry.phase("controller.apply");
    await dependencies.runTerraform(
      invocation,
      session,
      terraformDirectory,
      ["apply", "-auto-approve", "-input=false", "-no-color", "/work/plan.tfplan"],
      operationDeadlineMs,
    );
    // Terraform/provider execution is a cryptographic artifact trust boundary:
    // the exact Linux provider archive is SHA-256 pinned, checked against the
    // committed readonly lock, and supplied only from /plugins. Re-read every
    // declared resource after apply and require an exact zero-diff exit code.
    telemetry.phase("controller.apply-audit");
    await dependencies.runTerraform(
      invocation,
      session,
      terraformDirectory,
      [
        "plan",
        "-detailed-exitcode",
        "-input=false",
        "-lock=false",
        "-no-color",
        `-var=repository_id=${contract.repositoryId}`,
        ...(invocation.terraformRoot === "bootstrap"
          ? [
              `-var=active_workflow_sha=${invocation.platformSha}`,
              `-var=legacy_compatibility_mode=${invocation.legacyCompatibilityMode}`,
              `-var=transition_workflow_sha=${invocation.transitionWorkflowSha}`,
            ]
          : []),
      ],
      operationDeadlineMs,
    );
    const mutationCompletedAtMs = dependencies.now();
    telemetry.phase("controller.apply-drain");
    await dependencies.waitForPostMutationDrain(
      invocation,
      mutationCompletedAtMs,
      operationDeadlineMs,
    );
    const postApplyProof: ExecutionProof = {
      ...preparation,
      freezeProof: await dependencies.proveFreeze(invocation, preparation.tokenDrainSeconds),
      markerProof: await dependencies.proveMarkers(invocation, session, true),
    };
    if (
      invocation.terraformRoot === "bootstrap" &&
      Date.parse(postApplyProof.freezeProof.observedAt) - mutationCompletedAtMs <
        POST_MUTATION_DRAIN_SECONDS * 1_000
    ) {
      throw new Error("The post-WIF freeze snapshot predates the required token-expiry barrier.");
    }
    telemetry.phase("controller.apply-publish");
    await dependencies.publishPostApplyReceipt(
      invocation,
      session,
      review,
      postApplyProof,
      dependencies.now(),
    );
    await dependencies.appendSummary(
      invocation,
      reviewSummary(invocation, review, invocation.approvedPlanRunId),
    );
  } catch (error) {
    primaryFailure = error;
    throw error;
  } finally {
    telemetry.phase("controller.cleanup");
    // Schedule IAM containment first and independently. A large or damaged
    // private tree must not consume the cleanup window before the executor is
    // disabled, and a synchronous filesystem-cleanup throw must not prevent
    // the IAM attempt from starting.
    const cleanupResults = await Promise.allSettled([
      Promise.resolve().then(() =>
        dependencies.releaseExecutor(invocation, session, cleanupDeadlineMs)
      ),
      ...[planPath, tfDataPath, sandboxPath].map((path) =>
        Promise.resolve().then(() => dependencies.removePrivatePath(path))
      ),
    ]);
    const cleanupErrors = cleanupResults.flatMap((result) =>
      result.status === "rejected" ? [result.reason] : []
    );
    if (cleanupErrors.length > 0) {
      const cleanupFailure = new AggregateError(
        cleanupErrors,
        "Protected executor cleanup did not complete exactly.",
      );
      if (primaryFailure === undefined) throw cleanupFailure;
      throw new AggregateError(
        [primaryFailure, cleanupFailure],
        "The protected operation failed and its cleanup also failed.",
      );
    }
  }
}

export async function main(
  source: NodeJS.ProcessEnv = process.env,
  dependencies: BridgeDependencies | undefined = undefined,
  readSecrets: () => ControllerSecrets = readControllerSecretsFromStdin,
  telemetry: BridgeTelemetry | undefined = undefined,
): Promise<void> {
  const activeTelemetry = bestEffortTelemetry(
    telemetry ?? startBridgeTelemetry("controller.start"),
  );
  try {
    for (const name of [
      "CONSUMER_ACTIONS_READ_TOKEN",
      "OWNER_OAUTH_ACCESS_TOKEN",
      "PLATFORM_ACTIONS_READ_TOKEN",
    ]) {
      if (source[name] !== undefined || process.env[name] !== undefined) {
        delete source[name];
        delete process.env[name];
        throw new Error("Controller credentials must not exist in Bun's initial environment.");
      }
    }
    const secrets = readSecrets();
    const invocationSource: NodeJS.ProcessEnv = {
      ...source,
      CONSUMER_ACTIONS_READ_TOKEN: secrets.consumerActionsToken,
      OWNER_OAUTH_ACCESS_TOKEN: secrets.ownerAccessToken,
      PLATFORM_ACTIONS_READ_TOKEN: secrets.platformActionsToken,
    };
    const invocation = validateInvocation(invocationSource);
    delete invocationSource.CONSUMER_ACTIONS_READ_TOKEN;
    delete invocationSource.OWNER_OAUTH_ACCESS_TOKEN;
    delete invocationSource.PLATFORM_ACTIONS_READ_TOKEN;
    await runProtectedBootstrap(
      invocation,
      dependencies ?? defaultBridgeDependencies(activeTelemetry),
      activeTelemetry,
    );
    activeTelemetry.phase("controller.complete");
  } catch (error) {
    activeTelemetry.phase("controller.failed");
    throw error;
  } finally {
    activeTelemetry.stop();
  }
}

export async function runProtectedRecovery(
  invocation: RecoveryInvocation,
  dependencies: RecoveryDependencies = defaultRecoveryDependencies(),
  telemetry: BridgeTelemetry = NOOP_BRIDGE_TELEMETRY,
): Promise<void> {
  telemetry = bestEffortTelemetry(telemetry);
  const startedAtMs = dependencies.now();
  const recoveryDeadlineMs = startedAtMs + RECOVERY_OPERATION_MINUTES * 60_000;
  telemetry.phase("recovery.source-proof");
  await dependencies.verifySource(invocation);
  assertBeforeDeadline(dependencies.now(), recoveryDeadlineMs, "protected crash recovery");
  telemetry.phase("recovery.inventory");
  await dependencies.recoverArtifacts(invocation, recoveryDeadlineMs);
}

export async function recoveryMain(
  source: NodeJS.ProcessEnv = process.env,
  dependencies: RecoveryDependencies | undefined = undefined,
  readOwnerAccessToken: () => string = readRecoverySecretFromStdin,
  telemetry: BridgeTelemetry | undefined = undefined,
): Promise<void> {
  const activeTelemetry = bestEffortTelemetry(
    telemetry ?? startBridgeTelemetry("recovery.start"),
  );
  try {
    validateProtectedRoute(source);
    rejectRecoveryCapabilities(source);
    numeric(required(source, "GITHUB_RUN_ID_EXACT"), "GitHub run ID");
    sha(required(source, "GITHUB_SHA_EXACT"), "platform SHA");
    repositoryName(required(source, "TARGET_REPOSITORY"));
    safeAbsoluteDirectory(required(source, "PLATFORM_ROOT"), "platform root");
    safeAbsoluteDirectory(required(source, "RUNNER_TEMP_EXACT"), "runner temp");
    for (const name of [
      "CONSUMER_ACTIONS_READ_TOKEN",
      "OWNER_OAUTH_ACCESS_TOKEN",
      "PLATFORM_ACTIONS_READ_TOKEN",
    ]) {
      if (source[name] !== undefined || process.env[name] !== undefined) {
        delete source[name];
        delete process.env[name];
        throw new Error("Recovery credential must not exist in Bun's initial environment.");
      }
    }
    const invocationSource: NodeJS.ProcessEnv = {
      ...source,
      OWNER_OAUTH_ACCESS_TOKEN: readOwnerAccessToken(),
    };
    const invocation = validateRecoveryInvocation(invocationSource);
    delete invocationSource.OWNER_OAUTH_ACCESS_TOKEN;
    await runProtectedRecovery(
      invocation,
      dependencies ?? defaultRecoveryDependencies(),
      activeTelemetry,
    );
    activeTelemetry.phase("recovery.complete");
  } catch (error) {
    activeTelemetry.phase("recovery.failed");
    throw error;
  } finally {
    activeTelemetry.stop();
  }
}

export function parseControllerSecretBundle(value: Uint8Array): ControllerSecrets {
  if (value.byteLength < 4 || value.byteLength > MAX_SECRET_BUNDLE_BYTES) {
    throw new Error("Controller secret bundle escaped its size bound.");
  }
  const parts = Buffer.from(value).toString("utf8").split("\0");
  if (parts.length !== 4 || parts[3] !== "") {
    throw new Error("Controller secret bundle must contain exactly three NUL-terminated values.");
  }
  return {
    ownerAccessToken: secretValue(parts[0]!, "owner OAuth access token"),
    consumerActionsToken: secretValue(parts[1]!, "consumer Actions read token"),
    platformActionsToken: secretValue(parts[2]!, "platform Actions read token"),
  };
}

export function parseRecoverySecretBundle(value: Uint8Array): string {
  if (value.byteLength < 2 || value.byteLength > MAX_SECRET_BUNDLE_BYTES) {
    throw new Error("Recovery secret bundle escaped its size bound.");
  }
  const parts = Buffer.from(value).toString("utf8").split("\0");
  if (parts.length !== 2 || parts[1] !== "") {
    throw new Error("Recovery secret bundle must contain exactly one NUL-terminated value.");
  }
  return secretValue(parts[0]!, "owner OAuth access token");
}

function readControllerSecretsFromStdin(): ControllerSecrets {
  const buffer = Buffer.alloc(MAX_SECRET_BUNDLE_BYTES + 1);
  let offset = 0;
  try {
    while (offset < buffer.byteLength) {
      const count = readSync(0, buffer, offset, buffer.byteLength - offset, null);
      if (count === 0) break;
      offset += count;
    }
  } finally {
    closeSync(0);
  }
  if (offset > MAX_SECRET_BUNDLE_BYTES) {
    buffer.fill(0);
    throw new Error("Controller secret bundle escaped its size bound.");
  }
  try {
    return parseControllerSecretBundle(buffer.subarray(0, offset));
  } finally {
    buffer.fill(0);
  }
}

function readRecoverySecretFromStdin(): string {
  const buffer = Buffer.alloc(MAX_SECRET_BUNDLE_BYTES + 1);
  let offset = 0;
  try {
    while (offset < buffer.byteLength) {
      const count = readSync(0, buffer, offset, buffer.byteLength - offset, null);
      if (count === 0) break;
      offset += count;
    }
  } finally {
    closeSync(0);
  }
  if (offset > MAX_SECRET_BUNDLE_BYTES) {
    buffer.fill(0);
    throw new Error("Recovery secret bundle escaped its size bound.");
  }
  try {
    return parseRecoverySecretBundle(buffer.subarray(0, offset));
  } finally {
    buffer.fill(0);
  }
}

export async function proveConsumerFreeze(
  token: string,
  tokenDrainSeconds: number,
  fetcher: Fetcher,
  nowMs = Date.now(),
): Promise<ConsumerFreezeProof> {
  if (![300, LEGACY_MUTATOR_TOKEN_SECONDS].includes(tokenDrainSeconds)) {
    throw new Error("The consumer token-drain window escaped the reviewed values.");
  }
  if (!Number.isFinite(nowMs)) throw new Error("The consumer freeze time is invalid.");
  const requiredDrainMs = (tokenDrainSeconds + TOKEN_DRAIN_SKEW_SECONDS) * 1_000;
  const repositories: Array<ConsumerFreezeProof["repositories"][number]> = [];
  for (const repository of REPOSITORY_NAMES) {
    const contract = REPOSITORIES[repository];
    const base = `https://api.github.com/repos/${PLATFORM_OWNER}/${repository}`;
    const [metadataValue, permissionsValue, activeRuns, recentRuns] = await Promise.all([
      githubJson(base, token, fetcher),
      githubJson(`${base}/actions/permissions`, token, fetcher),
      githubActiveRuns(base, token, fetcher),
      githubAllRuns(base, token, fetcher),
    ]);
    const metadata = record(metadataValue, `${repository} metadata`);
    const owner = record(metadata.owner, `${repository} owner`);
    if (
      String(metadata.id) !== contract.repositoryId ||
      metadata.full_name !== `${PLATFORM_OWNER}/${repository}` ||
      String(owner.id) !== PLATFORM_OWNER_ID
    ) {
      throw new Error(`${repository} repository identity drifted.`);
    }
    const permissions = record(permissionsValue, `${repository} Actions permissions`);
    if (permissions.enabled !== false) {
      throw new Error(`${repository} GitHub Actions must remain disabled for the protected run.`);
    }
    if (activeRuns.length !== 0) {
      throw new Error(`${repository} still has an active GitHub Actions run.`);
    }
    const latestPossibleTokenIssuance = recentRuns.reduce<number>((latest, run) => {
      const recordValue = record(run, `${repository} workflow run`);
      const createdAt = Date.parse(requiredString(recordValue.created_at, "workflow run creation time"));
      const updatedAt = Date.parse(requiredString(recordValue.updated_at, "workflow run update time"));
      numeric(String(recordValue.id), "workflow run ID");
      if (
        !Number.isFinite(createdAt) ||
        !Number.isFinite(updatedAt) ||
        createdAt > updatedAt ||
        updatedAt > nowMs + TOKEN_DRAIN_SKEW_SECONDS * 1_000
      ) {
        throw new Error(`${repository} returned malformed workflow-run timing.`);
      }
      return Math.max(latest, updatedAt);
    }, 0);
    if (latestPossibleTokenIssuance !== 0 && nowMs - latestPossibleTokenIssuance < requiredDrainMs) {
      throw new Error(
        `${repository} has not drained the last possible old mutator token for ${tokenDrainSeconds} seconds plus skew.`,
      );
    }
    repositories.push({
      actionsEnabled: false,
      activeRunCount: 0,
      latestPossibleTokenIssuance: latestPossibleTokenIssuance === 0
        ? null
        : new Date(latestPossibleTokenIssuance).toISOString(),
      repository,
      repositoryId: contract.repositoryId,
    });
  }
  return {
    observedAt: new Date(nowMs).toISOString(),
    repositories,
    tokenDrainSeconds,
  };
}

async function githubAllRuns(
  base: string,
  token: string,
  fetcher: Fetcher,
): Promise<readonly JsonValue[]> {
  const results: JsonValue[] = [];
  let page = 1;
  let expectedTotal: number | undefined;
  do {
    const value = record(
      await githubJson(`${base}/actions/runs?per_page=100&page=${page}`, token, fetcher),
      "GitHub workflow runs",
    );
    exactKeys(value, new Set(["total_count", "workflow_runs"]), "GitHub workflow runs");
    const total = boundedInteger(
      value.total_count,
      "GitHub workflow run count",
      0,
      MAX_GITHUB_RUNS_PER_STATUS,
    );
    if (expectedTotal === undefined) expectedTotal = total;
    if (total !== expectedTotal) {
      throw new Error("GitHub workflow-run pagination changed during the token-drain proof.");
    }
    const pageRuns = array(value.workflow_runs, "GitHub workflow runs");
    if (pageRuns.length > 100) throw new Error("GitHub returned an oversized workflow-run page.");
    results.push(...pageRuns.map((run) => json(run, "GitHub workflow run")));
    page += 1;
  } while ((page - 1) * 100 < (expectedTotal ?? 0));
  if (results.length !== expectedTotal) {
    throw new Error("GitHub workflow-run pagination was incomplete.");
  }
  return results;
}

async function githubActiveRuns(
  base: string,
  token: string,
  fetcher: Fetcher,
): Promise<readonly JsonValue[]> {
  const results: JsonValue[] = [];
  for (const status of ["requested", "waiting", "pending", "queued", "in_progress"] as const) {
    let page = 1;
    let expectedTotal: number | undefined;
    do {
      const url = `${base}/actions/runs?status=${status}&per_page=100&page=${page}`;
      const value = record(await githubJson(url, token, fetcher), `GitHub ${status} runs`);
      exactKeys(value, new Set(["total_count", "workflow_runs"]), `GitHub ${status} runs`);
      const total = boundedInteger(value.total_count, `GitHub ${status} run count`, 0, MAX_GITHUB_RUNS_PER_STATUS);
      if (expectedTotal === undefined) expectedTotal = total;
      if (total !== expectedTotal) {
        throw new Error("GitHub active-run pagination changed during the freeze proof.");
      }
      const pageRuns = array(value.workflow_runs, `GitHub ${status} runs`);
      if (pageRuns.length > 100) throw new Error("GitHub returned an oversized run page.");
      for (const raw of pageRuns) {
        const run = record(raw, `GitHub ${status} run`);
        exact(run.status, status, `GitHub ${status} run status`);
        results.push(json(run, `GitHub ${status} run`));
      }
      page += 1;
    } while ((page - 1) * 100 < (expectedTotal ?? 0));
    if (results.length > REPOSITORY_NAMES.length * MAX_GITHUB_RUNS_PER_STATUS) {
      throw new Error("GitHub active-run proof exceeded its global bound.");
    }
  }
  return results;
}

export async function readConsumerWorkflowPin(consumerRoot: string): Promise<string> {
  const pins = new Set<string>();
  for (const [workflow, reusableCalls] of Object.entries(CONSUMER_WORKFLOW_CALLS)) {
    const path = join(consumerRoot, ".github", "workflows", workflow);
    const metadata = await lstat(path).catch(() => undefined);
    if (
      metadata === undefined ||
      !metadata.isFile() ||
      metadata.isSymbolicLink() ||
      metadata.size < 1 ||
      metadata.size > 1024 * 1024
    ) {
      throw new Error(`Consumer workflow ${workflow} is missing, symbolic, or oversized.`);
    }
    const text = await readFile(path, "utf8");
    for (const reusable of reusableCalls) {
      const pattern = new RegExp(
        `^\\s*uses:\\s*collinbentley1/platform/\\.github/workflows/${escapeRegExp(reusable)}@([0-9a-f]{40})\\s*(?:#.*)?$`,
        "gm",
      );
      const matches = [...text.matchAll(pattern)];
      if (matches.length !== 1) {
        throw new Error(`Consumer workflow ${workflow} must contain one exact ${reusable} call.`);
      }
      pins.add(sha(matches[0]![1]!, `consumer ${workflow} workflow pin`));
    }
  }
  if (pins.size !== 1) {
    throw new Error("The exact consumer commit has inconsistent platform workflow pins.");
  }
  const pin = [...pins][0]!;
  if (FORBIDDEN_PRE_MIGRATION_WORKFLOW_SHAS.has(pin)) {
    throw new Error("The exact consumer commit is pinned to a vulnerable pre-migration workflow SHA.");
  }
  return pin;
}

export async function verifyPlatformCapability(root: string): Promise<PlatformCapability> {
  await requireRealDirectory(root, "capability platform root");
  const manifestPath = join(root, CAPABILITY_MANIFEST_PATH);
  await requireRegularTreeFile(root, CAPABILITY_MANIFEST_PATH, 64 * 1024);
  let value: unknown;
  try {
    value = JSON.parse(await readFile(manifestPath, "utf8")) as unknown;
  } catch {
    throw new Error("The deployment-parity capability manifest is malformed JSON.");
  }
  const manifest = record(value, "deployment-parity capability manifest");
  exactKeys(
    manifest,
    new Set([
      "capability",
      "dhiParityId",
      "marker",
      "maxMutatorTokenLifetimeSeconds",
      "requiredFiles",
      "schemaVersion",
    ]),
    "deployment-parity capability manifest",
  );
  exact(manifest.schemaVersion, 1, "deployment-parity capability schema");
  exact(manifest.capability, "preview-deployment-parity", "deployment-parity capability name");
  const dhiParityId = requiredString(manifest.dhiParityId, "deployment-parity DHI parity ID");
  if (!/^[0-9a-z]{50}$/.test(dhiParityId)) {
    throw new Error("The deployment-parity DHI parity ID is malformed.");
  }
  const maxMutatorTokenLifetimeSeconds = boundedInteger(
    manifest.maxMutatorTokenLifetimeSeconds,
    "deployment-parity mutator token lifetime",
    1,
    LEGACY_MUTATOR_TOKEN_SECONDS,
  );
  exact(
    maxMutatorTokenLifetimeSeconds,
    300,
    "deployment-parity mutator token lifetime",
  );
  const marker = record(manifest.marker, "deployment-parity marker contract");
  exactKeys(
    marker,
    new Set(["bucketSuffix", "metadataVersion", "object"]),
    "deployment-parity marker contract",
  );
  exact(marker.bucketSuffix, "-deployment-parity-state", "marker bucket suffix");
  exact(marker.object, "deployment-parity-transition", "marker object");
  exact(marker.metadataVersion, "1", "marker metadata version");

  const requiredFiles = record(manifest.requiredFiles, "deployment-parity required files");
  exactKeys(
    requiredFiles,
    new Set(CAPABILITY_REQUIRED_FILES),
    "deployment-parity required files",
  );
  for (const relativePath of CAPABILITY_REQUIRED_FILES) {
    const commitment = requiredString(
      requiredFiles[relativePath],
      `deployment-parity hash for ${relativePath}`,
    );
    if (!/^sha256:[0-9a-f]{64}$/.test(commitment)) {
      throw new Error(`The deployment-parity hash for ${relativePath} is malformed.`);
    }
    await requireRegularTreeFile(root, relativePath, 8 * 1024 * 1024);
    const observed = `sha256:${createHash("sha256").update(await readFile(join(root, relativePath))).digest("hex")}`;
    exact(observed, commitment, `deployment-parity hash for ${relativePath}`);
  }
  return { dhiParityId, maxMutatorTokenLifetimeSeconds };
}

async function verifyTerraformProviderTrust(invocation: Invocation): Promise<void> {
  const archiveMetadata = await lstat(invocation.terraformProviderArchive);
  if (
    !archiveMetadata.isFile() ||
    archiveMetadata.isSymbolicLink() ||
    archiveMetadata.size < 1 ||
    archiveMetadata.size > 256 * 1024 * 1024
  ) {
    throw new Error("The pinned Google provider archive escaped its file contract.");
  }
  const archiveSha256 = createHash("sha256")
    .update(await readFile(invocation.terraformProviderArchive))
    .digest("hex");
  exact(archiveSha256, GOOGLE_PROVIDER_LINUX_AMD64_ZH, "Google provider archive SHA-256");

  const entries = (await readdir(invocation.terraformProviderDirectory, { withFileTypes: true }))
    .toSorted((left, right) => left.name.localeCompare(right.name));
  if (
    entries.length !== 2 ||
    entries[0]?.name !== "LICENSE.txt" ||
    !entries[0].isFile() ||
    entries[0].isSymbolicLink() ||
    entries[1]?.name !== GOOGLE_PROVIDER_BINARY ||
    !entries[1].isFile() ||
    entries[1].isSymbolicLink()
  ) {
    throw new Error("The extracted Google provider directory escaped its exact two-file contract.");
  }
  const providerBinary = join(invocation.terraformProviderDirectory, GOOGLE_PROVIDER_BINARY);
  const providerMetadata = await lstat(providerBinary);
  if ((providerMetadata.mode & 0o111) === 0) {
    throw new Error("The pinned Google provider binary is not executable.");
  }

  const root = `terraform/deployments/${invocation.terraformRoot}`;
  const lockPath = `${root}/.terraform.lock.hcl`;
  const versionsPath = `${root}/versions.tf`;
  await requireRegularTreeFile(invocation.platformRoot, lockPath, 1024 * 1024);
  await requireRegularTreeFile(invocation.platformRoot, versionsPath, 1024 * 1024);
  const lock = await readFile(join(invocation.platformRoot, lockPath), "utf8");
  const versions = await readFile(join(invocation.platformRoot, versionsPath), "utf8");
  if ((lock.match(/^provider\s+"/gm) ?? []).length !== 1) {
    throw new Error("The selected Terraform root must lock exactly one provider.");
  }
  for (const needle of [
    'provider "registry.terraform.io/hashicorp/google"',
    `version     = "${GOOGLE_PROVIDER_VERSION}"`,
    `zh:${GOOGLE_PROVIDER_LINUX_AMD64_ZH}`,
  ]) {
    if ((lock.split(needle).length - 1) !== 1) {
      throw new Error("The selected Terraform provider lock escaped its exact trusted artifact.");
    }
  }
  if (
    !versions.includes('source  = "hashicorp/google"') ||
    !versions.includes(`version = "= ${GOOGLE_PROVIDER_VERSION}"`)
  ) {
    throw new Error("The selected Terraform provider constraint is not exact.");
  }
}

export function requireSameDhiTransitionCapability(
  active: PlatformCapability,
  transition: PlatformCapability,
): PlatformCapability {
  exact(
    transition.dhiParityId,
    active.dhiParityId,
    "transition and active DHI parity ID",
  );
  exact(
    transition.maxMutatorTokenLifetimeSeconds,
    active.maxMutatorTokenLifetimeSeconds,
    "transition and active mutator-token lifetime",
  );
  return active;
}

async function verifyTransitionCapability(invocation: Invocation): Promise<PlatformCapability> {
  if (invocation.transitionWorkflowSha === "") {
    return verifyPlatformCapability(invocation.platformRoot);
  }
  const [active, transition] = await Promise.all([
    verifyPlatformCapability(invocation.platformRoot),
    verifyPlatformCapability(invocation.transitionPlatformRoot),
  ]);
  requireSameDhiTransitionCapability(active, transition);
  const environment = hardenedGitEnvironment(invocation.runnerTemp);
  await command(
    [
      ...hardenedGitCommand(),
      "merge-base",
      "--is-ancestor",
      invocation.transitionWorkflowSha,
      invocation.platformSha,
    ],
    {
      cwd: invocation.platformRoot,
      deadlineMs: Date.now() + 60_000,
      env: environment,
      label: "transition ancestry verification",
    },
  );
  return active;
}

async function requireRegularTreeFile(
  root: string,
  relativePath: string,
  maximumBytes: number,
): Promise<void> {
  if (
    relativePath.startsWith("/") ||
    relativePath.split("/").some((component) => component === "" || component === "." || component === "..")
  ) {
    throw new Error("A capability path escaped the checked-out source tree.");
  }
  let current = root;
  const components = relativePath.split("/");
  for (const [index, component] of components.entries()) {
    current = join(current, component);
    const metadata = await lstat(current).catch(() => undefined);
    const final = index === components.length - 1;
    if (
      metadata === undefined ||
      metadata.isSymbolicLink() ||
      (final ? !metadata.isFile() : !metadata.isDirectory())
    ) {
      throw new Error(`Capability path ${relativePath} is missing, symbolic, or malformed.`);
    }
    if (final && (metadata.size < 1 || metadata.size > maximumBytes)) {
      throw new Error(`Capability path ${relativePath} escaped its size bound.`);
    }
  }
}

async function runDoctor(
  invocation: Invocation,
  repositoryId: string,
  expectedConsumerWorkflowSha: string,
): Promise<void> {
  await command(
    [
      resolve(invocation.runnerTemp, "bun-bin", "bun-linux-x64", "bun"),
      "--no-env-file",
      "--no-orphans",
      resolve(invocation.platformRoot, "tools/platform.ts"),
      "doctor",
      invocation.consumerRoot,
    ],
    {
      cwd: invocation.platformRoot,
      deadlineMs: Date.now() + 5 * 60_000,
      env: {
        HOME: invocation.runnerTemp,
        PATH: required(process.env, "PATH"),
        PLATFORM_WORKFLOW_SHA: expectedConsumerWorkflowSha,
        TRUSTED_GITHUB_REPOSITORY_ID: repositoryId,
      },
      label: "trusted platform doctor",
    },
  );
}

export interface TerraformSandboxSpec {
  readonly args: readonly string[];
  readonly containerName: string;
  readonly invocation: Invocation;
  readonly terraformDirectory: string;
  readonly workDirectory: string;
}

export interface TerraformSandboxDriver {
  readonly create: (spec: TerraformSandboxSpec, deadlineMs: number) => Promise<void>;
  readonly kill: (containerName: string, invocation: Invocation, deadlineMs: number) => Promise<void>;
  readonly remove: (
    containerName: string,
    invocation: Invocation,
    deadlineMs: number,
  ) => Promise<void>;
  readonly start: (
    containerName: string,
    invocation: Invocation,
    executorToken: string,
    deadlineMs: number,
    capture: boolean,
  ) => Promise<string>;
  readonly wait: (containerName: string, invocation: Invocation, deadlineMs: number) => Promise<void>;
}

export class TerraformSandboxExecutor {
  readonly #driver: TerraformSandboxDriver;
  readonly #randomSuffix: (() => string) | undefined;
  #counter = 0;
  #active = new Map<string, Invocation>();

  constructor(
    driver: TerraformSandboxDriver = dockerTerraformSandboxDriver(),
    randomSuffix: (() => string) | undefined = undefined,
  ) {
    this.#driver = driver;
    this.#randomSuffix = randomSuffix;
  }

  async run(
    invocation: Invocation,
    session: ExecutorSession,
    terraformDirectory: string,
    args: readonly string[],
    operationDeadlineMs: number,
    capture = false,
  ): Promise<string> {
    assertSession(session, Date.now(), operationDeadlineMs);
    exact(
      terraformDirectory,
      resolve(invocation.platformRoot, "terraform", "deployments", invocation.terraformRoot),
      "sandbox Terraform directory",
    );
    const nextCounter = this.#counter + 1;
    if (nextCounter > 5) {
      throw new Error("Terraform sandbox escaped its finite reviewed phase count.");
    }
    const suffix = this.#randomSuffix?.() ?? deterministicArtifactHex(
      invocation.repository,
      invocation.githubRunId,
      `container-${nextCounter as 1 | 2 | 3 | 4 | 5}`,
    ).slice(0, 12);
    if (!/^[0-9a-f]{12}$/.test(suffix)) {
      throw new Error("Terraform sandbox suffix escaped its random syntax.");
    }
    this.#counter = nextCounter;
    const containerName = `pbt-${invocation.githubRunId}-${this.#counter}-${suffix}`;
    const workDirectory = resolve(
      invocation.runnerTemp,
      `protected-bootstrap-${invocation.githubRunId}.sandbox`,
    );
    await ensurePrivateDirectory(workDirectory);
    await ensurePrivateDirectory(resolve(workDirectory, "home"));
    await ensurePrivateDirectory(resolve(workDirectory, "tfdata"));
    this.#active.set(containerName, invocation);
    let primaryFailure: unknown;
    try {
      await this.#driver.create({
        args,
        containerName,
        invocation,
        terraformDirectory,
        workDirectory,
      }, operationDeadlineMs);
      return await this.#driver.start(
        containerName,
        invocation,
        session.accessToken,
        operationDeadlineMs,
        capture,
      );
    } catch (error) {
      primaryFailure = error;
      throw error;
    } finally {
      const cleanupDeadlineMs = Math.max(operationDeadlineMs, Date.now() + 60_000);
      try {
        await this.#cleanupOne(containerName, invocation, cleanupDeadlineMs);
      } catch (cleanupError) {
        if (primaryFailure === undefined) throw cleanupError;
        throw new AggregateError(
          [primaryFailure, cleanupError],
          "Terraform sandbox failed and its exact container cleanup also failed.",
        );
      }
    }
  }

  async cleanupAll(cleanupDeadlineMs: number): Promise<void> {
    const errors: unknown[] = [];
    for (const [containerName, invocation] of [...this.#active]) {
      await this.#cleanupOne(containerName, invocation, cleanupDeadlineMs).catch((error) =>
        errors.push(error)
      );
    }
    if (errors.length > 0) {
      throw new AggregateError(errors, "One or more Terraform sandbox containers survived cleanup.");
    }
  }

  async #cleanupOne(
    containerName: string,
    invocation: Invocation,
    cleanupDeadlineMs: number,
  ): Promise<void> {
    const errors: unknown[] = [];
    await this.#driver.kill(containerName, invocation, cleanupDeadlineMs).catch((error) =>
      errors.push(error)
    );
    await this.#driver.wait(containerName, invocation, cleanupDeadlineMs).catch((error) =>
      errors.push(error)
    );
    await this.#driver.remove(containerName, invocation, cleanupDeadlineMs).catch((error) =>
      errors.push(error)
    );
    if (errors.length > 0) {
      throw new AggregateError(errors, `Terraform sandbox ${containerName} was not removed exactly.`);
    }
    this.#active.delete(containerName);
  }
}

function dockerTerraformSandboxDriver(): TerraformSandboxDriver {
  const hostEnvironment = (invocation: Invocation): Readonly<Record<string, string>> => ({
    HOME: invocation.runnerTemp,
    PATH: "/usr/bin:/bin",
  });
  const runDocker = (
    invocation: Invocation,
    argv: readonly string[],
    deadlineMs: number,
    options: { readonly capture?: boolean; readonly ignoreFailure?: boolean; readonly stdin?: string; readonly label: string },
  ) => command(["/usr/bin/docker", ...argv], {
    ...options,
    cwd: invocation.runnerTemp,
    deadlineMs,
    env: hostEnvironment(invocation),
  });
  return {
    create: async (spec, deadlineMs) => {
      const uid = process.getuid?.();
      const gid = process.getgid?.();
      if (uid === undefined || gid === undefined || uid <= 0 || gid <= 0) {
        throw new Error("Terraform sandbox requires one non-root numeric runner identity.");
      }
      for (const value of [
        spec.invocation.platformRoot,
        spec.invocation.terraformBinary,
        spec.invocation.terraformProviderDirectory,
        spec.workDirectory,
      ]) {
        if (value.includes(",") || value.includes("\n") || value.includes("\r")) {
          throw new Error("A Terraform sandbox bind source escaped Docker mount syntax.");
        }
      }
      const relativeDirectory = spec.terraformDirectory.slice(spec.invocation.platformRoot.length);
      if (relativeDirectory !== `/terraform/deployments/${spec.invocation.terraformRoot}`) {
        throw new Error("Terraform sandbox working directory escaped the reviewed root.");
      }
      await runDocker(spec.invocation, [
        "create",
        `--name=${spec.containerName}`,
        `--label=${SANDBOX_OWNER_LABEL}=true`,
        `--label=${SANDBOX_RUN_LABEL}=${spec.invocation.githubRunId}`,
        `--label=${SANDBOX_PLATFORM_REPOSITORY_LABEL}=${PLATFORM_REPOSITORY_ID}`,
        `--label=${SANDBOX_TARGET_REPOSITORY_LABEL}=${REPOSITORIES[spec.invocation.repository].repositoryId}`,
        "--platform=linux/amd64",
        "--pull=never",
        "--network=bridge",
        "--pid=private",
        "--ipc=private",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        `--user=${uid}:${gid}`,
        "--pids-limit=256",
        "--memory=2g",
        "--cpus=2",
        "--ulimit=nofile=1024:1024",
        "--stop-timeout=1",
        "--init",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=1777",
        `--mount=type=bind,src=${spec.invocation.platformRoot},dst=/platform,readonly`,
        `--mount=type=bind,src=${spec.invocation.terraformBinary},dst=/opt/terraform,readonly`,
        `--mount=type=bind,src=${spec.invocation.terraformProviderDirectory},dst=/plugins,readonly`,
        `--mount=type=bind,src=${spec.workDirectory},dst=/work,rw`,
        `--workdir=/platform${relativeDirectory}`,
        "--env=CHECKPOINT_DISABLE=1",
        "--env=TF_DATA_DIR=/work/tfdata",
        "--env=TF_IN_AUTOMATION=1",
        "--entrypoint=/bin/sh",
        spec.invocation.terraformSandboxImage,
        "/platform/tools/ci/terraform-sandbox-entrypoint.sh",
        ...spec.args,
      ], deadlineMs, { label: "create Terraform sandbox" });
    },
    start: (containerName, invocation, executorToken, deadlineMs, capture) =>
      runDocker(invocation, ["start", "--attach", "--interactive", containerName], deadlineMs, {
        capture,
        label: "terraform sandbox",
        stdin: `${executorToken}\n`,
      }),
    kill: async (containerName, invocation, deadlineMs) => {
      await runDocker(invocation, ["kill", "--signal=KILL", containerName], deadlineMs, {
        ignoreFailure: true,
        label: "kill Terraform sandbox",
      });
    },
    wait: async (containerName, invocation, deadlineMs) => {
      await runDocker(invocation, ["wait", containerName], deadlineMs, {
        ignoreFailure: true,
        label: "wait for Terraform sandbox",
      });
    },
    remove: async (containerName, invocation, deadlineMs) => {
      await runDocker(invocation, ["rm", "--force", containerName], deadlineMs, {
        ignoreFailure: true,
        label: "remove Terraform sandbox",
      });
      const survivors = await runDocker(
        invocation,
        ["ps", "--all", "--filter", `name=^/${containerName}$`, "--format", "{{.Names}}"],
        deadlineMs,
        { capture: true, label: "prove Terraform sandbox removal" },
      );
      if (survivors.trim() !== "") {
        throw new Error(`Terraform sandbox ${containerName} survived kill/wait/remove.`);
      }
    },
  };
}

function defaultBridgeDependencies(
  telemetry: BridgeTelemetry = NOOP_BRIDGE_TELEMETRY,
): BridgeDependencies {
  const manager = new ExecutorLeaseManager(
    fetch,
    (milliseconds) => Bun.sleep(milliseconds),
    undefined,
    telemetry,
  );
  const sandbox = new TerraformSandboxExecutor(dockerTerraformSandboxDriver());
  let apiDeadlineMs = Date.now() + 5 * 60_000;
  const api = deadlineFetcher(fetch, () => apiDeadlineMs);
  return {
    acquireExecutor: (invocation, leaseExpiresAt, operationDeadlineMs) =>
      manager.acquire(invocation, leaseExpiresAt, operationDeadlineMs),
    appendSummary: (invocation, value) => appendFile(invocation.stepSummary, value),
    consumeApproval: (invocation, session, review, proof, nowMs) =>
      consumePlanReceipt(
        invocation,
        session.accessToken,
        review,
        proof,
        nowMs,
        api,
      ),
    elevateExecutor: (invocation, session, leaseExpiresAt, operationDeadlineMs) =>
      manager.elevate(invocation, session, leaseExpiresAt, operationDeadlineMs),
    inspectPlan: inspectPlanFile,
    now: () => Date.now(),
    prepare: async (invocation, operationDeadlineMs) => {
      apiDeadlineMs = operationDeadlineMs;
      assertBeforeDeadline(Date.now(), operationDeadlineMs, "source preparation");
      const contract = REPOSITORIES[invocation.repository];
      await Promise.all([
        requireRealDirectory(invocation.platformRoot, "platform root"),
        requireRealDirectory(invocation.consumerRoot, "consumer root"),
        requireRealDirectory(invocation.runnerTemp, "runner temp"),
        requireRealDirectory(
          invocation.terraformProviderDirectory,
          "Terraform provider directory",
        ),
        requireRegularFile(invocation.terraformBinary, "Terraform binary"),
        requireRegularFile(invocation.terraformProviderArchive, "Terraform provider archive"),
        requireRegularFile(
          resolve(invocation.platformRoot, "tools/ci/terraform-sandbox-entrypoint.sh"),
          "Terraform sandbox entrypoint",
        ),
      ]);
      await verifyTerraformProviderTrust(invocation);
      await verifyLocalSource(invocation.platformRoot, invocation.platformSha, undefined);
      const consumerTreeSha = await verifyLocalSource(
        invocation.consumerRoot,
        invocation.consumerSha,
        undefined,
      );
      const consumerWorkflowPin = await readConsumerWorkflowPin(invocation.consumerRoot);
      const expectedConsumerWorkflowPin = invocation.transitionWorkflowSha === ""
        ? invocation.platformSha
        : invocation.transitionWorkflowSha;
      exact(
        consumerWorkflowPin,
        expectedConsumerWorkflowPin,
        "consumer platform workflow pin",
      );
      if (invocation.transitionWorkflowSha !== "") {
        await requireRealDirectory(invocation.transitionPlatformRoot, "transition platform root");
        await verifyLocalSource(
          invocation.transitionPlatformRoot,
          invocation.transitionWorkflowSha,
          undefined,
        );
      }
      const capability = await verifyTransitionCapability(invocation);
      const tokenDrainSeconds = invocation.transitionWorkflowSha === ""
        ? LEGACY_MUTATOR_TOKEN_SECONDS
        : capability.maxMutatorTokenLifetimeSeconds;
      await proveConsumerFreeze(
        invocation.githubActionsToken,
        tokenDrainSeconds,
        api,
      );
      await runDoctor(invocation, contract.repositoryId, consumerWorkflowPin);
      return { ...capability, consumerTreeSha, tokenDrainSeconds };
    },
    proveFreeze: (invocation, tokenDrainSeconds) =>
      proveConsumerFreeze(invocation.githubActionsToken, tokenDrainSeconds, api),
    proveMarkers: (invocation, session, requireTargetClear) =>
      proveDeploymentParityMarkers(
        invocation,
        session.accessToken,
        requireTargetClear,
        api,
      ),
    publishPlanReceipt: (invocation, session, review, proof, nowMs) =>
      publishPlanReceipt(
        invocation,
        session.accessToken,
        review,
        proof,
        nowMs,
        api,
      ),
    publishPostApplyReceipt: (invocation, session, review, proof, nowMs) =>
      publishPostApplyReceipt(
        invocation,
        session.accessToken,
        review,
        proof,
        nowMs,
        api,
      ),
    readPlanJson: async (
      invocation,
      session,
      terraformDirectory,
      _planPath,
      operationDeadlineMs,
    ) =>
      sandbox.run(
        invocation,
        session,
        terraformDirectory,
        ["show", "-json", "/work/plan.tfplan"],
        operationDeadlineMs,
        true,
    ),
    releaseExecutor: async (invocation, _session, cleanupDeadlineMs) => {
      await releaseSandboxAndExecutor(
        () => sandbox.cleanupAll(cleanupDeadlineMs),
        () => manager.release(invocation, cleanupDeadlineMs),
      );
    },
    removePrivatePath: (path) => rm(path, { force: true, recursive: true }),
    runTerraform: async (
      invocation,
      session,
      terraformDirectory,
      args,
      operationDeadlineMs,
    ) => {
      await sandbox.run(
        invocation,
        session,
        terraformDirectory,
        args,
        operationDeadlineMs,
      );
    },
    verifyApproval: (invocation, session, proof, nowMs) =>
      verifyPlanApproval(invocation, session.accessToken, proof, nowMs, api),
    waitForPostMutationDrain: async (invocation, mutationCompletedAtMs, operationDeadlineMs) => {
      if (invocation.terraformRoot !== "bootstrap") return;
      const targetMs = mutationCompletedAtMs +
        POST_MUTATION_DRAIN_SECONDS * 1_000;
      if (targetMs >= operationDeadlineMs) {
        throw new Error("The protected deadline cannot cover the post-WIF token drain.");
      }
      const remainingMs = targetMs - Date.now();
      if (remainingMs > 0) await Bun.sleep(remainingMs);
      assertBeforeDeadline(Date.now(), operationDeadlineMs, "post-WIF token drain");
    },
  };
}

export async function releaseSandboxAndExecutor(
  cleanupSandbox: () => Promise<void>,
  cleanupExecutor: () => Promise<void>,
): Promise<void> {
  // Invoke IAM first and isolate both callbacks behind promises so a
  // synchronous Docker-cleanup failure cannot suppress executor containment.
  const results = await Promise.allSettled([
    Promise.resolve().then(cleanupExecutor),
    Promise.resolve().then(cleanupSandbox),
  ]);
  const errors = results.flatMap((result) =>
    result.status === "rejected" ? [result.reason] : []
  );
  if (errors.length > 0) {
    throw new AggregateError(errors, "Sandbox and executor cleanup did not both complete.");
  }
}

function defaultRecoveryDependencies(): RecoveryDependencies {
  let apiDeadlineMs = Date.now() + RECOVERY_OPERATION_MINUTES * 60_000;
  const api = deadlineFetcher(fetch, () => apiDeadlineMs);
  return {
    now: () => Date.now(),
    recoverArtifacts: async (invocation, recoveryDeadlineMs) => {
      apiDeadlineMs = recoveryDeadlineMs;
      await recoverBridgeArtifactsUntilStable(
        invocation,
        api,
        (milliseconds) => Bun.sleep(milliseconds),
        recoveryDeadlineMs,
        () => Date.now(),
      );
    },
    verifySource: async (invocation) => {
      await Promise.all([
        requireRealDirectory(invocation.platformRoot, "recovery platform root"),
        requireRealDirectory(invocation.runnerTemp, "recovery runner temp"),
      ]);
      await verifyLocalSource(invocation.platformRoot, invocation.platformSha, undefined);
    },
  };
}

async function inspectPlanFile(planPath: string): Promise<void> {
  const planMetadata = await lstat(planPath);
  if (
    !planMetadata.isFile() ||
    planMetadata.isSymbolicLink() ||
    planMetadata.size < 1 ||
    planMetadata.size > MAX_PLAN_FILE_BYTES
  ) {
    throw new Error("Terraform did not create one regular saved-plan file.");
  }
  await chmod(planPath, 0o600);
}

async function command(
  argv: readonly string[],
  options: {
    readonly capture?: boolean;
    readonly cwd: string;
    readonly deadlineMs: number;
    readonly env: Readonly<Record<string, string>>;
    readonly ignoreFailure?: boolean;
    readonly stdin?: string;
    readonly label: string;
  },
): Promise<string> {
  assertBeforeDeadline(Date.now(), options.deadlineMs, options.label);
  const child = Bun.spawn([...argv], {
    cwd: options.cwd,
    env: options.env,
    stdin: options.stdin === undefined ? "ignore" : "pipe",
    stderr: "pipe",
    stdout: "pipe",
  });
  if (options.stdin !== undefined) {
    const stdin = child.stdin;
    if (stdin === undefined || typeof stdin === "number") {
      child.kill("SIGKILL");
      throw new Error(`${options.label} did not expose its protected stdin pipe.`);
    }
    stdin.write(options.stdin);
    stdin.end();
  }
  const remainingMs = options.deadlineMs - Date.now();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`${options.label} exceeded the protected operation deadline.`));
    }, remainingMs);
  });
  let exitCode: number;
  let stdout: string;
  let stderr: string;
  try {
    [exitCode, stdout, stderr] = await Promise.race([
      Promise.all([
        child.exited,
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
      ]),
      timeout,
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
  if (exitCode !== 0 && options.ignoreFailure !== true) {
    const diagnostic = options.label.startsWith("terraform ")
      ? ""
      : redactDiagnostic(stderr, options.env);
    throw new Error(`${options.label} failed${diagnostic === "" ? "." : `: ${diagnostic}`}`);
  }
  return options.capture === true ? stdout : "";
}

function redactDiagnostic(
  diagnostic: string,
  environment: Readonly<Record<string, string>>,
): string {
  let result = diagnostic.slice(0, 4_096).replace(/[\r\n]+/g, " ").trim();
  for (const [name, value] of Object.entries(environment)) {
    if ((name.includes("TOKEN") || name.includes("ACCESS")) && value.length > 0) {
      result = result.replaceAll(value, "[REDACTED]");
    }
  }
  return result;
}

export async function verifyLocalSource(
  root: string,
  expectedSha: string,
  expectedTree: string | undefined,
  runnerTemp = required(process.env, "RUNNER_TEMP_EXACT"),
): Promise<string> {
  const env = hardenedGitEnvironment(runnerTemp);
  const git = hardenedGitCommand();
  const observedSha = (
    await command([...git, "rev-parse", "HEAD"], {
      capture: true,
      cwd: root,
      deadlineMs: Date.now() + 60_000,
      env,
      label: "git commit verification",
    })
  ).trim();
  exact(observedSha, expectedSha, "checked-out commit");
  const observedTree = (
    await command([...git, "rev-parse", "HEAD^{tree}"], {
      capture: true,
      cwd: root,
      deadlineMs: Date.now() + 60_000,
      env,
      label: "git tree verification",
    })
  ).trim();
  sha(observedTree, "checked-out tree");
  if (expectedTree !== undefined) {
    exact(observedTree, expectedTree, "checked-out tree");
  }
  const status = await command(
    [...git, "status", "--porcelain=v1", "--untracked-files=all"],
    {
      capture: true,
      cwd: root,
      deadlineMs: Date.now() + 60_000,
      env,
      label: "git cleanliness verification",
    },
  );
  if (status !== "") throw new Error("A protected source checkout is not completely clean.");
  return observedTree;
}

function hardenedGitEnvironment(runnerTemp: string): Readonly<Record<string, string>> {
  return {
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
    HOME: runnerTemp,
    PATH: "/usr/bin:/bin",
  };
}

function hardenedGitCommand(): readonly string[] {
  return [
    "/usr/bin/git",
    "-c",
    "credential.helper=",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "diff.external=",
    "-c",
    "protocol.file.allow=never",
    "-c",
    "protocol.version=2",
  ];
}

export interface PolicyMutationRecord {
  readonly get: () => Promise<IamPolicy>;
  readonly label: string;
  readonly leases: readonly IamBinding[];
  readonly original: IamPolicy;
  readonly set: (policy: IamPolicy) => Promise<IamPolicy | undefined>;
}

export class ExecutorLeaseManager {
  readonly #fetcher: Fetcher;
  readonly #randomHex: (() => string) | undefined;
  readonly #sleep: (milliseconds: number) => Promise<void>;
  readonly #telemetry: BridgeTelemetry;
  #accountId: string | undefined;
  #accountDescription: string | undefined;
  #accountIdentity: ServiceAccountIdentity | undefined;
  #acceptedRoleDeletions = new Set<string>();
  #apiDeadlineMs = 0;
  #account: ServiceAccount | undefined;
  #executorDeleteAccepted = false;
  #executorLifecycleArmed = false;
  #elevated = false;
  #invocation: Invocation | undefined;
  #mutations: PolicyMutationRecord[] = [];
  #policyCleanupComplete = false;
  #roleIntents = new Map<string, EphemeralRoleIntent>();
  #roles: ProjectCustomRole[] = [];
  #session: ExecutorSession | undefined;

  constructor(
    fetcher: Fetcher,
    sleep: (milliseconds: number) => Promise<void>,
    randomHex: (() => string) | undefined = undefined,
    telemetry: BridgeTelemetry = NOOP_BRIDGE_TELEMETRY,
  ) {
    this.#fetcher = deadlineFetcher(fetcher, () => this.#apiDeadlineMs);
    this.#sleep = sleep;
    this.#randomHex = randomHex;
    this.#telemetry = bestEffortTelemetry(telemetry);
  }

  async acquire(
    invocation: Invocation,
    leaseExpiresAt: Date,
    operationDeadlineMs: number,
  ): Promise<ExecutorSession> {
    if (this.#invocation !== undefined) throw new Error("The executor lease manager is single-use.");
    this.#invocation = invocation;
    this.#apiDeadlineMs = operationDeadlineMs;
    const contract = REPOSITORIES[invocation.repository];
    try {
      assertBeforeDeadline(Date.now(), operationDeadlineMs, "executor setup");
      this.#telemetry.phase("executor.inventory");
      const inventory = await inventoryBridgeArtifacts(
        contract.projectId,
        invocation.ownerAccessToken,
        this.#fetcher,
        this.#sleep,
        operationDeadlineMs,
      );
      const accountId = randomExecutorAccountId(
        this.#randomHex?.() ??
          deterministicArtifactHex(invocation.repository, invocation.githubRunId, "service-account"),
      );
      const readRoleId = randomExecutorRoleId(
        "read",
        this.#randomHex?.() ??
          deterministicArtifactHex(invocation.repository, invocation.githubRunId, "role-read"),
      );
      if (inventory.accountIds.has(accountId) || inventory.roleIds.has(readRoleId)) {
        throw new Error("A cryptographically random executor identifier collided; refusing reuse.");
      }
      this.#accountId = accountId;
      this.#accountDescription = executorDescription(executorProvenance(invocation, leaseExpiresAt));
      this.#telemetry.phase("executor.account-create");
      let account = await createEphemeralExecutor(
        contract.projectId,
        accountId,
        invocation,
        leaseExpiresAt,
        invocation.ownerAccessToken,
        this.#fetcher,
        this.#sleep,
        operationDeadlineMs,
        async () => {
          this.#executorLifecycleArmed = true;
        },
        () => {
          this.#executorLifecycleArmed = false;
        },
        (created) => {
          // The create response is the first authoritative source of the stable
          // unique ID. Arm exact-identity cleanup before any visibility read.
          this.#accountIdentity = created;
        },
      );
      this.#account = account;
      this.#accountIdentity = account;
      this.#telemetry.phase("executor.role-create");
      const readRole = await createEphemeralRole(
        contract.projectId,
        readRoleId,
        invocation.terraformRoot,
        "read",
        executorControlPermissions(invocation.repository, invocation.terraformRoot, "read"),
        invocation.ownerAccessToken,
        this.#fetcher,
        async (intent) => {
          this.#roleIntents.set(intent.name, intent);
        },
        (name) => this.#roleIntents.delete(name),
        (created) => {
          this.#roleIntents.delete(created.name);
          this.#roles.push(created);
        },
      );
      await this.#retryIamConsistency(
        "post-create executor key inventory",
        () => requireNoUserManagedKeys(
          account,
          invocation.ownerAccessToken,
          this.#fetcher,
        ),
      );
      const executorPolicy = await this.#retryIamConsistency(
        "post-create executor policy read",
        () => getServiceAccountPolicy(
          account,
          invocation.ownerAccessToken,
          this.#fetcher,
        ),
      );
      if (executorPolicy.bindings.length !== 0 || executorPolicy.auditConfigs !== undefined) {
        throw new Error("The dedicated executor has an unexpected standing IAM policy.");
      }

      const originalProjectPolicy = await getPolicy(
        contract.projectId,
        invocation.ownerAccessToken,
        this.#fetcher,
      );
      requireNoExecutorProjectBindings(originalProjectPolicy, account.email);

      this.#telemetry.phase("executor.policy");
      await this.#recordAndAdd(
        `executor service account ${account.email}`,
        [
          buildTokenCreatorLease(
            invocation.repository,
            invocation.githubRunId,
            leaseExpiresAt,
          ),
        ],
        () =>
          this.#retryIamConsistency(
            "post-create executor policy read-modify-write read",
            () => getServiceAccountPolicy(
              account,
              invocation.ownerAccessToken,
              this.#fetcher,
            ),
          ),
        (policy) =>
          this.#retryIamConsistency(
            "post-create executor policy read-modify-write write",
            () => setServiceAccountPolicy(
              account,
              invocation.ownerAccessToken,
              policy,
              this.#fetcher,
            ),
          ),
      );
      this.#telemetry.phase("executor.enable");
      account = await setExecutorDisabled(
        account,
        false,
        invocation.ownerAccessToken,
        this.#fetcher,
        this.#sleep,
        operationDeadlineMs,
      );
      this.#account = account;
      this.#telemetry.phase("executor.token-mint");
      const session = await this.#retryIamConsistency(
        "post-create executor token mint",
        () => mintExecutorToken(
          account,
          invocation.ownerAccessToken,
          this.#fetcher,
        ),
        true,
      );
      if (
        session.accessToken === invocation.ownerAccessToken ||
        session.accessToken === invocation.githubActionsToken ||
        session.accessToken === invocation.platformActionsToken
      ) {
        throw new Error("The minted executor token collided with a controller credential.");
      }
      assertSession(session, Date.now(), operationDeadlineMs);
      this.#session = session;
      this.#telemetry.phase("executor.baseline-proof");
      await waitForStatePermissions(
        contract.state[invocation.terraformRoot],
        invocation,
        session.accessToken,
        "none",
        this.#fetcher,
        this.#sleep,
      );
      await waitForControlPermissions(
        invocation,
        session.accessToken,
        "none",
        this.#fetcher,
        this.#sleep,
      );
      this.#telemetry.phase("executor.disable");
      account = await setExecutorDisabled(
        account,
        true,
        invocation.ownerAccessToken,
        this.#fetcher,
        this.#sleep,
        operationDeadlineMs,
      );
      this.#account = account;

      const projectLeases = [
        ...buildExecutorProjectLeases(
          invocation.repository,
          invocation.githubRunId,
          leaseExpiresAt,
          account.email,
          readRole.name,
          "read",
        ),
        buildStorageLease(
          invocation.repository,
          invocation.terraformRoot,
          invocation.githubRunId,
          leaseExpiresAt,
          account.email,
          "plan",
          "",
        ),
        ...buildReceiptLeases(
          invocation.repository,
          invocation.terraformRoot,
          invocation.githubRunId,
          leaseExpiresAt,
          invocation.mode,
          invocation.approvedPlanRunId,
          account.email,
        ),
        buildMarkerReadLease(
          invocation.repository,
          invocation.githubRunId,
          leaseExpiresAt,
          contract.projectId,
          account.email,
        ),
      ];
      this.#telemetry.phase("executor.project-leases");
      await this.#recordAndAdd(
        `project ${contract.projectId}`,
        projectLeases,
        () => getPolicy(contract.projectId, invocation.ownerAccessToken, this.#fetcher),
        (policy) =>
          setPolicy(
            contract.projectId,
            invocation.ownerAccessToken,
            policy,
            this.#fetcher,
          ),
        account.email,
      );
      this.#telemetry.phase("executor.marker-leases");
      for (const markerRepository of REPOSITORY_NAMES) {
        if (markerRepository === invocation.repository) continue;
        const markerProjectId = REPOSITORIES[markerRepository].projectId;
        await this.#recordAndAdd(
          `marker project ${markerProjectId}`,
          [
            buildMarkerReadLease(
              markerRepository,
              invocation.githubRunId,
              leaseExpiresAt,
              contract.projectId,
              account.email,
            ),
          ],
          () => getPolicy(markerProjectId, invocation.ownerAccessToken, this.#fetcher),
          (policy) =>
            setPolicy(
              markerProjectId,
              invocation.ownerAccessToken,
              policy,
              this.#fetcher,
            ),
          account.email,
        );
      }

      this.#telemetry.phase("executor.final-enable");
      account = await setExecutorDisabled(
        account,
        false,
        invocation.ownerAccessToken,
        this.#fetcher,
        this.#sleep,
        operationDeadlineMs,
      );
      this.#account = account;
      assertSession(session, Date.now(), operationDeadlineMs);
      this.#telemetry.phase("executor.permission-proof");
      await waitForStatePermissions(
        contract.state[invocation.terraformRoot],
        invocation,
        session.accessToken,
        "read",
        this.#fetcher,
        this.#sleep,
      );
      await waitForControlPermissions(
        invocation,
        session.accessToken,
        "read",
        this.#fetcher,
        this.#sleep,
      );
      this.#telemetry.phase("executor.ready");
      return session;
    } catch (error) {
      this.#apiDeadlineMs = Math.max(operationDeadlineMs, Date.now() + 5 * 60_000);
      const cleanupErrors = await this.#releaseAll(invocation, this.#apiDeadlineMs);
      if (cleanupErrors.length > 0) {
        throw new AggregateError(
          [error, ...cleanupErrors],
          "Executor setup failed and exact setup cleanup also failed.",
        );
      }
      throw error;
    }
  }

  async elevate(
    invocation: Invocation,
    session: ExecutorSession,
    leaseExpiresAt: Date,
    operationDeadlineMs: number,
  ): Promise<void> {
    if (invocation.mode !== "apply") throw new Error("Plan mode may never elevate its executor.");
    if (this.#invocation !== invocation || this.#session !== session || this.#account === undefined) {
      throw new Error("Executor elevation did not match the acquired single-run identity.");
    }
    if (this.#elevated) throw new Error("Executor mutation authority is single-use.");
    this.#apiDeadlineMs = operationDeadlineMs;
    assertSession(session, Date.now(), operationDeadlineMs);
    exact(session.executorEmail, this.#account.email, "executor elevation email");
    exact(session.executorUniqueId, this.#account.uniqueId, "executor elevation unique ID");
    const contract = REPOSITORIES[invocation.repository];
    const mutationRoleId = randomExecutorRoleId(
      "mutation",
      this.#randomHex?.() ??
        deterministicArtifactHex(invocation.repository, invocation.githubRunId, "role-mutation"),
    );
    const inventory = await listProjectCustomRoles(
      contract.projectId,
      invocation.ownerAccessToken,
      this.#fetcher,
      true,
    );
    if (inventory.some((role) => roleIdOrUndefined(role.name) === mutationRoleId)) {
      throw new Error("A cryptographically random mutation-role identifier collided; refusing reuse.");
    }
    const mutationRole = await createEphemeralRole(
      contract.projectId,
      mutationRoleId,
      invocation.terraformRoot,
      "mutation",
      executorControlPermissions(invocation.repository, invocation.terraformRoot, "mutation"),
      invocation.ownerAccessToken,
      this.#fetcher,
      async (intent) => {
        this.#roleIntents.set(intent.name, intent);
      },
      (name) => this.#roleIntents.delete(name),
      (created) => {
        this.#roleIntents.delete(created.name);
        this.#roles.push(created);
      },
    );
    await this.#recordAndAdd(
      `mutation project ${contract.projectId}`,
      [
        ...buildExecutorProjectLeases(
          invocation.repository,
          invocation.githubRunId,
          leaseExpiresAt,
          this.#account.email,
          mutationRole.name,
          "mutation",
        ),
        buildStorageLease(
          invocation.repository,
          invocation.terraformRoot,
          invocation.githubRunId,
          leaseExpiresAt,
          this.#account.email,
          "apply",
          invocation.approvedPlanRunId,
        ),
        ...(invocation.terraformRoot === "bootstrap"
          ? [
              buildMarkerMutationLease(
                invocation.repository,
                invocation.githubRunId,
                leaseExpiresAt,
                this.#account.email,
              ),
            ]
          : []),
      ],
      () => getPolicy(contract.projectId, invocation.ownerAccessToken, this.#fetcher),
      (policy) => setPolicy(contract.projectId, invocation.ownerAccessToken, policy, this.#fetcher),
      this.#account.email,
    );
    if (invocation.terraformRoot === "prod") {
      for (const [email, lease] of Object.entries(buildRuntimeActAsLeases(
        invocation.repository,
        invocation.githubRunId,
        leaseExpiresAt,
        this.#account.email,
      ))) {
        await this.#recordAndAdd(
          `runtime service account ${email}`,
          [lease],
          () => getServiceAccountPolicy(email, invocation.ownerAccessToken, this.#fetcher),
          (policy) =>
            setServiceAccountPolicy(email, invocation.ownerAccessToken, policy, this.#fetcher),
          this.#account.email,
        );
      }
    }
    await waitForStatePermissions(
      contract.state[invocation.terraformRoot],
      invocation,
      session.accessToken,
      "mutation",
      this.#fetcher,
      this.#sleep,
    );
    await waitForControlPermissions(
      invocation,
      session.accessToken,
      "mutation",
      this.#fetcher,
      this.#sleep,
    );
    this.#elevated = true;
  }

  async release(invocation: Invocation, cleanupDeadlineMs: number): Promise<void> {
    if (this.#invocation === undefined) return;
    if (this.#invocation !== invocation) throw new Error("Executor cleanup invocation drifted.");
    this.#apiDeadlineMs = cleanupDeadlineMs;
    const errors = await this.#releaseAll(invocation, cleanupDeadlineMs);
    if (errors.length > 0) {
      throw new AggregateError(errors, "Exact executor lease cleanup failed.");
    }
    this.#invocation = undefined;
  }

  async #recordAndAdd(
    label: string,
    leases: readonly IamBinding[],
    get: () => Promise<IamPolicy>,
    set: (policy: IamPolicy) => Promise<IamPolicy | undefined>,
    forbiddenMemberEmail?: string,
  ): Promise<void> {
    const original = await get();
    if (forbiddenMemberEmail !== undefined) {
      requireNoExecutorProjectBindings(original, forbiddenMemberEmail);
    }
    const record: PolicyMutationRecord = { get, label, leases, original, set };
    this.#policyCleanupComplete = false;
    this.#mutations.push(record);
    await addBindingsWithCas(record);
  }

  async #retryIamConsistency<T>(
    label: string,
    operation: () => Promise<T>,
    retryForbidden = false,
  ): Promise<T> {
    const consistencyDeadlineMs = Math.min(
      this.#apiDeadlineMs,
      Date.now() + IAM_CONSISTENCY_MAX_WAIT_MS,
    );
    let lastRetryableError: unknown;
    for (let attempt = 0; attempt < IAM_RETRY_MAX_ATTEMPTS; attempt += 1) {
      if (Date.now() >= consistencyDeadlineMs) break;
      try {
        return await operation();
      } catch (error) {
        const contextualPropagationDenial = retryForbidden && error instanceof Error &&
          /HTTP 403\b/.test(error.message);
        if (!contextualPropagationDenial && !retryableIamConsistencyError(error)) throw error;
        lastRetryableError = error;
      }
      const remainingMs = consistencyDeadlineMs - Date.now();
      if (remainingMs <= 0) break;
      await this.#sleep(Math.min(iamRetryDelayMs(attempt), remainingMs));
    }
    throw new AggregateError(
      lastRetryableError === undefined ? [] : [lastRetryableError],
      `${label} did not converge before the IAM consistency deadline.`,
    );
  }

  async #releaseAll(invocation: Invocation, cleanupDeadlineMs: number): Promise<unknown[]> {
    const errors: unknown[] = [];
    // Containment is independent of policy bookkeeping and always runs first.
    // In particular, a create response recorded in #account must be disabled by
    // its stable unique ID even when the first read-after-create never converged.
    if (this.#executorLifecycleArmed && !this.#executorDeleteAccepted) {
      await this.#containExecutor(invocation, cleanupDeadlineMs).catch((error) =>
        errors.push(error)
      );
    }
    if (!this.#policyCleanupComplete) {
      const policyErrors: unknown[] = [];
      let fenceSucceeded = false;
      await fencePolicyMutations(
        [...this.#mutations].reverse(),
        this.#sleep,
        cleanupDeadlineMs,
        () => this.#randomHex?.() ?? randomBytes(10).toString("hex"),
      ).then(() => {
        fenceSucceeded = true;
      }).catch((error) => policyErrors.push(error));
      if (fenceSucceeded && this.#account !== undefined) {
        for (const mutation of this.#mutations) {
          await mutation.get().then((policy) =>
            requireNoExecutorProjectBindings(policy, this.#account!.email)
          ).catch((error) => policyErrors.push(error));
        }
      }
      if (fenceSucceeded && policyErrors.length === 0) {
        this.#policyCleanupComplete = true;
        this.#mutations = [];
      }
      errors.push(...policyErrors);
    }
    if (errors.length === 0 && this.#session !== undefined) {
      await this.#proveExecutorPermissionsGone(invocation).catch((error) => errors.push(error));
    }
    if (errors.length === 0) {
      await this.#deleteLifecycleArtifacts(invocation, cleanupDeadlineMs).catch((error) =>
        errors.push(error)
      );
    }
    if (Date.now() >= cleanupDeadlineMs) {
      errors.push(new Error("Executor cleanup exceeded the reserved cleanup deadline."));
    }
    if (errors.length === 0) {
      this.#mutations = [];
      this.#roleIntents.clear();
      this.#roles = [];
      this.#session = undefined;
      this.#account = undefined;
      this.#accountId = undefined;
      this.#accountDescription = undefined;
      this.#accountIdentity = undefined;
      this.#acceptedRoleDeletions.clear();
      this.#executorDeleteAccepted = false;
      this.#policyCleanupComplete = false;
    }
    return errors;
  }

  async #containExecutor(invocation: Invocation, cleanupDeadlineMs: number): Promise<void> {
    const contract = REPOSITORIES[invocation.repository];
    if (this.#account === undefined) {
      if (this.#accountId === undefined || this.#accountDescription === undefined) {
        throw new Error("An ambiguous executor create lacks its exact recovery identity.");
      }
      if (this.#accountIdentity === undefined) {
        const consistencyDeadlineMs = Math.min(
          cleanupDeadlineMs,
          Date.now() + IAM_CONSISTENCY_MAX_WAIT_MS,
        );
        let lastRetryableError: unknown;
        for (let attempt = 0; attempt < IAM_RETRY_MAX_ATTEMPTS; attempt += 1) {
          if (Date.now() >= consistencyDeadlineMs) break;
          try {
            const observed = await getExecutorIdentity(
              contract.projectId,
              executorEmail(contract.projectId, this.#accountId),
              invocation.ownerAccessToken,
              this.#fetcher,
              false,
            );
            if (observed === undefined) {
              throw new Error("Ambiguous executor lookup unexpectedly returned no identity.");
            }
            exact(
              observed.email,
              executorEmail(contract.projectId, this.#accountId),
              "ambiguous executor email",
            );
            this.#accountIdentity = observed;
            break;
          } catch (error) {
            if (!retryableIamConsistencyError(error)) throw error;
            lastRetryableError = error;
          }
          const remainingMs = consistencyDeadlineMs - Date.now();
          if (remainingMs <= 0) break;
          await this.#sleep(Math.min(iamRetryDelayMs(attempt), remainingMs));
        }
        if (this.#accountIdentity === undefined) {
          throw new AggregateError(
            lastRetryableError === undefined ? [] : [lastRetryableError],
            "Ambiguous executor creation did not become observable before containment.",
          );
        }
      }
      let disabled: ServiceAccount;
      try {
        disabled = await setExecutorDisabled(
          this.#accountIdentity,
          true,
          invocation.ownerAccessToken,
          this.#fetcher,
          this.#sleep,
          cleanupDeadlineMs,
        );
      } catch (error) {
        throw new AggregateError(
          [error],
          "The ambiguous executor was targeted for containment but its full provenance could not be verified; manual cleanup is required.",
        );
      }
      try {
        exact(disabled.description, this.#accountDescription, "ambiguous executor provenance");
      } catch (error) {
        throw new AggregateError(
          [error],
          "The ambiguous executor identity has foreign provenance; manual cleanup is required.",
        );
      }
      this.#account = disabled;
      return;
    }
    this.#account = await setExecutorDisabled(
      this.#account,
      true,
      invocation.ownerAccessToken,
      this.#fetcher,
      this.#sleep,
      cleanupDeadlineMs,
    );
  }

  async #proveExecutorPermissionsGone(invocation: Invocation): Promise<void> {
    if (this.#session === undefined) return;
    const contract = REPOSITORIES[invocation.repository];
    await waitForStatePermissions(
      contract.state[invocation.terraformRoot],
      invocation,
      this.#session.accessToken,
      "none",
      this.#fetcher,
      this.#sleep,
    );
    await waitForControlPermissions(
      invocation,
      this.#session.accessToken,
      "none",
      this.#fetcher,
      this.#sleep,
    );
  }

  async #deleteLifecycleArtifacts(invocation: Invocation, cleanupDeadlineMs: number): Promise<void> {
    if (!this.#executorLifecycleArmed) return;
    const contract = REPOSITORIES[invocation.repository];
    let lastError: unknown;
    let attempt = 0;
    while (Date.now() < cleanupDeadlineMs) {
      try {
        for (const intent of this.#roleIntents.values()) {
          const observed = await getProjectCustomRole(
            intent.name,
            invocation.ownerAccessToken,
            this.#fetcher,
            true,
          );
          if (observed === undefined) {
            throw new Error("Ambiguous executor role creation is not yet observable.");
          }
          try {
            requireExactEphemeralRole(observed, intent);
          } catch (error) {
            throw new AggregateError(
              [error],
              "The ambiguous executor role has foreign provenance; manual cleanup is required.",
            );
          }
          this.#roleIntents.delete(intent.name);
          if (!this.#roles.some((role) => role.name === observed.name)) {
            this.#roles.push(observed);
          }
        }
        for (const role of this.#roles) {
          if (this.#acceptedRoleDeletions.has(role.name)) continue;
          const deletion = await deleteEphemeralRole(
            role,
            invocation.ownerAccessToken,
            this.#fetcher,
          );
          if (deletion === "deleted") {
            this.#acceptedRoleDeletions.add(role.name);
          } else {
            throw new Error("Ephemeral executor role deletion is not yet observable.");
          }
        }
        if (this.#accountId !== undefined) {
          if (this.#account === undefined || !this.#account.disabled) {
            throw new Error("Exact disabled executor identity was lost before deletion.");
          }
          const observed = await getExecutor(
            contract.projectId,
            this.#account.uniqueId,
            invocation.ownerAccessToken,
            this.#fetcher,
            true,
          );
          if (observed !== undefined) {
            if (this.#account !== undefined) {
              exact(observed.uniqueId, this.#account.uniqueId, "executor unique ID");
            }
            if (!observed.disabled) {
              this.#account = await setExecutorDisabled(
                observed,
                true,
                invocation.ownerAccessToken,
                this.#fetcher,
                this.#sleep,
                cleanupDeadlineMs,
              );
            }
            await this.#retryIamConsistency(
              "executor cleanup key inventory",
              () => requireNoUserManagedKeys(
                observed,
                invocation.ownerAccessToken,
                this.#fetcher,
              ),
            );
            const policy = await this.#retryIamConsistency(
              "executor cleanup policy read",
              () => getServiceAccountPolicy(
                observed,
                invocation.ownerAccessToken,
                this.#fetcher,
              ),
            );
            if (policy.bindings.length !== 0 || policy.auditConfigs !== undefined) {
              throw new Error("The executor retained an IAM policy before deletion.");
            }
            const projectPolicy = await getPolicy(
              contract.projectId,
              invocation.ownerAccessToken,
              this.#fetcher,
            );
            requireNoExecutorProjectBindings(projectPolicy, observed.email);
            const deletion = await deleteExecutorByUniqueId(
              observed,
              invocation.ownerAccessToken,
              this.#fetcher,
            );
            this.#executorDeleteAccepted ||= deletion === "deleted";
            throw new Error("Executor deletion is not yet observable.");
          } else if (!this.#executorDeleteAccepted) {
            // A GET or DELETE 404 can be a post-create visibility result. Keep
            // issuing the exact stable-ID DELETE until Google acknowledges it
            // with a successful write response.
            const deletion = await deleteExecutorByUniqueId(
              this.#account,
              invocation.ownerAccessToken,
              this.#fetcher,
            );
            this.#executorDeleteAccepted ||= deletion === "deleted";
            throw new Error("Executor deletion is not yet observable.");
          }
        }
        for (const role of this.#roles) {
          if (!this.#acceptedRoleDeletions.has(role.name)) {
            throw new Error("Ephemeral executor role deletion lacks a successful write acknowledgement.");
          }
          const observed = await getProjectCustomRole(
            role.name,
            invocation.ownerAccessToken,
            this.#fetcher,
            true,
          );
          if (observed !== undefined && !observed.deleted) {
            throw new Error("Ephemeral executor role deletion is not yet observable.");
          }
        }
        this.#executorLifecycleArmed = false;
        return;
      } catch (error) {
        if (!retryableCleanupError(error) &&
          !(error instanceof Error && /not yet observable/.test(error.message))) {
          throw error;
        }
        lastError = error;
      }
      const remainingMs = cleanupDeadlineMs - Date.now();
      if (remainingMs <= 0) break;
      await this.#sleep(Math.min(iamRetryDelayMs(attempt), remainingMs));
      attempt = Math.min(attempt + 1, IAM_RETRY_MAX_ATTEMPTS - 1);
    }
    throw new AggregateError(
      lastError === undefined ? [] : [lastError],
      "Random executor or custom-role deletion could not be proven before the cleanup deadline; manual reconciliation is required.",
    );
  }
}

async function addBindingsWithCas(record: PolicyMutationRecord): Promise<void> {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const current = attempt === 0 ? record.original : await record.get();
    const desired = addExactBindings(current, record.leases);
    const response = await record.set(desired);
    if (response === undefined) continue;
    requireContainsExactBindings(response, record.leases, record.label);
    return;
  }
  throw new Error(`Concurrent IAM updates prevented ${record.label} lease setup.`);
}

export async function fencePolicyMutations(
  records: readonly PolicyMutationRecord[],
  sleep: (milliseconds: number) => Promise<void>,
  cleanupDeadlineMs: number,
  randomHex: () => string = () => randomBytes(10).toString("hex"),
): Promise<void> {
  for (const record of records) {
    const suffix = randomHex();
    if (!/^[0-9a-f]{20}$/.test(suffix)) {
      throw new Error("IAM cleanup fence suffix escaped its random syntax.");
    }
    const basis = record.leases[0];
    if (basis === undefined) throw new Error("An IAM mutation record has no exact lease.");
    const fence: IamBinding = {
      condition: {
        description: CLEANUP_FENCE_DESCRIPTION,
        expression: `request.time < timestamp('${IAM_FENCE_EXPIRED_AT}')`,
        title: `codex-cleanup-fence-${createHash("sha256").update(record.label).digest("hex").slice(0, 12)}-${suffix}`,
      },
      members: [...basis.members],
      role: basis.role,
    };
    await fenceOnePolicyMutation(record, fence, sleep, cleanupDeadlineMs);
  }
}

async function fenceOnePolicyMutation(
  record: PolicyMutationRecord,
  fence: IamBinding,
  sleep: (milliseconds: number) => Promise<void>,
  cleanupDeadlineMs: number,
): Promise<void> {
  let fencePredecessorEtag: string | undefined;
  let observedFenceEtag: string | undefined;
  let lastRetryableError: unknown;
  while (Date.now() < cleanupDeadlineMs) {
    try {
      const current = await record.get();
      const leasesRemain = current.bindings.some((binding) =>
        record.leases.some((lease) => bindingEqualsLease(binding, lease))
      );
      const fenceRemains = current.bindings.some((binding) => bindingEqualsLease(binding, fence));
      if (leasesRemain) {
        const response = await record.set(removeExactBindings(current, record.leases, record.original));
        if (response !== undefined && response.etag === current.etag) {
          throw new Error(`${record.label} cleanup CAS did not advance its etag.`);
        }
      } else if (fenceRemains) {
        if (fencePredecessorEtag !== undefined && current.etag === fencePredecessorEtag) {
          throw new Error(`${record.label} cleanup fence did not advance its predecessor etag.`);
        }
        observedFenceEtag = current.etag;
        let desired = removeExactLease(current, fence);
        desired = removeExactBindings(desired, record.leases, record.original);
        const response = await record.set(desired);
        if (response !== undefined && response.etag === current.etag) {
          throw new Error(`${record.label} cleanup fence removal did not advance its etag.`);
        }
      } else if (observedFenceEtag !== undefined) {
        if (current.etag === observedFenceEtag) {
          throw new Error(`${record.label} cleanup fence disappeared without an advancing etag.`);
        }
        if (current.bindings.some((binding) => bindingEqualsLease(binding, fence))) {
          throw new Error(`${record.label} cleanup fence unexpectedly survived removal.`);
        }
        return;
      } else {
        fencePredecessorEtag = current.etag;
        const response = await record.set(addExactLease(current, fence));
        if (response !== undefined) {
          requireContainsExactBindings(response, [fence], `${record.label} cleanup fence`);
          if (response.etag === current.etag) {
            throw new Error(`${record.label} cleanup fence CAS did not advance its etag.`);
          }
        }
      }
      lastRetryableError = undefined;
    } catch (error) {
      if (!retryableCleanupError(error)) throw error;
      lastRetryableError = error;
    }
    await sleep(Math.min(CLEANUP_RETRY_INTERVAL_MS, cleanupDeadlineMs - Date.now()));
  }
  throw new AggregateError(
    lastRetryableError === undefined ? [] : [lastRetryableError],
    `${record.label} cleanup did not complete its etag-advancing fence.`,
  );
}

function retryableCleanupError(error: unknown): boolean {
  if (error instanceof DOMException && error.name === "AbortError") return true;
  if (error instanceof TypeError && /fetch|network|socket/i.test(error.message)) return true;
  if (!(error instanceof Error)) return false;
  return /aborted|fetch failed|network|socket|timed out|HTTP (?:408|429|5\d\d)/i.test(
    error.message,
  );
}

class UnresolvedDeterministicIdentityError extends Error {}

function recursivelyRetryableCleanupError(error: unknown): boolean {
  if (error instanceof UnresolvedDeterministicIdentityError) return true;
  if (error instanceof AggregateError) {
    const errors = [...error.errors];
    return errors.length > 0 && errors.every(recursivelyRetryableCleanupError);
  }
  return retryableCleanupError(error);
}

function retryableIamConsistencyError(error: unknown): boolean {
  if (error instanceof DOMException && error.name === "AbortError") return true;
  if (error instanceof TypeError && /fetch|network|socket/i.test(error.message)) return true;
  if (!(error instanceof Error)) return false;
  // IAM documents these statuses for truncated exponential backoff. A 404 is
  // retryable only in this narrowly post-create/post-lifecycle context.
  return /fetch failed|network|socket|timed out|HTTP (?:404|408|429|500|502|503|504)\b|HTTP 409 ABORTED\b/i.test(
    error.message,
  );
}

function iamRetryDelayMs(attempt: number): number {
  if (!Number.isInteger(attempt) || attempt < 0) {
    throw new Error("IAM retry attempt escaped its non-negative integer bound.");
  }
  const exponential = Math.min(IAM_RETRY_INITIAL_MS * 2 ** attempt, IAM_RETRY_MAX_MS);
  const jitter = randomBytes(4).readUInt32BE(0) % IAM_RETRY_INITIAL_MS;
  return Math.min(exponential + jitter, IAM_RETRY_MAX_MS);
}

export function addExactBindings(
  policy: IamPolicy,
  leases: readonly IamBinding[],
): IamPolicy {
  let result = policy;
  for (const lease of leases) result = addExactLease(result, lease);
  return result;
}

export function removeExactBindings(
  policy: IamPolicy,
  leases: readonly IamBinding[],
  original: IamPolicy,
): IamPolicy {
  let result = policy;
  for (const lease of leases) result = removeExactLease(result, lease);
  if (!Number.isInteger(original.version) || original.version < 1 || original.version > 3) {
    throw new Error("Original IAM policy version escaped its reviewed range.");
  }
  // Once a conditional fence has advanced the CAS generation, keep all
  // cleanup writes at policy version 3. Downgrading the removal request can
  // silently discard conditions that were concurrently introduced.
  return { ...result, version: 3 };
}

function requireContainsExactBindings(
  policy: IamPolicy,
  leases: readonly IamBinding[],
  label: string,
): void {
  for (const lease of leases) {
    if (!policy.bindings.some((binding) => bindingEqualsLease(binding, lease))) {
      throw new Error(`Google did not return the exact ${label} lease.`);
    }
  }
}

function requireNoExecutorProjectBindings(policy: IamPolicy, email: string): void {
  const member = `serviceAccount:${email}`;
  if (policy.bindings.some((binding) => binding.members.includes(member))) {
    throw new Error("The dedicated executor has a standing project IAM binding.");
  }
}

function knownExecutorBindingsRemain(
  policy: IamPolicy,
  email: string,
  knownLeases: readonly IamBinding[],
): boolean {
  const member = `serviceAccount:${email}`;
  let remains = false;
  for (const binding of policy.bindings) {
    if (!binding.members.includes(member)) continue;
    if (!knownLeases.some((lease) => bindingEqualsLease(binding, lease))) {
      throw new Error("The dedicated executor retained unknown standing project authority.");
    }
    remains = true;
  }
  return remains;
}

function policyPayloadEquals(left: IamPolicy, right: IamPolicy): boolean {
  return canonicalJson({
    ...(left.auditConfigs === undefined ? {} : { auditConfigs: [...left.auditConfigs] }),
    bindings: left.bindings.map((binding) => json(binding, "IAM binding")),
    version: left.version,
  }) === canonicalJson({
    ...(right.auditConfigs === undefined ? {} : { auditConfigs: [...right.auditConfigs] }),
    bindings: right.bindings.map((binding) => json(binding, "IAM binding")),
    version: right.version,
  });
}

export async function addLeaseWithCas(
  projectId: string,
  token: string,
  lease: StorageLease,
  fetcher: Fetcher,
): Promise<void> {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const current = await getPolicy(projectId, token, fetcher);
    const desired = addExactLease(current, lease);
    if (desired === current) return;
    const response = await setPolicy(projectId, token, desired, fetcher);
    if (response === undefined) continue;
    if (!response.bindings.some((binding) => bindingEqualsLease(binding, lease))) {
      throw new Error("Google did not return the exact temporary storage lease.");
    }
    return;
  }
  throw new Error("Concurrent IAM updates prevented the temporary lease CAS.");
}

export async function removeLeaseWithCas(
  projectId: string,
  token: string,
  lease: StorageLease,
  fetcher: Fetcher,
): Promise<void> {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const current = await getPolicy(projectId, token, fetcher);
    const desired = removeExactLease(current, lease);
    if (desired.bindings.length === current.bindings.length) return;
    const response = await setPolicy(projectId, token, desired, fetcher);
    if (response === undefined) continue;
    if (response.bindings.some((binding) => bindingEqualsLease(binding, lease))) {
      continue;
    }
    return;
  }
  throw new Error("Concurrent IAM updates prevented exact temporary lease cleanup.");
}

async function getPolicy(projectId: string, token: string, fetcher: Fetcher): Promise<IamPolicy> {
  const value = await googleJson(
    `https://cloudresourcemanager.googleapis.com/v1/projects/${projectId}:getIamPolicy`,
    token,
    { options: { requestedPolicyVersion: 3 } },
    fetcher,
  );
  return iamPolicy(value);
}

async function setPolicy(
  projectId: string,
  token: string,
  policy: IamPolicy,
  fetcher: Fetcher,
): Promise<IamPolicy | undefined> {
  const response = await fetcher(
    `https://cloudresourcemanager.googleapis.com/v1/projects/${projectId}:setIamPolicy`,
    {
      body: JSON.stringify({ policy: { ...policy, version: 3 } }),
      headers: googleHeaders(token),
      method: "POST",
      redirect: "error",
    },
  );
  if (response.status === 409 || response.status === 412) return undefined;
  if (!response.ok) throw new Error(`Google IAM setPolicy failed with HTTP ${response.status}.`);
  return iamPolicy(await boundedJson(response, 2 * 1024 * 1024));
}

export async function inventoryBridgeArtifacts(
  projectId: string,
  ownerToken: string,
  fetcher: Fetcher,
  sleep: (milliseconds: number) => Promise<void>,
  cleanupDeadlineMs: number,
  recovery: RecoveryInvocation | undefined = undefined,
): Promise<{
  readonly accountIds: ReadonlySet<string>;
  readonly hadActiveArtifacts: boolean;
  readonly roleIds: ReadonlySet<string>;
}> {
  const accountIds = new Set<string>();
  const containmentErrors: unknown[] = [];
  const disabledAccounts: ServiceAccount[] = [];
  let directDisableObservedAuthority = false;
  const deterministicEmail = recovery === undefined
    ? undefined
    : deterministicExecutorEmail(recovery);
  const directObservation = recovery === undefined
    ? Promise.resolve({
        accountId: undefined,
        disableResult: "absent" as const,
        identity: undefined,
      })
    : (async () => {
        exact(REPOSITORIES[recovery.repository].projectId, projectId, "recovery executor project");
        const accountId = randomExecutorAccountId(
          deterministicArtifactHex(recovery.repository, recovery.githubRunId, "service-account"),
        );
        const email = executorEmail(projectId, accountId);
        const disableResult = await disableDeterministicExecutorByEmail(
          projectId,
          email,
          ownerToken,
          fetcher,
        );
        return {
          accountId,
          disableResult,
          identity: await getExecutorIdentity(projectId, email, ownerToken, fetcher, true),
        };
      })();
  // The direct disable fetch above is invoked synchronously before this
  // detached-policy recovery starts. Keep the policy scrub independent from
  // global list, key, role, and legacy-orphan convergence so none of those can
  // consume its deadline. Settle the promise immediately to avoid an
  // unhandled rejection while the independent lifecycle work proceeds.
  const initialDetachedRecovery = recovery === undefined
    ? Promise.resolve({ observed: false, status: "fulfilled" as const })
    : recoverDetachedDeterministicPolicies(
        recovery,
        fetcher,
        sleep,
        cleanupDeadlineMs,
      ).then(
        (observed) => ({ observed, status: "fulfilled" as const }),
        (reason: unknown) => ({ reason, status: "rejected" as const }),
      );
  const listedObservation = (async () => {
    const entries = await listServiceAccountEntries(projectId, ownerToken, fetcher);
    const identities: ServiceAccountIdentity[] = [];
    const listedAccountIds: string[] = [];
    const errors: unknown[] = [];
    const seenEmails = new Set<string>();
    for (const entry of entries) {
      const accountId = reservedExecutorAccountIdOrUndefined(entry.email);
      if (accountId === undefined) continue;
      listedAccountIds.push(accountId);
      try {
        const account = parseReservedServiceAccountIdentity(entry.value, projectId);
        if (!seenEmails.has(account.email)) {
          identities.push(account);
          seenEmails.add(account.email);
        }
      } catch (error) {
        errors.push(error);
      }
    }
    return { errors, identities, listedAccountIds };
  })();
  const directContainment = directObservation.then(async (observed) => ({
    ...observed,
    account: observed.identity === undefined
      ? undefined
      : await disableOrphanExecutor(
          observed.identity,
          ownerToken,
          fetcher,
          sleep,
          cleanupDeadlineMs,
        ),
  }));
  // Launch every listed identity's disable as soon as the list resolves. In
  // particular, do not wait for the deterministic account's numeric-ID
  // convergence: a stale replica must not consume the recovery window while a
  // listed legacy peer remains enabled.
  const listedContainment = listedObservation.then(async (observed) => {
    const errors = [...observed.errors];
    const results = await Promise.allSettled(observed.identities.map((account) =>
      disableOrphanExecutor(
        account,
        ownerToken,
        fetcher,
        sleep,
        cleanupDeadlineMs,
      )
    ));
    const disabled: ServiceAccount[] = [];
    for (const result of results) {
      if (result.status === "fulfilled") disabled.push(result.value);
      else errors.push(result.reason);
    }
    return { ...observed, disabled, errors };
  });
  // Attach rejection handlers before awaiting either observation. A fast 4xx
  // in one containment branch must not become a fatal unhandled rejection
  // while the other branch is still waiting on a control-plane read.
  const containmentResults = Promise.allSettled([
    directContainment,
    listedContainment,
  ]);
  // Identity discovery completes before lifecycle convergence. This lets an
  // exact uniqueId-derived prior fence be authenticated and removed while the
  // idempotent disable/readback continues independently.
  const [directObservationResult, listObservationResult] = await Promise.allSettled([
    directObservation,
    listedObservation,
  ]);
  if (directObservationResult.status === "fulfilled") {
    directDisableObservedAuthority = directObservationResult.value.disableResult !== "absent";
    if (directObservationResult.value.identity !== undefined &&
      directObservationResult.value.accountId !== undefined) {
      accountIds.add(directObservationResult.value.accountId);
    }
  }
  if (listObservationResult.status === "fulfilled") {
    for (const accountId of listObservationResult.value.listedAccountIds) accountIds.add(accountId);
  }
  const listedDeterministicIdentity = listObservationResult.status === "fulfilled"
    ? listObservationResult.value.identities.find((account) => account.email === deterministicEmail)
    : undefined;
  const observedDeterministicUniqueId = directObservationResult.status === "fulfilled"
    ? directObservationResult.value.identity?.uniqueId ?? listedDeterministicIdentity?.uniqueId
    : listedDeterministicIdentity?.uniqueId;
  const detachedRecovery = initialDetachedRecovery.then(async (initial) => {
    if (initial.status === "fulfilled" || recovery === undefined ||
      observedDeterministicUniqueId === undefined) {
      return initial;
    }
    // A prior orphan-recovery fence incorporates Google's immutable numeric
    // identity. The early scrub cannot authenticate that title until the
    // direct containment read observes the account, so retry once with that
    // exact uniqueId. Every other unknown binding remains a hard failure.
    return recoverDetachedDeterministicPolicies(
      recovery,
      fetcher,
      sleep,
      cleanupDeadlineMs,
      observedDeterministicUniqueId,
    ).then(
      (observed) => ({ observed, status: "fulfilled" as const }),
      (reason: unknown) => ({ reason, status: "rejected" as const }),
    );
  });
  const [directResult, listResult] = await containmentResults;
  if (directResult.status === "fulfilled") {
    if (directResult.value.account !== undefined) disabledAccounts.push(directResult.value.account);
  } else {
    containmentErrors.push(directResult.reason);
  }
  if (listResult.status === "fulfilled") {
    containmentErrors.push(...listResult.value.errors);
    for (const account of listResult.value.disabled) {
      if (!disabledAccounts.some((candidate) => candidate.email === account.email)) {
        disabledAccounts.push(account);
      }
    }
  } else {
    containmentErrors.push(listResult.reason);
  }
  const keyResults = await Promise.allSettled(
    disabledAccounts.map((disabled) => requireNoUserManagedKeys(disabled, ownerToken, fetcher)),
  );
  const policyRecoverableAccounts: ServiceAccount[] = [];
  for (const [index, result] of keyResults.entries()) {
    if (result.status === "rejected") {
      containmentErrors.push(result.reason);
    } else {
      policyRecoverableAccounts.push(disabledAccounts[index]!);
    }
  }
  const listedRoles = await listProjectCustomRoles(projectId, ownerToken, fetcher, true).catch(
    (error) => {
      containmentErrors.push(error);
      return [];
    },
  );
  const roles: ProjectCustomRole[] = [];
  for (const role of listedRoles) {
    const id = role.name.slice(role.name.lastIndexOf("/") + 1);
    if (!id.startsWith(EXECUTOR_ROLE_PREFIX)) continue;
    if (roleIdOrUndefined(role.name) === undefined) {
      containmentErrors.push(new Error(
        "An orphan bridge role has a malformed reserved ID; manual cleanup is required.",
      ));
      continue;
    }
    roles.push(role);
  }
  const roleNames = new Set(roles.map((role) => role.name));
  for (const phase of ["read", "mutation"] as const) {
    if (recovery === undefined) break;
    const id = randomExecutorRoleId(
      phase,
      deterministicArtifactHex(
        recovery.repository,
        recovery.githubRunId,
        phase === "read" ? "role-read" : "role-mutation",
      ),
    );
    const name = `projects/${projectId}/roles/${id}`;
    if (roleNames.has(name)) continue;
    const observed = await getProjectCustomRole(name, ownerToken, fetcher, true).catch((error) => {
      containmentErrors.push(error);
      return undefined;
    });
    if (observed === undefined) continue;
    roles.push(observed);
    roleNames.add(observed.name);
  }
  const verifiedRoles: ProjectCustomRole[] = [];
  for (const role of roles) {
    try {
      verifyBridgeRole(role, projectId);
      verifiedRoles.push(role);
    } catch (error) {
      containmentErrors.push(error);
    }
  }
  const roleIds = new Set(verifiedRoles.map((role) => roleId(role.name)));
  const hadActiveArtifacts = directDisableObservedAuthority || accountIds.size > 0 ||
    verifiedRoles.some((role) => !role.deleted);
  const legacyAccountRecovery = Promise.allSettled(
    policyRecoverableAccounts
      .filter((disabled) => disabled.email !== deterministicEmail)
      .map((disabled) =>
        recoverOrphanExecutor(
          disabled,
          verifiedRoles,
          ownerToken,
          fetcher,
          sleep,
          cleanupDeadlineMs,
        )
      ),
  );
  // Detached recovery owns every policy surface for the deterministic
  // identity. Only after it settles cleanly may that same account run the
  // normal lifecycle proof/deletion, avoiding concurrent CAS racers on its
  // service-account policy while still allowing legacy orphan cleanup to run.
  const deterministicAccountRecovery = detachedRecovery.then((detached) => {
    if (detached.status === "rejected") return [];
    return Promise.allSettled(
      policyRecoverableAccounts.filter((disabled) => disabled.email === deterministicEmail).map(
        (disabled) =>
          recoverOrphanExecutor(
            disabled,
            verifiedRoles,
            ownerToken,
            fetcher,
            sleep,
            cleanupDeadlineMs,
          ),
      ),
    );
  });
  const [accountRecoveryResults, deterministicRecoveryResults, detachedResult] =
    await Promise.all([legacyAccountRecovery, deterministicAccountRecovery, detachedRecovery]);
  for (const result of accountRecoveryResults) {
    if (result.status === "rejected") containmentErrors.push(result.reason);
  }
  for (const result of deterministicRecoveryResults) {
    if (result.status === "rejected") containmentErrors.push(result.reason);
  }
  let detachedAuthorityObserved = false;
  if (detachedResult.status === "fulfilled") {
    detachedAuthorityObserved = detachedResult.observed;
  } else {
    containmentErrors.push(detachedResult.reason);
  }
  const roleDeletionResults = await Promise.allSettled(
    verifiedRoles.map((role) =>
      deleteOrphanRole(role, ownerToken, fetcher, sleep, cleanupDeadlineMs)
    ),
  );
  for (const result of roleDeletionResults) {
    if (result.status === "rejected") containmentErrors.push(result.reason);
  }
  if (containmentErrors.length > 0) {
    if (containmentErrors.length === 1) throw containmentErrors[0];
    throw new AggregateError(
      containmentErrors,
      "Every safely identified reserved executor was processed, but orphan containment was incomplete; manual cleanup is required.",
    );
  }
  return {
    accountIds,
    hadActiveArtifacts: hadActiveArtifacts || detachedAuthorityObserved,
    roleIds,
  };
}

async function bridgeArtifactsRemain(
  projectId: string,
  ownerToken: string,
  fetcher: Fetcher,
  recovery: RecoveryInvocation,
): Promise<boolean> {
  const observedAccounts = new Set<string>();
  let active = false;
  for (const entry of await listServiceAccountEntries(projectId, ownerToken, fetcher)) {
    if (reservedExecutorAccountIdOrUndefined(entry.email) === undefined) continue;
    const account = parseReservedServiceAccountIdentity(entry.value, projectId);
    observedAccounts.add(account.email);
    active = true;
  }
  {
    exact(REPOSITORIES[recovery.repository].projectId, projectId, "recovery executor project");
    const accountId = randomExecutorAccountId(
      deterministicArtifactHex(recovery.repository, recovery.githubRunId, "service-account"),
    );
    const email = executorEmail(projectId, accountId);
    if (!observedAccounts.has(email)) {
      const observed = await getExecutorIdentity(projectId, email, ownerToken, fetcher, true);
      if (observed !== undefined) active = true;
    }
  }

  const roles = await listProjectCustomRoles(projectId, ownerToken, fetcher, true);
  const observedRoles = new Set<string>();
  for (const role of roles) {
    verifyBridgeRole(role, projectId);
    observedRoles.add(role.name);
    if (!role.deleted) active = true;
  }
  for (const phase of ["read", "mutation"] as const) {
    const id = randomExecutorRoleId(
      phase,
      deterministicArtifactHex(
        recovery.repository,
        recovery.githubRunId,
        phase === "read" ? "role-read" : "role-mutation",
      ),
    );
    const name = `projects/${projectId}/roles/${id}`;
    if (observedRoles.has(name)) continue;
    const observed = await getProjectCustomRole(name, ownerToken, fetcher, true);
    if (observed === undefined) continue;
    verifyBridgeRole(observed, projectId);
    if (!observed.deleted) active = true;
  }
  return active || await detachedDeterministicPoliciesRemain(recovery, fetcher);
}

export async function recoverBridgeArtifactsUntilStable(
  invocation: RecoveryInvocation,
  fetcher: Fetcher,
  sleep: (milliseconds: number) => Promise<void>,
  cleanupDeadlineMs: number,
  now: () => number = () => Date.now(),
): Promise<void> {
  const projectId = REPOSITORIES[invocation.repository].projectId;
  let emptySinceMs: number | undefined;
  while (now() < cleanupDeadlineMs) {
    try {
      const inventory = await inventoryBridgeArtifacts(
        projectId,
        invocation.ownerAccessToken,
        fetcher,
        sleep,
        cleanupDeadlineMs,
        invocation,
      );
      const active = await bridgeArtifactsRemain(
        projectId,
        invocation.ownerAccessToken,
        fetcher,
        invocation,
      );
      if (active) {
        emptySinceMs = undefined;
      } else if (inventory.hadActiveArtifacts || emptySinceMs === undefined) {
        // This scan's final proof is clean, so it may begin (or reset) the
        // five-minute absence window even when the same scan contained an
        // artifact. It can never reuse absence time from before that artifact.
        emptySinceMs = now();
      } else if (now() - emptySinceMs >= RECOVERY_STABLE_EMPTY_MS) {
        return;
      }
    } catch (error) {
      if (!recursivelyRetryableCleanupError(error)) throw error;
      // A failed read is not negative proof. Retry the entire inventory while
      // preserving hard failure for identity drift and malformed authority.
      emptySinceMs = undefined;
      const remainingMs = cleanupDeadlineMs - now();
      if (remainingMs <= 0) break;
      await sleep(Math.min(CLEANUP_RETRY_INTERVAL_MS, remainingMs));
      continue;
    }
    const remainingMs = cleanupDeadlineMs - now();
    if (remainingMs <= 0) break;
    await sleep(Math.min(RECOVERY_STABLE_EMPTY_INTERVAL_MS, remainingMs));
  }
  throw new Error(
    "Protected crash recovery did not observe the required stable-empty artifact inventory before its deadline.",
  );
}

interface OrphanPolicySurface {
  readonly basis: IamBinding;
  readonly exclusive: boolean;
  readonly expected: readonly IamBinding[];
  readonly get: () => Promise<IamPolicy>;
  readonly label: string;
  readonly set: (policy: IamPolicy) => Promise<IamPolicy | undefined>;
  readonly strandedFences: readonly StrandedFenceContract[];
}

interface StrandedFenceContract {
  readonly basis: IamBinding;
  readonly description: string;
  readonly titlePrefix: string;
}

function strandedFenceContract(
  kind: "cleanup" | "orphan",
  label: string,
  basis: IamBinding,
): StrandedFenceContract {
  return {
    basis,
    description: kind === "cleanup" ? CLEANUP_FENCE_DESCRIPTION : ORPHAN_FENCE_DESCRIPTION,
    titlePrefix: `codex-${kind}-fence-${createHash("sha256").update(label).digest("hex").slice(0, 12)}-`,
  };
}

async function disableDeterministicExecutorByEmail(
  projectId: string,
  email: string,
  ownerToken: string,
  fetcher: Fetcher,
): Promise<"absent" | "disabled" | "transient"> {
  let response: Response;
  try {
    response = await fetcher(`${serviceAccountIdentifierUrl(projectId, email)}:disable`, {
      headers: googleHeaders(ownerToken),
      method: "POST",
      redirect: "error",
    });
  } catch (error) {
    // A lost disable response is ambiguous: the write may have committed.
    // Continue with exact GET/list proof and make the next recovery scan issue
    // the idempotent disable again. Authentication and validation failures are
    // never classified as transport loss here.
    if (retryableCleanupError(error)) return "transient";
    throw error;
  }
  if (response.ok) {
    await boundedText(response, 64 * 1024);
    return "disabled";
  }
  if (response.status === 404) return "absent";
  if ([408, 409, 429, 500, 502, 503, 504].includes(response.status)) return "transient";
  throw new Error(`Deterministic executor disable failed with HTTP ${response.status}.`);
}

async function disableOrphanExecutor(
  account: ServiceAccountIdentity,
  ownerToken: string,
  fetcher: Fetcher,
  sleep: (milliseconds: number) => Promise<void>,
  cleanupDeadlineMs: number,
): Promise<ServiceAccount> {
  try {
    return await setExecutorDisabled(
      account,
      true,
      ownerToken,
      fetcher,
      sleep,
      cleanupDeadlineMs,
    );
  } catch (error) {
    throw new AggregateError(
      [error],
      "Disabled reserved executor failed exact identity and provenance validation; manual cleanup is required.",
    );
  }
}

async function recoverOrphanExecutor(
  account: ServiceAccount,
  roles: readonly ProjectCustomRole[],
  ownerToken: string,
  fetcher: Fetcher,
  sleep: (milliseconds: number) => Promise<void>,
  cleanupDeadlineMs: number,
): Promise<void> {
  if (!account.disabled) throw new Error("Orphan recovery may run only after executor disable.");
  const provenance = parseExecutorProvenance(account.description, account.projectId);
  const surfaces = orphanPolicySurfaces(account, provenance, roles, ownerToken, fetcher);
  for (const surface of surfaces) {
    await recoverOrphanPolicy(surface, account.email, sleep, cleanupDeadlineMs);
  }
  await requireNoUserManagedKeys(account, ownerToken, fetcher);
  for (const surface of surfaces) {
    const policy = await surface.get();
    requireOrphanPolicyClean(policy, surface, account.email);
  }
  await deleteOrphanExecutor(account, ownerToken, fetcher, sleep, cleanupDeadlineMs);
}

function orphanPolicySurfaces(
  account: ServiceAccount,
  provenance: ExecutorProvenance,
  roles: readonly ProjectCustomRole[],
  ownerToken: string,
  fetcher: Fetcher,
): readonly OrphanPolicySurface[] {
  const contract = REPOSITORIES[provenance.repository];
  exact(contract.projectId, account.projectId, "orphan executor project");
  const expectedDeterministicAccountId = randomExecutorAccountId(
    deterministicArtifactHex(provenance.repository, provenance.runId, "service-account"),
  );
  const observedAccountId = account.email.slice(0, account.email.indexOf("@"));
  const policyRoles = [...roles];
  if (observedAccountId === expectedDeterministicAccountId) {
    const phases: readonly ("mutation" | "read")[] = provenance.mode === "apply"
      ? ["read", "mutation"]
      : ["read"];
    for (const phase of phases) {
      const expected = deterministicRecoveryRole(provenance, phase);
      if (!policyRoles.some((role) => role.name === expected.name)) policyRoles.push(expected);
    }
  }
  const roleLeaseGroups = policyRoles.flatMap((role) => {
    const roleContract = bridgeRoleContract(role, account.projectId);
    if (
      roleContract.root !== provenance.root ||
      (roleContract.phase === "mutation" && provenance.mode !== "apply")
    ) {
      return [];
    }
    return [{
      leases: buildExecutorProjectLeases(
        provenance.repository,
        provenance.runId,
        provenance.expiresAt,
        account.email,
        role.name,
        roleContract.phase,
      ),
      phase: roleContract.phase,
    }];
  });
  const projectExpected = [
    ...roleLeaseGroups.flatMap(({ leases }) => leases),
    buildStorageLease(
      provenance.repository,
      provenance.root,
      provenance.runId,
      provenance.expiresAt,
      account.email,
      "plan",
      "",
    ),
    ...buildReceiptLeases(
      provenance.repository,
      provenance.root,
      provenance.runId,
      provenance.expiresAt,
      provenance.mode,
      provenance.approvedPlanRunId,
      account.email,
    ),
    buildMarkerReadLease(
      provenance.repository,
      provenance.runId,
      provenance.expiresAt,
      contract.projectId,
      account.email,
    ),
    ...(provenance.mode === "apply"
      ? [
          buildStorageLease(
            provenance.repository,
            provenance.root,
            provenance.runId,
            provenance.expiresAt,
            account.email,
            "apply",
            provenance.approvedPlanRunId,
          ),
          ...(provenance.root === "bootstrap"
            ? [
                buildMarkerMutationLease(
                  provenance.repository,
                  provenance.runId,
                  provenance.expiresAt,
                  account.email,
                ),
              ]
            : []),
        ]
      : []),
  ];
  const projectSurface = (
    repository: RepositoryName,
    expected: readonly IamBinding[],
  ): OrphanPolicySurface => {
    const project = REPOSITORIES[repository].projectId;
    const basis = buildMarkerReadLease(
      repository,
      provenance.runId,
      provenance.expiresAt,
      contract.projectId,
      account.email,
    );
    const label = `orphan ${account.uniqueId} project ${project}`;
    const cleanupFences = repository === provenance.repository
      ? roleLeaseGroups.flatMap(({ leases, phase }) => {
          const first = leases[0];
          return first === undefined
            ? []
            : [strandedFenceContract(
                "cleanup",
                `${phase === "mutation" ? "mutation " : ""}project ${project}`,
                first,
              )];
        })
      : [strandedFenceContract("cleanup", `marker project ${project}`, basis)];
    return {
      basis,
      exclusive: false,
      expected,
      get: () => getPolicy(project, ownerToken, fetcher),
      label,
      set: (policy) => setPolicy(project, ownerToken, policy, fetcher),
      strandedFences: [strandedFenceContract("orphan", label, basis), ...cleanupFences],
    };
  };
  const surfaces: OrphanPolicySurface[] = REPOSITORY_NAMES.map((repository) =>
    projectSurface(
      repository,
      repository === provenance.repository
        ? projectExpected
        : [
            buildMarkerReadLease(
              repository,
              provenance.runId,
              provenance.expiresAt,
              contract.projectId,
              account.email,
            ),
          ],
    )
  );
  const runtimeLeases = provenance.root === "prod" && provenance.mode === "apply"
    ? buildRuntimeActAsLeases(
        provenance.repository,
        provenance.runId,
        provenance.expiresAt,
        account.email,
      )
    : {};
  for (const [index, email] of runtimeServiceAccountEmails(provenance.repository).entries()) {
    const expected = runtimeLeases[email] === undefined ? [] : [runtimeLeases[email]!];
    const basis = expected[0] ?? {
      condition: expiringCondition(
        `codex-executor-actas-${provenance.runId}-${index}`,
        `Temporary exact-runtime actAs lease for ${provenance.repository}.`,
        provenance.expiresAt,
      ),
      members: [`serviceAccount:${account.email}`],
      role: "roles/iam.serviceAccountUser",
    };
    const label = `orphan ${account.uniqueId} runtime ${email}`;
    surfaces.push({
      basis,
      exclusive: false,
      expected,
      get: () => getServiceAccountPolicy(email, ownerToken, fetcher),
      label,
      set: (policy) => setServiceAccountPolicy(email, ownerToken, policy, fetcher),
      strandedFences: [
        strandedFenceContract("orphan", label, basis),
        ...(expected.length === 0
          ? []
          : [strandedFenceContract("cleanup", `runtime service account ${email}`, basis)]),
      ],
    });
  }
  const ownerLease = buildTokenCreatorLease(
    provenance.repository,
    provenance.runId,
    provenance.expiresAt,
  );
  const executorPolicyLabel = `orphan ${account.uniqueId} executor policy`;
  surfaces.push({
    basis: ownerLease,
    exclusive: true,
    expected: [ownerLease],
      get: () => getServiceAccountPolicy(account, ownerToken, fetcher),
    label: executorPolicyLabel,
      set: (policy) => setServiceAccountPolicy(account, ownerToken, policy, fetcher),
    strandedFences: [
      strandedFenceContract("orphan", executorPolicyLabel, ownerLease),
      strandedFenceContract(
        "cleanup",
        `executor service account ${account.email}`,
        ownerLease,
      ),
    ],
  });
  return surfaces;
}

function deterministicRecoveryRole(
  provenance: ExecutorProvenance,
  phase: "mutation" | "read",
): ProjectCustomRole {
  const projectId = REPOSITORIES[provenance.repository].projectId;
  const id = randomExecutorRoleId(
    phase,
    deterministicArtifactHex(
      provenance.repository,
      provenance.runId,
      phase === "read" ? "role-read" : "role-mutation",
    ),
  );
  return {
    deleted: true,
    description: `Protected Terraform ${provenance.root} ${phase} single-run control role.`,
    etag: "recovery-only-missing-role",
    includedPermissions: executorControlPermissions(
      provenance.repository,
      provenance.root,
      phase,
    ),
    name: `projects/${projectId}/roles/${id}`,
    stage: "GA",
    title: `Protected Terraform ${phase === "read" ? "Read" : "Mutation"}`,
  };
}

interface DetachedPolicyDescriptor {
  readonly exclusive: boolean;
  readonly get: () => Promise<IamPolicy | undefined>;
  readonly kind: "executor" | "project" | "runtime";
  readonly label: string;
  readonly projectRepository?: RepositoryName;
  readonly runtimeEmail?: string;
  readonly set: (policy: IamPolicy) => Promise<IamPolicy | undefined>;
}

async function recoverDetachedDeterministicPolicies(
  invocation: RecoveryInvocation,
  fetcher: Fetcher,
  sleep: (milliseconds: number) => Promise<void>,
  cleanupDeadlineMs: number,
  executorUniqueId: string | undefined = undefined,
): Promise<boolean> {
  const loaded = await detachedDeterministicPolicySurfaces(
    invocation,
    fetcher,
    executorUniqueId,
  );
  let observed = false;
  const recoveryResults = await Promise.allSettled(loaded.surfaces.map(
    async ({ current, descriptor, expected, surface }) => {
      const relevant = detachedSurfaceHasRelevantBinding(current, descriptor, surface);
      if (expected.length === 0 && !relevant) return;
      observed = true;
      if (descriptor.kind === "executor") {
        await recoverOrphanPolicy(
          surface,
          deterministicExecutorEmail(invocation),
          sleep,
          cleanupDeadlineMs,
        );
      } else {
        await recoverDetachedExecutorMembers(
          invocation,
          descriptor,
          surface.basis,
          sleep,
          cleanupDeadlineMs,
        );
      }
    }
  ));
  const errors = [...loaded.errors];
  for (const result of recoveryResults) {
    if (result.status === "rejected") errors.push(result.reason);
  }
  if (errors.length > 0) {
    throw new AggregateError(errors, "Deterministic executor policy recovery was incomplete.");
  }
  return observed;
}

async function detachedDeterministicPoliciesRemain(
  invocation: RecoveryInvocation,
  fetcher: Fetcher,
): Promise<boolean> {
  const loaded = await detachedDeterministicPolicySurfaces(invocation, fetcher);
  let remains = false;
  for (const { current, descriptor, surface } of loaded.surfaces) {
    if (detachedSurfaceHasRelevantBinding(current, descriptor, surface)) remains = true;
  }
  if (loaded.errors.length > 0) {
    throw new AggregateError(loaded.errors, "Deterministic executor policy proof was incomplete.");
  }
  return remains;
}

async function detachedDeterministicPolicySurfaces(
  invocation: RecoveryInvocation,
  fetcher: Fetcher,
  executorUniqueId: string | undefined = undefined,
): Promise<{
  readonly errors: readonly unknown[];
  readonly surfaces: readonly {
    readonly current: IamPolicy;
    readonly descriptor: DetachedPolicyDescriptor;
    readonly expected: readonly IamBinding[];
    readonly surface: OrphanPolicySurface;
  }[];
}> {
  const token = invocation.ownerAccessToken;
  const executorEmail = deterministicExecutorEmail(invocation);
  const descriptors: DetachedPolicyDescriptor[] = REPOSITORY_NAMES.map((repository) => {
    const projectId = REPOSITORIES[repository].projectId;
    return {
      exclusive: false,
      get: () => getPolicy(projectId, token, fetcher),
      kind: "project",
      label: `deterministic run ${invocation.githubRunId} project ${projectId}`,
      projectRepository: repository,
      set: (policy) => setPolicy(projectId, token, policy, fetcher),
    };
  });
  for (const runtimeEmail of runtimeServiceAccountEmails(invocation.repository)) {
    descriptors.push({
      exclusive: false,
      get: () => getServiceAccountPolicyIfPresent(runtimeEmail, token, fetcher),
      kind: "runtime",
      label: `deterministic run ${invocation.githubRunId} runtime ${runtimeEmail}`,
      runtimeEmail,
      set: (policy) => setServiceAccountPolicy(runtimeEmail, token, policy, fetcher),
    });
  }
  descriptors.push({
    exclusive: true,
    get: () => getServiceAccountPolicyIfPresent(executorEmail, token, fetcher),
    kind: "executor",
    label: `deterministic run ${invocation.githubRunId} executor policy`,
    set: (policy) => setServiceAccountPolicy(executorEmail, token, policy, fetcher),
  });

  const result: Array<{
    current: IamPolicy;
    descriptor: DetachedPolicyDescriptor;
    expected: readonly IamBinding[];
    surface: OrphanPolicySurface;
  }> = [];
  const errors: unknown[] = [];
  const loads = await Promise.allSettled(descriptors.map(async (descriptor) => {
    const current = await descriptor.get();
    if (current === undefined) return undefined;
    const basis = detachedSurfaceBasis(invocation, descriptor);
    const strandedFences = [strandedFenceContract("orphan", descriptor.label, basis)];
    if (descriptor.kind === "executor") {
      strandedFences.push(strandedFenceContract(
        "cleanup",
        `executor service account ${executorEmail}`,
        basis,
      ));
      if (executorUniqueId !== undefined) {
        strandedFences.push(strandedFenceContract(
          "orphan",
          `orphan ${numeric(executorUniqueId, "detached executor unique ID")} executor policy`,
          basis,
        ));
      }
    }
    const expected: IamBinding[] = [];
    for (const binding of current.bindings) {
      const relevant = descriptor.exclusive ||
        bindingHasDeterministicExecutorMember(binding, executorEmail) ||
        strandedFences.some((contract) => bindingMatchesStrandedFence(binding, contract));
      if (!relevant) continue;
      if (strandedFences.some((contract) => bindingMatchesStrandedFence(binding, contract))) {
        continue;
      }
      if (descriptor.kind === "executor" &&
        !detachedExecutorPolicyBindingIsExact(invocation, binding)) {
        if (executorUniqueId === undefined &&
          bindingCouldBeUniqueIdOrphanFence(binding, basis)) {
          // The uniqueId is immutable but not derivable from the email. Keep
          // this inert candidate untouched and retry the disable/direct GET;
          // once identity is visible, its exact title hash is authenticated.
          throw new UnresolvedDeterministicIdentityError(
            `${descriptor.label} requires the exact executor unique ID before orphan-fence cleanup.`,
          );
        }
        throw new Error(
          `${descriptor.label} contains an unknown or modified binding; manual cleanup is required.`,
        );
      }
      expected.push(binding);
    }
    return {
      current,
      descriptor,
      expected,
      surface: {
        basis,
        exclusive: descriptor.exclusive,
        expected,
        get: async () => {
          const policy = await descriptor.get();
          if (policy === undefined) {
            throw new Error(`${descriptor.label} disappeared during IAM policy recovery.`);
          }
          return policy;
        },
        label: descriptor.label,
        set: descriptor.set,
        strandedFences,
      },
    };
  }));
  for (const load of loads) {
    if (load.status === "rejected") errors.push(load.reason);
    else if (load.value !== undefined) result.push(load.value);
  }
  return { errors, surfaces: result };
}

function detachedSurfaceHasRelevantBinding(
  policy: IamPolicy,
  descriptor: DetachedPolicyDescriptor,
  surface: OrphanPolicySurface,
): boolean {
  const executorMemberValue = surface.basis.members[0];
  const executorEmail = executorMemberValue?.startsWith("serviceAccount:") === true
    ? executorMemberValue.slice("serviceAccount:".length)
    : undefined;
  return (descriptor.exclusive && policy.auditConfigs !== undefined) ||
    policy.bindings.some((binding) =>
    descriptor.exclusive ||
    (executorEmail !== undefined && bindingHasDeterministicExecutorMember(binding, executorEmail)) ||
    surface.strandedFences.some((contract) => bindingMatchesStrandedFence(binding, contract))
    );
}

function detachedSurfaceBasis(
  invocation: RecoveryInvocation,
  descriptor: DetachedPolicyDescriptor,
): IamBinding {
  const executorEmail = deterministicExecutorEmail(invocation);
  if (descriptor.kind === "executor") {
    return buildTokenCreatorLease(
      invocation.repository,
      invocation.githubRunId,
      new Date(IAM_FENCE_EXPIRED_AT),
    );
  }
  if (descriptor.kind === "runtime") {
    return {
      condition: expiringCondition(
        `codex-executor-actas-${invocation.githubRunId}-0`,
        `Temporary exact-runtime actAs lease for ${invocation.repository}.`,
        new Date(IAM_FENCE_EXPIRED_AT),
      ),
      members: [`serviceAccount:${executorEmail}`],
      role: "roles/iam.serviceAccountUser",
    };
  }
  const repository = descriptor.projectRepository;
  if (repository === undefined) throw new Error("Detached project surface lost its repository.");
  if (repository === invocation.repository) {
    const roleIdValue = randomExecutorRoleId(
      "read",
      deterministicArtifactHex(invocation.repository, invocation.githubRunId, "role-read"),
    );
    return buildExecutorProjectLeases(
      invocation.repository,
      invocation.githubRunId,
      new Date(IAM_FENCE_EXPIRED_AT),
      executorEmail,
      `projects/${REPOSITORIES[invocation.repository].projectId}/roles/${roleIdValue}`,
      "read",
    )[0]!;
  }
  return buildMarkerReadLease(
    repository,
    invocation.githubRunId,
    new Date(IAM_FENCE_EXPIRED_AT),
    REPOSITORIES[invocation.repository].projectId,
    executorEmail,
  );
}

async function recoverDetachedExecutorMembers(
  invocation: RecoveryInvocation,
  descriptor: DetachedPolicyDescriptor,
  basis: IamBinding,
  sleep: (milliseconds: number) => Promise<void>,
  cleanupDeadlineMs: number,
): Promise<void> {
  const executorEmail = deterministicExecutorEmail(invocation);
  const suffix = randomBytes(10).toString("hex");
  const fence: IamBinding = {
    condition: {
      description: ORPHAN_FENCE_DESCRIPTION,
      expression: `request.time < timestamp('${IAM_FENCE_EXPIRED_AT}')`,
      title: `codex-orphan-fence-${createHash("sha256").update(descriptor.label).digest("hex").slice(0, 12)}-${suffix}`,
    },
    members: [...basis.members],
    role: basis.role,
  };
  let fencePredecessorEtag: string | undefined;
  let observedFenceEtag: string | undefined;
  let lastRetryableError: unknown;
  while (Date.now() < cleanupDeadlineMs) {
    try {
      const current = await descriptor.get();
      if (current === undefined) {
        throw new Error(`${descriptor.label} disappeared during deterministic-member recovery.`);
      }
      const fenceRemains = current.bindings.some((binding) => bindingEqualsLease(binding, fence));
      const desired = removeDeterministicExecutorMembers(current, executorEmail);
      if (!policyPayloadEquals(current, desired)) {
        if (fenceRemains) observedFenceEtag = current.etag;
        const response = await descriptor.set(desired);
        if (response !== undefined && response.etag === current.etag) {
          throw new Error(`${descriptor.label} cleanup CAS did not advance its etag.`);
        }
      } else if (observedFenceEtag !== undefined) {
        if (current.etag === observedFenceEtag) {
          throw new Error(`${descriptor.label} recovery fence disappeared without an advancing etag.`);
        }
        return;
      } else {
        fencePredecessorEtag = current.etag;
        const response = await descriptor.set(addExactLease(current, fence));
        if (response !== undefined) {
          requireContainsExactBindings(response, [fence], `${descriptor.label} recovery fence`);
          if (response.etag === current.etag) {
            throw new Error(`${descriptor.label} recovery fence CAS did not advance its etag.`);
          }
        }
      }
      if (fenceRemains && fencePredecessorEtag !== undefined &&
        current.etag === fencePredecessorEtag) {
        throw new Error(`${descriptor.label} recovery fence did not advance its predecessor etag.`);
      }
      lastRetryableError = undefined;
    } catch (error) {
      if (!retryableCleanupError(error)) throw error;
      lastRetryableError = error;
    }
    await sleep(Math.min(CLEANUP_RETRY_INTERVAL_MS, cleanupDeadlineMs - Date.now()));
  }
  throw new AggregateError(
    lastRetryableError === undefined ? [] : [lastRetryableError],
    `${descriptor.label} did not complete deterministic-member recovery.`,
  );
}

function removeDeterministicExecutorMembers(
  policy: IamPolicy,
  executorEmail: string,
): IamPolicy {
  const bindings: IamBinding[] = [];
  for (const binding of policy.bindings) {
    const members = binding.members.filter((member) =>
      member !== `serviceAccount:${executorEmail}` &&
      deletedDeterministicExecutorMember(member, executorEmail) === undefined
    );
    if (members.length === 0) continue;
    bindings.push({
      ...(binding.condition === undefined ? {} : { condition: binding.condition }),
      members,
      role: binding.role,
    });
  }
  return {
    ...(policy.auditConfigs === undefined ? {} : { auditConfigs: policy.auditConfigs }),
    bindings,
    etag: policy.etag,
    version: 3,
  };
}

function detachedExecutorPolicyBindingIsExact(
  invocation: RecoveryInvocation,
  binding: IamBinding,
): boolean {
  const condition = binding.condition;
  if (condition === undefined) return false;
  const timestamps = [...condition.expression.matchAll(
    /request\.time < timestamp\('([^']+)'\)/g,
  )].map((match) => match[1]!);
  if (timestamps.length !== 1) return false;
  const expiresAt = new Date(timestamps[0]!);
  if (!Number.isFinite(expiresAt.getTime()) || expiresAt.toISOString() !== timestamps[0]) {
    return false;
  }
  return bindingEqualsLease(
    buildTokenCreatorLease(invocation.repository, invocation.githubRunId, expiresAt),
    binding,
  );
}

function bindingHasDeterministicExecutorMember(
  binding: IamBinding,
  executorEmail: string,
): boolean {
  return binding.members.some((member) =>
    member === `serviceAccount:${executorEmail}` ||
    deletedDeterministicExecutorMember(member, executorEmail) !== undefined
  );
}

function deletedDeterministicExecutorMember(
  member: string,
  executorEmail: string,
): string | undefined {
  const escaped = executorEmail.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = new RegExp(
    `^deleted:serviceAccount:${escaped}\\?uid=([1-9][0-9]{5,30})$`,
  ).exec(member);
  return match?.[1];
}

function deterministicExecutorEmail(invocation: RecoveryInvocation): string {
  const projectId = REPOSITORIES[invocation.repository].projectId;
  return executorEmail(
    projectId,
    randomExecutorAccountId(
      deterministicArtifactHex(invocation.repository, invocation.githubRunId, "service-account"),
    ),
  );
}

async function recoverOrphanPolicy(
  surface: OrphanPolicySurface,
  executorEmail: string,
  sleep: (milliseconds: number) => Promise<void>,
  cleanupDeadlineMs: number,
): Promise<void> {
  const suffix = randomBytes(10).toString("hex");
  const fence: IamBinding = {
    condition: {
      description: ORPHAN_FENCE_DESCRIPTION,
      expression: `request.time < timestamp('${IAM_FENCE_EXPIRED_AT}')`,
      title: `codex-orphan-fence-${createHash("sha256").update(surface.label).digest("hex").slice(0, 12)}-${suffix}`,
    },
    members: [...surface.basis.members],
    role: surface.basis.role,
  };
  let observedFenceEtag: string | undefined;
  let fencePredecessorEtag: string | undefined;
  let lastRetryableError: unknown;
  while (Date.now() < cleanupDeadlineMs) {
    try {
      const current = await surface.get();
      const known = requireKnownOrphanBindings(current, surface, executorEmail, fence);
      const fenceRemains = current.bindings.some((binding) => bindingEqualsLease(binding, fence));
      if (known.length > 0) {
        const desired = removeKnownOrphanBindings(current, known);
        const response = await surface.set(desired);
        if (response !== undefined && response.etag === current.etag) {
          throw new Error(`${surface.label} cleanup CAS did not advance its etag.`);
        }
      } else if (fenceRemains) {
        if (fencePredecessorEtag !== undefined && current.etag === fencePredecessorEtag) {
          throw new Error(`${surface.label} recovery fence did not advance its predecessor etag.`);
        }
        observedFenceEtag = current.etag;
        const response = await surface.set(removeKnownOrphanBindings(current, [fence]));
        if (response !== undefined && response.etag === current.etag) {
          throw new Error(`${surface.label} recovery fence removal did not advance its etag.`);
        }
      } else if (observedFenceEtag !== undefined) {
        if (current.etag === observedFenceEtag) {
          throw new Error(`${surface.label} recovery fence disappeared without an advancing etag.`);
        }
        requireOrphanPolicyClean(current, surface, executorEmail);
        return;
      } else {
        fencePredecessorEtag = current.etag;
        const response = await surface.set(addExactLease(current, fence));
        if (response !== undefined) {
          requireContainsExactBindings(response, [fence], `${surface.label} recovery fence`);
          if (response.etag === current.etag) {
            throw new Error(`${surface.label} recovery fence CAS did not advance its etag.`);
          }
        }
      }
      lastRetryableError = undefined;
    } catch (error) {
      if (!retryableCleanupError(error)) throw error;
      lastRetryableError = error;
    }
    await sleep(Math.min(CLEANUP_RETRY_INTERVAL_MS, cleanupDeadlineMs - Date.now()));
  }
  throw new AggregateError(
    lastRetryableError === undefined ? [] : [lastRetryableError],
    `${surface.label} did not complete its etag-fenced orphan recovery.`,
  );
}

function requireKnownOrphanBindings(
  policy: IamPolicy,
  surface: OrphanPolicySurface,
  executorEmail: string,
  fence?: IamBinding,
): IamBinding[] {
  if (surface.exclusive && policy.auditConfigs !== undefined) {
    throw new Error(`${surface.label} has unknown audit policy; manual cleanup is required.`);
  }
  const member = `serviceAccount:${executorEmail}`;
  const expectedTitles = new Set(surface.expected.map((binding) => binding.condition?.title));
  const known: IamBinding[] = [];
  for (const binding of policy.bindings) {
    if (fence !== undefined && bindingEqualsLease(binding, fence)) continue;
    if (surface.strandedFences.some((contract) => bindingMatchesStrandedFence(binding, contract))) {
      known.push(binding);
      continue;
    }
    const relevant = surface.exclusive ||
      binding.members.includes(member) ||
      (binding.condition !== undefined && expectedTitles.has(binding.condition.title));
    if (!relevant) continue;
    if (!surface.expected.some((expected) => bindingEqualsLease(binding, expected))) {
      throw new Error(
        `${surface.label} contains an unknown or modified binding; manual cleanup is required.`,
      );
    }
    known.push(binding);
  }
  return known;
}

function bindingMatchesStrandedFence(
  binding: IamBinding,
  contract: StrandedFenceContract,
): boolean {
  const condition = binding.condition;
  if (condition === undefined ||
    !condition.title.startsWith(contract.titlePrefix)) return false;
  const suffix = condition.title.slice(contract.titlePrefix.length);
  if (!/^[0-9a-f]{20}$/.test(suffix)) return false;
  const expected: IamBinding = {
    condition: {
      description: contract.description,
      expression: `request.time < timestamp('${IAM_FENCE_EXPIRED_AT}')`,
      title: `${contract.titlePrefix}${suffix}`,
    },
    members: [...contract.basis.members],
    role: contract.basis.role,
  };
  return bindingEqualsLease(binding, expected);
}

function bindingCouldBeUniqueIdOrphanFence(
  binding: IamBinding,
  basis: IamBinding,
): boolean {
  const condition = binding.condition;
  if (condition === undefined ||
    !/^codex-orphan-fence-[0-9a-f]{12}-[0-9a-f]{20}$/.test(condition.title)) {
    return false;
  }
  return bindingEqualsLease(binding, {
    condition: {
      description: ORPHAN_FENCE_DESCRIPTION,
      expression: `request.time < timestamp('${IAM_FENCE_EXPIRED_AT}')`,
      title: condition.title,
    },
    members: [...basis.members],
    role: basis.role,
  });
}

function requireOrphanPolicyClean(
  policy: IamPolicy,
  surface: OrphanPolicySurface,
  executorEmail: string,
): void {
  const known = requireKnownOrphanBindings(policy, surface, executorEmail);
  if (known.length !== 0) {
    throw new Error(`${surface.label} retained a bridge lease after recovery.`);
  }
}

function removeKnownOrphanBindings(
  policy: IamPolicy,
  bindings: readonly IamBinding[],
): IamPolicy {
  const remove = new Set(bindings.map((binding) => canonicalJson(json(binding, "orphan binding"))));
  const remaining = policy.bindings.filter((binding) =>
    !remove.has(canonicalJson(json(binding, "IAM binding")))
  );
  return {
    ...(policy.auditConfigs === undefined ? {} : { auditConfigs: policy.auditConfigs }),
    bindings: remaining,
    etag: policy.etag,
    version: 3,
  };
}

async function deleteOrphanExecutor(
  account: ServiceAccount,
  ownerToken: string,
  fetcher: Fetcher,
  sleep: (milliseconds: number) => Promise<void>,
  cleanupDeadlineMs: number,
): Promise<void> {
  let lastError: unknown;
  let deleteAccepted = false;
  let attempt = 0;
  while (Date.now() < cleanupDeadlineMs) {
    try {
      const observed = await getExecutor(
        account.projectId,
        account.uniqueId,
        ownerToken,
        fetcher,
        true,
      );
      if (observed === undefined) {
        if (deleteAccepted) return;
        const deletion = await deleteExecutorByUniqueId(account, ownerToken, fetcher);
        deleteAccepted ||= deletion === "deleted";
        throw new Error("Orphan executor deletion is not yet observable.");
      }
      exact(observed.uniqueId, account.uniqueId, "orphan executor deletion unique ID");
      exact(observed.description, account.description, "orphan executor deletion provenance");
      if (!observed.disabled) {
        throw new Error("Orphan executor became enabled during cleanup; manual cleanup is required.");
      }
      const deletion = await deleteExecutorByUniqueId(observed, ownerToken, fetcher);
      deleteAccepted ||= deletion === "deleted";
      lastError = undefined;
    } catch (error) {
      if (!(error instanceof Error && /deletion is not yet observable/.test(error.message)) &&
        !retryableCleanupError(error)) throw error;
      lastError = error;
    }
    const remainingMs = cleanupDeadlineMs - Date.now();
    if (remainingMs <= 0) break;
    await sleep(Math.min(iamRetryDelayMs(attempt), remainingMs));
    attempt = Math.min(attempt + 1, IAM_RETRY_MAX_ATTEMPTS - 1);
  }
  throw new AggregateError(
    lastError === undefined ? [] : [lastError],
    "Orphan executor deletion could not be proven before the recovery deadline; manual reconciliation is required.",
  );
}

function roleIdOrUndefined(name: string): string | undefined {
  const value = name.slice(name.lastIndexOf("/") + 1);
  return /^pbt_[rm]_[0-9a-f]{20}$/.test(value) ? value : undefined;
}

async function listServiceAccountEntries(
  projectId: string,
  token: string,
  fetcher: Fetcher,
): Promise<readonly ServiceAccountListEntry[]> {
  const result: ServiceAccountListEntry[] = [];
  let pageToken = "";
  do {
    const url = new URL(`https://iam.googleapis.com/v1/projects/${projectId}/serviceAccounts`);
    url.searchParams.set("pageSize", "100");
    if (pageToken !== "") url.searchParams.set("pageToken", pageToken);
    const response = await fetcher(url, { headers: googleHeaders(token), redirect: "error" });
    if (!response.ok) throw new Error(`Executor inventory failed with HTTP ${response.status}.`);
    const value = record(await boundedJson(response, 2 * 1024 * 1024), "service account inventory");
    exactKeys(value, new Set(["accounts", "nextPageToken"]), "service account inventory");
    for (const candidate of array(value.accounts ?? [], "service accounts")) {
      const account = record(candidate, "service account list entry");
      const email = requiredString(account.email, "service account list email");
      if (email.length > 320 || !/^[^@\s]{1,128}@[^@\s]{1,255}$/.test(email)) {
        throw new Error("Service account list email escaped its bounded syntax.");
      }
      result.push({ email, value: account });
    }
    pageToken = value.nextPageToken === undefined
      ? ""
      : requiredString(value.nextPageToken, "service account inventory page token");
    if (result.length > 10_000) throw new Error("Service account inventory escaped its bound.");
  } while (pageToken !== "");
  return result;
}

async function createEphemeralRole(
  projectId: string,
  id: string,
  root: TerraformRoot,
  phase: "mutation" | "read",
  permissions: readonly string[],
  ownerToken: string,
  fetcher: Fetcher,
  recordCreateAttempt: (intent: EphemeralRoleIntent) => Promise<void>,
  recordCreateRejected: (name: string) => void,
  recordCreated: (role: ProjectCustomRole) => void,
): Promise<ProjectCustomRole> {
  const name = `projects/${projectId}/roles/${id}`;
  if (await getProjectCustomRole(name, ownerToken, fetcher, true) !== undefined) {
    throw new Error("The random executor custom role already exists; refusing reuse.");
  }
  const role: EphemeralRoleIntent = {
    description: `Protected Terraform ${root} ${phase} single-run control role.`,
    includedPermissions: [...permissions],
    name,
    stage: "GA",
    title: `Protected Terraform ${phase === "read" ? "Read" : "Mutation"}`,
  };
  await recordCreateAttempt(role);
  const response = await fetcher(`https://iam.googleapis.com/v1/projects/${projectId}/roles`, {
    body: JSON.stringify({
      role: {
        description: role.description,
        includedPermissions: role.includedPermissions,
        stage: role.stage,
        title: role.title,
      },
      roleId: id,
    }),
    headers: googleHeaders(ownerToken),
    method: "POST",
    redirect: "error",
  });
  if ([400, 401, 403].includes(response.status)) recordCreateRejected(name);
  if (response.status === 409) throw new Error("The random executor custom role collided at creation.");
  if (!response.ok) throw new Error(`Ephemeral executor role creation failed with HTTP ${response.status}.`);
  const created = parseProjectCustomRole(await boundedJson(response, 512 * 1024));
  requireExactEphemeralRole(created, role);
  exact(created.deleted, false, "created executor role deleted state");
  recordCreated(created);
  return created;
}

function requireExactEphemeralRole(
  observed: ProjectCustomRole,
  intent: EphemeralRoleIntent,
): void {
  exact(observed.name, intent.name, "executor role name");
  exact(observed.title, intent.title, "executor role title");
  exact(observed.description, intent.description, "executor role description");
  exact(observed.stage, intent.stage, "executor role stage");
  if (
    canonicalJson([...observed.includedPermissions].toSorted()) !==
      canonicalJson([...intent.includedPermissions].toSorted())
  ) {
    throw new Error("Executor role permissions drifted from the exact matrix.");
  }
}

async function listProjectCustomRoles(
  projectId: string,
  token: string,
  fetcher: Fetcher,
  showDeleted: boolean,
): Promise<readonly ProjectCustomRole[]> {
  const result: ProjectCustomRole[] = [];
  let pageToken = "";
  do {
    const url = new URL(`https://iam.googleapis.com/v1/projects/${projectId}/roles`);
    url.searchParams.set("pageSize", "100");
    url.searchParams.set("view", "FULL");
    url.searchParams.set("showDeleted", String(showDeleted));
    if (pageToken !== "") url.searchParams.set("pageToken", pageToken);
    const response = await fetcher(url, { headers: googleHeaders(token), redirect: "error" });
    if (!response.ok) throw new Error(`Executor role inventory failed with HTTP ${response.status}.`);
    const value = record(await boundedJson(response, 2 * 1024 * 1024), "custom role inventory");
    exactKeys(value, new Set(["nextPageToken", "roles"]), "custom role inventory");
    for (const candidate of array(value.roles ?? [], "custom roles")) {
      const role = record(candidate, "project custom role list entry");
      const name = requiredString(role.name, "project custom role list name");
      if (name.length > 512) throw new Error("Project custom role list name escaped its bound.");
      const match = /^projects\/([^/]+)\/roles\/([^/]+)$/.exec(name);
      const listedId = match?.[2] ?? name.slice(name.lastIndexOf("/") + 1);
      if (!listedId.startsWith(EXECUTOR_ROLE_PREFIX)) continue;
      if (match === null || match[1] !== projectId || roleIdOrUndefined(name) === undefined) {
        throw new Error("An orphan bridge role has a malformed reserved ID; manual cleanup is required.");
      }
      result.push(parseProjectCustomRole(role));
    }
    pageToken = value.nextPageToken === undefined
      ? ""
      : requiredString(value.nextPageToken, "custom role inventory page token");
    if (result.length > 10_000) throw new Error("Custom role inventory escaped its bound.");
  } while (pageToken !== "");
  return result;
}

async function getProjectCustomRole(
  name: string,
  token: string,
  fetcher: Fetcher,
  allowMissing: boolean,
): Promise<ProjectCustomRole | undefined> {
  if (!/^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]\/roles\/pbt_[rm]_[0-9a-f]{20}$/.test(name)) {
    throw new Error("Ephemeral executor role name escaped its exact syntax.");
  }
  const url = new URL(`https://iam.googleapis.com/v1/${name}`);
  const response = await fetcher(url, { headers: googleHeaders(token), redirect: "error" });
  if (allowMissing && response.status === 404) return undefined;
  if (!response.ok) throw new Error(`Ephemeral executor role lookup failed with HTTP ${response.status}.`);
  return parseProjectCustomRole(await boundedJson(response, 512 * 1024));
}

function parseProjectCustomRole(value: unknown): ProjectCustomRole {
  const role = record(value, "project custom role");
  exactKeys(
    role,
    new Set(["deleted", "description", "etag", "includedPermissions", "name", "stage", "title"]),
    "project custom role",
  );
  exact(role.stage, "GA", "project custom role stage");
  return {
    deleted: role.deleted === true,
    description: requiredString(role.description, "project custom role description"),
    etag: requiredString(role.etag, "project custom role etag"),
    includedPermissions: array(role.includedPermissions, "project custom role permissions").map(
      (permission) => requiredString(permission, "project custom role permission"),
    ).toSorted(),
    name: requiredString(role.name, "project custom role name"),
    stage: "GA",
    title: requiredString(role.title, "project custom role title"),
  };
}

function verifyBridgeRole(role: ProjectCustomRole, projectId: string): void {
  bridgeRoleContract(role, projectId);
}

function bridgeRoleContract(
  role: ProjectCustomRole,
  projectId: string,
): { readonly phase: "mutation" | "read"; readonly root: TerraformRoot } {
  if (!role.name.startsWith(`projects/${projectId}/roles/${EXECUTOR_ROLE_PREFIX}`)) {
    throw new Error("Bridge custom role escaped its project prefix.");
  }
  const description = /^Protected Terraform (bootstrap|prod) (read|mutation) single-run control role\.$/.exec(
    role.description,
  );
  if (description === null) throw new Error("An orphan bridge role has unknown provenance.");
  const root = rootName(description[1]!);
  const phase = description[2] === "read" ? "read" : "mutation";
  const id = roleId(role.name);
  if ((phase === "read") !== id.startsWith("pbt_r_")) {
    throw new Error("An orphan bridge role ID and phase provenance disagree.");
  }
  exact(role.title, `Protected Terraform ${phase === "read" ? "Read" : "Mutation"}`, "bridge role title");
  const repository = REPOSITORY_NAMES.find((name) => REPOSITORIES[name].projectId === projectId);
  if (repository === undefined) throw new Error("Bridge role project escaped the repository map.");
  const expected = executorControlPermissions(repository, root, phase);
  if (canonicalJson([...role.includedPermissions].toSorted()) !== canonicalJson([...expected].toSorted())) {
    throw new Error("An orphan bridge role permissions matrix drifted.");
  }
  return { phase, root };
}

async function deleteEphemeralRole(
  role: ProjectCustomRole,
  ownerToken: string,
  fetcher: Fetcher,
): Promise<"deleted" | "missing"> {
  if (role.deleted) return "deleted";
  const url = new URL(`https://iam.googleapis.com/v1/${role.name}`);
  url.searchParams.set("etag", role.etag);
  const response = await fetcher(url, {
    headers: googleHeaders(ownerToken),
    method: "DELETE",
    redirect: "error",
  });
  if (response.status === 404) return "missing";
  if (!response.ok) throw new Error(`Ephemeral executor role deletion failed with HTTP ${response.status}.`);
  const deleted = parseProjectCustomRole(await boundedJson(response, 512 * 1024));
  exact(deleted.name, role.name, "deleted executor role name");
  exact(deleted.deleted, true, "deleted executor role state");
  return "deleted";
}

async function deleteOrphanRole(
  role: ProjectCustomRole,
  ownerToken: string,
  fetcher: Fetcher,
  sleep: (milliseconds: number) => Promise<void>,
  cleanupDeadlineMs: number,
): Promise<void> {
  if (role.deleted) return;
  let deleteAccepted = false;
  let lastError: unknown;
  for (let attempt = 0; attempt < IAM_RETRY_MAX_ATTEMPTS; attempt += 1) {
    if (Date.now() >= cleanupDeadlineMs) break;
    try {
      if (!deleteAccepted) {
        const deletion = await deleteEphemeralRole(role, ownerToken, fetcher);
        deleteAccepted = deletion === "deleted";
        if (!deleteAccepted) {
          throw new Error("Orphan bridge role deletion lacks a successful write acknowledgement.");
        }
      }
      const observed = await getProjectCustomRole(role.name, ownerToken, fetcher, true);
      if (observed === undefined || observed.deleted) return;
      throw new Error("Orphan bridge role deletion is not yet observable.");
    } catch (error) {
      const retryableSentinel = error instanceof Error &&
        /(?:lacks a successful write acknowledgement|is not yet observable)/.test(error.message);
      if (!retryableSentinel && !retryableCleanupError(error)) throw error;
      lastError = error;
    }
    const remainingMs = cleanupDeadlineMs - Date.now();
    if (remainingMs <= 0) break;
    await sleep(Math.min(iamRetryDelayMs(attempt), remainingMs));
  }
  throw new AggregateError(
    lastError === undefined ? [] : [lastError],
    "Orphan custom-role deletion could not be proven before the recovery deadline; manual reconciliation is required.",
  );
}

function roleId(name: string): string {
  const value = name.slice(name.lastIndexOf("/") + 1);
  if (!/^pbt_[rm]_[0-9a-f]{20}$/.test(value)) {
    throw new Error("Executor custom role ID escaped its random syntax.");
  }
  return value;
}

export function randomExecutorAccountId(randomHexValue: string): string {
  if (!/^[0-9a-f]{20}$/.test(randomHexValue)) {
    throw new Error("Executor account randomness escaped its reviewed syntax.");
  }
  return `${EXECUTOR_ACCOUNT_PREFIX}${randomHexValue}`;
}

export function randomExecutorRoleId(
  phase: "mutation" | "read",
  randomHexValue: string,
): string {
  if (!/^[0-9a-f]{20}$/.test(randomHexValue)) {
    throw new Error("Executor role randomness escaped its reviewed syntax.");
  }
  return `${EXECUTOR_ROLE_PREFIX}${phase === "read" ? "r" : "m"}_${randomHexValue}`;
}

type DeterministicArtifactPhase =
  | "service-account"
  | "role-read"
  | "role-mutation"
  | `container-${1 | 2 | 3 | 4 | 5}`;

export function deterministicArtifactHex(
  repository: RepositoryName,
  runId: string,
  phase: DeterministicArtifactPhase,
): string {
  repositoryName(repository);
  numeric(runId, "deterministic artifact run ID");
  if (!/^(?:service-account|role-(?:read|mutation)|container-[1-5])$/.test(phase)) {
    throw new Error("Deterministic artifact phase escaped its closed vocabulary.");
  }
  const fields = [
    "protected-bootstrap-artifact-v1",
    PLATFORM_REPOSITORY_ID,
    REPOSITORIES[repository].repositoryId,
    runId,
    "1",
    phase,
  ];
  const hash = createHash("sha256");
  for (const field of fields) {
    hash.update(String(Buffer.byteLength(field, "utf8")));
    hash.update("\0");
    hash.update(field);
    hash.update("\0");
  }
  return hash.digest("hex").slice(0, 20);
}

function executorProvenance(
  invocation: Invocation,
  expiresAt: Date,
): ExecutorProvenance {
  if (!Number.isFinite(expiresAt.getTime())) throw new Error("Executor provenance expiry is invalid.");
  return {
    approvedPlanRunId: invocation.approvedPlanRunId,
    expiresAt,
    mode: invocation.mode,
    repository: invocation.repository,
    root: invocation.terraformRoot,
    runId: invocation.githubRunId,
  };
}

function executorDescription(provenance: ExecutorProvenance): string {
  numeric(provenance.runId, "executor provenance run ID");
  if (provenance.mode === "apply") {
    numeric(provenance.approvedPlanRunId, "executor provenance approved plan run ID");
  } else if (provenance.approvedPlanRunId !== "") {
    throw new Error("Plan executor provenance cannot name an approved run.");
  }
  return [
    EXECUTOR_DESCRIPTION_VERSION,
    `repository=${provenance.repository}`,
    `run=${provenance.runId}`,
    `root=${provenance.root}`,
    `mode=${provenance.mode}`,
    `approved=${provenance.approvedPlanRunId === "" ? "none" : provenance.approvedPlanRunId}`,
    `expires=${provenance.expiresAt.toISOString()}`,
  ].join(";");
}

function parseExecutorProvenance(description: string, projectId: string): ExecutorProvenance {
  const match = new RegExp(
    `^${EXECUTOR_DESCRIPTION_VERSION};repository=(${REPOSITORY_NAMES.join("|")});` +
      "run=([1-9][0-9]*);root=(bootstrap|prod);mode=(plan|apply);" +
      "approved=(none|[1-9][0-9]*);expires=([^;]+)$",
  ).exec(description);
  if (match === null) {
    throw new Error("An orphan bridge executor has unknown provenance; manual cleanup is required.");
  }
  const repository = repositoryName(match[1]!);
  exact(REPOSITORIES[repository].projectId, projectId, "executor provenance project");
  const runId = numeric(match[2]!, "executor provenance run ID");
  const root = rootName(match[3]!);
  const mode = match[4] === "plan" ? "plan" : "apply";
  const approvedPlanRunId = match[5] === "none"
    ? ""
    : numeric(match[5]!, "executor provenance approved plan run ID");
  if ((mode === "apply") !== (approvedPlanRunId !== "")) {
    throw new Error("An orphan bridge executor has malformed approval provenance; manual cleanup is required.");
  }
  const expiresAt = new Date(match[6]!);
  if (!Number.isFinite(expiresAt.getTime()) || expiresAt.toISOString() !== match[6]) {
    throw new Error("An orphan bridge executor has malformed expiry provenance; manual cleanup is required.");
  }
  const provenance = { approvedPlanRunId, expiresAt, mode, repository, root, runId } as const;
  exact(executorDescription(provenance), description, "executor provenance encoding");
  return provenance;
}

async function createEphemeralExecutor(
  projectId: string,
  accountId: string,
  invocation: Invocation,
  expiresAt: Date,
  ownerToken: string,
  fetcher: Fetcher,
  sleep: (milliseconds: number) => Promise<void>,
  deadlineMs: number,
  recordCreateAttempt: () => Promise<void>,
  recordCreateRejected: () => void,
  recordCreated: (account: ServiceAccountIdentity) => void,
): Promise<ServiceAccount> {
  const provenance = executorProvenance(invocation, expiresAt);
  exact(REPOSITORIES[provenance.repository].projectId, projectId, "executor provenance repository");
  const description = executorDescription(provenance);
  const email = executorEmail(projectId, accountId);
  if (await getExecutor(projectId, email, ownerToken, fetcher, true) !== undefined) {
    throw new Error("The random executor account already exists; refusing identity reuse.");
  }
  await recordCreateAttempt();
  const response = await fetcher(
    `https://iam.googleapis.com/v1/projects/${projectId}/serviceAccounts`,
    {
      body: JSON.stringify({
        accountId,
        serviceAccount: {
          description,
          displayName: EXECUTOR_DISPLAY_NAME,
        },
      }),
      headers: googleHeaders(ownerToken),
      method: "POST",
      redirect: "error",
    },
  );
  // A 409 after the preflight 404 can still be a not-yet-visible account or a
  // replayed create whose response was lost. Keep exact recovery armed so the
  // deterministic email must be proven, contained, and cleaned.
  if ([400, 401, 403].includes(response.status)) recordCreateRejected();
  if (response.status === 409) throw new Error("The random executor account collided at creation.");
  if (!response.ok) throw new Error(`Ephemeral executor creation failed with HTTP ${response.status}.`);
  const value = await boundedJson(response, 256 * 1024);
  const identity = parseReservedServiceAccountIdentity(value, projectId);
  exact(identity.email, email, "created executor email");
  recordCreated(identity);
  const created = verifyExecutorAccount(value, projectId, accountId);
  exact(created.description, description, "created executor provenance");
  const disabled = await setExecutorDisabled(
    created,
    true,
    ownerToken,
    fetcher,
    sleep,
    deadlineMs,
  );
  verifyExactExecutor(disabled, projectId, accountId, true);
  exact(disabled.description, description, "disabled executor provenance");
  return disabled;
}

async function getExecutor(
  projectId: string,
  identifier: string,
  token: string,
  fetcher: Fetcher,
  allowMissing: boolean,
): Promise<ServiceAccount | undefined> {
  const response = await fetcher(serviceAccountIdentifierUrl(projectId, identifier), {
    headers: googleHeaders(token),
    redirect: "error",
  });
  if (allowMissing && response.status === 404) return undefined;
  if (!response.ok) throw new Error(`Ephemeral executor lookup failed with HTTP ${response.status}.`);
  const account = parseServiceAccount(await boundedJson(response, 256 * 1024));
  const accountId = account.email.slice(0, account.email.indexOf("@"));
  verifyExactExecutor(account, projectId, accountId, undefined);
  return account;
}

async function getExecutorIdentity(
  projectId: string,
  identifier: string,
  token: string,
  fetcher: Fetcher,
  allowMissing: boolean,
): Promise<ServiceAccountIdentity | undefined> {
  const response = await fetcher(serviceAccountIdentifierUrl(projectId, identifier), {
    headers: googleHeaders(token),
    redirect: "error",
  });
  if (allowMissing && response.status === 404) return undefined;
  if (!response.ok) {
    throw new Error(`Ephemeral executor identity lookup failed with HTTP ${response.status}.`);
  }
  return parseReservedServiceAccountIdentity(
    await boundedJson(response, 256 * 1024),
    projectId,
  );
}

function parseReservedServiceAccountIdentity(
  value: unknown,
  projectId: string,
): ServiceAccountIdentity {
  const account = record(value, "reserved service account identity");
  const email = requiredString(account.email, "reserved executor email");
  const accountId = reservedExecutorAccountIdOrUndefined(email);
  if (accountId === undefined) {
    throw new Error("Reserved executor identity escaped its namespace.");
  }
  if (account.disabled !== undefined && typeof account.disabled !== "boolean") {
    throw new Error("Reserved executor disabled state must be boolean when present.");
  }
  const identity: ServiceAccountIdentity = {
    disabled: account.disabled === true,
    email,
    name: requiredString(account.name, "reserved executor resource name"),
    projectId: requiredString(account.projectId, "reserved executor project ID"),
    uniqueId: requiredString(account.uniqueId, "reserved executor unique ID"),
  };
  if (!/^[1-9][0-9]{5,30}$/.test(identity.uniqueId)) {
    throw new Error("Reserved executor unique ID escaped its bounded syntax.");
  }
  exact(identity.projectId, projectId, "reserved executor project ID");
  exact(identity.email, `${accountId}@${projectId}.iam.gserviceaccount.com`, "reserved executor email");
  exact(
    identity.name,
    `projects/${projectId}/serviceAccounts/${identity.email}`,
    "reserved executor resource name",
  );
  return identity;
}

function reservedExecutorAccountIdOrUndefined(email: string): string | undefined {
  const at = email.indexOf("@");
  if (at <= 0 || email.indexOf("@", at + 1) !== -1) {
    throw new Error("Service account list email escaped its single-address syntax.");
  }
  const accountId = email.slice(0, at);
  return accountId.startsWith(EXECUTOR_ACCOUNT_PREFIX) ? accountId : undefined;
}

function requireSameServiceAccountIdentity(
  observed: ServiceAccountIdentity,
  expected: ServiceAccountIdentity,
  label: string,
): void {
  exact(observed.projectId, expected.projectId, `${label} project ID`);
  exact(observed.email, expected.email, `${label} email`);
  exact(observed.name, expected.name, `${label} resource name`);
  exact(observed.uniqueId, expected.uniqueId, `${label} unique ID`);
}

function parseServiceAccount(value: unknown): ServiceAccount {
  const account = record(value, "service account");
  exactKeys(
    account,
    new Set([
      "description",
      "disabled",
      "displayName",
      "email",
      "etag",
      "name",
      "oauth2ClientId",
      "projectId",
      "uniqueId",
    ]),
    "service account",
  );
  const parsed: ServiceAccount = {
    description: requiredString(account.description, "executor description"),
    disabled: account.disabled === true,
    displayName: requiredString(account.displayName, "executor display name"),
    email: requiredString(account.email, "executor email"),
    etag: requiredString(account.etag, "executor etag"),
    name: requiredString(account.name, "executor resource name"),
    projectId: requiredString(account.projectId, "executor project ID"),
    uniqueId: numeric(requiredString(account.uniqueId, "executor unique ID"), "executor unique ID"),
  };
  return parsed;
}

function verifyExecutorAccount(
  value: unknown,
  projectId: string,
  accountId: string,
): ServiceAccount {
  const parsed = parseServiceAccount(value);
  verifyExactExecutor(parsed, projectId, accountId, undefined);
  return parsed;
}

function verifyExactExecutor(
  account: ServiceAccount,
  projectId: string,
  accountId: string,
  expectedDisabled: boolean | undefined,
): void {
  const email = executorEmail(projectId, accountId);
  exact(account.projectId, projectId, "executor project ID");
  exact(account.email, email, "executor email");
  exact(account.name, `projects/${projectId}/serviceAccounts/${email}`, "executor name");
  exact(account.displayName, EXECUTOR_DISPLAY_NAME, "executor display name");
  parseExecutorProvenance(account.description, projectId);
  if (expectedDisabled !== undefined) {
    exact(account.disabled, expectedDisabled, "executor disabled state");
  }
}

async function setExecutorDisabled(
  account: ServiceAccountIdentity,
  disabled: boolean,
  token: string,
  fetcher: Fetcher,
  sleep: (milliseconds: number) => Promise<void>,
  deadlineMs: number,
): Promise<ServiceAccount> {
  const action = disabled ? "disable" : "enable";
  const consistencyDeadlineMs = Math.min(
    deadlineMs,
    Date.now() + IAM_CONSISTENCY_MAX_WAIT_MS,
  );
  let lastRetryableError: unknown;
  for (let attempt = 0; attempt < IAM_RETRY_MAX_ATTEMPTS; attempt += 1) {
    if (Date.now() >= consistencyDeadlineMs) break;
    try {
      // The lifecycle methods are idempotent. Issue the exact stable-ID write
      // on every attempt before accepting any eventually-consistent readback;
      // a stale "already disabled/enabled" read can never skip containment.
      const response = await fetcher(
        `${serviceAccountIdentifierUrl(account.projectId, account.uniqueId)}:${action}`,
        {
          body: "{}",
          headers: googleHeaders(token),
          method: "POST",
          redirect: "error",
        },
      );
      if (response.status === 409) {
        const value = record(
          await boundedJson(response, 64 * 1024),
          `executor ${action} conflict`,
        );
        const conflict = record(value.error, `executor ${action} conflict error`);
        const status = requiredString(conflict.status, `executor ${action} conflict status`);
        if (status === "ABORTED") {
          throw new Error(`Executor ${action} failed with HTTP 409 ABORTED.`);
        }
        throw new Error(`Executor ${action} failed with HTTP 409.`);
      }
      if (!response.ok) {
        throw new Error(`Executor ${action} failed with HTTP ${response.status}.`);
      }
      await boundedJson(response, 64 * 1024);
      const observed = await getExecutor(
        account.projectId,
        account.uniqueId,
        token,
        fetcher,
        false,
      );
      if (observed === undefined) {
        throw new Error("Executor lifecycle validation unexpectedly returned no identity.");
      }
      requireSameServiceAccountIdentity(observed, account, `executor ${action}`);
      if ("description" in account) {
        exact(observed.description, account.description, `executor ${action} provenance`);
      }
      if ("displayName" in account) {
        exact(observed.displayName, account.displayName, `executor ${action} display name`);
      }
      if (observed.disabled === disabled) return observed;
      lastRetryableError = new Error(
        `Executor ${action} readback remained eventually consistent with the prior state.`,
      );
    } catch (error) {
      if (!retryableIamConsistencyError(error)) throw error;
      lastRetryableError = error;
    }
    const remainingMs = consistencyDeadlineMs - Date.now();
    if (remainingMs <= 0) break;
    await sleep(Math.min(iamRetryDelayMs(attempt), remainingMs));
  }
  throw new AggregateError(
    lastRetryableError === undefined ? [] : [lastRetryableError],
    `Executor ${action} did not converge before the IAM consistency deadline.`,
  );
}

async function deleteExecutorByUniqueId(
  account: ServiceAccount,
  token: string,
  fetcher: Fetcher,
): Promise<"deleted" | "missing"> {
  const response = await fetcher(
    serviceAccountIdentifierUrl(account.projectId, account.uniqueId),
    {
      headers: googleHeaders(token),
      method: "DELETE",
      redirect: "error",
    },
  );
  if (response.status === 404) return "missing";
  if (!response.ok) throw new Error(`Ephemeral executor deletion failed with HTTP ${response.status}.`);
  const body = await boundedText(response, 64 * 1024);
  if (body !== "" && body !== "{}" && body !== "{}\n") {
    throw new Error("Ephemeral executor deletion returned an unexpected body.");
  }
  return "deleted";
}

async function requireNoUserManagedKeys(
  account: ServiceAccount,
  token: string,
  fetcher: Fetcher,
): Promise<void> {
  const url = new URL(`${serviceAccountIdentifierUrl(account.projectId, account.uniqueId)}/keys`);
  url.searchParams.set("keyTypes", "USER_MANAGED");
  const response = await fetcher(url, { headers: googleHeaders(token), redirect: "error" });
  if (!response.ok) throw new Error(`Executor key inventory failed with HTTP ${response.status}.`);
  const value = record(await boundedJson(response, 256 * 1024), "executor key inventory");
  exactKeys(value, new Set(["keys", "nextPageToken"]), "executor key inventory");
  if (array(value.keys ?? [], "executor user-managed keys").length !== 0) {
    throw new Error("The dedicated executor has a user-managed key.");
  }
  if (value.nextPageToken !== undefined) {
    throw new Error("Executor key inventory unexpectedly paginated.");
  }
}

async function mintExecutorToken(
  account: ServiceAccount,
  ownerToken: string,
  fetcher: Fetcher,
): Promise<ExecutorSession> {
  const response = await fetcher(
    `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${account.uniqueId}:generateAccessToken`,
    {
      body: JSON.stringify({
        lifetime: `${EXECUTOR_TOKEN_MINUTES * 60}s`,
        scope: ["https://www.googleapis.com/auth/cloud-platform"],
      }),
      headers: googleHeaders(ownerToken),
      method: "POST",
      redirect: "error",
    },
  );
  if (!response.ok) throw new Error(`Executor token mint failed with HTTP ${response.status}.`);
  const value = record(await boundedJson(response, 64 * 1024), "executor token response");
  exactKeys(value, new Set(["accessToken", "expireTime"]), "executor token response");
  const accessToken = requiredString(value.accessToken, "executor access token");
  if (accessToken.length < 20 || accessToken.length > 4_096) {
    throw new Error("Executor access token has an invalid length.");
  }
  const tokenExpiresAtMs = Date.parse(requiredString(value.expireTime, "executor token expiry"));
  const lifetime = tokenExpiresAtMs - Date.now();
  if (
    !Number.isFinite(tokenExpiresAtMs) ||
    lifetime < (EXECUTOR_TOKEN_MINUTES - 2) * 60_000 ||
    lifetime > (EXECUTOR_TOKEN_MINUTES + 1) * 60_000
  ) {
    throw new Error("Executor token lifetime escaped the reviewed bound.");
  }
  return {
    accessToken,
    executorEmail: account.email,
    executorUniqueId: account.uniqueId,
    tokenExpiresAtMs,
  };
}

async function getServiceAccountPolicy(
  account: string | ServiceAccountIdentity,
  token: string,
  fetcher: Fetcher,
): Promise<IamPolicy> {
  const url = new URL(`${serviceAccountPolicyUrl(account)}:getIamPolicy`);
  // Unlike Resource Manager's getIamPolicy RPC, the IAM service-account
  // method requires an empty body and carries GetPolicyOptions in the query.
  url.searchParams.set("options.requestedPolicyVersion", "3");
  const response = await fetcher(url, {
    headers: googleHeaders(token),
    method: "POST",
    redirect: "error",
  });
  if (!response.ok) {
    throw new Error(`Service-account IAM getPolicy failed with HTTP ${response.status}.`);
  }
  return iamPolicy(await boundedJson(response, 2 * 1024 * 1024));
}

async function getServiceAccountPolicyIfPresent(
  account: string | ServiceAccountIdentity,
  token: string,
  fetcher: Fetcher,
): Promise<IamPolicy | undefined> {
  const url = new URL(`${serviceAccountPolicyUrl(account)}:getIamPolicy`);
  url.searchParams.set("options.requestedPolicyVersion", "3");
  const response = await fetcher(url, {
    headers: googleHeaders(token),
    method: "POST",
    redirect: "error",
  });
  if (response.status === 404) return undefined;
  if (!response.ok) {
    throw new Error(`Service-account IAM getPolicy failed with HTTP ${response.status}.`);
  }
  return iamPolicy(await boundedJson(response, 2 * 1024 * 1024));
}

async function setServiceAccountPolicy(
  account: string | ServiceAccountIdentity,
  token: string,
  policy: IamPolicy,
  fetcher: Fetcher,
): Promise<IamPolicy | undefined> {
  const response = await fetcher(`${serviceAccountPolicyUrl(account)}:setIamPolicy`, {
    body: JSON.stringify({ policy: { ...policy, version: 3 } }),
    headers: googleHeaders(token),
    method: "POST",
    redirect: "error",
  });
  if (response.status === 409 || response.status === 412) return undefined;
  if (!response.ok) {
    throw new Error(`Service-account IAM setPolicy failed with HTTP ${response.status}.`);
  }
  return iamPolicy(await boundedJson(response, 2 * 1024 * 1024));
}

function serviceAccountPolicyUrl(account: string | ServiceAccountIdentity): string {
  return typeof account === "string"
    ? serviceAccountUrl(account)
    : serviceAccountIdentifierUrl(account.projectId, account.uniqueId);
}

function serviceAccountUrl(email: string): string {
  if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$/.test(email)) {
    throw new Error("Service-account email escaped the exact syntax allowlist.");
  }
  const projectId = email.slice(email.indexOf("@") + 1, -".iam.gserviceaccount.com".length);
  if (!Object.values(REPOSITORIES).some((contract) => contract.projectId === projectId)) {
    throw new Error("Service-account email escaped the registered projects.");
  }
  return `https://iam.googleapis.com/v1/projects/${projectId}/serviceAccounts/${encodeURIComponent(email)}`;
}

function serviceAccountIdentifierUrl(projectId: string, identifier: string): string {
  if (!Object.values(REPOSITORIES).some((contract) => contract.projectId === projectId)) {
    throw new Error("Service-account identifier project escaped the registered projects.");
  }
  if (!/^[1-9][0-9]{5,30}$/.test(identifier) &&
    !/^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$/.test(identifier)) {
    throw new Error("Service-account identifier escaped its syntax allowlist.");
  }
  return `https://iam.googleapis.com/v1/projects/${projectId}/serviceAccounts/${encodeURIComponent(identifier)}`;
}

function executorEmail(projectId: string, accountId: string): string {
  if (!Object.values(REPOSITORIES).some((contract) => contract.projectId === projectId)) {
    throw new Error("Executor project escaped the registered projects.");
  }
  if (!new RegExp(`^${EXECUTOR_ACCOUNT_PREFIX}[0-9a-f]{20}$`).test(accountId)) {
    throw new Error("Executor account ID escaped the random prefix contract.");
  }
  return `${accountId}@${projectId}.iam.gserviceaccount.com`;
}

function executorMember(projectId: string, email: string): `serviceAccount:${string}` {
  const accountId = email.slice(0, email.indexOf("@"));
  exact(email, executorEmail(projectId, accountId), "executor lease member");
  return `serviceAccount:${email}`;
}

async function googleJson(
  url: string,
  token: string,
  body: JsonValue,
  fetcher: Fetcher,
): Promise<unknown> {
  const response = await fetcher(url, {
    body: JSON.stringify(body),
    headers: googleHeaders(token),
    method: "POST",
    redirect: "error",
  });
  if (!response.ok) throw new Error(`Google API request failed with HTTP ${response.status}.`);
  return boundedJson(response, 2 * 1024 * 1024);
}

export async function proveDeploymentParityMarkers(
  invocation: Invocation,
  executorToken: string,
  requireTargetClear: boolean,
  fetcher: Fetcher,
  sleep: (milliseconds: number) => Promise<void> = (milliseconds) => Bun.sleep(milliseconds),
): Promise<readonly MarkerStateProof[]> {
  const initialMigration = invocation.terraformRoot === "bootstrap" &&
    invocation.legacyCompatibilityMode && invocation.transitionWorkflowSha === "";
  const result: MarkerStateProof[] = [];
  for (const repository of REPOSITORY_NAMES) {
    const contract = REPOSITORIES[repository];
    const bucket = `${contract.projectId}${DEPLOYMENT_PARITY_BUCKET_SUFFIX}`;
    const url = new URL(
      `https://storage.googleapis.com/storage/v1/b/${bucket}/o/${DEPLOYMENT_PARITY_MARKER_OBJECT}`,
    );
    url.searchParams.set("fields", "bucket,name,generation,metageneration,metadata");
    let response: Response | undefined;
    for (let attempt = 0; attempt < 7; attempt += 1) {
      response = await fetcher(url, {
        headers: executorHeaders(executorToken),
        redirect: "error",
      });
      if (response.status !== 403 && response.status !== 429 && response.status < 500) break;
      await sleep(Math.min(2 ** attempt, 12) * 1_000);
    }
    if (response === undefined) throw new Error("Deployment-parity marker proof did not run.");
    if (response.status === 404) {
      if (!initialMigration || (requireTargetClear && repository === invocation.repository)) {
        throw new Error(
          `The ${repository} deployment-parity marker is absent outside its initial bootstrap.`,
        );
      }
      result.push({
        bucket,
        generation: null,
        metadata: null,
        metageneration: null,
        repository,
        repositoryId: contract.repositoryId,
        state: "absent",
      });
      continue;
    }
    if (!response.ok) {
      throw new Error(
        `The ${repository} deployment-parity marker proof failed with HTTP ${response.status}.`,
      );
    }
    const marker = record(
      await boundedJson(response, 64 * 1024),
      `${repository} deployment-parity marker`,
    );
    exactKeys(
      marker,
      new Set(["bucket", "generation", "metadata", "metageneration", "name"]),
      `${repository} deployment-parity marker`,
    );
    exact(marker.bucket, bucket, `${repository} marker bucket`);
    exact(marker.name, DEPLOYMENT_PARITY_MARKER_OBJECT, `${repository} marker object`);
    const generation = numeric(
      requiredString(marker.generation, `${repository} marker generation`),
      `${repository} marker generation`,
    );
    const metageneration = numeric(
      requiredString(marker.metageneration, `${repository} marker metageneration`),
      `${repository} marker metageneration`,
    );
    const metadata = record(marker.metadata, `${repository} marker metadata`);
    exactKeys(
      metadata,
      new Set(["repository-id", "state", "version"]),
      `${repository} marker metadata`,
    );
    exact(metadata.version, "1", `${repository} marker metadata version`);
    exact(
      metadata["repository-id"],
      contract.repositoryId,
      `${repository} marker metadata repository ID`,
    );
    exact(metadata.state, "clear", `${repository} marker state`);
    result.push({
      bucket,
      generation,
      metadata: {
        "repository-id": contract.repositoryId,
        state: "clear",
        version: "1",
      },
      metageneration,
      repository,
      repositoryId: contract.repositoryId,
      state: "clear",
    });
  }
  return result;
}

export async function waitForStatePermissions(
  state: { readonly bucket: string; readonly prefix: string },
  invocation: Invocation,
  executorToken: string,
  expected: "mutation" | "none" | "read",
  fetcher: Fetcher,
  sleep: (milliseconds: number) => Promise<void> = (milliseconds) => Bun.sleep(milliseconds),
): Promise<void> {
  const allObjectPermissions = [
    "storage.objects.create",
    "storage.objects.delete",
    "storage.objects.get",
    "storage.objects.update",
  ] as const;
  const readWrite = new Set<string>(allObjectPermissions);
  const stateRead = new Set<string>(["storage.objects.get"]);
  const noAccess = new Set<string>();
  const createRead = new Set<string>(["storage.objects.create", "storage.objects.get"]);
  const readOnly = new Set<string>(["storage.objects.get"]);
  const objects: readonly {
    readonly name: string;
    readonly required: ReadonlySet<string>;
  }[] = [
    {
      name: `${state.prefix}/default.tfstate`,
      required: expected === "mutation" ? readWrite : expected === "read" ? stateRead : noAccess,
    },
    {
      name: `${state.prefix}/default.tflock`,
      required: expected === "mutation" ? readWrite : noAccess,
    },
    {
      name: receiptObjectName(
        state,
        "plans",
        invocation.mode === "plan" ? invocation.githubRunId : invocation.approvedPlanRunId,
      ),
      required: expected === "none"
        ? noAccess
        : invocation.mode === "plan" ? createRead : readOnly,
    },
    ...(invocation.mode === "apply"
      ? [{
          name: receiptObjectName(state, "consumed", invocation.approvedPlanRunId),
          required: expected === "none" ? noAccess : createRead,
        }, {
          name: receiptObjectName(state, "results", invocation.githubRunId),
          required: expected === "none" ? noAccess : createRead,
        }]
      : []),
  ];
  for (let attempt = 0; attempt < 7; attempt += 1) {
    const observed: boolean[] = [];
    const bucketUrl = new URL(
      `https://storage.googleapis.com/storage/v1/b/${state.bucket}/iam/testPermissions`,
    );
    for (const permission of ["storage.buckets.get", "storage.objects.list"]) {
      bucketUrl.searchParams.append("permissions", permission);
    }
    const bucketResponse = await fetcher(bucketUrl, {
      headers: executorHeaders(executorToken),
      redirect: "error",
    });
    if (!bucketResponse.ok &&
      !(expected === "none" && permissionDenialProvesNoUsableCredential(bucketResponse))) {
      throw new Error(`Bucket permission test failed with HTTP ${bucketResponse.status}.`);
    }
    const requiredBucketPermissions = ["storage.buckets.get", "storage.objects.list"];
    if (!bucketResponse.ok) {
      observed.push(true);
    } else {
      const bucketValue = record(
        await boundedJson(bucketResponse, 64 * 1024),
        "bucket permission test",
      );
      exactKeys(bucketValue, new Set(["kind", "permissions"]), "bucket permission test");
      const bucketPermissions = new Set(
        array(bucketValue.permissions ?? [], "bucket permissions").map((entry) =>
          requiredString(entry, "bucket permission")
        ),
      );
      observed.push(
        expected !== "none"
          ? requiredBucketPermissions.every((permission) => bucketPermissions.has(permission))
          : requiredBucketPermissions.every((permission) => !bucketPermissions.has(permission)),
      );
    }

    for (const object of objects) {
      const resource = `projects/_/buckets/${state.bucket}/objects/${object.name}`;
      const response = await fetcher(
        `https://storage.googleapis.com/storage/v2/${encodeResourcePath(resource)}:testIamPermissions`,
        {
          body: JSON.stringify({ permissions: allObjectPermissions }),
          headers: { ...executorHeaders(executorToken), "Content-Type": "application/json" },
          method: "POST",
          redirect: "error",
        },
      );
      if (!response.ok &&
        !(expected === "none" && permissionDenialProvesNoUsableCredential(response))) {
        throw new Error(`Object permission test failed with HTTP ${response.status}.`);
      }
      if (!response.ok) {
        observed.push(true);
        continue;
      }
      const value = record(await boundedJson(response, 64 * 1024), "object permission test");
      exactKeys(value, new Set(["permissions"]), "object permission test");
      const permissions = new Set(
        array(value.permissions ?? [], "object permissions").map((entry) =>
          requiredString(entry, "object permission")
        ),
      );
      const forbidden = allObjectPermissions.filter((permission) => !object.required.has(permission));
      observed.push(
        expected !== "none"
          ? [...object.required].every((permission) => permissions.has(permission)) &&
            forbidden.every((permission) => !permissions.has(permission))
          : allObjectPermissions.every((permission) => !permissions.has(permission)),
      );
    }
    if (observed.every(Boolean)) return;
    await sleep(Math.min(2 ** attempt, 12) * 1_000);
  }
  throw new Error(
    expected !== "none"
      ? "The executor state lease did not propagate before the deadline."
      : "The executor retained state permissions after exact lease cleanup.",
  );
}

export async function waitForControlPermissions(
  invocation: Invocation,
  executorToken: string,
  expected: "mutation" | "none" | "read",
  fetcher: Fetcher,
  sleep: (milliseconds: number) => Promise<void> = (milliseconds) => Bun.sleep(milliseconds),
): Promise<void> {
  const contract = REPOSITORIES[invocation.repository];
  const projectPermissions = executorControlPermissions(
    invocation.repository,
    invocation.terraformRoot,
    "mutation",
  );
  const requiredPermissions = new Set(expected === "mutation"
    ? projectPermissions
    : expected === "read"
    ? executorControlPermissions(invocation.repository, invocation.terraformRoot, "read")
    : []);
  for (let attempt = 0; attempt < 7; attempt += 1) {
    const projectResponse = await fetcher(
      `https://cloudresourcemanager.googleapis.com/v1/projects/${contract.projectId}:testIamPermissions`,
      {
        body: JSON.stringify({ permissions: projectPermissions }),
        headers: { ...executorHeaders(executorToken), "Content-Type": "application/json" },
        method: "POST",
        redirect: "error",
      },
    );
    if (!projectResponse.ok &&
      !(expected === "none" && permissionDenialProvesNoUsableCredential(projectResponse))) {
      throw new Error(`Project permission test failed with HTTP ${projectResponse.status}.`);
    }
    let projectMatches = true;
    if (projectResponse.ok) {
      const projectValue = record(
        await boundedJson(projectResponse, 64 * 1024),
        "project permission test",
      );
      exactKeys(projectValue, new Set(["permissions"]), "project permission test");
      const granted = new Set(
        array(projectValue.permissions ?? [], "project permissions").map((entry) =>
          requiredString(entry, "project permission")
        ),
      );
      projectMatches = projectPermissions.every((permission) =>
        granted.has(permission) === requiredPermissions.has(permission)
      );
    }

    let actAsMatches = true;
    if (invocation.terraformRoot === "prod") {
      for (const email of runtimeServiceAccountEmails(invocation.repository)) {
        const response = await fetcher(`${serviceAccountUrl(email)}:testIamPermissions`, {
          body: JSON.stringify({ permissions: ["iam.serviceAccounts.actAs"] }),
          headers: { ...executorHeaders(executorToken), "Content-Type": "application/json" },
          method: "POST",
          redirect: "error",
        });
        if (!response.ok &&
          !(expected === "none" && permissionDenialProvesNoUsableCredential(response))) {
          throw new Error(`Runtime actAs permission test failed with HTTP ${response.status}.`);
        }
        if (!response.ok) continue;
        const value = record(await boundedJson(response, 64 * 1024), "runtime permission test");
        exactKeys(value, new Set(["permissions"]), "runtime permission test");
        const permissions = new Set(
          array(value.permissions ?? [], "runtime permissions").map((entry) =>
            requiredString(entry, "runtime permission")
          ),
        );
        if ((expected === "mutation") !== permissions.has("iam.serviceAccounts.actAs")) {
          actAsMatches = false;
        }
      }
    }
    if (projectMatches && actAsMatches) return;
    await sleep(Math.min(2 ** attempt, 12) * 1_000);
  }
  throw new Error(
    expected !== "none"
      ? "The executor control-plane lease did not propagate before the deadline."
      : "The executor token retained control-plane or runtime actAs permissions after cleanup.",
  );
}

function permissionDenialProvesNoUsableCredential(response: Response): boolean {
  return response.status === 401 || response.status === 403;
}

function executorHeaders(token: string): Record<string, string> {
  return { Accept: "application/json", Authorization: `Bearer ${token}` };
}

function encodeResourcePath(value: string): string {
  return value.split("/").map((part) => encodeURIComponent(part)).join("/");
}

interface PlanReceipt {
  readonly consumerSha: string;
  readonly consumerTreeSha: string;
  readonly createdAt: string;
  readonly dhiParityId: string;
  readonly expiresAt: string;
  readonly freezeProof: ConsumerFreezeProof;
  readonly legacyCompatibilityMode: boolean;
  readonly manifestSha256: string;
  readonly maxMutatorTokenLifetimeSeconds: number;
  readonly markerProof: readonly MarkerStateProof[];
  readonly mode: "plan";
  readonly planRunId: string;
  readonly platformSha: string;
  readonly projectId: string;
  readonly repository: RepositoryName;
  readonly repositoryId: string;
  readonly schemaVersion: 3;
  readonly terraformRoot: TerraformRoot;
  readonly tokenDrainSeconds: number;
  readonly transitionWorkflowSha: string;
}

export async function publishPlanReceipt(
  invocation: Invocation,
  executorToken: string,
  review: ReviewManifestResult,
  proof: ExecutionProof,
  nowMs: number,
  fetcher: Fetcher,
): Promise<void> {
  if (invocation.mode !== "plan") throw new Error("Only plan mode may publish a plan receipt.");
  const contract = REPOSITORIES[invocation.repository];
  const state = contract.state[invocation.terraformRoot];
  const receipt: PlanReceipt = {
    consumerSha: invocation.consumerSha,
    consumerTreeSha: proof.consumerTreeSha,
    createdAt: new Date(nowMs).toISOString(),
    dhiParityId: proof.dhiParityId,
    expiresAt: new Date(nowMs + APPROVAL_FRESHNESS_MINUTES * 60_000).toISOString(),
    freezeProof: normalizedFreezeProof(proof.freezeProof, proof.tokenDrainSeconds),
    legacyCompatibilityMode: invocation.legacyCompatibilityMode,
    manifestSha256: review.sha256,
    maxMutatorTokenLifetimeSeconds: proof.maxMutatorTokenLifetimeSeconds,
    markerProof: markerProofForReceipt(proof.markerProof, invocation),
    mode: "plan",
    planRunId: invocation.githubRunId,
    platformSha: invocation.platformSha,
    projectId: contract.projectId,
    repository: invocation.repository,
    repositoryId: contract.repositoryId,
    schemaVersion: 3,
    terraformRoot: invocation.terraformRoot,
    tokenDrainSeconds: proof.tokenDrainSeconds,
    transitionWorkflowSha: invocation.transitionWorkflowSha,
  };
  await writeImmutableObject(
    state.bucket,
    receiptObjectName(state, "plans", invocation.githubRunId),
    `${canonicalJson(json(receipt, "plan receipt"))}\n`,
    executorToken,
    fetcher,
  );
}

export async function verifyPlanApproval(
  invocation: Invocation,
  executorToken: string,
  proof: ExecutionProof,
  nowMs: number,
  fetcher: Fetcher,
): Promise<ReviewManifestResult> {
  if (invocation.mode !== "apply") throw new Error("Only apply mode may verify a plan approval.");
  await verifyPlanRun(invocation, nowMs, fetcher);
  const contract = REPOSITORIES[invocation.repository];
  const state = contract.state[invocation.terraformRoot];
  const raw = await readObject(
    state.bucket,
    receiptObjectName(state, "plans", invocation.approvedPlanRunId),
    executorToken,
    fetcher,
  );
  let value: unknown;
  try {
    value = JSON.parse(raw) as unknown;
  } catch {
    throw new Error("The approved plan receipt is malformed.");
  }
  const receipt = planReceipt(value);
  exact(receipt.planRunId, invocation.approvedPlanRunId, "approved plan receipt run ID");
  exact(receipt.manifestSha256, invocation.approvedManifestSha256, "approved digest");
  exact(receipt.platformSha, invocation.platformSha, "approved platform SHA");
  exact(receipt.consumerSha, invocation.consumerSha, "approved consumer SHA");
  exact(receipt.consumerTreeSha, proof.consumerTreeSha, "approved consumer tree SHA");
  exact(receipt.dhiParityId, proof.dhiParityId, "approved DHI parity ID");
  exact(
    receipt.legacyCompatibilityMode,
    invocation.legacyCompatibilityMode,
    "approved compatibility mode",
  );
  exact(receipt.projectId, contract.projectId, "approved project ID");
  exact(receipt.repository, invocation.repository, "approved repository");
  exact(receipt.repositoryId, contract.repositoryId, "approved repository ID");
  exact(receipt.terraformRoot, invocation.terraformRoot, "approved Terraform root");
  exact(
    receipt.maxMutatorTokenLifetimeSeconds,
    proof.maxMutatorTokenLifetimeSeconds,
    "approved mutator-token lifetime",
  );
  exact(
    canonicalJson(json(markerProofForReceipt(receipt.markerProof, invocation), "receipt markers")),
    canonicalJson(json(markerProofForReceipt(proof.markerProof, invocation), "current markers")),
    "approved deployment-parity marker proof",
  );
  exact(receipt.tokenDrainSeconds, proof.tokenDrainSeconds, "approved token-drain window");
  exact(receipt.transitionWorkflowSha, invocation.transitionWorkflowSha, "approved transition SHA");
  const createdAt = Date.parse(receipt.createdAt);
  const expiresAt = Date.parse(receipt.expiresAt);
  if (
    !Number.isFinite(createdAt) ||
    !Number.isFinite(expiresAt) ||
    createdAt > nowMs ||
    expiresAt <= nowMs ||
    expiresAt - createdAt !== APPROVAL_FRESHNESS_MINUTES * 60_000
  ) {
    throw new Error("The approved plan receipt is stale or has invalid timing.");
  }
  return { canonical: "", sha256: receipt.manifestSha256 };
}

export async function consumePlanReceipt(
  invocation: Invocation,
  executorToken: string,
  review: ReviewManifestResult,
  proof: ExecutionProof,
  nowMs: number,
  fetcher: Fetcher,
): Promise<void> {
  if (invocation.mode !== "apply") throw new Error("Only apply mode may consume a plan receipt.");
  const contract = REPOSITORIES[invocation.repository];
  const state = contract.state[invocation.terraformRoot];
  const consumed: JsonValue = {
    applyRunId: invocation.githubRunId,
    consumerSha: invocation.consumerSha,
    consumerTreeSha: proof.consumerTreeSha,
    consumedAt: new Date(nowMs).toISOString(),
    dhiParityId: proof.dhiParityId,
    freezeProof: json(
      normalizedFreezeProof(proof.freezeProof, proof.tokenDrainSeconds),
      "consumed receipt freeze proof",
    ),
    legacyCompatibilityMode: invocation.legacyCompatibilityMode,
    manifestSha256: review.sha256,
    maxMutatorTokenLifetimeSeconds: proof.maxMutatorTokenLifetimeSeconds,
    markerProof: json(
      markerProofForReceipt(proof.markerProof, invocation),
      "consumed receipt marker proof",
    ),
    mode: "apply",
    planRunId: invocation.approvedPlanRunId,
    platformSha: invocation.platformSha,
    projectId: contract.projectId,
    repository: invocation.repository,
    repositoryId: contract.repositoryId,
    schemaVersion: 3,
    terraformRoot: invocation.terraformRoot,
    tokenDrainSeconds: proof.tokenDrainSeconds,
    transitionWorkflowSha: invocation.transitionWorkflowSha,
  };
  await writeImmutableObject(
    state.bucket,
    receiptObjectName(state, "consumed", invocation.approvedPlanRunId),
    `${canonicalJson(consumed)}\n`,
    executorToken,
    fetcher,
  );
}

export async function publishPostApplyReceipt(
  invocation: Invocation,
  executorToken: string,
  review: ReviewManifestResult,
  proof: ExecutionProof,
  nowMs: number,
  fetcher: Fetcher,
): Promise<void> {
  if (invocation.mode !== "apply") {
    throw new Error("Only apply mode may publish a post-apply receipt.");
  }
  const contract = REPOSITORIES[invocation.repository];
  const state = contract.state[invocation.terraformRoot];
  const receipt: JsonValue = {
    applyRunId: invocation.githubRunId,
    consumerSha: invocation.consumerSha,
    consumerTreeSha: proof.consumerTreeSha,
    dhiParityId: proof.dhiParityId,
    freezeProof: json(
      normalizedFreezeProof(proof.freezeProof, proof.tokenDrainSeconds),
      "post-apply freeze proof",
    ),
    manifestSha256: review.sha256,
    markerProof: json(
      markerProofForReceipt(proof.markerProof, invocation),
      "post-apply marker proof",
    ),
    mode: "post-apply",
    planRunId: invocation.approvedPlanRunId,
    platformSha: invocation.platformSha,
    projectId: contract.projectId,
    publishedAt: new Date(nowMs).toISOString(),
    repository: invocation.repository,
    repositoryId: contract.repositoryId,
    schemaVersion: 3,
    terraformRoot: invocation.terraformRoot,
    tokenDrainSeconds: proof.tokenDrainSeconds,
    transitionWorkflowSha: invocation.transitionWorkflowSha,
  };
  await writeImmutableObject(
    state.bucket,
    receiptObjectName(state, "results", invocation.githubRunId),
    `${canonicalJson(receipt)}\n`,
    executorToken,
    fetcher,
  );
}

function planReceipt(value: unknown): PlanReceipt {
  const receipt = record(value, "plan receipt");
  exactKeys(
    receipt,
    new Set([
      "consumerSha",
      "consumerTreeSha",
      "createdAt",
      "dhiParityId",
      "expiresAt",
      "freezeProof",
      "legacyCompatibilityMode",
      "manifestSha256",
      "maxMutatorTokenLifetimeSeconds",
      "markerProof",
      "mode",
      "planRunId",
      "platformSha",
      "projectId",
      "repository",
      "repositoryId",
      "schemaVersion",
      "terraformRoot",
      "tokenDrainSeconds",
      "transitionWorkflowSha",
    ]),
    "plan receipt",
  );
  exact(receipt.schemaVersion, 3, "plan receipt schema");
  exact(receipt.mode, "plan", "plan receipt mode");
  if (typeof receipt.legacyCompatibilityMode !== "boolean") {
    throw new Error("Plan receipt compatibility mode is malformed.");
  }
  const transitionWorkflowSha = requiredStringOrEmpty(
    receipt.transitionWorkflowSha,
    "receipt transition workflow SHA",
  );
  if (transitionWorkflowSha !== "") sha(transitionWorkflowSha, "receipt transition workflow SHA");
  const terraformRoot = rootName(requiredString(receipt.terraformRoot, "receipt Terraform root"));
  if (receipt.legacyCompatibilityMode && transitionWorkflowSha !== "") {
    throw new Error("Plan receipt cannot combine legacy compatibility with a transition SHA.");
  }
  if (
    terraformRoot === "prod" &&
    (receipt.legacyCompatibilityMode || transitionWorkflowSha !== "")
  ) {
    throw new Error("Production plan receipt contains bootstrap migration controls.");
  }
  const markerProof = markerProofFromJson(
    receipt.markerProof,
    receipt.legacyCompatibilityMode,
  );
  const tokenDrainSeconds = (() => {
    const value = boundedInteger(
      receipt.tokenDrainSeconds,
      "receipt token-drain window",
      1,
      LEGACY_MUTATOR_TOKEN_SECONDS,
    );
    if (![300, LEGACY_MUTATOR_TOKEN_SECONDS].includes(value)) {
      throw new Error("Receipt token-drain window escaped the reviewed values.");
    }
    return value;
  })();
  return {
    consumerSha: sha(requiredString(receipt.consumerSha, "receipt consumer SHA"), "receipt consumer SHA"),
    consumerTreeSha: sha(
      requiredString(receipt.consumerTreeSha, "receipt consumer tree SHA"),
      "receipt consumer tree SHA",
    ),
    createdAt: requiredString(receipt.createdAt, "receipt creation time"),
    dhiParityId: (() => {
      const value = requiredString(receipt.dhiParityId, "receipt DHI parity ID");
      if (!/^[0-9a-z]{50}$/.test(value)) throw new Error("Receipt DHI parity ID is malformed.");
      return value;
    })(),
    expiresAt: requiredString(receipt.expiresAt, "receipt expiry time"),
    freezeProof: freezeProofFromJson(receipt.freezeProof, tokenDrainSeconds),
    legacyCompatibilityMode: receipt.legacyCompatibilityMode,
    manifestSha256: hash(
      requiredString(receipt.manifestSha256, "receipt manifest digest"),
      "receipt manifest digest",
    ),
    mode: "plan",
    maxMutatorTokenLifetimeSeconds: (() => {
      const value = boundedInteger(
        receipt.maxMutatorTokenLifetimeSeconds,
        "receipt mutator-token lifetime",
        1,
        LEGACY_MUTATOR_TOKEN_SECONDS,
      );
      exact(value, 300, "receipt mutator-token lifetime");
      return value;
    })(),
    markerProof,
    planRunId: numeric(requiredString(receipt.planRunId, "receipt plan run ID"), "receipt plan run ID"),
    platformSha: sha(requiredString(receipt.platformSha, "receipt platform SHA"), "receipt platform SHA"),
    projectId: requiredString(receipt.projectId, "receipt project ID"),
    repository: repositoryName(requiredString(receipt.repository, "receipt repository")),
    repositoryId: numeric(requiredString(receipt.repositoryId, "receipt repository ID"), "receipt repository ID"),
    schemaVersion: 3,
    terraformRoot,
    tokenDrainSeconds,
    transitionWorkflowSha,
  };
}

async function verifyPlanRun(
  invocation: Invocation,
  nowMs: number,
  fetcher: Fetcher,
): Promise<void> {
  const base = `https://api.github.com/repos/${PLATFORM_REPOSITORY}`;
  const run = record(
    await githubJson(
      `${base}/actions/runs/${invocation.approvedPlanRunId}`,
      invocation.platformActionsToken,
      fetcher,
    ),
    "approved GitHub plan run",
  );
  exact(String(run.id), invocation.approvedPlanRunId, "approved GitHub run ID");
  exact(String(run.run_attempt), "1", "approved GitHub run attempt");
  exact(run.event, "workflow_dispatch", "approved GitHub event");
  exact(run.status, "completed", "approved GitHub run status");
  exact(run.conclusion, "success", "approved GitHub run conclusion");
  exact(run.head_sha, invocation.platformSha, "approved GitHub head SHA");
  exact(run.head_branch, "main", "approved GitHub head branch");
  const actor = record(run.actor, "approved GitHub actor");
  exact(String(actor.id), PLATFORM_OWNER_ID, "approved GitHub actor ID");
  const repository = record(run.repository, "approved GitHub repository");
  exact(String(repository.id), PLATFORM_REPOSITORY_ID, "approved GitHub repository ID");
  const workflowId = numeric(String(run.workflow_id), "approved workflow ID");
  const workflow = record(
    await githubJson(
      `${base}/actions/workflows/${workflowId}`,
      invocation.platformActionsToken,
      fetcher,
    ),
    "approved GitHub workflow",
  );
  exact(
    workflow.path,
    ".github/workflows/protected-bootstrap-implementation.yml",
    "approved workflow path",
  );
  const createdAt = Date.parse(requiredString(run.created_at, "approved run creation time"));
  const updatedAt = Date.parse(requiredString(run.updated_at, "approved run update time"));
  if (
    !Number.isFinite(createdAt) ||
    !Number.isFinite(updatedAt) ||
    createdAt > updatedAt ||
    updatedAt > nowMs ||
    nowMs - createdAt > APPROVAL_FRESHNESS_MINUTES * 60_000
  ) {
    throw new Error("The approved GitHub plan run is not fresh.");
  }
  if (BigInt(invocation.approvedPlanRunId) >= BigInt(invocation.githubRunId)) {
    throw new Error("The approved plan run must precede the apply run.");
  }
}

async function writeImmutableObject(
  bucket: string,
  object: string,
  body: string,
  token: string,
  fetcher: Fetcher,
): Promise<void> {
  if (Buffer.byteLength(body) > 32 * 1024) throw new Error("Receipt exceeded its size bound.");
  const url = new URL(`https://storage.googleapis.com/upload/storage/v1/b/${bucket}/o`);
  url.searchParams.set("uploadType", "media");
  url.searchParams.set("name", object);
  url.searchParams.set("ifGenerationMatch", "0");
  const response = await fetcher(url, {
    body,
    headers: {
      ...executorHeaders(token),
      "Content-Type": "application/json; charset=utf-8",
    },
    method: "POST",
    redirect: "error",
  });
  if (response.status === 409 || response.status === 412) {
    throw new Error("The immutable plan receipt was already consumed or published.");
  }
  if (!response.ok) throw new Error(`Receipt upload failed with HTTP ${response.status}.`);
  await boundedJson(response, 256 * 1024);
  const observed = await readObject(bucket, object, token, fetcher);
  if (observed !== body) throw new Error("Immutable receipt readback was not byte-equivalent.");
}

async function readObject(
  bucket: string,
  object: string,
  token: string,
  fetcher: Fetcher,
): Promise<string> {
  const url = new URL(
    `https://storage.googleapis.com/storage/v1/b/${bucket}/o/${encodeURIComponent(object)}`,
  );
  url.searchParams.set("alt", "media");
  const response = await fetcher(url, {
    headers: executorHeaders(token),
    redirect: "error",
  });
  if (!response.ok) throw new Error(`Receipt read failed with HTTP ${response.status}.`);
  return boundedText(response, 32 * 1024);
}

function receiptObjectName(
  state: { readonly prefix: string },
  kind: "consumed" | "plans" | "results",
  runId: string,
): string {
  numeric(runId, "receipt run ID");
  return `${state.prefix}/.protected-bootstrap/${kind}/${runId}.json`;
}

async function githubJson(url: string, token: string, fetcher: Fetcher): Promise<unknown> {
  if (!url.startsWith("https://api.github.com/repos/collinbentley1/")) {
    throw new Error("GitHub API URL escaped the closed repository allowlist.");
  }
  const response = await fetcher(url, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
    },
    redirect: "error",
  });
  if (!response.ok) throw new Error(`GitHub freeze proof failed with HTTP ${response.status}.`);
  return boundedJson(response, 4 * 1024 * 1024);
}

async function boundedJson(response: Response, maximumBytes: number): Promise<unknown> {
  const value = await boundedText(response, maximumBytes);
  try {
    return JSON.parse(value) as unknown;
  } catch {
    throw new Error("API response was not valid JSON.");
  }
}

async function boundedText(response: Response, maximumBytes: number): Promise<string> {
  const value = await response.text();
  if (Buffer.byteLength(value) > maximumBytes) throw new Error("API response exceeded its bound.");
  return value;
}

export function deadlineFetcher(
  fetcher: Fetcher,
  deadline: () => number,
  maximumRequestMs = 20_000,
): Fetcher {
  return async (input, init = {}) => {
    const remainingMs = Math.min(maximumRequestMs, deadline() - Date.now());
    if (!Number.isFinite(remainingMs) || remainingMs <= 0) {
      throw new Error("API request reached the protected operation deadline.");
    }
    const controller = new AbortController();
    const upstream = init.signal;
    const abortFromUpstream = () => controller.abort(upstream?.reason);
    if (upstream?.aborted) controller.abort(upstream.reason);
    upstream?.addEventListener("abort", abortFromUpstream, { once: true });
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort(new Error("Protected API request timed out."));
        reject(new Error("Protected API request timed out before exact cleanup."));
      }, remainingMs);
    });
    try {
      return await Promise.race([
        fetcher(input, { ...init, signal: controller.signal }).then((response) =>
          bufferApiResponse(response, controller, MAX_API_RESPONSE_BYTES)
        ),
        timeout,
      ]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      upstream?.removeEventListener("abort", abortFromUpstream);
    }
  };
}

async function bufferApiResponse(
  response: Response,
  controller: AbortController,
  maximumBytes: number,
): Promise<Response> {
  if (response.body === null) {
    return new Response(null, {
      headers: response.headers,
      status: response.status,
      statusText: response.statusText,
    });
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximumBytes) {
        controller.abort(new Error("API response exceeded its global bound."));
        await reader.cancel("API response exceeded its global bound.").catch(() => undefined);
        throw new Error("API response exceeded its global bound.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new Response(body, {
    headers: response.headers,
    status: response.status,
    statusText: response.statusText,
  });
}

function googleHeaders(token: string): Record<string, string> {
  return {
    Accept: "application/json",
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };
}

function iamPolicy(value: unknown): IamPolicy {
  const policy = record(value, "IAM policy");
  exactKeys(
    policy,
    new Set(["auditConfigs", "bindings", "etag", "version"]),
    "IAM policy",
  );
  const etag = requiredString(policy.etag, "IAM etag");
  const version = Number(policy.version ?? 1);
  if (!Number.isInteger(version) || version < 1 || version > 3) {
    throw new Error("IAM policy version is outside the reviewed range.");
  }
  const bindings = array(policy.bindings ?? [], "IAM bindings").map((value) => {
    const binding = record(value, "IAM binding");
    exactKeys(binding, new Set(["condition", "members", "role"]), "IAM binding");
    const members = array(binding.members, "IAM members").map((member) =>
      requiredString(member, "IAM member"),
    );
    const conditionValue = binding.condition;
    let condition: IamBinding["condition"];
    if (conditionValue !== undefined) {
      const parsed = record(conditionValue, "IAM condition");
      exactKeys(
        parsed,
        new Set(["description", "expression", "location", "title"]),
        "IAM condition",
      );
      condition = {
        ...(parsed.description === undefined
          ? {}
          : { description: requiredString(parsed.description, "IAM condition description") }),
        expression: requiredString(parsed.expression, "IAM condition expression"),
        ...(parsed.location === undefined
          ? {}
          : { location: requiredString(parsed.location, "IAM condition location") }),
        title: requiredString(parsed.title, "IAM condition title"),
      };
    }
    return {
      ...(condition === undefined ? {} : { condition }),
      members,
      role: requiredString(binding.role, "IAM role"),
    };
  });
  const auditConfigs =
    policy.auditConfigs === undefined
      ? undefined
      : array(policy.auditConfigs, "IAM audit configs").map((entry) =>
          json(entry, "IAM audit config"),
        );
  return {
    ...(auditConfigs === undefined ? {} : { auditConfigs }),
    bindings,
    etag,
    version,
  };
}

function bindingEqualsLease(binding: IamBinding, lease: IamBinding): boolean {
  return (
    binding.role === lease.role &&
    canonicalJson(binding.members.map((member) => member).toSorted()) ===
      canonicalJson(lease.members.map((member) => member).toSorted()) &&
    lease.condition !== undefined &&
    binding.condition?.title === lease.condition.title &&
    binding.condition.expression === lease.condition.expression &&
    binding.condition.description === lease.condition.description &&
    binding.condition.location === undefined
  );
}

function normalizeChanges(value: unknown, identity: PlanIdentity, label: string): JsonValue[] {
  const root = identity.terraformRoot;
  const allowedTypes = root === "bootstrap" ? BOOTSTRAP_RESOURCE_TYPES : PROD_RESOURCE_TYPES;
  const modulePrefix = root === "bootstrap" ? "module.bootstrap." : "module.site.";
  const targetMarker = identity.markerProof.find((marker) => marker.repository === identity.repository);
  if (targetMarker === undefined) throw new Error("The target deployment-parity marker proof is missing.");
  let markerObjectSeen = false;
  const result = array(value ?? [], `Terraform ${label}s`)
    .map((entry) => {
      const change = record(entry, `Terraform ${label}`);
      exactKeys(
        change,
        new Set([
          "action_reason",
          "address",
          "change",
          "deposed",
          "index",
          "mode",
          "module_address",
          "name",
          "previous_address",
          "provider_name",
          "type",
        ]),
        `Terraform ${label}`,
      );
      const address = requiredString(change.address, `${label} address`);
      const mode = requiredString(change.mode, `${label} mode`);
      const type = requiredString(change.type, `${label} type`);
      const forgetOnly = root === "prod" && PROD_FORGET_ONLY_ADDRESSES.some((pattern) =>
        pattern.test(address)
      );
      const moduleAddress = requiredString(change.module_address, `${label} module address`);
      if (moduleAddress !== modulePrefix.slice(0, -1)) {
        throw new Error(`Terraform ${label} escaped the exact root module.`);
      }
      if (mode === "data") {
        if (root !== "bootstrap" || type !== "google_project" || !address.startsWith(modulePrefix)) {
          throw new Error(`Terraform ${label} contains an unreviewed data source.`);
        }
      } else if (
        mode !== "managed" ||
        !address.startsWith(modulePrefix) ||
        (!allowedTypes.has(type) && !forgetOnly)
      ) {
        throw new Error(`Terraform ${label} ${address} escaped the root resource allowlist.`);
      }
      exact(change.provider_name, "registry.terraform.io/hashicorp/google", `${label} provider`);
      const delta = record(change.change, `${label} delta`);
      exactKeys(
        delta,
        new Set([
          "actions",
          "after",
          "after_identity",
          "after_sensitive",
          "after_unknown",
          "before",
          "before_identity",
          "before_sensitive",
          "generated_config",
          "importing",
          "replace_paths",
        ]),
        `${label} delta`,
      );
      if (delta.importing !== undefined || delta.generated_config !== undefined) {
        throw new Error("Terraform import and generated configuration are outside this bridge.");
      }
      rejectSensitive(delta.before_sensitive, `${label} before-sensitive map`);
      rejectSensitive(delta.after_sensitive, `${label} after-sensitive map`);
      const actions = array(delta.actions, `${label} actions`).map((action) =>
        requiredString(action, `${label} action`),
      );
      const allowedActionSets = new Set([
        "create",
        "create,delete",
        "delete",
        "delete,create",
        "forget",
        "no-op",
        "read",
        "update",
      ]);
      if (!allowedActionSets.has(actions.join(","))) {
        throw new Error(`Terraform ${label} has an unreviewed action sequence.`);
      }
      if (type === "google_storage_bucket_object") {
        markerObjectSeen = true;
        validateDeploymentParityMarkerChange(
          address,
          actions,
          delta,
          identity,
          targetMarker,
          label,
        );
      }
      if (forgetOnly) {
        if (
          actions.length !== 1 ||
          actions[0] !== "forget" ||
          change.action_reason !== "delete_because_no_resource_config" ||
          delta.after !== null
        ) {
          throw new Error("A legacy production resource may only leave Terraform state.");
        }
      } else if (actions.includes("forget")) {
        throw new Error("Terraform may forget only the exact retired production addresses.");
      }
      const previousAddress =
        change.previous_address === undefined
          ? null
          : requiredString(change.previous_address, `${label} previous address`);
      if (previousAddress !== null && !previousAddress.startsWith(modulePrefix)) {
        throw new Error(`Terraform ${label} previous address escaped the exact root module.`);
      }
      return {
        actionReason:
          change.action_reason === undefined
            ? null
            : requiredString(change.action_reason, `${label} action reason`),
        actions,
        address,
        afterIdentitySha256: hashJson(json(delta.after_identity ?? null, `${label} after identity`)),
        afterSha256: hashJson(json(delta.after ?? null, `${label} after`)),
        afterUnknownSha256: hashJson(json(delta.after_unknown ?? false, `${label} after unknown`)),
        beforeIdentitySha256: hashJson(json(delta.before_identity ?? null, `${label} before identity`)),
        beforeSha256: hashJson(json(delta.before ?? null, `${label} before`)),
        deposedSha256: hashJson(json(change.deposed ?? null, `${label} deposed key`)),
        indexSha256: hashJson(json(change.index ?? null, `${label} index`)),
        mode,
        moduleAddress,
        name: requiredString(change.name, `${label} name`),
        previousAddress,
        provider: "registry.terraform.io/hashicorp/google",
        replacePathsSha256: hashJson(json(delta.replace_paths ?? [], `${label} replace paths`)),
        type,
      } satisfies JsonValue;
    })
    .filter((change) => canonicalJson(change.actions) !== '["no-op"]')
    .toSorted((left, right) => String(left.address).localeCompare(String(right.address)));
  if (label === "resource change" && root === "bootstrap" && targetMarker.state === "absent" && !markerObjectSeen) {
    throw new Error("Initial bootstrap did not create the exact deployment-parity marker object.");
  }
  return result;
}

function validateDeploymentParityMarkerChange(
  address: string,
  actions: readonly string[],
  delta: Record<string, unknown>,
  identity: PlanIdentity,
  targetMarker: MarkerStateProof,
  label: string,
): void {
  exact(
    address,
    "module.bootstrap.google_storage_bucket_object.deployment_parity_transition",
    `${label} deployment-parity marker address`,
  );
  if (label === "resource drift") {
    throw new Error("Terraform reported deployment-parity marker drift outside the reviewed API proof.");
  }
  const action = actions.join(",");
  if (targetMarker.state === "absent") {
    exact(action, "create", "initial deployment-parity marker action");
    exact(delta.before, null, "initial deployment-parity marker prior value");
  } else if (!new Set(["no-op", "read", "update"]).has(action)) {
    throw new Error("An existing deployment-parity marker has a destructive action.");
  }
  const after = record(delta.after, "deployment-parity marker after value");
  const contract = REPOSITORIES[identity.repository];
  exact(
    after.bucket,
    `${contract.projectId}${DEPLOYMENT_PARITY_BUCKET_SUFFIX}`,
    "deployment-parity marker bucket",
  );
  exact(after.name, DEPLOYMENT_PARITY_MARKER_OBJECT, "deployment-parity marker object");
  exact(after.content, "{\"version\":1}\n", "deployment-parity marker content");
  exact(after.content_type, "application/json", "deployment-parity marker content type");
  const metadata = record(after.metadata, "deployment-parity marker planned metadata");
  exactKeys(
    metadata,
    new Set(["repository-id", "state", "version"]),
    "deployment-parity marker planned metadata",
  );
  exact(metadata.version, "1", "deployment-parity marker planned metadata version");
  exact(
    metadata["repository-id"],
    contract.repositoryId,
    "deployment-parity marker planned repository ID",
  );
  exact(metadata.state, "clear", "deployment-parity marker planned state");
  const unknown = record(delta.after_unknown ?? {}, "deployment-parity marker unknown map");
  for (const key of ["bucket", "content", "content_type", "metadata", "name"]) {
    if (unknown[key] === true) {
      throw new Error(`The deployment-parity marker ${key} is unknown in the reviewed plan.`);
    }
  }
  const replacePaths = array(delta.replace_paths ?? [], "deployment-parity marker replace paths");
  if (replacePaths.length !== 0) {
    throw new Error("The deployment-parity marker may not be replaced.");
  }
}

function normalizeOutputChanges(value: unknown): JsonValue {
  const outputs = record(value ?? {}, "Terraform output changes");
  return Object.fromEntries(
    Object.entries(outputs).toSorted(([left], [right]) => left.localeCompare(right)).map(([name, raw]) => {
      safeName(name, "Terraform output name");
      const change = record(raw, `Terraform output ${name}`);
      exactKeys(
        change,
        new Set([
          "actions",
          "after",
          "after_sensitive",
          "after_unknown",
          "before",
          "before_sensitive",
        ]),
        `Terraform output ${name}`,
      );
      rejectSensitive(change.before_sensitive, `Terraform output ${name} before-sensitive map`);
      rejectSensitive(change.after_sensitive, `Terraform output ${name} after-sensitive map`);
      return [
        name,
        {
          actions: json(change.actions ?? [], `Terraform output ${name} actions`),
          afterSha256: hashJson(json(change.after ?? null, `Terraform output ${name} after`)),
          afterUnknownSha256: hashJson(
            json(change.after_unknown ?? false, `Terraform output ${name} after unknown`),
          ),
          beforeSha256: hashJson(json(change.before ?? null, `Terraform output ${name} before`)),
        } satisfies JsonValue,
      ];
    }),
  );
}

function normalizeNamedHashes(value: unknown, label: string): JsonValue {
  const entries = record(value, `${label}s`);
  return Object.fromEntries(
    Object.entries(entries)
      .toSorted(([left], [right]) => left.localeCompare(right))
      .map(([name, raw]) => {
        safeName(name, `${label} name`);
        return [name, hashJson(json(raw, label))];
      }),
  );
}

function hashJson(value: JsonValue): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function safeName(value: string, label: string): string {
  if (!/^[A-Za-z][A-Za-z0-9_-]{0,127}$/.test(value)) {
    throw new Error(`${label} escaped the safe name grammar.`);
  }
  return value;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function rejectSensitive(value: unknown, label: string): void {
  if (value === true) throw new Error(`${label} contains a sensitive value.`);
  if (Array.isArray(value)) {
    for (const entry of value) rejectSensitive(entry, label);
  } else if (value !== null && typeof value === "object") {
    for (const entry of Object.values(value)) rejectSensitive(entry, label);
  }
}

function reviewSummary(
  invocation: Invocation,
  review: ReviewManifestResult,
  approvedPlanRunId: string | undefined,
): string {
  const heading = invocation.mode === "plan" ? "Protected Terraform plan" : "Protected Terraform apply";
  const summary = [
    `## ${heading}`,
    "",
    `- Target: \`${invocation.repository}\` / \`${invocation.terraformRoot}\``,
    `- Consumer commit: \`${invocation.consumerSha}\``,
    `- Platform commit: \`${invocation.platformSha}\``,
    `- Review digest: \`${review.sha256}\``,
    ...(approvedPlanRunId === undefined
      ? [`- Plan run: \`${invocation.githubRunId}\` (fresh receipt required for apply)`]
      : [`- Consumed plan run: \`${approvedPlanRunId}\` (single use)`]),
    "",
    "The canonical manifest contains only allowlisted identities, actions, counts, and SHA-256 commitments. It contains no raw before/after values, variables, outputs, plan, or state.",
    "",
    "<pre>",
    escapeHtml(review.canonical.trimEnd()),
    "</pre>",
    "",
  ].join("\n");
  return `${summary}\n`;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function json(value: unknown, label: string): JsonValue {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return value;
  }
  if (Array.isArray(value)) return value.map((entry) => json(entry, label));
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, json(entry, label)]),
    );
  }
  throw new Error(`${label} is not JSON.`);
}

function exactKeys(value: Record<string, unknown>, allowed: Set<string>, label: string): void {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new Error(`${label} contains unreviewed field ${key}.`);
  }
}

function required(source: NodeJS.ProcessEnv, name: string): string {
  return requiredString(source[name], name);
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0 || value.includes("\n") || value.includes("\r")) {
    throw new Error(`${label} must be one non-empty line.`);
  }
  return value;
}

function requiredStringOrEmpty(value: unknown, label: string): string {
  if (typeof value !== "string" || value.includes("\n") || value.includes("\r")) {
    throw new Error(`${label} must be one line.`);
  }
  return value;
}

function boundedInteger(
  value: unknown,
  label: string,
  minimum: number,
  maximum: number,
): number {
  const parsed = typeof value === "number" ? value : Number.NaN;
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${label} escaped its integer bound.`);
  }
  return parsed;
}

function assertBeforeDeadline(nowMs: number, deadlineMs: number, label: string): void {
  if (!Number.isFinite(nowMs) || !Number.isFinite(deadlineMs) || nowMs >= deadlineMs) {
    throw new Error(`${label} reached the hard protected-operation deadline.`);
  }
}

function assertSession(
  session: ExecutorSession,
  nowMs: number,
  operationDeadlineMs: number,
): void {
  if (session.accessToken.length < 20 || session.accessToken.length > 4_096) {
    throw new Error("Executor session token has an invalid length.");
  }
  assertBeforeDeadline(nowMs, operationDeadlineMs, "executor session");
  if (session.tokenExpiresAtMs < operationDeadlineMs + 60_000) {
    throw new Error("Executor token does not cover the internal operation deadline.");
  }
}

function assertPreApplyTime(
  nowMs: number,
  operationDeadlineMs: number,
  leaseExpiresAtMs: number,
  tokenExpiresAtMs: number,
): void {
  const requiredUntil = nowMs + MINIMUM_PRE_APPLY_MINUTES * 60_000;
  if (
    requiredUntil >= operationDeadlineMs ||
    requiredUntil >= leaseExpiresAtMs ||
    requiredUntil >= tokenExpiresAtMs
  ) {
    throw new Error("Too little operation, IAM-lease, or executor-token lifetime remains to apply.");
  }
}

function secret(source: NodeJS.ProcessEnv, name: string): string {
  return secretValue(required(source, name), name);
}

function secretValue(value: string, label: string): string {
  requiredString(value, label);
  if (value.length < 20 || value.length > 4_096) {
    throw new Error(`${label} has an invalid length.`);
  }
  return value;
}

function exact(actual: unknown, expected: unknown, label: string): void {
  if (actual !== expected) throw new Error(`${label} drifted from the reviewed value.`);
}

function sha(value: string, label: string): string {
  if (!/^[0-9a-f]{40}$/.test(value)) throw new Error(`${label} must be one full lowercase SHA.`);
  return value;
}

function hash(value: string, label: string): string {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error(`${label} must be one lowercase SHA-256.`);
  return value;
}

function numeric(value: string, label: string): string {
  if (!/^[1-9][0-9]*$/.test(value)) throw new Error(`${label} must be a positive integer.`);
  return value;
}

function repositoryName(value: string): RepositoryName {
  if (!REPOSITORY_NAMES.some((name) => name === value)) {
    throw new Error("Target repository escaped the closed allowlist.");
  }
  return value as RepositoryName;
}

function rootName(value: string): TerraformRoot {
  if (value !== "bootstrap" && value !== "prod") {
    throw new Error("Terraform root escaped the closed allowlist.");
  }
  return value;
}

function executionMode(value: string): ExecutionMode {
  if (value !== "plan" && value !== "apply") {
    throw new Error("Execution mode escaped the closed allowlist.");
  }
  return value;
}

function booleanString(value: string, label: string): boolean {
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${label} must be exactly true or false.`);
}

function safeAbsoluteDirectory(value: string, label: string): string {
  return safeAbsolutePath(value, label);
}

function safeAbsolutePath(value: string, label: string): string {
  if (!value.startsWith("/") || value.includes("\0") || resolve(value) !== value) {
    throw new Error(`${label} must be one normalized absolute path.`);
  }
  return value;
}

async function requireRealDirectory(path: string, label: string): Promise<void> {
  const metadata = await lstat(path).catch(() => undefined);
  if (metadata === undefined || !metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`${label} must be one real directory.`);
  }
}

async function ensurePrivateDirectory(path: string): Promise<void> {
  await mkdir(path, { mode: 0o700, recursive: true });
  await requireRealDirectory(path, "Terraform sandbox directory");
  await chmod(path, 0o700);
}

async function requireRegularFile(path: string, label: string): Promise<void> {
  const metadata = await lstat(path).catch(() => undefined);
  if (metadata === undefined || !metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} must be one regular file.`);
  }
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
  return value as Record<string, unknown>;
}

function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array.`);
  return value;
}

if (import.meta.main) {
  const argumentsAfterScript = process.argv.slice(2);
  if (argumentsAfterScript.length === 0) {
    await main();
  } else if (
    argumentsAfterScript.length === 1 &&
    argumentsAfterScript[0] === "--recover-only"
  ) {
    await recoveryMain();
  } else {
    throw new Error("Protected bridge received an unknown operation.");
  }
}
