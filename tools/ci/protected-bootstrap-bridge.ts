import { createHash, randomBytes, randomUUID } from "node:crypto";
import { closeSync, readFileSync, readSync } from "node:fs";
import {
  connect as connectHttp2,
  constants as http2Constants,
  type ClientHttp2Session,
} from "node:http2";
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
const RUNSETTA_EXPOSURE_ADOPTION_CONFIRMATION = "ADOPT_RUNSETTA_EXPOSURE_STATE";
const OWNER_MEMBER = "user:CollinBentley1@gmail.com";
const EXECUTOR_ACCOUNT_PREFIX = "gha-pbt-";
const EXECUTOR_ROLE_PREFIX = "pbt_";
const EXECUTOR_DISPLAY_NAME = "Protected Terraform Executor";
const EXECUTOR_DESCRIPTION_VERSION = "pbt-v2";
const LEGACY_EXECUTOR_DESCRIPTION_VERSION = "pbt-v1";
const EXECUTOR_DESCRIPTION_MAX_BYTES = 256;
const EXECUTOR_PROVENANCE_NUMERIC_MAX_DIGITS = 20;
const TERRAFORM_SANDBOX_IMAGE =
  "docker.io/oven/bun@sha256:8aac45197595035f697ea6b11cd73ce2401d82503fcb2540b5fac606973b242b";
const TERRAFORM_VERSION = "1.14.5";
const GOOGLE_PROVIDER_VERSION = "7.45.0";
const GOOGLE_PROVIDER_LINUX_AMD64_ZH =
  "fb1b9d1ea7bc79b7409f02aa7c19ba39afa22dbead69e83ae7eb2691ac5c2426";
const GOOGLE_PROVIDER_BINARY = "terraform-provider-google_v7.45.0_x5";
const GOOGLE_PROVIDER_MIRROR_COMPONENTS = [
  "registry.terraform.io",
  "hashicorp",
  "google",
  GOOGLE_PROVIDER_VERSION,
  "linux_amd64",
] as const;
const PLAN_FORMAT_VERSION = "1.2";
const JOB_TIMEOUT_MINUTES = 41;
const PLAN_MAIN_STEP_TIMEOUT_MINUTES = 25;
const APPLY_MAIN_STEP_TIMEOUT_MINUTES = 39;
const LEASE_MINUTES = 54;
const PLAN_INTERNAL_OPERATION_MINUTES = 24;
const APPLY_INTERNAL_OPERATION_MINUTES = 33;
const RECOVERY_DOCUMENTED_PROPAGATION_MINUTES = 7;
const RECOVERY_STABLE_EMPTY_MINUTES = 3;
const RECOVERY_SCAN_INTERVAL_MINUTES = 1;
const RECOVERY_SCAN_LATENCY_MARGIN_MINUTES = 1;
const RECOVERY_LATE_RETRY_MARGIN_MINUTES = 1;
const RECOVERY_OPERATION_MINUTES = RECOVERY_DOCUMENTED_PROPAGATION_MINUTES +
  RECOVERY_STABLE_EMPTY_MINUTES + RECOVERY_SCAN_LATENCY_MARGIN_MINUTES +
  RECOVERY_LATE_RETRY_MARGIN_MINUTES;
const RECOVERY_SOURCE_PROOF_MINUTES = 1;
const RECOVERY_WATCHDOG_MARGIN_MINUTES = 1;
const RECOVERY_STEP_TIMEOUT_MINUTES = RECOVERY_SOURCE_PROOF_MINUTES +
  RECOVERY_OPERATION_MINUTES + RECOVERY_WATCHDOG_MARGIN_MINUTES;
const SAME_JOB_DOCKER_CLEANUP_MINUTES = 1;
const SAME_JOB_TRANSITION_MARGIN_MINUTES = 1;
const PLAN_MAIN_JOB_RECOVERY_RESERVE_MINUTES = SAME_JOB_DOCKER_CLEANUP_MINUTES +
  RECOVERY_STEP_TIMEOUT_MINUTES + SAME_JOB_TRANSITION_MARGIN_MINUTES;
const APPLY_MAIN_JOB_TAIL_MINUTES = 2;
const FRESH_RECOVERY_SETUP_STEP_COUNT = 3;
const FRESH_RECOVERY_TRANSITION_MARGIN_MINUTES = 1;
const FRESH_RECOVERY_JOB_TIMEOUT_MINUTES = FRESH_RECOVERY_SETUP_STEP_COUNT +
  RECOVERY_STEP_TIMEOUT_MINUTES + FRESH_RECOVERY_TRANSITION_MARGIN_MINUTES;
const EXECUTOR_TOKEN_MINUTES = 35;
// Reserve seven minutes for the mandatory 300s+120s post-WIF drain and eight
// more for the bounded apply, zero-diff readback, marker proof, and receipt.
const MINIMUM_PRE_APPLY_MINUTES = 15;
const APPROVAL_FRESHNESS_MINUTES = 6 * 60;
const MAX_PLAN_FILE_BYTES = 64 * 1024 * 1024;
const MAX_PLAN_JSON_BYTES = 32 * 1024 * 1024;
const MAX_COMMAND_STDERR_BYTES = 256 * 1024;
const MAX_TERRAFORM_DIAGNOSTIC_LINE_BYTES = 256 * 1024;
const MAX_TERRAFORM_DIAGNOSTICS = 8;
const MAX_TERRAFORM_UI_TAIL_LINES = 128;
// The closed vocabulary of plan actions. Like the resource-type allowlist,
// these are structural terms from Terraform's own JSON UI, not identifiers.
const TERRAFORM_CHANGE_ACTIONS = new Set([
  "create",
  "delete",
  "forget",
  "import",
  "move",
  "noop",
  "read",
  "replace",
  "update",
]);
const MAX_REVIEW_MANIFEST_BYTES = 800 * 1024;
const MAX_EXPOSURE_STATE_BYTES = 64 * 1024 * 1024;
const MAX_EXPOSURE_HEALTH_BYTES = 4 * 1024;
const MAX_GITHUB_RUNS_PER_STATUS = 10_000;
const MAX_API_RESPONSE_BYTES = 4 * 1024 * 1024;
const CLEANUP_RETRY_INTERVAL_MS = 2_000;
const IAM_CONSISTENCY_MAX_WAIT_MS = 5 * 60_000;
const PRE_ELEVATION_CONVERGENCE_MINUTES = IAM_CONSISTENCY_MAX_WAIT_MS / 60_000;
const MINIMUM_PLAN_BRIDGE_BUDGET_SECONDS = 7 * 60;
// The apply budget is the job envelope minus runner setup and the same-job
// tail, so it shortens by one second for every second of setup. What it must
// still buy is the whole reviewed internal operation window, less the
// wrapper's one-minute cleanup lead and the controller's five-minute
// exact-cleanup reserve.
const WRAPPER_CLEANUP_LEAD_SECONDS = 60;
const EXACT_CLEANUP_RESERVE_SECONDS = 5 * 60;
const APPLY_CLEANUP_OVERHEAD_SECONDS = WRAPPER_CLEANUP_LEAD_SECONDS +
  EXACT_CLEANUP_RESERVE_SECONDS;
// How much of that window setup may consume. The worst pre-elevation instant
// this design reviews -- executor acquisition using its entire five-minute IAM
// convergence window, then the plan re-read using its whole seven-minute bound
// -- needs 20 further minutes for elevation convergence and the post-mutation
// apply, and that only fits while setup stays inside this tolerance. Setup
// measured 6 to 9 seconds across the four protected plan runs of 2026-08-29.
//
// The previous 34-minute floor admitted five setup minutes, which leaves the
// pre-elevation reserve 239 seconds short: such a run passed validation and
// then failed twelve minutes later at assertPreElevationTime, after acquiring
// and elevating an executor. The floor now rejects it at the budget check.
const APPLY_SETUP_TOLERANCE_SECONDS = 20;
const MINIMUM_APPLY_BRIDGE_BUDGET_SECONDS = APPLY_INTERNAL_OPERATION_MINUTES * 60 +
  APPLY_CLEANUP_OVERHEAD_SECONDS - APPLY_SETUP_TOLERANCE_SECONDS;
// The whole pre-elevation path, modelled from the phase timeline of protected
// plan run 33230835879 (cdbentley bootstrap, 2026-08-29). Bridge start to the
// instant an apply reaches assertPreElevationTime measured 253 seconds there:
// prepare 36s, executor acquisition 177s, permission proof 32s, and Terraform
// init, plan, and read 8s combined.
//
// Acquisition carries its own hard bound, so it is modelled at that bound
// rather than at what it measured. The rest are modelled near three times
// measured. Modelling only the bounded operations understates the path: it
// omits prepare, the freeze and marker proofs, and all Terraform work, which
// together measured 76 of those 253 seconds.
const MODELLED_PREPARE_SECONDS = 90;
const MODELLED_PERMISSION_PROOF_SECONDS = 90;
const MODELLED_TERRAFORM_SECONDS = 120;
const MODELLED_PRE_ELEVATION_SECONDS = MODELLED_PREPARE_SECONDS +
  PRE_ELEVATION_CONVERGENCE_MINUTES * 60 + MODELLED_PERMISSION_PROOF_SECONDS +
  MODELLED_TERRAFORM_SECONDS;
const IAM_RETRY_INITIAL_MS = 1_000;
const IAM_RETRY_MAX_MS = 32_000;
const IAM_RETRY_MAX_ATTEMPTS = 16;
const IAM_FENCE_EXPIRED_AT = "2000-01-01T00:00:00.000Z";
const CLEANUP_FENCE_DESCRIPTION =
  "Expired inert binding used only to advance the cleanup CAS generation.";
const ORPHAN_FENCE_DESCRIPTION =
  "Expired inert binding used only to advance the orphan-recovery CAS generation.";
const MAX_SECRET_BUNDLE_BYTES = 16 * 1024;
const MAX_STORAGE_PERMISSION_RPC_BYTES = 64 * 1024;
const STORAGE_PERMISSION_RPC_TIMEOUT_MS = 15_000;
// healthmcp prod plan 33354517166 died in executor.permission-proof on a single
// "Storage permission RPC timed out." -- one setTimeout and out, with no retry
// on a path that had succeeded on every prior invocation. The GitHub proof
// reads gained a bounded retry in v0.5.30; this dependency had none.
//
// Deliberately small. This probe runs inside the permission-convergence window,
// so attempts here are spent from the same budget the convergence loop needs;
// three is enough to survive a transient fault without meaningfully narrowing
// that window.
const STORAGE_PERMISSION_RPC_ATTEMPTS = 3;
const GOOGLE_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform";
const GOOGLE_OWNER_TOKENINFO_ENDPOINT = "https://oauth2.googleapis.com/tokeninfo";
const GOOGLE_OWNER_SUBJECT_ID = "100549777206682928323";
const STORAGE_BACKEND_ROLE_PERMISSIONS = {
  "roles/storage.objectCreator": [
    "orgpolicy.policy.get",
    "resourcemanager.projects.get",
    "resourcemanager.projects.list",
    "storage.folders.create",
    "storage.managedFolders.create",
    "storage.multipartUploads.abort",
    "storage.multipartUploads.create",
    "storage.multipartUploads.listParts",
    "storage.objects.create",
    "storage.objects.createContext",
  ],
  "roles/storage.objectViewer": [
    "resourcemanager.projects.get",
    "resourcemanager.projects.list",
    "storage.folders.get",
    "storage.folders.list",
    "storage.managedFolders.get",
    "storage.managedFolders.list",
    "storage.objects.get",
    "storage.objects.list",
  ],
} as const;
const STORAGE_BACKEND_ROLE_STAGES = {
  "roles/storage.objectCreator": "GA",
  "roles/storage.objectViewer": "GA",
} as const;
const GOOGLE_USER_ACCESS_TOKEN_MAX_SECONDS = 3_600;
const OWNER_TOKEN_EXPIRY_MARGIN_SECONDS = 60;
const BRIDGE_TELEMETRY_INTERVAL_MS = 15_000;
// Google documents that a newly created service account can take 60 seconds or
// more to become visible, policy changes can take 7 minutes or longer to
// propagate, and its CI retry guidance allows a 300-second 404 convergence
// example. No finite interval is an absence guarantee. This bounded recovery
// policy observes seven minutes, then requires four clean inventories spanning
// three additional minutes; every artifact, failed read, or masking transition
// resets that corroborating proof. The operation also reserves one minute for
// accumulated scan latency and one minute for a bounded late retry. Later or
// repeated uncertainty still fails closed. Token checks reserve the reviewed
// job envelopes, while each recovery entry independently fails closed on
// freshness.
const RECOVERY_STABLE_EMPTY_MS = RECOVERY_STABLE_EMPTY_MINUTES * 60_000;
const RECOVERY_STABLE_EMPTY_INTERVAL_MS = RECOVERY_SCAN_INTERVAL_MINUTES * 60_000;
// The single reviewed mutator-token lifetime. Every `google-github-actions/auth`
// step in this repository declares it, `tools/lint.ts` refuses a step that does
// not, and the capability manifest's requiredFiles digests cover those very
// workflow files -- so `verifyPlatformCapability` proves the value rather than
// trusting it. Consumers mint no tokens of their own; they call these reusable
// workflows, and `prepare()` proves each consumer pins this exact platform SHA.
const MUTATOR_TOKEN_SECONDS = 300;
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
  "controller.de-elevate",
  "controller.federation-preflight",
  "controller.federation-restore",
  "controller.final-audit",
  "controller.local-cleanup",
  "controller.owner-completion",
  "controller.quarantine",
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
  "controller.exposure-state-adopt",
  "controller.exposure-create-revoke",
  "executor.permission-proof",
  "executor.ready",
  "recovery.start",
  "recovery.source-proof",
  "recovery.inventory",
  "recovery.complete",
  "recovery.federation",
  "recovery.failed",
] as const;
const BRIDGE_PHASE_SET = new Set<string>(BRIDGE_PHASES);

export type BridgePhase = (typeof BRIDGE_PHASES)[number];

const RECOVERY_SCAN_OUTCOMES = [
  "reset-active-artifact",
  "reset-propagation-horizon",
  "reset-masked-account",
  "reset-observed-artifact",
  "reset-retryable-read",
  "proof-start",
  "proof-continue",
  "proof-complete",
] as const;
const RECOVERY_SCAN_OUTCOME_SET = new Set<string>(RECOVERY_SCAN_OUTCOMES);

export type RecoveryScanOutcome = (typeof RECOVERY_SCAN_OUTCOMES)[number];

export interface RecoveryScanTelemetry {
  readonly elapsedMs: number;
  readonly outcome: RecoveryScanOutcome;
  readonly proofMs: number;
  readonly scanMs: number;
}

export interface BridgeTelemetry {
  readonly phase: (phase: BridgePhase) => void;
  readonly recoveryScan: (scan: RecoveryScanTelemetry) => void;
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
  recoveryScan: () => undefined,
  stop: () => undefined,
};


if (LEASE_MINUTES <= JOB_TIMEOUT_MINUTES + 10) {
  throw new Error("The emergency IAM expiry must remain safely beyond the job timeout.");
}
if (
  MINIMUM_PRE_APPLY_MINUTES + PRE_ELEVATION_CONVERGENCE_MINUTES >=
      APPLY_INTERNAL_OPERATION_MINUTES ||
  PLAN_INTERNAL_OPERATION_MINUTES > PLAN_MAIN_STEP_TIMEOUT_MINUTES ||
  APPLY_INTERNAL_OPERATION_MINUTES > APPLY_MAIN_STEP_TIMEOUT_MINUTES
) {
  throw new Error("The operation and pre-apply deadlines must reserve unconditional cleanup.");
}
if (
  PLAN_MAIN_STEP_TIMEOUT_MINUTES !==
      JOB_TIMEOUT_MINUTES - PLAN_MAIN_JOB_RECOVERY_RESERVE_MINUTES ||
  APPLY_MAIN_STEP_TIMEOUT_MINUTES !== JOB_TIMEOUT_MINUTES - APPLY_MAIN_JOB_TAIL_MINUTES
) {
  throw new Error("The crash-recovery deadline escaped the main job's reserved tail.");
}
if (
  RECOVERY_OPERATION_MINUTES !==
    RECOVERY_DOCUMENTED_PROPAGATION_MINUTES + RECOVERY_STABLE_EMPTY_MINUTES +
      RECOVERY_SCAN_LATENCY_MARGIN_MINUTES + RECOVERY_LATE_RETRY_MARGIN_MINUTES ||
  RECOVERY_SCAN_LATENCY_MARGIN_MINUTES < RECOVERY_SCAN_INTERVAL_MINUTES ||
  RECOVERY_LATE_RETRY_MARGIN_MINUTES < RECOVERY_SCAN_INTERVAL_MINUTES ||
  RECOVERY_STEP_TIMEOUT_MINUTES !==
    RECOVERY_SOURCE_PROOF_MINUTES + RECOVERY_OPERATION_MINUTES +
      RECOVERY_WATCHDOG_MARGIN_MINUTES ||
  FRESH_RECOVERY_JOB_TIMEOUT_MINUTES !==
    FRESH_RECOVERY_SETUP_STEP_COUNT + RECOVERY_STEP_TIMEOUT_MINUTES +
      FRESH_RECOVERY_TRANSITION_MARGIN_MINUTES
) {
  throw new Error("The crash-recovery operation escaped its reviewed timing envelope.");
}
if (
  APPLY_MAIN_STEP_TIMEOUT_MINUTES + APPLY_MAIN_JOB_TAIL_MINUTES +
      FRESH_RECOVERY_JOB_TIMEOUT_MINUTES >= GOOGLE_USER_ACCESS_TOKEN_MAX_SECONDS / 60 ||
  FRESH_RECOVERY_TRANSITION_MARGIN_MINUTES * 60 < OWNER_TOKEN_EXPIRY_MARGIN_SECONDS ||
  EXECUTOR_TOKEN_MINUTES < APPLY_INTERNAL_OPERATION_MINUTES + 1 ||
  // The floor must leave the modelled pre-elevation path room to finish and
  // still satisfy assertPreElevationTime. This does not prove that every apply
  // fits: assertPreElevationTime is the guard, and it fails closed before the
  // approval is consumed and before any executor is elevated. What it asserts
  // is that the floor keeps that guard's headroom above the path measured in
  // production, so lowering the floor cannot quietly cross it.
  Math.min(
      APPLY_INTERNAL_OPERATION_MINUTES * 60,
      MINIMUM_APPLY_BRIDGE_BUDGET_SECONDS - APPLY_CLEANUP_OVERHEAD_SECONDS,
    ) -
      (MINIMUM_PRE_APPLY_MINUTES + PRE_ELEVATION_CONVERGENCE_MINUTES) * 60 <
    MODELLED_PRE_ELEVATION_SECONDS
) {
  throw new Error("The apply token or fresh-recovery envelope escaped its reviewed bound.");
}

export const REPOSITORY_NAMES = [
  "cdbentley",
  "runsetta",
  "healthmcp",
  "critical-history",
] as const;

export type RepositoryName = (typeof REPOSITORY_NAMES)[number];
export type TerraformRoot = "bootstrap" | "prod" | "exposure";
export type ExecutionMode = "plan" | "apply" | "rehearsal";

// Stage one of the federation-quarantine rollout. The subsystem that closes the
// privileged window lands FIRST, with production apply refused outright, and a
// rehearsal route that exercises the whole federation lifecycle -- arm,
// disable, prove all four converged, de-elevate to a receipt-only identity,
// prove every mutation permission absent, restore, prove the restored
// fingerprints, and publish a final receipt -- while touching no business
// resource and running no Terraform mutation.
//
// The point is that the first live exercise of this code CANNOT grant an
// unvalidated production apply. A second, separately reviewed change flips this
// to false once the canary and the abrupt-loss recovery drills have both run
// against the merged code.
export const PRODUCTION_APPLY_ENABLED = false;

export interface RepositoryContract {
  readonly exposure: {
    readonly domains: readonly string[];
    readonly projectNumber: string;
    readonly region: "us-east4";
    readonly serviceName: string;
  };
  readonly projectId: string;
  readonly repositoryId: string;
  readonly state: {
    readonly bootstrap: { readonly bucket: string; readonly prefix: string };
    readonly exposure: { readonly bucket: string; readonly prefix: string };
    readonly prod: { readonly bucket: string; readonly prefix: string };
  };
}

export const REPOSITORIES: Readonly<Record<RepositoryName, RepositoryContract>> = {
  cdbentley: {
    exposure: {
      domains: ["cdbentley.com", "www.cdbentley.com"],
      projectNumber: "882468538648",
      region: "us-east4",
      serviceName: "cdbentley",
    },
    projectId: "cdbentley",
    repositoryId: "1255553151",
    state: {
      bootstrap: {
        bucket: "cdbentley-tfstate-882468538648-bootstrap",
        prefix: "cdbentley/bootstrap",
      },
      exposure: {
        bucket: "cdbentley-tfstate-882468538648-bootstrap",
        prefix: "cdbentley/exposure",
      },
      prod: { bucket: "cdbentley-tfstate-882468538648", prefix: "cdbentley/prod" },
    },
  },
  runsetta: {
    exposure: {
      domains: ["runsetta.com", "www.runsetta.com"],
      projectNumber: "601124730704",
      region: "us-east4",
      serviceName: "runsetta",
    },
    projectId: "runsetta",
    repositoryId: "711292980",
    state: {
      bootstrap: {
        bucket: "runsetta-tfstate-601124730704-bootstrap",
        prefix: "runsetta/bootstrap",
      },
      exposure: {
        bucket: "runsetta-tfstate-601124730704-bootstrap",
        prefix: "runsetta/exposure",
      },
      prod: { bucket: "runsetta-tfstate-601124730704", prefix: "runsetta/prod" },
    },
  },
  healthmcp: {
    exposure: {
      domains: [
        "medlock.ai",
        "www.medlock.ai",
        "mcp.medlock.ai",
        "healthmcp.ai",
        "www.healthmcp.ai",
        "healthmcp.app",
        "www.healthmcp.app",
      ],
      projectNumber: "229383559510",
      region: "us-east4",
      serviceName: "medlock",
    },
    projectId: "medlock-1025243085",
    repositoryId: "1025243085",
    state: {
      bootstrap: {
        bucket: "medlock-tfstate-1025243085-bootstrap",
        prefix: "medlock/bootstrap",
      },
      exposure: {
        bucket: "medlock-tfstate-1025243085-bootstrap",
        prefix: "medlock/exposure",
      },
      prod: { bucket: "medlock-tfstate-1025243085", prefix: "medlock/prod" },
    },
  },
  "critical-history": {
    exposure: {
      domains: ["ycriticalhistory.org", "www.ycriticalhistory.org"],
      projectNumber: "422714632513",
      region: "us-east4",
      serviceName: "critical-history",
    },
    projectId: "critical-history-16823277",
    repositoryId: "280932482",
    state: {
      bootstrap: {
        bucket: "critical-history-tfstate-422714632513-bootstrap",
        prefix: "critical-history/bootstrap",
      },
      exposure: {
        bucket: "critical-history-tfstate-422714632513-bootstrap",
        prefix: "critical-history/exposure",
      },
      prod: {
        bucket: "critical-history-tfstate-422714632513",
        prefix: "critical-history/prod",
      },
    },
  },
};

const BOOTSTRAP_RESOURCE_TYPES = new Set([
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

// Provider-computed attributes that carry no reviewable meaning and that this
// bridge's own operation is guaranteed to change between a plan and its apply.
//
// Google IAM `etag` is the parent policy's version counter, captured at refresh.
// Acquiring an executor writes the project IAM policy (read-role, storage,
// receipt, and marker leases land in one setPolicy) and releasing it writes the
// policy again -- so between a plan run's refresh and its apply run's refresh
// there are at least two unconditional project-policy writes, from the plan
// run's release and the apply run's acquire. Every managed project-IAM resource
// therefore refreshes with a different etag in the apply, one hashed leaf flips
// `semanticSha256`, and the apply-authorize equality check throws. That made
// plan -> apply impossible for every root, forever, with no external activity
// required. Observed live: runs 33281685967 (plan) and 33282187705 (apply),
// 2026-08-30, with four `SetIamPolicy` calls on the project in between.
//
// Marker read leases are granted on all four consumers' project policies, so
// this also coupled the fleet: any protected run in any repo invalidated every
// pending plan in the other three.
//
// Removing the etag from the digest removes nothing a reviewer can act on. It
// selects nothing, parameterizes nothing, and gates nothing: an `*_iam_member`
// apply is a read-modify-write keyed by role and member, both still hashed; an
// authoritative binding's applied member set comes from config, which is
// SHA-bound, and from apply-time live state, so plan-time `before` was always
// advisory. Any write that changes a role, member, condition, existence, or any
// other managed attribute still flips fields that remain fully hashed and is
// still refused. A write that leaves only an etag trace changed nothing the
// plan reads or the apply performs.
//
// Prod types are listed now rather than when prod applies begin: a prod apply
// writes the three runtime service-account policies, and bootstrap manages
// those same SAs' IAM, so the two roots invalidate each other's plans.
const PROVIDER_VOLATILE_ATTRIBUTES: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  ["google_artifact_registry_repository_iam_member", new Set(["etag"])],
  ["google_cloud_run_v2_service_iam_member", new Set(["etag"])],
  // Firestore reports a point-in-time-recovery window that slides with wall
  // clock: earliest_version_time is (now - version_retention_period), and the
  // etag moves with it. Two reads 90 seconds apart on an unchanged database
  // returned different values for exactly these two fields and identical
  // values for the other sixteen, so a plan and the apply that follows it can
  // never agree on a drift hash for this resource.
  //
  // That is what refused healthmcp prod apply 33341667742: the recomputed
  // manifest differed from the approved one at exactly
  // plan.drift[3].afterSha256 for module.site.google_firestore_database
  // .firestore[0], with an identical beforeSha256 and every other field --
  // 15 changes, 4 drift entries, checks, relevant attributes, all four marker
  // generations -- byte-identical.
  //
  // Excluding these two hides nothing configurable. version_retention_period
  // and point_in_time_recovery_enablement stay in the digest, so a real change
  // to the recovery configuration is still caught; only the derived sliding
  // timestamp and its concurrency token are dropped.
  ["google_firestore_database", new Set(["earliest_version_time", "etag"])],
  ["google_project_iam_binding", new Set(["etag"])],
  ["google_project_iam_member", new Set(["etag"])],
  ["google_secret_manager_secret_iam_member", new Set(["etag"])],
  ["google_service_account_iam_member", new Set(["etag"])],
  ["google_storage_bucket_iam_binding", new Set(["etag"])],
  ["google_storage_bucket_iam_member", new Set(["etag"])],
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

const EXPOSURE_RESOURCE_TYPES = new Set([
  "google_certificate_manager_certificate",
  "google_certificate_manager_certificate_map",
  "google_certificate_manager_certificate_map_entry",
  "google_certificate_manager_dns_authorization",
  "google_cloud_run_domain_mapping",
  "google_compute_backend_service",
  "google_compute_global_address",
  "google_compute_global_forwarding_rule",
  "google_compute_region_network_endpoint_group",
  "google_compute_ssl_policy",
  "google_compute_target_https_proxy",
  "google_compute_url_map",
]);

const TERRAFORM_DIAGNOSTIC_RESOURCE_TYPES = new Set([
  ...BOOTSTRAP_RESOURCE_TYPES,
  ...PROD_RESOURCE_TYPES,
  ...EXPOSURE_RESOURCE_TYPES,
]);

const TERRAFORM_DIAGNOSTIC_SERVICES = [
  "artifactregistry.googleapis.com",
  "cloudresourcemanager.googleapis.com",
  "datastore.googleapis.com",
  "firestore.googleapis.com",
  "iam.googleapis.com",
  "iamcredentials.googleapis.com",
  "orgpolicy.googleapis.com",
  "run.googleapis.com",
  "secretmanager.googleapis.com",
  "serviceusage.googleapis.com",
  "storage.googleapis.com",
  "sts.googleapis.com",
] as const;

const RUNSETTA_EXPOSURE_IMPORTS: ReadonlyMap<string, string> = new Map([
  [
    'module.domains.google_cloud_run_domain_mapping.site["runsetta.com"]',
    "locations/us-east4/namespaces/runsetta/domainmappings/runsetta.com",
  ],
  [
    'module.domains.google_cloud_run_domain_mapping.site["www.runsetta.com"]',
    "locations/us-east4/namespaces/runsetta/domainmappings/www.runsetta.com",
  ],
] as const);

const RUNSETTA_DOMAIN_RECORDS = {
  "runsetta.com": [
    { name: "", rrdata: "216.239.32.21", type: "A" },
    { name: "", rrdata: "216.239.34.21", type: "A" },
    { name: "", rrdata: "216.239.36.21", type: "A" },
    { name: "", rrdata: "216.239.38.21", type: "A" },
    { name: "", rrdata: "2001:4860:4802:32::15", type: "AAAA" },
    { name: "", rrdata: "2001:4860:4802:34::15", type: "AAAA" },
    { name: "", rrdata: "2001:4860:4802:36::15", type: "AAAA" },
    { name: "", rrdata: "2001:4860:4802:38::15", type: "AAAA" },
  ],
  "www.runsetta.com": [
    { name: "www", rrdata: "ghs.googlehosted.com.", type: "CNAME" },
  ],
} as const;
type RunsettaDomain = keyof typeof RUNSETTA_DOMAIN_RECORDS;
const RUNSETTA_DOMAINS = ["runsetta.com", "www.runsetta.com"] as const satisfies readonly RunsettaDomain[];

const RUNSETTA_DOMAIN_UIDS = {
  "runsetta.com": "054a1acd-cfa0-4a47-b6f2-238753c0c2bc",
  "www.runsetta.com": "3a72ca14-d15b-40f9-9920-a9b7083eb771",
} as const;

const RUNSETTA_FULL_CHECK_RESULT_ADDRESSES = [
  "module.domains.var.domains",
  "module.preview_domain.var.preview_domain",
  "module.preview_domain.var.preview_service_name",
  "module.preview_domain.var.resource_name_prefix",
  "var.repository_id",
] as const;

const CRITICAL_EXPOSURE_RESOURCES = new Map([
  ["google_compute_global_address.preview", "google_compute_global_address"],
  ["google_compute_region_network_endpoint_group.preview", "google_compute_region_network_endpoint_group"],
  ["google_compute_backend_service.preview", "google_compute_backend_service"],
  ["google_compute_url_map.preview", "google_compute_url_map"],
  ["google_compute_ssl_policy.preview", "google_compute_ssl_policy"],
  ["google_certificate_manager_dns_authorization.preview", "google_certificate_manager_dns_authorization"],
  ["google_certificate_manager_certificate.preview", "google_certificate_manager_certificate"],
  ["google_certificate_manager_certificate_map.preview", "google_certificate_manager_certificate_map"],
  ["google_certificate_manager_certificate_map_entry.preview", "google_certificate_manager_certificate_map_entry"],
  ["google_compute_target_https_proxy.preview", "google_compute_target_https_proxy"],
  ["google_compute_global_forwarding_rule.preview_https", "google_compute_global_forwarding_rule"],
] as const);

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
  readonly exposureAdoptionRunId: string;
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

export interface ExecutorProvenance {
  readonly approvedManifestSha256: string;
  readonly approvedPlanRunId: string;
  readonly expiresAt: Date;
  readonly exposureAdoptionRunId: string;
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
  readonly exposureAdoptionAudit?: ExposureAdoptionAudit;
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
  readonly exposureProof: ExposureProof | null;
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

export interface ExposureStateMappingProof {
  readonly address: string;
  readonly domain: string;
  readonly id: string;
}

export interface ExposureStateProof {
  readonly bucket: string;
  readonly generation: string | null;
  readonly lineage: string | null;
  readonly mappings: readonly ExposureStateMappingProof[];
  readonly metageneration: string | null;
  readonly object: string;
  readonly serial: number | null;
  readonly sha256: string | null;
  readonly size: string | null;
  readonly state: "absent" | "present";
}

export interface ExposureMappingProof {
  readonly domain: string;
  readonly generation: string;
  readonly id: string;
  readonly observedGeneration: string;
  readonly recordsSha256: string;
  readonly uid: string;
}

export interface ExposureHttpsProof {
  readonly bodySha256: string;
  readonly domain: "runsetta.com" | "www.runsetta.com";
  readonly status: 200;
  readonly url: string;
}

export interface ExposureProof {
  readonly adoptionReceipt: {
    readonly adoptedAt: string;
    readonly generation: string;
    readonly manifestSha256: string;
    readonly metageneration: string;
    readonly runId: string;
    readonly sha256: string;
    readonly size: string;
  } | null;
  readonly https: readonly ExposureHttpsProof[];
  readonly mappingListCount: number;
  readonly mappingListSha256: string;
  readonly mappings: readonly ExposureMappingProof[];
  readonly seedContract: {
    readonly adoptionAudit: ExposureAdoptionAudit | null;
    readonly byteLength: string;
    readonly confirmation: "ADOPT_RUNSETTA_EXPOSURE_STATE";
    readonly liveContinuitySha256: string;
    readonly mode: "controller-create-only-refreshless-v1";
    readonly provider: "registry.terraform.io/hashicorp/google@7.45.0";
    readonly resourceSchemaVersion: 1;
    readonly sha256: string;
    readonly stateFormatVersion: 4;
    readonly terraformVersion: "1.14.5";
  } | null;
  readonly state: ExposureStateProof;
}

export interface ExposureAdoptionAudit {
  readonly controllerCreateLeaseDisposition: "not-granted" | "removed";
  readonly initialState: ExposureStateProof;
  readonly liveContinuityEqual: true;
  readonly outcome: "created" | "exact-existing" | "precondition-reconciled" |
    "response-loss-reconciled";
  readonly postLiveSha256: string;
  readonly preLiveSha256: string;
  readonly stateTransitionSha256: string;
}

interface ExposureAdoptionResult {
  readonly audit: Omit<ExposureAdoptionAudit, "controllerCreateLeaseDisposition"> & {
    readonly controllerCreateLeaseDisposition: "not-granted" | "pending-removal";
  };
  readonly state: ExposureStateProof;
}

export interface ExecutionProof extends PreparationResult {
  readonly exposureProof: ExposureProof | null;
  readonly freezeProof: ConsumerFreezeProof;
  readonly markerProof: readonly MarkerStateProof[];
}

export interface FinalProtectedProofBase {
  readonly consumerSha: string;
  readonly deElevation: ExecutorDeElevationProof;
  // The digest and generation of the exact durable intent bytes this run armed.
  readonly intentDigest: string;
  readonly intentGeneration: string;
  // Read back from the API AFTER restoration. Never a copy of the intent: the
  // intent is what the run promised, this is what it left behind.
  readonly observedPools: readonly ObservedFederationPool[];
  readonly platformSha: string;
  readonly repository: RepositoryName;
  readonly reviewSha256: string;
  readonly root: TerraformRoot;
  readonly runId: string;
}

// A rehearsal runs no Terraform, so it cannot carry an apply proof, a restored
// zero-diff audit, or a countable verdict -- and the type is what stops it
// claiming any of them rather than a comment asking nicely.
export type FinalProtectedProof =
  | (FinalProtectedProofBase & {
    readonly countable: true;
    readonly kind: "apply";
    readonly quarantinedApplyProofDigest: string;
    readonly restoredAudit: {
      readonly detailedExitCode: 0;
      readonly observedAt: string;
      readonly outputSha256: string;
    };
  })
  | (FinalProtectedProofBase & {
    readonly countable: false;
    readonly kind: "rehearsal";
  });

// What an exact release actually establishes, captured before the manager
// forgets the identity. This is direct evidence about one named account --
// contained by its stable unique ID, every project binding fenced and re-read
// as absent, permissions positively proven gone, artifacts deleted -- and it is
// available inside the five-minute cleanup reserve.
//
// It is deliberately NOT the propagation-horizon proof. That proof answers a
// different question ("is anything left anywhere, for a run whose fate we do
// not know?"), needs seven minutes of propagation plus three stable, and cannot
// fit between operationDeadlineMs and cleanupDeadlineMs. Wiring it inline would
// have failed every apply at its last step.
// An exact reference to one published object, not merely its digest. Completion
// names the bucket, key, generation, size and content hash it countersigns, so
// a verifier can re-read exactly that object and nothing else.
export interface FinalReceiptReference {
  readonly bucket: string;
  readonly deElevationExecutorEmail: string;
  readonly deElevationExecutorUniqueId: string;
  readonly digest: string;
  readonly generation: string;
  readonly object: string;
  readonly publishedAt: string;
  readonly size: number;
}

export interface ExecutorReleaseProof {
  readonly artifactsDeleted: true;
  readonly executorEmail: string;
  readonly executorUniqueId: string;
  readonly observedAt: string;
  readonly permissionsProvenGone: true;
  readonly projectBindingsCleared: true;
}

export interface ExecutorDeElevationProof {
  readonly executorEmail: string;
  readonly executorUniqueId: string;
  readonly observedAt: string;
  // Exactly the permissions the mutation role carried that the read role does
  // not, proven absent against the live control plane after revocation.
  readonly provenAbsent: readonly string[];
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

export type CommandDiagnosticPolicy = "redacted-stderr" | "terraform-safe";

export interface CommandRequest {
  readonly argv: readonly string[];
  readonly capture?: boolean;
  readonly cwd: string;
  readonly deadlineMs: number;
  readonly diagnosticPolicy: CommandDiagnosticPolicy;
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
  // Revokes mutation authority and proves, against the live control plane, that
  // every mutation permission is gone while the receipt-scoped read authority
  // remains. The identity that publishes the final receipt is a reader.
  readonly deElevateExecutor: (
    invocation: Invocation,
    session: ExecutorSession,
    operationDeadlineMs: number,
  ) => Promise<ExecutorDeElevationProof>;
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
  readonly proveExposure: (
    invocation: Invocation,
    session: ExecutorSession,
    preparation: PreparationResult,
  ) => Promise<ExposureProof | null>;
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
  // The single countable success. Written only after de-elevation, federation
  // restoration, and the restored-state audit have all succeeded.
  // Written by the OWNER, not the executor. The executor holds no capability on
  // this object at any point in its life, so the ordering claim is enforced by
  // which credential can write it rather than by the order of two statements.
  readonly publishFinalReceipt: (
    invocation: Invocation,
    review: ReviewManifestResult,
    proof: FinalProtectedProof,
    nowMs: number,
  ) => Promise<FinalReceiptReference>;
  // Written by the OWNER, after the executor is provably gone. Until this
  // exists the final receipt is a claim, not a countable success: the receipt
  // is published by a de-elevated identity that still exists, and deleting that
  // identity can still fail afterwards.
  readonly publishOwnerCompletion: (
    invocation: Invocation,
    pending: FinalReceiptReference,
    releaseProof: ExecutorReleaseProof,
    cleanupDeadlineMs: number,
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
  ) => Promise<ExecutorReleaseProof | undefined>;
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
  // Disables the consumer workload identity pool before any privilege is
  // granted, and returns the exact state observed beforehand. See the comment
  // above federationPoolFingerprint for why the pool, and not the provider or a
  // clock, is what closes the window.
  // Reads all four pools and writes the durable intent. Deliberately performs
  // NO mutation: the controller holds the record before the first PATCH, so a
  // quarantine that fails halfway is still a quarantine this run must undo.
  readonly armFederationQuarantine: (
    invocation: Invocation,
    operationDeadlineMs: number,
  ) => Promise<{ readonly generation: string; readonly record: FederationQuarantineRecord }>;
  // Disables all four, proving each converged to disabled with an otherwise
  // unchanged fingerprint.
  readonly disableFederation: (
    invocation: Invocation,
    record: FederationQuarantineRecord,
    operationDeadlineMs: number,
  ) => Promise<void>;
  // Restores exactly the captured state and proves it converged. Runs after the
  // post-apply audit and after the executor is released.
  // Runs before any protected work. A run that started while an earlier run's
  // quarantine was still unrepaired would arm a second intent over pools that
  // are already disabled, and the two runs would then restore each other's
  // captured state.
  readonly recoverFederationPreflight: (
    invocation: Invocation,
    operationDeadlineMs: number,
  ) => Promise<FederationRecoverySummary>;
  readonly restoreFederation: (
    invocation: Invocation,
    record: FederationQuarantineRecord,
    generation: string,
    operationDeadlineMs: number,
  ) => Promise<readonly ObservedFederationPool[]>;
  // The restored-state audit. Its output digest is the zero-diff evidence the
  // final receipt binds; a timestamp alone would assert nothing.
  readonly auditRestoredState: (
    invocation: Invocation,
    session: ExecutorSession,
    terraformDirectory: string,
    operationDeadlineMs: number,
  ) => Promise<{
    readonly detailedExitCode: 0;
    readonly observedAt: string;
    readonly outputSha256: string;
  }>;
}

export interface RecoveryDependencies {
  readonly now: () => number;
  // Repairs any protected run, for any target, that died holding disabled
  // consumer pools. Fleet-wide by construction: an abruptly lost run for one
  // target can be followed by a run for a different one.
  readonly recoverFederation: (
    invocation: RecoveryInvocation,
    recoveryDeadlineMs: number,
  ) => Promise<FederationRecoverySummary>;
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
    "EXPOSURE_ADOPTION_CONFIRMATION",
    "EXPOSURE_ADOPTION_RUN_ID",
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

// `productionApplyEnabled` is the rollout gate, not a caller preference. It
// defaults to the compiled-in PRODUCTION_APPLY_ENABLED, which is false for the
// whole first stage; main() never passes it, so a deployed build cannot perform
// a production apply no matter what the environment says. The apply path still
// has to be exercised by tests, because stage two turns it on unchanged, and
// those are the only callers that pass it.
export function validateInvocation(
  source: NodeJS.ProcessEnv = process.env,
  productionApplyEnabled: boolean = PRODUCTION_APPLY_ENABLED,
): Invocation {
  validateProtectedRoute(source);

  const repository = repositoryName(required(source, "TARGET_REPOSITORY"));
  const terraformRoot = rootName(required(source, "TERRAFORM_ROOT"));
  const mode = executionMode(required(source, "EXECUTION_MODE"));
  assertModeIsPermitted(mode, productionApplyEnabled);
  const exposureAdoptionConfirmation = requiredStringOrEmpty(
    source.EXPOSURE_ADOPTION_CONFIRMATION,
    "exposure adoption confirmation",
  );
  if (terraformRoot === "exposure") {
    if (repository !== "runsetta" || mode !== "plan") {
      throw new Error("The one-shot exposure adoption is locked to a Runsetta plan run.");
    }
    exact(
      exposureAdoptionConfirmation,
      RUNSETTA_EXPOSURE_ADOPTION_CONFIRMATION,
      "Runsetta exposure adoption confirmation",
    );
  } else {
    exact(exposureAdoptionConfirmation, "", "non-exposure adoption confirmation");
  }
  const exposureAdoptionRunId = requiredStringOrEmpty(
    source.EXPOSURE_ADOPTION_RUN_ID,
    "exposure adoption run ID",
  );
  // Mode-specific, not repository-specific alone. A rehearsal adopts nothing,
  // and buildReceiptLeases refuses a rehearsal that names an adoption -- so
  // requiring one here would make Runsetta prod rehearsals unconstructible.
  if (repository === "runsetta" && terraformRoot === "prod" && mode !== "rehearsal") {
    numeric(exposureAdoptionRunId, "Runsetta exposure adoption run ID");
  } else {
    exact(exposureAdoptionRunId, "", "non-Runsetta-prod exposure adoption run ID");
  }
  const platformSha = sha(required(source, "GITHUB_SHA_EXACT"), "platform SHA");
  const consumerSha = sha(required(source, "CONSUMER_SHA"), "consumer SHA");
  const githubRunId = numeric(required(source, "GITHUB_RUN_ID_EXACT"), "GitHub run ID");
  const operationBudgetSeconds = Number(numeric(
    required(source, "BRIDGE_OPERATION_BUDGET_SECONDS_EXACT"),
    "bridge operation budget seconds",
  ));
  // A rehearsal runs the federation lifecycle and no Terraform mutation, so it
  // budgets like a plan rather than like an apply.
  const budgetsLikePlan = mode === "plan" || mode === "rehearsal";
  const minimumOperationBudgetSeconds = budgetsLikePlan
    ? MINIMUM_PLAN_BRIDGE_BUDGET_SECONDS
    : MINIMUM_APPLY_BRIDGE_BUDGET_SECONDS;
  const maximumOperationBudgetSeconds = (
    budgetsLikePlan ? PLAN_MAIN_STEP_TIMEOUT_MINUTES : APPLY_MAIN_STEP_TIMEOUT_MINUTES
  ) * 60;
  if (
    operationBudgetSeconds < minimumOperationBudgetSeconds ||
    operationBudgetSeconds > maximumOperationBudgetSeconds
  ) {
    throw new Error(
      `Bridge operation budget escaped its reviewed ${minimumOperationBudgetSeconds}..${maximumOperationBudgetSeconds} second ${mode} range.`,
    );
  }
  const legacyCompatibilityMode = booleanString(
    required(source, "LEGACY_COMPATIBILITY_MODE"),
    "legacy compatibility mode",
  );
  const transitionWorkflowSha = source.TRANSITION_WORKFLOW_SHA ?? "";
  if (transitionWorkflowSha !== "") sha(transitionWorkflowSha, "transition workflow SHA");
  if (terraformRoot !== "bootstrap" && (legacyCompatibilityMode || transitionWorkflowSha !== "")) {
    throw new Error("Non-bootstrap mode forbids bootstrap migration controls.");
  }
  if (legacyCompatibilityMode && transitionWorkflowSha !== "") {
    throw new Error("Legacy compatibility is allowed only for the initial migration without a transition SHA.");
  }
  if (transitionWorkflowSha === platformSha) {
    throw new Error("The transition workflow SHA must differ from the active platform SHA.");
  }
  const approvedManifestSha256 = source.APPROVED_MANIFEST_SHA256 ?? "";
  const approvedPlanRunId = source.APPROVED_PLAN_RUN_ID ?? "";
  // Every non-apply mode, not just plan. Naming an approved run in a rehearsal
  // would let it carry apply authority it can never legitimately exercise.
  if (mode !== "apply" && (approvedManifestSha256 !== "" || approvedPlanRunId !== "")) {
    throw new Error("Only apply mode may name an approved plan run or manifest digest.");
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
    exposureAdoptionRunId,
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

export function buildStorageReadLease(
  repository: RepositoryName,
  root: TerraformRoot,
  runId: string,
  expiresAt: Date,
  executorServiceAccountEmail: string,
): StorageLease {
  numeric(runId, "GitHub run ID");
  if (!Number.isFinite(expiresAt.getTime())) throw new Error("Lease expiration is invalid.");
  const contract = REPOSITORIES[repository];
  const backend = contract.state[root];
  const member = executorMember(contract.projectId, executorServiceAccountEmail);
  const bucketResource = `projects/_/buckets/${backend.bucket}`;
  const stateResource = `${bucketResource}/objects/${backend.prefix}/default.tfstate`;
  return {
    condition: {
      description: `List only the exact ${root} backend bucket and read only its state object for ${repository}.`,
      expression: [
        `request.time < timestamp('${expiresAt.toISOString()}')`,
        `((resource.type == 'storage.googleapis.com/Bucket' && resource.name == '${bucketResource}') || ` +
        `(resource.type == 'storage.googleapis.com/Object' && resource.name == '${stateResource}'))`,
      ].join(" && "),
      title: `codex-executor-storage-read-${runId}`,
    },
    members: [member],
    role: "roles/storage.objectViewer",
  };
}

export function buildStorageAcquisitionLeases(
  repository: RepositoryName,
  root: TerraformRoot,
  mode: ExecutionMode,
  runId: string,
  expiresAt: Date,
  executorServiceAccountEmail: string,
): readonly StorageLease[] {
  void mode;
  const leases = [
    buildStorageReadLease(
      repository,
      root,
      runId,
      expiresAt,
      executorServiceAccountEmail,
    ),
  ];
  if (repository === "runsetta" && root === "prod") {
    const backend = REPOSITORIES.runsetta.state.exposure;
    const resource =
      `projects/_/buckets/${backend.bucket}/objects/${backend.prefix}/default.tfstate`;
    leases.push({
      condition: {
        description: "Read only the canonical Runsetta exposure state prerequisite.",
        expression: [
          `request.time < timestamp('${expiresAt.toISOString()}')`,
          "resource.type == 'storage.googleapis.com/Object'",
          `resource.name == '${resource}'`,
        ].join(" && "),
        title: `codex-exposure-prerequisite-state-${runId}`,
      },
      members: [executorMember(REPOSITORIES.runsetta.projectId, executorServiceAccountEmail)],
      role: "roles/storage.objectViewer",
    });
  }
  return leases;
}

export function buildExposureControllerCreateLease(
  runId: string,
  expiresAt: Date,
): StorageLease {
  numeric(runId, "GitHub run ID");
  if (!Number.isFinite(expiresAt.getTime())) throw new Error("Lease expiration is invalid.");
  const backend = REPOSITORIES.runsetta.state.exposure;
  const stateResource =
    `projects/_/buckets/${backend.bucket}/objects/${backend.prefix}/default.tfstate`;
  return {
    condition: {
      description: "Controller may create only the absent canonical Runsetta exposure state.",
      expression: [
        `request.time < timestamp('${expiresAt.toISOString()}')`,
        "resource.type == 'storage.googleapis.com/Object'",
        `resource.name == '${stateResource}'`,
      ].join(" && "),
      title: `codex-controller-exposure-create-${runId}`,
    },
    members: [OWNER_MEMBER],
    role: "roles/storage.objectCreator",
  };
}

function bindingHasExposureControllerLeaseTitle(
  binding: IamBinding,
  runId: string,
): boolean {
  return binding.condition?.title === `codex-controller-exposure-create-${runId}`;
}

export function exposureControllerCreateLeaseOrUndefined(
  binding: IamBinding,
  runId: string,
): StorageLease | undefined {
  const condition = binding.condition;
  if (
    condition === undefined ||
    condition.title !== `codex-controller-exposure-create-${runId}` ||
    condition.description !==
      "Controller may create only the absent canonical Runsetta exposure state."
  ) {
    return undefined;
  }
  const match = condition.expression.match(
    /^request\.time < timestamp\('([^']+)'\) && resource\.type == 'storage\.googleapis\.com\/Object' && resource\.name == '[^']+'$/,
  );
  if (match === null) return undefined;
  const expiresAt = new Date(match[1]!);
  if (!Number.isFinite(expiresAt.getTime())) return undefined;
  const expected = buildExposureControllerCreateLease(runId, expiresAt);
  return bindingEqualsLease(binding, expected) ? expected : undefined;
}

export function requireExposureControllerCreateLeaseCandidate(
  binding: IamBinding,
  runId: string,
): StorageLease | undefined {
  if (!bindingHasExposureControllerLeaseTitle(binding, runId)) return undefined;
  const lease = exposureControllerCreateLeaseOrUndefined(binding, runId);
  if (lease === undefined) {
    throw new Error("A controller exposure-create lease title was reused with altered authority.");
  }
  return lease;
}

export function buildStorageLease(
  repository: RepositoryName,
  root: TerraformRoot,
  runId: string,
  expiresAt: Date,
  executorServiceAccountEmail: string,
  mode: ExecutionMode = "apply",
  approvedPlanRunId = "",
): StorageLease {
  numeric(runId, "GitHub run ID");
  if (mode === "plan") {
    throw new Error("Plan state access requires the exact storage read contract.");
  }
  if (mode === "apply") numeric(approvedPlanRunId, "approved plan run ID");
  if (!Number.isFinite(expiresAt.getTime())) throw new Error("Lease expiration is invalid.");
  const contract = REPOSITORIES[repository];
  const backend = contract.state[root];
  const bucketResources = root === "bootstrap"
    ? [
        contract.state.bootstrap.bucket,
        contract.state.prod.bucket,
        `${contract.state.prod.bucket}-access-logs`,
      ]
    : [backend.bucket];
  const resourceNames = [
    ...bucketResources.map((bucket) => `projects/_/buckets/${bucket}`),
    `projects/_/buckets/${backend.bucket}/objects/${backend.prefix}/default.tfstate`,
    `projects/_/buckets/${backend.bucket}/objects/${backend.prefix}/default.tflock`,
  ].toSorted();
  const expression = [
    `request.time < timestamp('${expiresAt.toISOString()}')`,
    `(${resourceNames.map((name) => `resource.name == '${name}'`).join(" || ")})`,
  ].join(" && ");
  return {
    condition: {
      description: `Temporary ${root} state lease for ${repository}; expires automatically.`,
      expression,
      title: `codex-executor-storage-apply-${runId}`,
    },
    members: [executorMember(contract.projectId, executorServiceAccountEmail)],
    role: root === "bootstrap"
      ? "roles/storage.admin"
      : "roles/storage.objectAdmin",
  };
}

// The title elevate removes. Exported so the removal names the binding rather
// than reconstructing it, which is what keeps grant and revocation from
// drifting apart.
// The v0.5.28-and-earlier apply shape: ONE objectCreator binding titled
// codex-receipt-create-<runId> covering the consumed and result receipts
// together. Orphan recovery compares binding expressions exactly, so a run that
// died before v0.5.29 would otherwise present a binding matching nothing in the
// expected set, hard-fail with "unknown or modified binding", and leave the
// protected path refusing every run until someone cleaned up by hand.
//
// Both apply runs that failed under the old shape (33296971474, 33300997122)
// completed their cleanup in process, so no such orphan is believed to exist --
// but "believed" is not the standard for a path whose failure mode is a manual
// outage.
// Historical orphan recognizer ONLY, and therefore FROZEN. This is the exact
// v0.5.28 shape -- consumed/* plus results/* in one combined creator binding --
// and it must never track current grants. If it drifts, recovery stops
// recognising the orphans it exists to clean up, and the protected path refuses
// every run until somebody clears them by hand. No current run is granted it:
// results/* no longer exists and final/* is the owner's.
export function buildLegacyCombinedReceiptCreateLease(
  repository: RepositoryName,
  root: TerraformRoot,
  runId: string,
  expiresAt: Date,
  approvedPlanRunId: string,
  executorServiceAccountEmail: string,
): IamBinding {
  numeric(runId, "GitHub run ID");
  numeric(approvedPlanRunId, "approved plan run ID");
  const contract = REPOSITORIES[repository];
  const state = contract.state[root];
  const resources = [
    `projects/_/buckets/${state.bucket}/objects/${receiptObjectName(state, "consumed", approvedPlanRunId)}`,
    `projects/_/buckets/${state.bucket}/objects/${receiptObjectName(state, "results", runId)}`,
  ];
  return {
    condition: {
      ...expiringCondition(
        `codex-receipt-create-${runId}`,
        `Create-only immutable receipt scope for ${repository} ${root}.`,
        expiresAt,
      ),
      expression: [
        `request.time < timestamp('${expiresAt.toISOString()}')`,
        `(${resources.map((resource) => `resource.name == '${resource}'`).join(" || ")})`,
      ].join(" && "),
    },
    members: [executorMember(contract.projectId, executorServiceAccountEmail)],
    role: "roles/storage.objectCreator",
  };
}

// What elevation's single project-policy write adds and removes.
//
// Extracted so the removal is testable without a live executor: the probes
// `#waitForPermissionProjection` uses are not injectable, so `elevate` cannot
// be driven end to end in process, and the wiring between "which binding must
// go" and "the CAS write that removes it" is exactly where this defect lived.
//
// `recordedLeases` is the acquire record's lease list -- the authority on what
// was actually granted. The consume lease is located there by title and its
// absence is fatal: rebuilding the binding here could drift from the grant, and
// a removal that silently matches nothing would leave the executor holding
// create on the consumed receipt while the mutation projection forbids it,
// which is the defect this closes.
export function elevationPolicyRecord(
  invocation: Invocation,
  executorServiceAccountEmail: string,
  leaseExpiresAt: Date,
  mutationRoleName: string,
  recordedLeases: readonly IamBinding[],
): { readonly leases: readonly IamBinding[]; readonly removals: readonly IamBinding[] } {
  if (invocation.mode !== "apply") {
    throw new Error("Only an apply elevates its executor.");
  }
  const consumeTitle = receiptConsumeLeaseTitle(invocation.githubRunId);
  const consumeLease = recordedLeases.find(
    (lease) => lease.condition?.title === consumeTitle,
  );
  if (consumeLease === undefined) {
    throw new Error(
      "Elevation could not find the recorded consumed-receipt create lease to revoke.",
    );
  }
  return {
    leases: [
      ...buildExecutorProjectLeases(
        invocation.repository,
        invocation.githubRunId,
        leaseExpiresAt,
        executorServiceAccountEmail,
        mutationRoleName,
        "mutation",
      ),
      buildStorageLease(
        invocation.repository,
        invocation.terraformRoot,
        invocation.githubRunId,
        leaseExpiresAt,
        executorServiceAccountEmail,
        "apply",
        invocation.approvedPlanRunId,
      ),
      ...(invocation.terraformRoot === "bootstrap"
        ? [
            buildMarkerMutationLease(
              invocation.repository,
              invocation.githubRunId,
              leaseExpiresAt,
              executorServiceAccountEmail,
            ),
          ]
        : []),
    ],
    removals: [consumeLease],
  };
}

export function receiptConsumeLeaseTitle(runId: string): string {
  numeric(runId, "GitHub run ID");
  return `codex-receipt-consume-${runId}`;
}

export function buildReceiptLeases(
  repository: RepositoryName,
  root: TerraformRoot,
  runId: string,
  expiresAt: Date,
  mode: ExecutionMode,
  approvedPlanRunId: string,
  executorServiceAccountEmail: string,
  exposureAdoptionRunId = "",
): readonly IamBinding[] {
  numeric(runId, "GitHub run ID");
  if (mode === "apply") numeric(approvedPlanRunId, "approved plan run ID");
  if (mode !== "apply" && approvedPlanRunId !== "") {
    throw new Error("A run that consumes no approved plan cannot name one.");
  }
  const contract = REPOSITORIES[repository];
  const state = contract.state[root];
  // A rehearsal reviews no plan, consumes no receipt, and publishes nothing
  // itself -- its receipt is the owner's. So it is granted no receipt scope at
  // all, and there is deliberately no plan resource to construct: doing so
  // would derive an object name from an approved run id that does not exist.
  if (mode === "rehearsal") {
    if (exposureAdoptionRunId !== "") {
      throw new Error("A rehearsal has no exposure adoption.");
    }
    return [];
  }
  const planRunId = mode === "plan" ? runId : approvedPlanRunId;
  const planReceiptKind = root === "exposure" ? "adoptions" : "plans";
  const planResource =
    `projects/_/buckets/${state.bucket}/objects/${receiptObjectName(state, planReceiptKind, planRunId)}`;
  const consumedResource = mode === "apply"
    ? `projects/_/buckets/${state.bucket}/objects/${receiptObjectName(state, "consumed", approvedPlanRunId)}`
    : undefined;
  // Deliberately absent: the executor is granted NO capability on the final
  // receipt, at acquire or at any later point. An acquire-time grant would let
  // IAM permit that object to be published while mutation authority was still
  // live, which would leave the publish-after-de-elevation ordering enforced by
  // cooperative code rather than by credentials. The owner writes it instead.
  const member = executorMember(contract.projectId, executorServiceAccountEmail);
  const viewerResources = [
    planResource,
    ...(consumedResource === undefined ? [] : [consumedResource]),
    ...(repository === "runsetta" && root === "prod" && exposureAdoptionRunId !== ""
      ? [
          `projects/_/buckets/${contract.state.exposure.bucket}/objects/${receiptObjectName(
            contract.state.exposure,
            "adoptions",
            numeric(exposureAdoptionRunId, "Runsetta exposure adoption run ID"),
          )}`,
        ]
      : []),
  ];
  // The consumed receipt keeps its own short-lived creator lease, revoked at
  // elevation: the executor must be able to write it during consumeApproval and
  // must NOT still be able to when elevate probes the mutation projection.
  // Observed on run 33300997122: `consumed/33300628538.json (unexpectedly holds
  // storage.objects.create)`.
  //
  // Beyond that, an apply or rehearsal executor now creates nothing at all. The
  // results receipt is gone and the final receipt is the owner's, so there is
  // no second creator lease to grant -- which is what makes "published only
  // after mutation authority was surrendered" a statement about credentials
  // rather than about the order of two lines of code.
  const creatorResources = mode === "plan" ? [planResource] : [];
  return [
    ...(consumedResource === undefined ? [] : [{
      condition: {
        ...expiringCondition(
          receiptConsumeLeaseTitle(runId),
          `Create-only consumed-receipt scope for ${repository} ${root}; revoked at elevation.`,
          expiresAt,
        ),
        expression: [
          `request.time < timestamp('${expiresAt.toISOString()}')`,
          `(resource.name == '${consumedResource}')`,
        ].join(" && "),
      },
      members: [member],
      role: "roles/storage.objectCreator",
    } satisfies IamBinding]),
    ...(creatorResources.length === 0 ? [] : [{
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
    } satisfies IamBinding]),
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


const V0513_ATTESTATION_RULES_READ_PERMISSION =
  "iam.workloadIdentityPools.getAttestationRules";
// Roles created by v0.5.15 through v0.5.26 carry the deny-policy permissions
// this release removes. Google retains deleted custom-role tombstones, and a
// crashed run can leave an active role behind, so recovery must still
// recognise those exact matrices -- otherwise it refuses to delete them and
// reports that manual cleanup is required. Bootstrap matrices do not vary by
// repository, so one digest per retired variant covers all four consumers.
const V0526_BOOTSTRAP_ROLE_PERMISSION_SHA256: readonly string[] = [
  // read: control and custom were identical, since deny get/list are the two
  // deny permissions Google does support in a custom role.
  "9c7d258abc8015eaf1c606aef5d969635e382265ecb89bb99a12ea813a97ebf2",
  // mutation control matrix, carrying the three deny writes.
  "6391432f0b98f19d6a19932c6408c57fc9ea99fb3a5e55800b5a7ea8d7ac5241",
  // mutation custom role, with those three filtered back out.
  "fd598b2dddd585eb6164b3d5b13c88b45b226ed336f816426db5da8998b6cbc7",
];
const V0512_BOOTSTRAP_ROLE_PERMISSION_SHA256 = {
  mutation: "6d2e97c830d53859f1040ac1090bd53303fa23d7743e3f2855095972369eca77",
  read: "cd250d221ea684765f6c2c04dbd806e8b6ce094666455ae50dedcc20564f86e4",
} as const;

export function executorControlPermissions(
  repository: RepositoryName,
  root: TerraformRoot,
  phase: "mutation" | "read",
): readonly string[] {
  // Exposure is controller-seeded state adoption. The executor gets no Cloud
  // Run project role and the direct Domain Mapping API is proven denied.
  if (root === "exposure") return [];
  const bootstrapRead = [
    "iam.roles.get",
    "iam.roles.list",
    "iam.serviceAccounts.get",
    "iam.serviceAccounts.getIamPolicy",
    "iam.serviceAccounts.list",
    "iam.workloadIdentityPools.get",
    V0513_ATTESTATION_RULES_READ_PERMISSION,
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

export function bridgeRolePermissionsRecognized(
  observed: readonly string[],
  repository: RepositoryName,
  root: TerraformRoot,
  phase: "mutation" | "read",
): boolean {
  const observedJson = canonicalJson([...observed].toSorted());
  // Compare against what createEphemeralRole actually creates. Since the
  // deny-policy permissions left both matrices these no longer diverge, but
  // the comparison stays explicit: if a future permission is again refused in
  // a custom role, recognising against the control matrix alone would leave
  // every such role -- including its retained tombstone -- unrecognised, and
  // recovery would refuse to delete it and report that manual cleanup is
  // required.
  const currentJson = canonicalJson([
    ...executorCustomRolePermissions(repository, root, phase),
  ].toSorted());
  if (observedJson === currentJson) return true;
  // Also accept the full control matrix, so a role created by a build that
  // predates the split is still recognised and cleanable.
  const controlJson = canonicalJson([
    ...executorControlPermissions(repository, root, phase),
  ].toSorted());
  if (observedJson === controlJson) return true;
  if (root !== "bootstrap") return false;
  // Google retains deleted custom-role tombstones, and abrupt v0.5.12 loss can
  // also leave an active role. The frozen digests recognize only those exact
  // prior matrices so cleanup can remove their leases and roles. Current role
  // creation and permission convergence use executorControlPermissions alone.
  const digest = createHash("sha256").update(observedJson).digest("hex");
  if (digest === V0512_BOOTSTRAP_ROLE_PERMISSION_SHA256[phase]) return true;
  return V0526_BOOTSTRAP_ROLE_PERMISSION_SHA256.includes(digest);
}

// Every permission the executor needs is now grantable through the ephemeral
// custom role, so this is the control matrix unchanged. It stays a distinct
// function because the custom role and the permission-convergence proof are
// separate contracts, and a future permission Google refuses in custom roles
// must fail here rather than silently widening the role.
export function executorCustomRolePermissions(
  repository: RepositoryName,
  root: TerraformRoot,
  phase: "mutation" | "read",
): readonly string[] {
  return executorControlPermissions(repository, root, phase);
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

// Every preview runtime principal in the fleet. The retired deny policy named
// these four explicitly; the plan gate below derives them so a repository added
// to REPOSITORIES cannot silently escape the check.
// Predefined roles that carry iam.workloadIdentityPools.update. A custom role
// cannot be evaluated from a plan alone, so any project custom role that names
// the permission is refused by the separate permission gate below.
const POOL_MUTATION_ROLES: ReadonlySet<string> = new Set([
  "roles/editor",
  "roles/iam.workloadIdentityPoolAdmin",
  "roles/owner",
]);

export const POOL_MUTATION_PERMISSION = "iam.workloadIdentityPools.update";

// The owner controller and the run's own ephemeral executor. Nothing else may
// be able to move a pool's disabled flag.
function isTrustedFederationController(principal: string): boolean {
  const member = principalWithoutUid(principal);
  return member === OWNER_MEMBER ||
    /^serviceAccount:gha-pbt-[0-9a-f]{20}@[a-z0-9-]+\.iam\.gserviceaccount\.com$/.test(member);
}

function previewRuntimeMembers(): ReadonlySet<string> {
  const members = new Set<string>();
  for (const repository of REPOSITORY_NAMES) {
    const email = `cloud-run-preview@${REPOSITORIES[repository].projectId}.iam.gserviceaccount.com`;
    members.add(`serviceAccount:${email}`);
    // Google renders a soft-deleted principal with this prefix, and it is
    // restorable, so it is the same identity for this purpose. It also appends
    // the account's stable identifier -- `deleted:serviceAccount:...?uid=123`
    // -- which principalWithoutUid strips before this set is consulted.
    members.add(`deleted:serviceAccount:${email}`);
  }
  return members;
}

// Members that grant the preview runtime access without naming it. Mirrors the
// `forbidden_member` predicate in tools/ci/preview-runtime-iam-contract.sh, so
// the preventive gate and the continuous proof refuse the same things: an
// `allUsers` binding, a group or domain that may contain the runtime, a
// primitive project role, or a service-account-wide principal set all confer
// access an exact-membership check would wave through.
const BROAD_MEMBER_PATTERNS: readonly RegExp[] = [
  /^(?:deleted:)?(?:group|domain):/,
  /^project(?:Owner|Editor|Viewer):/,
  /^principalSet:\/\/cloudresourcemanager\.googleapis\.com\/(?:projects|folders|organizations)\/[^/]+\/type\/ServiceAccount$/,
];
const BROAD_MEMBER_LITERALS: ReadonlySet<string> = new Set([
  "allUsers",
  "allAuthenticatedUsers",
]);

// Google's fixed delivery group for Cloud Storage access logs, required by
// google_storage_bucket_iam_member.terraform_state_access_logs_writer. It is a
// Google-owned group that cannot contain a principal of ours, and without this
// exemption the group pattern above rejects every bootstrap plan -- the binding
// is a managed resource, so Terraform reports it in resource_changes on every
// run. preview-runtime-iam-contract.sh never had to exempt it because it scans
// project policies, and this binding lives on a bucket.
const STORAGE_ACCESS_LOG_DELIVERY_MEMBER = "group:cloud-storage-analytics@google.com";

// IAM grant resources whose member is a principal. A computed member is
// resolved during apply, so a plan whose `after` omits it decides nothing at
// review time; these types must therefore have a known member or be refused.
const IAM_GRANT_RESOURCE_TYPES: ReadonlySet<string> = new Set([
  "google_artifact_registry_repository_iam_member",
  "google_cloud_run_v2_service_iam_member",
  "google_project_iam_binding",
  "google_project_iam_member",
  "google_secret_manager_secret_iam_member",
  "google_service_account_iam_member",
  "google_storage_bucket_iam_binding",
  "google_storage_bucket_iam_member",
]);

// Refuse an IAM grant whose principal Terraform has not resolved at plan time.
// The reviewer approves `after`; an unresolved member lives in `after_unknown`
// and could become a preview-runtime principal during apply, which the gate
// below would never see.
function rejectUnknownIamMember(
  type: string,
  afterUnknown: JsonValue,
  address: string,
  label: string,
): void {
  if (!IAM_GRANT_RESOURCE_TYPES.has(type)) return;
  if (afterUnknown === null || typeof afterUnknown !== "object" || Array.isArray(afterUnknown)) {
    return;
  }
  const unresolved = (node: JsonValue | undefined): boolean => {
    if (node === undefined || node === false || node === null) return false;
    if (node === true) return true;
    if (Array.isArray(node)) return node.some((entry) => unresolved(entry));
    if (typeof node === "object") return Object.values(node).some((entry) => unresolved(entry));
    return false;
  };
  for (const key of ["member", "members"]) {
    if (unresolved(afterUnknown[key])) {
      throw new Error(
        `${label} at ${address} leaves its IAM ${key} unresolved until apply, so the reviewed plan does not determine who is granted access.`,
      );
    }
  }
}

// The preview runtime must hold no access to storage, secrets, or Firestore in
// any of the four projects. That was enforced by an IAM deny policy until it
// proved unbuildable: roles/iam.denyAdmin is not grantable at project scope,
// iam.denypolicies writes are NOT_SUPPORTED in custom roles, and these projects
// have no organization or folder parent to grant it at instead, so no principal
// -- the owner included -- can ever write one here.
//
// The continuous control is unchanged and lives outside this bridge:
// tools/ci/preview-runtime-iam-contract.sh proves zero Policy Analyzer results
// for these principals across all four projects before every preview traffic
// commit and hourly from reconcile-previews. What this adds is the preventive
// half on the one write path the protected pipeline itself controls: no
// reviewed plan, in any root, may grant these principals anything. The module
// config grants them nothing today, so the expected match count is zero.
// Strip the stable identifier Google appends when it serialises a deleted
// principal, so `deleted:serviceAccount:x@y?uid=123` is recognised as the same
// identity as `deleted:serviceAccount:x@y`.
function principalWithoutUid(member: string): string {
  const marker = member.indexOf("?uid=");
  return marker === -1 ? member : member.slice(0, marker);
}

// Refuse a plan that would leave a preview runtime principal holding access,
// or leave access with a principal broad enough to include one. Called on the
// `after` state only: `before` describes what is being replaced, and a
// forbidden principal there is exactly what a corrective plan removes.
function rejectPreviewRuntimeGrant(
  type: string,
  state: JsonValue,
  address: string,
  label: string,
): void {
  // Only IAM grant resources confer access, and only through their principal
  // fields. Scanning every string in every resource would refuse a plan for a
  // Cloud Run container environment variable that merely contains "allUsers",
  // which grants nothing -- and because this runs before no-op changes are
  // filtered, that would block every protected plan.
  if (!IAM_GRANT_RESOURCE_TYPES.has(type)) return;
  if (state === null || typeof state !== "object" || Array.isArray(state)) return;
  const principals: string[] = [];
  const single = state.member;
  if (single !== undefined && single !== null) {
    if (typeof single !== "string") {
      throw new Error(`${label} at ${address} has a non-string IAM member.`);
    }
    principals.push(single);
  }
  const many = state.members;
  if (many !== undefined && many !== null) {
    if (!Array.isArray(many)) {
      throw new Error(`${label} at ${address} has a non-array IAM member list.`);
    }
    for (const entry of many) {
      if (typeof entry !== "string") {
        throw new Error(`${label} at ${address} has a non-string IAM member.`);
      }
      principals.push(entry);
    }
  }
  const members = previewRuntimeMembers();
  // The quarantine is only worth anything if the pools it disables cannot be
  // re-enabled by a principal inside the window. Only the owner controller and
  // the ephemeral executor may ever hold that capability, so a plan that grants
  // a pool-mutation role to anyone else is refused before it can be applied.
  const role = typeof state.role === "string" ? state.role : "";
  if (POOL_MUTATION_ROLES.has(role)) {
    for (const principal of principals) {
      if (!isTrustedFederationController(principal)) {
        throw new Error(
          `${label} at ${address} grants ${role} to ${principal}, which could re-enable a quarantined workload identity pool.`,
        );
      }
    }
  }
  for (const principal of principals) {
    if (members.has(principalWithoutUid(principal))) {
      throw new Error(
        `${label} at ${address} grants the preview runtime ${principal}, which must hold no access.`,
      );
    }
    if (principal === STORAGE_ACCESS_LOG_DELIVERY_MEMBER) continue;
    if (
      BROAD_MEMBER_LITERALS.has(principal) ||
      BROAD_MEMBER_PATTERNS.some((pattern) => pattern.test(principal))
    ) {
      throw new Error(
        `${label} at ${address} grants ${principal}, which confers access on the preview runtime without naming it.`,
      );
    }
  }
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
    identity.terraformRoot !== "bootstrap" &&
    (identity.legacyCompatibilityMode || identity.transitionWorkflowSha !== "")
  ) {
    throw new Error("Non-bootstrap review identity contains bootstrap migration controls.");
  }
  if (identity.legacyCompatibilityMode && identity.transitionWorkflowSha !== "") {
    throw new Error("Review identity cannot combine legacy compatibility with a transition SHA.");
  }
  if (!/^[0-9a-z]{50}$/.test(identity.dhiParityId)) {
    throw new Error("Review identity DHI parity ID is malformed.");
  }
  if (identity.maxMutatorTokenLifetimeSeconds !== MUTATOR_TOKEN_SECONDS) {
    throw new Error("Review identity mutator-token lifetime drifted.");
  }
  if (
    identity.tokenDrainSeconds !== MUTATOR_TOKEN_SECONDS ||
    identity.tokenDrainSeconds < identity.maxMutatorTokenLifetimeSeconds
  ) {
    throw new Error("Review identity token-drain window drifted.");
  }
  const markerProof = normalizeMarkerProof(
    identity.markerProof,
    identity.legacyCompatibilityMode,
  );
  const exposureProof = normalizeExposureProof(identity.exposureProof, identity);
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
  const exposureAdoption = identity.terraformRoot === "exposure";
  if (exposureAdoption) {
    exact(plan.applyable, false, "exposure adoption plan applyability");
    if (plan.resource_drift !== undefined && plan.resource_drift !== null) {
      exact(
        array(plan.resource_drift, "exposure resource drift").length,
        0,
        "exposure resource drift count",
      );
    }
  }
  const changes = normalizeChanges(plan.resource_changes, identity, "resource change");
  const drift = normalizeChanges(plan.resource_drift, identity, "resource drift");
  const outputChanges = normalizeOutputChanges(plan.output_changes);
  // Terraform does not guarantee the ordering of these two lists across runs,
  // and neither carries meaning in its order. Every other list-valued input to
  // the digest is already ordered -- `normalizeChanges` sorts by address,
  // `normalizeOutputChanges` sorts by output name -- so these were the only
  // remaining channels through which the same plan could hash two ways.
  //
  // Observed live: cdbentley bootstrap plans 33288435770 and 33289064233, run
  // eight minutes apart against an unchanged world at the same platform and
  // consumer SHAs. Every resource change, every drift entry, `source`,
  // `checksSha256`, `outputChanges`, and `variables` were byte-identical;
  // `relevantAttributesSha256` was not, and an apply would have refused its own
  // approved plan. `checks` matched there but is unordered for the same reason
  // and is normalized here too rather than waiting for it to bite.
  const checks = canonicalizeUnorderedList(plan.checks ?? [], "Terraform checks");
  const relevantAttributes = canonicalizeUnorderedList(
    plan.relevant_attributes ?? [],
    "Terraform relevant attributes",
  );
  if (exposureAdoption) {
    const expectedRelevantAttributes: JsonValue = [{
      attribute: [],
      resource: "module.domains.google_cloud_run_domain_mapping.site",
    }];
    exact(
      canonicalJson(relevantAttributes),
      canonicalJson(expectedRelevantAttributes),
      "exposure relevant attribute contract",
    );
    const rawOutputs = record(plan.output_changes ?? {}, "exposure output changes");
    exactKeys(
      rawOutputs,
      new Set([
        "cloud_run_domain_mappings",
        "preview_domain_dns_records",
        "preview_url_pattern",
      ]),
      "exposure output changes",
    );
    exact(
      canonicalJson(Object.keys(rawOutputs).toSorted()),
      canonicalJson([
        "cloud_run_domain_mappings",
        "preview_domain_dns_records",
        "preview_url_pattern",
      ]),
      "exposure output change names",
    );
    for (const [name, raw] of Object.entries(rawOutputs)) {
      const output = record(raw, `exposure output ${name}`);
      exactKeys(
        output,
        new Set([
          "actions",
          "after",
          "after_sensitive",
          "after_unknown",
          "before",
          "before_sensitive",
        ]),
        `exposure output ${name}`,
      );
      exact(
        canonicalJson(Object.keys(output).toSorted()),
        canonicalJson([
          "actions",
          "after",
          "after_sensitive",
          "after_unknown",
          "before",
          "before_sensitive",
        ]),
        `exposure output ${name} field names`,
      );
      exact(
        canonicalJson(json(output.actions ?? [], `exposure output ${name} actions`)),
        '["no-op"]',
        `exposure output ${name} actions`,
      );
      exact(
        canonicalJson(json(output.before ?? null, `exposure output ${name} before`)),
        canonicalJson(json(output.after ?? null, `exposure output ${name} after`)),
        `exposure output ${name} value`,
      );
      rejectSensitive(output.before_sensitive ?? false, `exposure output ${name} before sensitivity`);
      rejectSensitive(output.after_sensitive ?? false, `exposure output ${name} after sensitivity`);
      rejectSensitive(output.after_unknown ?? false, `exposure output ${name} unknown value`);
      if (name === "cloud_run_domain_mappings") {
        const expectedMappings: Record<string, JsonValue> = {};
        for (const domain of RUNSETTA_DOMAINS) {
          expectedMappings[domain] = RUNSETTA_DOMAIN_RECORDS[domain].map((record) => ({
            ...record,
          }));
        }
        exact(
          canonicalJson(json(output.after, "exposure mapping output")),
          canonicalJson(expectedMappings),
          "exposure mapping output",
        );
      } else {
        exact(output.after, null, `exposure output ${name} null value`);
      }
    }
  }
  const variables = normalizeNamedHashes(plan.variables ?? {}, "Terraform variable");
  const manifest: JsonValue = {
    plan: {
      applyable: plan.applyable,
      changes,
      checksCount: Array.isArray(checks) ? checks.length : 0,
      checksSha256: hashJson(checks),
      complete: true,
      drift,
      ...(exposureAdoption
        ? {
            exposureZeroActionProof: {
              applyable: false,
              outputChangesCount: Object.keys(record(plan.output_changes ?? {}, "exposure output changes")).length,
              outputChangesSha256: hashJson(json(plan.output_changes ?? {}, "exposure output changes")),
              relevantAttributesCount: 1,
              relevantAttributesSha256: hashJson(relevantAttributes),
              resourceChangesCount: array(plan.resource_changes ?? [], "exposure resource changes").length,
              resourceChangesSha256: hashJson(json(plan.resource_changes ?? [], "exposure resource changes")),
              resourceDriftCount: 0,
              resourceDriftSha256: hashJson(json(plan.resource_drift ?? [], "exposure resource drift")),
            },
          }
        : {}),
      outputChanges,
      // Published alongside the hash so a mismatch in this field can be read off
      // two manifests directly. The exposure branch already publishes a count;
      // diagnosing plans 33288435770 and 33289064233 required a field-by-field
      // diff of two step summaries because the general manifest did not.
      relevantAttributesCount: Array.isArray(relevantAttributes) ? relevantAttributes.length : 0,
      relevantAttributesSha256: hashJson(relevantAttributes),
      // Every published manifest states what its own digest does not bind, so a
      // reviewer sees the exclusion contract in the step summary and an auditor
      // can check it from the receipt alone.
      volatileAttributeExclusions: Object.fromEntries(
        [...PROVIDER_VOLATILE_ATTRIBUTES.entries()]
          .map(([type, attributes]) => [type, [...attributes].toSorted()] as const)
          .toSorted(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0)),
      ),
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
    // 3: `before`/`after` hashes exclude PROVIDER_VOLATILE_ATTRIBUTES, and the
    // manifest carries `volatileAttributeExclusions`. A version-2 digest can
    // never equal a version-3 digest over the same plan, which is correct --
    // no receipt survives the platform SHA advance that ships this anyway.
    schemaVersion: 3,
    source: {
      approvalMode: identity.terraformRoot === "exposure" ? "adoption" : "plan",
      consumerSha: sha(identity.consumerSha, "consumer SHA"),
      consumerTreeSha: sha(identity.consumerTreeSha, "consumer tree SHA"),
      dhiParityId: identity.dhiParityId,
      legacyCompatibilityMode: identity.legacyCompatibilityMode,
      maxMutatorTokenLifetimeSeconds: identity.maxMutatorTokenLifetimeSeconds,
      markerProof,
      exposureProof,
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

// Order a list whose ordering Terraform does not fix, by each entry's own
// canonical encoding. Deterministic, total, and content-preserving: two runs
// agree, and any change to what is in the list still changes the hash.
function canonicalizeUnorderedList(value: unknown, label: string): JsonValue {
  const entries = array(value, label).map((entry) => json(entry, label));
  return entries
    .map((entry) => [canonicalJson(entry), entry] as const)
    .toSorted(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([, entry]) => entry);
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

function exposureDomainAddress(domain: string): string {
  return `module.domains.google_cloud_run_domain_mapping.site[${JSON.stringify(domain)}]`;
}

function exposureDomainId(contract: RepositoryContract, domain: string): string {
  return `locations/${contract.exposure.region}/namespaces/${contract.projectId}/domainmappings/${domain}`;
}

function normalizeExposureProof(
  value: ExposureProof | null,
  identity: Pick<PlanIdentity, "repository" | "terraformRoot">,
): JsonValue | null {
  const adoptionReview = identity.terraformRoot === "exposure";
  const runsettaProdPrerequisite = identity.repository === "runsetta" &&
    identity.terraformRoot === "prod";
  if (!adoptionReview && !runsettaProdPrerequisite) {
    if (value !== null) throw new Error("A non-exposure review contains exposure proof.");
    return null;
  }
  if (value === null) throw new Error("An exposure review is missing its state and continuity proof.");
  const proof = record(value, "exposure proof");
  exactKeys(
    proof,
    new Set([
      "adoptionReceipt",
      "https",
      "mappingListCount",
      "mappingListSha256",
      "mappings",
      "seedContract",
      "state",
    ]),
    "exposure proof",
  );
  const contract = REPOSITORIES[identity.repository];
  const backend = contract.state.exposure;
  const expectedStateObject = `${backend.prefix}/default.tfstate`;
  const state = record(proof.state, "exposure state proof");
  exactKeys(
    state,
    new Set([
      "bucket",
      "generation",
      "lineage",
      "mappings",
      "metageneration",
      "object",
      "serial",
      "sha256",
      "size",
      "state",
    ]),
    "exposure state proof",
  );
  exact(state.bucket, backend.bucket, "exposure state bucket");
  exact(state.object, expectedStateObject, "exposure state object");
  const stateKind = requiredString(state.state, "exposure state kind");
  const stateMappings = array(state.mappings, "exposure state mappings").map((raw, index) => {
    const mapping = record(raw, `exposure state mapping ${index}`);
    exactKeys(mapping, new Set(["address", "domain", "id"]), "exposure state mapping");
    const domain = requiredString(mapping.domain, "exposure state mapping domain");
    if (!contract.exposure.domains.includes(domain)) {
      throw new Error("Exposure state owns an unreviewed domain mapping.");
    }
    const normalized = {
      address: requiredString(mapping.address, "exposure state mapping address"),
      domain,
      id: requiredString(mapping.id, "exposure state mapping ID"),
    };
    exact(normalized.address, exposureDomainAddress(domain), "exposure state mapping address");
    exact(normalized.id, exposureDomainId(contract, domain), "exposure state mapping ID");
    return normalized;
  }).toSorted((left, right) => left.domain.localeCompare(right.domain));
  if (new Set(stateMappings.map(({ domain }) => domain)).size !== stateMappings.length) {
    throw new Error("Exposure state contains duplicate domain-mapping ownership.");
  }
  const expectedDomains = [...contract.exposure.domains].toSorted();
  const stateDomains = stateMappings.map(({ domain }) => domain);
  let normalizedState: JsonValue;
  if (stateKind === "absent") {
    if (
      identity.repository !== "runsetta" ||
      state.generation !== null ||
      state.lineage !== null ||
      state.metageneration !== null ||
      state.serial !== null ||
      state.sha256 !== null ||
      state.size !== null ||
      stateMappings.length !== 0
    ) {
      throw new Error("Exposure state absence proof is inconsistent.");
    }
    normalizedState = {
      bucket: backend.bucket,
      generation: null,
      lineage: null,
      mappings: [],
      metageneration: null,
      object: expectedStateObject,
      serial: null,
      sha256: null,
      size: null,
      state: "absent",
    };
  } else if (stateKind === "present") {
    if (canonicalJson(stateDomains) !== canonicalJson(expectedDomains)) {
      throw new Error("Exposure state domain-mapping ownership is incomplete.");
    }
    const generation = numeric(
      requiredString(state.generation, "exposure state generation"),
      "exposure state generation",
    );
    const metageneration = numeric(
      requiredString(state.metageneration, "exposure state metageneration"),
      "exposure state metageneration",
    );
    const lineage = requiredString(state.lineage, "exposure state lineage");
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(lineage)) {
      throw new Error("Exposure state lineage is not canonical lowercase UUID-shaped hex.");
    }
    normalizedState = {
      bucket: backend.bucket,
      generation,
      lineage,
      mappings: stateMappings,
      metageneration,
      object: expectedStateObject,
      serial: boundedInteger(
        state.serial,
        "exposure state serial",
        identity.repository === "runsetta" ? 1 : 0,
        identity.repository === "runsetta" ? 1 : 2_147_483_647,
      ),
      sha256: hash(requiredString(state.sha256, "exposure state digest"), "exposure state digest"),
      size: numeric(requiredString(state.size, "exposure state size"), "exposure state size"),
      state: "present",
    };
  } else {
    throw new Error("Exposure state proof has an unreviewed state.");
  }

  let seedContract: JsonValue | null;
  if (stateKind === "absent") {
    exact(proof.seedContract, null, "absent exposure seed contract");
    seedContract = null;
  } else {
    const seed = record(proof.seedContract, "exposure seed contract");
    exactKeys(
      seed,
      new Set([
        "adoptionAudit",
        "byteLength",
        "confirmation",
        "liveContinuitySha256",
        "mode",
        "provider",
        "resourceSchemaVersion",
        "sha256",
        "stateFormatVersion",
        "terraformVersion",
      ]),
      "exposure seed contract",
    );
    exact(seed.confirmation, RUNSETTA_EXPOSURE_ADOPTION_CONFIRMATION, "exposure seed confirmation");
    exact(seed.byteLength, state.size, "exposure seed byte length");
    exact(seed.mode, "controller-create-only-refreshless-v1", "exposure seed mode");
    exact(
      seed.provider,
      "registry.terraform.io/hashicorp/google@7.45.0",
      "exposure seed provider",
    );
    exact(seed.resourceSchemaVersion, 1, "exposure seed resource schema version");
    exact(seed.stateFormatVersion, 4, "exposure seed state format version");
    exact(seed.terraformVersion, TERRAFORM_VERSION, "exposure seed Terraform version");
    exact(seed.sha256, state.sha256, "exposure seed state digest");
    seedContract = {
      adoptionAudit: seed.adoptionAudit === null || seed.adoptionAudit === undefined
        ? null
        : json(seed.adoptionAudit, "exposure adoption audit"),
      byteLength: requiredString(seed.byteLength, "exposure seed byte length"),
      confirmation: RUNSETTA_EXPOSURE_ADOPTION_CONFIRMATION,
      liveContinuitySha256: hash(
        requiredString(seed.liveContinuitySha256, "exposure live continuity digest"),
        "exposure live continuity digest",
      ),
      mode: "controller-create-only-refreshless-v1",
      provider: "registry.terraform.io/hashicorp/google@7.45.0",
      resourceSchemaVersion: 1,
      sha256: requiredString(seed.sha256, "exposure seed state digest"),
      stateFormatVersion: 4,
      terraformVersion: TERRAFORM_VERSION,
    };
  }

  const mappings = array(proof.mappings, "exposure mapping proofs").map((raw, index) => {
    const mapping = record(raw, `exposure mapping proof ${index}`);
    exactKeys(
      mapping,
      new Set(["domain", "generation", "id", "observedGeneration", "recordsSha256", "uid"]),
      "exposure mapping proof",
    );
    const domain = requiredString(mapping.domain, "exposure mapping domain");
    if (!contract.exposure.domains.includes(domain)) {
      throw new Error("Exposure proof contains an unreviewed live domain mapping.");
    }
    const generation = numeric(
      requiredString(mapping.generation, "exposure mapping generation"),
      "exposure mapping generation",
    );
    const observedGeneration = numeric(
      requiredString(mapping.observedGeneration, "exposure mapping observed generation"),
      "exposure mapping observed generation",
    );
    exact(observedGeneration, generation, "exposure mapping observed generation");
    const uid = requiredString(mapping.uid, "exposure mapping UID");
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(uid)) {
      throw new Error("Exposure mapping UID escaped its canonical syntax.");
    }
    return {
      domain,
      generation,
      id: (() => {
        const id = requiredString(mapping.id, "exposure mapping ID");
        exact(id, exposureDomainId(contract, domain), "exposure mapping ID");
        return id;
      })(),
      observedGeneration,
      recordsSha256: hash(
        requiredString(mapping.recordsSha256, "exposure record digest"),
        "exposure record digest",
      ),
      uid,
    };
  }).toSorted((left, right) => left.domain.localeCompare(right.domain));
  if (canonicalJson(mappings.map(({ domain }) => domain)) !== canonicalJson(expectedDomains)) {
    throw new Error("Exposure live mapping proof is incomplete or duplicated.");
  }
  exact(
    boundedInteger(proof.mappingListCount, "exposure mapping list count", 0, 100),
    expectedDomains.length,
    "exposure mapping list count",
  );
  const mappingListSha256 = hash(
    requiredString(proof.mappingListSha256, "exposure mapping list digest"),
    "exposure mapping list digest",
  );
  exact(
    mappingListSha256,
    hashJson(mappings.map(({ domain, generation, uid }) => ({ domain, generation, uid }))),
    "exposure mapping list digest",
  );

  const https = array(proof.https, "exposure HTTPS proofs").map((raw, index) => {
    const item = record(raw, `exposure HTTPS proof ${index}`);
    exactKeys(item, new Set(["bodySha256", "domain", "status", "url"]), "exposure HTTPS proof");
    const domain = requiredString(item.domain, "exposure HTTPS domain");
    if (domain !== "runsetta.com" && domain !== "www.runsetta.com") {
      throw new Error("Exposure HTTPS proof escaped the Runsetta hostname allowlist.");
    }
    exact(item.status, 200, "exposure HTTPS status");
    const url = requiredString(item.url, "exposure HTTPS URL");
    exact(url, `https://${domain}/livez`, "exposure HTTPS URL");
    return {
      bodySha256: hash(
        requiredString(item.bodySha256, "exposure HTTPS body digest"),
        "exposure HTTPS body digest",
      ),
      domain,
      status: 200,
      url,
    } as const;
  }).toSorted((left, right) => left.domain.localeCompare(right.domain));
  const expectedHttpsDomains = identity.repository === "runsetta"
    ? ["runsetta.com", "www.runsetta.com"]
    : [];
  if (canonicalJson(https.map(({ domain }) => domain)) !== canonicalJson(expectedHttpsDomains)) {
    throw new Error("Exposure HTTPS continuity proof is incomplete or unexpected.");
  }
  if (seedContract !== null) {
    const currentLiveDigest = exposureLiveContinuityDigest({
      https,
      mappingListCount: expectedDomains.length,
      mappingListSha256,
      mappings,
    });
    exact(
      record(seedContract, "normalized exposure seed contract").liveContinuitySha256,
      currentLiveDigest,
      "exposure pre/post live continuity digest",
    );
    const seed = record(seedContract, "normalized exposure seed contract");
    seed.adoptionAudit = seed.adoptionAudit === null
      ? null
      : normalizeExposureAdoptionAudit(seed.adoptionAudit, normalizedState, currentLiveDigest);
  }
  const adoptionReceipt = (() => {
    if (adoptionReview) {
      exact(proof.adoptionReceipt, null, "exposure adoption receipt prerequisite");
      return null;
    }
    const receipt = record(proof.adoptionReceipt, "Runsetta adoption receipt prerequisite");
    exactKeys(
      receipt,
      new Set([
        "adoptedAt",
        "generation",
        "manifestSha256",
        "metageneration",
        "runId",
        "sha256",
        "size",
      ]),
      "Runsetta adoption receipt prerequisite",
    );
    const adoptedAt = requiredString(receipt.adoptedAt, "Runsetta adoption receipt time");
    if (!Number.isFinite(Date.parse(adoptedAt))) {
      throw new Error("Runsetta adoption receipt time is malformed.");
    }
    return {
      adoptedAt,
      generation: numeric(
        requiredString(receipt.generation, "Runsetta adoption receipt generation"),
        "Runsetta adoption receipt generation",
      ),
      manifestSha256: hash(
        requiredString(receipt.manifestSha256, "Runsetta adoption manifest digest"),
        "Runsetta adoption manifest digest",
      ),
      metageneration: numeric(
        requiredString(receipt.metageneration, "Runsetta adoption receipt metageneration"),
        "Runsetta adoption receipt metageneration",
      ),
      runId: numeric(
        requiredString(receipt.runId, "Runsetta adoption receipt run ID"),
        "Runsetta adoption receipt run ID",
      ),
      sha256: hash(
        requiredString(receipt.sha256, "Runsetta adoption receipt digest"),
        "Runsetta adoption receipt digest",
      ),
      size: numeric(
        requiredString(receipt.size, "Runsetta adoption receipt size"),
        "Runsetta adoption receipt size",
      ),
    };
  })();
  if (runsettaProdPrerequisite) {
    if (stateKind !== "present") {
      throw new Error("Runsetta production requires canonical adopted exposure state.");
    }
    const audit = record(
      record(seedContract, "Runsetta exposure seed contract").adoptionAudit,
      "Runsetta exposure adoption audit",
    );
    exact(audit.liveContinuityEqual, true, "Runsetta exposure live continuity equality");
  }
  return {
    adoptionReceipt,
    https,
    mappingListCount: expectedDomains.length,
    mappingListSha256,
    mappings,
    seedContract,
    state: normalizedState,
  };
}

function normalizeExposureAdoptionAudit(
  value: unknown,
  finalStateValue: JsonValue,
  liveDigest: string,
): JsonValue {
  const audit = record(value, "exposure adoption audit");
  exactKeys(
    audit,
    new Set([
      "controllerCreateLeaseDisposition",
      "initialState",
      "liveContinuityEqual",
      "outcome",
      "postLiveSha256",
      "preLiveSha256",
      "stateTransitionSha256",
    ]),
    "exposure adoption audit",
  );
  const finalState = record(finalStateValue, "final exposure state proof");
  const initial = record(audit.initialState, "initial exposure state proof");
  exactKeys(
    initial,
    new Set([
      "bucket",
      "generation",
      "lineage",
      "mappings",
      "metageneration",
      "object",
      "serial",
      "sha256",
      "size",
      "state",
    ]),
    "initial exposure state proof",
  );
  exact(initial.bucket, finalState.bucket, "initial exposure state bucket");
  exact(initial.object, finalState.object, "initial exposure state object");
  const outcome = requiredString(audit.outcome, "exposure adoption outcome");
  if (![
    "created",
    "exact-existing",
    "precondition-reconciled",
    "response-loss-reconciled",
  ].includes(outcome)) {
    throw new Error("Exposure adoption outcome escaped its reviewed values.");
  }
  const controllerCreateLeaseDisposition = requiredString(
    audit.controllerCreateLeaseDisposition,
    "controller create lease disposition",
  );
  exact(
    controllerCreateLeaseDisposition,
    outcome === "exact-existing" ? "not-granted" : "removed",
    "controller create lease disposition",
  );
  let initialState: JsonValue;
  if (outcome === "exact-existing") {
    exact(
      canonicalJson(json(initial, "initial exposure state")),
      canonicalJson(finalStateValue),
      "reused canonical exposure state",
    );
    initialState = JSON.parse(canonicalJson(finalStateValue)) as JsonValue;
  } else {
    exact(initial.state, "absent", "initial exposure state kind");
    for (const key of ["generation", "lineage", "metageneration", "serial", "sha256", "size"]) {
      exact(initial[key], null, `initial exposure state ${key}`);
    }
    exact(array(initial.mappings, "initial exposure state mappings").length, 0, "initial exposure state mapping count");
    initialState = {
      bucket: requiredString(initial.bucket, "initial exposure state bucket"),
      generation: null,
      lineage: null,
      mappings: [],
      metageneration: null,
      object: requiredString(initial.object, "initial exposure state object"),
      serial: null,
      sha256: null,
      size: null,
      state: "absent",
    };
  }
  exact(audit.liveContinuityEqual, true, "exposure live continuity equality");
  const preLiveSha256 = hash(
    requiredString(audit.preLiveSha256, "pre-adoption live digest"),
    "pre-adoption live digest",
  );
  const postLiveSha256 = hash(
    requiredString(audit.postLiveSha256, "post-adoption live digest"),
    "post-adoption live digest",
  );
  exact(preLiveSha256, liveDigest, "pre-adoption live digest");
  exact(postLiveSha256, liveDigest, "post-adoption live digest");
  const stateTransitionSha256 = hash(
    requiredString(audit.stateTransitionSha256, "exposure state transition digest"),
    "exposure state transition digest",
  );
  exact(
    stateTransitionSha256,
    hashJson({ finalState: finalStateValue, initialState }),
    "exposure state transition digest",
  );
  return {
    controllerCreateLeaseDisposition,
    initialState,
    liveContinuityEqual: true,
    outcome,
    postLiveSha256,
    preLiveSha256,
    stateTransitionSha256,
  };
}

function exposureProofFromJson(
  value: unknown,
  repository: RepositoryName,
  terraformRoot: TerraformRoot,
): ExposureProof | null {
  const normalized = normalizeExposureProof(
    value as ExposureProof | null,
    { repository, terraformRoot },
  );
  return normalized === null
    ? null
    : JSON.parse(canonicalJson(normalized)) as ExposureProof;
}

function exposureProofForReceipt(
  value: ExposureProof | null,
  invocation: Pick<Invocation, "repository" | "terraformRoot">,
): ExposureProof | null {
  return exposureProofFromJson(value, invocation.repository, invocation.terraformRoot);
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
  if (proof.tokenDrainSeconds !== MUTATOR_TOKEN_SECONDS) {
    throw new Error("Freeze proof token-drain window escaped the reviewed value.");
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

export const FEDERATION_POOL_ID = "github-actions";
const FEDERATION_CONVERGENCE_INTERVAL_MS = 2_000;
const FEDERATION_QUARANTINE_PREFIX = "federation-quarantine";
const MAX_FEDERATION_INTENT_PAGES = 32;
const FEDERATION_MARKER_SKEW_MS = 5 * 60_000;

export interface FederationPoolState {
  readonly description: string;
  readonly disabled: boolean;
  readonly displayName: string;
  readonly name: string;
  readonly state: string;
}

// Everything about the pool except the flag the bridge is allowed to move.
// Restore compares this, so a run cannot hand back a pool whose condition,
// description, or lifecycle state drifted while it held privilege.
export function federationPoolFingerprint(pool: FederationPoolState): string {
  return canonicalJson(
    json(
      { description: pool.description, displayName: pool.displayName, name: pool.name, state: pool.state },
      "federation pool fingerprint",
    ),
  );
}

export interface FederationQuarantineRecord {
  readonly capturedAt: string;
  readonly platformSha: string;
  readonly pools: readonly {
    readonly disabled: boolean;
    readonly fingerprint: string;
    readonly name: string;
    readonly repository: RepositoryName;
  }[];
  readonly repository: RepositoryName;
  readonly root: TerraformRoot;
  readonly runId: string;
}

export async function readFederationPool(
  projectId: string,
  token: string,
  fetcher: Fetcher,
): Promise<FederationPoolState | undefined> {
  const response = await fetcher(federationPoolUrl(projectId), {
    headers: executorHeaders(token),
    redirect: "error",
  });
  if (response.status === 404) return undefined;
  if (!response.ok) {
    throw new Error(`Workload identity pool read failed with HTTP ${response.status}.`);
  }
  return federationPoolFromJson(await boundedJson(response, 256 * 1024), projectId);
}

// PATCH returns a long-running operation, so "the request was accepted" is not
// the same as "the pool is disabled". Convergence is proved by reading the pool
// back, because that is the only statement that matters to a token holder.
export async function setFederationPoolDisabled(
  projectId: string,
  disabled: boolean,
  token: string,
  fetcher: Fetcher,
  deadlineMs: number,
  sleep: (ms: number) => Promise<void> = (ms) => Bun.sleep(ms),
  now: () => number = () => Date.now(),
): Promise<FederationPoolState> {
  const url = new URL(federationPoolUrl(projectId));
  url.searchParams.set("updateMask", "disabled");
  const response = await fetcher(url, {
    body: JSON.stringify({ disabled }),
    headers: { ...executorHeaders(token), "Content-Type": "application/json; charset=utf-8" },
    method: "PATCH",
    redirect: "error",
  });
  if (!response.ok) {
    throw new Error(`Workload identity pool update failed with HTTP ${response.status}.`);
  }
  await boundedJson(response, 256 * 1024);
  for (;;) {
    assertBeforeDeadline(now(), deadlineMs, "workload identity pool convergence");
    const observed = await readFederationPool(projectId, token, fetcher);
    if (observed === undefined) {
      throw new Error("The workload identity pool vanished while it was being updated.");
    }
    if (observed.disabled === disabled) return observed;
    await sleep(FEDERATION_CONVERGENCE_INTERVAL_MS);
  }
}

function fortyHex(value: string, label: string): string {
  if (!/^[0-9a-f]{40}$/.test(value)) throw new Error(`${label} is not a commit SHA.`);
  return value;
}

function federationIntentBucket(invocation: Invocation): string {
  return REPOSITORIES[invocation.repository].state[invocation.terraformRoot].bucket;
}

function federationIntentPrefix(state: { readonly prefix: string }): string {
  return `${state.prefix}/.protected-bootstrap/${FEDERATION_QUARANTINE_PREFIX}/`;
}

function federationIntentObjectFor(state: { readonly prefix: string }, runId: string): string {
  return `${federationIntentPrefix(state)}${numeric(runId, "federation quarantine run ID")}.json`;
}

function federationIntentObject(invocation: Invocation): string {
  return federationIntentObjectFor(
    REPOSITORIES[invocation.repository].state[invocation.terraformRoot],
    invocation.githubRunId,
  );
}

// Every distinct bucket/prefix a quarantine intent can live under. An abruptly
// lost run for one target can be followed by a run for a different target, so
// recovery has to look everywhere rather than only where it happens to be
// pointed.
export interface FederationRecoverySummary {
  readonly restored: readonly string[];
  readonly scanned: number;
  readonly skippedComplete: readonly string[];
  readonly skippedUncontained: readonly string[];
}

interface StorageObjectListing {
  readonly generation: string;
  readonly metageneration: string;
  readonly name: string;
  readonly size: number;
}

// A listing that cannot be trusted cannot bound a restore. Duplicate names, a
// repeated or looping page token, and a page that arrives after the token said
// there were none are all refused rather than absorbed.
async function listStorageObjects(
  bucket: string,
  prefix: string,
  token: string,
  fetcher: Fetcher,
): Promise<readonly StorageObjectListing[]> {
  const items: StorageObjectListing[] = [];
  const names = new Set<string>();
  const seenTokens = new Set<string>();
  let pageToken: string | undefined;
  for (let page = 0; page < MAX_FEDERATION_INTENT_PAGES; page += 1) {
    const url = new URL(`https://storage.googleapis.com/storage/v1/b/${bucket}/o`);
    url.searchParams.set("prefix", prefix);
    url.searchParams.set("maxResults", "200");
    url.searchParams.set("fields", "items(name,generation,metageneration,size),nextPageToken");
    if (pageToken !== undefined) url.searchParams.set("pageToken", pageToken);
    const response = await fetcher(url, { headers: executorHeaders(token), redirect: "error" });
    if (!response.ok) {
      throw new Error(`Federation intent listing failed with HTTP ${response.status}.`);
    }
    const body = record(await boundedJson(response, 4 * 1024 * 1024), "federation intent listing");
    exactKeys(body, new Set(["items", "nextPageToken"]), "federation intent listing");
    for (const raw of array(body.items ?? [], "federation intent listing items")) {
      const item = record(raw, "federation intent listing item");
      const name = requiredString(item.name, "federation intent object name");
      if (!name.startsWith(prefix)) {
        throw new Error("Federation intent listing returned an object outside its prefix.");
      }
      // A name that appears twice means the pages shifted under the walk, and
      // the set that came back is not the set that exists.
      if (names.has(name)) {
        throw new Error(`Federation intent listing repeated ${name} across pages.`);
      }
      names.add(name);
      const size = Number(requiredString(item.size, "federation intent object size"));
      if (!Number.isSafeInteger(size) || size < 1 || size > 32 * 1024) {
        throw new Error("Federation intent object size escaped its bound.");
      }
      const generation = requiredString(item.generation, "federation intent generation");
      if (!/^[1-9][0-9]*$/.test(generation)) {
        throw new Error("Federation intent generation is malformed.");
      }
      items.push({
        generation,
        metageneration: requiredString(item.metageneration, "federation intent metageneration"),
        name,
        size,
      });
    }
    const next = body.nextPageToken;
    if (next === undefined || next === null) return items;
    const nextToken = requiredString(next, "federation intent page token");
    // A token the server has already handed out is a loop, not a page.
    if (seenTokens.has(nextToken)) {
      throw new Error("Federation intent listing repeated a page token.");
    }
    seenTokens.add(nextToken);
    pageToken = nextToken;
  }
  throw new Error("Federation intent listing did not terminate within its page bound.");
}

export interface FederationRestoreMarker {
  readonly intentDigest: string;
  readonly intentGeneration: string;
  readonly repository: RepositoryName;
  readonly restoredAt: string;
  readonly root: TerraformRoot;
  readonly runId: string;
}

export function federationRestoreMarkerBody(marker: FederationRestoreMarker): string {
  return `${canonicalJson(json({ ...marker }, "federation restore marker"))}\n`;
}

// A marker is only a completion record if it says, in full, which exact bytes
// of which exact object it completed. A file that merely has the right NAME
// proves nothing, and treating it as proof would let anyone suppress a restore
// by creating an empty object.
export function federationRestoreMarkerFromJson(
  value: unknown,
  nowMs: number,
  capturedAtMs: number,
): FederationRestoreMarker {
  const source = record(value, "federation restore marker");
  exactKeys(
    source,
    new Set(["intentDigest", "intentGeneration", "repository", "restoredAt", "root", "runId"]),
    "federation restore marker",
  );
  const intentDigest = requiredString(source.intentDigest, "federation restore marker digest");
  if (!/^[0-9a-f]{64}$/.test(intentDigest)) {
    throw new Error("Federation restore marker digest is not a SHA-256 digest.");
  }
  const intentGeneration = requiredString(
    source.intentGeneration,
    "federation restore marker intent generation",
  );
  if (!/^[1-9][0-9]*$/.test(intentGeneration)) {
    throw new Error("Federation restore marker intent generation is malformed.");
  }
  const restoredAt = requiredString(source.restoredAt, "federation restore marker time");
  const restoredAtMs = Date.parse(restoredAt);
  // A completion record is durable: it stays valid for as long as the intent it
  // completes exists. An arbitrary maximum age would eventually turn a valid
  // marker into a permanent preflight failure, or tempt someone to replay the
  // intent it completed. What IS checked is that it is canonical, that it did
  // not happen before the intent it claims to complete, and that it is not
  // dated into the future beyond clock skew.
  if (
    !Number.isFinite(restoredAtMs) ||
    new Date(restoredAtMs).toISOString() !== restoredAt ||
    restoredAtMs + FEDERATION_MARKER_SKEW_MS < capturedAtMs ||
    restoredAtMs > nowMs + FEDERATION_MARKER_SKEW_MS
  ) {
    throw new Error("Federation restore marker time is malformed or out of bounds.");
  }
  return {
    intentDigest,
    intentGeneration,
    repository: repositoryName(requiredString(source.repository, "federation restore marker repository")),
    restoredAt,
    root: rootName(requiredString(source.root, "federation restore marker root")),
    runId: numeric(requiredString(source.runId, "federation restore marker run ID"), "federation restore marker run ID"),
  };
}

// The production recovery path. It runs from --recover-only and as the preflight
// before every protected run, over the identical code, and it is the only thing
// that repairs a run that died holding four disabled pools.
//
// A pool is re-enabled only when all of this holds: the object sits at exactly
// the contracted key for the identity inside it, its listed size and generation
// match the bytes actually read back at that generation, it was written once,
// no VALIDATED completion marker exists for those exact bytes, and the executor
// for that record's own repository and run has been driven to provable absence
// through the same stable-empty recovery a lost run would get. Anything else is
// left closed and reported.
// The one containment path, shared verbatim by --recover-only and by the
// preflight every protected run performs. A single artifact probe is not
// containment: the executor is driven to provable absence through the same
// stable-empty, propagation-horizon recovery a lost run would receive, against
// the intent's OWN repository, run, project, and platform SHA -- never against
// whichever target this recovery run happens to be pointed at.
export function federationIntentContainment(options: {
  readonly fetcher: Fetcher;
  readonly now: () => number;
  readonly ownerAccessToken: string;
  readonly platformRoot: string;
  readonly runnerTemp: string;
  readonly sleep: (milliseconds: number) => Promise<void>;
  readonly telemetry?: BridgeTelemetry;
}): (intent: FederationQuarantineRecord, deadlineMs: number) => Promise<boolean> {
  return async (intent, deadlineMs) => {
    try {
      await recoverBridgeArtifactsUntilStable(
        {
          githubRunId: intent.runId,
          ownerAccessToken: options.ownerAccessToken,
          platformRoot: options.platformRoot,
          platformSha: intent.platformSha,
          repository: intent.repository,
          runnerTemp: options.runnerTemp,
        },
        options.fetcher,
        options.sleep,
        deadlineMs,
        options.now,
        options.telemetry,
      );
      return true;
    } catch {
      // Not contained is a state, not a crash: the caller leaves the pools
      // closed and reports the intent rather than guessing.
      return false;
    }
  };
}

interface DiscoveredIntent {
  readonly bucket: string;
  readonly capturedAtMs: number;
  readonly digest: string;
  readonly generation: string;
  readonly intent: FederationQuarantineRecord;
  readonly name: string;
}

// One canonical listing of every protected prefix, in a fixed order.
async function federationInventory(
  ownerAccessToken: string,
  fetcher: Fetcher,
): Promise<readonly (StorageObjectListing & { readonly bucket: string })[]> {
  const inventory: (StorageObjectListing & { readonly bucket: string })[] = [];
  for (const location of federationIntentLocations()) {
    const objects = await listStorageObjects(
      location.bucket,
      location.prefix,
      ownerAccessToken,
      fetcher,
    );
    for (const entry of objects) {
      const tail = entry.name.slice(location.prefix.length);
      // Nothing unknown may sit in a prefix whose contents authorize a restore.
      if (!/^[1-9][0-9]*\.json(\.restored)?$/.test(tail)) {
        throw new Error(`Federation intent prefix holds an unrecognised object: ${entry.name}.`);
      }
      inventory.push({ ...entry, bucket: location.bucket });
    }
    // A completion marker with no intent behind it is not a harmless leftover:
    // either the intent it completed was deleted, or somebody planted a marker
    // to suppress a restore that has not happened. Neither is safe to walk past.
    const present = new Set(objects.map((entry) => entry.name));
    for (const entry of objects) {
      if (!entry.name.endsWith(".restored")) continue;
      const intentName = entry.name.slice(0, -".restored".length);
      if (!present.has(intentName)) {
        throw new Error(
          `Federation restore marker ${entry.name} has no matching intent object.`,
        );
      }
    }
  }
  return inventory.toSorted((left, right) =>
    `${left.bucket}/${left.name}` < `${right.bucket}/${right.name}` ? -1 : 1
  );
}

// A single pass catches repeats but not omissions: a page that shifts can drop
// an object entirely and every within-pass check still passes. Two independent
// canonical listings must agree exactly -- name, generation, metageneration,
// size, and count -- before anything is restored on the strength of them.
async function stableFederationInventory(
  ownerAccessToken: string,
  fetcher: Fetcher,
): Promise<readonly (StorageObjectListing & { readonly bucket: string })[]> {
  const first = await federationInventory(ownerAccessToken, fetcher);
  const second = await federationInventory(ownerAccessToken, fetcher);
  if (first.length !== second.length) {
    throw new Error("The federation intent inventory changed size between two listings.");
  }
  first.forEach((entry, index) => {
    const later = second[index]!;
    if (
      entry.bucket !== later.bucket || entry.name !== later.name ||
      entry.generation !== later.generation || entry.metageneration !== later.metageneration ||
      entry.size !== later.size
    ) {
      throw new Error(`The federation intent inventory drifted at ${entry.bucket}/${entry.name}.`);
    }
  });
  return first;
}

// The production recovery path, shared verbatim by --recover-only and by the
// preflight every protected run performs.
//
// It is deliberately two-phase and fleet-global. Every intent covers ALL FOUR
// consumer pools, so restoring one intent re-enables federation everywhere. If
// a second incomplete intent existed whose executor was still privileged,
// restoring the first would hand that executor its credentials back. Nothing is
// therefore restored until every incomplete intent in the whole inventory has
// been validated and contained -- and if any one of them cannot be, none of
// them is touched.
export async function recoverFederationQuarantines(
  ownerAccessToken: string,
  fetcher: Fetcher,
  deadlineMs: number,
  containIntent: (intent: FederationQuarantineRecord, deadlineMs: number) => Promise<boolean>,
  sleep: (milliseconds: number) => Promise<void> = (ms) => Bun.sleep(ms),
  now: () => number = () => Date.now(),
): Promise<FederationRecoverySummary> {
  assertBeforeDeadline(now(), deadlineMs, "federation quarantine recovery scan");
  const inventory = await stableFederationInventory(ownerAccessToken, fetcher);
  const byKey = new Map(inventory.map((entry) => [`${entry.bucket}/${entry.name}`, entry]));
  const skippedComplete: string[] = [];
  const incomplete: DiscoveredIntent[] = [];
  let scanned = 0;

  // ---- phase one: validate and contain everything -------------------------
  for (const entry of inventory) {
    if (entry.name.endsWith(".restored")) continue;
    scanned += 1;
    assertBeforeDeadline(now(), deadlineMs, "federation quarantine recovery");
    const body = await readObjectGeneration(
      entry.bucket,
      entry.name,
      entry.generation,
      ownerAccessToken,
      fetcher,
    );
    if (Buffer.byteLength(body) !== entry.size) {
      throw new Error(`Federation intent ${entry.name} did not match its listed size.`);
    }
    const digest = sha256Hex(body);
    const intent = federationQuarantineRecordFromJson(JSON.parse(body) as unknown);
    const state = REPOSITORIES[intent.repository].state[intent.root];
    exact(entry.name, federationIntentObjectFor(state, intent.runId), "federation intent object name");
    exact(entry.bucket, state.bucket, "federation intent bucket");
    exact(entry.metageneration, "1", "federation intent metageneration");
    const capturedAtMs = Date.parse(intent.capturedAt);

    const markerEntry = byKey.get(`${entry.bucket}/${entry.name}.restored`);
    if (markerEntry !== undefined) {
      exact(markerEntry.metageneration, "1", "federation restore marker metageneration");
      const markerBody = await readObjectGeneration(
        entry.bucket,
        markerEntry.name,
        markerEntry.generation,
        ownerAccessToken,
        fetcher,
      );
      if (Buffer.byteLength(markerBody) !== markerEntry.size) {
        throw new Error(
          `Federation restore marker ${markerEntry.name} did not match its listed size.`,
        );
      }
      const marker = federationRestoreMarkerFromJson(
        JSON.parse(markerBody) as unknown,
        now(),
        capturedAtMs,
      );
      // Canonical bytes, not merely equivalent JSON: a marker that parses to the
      // right values but was serialised differently was not written by this
      // system, and the whole point of the marker is provenance.
      exact(markerBody, federationRestoreMarkerBody(marker), "federation restore marker bytes");
      exact(marker.intentDigest, digest, "federation restore marker intent digest");
      exact(marker.intentGeneration, entry.generation, "federation restore marker intent generation");
      exact(marker.repository, intent.repository, "federation restore marker repository");
      exact(marker.root, intent.root, "federation restore marker root");
      exact(marker.runId, intent.runId, "federation restore marker run ID");
      skippedComplete.push(entry.name);
      continue;
    }
    incomplete.push({
      bucket: entry.bucket,
      capturedAtMs,
      digest,
      generation: entry.generation,
      intent,
      name: entry.name,
    });
  }

  if (incomplete.length === 0) {
    return { restored: [], scanned, skippedComplete, skippedUncontained: [] };
  }

  // Overlapping incomplete intents describe the same four pools. They can only
  // be restored together if they agree about what those pools looked like
  // before anything moved; if they disagree, restoring either one invents a
  // state nobody reviewed, so this stops for a human.
  const shapes = new Set(
    incomplete.map((entry) => canonicalJson(json([...entry.intent.pools], "intent pool shape"))),
  );
  if (shapes.size > 1) {
    throw new Error(
      `Federation recovery found ${incomplete.length} incomplete quarantine intents that disagree about the pre-quarantine pool state; restore none and recover by hand.`,
    );
  }

  const uncontained: string[] = [];
  for (const entry of incomplete) {
    assertBeforeDeadline(now(), deadlineMs, "federation quarantine containment");
    if (!await containIntent(entry.intent, deadlineMs)) uncontained.push(entry.name);
  }
  if (uncontained.length > 0) {
    // Restore NOTHING. Every intent covers every pool, so handing back the
    // pools for a contained intent would also hand them back to the executor of
    // an uncontained one.
    return { restored: [], scanned, skippedComplete, skippedUncontained: uncontained };
  }

  // Containment takes minutes. A new intent can be armed, or a marker written,
  // in that window -- and phase one's conclusions would then be about a world
  // that no longer exists. Re-prove the inventory is byte-identical to the one
  // those conclusions were drawn from, immediately before the first pool moves.
  const confirmed = await stableFederationInventory(ownerAccessToken, fetcher);
  if (confirmed.length !== inventory.length) {
    throw new Error(
      "The federation intent inventory changed while incomplete intents were being contained; restore none and rescan.",
    );
  }
  inventory.forEach((entry, index) => {
    const later = confirmed[index]!;
    if (
      entry.bucket !== later.bucket || entry.name !== later.name ||
      entry.generation !== later.generation || entry.metageneration !== later.metageneration ||
      entry.size !== later.size
    ) {
      throw new Error(
        `The federation intent inventory changed at ${entry.bucket}/${entry.name} while incomplete intents were being contained; restore none and rescan.`,
      );
    }
  });

  // ---- phase two: restore, deterministically -------------------------------
  const restored: string[] = [];
  for (const entry of incomplete) {
    assertBeforeDeadline(now(), deadlineMs, "federation quarantine restore");
    await restoreQuarantinedFederation(
      entry.intent,
      ownerAccessToken,
      fetcher,
      deadlineMs,
      sleep,
      now,
    );
    await writeFederationRestoreMarker(
      entry.bucket,
      entry.name,
      {
        intentDigest: entry.digest,
        intentGeneration: entry.generation,
        repository: entry.intent.repository,
        restoredAt: new Date(now()).toISOString(),
        root: entry.intent.root,
        runId: entry.intent.runId,
      },
      ownerAccessToken,
      fetcher,
      now,
      entry.capturedAtMs,
    );
    restored.push(entry.name);
  }
  return { restored, scanned, skippedComplete, skippedUncontained: [] };
}

// Idempotent under a lost write response: if the marker is already there, it
// must be the marker this run would have written, byte for byte. Anything else
// is a conflict, not a retry.
// One write, reconciled honestly.
//
// A write can fail three ways: it never happened, it happened and the response
// was lost, or the key was already taken. Only the first is a real failure, and
// the caller cannot tell them apart from the error alone. So on ANY failure --
// a precondition conflict, a transport error after the bytes were committed, a
// truncated response -- this asks the one question that settles it: is there an
// object at this key, written once, of exactly this size, whose bytes at its
// own generation are exactly the bytes we meant to write?
//
// If yes, the write committed and this is a retry. If anything about that is
// not exactly so, the ORIGINAL failure is rethrown -- never a message about the
// reconciliation, which would hide what actually went wrong.
async function writeImmutableObjectIdempotent(
  bucket: string,
  object: string,
  body: string,
  token: string,
  fetcher: Fetcher,
  validate: (parsed: unknown) => void = () => {},
): Promise<void> {
  let original: unknown;
  try {
    await writeImmutableObject(bucket, object, body, token, fetcher);
    return;
  } catch (error) {
    original = error;
  }
  try {
    const metadata = await readObjectMetadata(bucket, object, token, fetcher);
    if (metadata.size !== Buffer.byteLength(body)) throw original;
    const observed = await readObjectGeneration(
      bucket,
      object,
      metadata.generation,
      token,
      fetcher,
    );
    if (observed !== body) throw original;
    validate(JSON.parse(observed) as unknown);
  } catch {
    throw original;
  }
}

export async function writeFederationRestoreMarker(
  bucket: string,
  intentObject: string,
  marker: FederationRestoreMarker,
  token: string,
  fetcher: Fetcher,
  now: () => number = () => Date.now(),
  capturedAtMs: number = Date.parse(marker.restoredAt),
): Promise<void> {
  await writeImmutableObjectIdempotent(
    bucket,
    `${intentObject}.restored`,
    federationRestoreMarkerBody(marker),
    token,
    fetcher,
    (parsed) => federationRestoreMarkerFromJson(parsed, now(), capturedAtMs),
  );
}

export function federationIntentLocations(): readonly {
  readonly bucket: string;
  readonly prefix: string;
  readonly repository: RepositoryName;
  readonly root: TerraformRoot;
}[] {
  const seen = new Set<string>();
  const locations: {
    bucket: string;
    prefix: string;
    repository: RepositoryName;
    root: TerraformRoot;
  }[] = [];
  for (const repository of REPOSITORY_NAMES) {
    for (const root of ["bootstrap", "exposure", "prod"] as const) {
      const state = REPOSITORIES[repository].state[root];
      const key = `${state.bucket}|${federationIntentPrefix(state)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      locations.push({
        bucket: state.bucket,
        prefix: federationIntentPrefix(state),
        repository,
        root,
      });
    }
  }
  return locations;
}

// Disabled is necessary but not sufficient: the pool must also still be the
// pool that was captured. A PATCH that returned success against a pool whose
// description or lifecycle state moved is not the pool this run reasoned about.
export function assertQuarantinedPool(
  observed: FederationPoolState,
  captured: FederationQuarantineRecord["pools"][number],
): void {
  exact(observed.name, captured.name, "quarantined workload identity pool identity");
  exact(
    federationPoolFingerprint(observed),
    captured.fingerprint,
    `quarantined ${captured.repository} workload identity pool`,
  );
  exact(observed.disabled, true, `quarantined ${captured.repository} workload identity pool state`);
}

// Everything the run is claiming, bound together in one value. A verifier that
// trusts this receipt is trusting exactly: which plan was reviewed, what the
// apply proved while federation was closed, that mutation authority was gone
// before any of this was written, which pools were handed back and in what
// state, that the restored world audits to zero diff, and which durable intent
// this all belongs to.
export function buildFinalProtectedProof(
  input:
    & {
      readonly deElevation: ExecutorDeElevationProof;
      readonly intentDigest: string;
      readonly intentGeneration: string;
      readonly intent: FederationQuarantineRecord;
      readonly invocation: Invocation;
      readonly observedPools: readonly ObservedFederationPool[];
      readonly review: ReviewManifestResult;
    }
    & (
      | {
        readonly kind: "apply";
        readonly quarantinedApplyProof: ExecutionProof;
        readonly restoredAudit: {
          readonly detailedExitCode: 0;
          readonly observedAt: string;
          readonly outputSha256: string;
        };
      }
      | { readonly kind: "rehearsal" }
    ),
): FinalProtectedProof {
  const { deElevation, intent, intentDigest, intentGeneration, invocation, observedPools, review } =
    input;
  exact(intent.repository, invocation.repository, "final receipt intent repository");
  exact(intent.root, invocation.terraformRoot, "final receipt intent root");
  exact(intent.runId, invocation.githubRunId, "final receipt intent run ID");
  exact(intent.platformSha, invocation.platformSha, "final receipt intent platform SHA");
  if (observedPools.length !== REPOSITORY_NAMES.length) {
    throw new Error("Final receipt did not observe every consumer pool after restoration.");
  }
  REPOSITORY_NAMES.forEach((repository, index) => {
    exact(observedPools[index]!.repository, repository, "final receipt observed pool order");
  });
  const base: FinalProtectedProofBase = {
    consumerSha: invocation.consumerSha,
    deElevation,
    intentDigest,
    intentGeneration,
    observedPools: observedPools.map((pool) => ({ ...pool })),
    platformSha: invocation.platformSha,
    repository: invocation.repository,
    reviewSha256: review.sha256,
    root: invocation.terraformRoot,
    runId: invocation.githubRunId,
  };
  if (input.kind === "rehearsal") {
    return { ...base, countable: false, kind: "rehearsal" };
  }
  return {
    ...base,
    countable: true,
    kind: "apply",
    quarantinedApplyProofDigest: sha256Hex(
      canonicalJson(json(input.quarantinedApplyProof, "final receipt apply proof")),
    ),
    restoredAudit: { ...input.restoredAudit },
  };
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function federationQuarantineRecordFromJson(value: unknown): FederationQuarantineRecord {
  const source = record(value, "federation quarantine record");
  exactKeys(
    source,
    new Set(["capturedAt", "platformSha", "pools", "repository", "root", "runId"]),
    "federation quarantine record",
  );
  const pools = array(source.pools, "federation quarantine pools").map((raw, index) => {
    const entry = record(raw, `federation quarantine pool ${index}`);
    exactKeys(
      entry,
      new Set(["disabled", "fingerprint", "name", "repository"]),
      `federation quarantine pool ${index}`,
    );
    const repository = repositoryName(
      requiredString(entry.repository, "federation quarantine repository"),
    );
    const expected =
      `projects/${REPOSITORIES[repository].projectId}/locations/global/workloadIdentityPools/${FEDERATION_POOL_ID}`;
    // Only the exact contracted pools are ever touched by a restore.
    exact(entry.name, expected, "federation quarantine pool name");
    if (typeof entry.disabled !== "boolean") {
      throw new Error("Federation quarantine disabled flag is malformed.");
    }
    return {
      disabled: entry.disabled,
      fingerprint: hexOrCanonical(entry.fingerprint, "federation quarantine fingerprint"),
      name: expected,
      repository,
    };
  });
  // Exactly one entry per consumer, in the contracted order. A record that
  // repeats a repository or omits one cannot be restored from safely, and a
  // partial restore is worse than none.
  if (pools.length !== REPOSITORY_NAMES.length) {
    throw new Error("Federation quarantine record does not cover every consumer pool.");
  }
  REPOSITORY_NAMES.forEach((repository, index) => {
    exact(pools[index]!.repository, repository, "federation quarantine repository order");
  });
  const capturedAt = requiredString(source.capturedAt, "federation quarantine capture time");
  const capturedAtMs = Date.parse(capturedAt);
  if (!Number.isFinite(capturedAtMs) || new Date(capturedAtMs).toISOString() !== capturedAt) {
    throw new Error("Federation quarantine capture time is malformed.");
  }
  return {
    capturedAt,
    platformSha: fortyHex(
      requiredString(source.platformSha, "federation quarantine platform SHA"),
      "federation quarantine platform SHA",
    ),
    pools,
    repository: repositoryName(
      requiredString(source.repository, "federation quarantine repository"),
    ),
    root: rootName(requiredString(source.root, "federation quarantine root")),
    runId: numeric(requiredString(source.runId, "federation quarantine run ID"), "federation quarantine run ID"),
  };
}

function hexOrCanonical(value: unknown, label: string): string {
  const text = requiredString(value, label);
  if (text.length > 4096) throw new Error(`${label} is oversized.`);
  return text;
}

// The one restore path. A pool is re-enabled only when this run is the one that
// disabled it, the pool is exactly a contracted pool, it is still the pool that
// was captured, and it was enabled beforehand. A pool that was already disabled
// when the run started stays disabled: turning it on would be inventing a state
// nobody reviewed.
export async function restoreQuarantinedFederation(
  record: FederationQuarantineRecord,
  token: string,
  fetcher: Fetcher,
  deadlineMs: number,
  sleep: (ms: number) => Promise<void> = (ms) => Bun.sleep(ms),
  now: () => number = () => Date.now(),
): Promise<readonly ObservedFederationPool[]> {
  // What the world actually looks like afterwards, read back from the API. A
  // receipt that copied the pre-mutation intent forward would be asserting the
  // very thing it was supposed to be proving.
  const observedFinal: ObservedFederationPool[] = [];
  for (const pool of record.pools) {
    const projectId = REPOSITORIES[pool.repository].projectId;
    const observed = await readFederationPool(projectId, token, fetcher);
    if (observed === undefined) {
      throw new Error(`The ${pool.repository} workload identity pool vanished during the protected run.`);
    }
    exact(observed.name, pool.name, "restored workload identity pool identity");
    // Drift in anything other than the flag this run is allowed to move means
    // the pool is no longer the one that was captured, so it is left alone and
    // the run fails rather than writing over somebody else's change.
    exact(
      federationPoolFingerprint(observed),
      pool.fingerprint,
      `restored ${pool.repository} workload identity pool`,
    );
    if (pool.disabled) {
      // Never re-enable a pool that was already disabled before this run.
      if (!observed.disabled) {
        throw new Error(
          `The ${pool.repository} workload identity pool was disabled before this run and is now enabled.`,
        );
      }
      observedFinal.push(observedPool(pool.repository, observed));
      continue;
    }
    if (!observed.disabled) {
      observedFinal.push(observedPool(pool.repository, observed));
      continue;
    }
    const restored = await setFederationPoolDisabled(
      projectId,
      pool.disabled,
      token,
      fetcher,
      deadlineMs,
      sleep,
      now,
    );
    exact(
      federationPoolFingerprint(restored),
      pool.fingerprint,
      `restored ${pool.repository} workload identity pool`,
    );
    // The flag is not part of the fingerprint, so it is asserted separately:
    // the pool must end the run in exactly the state it started it in.
    exact(
      restored.disabled,
      pool.disabled,
      `restored ${pool.repository} workload identity pool disabled flag`,
    );
    observedFinal.push(observedPool(pool.repository, restored));
  }
  if (observedFinal.length !== REPOSITORY_NAMES.length) {
    throw new Error("Federation restoration did not observe every consumer pool.");
  }
  return observedFinal;
}

export interface ObservedFederationPool {
  readonly disabled: boolean;
  readonly fingerprint: string;
  readonly name: string;
  readonly observedAt: string;
  readonly repository: RepositoryName;
}

function observedPool(
  repository: RepositoryName,
  pool: FederationPoolState,
): ObservedFederationPool {
  return {
    disabled: pool.disabled,
    fingerprint: federationPoolFingerprint(pool),
    name: pool.name,
    observedAt: new Date(Date.now()).toISOString(),
    repository,
  };
}

export function federationPoolUrl(projectId: string): string {
  return `https://iam.googleapis.com/v1/projects/${projectId}/locations/global/workloadIdentityPools/${FEDERATION_POOL_ID}`;
}

export function federationPoolFromJson(value: unknown, projectId: string): FederationPoolState {
  const pool = record(value, "workload identity pool");
  const name = requiredString(pool.name, "workload identity pool name");
  const expected =
    `projects/${projectId}/locations/global/workloadIdentityPools/${FEDERATION_POOL_ID}`;
  // Identity first, and exactly. A suffix test would accept
  // projects/<anything>/locations/global/workloadIdentityPools/github-actions,
  // which says nothing about the pool actually under contract.
  if (name !== expected) {
    throw new Error("The workload identity pool is not the contracted GitHub Actions pool.");
  }
  const state = requiredString(pool.state, "workload identity pool state");
  if (state !== "ACTIVE") {
    // DELETED means soft-deleted; it also blocks token use, but restoring it is
    // not this bridge's job and pretending otherwise would hide a real problem.
    throw new Error(`The workload identity pool is ${state}, not ACTIVE.`);
  }
  if (pool.disabled !== undefined && typeof pool.disabled !== "boolean") {
    throw new Error("The workload identity pool disabled flag is malformed.");
  }
  return {
    description: requiredStringOrEmpty(pool.description, "workload identity pool description"),
    disabled: pool.disabled === true,
    displayName: requiredStringOrEmpty(pool.displayName, "workload identity pool display name"),
    name,
    state,
  };
}

// What actually authorizes the privileged window.
//
// Not the run listings. GitHub's offset pages are not snapshot-bound; the
// status-filtered and unfiltered listings come from one authority, so a server
// that hides a run from both satisfies every cross-check; and a summary can be
// restored by deleting the run that produced it. Every one of those attacks
// works by editing the record of activity.
//
// Nor a clock. Observing Actions disabled at T0 and again at T1 does not mean
// they were disabled in between: they can be re-enabled at T0+4m50s, a consumer
// workflow can mint a service-account token, and Actions can be disabled again
// before the next snapshot. Both observations agree and the token is alive.
//
// So the window is closed at the authorization layer instead. Google's contract
// for a DISABLED workload identity pool is the strong one:
//
//   "You cannot use a disabled pool to exchange tokens, or use existing tokens
//    to access resources."
//
// -- which is why the POOL is quarantined and not the provider, whose contract
// is explicitly weaker ("existing tokens still grant access"). With the pool
// disabled, a token minted a second before the quarantine is as useless as one
// that was never minted, and the token-lifetime timing argument disappears
// rather than being bounded.
//
// The reviewed plan carries `federation_quarantined = true`, so the apply's own
// desired state keeps the pool disabled and cannot re-enable what the bridge
// disabled a moment earlier. Restoration happens after the post-apply audit and
// after the executor is released, and only to the exact fingerprint captured
// before quarantine.
//
// An IAM deny policy would be stronger still and is provably unavailable here:
// `iam.denypolicies.*` is NOT_SUPPORTED in project custom roles,
// `roles/iam.denyAdmin` is not grantable at project scope, and these four
// projects have no organization or folder parent to grant it at instead.
// Bootstrap apply run 33291080180 died on exactly that setIamPolicy with
// "Role roles/iam.denyAdmin is not supported for this resource".
//
// The Actions-disabled checks and the run listings stay, and stay strict, as
// corroborating defence in depth. They no longer authorize anything.
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
        MUTATOR_TOKEN_SECONDS,
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

export function formatRecoveryScanBreadcrumb(scan: RecoveryScanTelemetry): string {
  if (!RECOVERY_SCAN_OUTCOME_SET.has(scan.outcome)) {
    throw new Error("Protected recovery scan outcome escaped its closed vocabulary.");
  }
  const fields = [
    ["elapsed_ms", scan.elapsedMs],
    ["scan_ms", scan.scanMs],
    ["proof_ms", scan.proofMs],
  ] as const;
  for (const [, value] of fields) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error("Protected recovery scan timing escaped its integer bound.");
    }
  }
  return [
    `Protected bridge recovery scan outcome=${scan.outcome}`,
    ...fields.map(([label, value]) => `${label}=${value}`),
  ].join(" ");
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
    recoveryScan: (scan) => {
      try {
        telemetry.recoveryScan(scan);
      } catch {
        // Sanitized recovery diagnostics are best effort and never weaken cleanup.
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
    recoveryScan: (scan) => {
      try {
        sink(formatRecoveryScanBreadcrumb(scan));
      } catch {
        // Scan formatting and sink failures are strictly diagnostic.
      }
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
  if (invocation.terraformRoot === "exposure" && invocation.mode !== "plan") {
    throw new Error("Exposure is a one-shot state adoption and has no apply path.");
  }
  telemetry = bestEffortTelemetry(telemetry);
  const startedAtMs = dependencies.now();
  const wrapperDeadlineMs = startedAtMs + invocation.operationBudgetSeconds * 1_000;
  const cleanupDeadlineMs = wrapperDeadlineMs - WRAPPER_CLEANUP_LEAD_SECONDS * 1_000;
  const internalOperationMinutes = invocation.mode === "plan"
    ? PLAN_INTERNAL_OPERATION_MINUTES
    : APPLY_INTERNAL_OPERATION_MINUTES;
  const operationDeadlineMs = Math.min(
    startedAtMs + internalOperationMinutes * 60_000,
    cleanupDeadlineMs - EXACT_CLEANUP_RESERVE_SECONDS * 1_000,
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
  let quarantinedFederation:
    | { readonly generation: string; readonly record: FederationQuarantineRecord }
    | undefined;
  let federationRestored = false;
  let pendingReceipt: FinalReceiptReference | undefined;
  let completedReleaseProof: ExecutorReleaseProof | undefined;
  let privateCleanupComplete = false;
  try {
    // Private cleanup is a PREREQUISITE for either artifact, not an epilogue.
    // Publishing first would leave a pending receipt a later finalizer could
    // count -- or a terminal rehearsal record claiming success -- for a run
    // whose plan file, Terraform data directory and sandbox were still on disk.
    const proveLocalCleanup = async (): Promise<void> => {
      for (const path of [planPath, tfDataPath, sandboxPath]) {
        await dependencies.removePrivatePath(path);
      }
      privateCleanupComplete = true;
    };
    // Nothing starts until the fleet is known to be free of unrepaired
    // quarantines, for any target, not just this one.
    telemetry.phase("controller.federation-preflight");
    const preflight = await dependencies.recoverFederationPreflight(
      invocation,
      operationDeadlineMs,
    );
    if (preflight.skippedUncontained.length > 0) {
      throw new Error(
        `A previous protected run left ${preflight.skippedUncontained.length} consumer federation quarantine(s) closed and its executor is not provably contained; recover before starting another run.`,
      );
    }
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
      exposureProof: await dependencies.proveExposure(invocation, session, preparation),
      freezeProof: await dependencies.proveFreeze(invocation, preparation.tokenDrainSeconds),
      markerProof: await dependencies.proveMarkers(invocation, session, false),
    };

    // The rehearsal route. It exercises every federation boundary against live
    // infrastructure -- arm the durable intent, disable all four pools and
    // prove each converged, revoke mutation authority and prove its absence,
    // hand the pools back and prove the restored fingerprints, then publish the
    // one countable receipt -- while touching no business resource. No
    // Terraform runs, no plan is read or consumed, and the executor is never
    // elevated. This is what makes the first live exercise of the quarantine
    // incapable of granting a production apply.
    if (invocation.mode === "rehearsal") {
      telemetry.phase("controller.quarantine");
      quarantinedFederation = await dependencies.armFederationQuarantine(
        invocation,
        operationDeadlineMs,
      );
      await dependencies.disableFederation(
        invocation,
        quarantinedFederation.record,
        operationDeadlineMs,
      );
      telemetry.phase("controller.de-elevate");
      const rehearsalDeElevation = await dependencies.deElevateExecutor(
        invocation,
        session,
        operationDeadlineMs,
      );
      telemetry.phase("controller.federation-restore");
      const rehearsalPools = await dependencies.restoreFederation(
        invocation,
        quarantinedFederation.record,
        quarantinedFederation.generation,
        operationDeadlineMs,
      );
      federationRestored = true;
      // A rehearsal reviews no Terraform plan, so its manifest digest names the
      // rehearsal identity rather than pretending to name a plan.
      const rehearsalReview: ReviewManifestResult = {
        canonical: "",
        sha256: sha256Hex(canonicalJson(json({
          consumerSha: invocation.consumerSha,
          mode: "rehearsal",
          platformSha: invocation.platformSha,
          repository: invocation.repository,
          runId: invocation.githubRunId,
          terraformRoot: invocation.terraformRoot,
        }, "rehearsal review identity"))),
      };
      telemetry.phase("controller.local-cleanup");
      await proveLocalCleanup();
      telemetry.phase("controller.apply-publish");
      pendingReceipt = await dependencies.publishFinalReceipt(
        invocation,
        rehearsalReview,
        buildFinalProtectedProof({
          deElevation: rehearsalDeElevation,
          intent: quarantinedFederation.record,
          intentDigest: sha256Hex(
            canonicalJson(json(quarantinedFederation.record, "federation quarantine record")),
          ),
          intentGeneration: quarantinedFederation.generation,
          invocation,
          kind: "rehearsal",
          observedPools: rehearsalPools,
          review: rehearsalReview,
        }),
        dependencies.now(),
      );
      return;
    }

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
        "-json",
        "-input=false",
        "-lock=false",
        "-no-color",
        "-out=/work/plan.tfplan",
        ...(invocation.terraformRoot === "exposure" ? ["-refresh=false"] : []),
        `-var=repository_id=${contract.repositoryId}`,
        ...(invocation.terraformRoot === "bootstrap"
          ? [
              `-var=active_workflow_sha=${invocation.platformSha}`,
              // Both the plan and the apply carry this, so the reviewed plan is
              // the one that keeps federation quarantined and the recomputed
              // plan still matches its receipt. The bridge restores the pool
              // after the post-apply audit, which is why every bootstrap plan
              // legitimately contains this one disable.
              `-var=federation_quarantined=true`,
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
      exposureProof: proof.exposureProof,
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
      const publishExposureProof = await dependencies.proveExposure(
        invocation,
        session,
        preparation,
      );
      exact(
        canonicalJson(json(publishExposureProof, "terminal plan exposure prerequisite")),
        canonicalJson(json(proof.exposureProof, "reviewed plan exposure prerequisite")),
        "terminal plan exposure prerequisite",
      );
      const publishProof: ExecutionProof = { ...proof, exposureProof: publishExposureProof };
      telemetry.phase("controller.plan-publish");
      await dependencies.publishPlanReceipt(
        invocation,
        session,
        review,
        publishProof,
        dependencies.now(),
      );
      await dependencies.appendSummary(invocation, reviewSummary(invocation, review, { kind: "publishing" }));
      console.log(`Protected Terraform review digest: ${review.sha256}`);
      return;
    }

    telemetry.phase("controller.apply-authorize");
    if (
      approved === undefined ||
      approved.sha256 !== review.sha256 ||
      review.sha256 !== invocation.approvedManifestSha256
    ) {
      // Publish what the apply actually recomputed before refusing. The success
      // path already publishes its manifest; the refusal path published nothing,
      // and the receipt stores only a digest, so a mismatch left no way to see
      // what diverged. Manifests are hash commitments and identity, never raw
      // plan values, so displaying one on failure discloses nothing new.
      await dependencies.appendSummary(
        invocation,
        reviewSummary(invocation, review, {
          kind: "refused",
          planRunId: invocation.approvedPlanRunId,
        }),
      );
      throw new Error("The recomputed plan does not match the fresh approved plan receipt.");
    }
    assertPreElevationTime(
      dependencies.now(),
      operationDeadlineMs,
      leaseExpiresAt.getTime(),
      session.tokenExpiresAtMs,
    );
    const preApplyProof: ExecutionProof = {
      ...preparation,
      exposureProof: await dependencies.proveExposure(invocation, session, preparation),
      freezeProof: await dependencies.proveFreeze(invocation, preparation.tokenDrainSeconds),
      markerProof: await dependencies.proveMarkers(invocation, session, false),
    };
    exact(
      canonicalJson(json(preApplyProof.markerProof, "fresh pre-apply markers")),
      canonicalJson(json(proof.markerProof, "approved pre-apply markers")),
      "fresh pre-apply marker proof",
    );
    exact(
      canonicalJson(json(preApplyProof.exposureProof, "fresh pre-apply exposure proof")),
      canonicalJson(json(proof.exposureProof, "approved pre-apply exposure proof")),
      "fresh pre-apply exposure proof",
    );
    assertPreElevationTime(
      dependencies.now(),
      operationDeadlineMs,
      leaseExpiresAt.getTime(),
      session.tokenExpiresAtMs,
    );
    await dependencies.consumeApproval(
      invocation,
      session,
      review,
      preApplyProof,
      dependencies.now(),
    );
    assertPreElevationTime(
      dependencies.now(),
      operationDeadlineMs,
      leaseExpiresAt.getTime(),
      session.tokenExpiresAtMs,
    );
    // Close consumer federation before any privilege exists. A disabled pool
    // blocks token exchange AND stops already-issued tokens reaching resources,
    // so this is what makes the privileged window unreachable rather than
    // merely unobserved. The approved plan carries the same desired state, so
    // the apply cannot undo it.
    telemetry.phase("controller.quarantine");
    // Armed before the first mutation. If disableFederation dies after the
    // first PATCH, this run still owns the undo.
    quarantinedFederation = await dependencies.armFederationQuarantine(
      invocation,
      operationDeadlineMs,
    );
    await dependencies.disableFederation(
      invocation,
      quarantinedFederation.record,
      operationDeadlineMs,
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
    const finalPreApplyExposureProof = await dependencies.proveExposure(
      invocation,
      session,
      preparation,
    );
    exact(
      canonicalJson(json(finalPreApplyExposureProof, "final pre-apply exposure prerequisite")),
      canonicalJson(json(preApplyProof.exposureProof, "authorized pre-apply exposure prerequisite")),
      "final pre-apply exposure prerequisite",
    );
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
        "-json",
        "-detailed-exitcode",
        "-input=false",
        "-lock=false",
        "-no-color",
        `-var=repository_id=${contract.repositoryId}`,
        ...(invocation.terraformRoot === "bootstrap"
          ? [
              `-var=active_workflow_sha=${invocation.platformSha}`,
              // Both the plan and the apply carry this, so the reviewed plan is
              // the one that keeps federation quarantined and the recomputed
              // plan still matches its receipt. The bridge restores the pool
              // after the post-apply audit, which is why every bootstrap plan
              // legitimately contains this one disable.
              `-var=federation_quarantined=true`,
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
      exposureProof: await dependencies.proveExposure(invocation, session, preparation),
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
    // Nothing below this line may still be able to change anything. The
    // executor hands back mutation authority first and proves, against the live
    // control plane, that every mutation permission is gone -- so the identity
    // that publishes the result is a reader.
    telemetry.phase("controller.de-elevate");
    const deElevationProof = await dependencies.deElevateExecutor(
      invocation,
      session,
      operationDeadlineMs,
    );
    // Federation comes back only once privilege is gone, and on the success
    // path it happens here rather than in cleanup, so the audit and the receipt
    // describe the world as it will actually be left.
    telemetry.phase("controller.federation-restore");
    const observedPools = await dependencies.restoreFederation(
      invocation,
      quarantinedFederation!.record,
      quarantinedFederation!.generation,
      operationDeadlineMs,
    );
    federationRestored = true;
    // The post-apply audit ran with the pools quarantined, so it attests a
    // state restoration immediately ends. This one attests the state the run
    // actually leaves behind: desired state with federation enabled, zero diff,
    // and its output digest is what the receipt binds.
    telemetry.phase("controller.final-audit");
    const restoredAudit = await dependencies.auditRestoredState(
      invocation,
      session,
      terraformDirectory,
      operationDeadlineMs,
    );
    telemetry.phase("controller.local-cleanup");
    await proveLocalCleanup();
    telemetry.phase("controller.apply-publish");
    // One receipt. The legacy post-apply receipt is gone: it was written before
    // privilege was surrendered and before federation was handed back, so it
    // could be counted as success for a run that never finished either.
    pendingReceipt = await dependencies.publishFinalReceipt(
      invocation,
      review,
      buildFinalProtectedProof({
        deElevation: deElevationProof,
        intent: quarantinedFederation!.record,
        intentDigest: sha256Hex(
          canonicalJson(json(quarantinedFederation!.record, "federation quarantine record")),
        ),
        intentGeneration: quarantinedFederation!.generation,
        invocation,
        kind: "apply",
        observedPools,
        quarantinedApplyProof: postApplyProof,
        restoredAudit,
        review,
      }),
      dependencies.now(),
    );
    await dependencies.appendSummary(
      invocation,
      reviewSummary(invocation, review, {
        kind: "consumed",
        planRunId: invocation.approvedPlanRunId,
      }),
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
    const [releaseResult, ...pathResults] = await Promise.allSettled([
      Promise.resolve().then(() =>
        dependencies.releaseExecutor(invocation, session, cleanupDeadlineMs)
      ),
      ...(privateCleanupComplete ? [] : [planPath, tfDataPath, sandboxPath].map((path) =>
        Promise.resolve().then(() => dependencies.removePrivatePath(path))
      )),
    ]);
    const cleanupErrors: unknown[] = [releaseResult, ...pathResults].flatMap((result) =>
      result.status === "rejected" ? [result.reason] : []
    );
    // These two failures are not equivalent. A leftover private path is
    // recoverable at leisure; an executor whose privilege was not provably
    // revoked is the exact condition the quarantine exists for.
    const executorContained = releaseResult!.status === "fulfilled";
    // The exact release proof, available only when release actually succeeded.
    const releaseProof = releaseResult!.status === "fulfilled"
      ? releaseResult!.value
      : undefined;
    // Federation is restored only after the executor is gone, so no window
    // exists in which consumer tokens work again while privilege still does.
    completedReleaseProof = releaseProof;
    if (quarantinedFederation !== undefined && !federationRestored) {
      if (!executorContained) {
        // Leave federation closed. Re-opening it while an executor may still
        // hold privilege would hand back exactly the overlap this design
        // removes. A human unblocks it with the durable intent.
        cleanupErrors.push(
          new Error(
            "Consumer federation stays quarantined because executor containment was not proven; restore it from the durable quarantine intent after revoking the executor.",
          ),
        );
      } else {
        telemetry.phase("controller.federation-restore");
        try {
          await dependencies.restoreFederation(
            invocation,
            quarantinedFederation.record,
            quarantinedFederation.generation,
            cleanupDeadlineMs,
          );
        } catch (error) {
          cleanupErrors.push(error);
        }
      }
    }
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
  // Only reachable when nothing above threw: the apply succeeded, privilege was
  // surrendered, federation was handed back, the restored state audited clean,
  // and cleanup completed. The owner now proves the executor is gone and
  // countersigns the receipt. Until this object exists the final receipt is a
  // claim, not a countable success -- which is what stops a run whose executor
  // deletion failed from being counted as one.
  if (pendingReceipt !== undefined) {
    if (completedReleaseProof === undefined) {
      // The receipt the executor wrote stays pending. Nothing counts it, and a
      // later fresh recovery run -- which has the full propagation budget --
      // finalizes it once absence is proven there.
      throw new Error(
        "The protected run produced no exact executor release proof, so its final receipt stays pending until recovery finalizes it.",
      );
    }
    telemetry.phase("controller.owner-completion");
    await dependencies.publishOwnerCompletion(
      invocation,
      pendingReceipt,
      completedReleaseProof,
      cleanupDeadlineMs,
    );
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
  dependencies: RecoveryDependencies | undefined = undefined,
  telemetry: BridgeTelemetry = NOOP_BRIDGE_TELEMETRY,
): Promise<void> {
  telemetry = bestEffortTelemetry(telemetry);
  const activeDependencies = dependencies ?? defaultRecoveryDependencies(telemetry);
  const startedAtMs = activeDependencies.now();
  const sourceProofDeadlineMs = startedAtMs + RECOVERY_SOURCE_PROOF_MINUTES * 60_000;
  telemetry.phase("recovery.source-proof");
  await activeDependencies.verifySource(invocation);
  const sourceProofCompletedAtMs = activeDependencies.now();
  assertBeforeDeadline(
    sourceProofCompletedAtMs,
    sourceProofDeadlineMs,
    "protected crash recovery source proof",
  );
  const recoveryDeadlineMs = sourceProofCompletedAtMs +
    RECOVERY_OPERATION_MINUTES * 60_000;
  telemetry.phase("recovery.inventory");
  await activeDependencies.recoverArtifacts(invocation, recoveryDeadlineMs);
  // Executor containment is proven first, above, so federation is handed back
  // only once nothing can still be holding privilege with it.
  telemetry.phase("recovery.federation");
  const federation = await activeDependencies.recoverFederation(invocation, recoveryDeadlineMs);
  if (federation.skippedUncontained.length > 0) {
    throw new Error(
      `Federation quarantine recovery left ${federation.skippedUncontained.length} intent(s) closed because their executors are not provably contained.`,
    );
  }
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
      dependencies,
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
  // One budget for THIS proof. Created per composite operation so an early
  // proof cannot spend what a later one needs. Omitted, the reads behave
  // exactly as they did before this layer existed.
  retry?: GithubProofRetryPolicy,
): Promise<ConsumerFreezeProof> {
  if (tokenDrainSeconds !== MUTATOR_TOKEN_SECONDS) {
    throw new Error("The consumer token-drain window escaped the reviewed values.");
  }
  if (!Number.isFinite(nowMs)) throw new Error("The consumer freeze time is invalid.");
  const requiredDrainMs = (tokenDrainSeconds + TOKEN_DRAIN_SKEW_SECONDS) * 1_000;
  const repositories: Array<ConsumerFreezeProof["repositories"][number]> = [];
  for (const repository of REPOSITORY_NAMES) {
    const contract = REPOSITORIES[repository];
    const base = `https://api.github.com/repos/${PLATFORM_OWNER}/${repository}`;
    const [metadataValue, permissionsValue, activeRuns, recentRuns] = await Promise.all([
      githubJson(base, token, fetcher, retry),
      githubJson(`${base}/actions/permissions`, token, fetcher, retry),
      githubActiveRuns(base, token, fetcher, retry),
      githubAllRuns(base, token, fetcher, retry),
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
  retry?: GithubProofRetryPolicy,
): Promise<readonly JsonValue[]> {
  const results: JsonValue[] = [];
  let page = 1;
  let expectedTotal: number | undefined;
  do {
    const value = record(
      await githubJson(`${base}/actions/runs?per_page=100&page=${page}`, token, fetcher, retry),
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
  retry?: GithubProofRetryPolicy,
): Promise<readonly JsonValue[]> {
  const results: JsonValue[] = [];
  for (const status of ["requested", "waiting", "pending", "queued", "in_progress"] as const) {
    let page = 1;
    let expectedTotal: number | undefined;
    do {
      const url = `${base}/actions/runs?status=${status}&per_page=100&page=${page}`;
      const value = record(await githubJson(url, token, fetcher, retry), `GitHub ${status} runs`);
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
    MUTATOR_TOKEN_SECONDS,
  );
  exact(
    maxMutatorTokenLifetimeSeconds,
    MUTATOR_TOKEN_SECONDS,
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

  await verifyTerraformProviderMirrorLayout(invocation.terraformProviderDirectory);

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

export async function verifyTerraformProviderMirrorLayout(
  providerDirectory: string,
): Promise<void> {
  let directory = providerDirectory;
  const rootMetadata = await lstat(directory);
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
    throw new Error("The extracted Google provider mirror root is not a real directory.");
  }
  for (const component of GOOGLE_PROVIDER_MIRROR_COMPONENTS) {
    const entries = await readdir(directory, { withFileTypes: true });
    if (
      entries.length !== 1 ||
      entries[0]?.name !== component ||
      !entries[0].isDirectory() ||
      entries[0].isSymbolicLink()
    ) {
      throw new Error("The extracted Google provider mirror escaped its exact directory layout.");
    }
    directory = join(directory, component);
    const metadata = await lstat(directory);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new Error("The extracted Google provider mirror contains a linked directory.");
    }
  }
  const entries = (await readdir(directory, { withFileTypes: true }))
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
    throw new Error("The extracted Google provider mirror escaped its exact two-file leaf contract.");
  }
  const providerBinary = join(directory, GOOGLE_PROVIDER_BINARY);
  const providerMetadata = await lstat(providerBinary);
  if ((providerMetadata.mode & 0o111) === 0) {
    throw new Error("The pinned Google provider binary is not executable.");
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
      diagnosticPolicy: "redacted-stderr",
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
      diagnosticPolicy: "redacted-stderr",
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

export function terraformSandboxCreateArguments(
  spec: TerraformSandboxSpec,
  uid: number,
  gid: number,
): readonly string[] {
  if (!Number.isSafeInteger(uid) || !Number.isSafeInteger(gid) || uid <= 0 || gid <= 0) {
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
  return [
    "create",
    `--name=${spec.containerName}`,
    `--label=${SANDBOX_OWNER_LABEL}=true`,
    `--label=${SANDBOX_RUN_LABEL}=${spec.invocation.githubRunId}`,
    `--label=${SANDBOX_PLATFORM_REPOSITORY_LABEL}=${PLATFORM_REPOSITORY_ID}`,
    `--label=${SANDBOX_TARGET_REPOSITORY_LABEL}=${REPOSITORIES[spec.invocation.repository].repositoryId}`,
    "--platform=linux/amd64",
    "--pull=never",
    "--network=bridge",
    // Docker's omitted PID mode is a private namespace. Its accepted explicit
    // modes are host or container:<id>; the superficially symmetric
    // --pid=private spelling is rejected by the daemon.
    "--ipc=private",
    // docker start --interactive can attach stdin only when the container was
    // created with OpenStdin. The executor token travels on that one attached
    // stream and never enters the container configuration.
    "--interactive",
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
    `--mount=type=bind,src=${spec.workDirectory},dst=/work,readonly=false`,
    `--workdir=/platform${relativeDirectory}`,
    "--env=CHECKPOINT_DISABLE=1",
    "--env=TF_DATA_DIR=/work/tfdata",
    "--env=TF_IN_AUTOMATION=1",
    "--entrypoint=/bin/sh",
    spec.invocation.terraformSandboxImage,
    "/platform/tools/ci/terraform-sandbox-entrypoint.sh",
    ...spec.args,
  ];
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
    options: {
      readonly capture?: boolean;
      readonly diagnosticPolicy: CommandDiagnosticPolicy;
      readonly ignoreFailure?: boolean;
      readonly stdin?: string;
      readonly label: string;
    },
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
      if (uid === undefined || gid === undefined) {
        throw new Error("Terraform sandbox requires one non-root numeric runner identity.");
      }
      await runDocker(
        spec.invocation,
        terraformSandboxCreateArguments(spec, uid, gid),
        deadlineMs,
        { diagnosticPolicy: "redacted-stderr", label: "create Terraform sandbox" },
      );
    },
    start: (containerName, invocation, executorToken, deadlineMs, capture) =>
      runDocker(invocation, ["start", "--attach", "--interactive", containerName], deadlineMs, {
        capture,
        diagnosticPolicy: "terraform-safe",
        label: "terraform sandbox",
        stdin: `${executorToken}\n`,
      }),
    kill: async (containerName, invocation, deadlineMs) => {
      await runDocker(invocation, ["kill", "--signal=KILL", containerName], deadlineMs, {
        diagnosticPolicy: "redacted-stderr",
        ignoreFailure: true,
        label: "kill Terraform sandbox",
      });
    },
    wait: async (containerName, invocation, deadlineMs) => {
      await runDocker(invocation, ["wait", containerName], deadlineMs, {
        diagnosticPolicy: "redacted-stderr",
        ignoreFailure: true,
        label: "wait for Terraform sandbox",
      });
    },
    remove: async (containerName, invocation, deadlineMs) => {
      await runDocker(invocation, ["rm", "--force", containerName], deadlineMs, {
        diagnosticPolicy: "redacted-stderr",
        ignoreFailure: true,
        label: "remove Terraform sandbox",
      });
      const survivors = await runDocker(
        invocation,
        ["ps", "--all", "--filter", `name=^/${containerName}$`, "--format", "{{.Names}}"],
        deadlineMs,
        {
          capture: true,
          diagnosticPolicy: "redacted-stderr",
          label: "prove Terraform sandbox removal",
        },
      );
      if (survivors.trim() !== "") {
        throw new Error(`Terraform sandbox ${containerName} survived kill/wait/remove.`);
      }
    },
  };
}

export function requiredOwnerTokenRemainingSeconds(
  invocation: Pick<Invocation, "mode" | "operationBudgetSeconds">,
): number {
  if (invocation.mode === "apply") {
    // Apply's late-failure authority is the fresh-runner recovery job. Its
    // eighteen-minute envelope already ends with the one-minute expiry margin.
    return invocation.operationBudgetSeconds + APPLY_MAIN_JOB_TAIL_MINUTES * 60 +
      FRESH_RECOVERY_JOB_TIMEOUT_MINUTES * 60;
  }
  return invocation.operationBudgetSeconds + PLAN_MAIN_JOB_RECOVERY_RESERVE_MINUTES * 60 +
    OWNER_TOKEN_EXPIRY_MARGIN_SECONDS;
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
    deElevateExecutor: (invocation, session, operationDeadlineMs) =>
      manager.deElevate(invocation, session, operationDeadlineMs),
    elevateExecutor: (invocation, session, leaseExpiresAt, operationDeadlineMs) =>
      manager.elevate(invocation, session, leaseExpiresAt, operationDeadlineMs),
    inspectPlan: inspectPlanFile,
    now: () => Date.now(),
    prepare: async (invocation, operationDeadlineMs) => {
      apiDeadlineMs = operationDeadlineMs;
      assertBeforeDeadline(Date.now(), operationDeadlineMs, "source preparation");
      await requireFreshGoogleOwnerAccessToken(
        invocation.ownerAccessToken,
        requiredOwnerTokenRemainingSeconds(invocation),
        api,
      );
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
      // `verifyTransitionCapability` returns the verified active capability even
      // when no transition is in flight, so this is a proven value in every
      // mode. The former legacy branch discarded it for a 3600s assumption the
      // bridge had already disproved.
      const tokenDrainSeconds = capability.maxMutatorTokenLifetimeSeconds;
      await proveConsumerFreeze(
        invocation.githubActionsToken,
        tokenDrainSeconds,
        api,
        Date.now(),
        // A fresh budget per proof. These reads are ~80-120 sequential GETs
        // across four repositories, and a single transient 502 among them
        // killed apply run 33305344368 outright.
        githubProofRetryPolicy(() => apiDeadlineMs),
      );
      await runDoctor(invocation, contract.repositoryId, consumerWorkflowPin);
      return { ...capability, consumerTreeSha, tokenDrainSeconds };
    },
    proveExposure: (invocation, session, preparation) =>
      proveExposure(
        invocation,
        session.accessToken,
        api,
        invocation.ownerAccessToken,
        session.exposureAdoptionAudit,
        preparation,
        githubProofRetryPolicy(() => apiDeadlineMs),
      ),
    proveFreeze: (invocation, tokenDrainSeconds) =>
      proveConsumerFreeze(
        invocation.githubActionsToken,
        tokenDrainSeconds,
        api,
        Date.now(),
        githubProofRetryPolicy(() => apiDeadlineMs),
      ),
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
    publishFinalReceipt: (invocation, review, proof, nowMs) =>
      publishFinalProtectedReceipt(
        invocation,
        invocation.ownerAccessToken,
        review,
        proof,
        nowMs,
        api,
      ),
    publishOwnerCompletion: async (invocation, pending, releaseProof, cleanupDeadlineMs) => {
      assertBeforeDeadline(Date.now(), cleanupDeadlineMs, "owner completion proof");
      await publishOwnerCompletionProof(
        invocation,
        invocation.ownerAccessToken,
        pending,
        releaseProof,
        Date.now(),
        api,
      );
    },
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
    releaseExecutor: async (invocation, _session, cleanupDeadlineMs) =>
      await releaseSandboxAndExecutor(
        () => sandbox.cleanupAll(cleanupDeadlineMs),
        () => manager.release(invocation, cleanupDeadlineMs),
      ),
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
      verifyPlanApproval(
        invocation,
        session.accessToken,
        proof,
        nowMs,
        api,
        githubProofRetryPolicy(() => apiDeadlineMs),
      ),
    armFederationQuarantine: async (invocation, _operationDeadlineMs) => {
      const pools: FederationQuarantineRecord["pools"][number][] = [];
      // Every consumer pool, not just the target's. The freeze proof already
      // spans the whole fleet because consumer principals are not provably
      // confined to their own project, and quarantining a smaller set would
      // need a transitive-reachability proof this bridge cannot make.
      for (const repository of REPOSITORY_NAMES) {
        const projectId = REPOSITORIES[repository].projectId;
        const pool = await readFederationPool(projectId, invocation.ownerAccessToken, api);
        if (pool === undefined) {
          // Fail closed. An absent pool on an established consumer is a missing
          // precondition, not isolation.
          throw new Error(
            `The ${repository} workload identity pool is absent; protected elevation cannot prove federation is closed.`,
          );
        }
        pools.push({
          disabled: pool.disabled,
          fingerprint: federationPoolFingerprint(pool),
          name: pool.name,
          repository,
        });
      }
      const record: FederationQuarantineRecord = {
        capturedAt: new Date(Date.now()).toISOString(),
        platformSha: invocation.platformSha,
        pools,
        repository: invocation.repository,
        root: invocation.terraformRoot,
        runId: invocation.githubRunId,
      };
      // Durable, immutable, and written BEFORE any mutation, so a runner that
      // dies at any later boundary still leaves a fresh runner enough to
      // restore exactly these pools to exactly this state -- and nothing else.
      // The generation it lands at is what a completion marker binds to.
      const generation = await writeImmutableObject(
        federationIntentBucket(invocation),
        federationIntentObject(invocation),
        canonicalJson(json(record, "federation quarantine record")),
        invocation.ownerAccessToken,
        api,
      );
      return { generation, record };
    },
    disableFederation: async (invocation, record, operationDeadlineMs) => {
      for (const pool of record.pools) {
        const converged = await setFederationPoolDisabled(
          REPOSITORIES[pool.repository].projectId,
          true,
          invocation.ownerAccessToken,
          api,
          operationDeadlineMs,
        );
        assertQuarantinedPool(converged, pool);
      }
    },
    recoverFederationPreflight: async (invocation, operationDeadlineMs) =>
      await recoverFederationQuarantines(
        invocation.ownerAccessToken,
        api,
        operationDeadlineMs,
        federationIntentContainment({
          fetcher: api,
          now: () => Date.now(),
          ownerAccessToken: invocation.ownerAccessToken,
          platformRoot: invocation.platformRoot,
          runnerTemp: invocation.runnerTemp,
          sleep: (milliseconds) => Bun.sleep(milliseconds),
          telemetry,
        }),
      ),
    restoreFederation: async (invocation, record, generation, operationDeadlineMs) => {
      const observed = await restoreQuarantinedFederation(
        record,
        invocation.ownerAccessToken,
        api,
        operationDeadlineMs,
      );
      // Exactly the marker the recovery path writes, through exactly the same
      // idempotent writer, so one reader validates both and a lost response
      // does not turn a completed restore into a conflict.
      await writeFederationRestoreMarker(
        federationIntentBucket(invocation),
        federationIntentObject(invocation),
        {
          intentDigest: sha256Hex(canonicalJson(json(record, "federation quarantine record"))),
          intentGeneration: generation,
          repository: record.repository,
          restoredAt: new Date(Date.now()).toISOString(),
          root: record.root,
          runId: record.runId,
        },
        invocation.ownerAccessToken,
        api,
      );
      return observed;
    },
    auditRestoredState: async (invocation, session, terraformDirectory, operationDeadlineMs) => {
      const contract = REPOSITORIES[invocation.repository];
      const output = await sandbox.run(
        invocation,
        session,
        terraformDirectory,
        [
          "plan",
          "-json",
          "-detailed-exitcode",
          "-input=false",
          "-lock=false",
          "-no-color",
          `-var=repository_id=${contract.repositoryId}`,
          ...(invocation.terraformRoot === "bootstrap"
            ? [
              `-var=active_workflow_sha=${invocation.platformSha}`,
              `-var=federation_quarantined=false`,
              `-var=legacy_compatibility_mode=${invocation.legacyCompatibilityMode}`,
              `-var=transition_workflow_sha=${invocation.transitionWorkflowSha}`,
            ]
            : []),
        ],
        operationDeadlineMs,
        true,
      );
      // The sandbox throws on a non-zero detailed exit code, so reaching here
      // IS the zero-diff result; the digest is what makes it evidence.
      return {
        detailedExitCode: 0,
        observedAt: new Date(Date.now()).toISOString(),
        outputSha256: sha256Hex(output ?? ""),
      };
    },
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

export async function releaseSandboxAndExecutor<T>(
  cleanupSandbox: () => Promise<void>,
  cleanupExecutor: () => Promise<T>,
): Promise<T> {
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
  // The executor result is the exact release proof the countable owner object
  // is written against; the sandbox has nothing to report.
  return (results[0] as PromiseFulfilledResult<T>).value;
}

function defaultRecoveryDependencies(
  telemetry: BridgeTelemetry = NOOP_BRIDGE_TELEMETRY,
): RecoveryDependencies {
  let apiDeadlineMs = Date.now() + RECOVERY_OPERATION_MINUTES * 60_000;
  const api = deadlineFetcher(fetch, () => apiDeadlineMs);
  return {
    now: () => Date.now(),
    recoverFederation: async (invocation, recoveryDeadlineMs) => {
      apiDeadlineMs = recoveryDeadlineMs;
      return await recoverFederationQuarantines(
        invocation.ownerAccessToken,
        api,
        recoveryDeadlineMs,
        federationIntentContainment({
          fetcher: api,
          now: () => Date.now(),
          ownerAccessToken: invocation.ownerAccessToken,
          platformRoot: invocation.platformRoot,
          runnerTemp: invocation.runnerTemp,
          sleep: (milliseconds) => Bun.sleep(milliseconds),
          telemetry,
        }),
        (milliseconds) => Bun.sleep(milliseconds),
        () => Date.now(),
      );
    },
    recoverArtifacts: async (invocation, recoveryDeadlineMs) => {
      apiDeadlineMs = recoveryDeadlineMs;
      await recoverBridgeArtifactsUntilStable(
        invocation,
        api,
        (milliseconds) => Bun.sleep(milliseconds),
        recoveryDeadlineMs,
        () => Date.now(),
        telemetry,
      );
    },
    verifySource: async (invocation) => {
      await requireFreshGoogleOwnerAccessToken(
        invocation.ownerAccessToken,
        RECOVERY_STEP_TIMEOUT_MINUTES * 60 + OWNER_TOKEN_EXPIRY_MARGIN_SECONDS,
        api,
      );
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

type TerraformDiagnosticClass =
  | "api-disabled"
  | "api-error"
  | "authentication"
  | "backend-state"
  | "configuration"
  | "conflict"
  | "network"
  | "not-found"
  | "permission-denied"
  | "prevent-destroy"
  | "provider-plugin"
  | "rate-limited"
  | "state-move"
  | "unknown";

function terraformDiagnosticClass(value: string): TerraformDiagnosticClass {
  const text = value.slice(0, MAX_TERRAFORM_DIAGNOSTIC_LINE_BYTES).toLowerCase();
  if (
    text.includes("service_disabled") ||
    text.includes("accessnotconfigured") ||
    text.includes("api has not been used") ||
    text.includes("api is disabled") ||
    text.includes("service is disabled")
  ) return "api-disabled";
  if (
    text.includes("permission_denied") ||
    text.includes("permission denied") ||
    text.includes("permission is required") ||
    /\bpermission\b.{0,160}\bdenied\b/.test(text) ||
    (text.includes("does not have") && text.includes("access")) ||
    text.includes("http 403") ||
    text.includes("error 403") ||
    /\bforbidden\b/.test(text)
  ) return "permission-denied";
  if (
    text.includes("unauthenticated") ||
    text.includes("invalid credential") ||
    text.includes("invalid authentication") ||
    (text.includes("oauth token") && text.includes("invalid")) ||
    text.includes("http 401") ||
    text.includes("error 401")
  ) return "authentication";
  if (
    text.includes("resource_exhausted") ||
    text.includes("rate limit") ||
    text.includes("quota exceeded") ||
    text.includes("too many requests")
  ) return "rate-limited";
  if (
    text.includes("failed to load plugin schemas") ||
    text.includes("failed to instantiate provider") ||
    text.includes("plugin did not respond") ||
    text.includes("incompatible api version") ||
    text.includes("unrecognized remote plugin")
  ) return "provider-plugin";
  if (text.includes("prevent_destroy") || text.includes("prevent destroy")) {
    return "prevent-destroy";
  }
  if (
    text.includes("moved object") ||
    text.includes("moved resource instance") ||
    text.includes("moved from")
  ) return "state-move";
  if (
    text.includes("state snapshot") ||
    text.includes("state lock") ||
    text.includes("failed to load state") ||
    text.includes("backend initialization") ||
    text.includes("backend configuration")
  ) return "backend-state";
  if (
    text.includes("unsupported argument") ||
    text.includes("missing required") ||
    text.includes("reference to undeclared") ||
    text.includes("invalid value") ||
    text.includes("invalid expression") ||
    text.includes("cycle:")
  ) return "configuration";
  if (
    text.includes("name resolution") ||
    text.includes("no such host") ||
    text.includes("tls handshake") ||
    text.includes("connection refused") ||
    text.includes("connection reset") ||
    text.includes("deadline exceeded") ||
    text.includes("i/o timeout")
  ) return "network";
  if (text.includes("already exists") || text.includes("http 409") || text.includes("error 409")) {
    return "conflict";
  }
  if (text.includes("not_found") || text.includes("not found") || text.includes("http 404")) {
    return "not-found";
  }
  if (text.includes("googleapi:") || text.includes("api error") || text.includes("http 5")) {
    return "api-error";
  }
  return "unknown";
}

function terraformHttpStatuses(value: string): readonly number[] {
  const statuses = new Set<number>();
  const text = value.slice(0, MAX_TERRAFORM_DIAGNOSTIC_LINE_BYTES);
  for (const match of text.matchAll(
    /(?:HTTP(?:\s+status)?|StatusCode|googleapi:\s*Error)\s*[:=]?\s*(400|401|403|404|409|412|429|5[0-9]{2})\b/gi,
  )) {
    statuses.add(Number(match[1]));
  }
  return [...statuses].toSorted((left, right) => left - right);
}

function terraformUiTailLines(value: string): {
  readonly lines: readonly string[];
  readonly truncated: boolean;
} {
  const lines: string[] = [];
  let cursor = value.length;
  let scanned = 0;
  while (cursor > 0 && scanned < MAX_TERRAFORM_UI_TAIL_LINES) {
    const separator = value.lastIndexOf("\n", cursor - 1);
    let line = value.slice(separator + 1, cursor);
    if (line.endsWith("\r")) line = line.slice(0, -1);
    if (line !== "") lines.push(line);
    cursor = separator < 0 ? 0 : separator;
    scanned += 1;
  }
  return { lines: lines.toReversed(), truncated: cursor > 0 };
}

/**
 * Produce a finite operator-facing classification without returning any raw
 * Terraform UI, provider diagnostic, resource value, address, or identifier.
 */
export function terraformFailureEnvelope(
  stdout: string,
  stderr: string,
  exitCode: number,
): string {
  let jsonUi: "absent" | "invalid" | "truncated" | "valid" = stdout === ""
    ? "absent"
    : "invalid";
  let diagnosticsTruncated = false;
  const errorDiagnostics: Array<Record<string, unknown>> = [];
  // A post-apply audit failure is the one case that reports a failure while
  // carrying no error diagnostics at all: `plan -detailed-exitcode` exits 2 for
  // "succeeded, changes present", which is a SUCCESS as far as diagnostics are
  // concerned. Everything below keys off severity === "error", so that envelope
  // was necessarily {diagnosticCount: 0, resourceTypes: [], classes:
  // ["unknown"]} -- it said convergence failed while being structurally unable
  // to say what failed to converge. That is the worst failure to leave
  // unexplained, because the audit runs only after consumeApproval has already
  // burned the plan, so the next attempt pays a fresh plan to learn nothing.
  //
  // Report the SHAPE of the residual diff and nothing more. Actions come from
  // a closed vocabulary and resource types from the same allowlist the error
  // path already uses, so this honours the contract above: no raw UI, no
  // diagnostic text, no resource value, no address, no identifier.
  const changeActions = new Set<string>();
  const changeResourceTypes = new Set<string>();
  let changesObserved = 0;
  const firstLineEnd = stdout.indexOf("\n");
  let firstLine = stdout.slice(0, firstLineEnd < 0 ? stdout.length : firstLineEnd);
  if (firstLine.endsWith("\r")) firstLine = firstLine.slice(0, -1);
  if (firstLine !== "" && firstLine.length <= MAX_TERRAFORM_DIAGNOSTIC_LINE_BYTES) {
    try {
      const version = JSON.parse(firstLine) as Record<string, unknown>;
      if (
        version.type === "version" &&
        version["@module"] === "terraform.ui" &&
        version.terraform === TERRAFORM_VERSION &&
        typeof version.ui === "string" &&
        /^1(?:\.|$)/.test(version.ui)
      ) jsonUi = "valid";
    } catch {
      jsonUi = "invalid";
    }
  }

  const tail = terraformUiTailLines(stdout);
  diagnosticsTruncated = tail.truncated;
  if (tail.truncated && jsonUi === "valid") jsonUi = "truncated";
  for (const line of tail.lines) {
    if (line.length > MAX_TERRAFORM_DIAGNOSTIC_LINE_BYTES) {
      diagnosticsTruncated = true;
      jsonUi = "invalid";
      continue;
    }
    let message: Record<string, unknown>;
    try {
      const parsed = JSON.parse(line) as unknown;
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        jsonUi = "invalid";
        continue;
      }
      message = parsed as Record<string, unknown>;
    } catch {
      jsonUi = "invalid";
      continue;
    }
    if (message.type === "planned_change" || message.type === "resource_drift") {
      const change = message.change;
      if (change !== null && typeof change === "object" && !Array.isArray(change)) {
        const entry = change as Record<string, unknown>;
        changesObserved += 1;
        if (typeof entry.action === "string" && TERRAFORM_CHANGE_ACTIONS.has(entry.action)) {
          changeActions.add(entry.action);
        }
        const resource = entry.resource;
        if (resource !== null && typeof resource === "object" && !Array.isArray(resource)) {
          const type = (resource as Record<string, unknown>).resource_type;
          if (typeof type === "string" && TERRAFORM_DIAGNOSTIC_RESOURCE_TYPES.has(type)) {
            changeResourceTypes.add(type);
          }
        }
      }
      continue;
    }
    if (message.type !== "diagnostic" || message["@level"] !== "error") continue;
    const diagnostic = message.diagnostic;
    if (diagnostic === null || typeof diagnostic !== "object" || Array.isArray(diagnostic)) {
      jsonUi = "invalid";
      continue;
    }
    const record = diagnostic as Record<string, unknown>;
    if (record.severity === "error") errorDiagnostics.push(record);
  }

  if (errorDiagnostics.length > MAX_TERRAFORM_DIAGNOSTICS) diagnosticsTruncated = true;
  const selected = errorDiagnostics.slice(-MAX_TERRAFORM_DIAGNOSTICS);
  const classes = new Set<TerraformDiagnosticClass>();
  const httpStatuses = new Set<number>();
  const resourceTypes = new Set<string>();
  const services = new Set<string>();
  const classificationTexts = [stderr.slice(0, MAX_TERRAFORM_DIAGNOSTIC_LINE_BYTES)];
  for (const diagnostic of selected) {
    const summary = typeof diagnostic.summary === "string" ? diagnostic.summary : "";
    const detail = typeof diagnostic.detail === "string" ? diagnostic.detail : "";
    classificationTexts.push(`${summary}\n${detail}`.slice(0, MAX_TERRAFORM_DIAGNOSTIC_LINE_BYTES));
    const address = typeof diagnostic.address === "string"
      ? diagnostic.address.slice(0, 4_096)
      : "";
    const addressParts = new Set(address.split(/[^a-z0-9_]+/));
    for (const resourceType of TERRAFORM_DIAGNOSTIC_RESOURCE_TYPES) {
      if (addressParts.has(resourceType)) resourceTypes.add(resourceType);
    }
  }
  for (const text of classificationTexts) {
    classes.add(terraformDiagnosticClass(text));
    for (const status of terraformHttpStatuses(text)) httpStatuses.add(status);
    const lower = text.toLowerCase();
    for (const service of TERRAFORM_DIAGNOSTIC_SERVICES) {
      if (lower.includes(service)) services.add(service);
    }
  }
  if (classes.size > 1) classes.delete("unknown");

  return canonicalJson({
    // "Observed", not "total": the tail scan reads at most
    // MAX_TERRAFORM_UI_TAIL_LINES lines, so a larger diff is undercounted.
    // diagnosticsTruncated already says when the scan did not reach the start;
    // naming this field for what was seen keeps a partial count from reading
    // as a complete one.
    changeActions: [...changeActions].toSorted(),
    changeResourceTypes: [...changeResourceTypes].toSorted(),
    changesObserved,
    classes: [...classes].toSorted(),
    diagnosticCount: Math.min(errorDiagnostics.length, MAX_TERRAFORM_DIAGNOSTICS),
    diagnosticsTruncated,
    exitCode: Number.isSafeInteger(exitCode) && exitCode >= 0 && exitCode <= 255 ? exitCode : -1,
    httpStatuses: [...httpStatuses].toSorted((left, right) => left - right),
    jsonUi,
    resourceTypes: [...resourceTypes].toSorted(),
    schemaVersion: 2,
    services: [...services].toSorted(),
  });
}

async function boundedCommandText(
  stream: ReadableStream<Uint8Array>,
  maximumBytes: number,
  kill: () => void,
  label: string,
): Promise<string> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      const chunk = result.value;
      totalBytes += chunk.byteLength;
      if (totalBytes > maximumBytes) {
        kill();
        await reader.cancel().catch(() => undefined);
        throw new Error(`${label} exceeded its protected output bound.`);
      }
      chunks.push(chunk);
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(output);
}

async function command(
  argv: readonly string[],
  options: Omit<CommandRequest, "argv">,
): Promise<string> {
  assertBeforeDeadline(Date.now(), options.deadlineMs, options.label);
  const child = Bun.spawn([...argv], {
    cwd: options.cwd,
    env: options.env,
    stdin: options.stdin === undefined ? "ignore" : "pipe",
    stderr: "pipe",
    stdout: "pipe",
  });
  const kill = () => {
    try {
      child.kill("SIGKILL");
    } catch {
      // A concurrently completed process needs no further containment.
    }
  };
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
      kill();
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
        boundedCommandText(
          child.stdout,
          MAX_PLAN_JSON_BYTES,
          kill,
          `${options.label} stdout`,
        ),
        boundedCommandText(
          child.stderr,
          MAX_COMMAND_STDERR_BYTES,
          kill,
          `${options.label} stderr`,
        ),
      ]),
      timeout,
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
  if (exitCode !== 0 && options.ignoreFailure !== true) {
    throw new Error(commandFailureMessage(options, stdout, stderr, exitCode));
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

export function commandFailureMessage(
  request: Pick<CommandRequest, "diagnosticPolicy" | "env" | "label">,
  stdout: string,
  stderr: string,
  exitCode: number,
): string {
  let diagnostic: string;
  if (request.diagnosticPolicy === "terraform-safe") {
    diagnostic = terraformFailureEnvelope(stdout, stderr, exitCode);
  } else if (request.diagnosticPolicy === "redacted-stderr") {
    diagnostic = redactDiagnostic(stderr, request.env);
  } else {
    return `${request.label} failed: protected diagnostic policy was invalid.`;
  }
  return `${request.label} failed${diagnostic === "" ? "." : `: ${diagnostic}`}`;
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
      diagnosticPolicy: "redacted-stderr",
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
      diagnosticPolicy: "redacted-stderr",
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
      diagnosticPolicy: "redacted-stderr",
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

// One policy write's intent. Elevation's revocation is part of the same value
// as its grants so the two cannot drift apart or be separated by an edit.
export interface PolicyGrant {
  readonly leases: readonly IamBinding[];
  readonly removals?: readonly IamBinding[];
}

export interface PolicyMutationRecord {
  readonly get: () => Promise<IamPolicy>;
  readonly label: string;
  readonly leases: readonly IamBinding[];
  readonly original: IamPolicy;
  // Bindings this write must REMOVE, applied in the same policy write as the
  // additions. Elevation revokes the consumed-receipt create lease here, so the
  // revocation costs no extra policy write, no extra CAS generation, and no
  // extra propagation window -- the mutation projection that follows is its
  // data-plane proof. Every removal target is also in some earlier record's
  // `leases`, so cleanup completeness never depends on the removal happening.
  readonly removals?: readonly IamBinding[];
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
  // The acquire-phase target-project record. Elevation re-reads that same
  // policy and must be able to tell its own read leases apart from authority
  // nobody granted.
  #projectMutation: PolicyMutationRecord | undefined;
  readonly #elevationMutations: PolicyMutationRecord[] = [];
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

  async #waitForPermissionProjection(
    invocation: Invocation,
    executorToken: string,
    expected: "mutation" | "none" | "read",
  ): Promise<void> {
    // State and control probes prove one IAM transition and therefore consume
    // one absolute consistency window. A slow state proof cannot silently
    // obtain a second five-minute window before control-plane validation.
    const consistencyDeadlineMs = permissionConsistencyDeadlineMs(this.#apiDeadlineMs);
    await waitForStatePermissions(
      REPOSITORIES[invocation.repository].state[invocation.terraformRoot],
      invocation,
      executorToken,
      expected,
      this.#fetcher,
      this.#sleep,
      DEFAULT_STATE_STORAGE_PERMISSION_PROBES,
      consistencyDeadlineMs,
    );
    await waitForControlPermissions(
      invocation,
      executorToken,
      expected,
      this.#fetcher,
      this.#sleep,
      consistencyDeadlineMs,
    );
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
    let exposureAdoptionResult: ExposureAdoptionResult | undefined;
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
      const readRole = invocation.terraformRoot === "exposure"
        ? undefined
        : await createEphemeralRole(
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
        { leases: [
          buildTokenCreatorLease(
            invocation.repository,
            invocation.githubRunId,
            leaseExpiresAt,
          ),
        ] },
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
      await this.#waitForPermissionProjection(invocation, session.accessToken, "none");
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
      await requireStorageBackendRoleContracts(
        invocation.ownerAccessToken,
        this.#fetcher,
      );
      const projectLeases = [
        ...(readRole === undefined
          ? []
          : buildExecutorProjectLeases(
              invocation.repository,
              invocation.githubRunId,
              leaseExpiresAt,
              account.email,
              readRole.name,
              "read",
            )),
        ...buildStorageAcquisitionLeases(
          invocation.repository,
          invocation.terraformRoot,
          invocation.mode,
          invocation.githubRunId,
          leaseExpiresAt,
          account.email,
        ),
        ...buildReceiptLeases(
          invocation.repository,
          invocation.terraformRoot,
          invocation.githubRunId,
          leaseExpiresAt,
          invocation.mode,
          invocation.approvedPlanRunId,
          account.email,
          invocation.exposureAdoptionRunId,
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
      this.#projectMutation = await this.#recordAndAdd(
        `project ${contract.projectId}`,
        { leases: projectLeases },
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
          { leases: [
            buildMarkerReadLease(
              markerRepository,
              invocation.githubRunId,
              leaseExpiresAt,
              contract.projectId,
              account.email,
            ),
          ] },
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
      await this.#waitForPermissionProjection(invocation, session.accessToken, "read");
      if (invocation.terraformRoot === "exposure" && invocation.mode === "plan") {
        this.#telemetry.phase("controller.exposure-state-adopt");
        const initialExposureProof = await proveExposure(
          invocation,
          session.accessToken,
          this.#fetcher,
          invocation.ownerAccessToken,
        );
        if (initialExposureProof === null) {
          throw new Error("Exposure state initialization lacks its owner live proof.");
        }
        let controllerCreateMutation: PolicyMutationRecord | undefined;
        if (initialExposureProof.state.state === "absent") {
          controllerCreateMutation = await this.#recordAndAdd(
            `controller exposure create ${contract.projectId}`,
            { leases: [buildExposureControllerCreateLease(
              invocation.githubRunId,
              leaseExpiresAt,
            )] },
            () => getPolicy(contract.projectId, invocation.ownerAccessToken, this.#fetcher),
            (policy) => setPolicy(
              contract.projectId,
              invocation.ownerAccessToken,
              policy,
              this.#fetcher,
            ),
          );
        }
        exposureAdoptionResult = await ensureExposureStateInitialized(
          invocation,
          session.accessToken,
          invocation.ownerAccessToken,
          initialExposureProof,
          this.#fetcher,
          this.#sleep,
          permissionConsistencyDeadlineMs(operationDeadlineMs),
        );
        if (controllerCreateMutation !== undefined) {
          this.#telemetry.phase("controller.exposure-create-revoke");
          await this.#removeRecordedMutation(
            controllerCreateMutation,
            permissionConsistencyDeadlineMs(operationDeadlineMs),
          );
        }
      }
      if (exposureAdoptionResult !== undefined) {
        const postRevocationState = await readExposureStateProof(
          invocation,
          session.accessToken,
          this.#fetcher,
        );
        exact(
          canonicalJson(json(postRevocationState, "post-revocation exposure state")),
          canonicalJson(json(exposureAdoptionResult.state, "initialized exposure state")),
          "exposure state after controller adoption",
        );
      }
      this.#telemetry.phase("executor.ready");
      if (exposureAdoptionResult === undefined) return session;
      const disposition = exposureAdoptionResult.audit.controllerCreateLeaseDisposition;
      const exposureAdoptionAudit: ExposureAdoptionAudit = {
        ...exposureAdoptionResult.audit,
        controllerCreateLeaseDisposition: disposition === "pending-removal"
          ? "removed"
          : "not-granted",
      };
      return { ...session, exposureAdoptionAudit };
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
    if (invocation.terraformRoot === "exposure") {
      throw new Error("Exposure adoption may never elevate its executor.");
    }
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
        executorCustomRolePermissions(invocation.repository, invocation.terraformRoot, "mutation"),
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
    // One write: the mutation grants and the consumed-receipt revocation
    // together, so the revocation costs no extra CAS generation and no extra
    // propagation window. consumeApproval has already written the consumed
    // receipt, so the executor's need for create on it ended before this point.
    const elevation = elevationPolicyRecord(
      invocation,
      this.#account.email,
      leaseExpiresAt,
      mutationRole.name,
      this.#projectMutation?.leases ?? [],
    );
    this.#elevationMutations.push(await this.#recordAndAdd(
      `mutation project ${contract.projectId}`,
      elevation,
      () => getPolicy(contract.projectId, invocation.ownerAccessToken, this.#fetcher),
      (policy) => setPolicy(contract.projectId, invocation.ownerAccessToken, policy, this.#fetcher),
      this.#account.email,
      this.#projectMutation?.leases ?? [],
    ));
    if (invocation.terraformRoot === "prod") {
      for (const [email, lease] of Object.entries(buildRuntimeActAsLeases(
        invocation.repository,
        invocation.githubRunId,
        leaseExpiresAt,
        this.#account.email,
      ))) {
        this.#elevationMutations.push(await this.#recordAndAdd(
          `runtime service account ${email}`,
          { leases: [lease] },
          () => getServiceAccountPolicy(email, invocation.ownerAccessToken, this.#fetcher),
          (policy) =>
            setServiceAccountPolicy(email, invocation.ownerAccessToken, policy, this.#fetcher),
          this.#account.email,
        ));
      }
    }
    await this.#waitForPermissionProjection(invocation, session.accessToken, "mutation");
    this.#elevated = true;
  }

  // Hand back mutation authority while keeping exactly the receipt-scoped read
  // authority the final receipt needs to be written with. This is what makes it
  // possible for no countable success to exist until privilege is already gone:
  // the identity that publishes the result can no longer change anything.
  async deElevate(
    invocation: Invocation,
    session: ExecutorSession,
    operationDeadlineMs: number,
  ): Promise<ExecutorDeElevationProof> {
    if (
      this.#invocation !== invocation || this.#session !== session ||
      this.#account === undefined
    ) {
      throw new Error("Executor de-elevation did not match the acquired single-run identity.");
    }
    this.#apiDeadlineMs = operationDeadlineMs;
    // A rehearsal never elevates, so there is nothing to revoke; the proof
    // below still runs, and states the absence positively rather than assuming
    // it from the fact that no grant was made.
    while (this.#elevationMutations.length > 0) {
      await this.#removeRecordedMutation(this.#elevationMutations.pop()!, operationDeadlineMs);
    }
    this.#elevated = false;
    // Positive proof against the live control plane: the mutation permission
    // set must now be absent and only the acquire-time read authority may
    // remain. This is the same probe elevation itself is validated with.
    await this.#waitForPermissionProjection(invocation, session.accessToken, "read");
    const mutation = executorControlPermissions(
      invocation.repository,
      invocation.terraformRoot,
      "mutation",
    );
    const read = new Set(
      executorControlPermissions(invocation.repository, invocation.terraformRoot, "read"),
    );
    return {
      executorEmail: this.#account.email,
      executorUniqueId: this.#account.uniqueId,
      observedAt: new Date(Date.now()).toISOString(),
      provenAbsent: mutation.filter((permission) => !read.has(permission)).toSorted(),
    };
  }

  async release(
    invocation: Invocation,
    cleanupDeadlineMs: number,
  ): Promise<ExecutorReleaseProof | undefined> {
    if (this.#invocation === undefined) return undefined;
    if (this.#invocation !== invocation) throw new Error("Executor cleanup invocation drifted.");
    this.#apiDeadlineMs = cleanupDeadlineMs;
    // Captured before #releaseAll clears them on success.
    const released = this.#account;
    const errors = await this.#releaseAll(invocation, cleanupDeadlineMs);
    if (errors.length > 0) {
      throw new AggregateError(errors, "Exact executor lease cleanup failed.");
    }
    this.#invocation = undefined;
    if (released === undefined) return undefined;
    return {
      artifactsDeleted: true,
      executorEmail: released.email,
      executorUniqueId: released.uniqueId,
      observedAt: new Date(Date.now()).toISOString(),
      permissionsProvenGone: true,
      projectBindingsCleared: true,
    };
  }

  // The grant arrives as one value. Leases and removals travelling together is
  // deliberate: elevation's revocation must ride the same write as its grants,
  // and a signature that took them as separate arguments let the removal be
  // dropped at the call site while everything still compiled and every test
  // still passed.
  async #recordAndAdd(
    label: string,
    grant: PolicyGrant,
    get: () => Promise<IamPolicy>,
    set: (policy: IamPolicy) => Promise<IamPolicy | undefined>,
    forbiddenMemberEmail?: string,
    // Leases this bridge is known to have granted the executor already. Absent
    // (acquire), the executor must hold no project authority at all. Present
    // (elevation), it may hold exactly these and nothing else -- the guard is
    // still "no authority nobody granted", which is what it was protecting.
    grantedExecutorLeases?: readonly IamBinding[],
  ): Promise<PolicyMutationRecord> {
    const { leases, removals } = grant;
    const original = await get();
    if (forbiddenMemberEmail !== undefined) {
      if (grantedExecutorLeases === undefined) {
        requireNoExecutorProjectBindings(original, forbiddenMemberEmail);
      } else {
        knownExecutorBindingsRemain(original, forbiddenMemberEmail, grantedExecutorLeases);
      }
    }
    const record: PolicyMutationRecord = {
      get,
      label,
      leases,
      original,
      ...(removals === undefined || removals.length === 0 ? {} : { removals }),
      set,
    };
    this.#policyCleanupComplete = false;
    this.#mutations.push(record);
    await addBindingsWithCas(record);
    return record;
  }

  async #removeRecordedMutation(
    record: PolicyMutationRecord,
    cleanupDeadlineMs: number,
  ): Promise<void> {
    if (!this.#mutations.includes(record)) {
      throw new Error("Temporary IAM mutation cleanup lost its exact record.");
    }
    await fencePolicyMutations(
      [record],
      this.#sleep,
      cleanupDeadlineMs,
      () => this.#randomHex?.() ?? randomBytes(10).toString("hex"),
    );
    for (const lease of record.leases) {
      // Exposure is pinned to runsetta by provenance validation, which is why
      // this was correct while that was the only caller. It is a trap for the
      // next one: a caller on another repository would poll the wrong
      // project's policy and vacuously "prove" removal. Assert the precondition
      // this project id actually depends on.
      if (this.#invocation!.terraformRoot !== "exposure" ||
        this.#invocation!.repository !== "runsetta") {
        throw new Error(
          "Recorded-mutation removal readback is scoped to the Runsetta exposure root.",
        );
      }
      await requireLeaseAbsentWithReadback(
        REPOSITORIES.runsetta.projectId,
        this.#invocation!.ownerAccessToken,
        lease as StorageLease,
        this.#fetcher,
        this.#sleep,
        cleanupDeadlineMs,
      );
    }
    const index = this.#mutations.indexOf(record);
    if (index < 0) throw new Error("Temporary IAM mutation cleanup record disappeared.");
    this.#mutations.splice(index, 1);
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
    await this.#waitForPermissionProjection(
      invocation,
      this.#session.accessToken,
      "none",
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
              async () => {
                try {
                  await requireNoUserManagedKeys(
                    observed,
                    invocation.ownerAccessToken,
                    this.#fetcher,
                  );
                } catch (error) {
                  // A 404 here is only proof of no keys once the account is
                  // proven gone. Re-read it: absent satisfies the check, and a
                  // still-present account keeps the 404 a propagation error so
                  // the loop retries rather than skipping the proof.
                  if (!(error instanceof Error) || !/HTTP 404\b/.test(error.message)) throw error;
                  const present = await getExecutor(
                    contract.projectId,
                    observed.uniqueId,
                    invocation.ownerAccessToken,
                    this.#fetcher,
                    true,
                  );
                  if (present !== undefined) throw error;
                }
              },
            );
            // This proves the executor holds no policy before deletion. An
            // absent account satisfies that: there is no account, so there is no
            // policy. Reading it with the strict variant instead made 404 an
            // error -- and because 404 is classified retryable, a permanently
            // absent account burned the entire IAM consistency window before
            // failing a run whose work had already succeeded.
            const policy = await this.#retryIamConsistency(
              "executor cleanup policy read",
              () => getServiceAccountPolicyIfPresent(
                observed,
                invocation.ownerAccessToken,
                this.#fetcher,
              ),
            );
            if (
              policy !== undefined &&
              (policy.bindings.length !== 0 || policy.auditConfigs !== undefined)
            ) {
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

export async function addBindingsWithCas(record: PolicyMutationRecord): Promise<void> {
  const removals = record.removals ?? [];
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const current = attempt === 0 ? record.original : await record.get();
    // A pure add keeps exactly its previous shape. Only a write that actually
    // removes something routes through removeExactBindings, which pins version
    // 3, so the ordinary path is unchanged byte for byte.
    const desired = addExactBindings(
      removals.length === 0 ? current : removeExactBindings(current, removals, record.original),
      record.leases,
    );
    const response = await record.set(desired);
    if (response === undefined) continue;
    requireContainsExactBindings(response, record.leases, record.label);
    requireOmitsExactBindings(response, removals, record.label);
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
        const desired = removeExactBindings(current, record.leases, record.original);
        const response = await record.set(desired);
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

class ExactDeterministicAccountAbsentOrDeniedError extends Error {}

type DeterministicDisableObservation =
  | "absent"
  | "absent-or-denied"
  | "disabled"
  | "transient";

type DeterministicIdentityObservation =
  | { readonly identity: ServiceAccountIdentity; readonly state: "present" }
  | { readonly identity: undefined; readonly state: "absent" | "absent-or-denied" };

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

// The committed policy is what Google returns, so a removal that survives it
// was not applied. Checking here makes the control-plane proof explicit rather
// than leaving the projection to discover it a minute later.
function requireOmitsExactBindings(
  policy: IamPolicy,
  removals: readonly IamBinding[],
  label: string,
): void {
  for (const removal of removals) {
    if (policy.bindings.some((binding) => bindingEqualsLease(binding, removal))) {
      throw new Error(`Google retained the ${label} lease that this write removes.`);
    }
  }
}

export function requireNoExecutorProjectBindings(policy: IamPolicy, email: string): void {
  const member = `serviceAccount:${email}`;
  if (policy.bindings.some((binding) => binding.members.includes(member))) {
    throw new Error("The dedicated executor has a standing project IAM binding.");
  }
}

export function knownExecutorBindingsRemain(
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

export async function requireLeaseAbsentWithReadback(
  projectId: string,
  token: string,
  lease: StorageLease,
  fetcher: Fetcher,
  sleep: (milliseconds: number) => Promise<void> = (milliseconds) => Bun.sleep(milliseconds),
  deadlineMs: number = Date.now() + IAM_CONSISTENCY_MAX_WAIT_MS,
  now: () => number = Date.now,
): Promise<void> {
  const title = lease.condition.title;
  let attempt = 0;
  while (now() < deadlineMs) {
    const policy = await getPolicy(projectId, token, fetcher);
    if (!policy.bindings.some((binding) => bindingEqualsLease(binding, lease))) {
      if (policy.bindings.some((binding) => binding.condition?.title === title)) {
        throw new Error("The removed temporary lease title was reused with altered authority.");
      }
      return;
    }
    const remainingMs = deadlineMs - now();
    if (remainingMs <= 0) break;
    await sleep(Math.min(iamRetryDelayMs(attempt), remainingMs));
    attempt = Math.min(attempt + 1, IAM_RETRY_MAX_ATTEMPTS - 1);
  }
  throw new Error("The exact temporary lease removal did not become observable before the deadline.");
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
  readonly exactAccountAbsentOrDenied: boolean;
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
        identityState: "absent" as const,
      })
    : (async () => {
        exact(REPOSITORIES[recovery.repository].projectId, projectId, "recovery executor project");
        const accountId = randomExecutorAccountId(
          deterministicArtifactHex(recovery.repository, recovery.githubRunId, "service-account"),
        );
        const disableResult = await disableDeterministicExecutorByEmail(
          recovery,
          ownerToken,
          fetcher,
        );
        const identityObservation = await observeDeterministicExecutorIdentityByEmail(
          recovery,
          ownerToken,
          fetcher,
        );
        return {
          accountId,
          disableResult,
          identity: identityObservation.identity,
          identityState: identityObservation.state,
        };
      })();
  // The direct disable fetch above is invoked synchronously before this
  // detached-policy recovery starts. Keep the policy scrub independent from
  // global list, key, role, and legacy-orphan convergence so none of those can
  // consume its deadline. Settle the promise immediately to avoid an
  // unhandled rejection while the independent lifecycle work proceeds.
  const initialDetachedRecovery = recovery === undefined
    ? Promise.resolve({
        exactAccountAbsentOrDenied: false,
        observed: false,
        status: "fulfilled" as const,
      })
    : recoverDetachedDeterministicPolicies(
        recovery,
        fetcher,
        sleep,
        cleanupDeadlineMs,
      ).then(
        (observed) => ({ ...observed, status: "fulfilled" as const }),
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
    directDisableObservedAuthority = ["disabled", "transient"].includes(
      directObservationResult.value.disableResult,
    );
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
      (observed) => ({ ...observed, status: "fulfilled" as const }),
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
  let detachedExactAccountAbsentOrDenied = false;
  if (detachedResult.status === "fulfilled") {
    detachedAuthorityObserved = detachedResult.observed;
    detachedExactAccountAbsentOrDenied = detachedResult.exactAccountAbsentOrDenied;
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
    exactAccountAbsentOrDenied: detachedExactAccountAbsentOrDenied ||
      (directObservationResult.status === "fulfilled" &&
        (directObservationResult.value.disableResult === "absent-or-denied" ||
          directObservationResult.value.identityState === "absent-or-denied")),
    hadActiveArtifacts: hadActiveArtifacts || detachedAuthorityObserved,
    roleIds,
  };
}

async function bridgeArtifactsRemain(
  projectId: string,
  ownerToken: string,
  fetcher: Fetcher,
  recovery: RecoveryInvocation,
): Promise<{
  readonly active: boolean;
  readonly exactAccountAbsentOrDenied: boolean;
}> {
  const observedAccounts = new Set<string>();
  let active = false;
  let exactAccountAbsentOrDenied = false;
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
      const observed = await observeDeterministicExecutorIdentityByEmail(
        recovery,
        ownerToken,
        fetcher,
      );
      if (observed.state === "present") active = true;
      else if (observed.state === "absent-or-denied") exactAccountAbsentOrDenied = true;
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
  const detached = await detachedDeterministicPoliciesRemain(recovery, fetcher);
  return {
    active: active || detached.active,
    exactAccountAbsentOrDenied: exactAccountAbsentOrDenied ||
      detached.exactAccountAbsentOrDenied,
  };
}

export async function recoverBridgeArtifactsUntilStable(
  invocation: RecoveryInvocation,
  fetcher: Fetcher,
  sleep: (milliseconds: number) => Promise<void>,
  cleanupDeadlineMs: number,
  now: () => number = () => Date.now(),
  telemetry: BridgeTelemetry = NOOP_BRIDGE_TELEMETRY,
): Promise<void> {
  telemetry = bestEffortTelemetry(telemetry);
  const projectId = REPOSITORIES[invocation.repository].projectId;
  const observationStartedAtMs = now();
  let emptySinceMs: number | undefined;
  let exactAccountWasAbsentOrDenied = false;
  while (now() < cleanupDeadlineMs) {
    const scanStartedAtMs = now();
    try {
      const inventory = await inventoryBridgeArtifacts(
        projectId,
        invocation.ownerAccessToken,
        fetcher,
        sleep,
        cleanupDeadlineMs,
        invocation,
      );
      const remaining = await bridgeArtifactsRemain(
        projectId,
        invocation.ownerAccessToken,
        fetcher,
        invocation,
      );
      const scanCompletedAtMs = now();
      const propagationHorizonComplete = scanCompletedAtMs - observationStartedAtMs >=
        RECOVERY_DOCUMENTED_PROPAGATION_MINUTES * 60_000;
      const exactAccountAbsentOrDenied = inventory.exactAccountAbsentOrDenied ||
        remaining.exactAccountAbsentOrDenied;
      const newlyMaskedExactAccount = exactAccountAbsentOrDenied &&
        !exactAccountWasAbsentOrDenied;
      exactAccountWasAbsentOrDenied = exactAccountAbsentOrDenied;
      let outcome: RecoveryScanOutcome;
      let proofMs = 0;
      let proofComplete = false;
      if (remaining.active) {
        emptySinceMs = undefined;
        outcome = "reset-active-artifact";
      } else if (!propagationHorizonComplete) {
        // The stable-empty proof begins only after the complete propagation
        // horizon. Clean scans inside that horizon are observation, not proof.
        emptySinceMs = undefined;
        outcome = "reset-propagation-horizon";
      } else if (newlyMaskedExactAccount) {
        // A first authorization-masked exact-account read can begin a new
        // absence window only after every global and detached-policy surface
        // is clean. It can never reuse earlier 404 proof time.
        emptySinceMs = scanCompletedAtMs;
        outcome = "reset-masked-account";
      } else if (inventory.hadActiveArtifacts) {
        // Recovery may have contained an artifact during this scan. Its clean
        // final readback begins a new window but cannot inherit prior absence.
        emptySinceMs = scanCompletedAtMs;
        outcome = "reset-observed-artifact";
      } else if (emptySinceMs === undefined) {
        emptySinceMs = scanCompletedAtMs;
        outcome = "proof-start";
      } else {
        proofMs = scanCompletedAtMs - emptySinceMs;
        proofComplete = proofMs >= RECOVERY_STABLE_EMPTY_MS;
        outcome = proofComplete ? "proof-complete" : "proof-continue";
      }
      telemetry.recoveryScan({
        elapsedMs: scanCompletedAtMs - observationStartedAtMs,
        outcome,
        proofMs,
        scanMs: scanCompletedAtMs - scanStartedAtMs,
      });
      if (proofComplete) return;
    } catch (error) {
      if (!recursivelyRetryableCleanupError(error)) throw error;
      // A failed read is not negative proof. Retry the entire inventory while
      // preserving hard failure for identity drift and malformed authority.
      emptySinceMs = undefined;
      exactAccountWasAbsentOrDenied = false;
      const scanFailedAtMs = now();
      telemetry.recoveryScan({
        elapsedMs: scanFailedAtMs - observationStartedAtMs,
        outcome: "reset-retryable-read",
        proofMs: 0,
        scanMs: scanFailedAtMs - scanStartedAtMs,
      });
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
  invocation: RecoveryInvocation,
  ownerToken: string,
  fetcher: Fetcher,
): Promise<DeterministicDisableObservation> {
  const projectId = REPOSITORIES[invocation.repository].projectId;
  const email = deterministicExecutorEmail(invocation);
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
  if (response.status === 404) {
    await boundedText(response, 64 * 1024);
    return "absent";
  }
  if (response.status === 403) {
    // IAM deliberately masks some nonexistent service accounts as forbidden.
    // This is not success: only the exact deterministic email may enter this
    // state, and the independent global list/policy scans plus the complete
    // propagation and stable-empty windows must still prove absence.
    await boundedText(response, 64 * 1024);
    return "absent-or-denied";
  }
  if ([408, 409, 429, 500, 502, 503, 504].includes(response.status)) {
    await boundedText(response, 64 * 1024);
    return "transient";
  }
  await boundedText(response, 64 * 1024);
  throw new Error(`Deterministic executor disable failed with HTTP ${response.status}.`);
}

async function observeDeterministicExecutorIdentityByEmail(
  invocation: RecoveryInvocation,
  ownerToken: string,
  fetcher: Fetcher,
): Promise<DeterministicIdentityObservation> {
  const projectId = REPOSITORIES[invocation.repository].projectId;
  const email = deterministicExecutorEmail(invocation);
  const response = await fetcher(serviceAccountIdentifierUrl(projectId, email), {
    headers: googleHeaders(ownerToken),
    redirect: "error",
  });
  if (response.status === 404) {
    await boundedText(response, 64 * 1024);
    return { identity: undefined, state: "absent" };
  }
  if (response.status === 403) {
    await boundedText(response, 64 * 1024);
    return { identity: undefined, state: "absent-or-denied" };
  }
  if (!response.ok) {
    await boundedText(response, 64 * 1024);
    throw new Error(`Deterministic executor identity lookup failed with HTTP ${response.status}.`);
  }
  return {
    identity: parseReservedServiceAccountIdentity(
      await boundedJson(response, 256 * 1024),
      projectId,
    ),
    state: "present",
  };
}

export async function disableOrphanExecutor(
  account: ServiceAccountIdentity,
  ownerToken: string,
  fetcher: Fetcher,
  sleep: (milliseconds: number) => Promise<void>,
  cleanupDeadlineMs: number,
): Promise<ServiceAccount> {
  try {
    // Containment. In-job recovery for healthmcp prod apply 33341667742 died
    // here on a single non-retryable HTTP 403 while trying to disable the
    // executor; the fresh-runner recovery job then did the same work moments
    // later and succeeded, which is what a propagation delay looks like rather
    // than a real denial. Giving up instantly is the dangerous direction on
    // this path: the whole purpose is to disable an executor that may still be
    // live, and only the backstop job prevented that from mattering. Retrying
    // a 403 here still fails closed, just at the consistency deadline and with
    // an aggregate error naming every attempt.
    return await setExecutorDisabled(
      account,
      true,
      ownerToken,
      fetcher,
      sleep,
      cleanupDeadlineMs,
      true,
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
    const phases: readonly ("mutation" | "read")[] = provenance.root === "exposure"
      ? []
      : provenance.mode === "apply"
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
    ...buildStorageAcquisitionLeases(
      provenance.repository,
      provenance.root,
      provenance.mode,
      provenance.runId,
      provenance.expiresAt,
      account.email,
    ),
    ...buildReceiptLeases(
      provenance.repository,
      provenance.root,
      provenance.runId,
      provenance.expiresAt,
      provenance.mode,
      provenance.approvedPlanRunId,
      account.email,
      provenance.exposureAdoptionRunId,
    ),
    buildMarkerReadLease(
      provenance.repository,
      provenance.runId,
      provenance.expiresAt,
      contract.projectId,
      account.email,
    ),
    ...(provenance.repository === "runsetta" && provenance.root === "exposure" &&
        provenance.mode === "plan"
      ? [buildExposureControllerCreateLease(provenance.runId, provenance.expiresAt)]
      : []),
    ...(provenance.mode === "apply"
      ? [
          buildLegacyCombinedReceiptCreateLease(
            provenance.repository,
            provenance.root,
            provenance.runId,
            provenance.expiresAt,
            provenance.approvedPlanRunId,
            account.email,
          ),
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
    includedPermissions: executorCustomRolePermissions(
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
): Promise<{
  readonly exactAccountAbsentOrDenied: boolean;
  readonly observed: boolean;
}> {
  const loaded = await detachedDeterministicPolicySurfaces(
    invocation,
    fetcher,
    executorUniqueId,
  );
  let observed = false;
  const recoveryResults = await Promise.allSettled(loaded.surfaces.map(
    async ({ current, descriptor, expected, surface }) => {
      const relevant = detachedSurfaceHasRelevantBinding(
        current,
        descriptor,
        surface,
        invocation.githubRunId,
      );
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
  return {
    exactAccountAbsentOrDenied: loaded.exactAccountAbsentOrDenied,
    observed,
  };
}

async function detachedDeterministicPoliciesRemain(
  invocation: RecoveryInvocation,
  fetcher: Fetcher,
): Promise<{
  readonly active: boolean;
  readonly exactAccountAbsentOrDenied: boolean;
}> {
  const loaded = await detachedDeterministicPolicySurfaces(invocation, fetcher);
  let remains = false;
  for (const { current, descriptor, surface } of loaded.surfaces) {
    if (detachedSurfaceHasRelevantBinding(
      current,
      descriptor,
      surface,
      invocation.githubRunId,
    )) remains = true;
  }
  if (loaded.errors.length > 0) {
    throw new AggregateError(loaded.errors, "Deterministic executor policy proof was incomplete.");
  }
  return {
    active: remains,
    exactAccountAbsentOrDenied: loaded.exactAccountAbsentOrDenied,
  };
}

async function detachedDeterministicPolicySurfaces(
  invocation: RecoveryInvocation,
  fetcher: Fetcher,
  executorUniqueId: string | undefined = undefined,
): Promise<{
  readonly errors: readonly unknown[];
  readonly exactAccountAbsentOrDenied: boolean;
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
    get: () => getDeterministicExecutorPolicyIfPresent(invocation, token, fetcher),
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
  let exactAccountAbsentOrDenied = false;
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
      const controllerExposureLease = descriptor.kind === "project" &&
          descriptor.projectRepository === "runsetta" &&
          invocation.repository === "runsetta"
        ? requireExposureControllerCreateLeaseCandidate(binding, invocation.githubRunId)
        : undefined;
      const controllerExposureLeaseTitle = descriptor.kind === "project" &&
          descriptor.projectRepository === "runsetta" &&
          invocation.repository === "runsetta" &&
          bindingHasExposureControllerLeaseTitle(binding, invocation.githubRunId);
      const relevant = descriptor.exclusive ||
        bindingHasDeterministicExecutorMember(binding, executorEmail) ||
        controllerExposureLeaseTitle ||
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
      expected.push(controllerExposureLease ?? binding);
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
    if (load.status === "rejected") {
      if (load.reason instanceof ExactDeterministicAccountAbsentOrDeniedError) {
        exactAccountAbsentOrDenied = true;
      } else {
        errors.push(load.reason);
      }
    }
    else if (load.value !== undefined) result.push(load.value);
  }
  return { errors, exactAccountAbsentOrDenied, surfaces: result };
}

function detachedSurfaceHasRelevantBinding(
  policy: IamPolicy,
  descriptor: DetachedPolicyDescriptor,
  surface: OrphanPolicySurface,
  runId: string,
): boolean {
  const executorMemberValue = surface.basis.members[0];
  const executorEmail = executorMemberValue?.startsWith("serviceAccount:") === true
    ? executorMemberValue.slice("serviceAccount:".length)
    : undefined;
  return (descriptor.exclusive && policy.auditConfigs !== undefined) ||
    policy.bindings.some((binding) =>
    descriptor.exclusive ||
    (executorEmail !== undefined && bindingHasDeterministicExecutorMember(binding, executorEmail)) ||
    (descriptor.kind === "project" && descriptor.projectRepository === "runsetta" &&
      bindingHasExposureControllerLeaseTitle(binding, runId)) ||
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
      const desired = removeDeterministicExecutorMembers(
        current,
        executorEmail,
        descriptor.kind === "project" && descriptor.projectRepository === "runsetta" &&
            invocation.repository === "runsetta"
          ? invocation.githubRunId
          : undefined,
      );
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

export function removeDeterministicExecutorMembers(
  policy: IamPolicy,
  executorEmail: string,
  exposureControllerRunId: string | undefined = undefined,
): IamPolicy {
  const bindings: IamBinding[] = [];
  for (const binding of policy.bindings) {
    if (
      exposureControllerRunId !== undefined &&
      exposureControllerCreateLeaseOrUndefined(binding, exposureControllerRunId) !== undefined
    ) {
      continue;
    }
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
        const desired = removeKnownOrphanBindings(current, known, executorEmail);
        const response = await surface.set(desired);
        if (response !== undefined && response.etag === current.etag) {
          throw new Error(`${surface.label} cleanup CAS did not advance its etag.`);
        }
      } else if (fenceRemains) {
        if (fencePredecessorEtag !== undefined && current.etag === fencePredecessorEtag) {
          throw new Error(`${surface.label} recovery fence did not advance its predecessor etag.`);
        }
        observedFenceEtag = current.etag;
        const response = await surface.set(
          removeKnownOrphanBindings(current, [fence], executorEmail),
        );
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
  const expectedTitles = new Set(
    surface.expected.flatMap((binding) =>
      binding.condition === undefined ? [] : [binding.condition.title]
    ),
  );
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
  executorEmail: string,
): IamPolicy {
  const remove = new Set(bindings.map((binding) => canonicalJson(json(binding, "orphan binding"))));
  void executorEmail;
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
  if (!bridgeRolePermissionsRecognized(role.includedPermissions, repository, root, phase)) {
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
    approvedManifestSha256: invocation.approvedManifestSha256,
    approvedPlanRunId: invocation.approvedPlanRunId,
    expiresAt,
    exposureAdoptionRunId: invocation.exposureAdoptionRunId,
    mode: invocation.mode,
    repository: invocation.repository,
    root: invocation.terraformRoot,
    runId: invocation.githubRunId,
  };
}

export function executorDescription(provenance: ExecutorProvenance): string {
  const runId = executorProvenanceNumeric(provenance.runId, "executor provenance run ID");
  repositoryName(provenance.repository);
  rootName(provenance.root);
  executionMode(provenance.mode);
  if (
    provenance.root === "exposure" &&
    (provenance.repository !== "runsetta" || provenance.mode !== "plan")
  ) {
    throw new Error("Only Runsetta plan provenance may name the exposure root.");
  }
  if (provenance.mode === "apply") {
    executorProvenanceNumeric(
      provenance.approvedPlanRunId,
      "executor provenance approved plan run ID",
    );
    hash(provenance.approvedManifestSha256, "executor provenance approved manifest digest");
  } else if (
    provenance.approvedPlanRunId !== "" || provenance.approvedManifestSha256 !== ""
  ) {
    throw new Error("Only apply executor provenance may name an approved run.");
  }
  const adoptionRequired = provenance.repository === "runsetta" && provenance.root === "prod";
  if ((provenance.exposureAdoptionRunId !== "") !== adoptionRequired) {
    throw new Error("Executor provenance has malformed exposure-adoption authority.");
  }
  if (provenance.exposureAdoptionRunId !== "") {
    executorProvenanceNumeric(
      provenance.exposureAdoptionRunId,
      "executor provenance exposure adoption run ID",
    );
  }
  if (!Number.isFinite(provenance.expiresAt.getTime())) {
    throw new Error("Executor provenance expiry is invalid.");
  }
  const description = [
    EXECUTOR_DESCRIPTION_VERSION,
    `repository=${provenance.repository}`,
    `run=${runId}`,
    `root=${provenance.root}`,
    `mode=${provenance.mode}`,
    `approved=${provenance.approvedPlanRunId === "" ? "none" : provenance.approvedPlanRunId}`,
    `manifest=${provenance.approvedManifestSha256 === "" ? "none" : provenance.approvedManifestSha256}`,
    `adoption=${provenance.exposureAdoptionRunId === "" ? "none" : provenance.exposureAdoptionRunId}`,
    `expires=${provenance.expiresAt.toISOString()}`,
  ].join(";");
  requireExecutorDescriptionBound(description);
  return description;
}

export function parseExecutorProvenance(
  description: string,
  projectId: string,
): ExecutorProvenance {
  requireExecutorDescriptionBound(description);
  if (description.startsWith(`${EXECUTOR_DESCRIPTION_VERSION};`)) {
    return parseCurrentExecutorProvenance(description, projectId);
  }
  if (description.startsWith(`${LEGACY_EXECUTOR_DESCRIPTION_VERSION};`)) {
    return parseLegacyExecutorProvenance(description, projectId);
  }
  throw new Error("An orphan bridge executor has unknown provenance; manual cleanup is required.");
}

function parseCurrentExecutorProvenance(
  description: string,
  projectId: string,
): ExecutorProvenance {
  const match = new RegExp(
    `^${EXECUTOR_DESCRIPTION_VERSION};repository=(${REPOSITORY_NAMES.join("|")});` +
      "run=([1-9][0-9]{0,19});root=(bootstrap|prod|exposure);mode=(plan|apply|rehearsal);" +
      "approved=(none|[1-9][0-9]{0,19});manifest=(none|[0-9a-f]{64});" +
      "adoption=(none|[1-9][0-9]{0,19});expires=([^;]+)$",
  ).exec(description);
  if (match === null) {
    throw new Error("An orphan bridge executor has unknown provenance; manual cleanup is required.");
  }
  const repository = repositoryName(match[1]!);
  exact(REPOSITORIES[repository].projectId, projectId, "executor provenance project");
  const runId = executorProvenanceNumeric(match[2]!, "executor provenance run ID");
  const root = rootName(match[3]!);
  // Exact, never a fallback. Collapsing every non-plan mode to "apply"
  // would make crash recovery treat an abruptly lost REHEARSAL executor as
  // an apply executor -- a different lease shape, a different receipt
  // inventory, and a different idea of what the run was allowed to do.
  const mode = executionMode(match[4]!);
  const approvedPlanRunId = match[5] === "none"
    ? ""
    : executorProvenanceNumeric(match[5]!, "executor provenance approved plan run ID");
  const approvedManifestSha256 = match[6] === "none"
    ? ""
    : hash(match[6]!, "executor provenance approved manifest digest");
  const exposureAdoptionRunId = match[7] === "none"
    ? ""
    : executorProvenanceNumeric(match[7]!, "executor provenance exposure adoption run ID");
  const expiresAt = new Date(match[8]!);
  if (!Number.isFinite(expiresAt.getTime()) || expiresAt.toISOString() !== match[8]) {
    throw new Error("An orphan bridge executor has malformed expiry provenance; manual cleanup is required.");
  }
  const provenance = {
    approvedManifestSha256,
    approvedPlanRunId,
    expiresAt,
    exposureAdoptionRunId,
    mode,
    repository,
    root,
    runId,
  } as const;
  exact(executorDescription(provenance), description, "executor provenance encoding");
  return provenance;
}

function parseLegacyExecutorProvenance(
  description: string,
  projectId: string,
): ExecutorProvenance {
  const match = new RegExp(
    `^${LEGACY_EXECUTOR_DESCRIPTION_VERSION};repository=(${REPOSITORY_NAMES.join("|")});` +
      "run=([1-9][0-9]{0,19});root=(bootstrap|prod|exposure);mode=(plan|apply);" +
      "approved=(none|[1-9][0-9]{0,19});" +
      "(?:adoption=([1-9][0-9]{0,19});)?expires=([^;]+)$",
  ).exec(description);
  if (match === null) {
    throw new Error("An orphan bridge executor has unknown legacy provenance; manual cleanup is required.");
  }
  const repository = repositoryName(match[1]!);
  exact(REPOSITORIES[repository].projectId, projectId, "legacy executor provenance project");
  const runId = executorProvenanceNumeric(match[2]!, "legacy executor provenance run ID");
  const root = rootName(match[3]!);
  const mode = match[4] === "plan" ? "plan" : "apply";
  const approvedPlanRunId = match[5] === "none"
    ? ""
    : executorProvenanceNumeric(match[5]!, "legacy executor approved plan run ID");
  const exposureAdoptionRunId = match[6] === undefined
    ? ""
    : executorProvenanceNumeric(match[6], "legacy executor exposure adoption run ID");
  if (
    (mode === "apply") !== (approvedPlanRunId !== "") ||
    (root === "exposure" && (repository !== "runsetta" || mode !== "plan")) ||
    (exposureAdoptionRunId !== "" &&
      !(repository === "runsetta" && root === "prod"))
  ) {
    throw new Error(
      "An orphan bridge executor has malformed legacy approval provenance; manual cleanup is required.",
    );
  }
  const expiresAt = new Date(match[7]!);
  if (!Number.isFinite(expiresAt.getTime()) || expiresAt.toISOString() !== match[7]) {
    throw new Error(
      "An orphan bridge executor has malformed legacy expiry provenance; manual cleanup is required.",
    );
  }
  const provenance = {
    approvedManifestSha256: "",
    approvedPlanRunId,
    expiresAt,
    exposureAdoptionRunId,
    mode,
    repository,
    root,
    runId,
  } as const;
  const expectedDescription = [
    LEGACY_EXECUTOR_DESCRIPTION_VERSION,
    `repository=${repository}`,
    `run=${runId}`,
    `root=${root}`,
    `mode=${mode}`,
    `approved=${approvedPlanRunId === "" ? "none" : approvedPlanRunId}`,
    ...(exposureAdoptionRunId === "" ? [] : [`adoption=${exposureAdoptionRunId}`]),
    `expires=${expiresAt.toISOString()}`,
  ].join(";");
  exact(expectedDescription, description, "legacy executor provenance encoding");
  return provenance;
}

function executorProvenanceNumeric(value: string, label: string): string {
  const parsed = numeric(value, label);
  if (parsed.length > EXECUTOR_PROVENANCE_NUMERIC_MAX_DIGITS) {
    throw new Error(`${label} escaped its decimal length bound.`);
  }
  return parsed;
}

function requireExecutorDescriptionBound(description: string): void {
  requiredString(description, "executor provenance description");
  if (Buffer.byteLength(description, "utf8") > EXECUTOR_DESCRIPTION_MAX_BYTES) {
    throw new Error("Executor provenance description escaped Google's byte bound.");
  }
}

export async function createEphemeralExecutor(
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
  // Opt-in, and only for containment. IAM permission changes are eventually
  // consistent, so a 403 here can mean "the grant has not propagated yet"
  // rather than "you may not do this" -- the same reason retryForbidden
  // already exists on the elevated-session retry above. It is off by default
  // because on an ordinary path a 403 should surface immediately.
  retryForbidden = false,
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
      const contextualPropagationDenial = retryForbidden && error instanceof Error &&
        /HTTP 403\b/.test(error.message);
      if (!contextualPropagationDenial && !retryableIamConsistencyError(error)) throw error;
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

// Strict on purpose. Three of its four callers -- the post-create check in
// `acquire` and both orphan-recovery checks -- need a 404 to stay a propagation
// error, because this file classifies IAM 404s as retryable: tolerating one
// there would let a transient answer stand in for the zero-key proof and permit
// deleting an account whose user-managed key was never inventoried. Only the
// cleanup caller, which can independently confirm the account is gone, treats
// absence as satisfying it.
export async function requireNoUserManagedKeys(
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
  const response = await googleReadWithRetry(url, {
    headers: googleHeaders(token),
    method: "POST",
    redirect: "error",
  }, fetcher);
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
  const response = await googleReadWithRetry(url, {
    headers: googleHeaders(token),
    method: "POST",
    redirect: "error",
  }, fetcher);
  if (response.status === 404) return undefined;
  if (!response.ok) {
    throw new Error(`Service-account IAM getPolicy failed with HTTP ${response.status}.`);
  }
  return iamPolicy(await boundedJson(response, 2 * 1024 * 1024));
}

async function getDeterministicExecutorPolicyIfPresent(
  invocation: RecoveryInvocation,
  token: string,
  fetcher: Fetcher,
): Promise<IamPolicy | undefined> {
  const email = deterministicExecutorEmail(invocation);
  const url = new URL(`${serviceAccountUrl(email)}:getIamPolicy`);
  url.searchParams.set("options.requestedPolicyVersion", "3");
  const response = await googleReadWithRetry(url, {
    headers: googleHeaders(token),
    method: "POST",
    redirect: "error",
  }, fetcher);
  if (response.status === 404) {
    await boundedText(response, 64 * 1024);
    return undefined;
  }
  if (response.status === 403) {
    await boundedText(response, 64 * 1024);
    throw new ExactDeterministicAccountAbsentOrDeniedError(
      "Exact deterministic executor policy is absent or authorization-masked.",
    );
  }
  if (!response.ok) {
    await boundedText(response, 64 * 1024);
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

// Google answers a rate limit with HTTP 429 and a gateway fault with 502, 503,
// or 504. Both are transient and neither is a statement about authority: the
// request either never reached a service that could answer, or the service asked
// us to slow down. Before this retry class a single 429 on an IAM policy read
// ended a protected run outright -- observed on run 33390979102, where the read
// failed inside `acquire`, after the executor was already created, and cost the
// run plus a 55-minute residue wait. The recovery path already converges over
// transient policy failures; the acquire path had no equivalent.
//
// Four attempts with the same exponential-with-jitter backoff the IAM retries
// use, so a rate limit gets roughly 1-2s, then 2-4s, then 4-8s to clear before
// the run fails closed. A sustained 429 is real quota exhaustion and still ends
// the run, just not on the first sample.
//
// 429 is deliberately IN this class and deliberately OUT of the storage
// permission RPC's class, which is not a contradiction: that loop excluded it
// for "wanting backoff semantics this loop does not implement", and this loop
// implements exactly those semantics. 500 stays out of both -- a real server
// defect is worth surfacing rather than papering over with a retry.
const GOOGLE_READ_RETRY_ATTEMPTS = 4;
const GOOGLE_READ_TRANSIENT_HTTP_STATUSES: ReadonlySet<number> = new Set([429, 502, 503, 504]);

// Retrying is only ever sound for a request that cannot change state. Every
// caller below posts to a `:getIamPolicy` endpoint -- Google's IAM API uses POST
// for these reads -- and the pathname check below is what stops the retry class
// from silently covering a mutation if a future caller reaches for the helper. A
// retried setIamPolicy would be a correctness bug of exactly the kind this
// bridge exists to prevent, so it fails closed rather than trusting the caller.
const GOOGLE_READ_ONLY_URL_SUFFIX = ":getIamPolicy";

export function retryableGoogleReadStatus(status: number): boolean {
  return GOOGLE_READ_TRANSIENT_HTTP_STATUSES.has(status);
}

export interface GoogleReadRetryOptions {
  readonly now?: () => number;
  readonly sleep?: (milliseconds: number) => Promise<void>;
  readonly deadlineMs?: number;
}

// Performs an idempotent IAM policy read, retrying ONLY the transient statuses.
// Every other status -- 200, 403, 404, 400 -- is returned to the caller
// untouched, so each caller keeps its own status semantics unchanged.
export async function googleReadWithRetry(
  url: string | URL,
  init: RequestInit,
  fetcher: Fetcher,
  options: GoogleReadRetryOptions = {},
): Promise<Response> {
  // Compare the parsed pathname, never the raw string. A suffix test on the raw
  // URL is defeated by `...:setIamPolicy#:getIamPolicy`, because a fragment is
  // not part of the path the server ever sees -- so the guard would wave through
  // exactly the mutation it exists to stop. A URL this cannot parse fails closed.
  let path: string;
  try {
    path = new URL(typeof url === "string" ? url : url.toString()).pathname;
  } catch {
    throw new Error("The retrying Google read path refuses a URL it cannot parse.");
  }
  if (!path.endsWith(GOOGLE_READ_ONLY_URL_SUFFIX)) {
    throw new Error("The retrying Google read path refuses a URL that is not an IAM policy read.");
  }
  const now = options.now ?? Date.now;
  const sleep = options.sleep ?? ((milliseconds: number) => Bun.sleep(milliseconds));
  // An explicit deadline wins; otherwise inherit the one the fetcher was built
  // with. Without this the backoff sleeps are bounded only by the attempt cap,
  // so a transient arriving just before an acquisition, recovery, or cleanup
  // deadline could sleep past it and then ask again.
  const deadlineMs = options.deadlineMs ?? fetcherDeadlineMs(fetcher);
  let lastTransient: Response | undefined;
  for (let attempt = 0; attempt < GOOGLE_READ_RETRY_ATTEMPTS; attempt += 1) {
    // Never start an attempt the deadline cannot hold. The deadline fetcher
    // enforces this too; checking here avoids burning a backoff sleep first.
    if (deadlineMs !== undefined && deadlineMs - now() <= 0) break;
    const response = await fetcher(url, init);
    if (!retryableGoogleReadStatus(response.status)) return response;
    lastTransient = response;
    if (attempt + 1 >= GOOGLE_READ_RETRY_ATTEMPTS) break;
    // Clamped to the deadline so the sleep itself can never overrun the window.
    let delayMs = iamRetryDelayMs(attempt);
    if (deadlineMs !== undefined) {
      delayMs = Math.min(delayMs, deadlineMs - now());
    }
    if (delayMs <= 0) break;
    await sleep(delayMs);
  }
  // Hand the exhausted transient back rather than throwing here, so every caller
  // keeps its own error message and status handling. Throwing a generic message
  // would have rewritten the three service-account readers' "Service-account IAM
  // getPolicy failed with HTTP ..." into something that names the wrong call.
  //
  // Only the zero-attempt case has no response to return: the deadline was
  // already spent before the first ask.
  if (lastTransient === undefined) {
    throw new Error("The IAM policy read reached the protected operation deadline before any attempt.");
  }
  return lastTransient;
}

async function googleJson(
  url: string,
  token: string,
  body: JsonValue,
  fetcher: Fetcher,
  options: GoogleReadRetryOptions = {},
): Promise<unknown> {
  const response = await googleReadWithRetry(url, {
    body: JSON.stringify(body),
    headers: googleHeaders(token),
    method: "POST",
    redirect: "error",
  }, fetcher, options);
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

const STORAGE_OBJECT_PERMISSION_RPC_PATH =
  "/google.storage.v2.Storage/TestIamPermissions";
const STORAGE_OBJECT_PERMISSION_RPC_AUTHORITY = "https://storage.googleapis.com";
const STORAGE_OBJECT_RPC_PERMISSIONS = [
  "storage.objects.delete",
  "storage.objects.get",
  "storage.objects.update",
] as const;

export interface StorageObjectPermissionProbeRequest {
  readonly bucketResource: string;
  readonly executorToken: string;
  readonly permissions: readonly string[];
  readonly resource: string;
}

export interface StorageObjectPermissionProbeResult {
  readonly denied: boolean;
  readonly permissions: readonly string[];
  // Set only when `denied`, so the caller can tell a grant that has not
  // propagated yet from a credential that will never work.
  readonly status?: number;
}

export interface StorageObjectOverwriteProbeRequest {
  readonly bucket: string;
  readonly executorToken: string;
  readonly objectName: string;
}

export interface StateStoragePermissionProbes {
  readonly testObjectPermissions: (
    request: StorageObjectPermissionProbeRequest,
    options?: StoragePermissionRpcOptions,
  ) => Promise<StorageObjectPermissionProbeResult>;
  readonly testObjectOverwrite: (
    request: StorageObjectOverwriteProbeRequest,
    fetcher: Fetcher,
  ) => Promise<boolean>;
}

export interface StoragePermissionRpcOptions {
  readonly connect?: (authority: string) => ClientHttp2Session;
  readonly timeoutMs?: number;
  // Deadline-aware retry for this RPC's own transient faults. All optional:
  // without them the probe behaves exactly as it did before, one attempt and
  // out.
  readonly deadlineMs?: number;
  readonly now?: () => number;
  readonly sleep?: (milliseconds: number) => Promise<void>;
}

// gRPC canonical codes the storage permission RPC can answer a probe with.
// PERMISSION_DENIED is the ordinary shape of an IAM grant that has not
// propagated yet; UNAUTHENTICATED means the credential itself is unusable.
const STORAGE_RPC_PERMISSION_DENIED = 7;
const STORAGE_RPC_UNAUTHENTICATED = 16;

// Canonical gRPC statuses that describe the SERVICE failing, not the caller's
// permissions. Unlike 7 and 16 these are not answers to the probe at all, and
// this RPC is a read-only permission test, so re-asking is idempotent.
// UNAVAILABLE is a transient backend outage; DEADLINE_EXCEEDED is the server
// giving up rather than a verdict on the credential.
//
// Deliberately excludes INTERNAL and RESOURCE_EXHAUSTED: the first can mean a
// genuine server defect worth surfacing, and the second is rate limiting that
// wants backoff this loop does not implement.
const STORAGE_RPC_TRANSIENT_SERVICE_STATUSES: ReadonlySet<number> = new Set([
  4, // DEADLINE_EXCEEDED
  14, // UNAVAILABLE
]);

// A transport-layer HTTP status carried structurally rather than parsed back
// out of a message. Review of PR 56 caught the string-matching approach missing
// the stream-abort path; keying on a typed status removes that whole class of
// miss for the HTTP side.
export class StoragePermissionHttpStatusError extends Error {
  // The RAW header value, never coerced. Number() would both widen the retry
  // discriminator -- "0503" and " 503" become 503 -- and destroy the external
  // text, turning a non-numeric status into "HTTP NaN" instead of reporting
  // what the server actually sent.
  constructor(readonly rawStatus: string | undefined) {
    super(`Storage permission RPC failed with HTTP ${rawStatus ?? "missing"}.`);
    this.name = "StoragePermissionHttpStatusError";
  }
}

// Gateway failures where the request never reached a service that could
// answer -- the HTTP equivalent of gRPC UNAVAILABLE.
//
// Excludes 500 and 429 for the same reasons INTERNAL and RESOURCE_EXHAUSTED
// are excluded above: a 500 can be a genuine server defect worth surfacing,
// and a 429 is rate limiting that wants backoff semantics this loop does not
// implement. Every 4xx is terminal -- those are answers about the request.
// Exact canonical spellings. Matching strings rather than parsed numbers is
// what keeps "0503", " 503", and "503 " out of the retry class.
const STORAGE_RPC_TRANSIENT_HTTP_STATUSES: ReadonlySet<string> = new Set([
  "502", // Bad Gateway
  "503", // Service Unavailable
  "504", // Gateway Timeout
]);

export class StoragePermissionGrpcStatusError extends Error {
  constructor(readonly status: number) {
    super(`Storage object permission RPC failed with gRPC status ${status}.`);
    this.name = "StoragePermissionGrpcStatusError";
  }
}

function encodeUnsignedVarint(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error("Storage permission protobuf length escaped its bounded range.");
  }
  const result: number[] = [];
  let remaining = value;
  do {
    const next = remaining % 128;
    remaining = Math.floor(remaining / 128);
    result.push(next | (remaining === 0 ? 0 : 0x80));
  } while (remaining !== 0);
  return Uint8Array.from(result);
}

function encodeLengthDelimitedField(field: number, value: string): Uint8Array {
  const bytes = new TextEncoder().encode(value);
  const length = encodeUnsignedVarint(bytes.byteLength);
  return Buffer.concat([Uint8Array.of((field << 3) | 2), length, bytes]);
}

export function encodeStorageTestIamPermissionsRequest(
  resource: string,
  permissions: readonly string[],
): Uint8Array {
  const fields = [
    encodeLengthDelimitedField(1, resource),
    ...permissions.map((permission) => encodeLengthDelimitedField(2, permission)),
  ];
  const payload = Buffer.concat(fields);
  if (payload.byteLength > MAX_STORAGE_PERMISSION_RPC_BYTES) {
    throw new Error("Storage permission RPC request exceeded its bounded size.");
  }
  return payload;
}

function decodeUnsignedVarint(
  bytes: Uint8Array,
  offset: number,
): { readonly next: number; readonly value: number } {
  let value = 0;
  let multiplier = 1;
  for (let index = 0; index < 5; index += 1) {
    const byte = bytes[offset + index];
    if (byte === undefined) throw new Error("Storage permission protobuf was truncated.");
    value += (byte & 0x7f) * multiplier;
    if ((byte & 0x80) === 0) {
      if (!Number.isSafeInteger(value)) {
        throw new Error("Storage permission protobuf length was invalid.");
      }
      return { next: offset + index + 1, value };
    }
    multiplier *= 128;
  }
  throw new Error("Storage permission protobuf varint exceeded its bounded width.");
}

export function decodeStorageTestIamPermissionsResponse(
  payload: Uint8Array,
): readonly string[] {
  if (payload.byteLength > MAX_STORAGE_PERMISSION_RPC_BYTES) {
    throw new Error("Storage permission RPC response exceeded its bounded size.");
  }
  const permissions: string[] = [];
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let offset = 0;
  while (offset < payload.byteLength) {
    const tag = decodeUnsignedVarint(payload, offset);
    offset = tag.next;
    if (tag.value !== 10) {
      throw new Error("Storage permission protobuf contained an unexpected field.");
    }
    const length = decodeUnsignedVarint(payload, offset);
    offset = length.next;
    if (length.value > payload.byteLength - offset) {
      throw new Error("Storage permission protobuf field was truncated.");
    }
    let permission: string;
    try {
      permission = decoder.decode(payload.subarray(offset, offset + length.value));
    } catch {
      throw new Error("Storage permission protobuf contained invalid UTF-8.");
    }
    if (!/^storage\.objects\.(delete|get|update)$/.test(permission)) {
      throw new Error("Storage permission protobuf returned an unrequested permission.");
    }
    permissions.push(permission);
    offset += length.value;
  }
  if (new Set(permissions).size !== permissions.length) {
    throw new Error("Storage permission protobuf repeated a permission.");
  }
  return permissions;
}

function grpcFrame(payload: Uint8Array): Uint8Array {
  const result = Buffer.alloc(5 + payload.byteLength);
  result[0] = 0;
  result.writeUInt32BE(payload.byteLength, 1);
  result.set(payload, 5);
  return result;
}

function decodeGrpcFrame(bytes: Uint8Array): readonly string[] {
  if (bytes.byteLength < 5) throw new Error("Storage permission gRPC frame was truncated.");
  if (bytes[0] !== 0) throw new Error("Storage permission gRPC compression is not supported.");
  const length = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).readUInt32BE(1);
  if (length !== bytes.byteLength - 5) {
    throw new Error("Storage permission gRPC response was not exactly one bounded frame.");
  }
  return decodeStorageTestIamPermissionsResponse(bytes.subarray(5));
}

function singleHttp2Header(
  value: string | string[] | number | undefined,
  label: string,
): string | undefined {
  if (value === undefined) return undefined;
  if (Array.isArray(value)) throw new Error(`${label} was repeated.`);
  return String(value);
}

export async function storageV2TestIamPermissions(
  request: StorageObjectPermissionProbeRequest,
  options: StoragePermissionRpcOptions = {},
): Promise<readonly string[]> {
  if (!/^projects\/_\/buckets\/[a-z0-9][a-z0-9._-]{1,221}[a-z0-9]$/.test(
    request.bucketResource,
  )) {
    throw new Error("Storage permission RPC bucket escaped its exact resource syntax.");
  }
  if (!request.resource.startsWith(`${request.bucketResource}/objects/`) ||
    request.resource.length > 4_096 || request.resource.includes("\0")) {
    throw new Error("Storage permission RPC object escaped its exact resource syntax.");
  }
  if (request.executorToken.includes("\r") || request.executorToken.includes("\n")) {
    throw new Error("Storage permission RPC credential escaped its header syntax.");
  }
  if (request.permissions.length === 0 ||
    new Set(request.permissions).size !== request.permissions.length ||
    request.permissions.some((permission) =>
      !STORAGE_OBJECT_RPC_PERMISSIONS.includes(
        permission as typeof STORAGE_OBJECT_RPC_PERMISSIONS[number],
      ))) {
    throw new Error("Storage permission RPC request escaped its permission allowlist.");
  }
  const timeoutMs = options.timeoutMs ?? STORAGE_PERMISSION_RPC_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 ||
    timeoutMs > STORAGE_PERMISSION_RPC_TIMEOUT_MS) {
    throw new Error("Storage permission RPC timeout escaped its bounded range.");
  }
  const payload = encodeStorageTestIamPermissionsRequest(
    request.resource,
    request.permissions,
  );
  const body = grpcFrame(payload);
  const connector = options.connect ?? connectHttp2;

  return await new Promise<readonly string[]>((resolve, reject) => {
    let session: ClientHttp2Session | undefined;
    let stream: ReturnType<ClientHttp2Session["request"]> | undefined;
    let settled = false;
    let responseStatus: string | undefined;
    let responseContentType: string | undefined;
    let headerGrpcStatus: string | undefined;
    let trailerGrpcStatus: string | undefined;
    const chunks: Uint8Array[] = [];
    let receivedBytes = 0;
    const timer = setTimeout(() => {
      fail(new Error("Storage permission RPC timed out."));
    }, timeoutMs);

    const close = (destroy: boolean): void => {
      clearTimeout(timer);
      try {
        if (destroy) stream?.close(http2Constants.NGHTTP2_CANCEL);
      } catch {
        // The outcome is already fixed; transport shutdown is best effort.
      }
      try {
        if (destroy) session?.destroy();
        else session?.close();
      } catch {
        // The outcome is already fixed; transport shutdown is best effort.
      }
    };
    function fail(error: Error): void {
      if (settled) return;
      settled = true;
      close(true);
      reject(error);
    }
    function succeed(value: readonly string[]): void {
      if (settled) return;
      settled = true;
      close(false);
      resolve(value);
    }

    try {
      session = connector(STORAGE_OBJECT_PERMISSION_RPC_AUTHORITY);
      session.once("error", () => {
        fail(new Error("Storage permission RPC transport failed."));
      });
      stream = session.request({
        ":method": "POST",
        ":path": STORAGE_OBJECT_PERMISSION_RPC_PATH,
        authorization: `Bearer ${request.executorToken}`,
        "content-type": "application/grpc",
        te: "trailers",
        "x-goog-request-params": `bucket=${encodeURIComponent(request.bucketResource)}`,
      });
      stream.once("response", (headers) => {
        try {
          responseStatus = singleHttp2Header(headers[":status"], "Storage permission HTTP status");
          responseContentType = singleHttp2Header(
            headers["content-type"],
            "Storage permission content type",
          );
          headerGrpcStatus = singleHttp2Header(
            headers["grpc-status"],
            "Storage permission header gRPC status",
          );
        } catch (error) {
          fail(error instanceof Error ? error : new Error("Storage permission RPC headers failed."));
        }
      });
      stream.once("trailers", (headers) => {
        try {
          trailerGrpcStatus = singleHttp2Header(
            headers["grpc-status"],
            "Storage permission trailer gRPC status",
          );
        } catch (error) {
          fail(error instanceof Error ? error : new Error("Storage permission RPC trailers failed."));
        }
      });
      stream.on("data", (chunk: Uint8Array) => {
        if (settled) return;
        receivedBytes += chunk.byteLength;
        if (receivedBytes > MAX_STORAGE_PERMISSION_RPC_BYTES + 5) {
          fail(new Error("Storage permission RPC response exceeded its bounded size."));
          return;
        }
        chunks.push(Uint8Array.from(chunk));
      });
      stream.once("aborted", () => {
        fail(new Error("Storage permission RPC transport was aborted."));
      });
      stream.once("error", () => {
        fail(new Error("Storage permission RPC transport failed."));
      });
      stream.once("end", () => {
        if (settled) return;
        try {
          if (responseStatus !== "200") {
            // A non-200 that still carries a grpc-status is an ANSWER from the
            // service, not a gateway swallowing the request, and must stay
            // terminal and fully validated -- a repeated or malformed status is
            // a defect worth reporting whatever the HTTP code was. Only a bare
            // gateway response, with no grpc-status in headers or trailers, is
            // the transport fault the retry class exists for.
            if (headerGrpcStatus !== undefined && trailerGrpcStatus !== undefined) {
              throw new Error("Storage permission RPC repeated its gRPC status.");
            }
            const carriedGrpcStatus = trailerGrpcStatus ?? headerGrpcStatus;
            if (carriedGrpcStatus !== undefined) {
              if (!/^(?:0|[1-9]|1[0-6])$/.test(carriedGrpcStatus)) {
                throw new Error("Storage permission RPC omitted a valid gRPC status.");
              }
              throw new Error(
                `Storage permission RPC failed with HTTP ${responseStatus ?? "missing"}.`,
              );
            }
            throw new StoragePermissionHttpStatusError(responseStatus);
          }
          if (responseContentType === undefined ||
            !/^application\/grpc(?:\+proto)?(?:;|$)/.test(responseContentType)) {
            throw new Error("Storage permission RPC returned an unexpected content type.");
          }
          if (headerGrpcStatus !== undefined && trailerGrpcStatus !== undefined) {
            throw new Error("Storage permission RPC repeated its gRPC status.");
          }
          const grpcStatus = trailerGrpcStatus ?? headerGrpcStatus;
          if (grpcStatus === undefined || !/^(?:0|[1-9]|1[0-6])$/.test(grpcStatus)) {
            throw new Error("Storage permission RPC omitted a valid gRPC status.");
          }
          const numericStatus = Number(grpcStatus);
          if (numericStatus !== 0) throw new StoragePermissionGrpcStatusError(numericStatus);
          const permissions = decodeGrpcFrame(Buffer.concat(chunks));
          const requested = new Set(request.permissions);
          if (permissions.some((permission) => !requested.has(permission))) {
            throw new Error("Storage permission RPC returned an unrequested permission.");
          }
          succeed(permissions);
        } catch (error) {
          fail(error instanceof Error ? error : new Error("Storage permission RPC parse failed."));
        }
      });
      stream.end(body);
    } catch {
      fail(new Error("Storage permission RPC transport failed."));
    }
  });
}

// Retryable ONLY for this RPC's own transient faults, in two families.
//
// TRANSPORT: the timeout, a session error, and a stream abort. All three mean
// the request did not get an answer. "headers failed" and "trailers failed"
// are deliberately absent -- those come from header VALIDATION throwing, which
// is a protocol violation, not a transient fault -- as are every parse, size,
// and syntax failure.
//
// SERVICE: the canonical statuses that describe the service failing rather
// than answering. PERMISSION_DENIED and UNAUTHENTICATED are NOT here: they are
// genuine answers, converted to `denied` by the caller and re-probed by the
// convergence loop, so retrying them here would double-retry the same wait and
// could disguise a real denial as a fault.
const STORAGE_RPC_RETRYABLE_TRANSPORT_MESSAGES: ReadonlySet<string> = new Set([
  "Storage permission RPC timed out.",
  "Storage permission RPC transport failed.",
  "Storage permission RPC transport was aborted.",
]);

export function retryableStoragePermissionRpcError(error: unknown): boolean {
  if (error instanceof StoragePermissionGrpcStatusError) {
    return STORAGE_RPC_TRANSIENT_SERVICE_STATUSES.has(error.status);
  }
  // A bare gateway 5xx carries no grpc-status at all: the request never
  // reached a service that could answer, which is the same transient condition
  // as UNAVAILABLE and belongs in the same bounded, backed-off retry class.
  if (error instanceof StoragePermissionHttpStatusError) {
    return error.rawStatus !== undefined &&
      STORAGE_RPC_TRANSIENT_HTTP_STATUSES.has(error.rawStatus);
  }
  if (!(error instanceof Error)) return false;
  return STORAGE_RPC_RETRYABLE_TRANSPORT_MESSAGES.has(error.message);
}

export async function probeStorageObjectPermissions(
  request: StorageObjectPermissionProbeRequest,
  options: StoragePermissionRpcOptions = {},
): Promise<StorageObjectPermissionProbeResult> {
  const now = options.now ?? Date.now;
  const sleep = options.sleep ?? ((milliseconds: number) => Bun.sleep(milliseconds));
  const configuredTimeoutMs = options.timeoutMs ?? STORAGE_PERMISSION_RPC_TIMEOUT_MS;
  let lastTransientError: unknown;
  for (let attempt = 0; attempt < STORAGE_PERMISSION_RPC_ATTEMPTS; attempt += 1) {
    // Never start an attempt the deadline cannot hold. Without a deadline the
    // loop still runs, bounded by the attempt cap alone.
    let timeoutMs = configuredTimeoutMs;
    if (options.deadlineMs !== undefined) {
      timeoutMs = Math.min(configuredTimeoutMs, options.deadlineMs - now());
      if (timeoutMs <= 0) break;
    }
    try {
      return {
        denied: false,
        permissions: await storageV2TestIamPermissions(request, { ...options, timeoutMs }),
      };
    } catch (error) {
      if (error instanceof StoragePermissionGrpcStatusError &&
        (error.status === STORAGE_RPC_PERMISSION_DENIED ||
          error.status === STORAGE_RPC_UNAUTHENTICATED)) {
        return { denied: true, permissions: [], status: error.status };
      }
      if (!retryableStoragePermissionRpcError(error)) throw error;
      lastTransientError = error;
    }

    // Back off before re-asking. Without this the three attempts fire
    // back-to-back, so a short UNAVAILABLE or transport outage burns the whole
    // retry budget in roughly three RPC timeouts while most of the convergence
    // deadline is still unspent -- and hammers a service that is already
    // failing. iamRetryDelayMs is the same exponential-with-jitter the IAM
    // retries use; at a three-attempt cap it yields roughly 1-2s then 2-3s and
    // never approaches its own 32s ceiling.
    //
    // Clamped to the deadline, so the sleep itself can never overrun the
    // window. If there is no room left to wait, stop and fail closed rather
    // than sleeping past it; the top of the loop separately refuses an attempt
    // the deadline cannot hold.
    if (attempt + 1 < STORAGE_PERMISSION_RPC_ATTEMPTS) {
      let delayMs = iamRetryDelayMs(attempt);
      if (options.deadlineMs !== undefined) {
        delayMs = Math.min(delayMs, options.deadlineMs - now());
      }
      if (delayMs <= 0) break;
      await sleep(delayMs);
    }
  }
  // Fail closed. Exhaustion rethrows the fault that caused it, so the run
  // reports the same cause it always did rather than a new abstraction.
  throw lastTransientError ??
    new Error("Storage permission RPC had no attempt budget before its deadline.");
}

function validateResumableSessionUri(
  value: string,
  bucket: string,
  objectName: string,
): URL {
  if (value !== value.trim() || value.length > 8_192) {
    throw new Error("Storage overwrite probe returned an invalid session URI.");
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Storage overwrite probe returned an invalid session URI.");
  }
  if (url.protocol !== "https:" || url.hostname !== "storage.googleapis.com" ||
    url.port !== "" || url.username !== "" || url.password !== "" || url.hash !== "" ||
    url.pathname !== `/upload/storage/v1/b/${encodeURIComponent(bucket)}/o`) {
    throw new Error("Storage overwrite probe returned an invalid session URI.");
  }
  const keys = [...url.searchParams.keys()];
  if (keys.length !== 3 || new Set(keys).size !== keys.length ||
    !keys.includes("uploadType") || !keys.includes("name") || !keys.includes("upload_id") ||
    keys.some((key) => key !== "uploadType" && key !== "name" && key !== "upload_id") ||
    url.searchParams.get("uploadType") !== "resumable" ||
    url.searchParams.get("name") !== objectName) {
    throw new Error("Storage overwrite probe returned an invalid session URI.");
  }
  const uploadId = url.searchParams.get("upload_id") ?? "";
  if (!/^[A-Za-z0-9._~-]{20,4096}$/.test(uploadId)) {
    throw new Error("Storage overwrite probe returned an invalid session URI.");
  }
  return url;
}

export async function probeStorageObjectOverwritePermission(
  request: StorageObjectOverwriteProbeRequest,
  fetcher: Fetcher,
): Promise<boolean> {
  // This initiates a resumable upload session, which GCS authorizes against
  // storage.objects.create alone. It is therefore a sound CREATE detector, not
  // an effective-overwrite proof: finalizing a replacement of a live object
  // additionally requires storage.objects.delete, which no lease here grants.
  //
  // An earlier comment claimed the initiation itself required delete. Run
  // 33300997122 disproved it -- the executor held objectCreator on the live
  // consumed receipt and the probe correctly reported create -- and that wrong
  // claim is why the contradicting lease survived review. Exact IAM policy
  // readback separately proves the Creator binding was removed; the
  // generation-bound state reread proves no replacement occurred.
  if (!/^[a-z0-9][a-z0-9._-]{1,221}[a-z0-9]$/.test(request.bucket) ||
    request.objectName.length === 0 || request.objectName.length > 1_024 ||
    request.objectName.includes("\0") || request.executorToken.includes("\r") ||
    request.executorToken.includes("\n")) {
    throw new Error("Storage overwrite probe target escaped its exact syntax.");
  }
  const url = new URL(
    `https://storage.googleapis.com/upload/storage/v1/b/${encodeURIComponent(request.bucket)}/o`,
  );
  url.searchParams.set("name", request.objectName);
  url.searchParams.set("uploadType", "resumable");
  let response: Response;
  try {
    response = await fetcher(url, {
      headers: {
        Authorization: `Bearer ${request.executorToken}`,
        "Content-Length": "0",
      },
      method: "POST",
      redirect: "error",
    });
  } catch {
    throw new Error("Storage overwrite probe transport failed.");
  }
  let initiationBody = "";
  let initiationBodyError: Error | undefined;
  try {
    initiationBody = await boundedText(response, 16 * 1024);
  } catch (error) {
    initiationBodyError = error instanceof Error &&
        error.message === "API response exceeded its bound."
      ? new Error("Storage overwrite probe response body exceeded its bound.")
      : new Error("Storage overwrite probe response body failed.");
  }
  if (initiationBodyError !== undefined && response.status !== 200) {
    throw initiationBodyError;
  }
  if (response.status === 401 || response.status === 403) return false;
  if (response.status !== 200) {
    throw new Error(`Storage overwrite probe failed with HTTP ${response.status}.`);
  }
  const location = response.headers.get("location");
  if (location === null) throw new Error("Storage overwrite probe omitted its session URI.");
  const session = validateResumableSessionUri(location, request.bucket, request.objectName);
  let cancellation: Response;
  try {
    cancellation = await fetcher(session, {
      headers: { "Content-Length": "0" },
      method: "DELETE",
      redirect: "error",
    });
  } catch {
    throw new Error("Storage overwrite probe cancellation transport failed.");
  }
  // Google's status reference says 499 has no body, but the live JSON endpoint
  // returned one in the protected canary. Treat the exact validated-session
  // status as authoritative, consume the compatibility payload, and reject it
  // above the accepted size bound without depending on undocumented bytes.
  try {
    await boundedText(cancellation, 16 * 1024);
  } catch (error) {
    throw error instanceof Error && error.message === "API response exceeded its bound."
      ? new Error("Storage overwrite probe cancellation response body exceeded its bound.")
      : new Error("Storage overwrite probe cancellation response body failed.");
  }
  // JSON resumable-upload cancellation deliberately uses nonstandard 499.
  if (cancellation.status !== 499) {
    throw new Error(
      `Storage overwrite probe cancellation failed with HTTP ${cancellation.status}.`,
    );
  }
  if (initiationBodyError !== undefined) throw initiationBodyError;
  if (initiationBody !== "") {
    throw new Error("Storage overwrite probe returned an unexpected response body.");
  }
  return true;
}

const DEFAULT_STATE_STORAGE_PERMISSION_PROBES: StateStoragePermissionProbes = {
  testObjectOverwrite: probeStorageObjectOverwritePermission,
  testObjectPermissions: probeStorageObjectPermissions,
};

function permissionConsistencyDeadlineMs(apiDeadlineMs: number): number {
  return Math.min(apiDeadlineMs, Date.now() + IAM_CONSISTENCY_MAX_WAIT_MS);
}

class PermissionConsistencyDeadlineError extends Error {}

function permissionConsistencyRemainingMs(
  consistencyDeadlineMs: number,
  now: () => number,
): number {
  const remainingMs = consistencyDeadlineMs - now();
  if (!Number.isSafeInteger(remainingMs) || remainingMs <= 0) {
    throw new PermissionConsistencyDeadlineError();
  }
  return remainingMs;
}

async function permissionSubrequest<T>(
  operation: () => Promise<T>,
  consistencyDeadlineMs: number,
  now: () => number,
): Promise<T> {
  permissionConsistencyRemainingMs(consistencyDeadlineMs, now);
  try {
    const result = await operation();
    permissionConsistencyRemainingMs(consistencyDeadlineMs, now);
    return result;
  } catch (error) {
    if (now() >= consistencyDeadlineMs) throw new PermissionConsistencyDeadlineError();
    throw error;
  }
}

// What the last completed scan saw, so a timeout can say which probe never
// converged instead of only that none did. Apply run 33296971474 spent the
// whole five-minute elevation window here and failed with nothing but "The
// executor state lease did not propagate before the deadline" -- after
// consuming the approved plan, which is the most expensive moment in the run
// to be told nothing.
//
// This never widens what is accepted. Convergence is still all-or-nothing and
// the timeout still throws; only the message changes. The values are probe
// names, permission names, and object paths, all of which already appear in
// the reviewed manifest and in this file.
async function waitForPermissionConvergence(
  scan: () => Promise<boolean>,
  sleep: (milliseconds: number) => Promise<void>,
  consistencyDeadlineMs: number,
  timeoutMessage: string,
  now: () => number,
  describeLastScan: () => string = () => "",
): Promise<void> {
  let attempt = 0;
  while (now() < consistencyDeadlineMs) {
    let matches: boolean;
    try {
      matches = await scan();
    } catch (error) {
      if (error instanceof PermissionConsistencyDeadlineError) break;
      throw error;
    }
    const completedAtMs = now();
    if (matches && completedAtMs < consistencyDeadlineMs) return;
    const remainingMs = consistencyDeadlineMs - completedAtMs;
    if (remainingMs <= 0) break;
    await sleep(Math.min(Math.min(2 ** attempt, 12) * 1_000, remainingMs));
    attempt += 1;
  }
  const detail = describeLastScan();
  throw new Error(detail === "" ? timeoutMessage : `${timeoutMessage} ${detail}`);
}

export async function waitForStatePermissions(
  state: { readonly bucket: string; readonly prefix: string },
  invocation: Invocation,
  executorToken: string,
  expected: "mutation" | "none" | "read",
  fetcher: Fetcher,
  sleep: (milliseconds: number) => Promise<void> = (milliseconds) => Bun.sleep(milliseconds),
  probes: StateStoragePermissionProbes = DEFAULT_STATE_STORAGE_PERMISSION_PROBES,
  consistencyDeadlineMs: number = Date.now() + IAM_CONSISTENCY_MAX_WAIT_MS,
  now: () => number = Date.now,
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
  const permissionFetcher = deadlineFetcher(
    fetcher,
    () => consistencyDeadlineMs,
    20_000,
    now,
  );
  // Reset at the top of every scan so the timeout reports the LAST attempt,
  // not an accumulation across the whole window.
  let unconverged: string[] = [];
  const objects: readonly {
    readonly bucket: string;
    readonly name: string;
    readonly required: ReadonlySet<string>;
  }[] = [
    {
      bucket: state.bucket,
      name: `${state.prefix}/default.tfstate`,
      required: expected === "mutation" ? readWrite : expected === "read" ? stateRead : noAccess,
    },
    {
      bucket: state.bucket,
      name: `${state.prefix}/default.tflock`,
      required: expected === "mutation" ? readWrite : noAccess,
    },
    // Plan and apply only. A rehearsal reviews no plan and consumes no approved
    // run, so there is no plan or adoption object for it to name -- and naming
    // one would derive an object from an approved run id that is empty, which
    // is a numeric() failure long before the live lifecycle this projection is
    // supposed to be checking.
    ...(invocation.mode === "rehearsal" ? [] : [{
      bucket: state.bucket,
      name: receiptObjectName(
        state,
        invocation.terraformRoot === "exposure" ? "adoptions" : "plans",
        invocation.mode === "plan" ? invocation.githubRunId : invocation.approvedPlanRunId,
      ),
      required: expected === "none"
        ? noAccess
        : invocation.mode === "plan" ? createRead : readOnly,
    }]),
    ...(invocation.mode === "apply"
      ? [{
          bucket: state.bucket,
          // This receipt changes state across the run, so what must be provable
          // about it changes too, and the projection -- not the mode -- is what
          // distinguishes them.
          //
          // The "read" projection runs inside `acquire`, before
          // `consumeApproval`. The object is still absent and the receipt lease
          // already grants `roles/storage.objectCreator`, so create is both
          // provable and required: this run is about to write it.
          //
          // The "mutation" projection runs inside `elevate`, after
          // `consumeApproval` has written it, and elevate REVOKES the
          // consumed-receipt create lease in the same policy write that grants
          // mutation authority. Requiring create here would require the
          // executor to prove it can overwrite an immutable receipt -- the one
          // thing the create-without-delete lease exists to prevent.
          //
          // Until v0.5.29 nothing revoked that lease, so this expectation and
          // the acquire-time grant contradicted each other permanently: run
          // 33300997122 spent the whole elevation window reporting
          // `consumed/...json (unexpectedly holds storage.objects.create)` and
          // burned its approved plan. The projection was right; the lease was
          // wrong, and the lease moved.
          name: receiptObjectName(state, "consumed", invocation.approvedPlanRunId),
          required: expected === "none"
            ? noAccess
            : expected === "mutation"
            ? readOnly
            : createRead,
        }, ...ownerWrittenReceiptProbes(state, invocation)]
      : []),
    ...(invocation.mode === "rehearsal" ? ownerWrittenReceiptProbes(state, invocation) : []),
    ...(invocation.terraformRoot === "exposure"
      ? (() => {
          const contract = REPOSITORIES[invocation.repository];
          return [
            {
              bucket: contract.state.bootstrap.bucket,
              name: `${contract.state.bootstrap.prefix}/default.tfstate`,
              required: noAccess,
            },
            {
              bucket: contract.state.prod.bucket,
              name: `${contract.state.prod.prefix}/default.tfstate`,
              required: noAccess,
            },
          ];
        })()
      : []),
    ...(invocation.repository === "runsetta" && invocation.terraformRoot === "prod"
      ? [{
          bucket: REPOSITORIES.runsetta.state.exposure.bucket,
          name: `${REPOSITORIES.runsetta.state.exposure.prefix}/default.tfstate`,
          required: expected === "none" ? noAccess : readOnly,
        }, {
          bucket: REPOSITORIES.runsetta.state.exposure.bucket,
          name: receiptObjectName(
            REPOSITORIES.runsetta.state.exposure,
            "adoptions",
            invocation.exposureAdoptionRunId,
          ),
          required: expected === "none" ? noAccess : readOnly,
        }]
      : []),
  ];
  await waitForPermissionConvergence(async () => {
    const observed: boolean[] = [];
    // Scan-local. A subrequest that reaches the deadline throws
    // PermissionConsistencyDeadlineError out of this closure, so publishing as
    // we go would replace the last COMPLETED scan's verdict with a partial
    // prefix of an interrupted one -- or with nothing at all.
    const scanUnconverged: string[] = [];
    const bucketUrl = new URL(
      `https://storage.googleapis.com/storage/v1/b/${state.bucket}/iam/testPermissions`,
    );
    for (const permission of ["storage.objects.list"]) {
      bucketUrl.searchParams.append("permissions", permission);
    }
    const bucketResponse = await permissionSubrequest(
      () =>
        permissionFetcher(bucketUrl, {
          headers: executorHeaders(executorToken),
          redirect: "error",
        }),
      consistencyDeadlineMs,
      now,
    );
    if (!bucketResponse.ok &&
      !(expected === "none" && permissionDenialProvesNoUsableCredential(bucketResponse))) {
      // 403 while waiting for a grant to appear is exactly what this loop
      // exists to absorb, and 401 is the executor's own disable/re-enable cycle
      // -- `permissionDenialProvesNoUsableCredential` already treats the two as
      // one class. Throwing discards the rest of the convergence budget; report
      // "not converged yet" and let the deadline decide.
      if (expected !== "none" && transientPermissionDenial(bucketResponse)) {
        // Publish before returning. A persistent denial is exactly the
        // never-converging case, and leaving the previous scan's verdict in
        // place would report a stale mismatch as if it were current.
        scanUnconverged.push(
          `bucket ${state.bucket}(denied with HTTP ${bucketResponse.status})`,
        );
        unconverged = scanUnconverged;
        return false;
      }
      throw new Error(`Bucket permission test failed with HTTP ${bucketResponse.status}.`);
    }
    const requiredBucketPermissions = ["storage.objects.list"];
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
      const bucketMissing = expected !== "none"
        ? requiredBucketPermissions.filter((permission) => !bucketPermissions.has(permission))
        : [];
      const bucketHeld = expected === "none"
        ? requiredBucketPermissions.filter((permission) => bucketPermissions.has(permission))
        : [];
      const bucketConverged = bucketMissing.length === 0 && bucketHeld.length === 0;
      if (!bucketConverged) {
        scanUnconverged.push(
          `bucket ${state.bucket}(${
            bucketMissing.length === 0
              ? `unexpectedly holds ${bucketHeld.toSorted().join("+")}`
              : `missing ${bucketMissing.toSorted().join("+")}`
          })`,
        );
      }
      observed.push(bucketConverged);
    }

    for (const object of objects) {
      const resource = `projects/_/buckets/${object.bucket}/objects/${object.name}`;
      const rpcTimeoutMs = Math.min(
        STORAGE_PERMISSION_RPC_TIMEOUT_MS,
        permissionConsistencyRemainingMs(consistencyDeadlineMs, now),
      );
      const objectResult = await permissionSubrequest(
        () =>
          probes.testObjectPermissions({
            bucketResource: `projects/_/buckets/${object.bucket}`,
            executorToken,
            permissions: STORAGE_OBJECT_RPC_PERMISSIONS,
            resource,
            // The retry inside the probe is bounded by this same deadline, so
            // surviving a transient RPC fault can never eat the convergence
            // window the loop above still needs.
          }, { deadlineMs: consistencyDeadlineMs, now, timeoutMs: rpcTimeoutMs }),
        consistencyDeadlineMs,
        now,
      );
      if (objectResult.denied && expected !== "none") {
        // Both denial codes are transient here, and the bridge is what makes
        // them so. PERMISSION_DENIED is a lease still propagating.
        // UNAUTHENTICATED is the executor's own disable/re-enable cycle: the
        // token is minted before `executor.disable`, and disabling a service
        // account rejects its existing tokens until it is re-enabled and that
        // re-enable propagates. `executor.final-enable` immediately precedes
        // this projection, so a token minted minutes earlier is routinely
        // rejected for the first seconds of it.
        //
        // Neither can be distinguished from a genuinely unusable credential by
        // its code alone, and the convergence loop already bounds the wait: a
        // credential that never becomes usable fails on the deadline with the
        // lease-propagation message instead of aborting the run outright.
        scanUnconverged.push(`${object.name}(denied)`);
        unconverged = scanUnconverged;
        return false;
      }
      if (objectResult.denied && objectResult.permissions.length !== 0) {
        throw new Error("Denied storage object permission RPC returned permissions.");
      }
      const permissions = new Set(objectResult.permissions);
      for (const permission of permissions) {
        if (!STORAGE_OBJECT_RPC_PERMISSIONS.includes(
          permission as typeof STORAGE_OBJECT_RPC_PERMISSIONS[number],
        )) {
          throw new Error("Storage object permission probe escaped its permission allowlist.");
        }
      }
      const createOrOverwrite = await permissionSubrequest(
        () =>
          probes.testObjectOverwrite(
            { bucket: object.bucket, executorToken, objectName: object.name },
            permissionFetcher,
          ),
        consistencyDeadlineMs,
        now,
      );
      if (createOrOverwrite) permissions.add("storage.objects.create");
      const forbidden = allObjectPermissions.filter((permission) => !object.required.has(permission));
      const missing = [...object.required].filter((permission) => !permissions.has(permission));
      const held = forbidden.filter((permission) => permissions.has(permission));
      const converged = expected !== "none"
        ? missing.length === 0 && held.length === 0
        : allObjectPermissions.every((permission) => !permissions.has(permission));
      if (!converged) {
        // Object paths carry the run and plan ids and the state prefix, all of
        // which are already in the reviewed manifest; permission names are
        // constants in this file. Nothing here is a secret.
        scanUnconverged.push(
          `${object.name}(${
            [
              ...(missing.length === 0 ? [] : [`missing ${missing.toSorted().join("+")}`]),
              ...(held.length === 0 ? [] : [`unexpectedly holds ${held.toSorted().join("+")}`]),
              ...(expected === "none" && missing.length === 0 && held.length === 0
                ? [`still holds ${[...permissions].toSorted().join("+")}`]
                : []),
            ].join("; ")
          })`,
        );
      }
      observed.push(converged);
    }
    // The scan completed; only now is this a description of a whole attempt.
    unconverged = scanUnconverged;
    return observed.every(Boolean);
  }, sleep, consistencyDeadlineMs,
    expected !== "none"
      ? "The executor state lease did not propagate before the deadline."
      : "The executor retained state permissions after exact lease cleanup.",
    now,
    () =>
      unconverged.length === 0
        ? ""
        : `Unconverged after the final scan: ${unconverged.join(", ")}.`);
}

// Owner-written artifacts, probed in EVERY phase and required to return zero
// executor permissions.
//
// Removing the lease is not the same statement as proving the absence. A
// bucket-level binding, an inherited grant, or anything issued out of band
// would be invisible if these keys simply stopped being probed -- so they are
// probed precisely because nothing grants them. The negative result is the
// evidence; the missing lease is only the intent.
//
// `results/*` is included even though no current run writes it: a stale grant
// from a build that predates its removal is exactly the thing worth catching.
function ownerWrittenReceiptProbes(
  state: { readonly bucket: string; readonly prefix: string },
  invocation: Invocation,
): readonly {
  readonly bucket: string;
  readonly name: string;
  readonly required: ReadonlySet<string>;
}[] {
  const noAccess: ReadonlySet<string> = new Set<string>();
  return [
    receiptObjectName(state, "results", invocation.githubRunId),
    receiptObjectName(state, "final", invocation.githubRunId),
    receiptObjectName(state, "completion", invocation.githubRunId),
    ...(invocation.mode === "rehearsal"
      ? [receiptObjectName(state, "rehearsals", invocation.githubRunId)]
      : []),
  ].map((name) => ({ bucket: state.bucket, name, required: noAccess }));
}

export async function waitForControlPermissions(
  invocation: Invocation,
  executorToken: string,
  expected: "mutation" | "none" | "read",
  fetcher: Fetcher,
  sleep: (milliseconds: number) => Promise<void> = (milliseconds) => Bun.sleep(milliseconds),
  consistencyDeadlineMs: number = Date.now() + IAM_CONSISTENCY_MAX_WAIT_MS,
  now: () => number = Date.now,
): Promise<void> {
  const contract = REPOSITORIES[invocation.repository];
  if (invocation.terraformRoot === "exposure" && expected === "mutation") {
    throw new Error("Exposure adoption has no executor mutation phase.");
  }
  // Every exposure Storage/marker lease is resource-conditioned to a bucket or
  // object, so it intentionally grants no project-level permission. The owner
  // performs live DomainMapping reads outside the executor sandbox.
  const exposureReadPermissions = [] as const;
  const exposureForbiddenPermissions = [
    "run.domainmappings.create",
    "run.domainmappings.delete",
  ] as const;
  const projectPermissions = invocation.terraformRoot === "exposure"
    ? [...exposureReadPermissions, ...exposureForbiddenPermissions]
    : executorControlPermissions(
        invocation.repository,
        invocation.terraformRoot,
        "mutation",
      );
  const requiredPermissions = new Set(expected === "mutation"
    ? invocation.terraformRoot === "exposure" ? exposureReadPermissions : projectPermissions
    : expected === "read"
    ? invocation.terraformRoot === "exposure"
      ? exposureReadPermissions
      : executorControlPermissions(invocation.repository, invocation.terraformRoot, "read")
    : []);
  const permissionFetcher = deadlineFetcher(
    fetcher,
    () => consistencyDeadlineMs,
    20_000,
    now
  );
  // Reset per scan, so a timeout reports the last attempt rather than an
  // accumulation across the window.
  let controlUnconverged: string[] = [];
  await waitForPermissionConvergence(async () => {
    // Scan-local for the same reason as the state scan: a deadline reached
    // inside a subrequest must not replace the last completed verdict.
    const scanControlUnconverged: string[] = [];
    const projectResponse = await permissionSubrequest(
      () =>
        permissionFetcher(
          `https://cloudresourcemanager.googleapis.com/v1/projects/${contract.projectId}:testIamPermissions`,
          {
            body: JSON.stringify({ permissions: projectPermissions }),
            headers: { ...executorHeaders(executorToken), "Content-Type": "application/json" },
            method: "POST",
            redirect: "error",
          },
        ),
      consistencyDeadlineMs,
      now,
    );
    if (!projectResponse.ok &&
      !(expected === "none" && permissionDenialProvesNoUsableCredential(projectResponse))) {
      // Same transient class the state probe tolerates, and this projection
      // runs after the plan has been consumed, so throwing burns the approved
      // plan over a condition the convergence budget exists to wait out.
      if (expected !== "none" && transientPermissionDenial(projectResponse)) {
        scanControlUnconverged.push(`project(denied with HTTP ${projectResponse.status})`);
        controlUnconverged = scanControlUnconverged;
        return false;
      }
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
      const wrong = projectPermissions.filter((permission) =>
        granted.has(permission) !== requiredPermissions.has(permission)
      );
      projectMatches = wrong.length === 0;
      if (!projectMatches) {
        const absent = wrong.filter((permission) => requiredPermissions.has(permission));
        const extra = wrong.filter((permission) => !requiredPermissions.has(permission));
        scanControlUnconverged.push(
          `project(${
            [
              ...(absent.length === 0 ? [] : [`missing ${absent.toSorted().join("+")}`]),
              ...(extra.length === 0 ? [] : [`unexpectedly holds ${extra.toSorted().join("+")}`]),
            ].join("; ")
          })`,
        );
      }
    }

    let actAsMatches = true;
    if (invocation.terraformRoot === "prod" || invocation.terraformRoot === "exposure") {
      for (const email of runtimeServiceAccountEmails(invocation.repository)) {
        const runtimePermissions = [
          "iam.serviceAccounts.actAs",
          "iam.serviceAccounts.getAccessToken",
          "iam.serviceAccounts.signBlob",
          "iam.serviceAccounts.signJwt",
        ];
        const response = await permissionSubrequest(
          () =>
            permissionFetcher(`${serviceAccountUrl(email)}:testIamPermissions`, {
              body: JSON.stringify({ permissions: runtimePermissions }),
              headers: { ...executorHeaders(executorToken), "Content-Type": "application/json" },
              method: "POST",
              redirect: "error",
            }),
          consistencyDeadlineMs,
          now,
        );
        if (!response.ok &&
          !(expected === "none" && permissionDenialProvesNoUsableCredential(response))) {
          // A prod elevation adds the runtime actAs leases immediately before
          // this scan, so their denial is the same transient the project probe
          // above waits out -- and this runs post-consumption too.
          if (expected !== "none" && transientPermissionDenial(response)) {
            scanControlUnconverged.push(
              `runtime ${email}(denied with HTTP ${response.status})`,
            );
            controlUnconverged = scanControlUnconverged;
            return false;
          }
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
        const expectedActAs = invocation.terraformRoot === "prod" && expected === "mutation";
        if (
          permissions.has("iam.serviceAccounts.actAs") !== expectedActAs ||
          runtimePermissions.slice(1).some((permission) => permissions.has(permission))
        ) {
          actAsMatches = false;
          scanControlUnconverged.push(
            `runtime ${email}(actAs=${permissions.has("iam.serviceAccounts.actAs")} expected=${expectedActAs}; holds ${
              [...permissions].toSorted().join("+") || "nothing"
            })`,
          );
        }
      }
    }
    let exposureReadDenied = true;
    if (
      invocation.terraformRoot === "exposure" ||
      (invocation.repository === "runsetta" && invocation.terraformRoot === "prod")
    ) {
      const response = await permissionSubrequest(
        () => permissionFetcher(
          `https://${contract.exposure.region}-run.googleapis.com/apis/domains.cloudrun.com/v1/namespaces/${contract.projectId}/domainmappings`,
          { headers: executorHeaders(executorToken), redirect: "error" },
        ),
        consistencyDeadlineMs,
        now,
      );
      exposureReadDenied = permissionDenialProvesNoUsableCredential(response);
      if (!exposureReadDenied) {
        throw new Error(
          `Exposure executor unexpectedly reached the Domain Mapping API with HTTP ${response.status}.`,
        );
      }
    }
    if (!exposureReadDenied) {
      scanControlUnconverged.push("exposure Domain Mapping API was reachable");
    }
    controlUnconverged = scanControlUnconverged;
    return projectMatches && actAsMatches && exposureReadDenied;
  }, sleep, consistencyDeadlineMs,
    expected !== "none"
      ? "The executor control-plane lease did not propagate before the deadline."
      : "The executor token retained control-plane or runtime actAs permissions after cleanup.",
    now,
    () =>
      controlUnconverged.length === 0
        ? ""
        : `Unconverged after the final scan: ${controlUnconverged.join(", ")}.`);
}

type StorageBackendRoleName = keyof typeof STORAGE_BACKEND_ROLE_PERMISSIONS;


export async function requireStorageBackendRoleContracts(
  token: string,
  fetcher: Fetcher,
): Promise<void> {
  for (const roleName of Object.keys(STORAGE_BACKEND_ROLE_PERMISSIONS) as StorageBackendRoleName[]) {
    const response = await fetcher(`https://iam.googleapis.com/v1/${roleName}`, {
      headers: executorHeaders(token),
      redirect: "error",
    });
    if (!response.ok) {
      throw new Error(`${roleName} contract read failed with HTTP ${response.status}.`);
    }
    const role = record(
      await boundedJson(response, 256 * 1024),
      `${roleName} contract`,
    );
    exact(role.name, roleName, `${roleName} contract name`);
    exact(role.stage, STORAGE_BACKEND_ROLE_STAGES[roleName], `${roleName} contract stage`);
    const permissions = array(
      role.includedPermissions,
      `${roleName} contract permissions`,
    ).map((permission) => requiredString(permission, `${roleName} contract permission`));
    validateStorageBackendRolePermissionInventory(roleName, permissions);
  }
}

export function validateStorageBackendRolePermissionInventory(
  roleName: StorageBackendRoleName,
  permissionList: readonly string[],
): void {
  if (new Set(permissionList).size !== permissionList.length) {
    throw new Error(`${roleName} permission inventory contains duplicates.`);
  }
  const observed = [...permissionList].toSorted();
  const expected = [...STORAGE_BACKEND_ROLE_PERMISSIONS[roleName]].toSorted();
  exact(
    canonicalJson(observed),
    canonicalJson(expected),
    `${roleName} permission inventory`,
  );
  const forbidden = [
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccounts.signBlob",
    "secretmanager.versions.access",
    "storage.buckets.create",
    "storage.buckets.delete",
    "storage.buckets.getIamPolicy",
    "storage.buckets.setIamPolicy",
    "storage.buckets.update",
    "storage.objects.delete",
    "storage.objects.getIamPolicy",
    "storage.objects.setIamPolicy",
    "storage.objects.update",
  ];
  for (const permission of forbidden) {
    if (observed.includes(permission)) {
      throw new Error(`${roleName} gained forbidden backend mutation permission ${permission}.`);
    }
  }
  if (roleName !== "roles/storage.objectCreator" && observed.includes("storage.objects.create")) {
    throw new Error(`${roleName} gained forbidden backend mutation permission storage.objects.create.`);
  }
}

function runsettaExposureInstanceAttributes(
  domain: RunsettaDomain,
): JsonValue {
  const records = RUNSETTA_DOMAIN_RECORDS[domain];
  return {
    deletion_policy: "DELETE",
    id: exposureDomainId(REPOSITORIES.runsetta, domain),
    location: REPOSITORIES.runsetta.exposure.region,
    metadata: [{
      annotations: {},
      labels: {},
      namespace: REPOSITORIES.runsetta.projectId,
    }],
    name: domain,
    project: REPOSITORIES.runsetta.projectId,
    spec: [{
      certificate_mode: "AUTOMATIC",
      force_override: false,
      route_name: REPOSITORIES.runsetta.exposure.serviceName,
    }],
    status: [{
      conditions: ["Ready", "CertificateProvisioned", "DomainRoutable"].map((type) => ({
        message: "",
        reason: "",
        status: "True",
        type,
      })),
      mapped_route_name: REPOSITORIES.runsetta.exposure.serviceName,
      observed_generation: 1,
      resource_records: records.map((record) => ({ ...record })),
    }],
    timeouts: null,
  };
}

function runsettaFullExposureStateValue(lineage: string): JsonValue {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(lineage)) {
    throw new Error("New exposure state lineage is not a canonical lowercase UUIDv4.");
  }
  const outputTypeMembers: Record<string, JsonValue> = {};
  const outputValues: Record<string, JsonValue> = {};
  const instances = RUNSETTA_DOMAINS.map((domain) => {
    const records = RUNSETTA_DOMAIN_RECORDS[domain];
    outputTypeMembers[domain] = [
      "list",
      ["object", { name: "string", rrdata: "string", type: "string" }],
    ];
    outputValues[domain] = records.map((record) => ({ ...record }));
    return {
      attributes: runsettaExposureInstanceAttributes(domain),
      identity_schema_version: 0,
      index_key: domain,
      schema_version: 1,
      sensitive_attributes: [],
    };
  });
  const checkSpecs: readonly (readonly [string, string | null])[] = [
    ["module.preview_domain.var.preview_domain", null],
    ["var.repository_id", "var.repository_id"],
    ["module.domains.var.domains", "module.domains.var.domains"],
    ["module.preview_domain.var.resource_name_prefix", null],
    ["module.preview_domain.var.preview_service_name", null],
  ];
  const checkResults: JsonValue[] = checkSpecs.map(([configAddress, objectAddress]) => ({
    config_addr: configAddress,
    object_kind: "var",
    objects: objectAddress === null
      ? null
      : [{ object_addr: objectAddress, status: "pass" }],
    status: "pass",
  }));
  return {
    check_results: checkResults,
    lineage,
    outputs: {
      cloud_run_domain_mappings: {
        type: ["object", outputTypeMembers],
        value: outputValues,
      },
    },
    resources: [{
      instances,
      mode: "managed",
      module: "module.domains",
      name: "site",
      provider: 'provider["registry.terraform.io/hashicorp/google"]',
      type: "google_cloud_run_domain_mapping",
    }],
    serial: 1,
    terraform_version: TERRAFORM_VERSION,
    version: 4,
  };
}

export function canonicalRunsettaExposureState(lineage: string): string {
  return `${canonicalJson(runsettaFullExposureStateValue(lineage))}\n`;
}

function exposureLiveContinuityDigest(
  proof: Pick<ExposureProof, "https" | "mappingListCount" | "mappingListSha256" | "mappings">,
): string {
  return hashJson({
    https: json(proof.https, "exposure HTTPS continuity proof"),
    mappingListCount: proof.mappingListCount,
    mappingListSha256: proof.mappingListSha256,
    mappings: json(proof.mappings, "exposure mapping continuity proof"),
  });
}

async function readExposureStateProof(
  invocation: Invocation,
  executorToken: string,
  fetcher: Fetcher,
): Promise<ExposureStateProof> {
  exact(invocation.terraformRoot, "exposure", "exposure state proof root");
  exact(invocation.repository, "runsetta", "exposure state proof repository");
  const contract = REPOSITORIES[invocation.repository];
  const backend = contract.state.exposure;
  const object = `${backend.prefix}/default.tfstate`;
  const metadataUrl = new URL(
    `https://storage.googleapis.com/storage/v1/b/${backend.bucket}/o/${encodeURIComponent(object)}`,
  );
  const metadataResponse = await fetcher(metadataUrl, {
    headers: executorHeaders(executorToken),
    redirect: "error",
  });
  if (metadataResponse.status === 404) {
    return {
      bucket: backend.bucket,
      generation: null,
      lineage: null,
      mappings: [],
      metageneration: null,
      object,
      serial: null,
      sha256: null,
      size: null,
      state: "absent",
    };
  }
  if (!metadataResponse.ok) {
    throw new Error(`Exposure state metadata read failed with HTTP ${metadataResponse.status}.`);
  }
  const metadata = record(
    await boundedJson(metadataResponse, 256 * 1024),
    "exposure state metadata",
  );
  exact(metadata.bucket, backend.bucket, "exposure state metadata bucket");
  exact(metadata.name, object, "exposure state metadata object");
  const generation = numeric(
    requiredString(metadata.generation, "exposure state metadata generation"),
    "exposure state metadata generation",
  );
  const metageneration = numeric(
    requiredString(metadata.metageneration, "exposure state metadata metageneration"),
    "exposure state metadata metageneration",
  );
  const size = numeric(
    requiredString(metadata.size, "exposure state metadata size"),
    "exposure state metadata size",
  );
  if (BigInt(size) > BigInt(MAX_EXPOSURE_STATE_BYTES)) {
    throw new Error("Exposure state exceeds its private read bound.");
  }
  const mediaUrl = new URL(metadataUrl);
  mediaUrl.searchParams.set("alt", "media");
  mediaUrl.searchParams.set("ifGenerationMatch", generation);
  const mediaResponse = await fetcher(mediaUrl, {
    headers: executorHeaders(executorToken),
    redirect: "error",
  });
  if (!mediaResponse.ok) {
    throw new Error(`Generation-bound exposure state read failed with HTTP ${mediaResponse.status}.`);
  }
  const rawState = await boundedText(mediaResponse, MAX_EXPOSURE_STATE_BYTES);
  if (String(Buffer.byteLength(rawState)) !== size) {
    throw new Error("Generation-bound exposure state size changed during proof.");
  }
  let parsedState: unknown;
  try {
    parsedState = JSON.parse(rawState) as unknown;
  } catch {
    throw new Error("Exposure state is not valid Terraform JSON.");
  }
  const terraformState = record(parsedState, "exposure Terraform state");
  exactKeys(
    terraformState,
    new Set([
      "check_results",
      "lineage",
      "outputs",
      "resources",
      "serial",
      "terraform_version",
      "version",
    ]),
    "exposure Terraform state",
  );
  exact(terraformState.version, 4, "exposure Terraform state version");
  exact(terraformState.terraform_version, TERRAFORM_VERSION, "exposure Terraform version");
  const lineage = requiredString(terraformState.lineage, "exposure Terraform state lineage");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(lineage)) {
    throw new Error("Exposure state lineage is not canonical lowercase UUID-shaped hex.");
  }
  const serial = boundedInteger(
    terraformState.serial,
    "exposure Terraform state serial",
    1,
    1,
  );
  const expectedState = canonicalRunsettaExposureState(lineage);
  exact(rawState, expectedState, "canonical Runsetta exposure state bytes");
  const mappings: ExposureStateMappingProof[] = RUNSETTA_DOMAINS.map((domain) => ({
    address: exposureDomainAddress(domain),
    domain,
    id: exposureDomainId(contract, domain),
  }));
  return {
    bucket: backend.bucket,
    generation,
    lineage,
    mappings: mappings.toSorted((left, right) => left.domain.localeCompare(right.domain)),
    metageneration,
    object,
    serial,
    sha256: createHash("sha256").update(rawState).digest("hex"),
    size,
    state: "present",
  };
}

export async function ensureExposureStateInitialized(
  invocation: Invocation,
  stateReadToken: string,
  controllerOwnerToken: string,
  liveProof: ExposureProof,
  fetcher: Fetcher,
  sleep: (milliseconds: number) => Promise<void> = (milliseconds) => Bun.sleep(milliseconds),
  deadlineMs: number = Date.now() + IAM_CONSISTENCY_MAX_WAIT_MS,
  lineageFactory: () => string = randomUUID,
  now: () => number = Date.now,
): Promise<ExposureAdoptionResult> {
  exact(invocation.terraformRoot, "exposure", "exposure state adoption root");
  exact(invocation.repository, "runsetta", "exposure state adoption repository");
  secretValue(stateReadToken, "exposure adoption state-read token");
  secretValue(controllerOwnerToken, "exposure adoption owner token");
  if (stateReadToken === controllerOwnerToken) {
    throw new Error("Exposure state read and create/live tokens must remain distinct.");
  }
  const contract = REPOSITORIES.runsetta;
  const backend = contract.state.exposure;
  const normalizedProof = exposureProofFromJson(
    liveProof,
    invocation.repository,
    invocation.terraformRoot,
  );
  if (normalizedProof === null) throw new Error("Exposure state initializer lacks a live proof.");
  const initialLiveContinuityDigest = exposureLiveContinuityDigest(normalizedProof);
  const finishAdoption = async (
    state: ExposureStateProof,
    outcome: ExposureAdoptionAudit["outcome"],
  ): Promise<ExposureAdoptionResult> => {
    const postAdoptionProof = await proveExposure(
      invocation,
      stateReadToken,
      fetcher,
      controllerOwnerToken,
    );
    if (postAdoptionProof === null) {
      throw new Error("Exposure state adoption lacks its post-seed live proof.");
    }
    exact(
      exposureLiveContinuityDigest(postAdoptionProof),
      initialLiveContinuityDigest,
      "exposure live continuity across state adoption",
    );
    exact(
      canonicalJson(json(postAdoptionProof.state, "post-adoption exposure state")),
      canonicalJson(json(state, "adopted exposure state")),
      "post-adoption exposure state proof",
    );
    const postLiveSha256 = exposureLiveContinuityDigest(postAdoptionProof);
    return {
      audit: {
        controllerCreateLeaseDisposition: outcome === "exact-existing"
          ? "not-granted"
          : "pending-removal",
        initialState: normalizedProof.state,
        liveContinuityEqual: true,
        outcome,
        postLiveSha256,
        preLiveSha256: initialLiveContinuityDigest,
        stateTransitionSha256: hashJson({
          finalState: json(state, "final adopted exposure state"),
          initialState: json(normalizedProof.state, "initial exposure state"),
        }),
      },
      state,
    };
  };
  const expectedMappings = RUNSETTA_DOMAINS.map((domain) => ({
    domain,
    generation: "1",
    id: exposureDomainId(contract, domain),
    observedGeneration: "1",
    recordsSha256: hashJson(
      RUNSETTA_DOMAIN_RECORDS[domain].map((record) => ({ ...record }))
        .toSorted((left, right) => canonicalJson(left).localeCompare(canonicalJson(right))),
    ),
    uid: RUNSETTA_DOMAIN_UIDS[domain],
  })).toSorted((left, right) => left.domain.localeCompare(right.domain));
  exact(
    canonicalJson(json(normalizedProof.mappings, "initializer live mappings")),
    canonicalJson(expectedMappings),
    "initializer live mapping contract",
  );
  const lineage = lineageFactory();
  const proposed = canonicalRunsettaExposureState(lineage);
  const proposedSha256 = createHash("sha256").update(proposed).digest("hex");
  let requireExactProposedState = false;
  let createdGeneration: string | undefined;
  let pendingOutcome: ExposureAdoptionAudit["outcome"] | undefined;
  let attempt = 0;
  while (now() < deadlineMs) {
    try {
      const observed = await readExposureStateProof(invocation, stateReadToken, fetcher);
      if (observed.state === "present") {
        if (requireExactProposedState) {
          if (createdGeneration !== undefined) {
            exact(observed.generation, createdGeneration, "created exposure state generation");
          }
          exact(observed.lineage, lineage, "raced exposure state lineage");
          exact(observed.serial, 1, "raced exposure state serial");
          exact(observed.size, String(Buffer.byteLength(proposed)), "raced exposure state size");
          exact(observed.sha256, proposedSha256, "raced exposure state bytes");
          exact(
            observed.mappings.length,
            contract.exposure.domains.length,
            "raced exposure state mapping count",
          );
        } else if (normalizedProof.state.state === "present") {
          exact(
            canonicalJson(json(observed, "existing exposure state")),
            canonicalJson(json(normalizedProof.state, "initial exposure state")),
            "existing exposure state proof",
          );
        } else {
          throw new Error("Exposure state appeared before its create-only initialization attempt.");
        }
        return await finishAdoption(
          observed,
          requireExactProposedState ? pendingOutcome ?? "response-loss-reconciled" : "exact-existing",
        );
      }
      if (normalizedProof.state.state === "present") {
        throw new Error("The generation-bound exposure state disappeared before initialization.");
      }
      const uploadUrl = new URL(
        `https://storage.googleapis.com/upload/storage/v1/b/${backend.bucket}/o`,
      );
      uploadUrl.searchParams.set("ifGenerationMatch", "0");
      uploadUrl.searchParams.set("name", `${backend.prefix}/default.tfstate`);
      uploadUrl.searchParams.set("uploadType", "media");
      // A lost response can hide a committed create. From the first upload
      // attempt onward, only this invocation's exact proposed bytes are safe.
      requireExactProposedState = true;
      const response = await fetcher(uploadUrl, {
        body: proposed,
        headers: {
          ...executorHeaders(controllerOwnerToken),
          "Content-Type": "application/json; charset=utf-8",
        },
        method: "POST",
        redirect: "error",
      });
      if (response.status === 412) {
        pendingOutcome = "precondition-reconciled";
      } else {
        if (!response.ok) {
          throw new Error(`Exposure state adoption failed with HTTP ${response.status}.`);
        }
        pendingOutcome = "created";
        const created = record(
          await boundedJson(response, 256 * 1024),
          "created exposure state metadata",
        );
        exact(created.bucket, backend.bucket, "created exposure state bucket");
        exact(created.name, `${backend.prefix}/default.tfstate`, "created exposure state object");
        createdGeneration = numeric(
          requiredString(created.generation, "created exposure state generation"),
          "created exposure state generation",
        );
        exact(
          numeric(requiredString(created.size, "created exposure state size"), "created exposure state size"),
          String(Buffer.byteLength(proposed)),
          "created exposure state size",
        );
      }
    } catch (error) {
      if (requireExactProposedState && pendingOutcome === undefined && error instanceof TypeError) {
        pendingOutcome = "response-loss-reconciled";
      }
      if (!retryableIamConsistencyError(error) &&
        !(error instanceof Error && /HTTP 403\b/.test(error.message))) {
        throw error;
      }
    }
    const remainingMs = deadlineMs - now();
    if (remainingMs <= 0) break;
    await sleep(Math.min(iamRetryDelayMs(attempt), remainingMs));
    attempt = Math.min(attempt + 1, IAM_RETRY_MAX_ATTEMPTS - 1);
  }
  throw new Error("Canonical exposure state adoption did not converge before the deadline.");
}

interface GenerationBoundObject {
  readonly generation: string;
  readonly metageneration: string;
  readonly raw: string;
  readonly sha256: string;
  readonly size: string;
}

async function readGenerationBoundObject(
  bucket: string,
  object: string,
  token: string,
  maxBytes: number,
  fetcher: Fetcher,
): Promise<GenerationBoundObject> {
  const metadataUrl = new URL(
    `https://storage.googleapis.com/storage/v1/b/${bucket}/o/${encodeURIComponent(object)}`,
  );
  const metadataResponse = await fetcher(metadataUrl, {
    headers: executorHeaders(token),
    redirect: "error",
  });
  if (!metadataResponse.ok) {
    throw new Error(`Immutable object metadata read failed with HTTP ${metadataResponse.status}.`);
  }
  const metadata = record(
    await boundedJson(metadataResponse, 256 * 1024),
    "immutable object metadata",
  );
  exact(metadata.bucket, bucket, "immutable object metadata bucket");
  exact(metadata.name, object, "immutable object metadata name");
  const generation = numeric(
    requiredString(metadata.generation, "immutable object generation"),
    "immutable object generation",
  );
  const metageneration = numeric(
    requiredString(metadata.metageneration, "immutable object metageneration"),
    "immutable object metageneration",
  );
  const size = numeric(
    requiredString(metadata.size, "immutable object size"),
    "immutable object size",
  );
  if (BigInt(size) > BigInt(maxBytes)) throw new Error("Immutable object exceeded its read bound.");
  const mediaUrl = new URL(metadataUrl);
  mediaUrl.searchParams.set("alt", "media");
  mediaUrl.searchParams.set("ifGenerationMatch", generation);
  const mediaResponse = await fetcher(mediaUrl, {
    headers: executorHeaders(token),
    redirect: "error",
  });
  if (!mediaResponse.ok) {
    throw new Error(`Generation-bound immutable object read failed with HTTP ${mediaResponse.status}.`);
  }
  const raw = await boundedText(mediaResponse, maxBytes);
  exact(String(Buffer.byteLength(raw)), size, "generation-bound immutable object size");
  return {
    generation,
    metageneration,
    raw,
    sha256: createHash("sha256").update(raw).digest("hex"),
    size,
  };
}

export async function verifyAdoptionWorkflowRun(
  invocation: Invocation,
  fetcher: Fetcher,
  retry?: GithubProofRetryPolicy,
): Promise<void> {
  const runId = invocation.exposureAdoptionRunId;
  if (BigInt(runId) >= BigInt(invocation.githubRunId)) {
    throw new Error("Runsetta exposure adoption run must precede production.");
  }
  const base = `https://api.github.com/repos/${PLATFORM_REPOSITORY}`;
  const run = record(
    await githubJson(
      `${base}/actions/runs/${runId}`,
      invocation.platformActionsToken,
      fetcher,
      retry,
    ),
    "Runsetta exposure adoption GitHub run",
  );
  exact(String(run.id), runId, "Runsetta exposure adoption GitHub run ID");
  exact(String(run.run_attempt), "1", "Runsetta exposure adoption run attempt");
  exact(run.event, "workflow_dispatch", "Runsetta exposure adoption event");
  exact(run.status, "completed", "Runsetta exposure adoption status");
  exact(run.conclusion, "success", "Runsetta exposure adoption conclusion");
  // A platform release invalidates the adoption receipt exactly as it
  // invalidates every other pinned artifact, and this is where that surfaces --
  // in `proof`, after a single-use owner token has been minted, a human has
  // approved, and an executor has been elevated. The check itself is right: an
  // adoption performed under an older, possibly weaker platform must not
  // authorize a production apply. But the bare "drifted from the reviewed
  // value" sent an operator hunting a config error when the remedy is simply to
  // re-run the adoption, which is idempotent and finishes `exact-existing`
  // against live state.
  if (run.head_sha !== invocation.platformSha) {
    throw new Error(
      "Runsetta exposure adoption platform SHA drifted from the reviewed value: " +
        `adoption run ${runId} was performed at platform ${String(run.head_sha).slice(0, 12)}, ` +
        `the reviewed pin is ${invocation.platformSha.slice(0, 12)}. A platform release ` +
        "invalidates the adoption receipt; re-run the runsetta exposure adoption at the " +
        "current pin, then dispatch runsetta prod naming the new adoption run.",
    );
  }
  exact(run.head_branch, "main", "Runsetta exposure adoption branch");
  exact(
    String(record(run.actor, "Runsetta exposure adoption actor").id),
    PLATFORM_OWNER_ID,
    "Runsetta exposure adoption actor ID",
  );
  exact(
    String(record(run.repository, "Runsetta exposure adoption repository").id),
    PLATFORM_REPOSITORY_ID,
    "Runsetta exposure adoption repository ID",
  );
  const workflowId = numeric(String(run.workflow_id), "Runsetta exposure adoption workflow ID");
  const workflow = record(
    await githubJson(
      `${base}/actions/workflows/${workflowId}`,
      invocation.platformActionsToken,
      fetcher,
      retry,
    ),
    "Runsetta exposure adoption workflow",
  );
  exact(
    workflow.path,
    ".github/workflows/protected-bootstrap-implementation.yml",
    "Runsetta exposure adoption workflow path",
  );
}

async function verifyRunsettaExposureAdoptionPrerequisite(
  invocation: Invocation,
  executorToken: string,
  liveReadToken: string,
  preparation: PreparationResult,
  fetcher: Fetcher,
  retry?: GithubProofRetryPolicy,
): Promise<ExposureProof> {
  await verifyAdoptionWorkflowRun(invocation, fetcher, retry);
  const backend = REPOSITORIES.runsetta.state.exposure;
  const receiptObject = receiptObjectName(
    backend,
    "adoptions",
    invocation.exposureAdoptionRunId,
  );
  const object = await readGenerationBoundObject(
    backend.bucket,
    receiptObject,
    executorToken,
    32 * 1024,
    fetcher,
  );
  let parsed: unknown;
  try {
    parsed = JSON.parse(object.raw) as unknown;
  } catch {
    throw new Error("Runsetta exposure adoption receipt is malformed.");
  }
  const receipt = record(parsed, "Runsetta exposure adoption receipt");
  exactKeys(
    receipt,
    new Set([
      "adoptedAt",
      "confirmation",
      "consumerSha",
      "consumerTreeSha",
      "dhiParityId",
      "exposureProof",
      "freezeProof",
      "manifestSha256",
      "markerProof",
      "mode",
      "platformSha",
      "projectId",
      "repository",
      "repositoryId",
      "runId",
      "schemaVersion",
      "terraformRoot",
    ]),
    "Runsetta exposure adoption receipt",
  );
  exact(receipt.schemaVersion, 1, "Runsetta exposure adoption receipt schema");
  exact(receipt.mode, "adoption-complete", "Runsetta exposure adoption receipt mode");
  exact(
    receipt.confirmation,
    RUNSETTA_EXPOSURE_ADOPTION_CONFIRMATION,
    "Runsetta exposure adoption confirmation",
  );
  exact(receipt.runId, invocation.exposureAdoptionRunId, "Runsetta exposure adoption run ID");
  exact(receipt.platformSha, invocation.platformSha, "Runsetta adoption receipt platform SHA");
  exact(receipt.consumerSha, invocation.consumerSha, "Runsetta adoption receipt consumer SHA");
  exact(
    receipt.consumerTreeSha,
    preparation.consumerTreeSha,
    "Runsetta adoption receipt consumer tree SHA",
  );
  exact(receipt.dhiParityId, preparation.dhiParityId, "Runsetta adoption receipt DHI parity ID");
  exact(receipt.projectId, REPOSITORIES.runsetta.projectId, "Runsetta adoption project ID");
  exact(receipt.repository, "runsetta", "Runsetta adoption repository");
  exact(
    receipt.repositoryId,
    REPOSITORIES.runsetta.repositoryId,
    "Runsetta adoption repository ID",
  );
  exact(receipt.terraformRoot, "exposure", "Runsetta adoption Terraform root");
  const adoptedAt = requiredString(receipt.adoptedAt, "Runsetta exposure adoption time");
  if (!Number.isFinite(Date.parse(adoptedAt))) {
    throw new Error("Runsetta exposure adoption time is malformed.");
  }
  const manifestSha256 = hash(
    requiredString(receipt.manifestSha256, "Runsetta adoption manifest digest"),
    "Runsetta adoption manifest digest",
  );
  markerProofFromJson(receipt.markerProof, false);
  const freeze = freezeProofFromJson(receipt.freezeProof, preparation.tokenDrainSeconds);
  exact(
    freeze.tokenDrainSeconds,
    preparation.tokenDrainSeconds,
    "Runsetta adoption token-drain window",
  );
  const receiptProof = exposureProofFromJson(receipt.exposureProof, "runsetta", "exposure");
  if (receiptProof === null || receiptProof.seedContract?.adoptionAudit === null) {
    throw new Error("Runsetta exposure adoption receipt lacks its terminal audit proof.");
  }
  const proxyInvocation: Invocation = {
    ...invocation,
    exposureAdoptionRunId: "",
    mode: "plan",
    terraformRoot: "exposure",
  };
  const currentProof = await proveExposure(
    proxyInvocation,
    executorToken,
    fetcher,
    liveReadToken,
  );
  if (currentProof === null) throw new Error("Runsetta exposure prerequisite proof is absent.");
  exact(
    canonicalJson(json(currentProof.state, "current Runsetta exposure state")),
    canonicalJson(json(receiptProof.state, "adopted Runsetta exposure state")),
    "Runsetta exposure state against adoption receipt",
  );
  exact(
    exposureLiveContinuityDigest(currentProof),
    exposureLiveContinuityDigest(receiptProof),
    "Runsetta live exposure continuity against adoption receipt",
  );
  const proof: ExposureProof = {
    ...receiptProof,
    adoptionReceipt: {
      adoptedAt,
      generation: object.generation,
      manifestSha256,
      metageneration: object.metageneration,
      runId: invocation.exposureAdoptionRunId,
      sha256: object.sha256,
      size: object.size,
    },
  };
  return exposureProofFromJson(proof, "runsetta", "prod")!;
}

export async function proveExposure(
  invocation: Invocation,
  executorToken: string,
  fetcher: Fetcher,
  liveReadToken: string = executorToken,
  adoptionAudit: ExposureAdoptionAudit | undefined = undefined,
  preparation: PreparationResult | undefined = undefined,
  retry?: GithubProofRetryPolicy,
): Promise<ExposureProof | null> {
  if (invocation.terraformRoot === "prod" && invocation.repository === "runsetta") {
    if (preparation === undefined) {
      throw new Error("Runsetta production exposure prerequisite lacks source preparation.");
    }
    return verifyRunsettaExposureAdoptionPrerequisite(
      invocation,
      executorToken,
      liveReadToken,
      preparation,
      fetcher,
      retry,
    );
  }
  if (invocation.terraformRoot !== "exposure") return null;
  const contract = REPOSITORIES[invocation.repository];
  const state = await readExposureStateProof(invocation, executorToken, fetcher);

  const listUrl = new URL(
    `https://${contract.exposure.region}-run.googleapis.com/apis/domains.cloudrun.com/v1/namespaces/${contract.projectId}/domainmappings`,
  );
  const listResponse = await fetcher(listUrl, {
    headers: executorHeaders(liveReadToken),
    redirect: "error",
  });
  if (!listResponse.ok) {
    throw new Error(`Exposure domain mapping list failed with HTTP ${listResponse.status}.`);
  }
  const list = record(await boundedJson(listResponse, 2 * 1024 * 1024), "exposure mapping list");
  exactKeys(
    list,
    new Set(["apiVersion", "items", "kind", "metadata", "unreachable"]),
    "exposure mapping list",
  );
  exact(list.apiVersion, "domains.cloudrun.com/v1", "exposure mapping list API version");
  exact(list.kind, "DomainMappingList", "exposure mapping list kind");
  const listMetadata = record(list.metadata, "exposure mapping list metadata");
  exactKeys(
    listMetadata,
    new Set(["continue", "resourceVersion", "selfLink"]),
    "exposure mapping list metadata",
  );
  exact(
    listMetadata.selfLink,
    `/apis/domains.cloudrun.com/v1/namespaces/${contract.exposure.projectNumber}/domainmappings`,
    "exposure mapping list self link",
  );
  if (listMetadata.continue !== undefined && listMetadata.continue !== "") {
    throw new Error("Exposure mapping list has an unreviewed continuation page.");
  }
  if (listMetadata.resourceVersion !== undefined) {
    const resourceVersion = requiredString(
      listMetadata.resourceVersion,
      "exposure mapping list resource version",
    );
    if (resourceVersion !== resourceVersion.trim() || resourceVersion.length > 512) {
      throw new Error("Exposure mapping list resource version escaped its opaque bound.");
    }
  }
  if (
    list.unreachable !== undefined &&
    array(list.unreachable, "exposure mapping list unreachable resources").length !== 0
  ) {
    throw new Error("Exposure mapping list contains unreachable resources.");
  }
  const listed = new Map<string, { readonly generation: string; readonly uid: string }>();
  for (const rawItem of array(list.items ?? [], "exposure mapping list items")) {
    const item = record(rawItem, "exposure mapping list item");
    const metadata = record(item.metadata, "exposure mapping list item metadata");
    const domain = requiredString(metadata.name, "exposure mapping list domain");
    exact(metadata.namespace, contract.exposure.projectNumber, "exposure mapping list namespace");
    if (listed.has(domain)) throw new Error("Exposure mapping list contains a duplicate domain.");
    listed.set(domain, {
      generation: String(
        boundedInteger(
          metadata.generation,
          "exposure mapping list generation",
          1,
          2_147_483_647,
        ),
      ),
      uid: requiredString(metadata.uid, "exposure mapping list UID"),
    });
  }
  const expectedListedDomains = [...contract.exposure.domains].toSorted();
  if (canonicalJson([...listed.keys()].toSorted()) !== canonicalJson(expectedListedDomains)) {
    throw new Error("Exposure mapping list contains missing or foreign domains.");
  }

  const mappings: ExposureMappingProof[] = [];
  for (const domain of contract.exposure.domains) {
    const url = new URL(
      `https://${contract.exposure.region}-run.googleapis.com/apis/domains.cloudrun.com/v1/namespaces/${contract.projectId}/domainmappings/${encodeURIComponent(domain)}`,
    );
    const response = await fetcher(url, {
      headers: executorHeaders(liveReadToken),
      redirect: "error",
    });
    if (!response.ok) {
      throw new Error(`Exposure domain mapping read failed with HTTP ${response.status}.`);
    }
    const mapping = record(await boundedJson(response, 512 * 1024), "exposure domain mapping");
    exact(mapping.apiVersion, "domains.cloudrun.com/v1", "exposure mapping API version");
    exact(mapping.kind, "DomainMapping", "exposure mapping kind");
    const metadata = record(mapping.metadata, "exposure mapping metadata");
    exact(metadata.name, domain, "exposure mapping metadata name");
    exact(metadata.namespace, contract.exposure.projectNumber, "exposure mapping namespace");
    exact(
      metadata.selfLink,
      `/apis/domains.cloudrun.com/v1/namespaces/${contract.exposure.projectNumber}/domainmappings/${domain}`,
      "exposure mapping self link",
    );
    const uid = requiredString(metadata.uid, "exposure mapping UID");
    exact(
      uid,
      RUNSETTA_DOMAIN_UIDS[domain as keyof typeof RUNSETTA_DOMAIN_UIDS],
      "Runsetta exposure mapping UID",
    );
    const generation = String(
      boundedInteger(metadata.generation, "exposure mapping generation", 1, 2_147_483_647),
    );
    exact(generation, "1", "Runsetta exposure mapping generation");
    exact(listed.get(domain)?.uid, uid, "exposure mapping list UID");
    exact(listed.get(domain)?.generation, generation, "exposure mapping list generation");
    const spec = record(mapping.spec, "exposure mapping spec");
    exact(spec.routeName, contract.exposure.serviceName, "exposure mapping route");
    exact(spec.certificateMode, "AUTOMATIC", "exposure mapping certificate mode");
    if (spec.forceOverride !== undefined && spec.forceOverride !== false) {
      throw new Error("Exposure mapping forceOverride is enabled or malformed.");
    }
    const status = record(mapping.status, "exposure mapping status");
    exact(status.mappedRouteName, contract.exposure.serviceName, "exposure mapped route");
    const observedGeneration = String(
      boundedInteger(
        status.observedGeneration,
        "exposure mapping observed generation",
        1,
        2_147_483_647,
      ),
    );
    exact(observedGeneration, generation, "exposure mapping observed generation");
    const conditions = new Map<string, string>();
    for (const rawCondition of array(status.conditions, "exposure mapping conditions")) {
      const condition = record(rawCondition, "exposure mapping condition");
      const type = requiredString(condition.type, "exposure mapping condition type");
      if (conditions.has(type)) {
        throw new Error("Exposure mapping contains a duplicate condition type.");
      }
      conditions.set(type, requiredString(condition.status, "exposure mapping condition status"));
    }
    const requiredConditionTypes = ["CertificateProvisioned", "DomainRoutable", "Ready"];
    if (
      canonicalJson([...conditions.keys()].toSorted()) !==
        canonicalJson(requiredConditionTypes.toSorted())
    ) {
      throw new Error("Exposure mapping condition types drifted from the exact ready set.");
    }
    for (const type of requiredConditionTypes) {
      exact(conditions.get(type), "True", `exposure mapping ${type} condition`);
    }
    const records = array(status.resourceRecords, "exposure mapping resource records").map(
      (rawRecord) => {
        const recordValue = record(rawRecord, "exposure mapping resource record");
        const type = requiredString(recordValue.type, "exposure mapping record type");
        if (!new Set(["A", "AAAA", "CNAME"]).has(type)) {
          throw new Error("Exposure mapping record escaped its DNS type allowlist.");
        }
        return {
          name: recordValue.name === undefined
            ? ""
            : requiredString(recordValue.name, "exposure mapping record name"),
          rrdata: requiredString(recordValue.rrdata, "exposure mapping record value"),
          type,
        };
      },
    ).toSorted((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
    if (records.length === 0) throw new Error("Exposure mapping has no DNS records.");
    const expectedRecords = RUNSETTA_DOMAIN_RECORDS[
      domain as keyof typeof RUNSETTA_DOMAIN_RECORDS
    ].map((record) => ({ ...record }))
      .toSorted((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
    exact(
      canonicalJson(records),
      canonicalJson(expectedRecords),
      "Runsetta exposure mapping DNS records",
    );
    const delegatedLabel = domain.startsWith("www.")
      ? "www"
      : domain.startsWith("mcp.")
      ? "mcp"
      : "";
    if (delegatedLabel === "") {
      if (
        records.some((item) => item.name !== "" || item.type === "CNAME") ||
        !records.some((item) => item.type === "A") ||
        !records.some((item) => item.type === "AAAA")
      ) {
        throw new Error("Apex exposure mapping DNS record shape drifted.");
      }
    } else if (
      records.length !== 1 ||
      records[0]!.name !== delegatedLabel ||
      records[0]!.type !== "CNAME"
    ) {
      throw new Error("Delegated exposure mapping DNS record shape drifted.");
    }
    mappings.push({
      domain,
      generation,
      id: exposureDomainId(contract, domain),
      observedGeneration,
      recordsSha256: hashJson(records),
      uid,
    });
  }

  const https: ExposureHttpsProof[] = [];
  if (invocation.repository === "runsetta") {
    for (const domain of ["runsetta.com", "www.runsetta.com"] as const) {
      const url = `https://${domain}/livez`;
      const response = await fetcher(url, {
        headers: { Accept: "application/json" },
        redirect: "error",
      });
      if (response.status !== 200) {
        throw new Error(`Runsetta HTTPS continuity check failed with HTTP ${response.status}.`);
      }
      if (!(response.headers.get("content-type") ?? "").toLowerCase().startsWith("application/json")) {
        throw new Error("Runsetta HTTPS continuity response is not JSON.");
      }
      const body = await boundedText(response, MAX_EXPOSURE_HEALTH_BYTES);
      let parsed: unknown;
      try {
        parsed = JSON.parse(body) as unknown;
      } catch {
        throw new Error("Runsetta HTTPS continuity response is malformed.");
      }
      const health = record(parsed, "Runsetta HTTPS continuity response");
      exactKeys(
        health,
        new Set(["environment", "ok", "openaiConfigured", "service", "spotifyConfigured"]),
        "Runsetta HTTPS continuity response",
      );
      exact(health.ok, true, "Runsetta HTTPS health");
      exact(health.service, "runsetta", "Runsetta HTTPS service");
      exact(health.environment, "production", "Runsetta HTTPS environment");
      if (
        typeof health.openaiConfigured !== "boolean" ||
        typeof health.spotifyConfigured !== "boolean"
      ) {
        throw new Error("Runsetta HTTPS configuration health is malformed.");
      }
      https.push({
        bodySha256: createHash("sha256").update(body).digest("hex"),
        domain,
        status: 200,
        url,
      });
    }
  }
  const mappingListProof = mappings
    .map(({ domain, generation, uid }) => ({ domain, generation, uid }))
    .toSorted((left, right) => left.domain.localeCompare(right.domain));
  const proof = {
    adoptionReceipt: null,
    https,
    mappingListCount: listed.size,
    mappingListSha256: hashJson(mappingListProof),
    mappings,
    seedContract: state.state === "absent"
      ? null
      : {
          adoptionAudit: adoptionAudit ?? null,
          byteLength: state.size!,
          confirmation: RUNSETTA_EXPOSURE_ADOPTION_CONFIRMATION,
          liveContinuitySha256: exposureLiveContinuityDigest({
            https,
            mappingListCount: listed.size,
            mappingListSha256: hashJson(mappingListProof),
            mappings,
          }),
          mode: "controller-create-only-refreshless-v1",
          provider: "registry.terraform.io/hashicorp/google@7.45.0",
          resourceSchemaVersion: 1,
          sha256: state.sha256!,
          stateFormatVersion: 4,
          terraformVersion: TERRAFORM_VERSION,
        },
    state,
  } satisfies ExposureProof;
  normalizeExposureProof(proof, {
    repository: invocation.repository,
    terraformRoot: invocation.terraformRoot,
  });
  return proof;
}

// A denial the convergence loop should wait out rather than abort on. 403 is a
// grant that has not propagated; 401 is the executor's own disable/re-enable
// cycle, whose re-enable immediately precedes every permission projection.
// Neither is distinguishable from a permanent failure by status alone, and the
// loop already bounds the wait.
function transientPermissionDenial(response: Response): boolean {
  return response.status === 401 || response.status === 403;
}

function permissionDenialProvesNoUsableCredential(response: Response): boolean {
  return response.status === 401 || response.status === 403;
}

function executorHeaders(token: string): Record<string, string> {
  return { Accept: "application/json", Authorization: `Bearer ${token}` };
}

interface PlanReceipt {
  readonly consumerSha: string;
  readonly consumerTreeSha: string;
  readonly createdAt: string;
  readonly dhiParityId: string;
  readonly expiresAt: string;
  readonly exposureProof: ExposureProof | null;
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
  readonly schemaVersion: 4;
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
  if (invocation.terraformRoot === "exposure") {
    const exposureProof = exposureProofForReceipt(proof.exposureProof, invocation);
    if (
      exposureProof === null ||
      exposureProof.state.state !== "present" ||
      exposureProof.state.serial !== 1 ||
      exposureProof.seedContract === null
    ) {
      throw new Error("Runsetta exposure adoption lacks its exact canonical state proof.");
    }
    const adoptionReceipt: JsonValue = {
      adoptedAt: new Date(nowMs).toISOString(),
      confirmation: RUNSETTA_EXPOSURE_ADOPTION_CONFIRMATION,
      consumerSha: invocation.consumerSha,
      consumerTreeSha: proof.consumerTreeSha,
      dhiParityId: proof.dhiParityId,
      exposureProof: json(exposureProof, "exposure adoption proof"),
      freezeProof: json(
        normalizedFreezeProof(proof.freezeProof, proof.tokenDrainSeconds),
        "exposure adoption freeze proof",
      ),
      manifestSha256: review.sha256,
      markerProof: json(
        markerProofForReceipt(proof.markerProof, invocation),
        "exposure adoption marker proof",
      ),
      mode: "adoption-complete",
      platformSha: invocation.platformSha,
      projectId: contract.projectId,
      repository: invocation.repository,
      repositoryId: contract.repositoryId,
      runId: invocation.githubRunId,
      schemaVersion: 1,
      terraformRoot: "exposure",
    };
    await writeImmutableObject(
      state.bucket,
      receiptObjectName(state, "adoptions", invocation.githubRunId),
      `${canonicalJson(adoptionReceipt)}\n`,
      executorToken,
      fetcher,
    );
    return;
  }
  const receipt: PlanReceipt = {
    consumerSha: invocation.consumerSha,
    consumerTreeSha: proof.consumerTreeSha,
    createdAt: new Date(nowMs).toISOString(),
    dhiParityId: proof.dhiParityId,
    expiresAt: new Date(nowMs + APPROVAL_FRESHNESS_MINUTES * 60_000).toISOString(),
    exposureProof: exposureProofForReceipt(proof.exposureProof, invocation),
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
    schemaVersion: 4,
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
  retry?: GithubProofRetryPolicy,
): Promise<ReviewManifestResult> {
  if (invocation.mode !== "apply") throw new Error("Only apply mode may verify a plan approval.");
  if (invocation.terraformRoot === "exposure") {
    throw new Error("Exposure adoption has no plan approval or apply phase.");
  }
  await verifyPlanRun(invocation, nowMs, fetcher, retry);
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
    canonicalJson(json(receipt.exposureProof, "approved receipt exposure proof")),
    canonicalJson(json(exposureProofForReceipt(proof.exposureProof, invocation), "current exposure proof")),
    "approved exposure state and continuity proof",
  );
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
  if (invocation.terraformRoot === "exposure") {
    throw new Error("Exposure adoption has no consumable plan receipt.");
  }
  const contract = REPOSITORIES[invocation.repository];
  const state = contract.state[invocation.terraformRoot];
  const consumed: JsonValue = {
    applyRunId: invocation.githubRunId,
    consumerSha: invocation.consumerSha,
    consumerTreeSha: proof.consumerTreeSha,
    consumedAt: new Date(nowMs).toISOString(),
    dhiParityId: proof.dhiParityId,
    exposureProof: json(
      exposureProofForReceipt(proof.exposureProof, invocation),
      "consumed receipt exposure proof",
    ),
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
    schemaVersion: 4,
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

// The only countable success a protected run produces. Every field it carries
// is a claim that was already true when it was written: mutation authority was
// gone, all four pools were handed back to the state the durable intent
// captured, and the restored world audited to zero diff.
export async function publishFinalProtectedReceipt(
  invocation: Invocation,
  ownerToken: string,
  review: ReviewManifestResult,
  proof: FinalProtectedProof,
  nowMs: number,
  fetcher: Fetcher,
): Promise<FinalReceiptReference> {
  if (invocation.mode === "plan") {
    throw new Error("Plan mode produces no final protected receipt.");
  }
  if (invocation.terraformRoot === "exposure") {
    throw new Error("Exposure adoption has no final protected receipt.");
  }
  // The kind must match the run. A rehearsal receipt claiming an apply, or an
  // apply receipt written by a rehearsal, would each be a lie about whether any
  // Terraform ran.
  exact(
    proof.kind,
    invocation.mode === "rehearsal" ? "rehearsal" : "apply",
    "final receipt kind",
  );
  exact(proof.reviewSha256, review.sha256, "final receipt manifest digest");
  exact(proof.repository, invocation.repository, "final receipt repository");
  exact(proof.root, invocation.terraformRoot, "final receipt root");
  exact(proof.runId, invocation.githubRunId, "final receipt run ID");
  exact(proof.platformSha, invocation.platformSha, "final receipt platform SHA");
  exact(proof.consumerSha, invocation.consumerSha, "final receipt consumer SHA");
  if (proof.observedPools.length !== REPOSITORY_NAMES.length) {
    throw new Error("Final receipt does not account for every consumer pool.");
  }
  const contract = REPOSITORIES[invocation.repository];
  const state = contract.state[invocation.terraformRoot];
  const receipt: JsonValue = json(
    {
      consumerSha: proof.consumerSha,
      // Never countable, whatever the run was.
      //
      // An apply's object is `pending`: it is written before the executor's
      // deletion has been proven, so at that moment it can only be a claim, and
      // the owner's completion object is what makes it a success.
      //
      // A rehearsal's object is `rehearsal-complete`: terminal, and never
      // eligible for completion at all. It runs no Terraform, so there is
      // nothing for a completion to attest.
      countable: false,
      status: invocation.mode === "rehearsal" ? "rehearsal-complete" : "pending",
      deElevation: {
        executorEmail: proof.deElevation.executorEmail,
        executorUniqueId: proof.deElevation.executorUniqueId,
        observedAt: proof.deElevation.observedAt,
        provenAbsent: [...proof.deElevation.provenAbsent],
      },
      intentDigest: proof.intentDigest,
      intentGeneration: proof.intentGeneration,
      kind: proof.kind,
      manifestSha256: proof.reviewSha256,
      observedPools: proof.observedPools.map((pool) => ({ ...pool })),
      platformSha: proof.platformSha,
      projectId: contract.projectId,
      publishedAt: new Date(nowMs).toISOString(),
      repository: proof.repository,
      repositoryId: contract.repositoryId,
      runId: proof.runId,
      schemaVersion: 1,
      terraformRoot: proof.root,
      ...(proof.kind === "apply"
        ? {
          quarantinedApplyProofDigest: proof.quarantinedApplyProofDigest,
          restoredAudit: { ...proof.restoredAudit },
        }
        : {}),
    },
    "final protected receipt",
  );
  const body = `${canonicalJson(receipt)}\n`;
  const object = receiptObjectName(
    state,
    invocation.mode === "rehearsal" ? "rehearsals" : "final",
    invocation.githubRunId,
  );
  // Reconciled like every other immutable write: a terminal rehearsal receipt
  // whose response was lost must not turn a finished rehearsal into a failure.
  await writeImmutableObjectIdempotent(state.bucket, object, body, ownerToken, fetcher);
  const written = await readObjectMetadata(state.bucket, object, ownerToken, fetcher);
  const generation = written.generation;
  return {
    bucket: state.bucket,
    deElevationExecutorEmail: proof.deElevation.executorEmail,
    deElevationExecutorUniqueId: proof.deElevation.executorUniqueId,
    digest: sha256Hex(body),
    generation,
    object,
    publishedAt: new Date(nowMs).toISOString(),
    size: Buffer.byteLength(body),
  };
}

// The owner's countersignature. A verifier that requires this is requiring, in
// one object: that the final receipt exists with exactly these bytes, and that
// the executor which wrote it no longer exists.
export async function publishOwnerCompletionProof(
  invocation: Invocation,
  ownerToken: string,
  pending: FinalReceiptReference,
  releaseProof: ExecutorReleaseProof,
  nowMs: number,
  fetcher: Fetcher,
): Promise<void> {
  if (!/^[0-9a-f]{64}$/.test(pending.digest)) {
    throw new Error("Owner completion proof requires a SHA-256 final receipt digest.");
  }
  if (!/^[1-9][0-9]*$/.test(pending.generation)) {
    throw new Error("Owner completion proof requires a positive final receipt generation.");
  }
  // The identity that surrendered privilege and the identity that was deleted
  // must be the same account. Otherwise the completion would be countersigning
  // one executor's de-elevation with a different executor's removal.
  exact(
    releaseProof.executorEmail,
    pending.deElevationExecutorEmail,
    "owner completion executor email",
  );
  exact(
    releaseProof.executorUniqueId,
    pending.deElevationExecutorUniqueId,
    "owner completion executor unique ID",
  );
  const publishedAtMs = Date.parse(pending.publishedAt);
  const releasedAtMs = Date.parse(releaseProof.observedAt);
  if (
    !Number.isFinite(publishedAtMs) || !Number.isFinite(releasedAtMs) ||
    new Date(publishedAtMs).toISOString() !== pending.publishedAt ||
    new Date(releasedAtMs).toISOString() !== releaseProof.observedAt ||
    releasedAtMs < publishedAtMs || nowMs < releasedAtMs
  ) {
    throw new Error("Owner completion proof requires canonical, ordered timestamps.");
  }
  // Only an apply can ever be counted. A rehearsal runs no Terraform and a plan
  // changes nothing, so neither may produce a completion object at all.
  if (invocation.mode !== "apply") {
    throw new Error("Only an apply produces an owner completion proof.");
  }
  const contract = REPOSITORIES[invocation.repository];
  const state = contract.state[invocation.terraformRoot];
  // The reference is a caller's claim until this reads the object it names.
  // Exact bucket, exact key, exact generation, exact size, exact bytes -- and
  // then the receipt inside them has to be a pending apply receipt belonging to
  // this very run. A completion that countersigned an unread reference would be
  // countersigning whatever the caller said, which is not a proof of anything.
  exact(pending.bucket, state.bucket, "owner completion final receipt bucket");
  exact(
    pending.object,
    receiptObjectName(state, "final", invocation.githubRunId),
    "owner completion final receipt key",
  );
  const observedMetadata = await readObjectMetadata(
    pending.bucket,
    pending.object,
    ownerToken,
    fetcher,
  );
  exact(observedMetadata.generation, pending.generation, "owner completion final receipt generation");
  if (observedMetadata.size !== pending.size) {
    throw new Error("The pending final receipt is not the size the completion names.");
  }
  const observedBody = await readObjectGeneration(
    pending.bucket,
    pending.object,
    pending.generation,
    ownerToken,
    fetcher,
  );
  if (Buffer.byteLength(observedBody) !== pending.size) {
    throw new Error("The pending final receipt did not match its recorded size.");
  }
  exact(sha256Hex(observedBody), pending.digest, "owner completion final receipt digest");
  const pendingReceipt = record(JSON.parse(observedBody) as unknown, "pending final receipt");
  exact(pendingReceipt.status, "pending", "pending final receipt status");
  exact(pendingReceipt.kind, "apply", "pending final receipt kind");
  exact(pendingReceipt.countable, false, "pending final receipt countability");
  exact(pendingReceipt.runId, invocation.githubRunId, "pending final receipt run ID");
  exact(pendingReceipt.repository, invocation.repository, "pending final receipt repository");
  exact(pendingReceipt.terraformRoot, invocation.terraformRoot, "pending final receipt root");
  exact(pendingReceipt.platformSha, invocation.platformSha, "pending final receipt platform SHA");
  exact(pendingReceipt.consumerSha, invocation.consumerSha, "pending final receipt consumer SHA");
  const deElevation = record(pendingReceipt.deElevation, "pending final receipt de-elevation");
  exact(
    deElevation.executorEmail,
    pending.deElevationExecutorEmail,
    "pending final receipt de-elevation email",
  );
  exact(
    deElevation.executorUniqueId,
    pending.deElevationExecutorUniqueId,
    "pending final receipt de-elevation unique ID",
  );
  const body = `${canonicalJson(json({
    completedAt: new Date(nowMs).toISOString(),
    countable: true,
    executorRelease: {
      artifactsDeleted: releaseProof.artifactsDeleted,
      executorEmail: releaseProof.executorEmail,
      executorUniqueId: releaseProof.executorUniqueId,
      observedAt: releaseProof.observedAt,
      permissionsProvenGone: releaseProof.permissionsProvenGone,
      projectBindingsCleared: releaseProof.projectBindingsCleared,
    },
    finalReceipt: {
      bucket: pending.bucket,
      digest: pending.digest,
      generation: pending.generation,
      object: pending.object,
      publishedAt: pending.publishedAt,
      size: pending.size,
    },
    kind: "apply",
    platformSha: invocation.platformSha,
    repository: invocation.repository,
    repositoryId: contract.repositoryId,
    runId: invocation.githubRunId,
    schemaVersion: 1,
    terraformRoot: invocation.terraformRoot,
  }, "owner completion proof"))}\n`;
  // Same reconciliation as the marker: a lost response after a committed write
  // must not turn a finished run into a failed one, and must not be mistaken
  // for one either.
  await writeImmutableObjectIdempotent(
    state.bucket,
    receiptObjectName(state, "completion", invocation.githubRunId),
    body,
    ownerToken,
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
      "exposureProof",
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
  exact(receipt.schemaVersion, 4, "plan receipt schema");
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
  const repository = repositoryName(requiredString(receipt.repository, "receipt repository"));
  if (receipt.legacyCompatibilityMode && transitionWorkflowSha !== "") {
    throw new Error("Plan receipt cannot combine legacy compatibility with a transition SHA.");
  }
  if (
    terraformRoot !== "bootstrap" &&
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
      MUTATOR_TOKEN_SECONDS,
    );
    if (value !== MUTATOR_TOKEN_SECONDS) {
      throw new Error("Receipt token-drain window escaped the reviewed value.");
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
    exposureProof: exposureProofFromJson(receipt.exposureProof, repository, terraformRoot),
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
        MUTATOR_TOKEN_SECONDS,
      );
      exact(value, MUTATOR_TOKEN_SECONDS, "receipt mutator-token lifetime");
      return value;
    })(),
    markerProof,
    planRunId: numeric(requiredString(receipt.planRunId, "receipt plan run ID"), "receipt plan run ID"),
    platformSha: sha(requiredString(receipt.platformSha, "receipt platform SHA"), "receipt platform SHA"),
    projectId: requiredString(receipt.projectId, "receipt project ID"),
    repository,
    repositoryId: numeric(requiredString(receipt.repositoryId, "receipt repository ID"), "receipt repository ID"),
    schemaVersion: 4,
    terraformRoot,
    tokenDrainSeconds,
    transitionWorkflowSha,
  };
}

async function verifyPlanRun(
  invocation: Invocation,
  nowMs: number,
  fetcher: Fetcher,
  retry?: GithubProofRetryPolicy,
): Promise<void> {
  const base = `https://api.github.com/repos/${PLATFORM_REPOSITORY}`;
  const run = record(
    await githubJson(
      `${base}/actions/runs/${invocation.approvedPlanRunId}`,
      invocation.platformActionsToken,
      fetcher,
      retry,
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
      retry,
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
): Promise<string> {
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
    throw new Error("The immutable protected receipt was already published or consumed.");
  }
  if (!response.ok) throw new Error(`Receipt upload failed with HTTP ${response.status}.`);
  // The write must identify itself completely, and the readback must be bound
  // to the generation it reports. A readback by name alone verifies whatever
  // happens to be at that key now, which is not the same statement.
  const created = assertStorageObjectMetadata(
    await boundedJson(response, 256 * 1024),
    bucket,
    object,
    Buffer.byteLength(body),
    "immutable object write",
  );
  const observed = await readObjectGeneration(bucket, object, created.generation, token, fetcher);
  if (observed !== body) throw new Error("Immutable receipt readback was not byte-equivalent.");
  return created.generation;
}

// Exact identity for one storage object: the bucket and key it claims, the size
// it claims, a well-formed generation, and a metageneration proving nothing has
// rewritten its metadata since creation.
function assertStorageObjectMetadata(
  value: unknown,
  bucket: string,
  object: string,
  expectedSize: number,
  label: string,
): { readonly generation: string; readonly metageneration: string } {
  const metadata = record(value, label);
  exact(requiredString(metadata.name, `${label} name`), object, `${label} name`);
  // Required, not optional: a response that declines to say which bucket it
  // wrote to cannot establish that it wrote to this one.
  exact(requiredString(metadata.bucket, `${label} bucket`), bucket, `${label} bucket`);
  const size = Number(requiredString(metadata.size, `${label} size`));
  if (!Number.isSafeInteger(size) || size !== expectedSize) {
    throw new Error(`${label} size did not match the bytes written.`);
  }
  const generation = requiredString(metadata.generation, `${label} generation`);
  if (!/^[1-9][0-9]*$/.test(generation)) throw new Error(`${label} generation is malformed.`);
  const metageneration = requiredString(metadata.metageneration, `${label} metageneration`);
  exact(metageneration, "1", `${label} metageneration`);
  return { generation, metageneration };
}

// Exact metadata for one object, without reading its bytes.
async function readObjectMetadata(
  bucket: string,
  object: string,
  token: string,
  fetcher: Fetcher,
): Promise<{ readonly generation: string; readonly metageneration: string; readonly size: number }> {
  // Exact key, exact bucket, a positive generation, an unrewritten
  // metageneration, and a size inside the reviewed bound. Anything looser and
  // the reconciliation below is validating an object nobody named.
  const url = new URL(
    `https://storage.googleapis.com/storage/v1/b/${bucket}/o/${encodeURIComponent(object)}`,
  );
  url.searchParams.set("fields", "name,bucket,size,generation,metageneration");
  const response = await fetcher(url, { headers: executorHeaders(token), redirect: "error" });
  if (!response.ok) {
    throw new Error(`Object metadata read failed with HTTP ${response.status}.`);
  }
  const metadata = record(await boundedJson(response, 256 * 1024), "object metadata");
  exact(requiredString(metadata.name, "object metadata name"), object, "object metadata name");
  exact(requiredString(metadata.bucket, "object metadata bucket"), bucket, "object metadata bucket");
  const generation = requiredString(metadata.generation, "object metadata generation");
  if (!/^[1-9][0-9]*$/.test(generation)) {
    throw new Error("Object metadata generation is malformed.");
  }
  const metageneration = requiredString(metadata.metageneration, "object metadata metageneration");
  exact(metageneration, "1", "object metadata metageneration");
  const size = Number(requiredString(metadata.size, "object metadata size"));
  if (!Number.isSafeInteger(size) || size < 1 || size > 32 * 1024) {
    throw new Error("Object metadata size escaped its bound.");
  }
  return { generation, metageneration, size };
}

// Reads exactly the bytes a listing named. Without the generation an object can
// be replaced between the listing and the read, and every check below would
// then be validating something other than what was discovered.
async function readObjectGeneration(
  bucket: string,
  object: string,
  generation: string,
  token: string,
  fetcher: Fetcher,
): Promise<string> {
  const url = new URL(
    `https://storage.googleapis.com/storage/v1/b/${bucket}/o/${encodeURIComponent(object)}`,
  );
  url.searchParams.set("alt", "media");
  url.searchParams.set("generation", generation);
  const response = await fetcher(url, { headers: executorHeaders(token), redirect: "error" });
  if (!response.ok) {
    throw new Error(`Generation-bound read failed with HTTP ${response.status}.`);
  }
  return await boundedText(response, 32 * 1024);
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
  kind:
    | "adoptions"
    | "completion"
    | "consumed"
    | "final"
    | "plans"
    | "rehearsals"
    | "results",
  runId: string,
): string {
  numeric(runId, "receipt run ID");
  return `${state.prefix}/.protected-bootstrap/${kind}/${runId}.json`;
}

// A bounded retry budget for ONE composite proof. Created per composite
// operation rather than per run, so an early proof cannot drain the budget the
// post-apply proof will need -- the worst possible allocation.
export interface GithubProofRetryPolicy {
  readonly deadlineMs: () => number;
  readonly now: () => number;
  readonly sleep: (milliseconds: number) => Promise<void>;
  readonly random: () => number;
  // Retry-attributable time spent on this composite operation: the elapsed
  // time of FAILED attempts plus the backoff granted after them. Counting only
  // sleep was not the budget it advertised -- four attempts each burning a 20s
  // request timeout could span well past a minute while the counter showed
  // room; elapsed request time is what competes with the phase envelope. But
  // counting all wall clock was worse: successful reads drained it, so a blip
  // on the first repository could refuse a blip on the fourth its first retry.
  // Only the time this layer ADDS belongs here. Concurrent reads share one
  // policy and accumulate into it, which double-counts overlapping spend --
  // conservative in the right direction: a sustained multi-read outage
  // exhausts fast, a simultaneous blip costs almost nothing.
  retryCostMs: number;
}

export function githubProofRetryPolicy(
  deadlineMs: () => number,
  sleep: (milliseconds: number) => Promise<void> = (ms) => Bun.sleep(ms),
  now: () => number = Date.now,
  random: () => number = Math.random,
): GithubProofRetryPolicy {
  return { deadlineMs, now, random, retryCostMs: 0, sleep };
}

// Retryable: transport failure, any 5xx, 429, and the 403 shapes GitHub uses
// for rate limiting -- both the SECONDARY limit (Retry-After, or "secondary
// rate limit"/"abuse" in the body) and the PRIMARY quota
// (x-ratelimit-remaining: 0, paired with x-ratelimit-reset). Everything else
// -- 401, a plain 403, 404 -- is terminal on the first occurrence.
//
// Deliberately NOT `transientPermissionDenial`, which treats 401/403 as
// retryable in the storage permission probe for reasons specific to IAM
// propagation and the executor's own disable/re-enable cycle. Generalising
// that here would retry a GitHub token that is simply wrong.
export function retryableGithubReadFailure(
  status: number,
  headers: { get(name: string): string | null },
  body: string,
): boolean {
  if (status >= 500) return true;
  if (status === 429) return true;
  if (status !== 403) return false;
  if (headers.get("retry-after") !== null) return true;
  if (headers.get("x-ratelimit-remaining") === "0") return true;
  return /secondary rate limit|abuse/i.test(body);
}

// The deadline fetcher's own abort message. A run that has reached the
// operation deadline is doomed; retrying cannot resurrect it.
const OPERATION_DEADLINE_MESSAGE = "API request reached the protected operation deadline.";

// Any cancellation is terminal, not just that sentinel. An AbortError or a
// DOMException reaching here means something above deliberately stopped this
// request, and retrying it would override that decision -- the opposite of
// what cancellation means.
// Transport error text is attacker-influenced -- a proxy or gateway can put
// arbitrary bytes in it -- and it goes straight into a log line and an Error
// message. A newline forges a second log record, an escape sequence rewrites
// the reading operator's terminal, and a bidi control reorders what they read.
// Truncation alone stops none of it.
//
// Escape by Unicode CATEGORY rather than by enumerated ranges. An explicit
// range list is a denylist and was already incomplete: it missed U+2028 and
// U+2029, which JavaScript itself treats as line terminators and which many
// log readers break records on, and U+061C, a bidi control outside the ranges
// it listed. Cc and Cf cover every control and format character, including all
// terminal escapes, zero-width characters and bidi overrides; Zl and Zp are
// the line and paragraph separators; Cs is a lone surrogate, which would
// corrupt any JSON encoding of this evidence downstream.
const EVIDENCE_FORGERY = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/u;

// The whole returned representation, marker included, is <= maximumLength.
// An earlier version bounded only the payload and then appended the marker, so
// a limit of 9 could return 11 characters -- a caller budgeting a log line got
// more than it asked for, which is the same class of defect as unbounded
// evidence, just smaller.
const EVIDENCE_TRUNCATION_MARKER = "...";

export function evidenceText(value: string, maximumLength: number): string {
  if (maximumLength <= 0) return "";
  const tokens: string[] = [];
  let length = 0;
  let truncated = false;
  for (const character of value) {
    const token = EVIDENCE_FORGERY.test(character)
      ? `\\u{${character.codePointAt(0)?.toString(16) ?? "fffd"}}`
      : character;
    // Only whole tokens are ever admitted, so no bound can leave half an
    // escape sequence behind.
    if (length + token.length > maximumLength) {
      truncated = true;
      break;
    }
    tokens.push(token);
    length += token.length;
  }
  if (!truncated) return tokens.join("");
  const budget = maximumLength - EVIDENCE_TRUNCATION_MARKER.length;
  // A limit too small to hold the marker still says something was cut, as far
  // as the limit allows, rather than exceeding it.
  if (budget <= 0) return EVIDENCE_TRUNCATION_MARKER.slice(0, maximumLength);
  // Make room by dropping WHOLE tokens from the end.
  while (length > budget) length -= tokens.pop()?.length ?? 0;
  return tokens.join("") + EVIDENCE_TRUNCATION_MARKER;
}

export function cancellationError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  if (error.message === OPERATION_DEADLINE_MESSAGE) return true;
  if (error.name === "AbortError" || error.name === "TimeoutError") return true;
  return typeof DOMException !== "undefined" && error instanceof DOMException;
}
// What the server asked for, and which header asked. GitHub paces two
// different ways: the SECONDARY limit sends Retry-After; the PRIMARY quota
// sends x-ratelimit-remaining: 0 with an epoch x-ratelimit-reset and usually
// no Retry-After. Reading only the first burned three doomed jittered retries
// against a quota that resets in minutes, then died as "attempt cap reached"
// -- evidence naming the wrong cause. Read both; honour or fail closed.
export function serverRequestedDelay(
  response: Response | undefined,
  now: number,
): { readonly ms: number; readonly source: string } | undefined {
  if (response === undefined) return undefined;
  const retryAfter = retryAfterMs(response, now);
  if (retryAfter !== undefined) {
    return { ms: retryAfter, source: `Retry-After of ${retryAfter}ms` };
  }
  if (response.headers.get("x-ratelimit-remaining")?.trim() !== "0") return undefined;
  const reset = response.headers.get("x-ratelimit-reset")?.trim() ?? "";
  if (!/^\d{1,10}$/.test(reset)) return undefined;
  const ms = Math.max(0, Number(reset) * 1_000 - now);
  return { ms, source: `x-ratelimit-reset in ${ms}ms` };
}

// The ceiling deadlineFetcher puts on any single request. The retry gates
// reserve it for the attempt that follows a backoff, so it must be the same
// number in both places.
export const PROTECTED_MAX_REQUEST_MS = 20_000;

const GITHUB_PROOF_RETRY_BUDGET_MS = 60_000;
const GITHUB_PROOF_RETRY_ATTEMPTS = 4;
const GITHUB_PROOF_RETRY_BASE_MS = 1_000;
// Headroom only: at a 4-attempt cap the largest exponent yields 4000ms, so
// this never binds today. It bounds the pacing if the attempt cap ever rises.
const GITHUB_PROOF_RETRY_CAP_MS = 8_000;
// Never sleep so long that the receipt publish that follows has no runway.
// Runway left for the work that follows a retry inside the same phase. The
// costliest tail is the post-consume freeze proof followed by the receipt
// publish, and that publish is two requests -- the upload and the
// byte-equivalence readback -- at up to 20s each. A 30s reserve could not
// cover it. Raising it only tightens retries near the deadline.
const GITHUB_PROOF_RETRY_TAIL_RESERVE_MS = 60_000;

// `Retry-After` is delta-seconds or an HTTP-date. Anything else is not a
// value we will act on, and we fall back to jittered backoff rather than
// guessing -- the budget and deadline checks still bound the result.
export function retryAfterMs(
  response: { headers: { get(name: string): string | null } } | undefined,
  now: number = Date.now(),
): number | undefined {
  const raw = response?.headers.get("retry-after");
  if (raw === null || raw === undefined) return undefined;
  const trimmed = raw.trim();
  // Any non-negative delta-seconds. A {1,5} bound sent a 6-digit value down
  // the HTTP-date path, where Date.parse yields NaN, so an enormous server
  // instruction silently became a 1-8s jitter -- the server's instruction
  // ignored, the same sin as truncating it. The affordability gate below is
  // what refuses values we cannot afford; the parser must not pre-empt it.
  if (/^\d+$/.test(trimmed)) return Number(trimmed) * 1_000;
  const when = Date.parse(trimmed);
  if (!Number.isFinite(when)) return undefined;
  return Math.max(0, when - now);
}

async function githubJson(
  url: string,
  token: string,
  fetcher: Fetcher,
  retry?: GithubProofRetryPolicy,
): Promise<unknown> {
  if (!url.startsWith("https://api.github.com/repos/collinbentley1/")) {
    throw new Error("GitHub API URL escaped the closed repository allowlist.");
  }
  const path = new URL(url).pathname;
  let attempts = 0;
  // The OUTCOME of the most recent attempt, not a status that survives it.
  // Tracking only an HTTP status left it stale whenever a later attempt failed
  // in transport, so a 502 followed by two socket errors exhausted while
  // reporting "HTTP 502" -- naming a cause that was two attempts old, in both
  // the final error and the retry breadcrumb.
  let lastOutcome = "no attempt completed";
  for (;;) {
    attempts += 1;
    const attemptStartedMs = retry === undefined ? 0 : retry.now();
    let response: Response | undefined;
    let transportError: unknown;
    try {
      response = await fetcher(url, {
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: `Bearer ${token}`,
          "X-GitHub-Api-Version": "2022-11-28",
        },
        redirect: "error",
      });
    } catch (error) {
      // Cancellation is terminal. A per-request timeout raised by the bridge's
      // own wrapper is retryable, but the deadline checks below still gate it.
      if (cancellationError(error)) throw error;
      transportError = error;
      lastOutcome = `transport failure (${
        error instanceof Error ? evidenceText(error.message, 80) : "unknown"
      })`;
    }
    if (response !== undefined && response.ok) return boundedJson(response, 4 * 1024 * 1024);

    let retryable = transportError !== undefined;
    if (response !== undefined) {
      lastOutcome = `HTTP ${response.status}`;
      let body = "";
      try {
        // deadlineFetcher has already buffered the body, so this reads from
        // memory; a failure to read it simply leaves the body out of the
        // classification rather than masking the status.
        body = (await response.clone().text()).slice(0, 64 * 1024);
      } catch {
        body = "";
      }
      retryable = retryableGithubReadFailure(response.status, response.headers, body);
    }

    const describe = (reason: string) =>
      new Error(
        `GitHub proof read failed after ${attempts} attempt(s): ` +
          `${lastOutcome} from ${path} (${reason}).`,
      );

    if (retry === undefined || !retryable) {
      if (response !== undefined && retry === undefined) {
        throw new Error(`GitHub freeze proof failed with HTTP ${response.status}.`);
      }
      if (transportError !== undefined && retry === undefined) throw transportError;
      throw describe("not retryable");
    }
    if (attempts >= GITHUB_PROOF_RETRY_ATTEMPTS) throw describe("attempt cap reached");

    // Charge the failed attempt. Only failed attempts and the backoff granted
    // after them are retry-attributable: successful reads happen with or
    // without this layer and are already bounded by the operation deadline.
    // An armed wall-clock window counted them, so a minute of clean reads
    // between two unrelated blips refused the second blip its first retry --
    // reintroducing the very failure this layer exists to prevent.
    retry.retryCostMs += retry.now() - attemptStartedMs;
    if (retry.retryCostMs >= GITHUB_PROOF_RETRY_BUDGET_MS) {
      throw describe(
        `retry budget exhausted; ${retry.retryCostMs}ms of ` +
          `${GITHUB_PROOF_RETRY_BUDGET_MS}ms spent on retries`,
      );
    }
    const budgetRemainingMs = GITHUB_PROOF_RETRY_BUDGET_MS - retry.retryCostMs;

    // Full jitter may legally produce zero. That is an immediate retry, not an
    // exhausted budget, and conflating them reported the wrong cause.
    const jittered = Math.floor(
      retry.random() *
        Math.min(GITHUB_PROOF_RETRY_BASE_MS * 2 ** (attempts - 1), GITHUB_PROOF_RETRY_CAP_MS),
    );
    const serverRequested = serverRequestedDelay(response, retry.now());
    const requested = serverRequested?.ms ?? jittered;
    // Name the source. An operator reading this after a burned plan must be
    // able to tell a server instruction from our own backoff, and which of
    // GitHub's two limits spoke.
    const source = serverRequested?.source ?? `backoff of ${requested}ms`;
    // A server instruction is honoured or the run fails; it is never truncated.
    // Retrying earlier than asked lands while still limited and discards the
    // one signal the server gave us.
    // Granting a retry costs the backoff AND the attempt that follows it,
    // which deadlineFetcher caps at PROTECTED_MAX_REQUEST_MS. Checking only the
    // backoff let a Retry-After exactly equal to the remaining budget pass,
    // sleep the budget to zero, and then start a request that ran 20s past it;
    // the same omission let a retry eat into the advertised tail reserve.
    // Reserving both makes the 60s bound exact rather than 60s plus an overrun.
    const grantCostMs = requested + PROTECTED_MAX_REQUEST_MS;
    if (grantCostMs > budgetRemainingMs) {
      throw describe(
        `${source} plus the retried request exceeds the remaining retry ` +
          `budget of ${budgetRemainingMs}ms`,
      );
    }
    if (retry.deadlineMs() - retry.now() < grantCostMs + GITHUB_PROOF_RETRY_TAIL_RESERVE_MS) {
      throw describe(`${source} plus the retried request exceeds the operation deadline ` +
        `less its tail reserve`);
    }
    console.log(
      `Protected bridge GitHub proof retry path=${path} outcome=${lastOutcome} ` +
        `attempt=${attempts} sleep_ms=${requested}`,
    );
    retry.retryCostMs += requested;
    if (requested > 0) await retry.sleep(requested);
  }
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

export async function requireFreshGoogleOwnerAccessToken(
  accessToken: string,
  minimumRemainingSeconds: number,
  fetcher: Fetcher,
  nowMs: number = Date.now(),
): Promise<void> {
  secretValue(accessToken, "owner OAuth access token");
  if (
    !Number.isSafeInteger(minimumRemainingSeconds) ||
    minimumRemainingSeconds < 1 ||
    minimumRemainingSeconds > GOOGLE_USER_ACCESS_TOKEN_MAX_SECONDS
  ) {
    throw new Error("Owner OAuth access-token lifetime requirement escaped its bound.");
  }
  if (!Number.isFinite(nowMs) || nowMs < 0) {
    throw new Error("Owner OAuth access-token validation time was invalid.");
  }

  // Google documents user access tokens as opaque and introspectable at this
  // endpoint. Its official Node auth library sends the token in a Bearer
  // header on a POST, avoiding a bearer-bearing URL that intermediaries can
  // retain. Fail before creating any temporary IAM artifact when the token
  // cannot cover the protected and recovery job envelopes.
  let response: Response;
  try {
    response = await fetcher(GOOGLE_OWNER_TOKENINFO_ENDPOINT, {
      method: "POST",
      redirect: "error",
      headers: {
        authorization: `Bearer ${accessToken}`,
        "content-type": "application/x-www-form-urlencoded;charset=UTF-8",
      },
    });
  } catch {
    throw new Error("Google owner OAuth access-token introspection failed.");
  }
  let raw: string;
  try {
    raw = await boundedText(response, 16 * 1024);
  } catch {
    throw new Error("Google owner OAuth access-token metadata exceeded its bound.");
  }
  if (!response.ok) {
    throw new Error("Google owner OAuth access token was rejected.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new Error("Google owner OAuth access-token metadata was malformed.");
  }
  const metadata = record(parsed, "Google owner OAuth access-token metadata");
  const exp = metadata.exp;
  const expiresIn = metadata.expires_in;
  const scope = metadata.scope;
  const subject = metadata.sub;
  if (
    typeof exp !== "string" || !/^[1-9][0-9]*$/.test(exp) ||
    typeof expiresIn !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(expiresIn) ||
    typeof scope !== "string" || typeof subject !== "string" ||
    !/^[1-9][0-9]*$/.test(subject)
  ) {
    throw new Error("Google owner OAuth access-token metadata was malformed.");
  }
  if (subject !== GOOGLE_OWNER_SUBJECT_ID) {
    throw new Error("Google owner OAuth access token does not authenticate the exact owner.");
  }
  const expiryEpochSeconds = Number(exp);
  const reportedRemainingSeconds = Number(expiresIn);
  const observedRemainingSeconds = expiryEpochSeconds - Math.floor(nowMs / 1_000);
  if (
    !Number.isSafeInteger(expiryEpochSeconds) ||
    !Number.isSafeInteger(reportedRemainingSeconds) ||
    reportedRemainingSeconds > GOOGLE_USER_ACCESS_TOKEN_MAX_SECONDS
  ) {
    throw new Error("Google owner OAuth access-token metadata was inconsistent.");
  }
  const scopes = scope.split(" ").filter((value) => value !== "");
  if (new Set(scopes).size !== scopes.length || !scopes.includes(GOOGLE_CLOUD_PLATFORM_SCOPE)) {
    throw new Error("Google owner OAuth access token lacks the cloud-platform scope.");
  }
  if (
    observedRemainingSeconds < minimumRemainingSeconds ||
    reportedRemainingSeconds < minimumRemainingSeconds
  ) {
    throw new Error(
      "Google owner OAuth access token is too close to expiry; replace the protected-environment secret immediately before dispatch.",
    );
  }
}

// Retry loops layered above a deadline-bounded fetcher need the same deadline,
// or their backoff sleeps run past it. Threading it through every caller would
// work until someone adds a caller and forgets; publishing it on the fetcher
// makes the bound structural, so a new call site inherits it by construction.
export const PROTECTED_FETCHER_DEADLINE = Symbol.for("protected.fetcherDeadlineMs");

export type DeadlineBoundFetcher = Fetcher & {
  readonly [PROTECTED_FETCHER_DEADLINE]?: () => number;
};

// Reads the deadline a fetcher was built with, if it has one. A bare fetcher
// (tests, or any path that never wrapped) simply has none, and callers fall
// back to their attempt cap.
export function fetcherDeadlineMs(fetcher: Fetcher): number | undefined {
  const accessor = (fetcher as DeadlineBoundFetcher)[PROTECTED_FETCHER_DEADLINE];
  return accessor === undefined ? undefined : accessor();
}

export function deadlineFetcher(
  fetcher: Fetcher,
  deadline: () => number,
  maximumRequestMs = PROTECTED_MAX_REQUEST_MS,
  now: () => number = Date.now,
): Fetcher {
  const bound: DeadlineBoundFetcher = Object.assign(async (
    input: Parameters<Fetcher>[0],
    init: Parameters<Fetcher>[1] = {},
  ) => {
    const remainingMs = Math.min(maximumRequestMs, deadline() - now());
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
  }, { [PROTECTED_FETCHER_DEADLINE]: deadline });
  return bound;
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

function stripProviderVolatile(type: string, value: JsonValue, label: string): JsonValue {
  const volatile = PROVIDER_VOLATILE_ATTRIBUTES.get(type);
  if (
    volatile === undefined || value === null || typeof value !== "object" ||
    Array.isArray(value)
  ) {
    return value;
  }
  return Object.fromEntries(
    Object.entries(value).filter(([key, entry]) => {
      if (!volatile.has(key)) return true;
      // Only a scalar may be excluded. If the provider ever gives one of these
      // names structured content, the exclusion could conceal reviewable data,
      // so refuse rather than strip it.
      if (entry !== null && typeof entry !== "string") {
        throw new Error(`${label} volatile attribute ${key} escaped its scalar shape.`);
      }
      return false;
    }),
  );
}

function normalizeChanges(value: unknown, identity: PlanIdentity, label: string): JsonValue[] {
  const root = identity.terraformRoot;
  const allowedTypes = root === "bootstrap"
    ? BOOTSTRAP_RESOURCE_TYPES
    : root === "prod"
    ? PROD_RESOURCE_TYPES
    : EXPOSURE_RESOURCE_TYPES;
  const modulePrefix = root === "bootstrap"
    ? "module.bootstrap."
    : root === "prod"
    ? "module.site."
    : "";
  const exposureAddresses = new Map<string, { readonly module: string; readonly type: string }>();
  if (root === "exposure") {
    for (const domain of REPOSITORIES[identity.repository].exposure.domains) {
      exposureAddresses.set(exposureDomainAddress(domain), {
        module: "module.domains",
        type: "google_cloud_run_domain_mapping",
      });
    }
    if (identity.repository === "critical-history") {
      const module = 'module.preview_domain["preview.ycriticalhistory.org"]';
      for (const [suffix, type] of CRITICAL_EXPOSURE_RESOURCES) {
        exposureAddresses.set(`${module}.${suffix}`, { module, type });
      }
    }
  }
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
      if (root === "exposure") {
        const expected = exposureAddresses.get(address);
        if (
          expected === undefined ||
          moduleAddress !== expected.module ||
          mode !== "managed" ||
          type !== expected.type ||
          !allowedTypes.has(type)
        ) {
          throw new Error(`Terraform ${label} ${address} escaped the exact exposure resource map.`);
        }
        if (label === "resource drift") {
          throw new Error("Exposure Terraform reported remote drift; state-only adoption is blocked.");
        }
      } else if (moduleAddress !== modulePrefix.slice(0, -1)) {
        throw new Error(`Terraform ${label} escaped the exact root module.`);
      } else if (mode === "data") {
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
      if (delta.generated_config !== undefined) {
        throw new Error("Terraform generated configuration is outside this bridge.");
      }
      rejectSensitiveAttributes(
        delta.before_sensitive,
        delta.before,
        type,
        address,
        `${label} before-sensitive map`,
      );
      rejectSensitiveAttributes(
        delta.after_sensitive,
        delta.after,
        type,
        address,
        `${label} after-sensitive map`,
      );
      // Planned changes only, and only the state the apply leaves behind.
      //
      // `before` describes what is being replaced, so a forbidden principal
      // there is what a corrective plan REMOVES -- an authoritative binding
      // drops it from members, or the grant is deleted outright. Drift is the
      // same situation one step earlier: an out-of-band grant appears in
      // `resource_drift.after` as refreshed live state while the corrective
      // empty member set appears in `resource_changes.after`. Gating either
      // would refuse the plan that fixes the problem and leave the grant in
      // place until someone cleaned it up by hand.
      if (label === "resource change") {
        rejectUnknownIamMember(
          type,
          json(delta.after_unknown ?? false, `${label} after unknown`),
          address,
          `${label} after-unknown map`,
        );
        rejectPreviewRuntimeGrant(
          type,
          json(delta.after ?? null, `${label} after`),
          address,
          `${label} after state`,
        );
      }
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
      let importId: string | null = null;
      if (delta.importing !== undefined && delta.importing !== null) {
        if (
          root !== "exposure" ||
          identity.repository !== "runsetta" ||
          label !== "resource change" ||
          type !== "google_cloud_run_domain_mapping"
        ) {
          throw new Error("Terraform import escaped the exact Runsetta exposure migration.");
        }
        const importing = record(delta.importing, "Runsetta exposure import");
        exactKeys(importing, new Set(["id", "identity", "unknown"]), "Runsetta exposure import");
        importId = requiredString(importing.id, "Runsetta exposure import ID");
        exact(importId, RUNSETTA_EXPOSURE_IMPORTS.get(address), "Runsetta exposure import ID");
        if (
          importing.unknown !== undefined && importing.unknown !== false ||
          importing.identity !== undefined && importing.identity !== null ||
          actions.join(",") !== "no-op" ||
          delta.before === null ||
          canonicalJson(json(delta.before, "Runsetta exposure import before value")) !==
            canonicalJson(json(delta.after, "Runsetta exposure import after value"))
        ) {
          throw new Error("Runsetta exposure import is not a state-only no-op adoption.");
        }
      }
      if (root === "exposure" && actions.join(",") !== "no-op") {
        throw new Error("Exposure plans may not create, update, replace, forget, or destroy remote resources.");
      }
      if (root === "exposure" && type === "google_cloud_run_domain_mapping") {
        if (
          delta.before === null ||
          canonicalJson(json(delta.before, "exposure before value")) !==
            canonicalJson(json(delta.after, "exposure after value")) ||
          delta.importing !== undefined && delta.importing !== null ||
          delta.before_identity !== undefined && delta.before_identity !== null ||
          delta.after_identity !== undefined && delta.after_identity !== null
        ) {
          throw new Error("Exposure adoption must be an existing byte-equivalent no-op without import identity.");
        }
        rejectSensitive(delta.after_unknown ?? false, "exposure unknown value map");
        const domainMatch = /\["([a-z0-9.-]+)"\]$/.exec(address);
        if (domainMatch === null) throw new Error("Exposure domain address is malformed.");
        validateExposureDomainAfter(
          record(delta.after, "exposure domain mapping after value"),
          record(delta.after_unknown ?? {}, "exposure domain mapping unknown map"),
          array(delta.replace_paths ?? [], "exposure domain mapping replace paths"),
          REPOSITORIES[identity.repository],
          domainMatch[1]!,
        );
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
      if (
        previousAddress !== null &&
        (root === "exposure"
          ? !exposureAddresses.has(previousAddress)
          : !previousAddress.startsWith(modulePrefix))
      ) {
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
        afterSha256: hashJson(
          stripProviderVolatile(type, json(delta.after ?? null, `${label} after`), `${label} after`),
        ),
        afterUnknownSha256: hashJson(json(delta.after_unknown ?? false, `${label} after unknown`)),
        beforeIdentitySha256: hashJson(json(delta.before_identity ?? null, `${label} before identity`)),
        beforeSha256: hashJson(
          stripProviderVolatile(type, json(delta.before ?? null, `${label} before`), `${label} before`),
        ),
        deposedSha256: hashJson(json(change.deposed ?? null, `${label} deposed key`)),
        indexSha256: hashJson(json(change.index ?? null, `${label} index`)),
        importId,
        mode,
        moduleAddress,
        name: requiredString(change.name, `${label} name`),
        previousAddress,
        provider: "registry.terraform.io/hashicorp/google",
        replacePathsSha256: hashJson(json(delta.replace_paths ?? [], `${label} replace paths`)),
        type,
      } satisfies JsonValue;
    })
    .filter((change) =>
      root === "exposure" ||
      canonicalJson(change.actions) !== '["no-op"]' || change.importId !== null
    )
    .toSorted((left, right) => String(left.address).localeCompare(String(right.address)));
  if (label === "resource change" && root === "bootstrap" && targetMarker.state === "absent" && !markerObjectSeen) {
    throw new Error("Initial bootstrap did not create the exact deployment-parity marker object.");
  }
  if (label === "resource change" && root === "exposure") {
    const expectedAddresses = [...RUNSETTA_EXPOSURE_IMPORTS.keys()].toSorted();
    const observedAddresses = result.map((change) => String(change.address)).toSorted();
    if (canonicalJson(observedAddresses) !== canonicalJson(expectedAddresses)) {
      throw new Error("Exposure validation did not contain exactly both Runsetta domain mappings.");
    }
    const imports = result.filter((change) => change.importId !== null);
    const presentAddresses = new Set(
      identity.exposureProof?.state.mappings.map(({ address }) => address) ?? [],
    );
    const expectedImportAddresses = identity.repository === "runsetta"
      ? [...RUNSETTA_EXPOSURE_IMPORTS.keys()].filter((address) => !presentAddresses.has(address))
        .toSorted()
      : [];
    const importAddresses = imports.map((change) => String(change.address)).toSorted();
    if (canonicalJson(importAddresses) !== canonicalJson(expectedImportAddresses)) {
      throw new Error("Exposure plan imports do not match the generation-bound state ownership proof.");
    }
    if (
      imports.some((change) =>
        RUNSETTA_EXPOSURE_IMPORTS.get(String(change.address)) !== change.importId
      )
    ) {
      throw new Error("Exposure plan contains an unreviewed import address or ID.");
    }
  }
  return result;
}

function validateExposureDomainAfter(
  after: Record<string, unknown>,
  unknown: Record<string, unknown>,
  replacePaths: readonly unknown[],
  contract: RepositoryContract,
  domain: string,
): void {
  exact(after.project, contract.projectId, "exposure domain project");
  exact(after.location, contract.exposure.region, "exposure domain location");
  exact(after.name, domain, "exposure domain name");
  exact(after.id, exposureDomainId(contract, domain), "exposure domain ID");
  exact(after.deletion_policy, "DELETE", "exposure domain provider deletion policy");
  const metadata = array(after.metadata, "exposure domain metadata");
  if (metadata.length !== 1) throw new Error("Exposure domain metadata is not singular.");
  exact(
    record(metadata[0], "exposure domain metadata").namespace,
    contract.projectId,
    "exposure domain Terraform namespace",
  );
  const spec = array(after.spec, "exposure domain spec");
  if (spec.length !== 1) throw new Error("Exposure domain spec is not singular.");
  const specValue = record(spec[0], "exposure domain spec");
  exact(specValue.route_name, contract.exposure.serviceName, "exposure domain route");
  exact(specValue.certificate_mode, "AUTOMATIC", "exposure domain certificate mode");
  if (specValue.force_override !== undefined) {
    exact(specValue.force_override, false, "exposure domain force override");
  }
  if (Array.isArray(unknown.spec)) {
    const unknownSpec = array(unknown.spec, "exposure domain unknown spec");
    if (unknownSpec.length !== 1) {
      throw new Error("Exposure domain unknown spec is not singular.");
    }
    const unknownSpecValue = record(unknownSpec[0], "exposure domain unknown spec");
    if (unknownSpecValue.force_override === true) {
      throw new Error("Exposure domain force_override is unknown in the reviewed plan.");
    }
  }
  for (const key of ["deletion_policy", "id", "location", "metadata", "name", "project", "spec"]) {
    if (unknown[key] === true) {
      throw new Error(`Exposure domain ${key} is unknown in the reviewed plan.`);
    }
  }
  if (replacePaths.length !== 0) throw new Error("Exposure domain mapping may not be replaced.");
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

// Terraform derives `before_sensitive` / `after_sensitive` from the provider
// schema alone, so an attribute is flagged for its declared type rather than for
// the bytes this plan actually carries. `google_storage_bucket_object.content`
// is flagged unconditionally, which means the deployment-parity transition
// marker -- whose bytes are a constant written in the clear in
// terraform/modules/bootstrap/main.tf -- trips the same wire a real credential
// would, and no bootstrap plan can ever be reviewed.
//
// Exempt exactly one attribute of exactly one resource type, and only when the
// planned bytes equal the constant declared here. A sensitive marker on any
// other attribute, on any other type, or on these bytes changed to anything the
// platform did not declare, still aborts the run. The exemption deliberately
// carries the expected value instead of merely naming the attribute: it can
// only ever admit a value this file already discloses, so it cannot be widened
// into "trust the provider's judgement" by a later edit.
//
// Scoping to one attribute rather than one type is load-bearing. Other marks
// in this tree would carry real credentials if they ever materialized --
// `google_certificate_manager_certificate.self_managed.pem_private_key`, and
// `google_compute_backend_service.iap.oauth2_client_secret`, which enabling IAP
// out of band would pull into a refreshed `before`. Those must keep aborting.
// `customer_encryption.encryption_key` sits on the exempt type itself and is
// still refused, because only `content` is named here.
const SENSITIVE_MARKER_EXEMPTIONS: ReadonlyMap<string, ReadonlyMap<string, string>> = new Map([
  ["google_storage_bucket_object", new Map([["content", '{"version":1}\n']])],
]);

// Reject sensitive markers attribute by attribute, so an exemption can be bound
// to one attribute name rather than to a whole resource. Anything that is not a
// plain top-level map -- `true`, `false`, an array, a nested structure -- falls
// through to the unconditional walk.
function rejectSensitiveAttributes(
  sensitive: unknown,
  planned: unknown,
  resourceType: string,
  address: string,
  label: string,
): void {
  const exemptions = SENSITIVE_MARKER_EXEMPTIONS.get(resourceType);
  if (
    exemptions === undefined ||
    sensitive === null ||
    typeof sensitive !== "object" ||
    Array.isArray(sensitive)
  ) {
    rejectSensitive(sensitive, label);
    return;
  }
  const plannedAttributes =
    planned !== null && typeof planned === "object" && !Array.isArray(planned)
      ? (planned as Record<string, unknown>)
      : {};
  for (const [attribute, marker] of Object.entries(sensitive as Record<string, unknown>)) {
    const declared = exemptions.get(attribute);
    if (declared !== undefined && marker === true) {
      // A sensitive attribute whose value is unknown at plan time is absent from
      // `planned`, so this comparison fails closed rather than admitting it.
      if (plannedAttributes[attribute] !== declared) {
        throw new Error(
          `${address} marks ${attribute} sensitive with a value the platform does not declare.`,
        );
      }
      continue;
    }
    rejectSensitive(marker, label);
  }
}

function rejectSensitive(value: unknown, label: string): void {
  if (value === true) throw new Error(`${label} contains a sensitive value.`);
  if (Array.isArray(value)) {
    for (const entry of value) rejectSensitive(entry, label);
  } else if (value !== null && typeof value === "object") {
    for (const entry of Object.values(value)) rejectSensitive(entry, label);
  }
}

// Whether the approved plan receipt was spent. A refused apply stops before
// consumeApproval, so its receipt is still valid and still authorizes a retry;
// saying otherwise would send an operator to replace a plan they still hold.
type PlanReceiptDisposition =
  | { readonly kind: "publishing" }
  | { readonly kind: "consumed"; readonly planRunId: string }
  | { readonly kind: "refused"; readonly planRunId: string };

function reviewSummary(
  invocation: Invocation,
  review: ReviewManifestResult,
  disposition: PlanReceiptDisposition,
): string {
  const exposureAdoption = invocation.terraformRoot === "exposure";
  const heading = exposureAdoption
    ? "Runsetta exposure state adoption complete"
    : invocation.mode === "plan"
    ? "Protected Terraform plan"
    : disposition.kind === "refused"
    ? "Protected Terraform apply refused"
    : "Protected Terraform apply";
  const summary = [
    `## ${heading}`,
    "",
    `- Target: \`${invocation.repository}\` / \`${invocation.terraformRoot}\``,
    `- Consumer commit: \`${invocation.consumerSha}\``,
    `- Platform commit: \`${invocation.platformSha}\``,
    `- Review digest: \`${review.sha256}\``,
    ...(exposureAdoption
      ? [
          `- Adoption run: \`${invocation.githubRunId}\` (immutable completion receipt; no Terraform apply exists)`,
          `- Confirmation: \`${RUNSETTA_EXPOSURE_ADOPTION_CONFIRMATION}\``,
        ]
      : disposition.kind === "publishing"
      ? [`- Plan run: \`${invocation.githubRunId}\` (fresh receipt required for apply)`]
      : disposition.kind === "refused"
      ? [
          `- Approved plan run: \`${disposition.planRunId}\` (NOT consumed; still valid for a retry)`,
          `- Approved digest: \`${invocation.approvedManifestSha256}\``,
        ]
      : [`- Consumed plan run: \`${disposition.planRunId}\` (single use)`]),
    "",
    ...(exposureAdoption
      ? [
          "The trusted controller create-only adopted the exact live Runsetta mappings into canonical state before Terraform ran. Terraform then validated that state with `-refresh=false` and an exact zero-action plan; it did not apply or contact the Domain Mapping API.",
          "",
        ]
      : []),
    ...(disposition.kind === "refused"
      ? [
          "This apply recomputed its own plan and the result did not match the approved receipt, so it stopped before consuming the approval and before elevating any executor. Nothing was applied and the approved plan was not spent. The manifest below is what this run recomputed; compare it with the approved plan run's manifest to see what diverged.",
          "",
        ]
      : []),
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

function assertPreElevationTime(
  nowMs: number,
  operationDeadlineMs: number,
  leaseExpiresAtMs: number,
  tokenExpiresAtMs: number,
): void {
  const requiredUntil = nowMs +
    (MINIMUM_PRE_APPLY_MINUTES + PRE_ELEVATION_CONVERGENCE_MINUTES) * 60_000;
  if (
    requiredUntil >= operationDeadlineMs ||
    requiredUntil >= leaseExpiresAtMs ||
    requiredUntil >= tokenExpiresAtMs
  ) {
    throw new Error(
      "Too little operation, IAM-lease, or executor-token lifetime remains to converge elevation and apply.",
    );
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
  if (value !== "bootstrap" && value !== "prod" && value !== "exposure") {
    throw new Error("Terraform root escaped the closed allowlist.");
  }
  return value;
}

function executionMode(value: string): ExecutionMode {
  if (value !== "plan" && value !== "apply" && value !== "rehearsal") {
    throw new Error("Execution mode escaped the closed allowlist.");
  }
  return value;
}

// Only a run that is about to start is gated. Parsing the mode recorded in an
// already-published receipt must keep working, or stage one would be unable to
// read the history stage two depends on.
function assertModeIsPermitted(mode: ExecutionMode, productionApplyEnabled: boolean): void {
  if (mode === "apply" && !productionApplyEnabled) {
    // Fail closed by construction, not by configuration.
    throw new Error(
      "Production protected apply is disabled in this build: the federation-quarantine rollout enables it only after the rehearsal canary and recovery drills succeed.",
    );
  }
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
