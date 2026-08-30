import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { connect as connectHttp2, createServer as createHttp2Server } from "node:http2";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  addExactLease,
  addExactBindings,
  addBindingsWithCas,
  addLeaseWithCas,
  buildExecutorProjectLeases,
  buildExposureControllerCreateLease,
  buildMarkerMutationLease,
  buildMarkerReadLease,
  buildReceiptLeases,
  githubProofRetryPolicy,
  retryableGithubReadFailure,
  retryAfterMs,
  cancellationError,
  evidenceText,
  buildLegacyCombinedReceiptCreateLease,
  receiptConsumeLeaseTitle,
  elevationPolicyRecord,
  addExactBindings,
  buildReviewManifest,
  buildRuntimeActAsLeases,
  buildStorageLease,
  buildStorageAcquisitionLeases,
  buildStorageReadLease,
  buildTokenCreatorLease,
  canonicalJson,
  canonicalRunsettaExposureState,
  commandFailureMessage,
  consumePlanReceipt,
  createEphemeralExecutor,
  deadlineFetcher,
  decodeStorageTestIamPermissionsResponse,
  deterministicArtifactHex,
  encodeStorageTestIamPermissionsRequest,
  ExecutorLeaseManager,
  knownExecutorBindingsRemain,
  ensureExposureStateInitialized,
  exposureControllerCreateLeaseOrUndefined,
  bridgeRolePermissionsRecognized,
  REPOSITORY_NAMES,
  executorControlPermissions,
  executorCustomRolePermissions,
  executorDescription,
  fencePolicyMutations,
  formatBridgeBreadcrumb,
  formatRecoveryScanBreadcrumb,
  inventoryBridgeArtifacts,
  main,
  parseRecoverySecretBundle,
  parseExecutorProvenance,
  publishPlanReceipt,
  publishPostApplyReceipt,
  proveConsumerFreeze,
  proveDeploymentParityMarkers,
  proveExposure,
  probeStorageObjectOverwritePermission,
  probeStorageObjectPermissions,
  requireNoUserManagedKeys,
  requireNoExecutorProjectBindings,
  randomExecutorAccountId,
  randomExecutorRoleId,
  readConsumerWorkflowPin,
  REPOSITORIES,
  removeExactLease,
  removeExactBindings,
  removeDeterministicExecutorMembers,
  removeLeaseWithCas,
  recoveryMain,
  recoverBridgeArtifactsUntilStable,
  releaseSandboxAndExecutor,
  requiredOwnerTokenRemainingSeconds,
  requireFreshGoogleOwnerAccessToken,
  requireExposureControllerCreateLeaseCandidate,
  requireLeaseAbsentWithReadback,
  requireSameDhiTransitionCapability,
  requireStorageBackendRoleContracts,
  runProtectedBootstrap,
  runProtectedRecovery,
  storageV2TestIamPermissions,
  terraformFailureEnvelope,
  terraformSandboxCreateArguments,
  TerraformSandboxExecutor,
  validateInvocation,
  validateRecoveryInvocation,
  validateStorageBackendRolePermissionInventory,
  verifyTerraformProviderMirrorLayout,
  verifyLocalSource,
  verifyPlatformCapability,
  verifyPlanApproval,
  waitForControlPermissions,
  waitForStatePermissions,
  type BridgeDependencies,
  type ExecutorSession,
  type ExecutionProof,
  type ExposureProof,
  type IamBinding,
  type IamPolicy,
  type Invocation,
  type JsonValue,
  type MarkerStateProof,
  type PlanIdentity,
  type PreparationResult,
  type RecoveryDependencies,
  type RecoveryInvocation,
  type RecoveryScanTelemetry,
  type StateStoragePermissionProbes,
  type TerraformSandboxDriver,
  type TerraformSandboxSpec,
} from "../tools/ci/protected-bootstrap-bridge.ts";

const root = join(import.meta.dir, "..");
const platformSha = "a".repeat(40);
const consumerSha = "b".repeat(40);
const consumerTreeSha = "c".repeat(40);
const executorEmail = "gha-pbt-0123456789abcdefabcd@cdbentley.iam.gserviceaccount.com";
const capabilityFiles = [
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

describe("protected owner Terraform bridge", () => {
  test("workflow is one protected, dispatch-only, main-only owner route", async () => {
    const workflow = await readFile(
      join(root, ".github/workflows/protected-bootstrap-implementation.yml"),
      "utf8",
    );
    expect(workflow).toContain("workflow_dispatch:");
    expect(workflow).not.toContain("workflow_call:");
    expect(workflow).not.toContain("pull_request");
    expect(workflow).not.toContain("schedule:");
    expect(workflow).not.toContain("push:");
    expect(workflow).toContain('test "$GITHUB_REF_EXACT" = "refs/heads/main"');
    expect(workflow).toContain('test "$GITHUB_ACTOR_ID_EXACT" = "16823277"');
    expect(workflow).toContain('test "$GITHUB_REPOSITORY_ID_EXACT" = "1255856466"');
    expect(workflow).toContain("environment: protected-bootstrap-owner-token");
    expect(workflow).toContain("group: protected-owner-terraform-${{ inputs.target_repository }}");
    expect(workflow).toContain("cancel-in-progress: false");
    expect(workflow.match(/^  owner-terraform:$/gm)).toHaveLength(1);
    expect(workflow).toContain("actions: read");
    expect(workflow).toContain("APPROVED_PLAN_RUN_ID: ${{ inputs.approved_plan_run_id }}");
    expect(workflow).toContain(
      "LEGACY_COMPATIBILITY_MODE: ${{ inputs.legacy_compatibility_mode }}",
    );
    expect(workflow).toContain("TRANSITION_WORKFLOW_SHA: ${{ inputs.transition_workflow_sha }}");
    expect(workflow).toContain('if [ "$TERRAFORM_ROOT" = "exposure" ]; then');
    expect(workflow).toContain('test "$TARGET_REPOSITORY" = "runsetta"');
    expect(workflow).toContain('test "$EXECUTION_MODE" = "plan"');
    expect(workflow).toContain(
      'test "$EXPOSURE_ADOPTION_CONFIRMATION" = "ADOPT_RUNSETTA_EXPOSURE_STATE"',
    );
    expect(workflow).toContain(
      "EXPOSURE_ADOPTION_CONFIRMATION: ${{ inputs.exposure_adoption_confirmation }}",
    );
    expect(workflow).toContain(
      "EXPOSURE_ADOPTION_RUN_ID: ${{ inputs.exposure_adoption_run_id }}",
    );
    expect(workflow).toContain(
      'if [ "$TARGET_REPOSITORY" = "runsetta" ] && [ "$TERRAFORM_ROOT" = "prod" ]; then',
    );
    expect(workflow).toContain("PLATFORM_ACTIONS_READ_TOKEN: ${{ github.token }}");
    expect(workflow).toContain("/usr/bin/env -i");
    expect(workflow.match(/OWNER_OAUTH_ACCESS_TOKEN: \$\{\{ secrets\.OWNER_OAUTH_ACCESS_TOKEN \}\}/g)).toHaveLength(
      3,
    );
    expect(workflow).toContain("owner-terraform:\n    name:");
    expect(workflow).toContain("    if: ${{ always() }}\n    runs-on: ubuntu-24.04");
    expect(workflow.match(/if: \$\{\{ success\(\) && !cancelled\(\) \}\}/g)).toHaveLength(7);
    expect(workflow).toContain(
      "id: protected-bridge\n        if: ${{ success() && !cancelled() }}",
    );
    expect(
      workflow.match(
        /if: \$\{\{ always\(\) && \(steps\.protected-bridge\.outcome == 'failure' \|\| steps\.protected-bridge\.outcome == 'cancelled'\) \}\}/g,
      ),
    ).toHaveLength(2);
    expect(workflow).toContain(
      "id: recovery-route\n        if: ${{ always() }}",
    );
    expect(workflow).toContain(
      "id: recovery-source\n        if: ${{ always() && steps.recovery-route.outcome == 'success' }}",
    );
    expect(workflow).toContain(
      "id: recovery-bun\n        if: ${{ always() && steps.recovery-source.outcome == 'success' }}",
    );
    expect(workflow).toContain(
      "if: ${{ always() && steps.recovery-bun.outcome == 'success' }}",
    );
    expect(workflow).toContain("bridge_reserve_seconds=$((16 * 60))");
    expect(workflow).toContain("bridge_maximum_seconds=$((25 * 60))");
    expect(workflow).toContain("bridge_reserve_seconds=$((2 * 60))");
    // The apply floor is the ceiling less the reviewed setup tolerance; a
    // 34-minute floor admitted runs 239 seconds short of the pre-elevation
    // envelope, which only failed twelve minutes into the run.
    expect(workflow).toContain("bridge_minimum_seconds=$((39 * 60 - 20))");
    expect(workflow).not.toContain("bridge_minimum_seconds=$((34 * 60))");
    expect(workflow).toContain("bridge_maximum_seconds=$((39 * 60))");
    expect(workflow).toContain(
      "bridge_budget_seconds=$((41 * 60 - elapsed_seconds - bridge_reserve_seconds))",
    );
    expect(workflow).toContain(
      'test "$bridge_budget_seconds" -ge "$bridge_minimum_seconds"',
    );
    expect(workflow).toContain(
      'test "$bridge_budget_seconds" -le "$bridge_maximum_seconds"',
    );
    expect(workflow.match(/timeout-minutes: 14/g)).toHaveLength(2);
    const recoveryBlocks = [
      workflow.slice(
        workflow.indexOf("- name: Recover exact IAM artifacts after bridge failure"),
        workflow.indexOf("  owner-terraform-recovery:"),
      ),
      workflow.slice(
        workflow.indexOf("- name: Recover exact IAM artifacts on a fresh runner"),
      ),
    ];
    for (const recoveryBlock of recoveryBlocks) {
      expect(recoveryBlock).toContain("timeout-minutes: 14");
      expect(recoveryBlock).toContain(
        "exec /usr/bin/timeout --signal=TERM --kill-after=15s 795s \\\n" +
          "            /usr/bin/env -i \\",
      );
      expect(recoveryBlock).not.toContain("} | \\\n          exec /usr/bin/env -i");
      expect(recoveryBlock).toContain("--no-env-file --no-orphans");
    }
    const recoveryInternalDeadlineSeconds = (1 + 7 + 3 + 1 + 1) * 60;
    const recoveryWrapperSeconds = 795;
    const recoveryKillAfterSeconds = 15;
    const recoveryActionsStepSeconds = 14 * 60;
    expect(recoveryWrapperSeconds).toBeGreaterThan(recoveryInternalDeadlineSeconds);
    expect(recoveryWrapperSeconds + recoveryKillAfterSeconds).toBeLessThan(
      recoveryActionsStepSeconds,
    );
    expect(workflow).toContain(
      "owner-terraform-recovery:\n    name: Recover ${{ inputs.target_repository }} protected Terraform bridge\n" +
        "    needs: owner-terraform\n    if: ${{ always() && needs.owner-terraform.result != 'success' }}\n" +
        "    runs-on: ubuntu-24.04\n    timeout-minutes: 18",
    );
    expect(
      workflow.match(
        /CONSUMER_ACTIONS_READ_TOKEN: \$\{\{ secrets\.CONSUMER_ACTIONS_READ_TOKEN \}\}/g,
      ),
    ).toHaveLength(1);
    expect(workflow).not.toContain("id-token: write");
    expect(workflow).not.toContain("actions/upload-artifact");
    expect(workflow).not.toContain("gcloud ");
    expect(workflow).not.toContain("terraform apply");
    expect(workflow).not.toContain("terraform show");
  });

  test("recovery recognizes the mutation role it actually creates", () => {
    // Regression: the deny-admin split changed what createEphemeralRole builds
    // (45 permissions) without changing what the recovery recognizer expected
    // (48). Every bootstrap mutation role -- and the tombstone Google retains
    // for days after deletion -- would have been unrecognised, so recovery
    // would refuse to delete it and fail with "manual cleanup is required".
    for (const repository of ["cdbentley", "runsetta", "healthmcp", "critical-history"] as const) {
      for (const phase of ["read", "mutation"] as const) {
        const created = executorCustomRolePermissions(repository, "bootstrap", phase);
        expect(
          bridgeRolePermissionsRecognized(created, repository, "bootstrap", phase),
        ).toBeTrue();
        // A role from a build predating the split must stay cleanable too.
        expect(
          bridgeRolePermissionsRecognized(
            executorControlPermissions(repository, "bootstrap", phase),
            repository,
            "bootstrap",
            phase,
          ),
        ).toBeTrue();
      }
      // prod is unaffected by the split but must still recognize itself.
      expect(
        bridgeRolePermissionsRecognized(
          executorCustomRolePermissions(repository, "prod", "mutation"),
          repository,
          "prod",
          "mutation",
        ),
      ).toBeTrue();
    }
    // An unrelated matrix is still rejected.
    expect(
      bridgeRolePermissionsRecognized(["iam.roles.create"], "cdbentley", "bootstrap", "mutation"),
    ).toBeFalse();
  });

  test("the plan gate refuses preview-runtime access however it is conferred", () => {
    const planIdentity = { ...identity(), terraformRoot: "bootstrap" as const };
    const withMember = (member: string) =>
      plan([
        resourceChange(
          "module.bootstrap.google_project_iam_member.some_grant",
          "google_project_iam_member",
          null,
          { member, project: "cdbentley", role: "roles/viewer" },
        ),
      ]);

    // Named directly, in every project, live and soft-deleted.
    for (const project of [
      "cdbentley",
      "runsetta",
      "medlock-1025243085",
      "critical-history-16823277",
    ]) {
      const email = `cloud-run-preview@${project}.iam.gserviceaccount.com`;
      for (const member of [`serviceAccount:${email}`, `deleted:serviceAccount:${email}`]) {
        expect(() => buildReviewManifest(withMember(member), planIdentity)).toThrow(
          "must hold no access",
        );
      }
    }

    // Conferred without being named. These mirror the forbidden_member
    // predicate in tools/ci/preview-runtime-iam-contract.sh: a preventive gate
    // that accepted them would let the protected bridge introduce effective
    // preview-runtime access and leave only the detective proof to catch it.
    for (const member of [
      "allUsers",
      "allAuthenticatedUsers",
      "group:everyone@example.com",
      "deleted:group:old@example.com",
      "domain:example.com",
      "projectEditor:cdbentley",
      "projectOwner:cdbentley",
      "projectViewer:cdbentley",
      "principalSet://cloudresourcemanager.googleapis.com/projects/cdbentley/type/ServiceAccount",
      "principalSet://cloudresourcemanager.googleapis.com/organizations/1234/type/ServiceAccount",
    ]) {
      expect(() => buildReviewManifest(withMember(member), planIdentity)).toThrow(
        "without naming it",
      );
    }

    // The required Cloud Storage access-log delivery group must pass. It is a
    // managed binding, so Terraform reports it in resource_changes on every
    // run; rejecting it as a `group:` member would refuse every bootstrap plan.
    expect(() =>
      buildReviewManifest(
        plan([
          resourceChange(
            "module.bootstrap.google_storage_bucket_iam_member.terraform_state_access_logs_writer",
            "google_storage_bucket_iam_member",
            null,
            {
              bucket: "cdbentley-terraform-state-access-logs",
              member: "group:cloud-storage-analytics@google.com",
              role: "roles/storage.objectCreator",
            },
          ),
        ]),
        planIdentity,
      )
    ).not.toThrow();

    // A member Terraform resolves only during apply decides nothing at review
    // time, so an IAM grant that leaves one unresolved is refused.
    const unknownMember = plan([]) as Record<string, unknown>;
    unknownMember.resource_changes = [{
      address: "module.bootstrap.google_project_iam_member.computed",
      change: {
        actions: ["create"],
        after: { project: "cdbentley", role: "roles/viewer" },
        after_sensitive: {},
        after_unknown: { member: true },
        before: null,
        before_sensitive: {},
        replace_paths: [],
      },
      mode: "managed",
      module_address: "module.bootstrap",
      name: "computed",
      provider_name: "registry.terraform.io/hashicorp/google",
      type: "google_project_iam_member",
    }];
    expect(() => buildReviewManifest(unknownMember, planIdentity)).toThrow(
      "unresolved until apply",
    );

    // A non-IAM resource with unknown attributes is unaffected.
    const unknownElsewhere = plan([]) as Record<string, unknown>;
    unknownElsewhere.resource_changes = [{
      address: "module.bootstrap.google_storage_bucket.later",
      change: {
        actions: ["create"],
        after: { project: "cdbentley" },
        after_sensitive: {},
        after_unknown: { self_link: true },
        before: null,
        before_sensitive: {},
        replace_paths: [],
      },
      mode: "managed",
      module_address: "module.bootstrap",
      name: "later",
      provider_name: "registry.terraform.io/hashicorp/google",
      type: "google_storage_bucket",
    }];
    expect(() => buildReviewManifest(unknownElsewhere, planIdentity)).not.toThrow();

    // Deleted principals carry Google's stable identifier. Stripping it is what
    // makes the restorable account recognisable as the same identity.
    for (const project of ["cdbentley", "runsetta"]) {
      expect(() =>
        buildReviewManifest(
          withMember(
            `deleted:serviceAccount:cloud-run-preview@${project}.iam.gserviceaccount.com?uid=123456789012345678901`,
          ),
          planIdentity,
        )
      ).toThrow("must hold no access");
    }

    // Only IAM grant resources confer access, and only through their principal
    // fields. A container environment value that merely contains "allUsers"
    // grants nothing, and because this runs before no-op changes are filtered,
    // refusing it would block every protected plan that carries the service.
    const envValue = plan([]) as Record<string, unknown>;
    envValue.resource_changes = [{
      address: "module.site.google_cloud_run_v2_service.site",
      change: {
        actions: ["no-op"],
        after: {
          template: [{ containers: [{ env: [{ name: "AUDIENCE", value: "allUsers" }] }] }],
        },
        after_sensitive: {},
        after_unknown: {},
        before: {
          template: [{ containers: [{ env: [{ name: "AUDIENCE", value: "group:x@y.com" }] }] }],
        },
        before_sensitive: {},
        replace_paths: [],
      },
      mode: "managed",
      module_address: "module.site",
      name: "site",
      provider_name: "registry.terraform.io/hashicorp/google",
      type: "google_cloud_run_v2_service",
    }];
    expect(() =>
      buildReviewManifest(envValue, { ...identity(), terraformRoot: "prod" as const })
    ).not.toThrow();

    // A plan that REMOVES a forbidden principal must be allowed: that is the
    // corrective apply. Refusing it would leave the grant in place permanently.
    const removal = plan([]) as Record<string, unknown>;
    removal.resource_changes = [{
      address: "module.bootstrap.google_project_iam_binding.viewers",
      change: {
        actions: ["update"],
        after: {
          members: ["serviceAccount:gha-terraform@cdbentley.iam.gserviceaccount.com"],
          project: "cdbentley",
          role: "roles/viewer",
        },
        after_sensitive: {},
        after_unknown: {},
        before: {
          members: [
            "serviceAccount:gha-terraform@cdbentley.iam.gserviceaccount.com",
            "serviceAccount:cloud-run-preview@cdbentley.iam.gserviceaccount.com",
            "allUsers",
          ],
          project: "cdbentley",
          role: "roles/viewer",
        },
        before_sensitive: {},
        replace_paths: [],
      },
      mode: "managed",
      module_address: "module.bootstrap",
      name: "viewers",
      provider_name: "registry.terraform.io/hashicorp/google",
      type: "google_project_iam_binding",
    }];
    expect(() => buildReviewManifest(removal, planIdentity)).not.toThrow();

    // Deleting the grant outright is likewise allowed.
    const deletion = plan([]) as Record<string, unknown>;
    deletion.resource_changes = [{
      address: "module.bootstrap.google_project_iam_member.stale",
      change: {
        actions: ["delete"],
        after: null,
        after_sensitive: {},
        after_unknown: {},
        before: {
          member: "serviceAccount:cloud-run-preview@cdbentley.iam.gserviceaccount.com",
          project: "cdbentley",
          role: "roles/viewer",
        },
        before_sensitive: {},
        replace_paths: [],
      },
      mode: "managed",
      module_address: "module.bootstrap",
      name: "stale",
      provider_name: "registry.terraform.io/hashicorp/google",
      type: "google_project_iam_member",
    }];
    expect(() => buildReviewManifest(deletion, planIdentity)).not.toThrow();

    // An out-of-band grant shows up as refreshed live state in resource_drift
    // while the corrective empty member set is the planned change. Gating
    // drift would refuse the plan that fixes it.
    const drifted = plan(
      [
        resourceChange(
          "module.bootstrap.google_project_iam_binding.viewers",
          "google_project_iam_binding",
          { members: [], project: "cdbentley", role: "roles/viewer" },
          { members: [], project: "cdbentley", role: "roles/viewer" },
        ),
      ],
      [
        resourceChange(
          "module.bootstrap.google_project_iam_binding.viewers",
          "google_project_iam_binding",
          { members: [], project: "cdbentley", role: "roles/viewer" },
          {
            members: ["serviceAccount:cloud-run-preview@cdbentley.iam.gserviceaccount.com"],
            project: "cdbentley",
            role: "roles/viewer",
          },
        ),
      ],
    );
    expect(() => buildReviewManifest(drifted, planIdentity)).not.toThrow();

    // An ordinary grant to an unrelated principal is untouched.
    expect(() =>
      buildReviewManifest(
        withMember("serviceAccount:gha-terraform@cdbentley.iam.gserviceaccount.com"),
        planIdentity,
      )
    ).not.toThrow();
    // A similarly-named principal in no project of ours is not matched.
    expect(() =>
      buildReviewManifest(
        withMember("serviceAccount:cloud-run-preview@someone-else.iam.gserviceaccount.com"),
        planIdentity,
      )
    ).not.toThrow();
  });

  test("no deny-policy authority survives anywhere in the bridge", async () => {
    const controller = await readFile(
      join(root, "tools/ci/protected-bootstrap-bridge.ts"),
      "utf8",
    );
    // roles/iam.denyAdmin is not grantable at project scope, iam.denypolicies
    // writes are NOT_SUPPORTED in custom roles, and these projects have no
    // organization or folder parent to grant it at instead. The lease could
    // therefore never be created -- apply run 33291080180 died on exactly
    // that setPolicy -- so the executor must never again ask for it.
    // Assert on code, not prose: the comment explaining why this authority is
    // gone is worth keeping.
    expect(controller).not.toContain('"roles/iam.denyAdmin"');
    expect(controller).not.toContain("buildDenyAdminLease");
    expect(controller).not.toContain("requireDenyAdminRoleContract");
    expect(controller).not.toContain('"iam.denypolicies.');
    expect(controller).not.toContain('"google_iam_deny_policy"');
    for (const repository of REPOSITORY_NAMES) {
      for (const phase of ["read", "mutation"] as const) {
        for (const root of ["bootstrap", "prod"] as const) {
          const control = executorControlPermissions(repository, root, phase);
          expect(control.some((p) => p.startsWith("iam.denypolicies."))).toBeFalse();
          // Nothing is filtered out of the custom role any more, so the two
          // contracts must agree exactly.
          expect(executorCustomRolePermissions(repository, root, phase)).toEqual(control);
        }
      }
    }
  });

  test("roles created before the deny permissions were removed stay recoverable", () => {
    // Google retains deleted custom-role tombstones and a crashed run can
    // leave an active role, so recovery must still recognise the retired
    // matrices or it refuses to delete them and reports that manual cleanup
    // is required. These are the v0.5.26 bootstrap matrices.
    const retired = {
      read: [
        "iam.denypolicies.get", "iam.denypolicies.list", "iam.roles.get", "iam.roles.list",
        "iam.serviceAccounts.get", "iam.serviceAccounts.getIamPolicy",
        "iam.serviceAccounts.list", "iam.workloadIdentityPools.get",
        "iam.workloadIdentityPools.getAttestationRules", "iam.workloadIdentityPools.list",
        "iam.workloadIdentityPoolProviders.get", "iam.workloadIdentityPoolProviders.list",
        "resourcemanager.projects.get", "resourcemanager.projects.getIamPolicy",
        "serviceusage.services.get", "serviceusage.services.list",
        "serviceusage.services.use", "storage.buckets.get",
        "storage.buckets.getIamPolicy", "storage.buckets.list",
      ],
    };
    for (const repository of REPOSITORY_NAMES) {
      expect(
        bridgeRolePermissionsRecognized(retired.read, repository, "bootstrap", "read"),
      ).toBeTrue();
      // Two retired mutation variants: the control matrix carried the deny
      // reads and writes, and the custom role carried the reads only, because
      // get/list are the two deny permissions Google supports in a custom role.
      const denyReads = ["iam.denypolicies.get", "iam.denypolicies.list"];
      const denyWrites = [
        "iam.denypolicies.create",
        "iam.denypolicies.delete",
        "iam.denypolicies.update",
      ];
      for (const extra of [[...denyReads, ...denyWrites], denyReads]) {
        const retiredMutation = [
          ...executorControlPermissions(repository, "bootstrap", "mutation"),
          ...extra,
        ];
        expect(
          bridgeRolePermissionsRecognized(retiredMutation, repository, "bootstrap", "mutation"),
        ).toBeTrue();
      }
    }
    // An unrelated matrix is still rejected.
    expect(
      bridgeRolePermissionsRecognized(["iam.roles.create"], "cdbentley", "bootstrap", "mutation"),
    ).toBeFalse();
  });

  test("workflow pins downloads and runs no third-party host action", async () => {
    const workflow = await readFile(
      join(root, ".github/workflows/protected-bootstrap-implementation.yml"),
      "utf8",
    );
    expect(workflow).not.toContain("actions/checkout");
    expect(workflow).toContain(
      "BUN_SHA256: 2d03fb5fb83ac8b567aca0a281b2ce1a1a19d488f56c2968d88c3f25e92fe452",
    );
    expect(workflow).toContain(
      "TERRAFORM_SHA256: ac21c2b9dcd115711f540cbd27ead0596bb4288a917cb56dfa9b25edb3eb6280",
    );
    expect(workflow).toContain(
      "GOOGLE_PROVIDER_SHA256: fb1b9d1ea7bc79b7409f02aa7c19ba39afa22dbead69e83ae7eb2691ac5c2426",
    );
    expect(workflow).toContain("terraform-provider-google_7.45.0_linux_amd64.zip");
    expect(workflow).toContain(
      'mirror="$destination/registry.terraform.io/hashicorp/google/7.45.0/linux_amd64"',
    );
    expect(workflow.match(/^\s+uses:/gm)).toBeNull();
    expect(workflow).toContain("merge-base --is-ancestor");
    expect(workflow).toContain(
      "unset OWNER_OAUTH_ACCESS_TOKEN CONSUMER_ACTIONS_READ_TOKEN PLATFORM_ACTIONS_READ_TOKEN",
    );
    expect(workflow).toContain("export -n owner_token consumer_token platform_token");
    expect(workflow).toContain("docker.io/oven/bun@sha256:");
    expect(workflow).toContain(
      'canonical_image="${TERRAFORM_SANDBOX_IMAGE#docker.io/}"',
    );
    expect(workflow).toContain('test "$canonical_image" != "$TERRAFORM_SANDBOX_IMAGE"');
    expect(workflow).toContain('--arg image "$canonical_image"');
    expect(workflow).not.toContain('--arg image "$TERRAFORM_SANDBOX_IMAGE"');

    const exactConsumerFetch = workflow.slice(
      workflow.indexOf("fetch_exact_public_commit()"),
      workflow.indexOf("platform_root=\"$RUNNER_TEMP/platform\""),
    );
    expect(exactConsumerFetch).toContain(
      '"${git_command[@]}" -C "$destination" fetch --quiet --depth=1 --no-tags origin \\\n              "$expected_sha"',
    );
    expect(exactConsumerFetch).toContain(
      'test "$("${git_command[@]}" -C "$destination" rev-parse FETCH_HEAD)" = \\\n              "$expected_sha"',
    );
    expect(exactConsumerFetch).not.toContain("refs/heads/main");
    expect(exactConsumerFetch).not.toContain("merge-base");
    expect(workflow).toContain(
      'fetch_exact_public_commit "$RUNNER_TEMP/consumer" "$TARGET_REPOSITORY" "$CONSUMER_SHA"',
    );
  });

  test("Terraform provider extraction is an exact discoverable filesystem mirror", async () => {
    const directory = await mkdtemp(join(tmpdir(), "protected-provider-mirror-"));
    const leaf = join(
      directory,
      "registry.terraform.io/hashicorp/google/7.45.0/linux_amd64",
    );
    try {
      await mkdir(leaf, { recursive: true });
      await writeFile(join(leaf, "LICENSE.txt"), "license\n");
      const binary = join(leaf, "terraform-provider-google_v7.45.0_x5");
      await writeFile(binary, "provider\n");
      await chmod(binary, 0o500);
      await expect(verifyTerraformProviderMirrorLayout(directory)).resolves.toBeUndefined();

      await writeFile(join(directory, "terraform-provider-google_v7.45.0_x5"), "flat\n");
      await expect(verifyTerraformProviderMirrorLayout(directory)).rejects.toThrow(
        "exact directory layout",
      );
      await rm(join(directory, "terraform-provider-google_v7.45.0_x5"));
      await writeFile(join(leaf, "unexpected"), "foreign\n");
      await expect(verifyTerraformProviderMirrorLayout(directory)).rejects.toThrow(
        "exact two-file leaf contract",
      );
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  test("DHI-changing rollout keeps Actions disabled through the ordered nine-receipt gate", async () => {
    const [
      rolloutSource,
      deployPreview,
      productionCaller,
      reusableDeployProduction,
      infrastructureWorkflow,
      cleanupPreview,
      reconcilePreviews,
      cloudRunModule,
      exposureReadme,
      dockerignore,
      packageSource,
      readme,
    ] = await Promise.all([
      readFile(join(root, "docs/security-rollout.md"), "utf8"),
      readFile(join(root, "templates/app/.github/workflows/deploy-preview.yml"), "utf8"),
      readFile(join(root, "templates/app/.github/workflows/deploy-prod.yml"), "utf8"),
      readFile(join(root, ".github/workflows/deploy-prod.yml"), "utf8"),
      readFile(join(root, ".github/workflows/infrastructure.yml"), "utf8"),
      readFile(join(root, "templates/app/.github/workflows/cleanup-preview.yml"), "utf8"),
      readFile(join(root, "templates/app/.github/workflows/reconcile-previews.yml"), "utf8"),
      readFile(join(root, "terraform/modules/cloud-run-service/main.tf"), "utf8"),
      readFile(join(root, "terraform/deployments/exposure/README.md"), "utf8"),
      readFile(join(root, "templates/app/.dockerignore"), "utf8"),
      readFile(join(root, "package.json"), "utf8"),
      readFile(join(root, "README.md"), "utf8"),
    ]);
    const rollout = rolloutSource.replace(/\s+/g, " ");
    for (const requirement of [
      "current head of an open, unmerged public consumer PR",
      "deliberately imposes no consumer-`main` ancestry requirement",
      "Do not merge after bootstrap alone",
      "complete the one-shot Runsetta exposure-state adoption",
      "four successful production result receipts",
      "all nine prerequisite receipts established",
      "mark that exact draft ready while Actions remains globally disabled",
      "exactly the one expected `ready_for_review` lifecycle event was created",
      "zero workflow runs were created after the baseline",
      "using the receipt-bound head SHA as the exact `sha` precondition",
      "each resulting `main^{tree}` equals the receipt's `consumerTreeSha`",
      "Any platform-`main` advance after that freeze therefore invalidates every prepared pin",
      "current v0.4 initial adoption must use `legacy_compatibility_mode=true`",
      "generic later active-only DHI cutover",
      "must use `legacy_compatibility_mode=false`",
      "Never enable a marker-unaware legacy PR-triggered privileged deployment",
      "only the credentialless exact-head Application, Infrastructure validation, Socket, and, for Runsetta, Swift package checks",
      "Do not use the repository Events API as a security gate",
      "complete paginated `state=all` PR inventory",
      "repository issue-event ID baseline",
      "per-PR timeline ID baseline",
      "rule out `synchronize` by both the frozen head SHA/tree comparison and timeline records",
      "use the owner PAT for exactly one PR-body-only edit",
      "resulting `pull_request: edited` delivery is the sole check-window trigger",
      "Every expected job must first pass the shared fail-closed event-payload guard",
      "an `edited` payload is accepted only when `changes` contains exactly `body`",
      "title, base, mixed, missing, and expanded change shapes fail",
      "For non-`edited` pull-request deliveries the same guard accepts only `opened`, `reopened`, and `synchronize`",
      "GitHub does not replay the merge's disabled `push`",
      "the production workflow intentionally has no manual-dispatch trust path",
      "selected-actions GET returns 409",
      "sha_pinning_required:true",
      "github_owned_allowed:false",
      "verified_allowed:false",
      "each exact reusable caller path suffixed by `@S`",
      "PUT the exact general policy and then immediately PUT the exact selected policy",
      "immediately PUT `{enabled:false}`",
      "sole permitted PR lifecycle event is this initial `opened` event",
      "A draft does not make `synchronize` harmless",
      "All three preview lifecycle workflows are now individually disabled",
      "using the exact frozen head SHA as its `sha` precondition",
      "resulting `main^{tree}` to equal the frozen activation-head tree",
      "no replay of the missed closed, push, ready, or scheduled events",
      "Do not rerun the failed workflow",
      "branch-protection weakening",
      "the first `S` production deploy to complete the sealed DHI epoch transition",
      "never use the mixed-SHA transition path when `P` and `S` declare different DHI parity IDs",
      "wait at least 55 minutes after the failed workflow completes",
      "exceeding both the 54-minute conditioned lease and 35-minute executor-token lifetimes",
      "issue a new attempt-1 owner dispatch",
    ]) {
      expect(rollout).toContain(requirement);
    }

    let previousIndex = -1;
    const currentRolloutGate = rolloutSource.slice(
      rolloutSource.indexOf("4. Do not merge after bootstrap alone"),
      rolloutSource.indexOf("6. Recheck disabled Actions"),
    ).replace(/\s+/g, " ");
    previousIndex = -1;
    for (const orderedRequirement of [
      "four immutable bootstrap result receipts",
      "one-shot Runsetta exposure-state adoption",
      "four successful production result receipts",
      "all nine prerequisite receipts established",
      "prepare each of the four unchanged draft PRs for",
    ]) {
      const currentIndex = currentRolloutGate.indexOf(orderedRequirement);
      expect(currentIndex, orderedRequirement).toBeGreaterThan(previousIndex);
      previousIndex = currentIndex;
    }

    const activationSource = rolloutSource.slice(
      rolloutSource.indexOf("6. Recheck disabled Actions"),
      rolloutSource.indexOf("The active-only apply removes"),
    );
    const activation = activationSource.replace(/\s+/g, " ");
    previousIndex = -1;
    for (const orderedRequirement of [
      "prepare the complete activation branch before opening a PR",
      "platform-production-activation-v1",
      "canonical `.dockerignore` excludes `README.md`",
      "Derive an exact normalized Actions allowlist",
      "With Actions still globally disabled",
      "disable the `Cleanup preview`, `Reconcile previews`, and `Deploy production` workflow files",
      "explicitly enable `Deploy preview`",
      "inventory every open PR and its exact head repository and SHA",
      "complete PR inventory, issue-event, per-PR timeline, and run surfaces defined above",
      "Outside the conservative UTC minute `:12` through `:22`",
      "this enable sequence replayed no event",
      "sole PR lifecycle event repository-wide",
      "Open the already-frozen activation PR as a draft",
      "Wait only until that event's `Deploy preview` run materializes",
      "Immediately disable `Deploy preview`",
      "only then wait for and require all normal exact-head checks",
      "A draft does not make `synchronize` harmless",
      "globally disable Actions and drain all runs",
      "mark the unchanged PR ready while globally disabled",
      "exactly the one expected `ready_for_review` event occurred",
      "suppresses the workflow response to the ready event",
      "While still globally disabled, explicitly enable only `Deploy production`",
      "Re-enable with the same two-PUT general-then-selected sequence",
      "using the exact frozen head SHA as its `sha` precondition",
      "resulting `main^{tree}` to equal the frozen activation-head tree",
      "only cloud mutation admitted by the activation merge is the push-only `Deploy production`",
      "complete the sealed DHI epoch transition",
      "enable `Cleanup preview`, `Reconcile previews`, and `Deploy preview`",
      "no replay of the missed closed, push, ready, or scheduled events",
      "If the activation production run fails",
      "Do not rerun the failed workflow",
      "fresh immutable activation PR with a new attempt number",
    ]) {
      const currentIndex = activation.indexOf(orderedRequirement);
      expect(currentIndex, orderedRequirement).toBeGreaterThan(previousIndex);
      previousIndex = currentIndex;
    }

    expect(activation).toContain(
      "<!-- platform-production-activation-v1 platform-sha=<40hex> cutover-tree=<40hex> phase=<phase-a-or-phase-b> attempt=<positive-decimal> -->",
    );
    expect(activation).toContain("with no other content, path, or mode change");
    expect(activation).toContain("This active-only section selects the literal `phase-a`");
    expect(activation).toContain("Phase B step 4 selects the literal `phase-b`");
    expect(activation).toContain("that phase's protected-result receipt `consumerTreeSha`");
    expect(activation).toContain("every Dockerfile, build input, and effective image context");
    expect(activation).toContain(
      '{enabled:true,allowed_actions:"selected",sha_pinning_required:true}',
    );
    expect(activation).toContain(
      "forbid `synchronize`, `reopened`, `ready_for_review`, and `converted_to_draft`",
    );

    expect(productionCaller).toContain("on:\n  push:");
    expect(productionCaller).not.toContain("workflow_dispatch:");
    expect(productionCaller).toContain("  deploy:\n    needs: infrastructure");
    for (const event of [
      "opened",
      "synchronize",
      "reopened",
      "ready_for_review",
      "converted_to_draft",
    ]) {
      expect(deployPreview).toContain(`      - ${event}`);
    }
    const invalidateJob = deployPreview.slice(
      deployPreview.indexOf("  invalidate:"),
      deployPreview.indexOf("  deploy:"),
    );
    expect(invalidateJob).toContain("github.event.action == 'synchronize'");
    expect(invalidateJob).toContain("github.event.action == 'converted_to_draft'");
    expect(invalidateJob).toContain("id-token: write");
    expect(deployPreview).toContain("github.event.pull_request.draft == false");
    expect(cleanupPreview).toContain("pull_request_target:");
    expect(cleanupPreview).toContain("      - closed");
    expect(reconcilePreviews).toContain("  push:");
    expect(reconcilePreviews).toContain("schedule:");
    expect(reconcilePreviews).toContain("cron: '17 * * * *'");
    expect(dockerignore.split("\n")).toContain("README.md");

    const convergence = infrastructureWorkflow.slice(
      infrastructureWorkflow.indexOf("- name: Require production infrastructure to be converged"),
      infrastructureWorkflow.indexOf("- name: Require coherent controller-owned preview exposure"),
    );
    expect(convergence).toContain("-detailed-exitcode");
    expect(convergence).toContain("Production infrastructure drift or a requested change exists.");
    expect(convergence).toContain("exit 1");

    const exposureGate = infrastructureWorkflow.slice(
      infrastructureWorkflow.indexOf("- name: Require coherent controller-owned preview exposure"),
    );
    expect(exposureGate).toContain("def exact_public_terraform_bootstrap:");
    expect(exposureGate).toContain(
      "us-docker.pkg.dev/cloudrun/container/hello@sha256:9a0e9a5c7a19281e7617991d2fc61809de4973e6e75a10b2f07df3719ffda33c",
    );
    expect(exposureGate).toContain('"managed-by":"terraform"');
    expect(exposureGate).toContain(
      'serviceAccount:"cloud-run-preview@\\($project).iam.gserviceaccount.com"',
    );
    expect(exposureGate).toContain(
      '.traffic == [{type:"TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST",percent:100}]',
    );
    expect(exposureGate).toContain("if ($tags | length) == 0 then");
    expect(exposureGate).toContain("exact_public_terraform_bootstrap)");

    const parityIndex = reusableDeployProduction.indexOf(
      "- name: Refuse production if any live preview has different or unknown DHI lineage",
    );
    const epochPrepareIndex = reusableDeployProduction.indexOf(
      "- name: Use the same-DHI fast path or durably seal and prune the preview epoch",
    );
    const productionDeployIndex = reusableDeployProduction.indexOf(
      "- name: Deploy production to Cloud Run",
    );
    expect(parityIndex).toBeGreaterThan(-1);
    expect(
      reusableDeployProduction.slice(
        parityIndex,
        reusableDeployProduction.indexOf("- name:", parityIndex + 8),
      ),
    ).toContain("continue-on-error: true");
    expect(epochPrepareIndex).toBeGreaterThan(parityIndex);
    expect(productionDeployIndex).toBeGreaterThan(epochPrepareIndex);

    const previewResource = cloudRunModule.slice(
      cloudRunModule.indexOf('resource "google_cloud_run_v2_service" "preview"'),
      cloudRunModule.indexOf('resource "google_cloud_run_v2_service_iam_member" "preview_deploy"'),
    );
    expect(previewResource).toContain('ingress              = "INGRESS_TRAFFIC_INTERNAL_ONLY"');
    expect(previewResource).toContain("# The serialized preview controller owns these two top-level fields.");
    expect(previewResource).toContain("      ingress,");
    expect(previewResource).toContain("      invoker_iam_disabled,");
    const normalizedExposureReadme = exposureReadme.replace(/\s+/g, " ");
    expect(normalizedExposureReadme).toContain(
      "existing public preview ingress through the protected production apply",
    );
    expect(normalizedExposureReadme).toContain(
      "durably seal the zero-tag bootstrap to internal-only before deployment",
    );

    const criticalSequence = rolloutSource
      .slice(
        rolloutSource.indexOf("10. Keep consumer Actions disabled"),
        rolloutSource.indexOf("11. Reconciliation must continue"),
      )
      .replace(/\s+/g, " ");
    previousIndex = -1;
    for (const orderedRequirement of [
      "all four bootstrap results",
      "Runsetta terminal adoption receipt",
      "all four protected production results exist",
      "merge the four receipt-bound cutover trees",
      "read-only edge continuity proof from step 9",
      "there is no v0.5.13 exposure apply",
      "leave the existing public, zero-tag bootstrap exposure byte-for-byte unchanged",
      "production convergence plan is empty",
      "prerequisite infrastructure exposure proof may admit the public zero-tag state only",
      "immutable Google hello-image digest exactly equal the Terraform bootstrap object",
      "immediately following epoch-prepare controller",
      "push-only new-SHA production run to finish",
      "replace the sealed bootstrap with the sanitized production-DHI baseline",
      "create the live preview canary",
      "stable tagged URL healthy",
      "globally disable and drain Critical History again",
      "protected production plan to remain empty",
      "no second apply is expected",
      "Re-enable Critical only with the exact two-PUT selected/SHA-only policy",
      "one reviewed synchronization of the still-open canary",
      "invalidation and redeploy to succeed through the restricted frontend",
      "fresh activation PRs for cdbentley, Runsetta, and Health/Medlock",
    ]) {
      const currentIndex = criticalSequence.indexOf(orderedRequirement);
      expect(currentIndex, orderedRequirement).toBeGreaterThan(previousIndex);
      previousIndex = currentIndex;
    }

    const phaseB = rolloutSource
      .slice(rolloutSource.indexOf("## Phase B"))
      .replace(/\s+/g, " ");
    expect(phaseB).toContain("phase=phase-b");
    expect(phaseB).toContain("new phase-B production push");
    expect(phaseB).toContain("never rerun a phase-A run or add a dispatch trigger");
    expect(phaseB).toContain("four immutable successful phase-B result receipts");
    expect(phaseB).toContain("Activate all four consumers serially");
    expect(phaseB).toContain("Globally disable and drain that repository");

    const packageVersion = (JSON.parse(packageSource) as { version: string }).version;
    expect(readme).toContain(`Release \`${packageVersion}\``);
    expect(readme).toContain(`gh release create v${packageVersion} --target`);
  });

  test("invocation requires exact immutable owner and repository identities", () => {
    const environment = validEnvironment();
    const invocation = validateInvocation(environment);
    expect(invocation.repository).toBe("cdbentley");
    expect(invocation.terraformRoot).toBe("bootstrap");
    expect(invocation.mode).toBe("plan");

    for (const [name, value] of [
      ["GITHUB_ACTOR_ID_EXACT", "999"],
      ["GITHUB_REF_EXACT", "refs/heads/feature"],
      ["GITHUB_REPOSITORY_ID_EXACT", "999"],
      ["GITHUB_RUN_ATTEMPT_EXACT", "2"],
      ["TARGET_REPOSITORY", "platform"],
    ] as const) {
      expect(() => validateInvocation({ ...environment, [name]: value })).toThrow();
    }
    expect(() =>
      validateInvocation({
        ...environment,
        APPROVED_MANIFEST_SHA256: "d".repeat(64),
      }),
    ).toThrow("Plan mode forbids");
    expect(() =>
      validateInvocation({
        ...environment,
        APPROVED_MANIFEST_SHA256: "",
        BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "2340",
        EXECUTION_MODE: "apply",
      }),
    ).toThrow("approved manifest digest");
    expect(() =>
      validateInvocation({ ...environment, LEGACY_COMPATIBILITY_MODE: "1" })
    ).toThrow("exactly true or false");
    expect(validateInvocation({
      ...environment,
      TRANSITION_WORKFLOW_SHA: "d".repeat(40),
    }).transitionWorkflowSha).toBe("d".repeat(40));
    expect(() =>
      validateInvocation({
        ...environment,
        LEGACY_COMPATIBILITY_MODE: "true",
        TRANSITION_WORKFLOW_SHA: "d".repeat(40),
      })
    ).toThrow("initial migration");
    expect(validateInvocation({
      ...environment,
      LEGACY_COMPATIBILITY_MODE: "true",
      TRANSITION_WORKFLOW_SHA: "",
    }).legacyCompatibilityMode).toBeTrue();
    expect(() =>
      validateInvocation({
        ...environment,
        LEGACY_COMPATIBILITY_MODE: "true",
        TERRAFORM_ROOT: "prod",
      })
    ).toThrow("Non-bootstrap mode forbids");
    expect(() => validateInvocation({
      ...environment,
      TARGET_REPOSITORY: "cdbentley",
      TERRAFORM_ROOT: "exposure",
    })).toThrow("locked to a Runsetta plan run");
    expect(() => validateInvocation({
      ...environment,
      TARGET_REPOSITORY: "runsetta",
      TERRAFORM_ROOT: "exposure",
    })).toThrow("adoption confirmation drifted");
    expect(() => validateInvocation({
      ...environment,
      APPROVED_MANIFEST_SHA256: "d".repeat(64),
      APPROVED_PLAN_RUN_ID: "123455",
      BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "2340",
      EXECUTION_MODE: "apply",
      EXPOSURE_ADOPTION_CONFIRMATION: "ADOPT_RUNSETTA_EXPOSURE_STATE",
      TARGET_REPOSITORY: "runsetta",
      TERRAFORM_ROOT: "exposure",
    })).toThrow("locked to a Runsetta plan run");
    expect(validateInvocation({
      ...environment,
      EXPOSURE_ADOPTION_CONFIRMATION: "ADOPT_RUNSETTA_EXPOSURE_STATE",
      TARGET_REPOSITORY: "runsetta",
      TERRAFORM_ROOT: "exposure",
    }).repository).toBe("runsetta");
    expect(() => validateInvocation({
      ...environment,
      TARGET_REPOSITORY: "runsetta",
      TERRAFORM_ROOT: "prod",
    })).toThrow("exposure adoption run ID");
    expect(validateInvocation({
      ...environment,
      EXPOSURE_ADOPTION_RUN_ID: "123455",
      TARGET_REPOSITORY: "runsetta",
      TERRAFORM_ROOT: "prod",
    }).exposureAdoptionRunId).toBe("123455");
    expect(() => validateInvocation({
      ...environment,
      EXPOSURE_ADOPTION_RUN_ID: "123455",
    })).toThrow("non-Runsetta-prod");
  });

  test("consumer pin proof requires one consistent safe SHA across every reusable caller", async () => {
    const directory = await mkdtemp(join(tmpdir(), "protected-pin-"));
    const workflows = [
      "application.yml",
      "cleanup-preview.yml",
      "deploy-preview.yml",
      "deploy-prod.yml",
      "infrastructure.yml",
      "reconcile-previews.yml",
      "socket-firewall.yml",
    ];
    const workflowDirectory = join(directory, ".github", "workflows");
    await mkdir(workflowDirectory, { recursive: true });
    const render = async (workflow: string, pin: string) => {
      const template = await readFile(
        join(root, "templates", "app", ".github", "workflows", workflow),
        "utf8",
      );
      await writeFile(join(workflowDirectory, workflow), template.replaceAll("__PLATFORM_SHA__", pin));
    };
    try {
      for (const workflow of workflows) await render(workflow, platformSha);
      expect(await readConsumerWorkflowPin(directory)).toBe(platformSha);

      await render("application.yml", "d".repeat(40));
      await expect(readConsumerWorkflowPin(directory)).rejects.toThrow("inconsistent");

      const vulnerable = "734d0cd02187f88c6e91263f127dc3f4c0709feb";
      for (const workflow of workflows) await render(workflow, vulnerable);
      await expect(readConsumerWorkflowPin(directory)).rejects.toThrow("vulnerable");
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  test("a detached public PR-head commit is accepted without merge-to-main ancestry", async () => {
    const directory = await mkdtemp(join(tmpdir(), "protected-prepared-head-"));
    const author = join(directory, "author");
    const remote = join(directory, "consumer.git");
    const fetched = join(directory, "fetched");
    const workflows = [
      "application.yml",
      "cleanup-preview.yml",
      "deploy-preview.yml",
      "deploy-prod.yml",
      "infrastructure.yml",
      "reconcile-previews.yml",
      "socket-firewall.yml",
    ];
    try {
      await mkdir(author);
      await runGit(author, ["init"]);
      await runGit(author, ["symbolic-ref", "HEAD", "refs/heads/main"]);
      await runGit(author, ["config", "user.email", "protected-bridge@example.invalid"]);
      await runGit(author, ["config", "user.name", "Protected bridge test"]);
      await writeFile(join(author, "README.md"), "base\n");
      await runGit(author, ["add", "README.md"]);
      await runGit(author, ["commit", "-m", "base"]);
      const mainSha = await runGit(author, ["rev-parse", "HEAD"]);

      await mkdir(remote);
      await runGit(remote, ["init", "--bare"]);
      await runGit(author, ["remote", "add", "origin", remote]);
      await runGit(author, ["push", "origin", "main:refs/heads/main"]);
      await runGit(author, ["checkout", "-b", "prepared-dhi-cutover"]);
      const workflowDirectory = join(author, ".github", "workflows");
      await mkdir(workflowDirectory, { recursive: true });
      for (const workflow of workflows) {
        const template = await readFile(
          join(root, "templates", "app", ".github", "workflows", workflow),
          "utf8",
        );
        await writeFile(
          join(workflowDirectory, workflow),
          template.replaceAll("__PLATFORM_SHA__", platformSha),
        );
      }
      await runGit(author, ["add", ".github/workflows"]);
      await runGit(author, ["commit", "-m", "prepare exact active workflow pin"]);
      const preparedSha = await runGit(author, ["rev-parse", "HEAD"]);
      expect(preparedSha).not.toBe(mainSha);
      await runGit(author, ["push", "origin", "HEAD:refs/pull/17/head"]);
      expect(await runGit(remote, ["for-each-ref", "--format=%(refname)", "refs/heads"])).toBe(
        "refs/heads/main",
      );

      await mkdir(fetched);
      await runGit(fetched, ["init"]);
      await runGit(fetched, [
        "-c",
        "protocol.file.allow=always",
        "fetch",
        "--depth=1",
        "--no-tags",
        `file://${remote}`,
        preparedSha,
      ]);
      expect(await runGit(fetched, ["rev-parse", "FETCH_HEAD"])).toBe(preparedSha);
      await runGit(fetched, ["checkout", "--detach", preparedSha]);
      expect(await runGit(fetched, ["rev-parse", "--abbrev-ref", "HEAD"])).toBe("HEAD");
      const tree = await verifyLocalSource(fetched, preparedSha, undefined, directory);
      expect(tree).not.toBe(await runGit(author, ["rev-parse", "main^{tree}"]));
      expect(await readConsumerWorkflowPin(fetched)).toBe(platformSha);
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  test("deployment-parity capability is exact-key, hash-complete, and DHI-bound", async () => {
    const directory = await mkdtemp(join(tmpdir(), "protected-capability-"));
    const requiredFiles: Record<string, string> = {};
    try {
      for (const [index, relativePath] of capabilityFiles.entries()) {
        const body = `trusted capability file ${index}\n`;
        await mkdir(dirname(join(directory, relativePath)), { recursive: true });
        await writeFile(join(directory, relativePath), body);
        requiredFiles[relativePath] =
          `sha256:${createHash("sha256").update(body).digest("hex")}`;
      }
      const manifestPath = join(
        directory,
        "platform-capabilities/preview-deployment-parity-v1.json",
      );
      await mkdir(dirname(manifestPath), { recursive: true });
      const manifest = {
        capability: "preview-deployment-parity",
        dhiParityId: "z".repeat(50),
        marker: {
          bucketSuffix: "-deployment-parity-state",
          metadataVersion: "1",
          object: "deployment-parity-transition",
        },
        maxMutatorTokenLifetimeSeconds: 300,
        requiredFiles,
        schemaVersion: 1,
      };
      await writeFile(manifestPath, `${JSON.stringify(manifest)}\n`);
      expect(await verifyPlatformCapability(directory)).toEqual({
        dhiParityId: "z".repeat(50),
        maxMutatorTokenLifetimeSeconds: 300,
      });

      await writeFile(join(directory, capabilityFiles[0]), "tampered\n");
      await expect(verifyPlatformCapability(directory)).rejects.toThrow("hash");
      await writeFile(join(directory, capabilityFiles[0]), "trusted capability file 0\n");
      await writeFile(manifestPath, `${JSON.stringify({ ...manifest, extra: true })}\n`);
      await expect(verifyPlatformCapability(directory)).rejects.toThrow("unreviewed field extra");
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  test("committed deployment-parity capability matches every protected source", async () => {
    expect(await verifyPlatformCapability(root)).toEqual({
      dhiParityId: "1a4cho1elzg84pavos8mbanvvpmkieiht7kyhpjdofzpivf3k8",
      maxMutatorTokenLifetimeSeconds: 300,
    });
  });

  test("a mixed transition is accepted only when active and predecessor DHI parity match", () => {
    const active = {
      dhiParityId: "a".repeat(50),
      maxMutatorTokenLifetimeSeconds: 300,
    };
    expect(requireSameDhiTransitionCapability(active, { ...active })).toBe(active);
    expect(() =>
      requireSameDhiTransitionCapability(active, {
        ...active,
        dhiParityId: "b".repeat(50),
      })
    ).toThrow("transition and active DHI parity ID");
  });

  test("bootstrap storage lease targets the executor and exact state objects but no receipts", () => {
    const expiration = new Date("2026-08-22T21:32:00.000Z");
    const lease = buildStorageLease(
      "cdbentley",
      "bootstrap",
      "123456",
      expiration,
      executorEmail,
      "apply",
      "123455",
    );
    expect(lease.members).toEqual([
      `serviceAccount:${executorEmail}`,
    ]);
    expect(lease.role).toBe("roles/storage.admin");
    expect(lease.condition.title).toBe("codex-executor-storage-apply-123456");
    expect(lease.condition.expression).toContain("2026-08-22T21:32:00.000Z");
    expect(lease.condition.expression).not.toContain(".protected-bootstrap");
    expect(lease.condition.expression).toContain("cdbentley/bootstrap/default.tfstate");
    expect(lease.condition.expression).toContain("cdbentley/bootstrap/default.tflock");
    expect(lease.condition.expression).not.toContain("projects/cdbentley");
    expect(lease.condition.expression).not.toContain("*");
  });

  test("receipt leases are exact create/read-only scopes with no overwrite or delete authority", () => {
    const expiration = new Date("2026-08-22T21:32:00.000Z");
    const plan = buildReceiptLeases(
      "cdbentley",
      "bootstrap",
      "123456",
      expiration,
      "plan",
      "",
      executorEmail,
    );
    expect(plan.map((binding) => binding.role)).toEqual([
      "roles/storage.objectCreator",
      "roles/storage.objectViewer",
    ]);
    expect(plan.every((binding) => binding.condition.expression.includes(
      "cdbentley/bootstrap/.protected-bootstrap/plans/123456.json",
    ))).toBeTrue();
    expect(plan.some((binding) => binding.role.includes("Admin"))).toBeFalse();

    const apply = buildReceiptLeases(
      "healthmcp",
      "prod",
      "123457",
      expiration,
      "apply",
      "123456",
      "gha-pbt-0123456789abcdefabcd@medlock-1025243085.iam.gserviceaccount.com",
    );
    const creator = apply.find((binding) => binding.role === "roles/storage.objectCreator");
    const viewer = apply.find((binding) => binding.role === "roles/storage.objectViewer");
    expect(creator?.condition.expression).toContain(
      "medlock/prod/.protected-bootstrap/consumed/123456.json",
    );
    expect(creator?.condition.expression).not.toContain("/plans/123456.json");
    expect(viewer?.condition.expression).toContain("/plans/123456.json");
    expect(viewer?.condition.expression).toContain("/consumed/123456.json");
    expect(apply.some((binding) => binding.role === "roles/storage.objectAdmin")).toBeFalse();
  });

  test("marker leases are four distinct exact-object conditions and never state-wide", () => {
    const expiration = new Date("2026-08-22T21:32:00.000Z");
    const repositories = ["cdbentley", "runsetta", "healthmcp", "critical-history"] as const;
    const leases = repositories.map((repository) =>
      buildMarkerReadLease(repository, "123456", expiration, "cdbentley", executorEmail)
    );
    expect(new Set(leases.map((lease) => lease.condition?.title)).size).toBe(4);
    for (const [index, lease] of leases.entries()) {
      expect(lease.role).toBe("roles/storage.objectViewer");
      expect(lease.members).toEqual([`serviceAccount:${executorEmail}`]);
      expect(lease.condition?.expression).toContain(
        "resource.type == 'storage.googleapis.com/Object'",
      );
      expect(lease.condition?.expression).toContain("/objects/deployment-parity-transition");
      expect(lease.condition?.expression).toContain(repositories[index] === "healthmcp"
        ? "medlock-1025243085-deployment-parity-state"
        : repositories[index] === "critical-history"
        ? "critical-history-16823277-deployment-parity-state"
        : `${repositories[index]}-deployment-parity-state`);
      expect(lease.condition?.expression).not.toContain("tfstate");
    }
    const mutation = buildMarkerMutationLease(
      "cdbentley",
      "123456",
      expiration,
      executorEmail,
    );
    expect(mutation.role).toBe("roles/storage.objectAdmin");
    expect(mutation.condition?.expression).toContain(
      "projects/_/buckets/cdbentley-deployment-parity-state/objects/deployment-parity-transition",
    );
  });

  test("marker proof accepts 404 only during initial migration and requires target clear post-apply", async () => {
    const initial = validateInvocation({
      ...validEnvironment(),
      LEGACY_COMPATIBILITY_MODE: "true",
    });
    const missing = async (): Promise<Response> => new Response("", { status: 404 });
    expect(await proveDeploymentParityMarkers(
      initial,
      "short-lived-executor-access-token-value",
      false,
      missing,
      async () => undefined,
    )).toEqual(markers("absent"));
    await expect(proveDeploymentParityMarkers(
      initial,
      "short-lived-executor-access-token-value",
      true,
      missing,
      async () => undefined,
    )).rejects.toThrow("cdbentley deployment-parity marker is absent");
    await expect(proveDeploymentParityMarkers(
      validateInvocation(validEnvironment()),
      "short-lived-executor-access-token-value",
      false,
      missing,
      async () => undefined,
    )).rejects.toThrow("outside its initial bootstrap");
  });

  test("marker proof is exact-key, generation-bound, clear-only, and retries propagation", async () => {
    const expected = markers();
    let firstAttempts = 0;
    const exactMarkers = async (input: string | URL | Request): Promise<Response> => {
      const url = new URL(String(input));
      const bucket = url.pathname.split("/")[4] ?? "";
      if (bucket === "cdbentley-deployment-parity-state" && firstAttempts++ === 0) {
        return new Response("", { status: 403 });
      }
      const marker = expected.find((entry) => entry.bucket === bucket)!;
      return Response.json({
        bucket,
        generation: marker.generation,
        metadata: marker.metadata,
        metageneration: marker.metageneration,
        name: "deployment-parity-transition",
      });
    };
    expect(await proveDeploymentParityMarkers(
      validateInvocation(validEnvironment()),
      "short-lived-executor-access-token-value",
      false,
      exactMarkers,
      async () => undefined,
    )).toEqual(expected);
    expect(firstAttempts).toBe(2);

    await expect(proveDeploymentParityMarkers(
      validateInvocation(validEnvironment()),
      "short-lived-executor-access-token-value",
      false,
      async (input) => {
        const url = new URL(String(input));
        const bucket = url.pathname.split("/")[4] ?? "";
        const marker = expected.find((entry) => entry.bucket === bucket)!;
        return Response.json({
          bucket,
          generation: marker.generation,
          metadata: { ...marker.metadata, unexpected: "poison" },
          metageneration: marker.metageneration,
          name: "deployment-parity-transition",
        });
      },
      async () => undefined,
    )).rejects.toThrow("unreviewed field unexpected");
  });

  test("Runsetta exposure proof uses the regional API, exact list, live mappings, and HTTPS", async () => {
    const invocation = validateInvocation({
      ...validEnvironment(),
      EXPOSURE_ADOPTION_CONFIRMATION: "ADOPT_RUNSETTA_EXPOSURE_STATE",
      TARGET_REPOSITORY: "runsetta",
      TERRAFORM_ROOT: "exposure",
    });
    const urls: string[] = [];
    const fetcher = async (input: string | URL | Request): Promise<Response> => {
      const url = new URL(String(input));
      urls.push(url.href);
      if (url.hostname === "storage.googleapis.com") return new Response("", { status: 404 });
      if (url.hostname === "us-east4-run.googleapis.com") {
        const suffix = url.pathname.split("/domainmappings")[1] ?? "";
        if (suffix === "") {
          return Response.json({
            apiVersion: "domains.cloudrun.com/v1",
            items: ["runsetta.com", "www.runsetta.com"].map((domain, index) => ({
              metadata: {
                generation: 1,
                name: domain,
                namespace: "601124730704",
                uid: index === 0
                  ? "054a1acd-cfa0-4a47-b6f2-238753c0c2bc"
                  : "3a72ca14-d15b-40f9-9920-a9b7083eb771",
              },
            })),
            kind: "DomainMappingList",
            metadata: {
              resourceVersion: "opaque-601124730704-1",
              selfLink: "/apis/domains.cloudrun.com/v1/namespaces/601124730704/domainmappings",
            },
          });
        }
        const domain = decodeURIComponent(suffix.slice(1));
        const www = domain === "www.runsetta.com";
        return Response.json({
          apiVersion: "domains.cloudrun.com/v1",
          kind: "DomainMapping",
          metadata: {
            generation: 1,
            name: domain,
            namespace: "601124730704",
            selfLink:
              `/apis/domains.cloudrun.com/v1/namespaces/601124730704/domainmappings/${domain}`,
            uid: www
              ? "3a72ca14-d15b-40f9-9920-a9b7083eb771"
              : "054a1acd-cfa0-4a47-b6f2-238753c0c2bc",
          },
          spec: { certificateMode: "AUTOMATIC", routeName: "runsetta" },
          status: {
            conditions: ["Ready", "CertificateProvisioned", "DomainRoutable"].map((type) => ({
              status: "True",
              type,
            })),
            mappedRouteName: "runsetta",
            observedGeneration: 1,
            resourceRecords: www
              ? [{ name: "www", rrdata: "ghs.googlehosted.com.", type: "CNAME" }]
              : [
                  { rrdata: "216.239.32.21", type: "A" },
                  { rrdata: "216.239.34.21", type: "A" },
                  { rrdata: "216.239.36.21", type: "A" },
                  { rrdata: "216.239.38.21", type: "A" },
                  { rrdata: "2001:4860:4802:32::15", type: "AAAA" },
                  { rrdata: "2001:4860:4802:34::15", type: "AAAA" },
                  { rrdata: "2001:4860:4802:36::15", type: "AAAA" },
                  { rrdata: "2001:4860:4802:38::15", type: "AAAA" },
                ],
          },
        });
      }
      if (url.hostname === "runsetta.com" || url.hostname === "www.runsetta.com") {
        return new Response(
          JSON.stringify({
            environment: "production",
            ok: true,
            openaiConfigured: false,
            service: "runsetta",
            spotifyConfigured: false,
          }),
          { headers: { "content-type": "application/json; charset=utf-8" }, status: 200 },
        );
      }
      return new Response("", { status: 500 });
    };
    const proof = await proveExposure(
      invocation,
      "short-lived-executor-access-token-value",
      fetcher,
    );
    expect(proof?.state.state).toBe("absent");
    expect(proof?.mappingListCount).toBe(2);
    expect(proof?.mappings.map(({ domain }) => domain)).toEqual([
      "runsetta.com",
      "www.runsetta.com",
    ]);
    expect(proof?.https).toHaveLength(2);
    expect(urls.filter((url) => url.includes("run.googleapis.com"))).toHaveLength(3);
    expect(urls.some((url) => url.startsWith("https://run.googleapis.com/"))).toBeFalse();

    await expect(proveExposure(
      invocation,
      "short-lived-executor-access-token-value",
      async (input) => {
        const url = new URL(String(input));
        if (url.hostname === "storage.googleapis.com") return new Response("", { status: 404 });
        if (url.pathname.endsWith("/domainmappings")) {
          return Response.json({
            apiVersion: "domains.cloudrun.com/v1",
            items: [],
            kind: "DomainMappingList",
            metadata: {
              selfLink: "/apis/domains.cloudrun.com/v1/namespaces/601124730704/domainmappings",
            },
          });
        }
        return new Response("", { status: 500 });
      },
    )).rejects.toThrow("missing or foreign domains");

    await expect(proveExposure(
      invocation,
      "short-lived-executor-access-token-value",
      async (input, init) => {
        const url = new URL(String(input));
        const response = await fetcher(input, init);
        if (url.hostname !== "us-east4-run.googleapis.com" ||
          !url.pathname.endsWith("/domainmappings")) return response;
        const value = await response.json() as Record<string, unknown>;
        return Response.json({
          ...value,
          metadata: { ...(value.metadata as object), continue: "hidden-next-page" },
        });
      },
    )).rejects.toThrow("continuation page");

    await expect(proveExposure(
      invocation,
      "short-lived-executor-access-token-value",
      async (input, init) => {
        const url = new URL(String(input));
        const response = await fetcher(input, init);
        if (url.hostname !== "us-east4-run.googleapis.com" ||
          !url.pathname.endsWith("/domainmappings")) return response;
        const value = await response.json() as Record<string, unknown>;
        return Response.json({ ...value, unreachable: ["us-west1"] });
      },
    )).rejects.toThrow("unreachable resources");

    await expect(proveExposure(
      invocation,
      "short-lived-executor-access-token-value",
      async (input, init) => {
        const url = new URL(String(input));
        const response = await fetcher(input, init);
        if (
          url.hostname !== "us-east4-run.googleapis.com" ||
          url.pathname.endsWith("/domainmappings")
        ) return response;
        const value = await response.json() as Record<string, unknown>;
        return Response.json({
          ...value,
          spec: { ...(value.spec as object), forceOverride: true },
        });
      },
    )).rejects.toThrow("forceOverride is enabled");

    await expect(proveExposure(
      invocation,
      "short-lived-executor-access-token-value",
      async (input, init) => {
        const url = new URL(String(input));
        const response = await fetcher(input, init);
        if (
          url.hostname !== "us-east4-run.googleapis.com" ||
          url.pathname.endsWith("/domainmappings")
        ) return response;
        const value = await response.json() as Record<string, unknown>;
        const status = value.status as { conditions: unknown[] };
        return Response.json({
          ...value,
          status: { ...status, conditions: [...status.conditions, status.conditions[0]] },
        });
      },
    )).rejects.toThrow("duplicate condition type");
  });

  test("exposure state initialization is exact, generation-bound, and idempotent", async () => {
    const invocation = validateInvocation({
      ...validEnvironment(),
      EXPOSURE_ADOPTION_CONFIRMATION: "ADOPT_RUNSETTA_EXPOSURE_STATE",
      TARGET_REPOSITORY: "runsetta",
      TERRAFORM_ROOT: "exposure",
    });
    const lineage = "123e4567-e89b-42d3-a456-426614174000";
    let stored: string | undefined;
    let generation = "9";
    let uploads = 0;
    const fetcher = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      const liveResponse = runsettaExposureApiResponse(url);
      if (liveResponse !== undefined) return liveResponse;
      if (url.pathname.startsWith("/upload/storage/v1/")) {
        uploads += 1;
        expect(init?.method).toBe("POST");
        expect(url.searchParams.get("ifGenerationMatch")).toBe("0");
        expect(url.searchParams.get("name")).toBe("runsetta/exposure/default.tfstate");
        stored = String(init?.body);
        return Response.json({
          bucket: "runsetta-tfstate-601124730704-bootstrap",
          generation,
          name: "runsetta/exposure/default.tfstate",
          size: String(Buffer.byteLength(stored)),
        });
      }
      if (stored === undefined) return new Response("", { status: 404 });
      if (url.searchParams.get("alt") === "media") {
        expect(url.searchParams.get("ifGenerationMatch")).toBe(generation);
        return new Response(stored);
      }
      return Response.json({
        bucket: "runsetta-tfstate-601124730704-bootstrap",
        generation,
        metageneration: "1",
        name: "runsetta/exposure/default.tfstate",
        size: String(Buffer.byteLength(stored)),
      });
    };
    const created = await ensureExposureStateInitialized(
      invocation,
      "short-lived-executor-access-token-value",
      "google-owner-access-token-value",
      exposureProofFixture("runsetta", "unadopted"),
      fetcher,
      async () => undefined,
      Date.now() + 60_000,
      () => lineage,
    );
    expect(created.state).toMatchObject({ generation: "9", lineage, serial: 1, state: "present" });
    expect(stored).toBe(canonicalRunsettaExposureState(lineage));
    const existingProof = await proveExposure(
      invocation,
      "short-lived-executor-access-token-value",
      fetcher,
      "google-owner-access-token-value",
    );
    expect(existingProof).not.toBeNull();
    const existing = await ensureExposureStateInitialized(
      invocation,
      "short-lived-executor-access-token-value",
      "google-owner-access-token-value",
      existingProof!,
      fetcher,
      async () => undefined,
      Date.now() + 60_000,
      () => "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    );
    expect(existing.state.generation).toBe("9");
    expect(uploads).toBe(1);

    stored = undefined;
    generation = "10";
    await expect(ensureExposureStateInitialized(
      invocation,
      "short-lived-executor-access-token-value",
      "google-owner-access-token-value",
      exposureProofFixture("runsetta", "unadopted"),
      async (input, init) => {
        const url = new URL(String(input));
        const liveResponse = runsettaExposureApiResponse(url);
        if (liveResponse !== undefined) return liveResponse;
        if (url.pathname.startsWith("/upload/storage/v1/")) {
          stored = String(init?.body);
          return Response.json({
            bucket: "runsetta-tfstate-601124730704-bootstrap",
            generation: "9",
            name: "runsetta/exposure/default.tfstate",
            size: String(Buffer.byteLength(stored)),
          });
        }
        if (url.searchParams.get("alt") === "media") return new Response(stored);
        if (stored === undefined) return new Response("", { status: 404 });
        return Response.json({
          bucket: "runsetta-tfstate-601124730704-bootstrap",
          generation,
          metageneration: "1",
          name: "runsetta/exposure/default.tfstate",
          size: String(Buffer.byteLength(stored)),
        });
      },
      async () => undefined,
      Date.now() + 60_000,
      () => lineage,
    )).rejects.toThrow("created exposure state generation drifted");
  });

  test("exposure initialization accepts only its exact bytes after 412 or response loss", async () => {
    const invocation = validateInvocation({
      ...validEnvironment(),
      EXPOSURE_ADOPTION_CONFIRMATION: "ADOPT_RUNSETTA_EXPOSURE_STATE",
      TARGET_REPOSITORY: "runsetta",
      TERRAFORM_ROOT: "exposure",
    });
    const lineage = "123e4567-e89b-42d3-a456-426614174000";
    const different = canonicalRunsettaExposureState(
      "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    );
    const run = async (failure: "lost" | "precondition", sameBytes: boolean) => {
      let object: string | undefined;
      let attempted = false;
      return ensureExposureStateInitialized(
        invocation,
        "short-lived-executor-access-token-value",
        "google-owner-access-token-value",
        exposureProofFixture("runsetta", "unadopted"),
        async (input, init) => {
          const url = new URL(String(input));
          const liveResponse = runsettaExposureApiResponse(url);
          if (liveResponse !== undefined) return liveResponse;
          if (url.pathname.startsWith("/upload/storage/v1/")) {
            attempted = true;
            object = sameBytes ? String(init?.body) : different;
            if (failure === "lost") throw new TypeError("fetch failed after commit");
            return new Response("", { status: 412 });
          }
          if (!attempted) return new Response("", { status: 404 });
          if (url.searchParams.get("alt") === "media") return new Response(object);
          return Response.json({
            bucket: "runsetta-tfstate-601124730704-bootstrap",
            generation: "11",
            metageneration: "1",
            name: "runsetta/exposure/default.tfstate",
            size: String(Buffer.byteLength(object!)),
          });
        },
        async () => undefined,
        Date.now() + 60_000,
        () => lineage,
      );
    };
    await expect(run("precondition", true)).resolves.toMatchObject({
      state: {
        generation: "11",
        lineage,
        state: "present",
      },
    });
    await expect(run("precondition", false)).rejects.toThrow("raced exposure state lineage");
    await expect(run("lost", false)).rejects.toThrow("raced exposure state lineage");
  });

  test("production lease is object-only and cannot reach bootstrap or access-log buckets", () => {
    const lease = buildStorageLease(
      "healthmcp",
      "prod",
      "987654",
      new Date("2026-08-22T22:00:00.000Z"),
      "gha-pbt-0123456789abcdefabcd@medlock-1025243085.iam.gserviceaccount.com",
      "apply",
      "987653",
    );
    expect(lease.role).toBe("roles/storage.objectAdmin");
    expect(lease.condition.expression).toContain(
      "projects/_/buckets/medlock-tfstate-1025243085/objects/medlock/prod/default.tfstate",
    );
    expect(lease.condition.expression).toContain(
      "projects/_/buckets/medlock-tfstate-1025243085/objects/medlock/prod/default.tflock",
    );
    expect(lease.condition.expression).not.toContain("medlock-tfstate-1025243085-bootstrap");
    expect(lease.condition.expression).not.toContain("-access-logs");
  });

  test("exposure adoption identity is fixed and its executor receives read-only state access", () => {
    expect(REPOSITORIES.runsetta.exposure).toEqual({
      domains: ["runsetta.com", "www.runsetta.com"],
      projectNumber: "601124730704",
      region: "us-east4",
      serviceName: "runsetta",
    });
    expect(REPOSITORIES.healthmcp.repositoryId).toBe("1025243085");
    expect(REPOSITORIES.healthmcp.exposure.projectNumber).toBe("229383559510");
    expect(REPOSITORIES.healthmcp.exposure.projectNumber).not.toBe(
      REPOSITORIES.healthmcp.repositoryId,
    );
    const expiration = new Date("2026-08-26T22:00:00.000Z");
    const email = "gha-pbt-0123456789abcdefabcd@runsetta.iam.gserviceaccount.com";
    const leases = buildStorageAcquisitionLeases(
      "runsetta",
      "exposure",
      "plan",
      "123456",
      expiration,
      email,
    );
    expect(leases.map(({ role }) => role)).toEqual(["roles/storage.objectViewer"]);
    expect(leases[0]!.condition.expression).toContain("runsetta/exposure/default.tfstate");
    expect(leases[0]!.condition.expression).not.toContain("default.tflock");
    expect(leases[0]!.condition.expression).not.toContain("runsetta/prod");
    expect(executorControlPermissions("runsetta", "exposure", "read")).toEqual([]);
    expect(executorControlPermissions("runsetta", "exposure", "mutation")).toEqual([]);
  });

  test("Runsetta adoption separates executor read from owner create-only state authority", () => {
    const expiration = new Date("2026-08-26T22:00:00.000Z");
    const creator = buildExposureControllerCreateLease("123456", expiration);
    expect(creator).toEqual({
      condition: {
        description: "Controller may create only the absent canonical Runsetta exposure state.",
        expression:
          "request.time < timestamp('2026-08-26T22:00:00.000Z') && " +
          "resource.type == 'storage.googleapis.com/Object' && " +
          "resource.name == 'projects/_/buckets/runsetta-tfstate-601124730704-bootstrap/objects/runsetta/exposure/default.tfstate'",
        title: "codex-controller-exposure-create-123456",
      },
      members: ["user:CollinBentley1@gmail.com"],
      role: "roles/storage.objectCreator",
    });
    const executorRead = buildStorageAcquisitionLeases(
      "runsetta",
      "exposure",
      "plan",
      "123456",
      expiration,
      "gha-pbt-0123456789abcdefabcd@runsetta.iam.gserviceaccount.com",
    );
    expect(executorRead).toHaveLength(1);
    expect(executorRead[0]?.role).toBe("roles/storage.objectViewer");
    expect(executorRead[0]?.members).toEqual([
      "serviceAccount:gha-pbt-0123456789abcdefabcd@runsetta.iam.gserviceaccount.com",
    ]);
    expect(executorRead[0]?.condition.expression).toContain(
      "runsetta/exposure/default.tfstate",
    );
    expect(executorRead[0]?.condition.expression).not.toContain("roles/viewer");
    expect(creator.condition.expression).not.toContain("default.tflock");
    expect(creator.condition.expression).not.toContain("/plans/");

    expect(exposureControllerCreateLeaseOrUndefined(creator, "123456")).toEqual(creator);
    expect(exposureControllerCreateLeaseOrUndefined({
      ...creator,
      members: ["user:attacker@example.com"],
    }, "123456")).toBeUndefined();
    expect(() => requireExposureControllerCreateLeaseCandidate({
      ...creator,
      members: ["user:attacker@example.com"],
    }, "123456")).toThrow("title was reused with altered authority");
    const unrelated: IamBinding = {
      members: ["user:unrelated@example.com"],
      role: "roles/viewer",
    };
    const executorLease: IamBinding = {
      condition: {
        description: "temporary test lease",
        expression: "request.time < timestamp('2026-08-26T22:00:00.000Z')",
        title: "temporary-executor-lease",
      },
      members: [
        "serviceAccount:gha-pbt-0123456789abcdefabcd@runsetta.iam.gserviceaccount.com",
      ],
      role: "roles/storage.objectViewer",
    };
    const cleaned = removeDeterministicExecutorMembers(
      { bindings: [unrelated, executorLease, creator], etag: "etag-1", version: 3 },
      "gha-pbt-0123456789abcdefabcd@runsetta.iam.gserviceaccount.com",
      "123456",
    );
    expect(cleaned.bindings).toEqual([unrelated]);
    expect(removeDeterministicExecutorMembers(
      { bindings: [unrelated, creator], etag: "etag-1", version: 3 },
      "gha-pbt-0123456789abcdefabcd@runsetta.iam.gserviceaccount.com",
    ).bindings).toEqual([unrelated, creator]);
  });

  test("conditional IAM readback requires exact absence and rejects title reuse", async () => {
    const lease = buildStorageReadLease(
      "runsetta",
      "exposure",
      "123456",
      new Date("2026-08-26T22:00:00.000Z"),
      "gha-pbt-0123456789abcdefabcd@runsetta.iam.gserviceaccount.com",
    );
    const response = (bindings: IamPolicy["bindings"]): Response => Response.json({
      bindings,
      etag: "policy-etag",
      version: 3,
    });
    await expect(requireLeaseAbsentWithReadback(
      "runsetta",
      "owner-token-value",
      lease,
      async () => response([]),
    )).resolves.toBeUndefined();
    await expect(requireLeaseAbsentWithReadback(
      "runsetta",
      "owner-token-value",
      lease,
      async () => response([{
        ...lease,
        condition: { ...lease.condition, expression: "request.time < timestamp('2026-08-26T22:01:00Z')" },
      }]),
    )).rejects.toThrow("lease title was reused with altered authority");
    let nowMs = 1_000;
    let reads = 0;
    await expect(requireLeaseAbsentWithReadback(
      "runsetta",
      "owner-token-value",
      lease,
      async () => {
        reads += 1;
        return response([lease]);
      },
      async (milliseconds) => {
        nowMs += milliseconds;
      },
      5_000,
      () => nowMs,
    )).rejects.toThrow("lease removal did not become observable");
    expect(reads).toBeGreaterThan(1);
  });

  test("Storage read/create roles are inventory-pinned and contain no overwrite or delete", async () => {
    const inventories = {
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
    for (const [role, permissions] of Object.entries(inventories)) {
      expect(() => validateStorageBackendRolePermissionInventory(
        role as keyof typeof inventories,
        permissions,
      )).not.toThrow();
    }
    expect(() => validateStorageBackendRolePermissionInventory(
      "roles/storage.objectCreator",
      [...inventories["roles/storage.objectCreator"], "storage.objects.delete"],
    )).toThrow("permission inventory drifted");
    const seen: string[] = [];
    await requireStorageBackendRoleContracts(
      "owner-token-value",
      async (input) => {
        const role = new URL(String(input)).pathname.slice(4) as keyof typeof inventories;
        seen.push(role);
        return Response.json({
          includedPermissions: inventories[role],
          name: role,
          stage: "GA",
        });
      },
    );
    expect(seen.toSorted()).toEqual(Object.keys(inventories).toSorted());
  });

  test("executor roles are exact per root and prod actAs is only the three runtime accounts", () => {
    const expiration = new Date("2026-08-22T22:00:00.000Z");
    const bootstrapRoles = buildExecutorProjectLeases(
      "cdbentley",
      "88",
      expiration,
      executorEmail,
      "projects/cdbentley/roles/pbt_r_0123456789abcdefabcd",
      "read",
    ).map((binding) => binding.role);
    expect(bootstrapRoles).toEqual([
      "projects/cdbentley/roles/pbt_r_0123456789abcdefabcd",
    ]);
    const healthExecutor =
      "gha-pbt-0123456789abcdefabcd@medlock-1025243085.iam.gserviceaccount.com";
    const prodRoles = buildExecutorProjectLeases(
      "healthmcp",
      "89",
      expiration,
      healthExecutor,
      "projects/medlock-1025243085/roles/pbt_m_0123456789abcdefabcd",
      "mutation",
    ).map((binding) => binding.role);
    expect(prodRoles).toEqual([
      "projects/medlock-1025243085/roles/pbt_m_0123456789abcdefabcd",
    ]);
    const actAs = buildRuntimeActAsLeases("healthmcp", "89", expiration, healthExecutor);
    expect(Object.keys(actAs).toSorted()).toEqual([
      "cloud-run-bootstrap@medlock-1025243085.iam.gserviceaccount.com",
      "cloud-run-preview@medlock-1025243085.iam.gserviceaccount.com",
      "cloud-run-runtime@medlock-1025243085.iam.gserviceaccount.com",
    ]);
    for (const binding of Object.values(actAs)) {
      expect(binding.role).toBe("roles/iam.serviceAccountUser");
      expect(binding.members).toEqual([
        `serviceAccount:${healthExecutor}`,
      ]);
    }
    expect(buildTokenCreatorLease("cdbentley", "89", expiration).members).toEqual([
      "user:CollinBentley1@gmail.com",
    ]);
  });

  test("IAM transformations preserve latest policy data and remove only the exact lease", () => {
    const lease = buildStorageReadLease(
      "runsetta",
      "prod",
      "42",
      new Date("2026-08-22T22:00:00.000Z"),
      "gha-pbt-0123456789abcdefabcd@runsetta.iam.gserviceaccount.com",
    );
    const policy: IamPolicy = {
      auditConfigs: [{ service: "allServices" }],
      bindings: [{ members: ["user:someone@example.com"], role: "roles/viewer" }],
      etag: "BwY=",
      version: 1,
    };
    const added = addExactLease(policy, lease);
    expect(added.etag).toBe("BwY=");
    expect(added.version).toBe(3);
    expect(added.auditConfigs).toEqual(policy.auditConfigs);
    expect(added.bindings).toEqual([...policy.bindings, lease]);
    expect(addExactLease(added, lease)).toBe(added);

    const latest: IamPolicy = {
      ...added,
      bindings: [
        ...added.bindings,
        { members: ["serviceAccount:new@example.com"], role: "roles/logging.viewer" },
      ],
      etag: "BwZ=",
    };
    const removed = removeExactLease(latest, lease);
    expect(removed.etag).toBe("BwZ=");
    expect(removed.bindings).toEqual([
      policy.bindings[0],
      { members: ["serviceAccount:new@example.com"], role: "roles/logging.viewer" },
    ]);
    expect(removeExactLease(removed, lease)).toBe(removed);
  });

  test("condition-title collisions fail closed without modifying IAM", () => {
    const lease = buildStorageReadLease(
      "critical-history",
      "prod",
      "77",
      new Date("2026-08-22T22:00:00.000Z"),
      "gha-pbt-0123456789abcdefabcd@critical-history-16823277.iam.gserviceaccount.com",
    );
    const policy: IamPolicy = {
      bindings: [
        {
          condition: {
            ...lease.condition,
            expression: "request.time < timestamp('2099-01-01T00:00:00.000Z')",
          },
          members: [...lease.members],
          role: lease.role,
        },
      ],
      etag: "etag",
      version: 3,
    };
    expect(() => addExactLease(policy, lease)).toThrow("condition-title collision");
    expect(() => removeExactLease(policy, lease)).toThrow("changed and cannot be safely removed");
  });

  test("multi-binding cleanup retains a v3 request payload and preserves audit config", () => {
    const original: IamPolicy = {
      auditConfigs: [{ service: "allServices" }],
      bindings: [{ members: ["user:reader@example.com"], role: "roles/viewer" }],
      etag: "before",
      version: 1,
    };
    const leases = buildExecutorProjectLeases(
      "cdbentley",
      "501",
      new Date("2026-08-22T22:00:00.000Z"),
      executorEmail,
      "projects/cdbentley/roles/pbt_r_0123456789abcdefabcd",
      "read",
    );
    const added = addExactBindings(original, leases);
    expect(added.version).toBe(3);
    const cleaned = removeExactBindings({ ...added, etag: "latest" }, leases, original);
    expect(cleaned).toEqual({ ...original, etag: "latest", version: 3 });
  });

  test("IAM API writes use the fetched etag, retry CAS conflicts, and clean the latest policy", async () => {
    const lease = buildStorageReadLease(
      "cdbentley",
      "prod",
      "9001",
      new Date("2026-08-22T22:00:00.000Z"),
      executorEmail,
    );
    const unrelated = { members: ["user:reader@example.com"], role: "roles/viewer" };
    let current: IamPolicy = {
      bindings: [unrelated],
      etag: "etag-1",
      version: 1,
    };
    let setAttempts = 0;
    const fetcher = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      if (url.pathname.endsWith(":getIamPolicy")) {
        expectProjectIamPolicyRead(input, init);
        return Response.json(current);
      }
      expect(url.pathname).toEndWith(":setIamPolicy");
      const request = JSON.parse(String(init?.body)) as { policy: IamPolicy };
      expect(request.policy.etag).toBe(current.etag);
      setAttempts += 1;
      if (setAttempts === 1) {
        current = { ...current, etag: "etag-concurrent" };
        return new Response("", { status: 412 });
      }
      current = {
        ...request.policy,
        bindings: [...request.policy.bindings],
        etag: `etag-${setAttempts + 1}`,
      };
      return Response.json(current);
    };

    await addLeaseWithCas("cdbentley", "opaque-google-token", lease, fetcher);
    expect(setAttempts).toBe(2);
    expect(current.bindings).toEqual([unrelated, lease]);
    current = {
      ...current,
      bindings: [
        ...current.bindings,
        { members: ["serviceAccount:new@example.com"], role: "roles/logging.viewer" },
      ],
      etag: "etag-latest",
    };
    await removeLeaseWithCas("cdbentley", "opaque-google-token", lease, fetcher);
    expect(current.bindings).toEqual([
      unrelated,
      { members: ["serviceAccount:new@example.com"], role: "roles/logging.viewer" },
    ]);
  });

  test("cleanup removes a timed-out IAM add that commits after its first cleanup read", async () => {
    const unrelated = { members: ["user:reader@example.com"], role: "roles/viewer" };
    const original: IamPolicy = {
      auditConfigs: [{ service: "allServices" }],
      bindings: [unrelated],
      etag: "etag-0",
      version: 1,
    };
    const lease = buildStorageReadLease(
      "cdbentley",
      "prod",
      "8181",
      new Date("2026-08-22T22:00:00.000Z"),
      executorEmail,
    );
    const lateCommit = { ...addExactBindings(original, [lease]), etag: "etag-1" };
    let current = original;
    let sleeps = 0;
    let generation = 1;
    let droppedFirstFenceResponse = false;
    await fencePolicyMutations(
      [{
        get: async () => current,
        label: "mock project",
        leases: [lease],
        original,
        set: async (policy) => {
          expect(policy.etag).toBe(current.etag);
          const isFenceAdd = policy.bindings.some((binding) =>
            binding.condition?.title.startsWith("codex-cleanup-fence-")
          );
          if (isFenceAdd && !droppedFirstFenceResponse) {
            droppedFirstFenceResponse = true;
            return undefined;
          }
          generation += 1;
          current = { ...policy, etag: `etag-${generation}` };
          return current;
        },
      }],
      async () => {
        sleeps += 1;
        if (sleeps === 1) current = lateCommit;
      },
      Date.now() + 60_000,
      () => "0123456789abcdefabcd",
    );
    expect(current.bindings).toEqual([unrelated]);
    expect(current.auditConfigs).toEqual(original.auditConfigs);
    expect(current.version).toBe(3);
    expect(current.etag).not.toBe(original.etag);
    expect(sleeps).toBeGreaterThanOrEqual(4);
  });

  test("random executor identities and custom control roles exclude data-plane permissions", () => {
    expect(randomExecutorAccountId("0123456789abcdefabcd")).toBe(
      "gha-pbt-0123456789abcdefabcd",
    );
    expect(randomExecutorRoleId("read", "0123456789abcdefabcd")).toBe(
      "pbt_r_0123456789abcdefabcd",
    );
    expect(randomExecutorRoleId("mutation", "fedcba9876543210fedc")).toBe(
      "pbt_m_fedcba9876543210fedc",
    );
    expect(() => randomExecutorAccountId("0".repeat(19))).toThrow("randomness");
    const attestationReadPermission = "iam.workloadIdentityPools.getAttestationRules";
    expect(
      executorControlPermissions("cdbentley", "bootstrap", "read")
        .filter((permission) => permission === attestationReadPermission),
    ).toEqual([attestationReadPermission]);
    expect(
      executorControlPermissions("cdbentley", "bootstrap", "mutation")
        .filter((permission) => permission === attestationReadPermission),
    ).toEqual([attestationReadPermission]);
    expect(executorControlPermissions("cdbentley", "prod", "read")).not.toContain(
      attestationReadPermission,
    );
    const prod = executorControlPermissions("healthmcp", "prod", "mutation");
    for (const forbidden of [
      "artifactregistry.files.download",
      "artifactregistry.repositories.downloadArtifacts",
      "artifactregistry.repositories.uploadArtifacts",
      "datastore.entities.get",
      "datastore.entities.list",
      "datastore.entities.update",
      "secretmanager.versions.access",
      "secretmanager.versions.add",
    ]) {
      expect(prod).not.toContain(forbidden);
    }
    expect(prod).toContain("run.services.update");
    expect(prod).toContain("secretmanager.secrets.setIamPolicy");
    expect(prod).toContain("datastore.databases.update");
  });

  // Terraform fixes the ordering of none of the plan's lists. The digest must
  // therefore be invariant under permutation of every one of them, not only
  // resource_changes -- which is all the determinism test below shuffles.
  //
  // Live: cdbentley bootstrap plans 33288435770 and 33289064233, eight minutes
  // apart over an unchanged world at the same platform and consumer SHAs. Every
  // resource change, every drift entry, `source`, `checksSha256`,
  // `outputChanges` and `variables` were byte-identical; `relevant_attributes`
  // came back in a different order and the manifest hashed differently, so the
  // apply would have refused its own approved plan.
  test("the digest is invariant under the ordering of every unordered plan list", () => {
    const attributes = [
      { attribute: ["etag"], resource: "module.bootstrap.google_project_iam_member.reader" },
      { attribute: ["member"], resource: "module.bootstrap.google_service_account.prod_deploy" },
      { attribute: ["role"], resource: "module.bootstrap.google_project_iam_custom_role.deployer" },
    ];
    const checks = [
      { address: { kind: "check", to_display: "check.a" }, problems: [], status: "pass" },
      { address: { kind: "check", to_display: "check.b" }, problems: [], status: "pass" },
    ];
    const changes = [
      resourceChange(
        "module.bootstrap.google_project_iam_member.reader",
        "google_project_iam_member",
        { etag: "BwOne", member: "serviceAccount:a@cdbentley.iam.gserviceaccount.com", role: "roles/viewer" },
        { etag: "BwOne", member: "serviceAccount:a@cdbentley.iam.gserviceaccount.com", role: "roles/viewer" },
      ),
    ];
    const drift = [
      resourceChange(
        "module.bootstrap.google_service_account_iam_member.prod_deploy_wif_repo",
        "google_service_account_iam_member",
        { etag: "BwStale", member: "serviceAccount:b@cdbentley.iam.gserviceaccount.com", role: "roles/iam.workloadIdentityUser" },
        { etag: "BwFresh", member: "serviceAccount:b@cdbentley.iam.gserviceaccount.com", role: "roles/iam.workloadIdentityUser" },
      ),
    ];
    const build = (attrs: unknown[], chks: unknown[]) => {
      const raw = plan(changes, drift) as Record<string, unknown>;
      raw.relevant_attributes = attrs;
      raw.checks = chks;
      return buildReviewManifest(raw, { ...identity(), terraformRoot: "bootstrap" as const });
    };
    const ordered = build(attributes, checks);
    const reversed = build([...attributes].reverse(), [...checks].reverse());
    const rotated = build([attributes[2], attributes[0], attributes[1]], checks);
    expect(reversed.sha256).toBe(ordered.sha256);
    expect(rotated.sha256).toBe(ordered.sha256);

    // Ordering is normalized; membership is still bound.
    const removed = build(attributes.slice(0, 2), checks);
    expect(removed.sha256).not.toBe(ordered.sha256);
    const altered = build(
      [{ attribute: ["etag"], resource: "module.bootstrap.google_project_iam_member.OTHER" }, ...attributes.slice(1)],
      checks,
    );
    expect(altered.sha256).not.toBe(ordered.sha256);
    const failingCheck = build(attributes, [
      { address: { kind: "check", to_display: "check.a" }, problems: [], status: "fail" },
      checks[1],
    ]);
    expect(failingCheck.sha256).not.toBe(ordered.sha256);

    // The count is published so a mismatch here is readable off the manifest
    // rather than requiring a field-by-field diff of two step summaries.
    const published = JSON.parse(ordered.canonical) as {
      plan: { relevantAttributesCount: number; checksCount: number };
    };
    expect(published.plan.relevantAttributesCount).toBe(3);
    expect(published.plan.checksCount).toBe(2);
  });

  test("review digest is deterministic and binds exact full change semantics and sources", () => {
    const first = buildReviewManifest(
      plan([
        resourceChange(
          "module.site.google_cloud_run_v2_service.preview",
          "google_cloud_run_v2_service",
          { ingress: "INGRESS_TRAFFIC_ALL", project: "cdbentley" },
          { ingress: "INGRESS_TRAFFIC_INTERNAL_ONLY", project: "cdbentley" },
        ),
        resourceChange(
          "module.site.google_artifact_registry_repository.preview",
          "google_artifact_registry_repository",
          { immutable: false, project: "cdbentley" },
          { immutable: true, project: "cdbentley" },
        ),
      ]),
      identity(),
    );
    const second = buildReviewManifest(
      plan([
        resourceChange(
          "module.site.google_artifact_registry_repository.preview",
          "google_artifact_registry_repository",
          { immutable: false, project: "cdbentley" },
          { immutable: true, project: "cdbentley" },
        ),
        resourceChange(
          "module.site.google_cloud_run_v2_service.preview",
          "google_cloud_run_v2_service",
          { ingress: "INGRESS_TRAFFIC_ALL", project: "cdbentley" },
          { ingress: "INGRESS_TRAFFIC_INTERNAL_ONLY", project: "cdbentley" },
        ),
      ]),
      identity(),
    );
    expect(first).toEqual(second);
    expect(first.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(first.canonical).not.toContain('"INGRESS_TRAFFIC_INTERNAL_ONLY"');
    expect(first.canonical).toContain('"afterSha256"');
    expect(first.canonical).toContain(`"consumerSha":"${consumerSha}"`);
    expect(first.canonical).toContain(`"consumerTreeSha":"${consumerTreeSha}"`);
    expect(first.canonical).toContain('"approvalMode":"plan"');
    expect(first.canonical).toContain('"legacyCompatibilityMode":false');
    expect(first.canonical).toContain('"transitionWorkflowSha":null');

    const changed = buildReviewManifest(
      plan([
        resourceChange(
          "module.site.google_cloud_run_v2_service.preview",
          "google_cloud_run_v2_service",
          { ingress: "INGRESS_TRAFFIC_ALL", project: "cdbentley" },
          { ingress: "INGRESS_TRAFFIC_ALL", project: "cdbentley" },
        ),
      ]),
      identity(),
    );
    expect(changed.sha256).not.toBe(first.sha256);

    const migration = buildReviewManifest(plan([]), {
      ...identity(),
      legacyCompatibilityMode: true,
      terraformRoot: "bootstrap",
      transitionWorkflowSha: "",
    });
    const transition = buildReviewManifest(plan([]), {
      ...identity(),
      terraformRoot: "bootstrap",
      tokenDrainSeconds: 300,
      transitionWorkflowSha: "d".repeat(40),
    });
    expect(migration.sha256).not.toBe(transition.sha256);
    expect(migration.canonical).toContain('"legacyCompatibilityMode":true');
    expect(transition.canonical).toContain('"legacyCompatibilityMode":false');
    expect(transition.canonical).toContain(`"transitionWorkflowSha":"${"d".repeat(40)}"`);
    expect(() => buildReviewManifest(plan([]), {
      ...identity(),
      legacyCompatibilityMode: true,
      terraformRoot: "bootstrap",
      transitionWorkflowSha: "d".repeat(40),
    })).toThrow("cannot combine");
  });

  test("Runsetta adoption requires exactly two complete no-op resources and a non-applyable plan", () => {
    const exactChanges = [
      exposureDomainChange("runsetta.com", false),
      exposureDomainChange("www.runsetta.com", false),
    ];
    const adoption = exposureAdoptionPlan(exactChanges);
    const review = buildReviewManifest(adoption, exposureIdentity("runsetta", "adopted"));
    expect(review.canonical).toContain('"approvalMode":"adoption"');
    expect(review.canonical).toContain('"resourceChangesCount":2');
    expect(review.canonical).toContain('"applyable":false');

    const missing = exposureAdoptionPlan([exactChanges[0]]);
    expect(() => buildReviewManifest(missing, exposureIdentity("runsetta", "adopted")))
      .toThrow("exactly both Runsetta domain mappings");

    const importPlan = exposureAdoptionPlan([
      exposureDomainChange("runsetta.com", true),
      exposureDomainChange("www.runsetta.com", true),
    ]);
    expect(() => buildReviewManifest(importPlan, exposureIdentity("runsetta", "adopted")))
      .toThrow("without import identity");

    const applyable = exposureAdoptionPlan(exactChanges);
    applyable.applyable = true;
    expect(() => buildReviewManifest(applyable, exposureIdentity("runsetta", "adopted")))
      .toThrow("applyability drifted");

    const drift = exposureAdoptionPlan(exactChanges);
    drift.resource_drift = [exactChanges[0]];
    expect(() => buildReviewManifest(drift, exposureIdentity("runsetta", "adopted")))
      .toThrow("resource drift count drifted");

    const unknown = exposureAdoptionPlan(structuredClone(exactChanges));
    (unknown.resource_changes as typeof exactChanges)[0]!.change.after_unknown = { id: true };
    expect(() => buildReviewManifest(unknown, exposureIdentity("runsetta", "adopted")))
      .toThrow("unknown value map contains a sensitive value");

    const relevantDrift = exposureAdoptionPlan(exactChanges);
    relevantDrift.relevant_attributes = [{
      attribute: ["id"],
      resource: "module.domains.google_cloud_run_domain_mapping.site",
    }];
    expect(() => buildReviewManifest(relevantDrift, exposureIdentity("runsetta", "adopted")))
      .toThrow("relevant attribute contract");

    const outputDrift = exposureAdoptionPlan(exactChanges);
    delete (outputDrift.output_changes as Record<string, unknown>).preview_url_pattern;
    expect(() => buildReviewManifest(outputDrift, exposureIdentity("runsetta", "adopted")))
      .toThrow("exposure output change names drifted");
  });

  test("initial bootstrap review requires the one exact absent-to-clear marker creation", () => {
    const marker = resourceChange(
      "module.bootstrap.google_storage_bucket_object.deployment_parity_transition",
      "google_storage_bucket_object",
      null,
      {
        bucket: "cdbentley-deployment-parity-state",
        content: "{\"version\":1}\n",
        content_type: "application/json",
        metadata: { "repository-id": "1255553151", state: "clear", version: "1" },
        name: "deployment-parity-transition",
      },
    );
    marker.change.actions = ["create"];
    const initialIdentity: PlanIdentity = {
      ...identity(),
      legacyCompatibilityMode: true,
      markerProof: markers("absent"),
      terraformRoot: "bootstrap",
    };
    expect(buildReviewManifest(plan([marker]), initialIdentity).canonical).toContain(
      "google_storage_bucket_object.deployment_parity_transition",
    );
    expect(() => buildReviewManifest(plan([]), initialIdentity)).toThrow(
      "did not create the exact deployment-parity marker",
    );
    const foreign = structuredClone(marker);
    foreign.address = "module.bootstrap.google_storage_bucket_object.foreign";
    foreign.name = "foreign";
    expect(() => buildReviewManifest(plan([foreign]), initialIdentity)).toThrow(
      "marker address drifted",
    );
    const destructive = structuredClone(marker);
    destructive.change.actions = ["delete"];
    expect(() => buildReviewManifest(plan([destructive]), initialIdentity)).toThrow(
      "initial deployment-parity marker action drifted",
    );
  });

  test("provider sensitivity on the parity marker admits only the declared bytes", () => {
    // Terraform flags `google_storage_bucket_object.content` from the provider
    // schema on every plan. `resourceChange` models `after_sensitive` as an
    // empty map, so before this test nothing exercised the shape a real plan
    // actually has -- and the bridge aborted on its own parity marker the first
    // time it reached a live `terraform plan`.
    const marker = () => {
      const change = resourceChange(
        "module.bootstrap.google_storage_bucket_object.deployment_parity_transition",
        "google_storage_bucket_object",
        null,
        {
          bucket: "cdbentley-deployment-parity-state",
          content: "{\"version\":1}\n",
          content_type: "application/json",
          metadata: { "repository-id": "1255553151", state: "clear", version: "1" },
          name: "deployment-parity-transition",
        },
      );
      change.change.actions = ["create"];
      change.change.after_sensitive = { content: true };
      return change;
    };
    const initialIdentity: PlanIdentity = {
      ...identity(),
      legacyCompatibilityMode: true,
      markerProof: markers("absent"),
      terraformRoot: "bootstrap",
    };

    expect(buildReviewManifest(plan([marker()]), initialIdentity).canonical).toContain(
      "google_storage_bucket_object.deployment_parity_transition",
    );

    const rewritten = marker();
    (rewritten.change.after as Record<string, unknown>).content = "{\"version\":2}\n";
    expect(() => buildReviewManifest(plan([rewritten]), initialIdentity)).toThrow(
      "sensitive with a value the platform does not declare",
    );

    // Sensitive and unknown at plan time: the value is absent from `after`, so
    // the exemption must fail closed rather than admit an unreviewable write.
    const unknown = marker();
    delete (unknown.change.after as Record<string, unknown>).content;
    expect(() => buildReviewManifest(plan([unknown]), initialIdentity)).toThrow(
      "sensitive with a value the platform does not declare",
    );

    // The exemption is bound to one attribute, not to the resource type.
    const otherAttribute = marker();
    otherAttribute.change.after_sensitive = { content: true, metadata: true };
    expect(() => buildReviewManifest(plan([otherAttribute]), initialIdentity)).toThrow(
      "contains a sensitive value",
    );

    // A sensitive marker nested under the exempt attribute is not the exempt
    // scalar and must still abort.
    const nested = marker();
    nested.change.after_sensitive = { content: { inner: true } };
    expect(() => buildReviewManifest(plan([nested]), initialIdentity)).toThrow(
      "contains a sensitive value",
    );
  });

  test("manifest rejects secrets, imports, foreign modules, providers, and resource types", () => {
    const sensitive = resourceChange(
      "module.site.google_cloud_run_v2_service.preview",
      "google_cloud_run_v2_service",
      {},
      {},
    );
    sensitive.change.after_sensitive = { token: true };
    expect(() => buildReviewManifest(plan([sensitive]), identity())).toThrow("sensitive");

    const imported = resourceChange(
      "module.site.google_cloud_run_v2_service.preview",
      "google_cloud_run_v2_service",
      {},
      {},
    );
    imported.change.importing = { id: "foreign" };
    expect(() => buildReviewManifest(plan([imported]), identity())).toThrow("import");

    const foreignAddress = resourceChange(
      "google_cloud_run_v2_service.foreign",
      "google_cloud_run_v2_service",
      {},
      {},
    );
    expect(() => buildReviewManifest(plan([foreignAddress]), identity())).toThrow(
      "escaped the root resource allowlist",
    );

    const foreignType = resourceChange(
      "module.site.google_storage_bucket.foreign",
      "google_storage_bucket",
      {},
      {},
    );
    expect(() => buildReviewManifest(plan([foreignType]), identity())).toThrow(
      "escaped the root resource allowlist",
    );

    const foreignProvider = resourceChange(
      "module.site.google_cloud_run_v2_service.preview",
      "google_cloud_run_v2_service",
      {},
      {},
    );
    foreignProvider.provider_name = "registry.terraform.io/evil/google";
    expect(() => buildReviewManifest(plan([foreignProvider]), identity())).toThrow(
      "provider drifted",
    );
  });

  test("review manifest is strict hash-only and never copies raw values or state", () => {
    const raw = plan([
      resourceChange(
        "module.site.google_cloud_run_v2_service.preview",
        "google_cloud_run_v2_service",
        {},
        {},
      ),
    ]);
    raw.prior_state = { secretSentinel: "raw-prior-state" };
    raw.planned_values = { secretSentinel: "raw-planned-values" };
    raw.configuration = { secretSentinel: "raw-configuration" };
    raw.variables = { public_token: { value: "raw-variable-value" } };
    raw.output_changes = {
      endpoint: {
        actions: ["update"],
        after: "raw-output-value",
        after_sensitive: false,
        after_unknown: false,
        before: "raw-before-output",
        before_sensitive: false,
      },
    };
    const review = buildReviewManifest(raw, identity());
    expect(review.canonical).not.toContain("secretSentinel");
    expect(review.canonical).not.toContain("raw-prior-state");
    expect(review.canonical).not.toContain("raw-planned-values");
    expect(review.canonical).not.toContain("raw-configuration");
    expect(review.canonical).not.toContain("raw-variable-value");
    expect(review.canonical).not.toContain("raw-output-value");
    expect(review.canonical).not.toContain('"before":');
    expect(review.canonical).not.toContain('"after":');
  });

  test("canonical JSON sorts object keys but preserves array order", () => {
    expect(canonicalJson({ z: 1, a: [2, 1] })).toBe('{"a":[2,1],"z":1}');
  });

  test("Terraform JSON UI failures expose only a bounded allowlisted classification", () => {
    const secret = "operator-secret-sentinel";
    const stdout = [
      JSON.stringify({
        "@level": "info",
        "@module": "terraform.ui",
        terraform: "1.14.5",
        type: "version",
        ui: "1.2",
      }),
      JSON.stringify({
        "@level": "error",
        "@module": "terraform.ui",
        diagnostic: {
          address: "module.bootstrap.google_iam_workload_identity_pool.github",
          detail:
            `googleapi: Error 403: Permission 'iam.workloadIdentityPools.getAttestationRules' denied by iam.googleapis.com for ${secret}`,
          severity: "error",
          snippet: { code: `token = ${secret}` },
          summary: `Failed to read ${secret}`,
        },
        type: "diagnostic",
      }),
      JSON.stringify({
        "@level": "info",
        "@module": "terraform.ui",
        outputs: { secret: { value: secret } },
        type: "outputs",
      }),
    ].join("\n");

    const rendered = terraformFailureEnvelope(stdout, "", 1);
    expect(JSON.parse(rendered)).toEqual({
      classes: ["permission-denied"],
      diagnosticCount: 1,
      diagnosticsTruncated: false,
      exitCode: 1,
      httpStatuses: [403],
      jsonUi: "valid",
      resourceTypes: ["google_iam_workload_identity_pool"],
      schemaVersion: 1,
      services: ["iam.googleapis.com"],
    });
    expect(rendered).not.toContain(secret);
    expect(rendered).not.toContain("getAttestationRules");
    expect(rendered).not.toContain("module.bootstrap");
  });

  test("Terraform failure fallback classifies strict stderr without echoing it", () => {
    const secret = "stderr-secret-sentinel";
    const rendered = terraformFailureEnvelope(
      `not-json ${secret}`,
      `googleapi: Error 429: quota exceeded for ${secret}`,
      1,
    );
    expect(JSON.parse(rendered)).toEqual({
      classes: ["rate-limited"],
      diagnosticCount: 0,
      diagnosticsTruncated: false,
      exitCode: 1,
      httpStatuses: [429],
      jsonUi: "invalid",
      resourceTypes: [],
      schemaVersion: 1,
      services: [],
    });
    expect(rendered).not.toContain(secret);
    expect(rendered).not.toContain("quota exceeded");
  });

  test("explicit command diagnostic policy survives display-label drift", () => {
    const secret = "policy-secret-sentinel";
    const stdout = [
      JSON.stringify({
        "@level": "info",
        "@module": "terraform.ui",
        terraform: "1.14.5",
        type: "version",
        ui: "1.2",
      }),
      JSON.stringify({
        "@level": "error",
        diagnostic: {
          detail: `googleapi: Error 403: permission denied for ${secret}`,
          severity: "error",
          summary: `Failed for ${secret}`,
        },
        type: "diagnostic",
      }),
    ].join("\n");
    const renamedTerraform = commandFailureMessage({
      diagnosticPolicy: "terraform-safe",
      env: {},
      label: "renamed protected engine",
    }, stdout, `stderr ${secret}`, 1);
    expect(renamedTerraform).toStartWith("renamed protected engine failed: {");
    expect(renamedTerraform).toContain('"classes":["permission-denied"]');
    expect(renamedTerraform).not.toContain(secret);

    const nonTerraform = commandFailureMessage({
      diagnosticPolicy: "redacted-stderr",
      env: { OWNER_ACCESS_TOKEN: secret },
      label: "terraform-looking display label",
    }, stdout, `ordinary failure ${secret}`, 1);
    expect(nonTerraform).toBe(
      "terraform-looking display label failed: ordinary failure [REDACTED]",
    );

    const invalidPolicy = commandFailureMessage({
      diagnosticPolicy: "invalid" as never,
      env: {},
      label: "runtime policy drift",
    }, stdout, `ordinary failure ${secret}`, 1);
    expect(invalidPolicy).toBe(
      "runtime policy drift failed: protected diagnostic policy was invalid.",
    );
    expect(invalidPolicy).not.toContain(secret);
  });

  test("Terraform JSON UI never reports an unparsed truncated stream as valid", () => {
    const stdout = [
      JSON.stringify({
        "@level": "info",
        "@module": "terraform.ui",
        terraform: "1.14.5",
        type: "version",
        ui: "1.2",
      }),
      "malformed-unparsed-middle-line",
      ...Array.from({ length: 128 }, (_, index) =>
        JSON.stringify({ "@level": "info", type: "progress", index })
      ),
    ].join("\n");
    const envelope = JSON.parse(terraformFailureEnvelope(stdout, "", 1)) as {
      diagnosticsTruncated: boolean;
      jsonUi: string;
    };
    expect(envelope.jsonUi).toBe("truncated");
    expect(envelope.diagnosticsTruncated).toBeTrue();
  });

  test("controller has deadlines, unconditional exact cleanup, and no owner token in Terraform", async () => {
    const controller = await readFile(
      join(root, "tools/ci/protected-bootstrap-bridge.ts"),
      "utf8",
    );
    const minuteConstant = (name: string): number => {
      const match = new RegExp(`const ${name} = ([0-9]+);`).exec(controller);
      expect(match).not.toBeNull();
      return Number(match?.[1]);
    };
    expect(controller).toContain("} finally {");
    expect(controller).toContain("const JOB_TIMEOUT_MINUTES = 41;");
    expect(controller).toContain("const LEASE_MINUTES = 54;");
    expect(controller).toContain("const PLAN_INTERNAL_OPERATION_MINUTES = 24;");
    expect(controller).toContain("const APPLY_INTERNAL_OPERATION_MINUTES = 33;");
    expect(controller).toContain("const PLAN_MAIN_STEP_TIMEOUT_MINUTES = 25;");
    expect(controller).toContain("const APPLY_MAIN_STEP_TIMEOUT_MINUTES = 39;");
    expect(controller).toContain("const RECOVERY_DOCUMENTED_PROPAGATION_MINUTES = 7;");
    expect(controller).toContain("const RECOVERY_STABLE_EMPTY_MINUTES = 3;");
    expect(controller).toContain("const RECOVERY_SCAN_INTERVAL_MINUTES = 1;");
    expect(controller).toContain("const RECOVERY_SCAN_LATENCY_MARGIN_MINUTES = 1;");
    expect(controller).toContain("const RECOVERY_LATE_RETRY_MARGIN_MINUTES = 1;");
    expect(controller).toContain("const RECOVERY_SOURCE_PROOF_MINUTES = 1;");
    expect(controller).toContain("const RECOVERY_WATCHDOG_MARGIN_MINUTES = 1;");
    expect(controller).toContain("const RECOVERY_STEP_TIMEOUT_MINUTES = RECOVERY_SOURCE_PROOF_MINUTES +");
    expect(controller).toContain("const PLAN_MAIN_JOB_RECOVERY_RESERVE_MINUTES = SAME_JOB_DOCKER_CLEANUP_MINUTES +");
    expect(controller).toContain("const APPLY_MAIN_JOB_TAIL_MINUTES = 2;");
    expect(controller).toContain("const FRESH_RECOVERY_JOB_TIMEOUT_MINUTES = FRESH_RECOVERY_SETUP_STEP_COUNT +");
    expect(controller).toContain(
      "requiredOwnerTokenRemainingSeconds(invocation)",
    );
    const userAccessTokenMinutes = 60;
    const mainJobMinutes = 41;
    const freshRecoveryJobMinutes = 18;
    const freshRecoveryTokenRequirementMinutes = 14 + 1;
    const planTokenRequirementMinutes = requiredOwnerTokenRemainingSeconds({
      mode: "plan",
      operationBudgetSeconds: 25 * 60,
    }) / 60;
    const applyTokenRequirementMinutes = requiredOwnerTokenRemainingSeconds({
      mode: "apply",
      operationBudgetSeconds: 39 * 60,
    }) / 60;
    expect(planTokenRequirementMinutes).toBe(42);
    expect(applyTokenRequirementMinutes).toBe(59);
    expect(applyTokenRequirementMinutes).toBeLessThan(userAccessTokenMinutes);
    expect(mainJobMinutes + freshRecoveryTokenRequirementMinutes).toBeLessThan(
      userAccessTokenMinutes,
    );
    expect(mainJobMinutes + freshRecoveryJobMinutes).toBeLessThan(userAccessTokenMinutes);
    expect(minuteConstant("LEASE_MINUTES")).toBeGreaterThan(
      minuteConstant("JOB_TIMEOUT_MINUTES") + 10,
    );
    expect(minuteConstant("PLAN_MAIN_STEP_TIMEOUT_MINUTES")).toBe(25);
    expect(minuteConstant("APPLY_MAIN_STEP_TIMEOUT_MINUTES")).toBe(39);
    expect(minuteConstant("EXECUTOR_TOKEN_MINUTES")).toBe(35);
    expect(controller).toContain("fencePolicyMutations(");
    expect(controller).toContain("codex-cleanup-fence-");
    expect(controller).toContain("await waitForStatePermissions(");
    expect(controller).toContain("await waitForControlPermissions(");
    expect(controller).toContain("function permissionConsistencyDeadlineMs(");
    expect(controller).toContain("Math.min(apiDeadlineMs, Date.now() + IAM_CONSISTENCY_MAX_WAIT_MS)");
    expect(controller).toContain(
      "const consistencyDeadlineMs = permissionConsistencyDeadlineMs(this.#apiDeadlineMs);",
    );
    expect(controller).toContain(
      "this.#waitForPermissionProjection(invocation, session.accessToken, \"mutation\")",
    );
    expect(controller).toContain("while (now() < consistencyDeadlineMs)");
    expect(controller).not.toContain(
      "for (let attempt = 0; attempt < 7; attempt += 1) {\n    const observed: boolean[] = [];",
    );
    expect(controller).not.toContain(
      "for (let attempt = 0; attempt < 7; attempt += 1) {\n    const projectResponse",
    );
    expect(15 + 2 * 5 + 8).toBe(minuteConstant("APPLY_INTERNAL_OPERATION_MINUTES"));
    expect(controller).toContain('stdin: `${executorToken}\\n`');
    expect(controller).toContain('diagnosticPolicy: "terraform-safe"');
    expect(controller).toContain(
      "throw new Error(commandFailureMessage(options, stdout, stderr, exitCode));",
    );
    expect(controller).not.toContain("label.startsWith");
    expect(controller).not.toContain("GOOGLE_OAUTH_ACCESS_TOKEN: invocation.ownerAccessToken");
    expect(controller).toContain('delete process.env[name]');
    expect(controller).toContain("deadlineFetcher(fetch");
    expect(controller).toContain('"-plugin-dir=/plugins"');
    expect(controller).not.toContain('"--pid=');
    expect(controller).toContain("--read-only");
    expect(controller).toContain("--cap-drop=ALL");
    expect(controller).toContain("--security-opt=no-new-privileges=true");
    expect(controller).not.toContain("/var/run/docker.sock");
    expect(controller).not.toContain("upload-artifact");
    expect(controller).not.toContain("GITHUB_OUTPUT");
    expect(controller).not.toContain("refresh_token");
    const workflow = await readFile(
      join(root, ".github/workflows/protected-bootstrap-implementation.yml"),
      "utf8",
    );
    expect(workflow).toContain("timeout-minutes: 41");
  });

  test("Terraform sandbox create argv keeps only its work bind writable", () => {
    const invocation = validateInvocation(validEnvironment());
    const workDirectory = "/tmp/protected-bootstrap-123456.sandbox";
    const argv = terraformSandboxCreateArguments({
      args: ["init", "-input=false"],
      containerName: "platform-pbt-123456-init-0123456789abcdef",
      invocation,
      terraformDirectory: "/tmp/platform/terraform/deployments/bootstrap",
      workDirectory,
    }, 1001, 1002);

    expect(argv).toContain("--read-only");
    expect(argv).toContain("--interactive");
    expect(argv).not.toContain("--tty");
    expect(argv.some((argument) => argument.startsWith("--pid="))).toBeFalse();
    const mounts = argv.filter((argument) => argument.startsWith("--mount="));
    expect(mounts).toEqual([
      "--mount=type=bind,src=/tmp/platform,dst=/platform,readonly",
      "--mount=type=bind,src=/tmp/terraform,dst=/opt/terraform,readonly",
      "--mount=type=bind,src=/tmp/terraform-provider-google,dst=/plugins,readonly",
      `--mount=type=bind,src=${workDirectory},dst=/work,readonly=false`,
    ]);
    expect(mounts.filter((mount) => mount.endsWith(",readonly"))).toHaveLength(3);
    expect(mounts.filter((mount) => mount.endsWith(",readonly=false"))).toEqual([
      `--mount=type=bind,src=${workDirectory},dst=/work,readonly=false`,
    ]);
    expect(mounts.some((mount) => mount.includes(",rw"))).toBeFalse();
    for (const mount of mounts) {
      for (const field of mount.slice("--mount=".length).split(",")) {
        expect(field === "readonly" || /^[a-z][a-z-]*=.+$/.test(field)).toBeTrue();
      }
    }
  });

  test("Terraform sandbox kill-wait-remove contains a daemonized descendant after timeout", async () => {
    const directory = await mkdtemp(join(tmpdir(), "protected-sandbox-"));
    const events: string[] = [];
    let descendantAlive = false;
    let observedSpec: TerraformSandboxSpec | undefined;
    const driver: TerraformSandboxDriver = {
      create: async (spec) => {
        observedSpec = spec;
        events.push("create");
      },
      start: async () => {
        descendantAlive = true;
        events.push("start");
        throw new Error("simulated sandbox deadline");
      },
      kill: async () => {
        events.push("kill");
        descendantAlive = false;
      },
      wait: async () => {
        events.push("wait");
        expect(descendantAlive).toBeFalse();
      },
      remove: async () => {
        events.push("remove");
        expect(descendantAlive).toBeFalse();
      },
    };
    try {
      const invocation = validateInvocation({
        ...validEnvironment(),
        CONSUMER_ROOT: join(directory, "consumer"),
        GITHUB_STEP_SUMMARY_EXACT: join(directory, "summary"),
        PLATFORM_ROOT: join(directory, "platform"),
        RUNNER_TEMP_EXACT: directory,
        TERRAFORM_BINARY: join(directory, "terraform"),
        TERRAFORM_PROVIDER_ARCHIVE: join(directory, "provider.zip"),
        TERRAFORM_PROVIDER_DIRECTORY: join(directory, "provider"),
        TRANSITION_PLATFORM_ROOT: join(directory, "transition-platform"),
      });
      const executor = new TerraformSandboxExecutor(
        driver,
        () => "0123456789ab",
      );
      await expect(executor.run(
        invocation,
        {
          accessToken: "short-lived-executor-access-token-value",
          executorEmail,
          executorUniqueId: "123456789012345678901",
          tokenExpiresAtMs: Date.now() + 35 * 60_000,
        },
        join(invocation.platformRoot, "terraform/deployments/bootstrap"),
        ["plan", "-lock=false"],
        Date.now() + 60_000,
      )).rejects.toThrow("sandbox deadline");
      expect(events).toEqual(["create", "start", "kill", "wait", "remove"]);
      expect(descendantAlive).toBeFalse();
      expect(observedSpec?.containerName).toMatch(/^pbt-123456-1-[0-9a-f]{12}$/);
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  test("executable plan controller uses platform Terraform and always releases", async () => {
    const invocation = validateInvocation(validEnvironment());
    const events: string[] = [];
    const dependencies = fakeDependencies(events);
    await runProtectedBootstrap(invocation, dependencies);
    expect(events).toEqual([
      "prepare",
      "acquire",
      "freeze",
      "markers:pre",
      "terraform:init",
      "terraform:plan",
      "inspect",
      "show",
      "publish",
      "summary",
      "release",
      "remove:tfplan",
      "remove:tfdata",
      "remove:sandbox",
    ]);
    expect(events.some((event) => event.includes("consumer/infra"))).toBeFalse();
  });

  test("executable Runsetta adoption is refreshless, plan-only, and terminal", async () => {
    const invocation = validateInvocation({
      ...validEnvironment(),
      EXPOSURE_ADOPTION_CONFIRMATION: "ADOPT_RUNSETTA_EXPOSURE_STATE",
      TARGET_REPOSITORY: "runsetta",
      TERRAFORM_ROOT: "exposure",
    });
    const adoptionPlan = exposureAdoptionPlan([
      exposureDomainChange("runsetta.com", false),
      exposureDomainChange("www.runsetta.com", false),
    ]);
    const events: string[] = [];
    const terraformArgv: readonly string[][] = [];
    let publishedProof: ExposureProof | null | undefined;
    await runProtectedBootstrap(invocation, fakeDependencies(events, {
      planJson: JSON.stringify(adoptionPlan),
      proveExposure: async () => exposureProofFixture("runsetta", "adopted"),
      publishPlanReceipt: async (_invocation, _session, _review, proof) => {
        events.push("publish:adoption");
        publishedProof = proof.exposureProof;
      },
      runTerraform: async (_invocation, _session, directory, args) => {
        expect(directory).toBe("/tmp/platform/terraform/deployments/exposure");
        terraformArgv.push(args);
        events.push(`terraform:${args[0]}`);
      },
    }));
    const planArgv = terraformArgv.find((args) => args[0] === "plan");
    expect(planArgv).toContain("-json");
    expect(planArgv).toContain("-refresh=false");
    expect(terraformArgv.map((args) => args[0])).toEqual(["init", "plan"]);
    expect(events).toContain("publish:adoption");
    expect(events).not.toContain("consume");
    expect(events).not.toContain("elevate");
    expect(events).not.toContain("publish:post");
    expect(publishedProof?.seedContract?.confirmation).toBe(
      "ADOPT_RUNSETTA_EXPOSURE_STATE",
    );
  });

  test("normal cleanup starts IAM containment before blocked filesystem and Docker cleanup", async () => {
    let unblockFilesystem!: () => void;
    const filesystemBlocked = new Promise<void>((resolve) => {
      unblockFilesystem = resolve;
    });
    let releaseStarted!: () => void;
    const releaseObserved = new Promise<void>((resolve) => {
      releaseStarted = resolve;
    });
    const events: string[] = [];
    const run = runProtectedBootstrap(
      validateInvocation(validEnvironment()),
      fakeDependencies(events, {
        releaseExecutor: async () => {
          events.push("release");
          releaseStarted();
        },
        removePrivatePath: async (path) => {
          events.push(`blocked-remove:${path}`);
          await filesystemBlocked;
        },
      }),
    );
    await releaseObserved;
    expect(events).toContain("release");
    expect(events.filter((event) => event.startsWith("blocked-remove:"))).toHaveLength(3);
    unblockFilesystem();
    await run;

    let unblockSandbox!: () => void;
    const sandboxBlocked = new Promise<void>((resolve) => {
      unblockSandbox = resolve;
    });
    let executorStarted = false;
    const release = releaseSandboxAndExecutor(
      () => sandboxBlocked,
      async () => {
        executorStarted = true;
      },
    );
    await Promise.resolve();
    await Promise.resolve();
    expect(executorStarted).toBeTrue();
    unblockSandbox();
    await release;

    let synchronousExecutorStarted = false;
    await expect(releaseSandboxAndExecutor(
      () => {
        throw new Error("synchronous sandbox failure");
      },
      async () => {
        synchronousExecutorStarted = true;
      },
    )).rejects.toThrow("Sandbox and executor cleanup did not both complete");
    expect(synchronousExecutorStarted).toBeTrue();
  });

  test("bootstrap Terraform receives every required migration variable as one validated argv", async () => {
    const invocation = validateInvocation({
      ...validEnvironment(),
      LEGACY_COMPATIBILITY_MODE: "true",
      TRANSITION_WORKFLOW_SHA: "",
    });
    const events: string[] = [];
    let planArguments: readonly string[] = [];
    const dependencies = fakeDependencies(events, {
      runTerraform: async (_invocation, _session, directory, args) => {
        expect(directory).toBe("/tmp/platform/terraform/deployments/bootstrap");
        events.push(`terraform:${args[0]}`);
        if (args[0] === "plan") planArguments = args;
      },
    });
    await runProtectedBootstrap(invocation, dependencies);
    expect(planArguments).toContain("-json");
    expect(planArguments).toContain("-var=repository_id=1255553151");
    expect(planArguments).toContain(`-var=active_workflow_sha=${platformSha}`);
    expect(planArguments).toContain("-var=legacy_compatibility_mode=true");
    expect(planArguments).toContain("-var=transition_workflow_sha=");
  });

  test("executable main validates, erases controller credentials, and enters core finally", async () => {
    const environment = validEnvironment();
    const secrets = {
      consumerActionsToken: environment.CONSUMER_ACTIONS_READ_TOKEN!,
      ownerAccessToken: environment.OWNER_OAUTH_ACCESS_TOKEN!,
      platformActionsToken: environment.PLATFORM_ACTIONS_READ_TOKEN!,
    };
    delete environment.CONSUMER_ACTIONS_READ_TOKEN;
    delete environment.OWNER_OAUTH_ACCESS_TOKEN;
    delete environment.PLATFORM_ACTIONS_READ_TOKEN;
    const events: string[] = [];
    await main(environment, fakeDependencies(events), () => secrets);
    expect(environment.CONSUMER_ACTIONS_READ_TOKEN).toBeUndefined();
    expect(environment.OWNER_OAUTH_ACCESS_TOKEN).toBeUndefined();
    expect(environment.PLATFORM_ACTIONS_READ_TOKEN).toBeUndefined();
    expect(events).toContain("release");
  });

  test("deterministic crash-recovery identifiers use one stable domain-separated vector", () => {
    expect(deterministicArtifactHex("cdbentley", "123456", "service-account")).toBe(
      "070cdcf5fee1f39f9203",
    );
    expect(deterministicArtifactHex("cdbentley", "123456", "role-read")).toBe(
      "7fd5b28cf1a5aca5483f",
    );
    expect(deterministicArtifactHex("cdbentley", "123456", "role-mutation")).toBe(
      "764ee57bc43114594e6a",
    );
    expect(deterministicArtifactHex("cdbentley", "123456", "container-1")).toBe(
      "1fed2c2ce4aa298e75e5",
    );
    expect(deterministicArtifactHex("runsetta", "123456", "service-account")).not.toBe(
      deterministicArtifactHex("cdbentley", "123456", "service-account"),
    );
  });

  test("executor provenance v2 is fixed-field, bounded, and approval-complete", () => {
    const expiresAt = new Date("2026-08-26T23:00:00.000Z");
    const manifest = "d".repeat(64);
    const apply = {
      approvedManifestSha256: manifest,
      approvedPlanRunId: "7654320",
      expiresAt,
      exposureAdoptionRunId: "7654319",
      mode: "apply" as const,
      repository: "runsetta" as const,
      root: "prod" as const,
      runId: "7654321",
    };
    const description = executorDescription(apply);
    expect(description).toBe(
      "pbt-v2;repository=runsetta;run=7654321;root=prod;mode=apply;" +
        `approved=7654320;manifest=${manifest};adoption=7654319;` +
        "expires=2026-08-26T23:00:00.000Z",
    );
    expect(Buffer.byteLength(description, "utf8")).toBeLessThanOrEqual(256);
    expect(parseExecutorProvenance(description, "runsetta")).toEqual(apply);
    const maximumDescription = executorDescription({
      ...apply,
      approvedPlanRunId: "9".repeat(20),
      exposureAdoptionRunId: "9".repeat(20),
      runId: "9".repeat(20),
    });
    expect(Buffer.byteLength(maximumDescription, "utf8")).toBe(239);

    const plan = {
      approvedManifestSha256: "",
      approvedPlanRunId: "",
      expiresAt,
      exposureAdoptionRunId: "",
      mode: "plan" as const,
      repository: "cdbentley" as const,
      root: "bootstrap" as const,
      runId: "7654321",
    };
    expect(executorDescription(plan)).toContain(
      ";approved=none;manifest=none;adoption=none;expires=",
    );
    expect(parseExecutorProvenance(executorDescription(plan), "cdbentley")).toEqual(plan);
    const runsettaPlan = {
      ...plan,
      exposureAdoptionRunId: "7654319",
      repository: "runsetta" as const,
      root: "prod" as const,
    };
    expect(executorDescription(runsettaPlan)).toContain(
      ";approved=none;manifest=none;adoption=7654319;expires=",
    );
    expect(parseExecutorProvenance(executorDescription(runsettaPlan), "runsetta"))
      .toEqual(runsettaPlan);
    expect(() => executorDescription({ ...plan, root: "exposure" })).toThrow(
      "Only Runsetta plan provenance may name the exposure root",
    );

    const invalidV2 = [
      description.replace(`manifest=${manifest}`, "manifest=none"),
      description.replace("approved=7654320", "approved=none"),
      executorDescription(plan).replace("approved=none", "approved=7654320"),
      executorDescription(plan).replace("manifest=none", `manifest=${manifest}`),
      description.replace("adoption=7654319", "adoption=none"),
      description.replace(";adoption=7654319", ""),
      executorDescription(plan).replace("adoption=none", "adoption=7654319"),
      executorDescription(plan).replace("root=bootstrap", "root=exposure"),
      description.replace("root=prod", "root=exposure"),
      description.replace("run=7654321", `run=${"9".repeat(21)}`),
    ];
    for (const invalid of invalidV2) {
      expect(() => parseExecutorProvenance(invalid, invalid.includes("repository=runsetta")
        ? "runsetta"
        : "cdbentley")).toThrow();
    }
    expect(() => executorDescription({ ...apply, runId: "9".repeat(21) }))
      .toThrow("decimal length bound");
  });

  test("executor provenance v1 recovery accepts only legacy and the precise stranded adoption shape", () => {
    const expiresAt = "2026-08-26T23:00:00.000Z";

    const legacy =
      "pbt-v1;repository=cdbentley;run=7654321;root=prod;mode=apply;" +
      `approved=7654320;expires=${expiresAt}`;
    expect(parseExecutorProvenance(legacy, "cdbentley")).toMatchObject({
      approvedManifestSha256: "",
      approvedPlanRunId: "7654320",
      exposureAdoptionRunId: "",
      mode: "apply",
    });

    const strandedManifestlessAdoption =
      "pbt-v1;repository=runsetta;run=7654321;root=prod;mode=apply;" +
      `approved=7654320;adoption=7654319;expires=${expiresAt}`;
    expect(parseExecutorProvenance(strandedManifestlessAdoption, "runsetta")).toMatchObject({
      approvedManifestSha256: "",
      approvedPlanRunId: "7654320",
      exposureAdoptionRunId: "7654319",
      mode: "apply",
      repository: "runsetta",
      root: "prod",
    });
    const strandedManifestlessPlan =
      "pbt-v1;repository=runsetta;run=7654321;root=prod;mode=plan;" +
      `approved=none;adoption=7654319;expires=${expiresAt}`;
    expect(parseExecutorProvenance(strandedManifestlessPlan, "runsetta")).toMatchObject({
      approvedManifestSha256: "",
      approvedPlanRunId: "",
      exposureAdoptionRunId: "7654319",
      mode: "plan",
      repository: "runsetta",
      root: "prod",
    });

    for (const invalid of [
      strandedManifestlessAdoption.replace("repository=runsetta", "repository=cdbentley"),
      strandedManifestlessAdoption.replace("root=prod", "root=bootstrap"),
      strandedManifestlessAdoption.replace("mode=apply", "mode=plan"),
      strandedManifestlessAdoption.replace(";adoption=7654319", ";manifest=none;adoption=7654319"),
      strandedManifestlessAdoption.replace("run=7654321", `run=${"9".repeat(21)}`),
      `pbt-v1;repository=cdbentley;run=7654321;root=exposure;mode=plan;` +
      `approved=none;expires=${expiresAt}`,
    ]) {
      expect(() => parseExecutorProvenance(
        invalid,
        invalid.includes("repository=runsetta") ? "runsetta" : "cdbentley",
      )).toThrow();
    }
  });

  test("Runsetta prod apply creates and disables an exact v2 executor", async () => {
    const manifest = "d".repeat(64);
    const invocation = validateInvocation({
      ...validEnvironment(),
      APPROVED_MANIFEST_SHA256: manifest,
      APPROVED_PLAN_RUN_ID: "7654320",
      BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "2340",
      EXECUTION_MODE: "apply",
      EXPOSURE_ADOPTION_RUN_ID: "7654319",
      GITHUB_RUN_ID_EXACT: "7654321",
      TARGET_REPOSITORY: "runsetta",
      TERRAFORM_ROOT: "prod",
    });
    const expiresAt = new Date("2026-08-26T23:00:00.000Z");
    const accountId = "gha-pbt-33333333333333333333";
    const email = `${accountId}@runsetta.iam.gserviceaccount.com`;
    const uniqueId = "333333333333333333333";
    const calls: Array<{ method: string; path: string }> = [];
    let account: Record<string, unknown> | undefined;
    let attempted = false;
    let rejected = false;
    let armedUniqueId: string | undefined;
    const fetcher = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      const path = decodeURIComponent(url.pathname);
      const method = init?.method ?? "GET";
      calls.push({ method, path });
      if (path.endsWith(`/serviceAccounts/${email}`) && method === "GET") {
        return new Response("", { status: 404 });
      }
      if (path === "/v1/projects/runsetta/serviceAccounts" && method === "POST") {
        const request = JSON.parse(String(init?.body)) as {
          accountId: string;
          serviceAccount: { description: string; displayName: string };
        };
        expect(request.accountId).toBe(accountId);
        expect(request.serviceAccount.description).toContain(
          `;approved=7654320;manifest=${manifest};adoption=7654319;`,
        );
        account = {
          description: request.serviceAccount.description,
          disabled: false,
          displayName: request.serviceAccount.displayName,
          email,
          etag: "executor-etag-1",
          name: `projects/runsetta/serviceAccounts/${email}`,
          projectId: "runsetta",
          uniqueId,
        };
        return Response.json(account);
      }
      if (path.endsWith(`/serviceAccounts/${uniqueId}:disable`) && method === "POST") {
        account = { ...account!, disabled: true };
        return Response.json({});
      }
      if (path.endsWith(`/serviceAccounts/${uniqueId}`) && method === "GET") {
        return Response.json(account);
      }
      return new Response("", { status: 400 });
    };
    const created = await createEphemeralExecutor(
      "runsetta",
      accountId,
      invocation,
      expiresAt,
      "google-owner-access-token-value",
      fetcher,
      async () => undefined,
      Date.now() + 60_000,
      async () => {
        attempted = true;
      },
      () => {
        rejected = true;
      },
      (identity) => {
        armedUniqueId = identity.uniqueId;
      },
    );
    expect(attempted).toBeTrue();
    expect(rejected).toBeFalse();
    expect(armedUniqueId).toBe(uniqueId);
    expect(created.disabled).toBeTrue();
    expect(created.description).toStartWith("pbt-v2;");
    const disableIndex = calls.findIndex(({ path, method }) =>
      method === "POST" && path.endsWith(`/${uniqueId}:disable`)
    );
    const readbackIndex = calls.findIndex(({ path, method }, index) =>
      index > disableIndex && method === "GET" && path.endsWith(`/${uniqueId}`)
    );
    expect(disableIndex).toBeGreaterThanOrEqual(0);
    expect(readbackIndex).toBeGreaterThan(disableIndex);
  });

  test("normal bridge budget reserves in-process cleanup before the wrapper deadline", async () => {
    const startedAt = 1_800_000_000_000;
    const invocation = validateInvocation({
      ...validEnvironment(),
      BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "420",
    });
    let acquireDeadline = 0;
    let cleanupDeadline = 0;
    await runProtectedBootstrap(invocation, fakeDependencies([], {
      acquireExecutor: async (_invocation, _expiresAt, deadline) => {
        acquireDeadline = deadline;
        return {
          accessToken: "short-lived-executor-access-token-value",
          executorEmail,
          executorUniqueId: "123456789012345678901",
          tokenExpiresAtMs: startedAt + 35 * 60_000,
        };
      },
      now: () => startedAt,
      releaseExecutor: async (_invocation, _session, deadline) => {
        cleanupDeadline = deadline;
      },
    }));
    expect(acquireDeadline).toBe(startedAt + 60_000);
    expect(cleanupDeadline).toBe(startedAt + 360_000);
    expect(() => validateInvocation({
      ...validEnvironment(),
      BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "419",
    })).toThrow("420..1500");
  });

  test("apply admits both five-minute IAM windows without weakening its reserve", async () => {
    const startedAt = 1_800_000_000_000;
    let now = startedAt;
    const raw = plan([]);
    const review = buildReviewManifest(raw, {
      ...identity(),
      terraformRoot: "bootstrap",
    });
    const invocation = validateInvocation({
      ...validEnvironment(),
      APPROVED_MANIFEST_SHA256: review.sha256,
      APPROVED_PLAN_RUN_ID: "123455",
      BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "2340",
      EXECUTION_MODE: "apply",
    });
    const events: string[] = [];
    let acquireDeadline = 0;
    let cleanupDeadline = 0;
    await runProtectedBootstrap(invocation, fakeDependencies(events, {
      acquireExecutor: async (_invocation, _expiresAt, deadline) => {
        events.push("acquire");
        acquireDeadline = deadline;
        now += 5 * 60_000 - 1_000;
        return {
          accessToken: "short-lived-executor-access-token-value",
          executorEmail,
          executorUniqueId: "123456789012345678901",
          tokenExpiresAtMs: startedAt + 35 * 60_000,
        };
      },
      elevateExecutor: async () => {
        events.push("elevate");
        now += 5 * 60_000 - 1_000;
      },
      now: () => now,
      planJson: JSON.stringify(raw),
      readPlanJson: async () => {
        events.push("show");
        now += 7 * 60_000;
        return JSON.stringify(raw);
      },
      releaseExecutor: async (_invocation, _session, deadline) => {
        events.push("release");
        cleanupDeadline = deadline;
      },
      verifyApproval: async () => ({ canonical: "", sha256: review.sha256 }),
      waitForPostMutationDrain: async (_invocation, mutationCompletedAtMs) => {
        events.push("drain:post");
        now = mutationCompletedAtMs + 7 * 60_000;
      },
    }));
    expect(acquireDeadline).toBe(startedAt + 33 * 60_000);
    expect(cleanupDeadline).toBe(startedAt + 38 * 60_000);
    expect(events).toContain("terraform:apply");
    expect(events).toContain("publish:post");
    for (const budget of ["2319", "2341"]) {
      expect(() => validateInvocation({
        ...validEnvironment(),
        APPROVED_MANIFEST_SHA256: review.sha256,
        APPROVED_PLAN_RUN_ID: "123455",
        BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: budget,
        EXECUTION_MODE: "apply",
      })).toThrow("2320..2340 second apply range");
    }
  });

  // Two protected runs over an unchanged world. Every apply-path test above
  // stubs `verifyApproval` to return the digest the apply itself just
  // recomputed, so the equality check at controller.apply-authorize is
  // trivially true and could never fail. These build the plan run's manifest
  // from a DIFFERENT fixture than the apply run reads, related only by the
  // refresh noise a real apply always sees, and that is the only shape in
  // which the defect is visible.
  //
  // Live: plan run 33281685967 and apply run 33282187705 (2026-08-30). Four
  // `SetIamPolicy` calls landed on the project between the two refreshes, all
  // of them the bridge's own executor acquire and release, so the project IAM
  // etag had necessarily moved and the apply refused its own approved plan.
  const iamMember = (etag: string, member: string) => ({
    condition: null,
    etag,
    member,
    project: "cdbentley",
    role: "roles/viewer",
  });

  const twoRunFixtures = (planEtag: string, applyEtag: string) => {
    const changes = (etag: string) => [
      resourceChange(
        "module.bootstrap.google_project_iam_member.terraform_convergence_reader",
        "google_project_iam_member",
        iamMember(etag, "serviceAccount:tf@cdbentley.iam.gserviceaccount.com"),
        iamMember(etag, "serviceAccount:tf@cdbentley.iam.gserviceaccount.com"),
      ),
    ];
    const drift = (etag: string) => [
      resourceChange(
        "module.bootstrap.google_service_account_iam_member.prod_deploy_wif_repo",
        "google_service_account_iam_member",
        iamMember("BwStaleStored", "serviceAccount:prod@cdbentley.iam.gserviceaccount.com"),
        iamMember(etag, "serviceAccount:prod@cdbentley.iam.gserviceaccount.com"),
      ),
    ];
    return plan(changes(planEtag), drift(applyEtag));
  };

  test("a plan and its apply agree across the IAM etag churn the bridge itself causes", () => {
    const planIdentity = { ...identity(), terraformRoot: "bootstrap" as const };
    const atPlan = buildReviewManifest(twoRunFixtures("BwPlanEtag01", "BwPlanEtag01"), planIdentity);
    const atApply = buildReviewManifest(twoRunFixtures("BwApplyEtag9", "BwApplyEtag9"), planIdentity);
    expect(atApply.sha256).toBe(atPlan.sha256);

    // The exclusion is stated in the manifest the reviewer reads, not only in
    // the code that applies it.
    const published = JSON.parse(atPlan.canonical) as {
      plan: { volatileAttributeExclusions: Record<string, string[]> };
      schemaVersion: number;
    };
    expect(published.schemaVersion).toBe(3);
    expect(published.plan.volatileAttributeExclusions["google_project_iam_member"]).toEqual(["etag"]);
    expect(published.plan.volatileAttributeExclusions["google_service_account_iam_member"]).toEqual([
      "etag",
    ]);
    // Prod types are excluded now, because a prod apply writes the runtime
    // service-account policies whose IAM the bootstrap root manages.
    for (const type of [
      "google_artifact_registry_repository_iam_member",
      "google_cloud_run_v2_service_iam_member",
      "google_secret_manager_secret_iam_member",
    ]) {
      expect(published.plan.volatileAttributeExclusions[type]).toEqual(["etag"]);
    }
  });

  test("etag churn alone does not stop an apply from reaching terraform", async () => {
    const planIdentity = { ...identity(), terraformRoot: "bootstrap" as const };
    const atPlanRun = buildReviewManifest(twoRunFixtures("BwPlanEtag01", "BwPlanEtag01"), planIdentity);
    const atApplyRun = twoRunFixtures("BwApplyEtag9", "BwApplyEtag9");
    const events: string[] = [];
    await runProtectedBootstrap(
      validateInvocation({
        ...validEnvironment(),
        APPROVED_MANIFEST_SHA256: atPlanRun.sha256,
        APPROVED_PLAN_RUN_ID: "123455",
        BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "2320",
        EXECUTION_MODE: "apply",
      }),
      fakeDependencies(events, {
        planJson: JSON.stringify(atApplyRun),
        // The receipt digest comes from the PLAN run's fixture, never from what
        // the apply recomputes. Deriving it from `review.sha256` is what made
        // every previous apply test tautological.
        readPlanJson: async () => JSON.stringify(atApplyRun),
        verifyApproval: async () => ({ canonical: "", sha256: atPlanRun.sha256 }),
      }),
    );
    expect(events).toContain("consume");
    expect(events).toContain("elevate");
    expect(events).toContain("terraform:apply");
  });

  test("a semantic change between plan and apply still refuses, before consuming", async () => {
    const planIdentity = { ...identity(), terraformRoot: "bootstrap" as const };
    const atPlanRun = buildReviewManifest(twoRunFixtures("BwPlanEtag01", "BwPlanEtag01"), planIdentity);
    // Same etag churn, plus one member substitution: exactly the thing the
    // digest exists to catch.
    const tampered = plan(
      [
        resourceChange(
          "module.bootstrap.google_project_iam_member.terraform_convergence_reader",
          "google_project_iam_member",
          iamMember("BwApplyEtag9", "serviceAccount:attacker@cdbentley.iam.gserviceaccount.com"),
          iamMember("BwApplyEtag9", "serviceAccount:attacker@cdbentley.iam.gserviceaccount.com"),
        ),
      ],
      [
        resourceChange(
          "module.bootstrap.google_service_account_iam_member.prod_deploy_wif_repo",
          "google_service_account_iam_member",
          iamMember("BwStaleStored", "serviceAccount:prod@cdbentley.iam.gserviceaccount.com"),
          iamMember("BwApplyEtag9", "serviceAccount:prod@cdbentley.iam.gserviceaccount.com"),
        ),
      ],
    );
    expect(buildReviewManifest(tampered, planIdentity).sha256).not.toBe(atPlanRun.sha256);

    const events: string[] = [];
    const summaries: string[] = [];
    await expect(runProtectedBootstrap(
      validateInvocation({
        ...validEnvironment(),
        APPROVED_MANIFEST_SHA256: atPlanRun.sha256,
        APPROVED_PLAN_RUN_ID: "123455",
        BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "2320",
        EXECUTION_MODE: "apply",
      }),
      fakeDependencies(events, {
        appendSummary: async (_invocation, body) => {
          events.push("summary");
          summaries.push(body);
        },
        planJson: JSON.stringify(tampered),
        readPlanJson: async () => JSON.stringify(tampered),
        verifyApproval: async () => ({ canonical: "", sha256: atPlanRun.sha256 }),
      }),
    )).rejects.toThrow("The recomputed plan does not match");
    expect(events).not.toContain("consume");
    expect(events).not.toContain("elevate");
    expect(events).not.toContain("terraform:apply");
    // The refusal publishes what it recomputed, so the divergence is
    // diagnosable without a second run -- and it must not claim the approved
    // plan was spent, because it was not.
    expect(events).toContain("summary");
    expect(summaries).toHaveLength(1);
    expect(summaries[0]).toContain("Protected Terraform apply refused");
    expect(summaries[0]).toContain("NOT consumed; still valid for a retry");
    expect(summaries[0]).not.toContain("(single use)");
  });

  test("a volatile exclusion may never hide structured content", () => {
    const planIdentity = { ...identity(), terraformRoot: "bootstrap" as const };
    const structured = plan([
      resourceChange(
        "module.bootstrap.google_project_iam_member.terraform_convergence_reader",
        "google_project_iam_member",
        { condition: null, etag: { nested: "payload" }, member: "serviceAccount:a@b.iam.gserviceaccount.com", project: "cdbentley", role: "roles/viewer" },
        null,
      ),
    ]);
    expect(() => buildReviewManifest(structured, planIdentity)).toThrow(
      "volatile attribute etag escaped its scalar shape",
    );
  });

  test("the apply budget floor admits the whole modelled pre-elevation path", async () => {
    const startedAt = 1_800_000_000_000;
    let now = startedAt;
    const raw = plan([]);
    const review = buildReviewManifest(raw, {
      ...identity(),
      terraformRoot: "bootstrap",
    });
    // The model the bridge derives its floor from, and the run it came from.
    // Modelling only acquisition and the plan re-read understates the path:
    // prepare, the freeze and marker proofs, and Terraform are real work that
    // happens before assertPreElevationTime, and they measured 76 of the 253
    // seconds run 33230835879 spent reaching that point.
    const MODELLED = {
      prepare: 90_000,
      acquire: 5 * 60_000,
      freeze: 45_000,
      markers: 45_000,
      terraformInit: 40_000,
      terraformPlan: 40_000,
      planRead: 30_000,
      inspect: 10_000,
    };
    const modelledTotal = Object.values(MODELLED).reduce((a, b) => a + b, 0);
    expect(modelledTotal).toBe(600_000);

    let elevatedAtMs = 0;
    const walk = (sink: string[]) => ({
      acquireExecutor: async () => {
        sink.push("acquire");
        now += MODELLED.acquire;
        return {
          accessToken: "short-lived-executor-access-token-value",
          executorEmail,
          executorUniqueId: "123456789012345678901",
          tokenExpiresAtMs: startedAt + 35 * 60_000,
        };
      },
      elevateExecutor: async () => {
        sink.push("elevate");
        elevatedAtMs = now;
        now += 5 * 60_000 - 1_000;
      },
      inspectPlan: async () => {
        sink.push("inspect");
        now += MODELLED.inspect;
      },
      now: () => now,
      planJson: JSON.stringify(raw),
      prepare: async () => {
        sink.push("prepare");
        now += MODELLED.prepare;
        return preparation();
      },
      proveFreeze: async (_invocation, tokenDrainSeconds) => {
        sink.push("freeze");
        now += MODELLED.freeze;
        return freezeSnapshot(now, tokenDrainSeconds);
      },
      proveMarkers: async (_invocation, _session, requireTargetClear) => {
        sink.push(`markers:${requireTargetClear ? "post" : "pre"}`);
        now += MODELLED.markers;
        return markers();
      },
      readPlanJson: async () => {
        now += MODELLED.planRead;
        return JSON.stringify(raw);
      },
      runTerraform: async (_invocation, _session, _directory, args) => {
        const phase = args[0] === "plan" && args.includes("-detailed-exitcode")
          ? "audit"
          : args[0];
        sink.push(`terraform:${phase}`);
        // Only the pre-elevation init and plan are charged against the model;
        // the post-elevation apply and audit run inside the reserve.
        if (phase === "init") now += MODELLED.terraformInit;
        if (phase === "plan") now += MODELLED.terraformPlan;
      },
      verifyApproval: async () => ({ canonical: "", sha256: review.sha256 }),
      waitForPostMutationDrain: async (_invocation, mutationCompletedAtMs) => {
        now = mutationCompletedAtMs + 7 * 60_000;
      },
    });

    // 2320 is the floor: 39 minutes of job envelope less the 20-second setup
    // tolerance. The whole modelled path must still reach elevation there.
    const atFloor: string[] = [];
    await runProtectedBootstrap(
      validateInvocation({
        ...validEnvironment(),
        APPROVED_MANIFEST_SHA256: review.sha256,
        APPROVED_PLAN_RUN_ID: "123455",
        BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "2320",
        EXECUTION_MODE: "apply",
      }),
      fakeDependencies(atFloor, walk(atFloor)),
    );
    expect(atFloor).toContain("elevate");
    expect(atFloor).toContain("terraform:apply");
    // The walk really did spend the modelled path before elevating, so this
    // test cannot silently stop covering it.
    expect(elevatedAtMs - startedAt).toBeGreaterThanOrEqual(modelledTotal);

    // The retired 34-minute floor fails, and only after acquiring an executor
    // -- twelve modelled minutes in, with IAM already mutated. That late,
    // post-acquisition failure is what moving the floor prevents.
    now = startedAt;
    const retired: string[] = [];
    await expect(runProtectedBootstrap(
      {
        ...validateInvocation({
          ...validEnvironment(),
          APPROVED_MANIFEST_SHA256: review.sha256,
          APPROVED_PLAN_RUN_ID: "123455",
          BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "2320",
          EXECUTION_MODE: "apply",
        }),
        operationBudgetSeconds: 34 * 60,
      },
      fakeDependencies(retired, walk(retired)),
    )).rejects.toThrow("converge elevation and apply");
    expect(retired).toContain("acquire");
    expect(retired).not.toContain("elevate");
    expect(retired).not.toContain("terraform:apply");
  });

  test("owner token introspection requires exact cloud scope and enough recovery lifetime", async () => {
    const accessToken = "fresh-google-owner-oauth-access-token-value";
    const nowMs = 1_800_000_000_000;
    let observedUrl: URL | undefined;
    let observedInit: RequestInit | undefined;
    const fetcher = async (input: string | URL | Request, init?: RequestInit) => {
      observedUrl = new URL(String(input));
      observedInit = init;
      return Response.json({
        exp: String(nowMs / 1_000 + 3_000),
        expires_in: "3000",
        scope: "openid https://www.googleapis.com/auth/cloud-platform",
        sub: "100549777206682928323",
      });
    };
    await requireFreshGoogleOwnerAccessToken(accessToken, 2_999, fetcher, nowMs);
    expect(observedUrl?.origin).toBe("https://oauth2.googleapis.com");
    expect(observedUrl?.pathname).toBe("/tokeninfo");
    expect([...observedUrl!.searchParams.keys()]).toEqual([]);
    expect(observedInit?.method).toBe("POST");
    expect(observedInit?.redirect).toBe("error");
    const observedHeaders = new Headers(observedInit?.headers);
    expect(observedHeaders.get("authorization")).toBe(`Bearer ${accessToken}`);
    expect(observedHeaders.get("content-type")).toBe(
      "application/x-www-form-urlencoded;charset=UTF-8",
    );
    expect(observedHeaders.get("content-length")).toBeNull();

    await expect(requireFreshGoogleOwnerAccessToken(
      accessToken,
      3_001,
      fetcher,
      nowMs,
    )).rejects.toThrow("too close to expiry");
    await expect(requireFreshGoogleOwnerAccessToken(
      accessToken,
      60,
      async () => Response.json({
        exp: String(nowMs / 1_000 + 3_000),
        expires_in: "3000",
        scope: "openid",
        sub: "100549777206682928323",
      }),
      nowMs,
    )).rejects.toThrow("lacks the cloud-platform scope");
    await expect(requireFreshGoogleOwnerAccessToken(
      accessToken,
      60,
      async () => Response.json({
        exp: String(nowMs / 1_000 + 3_000),
        expires_in: "3000",
        scope: "https://www.googleapis.com/auth/cloud-platform",
        sub: "999999999999999999999",
      }),
      nowMs,
    )).rejects.toThrow("does not authenticate the exact owner");
    await expect(requireFreshGoogleOwnerAccessToken(
      accessToken,
      60,
      async () => Response.json({
        exp: String(nowMs / 1_000 + 3_000),
        expires_in: "3000",
        scope: "https://www.googleapis.com/auth/cloud-platform",
      }),
      nowMs,
    )).rejects.toThrow("metadata was malformed");
    await requireFreshGoogleOwnerAccessToken(
      accessToken,
      2_900,
      async () => Response.json({
        exp: String(nowMs / 1_000 + 3_000),
        expires_in: "2970",
        scope: "https://www.googleapis.com/auth/cloud-platform",
        sub: "100549777206682928323",
      }),
      nowMs,
    );
    await requireFreshGoogleOwnerAccessToken(
      accessToken,
      2_900,
      async () => Response.json({
        exp: String(nowMs / 1_000 + 3_700),
        expires_in: "3000",
        scope: "https://www.googleapis.com/auth/cloud-platform",
        sub: "100549777206682928323",
      }),
      nowMs,
    );
    const rejected = new Response("bounded rejection", { status: 401 });
    await expect(requireFreshGoogleOwnerAccessToken(
      accessToken,
      60,
      async () => rejected,
      nowMs,
    )).rejects.toThrow("was rejected");
    expect(rejected.bodyUsed).toBeTrue();
    await expect(requireFreshGoogleOwnerAccessToken(
      accessToken,
      60,
      async () => { throw new Error(`do not expose ${accessToken}`); },
      nowMs,
    )).rejects.not.toThrow(accessToken);
  });

  test("recovery-only entry accepts one owner token and rejects normal capabilities", async () => {
    expect(parseRecoverySecretBundle(Buffer.from("owner-recovery-token-value\0"))).toBe(
      "owner-recovery-token-value",
    );
    expect(() => parseRecoverySecretBundle(Buffer.from("one\0two\0"))).toThrow(
      "exactly one",
    );
    const environment = validRecoveryEnvironment();
    const ownerToken = environment.OWNER_OAUTH_ACCESS_TOKEN!;
    delete environment.OWNER_OAUTH_ACCESS_TOKEN;
    const events: string[] = [];
    const dependencies: RecoveryDependencies = {
      now: () => 1_800_000_000_000,
      recoverArtifacts: async (invocation) => {
        expect(invocation.ownerAccessToken).toBe(ownerToken);
        events.push("recover");
      },
      verifySource: async () => {
        events.push("source");
      },
    };
    await recoveryMain(environment, dependencies, () => ownerToken);
    expect(events).toEqual(["source", "recover"]);
    expect(environment.OWNER_OAUTH_ACCESS_TOKEN).toBeUndefined();
    expect(() => validateRecoveryInvocation({
      ...validRecoveryEnvironment(),
      BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "1500",
    })).toThrow("normal-operation capability");
  });

  test("recovery retries a lost deterministic disable response and contains later visibility", async () => {
    const fixture = deterministicRecoveryHarness({
      firstDisableTransportLoss: true,
      keyFailureStatus: 403,
    });
    const first = await inventoryBridgeArtifacts(
      "cdbentley",
      fixture.invocation.ownerAccessToken,
      fixture.fetcher,
      fixture.sleep,
      fixture.now() + 60_000,
      fixture.invocation,
    );
    expect(first.hadActiveArtifacts).toBeTrue();
    expect(fixture.calls.some((call) => call.tag === "deterministic-account-404")).toBeTrue();
    expect(fixture.calls.some((call) => call.tag === "empty-account-list")).toBeTrue();

    fixture.revealAccount();
    let failure: unknown;
    try {
      await inventoryBridgeArtifacts(
        "cdbentley",
        fixture.invocation.ownerAccessToken,
        fixture.fetcher,
        fixture.sleep,
        fixture.now() + 60_000,
        fixture.invocation,
      );
    } catch (error) {
      failure = error;
    }
    expect(errorMessages(failure).join("\n")).toContain("key inventory failed with HTTP 403");
    expect(fixture.account.disabled).toBeTrue();
    expect(fixture.callIndex("disable-response-loss")).toBeLessThan(
      fixture.callIndex("deterministic-account-404"),
    );
    expect(fixture.callIndex("deterministic-email-disable")).toBeLessThan(
      fixture.callIndex("numeric-id-disable"),
    );
  });

  test("detached recovery scrubs active and deleted exact members despite global inventory failure", async () => {
    const fixture = deterministicRecoveryHarness({
      accountListFailureStatus: 503,
      targetProjectMembers: true,
    });
    let failure: unknown;
    try {
      await inventoryBridgeArtifacts(
        "cdbentley",
        fixture.invocation.ownerAccessToken,
        fixture.fetcher,
        fixture.sleep,
        fixture.now() + 60_000,
        fixture.invocation,
      );
    } catch (error) {
      failure = error;
    }
    expect(errorMessages(failure).join("\n")).toContain("HTTP 503");
    const target = fixture.policy("project:cdbentley");
    expect(target.version).toBe(3);
    expect(target.auditConfigs).toEqual([{ auditLogConfigs: [{ logType: "ADMIN_READ" }], service: "allServices" }]);
    expect(target.bindings).toEqual([{
      members: ["user:unrelated@example.com"],
      role: "roles/editor",
    }]);
    expect(fixture.callIndex("deterministic-email-disable")).toBeLessThan(
      fixture.callIndex("target-project-policy-get"),
    );
    expect(fixture.callIndex("account-list-503")).toBeLessThan(
      fixture.callIndex("target-project-policy-set"),
    );
  });

  test("detached executor recovery accepts exact live cleanup fences and refuses near matches", async () => {
    const exact = deterministicRecoveryHarness({ executorCleanupFence: "exact" });
    await inventoryBridgeArtifacts(
      "cdbentley",
      exact.invocation.ownerAccessToken,
      exact.fetcher,
      exact.sleep,
      exact.now() + 60_000,
      exact.invocation,
    );
    expect(exact.policy(`sa:${exact.email}`).bindings).toEqual([]);

    const tampered = deterministicRecoveryHarness({ executorCleanupFence: "tampered" });
    let failure: unknown;
    try {
      await inventoryBridgeArtifacts(
        "cdbentley",
        tampered.invocation.ownerAccessToken,
        tampered.fetcher,
        tampered.sleep,
        tampered.now() + 60_000,
        tampered.invocation,
      );
    } catch (error) {
      failure = error;
    }
    expect(errorMessages(failure).join("\n")).toContain(
      "unknown or modified binding; manual cleanup is required",
    );
    expect(tampered.policy(`sa:${tampered.email}`).bindings).toHaveLength(1);
  });

  test("a visible deterministic identity authenticates and removes its exact prior orphan fence", async () => {
    const fixture = deterministicRecoveryHarness({
      executorUniqueIdFence: true,
      initiallyVisibleAccount: true,
      keyFailureStatus: 403,
    });
    let failure: unknown;
    try {
      await inventoryBridgeArtifacts(
        "cdbentley",
        fixture.invocation.ownerAccessToken,
        fixture.fetcher,
        fixture.sleep,
        fixture.now() + 60_000,
        fixture.invocation,
      );
    } catch (error) {
      failure = error;
    }
    expect(errorMessages(failure).join("\n")).toContain("key inventory failed with HTTP 403");
    expect(fixture.account.disabled).toBeTrue();
    expect(fixture.policy(`sa:${fixture.email}`).bindings).toEqual([]);
  });

  test("a nonconverging deterministic readback cannot starve a listed peer disable", async () => {
    const fixture = deterministicRecoveryHarness({
      directReadbackNeverConverges: true,
      initiallyVisibleAccount: true,
      listedLegacyPeer: true,
    });
    let failure: unknown;
    try {
      await inventoryBridgeArtifacts(
        "cdbentley",
        fixture.invocation.ownerAccessToken,
        fixture.fetcher,
        fixture.sleep,
        fixture.now() + 60_000,
        fixture.invocation,
      );
    } catch (error) {
      failure = error;
    }
    expect(errorMessages(failure).join("\n")).toContain("manual cleanup is required");
    expect(fixture.callIndex("peer-numeric-id-disable")).toBeGreaterThanOrEqual(0);
    expect(fixture.callIndex("peer-numeric-id-disable")).toBeLessThan(
      fixture.callIndex("sleep"),
    );
  });

  test("a fast listed 403 is handled while direct identity observation is still pending", async () => {
    const fixture = deterministicRecoveryHarness({
      delayDeterministicDirectGet: true,
      initiallyVisibleAccount: true,
      listedLegacyPeer: true,
      peerDisableStatus: 403,
    });
    const outcome = inventoryBridgeArtifacts(
      "cdbentley",
      fixture.invocation.ownerAccessToken,
      fixture.fetcher,
      fixture.sleep,
      fixture.now() + 60_000,
      fixture.invocation,
    ).then(
      () => undefined,
      (error: unknown) => error,
    );
    await Bun.sleep(0);
    expect(fixture.callIndex("deterministic-direct-get-delayed")).toBeGreaterThanOrEqual(0);
    expect(fixture.callIndex("peer-numeric-id-disable")).toBeGreaterThanOrEqual(0);
    fixture.releaseDirectGet();
    const failure = await outcome;
    expect(errorMessages(failure).join("\n")).toContain("HTTP 403");

    // A list-level rejection exercises the child-promise handler itself (the
    // per-identity branch above is intentionally all-settled internally).
    const listFailure = deterministicRecoveryHarness({
      accountListFailureStatus: 403,
      delayDeterministicDirectGet: true,
      initiallyVisibleAccount: true,
    });
    const listOutcome = inventoryBridgeArtifacts(
      "cdbentley",
      listFailure.invocation.ownerAccessToken,
      listFailure.fetcher,
      listFailure.sleep,
      listFailure.now() + 60_000,
      listFailure.invocation,
    ).then(
      () => undefined,
      (error: unknown) => error,
    );
    await Bun.sleep(0);
    expect(listFailure.callIndex("account-list-403")).toBeGreaterThanOrEqual(0);
    listFailure.releaseDirectGet();
    expect(errorMessages(await listOutcome).join("\n")).toContain("HTTP 403");
  });

  test("unresolved uniqueId fence recovery retries 404 and transient policy reads until exact identity", async () => {
    const fixture = deterministicRecoveryHarness({
      executorUniqueIdFence: true,
      revealAccountOnScan: 2,
      transientTargetPolicyFailures: 1,
    });
    const startedAt = fixture.now();
    await recoverBridgeArtifactsUntilStable(
      fixture.invocation,
      fixture.fetcher,
      fixture.sleep,
      startedAt + 12 * 60_000,
      fixture.now,
    );
    expect(fixture.callCount("target-project-policy-503")).toBe(1);
    expect(fixture.callCount("deterministic-account-404")).toBeGreaterThan(0);
    expect(fixture.callCount("numeric-id-disable")).toBeGreaterThan(0);
    expect(fixture.policy(`sa:${fixture.email}`).bindings).toEqual([]);
    expect(fixture.callCount("deterministic-account-delete")).toBe(1);

    const tampered = deterministicRecoveryHarness({
      executorUniqueIdFenceTampered: true,
      initiallyVisibleAccount: true,
      keyFailureStatus: 403,
    });
    let failure: unknown;
    try {
      await inventoryBridgeArtifacts(
        "cdbentley",
        tampered.invocation.ownerAccessToken,
        tampered.fetcher,
        tampered.sleep,
        tampered.now() + 60_000,
        tampered.invocation,
      );
    } catch (error) {
      failure = error;
    }
    expect(errorMessages(failure).join("\n")).toContain(
      "unknown or modified binding; manual cleanup is required",
    );
    expect(tampered.policy(`sa:${tampered.email}`).bindings).toHaveLength(1);
  });

  test("stable-empty recovery starts proof after the horizon even after first-scan cleanup", async () => {
    const fixture = deterministicRecoveryHarness({ roleAppearanceScan: 1 });
    const startedAt = fixture.now();
    await recoverBridgeArtifactsUntilStable(
      fixture.invocation,
      fixture.fetcher,
      fixture.sleep,
      startedAt + 12 * 60_000,
      fixture.now,
    );
    expect(fixture.now() - startedAt).toBe(10 * 60_000);
    expect(fixture.role.deleted).toBeTrue();
  });

  test("an empty first scan requires seven-minute observation then three-minute proof", async () => {
    const fixture = deterministicRecoveryHarness();
    const startedAt = fixture.now();
    await recoverBridgeArtifactsUntilStable(
      fixture.invocation,
      fixture.fetcher,
      fixture.sleep,
      startedAt + 12 * 60_000,
      fixture.now,
    );
    expect(fixture.now() - startedAt).toBe(10 * 60_000);
  });

  test("post-delete exact-email 403s require clean global scans and the full absence proof", async () => {
    const fixture = deterministicRecoveryHarness({ postDeleteMasked403: true });
    const first = await inventoryBridgeArtifacts(
      "cdbentley",
      fixture.invocation.ownerAccessToken,
      fixture.fetcher,
      fixture.sleep,
      fixture.now() + 12 * 60_000,
      fixture.invocation,
    );
    expect(first.exactAccountAbsentOrDenied).toBeTrue();
    expect(first.hadActiveArtifacts).toBeFalse();

    const startedAt = fixture.now();
    await recoverBridgeArtifactsUntilStable(
      fixture.invocation,
      fixture.fetcher,
      fixture.sleep,
      startedAt + 12 * 60_000,
      fixture.now,
    );
    expect(fixture.now() - startedAt).toBe(10 * 60_000);
    expect(fixture.callCount("deterministic-email-disable-403")).toBeGreaterThan(0);
    expect(fixture.callCount("deterministic-account-403")).toBeGreaterThan(0);
    expect(fixture.callCount("executor-policy-403")).toBeGreaterThan(0);
    expect(fixture.callCount("empty-account-list")).toBeGreaterThan(0);
    expect(fixture.callCount("target-project-policy-get")).toBeGreaterThan(0);
    expect(fixture.callCount("project-policy-get")).toBeGreaterThan(0);
    expect(fixture.callCount("runtime-policy-get")).toBeGreaterThan(0);
  });

  test("a delayed live identity cannot turn an exact-email 403 into successful containment", async () => {
    const fixture = deterministicRecoveryHarness({
      emailDisableFailureStatus: 403,
      numericDisableFailureStatus: 403,
      postDeleteMasked403: true,
      revealAccountOnScan: 2,
    });
    await expect(recoverBridgeArtifactsUntilStable(
      fixture.invocation,
      fixture.fetcher,
      fixture.sleep,
      fixture.now() + 12 * 60_000,
      fixture.now,
    )).rejects.toThrow("orphan containment was incomplete; manual cleanup is required");
    expect(fixture.callCount("deterministic-email-disable-403")).toBeGreaterThan(1);
    expect(fixture.callCount("numeric-id-disable")).toBeGreaterThan(0);
    expect(fixture.account.disabled).toBeFalse();
  });

  test("a late exact-email 403 resets rather than inherits prior 404 proof time", async () => {
    const fixture = deterministicRecoveryHarness({
      postDeleteMasked403: true,
      postDeleteMasked403StartScan: 11,
    });
    const startedAt = fixture.now();
    await expect(recoverBridgeArtifactsUntilStable(
      fixture.invocation,
      fixture.fetcher,
      fixture.sleep,
      startedAt + 12 * 60_000,
      fixture.now,
    )).rejects.toThrow(
      "did not observe the required stable-empty artifact inventory before its deadline",
    );
    expect(fixture.callCount("deterministic-email-disable-403")).toBe(2);
    expect(fixture.now() - startedAt).toBe(12 * 60_000);
  });

  test("post-delete masking never relaxes global-list or policy 403s", async () => {
    for (const [options, tag, message] of [
      [{ accountListFailureStatus: 403 }, "account-list-403", "Executor inventory failed with HTTP 403"],
      [{ runtimePolicyFailureStatus: 403 }, "runtime-policy-403", "Deterministic executor policy recovery was incomplete"],
      [{ targetProjectPolicyFailureStatus: 403 }, "target-project-policy-403", "Deterministic executor policy recovery was incomplete"],
    ] as const) {
      const fixture = deterministicRecoveryHarness({
        postDeleteMasked403: true,
        ...options,
      });
      await expect(recoverBridgeArtifactsUntilStable(
        fixture.invocation,
        fixture.fetcher,
        fixture.sleep,
        fixture.now() + 12 * 60_000,
        fixture.now,
      )).rejects.toThrow(message);
      expect(fixture.callCount(tag)).toBeGreaterThan(0);
      expect(fixture.callCount("sleep")).toBe(0);
    }
  });

  test("the production recovery budget proves 180 stable seconds after a second-scan artifact", async () => {
    const fixture = deterministicRecoveryHarness({ roleAppearanceScan: 2 });
    const startedAt = fixture.now();
    let recoveryDeadlineMs = 0;
    await runProtectedRecovery(fixture.invocation, {
      now: fixture.now,
      recoverArtifacts: async (invocation, deadlineMs) => {
        recoveryDeadlineMs = deadlineMs;
        await recoverBridgeArtifactsUntilStable(
          invocation,
          fixture.fetcher,
          fixture.sleep,
          deadlineMs,
          fixture.now,
        );
      },
      verifySource: async () => undefined,
    });
    expect(recoveryDeadlineMs - startedAt).toBe(12 * 60_000);
    expect(fixture.now() - startedAt).toBe(10 * 60_000);
    expect(fixture.role.deleted).toBeTrue();
  });

  test("the production recovery budget covers seven-minute propagation plus the full proof", async () => {
    const fixture = deterministicRecoveryHarness({ roleAppearanceScan: 8 });
    const startedAt = fixture.now();
    await runProtectedRecovery(fixture.invocation, {
      now: fixture.now,
      recoverArtifacts: (invocation, deadlineMs) =>
        recoverBridgeArtifactsUntilStable(
          invocation,
          fixture.fetcher,
          fixture.sleep,
          deadlineMs,
          fixture.now,
        ),
      verifySource: async () => undefined,
    });
    expect(fixture.now() - startedAt).toBe(10 * 60_000);
    expect(fixture.role.deleted).toBeTrue();
  });

  test("the production recovery budget absorbs bounded nonzero scan latency", async () => {
    const fixture = deterministicRecoveryHarness({ scanDurationMs: 5_000 });
    const startedAt = fixture.now();
    await recoverBridgeArtifactsUntilStable(
      fixture.invocation,
      fixture.fetcher,
      fixture.sleep,
      startedAt + 12 * 60_000,
      fixture.now,
    );
    expect(fixture.now() - startedAt).toBeGreaterThan(10 * 60_000);
    expect(fixture.now() - startedAt).toBeLessThan(12 * 60_000);
  });

  test("a late retryable read resets proof and completes inside the bounded margin", async () => {
    const fixture = deterministicRecoveryHarness({ transientAccountListFailureScan: 9 });
    const startedAt = fixture.now();
    const scans: RecoveryScanTelemetry[] = [];
    await recoverBridgeArtifactsUntilStable(
      fixture.invocation,
      fixture.fetcher,
      fixture.sleep,
      startedAt + 12 * 60_000,
      fixture.now,
      {
        phase: () => undefined,
        recoveryScan: (scan) => scans.push(scan),
        stop: () => undefined,
      },
    );
    expect(fixture.callCount("account-list-503")).toBe(1);
    expect(fixture.now() - startedAt).toBeGreaterThan(11 * 60_000);
    expect(fixture.now() - startedAt).toBeLessThan(12 * 60_000);
    expect(scans.map((scan) => scan.outcome)).toContain("reset-retryable-read");
    expect(scans.filter((scan) => scan.outcome === "proof-start")).toHaveLength(2);
    expect(scans.at(-1)?.outcome).toBe("proof-complete");
    expect(scans.every((scan) =>
      [scan.elapsedMs, scan.proofMs, scan.scanMs].every((value) =>
        Number.isSafeInteger(value) && value >= 0
      )
    )).toBeTrue();
  });

  test("source proof has its own bound and cannot consume the IAM recovery horizon", async () => {
    const fixture = deterministicRecoveryHarness();
    const startedAt = fixture.now();
    let virtualNow = startedAt;
    let recoveryDeadlineMs = 0;
    await runProtectedRecovery(fixture.invocation, {
      now: () => virtualNow,
      recoverArtifacts: async (_invocation, deadlineMs) => {
        recoveryDeadlineMs = deadlineMs;
      },
      verifySource: async () => {
        virtualNow += 59_000;
      },
    });
    expect(recoveryDeadlineMs).toBe(startedAt + 59_000 + 12 * 60_000);

    let recoveryStarted = false;
    virtualNow = startedAt;
    await expect(runProtectedRecovery(fixture.invocation, {
      now: () => virtualNow,
      recoverArtifacts: async () => {
        recoveryStarted = true;
      },
      verifySource: async () => {
        virtualNow += 60_000;
      },
    })).rejects.toThrow(
      "protected crash recovery source proof reached the hard protected-operation deadline",
    );
    expect(recoveryStarted).toBeFalse();
  });

  test("a role observed and cleaned on the nominal final scan resets the 180-second proof", async () => {
    const fixture = deterministicRecoveryHarness({ roleAppearanceScan: 6 });
    const startedAt = fixture.now();
    await recoverBridgeArtifactsUntilStable(
      fixture.invocation,
      fixture.fetcher,
      fixture.sleep,
      startedAt + 12 * 60_000,
      fixture.now,
    );
    expect(fixture.now() - startedAt).toBe(10 * 60_000);
    expect(fixture.role.deleted).toBeTrue();
  });

  test("a fully retryable failed scan resets proof and retries without weakening hard failures", async () => {
    const fixture = deterministicRecoveryHarness({ transientAccountListFailures: 1 });
    const startedAt = fixture.now();
    await recoverBridgeArtifactsUntilStable(
      fixture.invocation,
      fixture.fetcher,
      fixture.sleep,
      startedAt + 12 * 60_000,
      fixture.now,
    );
    expect(fixture.callCount("account-list-503")).toBe(1);
    expect(fixture.now() - startedAt).toBeGreaterThanOrEqual(302_000);

    const hard = deterministicRecoveryHarness({ executorCleanupFence: "tampered" });
    let sleeps = 0;
    await expect(recoverBridgeArtifactsUntilStable(
      hard.invocation,
      hard.fetcher,
      async (milliseconds) => {
        sleeps += 1;
        await hard.sleep(milliseconds);
      },
      hard.now() + 700_000,
      hard.now,
    )).rejects.toThrow("Deterministic executor policy recovery was incomplete");
    expect(sleeps).toBe(0);
  });

  test("telemetry failures and formatting never alter the protected outcome or expose values", async () => {
    const events: string[] = [];
    await runProtectedBootstrap(
      validateInvocation(validEnvironment()),
      fakeDependencies(events),
      {
        phase: () => {
          throw new Error("telemetry sink failed with secret-value");
        },
        recoveryScan: () => {
          throw new Error("telemetry scan failed with secret-value");
        },
        stop: () => {
          throw new Error("telemetry stop failed with secret-value");
        },
      },
    );
    expect(events).toContain("release");
    const recovery = deterministicRecoveryHarness();
    const recoveryStartedAtMs = recovery.now();
    await recoverBridgeArtifactsUntilStable(
      recovery.invocation,
      recovery.fetcher,
      recovery.sleep,
      recoveryStartedAtMs + 12 * 60_000,
      recovery.now,
      {
        phase: () => undefined,
        recoveryScan: () => {
          throw new Error("telemetry scan failed with secret-value");
        },
        stop: () => undefined,
      },
    );
    expect(recovery.now() - recoveryStartedAtMs).toBe(10 * 60_000);
    const breadcrumb = formatBridgeBreadcrumb("executor.permission-proof", 2_049, {
      currentBytes: 4_097,
      oom: 2,
      oomKill: 1,
      peakBytes: 8_193,
    });
    expect(breadcrumb).toBe(
      "Protected bridge telemetry phase=executor.permission-proof rss_kib=3 " +
        "cgroup_current_kib=5 cgroup_peak_kib=9 cgroup_oom=2 cgroup_oom_kill=1",
    );
    expect(breadcrumb).not.toContain("secret");
    const scanBreadcrumb = formatRecoveryScanBreadcrumb({
      elapsedMs: 481_234,
      outcome: "reset-retryable-read",
      proofMs: 0,
      scanMs: 5_678,
    });
    expect(scanBreadcrumb).toBe(
      "Protected bridge recovery scan outcome=reset-retryable-read " +
        "elapsed_ms=481234 scan_ms=5678 proof_ms=0",
    );
    expect(scanBreadcrumb).not.toContain("cdbentley");
    expect(scanBreadcrumb).not.toContain("gha-pbt");
    expect(scanBreadcrumb).not.toContain("HTTP");
  });

  test("executable apply consumes the fresh receipt once immediately before apply", async () => {
    const raw = plan([]);
    const review = buildReviewManifest(raw, {
      ...identity(),
      terraformRoot: "bootstrap",
    });
    const invocation = validateInvocation({
      ...validEnvironment(),
      APPROVED_MANIFEST_SHA256: review.sha256,
      APPROVED_PLAN_RUN_ID: "123455",
      BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "2340",
      EXECUTION_MODE: "apply",
    });
    const events: string[] = [];
    const terraformArgv: Array<readonly string[]> = [];
    const dependencies = fakeDependencies(events, {
      planJson: JSON.stringify(raw),
      runTerraform: async (_invocation, _session, _directory, args) => {
        terraformArgv.push(args);
        events.push(
          args[0] === "plan" && args.includes("-detailed-exitcode")
            ? "terraform:audit"
            : `terraform:${args[0]}`,
        );
      },
      verifyApproval: async () => ({ canonical: "", sha256: review.sha256 }),
    });
    await runProtectedBootstrap(invocation, dependencies);
    const consumeIndex = events.indexOf("consume");
    expect(events.slice(0, consumeIndex).filter((event) => event === "freeze")).toHaveLength(2);
    expect(events.indexOf("elevate")).toBeGreaterThan(consumeIndex);
    expect(events.indexOf("elevate")).toBeLessThan(events.indexOf("terraform:apply"));
    expect(consumeIndex).toBeLessThan(events.indexOf("terraform:apply"));
    expect(events.indexOf("terraform:audit")).toBeGreaterThan(events.indexOf("terraform:apply"));
    expect(events.indexOf("drain:post")).toBeGreaterThan(events.indexOf("terraform:audit"));
    expect(events.indexOf("markers:post")).toBeGreaterThan(events.indexOf("terraform:audit"));
    expect(events.indexOf("publish:post")).toBeGreaterThan(events.indexOf("markers:post"));
    expect(events.filter((event) => event === "consume")).toHaveLength(1);
    expect(events).toContain("release");
    const auditArgv = terraformArgv.find((args) =>
      args[0] === "plan" && args.includes("-detailed-exitcode")
    );
    expect(auditArgv).toBeDefined();
    expect(auditArgv).toContain("-json");
    expect(auditArgv).toContain("-detailed-exitcode");
  });

  test("Runsetta production revalidates adoption through elevation and reaches apply", async () => {
    const exposureProof = runsettaProdExposureProof("123454");
    const raw = plan([]);
    const review = buildReviewManifest(raw, {
      ...identity(),
      exposureProof,
      projectId: "runsetta",
      repository: "runsetta",
      repositoryId: "711292980",
      terraformRoot: "prod",
    });
    const invocation = validateInvocation({
      ...validEnvironment(),
      APPROVED_MANIFEST_SHA256: review.sha256,
      APPROVED_PLAN_RUN_ID: "123455",
      BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "2340",
      EXECUTION_MODE: "apply",
      EXPOSURE_ADOPTION_RUN_ID: "123454",
      TARGET_REPOSITORY: "runsetta",
      TERRAFORM_ROOT: "prod",
    });
    const events: string[] = [];
    const dependencies = fakeDependencies(events, {
      planJson: JSON.stringify(raw),
      proveExposure: async () => {
        events.push("exposure");
        return exposureProof;
      },
      verifyApproval: async () => ({ canonical: "", sha256: review.sha256 }),
    });
    await runProtectedBootstrap(invocation, dependencies);
    expect(events.filter((event) => event === "exposure")).toHaveLength(4);
    expect(events.indexOf("elevate")).toBeGreaterThan(events.indexOf("consume"));
    expect(events.indexOf("terraform:apply")).toBeGreaterThan(events.indexOf("elevate"));
    expect(events.indexOf("publish:post")).toBeGreaterThan(events.indexOf("terraform:apply"));

    const rejectedEvents: string[] = [];
    await expect(runProtectedBootstrap(
      invocation,
      fakeDependencies(rejectedEvents, {
        proveExposure: async () => {
          throw new Error("missing exact Runsetta adoption prerequisite");
        },
      }),
    )).rejects.toThrow("missing exact Runsetta adoption prerequisite");
    expect(rejectedEvents).not.toContain("elevate");
    expect(rejectedEvents).not.toContain("terraform:apply");

    const unacquiredManager = new ExecutorLeaseManager(
      async () => new Response("", { status: 500 }),
      async () => undefined,
    );
    await expect(unacquiredManager.elevate(
      invocation,
      {
        accessToken: "short-lived-executor-access-token-value",
        executorEmail: "gha-pbt-0123456789abcdefabcd@runsetta.iam.gserviceaccount.com",
        executorUniqueId: "123456789012345678901",
        tokenExpiresAtMs: Date.now() + 35 * 60_000,
      },
      new Date(Date.now() + 54 * 60_000),
      Date.now() + 20 * 60_000,
    )).rejects.toThrow("did not match the acquired single-run identity");
  });

  test("Terraform crash and malformed plan both execute finally cleanup", async () => {
    for (const failure of ["terraform", "malformed"] as const) {
      const events: string[] = [];
      const dependencies = fakeDependencies(events, {
        ...(failure === "malformed" ? { planJson: "{" } : {}),
        ...(failure === "terraform"
          ? {
              runTerraform: async (_invocation, _session, _directory, args) => {
                events.push(`terraform:${args[0]}`);
                if (args[0] === "plan") throw new Error("simulated Terraform crash");
              },
            }
          : {}),
      });
      await expect(runProtectedBootstrap(validateInvocation(validEnvironment()), dependencies))
        .rejects.toThrow();
      expect(events).toContain("remove:tfplan");
      expect(events).toContain("remove:tfdata");
      expect(events).toContain("release");
    }
  });

  test("hard internal timeout aborts before lease acquisition and still enters finally", async () => {
    const events: string[] = [];
    const startedAt = 1_800_000_000_000;
    let now = startedAt;
    const dependencies = fakeDependencies(events, {
      now: () => now,
      prepare: async () => {
        events.push("prepare");
        now = startedAt + 24 * 60_000;
        return preparation();
      },
    });
    await expect(runProtectedBootstrap(validateInvocation(validEnvironment()), dependencies))
      .rejects.toThrow("deadline");
    expect(events).not.toContain("acquire");
    expect(events).toContain("release");
  });

  test("apply refuses before mutation when elevation convergence plus reserve cannot fit", async () => {
    const startedAt = 1_800_000_000_000;
    let now = startedAt;
    const raw = plan([]);
    const review = buildReviewManifest(raw, {
      ...identity(),
      terraformRoot: "bootstrap",
    });
    const invocation = validateInvocation({
      ...validEnvironment(),
      APPROVED_MANIFEST_SHA256: review.sha256,
      APPROVED_PLAN_RUN_ID: "123455",
      BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "2340",
      EXECUTION_MODE: "apply",
    });
    const events: string[] = [];
    const dependencies = fakeDependencies(events, {
      now: () => now,
      readPlanJson: async () => {
        events.push("show");
        now = startedAt + 14 * 60_000;
        return JSON.stringify(raw);
      },
      verifyApproval: async () => ({ canonical: "", sha256: review.sha256 }),
    });
    await expect(runProtectedBootstrap(invocation, dependencies)).rejects.toThrow(
      "Too little operation, IAM-lease, or executor-token lifetime remains to converge elevation and apply",
    );
    expect(events).not.toContain("consume");
    expect(events).not.toContain("elevate");
    expect(events).not.toContain("terraform:apply");
    expect(events).toContain("release");
  });

  test("cleanup failure is surfaced and never converted into success", async () => {
    const events: string[] = [];
    const dependencies = fakeDependencies(events, {
      releaseExecutor: async () => {
        events.push("release");
        throw new Error("simulated cleanup failure");
      },
    });
    await expect(runProtectedBootstrap(validateInvocation(validEnvironment()), dependencies))
      .rejects.toThrow("cleanup did not complete exactly");
  });

  test("never-resolving API is aborted and controller finally still releases", async () => {
    const events: string[] = [];
    let aborted = false;
    const bounded = deadlineFetcher(
      async (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            aborted = true;
            reject(new Error("aborted"));
          }, { once: true });
        }),
      () => Date.now() + 1_000,
      5,
    );
    const dependencies = fakeDependencies(events, {
      acquireExecutor: async () => {
        events.push("acquire");
        await bounded("https://example.invalid/hangs");
        throw new Error("unreachable");
      },
    });
    await expect(runProtectedBootstrap(validateInvocation(validEnvironment()), dependencies))
      .rejects.toThrow("timed out");
    expect(aborted).toBeTrue();
    expect(events).toContain("release");
  });

  test("API deadline remains active after headers while the response body hangs", async () => {
    const bounded = deadlineFetcher(
      async () =>
        new Response(new ReadableStream<Uint8Array>({
          pull: async () => new Promise<void>(() => undefined),
        })),
      () => Date.now() + 1_000,
      5,
    );
    await expect(bounded("https://example.invalid/hanging-body")).rejects.toThrow("timed out");
  });

  test("fresh plan receipt is source-bound, byte-verified, and consumed exactly once", async () => {
    const now = Date.parse("2026-08-22T21:30:00.000Z");
    const planInvocation = validateInvocation(validEnvironment());
    const review = buildReviewManifest(plan([]), {
      ...identity(),
      terraformRoot: "bootstrap",
    });
    const objects = new Map<string, string>();
    const fetcher = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      if (url.hostname === "api.github.com" && url.pathname.endsWith("/actions/runs/123456")) {
        return Response.json({
          actor: { id: 16823277 },
          conclusion: "success",
          created_at: "2026-08-22T21:29:00.000Z",
          event: "workflow_dispatch",
          head_branch: "main",
          head_sha: platformSha,
          id: 123456,
          repository: { id: 1255856466 },
          run_attempt: 1,
          status: "completed",
          updated_at: "2026-08-22T21:29:30.000Z",
          workflow_id: 77,
        });
      }
      if (url.hostname === "api.github.com" && url.pathname.endsWith("/actions/workflows/77")) {
        return Response.json({ path: ".github/workflows/protected-bootstrap-implementation.yml" });
      }
      if (url.hostname === "storage.googleapis.com" && url.pathname.startsWith("/upload/")) {
        const name = url.searchParams.get("name");
        if (name === null) return new Response("", { status: 400 });
        if (objects.has(name)) return new Response("", { status: 412 });
        objects.set(name, String(init?.body));
        return Response.json({ bucket: "cdbentley-tfstate-882468538648-bootstrap", name });
      }
      if (url.hostname === "storage.googleapis.com" && url.searchParams.get("alt") === "media") {
        const encoded = url.pathname.split("/o/")[1];
        const name = encoded === undefined ? "" : decodeURIComponent(encoded);
        const body = objects.get(name);
        return body === undefined ? new Response("", { status: 404 }) : new Response(body);
      }
      return new Response("", { status: 500 });
    };
    const executorToken = "short-lived-executor-access-token-value";
    await publishPlanReceipt(
      planInvocation,
      executorToken,
      review,
      executionProof(),
      now,
      fetcher,
    );
    const publishedReceipt = JSON.parse(
      objects.get("cdbentley/bootstrap/.protected-bootstrap/plans/123456.json") ?? "{}",
    ) as Record<string, unknown>;
    expect(publishedReceipt.mode).toBe("plan");
    expect(publishedReceipt.schemaVersion).toBe(4);
    expect(publishedReceipt.exposureProof).toBeNull();
    expect(publishedReceipt.legacyCompatibilityMode).toBeFalse();
    expect(publishedReceipt.markerProof).toEqual(markers());
    expect(publishedReceipt.transitionWorkflowSha).toBe("");
    const applyInvocation = validateInvocation({
      ...validEnvironment(),
      APPROVED_MANIFEST_SHA256: review.sha256,
      APPROVED_PLAN_RUN_ID: "123456",
      BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "2340",
      EXECUTION_MODE: "apply",
      GITHUB_RUN_ID_EXACT: "123457",
    });
    const approved = await verifyPlanApproval(
      applyInvocation,
      executorToken,
      executionProof(),
      now,
      fetcher,
    );
    expect(approved.sha256).toBe(review.sha256);
    const changedMarkers = markers().map((marker, index) =>
      index === 0 ? { ...marker, generation: "999" } : marker
    );
    await expect(verifyPlanApproval(
      applyInvocation,
      executorToken,
      executionProof({ markerProof: changedMarkers }),
      now,
      fetcher,
    )).rejects.toThrow("approved deployment-parity marker proof");
    await consumePlanReceipt(applyInvocation, executorToken, review, executionProof(), now, fetcher);
    await expect(
      consumePlanReceipt(applyInvocation, executorToken, review, executionProof(), now, fetcher),
    )
      .rejects.toThrow("already published or consumed");
    expect([...objects.keys()].filter((name) => name.includes("/consumed/"))).toHaveLength(1);
    const postProof = executionProof({
      freezeProof: freezeSnapshot(now + 420_000),
    });
    await publishPostApplyReceipt(
      applyInvocation,
      executorToken,
      review,
      postProof,
      now + 420_000,
      fetcher,
    );
    const result = JSON.parse(
      objects.get("cdbentley/bootstrap/.protected-bootstrap/results/123457.json") ?? "{}",
    ) as Record<string, unknown>;
    expect(result.mode).toBe("post-apply");
    expect(result.markerProof).toEqual(markers());
    expect((result.freezeProof as Record<string, unknown>).observedAt).toBe(
      new Date(now + 420_000).toISOString(),
    );
  });

  test("Runsetta adoption publishes one immutable terminal receipt with no apply capability", async () => {
    const now = Date.parse("2026-08-26T16:00:00.000Z");
    const invocation = validateInvocation({
      ...validEnvironment(),
      EXPOSURE_ADOPTION_CONFIRMATION: "ADOPT_RUNSETTA_EXPOSURE_STATE",
      TARGET_REPOSITORY: "runsetta",
      TERRAFORM_ROOT: "exposure",
    });
    const adoptedProof = exposureProofFixture("runsetta", "adopted");
    const rawPlan = exposureAdoptionPlan([
      exposureDomainChange("runsetta.com", false),
      exposureDomainChange("www.runsetta.com", false),
    ]);
    const review = buildReviewManifest(rawPlan, exposureIdentity("runsetta", "adopted"));
    const objects = new Map<string, string>();
    const fetcher = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      if (url.hostname === "storage.googleapis.com" && url.pathname.startsWith("/upload/")) {
        expect(url.searchParams.get("ifGenerationMatch")).toBe("0");
        const name = url.searchParams.get("name");
        if (name === null) return new Response("", { status: 400 });
        if (objects.has(name)) return new Response("", { status: 412 });
        objects.set(name, String(init?.body));
        return Response.json({ bucket: REPOSITORIES.runsetta.state.exposure.bucket, name });
      }
      if (url.hostname === "storage.googleapis.com" && url.searchParams.get("alt") === "media") {
        const encoded = url.pathname.split("/o/")[1];
        const name = encoded === undefined ? "" : decodeURIComponent(encoded);
        const body = objects.get(name);
        return body === undefined ? new Response("", { status: 404 }) : new Response(body);
      }
      return new Response("", { status: 500 });
    };
    await publishPlanReceipt(
      invocation,
      "short-lived-executor-access-token-value",
      review,
      executionProof({ exposureProof: adoptedProof }),
      now,
      fetcher,
    );
    const objectName = "runsetta/exposure/.protected-bootstrap/adoptions/123456.json";
    expect([...objects.keys()]).toEqual([objectName]);
    const receipt = JSON.parse(objects.get(objectName) ?? "{}") as Record<string, unknown>;
    expect(receipt.mode).toBe("adoption-complete");
    expect(receipt.schemaVersion).toBe(1);
    expect(receipt.confirmation).toBe("ADOPT_RUNSETTA_EXPOSURE_STATE");
    expect(receipt.runId).toBe("123456");
    expect(receipt.exposureProof).toEqual(adoptedProof);
    expect(receipt).not.toHaveProperty("expiresAt");
    expect(receipt).not.toHaveProperty("planRunId");
    expect(receipt).not.toHaveProperty("approvedPlanRunId");
    await expect(publishPlanReceipt(
      invocation,
      "short-lived-executor-access-token-value",
      review,
      executionProof({ exposureProof: adoptedProof }),
      now,
      fetcher,
    )).rejects.toThrow("already published or consumed");
  });

  test("Runsetta production requires the exact successful adoption run, state, receipt, and live proof", async () => {
    const now = Date.parse("2026-08-26T16:00:00.000Z");
    const executorToken = "short-lived-executor-access-token-value";
    const ownerToken = "google-owner-access-token-value";
    const adoptionInvocation = validateInvocation({
      ...validEnvironment(),
      EXPOSURE_ADOPTION_CONFIRMATION: "ADOPT_RUNSETTA_EXPOSURE_STATE",
      TARGET_REPOSITORY: "runsetta",
      TERRAFORM_ROOT: "exposure",
    });
    const adoptedProof = exposureProofFixture("runsetta", "adopted");
    const rawPlan = exposureAdoptionPlan([
      exposureDomainChange("runsetta.com", false),
      exposureDomainChange("www.runsetta.com", false),
    ]);
    const review = buildReviewManifest(rawPlan, exposureIdentity("runsetta", "adopted"));
    const stateName = "runsetta/exposure/default.tfstate";
    const receiptName = "runsetta/exposure/.protected-bootstrap/adoptions/123456.json";
    const objects = new Map<string, {
      generation: string;
      metageneration: string;
      raw: string;
    }>([[stateName, {
      generation: "7",
      metageneration: "1",
      raw: canonicalRunsettaExposureState("123e4567-e89b-42d3-a456-426614174000"),
    }]]);
    const observedAuthorization = {
      github: new Set<string>(),
      https: new Set<string | null>(),
      live: new Set<string>(),
      storage: new Set<string>(),
    };
    const fetcher = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      const authorization = new Headers(init?.headers).get("authorization");
      if (url.hostname === "api.github.com") {
        observedAuthorization.github.add(authorization ?? "");
        if (url.pathname.endsWith("/actions/runs/123456")) {
          return Response.json({
            actor: { id: 16823277 },
            conclusion: "success",
            event: "workflow_dispatch",
            head_branch: "main",
            head_sha: platformSha,
            id: 123456,
            repository: { id: 1255856466 },
            run_attempt: 1,
            status: "completed",
            workflow_id: 77,
          });
        }
        if (url.pathname.endsWith("/actions/workflows/77")) {
          return Response.json({
            path: ".github/workflows/protected-bootstrap-implementation.yml",
          });
        }
      }
      const liveResponse = runsettaExposureApiResponse(url);
      if (liveResponse !== undefined) {
        if (url.hostname.endsWith("-run.googleapis.com")) {
          observedAuthorization.live.add(authorization ?? "");
        } else {
          observedAuthorization.https.add(authorization);
        }
        return liveResponse;
      }
      if (url.hostname === "storage.googleapis.com") {
        observedAuthorization.storage.add(authorization ?? "");
        if (url.pathname.startsWith("/upload/")) {
          const name = url.searchParams.get("name");
          if (name === null) return new Response("", { status: 400 });
          if (objects.has(name)) return new Response("", { status: 412 });
          const raw = String(init?.body);
          objects.set(name, { generation: "8", metageneration: "1", raw });
          return Response.json({
            bucket: REPOSITORIES.runsetta.state.exposure.bucket,
            generation: "8",
            name,
            size: String(Buffer.byteLength(raw)),
          });
        }
        const encoded = url.pathname.split("/o/")[1];
        const name = encoded === undefined ? "" : decodeURIComponent(encoded);
        const object = objects.get(name);
        if (object === undefined) return new Response("", { status: 404 });
        if (url.searchParams.get("alt") === "media") {
          const generation = url.searchParams.get("ifGenerationMatch");
          if (generation !== null) expect(generation).toBe(object.generation);
          return new Response(object.raw);
        }
        return Response.json({
          bucket: REPOSITORIES.runsetta.state.exposure.bucket,
          generation: object.generation,
          metageneration: object.metageneration,
          name,
          size: String(Buffer.byteLength(object.raw)),
        });
      }
      return new Response("", { status: 500 });
    };
    await publishPlanReceipt(
      adoptionInvocation,
      executorToken,
      review,
      executionProof({ exposureProof: adoptedProof }),
      now,
      fetcher,
    );
    expect(objects.has(receiptName)).toBeTrue();
    const prodInvocation = validateInvocation({
      ...validEnvironment(),
      EXPOSURE_ADOPTION_RUN_ID: "123456",
      GITHUB_RUN_ID_EXACT: "123457",
      TARGET_REPOSITORY: "runsetta",
      TERRAFORM_ROOT: "prod",
    });
    const proof = await proveExposure(
      prodInvocation,
      executorToken,
      fetcher,
      ownerToken,
      undefined,
      preparation(),
    );
    expect(proof?.adoptionReceipt).toMatchObject({
      generation: "8",
      metageneration: "1",
      runId: "123456",
      size: String(Buffer.byteLength(objects.get(receiptName)!.raw)),
    });
    expect(observedAuthorization.github).toEqual(new Set([
      "Bearer platform-actions-read-token-value",
    ]));
    expect(observedAuthorization.storage).toEqual(new Set([`Bearer ${executorToken}`]));
    expect(observedAuthorization.live).toEqual(new Set([`Bearer ${ownerToken}`]));
    expect(observedAuthorization.https).toEqual(new Set([null]));

    await expect(proveExposure(
      prodInvocation,
      executorToken,
      async (input, init) => {
        const url = new URL(String(input));
        if (url.hostname === "api.github.com" && url.pathname.endsWith("/actions/runs/123456")) {
          const response = await fetcher(input, init);
          const value = await response.json() as Record<string, unknown>;
          return Response.json({ ...value, conclusion: "failure" });
        }
        return fetcher(input, init);
      },
      ownerToken,
      undefined,
      preparation(),
    )).rejects.toThrow("adoption conclusion");

    await expect(proveExposure(
      prodInvocation,
      executorToken,
      async (input, init) => {
        const url = new URL(String(input));
        if (
          url.hostname === "us-east4-run.googleapis.com" &&
          url.pathname.endsWith("/domainmappings/runsetta.com")
        ) {
          const response = await fetcher(input, init);
          const value = await response.json() as Record<string, unknown>;
          return Response.json({
            ...value,
            spec: { ...(value.spec as object), routeName: "foreign-service" },
          });
        }
        return fetcher(input, init);
      },
      ownerToken,
      undefined,
      preparation(),
    )).rejects.toThrow("exposure mapping route");
  });

  test("consumer freeze status-filters every active state and paginates beyond 100", async () => {
    const requestedPages: number[] = [];
    const fetcher = async (input: string | URL | Request): Promise<Response> => {
      const url = new URL(String(input));
      const repository = url.pathname.split("/")[3] ?? "";
      const ids: Record<string, string> = {
        cdbentley: "1255553151",
        "critical-history": "280932482",
        healthmcp: "1025243085",
        runsetta: "711292980",
      };
      if (url.pathname.endsWith("/actions/permissions")) return Response.json({ enabled: false });
      if (url.pathname.endsWith("/actions/runs")) {
        const status = url.searchParams.get("status");
        const page = Number(url.searchParams.get("page"));
        if (repository === "cdbentley" && status === "requested") {
          requestedPages.push(page);
          return Response.json({
            total_count: 101,
            workflow_runs: Array.from({ length: page === 1 ? 100 : 1 }, () => ({
              status: "requested",
            })),
          });
        }
        return Response.json({ total_count: 0, workflow_runs: [] });
      }
      return Response.json({
        full_name: `collinbentley1/${repository}`,
        id: Number(ids[repository]),
        owner: { id: 16823277 },
      });
    };
    await expect(proveConsumerFreeze(
      "consumer-actions-token-value",
      300,
      fetcher,
      Date.parse("2026-08-22T21:30:00.000Z"),
    ))
      .rejects.toThrow("active GitHub Actions run");
    expect(requestedPages).toEqual([1, 2]);
  });

  test("state validation uses exact gRPC/overwrite probes and never reads or writes object bytes", async () => {
    const invocation = validateInvocation(validEnvironment());
    const requests: Array<{ method: string; url: string }> = [];
    const objectRequests: Array<{
      create: boolean;
      permissions: readonly string[];
      resource: string;
    }> = [];
    let granted = true;
    const fetcher = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = String(input);
      requests.push({ method: init?.method ?? "GET", url });
      expect(url).toContain("iam/testPermissions");
      return Response.json({ permissions: granted ? new URL(url).searchParams.getAll("permissions") : [] });
    };
    const probes: StateStoragePermissionProbes = {
      testObjectOverwrite: async ({ objectName }) => {
        const allowed = granted && objectName.includes("/.protected-bootstrap/plans/");
        objectRequests.push({ create: allowed, permissions: [], resource: objectName });
        return allowed;
      },
      testObjectPermissions: async ({ permissions, resource }) => {
        const returned = !granted
          ? []
          : resource.includes("/.protected-bootstrap/plans/") ||
              resource.endsWith("default.tfstate")
          ? permissions.filter((permission) => permission === "storage.objects.get")
          : [];
        objectRequests.push({ create: false, permissions: returned, resource });
        return { denied: false, permissions: returned };
      },
    };
    const state = {
      bucket: "cdbentley-tfstate-882468538648-bootstrap",
      prefix: "cdbentley/bootstrap",
    };
    await waitForStatePermissions(
      state,
      invocation,
      "short-lived-executor-access-token-value",
      "read",
      fetcher,
      async () => undefined,
      probes,
    );
    granted = false;
    await waitForStatePermissions(
      state,
      invocation,
      "short-lived-executor-access-token-value",
      "none",
      fetcher,
      async () => undefined,
      probes,
    );
    expect(requests.every((request) => request.url.includes("iam/testPermissions"))).toBeTrue();
    expect(requests.every((request) => request.method === "GET")).toBeTrue();
    expect(requests.some((request) => request.url.includes("alt=media"))).toBeFalse();
    expect(requests.some((request) => request.url.includes("storage/v2"))).toBeFalse();
    const planPermissionGrant = objectRequests.find((request) =>
      request.resource.includes("/.protected-bootstrap/plans/") &&
      request.permissions.length > 0
    );
    const planCreateGrant = objectRequests.find((request) =>
      request.resource.includes("/.protected-bootstrap/plans/") && request.create
    );
    expect(planPermissionGrant?.permissions).toEqual(["storage.objects.get"]);
    expect(planCreateGrant?.create).toBeTrue();
  });

  test("read projection cannot pass while effective exposure-state overwrite remains", async () => {
    const invocation = validateInvocation({
      ...validEnvironment(),
      EXPOSURE_ADOPTION_CONFIRMATION: "ADOPT_RUNSETTA_EXPOSURE_STATE",
      TARGET_REPOSITORY: "runsetta",
      TERRAFORM_ROOT: "exposure",
    });
    let nowMs = 1_000;
    await expect(waitForStatePermissions(
      REPOSITORIES.runsetta.state.exposure,
      invocation,
      "short-lived-executor-access-token-value",
      "read",
      async (input) => {
        nowMs += 100;
        return Response.json({
          permissions: new URL(String(input)).searchParams.getAll("permissions"),
        });
      },
      async (milliseconds) => {
        nowMs += milliseconds;
      },
      {
        testObjectOverwrite: async ({ objectName }) =>
          objectName === "runsetta/exposure/default.tfstate" ||
          objectName.includes("/.protected-bootstrap/adoptions/"),
        testObjectPermissions: async ({ permissions, resource }) => ({
          denied: false,
          permissions: resource.endsWith("default.tfstate") ||
              resource.includes("/.protected-bootstrap/adoptions/")
            ? permissions.filter((permission) => permission === "storage.objects.get")
            : [],
        }),
      },
      2_000,
      () => nowMs,
    )).rejects.toThrow("state lease did not propagate before the deadline");
  });

  // Probe answers DERIVED FROM THE LEASES, with no phase or object-name special
  // cases. That is the seam this defect lived in: every existing probe fake
  // encodes the author's belief about what the executor holds, and the belief
  // was wrong -- the acquire-time objectCreator grant on the consumed receipt
  // persisted into the mutation projection, which forbids create on it, so the
  // two contradicted each other permanently. Run 33300997122 burned its
  // approved plan discovering that. Derived probes cannot hold a wrong belief.
  const derivedProbes = (leases: readonly { role: string; condition?: { expression?: string } | null }[]) => {
    const permissionsFor = (resource: string): Set<string> => {
      const held = new Set<string>();
      for (const lease of leases) {
        const expression = lease.condition?.expression ?? "";
        if (!expression.includes(`resource.name == '${resource}'`)) continue;
        if (lease.role === "roles/storage.objectViewer") held.add("storage.objects.get");
        if (lease.role === "roles/storage.objectCreator") held.add("storage.objects.create");
        if (lease.role === "roles/storage.admin" || lease.role === "roles/storage.objectAdmin") {
          for (const permission of [
            "storage.objects.create", "storage.objects.delete",
            "storage.objects.get", "storage.objects.update",
          ]) held.add(permission);
        }
      }
      return held;
    };
    return {
      // Initiating a resumable upload authorizes against create alone, which is
      // what run 33300997122 demonstrated.
      testObjectOverwrite: async ({ bucket, objectName }: { bucket: string; objectName: string }) =>
        permissionsFor(`projects/_/buckets/${bucket}/objects/${objectName}`).has(
          "storage.objects.create",
        ),
      testObjectPermissions: async ({ permissions, resource }: { permissions: readonly string[]; resource: string }) => ({
        denied: false,
        permissions: permissions.filter((permission) => permissionsFor(resource).has(permission)),
      }),
    };
  };

  const applyInvocationFor = (digest: string) =>
    validateInvocation({
      ...validEnvironment(),
      APPROVED_MANIFEST_SHA256: digest,
      APPROVED_PLAN_RUN_ID: "123455",
      BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "2320",
      EXECUTION_MODE: "apply",
    });

  const applyReceiptLeases = () =>
    buildReceiptLeases(
      "cdbentley", "bootstrap", "123456", new Date("2026-08-30T12:00:00.000Z"),
      "apply", "123455", executorEmail, "",
    );

  // Acquire holds only the read lease; elevate adds the mutating storage lease.
  const acquireStateLeases = () => [
    ...buildStorageAcquisitionLeases(
      "cdbentley", "bootstrap", "apply", "123456",
      new Date("2026-08-30T12:00:00.000Z"), executorEmail,
    ),
  ];
  const elevatedStateLeases = () => [
    ...acquireStateLeases(),
    buildStorageLease(
      "cdbentley", "bootstrap", "123456", new Date("2026-08-30T12:00:00.000Z"),
      executorEmail, "apply", "123455",
    ),
  ];

  const runProjection = (
    expected: "mutation" | "read",
    leases: readonly { role: string; condition?: { expression?: string } | null }[],
  ) => {
    let nowMs = 1_000;
    return waitForStatePermissions(
      REPOSITORIES.cdbentley.state.bootstrap,
      applyInvocationFor("a".repeat(64)),
      "short-lived-executor-access-token-value",
      expected,
      async (input) => {
        nowMs += 100;
        return Response.json({
          permissions: new URL(String(input)).searchParams.getAll("permissions"),
        });
      },
      async (milliseconds) => {
        nowMs += milliseconds;
      },
      derivedProbes(leases) as never,
      3_000,
      () => nowMs,
    );
  };

  test("elevation's single policy write removes exactly the consume binding and adds mutation authority", async () => {
    // The projection tests above filter the consume lease out by hand, so they
    // would still pass if elevate never wired `removals` into the CAS write.
    // This starts from the policy acquire actually leaves behind, drives the
    // REAL addBindingsWithCas through the record elevate builds, and inspects
    // the transition Google would receive.
    const leaseExpiresAt = new Date("2026-08-30T12:00:00.000Z");
    const invocation = validateInvocation({
      ...validEnvironment(),
      APPROVED_MANIFEST_SHA256: "a".repeat(64),
      APPROVED_PLAN_RUN_ID: "123455",
      BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "2320",
      EXECUTION_MODE: "apply",
    });
    const acquireLeases = [
      ...buildStorageAcquisitionLeases(
        "cdbentley", "bootstrap", "apply", "123456", leaseExpiresAt, executorEmail,
      ),
      ...buildReceiptLeases(
        "cdbentley", "bootstrap", "123456", leaseExpiresAt,
        "apply", "123455", executorEmail, "",
      ),
    ];
    const consumeTitle = receiptConsumeLeaseTitle("123456");
    const consumeLease = acquireLeases.find((l) => l.condition?.title === consumeTitle)!;
    expect(consumeLease).toBeDefined();

    // The policy as acquire leaves it: contains the exact consume binding.
    const acquirePolicy: IamPolicy = addExactBindings(
      { bindings: [], etag: "acquire-etag-1", version: 3 },
      acquireLeases,
    );
    expect(
      acquirePolicy.bindings.some((b) => b.condition?.title === consumeTitle),
    ).toBeTrue();

    const elevation = elevationPolicyRecord(
      invocation, executorEmail, leaseExpiresAt, "projects/cdbentley/roles/pbt_m_x", acquireLeases,
    );

    const writes: IamPolicy[] = [];
    let generation = 1;
    await addBindingsWithCas({
      get: async () => acquirePolicy,
      label: "mutation project cdbentley",
      leases: elevation.leases,
      original: acquirePolicy,
      removals: elevation.removals,
      set: async (policy) => {
        expect(policy.etag).toBe(acquirePolicy.etag);
        writes.push(policy);
        generation += 1;
        return { ...policy, etag: `acquire-etag-${generation}` };
      },
    });

    // Exactly one etag-advancing write.
    expect(writes).toHaveLength(1);
    const written = writes[0]!;

    // The consume binding is gone from that same write.
    expect(written.bindings.some((b) => b.condition?.title === consumeTitle)).toBeFalse();

    // ONLY it. Every other acquire binding survives, including the result
    // creator, which is still needed to publish the post-apply receipt.
    for (const lease of acquireLeases) {
      if (lease.condition?.title === consumeTitle) continue;
      expect(
        written.bindings.some((b) => b.condition?.title === lease.condition?.title),
      ).toBeTrue();
    }
    expect(
      written.bindings.some((b) => b.condition?.title === "codex-receipt-create-123456"),
    ).toBeTrue();

    // And mutation authority arrived in the same write.
    for (const lease of elevation.leases) {
      expect(
        written.bindings.some((b) => b.condition?.title === lease.condition?.title),
      ).toBeTrue();
    }

    // Cleanup leaves no residue: removing both records' leases from the
    // post-elevation policy leaves no executor binding at all.
    const afterCleanup = removeExactBindings(
      removeExactBindings(written, elevation.leases, acquirePolicy),
      acquireLeases,
      acquirePolicy,
    );
    expect(() =>
      requireNoExecutorProjectBindings(afterCleanup, executorEmail)
    ).not.toThrow();
  });

  test("elevation refuses to proceed when the acquire record has no consume lease", () => {
    // A removal that silently matches nothing is the defect, not a fix.
    const invocation = validateInvocation({
      ...validEnvironment(),
      APPROVED_MANIFEST_SHA256: "a".repeat(64),
      APPROVED_PLAN_RUN_ID: "123455",
      BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "2320",
      EXECUTION_MODE: "apply",
    });
    expect(() =>
      elevationPolicyRecord(
        invocation, executorEmail, new Date("2026-08-30T12:00:00.000Z"),
        "projects/cdbentley/roles/pbt_m_x", [],
      )
    ).toThrow("could not find the recorded consumed-receipt create lease");
  });

  test("a policy write that retains a removed binding is refused", async () => {
    // Google's returned policy is the committed policy, so a removal that
    // survives it was not applied.
    const leaseExpiresAt = new Date("2026-08-30T12:00:00.000Z");
    const consume = buildReceiptLeases(
      "cdbentley", "bootstrap", "123456", leaseExpiresAt,
      "apply", "123455", executorEmail, "",
    ).find((l) => l.condition?.title === receiptConsumeLeaseTitle("123456"))!;
    const original: IamPolicy = addExactBindings(
      { bindings: [], etag: "e1", version: 3 }, [consume],
    );
    await expect(addBindingsWithCas({
      get: async () => original,
      label: "mutation project cdbentley",
      leases: [],
      original,
      removals: [consume],
      // A server that echoes the removed binding back.
      set: async () => original,
    })).rejects.toThrow("retained the mutation project cdbentley lease that this write removes");
  });

  test("the acquire grant satisfies the read projection, derived from the leases themselves", async () => {
    // Establishes the harness is faithful rather than permissive: acquire must
    // converge, and it can only do so because the executor really does hold
    // create and get on the consumed receipt at that point.
    await runProjection("read", [...applyReceiptLeases(), ...acquireStateLeases()]);
  });

  test("elevation converges only once the consumed-receipt create lease is revoked", async () => {
    const receipts = applyReceiptLeases();
    const consumeTitle = receiptConsumeLeaseTitle("123456");
    const consume = receipts.find((lease) => lease.condition?.title === consumeTitle);
    expect(consume).toBeDefined();

    // v0.5.28 shape: nothing revoked the consumed grant. This reproduces the
    // live failure from the leases, message for message.
    await expect(runProjection("mutation", [...receipts, ...elevatedStateLeases()])).rejects.toThrow(
      /consumed\/123455\.json\(unexpectedly holds storage\.objects\.create\)/,
    );

    // v0.5.29 shape: elevate removes exactly that binding and the projection
    // converges. The result receipt keeps its create grant, which it needs to
    // publish the post-apply receipt.
    const elevated = receipts.filter((lease) => lease.condition?.title !== consumeTitle);
    await runProjection("mutation", [...elevated, ...elevatedStateLeases()]);
  });

  test("apply receipt leases split the creator scope and leave the reader whole", () => {
    const leases = applyReceiptLeases();
    const creators = leases.filter((lease) => lease.role === "roles/storage.objectCreator");
    expect(creators).toHaveLength(2);
    const consume = creators.find(
      (lease) => lease.condition?.title === receiptConsumeLeaseTitle("123456"),
    )!;
    const create = creators.find(
      (lease) => lease.condition?.title !== receiptConsumeLeaseTitle("123456"),
    )!;
    // Disjoint: neither creator scope names the other's object.
    expect(consume.condition!.expression).toContain("/consumed/123455.json");
    expect(consume.condition!.expression).not.toContain("/results/");
    expect(create.condition!.expression).toContain("/results/123456.json");
    expect(create.condition!.expression).not.toContain("/consumed/");
    // The plan receipt is never creatable during apply.
    for (const creator of creators) {
      expect(creator.condition!.expression).not.toContain("/plans/");
    }
    // Read scope is unchanged: all three receipts remain readable.
    const viewer = leases.find((lease) => lease.role === "roles/storage.objectViewer")!;
    for (const fragment of ["/plans/123455.json", "/consumed/123455.json", "/results/123456.json"]) {
      expect(viewer.condition!.expression).toContain(fragment);
    }
  });

  test("recovery still recognises an orphan left by the pre-revocation shape", () => {
    // Orphan recovery compares expressions exactly, so a run that died under
    // v0.5.28 presents one combined creator binding. If the expected set no
    // longer contains that shape, recovery hard-fails and the protected path
    // refuses every run until someone cleans up by hand.
    const legacy = buildLegacyCombinedReceiptCreateLease(
      "cdbentley", "bootstrap", "123456", new Date("2026-08-30T12:00:00.000Z"),
      "123455", executorEmail,
    );
    expect(legacy.condition.title).toBe("codex-receipt-create-123456");
    expect(legacy.condition.expression).toContain("/consumed/123455.json");
    expect(legacy.condition.expression).toContain("/results/123456.json");
    // It is distinguishable from the current pair: same title as the current
    // result-only creator, different expression.
    const current = applyReceiptLeases().find(
      (lease) => lease.condition?.title === "codex-receipt-create-123456",
    )!;
    expect(current.condition!.expression).not.toBe(legacy.condition.expression);
  });

  // Apply run 33305344368 died at controller.proof on a single transient
  // `GitHub freeze proof failed with HTTP 502`. proveConsumerFreeze makes
  // ~80-120 sequential GETs across four repositories and githubJson threw on
  // the first non-ok response, so one hiccup among a hundred reads killed a
  // run that had already passed prepare, acquire, and the permission proof.
  const freezeToken = "ghp_" + "c".repeat(36);
  const CDBENTLEY_PERMISSIONS = "/repos/collinbentley1/cdbentley/actions/permissions";
  const okBody = (path: string) => {
    if (path.endsWith("/actions/permissions")) {
      return { enabled: false, sha_pinning_required: false };
    }
    if (path.includes("/actions/runs")) return { total_count: 0, workflow_runs: [] };
    // Identity must be the real contract value per repository; the freeze
    // proof refuses anything else, which is what makes this fixture faithful.
    const name = path.split("/")[3]!;
    const repository = REPOSITORY_NAMES.find((candidate) => candidate === name)!;
    return {
      full_name: `collinbentley1/${repository}`,
      id: Number(REPOSITORIES[repository].repositoryId),
      owner: { id: 16823277 },
    };
  };
  const freezeFetcher = (script: (path: string, n: number) => Response | Error) => {
    const counts = new Map<string, number>();
    const seen: { path: string; attempt: number }[] = [];
    return {
      counts,
      seen,
      fetcher: (async (input: string | URL) => {
        const path = new URL(String(input)).pathname + new URL(String(input)).search;
        const n = (counts.get(path) ?? 0) + 1;
        counts.set(path, n);
        seen.push({ attempt: n, path });
        const result = script(path, n);
        if (result instanceof Error) throw result;
        return result;
      }) as unknown as typeof fetch,
    };
  };
  const policyWith = (sleeps: number[], deadlineMs = Date.now() + 10 * 60_000) =>
    githubProofRetryPolicy(
      () => deadlineMs,
      async (ms) => {
        sleeps.push(ms);
      },
      () => Date.now(),
      () => 1,
    );

  test("a transient 502 among the freeze reads no longer kills the run", async () => {
    // The live signature of run 33305344368.
    const sleeps: number[] = [];
    const { fetcher, counts } = freezeFetcher((path, n) =>
      path === CDBENTLEY_PERMISSIONS && n === 1
        ? new Response("bad gateway", { status: 502 })
        : Response.json(okBody(path))
    );
    await proveConsumerFreeze(freezeToken, 300, fetcher, Date.now(), policyWith(sleeps));
    expect(counts.get(CDBENTLEY_PERMISSIONS)).toBe(2);
    expect(sleeps).toHaveLength(1);
  });

  test("retries stop at the attempt cap and fail closed with evidence", async () => {
    const sleeps: number[] = [];
    const { fetcher } = freezeFetcher((path) =>
      path === CDBENTLEY_PERMISSIONS
        ? new Response("bad gateway", { status: 502 })
        : Response.json(okBody(path))
    );
    await expect(
      proveConsumerFreeze(freezeToken, 300, fetcher, Date.now(), policyWith(sleeps)),
    ).rejects.toThrow(
      /GitHub proof read failed after 4 attempt\(s\): HTTP 502 from \/repos\/collinbentley1\/cdbentley\/actions\/permissions \(attempt cap reached\)/,
    );
    // Bounded: never more sleeps than the cap allows.
    expect(sleeps.length).toBeLessThanOrEqual(3);
  });

  test("a transport failure is retried and eventually succeeds", async () => {
    const sleeps: number[] = [];
    const { fetcher, counts } = freezeFetcher((path, n) =>
      path === CDBENTLEY_PERMISSIONS && n < 3
        ? new Error("socket hang up")
        : Response.json(okBody(path))
    );
    await proveConsumerFreeze(freezeToken, 300, fetcher, Date.now(), policyWith(sleeps));
    expect(counts.get(CDBENTLEY_PERMISSIONS)).toBe(3);
    expect(sleeps).toHaveLength(2);
  });

  test("a secondary rate limit is honoured; a plain 403 is terminal", async () => {
    // 429 with Retry-After sleeps exactly that long.
    const sleeps: number[] = [];
    const { fetcher } = freezeFetcher((path, n) =>
      path === CDBENTLEY_PERMISSIONS && n === 1
        ? new Response("slow down", { headers: { "retry-after": "2" }, status: 429 })
        : Response.json(okBody(path))
    );
    await proveConsumerFreeze(freezeToken, 300, fetcher, Date.now(), policyWith(sleeps));
    expect(sleeps).toEqual([2_000]);

    // The three secondary-limit shapes GitHub actually uses.
    expect(retryableGithubReadFailure(403, new Headers({ "retry-after": "1" }), "")).toBeTrue();
    expect(
      retryableGithubReadFailure(403, new Headers({ "x-ratelimit-remaining": "0" }), ""),
    ).toBeTrue();
    expect(
      retryableGithubReadFailure(403, new Headers(), "You have exceeded a secondary rate limit"),
    ).toBeTrue();

    // A plain 403 is a wrong token, not a rate limit. Terminal, first time.
    expect(retryableGithubReadFailure(403, new Headers(), "Forbidden")).toBeFalse();
    const bare: number[] = [];
    const { fetcher: f403, counts } = freezeFetcher((path) =>
      path === CDBENTLEY_PERMISSIONS
        ? new Response("Forbidden", { status: 403 })
        : Response.json(okBody(path))
    );
    await expect(
      proveConsumerFreeze(freezeToken, 300, f403, Date.now(), policyWith(bare)),
    ).rejects.toThrow(/HTTP 403 .*\(not retryable\)/);
    expect(counts.get(CDBENTLEY_PERMISSIONS)).toBe(1);
    expect(bare).toHaveLength(0);
  });

  test("401 and 404 are never retried", async () => {
    for (const status of [401, 404] as const) {
      expect(retryableGithubReadFailure(status, new Headers(), "")).toBeFalse();
      const sleeps: number[] = [];
      const { fetcher, counts } = freezeFetcher((path) =>
        path === CDBENTLEY_PERMISSIONS
          ? new Response("", { status })
          : Response.json(okBody(path))
      );
      await expect(
        proveConsumerFreeze(freezeToken, 300, fetcher, Date.now(), policyWith(sleeps)),
      ).rejects.toThrow(new RegExp(`HTTP ${status} .*\\(not retryable\\)`));
      expect(counts.get(CDBENTLEY_PERMISSIONS)).toBe(1);
      expect(sleeps).toHaveLength(0);
    }
  });

  test("cancellation wins: the deadline sentinel is never retried and no sleep outlives it", async () => {
    // The deadline fetcher's own abort is terminal by exact match. A doomed
    // run must not be resurrected by a retry.
    const sleeps: number[] = [];
    const { fetcher, counts } = freezeFetcher(() =>
      new Error("API request reached the protected operation deadline.")
    );
    await expect(
      proveConsumerFreeze(freezeToken, 300, fetcher, Date.now(), policyWith(sleeps)),
    ).rejects.toThrow("API request reached the protected operation deadline.");
    expect([...counts.values()].every((n) => n === 1)).toBeTrue();
    expect(sleeps).toHaveLength(0);

    // And a retryable failure with no time left refuses to sleep past the
    // deadline rather than stealing the runway that follows the proof.
    const late: number[] = [];
    const { fetcher: f502 } = freezeFetcher((path) =>
      path === CDBENTLEY_PERMISSIONS
        ? new Response("", { status: 502 })
        : Response.json(okBody(path))
    );
    await expect(
      proveConsumerFreeze(freezeToken, 300, f502, Date.now(), policyWith(late, Date.now() + 5_000)),
    ).rejects.toThrow(/backoff of \d+ms plus the retried request exceeds the operation deadline less its tail reserve/);
    expect(late).toHaveLength(0);
  });

  test("a Retry-After longer than the budget fails closed rather than retrying early", async () => {
    // Truncating the server's instruction to whatever budget remains retries
    // while still limited and discards the only signal the server gave us.
    const sleeps: number[] = [];
    const { fetcher, counts } = freezeFetcher((path) =>
      path === CDBENTLEY_PERMISSIONS
        ? new Response("slow down", { headers: { "retry-after": "300" }, status: 429 })
        : Response.json(okBody(path))
    );
    await expect(
      proveConsumerFreeze(freezeToken, 300, fetcher, Date.now(), policyWith(sleeps)),
    ).rejects.toThrow(/Retry-After of 300000ms plus the retried request exceeds the remaining retry budget/);
    expect(sleeps).toHaveLength(0);
    expect(counts.get(CDBENTLEY_PERMISSIONS)).toBe(1);
  });

  test("Retry-After accepts delta-seconds and an HTTP-date, and ignores nonsense", () => {
    const now = Date.parse("2026-08-30T12:00:00.000Z");
    const at = (value: string) =>
      retryAfterMs({ headers: { get: () => value } }, now);
    expect(at("2")).toBe(2_000);
    expect(at("  7 ")).toBe(7_000);
    // HTTP-date form is legal and GitHub may use it.
    expect(at("Sun, 30 Aug 2026 12:00:30 GMT")).toBe(30_000);
    // A date already past means retry now, not a negative sleep.
    expect(at("Sun, 30 Aug 2026 11:59:00 GMT")).toBe(0);
    // Unparseable falls back to our own backoff rather than guessing.
    expect(at("soon")).toBeUndefined();
    expect(retryAfterMs(undefined, now)).toBeUndefined();
  });

  test("cancellation is terminal however it is raised", async () => {
    // Only the deadline sentinel was terminal before, so an AbortError or a
    // DOMException fell through to the transport branch and was retried --
    // overriding a deliberate decision to stop.
    expect(cancellationError(new Error("API request reached the protected operation deadline."))).toBeTrue();
    const abort = new Error("aborted");
    abort.name = "AbortError";
    expect(cancellationError(abort)).toBeTrue();
    const timeout = new Error("timed out");
    timeout.name = "TimeoutError";
    expect(cancellationError(timeout)).toBeTrue();
    expect(cancellationError(new DOMException("stopped", "AbortError"))).toBeTrue();
    // An ordinary transport failure is still retryable.
    expect(cancellationError(new Error("socket hang up"))).toBeFalse();

    const sleeps: number[] = [];
    const { fetcher, counts } = freezeFetcher(() => {
      const error = new Error("aborted");
      error.name = "AbortError";
      return error;
    });
    await expect(
      proveConsumerFreeze(freezeToken, 300, fetcher, Date.now(), policyWith(sleeps)),
    ).rejects.toThrow("aborted");
    expect([...counts.values()].every((n) => n === 1)).toBeTrue();
    expect(sleeps).toHaveLength(0);
  });

  test("zero jitter is an immediate retry, not an exhausted budget", async () => {
    // Full jitter may legally return 0. Reporting that as exhaustion was both
    // wrong and misleading evidence.
    const sleeps: number[] = [];
    const zeroJitter = githubProofRetryPolicy(
      () => Date.now() + 10 * 60_000,
      async (ms) => {
        sleeps.push(ms);
      },
      () => Date.now(),
      () => 0,
    );
    const { fetcher, counts } = freezeFetcher((path, n) =>
      path === CDBENTLEY_PERMISSIONS && n === 1
        ? new Response("", { status: 502 })
        : Response.json(okBody(path))
    );
    await proveConsumerFreeze(freezeToken, 300, fetcher, Date.now(), zeroJitter);
    expect(counts.get(CDBENTLEY_PERMISSIONS)).toBe(2);
    // Retried without sleeping at all.
    expect(sleeps).toHaveLength(0);
  });

  test("slow FAILED attempts exhaust the budget even without sleeping", async () => {
    // Accounting only for sleep time meant a "60 second budget" could span far
    // more wall clock: four attempts each burning a request timeout still
    // showed room. Failed-attempt time is retry-attributable and must count --
    // unlike successful reads, which the sibling test above protects.
    let clock = 1_000_000;
    const sleeps: number[] = [];
    const policy = githubProofRetryPolicy(
      () => clock + 10 * 60_000,
      async (ms) => {
        sleeps.push(ms);
        clock += ms;
      },
      () => clock,
      () => 0,
    );
    const { fetcher, counts } = freezeFetcher((path) => {
      if (path !== CDBENTLEY_PERMISSIONS) return Response.json(okBody(path));
      clock += 40_000; // each failed attempt burns real time
      return new Response("", { status: 502 });
    });
    await expect(
      proveConsumerFreeze(freezeToken, 300, fetcher, Date.now(), policy),
    ).rejects.toThrow(/retry budget exhausted/);
    // Exhausted on elapsed time before the attempt cap could be reached.
    expect(counts.get(CDBENTLEY_PERMISSIONS)!).toBeLessThan(4);
  });

  const captureLog = async (body: () => Promise<void>): Promise<string[]> => {
    const lines: string[] = [];
    const original = console.log;
    console.log = (...parts: unknown[]) => {
      lines.push(parts.map(String).join(" "));
    };
    try {
      await body();
    } finally {
      console.log = original;
    }
    return lines;
  };

  test("exhaustion names the LAST outcome, not a stale HTTP status", async () => {
    // Tracking only an HTTP status left it stale across a later transport
    // failure: 502 then two socket errors exhausted while reporting "HTTP 502",
    // naming a cause two attempts old in both the error and the breadcrumb.
    // That sends an operator to GitHub's status page for a gateway error that
    // was already over, while the live fault is the network path.
    const sleeps: number[] = [];
    const { fetcher } = freezeFetcher((path, n) => {
      if (path !== CDBENTLEY_PERMISSIONS) return Response.json(okBody(path));
      return n === 1 ? new Response("bad gateway", { status: 502 }) : new Error("socket hang up");
    });
    let thrown: unknown;
    const lines = await captureLog(async () => {
      thrown = await proveConsumerFreeze(
        freezeToken,
        300,
        fetcher,
        Date.now(),
        policyWith(sleeps),
      ).catch((error: unknown) => error);
    });
    expect((thrown as Error).message).toBe(
      "GitHub proof read failed after 4 attempt(s): " +
        "transport failure (socket hang up) from " +
        "/repos/collinbentley1/cdbentley/actions/permissions (attempt cap reached).",
    );
    // The stale status must not appear anywhere in the final evidence.
    expect((thrown as Error).message).not.toContain("502");
    // Each breadcrumb reports the attempt it actually describes.
    const outcomes = lines
      .filter((line) => line.includes("GitHub proof retry"))
      .map((line) => /outcome=(.*) attempt=(\d+)/.exec(line))
      .map((match) => [match![2], match![1]]);
    expect(outcomes).toEqual([
      ["1", "HTTP 502"],
      ["2", "transport failure (socket hang up)"],
      ["3", "transport failure (socket hang up)"],
    ]);
  });

  test("a hostile transport error cannot flood the evidence", async () => {
    // Transport error messages are attacker-influenced in the limit (proxy or
    // gateway text). Evidence has to stay readable and bounded.
    const sleeps: number[] = [];
    const { fetcher } = freezeFetcher((path) =>
      path === CDBENTLEY_PERMISSIONS
        ? new Error("x".repeat(50_000))
        : Response.json(okBody(path))
    );
    const thrown = (await proveConsumerFreeze(
      freezeToken,
      300,
      fetcher,
      Date.now(),
      policyWith(sleeps),
    ).catch((error: unknown) => error)) as Error;
    // Truncation is marked, not silent: evidence that was cut must say so.
    expect(thrown.message).toContain("transport failure (" + "x".repeat(80) + "...)");
    expect(thrown.message.length).toBeLessThan(300);
  });

  test("a transport failure followed by an HTTP failure reports the HTTP one", async () => {
    // The converse direction: the outcome must track forward as well as reset,
    // so a fix that merely blanked the status on transport errors is not enough.
    const sleeps: number[] = [];
    const { fetcher } = freezeFetcher((path, n) => {
      if (path !== CDBENTLEY_PERMISSIONS) return Response.json(okBody(path));
      return n === 1 ? new Error("socket hang up") : new Response("", { status: 503 });
    });
    await expect(
      proveConsumerFreeze(freezeToken, 300, fetcher, Date.now(), policyWith(sleeps)),
    ).rejects.toThrow(
      /after 4 attempt\(s\): HTTP 503 from \/repos\/collinbentley1\/cdbentley\/actions\/permissions/,
    );
  });

  test("two unrelated blips far apart in one proof both still retry", async () => {
    // The armed-window budget counted SUCCESSFUL reads against it. One proof
    // walks all four repositories sequentially (~80-120 GETs), so a blip on
    // cdbentley armed the window, a minute of clean reads drained it, and a
    // blip on critical-history died on its first attempt with zero retries
    // granted -- the exact failure this layer exists to prevent, and the
    // post-apply freeze proof (never-rerun) is the op most exposed.
    let clock = 1_000_000;
    const sleeps: number[] = [];
    const policy = githubProofRetryPolicy(
      () => clock + 30 * 60_000,
      async (ms) => {
        sleeps.push(ms);
        clock += ms;
      },
      () => clock,
      () => 1,
    );
    const LAST = "/repos/collinbentley1/critical-history/actions/permissions";
    const { fetcher, counts } = freezeFetcher((path, n) => {
      // Every read costs real time, as it does live.
      clock += 4_000;
      if ((path === CDBENTLEY_PERMISSIONS || path === LAST) && n === 1) {
        return new Response("bad gateway", { status: 502 });
      }
      return Response.json(okBody(path));
    });
    await proveConsumerFreeze(freezeToken, 300, fetcher, Date.now(), policy);
    // Both blips were retried; neither was refused for a budget that
    // successful reads had drained.
    expect(counts.get(CDBENTLEY_PERMISSIONS)).toBe(2);
    expect(counts.get(LAST)).toBe(2);
    expect(sleeps).toHaveLength(2);
  });

  test("one repository's four concurrent reads share the budget and survive", async () => {
    // The real simultaneous case: proveConsumerFreeze walks repositories
    // sequentially but issues each repository's four reads together, so four
    // chains accumulate into one policy. A simultaneous blip must not exhaust
    // it -- overlapping spend is double-counted, which is conservative, but
    // must not be so conservative that a blip kills the proof.
    const sleeps: number[] = [];
    const { fetcher, counts } = freezeFetcher((path, n) =>
      path.startsWith("/repos/collinbentley1/cdbentley") && n === 1
        ? new Response("bad gateway", { status: 502 })
        : Response.json(okBody(path))
    );
    await proveConsumerFreeze(freezeToken, 300, fetcher, Date.now(), policyWith(sleeps));
    // Every cdbentley URL blipped once, retried once, and succeeded -- the run
    // listings paginate, so this is more concurrent chains than the four reads
    // alone. The proof completed rather than exhausting a shared budget.
    const cdbentley = [...counts.entries()].filter(([path]) =>
      path.startsWith("/repos/collinbentley1/cdbentley")
    );
    expect(cdbentley.length).toBeGreaterThanOrEqual(4);
    expect(sleeps).toHaveLength(cdbentley.length);
    expect(cdbentley.every(([, n]) => n === 2)).toBeTrue();
  });

  test("a primary quota limit fails closed naming its reset, not the attempt cap", async () => {
    // remaining: 0 with an epoch reset is the PRIMARY quota, and it arrives
    // without Retry-After. Ignoring the reset burned three doomed jittered
    // retries and reported "attempt cap reached" -- the wrong cause, and three
    // wasted attempts of phase time.
    const now = Date.now();
    const sleeps: number[] = [];
    const { fetcher, counts } = freezeFetcher((path) =>
      path === CDBENTLEY_PERMISSIONS
        ? new Response("", {
          headers: {
            "x-ratelimit-remaining": "0",
            "x-ratelimit-reset": String(Math.floor(now / 1_000) + 900),
          },
          status: 403,
        })
        : Response.json(okBody(path))
    );
    await expect(
      proveConsumerFreeze(freezeToken, 300, fetcher, now, policyWith(sleeps, now + 30 * 60_000)),
    ).rejects.toThrow(/x-ratelimit-reset in \d+ms plus the retried request exceeds the remaining retry budget of \d+ms/);
    // Refused immediately, naming the reset. No doomed retries.
    expect(counts.get(CDBENTLEY_PERMISSIONS)).toBe(1);
    expect(sleeps).toHaveLength(0);
  });

  test("a six-digit Retry-After is honoured or refused, never silently dropped", () => {
    const now = Date.parse("2026-08-30T12:00:00.000Z");
    // A {1,5} bound sent this to Date.parse, which is NaN, so it became a
    // 1-8s jitter: the server's instruction ignored.
    expect(retryAfterMs({ headers: { get: () => "999999" } }, now)).toBe(999_999_000);
  });

  test("the wrapper's own request timeout stays retryable", async () => {
    // cancellationError is terminal for AbortError/TimeoutError/DOMException.
    // deadlineFetcher's per-request timeout is a plain Error and must NOT be
    // caught by it, or every per-request timeout becomes terminal and this
    // whole layer dies. Pinning the coupling so a future refactor to
    // AbortSignal.timeout() fails here rather than in production.
    expect(cancellationError(new Error("Protected API request timed out before exact cleanup.")))
      .toBeFalse();
    const sleeps: number[] = [];
    const { fetcher, counts } = freezeFetcher((path, n) =>
      path === CDBENTLEY_PERMISSIONS && n === 1
        ? new Error("Protected API request timed out before exact cleanup.")
        : Response.json(okBody(path))
    );
    await proveConsumerFreeze(freezeToken, 300, fetcher, Date.now(), policyWith(sleeps));
    expect(counts.get(CDBENTLEY_PERMISSIONS)).toBe(2);
  });

  test("granted backoff accumulates, so a second long wait is refused", async () => {
    // The budget has to remember what it already granted. Two 40s server waits
    // cannot both fit in 60s; the second must fail closed rather than push the
    // phase past its envelope.
    let clock = 1_000_000;
    const sleeps: number[] = [];
    const policy = githubProofRetryPolicy(
      () => clock + 30 * 60_000,
      async (ms) => {
        sleeps.push(ms);
        clock += ms;
      },
      () => clock,
      () => 1,
    );
    const { fetcher } = freezeFetcher((path) =>
      path === CDBENTLEY_PERMISSIONS
        ? new Response("", { headers: { "retry-after": "40" }, status: 429 })
        : Response.json(okBody(path))
    );
    await expect(
      proveConsumerFreeze(freezeToken, 300, fetcher, Date.now(), policy),
    ).rejects.toThrow(/Retry-After of 40000ms plus the retried request exceeds the remaining retry budget of 20000ms/);
    // The first wait was granted and charged; the second was refused.
    expect(sleeps).toEqual([40_000]);
  });

  test("a wait that exactly fills the budget is refused, not slept to zero", async () => {
    // Granting a retry costs the backoff AND the attempt after it. Checking
    // only the backoff let a Retry-After exactly equal to the remaining budget
    // pass, sleep the budget to zero, then start a request that ran 20s past
    // it -- so the advertised 60s bound was really 60s plus an overrun.
    let clock = 1_000_000;
    const sleeps: number[] = [];
    const policy = githubProofRetryPolicy(
      () => clock + 30 * 60_000,
      async (ms) => {
        sleeps.push(ms);
        clock += ms;
      },
      () => clock,
      () => 1,
    );
    const { fetcher } = freezeFetcher((path) =>
      path === CDBENTLEY_PERMISSIONS
        ? new Response("", { headers: { "retry-after": "60" }, status: 429 })
        : Response.json(okBody(path))
    );
    await expect(
      proveConsumerFreeze(freezeToken, 300, fetcher, Date.now(), policy),
    ).rejects.toThrow(
      /Retry-After of 60000ms plus the retried request exceeds the remaining retry budget/,
    );
    expect(sleeps).toHaveLength(0);
  });

  test("a hostile transport error cannot forge a log record", async () => {
    // Truncation alone does not stop a newline from forging a second log line,
    // or an escape sequence from rewriting the operator's terminal. Evidence
    // has to stay one record.
    expect(evidenceText("a\nb", 80)).toBe("a\\u{a}b");
    expect(evidenceText("\u001b[2Kfake", 80)).toBe("\\u{1b}[2Kfake");
    // Zl and Zp. JavaScript itself treats these as line terminators and many
    // log readers break records on them, yet they are neither C0/C1 nor bidi,
    // so an enumerated range list missed them entirely.
    expect(evidenceText("a\u2028b", 80)).toBe("a\\u{2028}b");
    expect(evidenceText("a\u2029b", 80)).toBe("a\\u{2029}b");
    // Cf, one representative per shape: bidi override, the mark an enumerated
    // list omitted, a zero-width character, and the byte-order mark.
    expect(evidenceText("real\u202edekaf", 80)).toBe("real\\u{202e}dekaf");
    expect(evidenceText("a\u061cb", 80)).toBe("a\\u{61c}b");
    expect(evidenceText("a\u200bb", 80)).toBe("a\\u{200b}b");
    expect(evidenceText("a\ufeffb", 80)).toBe("a\\u{feff}b");
    // Cc, including the C1 range some terminals also act on.
    expect(evidenceText("a\u009bb", 80)).toBe("a\\u{9b}b");
    // Cs. A lone surrogate would corrupt any JSON encoding of this evidence.
    expect(evidenceText("a\ud800b", 80)).toBe("a\\u{d800}b");
    // Benign text is left exactly as it is, including astral characters.
    expect(evidenceText("plain \u00a0 text \u{1f600}", 80)).toBe("plain \u00a0 text \u{1f600}");
    // The bound applies after escaping and never splits an escape token.
    expect(evidenceText("\u2028\u2028", 9)).toBe("\\u{2028}...");
    const sleeps: number[] = [];
    // A forged breadcrumb behind each separator an attacker might reach for.
    const { fetcher } = freezeFetcher((path) =>
      path === CDBENTLEY_PERMISSIONS
        ? new Error(
          "boom\u2028Protected bridge GitHub proof retry path=/forged outcome=ok" +
            "\u2029second forged record\nthird",
        )
        : Response.json(okBody(path))
    );
    const thrown = (await proveConsumerFreeze(
      freezeToken,
      300,
      fetcher,
      Date.now(),
      policyWith(sleeps),
    ).catch((error: unknown) => error)) as Error;
    expect(thrown.message).toContain("boom\\u{2028}Protected bridge");
    // Not one of the three separators survives as a real record boundary.
    expect(thrown.message).not.toContain("\u2028");
    expect(thrown.message).not.toContain("\u2029");
    expect(thrown.message).not.toContain("\n");
  });

  test("the tail reserve covers the retried request, not just its backoff", async () => {
    // Starting a retry with only "reserve + backoff" left let the request
    // itself eat the reserve the receipt publish depends on. The reserve has
    // to sit behind the retried request, not in front of it.
    let clock = 1_000_000;
    const sleeps: number[] = [];
    // Exactly enough for the backoff plus the reserve, and 10s short of also
    // covering the request that follows.
    const deadline = clock + 1_000 + 60_000 + 10_000;
    const policy = githubProofRetryPolicy(
      () => deadline,
      async (ms) => {
        sleeps.push(ms);
        clock += ms;
      },
      () => clock,
      () => 1,
    );
    const { fetcher } = freezeFetcher((path) =>
      path === CDBENTLEY_PERMISSIONS
        ? new Response("", { status: 502 })
        : Response.json(okBody(path))
    );
    await expect(
      proveConsumerFreeze(freezeToken, 300, fetcher, Date.now(), policy),
    ).rejects.toThrow(
      /backoff of 1000ms plus the retried request exceeds the operation deadline less its tail reserve/,
    );
    expect(sleeps).toHaveLength(0);
  });

  test("without a policy the reads behave exactly as they did before", async () => {
    const { fetcher, counts } = freezeFetcher((path) =>
      path === CDBENTLEY_PERMISSIONS
        ? new Response("", { status: 502 })
        : Response.json(okBody(path))
    );
    await expect(proveConsumerFreeze(freezeToken, 300, fetcher)).rejects.toThrow(
      "GitHub freeze proof failed with HTTP 502.",
    );
    expect(counts.get(CDBENTLEY_PERMISSIONS)).toBe(1);
  });

  test("a convergence timeout names the object and permissions that never matched", async () => {
    // Apply run 33296971474 spent the whole five-minute elevation window in
    // this probe and failed with nothing but "The executor state lease did not
    // propagate before the deadline" -- after consuming the approved plan,
    // which is the most expensive moment in the run to learn nothing. The
    // per-object verdict was computed and discarded.
    const invocation = validateInvocation({
      ...validEnvironment(),
      APPROVED_MANIFEST_SHA256: "a".repeat(64),
      APPROVED_PLAN_RUN_ID: "123455",
      BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "2320",
      EXECUTION_MODE: "apply",
    });
    let nowMs = 1_000;
    const state = REPOSITORIES.cdbentley.state.bootstrap;
    const consumed = `${state.prefix}/.protected-bootstrap/consumed/123455.json`;
    await expect(waitForStatePermissions(
      state,
      invocation,
      "short-lived-executor-access-token-value",
      "mutation",
      async (input) => {
        nowMs += 100;
        return Response.json({
          permissions: new URL(String(input)).searchParams.getAll("permissions"),
        });
      },
      async (milliseconds) => {
        nowMs += milliseconds;
      },
      {
        // The consumed receipt is live and the executor holds create on it,
        // which the mutation projection forbids. Everything else converges, so
        // the message must isolate this one object.
        testObjectOverwrite: async ({ objectName }) => objectName === consumed,
        testObjectPermissions: async ({ permissions, resource }) => ({
          denied: false,
          permissions: resource.endsWith(consumed)
            ? permissions.filter((permission) => permission === "storage.objects.get")
            : permissions,
        }),
      },
      2_000,
      () => nowMs,
    )).rejects.toThrow(/consumed\/123455\.json\(unexpectedly holds storage\.objects\.create\)/);
  });

  test("a persistent denial is named rather than reported as a stale mismatch", async () => {
    // A never-converging 403 is the case the denial handling exists for, and
    // the early return skipped the diagnostic entirely -- so the timeout either
    // named nothing or, worse, reported a completed earlier scan's verdict as
    // if it were current.
    const invocation = validateInvocation(validEnvironment());
    let nowMs = 1_000;
    const state = REPOSITORIES.cdbentley.state.bootstrap;
    await expect(waitForStatePermissions(
      state,
      invocation,
      "short-lived-executor-access-token-value",
      "read",
      async () => {
        nowMs += 100;
        return new Response("", { status: 403 });
      },
      async (milliseconds) => {
        nowMs += milliseconds;
      },
      {
        testObjectOverwrite: async () => false,
        testObjectPermissions: async () => ({ denied: true, permissions: [] }),
      },
      2_000,
      () => nowMs,
    )).rejects.toThrow(
      new RegExp(`bucket ${state.bucket}\\(denied with HTTP 403\\)`),
    );
  });

  test("a convergence timeout names a bucket-only mismatch", async () => {
    // The bucket probe consumed the window on its own: every object converges
    // but storage.objects.list never appears. Without the bucket verdict the
    // message falls back to the generic text and names nothing.
    const invocation = validateInvocation(validEnvironment());
    let nowMs = 1_000;
    const state = REPOSITORIES.cdbentley.state.bootstrap;
    await expect(waitForStatePermissions(
      state,
      invocation,
      "short-lived-executor-access-token-value",
      "read",
      async () => {
        nowMs += 100;
        // Bucket probe answers successfully with no permissions.
        return Response.json({ kind: "storage#testIamPermissionsResponse", permissions: [] });
      },
      async (milliseconds) => {
        nowMs += milliseconds;
      },
      {
        testObjectOverwrite: async () => false,
        testObjectPermissions: async ({ permissions }) => ({
          denied: false,
          permissions: permissions.filter((permission) => permission === "storage.objects.get"),
        }),
      },
      2_000,
      () => nowMs,
    )).rejects.toThrow(
      new RegExp(`bucket ${state.bucket}\\(missing storage\\.objects\\.list\\)`),
    );
  });

  test("a convergence timeout names a missing permission too", async () => {
    const invocation = validateInvocation(validEnvironment());
    let nowMs = 1_000;
    const state = REPOSITORIES.cdbentley.state.bootstrap;
    await expect(waitForStatePermissions(
      state,
      invocation,
      "short-lived-executor-access-token-value",
      "read",
      async (input) => {
        nowMs += 100;
        return Response.json({
          permissions: new URL(String(input)).searchParams.getAll("permissions"),
        });
      },
      async (milliseconds) => {
        nowMs += milliseconds;
      },
      {
        testObjectOverwrite: async () => false,
        // Nothing is granted anywhere, so the read projection's required
        // storage.objects.get is missing on the state object.
        testObjectPermissions: async () => ({ denied: false, permissions: [] }),
      },
      2_000,
      () => nowMs,
    )).rejects.toThrow(/default\.tfstate\(missing storage\.objects\.get\)/);
  });

  test("state grant and revocation proofs converge beyond seven realistic-latency scans within the shared deadline", async () => {
    const invocation = validateInvocation(validEnvironment());
    const state = {
      bucket: "cdbentley-tfstate-882468538648-bootstrap",
      prefix: "cdbentley/bootstrap",
    };
    const run = async (expected: "none" | "read"): Promise<void> => {
      const startedAtMs = 1_000;
      let nowMs = startedAtMs;
      let scan = 0;
      let active = expected === "none";
      const fetcher = async (input: string | URL | Request): Promise<Response> => {
        scan += 1;
        nowMs += 20_000;
        active = expected === "none" ? scan < 8 : scan >= 8;
        const requested = new URL(String(input)).searchParams.getAll("permissions");
        return Response.json({ permissions: active ? requested : [] });
      };
      const probes: StateStoragePermissionProbes = {
        testObjectOverwrite: async ({ objectName }) =>
          active && objectName.includes("/.protected-bootstrap/plans/"),
        testObjectPermissions: async ({ permissions, resource }) => ({
          denied: false,
          permissions: active &&
              (resource.endsWith("default.tfstate") ||
                resource.includes("/.protected-bootstrap/plans/"))
            ? permissions.filter((permission) => permission === "storage.objects.get")
            : [],
        }),
      };
      await waitForStatePermissions(
        state,
        invocation,
        "short-lived-executor-access-token-value",
        expected,
        fetcher,
        async (milliseconds) => {
          nowMs += milliseconds;
        },
        probes,
        startedAtMs + 5 * 60_000,
        () => nowMs,
      );
      expect(scan).toBe(8);
      expect(nowMs - startedAtMs).toBeGreaterThan(3 * 60_000);
      expect(nowMs - startedAtMs).toBeLessThan(5 * 60_000);
    };

    await run("read");
    await run("none");
  });

  test("shared permission convergence fails closed exactly at its bounded deadline", async () => {
    const invocation = validateInvocation(validEnvironment());
    const startedAtMs = 1_000;
    const deadlineMs = startedAtMs + 3 * 60_000;
    let nowMs = startedAtMs;
    let scan = 0;
    await expect(waitForStatePermissions(
      {
        bucket: "cdbentley-tfstate-882468538648-bootstrap",
        prefix: "cdbentley/bootstrap",
      },
      invocation,
      "short-lived-executor-access-token-value",
      "read",
      async () => {
        scan += 1;
        nowMs += 20_000;
        return Response.json({ permissions: [] });
      },
      async (milliseconds) => {
        nowMs += milliseconds;
      },
      {
        testObjectOverwrite: async () => false,
        testObjectPermissions: async () => ({ denied: false, permissions: [] }),
      },
      deadlineMs,
      () => nowMs,
    )).rejects.toThrow("state lease did not propagate before the deadline");
    expect(scan).toBe(7);
    expect(nowMs).toBe(deadlineMs);
  });

  test("state scans apply the absolute consistency deadline to every subprobe", async () => {
    const invocation = validateInvocation(validEnvironment());
    const startedAtMs = 1_000;
    const deadlineMs = startedAtMs + 10_000;
    let nowMs = startedAtMs;
    let bucketCalls = 0;
    let objectPermissionCalls = 0;
    let objectCreateCalls = 0;
    let observedRpcTimeoutMs: number | undefined;
    await expect(waitForStatePermissions(
      {
        bucket: "cdbentley-tfstate-882468538648-bootstrap",
        prefix: "cdbentley/bootstrap",
      },
      invocation,
      "short-lived-executor-access-token-value",
      "read",
      async (input) => {
        bucketCalls += 1;
        nowMs += 8_000;
        return Response.json({
          permissions: new URL(String(input)).searchParams.getAll("permissions"),
        });
      },
      async () => undefined,
      {
        testObjectOverwrite: async () => {
          objectCreateCalls += 1;
          return true;
        },
        testObjectPermissions: async (_request, options) => {
          objectPermissionCalls += 1;
          observedRpcTimeoutMs = options?.timeoutMs;
          nowMs += 3_000;
          return { denied: false, permissions: ["storage.objects.get"] };
        },
      },
      deadlineMs,
      () => nowMs,
    )).rejects.toThrow("state lease did not propagate before the deadline");
    expect(bucketCalls).toBe(1);
    expect(objectPermissionCalls).toBe(1);
    expect(objectCreateCalls).toBe(0);
    expect(observedRpcTimeoutMs).toBe(2_000);
    expect(nowMs).toBeGreaterThan(deadlineMs);
  });

  test("state validation treats gRPC credential denial as absence only for the no-access proof", async () => {
    const invocation = validateInvocation(validEnvironment());
    const state = {
      bucket: "cdbentley-tfstate-882468538648-bootstrap",
      prefix: "cdbentley/bootstrap",
    };
    const grantedBucketFetcher = async (input: string | URL | Request): Promise<Response> => {
      const requested = new URL(String(input)).searchParams.getAll("permissions");
      return Response.json({ kind: "storage#testIamPermissionsResponse", permissions: requested });
    };
    const deniedBucketFetcher = async (): Promise<Response> => new Response("", { status: 403 });
    const denied: StateStoragePermissionProbes = {
      testObjectOverwrite: async () => false,
      testObjectPermissions: async () => ({ denied: true, permissions: [] }),
    };
    await waitForStatePermissions(
      state,
      invocation,
      "short-lived-executor-access-token-value",
      "none",
      deniedBucketFetcher,
      async () => undefined,
      denied,
    );
    // A PERMISSION_DENIED answer is a grant that has not propagated yet, so the
    // loop keeps re-scanning and only the deadline ends it. Throwing on the
    // first denial threw away four of the five available minutes.
    let deniedClock = 0;
    await expect(waitForStatePermissions(
      state,
      invocation,
      "short-lived-executor-access-token-value",
      "read",
      grantedBucketFetcher,
      async () => {
        deniedClock += 1_000;
      },
      denied,
      30_000,
      () => deniedClock,
    )).rejects.toThrow("did not propagate before the deadline");
    await expect(waitForStatePermissions(
      state,
      invocation,
      "short-lived-executor-access-token-value",
      "none",
      deniedBucketFetcher,
      async () => undefined,
      {
        ...denied,
        testObjectPermissions: async () => ({
          denied: true,
          permissions: ["storage.objects.get"],
        }),
      },
    )).rejects.toThrow("Denied storage object permission RPC returned permissions");
  });

  test("state permission convergence waits out both denial codes", async () => {
    const state = {
      bucket: "cdbentley-tfstate-882468538648-bootstrap",
      prefix: "cdbentley/bootstrap",
    };
    const invocation = validateInvocation(validEnvironment());
    const grantedRead = (permissions: readonly string[], resource: string) =>
      resource.includes("/.protected-bootstrap/plans/") || resource.endsWith("default.tfstate")
        ? permissions.filter((permission) => permission === "storage.objects.get")
        : [];
    const grantedBucketFetcher = async (input: URL | string): Promise<Response> => {
      const requested = new URL(String(input)).searchParams.getAll("permissions");
      return Response.json({ kind: "storage#testIamPermissionsResponse", permissions: requested });
    };

    // Both denial codes are transient, and the bridge is what makes them so.
    // UNAUTHENTICATED (16) is the executor's own disable/re-enable cycle: the
    // token is minted before `executor.disable`, and the re-enable that
    // immediately precedes this projection has not propagated yet.
    // PERMISSION_DENIED (7) is a lease still propagating.
    for (const status of [7, 16]) {
      let clock = 0;
      let attempts = 0;
      await waitForStatePermissions(
        state,
        invocation,
        "short-lived-executor-access-token-value",
        "read",
        grantedBucketFetcher,
        async () => {
          clock += 1_000;
        },
        {
          testObjectOverwrite: async ({ objectName }) =>
            objectName.includes("/.protected-bootstrap/plans/"),
          testObjectPermissions: async ({ permissions, resource }) => {
            attempts += 1;
            return attempts <= 3
              ? { denied: true, permissions: [], status }
              : { denied: false, permissions: grantedRead(permissions, resource) };
          },
        },
        300_000,
        () => clock,
      );
      expect(attempts).toBeGreaterThan(3);
    }

    // A denial that never heals still fails, on the deadline rather than on the
    // first scan, and names propagation rather than the credential.
    let deadlineClock = 0;
    await expect(waitForStatePermissions(
      state,
      invocation,
      "short-lived-executor-access-token-value",
      "read",
      grantedBucketFetcher,
      async () => {
        deadlineClock += 1_000;
      },
      {
        testObjectOverwrite: async () => false,
        testObjectPermissions: async () => ({ denied: true, permissions: [], status: 16 }),
      },
      30_000,
      () => deadlineClock,
    )).rejects.toThrow("did not propagate before the deadline");
  });

  test("elevation admits the leases acquire granted and nothing else", () => {
    const email = "gha-pbt-0123456789ab@cdbentley.iam.gserviceaccount.com";
    const member = `serviceAccount:${email}`;
    const acquireLease = {
      condition: {
        description: "codex executor read lease",
        expression: 'request.time < timestamp("2026-08-28T06:00:00Z")',
        title: "codex-executor-read-33139552461",
      },
      members: [member],
      role: "projects/cdbentley/roles/pbt_read_33139552461",
    };
    const granted = { bindings: [acquireLease], version: 3 };

    // Acquire's guard: a freshly created executor must hold nothing at all.
    expect(() => requireNoExecutorProjectBindings({ bindings: [], version: 3 }, email)).not.toThrow();
    expect(() => requireNoExecutorProjectBindings(granted, email))
      .toThrow("standing project IAM binding");

    // Elevation's guard: the executor legitimately still holds the acquire
    // leases, so absolute absence is the wrong question. Asking it there made
    // every apply throw *after* consumeApproval had already burned the plan.
    expect(knownExecutorBindingsRemain(granted, email, [acquireLease])).toBeTrue();

    // The security property is unchanged: authority nobody granted still fails.
    const smuggled = {
      bindings: [acquireLease, { members: [member], role: "roles/owner" }],
      version: 3,
    };
    expect(() => knownExecutorBindingsRemain(smuggled, email, [acquireLease]))
      .toThrow("retained unknown standing project authority");

    // A lease whose condition was altered is not the lease that was granted.
    const rewritten = {
      bindings: [{
        ...acquireLease,
        condition: { ...acquireLease.condition, expression: "true" },
      }],
      version: 3,
    };
    expect(() => knownExecutorBindingsRemain(rewritten, email, [acquireLease]))
      .toThrow("retained unknown standing project authority");

    // Bindings for other members are none of this guard's business.
    expect(knownExecutorBindingsRemain(
      { bindings: [{ members: ["serviceAccount:other@x.iam.gserviceaccount.com"], role: "roles/viewer" }], version: 3 },
      email,
      [],
    )).toBeFalse();
  });

  test("elevation passes acquire's recorded leases to the executor-binding guard", async () => {
    const source = await readFile(join(root, "tools/ci/protected-bootstrap-bridge.ts"), "utf8");
    // Structural, because no fixture drives acquire -> elevate against stateful
    // IAM yet; that missing integration is what let the self-collision ship.
    expect(source).toContain("this.#projectMutation = await this.#recordAndAdd(");
    expect(source).toContain("this.#projectMutation?.leases ?? []");
    expect(source).toContain("knownExecutorBindingsRemain(original, forbiddenMemberEmail, grantedExecutorLeases)");
  });

  test("every control-plane probe waits out a propagating 403", async () => {
    // This projection runs during elevation, i.e. after consumeApproval has
    // already burned the approved plan, so a grant that has merely not
    // propagated yet must not abort it.
    const bootstrap = validateInvocation(validEnvironment());
    let projectAttempts = 0;
    let clock = 0;
    await waitForControlPermissions(
      bootstrap,
      "short-lived-executor-access-token-value",
      "mutation",
      async (input, init) => {
        const url = String(input);
        const permissions =
          (JSON.parse(String(init?.body)) as { permissions: string[] }).permissions;
        if (url.includes("cloudresourcemanager")) {
          projectAttempts += 1;
          if (projectAttempts <= 2) return new Response("", { status: 403 });
        }
        return Response.json({ permissions });
      },
      async () => {
        clock += 1_000;
      },
      300_000,
      () => clock,
    );
    expect(projectAttempts).toBeGreaterThan(2);

    // A prod elevation adds the three runtime actAs leases immediately before
    // this scan, so their propagation 403 has exactly the same standing.
    const prod = validateInvocation({ ...validEnvironment(), TERRAFORM_ROOT: "prod" });
    let runtimeAttempts = 0;
    let prodClock = 0;
    await waitForControlPermissions(
      prod,
      "short-lived-executor-access-token-value",
      "mutation",
      async (input, init) => {
        const url = String(input);
        const permissions =
          (JSON.parse(String(init?.body)) as { permissions: string[] }).permissions;
        if (url.includes("iam.googleapis.com")) {
          runtimeAttempts += 1;
          if (runtimeAttempts <= 3) return new Response("", { status: 403 });
          return Response.json({
            permissions: permissions.filter(
              (permission) => permission === "iam.serviceAccounts.actAs",
            ),
          });
        }
        return Response.json({ permissions });
      },
      async () => {
        prodClock += 1_000;
      },
      300_000,
      () => prodClock,
    );
    expect(runtimeAttempts).toBeGreaterThan(3);

    // 401 is the same transient: the executor's re-enable immediately precedes
    // this projection, and a token minted before the disable is rejected until
    // it propagates.
    let unauthClock = 0;
    let unauthAttempts = 0;
    await waitForControlPermissions(
      bootstrap,
      "short-lived-executor-access-token-value",
      "mutation",
      async (input, init) => {
        unauthAttempts += 1;
        if (unauthAttempts <= 2) return new Response("", { status: 401 });
        const permissions =
          (JSON.parse(String(init?.body)) as { permissions: string[] }).permissions;
        return Response.json({ permissions });
      },
      async () => {
        unauthClock += 1_000;
      },
      300_000,
      () => unauthClock,
    );
    expect(unauthAttempts).toBeGreaterThan(2);

    // Only 401 and 403 are transient. Anything else is still fatal, immediately.
    await expect(waitForControlPermissions(
      bootstrap,
      "short-lived-executor-access-token-value",
      "mutation",
      async () => new Response("", { status: 500 }),
      async () => undefined,
      300_000,
      () => 0,
    )).rejects.toThrow("Project permission test failed with HTTP 500");
  });

  test("the token drain is derived from the verified capability in every mode", async () => {
    const source = await readFile(join(root, "tools/ci/protected-bootstrap-bridge.ts"), "utf8");
    // Structural, because `prepare` is stubbed in the dependency harness and the
    // selection itself is therefore never executed here.
    //
    // `verifyTransitionCapability` returns the verified active capability even
    // when no transition is in flight, so there is nothing a legacy branch could
    // supply that the bridge has not already proven. The former branch discarded
    // that proof for a 3600s assumption.
    expect(source).toContain(
      "const tokenDrainSeconds = capability.maxMutatorTokenLifetimeSeconds;",
    );
    expect(source).not.toContain("LEGACY_MUTATOR_TOKEN_SECONDS");
    // One reviewed lifetime, asserted wherever a drain crosses a trust boundary.
    expect(source).toContain("const MUTATOR_TOKEN_SECONDS = 300;");
    for (
      const guard of [
        "identity.tokenDrainSeconds !== MUTATOR_TOKEN_SECONDS",
        "proof.tokenDrainSeconds !== MUTATOR_TOKEN_SECONDS",
        "tokenDrainSeconds !== MUTATOR_TOKEN_SECONDS",
        "value !== MUTATOR_TOKEN_SECONDS",
      ]
    ) {
      expect(source).toContain(guard);
    }
  });

  test("cleanup proves no retained policy with a read that tolerates absence", async () => {
    const source = await readFile(join(root, "tools/ci/protected-bootstrap-bridge.ts"), "utf8");
    // Structural: the release path is reachable in tests only through the
    // lifecycle fixture, which cannot distinguish this read from the fence
    // reads that precede it -- the fence is a CAS retry loop and reads the same
    // policy an unbounded number of times.
    //
    // `observed` comes from `getExecutor`, which already tolerates absence, so
    // an account can be inventoried and gone by the time this read runs. That
    // 404 is the proof this read is looking for -- no account, no retained
    // policy -- and because 404 is classified retryable, the strict variant
    // spent the whole IAM consistency window on it before failing a run whose
    // work had already succeeded.
    expect(source).toContain(
      '"executor cleanup policy read",\n              () => getServiceAccountPolicyIfPresent(',
    );
    expect(source).toContain(
      "policy !== undefined &&\n              (policy.bindings.length !== 0 || policy.auditConfigs !== undefined)",
    );
  });

  test("the key inventory stays strict; only absence-confirmed cleanup tolerates 404", async () => {
    const account = {
      description: "Protected Terraform Executor",
      disabled: false,
      displayName: "Protected Terraform Executor",
      email: "gha-pbt-0123456789abcdefabcd@cdbentley.iam.gserviceaccount.com",
      etag: "account-etag-1",
      name:
        "projects/cdbentley/serviceAccounts/gha-pbt-0123456789abcdefabcd@cdbentley.iam.gserviceaccount.com",
      oauth2ClientId: "123456789",
      projectId: "cdbentley",
      uniqueId: "123456789012345678901",
    };
    const token = "short-lived-owner-access-token-value";

    // The shared verifier has four callers. Three of them -- the post-create
    // check in `acquire` and both orphan-recovery checks -- need 404 to remain a
    // propagation error, or a transient answer stands in for the zero-key proof
    // and an account with a user-managed key could be deleted uninventoried.
    await expect(requireNoUserManagedKeys(account, token, async () => new Response("", { status: 404 })))
      .rejects.toThrow("Executor key inventory failed with HTTP 404");

    // A present account with no user-managed keys passes.
    await requireNoUserManagedKeys(account, token, async () => Response.json({}));

    // A present account holding one fails.
    await expect(requireNoUserManagedKeys(
      account,
      token,
      async () =>
        Response.json({
          keys: [{
            keyType: "USER_MANAGED",
            name: `${account.name}/keys/abcdef0123456789abcdef0123456789abcdef01`,
          }],
        }),
    )).rejects.toThrow();

    // Every other status still fails.
    await expect(requireNoUserManagedKeys(account, token, async () => new Response("", { status: 500 })))
      .rejects.toThrow("Executor key inventory failed with HTTP 500");

    // Only the cleanup caller tolerates 404, and only after re-reading the
    // account and finding it gone. Structural: the release path is reachable in
    // tests only through the lifecycle fixture, which cannot drive this branch
    // without also driving the fence reads that precede it.
    const source = await readFile(join(root, "tools/ci/protected-bootstrap-bridge.ts"), "utf8");
    expect(source).toContain('"executor cleanup key inventory",');
    expect(source).toContain("if (!(error instanceof Error) || !/HTTP 404\\b/.test(error.message)) throw error;");
    expect(source).toContain("if (present !== undefined) throw error;");
  });

  test("the consumed receipt is creatable before consumption and read-only after", async () => {
    // `consumeApproval` writes consumed/<planRunId>.json before elevation, so by
    // the time the mutation projection probes it the object exists and the
    // executor holds create-without-delete on it, deliberately, so the receipt
    // cannot be rewritten. `storage.objects.create` is observable only through
    // the effective-overwrite probe -- it is excluded from
    // STORAGE_OBJECT_RPC_PERMISSIONS -- and GCS answers that probe on a live
    // object by requiring delete as well. Requiring provable create there asked
    // the executor to prove it could overwrite an immutable receipt, so the scan
    // could never converge and elevation would time out after the burn.
    const invocation = validateInvocation({
      ...validEnvironment(),
      APPROVED_MANIFEST_SHA256: "a".repeat(64),
      APPROVED_PLAN_RUN_ID: "33230835879",
      BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "2340",
      EXECUTION_MODE: "apply",
    });
    const state = {
      bucket: "cdbentley-tfstate-882468538648-bootstrap",
      prefix: "cdbentley/bootstrap",
    };
    const consumed = `${state.prefix}/.protected-bootstrap/consumed/33230835879.json`;
    const results = `${state.prefix}/.protected-bootstrap/results/123456.json`;
    const plans = `${state.prefix}/.protected-bootstrap/plans/33230835879.json`;
    const overwritten: string[] = [];
    let clock = 0;

    await waitForStatePermissions(
      state,
      invocation,
      "short-lived-executor-access-token-value",
      "mutation",
      async (input: URL | string): Promise<Response> => {
        const requested = new URL(String(input)).searchParams.getAll("permissions");
        return Response.json({
          kind: "storage#testIamPermissionsResponse",
          permissions: requested,
        });
      },
      async () => {
        clock += 1_000;
      },
      {
        // Receipts already written cannot be overwritten: the executor holds
        // create-without-delete on them by design. The results receipt does not
        // exist yet, so create is both provable and required there.
        testObjectOverwrite: async ({ objectName }) => {
          overwritten.push(objectName);
          return !(objectName === consumed || objectName === plans);
        },
        // `storage.objects.create` is never reported here -- it is excluded from
        // STORAGE_OBJECT_RPC_PERMISSIONS and arrives only via the probe above.
        testObjectPermissions: async ({ permissions, resource }) => ({
          denied: false,
          permissions: resource.includes("/.protected-bootstrap/")
            ? permissions.filter((permission) => permission === "storage.objects.get")
            : permissions.filter((permission) => permission !== "storage.objects.create"),
        }),
      },
      300_000,
      () => clock,
    );

    // It probed the object that matters, and did not need it to be overwritable.
    expect(overwritten).toContain(consumed);
    expect(overwritten).toContain(results);

    // The "read" projection runs inside `acquire`, before `consumeApproval`.
    // The receipt is still absent and the lease already grants objectCreator, so
    // the probe reports create -- and requiring read-only there would treat that
    // as forbidden and hang until the deadline, failing every apply before it
    // could ever reach consumption.
    let readClock = 0;
    await waitForStatePermissions(
      state,
      invocation,
      "short-lived-executor-access-token-value",
      "read",
      async (input: URL | string): Promise<Response> => {
        const requested = new URL(String(input)).searchParams.getAll("permissions");
        return Response.json({
          kind: "storage#testIamPermissionsResponse",
          permissions: requested,
        });
      },
      async () => {
        readClock += 1_000;
      },
      {
        // Only the two receipts this run will write are absent and leased to the
        // executor as creator. The plan receipt already exists, and the read
        // projection holds no write lease on the state objects at all.
        testObjectOverwrite: async ({ objectName }) =>
          objectName === consumed || objectName === results,
        // The lock object is reachable only by the mutation projection, so the
        // read projection must observe nothing at all on it.
        testObjectPermissions: async ({ permissions, resource }) => ({
          denied: false,
          permissions: resource.endsWith("default.tflock")
            ? []
            : permissions.filter((permission) => permission === "storage.objects.get"),
        }),
      },
      300_000,
      () => readClock,
    );
  });

  test("Storage permission protobuf is bounded, exact, and rejects unknown response fields", () => {
    expect(Buffer.from(encodeStorageTestIamPermissionsRequest("r", ["p"])).toString("hex"))
      .toBe("0a0172120170");
    const permission = Buffer.from("storage.objects.get", "utf8");
    const valid = Buffer.concat([Buffer.from([0x0a, permission.length]), permission]);
    expect(decodeStorageTestIamPermissionsResponse(valid)).toEqual(["storage.objects.get"]);
    expect(() => decodeStorageTestIamPermissionsResponse(Buffer.from([0x12, 0x00])))
      .toThrow("unexpected field");
    expect(() => decodeStorageTestIamPermissionsResponse(Buffer.alloc(64 * 1024 + 1)))
      .toThrow("bounded size");
    expect(() => decodeStorageTestIamPermissionsResponse(Buffer.from([0x0a, 0x01, 0xff])))
      .toThrow("invalid UTF-8");
  });

  test("Storage v2 permission RPC uses exact gRPC routing, framing, and trailers", async () => {
    const server = createHttp2Server();
    let observedHeaders: Record<string, unknown> | undefined;
    let observedBody = Buffer.alloc(0);
    server.on("stream", (stream, headers) => {
      observedHeaders = headers;
      const chunks: Buffer[] = [];
      stream.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
      stream.on("end", () => {
        observedBody = Buffer.concat(chunks);
        const permission = Buffer.from("storage.objects.get", "utf8");
        const protobuf = Buffer.concat([Buffer.from([0x0a, permission.length]), permission]);
        const frame = Buffer.alloc(5 + protobuf.length);
        frame.writeUInt32BE(protobuf.length, 1);
        frame.set(protobuf, 5);
        stream.respond(
          { ":status": 200, "content-type": "application/grpc" },
          { waitForTrailers: true },
        );
        stream.on("wantTrailers", () => stream.sendTrailers({ "grpc-status": "0" }));
        stream.end(frame);
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("HTTP/2 test server failed.");
    try {
      const result = await storageV2TestIamPermissions(
        {
          bucketResource: "projects/_/buckets/example-bucket",
          executorToken: "short-lived-executor-access-token-value",
          permissions: ["storage.objects.get"],
          resource: "projects/_/buckets/example-bucket/objects/exact/object",
        },
        {
          connect: () => connectHttp2(`http://127.0.0.1:${address.port}`),
          timeoutMs: 1_000,
        },
      );
      expect(result).toEqual(["storage.objects.get"]);
      expect(observedHeaders?.[":path"]).toBe(
        "/google.storage.v2.Storage/TestIamPermissions",
      );
      expect(observedHeaders?.["content-type"]).toBe("application/grpc");
      expect(observedHeaders?.["te"]).toBe("trailers");
      expect(observedHeaders?.["x-goog-request-params"]).toBe(
        "bucket=projects%2F_%2Fbuckets%2Fexample-bucket",
      );
      expect(observedBody[0]).toBe(0);
      expect(observedBody.readUInt32BE(1)).toBe(observedBody.length - 5);
      expect(observedBody.toString("utf8", 5)).toContain(
        "projects/_/buckets/example-bucket/objects/exact/object",
      );
      expect(observedBody.toString("utf8", 5)).toContain("storage.objects.get");
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => error === undefined ? resolve() : reject(error))
      );
    }
  });

  test("Storage v2 permission RPC bounds time and rejects malformed protocol without leaking causes", async () => {
    const server = createHttp2Server();
    server.on("stream", () => undefined);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("HTTP/2 test server failed.");
    try {
      await expect(storageV2TestIamPermissions(
        {
          bucketResource: "projects/_/buckets/example-bucket",
          executorToken: "short-lived-executor-access-token-value",
          permissions: ["storage.objects.get"],
          resource: "projects/_/buckets/example-bucket/objects/exact/object",
        },
        {
          connect: () => connectHttp2(`http://127.0.0.1:${address.port}`),
          timeoutMs: 20,
        },
      )).rejects.toThrow("timed out");
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => error === undefined ? resolve() : reject(error))
      );
    }
    await expect(storageV2TestIamPermissions(
      {
        bucketResource: "projects/_/buckets/example-bucket",
        executorToken: "short-lived-executor-access-token-value",
        permissions: ["storage.objects.get"],
        resource: "projects/_/buckets/example-bucket/objects/exact/object",
      },
      { connect: () => { throw new Error("secret transport detail"); }, timeoutMs: 20 },
    )).rejects.toThrow("transport failed");
    await expect(storageV2TestIamPermissions(
      {
        bucketResource: "projects/_/buckets/example-bucket",
        executorToken: "short-lived-executor-access-token-value",
        permissions: ["storage.objects.get"],
        resource: "projects/_/buckets/example-bucket/objects/exact/object",
      },
      { connect: () => { throw new Error("secret transport detail"); }, timeoutMs: 20 },
    )).rejects.not.toThrow("secret transport detail");
  });

  test("Storage v2 permission probing distinguishes credential denial from missing objects and malformed frames", async () => {
    const server = createHttp2Server();
    let mode: "compressed" | "not-found" | "oversized" | "permission-denied" | "unauthenticated" =
      "permission-denied";
    server.on("stream", (stream) => {
      const status = mode === "permission-denied"
        ? "7"
        : mode === "unauthenticated"
        ? "16"
        : mode === "not-found"
        ? "5"
        : "0";
      stream.respond({
        ":status": 200,
        "content-type": "application/grpc",
        "grpc-status": status,
      });
      if (mode === "compressed") stream.end(Buffer.from([1, 0, 0, 0, 0]));
      else if (mode === "oversized") stream.end(Buffer.alloc(64 * 1024 + 6));
      else stream.end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("HTTP/2 test server failed.");
    const request = {
      bucketResource: "projects/_/buckets/example-bucket",
      executorToken: "short-lived-executor-access-token-value",
      permissions: ["storage.objects.get"],
      resource: "projects/_/buckets/example-bucket/objects/exact/object",
    } as const;
    const options = {
      connect: () => connectHttp2(`http://127.0.0.1:${address.port}`),
      timeoutMs: 1_000,
    } as const;
    try {
      expect(await probeStorageObjectPermissions(request, options)).toEqual({
        denied: true,
        permissions: [],
        status: 7,
      });
      mode = "unauthenticated";
      expect(await probeStorageObjectPermissions(request, options)).toEqual({
        denied: true,
        permissions: [],
        status: 16,
      });
      mode = "not-found";
      await expect(probeStorageObjectPermissions(request, options)).rejects.toThrow(
        "gRPC status 5",
      );
      mode = "compressed";
      await expect(storageV2TestIamPermissions(request, options)).rejects.toThrow(
        "compression is not supported",
      );
      mode = "oversized";
      await expect(storageV2TestIamPermissions(request, options)).rejects.toThrow(
        "exceeded its bounded size",
      );
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => error === undefined ? resolve() : reject(error))
      );
    }
  });

  test("exact overwrite proof only initiates and cancels a validated resumable session", async () => {
    const objectName = "cdbentley/bootstrap/.protected-bootstrap/plans/32894958492.json";
    const session = new URL(
      "https://storage.googleapis.com/upload/storage/v1/b/example-bucket/o",
    );
    session.searchParams.set("uploadType", "resumable");
    session.searchParams.set("name", objectName);
    session.searchParams.set("upload_id", "A".repeat(32));
    const requests: Array<{
      body: BodyInit | null | undefined;
      headers: Headers;
      method: string;
      url: string;
    }> = [];
    const fetcher = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      requests.push({
        body: init?.body,
        headers: new Headers(init?.headers),
        method: init?.method ?? "GET",
        url: String(input),
      });
      if (init?.method === "POST") {
        return new Response("", { headers: { location: session.href }, status: 200 });
      }
      return new Response("", { status: 499 });
    };
    expect(await probeStorageObjectOverwritePermission(
      {
        bucket: "example-bucket",
        executorToken: "short-lived-executor-access-token-value",
        objectName,
      },
      fetcher,
    )).toBeTrue();
    expect(requests.map(({ method }) => method)).toEqual(["POST", "DELETE"]);
    const initiation = new URL(requests[0]!.url);
    expect(initiation.pathname).toBe("/upload/storage/v1/b/example-bucket/o");
    expect(initiation.searchParams.get("uploadType")).toBe("resumable");
    expect(initiation.searchParams.get("name")).toBe(objectName);
    expect(initiation.searchParams.has("ifGenerationMatch")).toBeFalse();
    expect([...initiation.searchParams.keys()].toSorted()).toEqual(["name", "uploadType"]);
    expect(requests[0]!.body).toBeUndefined();
    expect(requests[0]!.headers.get("content-length")).toBe("0");
    expect(requests[0]!.headers.get("content-type")).toBeNull();
    expect(requests[0]!.headers.get("authorization")).toBe(
      "Bearer short-lived-executor-access-token-value",
    );
    expect([...requests[0]!.headers.keys()]).toEqual(["authorization", "content-length"]);
    expect(requests[1]!.body).toBeUndefined();
    expect(requests[1]!.headers.get("content-length")).toBe("0");
    expect(requests[1]!.headers.get("authorization")).toBeNull();
  });

  test("overwrite proof accepts only denial as absence and rejects precondition ambiguity", async () => {
    const request = {
      bucket: "example-bucket",
      executorToken: "short-lived-executor-access-token-value",
      objectName: "exact/object",
    } as const;
    for (const status of [401, 403]) {
      const response = new Response("bounded diagnostic", { status });
      expect(await probeStorageObjectOverwritePermission(
        request,
        async () => response,
      )).toBeFalse();
      expect(response.bodyUsed).toBeTrue();
    }
    const precondition = new Response("bounded diagnostic", { status: 412 });
    let preconditionCalls = 0;
    await expect(probeStorageObjectOverwritePermission(
      request,
      async () => {
        preconditionCalls += 1;
        return precondition;
      },
    )).rejects.toThrow("HTTP 412");
    expect(precondition.bodyUsed).toBeTrue();
    expect(preconditionCalls).toBe(1);
    const missing = new Response("bounded diagnostic", { status: 404 });
    await expect(probeStorageObjectOverwritePermission(
      request,
      async () => missing,
    )).rejects.toThrow("HTTP 404");
    expect(missing.bodyUsed).toBeTrue();
    const session =
      "https://storage.googleapis.com/upload/storage/v1/b/example-bucket/o" +
      "?uploadType=resumable&name=exact%2Fobject&upload_id=" + "B".repeat(32);
    await expect(probeStorageObjectOverwritePermission(
      request,
      async (_input, init) => init?.method === "POST"
        ? new Response("", { headers: { location: session }, status: 200 })
        : new Response("", { status: 500 }),
    )).rejects.toThrow("cancellation failed with HTTP 500");
    await expect(probeStorageObjectOverwritePermission(
      request,
      async () => { throw new Error(`secret ${session}`); },
    )).rejects.toThrow("transport failed");
    await expect(probeStorageObjectOverwritePermission(
      request,
      async () => { throw new Error(`secret ${session}`); },
    )).rejects.not.toThrow(session);
    let unexpectedInitiationCalls = 0;
    await expect(probeStorageObjectOverwritePermission(
      request,
      async (_input, init) => {
        unexpectedInitiationCalls += 1;
        return init?.method === "POST"
          ? new Response("unexpected", { headers: { location: session }, status: 200 })
          : new Response("", { status: 499 });
      },
    )).rejects.toThrow("unexpected response body");
    expect(unexpectedInitiationCalls).toBe(2);
    const documentedCancellation = new Response("bounded-undocumented-payload", {
      status: 499,
    });
    await expect(probeStorageObjectOverwritePermission(
      request,
      async (_input, init) => init?.method === "POST"
        ? new Response("", { headers: { location: session }, status: 200 })
        : documentedCancellation,
    )).resolves.toBeTrue();
    expect(documentedCancellation.bodyUsed).toBeTrue();
    await expect(probeStorageObjectOverwritePermission(
      request,
      async () => new Response("x".repeat(16 * 1024 + 1), { status: 403 }),
    )).rejects.toThrow("exceeded its bound");
    let oversizedInitiationCalls = 0;
    await expect(probeStorageObjectOverwritePermission(
      request,
      async (_input, init) => {
        oversizedInitiationCalls += 1;
        return init?.method === "POST"
          ? new Response("x".repeat(16 * 1024 + 1), {
              headers: { location: session },
              status: 200,
            })
          : new Response("", { status: 499 });
      },
    )).rejects.toThrow("exceeded its bound");
    expect(oversizedInitiationCalls).toBe(2);
  });

  test("overwrite proof rejects every session URI that is not exactly target-bound", async () => {
    const request = {
      bucket: "example-bucket",
      executorToken: "short-lived-executor-access-token-value",
      objectName: "exact/object",
    } as const;
    const valid = new URL("https://storage.googleapis.com/upload/storage/v1/b/example-bucket/o");
    valid.searchParams.set("uploadType", "resumable");
    valid.searchParams.set("name", request.objectName);
    valid.searchParams.set("upload_id", "C".repeat(32));
    const invalidSessions = [
      valid.href.replace("storage.googleapis.com", "attacker.example"),
      `${valid.href}&upload_id=${"D".repeat(32)}`,
      `${valid.href}&unexpected=value`,
      valid.href.replace("name=exact%2Fobject&", ""),
      `${valid.href}&ifGenerationMatch=0`,
    ];
    for (const invalidSession of invalidSessions) {
      let calls = 0;
      const result = probeStorageObjectOverwritePermission(request, async () => {
        calls += 1;
        return new Response("", { headers: { location: invalidSession }, status: 200 });
      });
      await expect(result).rejects.toThrow("invalid session URI");
      await expect(probeStorageObjectOverwritePermission(request, async () => {
        throw new Error(`secret ${invalidSession}`);
      })).rejects.not.toThrow(invalidSession);
      expect(calls).toBe(1);
    }
  });

  test("control permission proof covers deny/API mutation and exactly three prod actAs targets", async () => {
    const bootstrap = validateInvocation(validEnvironment());
    const bootstrapPermissions: string[] = [];
    const fetcher = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = String(input);
      const permissions = (JSON.parse(String(init?.body)) as { permissions: string[] }).permissions;
      if (url.includes("cloudresourcemanager")) bootstrapPermissions.push(...permissions);
      return Response.json({ permissions });
    };
    await waitForControlPermissions(
      bootstrap,
      "short-lived-executor-access-token-value",
      "mutation",
      fetcher,
      async () => undefined,
    );
    // The proof must no longer demand ANY deny-policy authority: the executor
    // can never hold it, so probing for it would never converge.
    expect(bootstrapPermissions.some((p) => p.startsWith("iam.denypolicies."))).toBeFalse();
    expect(
      bootstrapPermissions.filter((permission) =>
        permission === "iam.workloadIdentityPools.getAttestationRules"
      ),
    ).toEqual(["iam.workloadIdentityPools.getAttestationRules"]);
    expect(bootstrapPermissions).toContain("serviceusage.services.disable");
    expect(bootstrapPermissions).toContain("serviceusage.services.enable");

    // Nothing is filtered out of the ephemeral custom role any more, so the
    // control matrix and the custom role must agree exactly in every root and
    // phase. Any future divergence means Google refused a permission in a
    // custom role, which must fail loudly rather than silently widen the role.
    for (const repository of REPOSITORY_NAMES) {
      for (const root_ of ["bootstrap", "prod"] as const) {
        for (const phase of ["read", "mutation"] as const) {
          expect(executorCustomRolePermissions(repository, root_, phase))
            .toEqual(executorControlPermissions(repository, root_, phase));
        }
      }
    }

    const prod = validateInvocation({ ...validEnvironment(), TERRAFORM_ROOT: "prod" });
    const urls: string[] = [];
    await waitForControlPermissions(
      prod,
      "short-lived-executor-access-token-value",
      "mutation",
      async (input, init) => {
        const url = String(input);
        urls.push(url);
        const permissions = (JSON.parse(String(init?.body)) as { permissions: string[] }).permissions;
        return Response.json({
          permissions: url.includes("iam.googleapis.com")
            ? permissions.filter((permission) => permission === "iam.serviceAccounts.actAs")
            : permissions,
        });
      },
      async () => undefined,
    );
    const actAsUrls = urls.filter((url) => url.endsWith(":testIamPermissions") && url.includes("iam.googleapis.com"));
    expect(actAsUrls).toHaveLength(3);
    expect(actAsUrls.toSorted()).toEqual([
      "https://iam.googleapis.com/v1/projects/cdbentley/serviceAccounts/cloud-run-bootstrap%40cdbentley.iam.gserviceaccount.com:testIamPermissions",
      "https://iam.googleapis.com/v1/projects/cdbentley/serviceAccounts/cloud-run-preview%40cdbentley.iam.gserviceaccount.com:testIamPermissions",
      "https://iam.googleapis.com/v1/projects/cdbentley/serviceAccounts/cloud-run-runtime%40cdbentley.iam.gserviceaccount.com:testIamPermissions",
    ]);

    const runsettaProd = validateInvocation({
      ...validEnvironment(),
      EXPOSURE_ADOPTION_RUN_ID: "123455",
      TARGET_REPOSITORY: "runsetta",
      TERRAFORM_ROOT: "prod",
    });
    const runControlProof = (mappingStatus: number) => {
      let nowMs = 1_000;
      return waitForControlPermissions(
        runsettaProd,
        "short-lived-executor-access-token-value",
        "read",
        async (input, init) => {
          const url = String(input);
          if (url.includes("-run.googleapis.com/apis/domains.cloudrun.com/")) {
            return new Response("", { status: mappingStatus });
          }
          const permissions = (JSON.parse(String(init?.body)) as { permissions: string[] })
            .permissions;
          const readPermissions = new Set(executorControlPermissions("runsetta", "prod", "read"));
          return Response.json({
            permissions: url.includes("iam.googleapis.com")
              ? []
              : permissions.filter((permission) => readPermissions.has(permission)),
          });
        },
        async (milliseconds) => {
          nowMs += milliseconds;
        },
        61_000,
        () => nowMs,
      );
    };
    await runControlProof(403);
    await expect(runControlProof(200)).rejects.toThrow(
      "unexpectedly reached the Domain Mapping API",
    );

    const exposure = validateInvocation({
      ...validEnvironment(),
      EXPOSURE_ADOPTION_CONFIRMATION: "ADOPT_RUNSETTA_EXPOSURE_STATE",
      TARGET_REPOSITORY: "runsetta",
      TERRAFORM_ROOT: "exposure",
    });
    const exposureProjectGrants: string[] = [];
    await waitForControlPermissions(
      exposure,
      "short-lived-executor-access-token-value",
      "read",
      async (input, init) => {
        const url = String(input);
        if (url.includes("-run.googleapis.com/apis/domains.cloudrun.com/")) {
          return new Response("", { status: 403 });
        }
        const permissions = (JSON.parse(String(init?.body)) as { permissions: string[] })
          .permissions;
        if (url.includes("cloudresourcemanager")) exposureProjectGrants.push(...permissions);
        return Response.json({ permissions: [] });
      },
      async () => undefined,
    );
    expect(exposureProjectGrants.toSorted()).toEqual([
      "run.domainmappings.create",
      "run.domainmappings.delete",
    ]);
  });

  test("control and runtime actAs grant and revocation proofs converge beyond seven scans within the shared deadline", async () => {
    const invocation = validateInvocation({ ...validEnvironment(), TERRAFORM_ROOT: "prod" });
    const run = async (expected: "mutation" | "none"): Promise<void> => {
      const startedAtMs = 1_000;
      let nowMs = startedAtMs;
      let scan = 0;
      let active = expected === "none";
      await waitForControlPermissions(
        invocation,
        "short-lived-executor-access-token-value",
        expected,
        async (input, init) => {
          if (String(input).includes("cloudresourcemanager")) {
            scan += 1;
            nowMs += 20_000;
            active = expected === "none" ? scan < 8 : scan >= 8;
          }
          const permissions = (JSON.parse(String(init?.body)) as { permissions: string[] })
            .permissions;
          return Response.json({
            permissions: active
              ? String(input).includes("iam.googleapis.com")
                ? permissions.filter((permission) => permission === "iam.serviceAccounts.actAs")
                : permissions
              : [],
          });
        },
        async (milliseconds) => {
          nowMs += milliseconds;
        },
        startedAtMs + 5 * 60_000,
        () => nowMs,
      );
      expect(scan).toBe(8);
      expect(nowMs - startedAtMs).toBeGreaterThan(3 * 60_000);
      expect(nowMs - startedAtMs).toBeLessThan(5 * 60_000);
    };

    await run("mutation");
    await run("none");
  });

  test("control scans stop at the absolute deadline before any remaining runtime surface", async () => {
    const invocation = validateInvocation({ ...validEnvironment(), TERRAFORM_ROOT: "prod" });
    const startedAtMs = 1_000;
    let nowMs = startedAtMs;
    const urls: string[] = [];
    await expect(waitForControlPermissions(
      invocation,
      "short-lived-executor-access-token-value",
      "mutation",
      async (input, init) => {
        urls.push(String(input));
        nowMs += 11_000;
        const permissions = (JSON.parse(String(init?.body)) as { permissions: string[] })
          .permissions;
        return Response.json({ permissions });
      },
      async () => undefined,
      startedAtMs + 10_000,
      () => nowMs,
    )).rejects.toThrow("control-plane lease did not propagate before the deadline");
    expect(urls).toHaveLength(1);
    expect(urls[0]).toContain("cloudresourcemanager.googleapis.com");
    expect(urls.some((url) => url.includes("iam.googleapis.com"))).toBeFalse();
  });

  test("new executor visibility retries 404s and lifecycle writes use the stable unique ID", async () => {
    const leaseExpiresAt = new Date(Date.now() + 47 * 60_000);
    const fixture = executorLifecycleFixture("delayed-create", leaseExpiresAt);
    const manager = new ExecutorLeaseManager(
      fixture.fetcher,
      fixture.sleep,
      () => "0123456789abcdefabcd",
    );

    await expect(manager.acquire(
      validateInvocation(validEnvironment()),
      leaseExpiresAt,
      Date.now() + 24 * 60_000,
    )).rejects.toThrow("Ephemeral executor role lookup failed with HTTP 403");

    expect(fixture.accountDeleted()).toBeTrue();
    expect(fixture.createCalls()).toBe(1);
    expect(fixture.setupVisibility404s()).toBe(2);
    expect(fixture.setupDisableWrites()).toBeGreaterThanOrEqual(1);
    expect(fixture.staleDisableReads()).toBe(1);
    expect(fixture.setupLifecycleUrls().length).toBeGreaterThan(0);
    for (const url of fixture.setupLifecycleUrls()) {
      expect(url).toEndWith(`/${fixture.account.uniqueId}:disable`);
      expect(url).not.toContain(encodeURIComponent(fixture.account.email));
    }
    expect(fixture.setupSleeps()).toHaveLength(3);
    const backoffRanges = [
      [1_000, 1_999],
      [2_000, 2_999],
      [4_000, 4_999],
    ] as const;
    for (const [index, delay] of fixture.setupSleeps().entries()) {
      const [minimum, maximum] = backoffRanges[index]!;
      expect(delay).toBeGreaterThanOrEqual(minimum);
      expect(delay).toBeLessThanOrEqual(maximum);
    }
  });

  test("executor lifecycle retries only a bounded HTTP 409 ABORTED conflict", async () => {
    const leaseExpiresAt = new Date(Date.now() + 47 * 60_000);
    const aborted = executorLifecycleFixture("lifecycle-aborted", leaseExpiresAt);
    const abortedManager = new ExecutorLeaseManager(
      aborted.fetcher,
      aborted.sleep,
      () => "0123456789abcdefabcd",
    );

    await expect(abortedManager.acquire(
      validateInvocation(validEnvironment()),
      leaseExpiresAt,
      Date.now() + 24 * 60_000,
    )).rejects.toThrow("Ephemeral executor role lookup failed with HTTP 403");

    expect(aborted.accountDeleted()).toBeTrue();
    expect(aborted.setupDisableWrites()).toBe(2);
    expect(aborted.setupLifecycleUrls()).toHaveLength(2);
    for (const url of aborted.setupLifecycleUrls()) {
      expect(url).toEndWith(`/${aborted.account.uniqueId}:disable`);
    }
    expect(aborted.setupSleeps()).toHaveLength(1);
    expect(aborted.setupSleeps()[0]!).toBeGreaterThanOrEqual(1_000);
    expect(aborted.setupSleeps()[0]!).toBeLessThanOrEqual(1_999);

    const terminal = executorLifecycleFixture("lifecycle-conflict-terminal", leaseExpiresAt);
    const terminalManager = new ExecutorLeaseManager(
      terminal.fetcher,
      terminal.sleep,
      () => "0123456789abcdefabcd",
    );
    await expect(terminalManager.acquire(
      validateInvocation(validEnvironment()),
      leaseExpiresAt,
      Date.now() + 24 * 60_000,
    )).rejects.toThrow("Executor disable failed with HTTP 409");

    expect(terminal.setupDisableWrites()).toBe(1);
    expect(terminal.setupSleeps()).toEqual([]);
    expect(terminal.accountDeleted()).toBeTrue();
    const terminalIndex = terminal.callIndex("disable-409-non-aborted");
    expect(terminalIndex).toBeGreaterThanOrEqual(0);
    expect(terminal.calls[terminalIndex]!.url).toEndWith(
      `/${terminal.account.uniqueId}:disable`,
    );
  });

  test("cleanup contains before IAM fencing and never accepts a pre-delete 404 as absence", async () => {
    const leaseExpiresAt = new Date(Date.now() + 47 * 60_000);
    const fixture = executorLifecycleFixture("cleanup-order", leaseExpiresAt);
    const manager = new ExecutorLeaseManager(
      fixture.fetcher,
      fixture.sleep,
      () => "0123456789abcdefabcd",
    );

    await expect(manager.acquire(
      validateInvocation(validEnvironment()),
      leaseExpiresAt,
      Date.now() + 24 * 60_000,
    )).rejects.toThrow("Executor token mint failed with HTTP 400");

    expect(fixture.accountDeleted()).toBeTrue();
    const mintIndex = fixture.callIndex("mint-400");
    const containment404Index = fixture.callIndex("cleanup-containment-404");
    const disableIndex = fixture.callIndex("cleanup-disable");
    const cleanupPolicyReadIndex = fixture.callIndex("cleanup-policy-read");
    const cleanupFenceIndex = fixture.callIndex("cleanup-fence-write");
    const preDelete404Index = fixture.callIndex("pre-delete-404");
    const deleteIndex = fixture.callIndex("delete-executor");
    const postDelete404Index = fixture.callIndex("post-delete-404");
    expect(mintIndex).toBeGreaterThanOrEqual(0);
    expect(disableIndex).toBeGreaterThan(mintIndex);
    expect(containment404Index).toBeGreaterThan(disableIndex);
    expect(cleanupPolicyReadIndex).toBeGreaterThan(disableIndex);
    expect(cleanupFenceIndex).toBeGreaterThan(disableIndex);
    expect(preDelete404Index).toBeGreaterThan(cleanupFenceIndex);
    expect(deleteIndex).toBeGreaterThan(preDelete404Index);
    expect(postDelete404Index).toBeGreaterThan(deleteIndex);
    expect(fixture.calls[disableIndex]!.url).toEndWith(`/${fixture.account.uniqueId}:disable`);
    expect(new Set(fixture.policyReadHosts())).toEqual(new Set([
      "cloudresourcemanager.googleapis.com",
      "iam.googleapis.com",
    ]));
    for (const body of fixture.policyReadBodies()) {
      expect(body).toEqual({ options: { requestedPolicyVersion: 3 } });
    }
    expect(fixture.serviceAccountPolicyReadUrls().length).toBeGreaterThan(0);
    for (const value of fixture.serviceAccountPolicyReadUrls()) {
      expect([...new URL(value).searchParams.entries()]).toEqual([
        ["options.requestedPolicyVersion", "3"],
      ]);
    }
  });

  test("IAM consistency retry fails fast on authorization errors and still cleans the created identity", async () => {
    const leaseExpiresAt = new Date(Date.now() + 47 * 60_000);
    const fixture = executorLifecycleFixture("fail-fast", leaseExpiresAt);
    const manager = new ExecutorLeaseManager(
      fixture.fetcher,
      fixture.sleep,
      () => "0123456789abcdefabcd",
    );

    await expect(manager.acquire(
      validateInvocation(validEnvironment()),
      leaseExpiresAt,
      Date.now() + 24 * 60_000,
    )).rejects.toThrow("Ephemeral executor lookup failed with HTTP 403");

    expect(fixture.setupContainmentReads()).toBe(1);
    expect(fixture.setupSleeps()).toEqual([]);
    expect(fixture.accountDeleted()).toBeTrue();
    expect(fixture.callIndex("cleanup-disable")).toBeGreaterThan(
      fixture.callIndex("setup-403"),
    );
  });

  test("executor policy and token mint retry only their documented post-create propagation window", async () => {
    const leaseExpiresAt = new Date(Date.now() + 47 * 60_000);
    const fixture = executorLifecycleFixture("policy-mint-propagation", leaseExpiresAt);
    const manager = new ExecutorLeaseManager(
      fixture.fetcher,
      fixture.sleep,
      () => "0123456789abcdefabcd",
    );

    await expect(manager.acquire(
      validateInvocation(validEnvironment()),
      leaseExpiresAt,
      Date.now() + 24 * 60_000,
    )).rejects.toThrow("minted executor token collided with a controller credential");

    expect(fixture.accountDeleted()).toBeTrue();
    const fullGetIndex = fixture.callIndex("setup-full-get");
    const policy404Index = fixture.callIndex("executor-policy-404");
    const policyConfirmedIndex = fixture.callIndex("token-policy-confirmed");
    const mint404Index = fixture.callIndex("mint-404");
    const mint403Index = fixture.callIndex("mint-propagation-403");
    const mint200Index = fixture.callIndex("mint-200");
    expect(fullGetIndex).toBeGreaterThanOrEqual(0);
    expect(policy404Index).toBeGreaterThan(fullGetIndex);
    expect(policyConfirmedIndex).toBeGreaterThan(policy404Index);
    expect(mint404Index).toBeGreaterThan(policyConfirmedIndex);
    expect(mint403Index).toBeGreaterThan(mint404Index);
    expect(mint200Index).toBeGreaterThan(mint403Index);
    const policy404Url = new URL(fixture.calls[policy404Index]!.url);
    expect(policy404Url.pathname).toEndWith(
      `/${fixture.account.uniqueId}:getIamPolicy`,
    );
    expect([...policy404Url.searchParams.entries()]).toEqual([
      ["options.requestedPolicyVersion", "3"],
    ]);
    expect(fixture.mintAttempts()).toBe(3);
    expect(fixture.policyPropagationSleeps()).toHaveLength(1);
    expect(fixture.policyPropagationSleeps()[0]!).toBeGreaterThanOrEqual(1_000);
    expect(fixture.policyPropagationSleeps()[0]!).toBeLessThanOrEqual(1_999);
    expect(fixture.mintPropagationSleeps()).toHaveLength(2);
    expect(fixture.mintPropagationSleeps()[0]!).toBeGreaterThanOrEqual(1_000);
    expect(fixture.mintPropagationSleeps()[0]!).toBeLessThanOrEqual(1_999);
    expect(fixture.mintPropagationSleeps()[1]!).toBeGreaterThanOrEqual(2_000);
    expect(fixture.mintPropagationSleeps()[1]!).toBeLessThanOrEqual(2_999);
  });

  test("terminal IAM statuses remain fail-fast outside the confirmed token-mint 403 window", async () => {
    const leaseExpiresAt = new Date(Date.now() + 47 * 60_000);
    for (const status of [400, 401, 403] as const) {
      const fixture = executorLifecycleFixture("policy-terminal", leaseExpiresAt, status);
      const manager = new ExecutorLeaseManager(
        fixture.fetcher,
        fixture.sleep,
        () => "0123456789abcdefabcd",
      );
      let failure: unknown;
      try {
        await manager.acquire(
          validateInvocation(validEnvironment()),
          leaseExpiresAt,
          Date.now() + 24 * 60_000,
        );
      } catch (error) {
        failure = error;
      }
      expect(errorMessages(failure).join("\n")).toContain(`HTTP ${status}`);
      expect(fixture.calls.filter((call) =>
        call.tag === `executor-policy-${status}`
      )).toHaveLength(1);
      expect(fixture.terminalSleeps()).toEqual([]);
      expect(fixture.accountDeleted()).toBeTrue();
    }

    for (const status of [400, 401] as const) {
      const fixture = executorLifecycleFixture("mint-terminal", leaseExpiresAt, status);
      const manager = new ExecutorLeaseManager(
        fixture.fetcher,
        fixture.sleep,
        () => "0123456789abcdefabcd",
      );
      let failure: unknown;
      try {
        await manager.acquire(
          validateInvocation(validEnvironment()),
          leaseExpiresAt,
          Date.now() + 24 * 60_000,
        );
      } catch (error) {
        failure = error;
      }
      expect(errorMessages(failure).join("\n")).toContain(`HTTP ${status}`);
      expect(fixture.mintAttempts()).toBe(1);
      expect(fixture.terminalSleeps()).toEqual([]);
      expect(fixture.accountDeleted()).toBeTrue();
    }
  });

  test("deletion requires a 2xx acknowledgement after 404 or ambiguous transport outcomes", async () => {
    const leaseExpiresAt = new Date(Date.now() + 47 * 60_000);
    for (const scenario of ["delete-404s", "delete-ambiguous"] as const) {
      const fixture = executorLifecycleFixture(scenario, leaseExpiresAt);
      const manager = new ExecutorLeaseManager(
        fixture.fetcher,
        fixture.sleep,
        () => "0123456789abcdefabcd",
      );
      await expect(manager.acquire(
        validateInvocation(validEnvironment()),
        leaseExpiresAt,
        Date.now() + 24 * 60_000,
      )).rejects.toThrow("Executor token mint failed with HTTP 400");

      expect(fixture.accountDeleted()).toBeTrue();
      expect(fixture.callIndex("role-delete-404")).toBeGreaterThanOrEqual(0);
      expect(fixture.callIndex("role-delete-2xx")).toBeGreaterThan(
        fixture.callIndex("role-delete-404"),
      );
      if (scenario === "delete-404s") {
        expect(fixture.callIndex("executor-delete-404")).toBeGreaterThanOrEqual(0);
        expect(fixture.callIndex("executor-delete-2xx")).toBeGreaterThan(
          fixture.callIndex("executor-delete-404"),
        );
      } else {
        expect(fixture.callIndex("executor-delete-ambiguous")).toBeGreaterThanOrEqual(0);
        expect(fixture.callIndex("stale-get-404-after-ambiguous-delete")).toBeGreaterThan(
          fixture.callIndex("executor-delete-ambiguous"),
        );
        expect(fixture.callIndex("executor-delete-2xx")).toBeGreaterThan(
          fixture.callIndex("stale-get-404-after-ambiguous-delete"),
        );
      }
      expect(fixture.callIndex("post-delete-404")).toBeGreaterThan(
        fixture.callIndex("executor-delete-2xx"),
      );
    }
  });

  test("a committed DELETE with a lost response fails closed without a false acknowledgement", async () => {
    const realDateNow = Date.now;
    let virtualNow = realDateNow();
    Date.now = () => virtualNow;
    try {
      const leaseExpiresAt = new Date(virtualNow + 47 * 60_000);
      const fixture = executorLifecycleFixture("delete-committed-loss", leaseExpiresAt);
      const manager = new ExecutorLeaseManager(
        fixture.fetcher,
        async (milliseconds) => {
          await fixture.sleep(milliseconds);
          virtualNow += milliseconds;
        },
        () => "0123456789abcdefabcd",
      );
      let failure: unknown;
      try {
        await manager.acquire(
          validateInvocation(validEnvironment()),
          leaseExpiresAt,
          virtualNow + 60_000,
        );
      } catch (error) {
        failure = error;
      }

      expect(failure).toBeInstanceOf(AggregateError);
      expect(errorMessages(failure).join("\n")).toContain(
        "deletion could not be proven before the cleanup deadline; manual reconciliation is required",
      );
      expect(fixture.callIndex("executor-delete-committed-loss")).toBeGreaterThanOrEqual(0);
      expect(fixture.callIndex("executor-get-404-after-loss")).toBeGreaterThan(
        fixture.callIndex("executor-delete-committed-loss"),
      );
      expect(fixture.callIndex("executor-delete-404-after-loss")).toBeGreaterThan(
        fixture.callIndex("executor-get-404-after-loss"),
      );
      expect(fixture.accountDeleted()).toBeTrue();
      expect(fixture.roleDeleted()).toBeTrue();
    } finally {
      Date.now = realDateNow;
    }
  });

  test("successful deletion acknowledgements persist across a later cleanup call", async () => {
    const realDateNow = Date.now;
    let virtualNow = realDateNow();
    Date.now = () => virtualNow;
    try {
      const leaseExpiresAt = new Date(virtualNow + 47 * 60_000);
      const fixture = executorLifecycleFixture("delete-acked-retry", leaseExpiresAt);
      const invocation = validateInvocation(validEnvironment());
      let firstCleanupTimedOut = false;
      const manager = new ExecutorLeaseManager(
        fixture.fetcher,
        async (milliseconds) => {
          await fixture.sleep(milliseconds);
          if (fixture.accountDeleted() && !firstCleanupTimedOut) {
            firstCleanupTimedOut = true;
            virtualNow += 10 * 60_000;
          } else {
            virtualNow += milliseconds;
          }
        },
        () => "0123456789abcdefabcd",
      );
      let setupFailure: unknown;
      try {
        await manager.acquire(
          invocation,
          leaseExpiresAt,
          virtualNow + 60_000,
        );
      } catch (error) {
        setupFailure = error;
      }

      expect(setupFailure).toBeInstanceOf(AggregateError);
      expect(errorMessages(setupFailure).join("\n")).toContain(
        "deletion could not be proven before the cleanup deadline; manual reconciliation is required",
      );
      expect(fixture.roleDeleted()).toBeTrue();
      expect(fixture.accountDeleted()).toBeTrue();
      expect(fixture.roleDeleteAttempts()).toBe(1);
      expect(fixture.executorDeleteAttempts()).toBe(1);
      expect(fixture.callIndex("token-policy-confirmed")).toBeGreaterThanOrEqual(0);

      const retryBoundary = fixture.calls.length;
      await manager.release(invocation, virtualNow + 60_000);

      expect(fixture.roleDeleteAttempts()).toBe(1);
      expect(fixture.executorDeleteAttempts()).toBe(1);
      const retryCalls = fixture.calls.slice(retryBoundary);
      expect(retryCalls.some((call) => call.method === "DELETE")).toBeFalse();
      expect(retryCalls.some((call) => {
        const url = new URL(call.url);
        return url.hostname === "iam.googleapis.com" &&
          url.pathname.endsWith(":getIamPolicy");
      })).toBeFalse();
      expect(fixture.calls.findIndex((call, index) =>
        index >= retryBoundary && call.tag === "acked-account-get-404"
      )).toBeGreaterThanOrEqual(retryBoundary);
      expect(fixture.calls.findIndex((call, index) =>
        index >= retryBoundary && call.tag === "acked-role-get-404"
      )).toBeGreaterThanOrEqual(retryBoundary);
    } finally {
      Date.now = realDateNow;
    }
  });

  test("a create 409 recovers and deletes only the exact deterministic executor", async () => {
    const leaseExpiresAt = new Date(Date.now() + 47 * 60_000);
    const exact = executorLifecycleFixture("create-conflict-exact", leaseExpiresAt);
    const exactManager = new ExecutorLeaseManager(
      exact.fetcher,
      exact.sleep,
      () => "0123456789abcdefabcd",
    );

    await expect(exactManager.acquire(
      validateInvocation(validEnvironment()),
      leaseExpiresAt,
      Date.now() + 24 * 60_000,
    )).rejects.toThrow("random executor account collided at creation");

    expect(exact.callIndex("preflight-404")).toBeGreaterThanOrEqual(0);
    expect(exact.callIndex("create-409")).toBeGreaterThan(exact.callIndex("preflight-404"));
    expect(exact.callIndex("conflict-recovery-read")).toBeGreaterThan(
      exact.callIndex("create-409"),
    );
    expect(exact.callIndex("cleanup-disable")).toBeGreaterThan(
      exact.callIndex("conflict-recovery-read"),
    );
    expect(exact.callIndex("executor-delete-2xx")).toBeGreaterThan(
      exact.callIndex("cleanup-disable"),
    );
    expect(exact.accountDeleted()).toBeTrue();
    expect(exact.calls[exact.callIndex("cleanup-disable")]!.url).toEndWith(
      `/${exact.account.uniqueId}:disable`,
    );
    expect(exact.calls[exact.callIndex("executor-delete-2xx")]!.url).toContain(
      `/serviceAccounts/${exact.account.uniqueId}`,
    );

    const foreign = executorLifecycleFixture("create-conflict-foreign", leaseExpiresAt);
    const foreignManager = new ExecutorLeaseManager(
      foreign.fetcher,
      foreign.sleep,
      () => "0123456789abcdefabcd",
    );
    let failure: unknown;
    try {
      await foreignManager.acquire(
        validateInvocation(validEnvironment()),
        leaseExpiresAt,
        Date.now() + 24 * 60_000,
      );
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(AggregateError);
    expect(errorMessages(failure).join("\n")).toContain(
      "ambiguous executor identity has foreign provenance; manual cleanup is required",
    );
    expect(foreign.callIndex("foreign-conflict-email-read")).toBeGreaterThan(
      foreign.callIndex("create-409"),
    );
    expect(foreign.callIndex("cleanup-disable")).toBeGreaterThan(
      foreign.callIndex("foreign-conflict-email-read"),
    );
    expect(foreign.callIndex("foreign-conflict-numeric-read")).toBeGreaterThan(
      foreign.callIndex("cleanup-disable"),
    );
    expect(foreign.calls.some((call) => call.method === "DELETE" &&
      call.url.includes("/serviceAccounts/"))).toBeFalse();
    expect(foreign.calls.some((call) =>
      call.method === "POST" && call.url.endsWith(`/${foreign.account.uniqueId}:disable`)
    )).toBeTrue();
    expect(foreign.accountDisabled()).toBeTrue();
    expect(foreign.accountDeleted()).toBeFalse();
  });

  test("a malformed successful create response is contained by immutable identity before rejection", async () => {
    const leaseExpiresAt = new Date(Date.now() + 47 * 60_000);
    const fixture = executorLifecycleFixture("create-response-mutable-drift", leaseExpiresAt);
    const manager = new ExecutorLeaseManager(
      fixture.fetcher,
      fixture.sleep,
      () => "0123456789abcdefabcd",
    );
    let failure: unknown;
    try {
      await manager.acquire(
        validateInvocation(validEnvironment()),
        leaseExpiresAt,
        Date.now() + 24 * 60_000,
      );
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(AggregateError);
    expect(errorMessages(failure).join("\n")).toContain(
      "ambiguous executor was targeted for containment but its full provenance could not be verified; manual cleanup is required",
    );
    expect(fixture.callIndex("cleanup-disable")).toBeGreaterThan(
      fixture.callIndex("create-2xx-mutable-drift"),
    );
    expect(fixture.callIndex("mutable-drift-read")).toBeGreaterThan(
      fixture.callIndex("cleanup-disable"),
    );
    expect(fixture.calls.some((call) => call.method === "DELETE" &&
      call.url.includes("/serviceAccounts/"))).toBeFalse();
    expect(fixture.accountDisabled()).toBeTrue();
    expect(fixture.accountDeleted()).toBeFalse();
  });

  test("a lost custom-role create response recovers only the exact intended role", async () => {
    const leaseExpiresAt = new Date(Date.now() + 47 * 60_000);
    const exact = executorLifecycleFixture("role-create-loss-exact", leaseExpiresAt);
    const exactManager = new ExecutorLeaseManager(
      exact.fetcher,
      exact.sleep,
      () => "0123456789abcdefabcd",
    );
    await expect(exactManager.acquire(
      validateInvocation(validEnvironment()),
      leaseExpiresAt,
      Date.now() + 24 * 60_000,
    )).rejects.toThrow("fetch failed after the custom-role POST committed");

    expect(exact.callIndex("recovered-role-read")).toBeGreaterThan(
      exact.callIndex("role-create-committed-loss"),
    );
    expect(exact.callIndex("recovered-role-delete")).toBeGreaterThan(
      exact.callIndex("recovered-role-read"),
    );
    expect(exact.roleDeleted()).toBeTrue();
    expect(exact.accountDeleted()).toBeTrue();

    const foreign = executorLifecycleFixture("role-create-loss-foreign", leaseExpiresAt);
    const foreignManager = new ExecutorLeaseManager(
      foreign.fetcher,
      foreign.sleep,
      () => "0123456789abcdefabcd",
    );
    let failure: unknown;
    try {
      await foreignManager.acquire(
        validateInvocation(validEnvironment()),
        leaseExpiresAt,
        Date.now() + 24 * 60_000,
      );
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(AggregateError);
    expect(errorMessages(failure).join("\n")).toContain(
      "ambiguous executor role has foreign provenance; manual cleanup is required",
    );
    expect(foreign.callIndex("foreign-role-read")).toBeGreaterThan(
      foreign.callIndex("role-create-committed-loss"),
    );
    expect(foreign.calls.some((call) => call.method === "DELETE")).toBeFalse();
    expect(foreign.roleDeleted()).toBeFalse();
    expect(foreign.accountDisabled()).toBeTrue();
    expect(foreign.accountDeleted()).toBeFalse();
  });

  test("orphan inventory contains only exact v0.5.12 bootstrap role matrices", async () => {
    const attestationReadPermission = "iam.workloadIdentityPools.getAttestationRules";
    const fixture = (
      phase: "mutation" | "read",
      initiallyDeleted: boolean,
      includedPermissions: readonly string[],
    ) => {
      const role = {
        deleted: initiallyDeleted,
        description: `Protected Terraform bootstrap ${phase} single-run control role.`,
        etag: "v0512-role-etag",
        includedPermissions: [...includedPermissions],
        name: `projects/cdbentley/roles/pbt_${phase === "read" ? "r" : "m"}_44444444444444444444`,
        stage: "GA",
        title: `Protected Terraform ${phase === "read" ? "Read" : "Mutation"}`,
      };
      let deleteCalls = 0;
      const fetcher = async (
        input: string | URL | Request,
        init?: RequestInit,
      ): Promise<Response> => {
        const url = new URL(String(input));
        const path = decodeURIComponent(url.pathname);
        const method = init?.method ?? "GET";
        if (path === "/v1/projects/cdbentley/serviceAccounts" && method === "GET") {
          return Response.json({ accounts: [] });
        }
        if (path === "/v1/projects/cdbentley/roles" && method === "GET") {
          return Response.json({ roles: [role] });
        }
        if (path === `/v1/${role.name}`) {
          if (method === "DELETE") {
            deleteCalls += 1;
            role.deleted = true;
          }
          return Response.json(role);
        }
        return new Response("", { status: 500 });
      };
      return { deleteCalls: () => deleteCalls, fetcher, role };
    };

    // The v0.5.12 matrix is no longer "current minus the attestation read":
    // the deny-policy permissions left the matrix when roles/iam.denyAdmin
    // proved ungrantable at project scope, so it is current, plus the deny
    // permissions of that era, minus the attestation read.
    const denyReads = ["iam.denypolicies.get", "iam.denypolicies.list"];
    const denyWrites = [
      "iam.denypolicies.create",
      "iam.denypolicies.delete",
      "iam.denypolicies.update",
    ];
    const v0512Matrix = (phase: "read" | "mutation"): readonly string[] =>
      [
        ...executorControlPermissions("cdbentley", "bootstrap", phase),
        ...(phase === "read" ? denyReads : [...denyReads, ...denyWrites]),
      ].filter((permission) => permission !== attestationReadPermission);

    for (const phase of ["read", "mutation"] as const) {
      const currentPermissions = executorControlPermissions("cdbentley", "bootstrap", phase);
      const v0512Permissions = v0512Matrix(phase);
      expect(currentPermissions).toContain(attestationReadPermission);
      expect(v0512Permissions).not.toContain(attestationReadPermission);
      // The frozen digest is the authority; if this derivation drifts from it
      // the recognition test below is testing nothing.
      expect(
        bridgeRolePermissionsRecognized(v0512Permissions, "cdbentley", "bootstrap", phase),
      ).toBeTrue();
      for (const initiallyDeleted of [false, true]) {
        const exact = fixture(phase, initiallyDeleted, v0512Permissions);
        await inventoryBridgeArtifacts(
          "cdbentley",
          "google-owner-access-token-value",
          exact.fetcher,
          async () => undefined,
          Date.now() + 60_000,
        );
        expect(exact.role.deleted).toBeTrue();
        expect(exact.deleteCalls()).toBe(initiallyDeleted ? 0 : 1);
      }
    }

    const v0512ReadPermissions = v0512Matrix("read");
    const arbitraryMatrices = [
      v0512ReadPermissions.filter((permission) => permission !== "iam.workloadIdentityPools.get"),
      [...v0512ReadPermissions, "iam.workloadIdentityPools.setAttestationRules"],
    ];
    for (const permissions of arbitraryMatrices) {
      const altered = fixture("read", false, permissions);
      await expect(inventoryBridgeArtifacts(
        "cdbentley",
        "google-owner-access-token-value",
        altered.fetcher,
        async () => undefined,
        Date.now() + 60_000,
      )).rejects.toThrow("permissions matrix drifted");
      expect(altered.role.deleted).toBeFalse();
      expect(altered.deleteCalls()).toBe(0);
    }
  });

  test("abrupt-loss recovery preserves unrelated v3 conditions while fencing and deleting exact leases", async () => {
    const fixture = abruptLossFixture();
    await inventoryBridgeArtifacts(
      "cdbentley",
      "google-owner-access-token-value",
      fixture.fetcher,
      fixture.sleep,
      Date.now() + 60_000,
    );
    expect(fixture.account.disabled).toBeTrue();
    expect(fixture.calls.some(({ url }) => url.includes(fixture.foreignAccount.uniqueId))).toBeFalse();
    expect(fixture.calls.some(({ url }) => url.includes(fixture.foreignRole.name))).toBeFalse();
    expect(fixture.accountDeleted()).toBeTrue();
    expect(fixture.lostResponseObserved()).toBeTrue();
    expect(fixture.lateWriteRejected()).toBeTrue();
    expect(fixture.roles.every((role) => role.deleted)).toBeTrue();
    const disableIndex = fixture.calls.findIndex(({ url }) => url.endsWith(":disable"));
    const authorityReadIndex = fixture.calls.findIndex(({ url }) =>
      new URL(url).pathname.endsWith(":getIamPolicy")
    );
    expect(disableIndex).toBeGreaterThanOrEqual(0);
    expect(disableIndex).toBeLessThan(authorityReadIndex);
    for (const policy of fixture.policies.values()) {
      expect(policy.bindings.some((binding) =>
        binding.members.includes(`serviceAccount:${fixture.account.email}`)
      )).toBeFalse();
      expect(policy.bindings.some((binding) =>
        binding.condition?.title.startsWith("codex-orphan-fence-")
      )).toBeFalse();
    }
    expect(fixture.policies.get("project:cdbentley")?.bindings).toContainEqual({
      members: ["user:unrelated@example.com"],
      role: "roles/viewer",
    });
    expect(fixture.policies.get(`sa:${fixture.account.email}`)?.bindings).toEqual([]);
    const preservedRuntimePolicy = [...fixture.policies.values()].find((policy) =>
      policy.bindings.some((binding) =>
        canonicalJson(binding) === canonicalJson(fixture.preservedRuntimeCondition)
      )
    );
    expect(preservedRuntimePolicy?.version).toBe(3);
    expect(preservedRuntimePolicy?.bindings).toContainEqual(fixture.preservedRuntimeCondition);

    await inventoryBridgeArtifacts(
      "cdbentley",
      "google-owner-access-token-value",
      fixture.fetcher,
      fixture.sleep,
      Date.now() + 60_000,
    );
    expect(fixture.accountDeleted()).toBeTrue();
  });

  test("fresh recovery deletes a disabled v1 Runsetta adoption executor", async () => {
    const runId = "7654321";
    const uniqueId = "333333333333333333333";
    const accountId = randomExecutorAccountId(
      deterministicArtifactHex("runsetta", runId, "service-account"),
    );
    const email = `${accountId}@runsetta.iam.gserviceaccount.com`;
    const account = {
      description:
        `pbt-v1;repository=runsetta;run=${runId};root=prod;mode=apply;` +
        "approved=7654320;adoption=7654319;expires=2026-08-26T23:00:00.000Z",
      disabled: false,
      displayName: "Protected Terraform Executor",
      email,
      etag: "executor-etag-1",
      name: `projects/runsetta/serviceAccounts/${email}`,
      projectId: "runsetta",
      uniqueId,
    };
    const calls: Array<{ method: string; path: string }> = [];
    const policies = new Map<string, IamPolicy>();
    let policyGeneration = 1;
    let exists = true;
    const fetcher = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = new URL(String(input));
      const path = decodeURIComponent(url.pathname);
      const method = init?.method ?? "GET";
      calls.push({ method, path });
      if (path === "/v1/projects/runsetta/serviceAccounts" && method === "GET") {
        return Response.json({ accounts: exists ? [account] : [] });
      }
      if (path === "/v1/projects/runsetta/roles" && method === "GET") {
        return Response.json({ roles: [] });
      }
      if (
        (path.endsWith(`/serviceAccounts/${uniqueId}:disable`) ||
          path.endsWith(`/serviceAccounts/${email}:disable`)) &&
        method === "POST"
      ) {
        account.disabled = true;
        return Response.json({});
      }
      if (/^\/v1\/projects\/runsetta\/roles\/pbt_[rm]_[0-9a-f]{20}$/.test(path) &&
        method === "GET") {
        return new Response("", { status: 404 });
      }
      if (path.endsWith(`/serviceAccounts/${uniqueId}/keys`) && method === "GET") {
        return Response.json({ keys: [] });
      }
      const policyMatch = /^(.*):(get|set)IamPolicy$/.exec(path);
      if (policyMatch !== null && method === "POST") {
        const key = `${url.hostname}${policyMatch[1]}`;
        const current = policies.get(key) ?? {
          bindings: [],
          etag: `policy-etag-${policyGeneration}`,
          version: 1,
        };
        policies.set(key, current);
        if (policyMatch[2] === "get") return Response.json(current);
        const requested = (JSON.parse(String(init?.body)) as { policy: IamPolicy }).policy;
        if (requested.etag !== current.etag) return new Response("", { status: 412 });
        policyGeneration += 1;
        const updated = { ...requested, etag: `policy-etag-${policyGeneration}` };
        policies.set(key, updated);
        return Response.json(updated);
      }
      if (
        path.endsWith(`/serviceAccounts/${uniqueId}`) ||
        path.endsWith(`/serviceAccounts/${email}`)
      ) {
        if (!exists) return new Response("", { status: 404 });
        if (method === "DELETE") {
          exists = false;
          return new Response("{}");
        }
        if (method === "GET") return Response.json(account);
      }
      return new Response("", { status: 400 });
    };
    const recoveryInvocation = validateRecoveryInvocation({
      ...validRecoveryEnvironment(),
      GITHUB_RUN_ID_EXACT: runId,
      TARGET_REPOSITORY: "runsetta",
    });
    await inventoryBridgeArtifacts(
      "runsetta",
      "google-owner-access-token-value",
      fetcher,
      async () => undefined,
      Date.now() + 60_000,
      recoveryInvocation,
    );
    expect(account.disabled).toBeTrue();
    expect(exists).toBeFalse();
    const disableIndex = calls.findIndex(({ method, path }) =>
      method === "POST" && path.endsWith(":disable")
    );
    const policyIndex = calls.findIndex(({ method, path }) =>
      method === "POST" && path.endsWith(":getIamPolicy")
    );
    const deleteIndex = calls.findIndex(({ method, path }) =>
      method === "DELETE" && path.endsWith(`/${uniqueId}`)
    );
    expect(disableIndex).toBeGreaterThanOrEqual(0);
    expect(policyIndex).toBeGreaterThan(disableIndex);
    expect(deleteIndex).toBeGreaterThan(policyIndex);
    expect(calls.some(({ path }) => path.endsWith(":setIamPolicy"))).toBeTrue();
    expect([...policies.values()].every((policy) => policy.bindings.length === 0)).toBeTrue();
  });

  test("orphan custom-role deletion fails fast on HTTP 403 without retry backoff", async () => {
    const fixture = abruptLossFixture({ roleDeleteForbidden: true });
    let failure: unknown;
    try {
      await inventoryBridgeArtifacts(
        "cdbentley",
        "google-owner-access-token-value",
        fixture.fetcher,
        fixture.sleep,
        Date.now() + 60_000,
      );
    } catch (error) {
      failure = error;
    }
    expect(errorMessages(failure).join("\n")).toContain(
      "Ephemeral executor role deletion failed with HTTP 403",
    );
    expect(fixture.orphanRoleDeleteAttempts()).toBe(fixture.roles.length);
    expect(fixture.postForbiddenRoleDeleteSleeps()).toBe(0);
    expect(fixture.roles.some((role) => !role.deleted)).toBeTrue();
  });

  test("orphan recovery accepts only an exact stranded fence contract on restart", async () => {
    const exact = abruptLossFixture({ strandedFence: "exact" });
    await inventoryBridgeArtifacts(
      "cdbentley",
      "google-owner-access-token-value",
      exact.fetcher,
      exact.sleep,
      Date.now() + 60_000,
    );
    expect(exact.accountDeleted()).toBeTrue();
    expect(exact.strandedFence).toBeDefined();
    expect([...exact.policies.values()].some((policy) =>
      policy.bindings.includes(exact.strandedFence!)
    )).toBeFalse();

    const tampered = abruptLossFixture({ strandedFence: "tampered" });
    await expect(inventoryBridgeArtifacts(
      "cdbentley",
      "google-owner-access-token-value",
      tampered.fetcher,
      tampered.sleep,
      Date.now() + 60_000,
    )).rejects.toThrow("unknown or modified binding; manual cleanup is required");
    expect(tampered.account.disabled).toBeTrue();
    expect(tampered.accountDeleted()).toBeFalse();
    expect(tampered.policies.get("project:cdbentley")?.bindings).toContainEqual(
      tampered.strandedFence!,
    );
  });

  test("orphan recovery accepts only the canonical owner on an executor-policy fence", async () => {
    const exact = abruptLossFixture({ executorStrandedFence: "exact" });
    await inventoryBridgeArtifacts(
      "cdbentley",
      "google-owner-access-token-value",
      exact.fetcher,
      exact.sleep,
      Date.now() + 60_000,
    );
    expect(exact.accountDeleted()).toBeTrue();
    expect(exact.executorStrandedFence).toBeDefined();
    expect(exact.policies.get(`sa:${exact.account.email}`)?.bindings).not.toContainEqual(
      exact.executorStrandedFence!,
    );

    const attacker = abruptLossFixture({ executorStrandedFence: "attacker" });
    await expect(inventoryBridgeArtifacts(
      "cdbentley",
      "google-owner-access-token-value",
      attacker.fetcher,
      attacker.sleep,
      Date.now() + 60_000,
    )).rejects.toThrow("unknown or modified binding; manual cleanup is required");
    expect(attacker.account.disabled).toBeTrue();
    expect(attacker.accountDeleted()).toBeFalse();
    expect(attacker.policies.get(`sa:${attacker.account.email}`)?.bindings).toContainEqual(
      attacker.executorStrandedFence!,
    );
  });

  test("orphan recovery disables but refuses an altered lease with manual-cleanup guidance", async () => {
    const fixture = abruptLossFixture({ alterTargetLease: true });
    await expect(inventoryBridgeArtifacts(
      "cdbentley",
      "google-owner-access-token-value",
      fixture.fetcher,
      fixture.sleep,
      Date.now() + 60_000,
    )).rejects.toThrow("unknown or modified binding; manual cleanup is required");
    expect(fixture.account.disabled).toBeTrue();
    expect(fixture.accountDeleted()).toBeFalse();
    const disableIndex = fixture.calls.findIndex(({ url }) => url.endsWith(":disable"));
    const authorityReadIndex = fixture.calls.findIndex(({ url }) =>
      new URL(url).pathname.endsWith(":getIamPolicy")
    );
    expect(disableIndex).toBeGreaterThanOrEqual(0);
    expect(disableIndex).toBeLessThan(authorityReadIndex);
  });

  test("key presence or key-inventory failure occurs only after orphan disable", async () => {
    for (const [options, message] of [
      [{ userManagedKey: true }, "user-managed key"],
      [{ keyInventoryFailure: true }, "key inventory failed with HTTP 503"],
    ] as const) {
      const fixture = abruptLossFixture(options);
      await expect(inventoryBridgeArtifacts(
        "cdbentley",
        "google-owner-access-token-value",
        fixture.fetcher,
        fixture.sleep,
        Date.now() + 60_000,
      )).rejects.toThrow(message);
      expect(fixture.account.disabled).toBeTrue();
      expect(fixture.accountDeleted()).toBeFalse();
      expect(fixture.calls.some(({ url }) => url.includes(fixture.foreignAccount.uniqueId))).toBeFalse();
      const disableIndex = fixture.calls.findIndex(({ url }) => url.endsWith(":disable"));
      const keyIndex = fixture.calls.findIndex(({ url }) => url.includes("/keys?"));
      expect(disableIndex).toBeGreaterThanOrEqual(0);
      expect(disableIndex).toBeLessThan(keyIndex);
    }
  });

  test("mutable orphan provenance cannot defer containment or block reserved peers", async () => {
    for (const [tamperedIndex, tamperedField] of [
      [0, "description"],
      [1, "displayName"],
    ] as const) {
      const fixture = mutableOrphanContainmentFixture(tamperedIndex, tamperedField);
      await expect(inventoryBridgeArtifacts(
        "cdbentley",
        "google-owner-access-token-value",
        fixture.fetcher,
        async () => undefined,
        Date.now() + 60_000,
      )).rejects.toThrow("manual cleanup is required");
      expect(fixture.accounts.every((account) => account.disabled)).toBeTrue();
      expect(fixture.calls.filter(({ url }) => url.endsWith(":disable"))).toHaveLength(2);
      expect(fixture.calls.some(({ url }) => url.includes(fixture.foreignAccount.uniqueId))).toBeFalse();
      const executorLookupIndexes = fixture.calls.flatMap(({ method, url }, index) =>
        method === "GET" && fixture.accounts.some((account) =>
          url.endsWith(`/serviceAccounts/${account.uniqueId}`)
        ) ? [index] : []
      );
      const lastDisable = fixture.calls.findLastIndex(({ url }) => url.endsWith(":disable"));
      expect(executorLookupIndexes).toHaveLength(2);
      expect(lastDisable).toBeLessThan(executorLookupIndexes[1]!);
      for (const account of fixture.accounts) {
        const disableIndex = fixture.calls.findIndex(({ url }) =>
          url.endsWith(`/serviceAccounts/${account.uniqueId}:disable`)
        );
        const lookupIndex = fixture.calls.findIndex(({ method, url }) =>
          method === "GET" && url.endsWith(`/serviceAccounts/${account.uniqueId}`)
        );
        expect(disableIndex).toBeGreaterThanOrEqual(0);
        expect(lookupIndex).toBeGreaterThan(disableIndex);
      }
    }
  });

  test("a nonconverging orphan cannot delay the peer's stable-ID disable write", async () => {
    const fixture = orphanPeerConvergenceFixture();
    await expect(inventoryBridgeArtifacts(
      "cdbentley",
      "google-owner-access-token-value",
      fixture.fetcher,
      async () => undefined,
      Date.now() + 60_000,
    )).rejects.toThrow("orphan containment was incomplete; manual cleanup is required");

    const firstDisableIndex = fixture.calls.findIndex(({ method, url }) =>
      method === "POST" && url.endsWith(`/${fixture.accounts[0]!.uniqueId}:disable`)
    );
    const peerDisableIndex = fixture.calls.findIndex(({ method, url }) =>
      method === "POST" && url.endsWith(`/${fixture.accounts[1]!.uniqueId}:disable`)
    );
    const firstReadIndex = fixture.calls.findIndex(({ method, url }) =>
      method === "GET" && url.endsWith(`/${fixture.accounts[0]!.uniqueId}`)
    );
    expect(firstDisableIndex).toBeGreaterThanOrEqual(0);
    expect(peerDisableIndex).toBeGreaterThan(firstDisableIndex);
    expect(peerDisableIndex).toBeLessThan(firstReadIndex);
    expect(fixture.accounts[1]!.disabled).toBeTrue();
  });

  test("preexisting executor project authority aborts before enable, mint, or policy mutation", async () => {
    const accountId = "gha-pbt-0123456789abcdefabcd";
    const randomEmail = `${accountId}@cdbentley.iam.gserviceaccount.com`;
    const leaseExpiresAt = new Date(Date.now() + 47 * 60_000);
    const account = {
      description: `pbt-v2;repository=cdbentley;run=123456;root=bootstrap;mode=plan;approved=none;manifest=none;adoption=none;expires=${leaseExpiresAt.toISOString()}`,
      disabled: true,
      displayName: "Protected Terraform Executor",
      email: randomEmail,
      etag: "account-etag",
      name: `projects/cdbentley/serviceAccounts/${randomEmail}`,
      oauth2ClientId: "123456789",
      projectId: "cdbentley",
      uniqueId: "123456789012345678901",
    };
    const permissions = executorControlPermissions("cdbentley", "bootstrap", "read");
    const role = {
      deleted: false,
      description: "Protected Terraform bootstrap read single-run control role.",
      etag: "role-etag",
      includedPermissions: permissions,
      name: "projects/cdbentley/roles/pbt_r_0123456789abcdefabcd",
      stage: "GA",
      title: "Protected Terraform Read",
    };
    const calls: Array<{ method: string; url: string }> = [];
    let accountCreated = false;
    let accountDeleted = false;
    let roleCreated = false;
    let roleDeleted = false;
    const fetcher = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = String(input);
      const parsedUrl = new URL(url);
      const method = init?.method ?? "GET";
      calls.push({ method, url });
      if (parsedUrl.hostname === "cloudresourcemanager.googleapis.com" &&
        parsedUrl.pathname.endsWith(":getIamPolicy")) {
        expectProjectIamPolicyRead(input, init);
        return Response.json({
          bindings: [{ members: [`serviceAccount:${randomEmail}`], role: "roles/owner" }],
          etag: "project-policy",
          version: 1,
        });
      }
      if (url.includes("/serviceAccounts?") && method === "GET") {
        return Response.json({ accounts: [] });
      }
      if (url.includes("/roles?") && method === "GET") return Response.json({ roles: [] });
      if (url.endsWith("/serviceAccounts") && method === "POST") {
        accountCreated = true;
        return Response.json(account);
      }
      if (url.includes(`/serviceAccounts/${encodeURIComponent(randomEmail)}`) ||
        url.includes(`/serviceAccounts/${account.uniqueId}`)) {
        if (!accountCreated || accountDeleted) return new Response("", { status: 404 });
        if (method === "DELETE") {
          accountDeleted = true;
          return new Response("{}");
        }
        if (url.includes("/keys?")) return Response.json({ keys: [] });
        if (parsedUrl.pathname.endsWith(":getIamPolicy")) {
          expectServiceAccountIamPolicyRead(input, init);
          return Response.json({ bindings: [], etag: "sa-policy", version: 1 });
        }
        return Response.json(account);
      }
      if (url.includes("/roles/pbt_r_0123456789abcdefabcd")) {
        if (method === "DELETE") {
          roleDeleted = true;
          return Response.json({ ...role, deleted: true });
        }
        return roleCreated
          ? Response.json({ ...role, deleted: roleDeleted })
          : new Response("", { status: 404 });
      }
      if (url.endsWith("/roles") && method === "POST") {
        roleCreated = true;
        return Response.json(role);
      }
      return new Response("", { status: 500 });
    };
    const manager = new ExecutorLeaseManager(
      fetcher,
      async () => undefined,
      () => "0123456789abcdefabcd",
    );
    let failure: unknown;
    try {
      await manager.acquire(
        validateInvocation(validEnvironment()),
        leaseExpiresAt,
        Date.now() + 24 * 60_000,
      );
    } catch (error) {
      failure = error;
    }
    expect(errorMessages(failure)).toContain("The dedicated executor has a standing project IAM binding.");
    expect(accountCreated).toBeTrue();
    expect(roleCreated).toBeTrue();
    expect(calls.some(({ url }) => url.endsWith(":enable"))).toBeFalse();
    expect(calls.some(({ url }) => url.includes(":generateAccessToken"))).toBeFalse();
    expect(calls.some(({ url }) => url.endsWith(":setIamPolicy"))).toBeFalse();
  });
});

function fakeDependencies(
  events: string[],
  overrides: Partial<BridgeDependencies> & { readonly planJson?: string } = {},
): BridgeDependencies {
  const defaultNow = 1_800_000_000_000;
  let fakeNow = defaultNow;
  const now = overrides.now ?? (() => fakeNow);
  const session: ExecutorSession = {
    accessToken: "short-lived-executor-access-token-value",
    executorEmail: "gha-pbt-0123456789abcdefabcd@cdbentley.iam.gserviceaccount.com",
    executorUniqueId: "123456789012345678901",
    tokenExpiresAtMs: defaultNow + 35 * 60_000,
  };
  return {
    acquireExecutor: overrides.acquireExecutor ?? (async () => {
      events.push("acquire");
      return { ...session, tokenExpiresAtMs: now() + 35 * 60_000 };
    }),
    appendSummary: overrides.appendSummary ?? (async () => {
      events.push("summary");
    }),
    consumeApproval: overrides.consumeApproval ?? (async () => {
      events.push("consume");
    }),
    elevateExecutor: overrides.elevateExecutor ?? (async () => {
      events.push("elevate");
    }),
    inspectPlan: overrides.inspectPlan ?? (async () => {
      events.push("inspect");
    }),
    now,
    prepare: overrides.prepare ?? (async () => {
      events.push("prepare");
      return preparation();
    }),
    proveExposure: overrides.proveExposure ?? (async () => null),
    proveFreeze: overrides.proveFreeze ?? (async (_invocation, tokenDrainSeconds) => {
      events.push("freeze");
      return freezeSnapshot(now(), tokenDrainSeconds);
    }),
    proveMarkers: overrides.proveMarkers ?? (async (_invocation, _session, requireTargetClear) => {
      events.push(`markers:${requireTargetClear ? "post" : "pre"}`);
      return markers();
    }),
    publishPlanReceipt: overrides.publishPlanReceipt ?? (async () => {
      events.push("publish");
    }),
    publishPostApplyReceipt: overrides.publishPostApplyReceipt ?? (async () => {
      events.push("publish:post");
    }),
    readPlanJson: overrides.readPlanJson ?? (async () => {
      events.push("show");
      return overrides.planJson ?? JSON.stringify(plan([]));
    }),
    releaseExecutor: overrides.releaseExecutor ?? (async () => {
      events.push("release");
    }),
    removePrivatePath: overrides.removePrivatePath ?? (async (path) => {
      events.push(`remove:${path.endsWith(".tfplan") ? "tfplan" : path.endsWith("/tfdata") ? "tfdata" : "sandbox"}`);
    }),
    runTerraform: overrides.runTerraform ?? (async (_invocation, receivedSession, directory, args) => {
      expect(receivedSession.accessToken).toBe(session.accessToken);
      expect(directory).toStartWith("/tmp/platform/terraform/deployments/");
      events.push(
        args[0] === "plan" && args.includes("-detailed-exitcode")
          ? "terraform:audit"
          : `terraform:${args[0]}`,
      );
    }),
    verifyApproval: overrides.verifyApproval ?? (async () => {
      throw new Error("Unexpected approval verification in plan mode.");
    }),
    waitForPostMutationDrain: overrides.waitForPostMutationDrain ?? (async (
      invocation,
      mutationCompletedAtMs,
    ) => {
      events.push("drain:post");
      if (invocation.terraformRoot === "bootstrap" && overrides.now === undefined) {
        fakeNow = mutationCompletedAtMs + 420_000;
      }
    }),
  };
}

function validEnvironment(): NodeJS.ProcessEnv {
  return {
    APPROVED_MANIFEST_SHA256: "",
    APPROVED_PLAN_RUN_ID: "",
    BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "1500",
    CONSUMER_ACTIONS_READ_TOKEN: "github-actions-read-token-value",
    CONSUMER_ROOT: "/tmp/consumer",
    CONSUMER_SHA: consumerSha,
    EXECUTION_MODE: "plan",
    EXPOSURE_ADOPTION_CONFIRMATION: "",
    EXPOSURE_ADOPTION_RUN_ID: "",
    GITHUB_ACTOR_ID_EXACT: "16823277",
    GITHUB_EVENT_NAME_EXACT: "workflow_dispatch",
    GITHUB_REF_EXACT: "refs/heads/main",
    GITHUB_REPOSITORY_EXACT: "collinbentley1/platform",
    GITHUB_REPOSITORY_ID_EXACT: "1255856466",
    GITHUB_REPOSITORY_OWNER_ID_EXACT: "16823277",
    GITHUB_RUN_ATTEMPT_EXACT: "1",
    GITHUB_RUN_ID_EXACT: "123456",
    GITHUB_SHA_EXACT: platformSha,
    GITHUB_STEP_SUMMARY_EXACT: "/tmp/summary",
    GITHUB_WORKFLOW_REF_EXACT:
      "collinbentley1/platform/.github/workflows/protected-bootstrap-implementation.yml@refs/heads/main",
    LEGACY_COMPATIBILITY_MODE: "false",
    OWNER_OAUTH_ACCESS_TOKEN: "google-owner-access-token-value",
    PLATFORM_ACTIONS_READ_TOKEN: "platform-actions-read-token-value",
    PLATFORM_ROOT: "/tmp/platform",
    RUNNER_ARCH_EXACT: "X64",
    RUNNER_ENVIRONMENT_EXACT: "github-hosted",
    RUNNER_OS_EXACT: "Linux",
    RUNNER_TEMP_EXACT: "/tmp",
    TARGET_REPOSITORY: "cdbentley",
    TERRAFORM_BINARY: "/tmp/terraform",
    TERRAFORM_PROVIDER_ARCHIVE: "/tmp/terraform-provider-google.zip",
    TERRAFORM_PROVIDER_DIRECTORY: "/tmp/terraform-provider-google",
    TERRAFORM_ROOT: "bootstrap",
    TERRAFORM_SANDBOX_IMAGE:
      "docker.io/oven/bun@sha256:8aac45197595035f697ea6b11cd73ce2401d82503fcb2540b5fac606973b242b",
    TRANSITION_PLATFORM_ROOT: "/tmp/transition-platform",
    TRANSITION_WORKFLOW_SHA: "",
  };
}

function validRecoveryEnvironment(): NodeJS.ProcessEnv {
  return {
    GITHUB_ACTOR_ID_EXACT: "16823277",
    GITHUB_EVENT_NAME_EXACT: "workflow_dispatch",
    GITHUB_REF_EXACT: "refs/heads/main",
    GITHUB_REPOSITORY_EXACT: "collinbentley1/platform",
    GITHUB_REPOSITORY_ID_EXACT: "1255856466",
    GITHUB_REPOSITORY_OWNER_ID_EXACT: "16823277",
    GITHUB_RUN_ATTEMPT_EXACT: "1",
    GITHUB_RUN_ID_EXACT: "123456",
    GITHUB_SHA_EXACT: platformSha,
    GITHUB_WORKFLOW_REF_EXACT:
      "collinbentley1/platform/.github/workflows/protected-bootstrap-implementation.yml@refs/heads/main",
    OWNER_OAUTH_ACCESS_TOKEN: "google-owner-access-token-value",
    PLATFORM_ROOT: "/tmp/platform",
    RUNNER_ARCH_EXACT: "X64",
    RUNNER_ENVIRONMENT_EXACT: "github-hosted",
    RUNNER_OS_EXACT: "Linux",
    RUNNER_TEMP_EXACT: "/tmp",
    TARGET_REPOSITORY: "cdbentley",
  };
}

function deterministicRecoveryHarness(options: {
  readonly accountListFailureStatus?: number;
  readonly delayDeterministicDirectGet?: boolean;
  readonly directReadbackNeverConverges?: boolean;
  readonly executorCleanupFence?: "exact" | "tampered";
  readonly executorUniqueIdFence?: boolean;
  readonly executorUniqueIdFenceTampered?: boolean;
  readonly emailDisableFailureStatus?: number;
  readonly firstDisableTransportLoss?: boolean;
  readonly initiallyVisibleAccount?: boolean;
  readonly keyFailureStatus?: number;
  readonly listedLegacyPeer?: boolean;
  readonly numericDisableFailureStatus?: number;
  readonly peerDisableStatus?: number;
  readonly postDeleteMasked403?: boolean;
  readonly postDeleteMasked403StartScan?: number;
  readonly revealAccountOnScan?: number;
  readonly roleAppearanceScan?: number;
  readonly runtimePolicyFailureStatus?: number;
  readonly scanDurationMs?: number;
  readonly targetProjectPolicyFailureStatus?: number;
  readonly targetProjectMembers?: boolean;
  readonly transientAccountListFailureScan?: number;
  readonly transientAccountListFailures?: number;
  readonly transientTargetPolicyFailures?: number;
} = {}) {
  const invocation = validateRecoveryInvocation(validRecoveryEnvironment());
  const projectId = REPOSITORIES[invocation.repository].projectId;
  const accountId = randomExecutorAccountId(
    deterministicArtifactHex(invocation.repository, invocation.githubRunId, "service-account"),
  );
  const email = `${accountId}@${projectId}.iam.gserviceaccount.com`;
  const account = {
    description:
      `pbt-v1;repository=${invocation.repository};run=${invocation.githubRunId};root=bootstrap;mode=plan;approved=none;expires=2026-08-25T23:00:00.000Z`,
    disabled: false,
    displayName: "Protected Terraform Executor",
    email,
    etag: "deterministic-account-etag-1",
    name: `projects/${projectId}/serviceAccounts/${email}`,
    oauth2ClientId: "123456789",
    projectId,
    uniqueId: "123456789012345678901",
  };
  const peerAccountId = "gha-pbt-fedcba9876543210abcd";
  const peerEmail = `${peerAccountId}@${projectId}.iam.gserviceaccount.com`;
  const peerAccount = {
    description:
      `pbt-v1;repository=${invocation.repository};run=654321;root=bootstrap;mode=plan;approved=none;expires=2026-08-25T23:00:00.000Z`,
    disabled: false,
    displayName: "Protected Terraform Executor",
    email: peerEmail,
    etag: "peer-account-etag-1",
    name: `projects/${projectId}/serviceAccounts/${peerEmail}`,
    oauth2ClientId: "987654321",
    projectId,
    uniqueId: "987654321098765432109",
  };
  const roleId = randomExecutorRoleId(
    "read",
    deterministicArtifactHex(invocation.repository, invocation.githubRunId, "role-read"),
  );
  const role = {
    deleted: false,
    description: "Protected Terraform bootstrap read single-run control role.",
    etag: "deterministic-role-etag-1",
    includedPermissions: executorControlPermissions(invocation.repository, "bootstrap", "read"),
    name: `projects/${projectId}/roles/${roleId}`,
    stage: "GA",
    title: "Protected Terraform Read",
  };
  const projectIds = Object.values(REPOSITORIES).map((contract) => contract.projectId);
  const runtimeEmails = [
    `cloud-run-bootstrap@${projectId}.iam.gserviceaccount.com`,
    `cloud-run-preview@${projectId}.iam.gserviceaccount.com`,
    `cloud-run-runtime@${projectId}.iam.gserviceaccount.com`,
  ];
  const policies = new Map<string, IamPolicy>();
  for (const id of projectIds) {
    policies.set(`project:${id}`, {
      bindings: [],
      etag: `project-${id}-etag-1`,
      version: 3,
    });
  }
  for (const runtimeEmail of runtimeEmails) {
    policies.set(`sa:${runtimeEmail}`, {
      bindings: [],
      etag: `runtime-${runtimeEmail.split("@")[0]}-etag-1`,
      version: 3,
    });
  }
  if (options.targetProjectMembers === true) {
    policies.set(`project:${projectId}`, {
      auditConfigs: [{
        auditLogConfigs: [{ logType: "ADMIN_READ" }],
        service: "allServices",
      }],
      bindings: [{
        members: [
          `serviceAccount:${email}`,
          `deleted:serviceAccount:${email}?uid=${account.uniqueId}`,
          "user:unrelated@example.com",
        ],
        role: "roles/editor",
      }],
      etag: "target-project-etag-1",
      version: 3,
    });
  }
  const fenceSuffix = "0123456789abcdefabcd";
  if (options.executorCleanupFence !== undefined) {
    const label = `executor service account ${email}`;
    policies.set(`sa:${email}`, {
      bindings: [{
        condition: {
          description: "Expired inert binding used only to advance the cleanup CAS generation.",
          expression: options.executorCleanupFence === "exact"
            ? "request.time < timestamp('2000-01-01T00:00:00.000Z')"
            : "request.time < timestamp('2001-01-01T00:00:00.000Z')",
          title: `codex-cleanup-fence-${createHash("sha256").update(label).digest("hex").slice(0, 12)}-${fenceSuffix}`,
        },
        members: ["user:CollinBentley1@gmail.com"],
        role: "roles/iam.serviceAccountTokenCreator",
      }],
      etag: "executor-policy-etag-1",
      version: 3,
    });
  }
  if (options.executorUniqueIdFence === true || options.executorUniqueIdFenceTampered === true) {
    const label = `orphan ${account.uniqueId} executor policy`;
    policies.set(`sa:${email}`, {
      bindings: [{
        condition: {
          description:
            "Expired inert binding used only to advance the orphan-recovery CAS generation.",
          expression: options.executorUniqueIdFenceTampered === true
            ? "request.time < timestamp('2001-01-01T00:00:00.000Z')"
            : "request.time < timestamp('2000-01-01T00:00:00.000Z')",
          title: `codex-orphan-fence-${createHash("sha256").update(label).digest("hex").slice(0, 12)}-${fenceSuffix}`,
        },
        members: ["user:CollinBentley1@gmail.com"],
        role: "roles/iam.serviceAccountTokenCreator",
      }],
      etag: "executor-policy-etag-1",
      version: 3,
    });
  }

  const calls: Array<{ method: string; tag: string; url: string }> = [];
  let accountVisible = options.initiallyVisibleAccount === true;
  let disableAttempts = 0;
  let generation = 1;
  let roleExists = false;
  let roleAppearanceObserved = false;
  let scan = 0;
  let transientAccountListFailureScanObserved = false;
  let transientAccountListFailures = options.transientAccountListFailures ?? 0;
  let transientTargetPolicyFailures = options.transientTargetPolicyFailures ?? 0;
  let fakeNow = Date.now();
  let releaseDirectGet!: () => void;
  const directGetGate = new Promise<void>((resolve) => {
    releaseDirectGet = resolve;
  });
  let directGetReleased = false;
  const postDeleteMaskingActive = (): boolean => options.postDeleteMasked403 === true &&
    scan >= (options.postDeleteMasked403StartScan ?? 1);
  const recordCall = (method: string, tag: string, url: string): void => {
    calls.push({ method, tag, url });
  };
  const updatePolicy = (key: string, init: RequestInit | undefined): Response => {
    const current = policies.get(key);
    if (current === undefined) return new Response("", { status: 404 });
    const requested = (JSON.parse(String(init?.body)) as { policy: IamPolicy }).policy;
    if (requested.version !== 3) return new Response("", { status: 400 });
    if (requested.etag !== current.etag) return new Response("", { status: 412 });
    generation += 1;
    const updated: IamPolicy = {
      ...requested,
      etag: `recovery-policy-etag-${generation}`,
      version: 3,
    };
    policies.set(key, updated);
    return Response.json(updated);
  };
  const fetcher = async (
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> => {
    const rawUrl = String(input);
    const url = new URL(rawUrl);
    const path = decodeURIComponent(url.pathname);
    const method = init?.method ?? "GET";

    if (path.endsWith(`/serviceAccounts/${email}:disable`) && method === "POST") {
      scan += 1;
      fakeNow += options.scanDurationMs ?? 0;
      disableAttempts += 1;
      if (options.revealAccountOnScan === scan) accountVisible = true;
      if (!roleAppearanceObserved && options.roleAppearanceScan === scan) {
        roleAppearanceObserved = true;
        roleExists = true;
        role.deleted = false;
      }
      if (options.firstDisableTransportLoss === true && disableAttempts === 1) {
        recordCall(method, "disable-response-loss", rawUrl);
        throw new TypeError("fetch failed after deterministic disable committed");
      }
      recordCall(method, "deterministic-email-disable", rawUrl);
      if (options.emailDisableFailureStatus !== undefined) {
        recordCall(method, `deterministic-email-disable-${options.emailDisableFailureStatus}`, rawUrl);
        return new Response("", { status: options.emailDisableFailureStatus });
      }
      if (!accountVisible) {
        if (postDeleteMaskingActive()) {
          recordCall(method, "deterministic-email-disable-403", rawUrl);
          return new Response("", { status: 403 });
        }
        return new Response("", { status: 404 });
      }
      if (options.directReadbackNeverConverges !== true) account.disabled = true;
      return Response.json({});
    }

    const projectPolicy = /^\/v1\/projects\/([^/:]+):(get|set)IamPolicy$/.exec(path);
    if (projectPolicy !== null) {
      const key = `project:${projectPolicy[1]}`;
      const target = projectPolicy[1] === projectId;
      if (projectPolicy[2] === "get") {
        if (target && transientTargetPolicyFailures > 0) {
          transientTargetPolicyFailures -= 1;
          recordCall(method, "target-project-policy-503", rawUrl);
          return new Response("", { status: 503 });
        }
        if (target && options.targetProjectPolicyFailureStatus !== undefined) {
          recordCall(method, `target-project-policy-${options.targetProjectPolicyFailureStatus}`, rawUrl);
          return new Response("", { status: options.targetProjectPolicyFailureStatus });
        }
        recordCall(method, target ? "target-project-policy-get" : "project-policy-get", rawUrl);
        return Response.json(policies.get(key));
      }
      recordCall(method, target ? "target-project-policy-set" : "project-policy-set", rawUrl);
      return updatePolicy(key, init);
    }

    const serviceAccountPolicy =
      /^\/v1\/projects\/[^/]+\/serviceAccounts\/(.+):(get|set)IamPolicy$/.exec(path);
    if (serviceAccountPolicy !== null) {
      const identifier = serviceAccountPolicy[1]!;
      const policyEmail = identifier === account.uniqueId ? email : identifier;
      const key = `sa:${policyEmail}`;
      if (serviceAccountPolicy[2] === "get") {
        recordCall(method, policyEmail === email ? "executor-policy-get" : "runtime-policy-get", rawUrl);
        const current = policies.get(key);
        if (policyEmail !== email && options.runtimePolicyFailureStatus !== undefined) {
          recordCall(method, `runtime-policy-${options.runtimePolicyFailureStatus}`, rawUrl);
          return new Response("", { status: options.runtimePolicyFailureStatus });
        }
        if (policyEmail === email && identifier === email && current === undefined &&
          !accountVisible && postDeleteMaskingActive()) {
          recordCall(method, "executor-policy-403", rawUrl);
          return new Response("", { status: 403 });
        }
        return current === undefined ? new Response("", { status: 404 }) : Response.json(current);
      }
      recordCall(method, policyEmail === email ? "executor-policy-set" : "runtime-policy-set", rawUrl);
      return updatePolicy(key, init);
    }

    if (path === `/v1/projects/${projectId}/serviceAccounts` && method === "GET") {
      if (
        transientAccountListFailures > 0 ||
        (!transientAccountListFailureScanObserved &&
          options.transientAccountListFailureScan === scan)
      ) {
        if (transientAccountListFailures > 0) transientAccountListFailures -= 1;
        transientAccountListFailureScanObserved = true;
        recordCall(method, "account-list-503", rawUrl);
        return new Response("", { status: 503 });
      }
      if (options.accountListFailureStatus !== undefined) {
        recordCall(method, `account-list-${options.accountListFailureStatus}`, rawUrl);
        return new Response("", { status: options.accountListFailureStatus });
      }
      recordCall(method, accountVisible ? "visible-account-list" : "empty-account-list", rawUrl);
      return Response.json({
        accounts: options.listedLegacyPeer === true
          ? [peerAccount]
          : accountVisible ? [account] : [],
      });
    }

    if (path === `/v1/projects/${projectId}/roles` && method === "GET") {
      recordCall(method, "role-list", rawUrl);
      return Response.json({ roles: roleExists ? [role] : [] });
    }
    if (path === `/v1/${role.name}`) {
      if (method === "DELETE") {
        recordCall(method, "role-delete", rawUrl);
        role.deleted = true;
        role.etag = `deterministic-role-etag-${scan + 1}`;
        return Response.json(role);
      }
      recordCall(method, roleExists ? "role-get" : "role-404", rawUrl);
      return roleExists ? Response.json(role) : new Response("", { status: 404 });
    }
    if (/^\/v1\/projects\/cdbentley\/roles\/pbt_[rm]_[0-9a-f]{20}$/.test(path)) {
      recordCall(method, "other-role-404", rawUrl);
      return new Response("", { status: 404 });
    }

    if (path.endsWith(`/serviceAccounts/${account.uniqueId}/keys`) && method === "GET") {
      recordCall(method, "key-inventory", rawUrl);
      if (options.keyFailureStatus !== undefined) {
        return new Response("", { status: options.keyFailureStatus });
      }
      return Response.json({ keys: [] });
    }
    if (path.endsWith(`/serviceAccounts/${account.uniqueId}:disable`) && method === "POST") {
      recordCall(method, "numeric-id-disable", rawUrl);
      if (options.numericDisableFailureStatus !== undefined) {
        return new Response("", { status: options.numericDisableFailureStatus });
      }
      if (options.directReadbackNeverConverges !== true) account.disabled = true;
      return Response.json({});
    }
    if (path.endsWith(`/serviceAccounts/${peerAccount.uniqueId}/keys`) && method === "GET") {
      recordCall(method, "peer-key-inventory", rawUrl);
      return new Response("", { status: 403 });
    }
    if (path.endsWith(`/serviceAccounts/${peerAccount.uniqueId}:disable`) && method === "POST") {
      recordCall(method, "peer-numeric-id-disable", rawUrl);
      if (options.peerDisableStatus !== undefined) {
        return new Response("", { status: options.peerDisableStatus });
      }
      peerAccount.disabled = true;
      return Response.json({});
    }
    if (
      path.endsWith(`/serviceAccounts/${peerAccount.uniqueId}`) ||
      path.endsWith(`/serviceAccounts/${peerEmail}`)
    ) {
      recordCall(method, "peer-account-get", rawUrl);
      return Response.json(peerAccount);
    }
    if (
      path.endsWith(`/serviceAccounts/${account.uniqueId}`) ||
      path.endsWith(`/serviceAccounts/${email}`)
    ) {
      if (!accountVisible) {
        if (postDeleteMaskingActive() && path.endsWith(`/serviceAccounts/${email}`)) {
          recordCall(method, "deterministic-account-403", rawUrl);
          return new Response("", { status: 403 });
        }
        recordCall(method, "deterministic-account-404", rawUrl);
        return new Response("", { status: 404 });
      }
      if (path.endsWith(`/serviceAccounts/${email}`) &&
        options.delayDeterministicDirectGet === true && !directGetReleased) {
        recordCall(method, "deterministic-direct-get-delayed", rawUrl);
        await directGetGate;
        directGetReleased = true;
      }
      if (method === "DELETE") {
        recordCall(method, "deterministic-account-delete", rawUrl);
        accountVisible = false;
        return Response.json({});
      }
      recordCall(method, "deterministic-account-get", rawUrl);
      return Response.json(account);
    }

    recordCall(method, "unhandled", rawUrl);
    return new Response("", { status: 500 });
  };

  return {
    account,
    callCount: (tag: string) => calls.filter((call) => call.tag === tag).length,
    callIndex: (tag: string) => calls.findIndex((call) => call.tag === tag),
    calls,
    email,
    fetcher,
    invocation,
    now: () => fakeNow,
    policy: (key: string) => policies.get(key)!,
    releaseDirectGet,
    revealAccount: () => {
      accountVisible = true;
    },
    role,
    sleep: async (milliseconds: number) => {
      recordCall("SLEEP", "sleep", String(milliseconds));
      fakeNow += milliseconds;
    },
  };
}

function identity(): PlanIdentity {
  return {
    consumerSha,
    consumerTreeSha,
    dhiParityId: "a".repeat(50),
    exposureProof: null,
    legacyCompatibilityMode: false,
    maxMutatorTokenLifetimeSeconds: 300,
    markerProof: markers(),
    platformSha,
    projectId: "cdbentley",
    repository: "cdbentley",
    repositoryId: "1255553151",
    terraformRoot: "prod",
    tokenDrainSeconds: 300,
    transitionWorkflowSha: "",
  };
}

function preparation(overrides: Partial<PreparationResult> = {}): PreparationResult {
  return {
    consumerTreeSha,
    dhiParityId: "a".repeat(50),
    maxMutatorTokenLifetimeSeconds: 300,
    tokenDrainSeconds: 300,
    ...overrides,
  };
}

function executionProof(overrides: Partial<ExecutionProof> = {}): ExecutionProof {
  return {
    ...preparation(),
    exposureProof: null,
    freezeProof: freezeSnapshot(1_800_000_000_000),
    markerProof: markers(),
    ...overrides,
  };
}

function freezeSnapshot(
  observedAtMs: number,
  tokenDrainSeconds = 300,
): ExecutionProof["freezeProof"] {
  return {
    observedAt: new Date(observedAtMs).toISOString(),
    repositories: [
      ["cdbentley", "1255553151"],
      ["runsetta", "711292980"],
      ["healthmcp", "1025243085"],
      ["critical-history", "280932482"],
    ].map(([repository, repositoryId]) => ({
      actionsEnabled: false,
      activeRunCount: 0,
      latestPossibleTokenIssuance: null,
      repository: repository as MarkerStateProof["repository"],
      repositoryId,
    })),
    tokenDrainSeconds,
  };
}

function markers(state: "absent" | "clear" = "clear"): readonly MarkerStateProof[] {
  const contracts = [
    ["cdbentley", "cdbentley", "1255553151"],
    ["runsetta", "runsetta", "711292980"],
    ["healthmcp", "medlock-1025243085", "1025243085"],
    ["critical-history", "critical-history-16823277", "280932482"],
  ] as const;
  return contracts.map(([repository, projectId, repositoryId], index) => ({
    bucket: `${projectId}-deployment-parity-state`,
    generation: state === "clear" ? String(index + 1) : null,
    metadata: state === "clear"
      ? { "repository-id": repositoryId, state: "clear", version: "1" }
      : null,
    metageneration: state === "clear" ? "1" : null,
    repository,
    repositoryId,
    state,
  }));
}

function errorMessages(error: unknown): string[] {
  if (error instanceof AggregateError) {
    return [error.message, ...error.errors.flatMap(errorMessages)];
  }
  return error instanceof Error ? [error.message] : [String(error)];
}

function expectProjectIamPolicyRead(
  input: string | URL | Request,
  init: RequestInit | undefined,
): void {
  const url = new URL(String(input));
  expect(init?.method).toBe("POST");
  expect([...url.searchParams.entries()]).toEqual([]);
  expect(JSON.parse(String(init?.body))).toEqual({
    options: { requestedPolicyVersion: 3 },
  });
}

function expectServiceAccountIamPolicyRead(
  input: string | URL | Request,
  init: RequestInit | undefined,
): void {
  const url = new URL(String(input));
  expect(init?.method).toBe("POST");
  expect(init?.body).toBeUndefined();
  expect([...url.searchParams.entries()]).toEqual([
    ["options.requestedPolicyVersion", "3"],
  ]);
}

function plan(resourceChanges: unknown[], resourceDrift: unknown[] = []): Record<string, unknown> {
  return {
    applyable: true,
    checks: [],
    complete: true,
    configuration: {},
    errored: false,
    format_version: "1.2",
    output_changes: {},
    planned_values: {},
    prior_state: {},
    relevant_attributes: [],
    resource_changes: resourceChanges,
    resource_drift: resourceDrift,
    terraform_version: "1.14.5",
    timestamp: "2026-08-22T21:00:00Z",
    variables: {},
  };
}

function exposureAdoptionPlan(resourceChanges: unknown[]): Record<string, unknown> {
  const result = plan(resourceChanges);
  const state = JSON.parse(
    canonicalRunsettaExposureState("123e4567-e89b-42d3-a456-426614174000"),
  ) as { outputs: { cloud_run_domain_mappings: { value: unknown } } };
  const mappingOutput = state.outputs.cloud_run_domain_mappings.value;
  const noOpOutput = (value: unknown) => ({
    actions: ["no-op"],
    after: structuredClone(value),
    after_sensitive: false,
    after_unknown: false,
    before: structuredClone(value),
    before_sensitive: false,
  });
  result.applyable = false;
  result.output_changes = {
    cloud_run_domain_mappings: noOpOutput(mappingOutput),
    preview_domain_dns_records: noOpOutput(null),
    preview_url_pattern: noOpOutput(null),
  };
  result.relevant_attributes = [{
    attribute: [],
    resource: "module.domains.google_cloud_run_domain_mapping.site",
  }];
  return result;
}

function exposureProofFixture(
  repository: "runsetta",
  stateMode: "adopted" | "unadopted",
): ExposureProof {
  const contract = REPOSITORIES[repository];
  const domains = ["runsetta.com", "www.runsetta.com"] as const;
  const records = {
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
  const lineage = "123e4567-e89b-42d3-a456-426614174000";
  const rawState = canonicalRunsettaExposureState(lineage);
  const stateMappings = stateMode === "adopted"
    ? domains.map((domain) => ({
        address: `module.domains.google_cloud_run_domain_mapping.site[${JSON.stringify(domain)}]`,
        domain,
        id: `locations/us-east4/namespaces/${contract.projectId}/domainmappings/${domain}`,
      }))
    : [];
  const mappings = domains.map((domain) => ({
    domain,
    generation: "1",
    id: `locations/us-east4/namespaces/${contract.projectId}/domainmappings/${domain}`,
    observedGeneration: "1",
    recordsSha256: createHash("sha256").update(canonicalJson(
      [...records[domain]].toSorted((left, right) =>
        canonicalJson(left).localeCompare(canonicalJson(right))
      ),
    )).digest("hex"),
    uid: domain === "runsetta.com"
      ? "054a1acd-cfa0-4a47-b6f2-238753c0c2bc"
      : "3a72ca14-d15b-40f9-9920-a9b7083eb771",
  }));
  const healthBody = JSON.stringify({
    environment: "production",
    ok: true,
    openaiConfigured: false,
    service: "runsetta",
    spotifyConfigured: false,
  });
  const https = domains.map((domain) => ({
    bodySha256: createHash("sha256").update(healthBody).digest("hex"),
    domain,
    status: 200 as const,
    url: `https://${domain}/livez`,
  }));
  const mappingListSha256 = createHash("sha256").update(canonicalJson(
    mappings.map(({ domain, generation, uid }) => ({ domain, generation, uid })),
  )).digest("hex");
  const liveContinuitySha256 = createHash("sha256").update(canonicalJson({
    https,
    mappingListCount: mappings.length,
    mappingListSha256,
    mappings,
  })).digest("hex");
  const absentState: ExposureProof["state"] = {
    bucket: contract.state.exposure.bucket,
    generation: null,
    lineage: null,
    mappings: [],
    metageneration: null,
    object: `${contract.state.exposure.prefix}/default.tfstate`,
    serial: null,
    sha256: null,
    size: null,
    state: "absent",
  };
  const adoptedState: ExposureProof["state"] = {
    bucket: contract.state.exposure.bucket,
    generation: "7",
    lineage,
    mappings: stateMappings,
    metageneration: "1",
    object: `${contract.state.exposure.prefix}/default.tfstate`,
    serial: 1,
    sha256: createHash("sha256").update(rawState).digest("hex"),
    size: String(Buffer.byteLength(rawState)),
    state: "present",
  };
  return {
    adoptionReceipt: null,
    https,
    mappingListCount: mappings.length,
    mappingListSha256,
    mappings,
    seedContract: stateMode === "unadopted"
      ? null
      : {
          adoptionAudit: {
            controllerCreateLeaseDisposition: "removed",
            initialState: absentState,
            liveContinuityEqual: true,
            outcome: "created",
            postLiveSha256: liveContinuitySha256,
            preLiveSha256: liveContinuitySha256,
            stateTransitionSha256: createHash("sha256").update(canonicalJson({
              finalState: adoptedState,
              initialState: absentState,
            })).digest("hex"),
          },
          byteLength: String(Buffer.byteLength(rawState)),
          confirmation: "ADOPT_RUNSETTA_EXPOSURE_STATE",
          liveContinuitySha256,
          mode: "controller-create-only-refreshless-v1",
          provider: "registry.terraform.io/hashicorp/google@7.45.0",
          resourceSchemaVersion: 1,
          sha256: createHash("sha256").update(rawState).digest("hex"),
          stateFormatVersion: 4,
          terraformVersion: "1.14.5",
        },
    state: stateMode === "unadopted" ? absentState : adoptedState,
  };
}

function runsettaProdExposureProof(adoptionRunId: string): ExposureProof {
  const proof = exposureProofFixture("runsetta", "adopted");
  return {
    ...proof,
    adoptionReceipt: {
      adoptedAt: "2026-08-26T16:00:00.000Z",
      generation: "8",
      manifestSha256: "d".repeat(64),
      metageneration: "1",
      runId: adoptionRunId,
      sha256: "e".repeat(64),
      size: "16000",
    },
  };
}

function exposureIdentity(
  repository: "runsetta",
  stateMode: "adopted" | "unadopted",
): PlanIdentity {
  const contract = REPOSITORIES[repository];
  return {
    ...identity(),
    exposureProof: exposureProofFixture(repository, stateMode),
    projectId: contract.projectId,
    repository,
    repositoryId: contract.repositoryId,
    terraformRoot: "exposure",
  };
}

function exposureDomainChange(
  domain: "runsetta.com" | "www.runsetta.com",
  importing: boolean,
): {
  address: string;
  change: Record<string, unknown>;
  index: string;
  mode: string;
  module_address: string;
  name: string;
  provider_name: string;
  type: string;
} {
  const id = `locations/us-east4/namespaces/runsetta/domainmappings/${domain}`;
  const after = {
    deletion_policy: "DELETE",
    id,
    location: "us-east4",
    metadata: [{ namespace: "runsetta" }],
    name: domain,
    project: "runsetta",
    spec: [{ certificate_mode: "AUTOMATIC", route_name: "runsetta" }],
  };
  return {
    address: `module.domains.google_cloud_run_domain_mapping.site[${JSON.stringify(domain)}]`,
    change: {
      actions: ["no-op"],
      after,
      after_sensitive: {},
      after_unknown: {},
      before: after,
      before_sensitive: {},
      ...(importing ? { importing: { id } } : {}),
      replace_paths: [],
    },
    index: domain,
    mode: "managed",
    module_address: "module.domains",
    name: "site",
    provider_name: "registry.terraform.io/hashicorp/google",
    type: "google_cloud_run_domain_mapping",
  };
}

function runsettaExposureApiResponse(url: URL): Response | undefined {
  if (url.hostname === "us-east4-run.googleapis.com") {
    const suffix = url.pathname.split("/domainmappings")[1] ?? "";
    if (suffix === "") {
      return Response.json({
        apiVersion: "domains.cloudrun.com/v1",
        items: ["runsetta.com", "www.runsetta.com"].map((domain, index) => ({
          metadata: {
            generation: 1,
            name: domain,
            namespace: "601124730704",
            uid: index === 0
              ? "054a1acd-cfa0-4a47-b6f2-238753c0c2bc"
              : "3a72ca14-d15b-40f9-9920-a9b7083eb771",
          },
        })),
        kind: "DomainMappingList",
        metadata: {
          selfLink: "/apis/domains.cloudrun.com/v1/namespaces/601124730704/domainmappings",
        },
      });
    }
    const domain = decodeURIComponent(suffix.slice(1));
    const www = domain === "www.runsetta.com";
    return Response.json({
      apiVersion: "domains.cloudrun.com/v1",
      kind: "DomainMapping",
      metadata: {
        generation: 1,
        name: domain,
        namespace: "601124730704",
        selfLink:
          `/apis/domains.cloudrun.com/v1/namespaces/601124730704/domainmappings/${domain}`,
        uid: www
          ? "3a72ca14-d15b-40f9-9920-a9b7083eb771"
          : "054a1acd-cfa0-4a47-b6f2-238753c0c2bc",
      },
      spec: { certificateMode: "AUTOMATIC", routeName: "runsetta" },
      status: {
        conditions: ["Ready", "CertificateProvisioned", "DomainRoutable"].map((type) => ({
          status: "True",
          type,
        })),
        mappedRouteName: "runsetta",
        observedGeneration: 1,
        resourceRecords: www
          ? [{ name: "www", rrdata: "ghs.googlehosted.com.", type: "CNAME" }]
          : [
              { rrdata: "216.239.32.21", type: "A" },
              { rrdata: "216.239.34.21", type: "A" },
              { rrdata: "216.239.36.21", type: "A" },
              { rrdata: "216.239.38.21", type: "A" },
              { rrdata: "2001:4860:4802:32::15", type: "AAAA" },
              { rrdata: "2001:4860:4802:34::15", type: "AAAA" },
              { rrdata: "2001:4860:4802:36::15", type: "AAAA" },
              { rrdata: "2001:4860:4802:38::15", type: "AAAA" },
            ],
      },
    });
  }
  if (url.hostname === "runsetta.com" || url.hostname === "www.runsetta.com") {
    return new Response(
      JSON.stringify({
        environment: "production",
        ok: true,
        openaiConfigured: false,
        service: "runsetta",
        spotifyConfigured: false,
      }),
      { headers: { "content-type": "application/json; charset=utf-8" }, status: 200 },
    );
  }
  return undefined;
}

function resourceChange(
  address: string,
  type: string,
  before: JsonValue,
  after: JsonValue,
): {
  address: string;
  change: Record<string, unknown>;
  mode: string;
  module_address: string;
  name: string;
  provider_name: string;
  type: string;
} {
  return {
    address,
    change: {
      actions: ["update"],
      after,
      after_sensitive: {},
      after_unknown: {},
      before,
      before_sensitive: {},
      replace_paths: [],
    },
    mode: "managed",
    module_address: address.startsWith("module.bootstrap.") ? "module.bootstrap" : "module.site",
    name: address.split(".").at(-1) ?? "resource",
    provider_name: "registry.terraform.io/hashicorp/google",
    type,
  };
}

async function runGit(cwd: string, args: readonly string[]): Promise<string> {
  const child = Bun.spawn(["/usr/bin/git", ...args], {
    cwd,
    env: {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_TERMINAL_PROMPT: "0",
      HOME: cwd,
      LANG: "C",
      PATH: "/usr/bin:/bin",
    },
    stderr: "pipe",
    stdout: "pipe",
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (exitCode !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${stderr.trim()}`);
  }
  return stdout.trim();
}

type ExecutorLifecycleScenario =
  | "cleanup-order"
  | "create-conflict-exact"
  | "create-conflict-foreign"
  | "create-response-mutable-drift"
  | "delayed-create"
  | "delete-404s"
  | "delete-acked-retry"
  | "delete-ambiguous"
  | "delete-committed-loss"
  | "fail-fast"
  | "lifecycle-aborted"
  | "lifecycle-conflict-terminal"
  | "mint-terminal"
  | "policy-mint-propagation"
  | "policy-terminal"
  | "role-create-loss-exact"
  | "role-create-loss-foreign";

function executorLifecycleFixture(
  scenario: ExecutorLifecycleScenario,
  leaseExpiresAt: Date,
  terminalStatus: 400 | 401 | 403 = 403,
) {
  const accountId = "gha-pbt-0123456789abcdefabcd";
  const email = `${accountId}@cdbentley.iam.gserviceaccount.com`;
  const account = {
    description: `pbt-v2;repository=cdbentley;run=123456;root=bootstrap;mode=plan;approved=none;manifest=none;adoption=none;expires=${leaseExpiresAt.toISOString()}`,
    disabled: false,
    displayName: "Protected Terraform Executor",
    email,
    etag: "account-etag-1",
    name: `projects/cdbentley/serviceAccounts/${email}`,
    oauth2ClientId: "123456789",
    projectId: "cdbentley",
    uniqueId: "123456789012345678901",
  };
  const role = {
    deleted: false,
    description: "Protected Terraform bootstrap read single-run control role.",
    etag: "role-etag-1",
    includedPermissions: executorControlPermissions("cdbentley", "bootstrap", "read"),
    name: "projects/cdbentley/roles/pbt_r_0123456789abcdefabcd",
    stage: "GA",
    title: "Protected Terraform Read",
  };
  const calls: Array<{ body: string; method: string; tag?: string; url: string }> = [];
  const setupSleeps: number[] = [];
  const mintPropagationSleeps: number[] = [];
  const policyPropagationSleeps: number[] = [];
  const terminalSleeps: number[] = [];
  const policyReadBodies: Array<Record<string, unknown>> = [];
  const policyReadHosts: string[] = [];
  const serviceAccountPolicyReadUrls: string[] = [];
  let phase: "cleanup" | "setup" = "setup";
  let accountCreated = false;
  let accountExists = false;
  let accountDisabled = false;
  let accountDeleted = false;
  let roleCreated = false;
  let roleDeleted = false;
  let createCalls = 0;
  let setupContainmentReads = 0;
  let setupVisibility404s = 0;
  let setupDisableWrites = 0;
  let staleDisableReads = 0;
  let staleDisablePending = false;
  let cleanupContainment404Served = false;
  let deletionStage = false;
  let preDelete404Served = false;
  let serviceAccountPolicy: IamPolicy = {
    bindings: [],
    etag: "sa-policy-etag-1",
    version: 1,
  };
  let projectPolicy: IamPolicy = {
    bindings: [],
    etag: "project-policy-etag-1",
    version: 1,
  };
  let policyGeneration = 1;
  let executorPolicy404s = 0;
  let executorPolicyTerminalAttempts = 0;
  let mintAttempts = 0;
  let pendingSleep: "mint" | "policy" | "terminal" | undefined;
  let roleDeleteAttempts = 0;
  let executorDeleteAttempts = 0;
  let ambiguousDeleteThrown = false;
  let ambiguousStaleGetServed = false;

  const accountResponse = (disabled = accountDisabled) => ({
    ...account,
    disabled,
    etag: `account-etag-${disabled ? "disabled" : "enabled"}`,
  });
  const capturePolicyRead = (url: URL, init: RequestInit | undefined) => {
    policyReadHosts.push(url.hostname);
    if (url.hostname === "cloudresourcemanager.googleapis.com") {
      expectProjectIamPolicyRead(url, init);
      policyReadBodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return;
    }
    expectServiceAccountIamPolicyRead(url, init);
    serviceAccountPolicyReadUrls.push(String(url));
  };
  const updatePolicy = (
    current: IamPolicy,
    init: RequestInit | undefined,
    prefix: string,
  ): IamPolicy => {
    const requested = (JSON.parse(String(init?.body)) as { policy: IamPolicy }).policy;
    expect(requested.version).toBe(3);
    expect(requested.etag).toBe(current.etag);
    policyGeneration += 1;
    return { ...requested, etag: `${prefix}-policy-etag-${policyGeneration}` };
  };

  const fetcher = async (
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> => {
    const url = new URL(String(input));
    const path = decodeURIComponent(url.pathname);
    const method = init?.method ?? "GET";
    const call = { body: String(init?.body ?? ""), method, url: String(input) } as {
      body: string;
      method: string;
      tag?: string;
      url: string;
    };
    // A retry delay is immediate. If another API call starts first, the prior
    // terminal response was not retried and a later cleanup delay must not be
    // misclassified as IAM propagation backoff.
    pendingSleep = undefined;
    calls.push(call);

    if (url.hostname === "cloudresourcemanager.googleapis.com" &&
      path === "/v1/projects/cdbentley:getIamPolicy") {
      capturePolicyRead(url, init);
      if (phase === "cleanup" && calls.every((candidate) =>
        candidate === call || candidate.tag !== "cleanup-policy-read"
      )) call.tag = "cleanup-policy-read";
      return Response.json(projectPolicy);
    }
    if (url.hostname === "cloudresourcemanager.googleapis.com" &&
      path === "/v1/projects/cdbentley:setIamPolicy") {
      projectPolicy = updatePolicy(projectPolicy, init, "project");
      if (phase === "cleanup" && call.body.includes("codex-cleanup-fence-")) {
        call.tag = "cleanup-fence-write";
      }
      return Response.json(projectPolicy);
    }
    const executorPolicyGet = url.hostname === "iam.googleapis.com" && (
      path === `/v1/projects/cdbentley/serviceAccounts/${email}:getIamPolicy` ||
      path === `/v1/projects/cdbentley/serviceAccounts/${account.uniqueId}:getIamPolicy`
    );
    if (executorPolicyGet) {
      capturePolicyRead(url, init);
      if (scenario === "policy-mint-propagation" && phase === "setup" &&
        executorPolicy404s === 0) {
        executorPolicy404s += 1;
        pendingSleep = "policy";
        call.tag = "executor-policy-404";
        return new Response("", { status: 404 });
      }
      if (scenario === "policy-terminal" && phase === "setup" &&
        executorPolicyTerminalAttempts === 0) {
        executorPolicyTerminalAttempts += 1;
        pendingSleep = "terminal";
        phase = "cleanup";
        call.tag = `executor-policy-${terminalStatus}`;
        return new Response("", { status: terminalStatus });
      }
      if (phase === "cleanup" && calls.every((candidate) =>
        candidate === call || candidate.tag !== "cleanup-policy-read"
      )) call.tag = "cleanup-policy-read";
      return Response.json(serviceAccountPolicy);
    }
    const executorPolicySet = url.hostname === "iam.googleapis.com" && (
      path === `/v1/projects/cdbentley/serviceAccounts/${email}:setIamPolicy` ||
      path === `/v1/projects/cdbentley/serviceAccounts/${account.uniqueId}:setIamPolicy`
    );
    if (executorPolicySet) {
      serviceAccountPolicy = updatePolicy(serviceAccountPolicy, init, "sa");
      if (serviceAccountPolicy.bindings.some((binding) =>
        binding.condition?.title === "codex-owner-mint-123456"
      )) call.tag = "token-policy-confirmed";
      if (phase === "cleanup" && call.body.includes("codex-cleanup-fence-")) {
        call.tag = "cleanup-fence-write";
      }
      return Response.json(serviceAccountPolicy);
    }

    if (url.hostname === "iamcredentials.googleapis.com" &&
      path.endsWith(`/${account.uniqueId}:generateAccessToken`)) {
      mintAttempts += 1;
      if (scenario === "policy-mint-propagation") {
        expect(serviceAccountPolicy.bindings.some((binding) =>
          binding.condition?.title === "codex-owner-mint-123456"
        )).toBeTrue();
        if (mintAttempts === 1) {
          pendingSleep = "mint";
          call.tag = "mint-404";
          return new Response("", { status: 404 });
        }
        if (mintAttempts === 2) {
          pendingSleep = "mint";
          call.tag = "mint-propagation-403";
          return new Response("", { status: 403 });
        }
        phase = "cleanup";
        call.tag = "mint-200";
        return Response.json({
          accessToken: "google-owner-access-token-value",
          expireTime: new Date(Date.now() + 35 * 60_000).toISOString(),
        });
      }
      phase = "cleanup";
      const status = scenario === "mint-terminal"
        ? terminalStatus
        : scenario === "cleanup-order" || scenario.startsWith("delete-") ? 400 : 403;
      if (scenario === "mint-terminal") pendingSleep = "terminal";
      call.tag = `mint-${status}`;
      return new Response("", { status });
    }

    if (url.hostname === "iam.googleapis.com" &&
      path === "/v1/projects/cdbentley/serviceAccounts" && method === "GET") {
      return Response.json({ accounts: [] });
    }
    if (url.hostname === "iam.googleapis.com" &&
      path === "/v1/projects/cdbentley/serviceAccounts" && method === "POST") {
      createCalls += 1;
      accountCreated = true;
      accountExists = true;
      accountDisabled = false;
      if (scenario.startsWith("create-conflict-")) {
        phase = "cleanup";
        call.tag = "create-409";
        return new Response("", { status: 409 });
      }
      if (scenario === "create-response-mutable-drift") {
        phase = "cleanup";
        call.tag = "create-2xx-mutable-drift";
        return Response.json({
          ...accountResponse(false),
          description: account.description.replace("run=123456", "run=654321"),
          displayName: "Drifted executor display",
          futureMutableField: { drifted: true },
        });
      }
      return Response.json(accountResponse(false));
    }
    if (url.hostname === "iam.googleapis.com" &&
      path === "/v1/projects/cdbentley/roles" && method === "GET") {
      expect(Object.fromEntries(url.searchParams)).toEqual({
        pageSize: "100",
        showDeleted: "true",
        view: "FULL",
      });
      return Response.json({ roles: [] });
    }
    if (url.hostname === "iam.googleapis.com" &&
      path === "/v1/projects/cdbentley/roles" && method === "POST") {
      roleCreated = true;
      if (scenario === "role-create-loss-exact" ||
        scenario === "role-create-loss-foreign") {
        phase = "cleanup";
        call.tag = "role-create-committed-loss";
        throw new TypeError("fetch failed after the custom-role POST committed");
      }
      return Response.json(role);
    }
    if (url.hostname === "iam.googleapis.com" && path === `/v1/${role.name}`) {
      if (method === "GET") expect(url.search).toBe("");
      if (method === "DELETE") {
        roleDeleteAttempts += 1;
        deletionStage = true;
        if ((scenario === "delete-404s" || scenario === "delete-ambiguous") &&
          roleDeleteAttempts === 1) {
          call.tag = "role-delete-404";
          return new Response("", { status: 404 });
        }
        roleDeleted = true;
        if (scenario === "role-create-loss-exact") call.tag = "recovered-role-delete";
        if (scenario === "delete-acked-retry") call.tag = "role-delete-acked";
        if (scenario.startsWith("delete-") && calls.every((candidate) =>
          candidate === call || candidate.tag !== "role-delete-2xx"
        )) call.tag = "role-delete-2xx";
        return Response.json({ ...role, deleted: true });
      }
      if ((scenario === "delayed-create" || scenario === "lifecycle-aborted") &&
        !roleCreated) {
        phase = "cleanup";
        call.tag = "role-403";
        return new Response("", { status: 403 });
      }
      if (roleCreated && scenario === "role-create-loss-exact") {
        call.tag = "recovered-role-read";
      }
      if (roleCreated && scenario === "role-create-loss-foreign") {
        call.tag = "foreign-role-read";
        return Response.json({ ...role, title: "Foreign role collision" });
      }
      if (roleDeleted && scenario === "delete-acked-retry") {
        call.tag = "acked-role-get-404";
        return new Response("", { status: 404 });
      }
      return roleCreated
        ? Response.json({ ...role, deleted: roleDeleted })
        : new Response("", { status: 404 });
    }

    if (url.hostname === "iam.googleapis.com" &&
      path === `/v1/projects/cdbentley/serviceAccounts/${account.uniqueId}:disable` &&
      method === "POST") {
      if (phase === "setup") {
        setupDisableWrites += 1;
        if (scenario === "lifecycle-aborted" && setupDisableWrites === 1) {
          call.tag = "disable-409-aborted";
          return Response.json({
            error: { code: 409, message: "concurrent IAM lifecycle update", status: "ABORTED" },
          }, { status: 409 });
        }
        if (scenario === "lifecycle-conflict-terminal" && setupDisableWrites === 1) {
          phase = "cleanup";
          call.tag = "disable-409-non-aborted";
          return Response.json({
            error: { code: 409, message: "not an aborted transaction", status: "ALREADY_EXISTS" },
          }, { status: 409 });
        }
        if (scenario === "delayed-create" && setupDisableWrites === 1) {
          staleDisablePending = true;
        }
      } else if (calls.every((candidate) =>
        candidate === call || candidate.tag !== "cleanup-disable"
      )) {
        call.tag = "cleanup-disable";
      }
      accountDisabled = true;
      return Response.json({});
    }
    if (url.hostname === "iam.googleapis.com" &&
      path === `/v1/projects/cdbentley/serviceAccounts/${account.uniqueId}:enable` &&
      method === "POST") {
      accountDisabled = false;
      return Response.json({});
    }
    if (url.hostname === "iam.googleapis.com" &&
      path === `/v1/projects/cdbentley/serviceAccounts/${account.uniqueId}/keys` &&
      method === "GET") {
      return Response.json({ keys: [] });
    }

    const byUniqueId = path === `/v1/projects/cdbentley/serviceAccounts/${account.uniqueId}`;
    const byEmail = path === `/v1/projects/cdbentley/serviceAccounts/${email}`;
    if (url.hostname === "iam.googleapis.com" && (byUniqueId || byEmail)) {
      if (method === "DELETE") {
        executorDeleteAttempts += 1;
        if (scenario === "delete-committed-loss") {
          if (executorDeleteAttempts === 1) {
            accountExists = false;
            accountDeleted = true;
            call.tag = "executor-delete-committed-loss";
            throw new TypeError("fetch failed after the executor DELETE committed");
          }
          call.tag = "executor-delete-404-after-loss";
          return new Response("", { status: 404 });
        }
        if (scenario === "delete-404s" && executorDeleteAttempts === 1) {
          call.tag = "executor-delete-404";
          return new Response("", { status: 404 });
        }
        if (scenario === "delete-ambiguous" && executorDeleteAttempts === 1) {
          ambiguousDeleteThrown = true;
          call.tag = "executor-delete-ambiguous";
          throw new TypeError("fetch failed after the executor DELETE may have committed");
        }
        call.tag = "delete-executor";
        if (scenario.startsWith("delete-") || scenario === "create-conflict-exact") {
          call.tag = "executor-delete-2xx";
        }
        accountExists = false;
        accountDeleted = true;
        return new Response("{}");
      }
      if (!accountCreated || !accountExists) {
        if (byEmail && !accountCreated && scenario.startsWith("create-conflict-")) {
          call.tag = "preflight-404";
        }
        if (accountDeleted) {
          call.tag = scenario === "delete-committed-loss"
            ? "executor-get-404-after-loss"
            : scenario === "delete-acked-retry"
            ? "acked-account-get-404"
            : "post-delete-404";
        }
        return new Response("", { status: 404 });
      }
      if (byEmail && scenario === "create-conflict-exact") {
        if (calls.every((candidate) =>
          candidate === call || candidate.tag !== "conflict-recovery-read"
        )) call.tag = "conflict-recovery-read";
      }
      if ((byEmail || byUniqueId) && scenario === "create-conflict-foreign") {
        call.tag = byEmail ? "foreign-conflict-email-read" : "foreign-conflict-numeric-read";
        return Response.json({
          ...accountResponse(),
          description: account.description.replace("run=123456", "run=654321"),
        });
      }
      if (byUniqueId && scenario === "create-response-mutable-drift") {
        call.tag = "mutable-drift-read";
        return Response.json({
          ...accountResponse(),
          description: account.description.replace("run=123456", "run=654321"),
          displayName: "Drifted executor display",
        });
      }
      if (byUniqueId && phase === "setup") {
        setupContainmentReads += 1;
        if (scenario === "fail-fast") {
          phase = "cleanup";
          call.tag = "setup-403";
          return new Response("", { status: 403 });
        }
        if (scenario === "delayed-create") {
          if (setupVisibility404s < 2) {
            setupVisibility404s += 1;
            return new Response("", { status: 404 });
          }
          if (setupDisableWrites === 0) {
            // A stale desired-state read must never replace the idempotent
            // lifecycle write required to establish a happens-before edge.
            return Response.json(accountResponse(true));
          }
          if (staleDisablePending) {
            staleDisablePending = false;
            staleDisableReads += 1;
            return Response.json(accountResponse(false));
          }
          return Response.json(accountResponse(true));
        }
      }
      if (scenario === "cleanup-order" && phase === "cleanup" && !deletionStage &&
        !cleanupContainment404Served) {
        cleanupContainment404Served = true;
        call.tag = "cleanup-containment-404";
        return new Response("", { status: 404 });
      }
      if (scenario === "cleanup-order" && deletionStage && !preDelete404Served) {
        preDelete404Served = true;
        call.tag = "pre-delete-404";
        return new Response("", { status: 404 });
      }
      if (scenario === "delete-ambiguous" && phase === "cleanup" &&
        ambiguousDeleteThrown && !ambiguousStaleGetServed) {
        ambiguousStaleGetServed = true;
        call.tag = "stale-get-404-after-ambiguous-delete";
        return new Response("", { status: 404 });
      }
      if (byUniqueId && phase === "setup" && calls.every((candidate) =>
        candidate === call || candidate.tag !== "setup-full-get"
      )) call.tag = "setup-full-get";
      return Response.json(accountResponse());
    }

    return new Response("", { status: 500 });
  };

  const sleep = async (milliseconds: number) => {
    if (pendingSleep === "mint") mintPropagationSleeps.push(milliseconds);
    else if (pendingSleep === "policy") policyPropagationSleeps.push(milliseconds);
    else if (pendingSleep === "terminal") terminalSleeps.push(milliseconds);
    else if (phase === "setup") setupSleeps.push(milliseconds);
    pendingSleep = undefined;
  };

  return {
    account,
    accountDeleted: () => accountDeleted,
    accountDisabled: () => accountDisabled,
    callIndex: (tag: string) => calls.findIndex((call) => call.tag === tag),
    calls,
    createCalls: () => createCalls,
    fetcher,
    mintAttempts: () => mintAttempts,
    mintPropagationSleeps: () => mintPropagationSleeps,
    policyReadBodies: () => policyReadBodies,
    policyReadHosts: () => policyReadHosts,
    policyPropagationSleeps: () => policyPropagationSleeps,
    roleDeleted: () => roleDeleted,
    roleDeleteAttempts: () => roleDeleteAttempts,
    serviceAccountPolicyReadUrls: () => serviceAccountPolicyReadUrls,
    setupContainmentReads: () => setupContainmentReads,
    setupDisableWrites: () => setupDisableWrites,
    setupLifecycleUrls: () => calls.filter((call) =>
      call.method === "POST" && call.url.endsWith(`/${account.uniqueId}:disable`) &&
      calls.indexOf(call) < calls.findIndex((candidate) => candidate.tag === "role-403")
    ).map((call) => call.url),
    setupSleeps: () => setupSleeps,
    setupVisibility404s: () => setupVisibility404s,
    sleep,
    staleDisableReads: () => staleDisableReads,
    terminalSleeps: () => terminalSleeps,
    executorDeleteAttempts: () => executorDeleteAttempts,
  };
}

function abruptLossFixture(options: {
  readonly alterTargetLease?: boolean;
  readonly executorStrandedFence?: "attacker" | "exact";
  readonly keyInventoryFailure?: boolean;
  readonly roleDeleteForbidden?: boolean;
  readonly strandedFence?: "exact" | "tampered";
  readonly userManagedKey?: boolean;
} = {}) {
  const runId = "7654321";
  const approvedPlanRunId = "7654320";
  const expiresAt = new Date("2026-08-22T20:00:00.000Z");
  const accountId = "gha-pbt-33333333333333333333";
  const email = `${accountId}@cdbentley.iam.gserviceaccount.com`;
  const account = {
    description: `pbt-v1;repository=cdbentley;run=${runId};root=prod;mode=apply;approved=${approvedPlanRunId};expires=${expiresAt.toISOString()}`,
    disabled: false,
    displayName: "Protected Terraform Executor",
    email,
    etag: "account-etag-1",
    name: `projects/cdbentley/serviceAccounts/${email}`,
    oauth2ClientId: "123456789",
    projectId: "cdbentley",
    uniqueId: "333333333333333333333",
  };
  const foreignAccount = {
    email: "882468538648-compute@developer.gserviceaccount.com",
    futureListOnlyField: { ignored: true },
    name: "projects/cdbentley/serviceAccounts/882468538648-compute@developer.gserviceaccount.com",
    projectId: "cdbentley",
    uniqueId: "444444444444444444444",
  };
  const roles = [
    {
      deleted: false,
      description: "Protected Terraform prod read single-run control role.",
      etag: "role-read-etag",
      includedPermissions: executorControlPermissions("cdbentley", "prod", "read"),
      name: "projects/cdbentley/roles/pbt_r_11111111111111111111",
      stage: "GA",
      title: "Protected Terraform Read",
    },
    {
      deleted: false,
      description: "Protected Terraform prod mutation single-run control role.",
      etag: "role-mutation-etag",
      includedPermissions: executorControlPermissions("cdbentley", "prod", "mutation"),
      name: "projects/cdbentley/roles/pbt_m_22222222222222222222",
      stage: "GA",
      title: "Protected Terraform Mutation",
    },
  ];
  const foreignRole = {
    name: "projects/cdbentley/roles/cloudRunRevisionDeployer",
    stage: "GA",
    title: "Permanent Cloud Run revision deployer",
    futureListOnlyField: { ignored: true },
  };
  const targetLeases: IamBinding[] = [
    ...buildExecutorProjectLeases(
      "cdbentley",
      runId,
      expiresAt,
      email,
      roles[0]!.name,
      "read",
    ),
    ...buildExecutorProjectLeases(
      "cdbentley",
      runId,
      expiresAt,
      email,
      roles[1]!.name,
      "mutation",
    ),
    buildStorageReadLease("cdbentley", "prod", runId, expiresAt, email),
    ...buildReceiptLeases(
      "cdbentley",
      "prod",
      runId,
      expiresAt,
      "apply",
      approvedPlanRunId,
      email,
    ),
    buildMarkerReadLease("cdbentley", runId, expiresAt, "cdbentley", email),
    buildStorageLease(
      "cdbentley",
      "prod",
      runId,
      expiresAt,
      email,
      "apply",
      approvedPlanRunId,
    ),
  ];
  if (options.alterTargetLease === true) {
    const first = targetLeases[0]!;
    targetLeases[0] = {
      ...first,
      condition: {
        ...first.condition!,
        expression: "request.time < timestamp('2099-01-01T00:00:00.000Z')",
      },
    };
  }
  const strandedFenceBasis = buildMarkerReadLease(
    "cdbentley",
    runId,
    expiresAt,
    "cdbentley",
    email,
  );
  const strandedFence: IamBinding | undefined = options.strandedFence === undefined
    ? undefined
    : {
        condition: {
          description:
            "Expired inert binding used only to advance the orphan-recovery CAS generation.",
          expression: options.strandedFence === "exact"
            ? "request.time < timestamp('2000-01-01T00:00:00.000Z')"
            : "request.time < timestamp('2099-01-01T00:00:00.000Z')",
          title: `codex-orphan-fence-${createHash("sha256")
            .update(`orphan ${account.uniqueId} project cdbentley`)
            .digest("hex").slice(0, 12)}-0123456789abcdefabcd`,
        },
        members: [...strandedFenceBasis.members],
        role: strandedFenceBasis.role,
      };
  const executorStrandedFence: IamBinding | undefined =
    options.executorStrandedFence === undefined
      ? undefined
      : {
          condition: {
            description:
              "Expired inert binding used only to advance the orphan-recovery CAS generation.",
            expression: "request.time < timestamp('2000-01-01T00:00:00.000Z')",
            title: `codex-orphan-fence-${createHash("sha256")
              .update(`orphan ${account.uniqueId} executor policy`)
              .digest("hex").slice(0, 12)}-5a5e027fc51b61baf2e4`,
          },
          members: [options.executorStrandedFence === "exact"
            ? "user:CollinBentley1@gmail.com"
            : "user:attacker@example.com"],
          role: "roles/iam.serviceAccountTokenCreator",
        };
  const policies = new Map<string, IamPolicy>();
  policies.set("project:cdbentley", addExactBindings({
    bindings: [{ members: ["user:unrelated@example.com"], role: "roles/viewer" }],
    etag: "project-cdb-etag-1",
    version: 1,
  }, [
    ...targetLeases,
    ...(strandedFence === undefined ? [] : [strandedFence]),
  ]));
  for (const repository of ["runsetta", "healthmcp"] as const) {
    const projectId = repository === "healthmcp" ? "medlock-1025243085" : repository;
    policies.set(`project:${projectId}`, addExactBindings({
      bindings: [],
      etag: `project-${projectId}-etag-1`,
      version: 1,
    }, [buildMarkerReadLease(repository, runId, expiresAt, "cdbentley", email)]));
  }
  const lateRepository = "critical-history" as const;
  const lateProjectId = "critical-history-16823277";
  const lateLease = buildMarkerReadLease(
    lateRepository,
    runId,
    expiresAt,
    "cdbentley",
    email,
  );
  policies.set(`project:${lateProjectId}`, {
    bindings: [],
    etag: "project-critical-etag-1",
    version: 1,
  });
  const runtimeLeases = buildRuntimeActAsLeases("cdbentley", runId, expiresAt, email);
  const preservedRuntimeCondition: IamBinding = {
    condition: {
      description: "Unrelated conditional runtime binding that recovery must preserve.",
      expression: "request.time < timestamp('2027-01-01T00:00:00.000Z')",
      title: "preserved-unrelated-runtime-condition",
    },
    members: ["serviceAccount:unrelated@example.iam.gserviceaccount.com"],
    role: "roles/iam.serviceAccountTokenCreator",
  };
  let preservedConditionAdded = false;
  for (const [runtimeEmail, lease] of Object.entries(runtimeLeases)) {
    policies.set(`sa:${runtimeEmail}`, addExactBindings({
      bindings: [],
      etag: `runtime-${runtimeEmail.split("@")[0]}-etag-1`,
      version: 1,
    }, [
      lease,
      ...(preservedConditionAdded ? [] : [preservedRuntimeCondition]),
    ]));
    preservedConditionAdded = true;
  }
  policies.set(`sa:${email}`, executorStrandedFence === undefined
    ? addExactBindings({
        bindings: [],
        etag: "executor-policy-etag-1",
        version: 1,
      }, [buildTokenCreatorLease("cdbentley", runId, expiresAt)])
    : {
        bindings: [executorStrandedFence],
        etag: "executor-policy-etag-1",
        version: 3,
      });

  const calls: Array<{ method: string; url: string }> = [];
  let accountExists = true;
  let generation = 1;
  let lostResponseObserved = false;
  let lateWriteReconciled = false;
  let orphanRoleDeleteAttempts = 0;
  let roleDeleteForbiddenObserved = false;
  let postForbiddenRoleDeleteSleeps = 0;
  const setPolicy = (
    key: string,
    requested: IamPolicy,
  ): Response => {
    const current = policies.get(key);
    if (current === undefined) return new Response("", { status: 404 });
    if (
      key === `project:${lateProjectId}` &&
      !lateWriteReconciled &&
      requested.bindings.some((binding) =>
        binding.condition?.title.startsWith("codex-orphan-fence-")
      )
    ) {
      generation += 1;
      policies.set(key, {
        ...addExactBindings(current, [lateLease]),
        etag: `etag-${generation}`,
      });
      lateWriteReconciled = true;
      return new Response("", { status: 412 });
    }
    if (requested.etag !== current.etag) return new Response("", { status: 412 });
    generation += 1;
    const updated = { ...requested, etag: `etag-${generation}` };
    policies.set(key, updated);
    if (key === "project:cdbentley" && !lostResponseObserved) {
      lostResponseObserved = true;
      return new Response("", { status: 503 });
    }
    return Response.json(updated);
  };
  const fetcher = async (
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> => {
    const url = new URL(String(input));
    const path = decodeURIComponent(url.pathname);
    const method = init?.method ?? "GET";
    calls.push({ method, url: String(input) });
    const projectPolicy = /^\/v1\/projects\/([^/:]+):(get|set)IamPolicy$/.exec(path);
    if (projectPolicy !== null) {
      const key = `project:${projectPolicy[1]}`;
      if (projectPolicy[2] === "get") {
        expectProjectIamPolicyRead(input, init);
        return Response.json(policies.get(key));
      }
      const requested = (JSON.parse(String(init?.body)) as { policy: IamPolicy }).policy;
      return setPolicy(key, requested);
    }
    const serviceAccountPolicy = /^\/v1\/projects\/[^/]+\/serviceAccounts\/(.+):(get|set)IamPolicy$/.exec(
      path,
    );
    if (serviceAccountPolicy !== null) {
      const identifier = serviceAccountPolicy[1]!;
      const key = `sa:${identifier === account.uniqueId ? email : identifier}`;
      if (serviceAccountPolicy[2] === "get") {
        expectServiceAccountIamPolicyRead(input, init);
        return Response.json(policies.get(key));
      }
      const requested = (JSON.parse(String(init?.body)) as { policy: IamPolicy }).policy;
      return setPolicy(key, requested);
    }
    if (path === "/v1/projects/cdbentley/roles" && method === "GET") {
      return Response.json({ roles: [...roles, foreignRole] });
    }
    const roleMatch = /^\/v1\/(projects\/cdbentley\/roles\/pbt_[rm]_[0-9a-f]{20})$/.exec(path);
    if (roleMatch !== null) {
      const role = roles.find((candidate) => candidate.name === roleMatch[1]);
      if (role === undefined) return new Response("", { status: 404 });
      if (method === "DELETE") {
        orphanRoleDeleteAttempts += 1;
        if (options.roleDeleteForbidden === true) {
          roleDeleteForbiddenObserved = true;
          return new Response("", { status: 403 });
        }
        role.deleted = true;
        return Response.json(role);
      }
      return Response.json(role);
    }
    if (path === "/v1/projects/cdbentley/serviceAccounts" && method === "GET") {
      return Response.json({ accounts: accountExists ? [account, foreignAccount] : [foreignAccount] });
    }
    if (path.endsWith(`/serviceAccounts/${account.uniqueId}/keys`) && method === "GET") {
      if (options.keyInventoryFailure === true) return new Response("", { status: 503 });
      return Response.json({ keys: options.userManagedKey === true ? [{}] : [] });
    }
    if (path.endsWith(`/serviceAccounts/${account.uniqueId}:disable`) && method === "POST") {
      account.disabled = true;
      return Response.json({});
    }
    if (
      path.endsWith(`/serviceAccounts/${account.uniqueId}`) ||
      path.endsWith(`/serviceAccounts/${email}`)
    ) {
      if (!accountExists) return new Response("", { status: 404 });
      if (method === "DELETE") {
        accountExists = false;
        return new Response("{}");
      }
      return Response.json(account);
    }
    return new Response("", { status: 500 });
  };
  return {
    account,
    accountDeleted: () => !accountExists,
    calls,
    executorStrandedFence,
    fetcher,
    foreignAccount,
    foreignRole,
    lateWriteRejected: () => lateWriteReconciled,
    lostResponseObserved: () => lostResponseObserved,
    orphanRoleDeleteAttempts: () => orphanRoleDeleteAttempts,
    policies,
    postForbiddenRoleDeleteSleeps: () => postForbiddenRoleDeleteSleeps,
    preservedRuntimeCondition,
    roles,
    sleep: async () => {
      if (roleDeleteForbiddenObserved) postForbiddenRoleDeleteSleeps += 1;
    },
    strandedFence,
  };
}

function mutableOrphanContainmentFixture(
  tamperedIndex: 0 | 1,
  tamperedField: "description" | "displayName",
) {
  const accounts = ["55555555555555555555", "66666666666666666666"].map((random, index) => {
    const accountId = `gha-pbt-${random}`;
    const email = `${accountId}@cdbentley.iam.gserviceaccount.com`;
    const account = {
      description: `pbt-v1;repository=cdbentley;run=${8000000 + index};root=prod;mode=plan;approved=none;expires=2026-08-22T20:00:00.000Z`,
      disabled: false,
      displayName: "Protected Terraform Executor",
      email,
      etag: `account-etag-${index}`,
      name: `projects/cdbentley/serviceAccounts/${email}`,
      oauth2ClientId: `${9000000 + index}`,
      projectId: "cdbentley",
      uniqueId: `${index + 5}`.repeat(21),
    };
    if (index === tamperedIndex) {
      if (tamperedField === "description") account.description = "attacker-mutated-provenance";
      else account.displayName = "Attacker Mutated Display";
    }
    return account;
  });
  const foreignAccount = {
    email: "882468538648-compute@developer.gserviceaccount.com",
    name: "projects/cdbentley/serviceAccounts/882468538648-compute@developer.gserviceaccount.com",
    projectId: "cdbentley",
    uniqueId: "777777777777777777777",
  };
  const calls: Array<{ method: string; url: string }> = [];
  const fetcher = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    const path = decodeURIComponent(url.pathname);
    const method = init?.method ?? "GET";
    calls.push({ method, url: String(input) });
    if (path === "/v1/projects/cdbentley/serviceAccounts" && method === "GET") {
      return Response.json({ accounts: [...accounts, foreignAccount] });
    }
    for (const account of accounts) {
      if (path.endsWith(`/serviceAccounts/${account.uniqueId}:disable`) && method === "POST") {
        account.disabled = true;
        return Response.json({});
      }
      if (
        path.endsWith(`/serviceAccounts/${account.uniqueId}`) ||
        path.endsWith(`/serviceAccounts/${account.email}`)
      ) {
        return Response.json(account);
      }
    }
    return new Response("", { status: 500 });
  };
  return { accounts, calls, fetcher, foreignAccount };
}

function orphanPeerConvergenceFixture() {
  const accounts = ["88888888888888888888", "99999999999999999999"].map(
    (random, index) => {
      const accountId = `gha-pbt-${random}`;
      const email = `${accountId}@cdbentley.iam.gserviceaccount.com`;
      return {
        description:
          `pbt-v1;repository=cdbentley;run=${9100000 + index};root=bootstrap;mode=plan;approved=none;expires=2026-08-25T20:00:00.000Z`,
        disabled: false,
        displayName: "Protected Terraform Executor",
        email,
        etag: `account-etag-${index}`,
        name: `projects/cdbentley/serviceAccounts/${email}`,
        oauth2ClientId: `${9200000 + index}`,
        projectId: "cdbentley",
        uniqueId: `${index + 8}`.repeat(21),
      };
    },
  );
  const foreignAccount = {
    email: "882468538648-compute@developer.gserviceaccount.com",
    name: "projects/cdbentley/serviceAccounts/882468538648-compute@developer.gserviceaccount.com",
    projectId: "cdbentley",
    uniqueId: "777777777777777777777",
  };
  const calls: Array<{ method: string; url: string }> = [];
  const fetcher = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    const path = decodeURIComponent(url.pathname);
    const method = init?.method ?? "GET";
    calls.push({ method, url: String(input) });
    if (path === "/v1/projects/cdbentley/serviceAccounts" && method === "GET") {
      return Response.json({ accounts: [...accounts, foreignAccount] });
    }
    for (const [index, account] of accounts.entries()) {
      if (path.endsWith(`/serviceAccounts/${account.uniqueId}:disable`) && method === "POST") {
        account.disabled = true;
        return Response.json({});
      }
      if (path.endsWith(`/serviceAccounts/${account.uniqueId}`) && method === "GET") {
        return index === 0 ? new Response("", { status: 404 }) : Response.json(account);
      }
    }
    return new Response("", { status: 500 });
  };
  return { accounts, calls, fetcher, foreignAccount };
}
