import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  addExactLease,
  addExactBindings,
  addLeaseWithCas,
  buildExecutorProjectLeases,
  buildMarkerMutationLease,
  buildMarkerReadLease,
  buildReceiptLeases,
  buildReviewManifest,
  buildRuntimeActAsLeases,
  buildStorageLease,
  buildTokenCreatorLease,
  canonicalJson,
  consumePlanReceipt,
  deadlineFetcher,
  ExecutorLeaseManager,
  executorControlPermissions,
  fencePolicyMutations,
  inventoryBridgeArtifacts,
  main,
  publishPlanReceipt,
  publishPostApplyReceipt,
  proveConsumerFreeze,
  proveDeploymentParityMarkers,
  randomExecutorAccountId,
  randomExecutorRoleId,
  readConsumerWorkflowPin,
  removeExactLease,
  removeExactBindings,
  removeLeaseWithCas,
  requireSameDhiTransitionCapability,
  runProtectedBootstrap,
  TerraformSandboxExecutor,
  validateInvocation,
  verifyLocalSource,
  verifyPlatformCapability,
  verifyPlanApproval,
  waitForControlPermissions,
  waitForStatePermissions,
  type BridgeDependencies,
  type ExecutorSession,
  type ExecutionProof,
  type IamBinding,
  type IamPolicy,
  type Invocation,
  type JsonValue,
  type MarkerStateProof,
  type PlanIdentity,
  type PreparationResult,
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
    expect(workflow).toContain("PLATFORM_ACTIONS_READ_TOKEN: ${{ github.token }}");
    expect(workflow).toContain("exec /usr/bin/env -i");
    expect(workflow.match(/OWNER_OAUTH_ACCESS_TOKEN: \$\{\{ secrets\.OWNER_OAUTH_ACCESS_TOKEN \}\}/g)).toHaveLength(
      1,
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

  test("DHI-changing rollout keeps Actions disabled through four result receipts and merges", async () => {
    const rollout = (await readFile(join(root, "docs/security-rollout.md"), "utf8"))
      .replace(/\s+/g, " ");
    for (const requirement of [
      "current head of an open, unmerged public consumer PR",
      "deliberately imposes no consumer-`main` ancestry requirement",
      "Do not merge any PR until four immutable result receipts exist",
      "With Actions still disabled, merge the four unchanged prepared heads",
      "each resulting `main^{tree}` equals the receipt's `consumerTreeSha`",
      "the first `S` production deploy performs the sealed DHI epoch transition",
      "never use the mixed-SHA transition path when `P` and `S` declare different DHI parity IDs",
    ]) {
      expect(rollout).toContain(requirement);
    }
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
    ).toThrow("Production mode forbids");
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
  });

  test("IAM transformations preserve latest policy data and remove only the exact lease", () => {
    const lease = buildStorageLease(
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
    const lease = buildStorageLease(
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

  test("multi-binding cleanup restores v1 payload and audit config without v3 residue", () => {
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
    expect(cleaned).toEqual({ ...original, etag: "latest" });
  });

  test("IAM API writes use the fetched etag, retry CAS conflicts, and clean the latest policy", async () => {
    const lease = buildStorageLease(
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
      const url = String(input);
      if (url.endsWith(":getIamPolicy")) {
        return Response.json(current);
      }
      expect(url).toEndWith(":setIamPolicy");
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
    const lease = buildStorageLease(
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
    expect(current.version).toBe(1);
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

  test("controller has deadlines, unconditional exact cleanup, and no owner token in Terraform", async () => {
    const controller = await readFile(
      join(root, "tools/ci/protected-bootstrap-bridge.ts"),
      "utf8",
    );
    expect(controller).toContain("} finally {");
    expect(controller).toContain("const LEASE_MINUTES = 47;");
    expect(controller).toContain("const INTERNAL_OPERATION_MINUTES = 24;");
    expect(controller).toContain("fencePolicyMutations(");
    expect(controller).toContain("codex-cleanup-fence-");
    expect(controller).toContain("await waitForStatePermissions(");
    expect(controller).toContain("await waitForControlPermissions(");
    expect(controller).toContain('stdin: `${executorToken}\\n`');
    expect(controller).not.toContain("GOOGLE_OAUTH_ACCESS_TOKEN: invocation.ownerAccessToken");
    expect(controller).toContain('delete process.env[name]');
    expect(controller).toContain("deadlineFetcher(fetch");
    expect(controller).toContain('"-plugin-dir=/plugins"');
    expect(controller).toContain("--pid=private");
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
    expect(workflow).toContain("timeout-minutes: 35");
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
          tokenExpiresAtMs: Date.now() + 30 * 60_000,
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
      "remove:tfplan",
      "remove:tfdata",
      "remove:sandbox",
      "release",
    ]);
    expect(events.some((event) => event.includes("consumer/infra"))).toBeFalse();
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
    expect(events.at(-1)).toBe("release");
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
      EXECUTION_MODE: "apply",
    });
    const events: string[] = [];
    const dependencies = fakeDependencies(events, {
      planJson: JSON.stringify(raw),
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
    expect(events.at(-1)).toBe("release");
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
      expect(events.at(-1)).toBe("release");
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
    expect(events.at(-1)).toBe("release");
  });

  test("apply refuses before mutation when the full post-WIF drain reserve cannot fit", async () => {
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
      EXECUTION_MODE: "apply",
    });
    const events: string[] = [];
    const dependencies = fakeDependencies(events, {
      now: () => now,
      readPlanJson: async () => {
        events.push("show");
        now = startedAt + 10 * 60_000;
        return JSON.stringify(raw);
      },
      verifyApproval: async () => ({ canonical: "", sha256: review.sha256 }),
    });
    await expect(runProtectedBootstrap(invocation, dependencies)).rejects.toThrow(
      "Too little operation, IAM-lease, or executor-token lifetime remains to apply",
    );
    expect(events).not.toContain("consume");
    expect(events).not.toContain("elevate");
    expect(events).not.toContain("terraform:apply");
    expect(events.at(-1)).toBe("release");
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
    expect(events.at(-1)).toBe("release");
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
    expect(publishedReceipt.schemaVersion).toBe(3);
    expect(publishedReceipt.legacyCompatibilityMode).toBeFalse();
    expect(publishedReceipt.markerProof).toEqual(markers());
    expect(publishedReceipt.transitionWorkflowSha).toBe("");
    const applyInvocation = validateInvocation({
      ...validEnvironment(),
      APPROVED_MANIFEST_SHA256: review.sha256,
      APPROVED_PLAN_RUN_ID: "123456",
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
      .rejects.toThrow("already consumed");
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

  test("state validation uses only testIamPermissions and never reads or writes state objects", async () => {
    const invocation = validateInvocation(validEnvironment());
    const requests: Array<{ method: string; url: string }> = [];
    const returnedPermissions = new Map<string, readonly string[]>();
    let granted = true;
    const fetcher = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = String(input);
      requests.push({ method: init?.method ?? "GET", url });
      if (!url.includes("testIamPermissions") && !url.includes("iam/testPermissions")) {
        return new Response("", { status: 500 });
      }
      const requested = url.includes("storage/v2/")
        ? (JSON.parse(String(init?.body)) as { permissions: string[] }).permissions
        : new URL(url).searchParams.getAll("permissions");
      const decoded = decodeURIComponent(url);
      const permissions = !granted
        ? []
        : decoded.includes("/.protected-bootstrap/plans/")
        ? requested.filter((permission) =>
            permission === "storage.objects.create" || permission === "storage.objects.get"
          )
        : decoded.includes("default.tfstate")
        ? requested.filter((permission) => permission === "storage.objects.get")
        : decoded.includes("default.tflock")
        ? []
        : requested;
      if (granted) returnedPermissions.set(decoded, permissions);
      return Response.json({ permissions });
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
    );
    granted = false;
    await waitForStatePermissions(
      state,
      invocation,
      "short-lived-executor-access-token-value",
      "none",
      fetcher,
      async () => undefined,
    );
    expect(
      requests.every((request) =>
        request.url.includes("testIamPermissions") || request.url.includes("iam/testPermissions")
      ),
    ).toBeTrue();
    expect(requests.some((request) => request.url.includes("alt=media"))).toBeFalse();
    expect(requests.some((request) => request.url.includes("default.tfstate"))).toBeTrue();
    const planGrant = [...returnedPermissions.entries()].find(([url]) =>
      url.includes("/.protected-bootstrap/plans/")
    )?.[1];
    expect(planGrant).toContain("storage.objects.create");
    expect(planGrant).toContain("storage.objects.get");
    expect(planGrant).not.toContain("storage.objects.delete");
    expect(planGrant).not.toContain("storage.objects.update");
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
    expect(bootstrapPermissions).toContain("iam.denypolicies.create");
    expect(bootstrapPermissions).toContain("iam.denypolicies.delete");
    expect(bootstrapPermissions).toContain("iam.denypolicies.get");
    expect(bootstrapPermissions).toContain("iam.denypolicies.list");
    expect(bootstrapPermissions).toContain("iam.denypolicies.update");
    expect(bootstrapPermissions).toContain("serviceusage.services.disable");
    expect(bootstrapPermissions).toContain("serviceusage.services.enable");

    const prod = validateInvocation({ ...validEnvironment(), TERRAFORM_ROOT: "prod" });
    const urls: string[] = [];
    await waitForControlPermissions(
      prod,
      "short-lived-executor-access-token-value",
      "mutation",
      async (input, init) => {
        urls.push(String(input));
        const permissions = (JSON.parse(String(init?.body)) as { permissions: string[] }).permissions;
        return Response.json({ permissions });
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
  });

  test("abrupt-loss recovery disables first, fences late writes, deletes exact leases, and is retryable", async () => {
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
    const authorityReadIndex = fixture.calls.findIndex(({ url }) => url.endsWith(":getIamPolicy"));
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

    await inventoryBridgeArtifacts(
      "cdbentley",
      "google-owner-access-token-value",
      fixture.fetcher,
      fixture.sleep,
      Date.now() + 60_000,
    );
    expect(fixture.accountDeleted()).toBeTrue();
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
    const authorityReadIndex = fixture.calls.findIndex(({ url }) => url.endsWith(":getIamPolicy"));
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
      expect(executorLookupIndexes).toHaveLength(6);
      expect(lastDisable).toBeLessThan(executorLookupIndexes[4]!);
      for (const account of fixture.accounts) {
        const disableIndex = fixture.calls.findIndex(({ url }) =>
          url.endsWith(`/serviceAccounts/${account.uniqueId}:disable`)
        );
        expect(disableIndex).toBeGreaterThanOrEqual(0);
      }
    }
  });

  test("preexisting executor project authority aborts before enable, mint, or policy mutation", async () => {
    const accountId = "gha-pbt-0123456789abcdefabcd";
    const randomEmail = `${accountId}@cdbentley.iam.gserviceaccount.com`;
    const leaseExpiresAt = new Date(Date.now() + 47 * 60_000);
    const account = {
      description: `pbt-v1;repository=cdbentley;run=123456;root=bootstrap;mode=plan;approved=none;expires=${leaseExpiresAt.toISOString()}`,
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
      const method = init?.method ?? "GET";
      calls.push({ method, url });
      if (url.includes("cloudresourcemanager") && url.endsWith(":getIamPolicy")) {
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
        if (url.endsWith(":getIamPolicy")) {
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
    tokenExpiresAtMs: defaultNow + 30 * 60_000,
  };
  return {
    acquireExecutor: overrides.acquireExecutor ?? (async () => {
      events.push("acquire");
      return { ...session, tokenExpiresAtMs: now() + 30 * 60_000 };
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
    CONSUMER_ACTIONS_READ_TOKEN: "github-actions-read-token-value",
    CONSUMER_ROOT: "/tmp/consumer",
    CONSUMER_SHA: consumerSha,
    EXECUTION_MODE: "plan",
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

function identity(): PlanIdentity {
  return {
    consumerSha,
    consumerTreeSha,
    dhiParityId: "a".repeat(50),
    legacyCompatibilityMode: false,
    maxMutatorTokenLifetimeSeconds: 300,
    markerProof: markers(),
    platformSha,
    projectId: "cdbentley",
    repository: "cdbentley",
    repositoryId: "1255553151",
    terraformRoot: "prod",
    tokenDrainSeconds: 3600,
    transitionWorkflowSha: "",
  };
}

function preparation(overrides: Partial<PreparationResult> = {}): PreparationResult {
  return {
    consumerTreeSha,
    dhiParityId: "a".repeat(50),
    maxMutatorTokenLifetimeSeconds: 300,
    tokenDrainSeconds: 3600,
    ...overrides,
  };
}

function executionProof(overrides: Partial<ExecutionProof> = {}): ExecutionProof {
  return {
    ...preparation(),
    freezeProof: freezeSnapshot(1_800_000_000_000),
    markerProof: markers(),
    ...overrides,
  };
}

function freezeSnapshot(
  observedAtMs: number,
  tokenDrainSeconds = 3600,
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

function plan(resourceChanges: unknown[]): Record<string, unknown> {
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
    resource_drift: [],
    terraform_version: "1.14.5",
    timestamp: "2026-08-22T21:00:00Z",
    variables: {},
  };
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

function abruptLossFixture(options: {
  readonly alterTargetLease?: boolean;
  readonly keyInventoryFailure?: boolean;
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
    buildStorageLease("cdbentley", "prod", runId, expiresAt, email, "plan", ""),
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
  const policies = new Map<string, IamPolicy>();
  policies.set("project:cdbentley", addExactBindings({
    bindings: [{ members: ["user:unrelated@example.com"], role: "roles/viewer" }],
    etag: "project-cdb-etag-1",
    version: 1,
  }, targetLeases));
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
  for (const [runtimeEmail, lease] of Object.entries(runtimeLeases)) {
    policies.set(`sa:${runtimeEmail}`, addExactBindings({
      bindings: [],
      etag: `runtime-${runtimeEmail.split("@")[0]}-etag-1`,
      version: 1,
    }, [lease]));
  }
  policies.set(`sa:${email}`, addExactBindings({
    bindings: [],
    etag: "executor-policy-etag-1",
    version: 1,
  }, [buildTokenCreatorLease("cdbentley", runId, expiresAt)]));

  const calls: Array<{ method: string; url: string }> = [];
  let accountExists = true;
  let generation = 1;
  let lostResponseObserved = false;
  let lateWriteReconciled = false;
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
      if (projectPolicy[2] === "get") return Response.json(policies.get(key));
      const requested = (JSON.parse(String(init?.body)) as { policy: IamPolicy }).policy;
      return setPolicy(key, requested);
    }
    const serviceAccountPolicy = /^\/v1\/projects\/[^/]+\/serviceAccounts\/(.+):(get|set)IamPolicy$/.exec(
      path,
    );
    if (serviceAccountPolicy !== null) {
      const key = `sa:${serviceAccountPolicy[1]}`;
      if (serviceAccountPolicy[2] === "get") return Response.json(policies.get(key));
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
        role.deleted = true;
        return Response.json(role);
      }
      return Response.json(role);
    }
    if (path === "/v1/projects/cdbentley/serviceAccounts" && method === "GET") {
      return Response.json({ accounts: accountExists ? [account, foreignAccount] : [foreignAccount] });
    }
    if (path.endsWith(`/serviceAccounts/${email}/keys`) && method === "GET") {
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
    fetcher,
    foreignAccount,
    foreignRole,
    lateWriteRejected: () => lateWriteReconciled,
    lostResponseObserved: () => lostResponseObserved,
    policies,
    roles,
    sleep: async () => undefined,
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
