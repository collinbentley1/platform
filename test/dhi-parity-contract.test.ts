import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "..");
const cloudHelper = join(repoRoot, "tools/ci/cloud-run-dhi-parity.sh");
const parityId = "1a4cho1elzg84pavos8mbanvvpmkieiht7kyhpjdofzpivf3k8";
const projectNumber = "882468538648";
const repositoryId = "1255553151";
const headSha = "0123456789abcdef0123456789abcdef01234567";
const workflowSha = "1234567890abcdef1234567890abcdef12345678";
const productionImage = "us-east4-docker.pkg.dev/cdbentley/site/cdbentley";
const previewImage = "us-east4-docker.pkg.dev/cdbentley/site-preview/cdbentley";
const indexDigest = `sha256:${"a".repeat(64)}`;
const runnableDigest = `sha256:${"b".repeat(64)}`;
const previewRuntime = "cloud-run-preview@cdbentley.iam.gserviceaccount.com";
const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("durable preview/production DHI parity", () => {
  test("the label id is the full executable hash of the documented canonical DHI tuple", async () => {
    const containerPolicy = await readFile(
      join(repoRoot, "tools/ci/container-artifact-contract.sh"),
      "utf8",
    );
    const cloudPolicy = await readFile(cloudHelper, "utf8");
    const constant = (name: string): string => {
      const match = containerPolicy.match(new RegExp(`readonly ${name}=(sha256:[0-9a-f]{64})`));
      expect(match).not.toBeNull();
      return match![1]!;
    };
    const canonical = JSON.stringify({
      dhiDev: {
        childDigest: constant("DHI_DEV_AMD64_DIGEST"),
        topDigest: constant("DHI_DEV_TOP_DIGEST"),
      },
      dhiRuntime: {
        childDigest: constant("DHI_RUNTIME_AMD64_DIGEST"),
        topDigest: constant("DHI_RUNTIME_TOP_DIGEST"),
      },
    });
    expect(canonical).toBe(
      '{"dhiDev":{"childDigest":"sha256:58a392f5dec3be5cb20a2495baca84ac785f237a2d2904c5b9cad7ba11f3e475","topDigest":"sha256:d364f4eb6d20f8e906bdb9d12726995f8335878f46e0c1c69c910df9d92df5d8"},"dhiRuntime":{"childDigest":"sha256:0f9e5f506d653e0f87e44bb5c24fece19f9fb7253016f6e49d7a4783026f876d","topDigest":"sha256:b169efde3cf30151d66f3d7988cad69b4d08833cc4cfaeca7da6bda2bd0a89b3"}}',
    );
    const hex = createHash("sha256").update(canonical, "utf8").digest("hex");
    expect(hex).toBe("3366d5ab494ec989466392ff17bbd3a4ba66fe70938cca7254fefbe779cf16c8");
    const canonicalBase36 = (digest: string): string =>
      BigInt(`0x${digest}`).toString(36).padStart(50, "0");
    expect(canonicalBase36(hex)).toBe(parityId);
    const naturally49CharacterDigest = `0f${"f".repeat(62)}`;
    expect(BigInt(`0x${naturally49CharacterDigest}`).toString(36)).toHaveLength(49);
    expect(canonicalBase36(naturally49CharacterDigest)).toMatch(/^0[a-z0-9]{49}$/);
    expect(containerPolicy).toContain(`readonly DHI_PARITY_ID=${parityId}`);
    expect(cloudPolicy).toContain(`readonly DHI_PARITY_ID=${parityId}`);
  });

  test("every traffic-changing workflow uses the same FIFO deployment lock", async () => {
    const cases = [
      ["deploy-preview.yml", "deploy"],
      ["deploy-preview.yml", "invalidate"],
      ["deploy-prod.yml", "deploy"],
      ["cleanup-preview.yml", "cleanup"],
      ["reconcile-previews.yml", "reconcile"],
    ] as const;
    for (const [file, jobName] of cases) {
      const source = await readFile(join(repoRoot, ".github/workflows", file), "utf8");
      const workflow = Bun.YAML.parse(source) as {
        jobs: Record<string, { concurrency: Record<string, unknown> }>;
      };
      expect(workflow.jobs[jobName]!.concurrency).toEqual({
        group: "deployment-parity-${{ github.event.repository.id }}",
        queue: "max",
        "cancel-in-progress": false,
      });
    }
  });

  test("preview and production builds consume the same Dockerfile and verified DHI contexts", async () => {
    const buildInputs = async (workflowName: string): Promise<Record<string, unknown>> => {
      const workflow = Bun.YAML.parse(
        await readFile(join(repoRoot, ".github/workflows", workflowName), "utf8"),
      ) as { jobs: { build: { steps: Array<Record<string, any>> } } };
      const step = workflow.jobs.build.steps.find((candidate) =>
        String(candidate.uses ?? "").startsWith("docker/build-push-action@")
      );
      expect(step).toBeDefined();
      return {
        "build-contexts": step!.with["build-contexts"],
        context: step!.with.context,
        file: step!.with.file,
      };
    };
    const preview = await buildInputs("deploy-preview.yml");
    const production = await buildInputs("deploy-prod.yml");
    expect(preview).toEqual(production);
    expect(preview).toEqual({
      "build-contexts": [
        "platform.invalid/bun-release=oci-layout://${{ steps.base_images.outputs.oven_layout }}@${{ steps.base_images.outputs.oven_child_digest }}",
        "platform.invalid/dhi-bun-dev=oci-layout://${{ steps.base_images.outputs.dhi_dev_layout }}@${{ steps.base_images.outputs.dhi_dev_child_digest }}",
        "platform.invalid/dhi-bun-runtime=oci-layout://${{ steps.base_images.outputs.dhi_runtime_layout }}@${{ steps.base_images.outputs.dhi_runtime_child_digest }}",
      ].join("\n") + "\n",
      context: ".",
      file: "Dockerfile",
    });
  });

  test("preview admission verifies remote production OCI and brackets it with exact projections", async () => {
    const preview = await readFile(join(repoRoot, ".github/workflows/deploy-preview.yml"), "utf8");
    const transaction = await readFile(join(repoRoot, "tools/ci/cloud-run-preview-traffic.sh"), "utf8");
    expect(preview).toContain("verify-live-production");
    expect(preview.match(/cloud-run-dhi-parity\.sh\" prove-production/g)?.length).toBe(3);
    expect(preview).toContain("Production changed while its remote OCI graph was being verified.");
    expect(preview).toContain("rm -f -- \"$token_file\"");
    expect(preview.indexOf("rm -f -- \"$token_file\"")).toBeLessThan(
      preview.indexOf("- name: Authenticate preview deployer"),
    );
    expect(preview).toContain("dhi-parity-id=${DHI_PARITY_ID}");
    expect(preview).toContain("digest-mismatch: error");
    expect(preview).toContain("skip-decompress: true");
    expect(preview).toContain("timeout-minutes: 30");
    expect(preview).not.toContain("Revalidate every route and open only as the final mutation");
    expect(preview).toContain("admission-open: ${{ steps.traffic-commit.outcome }}");
    expect(preview).toContain("lifecycle-keep: ${{ steps.traffic-commit.outputs.admitted }}");
    expect(transaction).toContain("capture_snapshot before true");
    expect(transaction).toContain("capture_snapshot after false");
    expect(transaction).toContain("commit_update_mask=traffic");
    expect(transaction).toContain("commit_update_mask=traffic,ingress,invokerIamDisabled");
    expect(transaction).toContain("?updateMask=${commit_update_mask}&allowMissing=false");
    expect(transaction).toContain("capture_snapshot health-after false");
    expect(transaction).toContain("((.vpcAccess // {}) == {})");
    expect(transaction.indexOf("patched=true")).toBeLessThan(
      transaction.indexOf("?updateMask=${commit_update_mask}&allowMissing=false", transaction.indexOf("patched=true")),
    );
    expect(transaction.lastIndexOf("capture_snapshot health-after false")).toBeLessThan(
      transaction.lastIndexOf("patched=false"),
    );
  });

  test("monotonic teardown preserves proven survivors and seals the zero-tag state", async () => {
    const controller = await readFile(join(repoRoot, "tools/ci/cloud-run-preview-controller.sh"), "utf8");
    for (const workflowName of ["cleanup-preview.yml", "reconcile-previews.yml"]) {
      const workflow = await readFile(join(repoRoot, ".github/workflows", workflowName), "utf8");
      expect(workflow).toContain("cloud-run-preview-controller.sh");
      expect(workflow).toContain("deployment-parity-transition.sh");
      expect(workflow).toContain("DHI_PARITY_ID: \${{ steps.parity-policy.outputs.dhi-parity-id }}");
    }
    expect(controller).toContain("inspect-preview-routes");
    expect(controller).toContain("update_mask=traffic,ingress,invokerIamDisabled");
    expect(controller).toContain('[ "$status" = 404 ]');
    expect(controller).toContain('.metadata.labels["platform-workflow-sha"] == $workflow_sha');
    expect(controller).toContain("acquire_transition preview-maintenance");
  });

  test("dedicated parity IAM is get/download-only and exact-workflow bound", async () => {
    const bootstrap = await readFile(join(repoRoot, "terraform/modules/bootstrap/main.tf"), "utf8");
    const serviceModule = await readFile(join(repoRoot, "terraform/modules/cloud-run-service/main.tf"), "utf8");
    const cloudRunRole = block(bootstrap, "google_project_iam_custom_role", "deployment_parity_cloud_run_reader");
    const imageRole = block(bootstrap, "google_project_iam_custom_role", "deployment_parity_image_downloader");
    expect(quotedPermissions(cloudRunRole)).toEqual(["run.revisions.get", "run.services.get"]);
    expect(quotedPermissions(imageRole)).toEqual(["artifactregistry.repositories.downloadArtifacts"]);
    for (const forbidden of ["list", "update", "delete", "setIamPolicy", "getIamPolicy", "actAs", "secretmanager"] ) {
      expect(`${cloudRunRole}\n${imageRole}`).not.toContain(forbidden);
    }
    expect(bootstrap).toContain('account_id   = "gha-deploy-parity"');
    const authority = JSON.parse(
      await readFile(join(repoRoot, "terraform/modules/bootstrap/workflow-authority.json"), "utf8"),
    ) as Array<{ path: string; serviceAccounts: string[] }>;
    const grantedTo = (account: string) =>
      authority.filter((entry) => entry.serviceAccounts.includes(account)).map((entry) => entry.path);
    expect(grantedTo("gha-deploy-parity")).toEqual([
      ".github/workflows/deploy-preview.yml",
      ".github/workflows/deploy-prod.yml",
    ]);
    const revisionDeployer = block(
      bootstrap,
      "google_project_iam_custom_role",
      "cloud_run_revision_deployer",
    );
    expect(quotedPermissions(revisionDeployer)).toEqual([
      "run.operations.get",
      "run.revisions.get",
      "run.services.get",
      "run.services.update",
    ]);
    expect(revisionDeployer).not.toContain("setIamPolicy");
    const previewCommitter = block(
      bootstrap,
      "google_project_iam_custom_role",
      "preview_traffic_committer",
    );
    expect(quotedPermissions(previewCommitter)).toEqual([
      "run.operations.get",
      "run.revisions.get",
      "run.services.get",
      "run.services.getIamPolicy",
      "run.services.setIamPolicy",
      "run.services.update",
    ]);
    expect(bootstrap).toContain('account_id   = "gha-preview-commit"');
    expect(grantedTo("gha-preview-commit")).toEqual([
      ".github/workflows/cleanup-preview.yml",
      ".github/workflows/deploy-preview.yml",
      ".github/workflows/deploy-prod.yml",
      ".github/workflows/reconcile-previews.yml",
    ]);
    expect(grantedTo("gha-preview-deploy")).toEqual([
      ".github/workflows/deploy-preview.yml",
      ".github/workflows/deploy-prod.yml",
    ]);
    expect(bootstrap).toContain('resource "google_service_account_iam_member" "workflow_authority"');
    const prodImageGrant = block(
      serviceModule,
      "google_artifact_registry_repository_iam_member",
      "deployment_parity_prod_image_reader",
    );
    const previewImageGrant = block(
      serviceModule,
      "google_artifact_registry_repository_iam_member",
      "deployment_parity_preview_image_reader",
    );
    expect(prodImageGrant).toContain("repository = google_artifact_registry_repository.site.repository_id");
    expect(previewImageGrant).toContain("repository = google_artifact_registry_repository.preview.repository_id");
    for (const grant of [prodImageGrant, previewImageGrant]) {
      expect(grant).toContain('role       = "projects/${var.project_id}/roles/deploymentParityImageDownloader"');
      expect(grant).toContain('member     = "serviceAccount:${var.deployment_parity_reader_service_account_email}"');
    }
    const baselineGrant = block(
      serviceModule,
      "google_artifact_registry_repository_iam_member",
      "preview_deploy_prod_image_reader",
    );
    expect(baselineGrant).toContain("repository = google_artifact_registry_repository.site.repository_id");
    expect(baselineGrant).toContain('role       = "roles/artifactregistry.reader"');
    expect(baselineGrant).toContain('member     = "serviceAccount:${var.preview_deploy_service_account_email}"');
    for (const [resource, repository] of [
      ["preview_commit_prod_image_reader", "site"],
      ["preview_commit_preview_image_reader", "preview"],
    ] as const) {
      const grant = block(
        serviceModule,
        "google_artifact_registry_repository_iam_member",
        resource,
      );
      expect(grant).toContain(`repository = google_artifact_registry_repository.${repository}.repository_id`);
      expect(grant).toContain('role       = "projects/${var.project_id}/roles/deploymentParityImageDownloader"');
      expect(grant).toContain('member     = "serviceAccount:${var.preview_commit_service_account_email}"');
    }
    const previewCommitGrant = block(
      serviceModule,
      "google_cloud_run_v2_service_iam_member",
      "preview_commit",
    );
    expect(previewCommitGrant).toContain("name     = google_cloud_run_v2_service.preview.name");
    expect(previewCommitGrant).toContain('role     = "projects/${var.project_id}/roles/previewTrafficCommitter"');
    expect(previewCommitGrant).toContain('member   = "serviceAccount:${var.preview_commit_service_account_email}"');
    const previewCommitProdRead = block(
      serviceModule,
      "google_cloud_run_v2_service_iam_member",
      "preview_commit_prod_reader",
    );
    expect(previewCommitProdRead).toContain("name     = google_cloud_run_v2_service.site.name");
    expect(previewCommitProdRead).toContain('role     = "projects/${var.project_id}/roles/deploymentParityCloudRunReader"');
    expect(previewCommitProdRead).toContain('member   = "serviceAccount:${var.preview_commit_service_account_email}"');
    for (const forbidden of ["update", "setIamPolicy", "getIamPolicy", "list", "actAs", "secretmanager"]) {
      expect(`${previewCommitProdRead}\n${cloudRunRole}`).not.toContain(forbidden);
    }
    const prodDeployGrant = block(
      serviceModule,
      "google_cloud_run_v2_service_iam_member",
      "prod_deploy",
    );
    expect(prodDeployGrant).not.toContain("previewTrafficCommitter");
    expect(prodDeployGrant).not.toContain("setIamPolicy");
  });

  test("production validates every live preview OCI graph and brackets exact Cloud Run projections", async () => {
    const production = await readFile(join(repoRoot, ".github/workflows/deploy-prod.yml"), "utf8");
    expect(production).toContain("verify-live-images");
    expect(production).toContain('LIVE_IMAGE_SET_FILE="$image_set"');
    expect(production).toContain("preview-parity-before-revisions");
    expect(production).toContain("capture_preview_routes before inspect-preview-routes");
    expect(production).toContain("capture_preview_routes after inspect-preview-routes");
    expect(production).toContain("Preview traffic changed while the production parity guard was evaluating it.");
    expect(production).toContain("tools/ci/container-artifact-contract.sh");
    expect(production).toContain("platform-production-bases-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}.tar");
    expect(production).toContain("digest-mismatch: error");
    expect(production).toContain("skip-decompress: true");
    expect(production.indexOf('rm -f -- "$token_file" "$PARITY_CREDENTIAL_FILE"')).toBeLessThan(
      production.indexOf("- name: Authenticate production deployer"),
    );
  });

  test("live production projection accepts only exact 100% traffic and parity labels", async () => {
    const service = productionService();
    const revision = productionRevision();
    const accepted = await runCloudContract("prove-production", { service, revisions: [revision] });
    expect(accepted.exitCode, accepted.stderr).toBe(0);
    expect(accepted.outputs.dhi_parity_id).toBe(parityId);
    expect(accepted.outputs.live_production_index_image).toBe(`${productionImage}@${indexDigest}`);
    expect(accepted.outputs.live_production_runnable_image).toBe(`${productionImage}@${runnableDigest}`);

    service.status.traffic[0].percent = 99;
    const split = await runCloudContract("prove-production", { service, revisions: [revision] });
    expect(split.exitCode).not.toBe(0);
    expect(split.stderr).toContain("not exactly one healthy, untagged, 100%-served");

    const missing = productionRevision();
    delete missing.metadata.labels["dhi-parity-id"];
    const unlabeled = await runCloudContract("prove-production", {
      service: productionService(),
      revisions: [missing],
    });
    expect(unlabeled.exitCode).not.toBe(0);
    expect(unlabeled.stderr).toContain("lacks a bound OCI index, runnable child, or trusted DHI provenance metadata");

    const forgedParent = productionRevision();
    forgedParent.spec.containers[0].env.find((entry: any) => entry.name === "PLATFORM_IMAGE_INDEX_DIGEST").value =
      `sha256:${"f".repeat(64)}`;
    const parentResult = await runCloudContract("prove-production", {
      service: productionService(),
      revisions: [forgedParent],
    });
    expect(parentResult.exitCode, parentResult.stderr).toBe(0);
    expect(parentResult.outputs.live_production_index_image).toBe(`${productionImage}@sha256:${"f".repeat(64)}`);

    const forgedChild = productionRevision();
    forgedChild.spec.containers[0].env.find((entry: any) => entry.name === "PLATFORM_IMAGE_RUNNABLE_DIGEST").value =
      `sha256:${"f".repeat(64)}`;
    const childResult = await runCloudContract("prove-production", {
      service: productionService(),
      revisions: [forgedChild],
    });
    expect(childResult.exitCode).not.toBe(0);
  });

  test("production rejects missing or different preview parity metadata before OCI inspection", async () => {
    const service = previewService();
    const revisions = [baselineRevision(), previewRevision()];
    const accepted = await runCloudContract("prove-preview-tags", { service, revisions });
    expect(accepted.exitCode, accepted.stderr).toBe(0);
    expect(accepted.outputs.active_preview_count).toBe("1");

    revisions[1].metadata.labels["dhi-parity-id"] = "different";
    const mismatched = await runCloudContract("prove-preview-tags", { service, revisions });
    expect(mismatched.exitCode).not.toBe(0);
    expect(mismatched.stderr).toContain("lacks the exact candidate DHI parity provenance");
  });

  test("every untagged route must be the sanitized production-image baseline", async () => {
    const baseline = baselineRevision();
    baseline.spec.containers[0].image = `${previewImage}@${runnableDigest}`;
    baseline.status.imageDigest = baseline.spec.containers[0].image;
    const rejected = await runCloudContract("prove-preview-routes", {
      service: previewService(),
      revisions: [baseline, previewRevision()],
    });
    expect(rejected.exitCode).not.toBe(0);
    expect(rejected.stderr).toContain("lacks the exact candidate DHI parity provenance");
  });

  test("preview routes reject workflow, environment, and network drift", async () => {
    const extraEnvironment = previewRevision();
    extraEnvironment.spec.containers[0].env.push({ name: "ARBITRARY", value: "plain-but-unreviewed" });
    let rejected = await runCloudContract("prove-preview-routes", {
      service: previewService(),
      revisions: [baselineRevision(), extraEnvironment],
    });
    expect(rejected.exitCode).not.toBe(0);

    const oldWorkflow = previewRevision();
    oldWorkflow.metadata.labels["platform-workflow-sha"] = "f".repeat(40);
    rejected = await runCloudContract("prove-preview-routes", {
      service: previewService(),
      revisions: [baselineRevision(), oldWorkflow],
    });
    expect(rejected.exitCode).not.toBe(0);

    const directVpc = previewRevision();
    directVpc.metadata.annotations = {
      "run.googleapis.com/network-interfaces": '[{"network":"default"}]',
    };
    rejected = await runCloudContract("prove-preview-routes", {
      service: previewService(),
      revisions: [baselineRevision(), directVpc],
    });
    expect(rejected.exitCode).not.toBe(0);

    const cloudSql = previewRevision();
    cloudSql.metadata.annotations = { "run.googleapis.com/cloudsql-instances": "project:region:db" };
    rejected = await runCloudContract("prove-preview-routes", {
      service: previewService(),
      revisions: [baselineRevision(), cloudSql],
    });
    expect(rejected.exitCode).not.toBe(0);

    const automaticBase = previewRevision();
    automaticBase.metadata.annotations = {
      "run.googleapis.com/base-images": '{"application":"nodejs24"}',
    };
    rejected = await runCloudContract("prove-preview-routes", {
      service: previewService(),
      revisions: [baselineRevision(), automaticBase],
    });
    expect(rejected.exitCode).not.toBe(0);

    const automaticRuntime = previewRevision();
    automaticRuntime.spec.runtimeClassName = "run.googleapis.com/linux-base-image-update";
    rejected = await runCloudContract("prove-preview-routes", {
      service: previewService(),
      revisions: [baselineRevision(), automaticRuntime],
    });
    expect(rejected.exitCode).not.toBe(0);
  });

  test("all explicit image deploys clear Cloud Run automatic base-image rebasing", async () => {
    const preview = await readFile(join(repoRoot, ".github/workflows/deploy-preview.yml"), "utf8");
    const production = await readFile(join(repoRoot, ".github/workflows/deploy-prod.yml"), "utf8");
    expect(preview.match(/--clear-base-image/g)?.length).toBe(2);
    expect(production.match(/--clear-base-image/g)?.length).toBe(2);
    expect(`${preview}\n${production}`).not.toContain("--no-automatic-updates");
  });

  test("every mutator access token has the manifest-bounded five-minute lifetime", async () => {
    for (const workflowName of [
      "cleanup-preview.yml",
      "deploy-preview.yml",
      "deploy-prod.yml",
      "infrastructure.yml",
      "reconcile-previews.yml",
    ]) {
      const workflow = Bun.YAML.parse(
        await readFile(join(repoRoot, ".github/workflows", workflowName), "utf8"),
      ) as { jobs: Record<string, { steps?: Array<Record<string, any>> }> };
      for (const job of Object.values(workflow.jobs)) {
        for (const step of job.steps ?? []) {
          if (step.uses !== "google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093") continue;
          const serviceAccount = String(step.with?.service_account ?? "");
          if (!/(?:publish|deploy|commit|terraform)_service_account/.test(serviceAccount)) continue;
          expect(step.with.token_format, `${workflowName}: ${step.name}`).toBe("access_token");
          expect(step.with.access_token_lifetime, `${workflowName}: ${step.name}`).toBe("300s");
        }
      }
    }
  });

  test("only the exact sealed Terraform hello bootstrap is a transition exception", async () => {
    const service = bootstrapPreviewService();
    const bootstrap = bootstrapRevision();
    const accepted = await runCloudContract("inspect-preview-routes", { service, revisions: [bootstrap] });
    expect(accepted.exitCode, accepted.stderr).toBe(0);
    expect(accepted.outputs.sealed_bootstrap).toBe("true");
    expect(accepted.outputs.active_preview_count).toBe("0");

    bootstrap.spec.containers[0].image = `${productionImage}@${runnableDigest}`;
    bootstrap.status.imageDigest = bootstrap.spec.containers[0].image;
    const arbitrary = await runCloudContract("inspect-preview-routes", { service, revisions: [bootstrap] });
    expect(arbitrary.exitCode, arbitrary.stderr).toBe(0);
    expect(arbitrary.outputs.sealed_bootstrap).toBe("false");

    const publicService = bootstrapPreviewService();
    publicService.metadata.annotations["run.googleapis.com/ingress"] = "all";
    const publicResult = await runCloudContract("inspect-preview-routes", {
      service: publicService,
      revisions: [bootstrapRevision()],
    });
    expect(publicResult.outputs.sealed_bootstrap).toBe("false");
  });
});

function block(source: string, type: string, name: string): string {
  const start = source.indexOf(`resource "${type}" "${name}" {`);
  expect(start).toBeGreaterThanOrEqual(0);
  let depth = 0;
  for (let index = start; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(start, index + 1);
    }
  }
  throw new Error(`unterminated ${type}.${name}`);
}

function quotedPermissions(source: string): string[] {
  const permissions = source.match(/permissions\s*=\s*\[([\s\S]*?)\]/)?.[1] ?? "";
  return [...permissions.matchAll(/"([^"]+)"/g)].map((match) => match[1]!).sort();
}

function productionService(): any {
  return {
    apiVersion: "serving.knative.dev/v1",
    kind: "Service",
    metadata: {
      generation: 7,
      labels: { "dhi-parity-id": parityId, environment: "production", "managed-by": "github-actions" },
      name: "cdbentley",
      namespace: projectNumber,
    },
    spec: { traffic: [{ latestRevision: true, percent: 100 }] },
    status: {
      conditions: ["Ready", "ConfigurationsReady", "RoutesReady"].map((type) => ({ status: "True", type })),
      latestCreatedRevisionName: "cdbentley-00007-abc",
      latestReadyRevisionName: "cdbentley-00007-abc",
      observedGeneration: 7,
      traffic: [{ latestRevision: true, percent: 100, revisionName: "cdbentley-00007-abc" }],
    },
  };
}

function productionRevision(): any {
  return revision("cdbentley-00007-abc", "cdbentley", "production", productionImage);
}

function previewService(): any {
  return {
    apiVersion: "serving.knative.dev/v1",
    kind: "Service",
    metadata: {
      annotations: {
        "run.googleapis.com/ingress": "all",
        "run.googleapis.com/invoker-iam-disabled": "true",
      },
      generation: 9,
      name: "cdbentley-preview",
      namespace: projectNumber,
    },
    spec: {
      traffic: [
        { revisionName: "cdbentley-preview-baseline", percent: 100 },
        { revisionName: "cdbentley-preview-p31-abc", tag: "pr-31" },
      ],
    },
    status: {
      conditions: ["Ready", "ConfigurationsReady", "RoutesReady"].map((type) => ({ status: "True", type })),
      observedGeneration: 9,
      traffic: [
        { percent: 100, revisionName: "cdbentley-preview-baseline" },
        { revisionName: "cdbentley-preview-p31-abc", tag: "pr-31", url: "https://pr-31.example" },
      ],
    },
  };
}

function previewRevision(): any {
  const value = revision("cdbentley-preview-p31-abc", "cdbentley-preview", "preview", previewImage);
  value.metadata.labels["preview-role"] = "pr";
  value.metadata.labels["github-pr"] = "31";
  value.spec.containers[0].command = [];
  value.spec.containers[0].args = [];
  value.spec.containers[0].env.push(
    { name: "PLATFORM_DEPLOY_ENVIRONMENT", value: "preview" },
    { name: "PLATFORM_DEPLOY_NONCE", value: "c".repeat(64) },
    { name: "PLATFORM_PREVIEW_NUMBER", value: "31" },
  );
  return value;
}

function baselineRevision(): any {
  const value = revision("cdbentley-preview-baseline", "cdbentley-preview", "preview", productionImage);
  value.metadata.labels["preview-role"] = "baseline";
  value.spec.containers[0].command = ["bun"];
  value.spec.containers[0].args = [
    "-e",
    "Bun.serve({port:+process.env.PORT,fetch(){return new Response(null,{status:404})}})",
  ];
  value.spec.containers[0].env.unshift({ name: "PLATFORM_DEPLOY_ENVIRONMENT", value: "preview-baseline" });
  return value;
}

function bootstrapPreviewService(): any {
  const value = previewService();
  value.metadata.annotations["run.googleapis.com/ingress"] = "internal";
  value.metadata.annotations["run.googleapis.com/invoker-iam-disabled"] = "false";
  value.spec.traffic = [{ latestRevision: true, percent: 100 }];
  value.status.traffic = [{ latestRevision: true, percent: 100, revisionName: "cdbentley-preview-bootstrap" }];
  return value;
}

function bootstrapRevision(): any {
  const value = revision(
    "cdbentley-preview-bootstrap",
    "cdbentley-preview",
    "preview",
    "us-docker.pkg.dev/cloudrun/container/hello",
  );
  value.spec.containers[0].image =
    "us-docker.pkg.dev/cloudrun/container/hello@sha256:9a0e9a5c7a19281e7617991d2fc61809de4973e6e75a10b2f07df3719ffda33c";
  value.status.imageDigest = value.spec.containers[0].image;
  value.spec.containers[0].env = [{ name: "PLATFORM_DEPLOY_ENVIRONMENT", value: "preview" }];
  delete value.metadata.labels["dhi-parity-id"];
  delete value.metadata.labels["git-head-sha"];
  delete value.metadata.labels["managed-by"];
  delete value.metadata.labels["platform-workflow-sha"];
  return value;
}

function revision(name: string, service: string, environment: string, image: string): any {
  return {
    apiVersion: "serving.knative.dev/v1",
    kind: "Revision",
    metadata: {
      generation: 1,
      labels: {
        "dhi-parity-id": parityId,
        environment,
        "git-head-sha": headSha,
        "github-repository-id": repositoryId,
        "managed-by": "github-actions",
        "platform-workflow-sha": workflowSha,
        "serving.knative.dev/service": service,
      },
      name,
      namespace: projectNumber,
    },
    spec: {
      containers: [{
        env: [
          { name: "PLATFORM_IMAGE_INDEX_DIGEST", value: indexDigest },
          { name: "PLATFORM_IMAGE_RUNNABLE_DIGEST", value: runnableDigest },
        ],
        image: `${image}@${runnableDigest}`,
      }],
      serviceAccountName: environment === "production"
        ? "cloud-run-runtime@cdbentley.iam.gserviceaccount.com"
        : previewRuntime,
    },
    status: {
      conditions: [
        { status: "True", type: "Ready" },
        { status: "True", type: "ContainerHealthy" },
      ],
      imageDigest: `${image}@${runnableDigest}`,
      observedGeneration: 1,
    },
  };
}

async function runCloudContract(
  command: "prove-production" | "inspect-preview-routes" | "prove-preview-routes" | "prove-preview-tags",
  fixture: { service: any; revisions: any[] },
): Promise<{ exitCode: number; stderr: string; outputs: Record<string, string> }> {
  const root = await mkdtemp(join(tmpdir(), "platform-dhi-parity-"));
  temporaryRoots.push(root);
  const servicePath = join(root, "service.json");
  const revisionDir = join(root, "revisions");
  const output = join(root, "github-output");
  await mkdir(revisionDir);
  await writeFile(servicePath, JSON.stringify(fixture.service));
  for (const revisionFixture of fixture.revisions) {
    await writeFile(join(revisionDir, `${revisionFixture.metadata.name}.json`), JSON.stringify(revisionFixture));
  }
  const productionRevisionFixture = fixture.revisions[0];
  const child = Bun.spawn(["/bin/bash", cloudHelper, command], {
    cwd: repoRoot,
    env: {
      ...process.env,
      EXPECTED_PREVIEW_IMAGE_NAME: previewImage,
      EXPECTED_PREVIEW_SERVICE_NAME: "cdbentley-preview",
      EXPECTED_PREVIEW_RUNTIME_SERVICE_ACCOUNT: previewRuntime,
      EXPECTED_PLATFORM_WORKFLOW_SHA: workflowSha,
      EXPECTED_PRODUCTION_IMAGE_NAME: productionImage,
      EXPECTED_BASELINE_PRODUCTION_HEAD_SHA: headSha,
      EXPECTED_BASELINE_PRODUCTION_INDEX_IMAGE: `${productionImage}@${indexDigest}`,
      EXPECTED_BASELINE_PRODUCTION_RUNNABLE_IMAGE: `${productionImage}@${runnableDigest}`,
      EXPECTED_PROJECT_NUMBER: projectNumber,
      EXPECTED_REPOSITORY_ID: repositoryId,
      EXPECTED_SERVICE_NAME: "cdbentley",
      GITHUB_OUTPUT: output,
      PARITY_REVISION_DIR: revisionDir,
      PARITY_REVISION_JSON: productionRevisionFixture
        ? join(revisionDir, `${productionRevisionFixture.metadata.name}.json`)
        : "",
      PARITY_SERVICE_JSON: servicePath,
      RUNNER_TEMP: root,
    },
    stderr: "pipe",
    stdout: "ignore",
  });
  const [exitCode, stderr] = await Promise.all([
    child.exited,
    new Response(child.stderr).text(),
  ]);
  const outputText = await readFile(output, "utf8").catch(() => "");
  const outputs = Object.fromEntries(
    outputText.trim().split("\n").filter(Boolean).map((line) => {
      const separator = line.indexOf("=");
      return [line.slice(0, separator), line.slice(separator + 1)];
    }),
  );
  return { exitCode, stderr, outputs };
}
