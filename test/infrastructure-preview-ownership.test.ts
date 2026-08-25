import { describe, expect, test } from "bun:test";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "..");

describe("preview exposure controller ownership", () => {
  const loadWorkflow = async () => {
    const source = await readFile(
      resolve(repoRoot, ".github/workflows/infrastructure.yml"),
      "utf8",
    );
    return Bun.YAML.parse(source) as {
      jobs: Record<
        string,
        { concurrency?: Record<string, unknown>; steps?: Array<Record<string, any>> }
      >;
    };
  };

  test("Terraform convergence shares the deployment lock and audits live exposure", async () => {
    const workflow = await loadWorkflow();
    expect(workflow.jobs["terraform-convergence"]!.concurrency).toEqual({
      group: "deployment-parity-${{ github.event.repository.id }}",
      queue: "max",
      "cancel-in-progress": false,
    });
    const step = workflow.jobs["terraform-convergence"]!.steps!.find(
      (candidate) => candidate.name === "Require coherent controller-owned preview exposure",
    );
    expect(step).toBeDefined();
    const run = String(step!.run);
    for (const boundary of [
      "INGRESS_TRAFFIC_INTERNAL_ONLY",
      "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER",
      "INGRESS_TRAFFIC_ALL",
      "invokerIamDisabled",
      "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION",
      "run.googleapis.com/base-images",
      "run.googleapis.com/build-base-image",
      "run.googleapis.com/build-enable-automatic-updates",
      "run.googleapis.com/enable-automatic-updates",
      "run.googleapis.com/linux-base-image-update",
      "buildConfig",
      "baseImageUri",
      "template.containers // []",
      "generation == .observedGeneration",
      'terminalCondition.state == "CONDITION_SUCCEEDED"',
      "exact_public_terraform_bootstrap",
      "9a0e9a5c7a19281e7617991d2fc61809de4973e6e75a10b2f07df3719ffda33c",
      '"managed-by":"terraform"',
    ]) {
      expect(run).toContain(boundary);
    }
  });

  test("the live exposure audit accepts only coherent sealed or explicit admitted graphs", async () => {
    const workflow = await loadWorkflow();
    const step = workflow.jobs["terraform-convergence"]!.steps!.find(
      (candidate) => candidate.name === "Require coherent controller-owned preview exposure",
    );
    const script = String(step!.run);
    const root = await mkdtemp(join(tmpdir(), "platform-preview-exposure-"));
    try {
      const mockBin = join(root, "bin");
      await mkdir(mockBin);
      const curl = join(mockBin, "curl");
      await writeFile(
        curl,
        `#!/bin/bash
set -euo pipefail
destination=
while [ "$#" -gt 0 ]; do
  if [ "$1" = --output ]; then
    destination="$2"
    shift 2
  else
    shift
  fi
done
test -n "$destination"
cp -- "$FIXTURE_SERVICE_JSON" "$destination"
`,
        { mode: 0o700 },
      );
      await chmod(curl, 0o700);
      const base = {
        name: "projects/cdbentley/locations/us-east4/services/cdbentley-preview",
        etag: '"opaque-etag"',
        generation: "7",
        observedGeneration: "7",
        reconciling: false,
        terminalCondition: { type: "Ready", state: "CONDITION_SUCCEEDED" },
        defaultUriDisabled: false,
        ingress: "INGRESS_TRAFFIC_INTERNAL_ONLY",
        invokerIamDisabled: false,
        template: { containers: [{ image: "example.invalid/image@sha256:abc" }] },
        traffic: [{ type: "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST", percent: 100 }],
      };
      const validOpen = {
        ...base,
        ingress: "INGRESS_TRAFFIC_ALL",
        invokerIamDisabled: true,
        traffic: [
          {
            type: "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION",
            revision: "prod-baseline-a",
            percent: 100,
          },
          {
            type: "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION",
            revision: "preview-pr-31-a",
            percent: 0,
            tag: "pr-31",
          },
        ],
      };
      const publicTerraformBootstrap = {
        ...base,
        labels: {
          app: "cdbentley",
          environment: "preview",
          "goog-terraform-provisioned": "true",
          "managed-by": "terraform",
        },
        ingress: "INGRESS_TRAFFIC_ALL",
        invokerIamDisabled: true,
        traffic: [{ type: "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST", percent: 100 }],
        trafficStatuses: [{ type: "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST", percent: 100 }],
        latestReadyRevision:
          "projects/cdbentley/locations/us-east4/services/cdbentley-preview/revisions/cdbentley-preview-00001-abc",
        template: {
          scaling: { maxInstanceCount: 2 },
          timeout: "300s",
          serviceAccount: "cloud-run-preview@cdbentley.iam.gserviceaccount.com",
          containers: [{
            name: "site",
            image:
              "us-docker.pkg.dev/cloudrun/container/hello@sha256:9a0e9a5c7a19281e7617991d2fc61809de4973e6e75a10b2f07df3719ffda33c",
            env: [{ name: "PLATFORM_DEPLOY_ENVIRONMENT", value: "preview" }],
            resources: {
              limits: { cpu: "1", memory: "512Mi" },
              cpuIdle: true,
              startupCpuBoost: true,
            },
            ports: [{ name: "http1", containerPort: 8080 }],
            startupProbe: {
              timeoutSeconds: 240,
              periodSeconds: 240,
              failureThreshold: 1,
              tcpSocket: { port: 8080 },
            },
          }],
          maxInstanceRequestConcurrency: 80,
        },
      };
      const cases = [
        ["sealed bootstrap", base, true],
        ["exact public Terraform bootstrap", publicTerraformBootstrap, true],
        [
          "public bootstrap wrong image",
          {
            ...publicTerraformBootstrap,
            template: {
              ...publicTerraformBootstrap.template,
              containers: [{
                ...publicTerraformBootstrap.template.containers[0],
                image: "us-docker.pkg.dev/cloudrun/container/hello@sha256:" + "0".repeat(64),
              }],
            },
          },
          false,
        ],
        [
          "public bootstrap extra environment",
          {
            ...publicTerraformBootstrap,
            template: {
              ...publicTerraformBootstrap.template,
              containers: [{
                ...publicTerraformBootstrap.template.containers[0],
                env: [
                  ...publicTerraformBootstrap.template.containers[0].env,
                  { name: "FOREIGN", value: "1" },
                ],
              }],
            },
          },
          false,
        ],
        [
          "public bootstrap controller label",
          {
            ...publicTerraformBootstrap,
            labels: { ...publicTerraformBootstrap.labels, "managed-by": "github-actions" },
          },
          false,
        ],
        ["admitted graph", validOpen, true],
        [
          "automatic base URI",
          { ...validOpen, template: { containers: [{ baseImageUri: "dhi.io/bun:1" }] } },
          false,
        ],
        ["tagged but sealed", { ...validOpen, ingress: base.ingress }, false],
        [
          "raw latest tagged route",
          {
            ...validOpen,
            traffic: [validOpen.traffic[0], { type: "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST", percent: 0, tag: "pr-31" }],
          },
          false,
        ],
        [
          "automatic runtime class",
          {
            ...validOpen,
            template: {
              runtimeClassName: "run.googleapis.com/linux-base-image-update",
              containers: validOpen.template.containers,
            },
          },
          false,
        ],
        ["automatic build config", { ...validOpen, buildConfig: { baseImage: "bun" } }, false],
      ] as const;
      for (const [name, fixture, shouldPass] of cases) {
        const fixturePath = join(root, `${name.replaceAll(" ", "-")}.json`);
        await writeFile(fixturePath, JSON.stringify(fixture));
        const result = Bun.spawnSync(["/bin/bash", "--noprofile", "--norc", "-c", script], {
          cwd: repoRoot,
          env: {
            ...process.env,
            ACCESS_TOKEN: "test-token",
            EXPECTED_OPEN_INGRESS: "INGRESS_TRAFFIC_ALL",
            FIXTURE_SERVICE_JSON: fixturePath,
            PATH: `${mockBin}:${process.env.PATH ?? ""}`,
            PREVIEW_SERVICE: "cdbentley-preview",
            PROJECT_ID: "cdbentley",
            RUNNER_TEMP: root,
          },
          stderr: "pipe",
          stdout: "pipe",
        });
        expect(result.exitCode, name).toBe(shouldPass ? 0 : 1);
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("Terraform ignores only the preview exposure fields owned by the controller", async () => {
    const source = await readFile(
      resolve(repoRoot, "terraform/modules/cloud-run-service/main.tf"),
      "utf8",
    );
    const preview = source.slice(
      source.indexOf('resource "google_cloud_run_v2_service" "preview"'),
      source.indexOf('resource "google_cloud_run_v2_service_iam_member" "preview_deploy"'),
    );
    expect(preview).toContain("ingress,");
    expect(preview).toContain("invoker_iam_disabled,");
    expect(preview).toContain("traffic,");
    expect(preview).not.toContain("ignore_changes = all");
  });
});
