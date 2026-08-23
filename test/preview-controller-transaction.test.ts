import { afterEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "..");
const helper = join(repoRoot, "tools/ci/cloud-run-preview-controller.sh");
const mockCli = join(repoRoot, "test/fixtures/preview-controller-mock-cli.ts");
const parityId = "1a4cho1elzg84pavos8mbanvvpmkieiht7kyhpjdofzpivf3k8";
const workflowSha = "1".repeat(40);
const productionHead = "2".repeat(40);
const head31 = "3".repeat(40);
const head44 = "4".repeat(40);
const projectId = "cdbentley";
const projectNumber = "882468538648";
const region = "us-east4";
const productionService = "cdbentley";
const previewService = "cdbentley-preview";
const productionImage = "us-east4-docker.pkg.dev/cdbentley/site/cdbentley";
const previewImage = "us-east4-docker.pkg.dev/cdbentley/site-preview/cdbentley";
const runtimeServiceAccount = "cloud-run-preview@cdbentley.iam.gserviceaccount.com";
const productionRevision = "cdbentley-production-current";
const baselineRevision = "cdbentley-preview-baseline";
const revision31 = "cdbentley-preview-pr31";
const revision44 = "cdbentley-preview-pr44";
const temporaryRoots: string[] = [];

const exactPreviewIamBindings = [
  {
    members: ["serviceAccount:gha-preview-deploy@cdbentley.iam.gserviceaccount.com"],
    role: "projects/cdbentley/roles/cloudRunRevisionDeployer",
  },
  {
    members: ["serviceAccount:gha-deploy-parity@cdbentley.iam.gserviceaccount.com"],
    role: "projects/cdbentley/roles/deploymentParityCloudRunReader",
  },
  {
    members: ["serviceAccount:gha-preview-commit@cdbentley.iam.gserviceaccount.com"],
    role: "projects/cdbentley/roles/previewTrafficCommitter",
  },
];

setDefaultTimeout(30_000);

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("shared preview controller transaction", () => {
  test("maintenance workflows seal with the committer when evidence collection fails", async () => {
    const contracts = [
      ["cleanup-preview.yml", "cleanup"],
      ["reconcile-previews.yml", "reconcile"],
      ["deploy-preview.yml", "invalidate"],
    ] as const;
    for (const [workflowName, jobName] of contracts) {
      const workflow = Bun.YAML.parse(
        await readFile(join(repoRoot, ".github/workflows", workflowName), "utf8"),
      ) as { jobs: Record<string, any> };
      const job = workflow.jobs[jobName];
      expect(job.if).toContain("always()");
      expect(job.if).not.toContain("needs.prefetch-bases.result == 'success'");
      const commit = job.steps.find((step: any) => step.id === "commit-auth");
      expect(commit.with.token_format).toBe("access_token");
      expect(commit.if ?? "").not.toContain("iam-audit.outputs.admitted");
      const maintenance = job.steps.find((step: any) => step.id === "maintenance");
      expect(maintenance["continue-on-error"]).toBe(true);
      expect(maintenance.env.DHI_PARITY_ID).toBe("${{ steps.parity-policy.outputs.dhi-parity-id }}");
      expect(maintenance.env.EXPECTED_PLATFORM_WORKFLOW_SHA).toBe("${{ job.workflow_sha }}");
      const policy = job.steps.find((step: any) => step.id === "parity-policy");
      expect(policy.run).toContain("tools/ci/deployment-parity-transition.sh");
      expect(policy.run).toContain("print-dhi-parity-id");
      const seal = job.steps.find((step: any) => step.id === "fail-closed-seal");
      expect(seal.if).toContain("needs.prefetch-bases.result != 'success'");
      expect(seal.if).toContain("steps.iam-audit.outputs.admitted != 'true'");
      expect(seal.if).toContain("steps.maintenance.outcome == 'failure'");
      expect(seal.run).toContain('cloud-run-preview-controller.sh" seal');
      expect(seal.env.ACCESS_TOKEN).toBe("${{ steps.commit-auth.outputs.access_token }}");
      expect(seal.env.DHI_PARITY_ID).toBe("${{ steps.parity-policy.outputs.dhi-parity-id }}");
      expect(seal.env.EXPECTED_PLATFORM_WORKFLOW_SHA).toBe("${{ job.workflow_sha }}");
      expect(seal.env.REPOSITORY_ID).toBe("${{ github.event.repository.id }}");
    }

    const preview = Bun.YAML.parse(
      await readFile(join(repoRoot, ".github/workflows/deploy-preview.yml"), "utf8"),
    ) as { jobs: Record<string, any> };
    const deploy = preview.jobs.deploy;
    expect(deploy.steps.find((step: any) => step.id === "traffic-commit")["continue-on-error"]).toBe(true);
    const deploySeal = deploy.steps.find((step: any) => step.id === "fail-closed-seal");
    expect(deploySeal.if).toContain("steps.post-parity.outcome != 'success'");
    expect(deploySeal.if).toContain("steps.traffic-commit.outcome == 'failure'");
  });

  test("reconcile keeps an OPEN fully proven survivor graph without mutation", async () => {
    const result = await runController({ exposure: "open", mode: "reconcile", tags: ["31", "44"] });
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.state.exposure).toBe("open");
    expect(routeTags(result.state)).toEqual(["baseline", "pr-31", "pr-44"]);
    expect(result.log).not.toContain("patch-attempt");
    expect(result.output).toContain("admitted=true");
    expect(result.output).toContain("removed-count=0");
    expect(result.log).toContain("health-pr-31");
    expect(result.log).toContain("health-pr-44");
  });

  test("reconcile reopens a fully proven SEALED survivor graph", async () => {
    const result = await runController({ exposure: "sealed", mode: "reconcile", tags: ["31", "44"] });
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.state.exposure).toBe("open");
    expect(routeTags(result.state)).toEqual(["baseline", "pr-31", "pr-44"]);
    expect(patchCommits(result.log)).toEqual([
      "patch-commit mask=ingress,invokerIamDisabled exposure=open tags=baseline,pr-31,pr-44",
    ]);
  });

  test("remove deletes exactly one tag with one etag PATCH and preserves its sibling", async () => {
    const result = await runController({ exposure: "open", mode: "remove", tags: ["31", "44"] });
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.state.exposure).toBe("open");
    expect(routeTags(result.state)).toEqual(["baseline", "pr-44"]);
    expect(patchCommits(result.log)).toEqual([
      "patch-commit mask=traffic,ingress,invokerIamDisabled exposure=sealed tags=baseline,pr-44",
      "patch-commit mask=ingress,invokerIamDisabled exposure=open tags=baseline,pr-44",
    ]);
    expect(result.log).toContain("health-pr-44");
    expect(result.log).toContain("removed-pr-31");
    expect(result.output).toContain("removed-count=1");
  });

  test("remove of the last tag changes traffic and seals exposure atomically", async () => {
    const result = await runController({ exposure: "open", mode: "remove", tags: ["31"] });
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.state.exposure).toBe("sealed");
    expect(routeTags(result.state)).toEqual(["baseline"]);
    expect(patchCommits(result.log)).toEqual([
      "patch-commit mask=traffic,ingress,invokerIamDisabled exposure=sealed tags=baseline",
    ]);
    expect(result.log).toContain("removed-pr-31");
  });

  test("platform repin retires predecessor and missing-workflow routes while SEALED", async () => {
    const result = await runController({
      baselineWorkflow: "predecessor",
      exposure: "open",
      mode: "reconcile",
      routeWorkflow: { "31": "predecessor", "44": "missing" },
      tags: ["31", "44"],
    });
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.state.exposure).toBe("sealed");
    expect(routeTags(result.state)).toEqual(["baseline"]);
    expect(patchCommits(result.log)).toEqual([
      "patch-commit mask=traffic,ingress,invokerIamDisabled exposure=sealed tags=baseline",
    ]);
    expect(result.log).not.toContain("lifecycle-31");
    expect(result.log).not.toContain("lifecycle-44");
    expect(result.output).toContain("removed-count=2");
    expect(result.state.transitionMetadata.state).toBe("clear");
  });

  test("malformed immutable head metadata is retired before lifecycle lookup", async () => {
    const result = await runController({
      exposure: "open",
      malformedHeadTags: ["31"],
      mode: "reconcile",
      tags: ["31", "44"],
    });
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.state.exposure).toBe("open");
    expect(routeTags(result.state)).toEqual(["baseline", "pr-44"]);
    expect(result.log).not.toContain("lifecycle-31");
    expect(result.log).toContain("lifecycle-44");
  });

  test("a read failure before proof or mutation preserves the admitted state", async () => {
    const result = await runController({
      exposure: "open",
      initialReadFailure: true,
      mode: "reconcile",
      tags: ["31", "44"],
    });
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("mock transient preview read failure");
    expect(result.state.exposure).toBe("open");
    expect(routeTags(result.state)).toEqual(["baseline", "pr-31", "pr-44"]);
    expect(result.log).not.toContain("patch-attempt");
  });

  test("a PATCH conflict preserves the complete prior graph", async () => {
    const result = await runController({
      exposure: "open",
      mode: "remove",
      patchConflict: true,
      tags: ["31", "44"],
    });
    expect(result.exitCode).not.toBe(0);
    expect(result.state.exposure).toBe("open");
    expect(routeTags(result.state)).toEqual(["baseline", "pr-31", "pr-44"]);
    expect(result.log).toContain('patch-attempt mask=traffic,ingress,invokerIamDisabled etag="\\\"controller-etag-1\\\""');
    expect(result.log).toContain("patch-conflict");
    expect(result.log).not.toContain("patch-commit");
  });

  test("a post-mutation proof failure seals with the newly current exact etag", async () => {
    const result = await runController({
      exposure: "sealed",
      failPostMutationProof: true,
      mode: "reconcile",
      tags: ["31"],
    });
    expect(result.exitCode).not.toBe(0);
    expect(result.state.exposure).toBe("sealed");
    expect(routeTags(result.state)).toEqual(["baseline", "pr-31"]);
    expect(patchCommits(result.log)).toEqual([
      "patch-commit mask=ingress,invokerIamDisabled exposure=open tags=baseline,pr-31",
      "patch-commit mask=ingress,invokerIamDisabled exposure=sealed tags=baseline,pr-31",
    ]);
    expect(result.log).toContain('patch-attempt mask=ingress,invokerIamDisabled etag="\\\"controller-etag-1\\\""');
    expect(result.log).toContain('patch-attempt mask=ingress,invokerIamDisabled etag="\\\"controller-etag-2\\\""');
    expect(result.stderr).toContain("attempting a known SEALED recovery while retaining the durable poison");
  });

  test("an accepted PATCH followed by transport loss retains poison and performs no inference", async () => {
    const result = await runController({
      exposure: "open",
      mode: "remove",
      patchTransportLoss: true,
      tags: ["31", "44"],
    });
    expect(result.exitCode).not.toBe(0);
    expect(result.log).toContain("patch-transport-loss");
    expect(result.state.exposure).toBe("open");
    expect(routeTags(result.state)).toEqual(["baseline", "pr-31", "pr-44"]);
    expect(result.state.transitionMetadata.state).toBe("preview-maintenance");
    expect(result.log).not.toContain("patch-commit");
    expect(result.stderr).toContain("retaining the durable parity poison");
  });

  test("evidence failure seals an OPEN service with a two-write etag fence and no traffic drift", async () => {
    const result = await runController({ exposure: "open", mode: "seal", tags: ["31", "44"] });
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.state.exposure).toBe("sealed");
    expect(routeTags(result.state)).toEqual(["baseline", "pr-31", "pr-44"]);
    expect(patchCommits(result.log)).toEqual([
      "patch-commit mask=labels,ingress,invokerIamDisabled exposure=sealed tags=baseline,pr-31,pr-44",
      "patch-commit mask=labels,ingress,invokerIamDisabled exposure=sealed tags=baseline,pr-31,pr-44",
    ]);
    expect(result.output).toContain("admitted=true");
    expect(result.output).toContain("exposure=sealed");
  });

  test("evidence failure leaves an already SEALED service and its traffic untouched", async () => {
    const result = await runController({ exposure: "sealed", mode: "seal", tags: ["31"] });
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.state.exposure).toBe("sealed");
    expect(routeTags(result.state)).toEqual(["baseline", "pr-31"]);
    expect(patchCommits(result.log)).toEqual([
      "patch-commit mask=labels,ingress,invokerIamDisabled exposure=sealed tags=baseline,pr-31",
      "patch-commit mask=labels,ingress,invokerIamDisabled exposure=sealed tags=baseline,pr-31",
    ]);
    expect(result.state.transitionMetadata.state).toBe("clear");
  });

  test("either fence leg retaining the prior service etag retains poison", async () => {
    for (const patchDoesNotAdvanceEtagOnAttempt of [1, 2]) {
      const result = await runController({
        exposure: "sealed",
        mode: "seal",
        patchDoesNotAdvanceEtagOnAttempt,
        tags: ["31"],
        transitionState: "preview-emergency-seal",
      });
      expect(result.exitCode).not.toBe(0);
      expect(result.state.exposure).toBe("sealed");
      expect(routeTags(result.state)).toEqual(["baseline", "pr-31"]);
      expect(result.state.transitionMetadata.state).toBe("preview-emergency-seal");
      expect(result.log).not.toContain("transition-clear");
    }
  });

  test("seal recovery replaces a stale fence, preserves every other label, and removes its fence", async () => {
    const labels = {
      environment: "preview",
      owner: "platform",
      "platform-preview-seal-fence": "stale-fence-value",
    };
    const result = await runController({
      exposure: "sealed",
      initialLabels: labels,
      mode: "seal",
      tags: ["31"],
      transitionState: "preview-emergency-seal",
    });
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.state.labels).toEqual({ environment: "preview", owner: "platform" });
    expect(result.state.labels).not.toHaveProperty("platform-preview-seal-fence");
    expect(result.state.transitionMetadata.state).toBe("clear");
  });

  test("the same active workflow and DHI recover every preview poison only through a fresh seal", async () => {
    for (const transitionState of [
      "preview-admission",
      "preview-maintenance",
      "preview-emergency-seal",
    ] as const) {
      const result = await runController({
        exposure: "open",
        mode: "seal",
        tags: ["31", "44"],
        transitionState,
      });
      expect(result.exitCode, `${transitionState}: ${result.stderr}`).toBe(0);
      expect(result.state.exposure).toBe("sealed");
      expect(routeTags(result.state)).toEqual(["baseline", "pr-31", "pr-44"]);
      expect(result.log).toContain("transition-preview-emergency-seal");
      expect(result.state.transitionMetadata.state).toBe("clear");
      expect(patchCommits(result.log)).toEqual([
        "patch-commit mask=labels,ingress,invokerIamDisabled exposure=sealed tags=baseline,pr-31,pr-44",
        "patch-commit mask=labels,ingress,invokerIamDisabled exposure=sealed tags=baseline,pr-31,pr-44",
      ]);
    }
  });

  test("seal recovery retries one definitive etag conflict without changing traffic", async () => {
    const result = await runController({
      exposure: "open",
      mode: "seal",
      patchConflictsRemaining: 1,
      tags: ["31", "44"],
      transitionState: "preview-maintenance",
    });
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.state.exposure).toBe("sealed");
    expect(routeTags(result.state)).toEqual(["baseline", "pr-31", "pr-44"]);
    expect(result.log).toContain("patch-conflict-once");
    expect(result.log.match(/patch-attempt/g)).toHaveLength(3);
    expect(result.state.transitionMetadata.state).toBe("clear");
  });

  test("a lost response on either fence leg retains poison and never infers recovery", async () => {
    for (const patchTransportLossOnAttempt of [1, 2]) {
      const result = await runController({
        exposure: "open",
        mode: "seal",
        patchTransportLossOnAttempt,
        tags: ["31"],
        transitionState: "preview-emergency-seal",
      });
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("outcome is ambiguous; durable poison retained");
      expect(routeTags(result.state)).toEqual(["baseline", "pr-31"]);
      expect(result.state.transitionMetadata.state).toBe("preview-emergency-seal");
      expect(result.log).toContain("patch-transport-loss");
      expect(result.log).not.toContain("transition-clear");
    }
  });

  test("an absent preview service clears only an exact matching preview poison", async () => {
    const clear = await runController({
      exposure: "sealed",
      mode: "seal",
      previewServiceAbsent: true,
      tags: [],
    });
    expect(clear.exitCode, clear.stderr).toBe(0);
    expect(clear.output).toContain("exposure=absent");
    expect(clear.state.transitionMetadata.state).toBe("clear");
    expect(clear.log).not.toContain("patch-attempt");

    const matching = await runController({
      exposure: "sealed",
      mode: "seal",
      previewServiceAbsent: true,
      tags: [],
      transitionState: "preview-admission",
    });
    expect(matching.exitCode, matching.stderr).toBe(0);
    expect(matching.state.transitionMetadata.state).toBe("clear");
    expect(matching.log).toContain("transition-preview-emergency-seal");
    expect(matching.log).not.toContain("patch-attempt");

    const unrelated = await runController({
      exposure: "sealed",
      mode: "seal",
      previewServiceAbsent: true,
      tags: [],
      transitionState: "prod-dhi-transition",
    });
    expect(unrelated.exitCode).not.toBe(0);
    expect(unrelated.state.transitionMetadata.state).toBe("prod-dhi-transition");
    expect(unrelated.log).not.toContain("patch-attempt");
  });

  test("fail-closed sealing converges hostile named, public, principal-set, and custom-role grants to the exact IaC policy", async () => {
    const result = await runController({ exposure: "open", mode: "seal", publicInvoker: true, tags: ["31"] });
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.state.exposure).toBe("sealed");
    expect(result.log).toContain("iam-policy-sanitize");
    expect(result.state.iamBindings).toEqual(exactPreviewIamBindings);
  });

  test("reconcile repairs legacy IAM under the marker and re-admits a fully proven survivor graph", async () => {
    const result = await runController({ exposure: "open", mode: "reconcile", publicInvoker: true, tags: ["31", "44"] });
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.state.exposure).toBe("open");
    expect(routeTags(result.state)).toEqual(["baseline", "pr-31", "pr-44"]);
    expect(result.state.iamBindings).toEqual(exactPreviewIamBindings);
    expect(result.log).toContain("iam-policy-sanitize");
    expect(result.state.transitionMetadata.state).toBe("clear");
  });

  test("a lost setIamPolicy response releases only after authoritative exact-policy readback", async () => {
    const result = await runController({
      exposure: "open",
      iamSetTransportLoss: true,
      mode: "reconcile",
      publicInvoker: true,
      tags: ["31"],
    });
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.state.iamBindings).toEqual(exactPreviewIamBindings);
    expect(result.log).toContain("iam-policy-sanitize-response-lost");
    expect(result.state.transitionMetadata.state).toBe("clear");
  });
});

type RunOptions = {
  baselineWorkflow?: "current" | "predecessor";
  exposure: "open" | "sealed";
  failPostMutationProof?: boolean;
  initialLabels?: Record<string, string>;
  initialReadFailure?: boolean;
  iamSetTransportLoss?: boolean;
  mode: "reconcile" | "remove" | "seal";
  patchConflict?: boolean;
  patchConflictsRemaining?: number;
  patchDoesNotAdvanceEtagOnAttempt?: number;
  patchTransportLoss?: boolean;
  patchTransportLossOnAttempt?: number;
  previewServiceAbsent?: boolean;
  publicInvoker?: boolean;
  malformedHeadTags?: Array<"31" | "44">;
  routeWorkflow?: Partial<Record<"31" | "44", "current" | "missing" | "predecessor">>;
  tags: Array<"31" | "44">;
  transitionParity?: "current" | "different";
  transitionState?:
    | "clear"
    | "preview-admission"
    | "preview-maintenance"
    | "preview-emergency-seal"
    | "prod-dhi-transition";
  transitionWorkflow?: "current" | "predecessor";
};

async function runController(options: RunOptions): Promise<{
  exitCode: number;
  log: string;
  output: string;
  state: any;
  stderr: string;
}> {
  const root = await mkdtemp(join(tmpdir(), "platform-preview-controller-"));
  temporaryRoots.push(root);
  const bin = join(root, "bin");
  const policy = join(root, "policy/tools/ci");
  const statePath = join(root, "state.json");
  const logPath = join(root, "events.log");
  const outputPath = join(root, "github-output");
  await mkdir(bin, { recursive: true });
  await mkdir(policy, { recursive: true });
  await writeFile(logPath, "");
  await writeFile(outputPath, "");

  const wrapper = (command: string) => [
    "#!/bin/sh",
    "set -eu",
    `MOCK_COMMAND=${command} exec bun "$MOCK_CLI" "$@"`,
    "",
  ].join("\n");
  for (const command of ["curl", "gcloud", "gh"]) {
    const path = join(bin, command);
    await writeFile(path, wrapper(command));
    await chmod(path, 0o755);
  }
  const sleep = join(bin, "sleep");
  await writeFile(sleep, "#!/bin/sh\nexit 0\n");
  await chmod(sleep, 0o755);

  const parityPolicy = join(policy, "cloud-run-dhi-parity.sh");
  await writeFile(parityPolicy, [
    "#!/bin/bash",
    "set -euo pipefail",
    "case \"$1\" in",
    "  prove-production)",
    "    test -s \"$PARITY_SERVICE_JSON\" && test -s \"$PARITY_REVISION_JSON\"",
    "    if [ \"${MOCK_FAIL_POST_MUTATION:-0}\" = 1 ] && [ \"$(jq -r .etag \"$MOCK_STATE\")\" -gt 1 ]; then",
    "      echo post-mutation-production-proof-failure >> \"$MOCK_LOG\"",
    "      exit 41",
    "    fi",
    "    echo production-proof >> \"$MOCK_LOG\"",
    `    echo live_production_head_sha=${productionHead} >> "$GITHUB_OUTPUT"`,
    `    echo live_production_index_image=${productionImage}@sha256:${"a".repeat(64)} >> "$GITHUB_OUTPUT"`,
    `    echo live_production_runnable_image=${productionImage}@sha256:${"b".repeat(64)} >> "$GITHUB_OUTPUT"`,
    "    ;;",
    "  inspect-preview-routes)",
    "    jq -e '([.status.traffic[]? | select((.tag // \"\") == \"\" and .percent == 100)] | length) == 1' \"$PARITY_SERVICE_JSON\" >/dev/null",
    "    while IFS= read -r revision; do test -s \"$PARITY_REVISION_DIR/$revision.json\"; done < <(jq -r '.status.traffic[].revisionName' \"$PARITY_SERVICE_JSON\")",
    "    echo preview-proof >> \"$MOCK_LOG\"",
    "    candidate=true",
    "    while IFS= read -r revision; do",
    "      jq -e --arg workflow \"$EXPECTED_PLATFORM_WORKFLOW_SHA\" --arg parity \"$DHI_PARITY_ID\" '.metadata.labels[\"platform-workflow-sha\"] == $workflow and .metadata.labels[\"dhi-parity-id\"] == $parity' \"$PARITY_REVISION_DIR/$revision.json\" >/dev/null || candidate=false",
    "    done < <(jq -r '.status.traffic[].revisionName' \"$PARITY_SERVICE_JSON\")",
    "    tags=$(jq -r '[.status.traffic[]? | select(has(\"tag\"))] | length' \"$PARITY_SERVICE_JSON\")",
    "    ingress=$(jq -r '.metadata.annotations[\"run.googleapis.com/ingress\"]' \"$PARITY_SERVICE_JSON\")",
    "    invoker=$(jq -r '.metadata.annotations[\"run.googleapis.com/invoker-iam-disabled\"] // \"false\"' \"$PARITY_SERVICE_JSON\")",
    "    sealed=false; if [ \"$tags\" = 0 ] && [ \"$ingress\" = internal ] && [ \"$invoker\" = false ]; then sealed=true; fi",
    "    echo all_routes_candidate_parity=$candidate >> \"$GITHUB_OUTPUT\"",
    "    echo sealed_baseline=$sealed >> \"$GITHUB_OUTPUT\"",
    `    echo dhi_parity_id=${parityId} >> "$GITHUB_OUTPUT"`,
    "    ;;",
    "  *) exit 97 ;;",
    "esac",
    "",
  ].join("\n"));
  await chmod(parityPolicy, 0o755);

  const graphPolicy = join(policy, "container-artifact-contract.sh");
  await writeFile(graphPolicy, [
    "#!/bin/bash",
    "set -euo pipefail",
    "test \"$1\" = verify-live-images",
    "jq -e 'length >= 1 and all(.[]; (.index | test(\"@sha256:[0-9a-f]{64}$\")) and (.runnable | test(\"@sha256:[0-9a-f]{64}$\")))' \"$LIVE_IMAGE_SET_FILE\" >/dev/null",
    "echo graph-proof >> \"$MOCK_LOG\"",
    `echo dhi_parity_id=${parityId} >> "$GITHUB_OUTPUT"`,
    "",
  ].join("\n"));
  await chmod(graphPolicy, 0o755);
  const transitionPolicy = join(policy, "deployment-parity-transition.sh");
  await writeFile(transitionPolicy, await readFile(join(repoRoot, "tools/ci/deployment-parity-transition.sh")));
  await chmod(transitionPolicy, 0o755);

  const revisions = {
    [baselineRevision]: revision(baselineRevision, "baseline", productionHead, undefined, "c"),
    [revision31]: revision(revision31, "pr", head31, "31", "d"),
    [revision44]: revision(revision44, "pr", head44, "44", "e"),
  };
  if (options.baselineWorkflow === "predecessor") {
    setRevisionLabel(revisions[baselineRevision], "platform-workflow-sha", "9".repeat(40));
  }
  for (const tag of ["31", "44"] as const) {
    const fixture = revisions[tag === "31" ? revision31 : revision44];
    const workflow = options.routeWorkflow?.[tag];
    if (workflow === "predecessor") {
      setRevisionLabel(fixture, "platform-workflow-sha", "9".repeat(40));
    } else if (workflow === "missing") {
      setRevisionLabel(fixture, "platform-workflow-sha", undefined);
    }
    if (options.malformedHeadTags?.includes(tag)) {
      setRevisionLabel(fixture, "git-head-sha", "malformed");
    }
  }
  const traffic = [target(baselineRevision, 100)];
  if (options.tags.includes("31")) traffic.push(target(revision31, 0, "pr-31"));
  if (options.tags.includes("44")) traffic.push(target(revision44, 0, "pr-44"));
  const transitionState = options.transitionState ?? "clear";
  const transitionMetadata = transitionState === "clear"
    ? { "repository-id": "1255553151", state: "clear", version: "1" }
    : {
        "dhi-parity-id": options.transitionParity === "different" ? "z".repeat(50) : parityId,
        "github-run-attempt": "1",
        "github-run-id": "999",
        nonce: "f".repeat(64),
        "platform-workflow-sha": options.transitionWorkflow === "predecessor"
          ? "9".repeat(40)
          : workflowSha,
        "repository-id": "1255553151",
        state: transitionState,
        version: "1",
      };
  await writeFile(statePath, JSON.stringify({
    etag: 1,
    exposure: options.exposure,
    generation: 7,
    ghHeads: { "31": head31, "44": head44 },
    iamBindings: options.publicInvoker
      ? [
          ...exactPreviewIamBindings,
          {
            members: [
              "allUsers",
              "group:preview-admins@example.com",
              "principalSet://iam.googleapis.com/projects/123/type/ServiceAccount",
              "serviceAccount:reviewer@example.iam.gserviceaccount.com",
              "user:reviewer@example.com",
            ],
            role: "projects/cdbentley/roles/customPreviewInvoker",
          },
        ]
      : exactPreviewIamBindings,
    iamEtag: 1,
    iamSetTransportLoss: options.iamSetTransportLoss,
    initialReadFailure: options.initialReadFailure,
    labels: options.initialLabels ?? { environment: "preview" },
    operation: 0,
    patchConflict: options.patchConflict,
    patchConflictsRemaining: options.patchConflictsRemaining,
    patchDoesNotAdvanceEtagOnAttempt: options.patchDoesNotAdvanceEtagOnAttempt,
    patchTransportLoss: options.patchTransportLoss,
    patchTransportLossOnAttempt: options.patchTransportLossOnAttempt,
    previewService,
    previewServiceAbsent: options.previewServiceAbsent,
    productionRevision: productionRevisionFixture(),
    productionService,
    projectId,
    projectNumber,
    region,
    revisions,
    traffic,
    transitionGeneration: "17",
    transitionMetadata,
    transitionMetageneration: transitionState === "clear" ? "1" : "8",
  }));

  const child = Bun.spawn(["/bin/bash", helper, options.mode], {
    cwd: repoRoot,
    env: {
      ...process.env,
      BASE_CONTENT_SHA256: "6".repeat(64),
      BASE_DOWNLOAD_DIR: root,
      BASE_MANIFEST_SHA256: "7".repeat(64),
      ACCESS_TOKEN: "fixture-committer-token",
      EXPECTED_PLATFORM_WORKFLOW_SHA: workflowSha,
      DHI_PARITY_ID: parityId,
      EXPECTED_PREVIEW_IMAGE_NAME: previewImage,
      EXPECTED_PREVIEW_RUNTIME_SERVICE_ACCOUNT: runtimeServiceAccount,
      EXPECTED_PRODUCTION_IMAGE_NAME: productionImage,
      EXPECTED_PROJECT_NUMBER: projectNumber,
      EXPECTED_REPOSITORY: "collinbentley1/cdbentley",
      EXPECTED_TARGET_HEAD_SHA: options.mode === "remove" ? head31 : "",
      EXPECTED_TARGET_REVISION: options.mode === "remove" ? revision31 : "",
      GH_TOKEN: "fixture-token",
      GITHUB_OUTPUT: outputPath,
      GITHUB_REPOSITORY: "collinbentley1/cdbentley",
      GITHUB_RUN_ATTEMPT: "1",
      GITHUB_RUN_ID: "123456789",
      MOCK_CLI: mockCli,
      MOCK_FAIL_POST_MUTATION: options.failPostMutationProof ? "1" : "0",
      MOCK_LOG: logPath,
      MOCK_STATE: statePath,
      PARITY_POLICY_ROOT: join(root, "policy"),
      PATH: `${bin}:${process.env.PATH ?? "/usr/bin:/bin"}`,
      PRESERVE_TARGET_HEAD_SHA: "",
      PREVIEW_INGRESS: "all",
      PREVIEW_SERVICE: previewService,
      PROJECT_ID: projectId,
      REGION: region,
      REPOSITORY_ID: "1255553151",
      RUNNER_TEMP: root,
      SERVICE_NAME: productionService,
      STABLE_PREVIEW_DOMAIN: "",
      TARGET_TAG: options.mode === "remove" ? "pr-31" : "",
    },
    stdout: "ignore",
    stderr: "pipe",
  });
  const [exitCode, stderr] = await Promise.all([
    child.exited,
    new Response(child.stderr).text(),
  ]);
  return {
    exitCode,
    log: await readFile(logPath, "utf8"),
    output: await readFile(outputPath, "utf8"),
    state: JSON.parse(await readFile(statePath, "utf8")),
    stderr,
  };
}

function target(revision: string, percent: number, tag?: string): any {
  return {
    percent,
    revision,
    ...(tag ? { tag } : {}),
    type: "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION",
  };
}

function routeTags(state: any): string[] {
  return state.traffic.map((target: any) => target.tag ?? "baseline");
}

function patchCommits(log: string): string[] {
  return log.trim().split("\n").filter((line) => line.startsWith("patch-commit"));
}

function revision(
  name: string,
  role: "baseline" | "pr",
  head: string,
  pull: string | undefined,
  digestCharacter: string,
): { v1: any; v2: any } {
  const baseline = role === "baseline";
  const imageName = baseline ? productionImage : previewImage;
  const index = `sha256:${digestCharacter.repeat(64)}`;
  const runnable = `sha256:${digestCharacter.repeat(64)}`;
  const env = baseline
    ? [
        { name: "PLATFORM_DEPLOY_ENVIRONMENT", value: "preview-baseline" },
        { name: "PLATFORM_IMAGE_INDEX_DIGEST", value: index },
        { name: "PLATFORM_IMAGE_RUNNABLE_DIGEST", value: runnable },
      ]
    : [
        { name: "PLATFORM_DEPLOY_ENVIRONMENT", value: "preview" },
        { name: "PLATFORM_DEPLOY_NONCE", value: digestCharacter.repeat(64) },
        { name: "PLATFORM_IMAGE_INDEX_DIGEST", value: index },
        { name: "PLATFORM_IMAGE_RUNNABLE_DIGEST", value: runnable },
        { name: "PLATFORM_PREVIEW_NUMBER", value: pull },
      ];
  const command = baseline ? ["bun"] : [];
  const args = baseline
    ? ["-e", "Bun.serve({port:+process.env.PORT,fetch(){return new Response(null,{status:404})}})"]
    : [];
  const labels = {
    "dhi-parity-id": parityId,
    environment: "preview",
    "git-head-sha": head,
    "github-repository-id": "1255553151",
    "managed-by": "github-actions",
    "platform-workflow-sha": workflowSha,
    "preview-role": role,
    ...(pull ? { "github-pr": pull } : {}),
  };
  const container = { args, command, env, image: `${imageName}@${runnable}` };
  return {
    v1: {
      metadata: { generation: 1, labels, name, namespace: projectNumber },
      spec: { containers: [container], serviceAccountName: runtimeServiceAccount },
      status: {
        conditions: [{ status: "True", type: "Ready" }],
        imageDigest: `${imageName}@${runnable}`,
        observedGeneration: 1,
      },
    },
    v2: {
      conditions: [{ state: "CONDITION_SUCCEEDED", type: "Ready" }],
      containers: [container],
      generation: "1",
      labels,
      name: `projects/${projectId}/locations/${region}/services/${previewService}/revisions/${name}`,
      serviceAccount: runtimeServiceAccount,
    },
  };
}

function productionRevisionFixture(): { v1: any; v2: any } {
  const index = `sha256:${"a".repeat(64)}`;
  const runnable = `sha256:${"b".repeat(64)}`;
  const env = [
    { name: "PLATFORM_IMAGE_INDEX_DIGEST", value: index },
    { name: "PLATFORM_IMAGE_RUNNABLE_DIGEST", value: runnable },
  ];
  return {
    v1: {
      metadata: { generation: 1, name: productionRevision, namespace: projectNumber },
      spec: { containers: [{ env, image: `${productionImage}@${runnable}` }] },
      status: { conditions: [{ status: "True", type: "Ready" }], observedGeneration: 1 },
    },
    v2: {
      conditions: [{ state: "CONDITION_SUCCEEDED", type: "Ready" }],
      containers: [{ env, image: `${productionImage}@${runnable}` }],
      name: `projects/${projectId}/locations/${region}/services/${productionService}/revisions/${productionRevision}`,
    },
  };
}

function setRevisionLabel(
  fixture: { v1: any; v2: any },
  label: string,
  value: string | undefined,
): void {
  for (const document of [fixture.v1, fixture.v2]) {
    const labels = document.metadata?.labels ?? document.labels;
    if (value === undefined) delete labels[label];
    else labels[label] = value;
  }
}
