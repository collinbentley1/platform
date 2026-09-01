import { afterEach, describe, expect, test } from "bun:test";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "..");
const headSha = "0123456789abcdef0123456789abcdef01234567";
const platformWorkflowSha = "1234567890abcdef1234567890abcdef12345678";
const dhiParityId = "1a4cho1elzg84pavos8mbanvvpmkieiht7kyhpjdofzpivf3k8";
const recaptchaSiteKey = "6LmedlockWaitlistOwnershipKey_1234567890";
const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("production Secret Manager deploy boundary", () => {
  test("generates a key only for an empty binding/inventory and never exposes its payload", async () => {
    const deployScript = await productionDeployScript();
    const created = await runDeployScript(deployScript, serviceWithWaitlistEntries([]), []);

    expect({ exitCode: created.exitCode, stderr: created.stderr }).toEqual({
      exitCode: 0,
      stderr: "",
    });
    expect(created.calls).toContain("secrets\tversions\tlist\t");
    expect(created.calls).toContain("secrets\tversions\tadd\twaitlist-identity-keyset");
    expect(created.calls).toContain("secrets\tversions\tdescribe\t7");
    expect(created.stdinDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(created.deployArguments).toContain(
      "--set-secrets=WAITLIST_IDENTITY_KEYSET=waitlist-identity-keyset:7",
    );
    expect(created.deployArguments).toContain(
      `--labels=managed-by=github-actions,environment=production,dhi-parity-id=${dhiParityId},git-head-sha=${headSha},` +
        "github-repository-id=1025243085,github-run-id=987654321," +
        `github-run-attempt=1,platform-workflow-sha=${platformWorkflowSha},waitlist-secret-version=7`,
    );
    expect(created.capturedEnvironment).not.toContain("WAITLIST_IDENTITY_KEYSET");
    expect(JSON.parse(created.capturedEnvironment)).toMatchObject({
      IDENTITY_PLATFORM_AUDIENCE: "medlock-1025243085",
      IDENTITY_PLATFORM_CONTINUE_URL: "https://medlock.ai/api/waitlist/confirm",
      RECAPTCHA_PROJECT_ID: "medlock-1025243085",
      RECAPTCHA_SITE_KEY: recaptchaSiteKey,
    });
    expect(created.calls).toContain(`recaptcha\tkeys\tdescribe\t${recaptchaSiteKey}`);
    expect(created.calls).not.toContain(created.stdinDigest);
    expect(created.deployArguments).not.toContain(created.stdinDigest);
  });

  test("reuses one exact enabled numeric binding without generating or listing payload versions", async () => {
    const deployScript = await productionDeployScript();
    const reused = await runDeployScript(
      deployScript,
      serviceWithWaitlistEntries([exactWaitlistEntry("6")]),
      [{ name: "projects/229383559510/secrets/waitlist-identity-keyset/versions/6", state: "ENABLED" }],
    );

    expect({ exitCode: reused.exitCode, stderr: reused.stderr }).toEqual({
      exitCode: 0,
      stderr: "",
    });
    expect(reused.calls).not.toContain("secrets\tversions\tlist");
    expect(reused.calls).not.toContain("secrets\tversions\tadd");
    expect(reused.calls).toContain("secrets\tversions\tdescribe\t6");
    expect(reused.stdinDigest).toBe("");
    expect(reused.deployArguments).toContain(
      "--set-secrets=WAITLIST_IDENTITY_KEYSET=waitlist-identity-keyset:6",
    );
    expect(reused.deployArguments).toContain("waitlist-secret-version=6");
  });

  test("rejects unbound enabled versions, foreign entries, duplicates, and disabled bindings", async () => {
    const deployScript = await productionDeployScript();
    const cases: Array<{
      entries: unknown[];
      expected?: string;
      state?: "DISABLED" | "ENABLED";
      versions?: unknown[];
    }> = [
      {
        entries: [],
        expected: "Refusing to guess an unbound existing Medlock secret version.",
        versions: [{
          name: "projects/229383559510/secrets/waitlist-identity-keyset/versions/4",
          state: "ENABLED",
        }],
      },
      {
        entries: [{
          name: "WAITLIST_IDENTITY_KEYSET",
          valueFrom: { secretKeyRef: { key: "4", name: "foreign-secret" } },
        }],
      },
      {
        entries: [exactWaitlistEntry("4"), exactWaitlistEntry("5")],
        expected: "Medlock has multiple WAITLIST_IDENTITY_KEYSET runtime entries.",
      },
      {
        entries: [exactWaitlistEntry("4")],
        state: "DISABLED",
      },
    ];

    for (const testCase of cases) {
      const rejected = await runDeployScript(
        deployScript,
        serviceWithWaitlistEntries(testCase.entries),
        testCase.versions ?? [],
        testCase.state ?? "ENABLED",
      );
      expect(rejected.exitCode).not.toBe(0);
      if (testCase.expected) {
        expect(rejected.stderr).toContain(testCase.expected);
      }
      expect(rejected.calls).not.toContain("run\tdeploy");
      expect(rejected.deployArguments).toBe("");
    }
  });

  test("rejects missing, duplicated, or changed ownership runtime settings", async () => {
    const deployScript = await productionDeployScript();
    const exact = ownershipEntries();
    const cases = [
      exact.filter((entry) => entry.name !== "RECAPTCHA_SITE_KEY"),
      [...exact, { name: "RECAPTCHA_SITE_KEY", value: recaptchaSiteKey }],
      exact.map((entry) => entry.name === "IDENTITY_PLATFORM_AUDIENCE"
        ? { ...entry, value: "foreign-project" }
        : entry),
      exact.map((entry) => entry.name === "RECAPTCHA_SITE_KEY"
        ? { ...entry, value: "not a key" }
        : entry),
    ];

    for (const ownership of cases) {
      const rejected = await runDeployScript(
        deployScript,
        serviceWithWaitlistEntries([], ownership),
        [],
      );
      expect(rejected.exitCode).not.toBe(0);
      expect(rejected.calls).not.toContain("run\tdeploy");
    }
  });

  test("rejects a site key whose live public policy drifted", async () => {
    const deployScript = await productionDeployScript();
    const exact = exactRecaptchaKey();
    const cases = [
      { ...exact, displayName: "Foreign key" },
      { ...exact, webSettings: { ...exact.webSettings, allowAllDomains: true } },
      { ...exact, webSettings: { ...exact.webSettings, allowedDomains: ["attacker.example"] } },
      { ...exact, testingOptions: { testingScore: 1 } },
      { ...exact, wafSettings: { wafFeature: "CHALLENGE_PAGE", wafService: "CA" } },
    ];

    for (const key of cases) {
      const rejected = await runDeployScript(
        deployScript,
        serviceWithWaitlistEntries([]),
        [],
        "ENABLED",
        key,
      );
      expect(rejected.exitCode).not.toBe(0);
      expect(rejected.stderr).toContain(
        "The live Medlock reCAPTCHA key escaped its Terraform-reviewed public policy.",
      );
      expect(rejected.calls).not.toContain("run\tdeploy");
    }
  });
});

async function productionDeployScript(): Promise<string> {
  const workflow = await readFile(join(repoRoot, ".github/workflows/deploy-prod.yml"), "utf8");
  const parsed = Bun.YAML.parse(workflow) as {
    jobs: { deploy: { steps: Array<{ name?: string; run?: string }> } };
  };
  const deployScript = parsed.jobs.deploy.steps.find(
    (step) => step.name === "Deploy production to Cloud Run",
  )?.run;
  expect(deployScript).toBeDefined();
  if (!deployScript) throw new Error("Production deploy script is missing.");
  return deployScript.replaceAll("${{ steps.parity-policy.outputs.root }}", repoRoot);
}

function serviceWithWaitlistEntries(
  entries: unknown[],
  ownership: Array<{ name: string; value: string }> = ownershipEntries(),
): object {
  return {
    apiVersion: "serving.knative.dev/v1",
    kind: "Service",
    metadata: {
      generation: 7,
      labels: {
        "dhi-parity-id": dhiParityId,
        environment: "production",
        "managed-by": "github-actions",
      },
      name: "medlock",
      namespace: "229383559510",
    },
    spec: {
      template: { spec: { containers: [{ env: [...ownership, ...entries] }] } },
      traffic: [{ latestRevision: true, percent: 100 }],
    },
    status: {
      conditions: ["Ready", "ConfigurationsReady", "RoutesReady"].map((type) => ({
        status: "True",
        type,
      })),
      latestCreatedRevisionName: "medlock-00007-abc",
      latestReadyRevisionName: "medlock-00007-abc",
      observedGeneration: 7,
      traffic: [{ latestRevision: true, percent: 100, revisionName: "medlock-00007-abc" }],
    },
  };
}

function ownershipEntries(): Array<{ name: string; value: string }> {
  return [
    { name: "IDENTITY_PLATFORM_AUDIENCE", value: "medlock-1025243085" },
    {
      name: "IDENTITY_PLATFORM_CONTINUE_URL",
      value: "https://medlock.ai/api/waitlist/confirm",
    },
    { name: "RECAPTCHA_PROJECT_ID", value: "medlock-1025243085" },
    { name: "RECAPTCHA_SITE_KEY", value: recaptchaSiteKey },
  ];
}

function exactRecaptchaKey(): {
  displayName: string;
  name: string;
  webSettings: {
    allowAllDomains: boolean;
    allowAmpTraffic: boolean;
    allowedDomains: string[];
    integrationType: string;
  };
} {
  return {
    displayName: "Medlock waitlist ownership",
    name: `projects/229383559510/keys/${recaptchaSiteKey}`,
    webSettings: {
      allowAllDomains: false,
      allowAmpTraffic: false,
      allowedDomains: ["medlock.ai"],
      integrationType: "SCORE",
    },
  };
}

function productionRevisionFixture(): object {
  const image = `us-east4-docker.pkg.dev/medlock-1025243085/site/medlock@sha256:${"b".repeat(64)}`;
  return {
    apiVersion: "serving.knative.dev/v1",
    kind: "Revision",
    metadata: {
      generation: 1,
      labels: {
        "dhi-parity-id": dhiParityId,
        environment: "production",
        "git-head-sha": headSha,
        "github-repository-id": "1025243085",
        "managed-by": "github-actions",
        "platform-workflow-sha": platformWorkflowSha,
        "serving.knative.dev/service": "medlock",
      },
      name: "medlock-00007-abc",
      namespace: "229383559510",
    },
    spec: {
      containers: [{
        env: [
          { name: "PLATFORM_IMAGE_INDEX_DIGEST", value: `sha256:${"a".repeat(64)}` },
          { name: "PLATFORM_IMAGE_RUNNABLE_DIGEST", value: `sha256:${"b".repeat(64)}` },
          ...ownershipEntries(),
        ],
        image,
      }],
    },
    status: {
      conditions: [
        { status: "True", type: "Ready" },
        { status: "True", type: "ContainerHealthy" },
      ],
      imageDigest: image,
      observedGeneration: 1,
    },
  };
}

function exactWaitlistEntry(version: string): object {
  return {
    name: "WAITLIST_IDENTITY_KEYSET",
    valueFrom: {
      secretKeyRef: { key: version, name: "waitlist-identity-keyset" },
    },
  };
}

async function runDeployScript(
  deployScript: string,
  serviceSnapshot: unknown,
  versionsSnapshot: unknown[],
  versionState: "DISABLED" | "ENABLED" = "ENABLED",
  keySnapshot: unknown = exactRecaptchaKey(),
): Promise<{
  calls: string;
  capturedEnvironment: string;
  deployArguments: string;
  exitCode: number;
  stderr: string;
  stdinDigest: string;
}> {
  const root = await mkdtemp(join(tmpdir(), "platform-production-secret-"));
  temporaryRoots.push(root);
  const bin = join(root, "bin");
  await mkdir(bin);
  const calls = join(root, "calls.txt");
  const capturedEnvironment = join(root, "captured-env.json");
  const deployArguments = join(root, "deploy-arguments.txt");
  const stdinDigest = join(root, "stdin-digest.txt");
  const serviceFixture = join(root, "service-fixture.json");
  const revisionFixture = join(root, "revision-fixture.json");
  const keyFixture = join(root, "key-fixture.json");
  const versionsFixture = join(root, "versions-fixture.json");
  const v2ServiceFixture = join(root, "v2-service-fixture.json");
  const v2RevisionFixture = join(root, "v2-revision-fixture.json");
  await writeFile(serviceFixture, JSON.stringify(serviceSnapshot));
  await writeFile(revisionFixture, JSON.stringify(productionRevisionFixture()));
  await writeFile(keyFixture, JSON.stringify(keySnapshot));
  await writeFile(versionsFixture, JSON.stringify(versionsSnapshot));
  await writeFile(v2ServiceFixture, JSON.stringify({
    defaultUriDisabled: false,
    generation: "7",
    ingress: "INGRESS_TRAFFIC_ALL",
    invokerIamDisabled: true,
    latestReadyRevision: "projects/medlock-1025243085/locations/us-east4/services/medlock/revisions/medlock-00007-abc",
    name: "projects/medlock-1025243085/locations/us-east4/services/medlock",
    observedGeneration: "7",
    reconciling: false,
    template: { containers: [{}] },
    terminalCondition: { state: "CONDITION_SUCCEEDED", type: "Ready" },
    traffic: [{ percent: 100, type: "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST" }],
    trafficStatuses: [{ percent: 100, type: "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST" }],
    uri: "https://medlock.example.run.app",
    urls: ["https://medlock.example.run.app"],
  }));
  await writeFile(v2RevisionFixture, JSON.stringify({
    conditions: [{ state: "CONDITION_SUCCEEDED", type: "Ready" }],
    containers: [{
      env: [
        { name: "PLATFORM_IMAGE_INDEX_DIGEST", value: `sha256:${"a".repeat(64)}` },
        { name: "PLATFORM_IMAGE_RUNNABLE_DIGEST", value: `sha256:${"b".repeat(64)}` },
        ...ownershipEntries(),
      ],
      image: `us-east4-docker.pkg.dev/medlock-1025243085/site/medlock@sha256:${"b".repeat(64)}`,
    }],
    name: "projects/medlock-1025243085/locations/us-east4/services/medlock/revisions/medlock-00007-abc",
    reconciling: false,
  }));

  const fakeGcloud = join(bin, "gcloud");
  await writeFile(
    fakeGcloud,
    [
      "#!/bin/bash",
      "set -euo pipefail",
      'if [ "${WAITLIST_IDENTITY_KEYSET+x}" = "x" ]; then',
      '  echo "gcloud inherited WAITLIST_IDENTITY_KEYSET" >&2',
      "  exit 90",
      "fi",
      'printf "%s\\t" "$@" >> "$GCLOUD_CALLS"',
      'printf "\\n" >> "$GCLOUD_CALLS"',
      'case "${1:-}:${2:-}:${3:-}" in',
      "  run:services:describe)",
      '    cat "$GCLOUD_SERVICE_FIXTURE"',
      "    ;;",
      "  run:revisions:describe)",
      '    cat "$GCLOUD_REVISION_FIXTURE"',
      "    ;;",
      "  recaptcha:keys:describe)",
      '    cat "$GCLOUD_RECAPTCHA_KEY_FIXTURE"',
      "    ;;",
      "  secrets:versions:list)",
      '    cat "$GCLOUD_VERSIONS_FIXTURE"',
      "    ;;",
      "  secrets:versions:add)",
      "    sha256sum | cut -d ' ' -f1 > \"$GCLOUD_STDIN_DIGEST\"",
      '    printf "%s\\n" "projects/229383559510/secrets/waitlist-identity-keyset/versions/7"',
      "    ;;",
      "  secrets:versions:describe)",
      '    printf \'{"name":"projects/229383559510/secrets/waitlist-identity-keyset/versions/%s","state":"%s"}\\n\' "$4" "$GCLOUD_VERSION_STATE"',
      "    ;;",
      "  run:deploy:*)",
      '    printf "%s\\n" "$@" > "$GCLOUD_DEPLOY_ARGUMENTS"',
      '    for argument in "$@"; do',
      '      case "$argument" in',
      "        --env-vars-file=*)",
      '          cp "${argument#--env-vars-file=}" "$GCLOUD_CAPTURED_ENVIRONMENT"',
      "          ;;",
      "      esac",
      "    done",
      "    ;;",
      "  auth:print-access-token:)",
      '    printf "%s\\n" "test-access-token"',
      "    ;;",
      "  *)",
      '    echo "Unexpected gcloud invocation" >&2',
      "    exit 91",
      "    ;;",
      "esac",
      "",
    ].join("\n"),
  );
  await chmod(fakeGcloud, 0o755);

  const fakeCurl = join(bin, "curl");
  await writeFile(
    fakeCurl,
    [
      "#!/bin/bash",
      "set -euo pipefail",
      'output=""',
      'url=""',
      'while [ "$#" -gt 0 ]; do',
      '  case "$1" in',
      '    --output) output="$2"; shift 2 ;;',
      '    https://*) url="$1"; shift ;;',
      '    *) shift ;;',
      '  esac',
      'done',
      'case "$url" in',
      '  */revisions/*) cp "$GCLOUD_V2_REVISION_FIXTURE" "$output" ;;',
      '  */services/*) cp "$GCLOUD_V2_SERVICE_FIXTURE" "$output" ;;',
      '  *) echo "Unexpected curl URL" >&2; exit 92 ;;',
      'esac',
    ].join("\n"),
  );
  await chmod(fakeCurl, 0o755);

  const child = Bun.spawn(["/bin/bash", "-c", deployScript], {
    cwd: root,
    env: {
      GCLOUD_CALLS: calls,
      GCLOUD_CAPTURED_ENVIRONMENT: capturedEnvironment,
      GCLOUD_DEPLOY_ARGUMENTS: deployArguments,
      GCLOUD_SERVICE_FIXTURE: serviceFixture,
      GCLOUD_REVISION_FIXTURE: revisionFixture,
      GCLOUD_RECAPTCHA_KEY_FIXTURE: keyFixture,
      GCLOUD_STDIN_DIGEST: stdinDigest,
      GCLOUD_VERSIONS_FIXTURE: versionsFixture,
      GCLOUD_VERSION_STATE: versionState,
      GCLOUD_V2_REVISION_FIXTURE: v2RevisionFixture,
      GCLOUD_V2_SERVICE_FIXTURE: v2ServiceFixture,
      GITHUB_OUTPUT: join(root, "github-output.txt"),
      GITHUB_RUN_ATTEMPT: "1",
      GITHUB_RUN_ID: "987654321",
      GITHUB_SHA: headSha,
      DHI_PARITY_ID: dhiParityId,
      IMAGE_DIGEST: "sha256:" + "a".repeat(64),
      RUNNABLE_DIGEST: "sha256:" + "b".repeat(64),
      IMAGE_NAME: "us-east4-docker.pkg.dev/medlock-1025243085/site/medlock",
      MAPBOX_PUBLIC_TOKEN: "",
      PATH: bin + ":" + (process.env.PATH ?? "/usr/bin:/bin"),
      PLATFORM_WORKFLOW_SHA: platformWorkflowSha,
      PROJECT_ID: "medlock-1025243085",
      PROJECT_NUMBER: "229383559510",
      REGION: "us-east4",
      REPOSITORY_ID: "1025243085",
      RUNNER_TEMP: root,
      RUNTIME_SERVICE_ACCOUNT: "cloud-run-runtime@medlock-1025243085.iam.gserviceaccount.com",
      SERVICE_NAME: "medlock",
    },
    stderr: "pipe",
    stdout: "ignore",
  });
  const [exitCode, stderr] = await Promise.all([
    child.exited,
    new Response(child.stderr).text(),
  ]);
  return {
    calls: await optionalText(calls),
    capturedEnvironment: await optionalText(capturedEnvironment),
    deployArguments: await optionalText(deployArguments),
    exitCode,
    stderr,
    stdinDigest: (await optionalText(stdinDigest)).trim(),
  };
}

async function optionalText(path: string): Promise<string> {
  return (await Bun.file(path).exists()) ? Bun.file(path).text() : "";
}
