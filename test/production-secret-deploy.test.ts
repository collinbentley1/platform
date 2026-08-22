import { afterEach, describe, expect, test } from "bun:test";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "..");
const headSha = "0123456789abcdef0123456789abcdef01234567";
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
      `--labels=managed-by=github-actions,environment=production,git-head-sha=${headSha},` +
        "github-repository-id=1025243085,github-run-id=987654321," +
        "github-run-attempt=1,waitlist-secret-version=7",
    );
    expect(created.capturedEnvironment).not.toContain("WAITLIST_IDENTITY_KEYSET");
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
  return deployScript;
}

function serviceWithWaitlistEntries(entries: unknown[]): object {
  return {
    metadata: { labels: {} },
    spec: { template: { spec: { containers: [{ env: entries }] } } },
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
  const versionsFixture = join(root, "versions-fixture.json");
  await writeFile(serviceFixture, JSON.stringify(serviceSnapshot));
  await writeFile(versionsFixture, JSON.stringify(versionsSnapshot));

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
      "  *)",
      '    echo "Unexpected gcloud invocation" >&2',
      "    exit 91",
      "    ;;",
      "esac",
      "",
    ].join("\n"),
  );
  await chmod(fakeGcloud, 0o755);

  const child = Bun.spawn(["/bin/bash", "-c", deployScript], {
    cwd: root,
    env: {
      GCLOUD_CALLS: calls,
      GCLOUD_CAPTURED_ENVIRONMENT: capturedEnvironment,
      GCLOUD_DEPLOY_ARGUMENTS: deployArguments,
      GCLOUD_SERVICE_FIXTURE: serviceFixture,
      GCLOUD_STDIN_DIGEST: stdinDigest,
      GCLOUD_VERSIONS_FIXTURE: versionsFixture,
      GCLOUD_VERSION_STATE: versionState,
      GITHUB_RUN_ATTEMPT: "1",
      GITHUB_RUN_ID: "987654321",
      GITHUB_SHA: headSha,
      IMAGE_DIGEST: "sha256:" + "a".repeat(64),
      IMAGE_NAME: "us-east4-docker.pkg.dev/medlock-1025243085/site/medlock",
      MAPBOX_PUBLIC_TOKEN: "",
      PATH: bin + ":" + (process.env.PATH ?? "/usr/bin:/bin"),
      PROJECT_ID: "medlock-1025243085",
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
