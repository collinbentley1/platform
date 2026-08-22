import { afterEach, describe, expect, test } from "bun:test";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "..");
const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("production Secret Manager deploy boundary", () => {
  test("validates canonically, creates only on change, and never gives gcloud the payload", async () => {
    const workflow = await readFile(join(repoRoot, ".github/workflows/deploy-prod.yml"), "utf8");
    const parsed = Bun.YAML.parse(workflow) as {
      jobs: { deploy: { steps: Array<{ name?: string; run?: string }> } };
    };
    const deployScript = parsed.jobs.deploy.steps.find(
      (step) => step.name === "Deploy production to Cloud Run",
    )?.run;
    expect(deployScript).toBeDefined();
    if (!deployScript) {
      throw new Error("Production deploy script is missing.");
    }

    const keyset = Buffer.alloc(32, 7).toString("base64url");
    const fingerprint = createHash("sha256").update(keyset).digest("hex").slice(0, 48);
    const changed = await runDeployScript(deployScript, keyset, {
      metadata: { labels: {} },
      spec: { template: { spec: { containers: [{ env: [] }] } } },
    });
    expect({ exitCode: changed.exitCode, stderr: changed.stderr }).toEqual({
      exitCode: 0,
      stderr: "",
    });
    expect(changed.calls).toContain("secrets\tversions\tadd\twaitlist-identity-keyset");
    expect(changed.stdinDigest).toBe(createHash("sha256").update(keyset).digest("hex"));
    expect(changed.deployArguments).toContain(
      "--set-secrets=WAITLIST_IDENTITY_KEYSET=waitlist-identity-keyset:7",
    );
    expect(changed.deployArguments).toContain(
      "--labels=managed-by=github-actions,environment=production,waitlist-keyset-fingerprint=" +
        fingerprint,
    );
    expect(changed.deployArguments).not.toContain(keyset);
    expect(changed.capturedEnvironment).not.toContain(keyset);
    expect(changed.capturedEnvironment).not.toContain("WAITLIST_IDENTITY_KEYSET");
    expect(changed.calls).not.toContain(keyset);

    const unchanged = await runDeployScript(deployScript, keyset, {
      metadata: { labels: { "waitlist-keyset-fingerprint": fingerprint } },
      spec: {
        template: {
          spec: {
            containers: [
              {
                env: [
                  {
                    name: "WAITLIST_IDENTITY_KEYSET",
                    valueFrom: {
                      secretKeyRef: { key: "6", name: "waitlist-identity-keyset" },
                    },
                  },
                ],
              },
            ],
          },
        },
      },
    });
    expect({ exitCode: unchanged.exitCode, stderr: unchanged.stderr }).toEqual({
      exitCode: 0,
      stderr: "",
    });
    expect(unchanged.calls).not.toContain("secrets\tversions\tadd");
    expect(unchanged.stdinDigest).toBe("");
    expect(unchanged.deployArguments).toContain(
      "--set-secrets=WAITLIST_IDENTITY_KEYSET=waitlist-identity-keyset:6",
    );

    const noncanonical = keyset.slice(0, -1) + "B";
    expect(noncanonical).toHaveLength(43);
    const rejected = await runDeployScript(deployScript, noncanonical, {
      metadata: { labels: {} },
      spec: { template: { spec: { containers: [{ env: [] }] } } },
    });
    expect(rejected.exitCode).not.toBe(0);
    expect(rejected.stderr).toContain(
      "Medlock waitlist keys must use canonical base64url encoding of exactly 32 bytes.",
    );
    expect(rejected.calls).toBe("");
    expect(rejected.deployArguments).toBe("");
    expect(rejected.stdinDigest).toBe("");

    const rejectedPrior = await runDeployScript(deployScript, keyset + "," + noncanonical, {
      metadata: { labels: {} },
      spec: { template: { spec: { containers: [{ env: [] }] } } },
    });
    expect(rejectedPrior.exitCode).not.toBe(0);
    expect(rejectedPrior.stderr).toContain(
      "Medlock waitlist keys must use canonical base64url encoding of exactly 32 bytes.",
    );
    expect(rejectedPrior.calls).toBe("");
  });
});

async function runDeployScript(
  deployScript: string,
  keyset: string,
  serviceSnapshot: unknown,
): Promise<{
  exitCode: number;
  stderr: string;
  calls: string;
  capturedEnvironment: string;
  deployArguments: string;
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
  await writeFile(serviceFixture, JSON.stringify(serviceSnapshot));

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
      "  secrets:versions:add)",
      "    sha256sum | cut -d ' ' -f1 > \"$GCLOUD_STDIN_DIGEST\"",
      '    printf "%s\\n" "projects/229383559510/secrets/waitlist-identity-keyset/versions/7"',
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
      WAITLIST_IDENTITY_KEYSET: keyset,
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
    stderr,
    calls: await optionalText(calls),
    capturedEnvironment: await optionalText(capturedEnvironment),
    deployArguments: await optionalText(deployArguments),
    stdinDigest: (await optionalText(stdinDigest)).trim(),
  };
}

async function optionalText(path: string): Promise<string> {
  return (await Bun.file(path).exists()) ? Bun.file(path).text() : "";
}
