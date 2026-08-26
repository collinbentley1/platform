import { expect, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  terraformSandboxCreateArguments,
  validateInvocation,
} from "../../tools/ci/protected-bootstrap-bridge.ts";

const terraformSandboxImage =
  "docker.io/oven/bun@sha256:8aac45197595035f697ea6b11cd73ce2401d82503fcb2540b5fac606973b242b";

interface DockerCommandResult {
  readonly exitCode: number;
  readonly stderr: string;
  readonly stdout: string;
}

interface DockerHostMount {
  readonly ReadOnly?: boolean;
  readonly Source?: string;
  readonly Target?: string;
  readonly Type?: string;
}

interface DockerRuntimeMount {
  readonly Destination?: string;
  readonly RW?: boolean;
  readonly Type?: string;
}

interface DockerInspection {
  readonly Config?: {
    readonly Env?: readonly string[];
    readonly Image?: string;
    readonly OpenStdin?: boolean;
    readonly Tty?: boolean;
    readonly Volumes?: Readonly<Record<string, unknown>> | null;
  };
  readonly HostConfig?: {
    readonly Binds?: readonly string[] | null;
    readonly Mounts?: readonly DockerHostMount[] | null;
    readonly PidMode?: string;
    readonly ReadonlyRootfs?: boolean;
    readonly Tmpfs?: Readonly<Record<string, string>> | null;
  };
  readonly Image?: string;
  readonly Mounts?: readonly DockerRuntimeMount[] | null;
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") {
    throw new Error(`The Docker integration contract requires ${name}.`);
  }
  return value;
}

function runDocker(
  dockerBinary: string,
  args: readonly string[],
  cwd: string,
  stdin?: string,
): DockerCommandResult {
  const result = Bun.spawnSync([dockerBinary, ...args], {
    cwd,
    env: {
      DOCKER_CONTEXT: process.env.DOCKER_CONTEXT ?? "",
      DOCKER_HOST: process.env.DOCKER_HOST ?? "",
      HOME: requiredEnvironment("HOME"),
      PATH: process.env.PATH ?? "/usr/bin:/bin",
    },
    killSignal: "SIGKILL",
    maxBuffer: 1024 * 1024,
    stderr: "pipe",
    stdin: stdin === undefined ? "ignore" : new TextEncoder().encode(stdin),
    stdout: "pipe",
    timeout: 30_000,
  });
  return {
    exitCode: result.exitCode,
    stderr: new TextDecoder().decode(result.stderr).trim(),
    stdout: new TextDecoder().decode(result.stdout).trim(),
  };
}

function requireDockerSuccess(result: DockerCommandResult, label: string): string {
  if (result.exitCode !== 0) {
    throw new Error(`${label} failed: ${result.stderr.slice(0, 4_096)}`);
  }
  return result.stdout;
}

test("the exact Terraform sandbox argv accepts its one-line token and keeps only /work writable", async () => {
  expect(requiredEnvironment("PROTECTED_BOOTSTRAP_DOCKER_INTEGRATION")).toBe("1");
  const dockerBinary = requiredEnvironment("PROTECTED_BOOTSTRAP_DOCKER_BINARY");
  expect(resolve(dockerBinary)).toBe(dockerBinary);

  const temporaryRoot = await mkdtemp(join(tmpdir(), "protected-bootstrap-docker-"));
  const platformRoot = join(temporaryRoot, "platform");
  const terraformDirectory = join(platformRoot, "terraform/deployments/bootstrap");
  const terraformBinary = join(temporaryRoot, "terraform");
  const terraformProviderArchive = join(temporaryRoot, "terraform-provider-google.zip");
  const terraformProviderDirectory = join(temporaryRoot, "terraform-provider-google");
  const workDirectory = join(temporaryRoot, "work");
  const runId = `${Date.now()}`;
  const containerName = `pbt-docker-contract-${runId}-${randomBytes(6).toString("hex")}`;
  const executorToken = "docker-integration-executor-token-0123456789";
  let containerId: string | undefined;
  let primaryFailure: unknown;

  try {
    await Promise.all([
      mkdir(join(temporaryRoot, "consumer"), { mode: 0o700 }),
      mkdir(terraformDirectory, { mode: 0o700, recursive: true }),
      mkdir(terraformProviderDirectory, { mode: 0o700 }),
      mkdir(join(temporaryRoot, "transition-platform"), { mode: 0o700 }),
      mkdir(workDirectory, { mode: 0o700 }),
      writeFile(terraformBinary, "#!/bin/sh\nexit 0\n", { mode: 0o700 }),
      writeFile(terraformProviderArchive, "integration fixture\n", { mode: 0o600 }),
    ]);
    await chmod(terraformBinary, 0o700);
    await mkdir(join(platformRoot, "tools/ci"), { mode: 0o700, recursive: true });
    await writeFile(
      join(platformRoot, "tools/ci/terraform-sandbox-entrypoint.sh"),
      `#!/bin/sh
set -eu
IFS= read -r received
[ "$received" = "${executorToken}" ]
if IFS= read -r unexpected; then
  exit 65
fi
[ "$#" -eq 2 ]
[ "$1" = "init" ]
[ "$2" = "-input=false" ]
printf '%s\\n' protected-sandbox-stdin-ok
`,
      { mode: 0o700 },
    );

    const invocation = validateInvocation({
      APPROVED_MANIFEST_SHA256: "",
      APPROVED_PLAN_RUN_ID: "",
      BRIDGE_OPERATION_BUDGET_SECONDS_EXACT: "1500",
      CONSUMER_ACTIONS_READ_TOKEN: "github-actions-read-token-value",
      CONSUMER_ROOT: join(temporaryRoot, "consumer"),
      CONSUMER_SHA: "b".repeat(40),
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
      GITHUB_RUN_ID_EXACT: runId,
      GITHUB_SHA_EXACT: "a".repeat(40),
      GITHUB_STEP_SUMMARY_EXACT: join(temporaryRoot, "summary"),
      GITHUB_WORKFLOW_REF_EXACT:
        "collinbentley1/platform/.github/workflows/protected-bootstrap-implementation.yml@refs/heads/main",
      LEGACY_COMPATIBILITY_MODE: "false",
      OWNER_OAUTH_ACCESS_TOKEN: "google-owner-access-token-value",
      PLATFORM_ACTIONS_READ_TOKEN: "platform-actions-read-token-value",
      PLATFORM_ROOT: platformRoot,
      RUNNER_ARCH_EXACT: "X64",
      RUNNER_ENVIRONMENT_EXACT: "github-hosted",
      RUNNER_OS_EXACT: "Linux",
      RUNNER_TEMP_EXACT: temporaryRoot,
      TARGET_REPOSITORY: "cdbentley",
      TERRAFORM_BINARY: terraformBinary,
      TERRAFORM_PROVIDER_ARCHIVE: terraformProviderArchive,
      TERRAFORM_PROVIDER_DIRECTORY: terraformProviderDirectory,
      TERRAFORM_ROOT: "bootstrap",
      TERRAFORM_SANDBOX_IMAGE: terraformSandboxImage,
      TRANSITION_PLATFORM_ROOT: join(temporaryRoot, "transition-platform"),
      TRANSITION_WORKFLOW_SHA: "",
    });
    const uid = process.getuid?.();
    const gid = process.getgid?.();
    if (uid === undefined || gid === undefined) {
      throw new Error("The Docker integration contract requires a numeric Unix identity.");
    }
    const createArguments = terraformSandboxCreateArguments({
      args: ["init", "-input=false"],
      containerName,
      invocation,
      terraformDirectory,
      workDirectory,
    }, uid, gid);
    expect(createArguments).toContain(
      `--mount=type=bind,src=${workDirectory},dst=/work,readonly=false`,
    );

    const expectedImageId = requireDockerSuccess(
      runDocker(dockerBinary, ["image", "inspect", "--format", "{{.Id}}", terraformSandboxImage], temporaryRoot),
      "inspect the exact Terraform sandbox image",
    );
    containerId = requireDockerSuccess(
      runDocker(dockerBinary, createArguments, temporaryRoot),
      "create the exact Terraform sandbox",
    );
    expect(containerId).toMatch(/^[0-9a-f]{64}$/);

    const inspection = JSON.parse(requireDockerSuccess(
      runDocker(dockerBinary, ["inspect", "--type=container", containerId], temporaryRoot),
      "inspect the created Terraform sandbox",
    )) as readonly DockerInspection[];
    expect(inspection).toHaveLength(1);
    const [container] = inspection;
    expect(container?.Config?.Image).toBe(terraformSandboxImage);
    expect(container?.Config?.OpenStdin).toBeTrue();
    expect(container?.Config?.Tty).toBeFalse();
    expect(container?.Config?.Volumes ?? null).toBeNull();
    expect(new Set(container?.Config?.Env ?? [])).toEqual(new Set([
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bun-node-fallback-bin",
      "BUN_RUNTIME_TRANSPILER_CACHE_PATH=0",
      "BUN_INSTALL_BIN=/usr/local/bin",
      "CHECKPOINT_DISABLE=1",
      "TF_DATA_DIR=/work/tfdata",
      "TF_IN_AUTOMATION=1",
    ]));
    expect(JSON.stringify(container)).not.toContain(executorToken);
    expect(JSON.stringify(container)).not.toContain("google-owner-access-token-value");
    expect(container?.Image).toBe(expectedImageId);
    expect(container?.HostConfig?.PidMode ?? "").toBe("");
    expect(container?.HostConfig?.ReadonlyRootfs).toBeTrue();
    expect(container?.HostConfig?.Binds ?? []).toEqual([]);

    const configuredMounts = container?.HostConfig?.Mounts ?? [];
    expect(configuredMounts).toHaveLength(4);
    const configuredBinds = configuredMounts
      .filter((mount) => mount.Type === "bind")
      .map((mount) => ({
        destination: mount.Target,
        readOnly: mount.ReadOnly === true,
      }))
      .sort((left, right) => `${left.destination}`.localeCompare(`${right.destination}`));
    expect(configuredBinds).toEqual([
      { destination: "/opt/terraform", readOnly: true },
      { destination: "/platform", readOnly: true },
      { destination: "/plugins", readOnly: true },
      { destination: "/work", readOnly: false },
    ]);

    const runtimeBinds = (container?.Mounts ?? [])
      .filter((mount) => mount.Type === "bind")
      .map((mount) => ({ destination: mount.Destination, writable: mount.RW === true }))
      .sort((left, right) => `${left.destination}`.localeCompare(`${right.destination}`));
    expect(runtimeBinds).toEqual([
      { destination: "/opt/terraform", writable: false },
      { destination: "/platform", writable: false },
      { destination: "/plugins", writable: false },
      { destination: "/work", writable: true },
    ]);

    const configuredTmpfs = container?.HostConfig?.Tmpfs ?? {};
    expect(Object.keys(configuredTmpfs)).toEqual(["/tmp"]);
    expect(new Set(configuredTmpfs["/tmp"]?.split(","))).toEqual(new Set([
      "rw",
      "noexec",
      "nosuid",
      "nodev",
      "size=67108864",
      "mode=1777",
    ]));

    expect(requireDockerSuccess(
      runDocker(
        dockerBinary,
        ["start", "--attach", "--interactive", containerId],
        temporaryRoot,
        `${executorToken}\n`,
      ),
      "start the Terraform sandbox with its one-line executor token",
    )).toBe("protected-sandbox-stdin-ok");
  } catch (error) {
    primaryFailure = error;
    throw error;
  } finally {
    const cleanupFailures: unknown[] = [];
    const cleanup = runDocker(dockerBinary, ["rm", "--force", containerName], temporaryRoot);
    const survivors = runDocker(
      dockerBinary,
      ["ps", "--all", "--filter", `name=^/${containerName}$`, "--format", "{{.ID}}"],
      temporaryRoot,
    );
    if (survivors.exitCode !== 0) {
      cleanupFailures.push(
        new Error(
          `prove Docker contract container removal failed: ${survivors.stderr}; ` +
            `remove result: ${cleanup.stderr}`,
        ),
      );
    } else if (survivors.stdout !== "") {
      cleanupFailures.push(
        new Error(
          `Docker contract container survived cleanup: ${survivors.stdout}; ` +
            `remove result: ${cleanup.stderr}`,
        ),
      );
    }
    try {
      await rm(temporaryRoot, { force: true, recursive: true });
    } catch (error) {
      cleanupFailures.push(error);
    }
    if (cleanupFailures.length > 0) {
      if (primaryFailure !== undefined) {
        throw new AggregateError(
          [primaryFailure, ...cleanupFailures],
          "The Docker contract failed and its container cleanup also failed.",
        );
      }
      throw new AggregateError(cleanupFailures, "The Docker contract cleanup failed.");
    }
  }
}, 180_000);
