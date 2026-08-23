import { afterEach, describe, expect, test } from "bun:test";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "..");
const helper = join(repoRoot, "tools/ci/deployment-parity-transition.sh");
const mock = join(repoRoot, "test/fixtures/deployment-parity-transition-mock-curl.ts");
const projectId = "cdbentley";
const repositoryId = "1255553151";
const workflowSha = "1".repeat(40);
const parityId = "1a4cho1elzg84pavos8mbanvvpmkieiht7kyhpjdofzpivf3k8";
const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("durable deployment parity transition marker", () => {
  test("acquire and release use generation plus metageneration CAS without create, delete, or list", async () => {
    const fixture = await setup();
    const acquired = await run(fixture, "acquire");
    expect(acquired.exitCode, acquired.stderr).toBe(0);
    expect(acquired.state.metadata.state).toBe("preview-admission");
    expect(acquired.state.metadata.nonce).toMatch(/^[0-9a-f]{64}$/);
    expect(acquired.log).toContain("patch generation=17 metageneration=1");
    expect(await readFile(fixture.lease, "utf8")).toContain('"metageneration":"2"');

    const released = await run(fixture, "release");
    expect(released.exitCode, released.stderr).toBe(0);
    expect(released.state.metadata).toEqual({
      "repository-id": repositoryId,
      state: "clear",
      version: "1",
    });
    expect(released.log).toContain("patch generation=17 metageneration=2");
    expect(released.log).not.toMatch(/create|delete|list/);
  });

  test("an existing poison refuses a second unsafe transition without mutation", async () => {
    const fixture = await setup({
      metadata: {
        "dhi-parity-id": parityId,
        "github-run-attempt": "1",
        "github-run-id": "9",
        nonce: "a".repeat(64),
        "platform-workflow-sha": workflowSha,
        "repository-id": repositoryId,
        state: "preview-admission",
        version: "1",
      },
      metageneration: "8",
    });
    const result = await run(fixture, "acquire");
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("transition is active");
    expect(result.log.trim()).toBe("get");
  });

  test("a response-lost acquire authorizes only after the exact nonce is strongly observed", async () => {
    const fixture = await setup({ mode: "acquire-transport-loss" });
    const result = await run(fixture, "acquire");
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.state.metadata.state).toBe("preview-admission");
    expect(await Bun.file(fixture.lease).exists()).toBe(true);
    expect(result.log).toContain("acquire-applied-response-lost");
    const retry = await run(fixture, "acquire");
    expect(retry.exitCode).not.toBe(0);
    expect(retry.stderr).toContain("transition is active");
  });

  test("a metadata CAS conflict cannot authorize mutation", async () => {
    const fixture = await setup({ mode: "acquire-conflict" });
    const result = await run(fixture, "acquire");
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("CAS was not observed at its exact nonce");
    expect(result.state.metadata.state).toBe("external-poison");
    expect(await Bun.file(fixture.lease).exists()).toBe(false);
  });

  test("a response-lost release is safe and an old metageneration cannot clear a later lease", async () => {
    const fixture = await setup();
    expect((await run(fixture, "acquire")).exitCode).toBe(0);
    fixture.mode = "release-transport-loss";
    await writeStateMode(fixture);
    const release = await run(fixture, "release");
    expect(release.exitCode, release.stderr).toBe(0);
    expect(release.state.metadata.state).toBe("clear");

    fixture.mode = undefined;
    await writeStateMode(fixture);
    await rm(fixture.lease, { force: true });
    expect((await run(fixture, "acquire")).exitCode).toBe(0);
    const current = JSON.parse(await readFile(fixture.state, "utf8"));
    expect(current.metageneration).toBe("4");
    expect(current.metadata.state).toBe("preview-admission");
  });

  test("only the same active workflow and DHI can CAS-rekey a stranded production epoch", async () => {
    const fixture = await setup({
      metadata: {
        "dhi-parity-id": parityId,
        "github-run-attempt": "1",
        "github-run-id": "9",
        nonce: "a".repeat(64),
        "platform-workflow-sha": workflowSha,
        "repository-id": repositoryId,
        state: "prod-dhi-transition",
        version: "1",
      },
      metageneration: "8",
    });
    const resumed = await run(fixture, "resume-prod");
    expect(resumed.exitCode, resumed.stderr).toBe(0);
    expect(resumed.state.metageneration).toBe("9");
    expect(resumed.state.metadata["github-run-id"]).toBe("1234");
    expect(resumed.state.metadata.nonce).not.toBe("a".repeat(64));
    expect((await run(fixture, "release")).exitCode).toBe(0);

    const wrong = await setup({
      metadata: {
        "dhi-parity-id": "z".repeat(50),
        "github-run-attempt": "1",
        "github-run-id": "9",
        nonce: "b".repeat(64),
        "platform-workflow-sha": workflowSha,
        "repository-id": repositoryId,
        state: "prod-dhi-transition",
        version: "1",
      },
      metageneration: "4",
    });
    const rejected = await run(wrong, "resume-prod");
    expect(rejected.exitCode).not.toBe(0);
    expect(rejected.log.trim()).toBe("get");
  });

  test("only the same active workflow and DHI can rekey each preview poison to emergency seal", async () => {
    for (const state of [
      "preview-admission",
      "preview-maintenance",
      "preview-emergency-seal",
    ]) {
      const fixture = await setup({
        metadata: {
          "dhi-parity-id": parityId,
          "github-run-attempt": "1",
          "github-run-id": "9",
          nonce: "c".repeat(64),
          "platform-workflow-sha": workflowSha,
          "repository-id": repositoryId,
          state,
          version: "1",
        },
        metageneration: "8",
      });
      const resumed = await run(fixture, "resume-seal");
      expect(resumed.exitCode, `${state}: ${resumed.stderr}`).toBe(0);
      expect(resumed.state.metadata.state).toBe("preview-emergency-seal");
      expect(resumed.state.metadata["github-run-id"]).toBe("1234");
      expect(resumed.state.metadata.nonce).not.toBe("c".repeat(64));
      expect((await run(fixture, "release")).exitCode).toBe(0);
    }

    for (const metadata of [
      {
        "dhi-parity-id": parityId,
        "platform-workflow-sha": workflowSha,
        state: "prod-dhi-transition",
      },
      {
        "dhi-parity-id": "z".repeat(50),
        "platform-workflow-sha": workflowSha,
        state: "preview-maintenance",
      },
      {
        "dhi-parity-id": parityId,
        "platform-workflow-sha": "9".repeat(40),
        state: "preview-admission",
      },
    ]) {
      const fixture = await setup({
        metadata: {
          "github-run-attempt": "1",
          "github-run-id": "9",
          nonce: "d".repeat(64),
          "repository-id": repositoryId,
          version: "1",
          ...metadata,
        },
        metageneration: "4",
      });
      const rejected = await run(fixture, "resume-seal");
      expect(rejected.exitCode).not.toBe(0);
      expect(rejected.log.trim()).toBe("get");
    }
  });
});

type Fixture = {
  bin: string;
  lease: string;
  log: string;
  mode?: string;
  root: string;
  state: string;
};

async function setup(overrides: Record<string, unknown> = {}): Promise<Fixture> {
  const root = await mkdtemp(join(tmpdir(), "platform-parity-transition-"));
  temporaryRoots.push(root);
  const bin = join(root, "bin");
  const state = join(root, "state.json");
  const log = join(root, "events.log");
  const lease = join(root, "lease.json");
  await mkdir(bin);
  await writeFile(log, "");
  const curl = join(bin, "curl");
  await writeFile(curl, `#!/bin/sh\nMOCK_STATE="$MOCK_STATE" MOCK_LOG="$MOCK_LOG" exec bun "${mock}" "$@"\n`);
  await chmod(curl, 0o755);
  const initial = {
    bucket: `${projectId}-deployment-parity-state`,
    generation: "17",
    metadata: { "repository-id": repositoryId, state: "clear", version: "1" },
    metageneration: "1",
    name: "deployment-parity-transition",
    ...overrides,
  };
  await writeFile(state, JSON.stringify(initial));
  return { bin, lease, log, mode: overrides.mode as string | undefined, root, state };
}

async function writeStateMode(fixture: Fixture): Promise<void> {
  const state = JSON.parse(await readFile(fixture.state, "utf8"));
  if (fixture.mode) state.mode = fixture.mode;
  else delete state.mode;
  await writeFile(fixture.state, JSON.stringify(state));
}

async function run(
  fixture: Fixture,
  command: "acquire" | "resume-prod" | "resume-seal" | "release",
): Promise<{
  exitCode: number;
  log: string;
  state: any;
  stderr: string;
}> {
  const child = Bun.spawn(["/bin/bash", helper, command], {
    cwd: repoRoot,
    env: {
      ...process.env,
      ACCESS_TOKEN: "fixture-token",
      DHI_PARITY_ID: parityId,
      EXPECTED_PLATFORM_WORKFLOW_SHA: workflowSha,
      GITHUB_RUN_ATTEMPT: "1",
      GITHUB_RUN_ID: "1234",
      MOCK_LOG: fixture.log,
      MOCK_STATE: fixture.state,
      PATH: `${fixture.bin}:${process.env.PATH ?? "/usr/bin:/bin"}`,
      PROJECT_ID: projectId,
      REPOSITORY_ID: repositoryId,
      RUNNER_TEMP: fixture.root,
      TRANSITION_KIND: "preview-admission",
      TRANSITION_LEASE_FILE: fixture.lease,
    },
    stdout: "ignore",
    stderr: "pipe",
  });
  const [exitCode, stderr] = await Promise.all([child.exited, new Response(child.stderr).text()]);
  return {
    exitCode,
    log: await readFile(fixture.log, "utf8"),
    state: JSON.parse(await readFile(fixture.state, "utf8")),
    stderr,
  };
}
