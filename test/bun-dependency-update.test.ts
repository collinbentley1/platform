import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  validateBunDependencyUpdate,
  validateBunDependencyProposal,
} from "../tools/ci/update-bun-dependencies";

const baseManifest = {
  dependencies: { "fixture-package": "1.0.0" },
  devDependencies: { typescript: "7.0.2" },
  name: "bun-update-fixture",
  packageManager: "bun@1.4.0",
  private: true,
  scripts: { test: "bun test" },
  version: "1.0.0",
};

const baseLock = {
  configVersion: 1,
  lockfileVersion: 2,
  packages: {
    "fixture-package": [
      "fixture-package@1.0.0",
      "",
      {},
      `sha512-${"A".repeat(86)}==`,
    ],
    typescript: ["typescript@7.0.2", "", {}, `sha512-${"B".repeat(86)}==`],
  },
  workspaces: {
    "": {
      dependencies: { "fixture-package": "1.0.0" },
      devDependencies: { typescript: "7.0.2" },
      name: "bun-update-fixture",
    },
  },
};

const manifestText = (value: unknown): string => `${JSON.stringify(value, null, 2)}\n`;
const lockText = (value: unknown): string => `${JSON.stringify(value, null, 2)}\n`;

function asOfficialRegistryLock(text: string, registry: string): string {
  const lock = Bun.JSONC.parse(text) as {
    packages: Record<string, [string, string, Record<string, unknown>, string]>;
  };
  const registryUrl = new URL(registry);
  if (registryUrl.protocol !== "http:" || registryUrl.hostname !== "127.0.0.1") {
    throw new Error("fixture registry must be loopback HTTP");
  }
  for (const [name, entry] of Object.entries(lock.packages)) {
    const tarball = new URL(entry[1]);
    if (tarball.origin !== registryUrl.origin || tarball.username || tarball.password ||
      tarball.search || tarball.hash) {
      throw new Error(`fixture lock package ${name} escaped the loopback registry`);
    }
    entry[1] = "";
  }
  return lockText(lock);
}

test("an update must move the manifest and Bun text lock v2 atomically", () => {
  const updatedManifest = structuredClone(baseManifest);
  updatedManifest.dependencies["fixture-package"] = "2.0.0";
  expect(() =>
    validateBunDependencyUpdate(
      manifestText(baseManifest),
      lockText(baseLock),
      manifestText(updatedManifest),
      lockText(baseLock),
    )
  ).toThrow("package.json and bun.lock must move together");

  const updatedLock = structuredClone(baseLock);
  updatedLock.workspaces[""].dependencies["fixture-package"] = "2.0.0";
  updatedLock.packages["fixture-package"][0] = "fixture-package@2.0.0";
  expect(() =>
    validateBunDependencyUpdate(
      manifestText(baseManifest),
      lockText(baseLock),
      manifestText(baseManifest),
      lockText(updatedLock),
    )
  ).toThrow("package.json and bun.lock must move together");
});

test("coordinated TypeScript and non-dependency manifest fields cannot move", () => {
  const updatedManifest = structuredClone(baseManifest);
  updatedManifest.devDependencies.typescript = "7.0.3";
  const updatedLock = structuredClone(baseLock);
  updatedLock.workspaces[""].devDependencies.typescript = "7.0.3";
  updatedLock.packages.typescript[0] = "typescript@7.0.3";
  expect(() =>
    validateBunDependencyUpdate(
      manifestText(baseManifest),
      lockText(baseLock),
      manifestText(updatedManifest),
      lockText(updatedLock),
    )
  ).toThrow("coordinated dependency typescript");

  const renamed = { ...baseManifest, name: "renamed-fixture" };
  expect(() =>
    validateBunDependencyUpdate(
      manifestText(baseManifest),
      lockText(baseLock),
      manifestText(renamed),
      lockText({ ...baseLock, marker: true }),
    )
  ).toThrow("outside direct dependency versions");
});

test("direct dependency changes must be strict upgrades without alias retargeting", () => {
  const downgradedManifest = structuredClone(baseManifest);
  downgradedManifest.dependencies["fixture-package"] = "0.9.0";
  const downgradedLock = structuredClone(baseLock);
  downgradedLock.workspaces[""].dependencies["fixture-package"] = "0.9.0";
  downgradedLock.packages["fixture-package"][0] = "fixture-package@0.9.0";
  expect(() =>
    validateBunDependencyUpdate(
      manifestText(baseManifest),
      lockText(baseLock),
      manifestText(downgradedManifest),
      lockText(downgradedLock),
    )
  ).toThrow("did not strictly upgrade dependency fixture-package");

  const aliasBaseManifest = structuredClone(baseManifest);
  aliasBaseManifest.dependencies["fixture-package"] = "npm:fixture-package@1.0.0";
  const aliasBaseLock = structuredClone(baseLock);
  aliasBaseLock.workspaces[""].dependencies["fixture-package"] =
    "npm:fixture-package@1.0.0";
  const retargetedManifest = structuredClone(aliasBaseManifest);
  retargetedManifest.dependencies["fixture-package"] = "npm:different-package@2.0.0";
  const retargetedLock = structuredClone(aliasBaseLock);
  retargetedLock.workspaces[""].dependencies["fixture-package"] =
    "npm:different-package@2.0.0";
  retargetedLock.packages["fixture-package"][0] = "different-package@2.0.0";
  expect(() =>
    validateBunDependencyUpdate(
      manifestText(aliasBaseManifest),
      lockText(aliasBaseLock),
      manifestText(retargetedManifest),
      lockText(retargetedLock),
    )
  ).toThrow("retargeted dependency fixture-package");
});

test("the privileged proposal boundary accepts only the two validated artifacts", async () => {
  const root = await mkdtemp(join(tmpdir(), "platform-bun-proposal-"));
  try {
    const base = join(root, "base");
    const proposal = join(root, "proposal");
    await Promise.all([mkdir(base), mkdir(proposal)]);
    const updatedManifest = structuredClone(baseManifest);
    updatedManifest.dependencies["fixture-package"] = "2.0.0";
    const updatedLock = structuredClone(baseLock);
    updatedLock.workspaces[""].dependencies["fixture-package"] = "2.0.0";
    updatedLock.packages["fixture-package"][0] = "fixture-package@2.0.0";
    await Promise.all([
      writeFile(join(base, "package.json"), manifestText(baseManifest)),
      writeFile(join(base, "bun.lock"), lockText(baseLock)),
      writeFile(join(proposal, "package.json"), manifestText(updatedManifest)),
      writeFile(join(proposal, "bun.lock"), lockText(updatedLock)),
    ]);

    expect(await validateBunDependencyProposal(base, proposal)).toEqual({
      changed: true,
      dependencies: [{
        from: "1.0.0",
        group: "dependencies",
        name: "fixture-package",
        to: "2.0.0",
      }],
    });
    await writeFile(join(proposal, "unexpected.txt"), "not allowed\n");
    expect(validateBunDependencyProposal(base, proposal)).rejects.toThrow(
      "must contain exactly package.json and bun.lock",
    );
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("the weekly workflow verifies on a read-only runner before a fresh writer opens a PR", async () => {
  const workflow = await readFile(
    join(import.meta.dir, "../.github/workflows/bun-dependency-update.yml"),
    "utf8",
  );
  const resolveStart = workflow.indexOf("  resolve:\n");
  const verifyStart = workflow.indexOf("  verify:\n");
  const proposeStart = workflow.indexOf("  propose:\n");
  const resolveJob = workflow.slice(resolveStart, verifyStart);
  const verifyJob = workflow.slice(verifyStart, proposeStart);
  const proposeJob = workflow.slice(proposeStart);

  expect(resolveStart).toBeGreaterThan(0);
  expect(verifyStart).toBeGreaterThan(resolveStart);
  expect(proposeStart).toBeGreaterThan(verifyStart);
  expect(resolveJob).toContain("contents: read");
  expect(verifyJob).toContain("contents: read");
  expect(resolveJob).not.toContain("contents: write");
  expect(verifyJob).not.toContain("contents: write");
  expect(resolveJob).not.toContain("github.token");
  expect(verifyJob).not.toContain("github.token");
  expect(proposeJob).toContain("needs: [resolve, verify]");
  expect(proposeJob).toContain("needs.verify.result == 'success'");
  expect(proposeJob).toContain('test "$digest" = "$RESOLVED_DIGEST"');
  expect(proposeJob).toContain('test "$digest" = "$VERIFIED_DIGEST"');
  expect(proposeJob.indexOf("Revalidate the artifact")).toBeLessThan(
    proposeJob.indexOf("GH_TOKEN: ${{ github.token }}"),
  );
  expect(workflow.split("contents: write")).toHaveLength(2);
  expect(workflow).not.toContain("--force");
  expect(workflow).not.toContain("environment:");
  expect(workflow).not.toContain("id-token: write");
});

test("Bun 1.4 updates a stale direct dependency and its text lock v2 together", async () => {
  const root = await mkdtemp(join(tmpdir(), "platform-bun-update-"));
  let server: ReturnType<typeof Bun.serve> | undefined;
  try {
    const registryRoot = join(root, "registry");
    await mkdir(registryRoot);
    const packages = new Map<string, Uint8Array>();
    for (const [name, versions] of [
      ["fixture-package", ["1.0.0", "2.0.0"]],
      ["typescript", ["7.0.2"]],
    ] as const) {
      for (const version of versions) {
        const packageRoot = join(registryRoot, `${name}-${version}`, "package");
        await mkdir(packageRoot, { recursive: true });
        await writeFile(
          join(packageRoot, "package.json"),
          JSON.stringify({ name, version }, null, 2),
        );
        await writeFile(join(packageRoot, "index.js"), "export default true;\n");
        const archive = join(registryRoot, `${name}-${version}.tgz`);
        const tar = Bun.spawn([
          "tar",
          "-czf",
          archive,
          "-C",
          join(registryRoot, `${name}-${version}`),
          "package",
        ], { stderr: "pipe", stdout: "ignore" });
        const tarError = new Response(tar.stderr).text();
        const [tarExit, stderr] = await Promise.all([tar.exited, tarError]);
        if (tarExit !== 0) throw new Error(`tar failed: ${stderr}`);
        packages.set(`/${name}-${version}.tgz`, new Uint8Array(await Bun.file(archive).arrayBuffer()));
      }
    }

    let latestFixture = "1.0.0";
    server = Bun.serve({
      port: 0,
      fetch(request) {
        const url = new URL(request.url);
        const archive = packages.get(url.pathname);
        if (archive) return new Response(archive, { headers: { "Content-Type": "application/gzip" } });
        const name = url.pathname.slice(1);
        const versions = name === "fixture-package"
          ? ["1.0.0", "2.0.0"]
          : name === "typescript"
          ? ["7.0.2"]
          : [];
        if (versions.length === 0) return new Response("not found", { status: 404 });
        const base = `http://127.0.0.1:${server!.port}`;
        const records = Object.fromEntries(versions.map((version) => {
          const bytes = packages.get(`/${name}-${version}.tgz`)!;
          return [version, {
            dist: {
              integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`,
              shasum: createHash("sha1").update(bytes).digest("hex"),
              tarball: `${base}/${name}-${version}.tgz`,
            },
            name,
            version,
          }];
        }));
        return Response.json({
          "dist-tags": { latest: name === "fixture-package" ? latestFixture : "7.0.2" },
          name,
          versions: records,
        });
      },
    });
    const registry = `http://127.0.0.1:${server.port}`;
    await writeFile(join(root, "package.json"), manifestText(baseManifest));
    await writeFile(join(root, "platform-pin.txt"), "platform-workflow-sha=unchanged\n");
    const install = Bun.spawn([
      process.execPath,
      "--no-env-file",
      "--no-orphans",
      "install",
      "--lockfile-only",
      "--ignore-scripts",
      "--no-cache",
      "--minimum-release-age=0",
      `--registry=${registry}`,
    ], { cwd: root, stderr: "pipe", stdout: "pipe" });
    await Promise.all([
      new Response(install.stdout).arrayBuffer(),
      new Response(install.stderr).arrayBuffer(),
    ]);
    expect(await install.exited).toBe(0);
    expect((Bun.JSONC.parse(await readFile(join(root, "bun.lock"), "utf8")) as {
      lockfileVersion: number;
    }).lockfileVersion).toBe(2);
    const beforeManifest = await readFile(join(root, "package.json"), "utf8");
    const beforeLock = await readFile(join(root, "bun.lock"), "utf8");

    latestFixture = "2.0.0";
    const update = Bun.spawn([
      process.execPath,
      "--no-env-file",
      "--no-orphans",
      "update",
      "--latest",
      "--lockfile-only",
      "--ignore-scripts",
      "--no-cache",
      "--no-progress",
      "--minimum-release-age=0",
      `--registry=${registry}`,
      "fixture-package",
    ], { cwd: root, stderr: "pipe", stdout: "pipe" });
    await Promise.all([
      new Response(update.stdout).arrayBuffer(),
      new Response(update.stderr).arrayBuffer(),
    ]);
    expect(await update.exited).toBe(0);
    const reconcile = Bun.spawn([
      process.execPath,
      "--no-env-file",
      "--no-orphans",
      "install",
      "--lockfile-only",
      "--ignore-scripts",
      "--no-cache",
      `--registry=${registry}`,
    ], { cwd: root, stderr: "pipe", stdout: "pipe" });
    await Promise.all([
      new Response(reconcile.stdout).arrayBuffer(),
      new Response(reconcile.stderr).arrayBuffer(),
    ]);
    expect(await reconcile.exited).toBe(0);
    const afterManifest = await readFile(join(root, "package.json"), "utf8");
    const afterLock = await readFile(join(root, "bun.lock"), "utf8");

    expect(afterManifest).not.toBe(beforeManifest);
    expect(afterLock).not.toBe(beforeLock);
    const result = validateBunDependencyUpdate(
      beforeManifest,
      asOfficialRegistryLock(beforeLock, registry),
      afterManifest,
      asOfficialRegistryLock(afterLock, registry),
    );

    expect(result).toEqual({
      changed: true,
      dependencies: [{
        from: "1.0.0",
        group: "dependencies",
        name: "fixture-package",
        to: "2.0.0",
      }],
    });
    const updatedManifest = JSON.parse(afterManifest);
    const updatedLock = afterLock;
    expect(updatedManifest.dependencies["fixture-package"]).toBe("2.0.0");
    expect(updatedManifest.devDependencies.typescript).toBe("7.0.2");
    expect(updatedLock).toContain("fixture-package@2.0.0");
    expect(updatedLock).toContain("typescript@7.0.2");
    expect(await readFile(join(root, "platform-pin.txt"), "utf8")).toBe(
      "platform-workflow-sha=unchanged\n",
    );
  } finally {
    server?.stop(true);
    await rm(root, { force: true, recursive: true });
  }
});
