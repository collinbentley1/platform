import { lstat, realpath } from "node:fs/promises";
import { join, resolve } from "node:path";

const [rootArg] = Bun.argv.slice(2);
if (!rootArg) {
  throw new Error("Usage: verify-platform.ts <platform-root>");
}
if (process.platform !== "linux") {
  throw new Error("Privileged platform verification requires Linux /proc executable pinning.");
}

const root = await realpath(resolve(rootArg));
const immutableBunExecutable = `/proc/${process.pid}/exe`;
const tscEntrypoint = join(root, "node_modules/typescript/bin/tsc");
if (await lstat(join(root, "node_modules/.bin/bun")).catch(() => undefined)) {
  throw new Error("Dependencies must not install a node_modules/.bin/bun executable shadow.");
}
const tsc = await lstat(tscEntrypoint).catch(() => undefined);
if (!tsc?.isFile() || tsc.isSymbolicLink()) {
  throw new Error("The reviewed TypeScript compiler entrypoint must be a regular file.");
}

const environment = { ...process.env };
for (const name of [
  "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
  "ACTIONS_ID_TOKEN_REQUEST_URL",
  "GOOGLE_APPLICATION_CREDENTIALS",
  "GITHUB_TOKEN",
  "SOCKET_API_KEY",
  "SOCKET_API_TOKEN",
]) {
  delete environment[name];
}

const commands: Array<[string, string[]]> = [
  ["typecheck", [immutableBunExecutable, "--no-env-file", "--no-orphans", tscEntrypoint, "--noEmit"]],
  [
    "format check",
    [immutableBunExecutable, "--no-env-file", "--no-orphans", join(root, "tools/format.ts"), "--check"],
  ],
  ["lint", [immutableBunExecutable, "--no-env-file", "--no-orphans", join(root, "tools/lint.ts")]],
  ["test", [immutableBunExecutable, "--no-env-file", "--no-orphans", "test"]],
];

for (const [label, command] of commands) {
  console.log(`Running trusted platform ${label} command...`);
  const child = Bun.spawn(command, {
    cwd: root,
    env: environment,
    stdin: "ignore",
    stdout: "inherit",
    stderr: "inherit",
  });
  const exitCode = await child.exited;
  if (exitCode !== 0) {
    throw new Error(`${label} failed with exit code ${exitCode}.`);
  }
}
