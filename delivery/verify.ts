import manifest from "../package.json";
import { lstat, realpath } from "node:fs/promises";
import { join, resolve } from "node:path";

export async function verifyApplication(directory: string): Promise<void> {
  if (`bun@${Bun.version}` !== manifest.packageManager) throw new Error(`Application verification requires ${manifest.packageManager}.`);
  const root = await realpath(resolve(directory));
  if (await lstat(join(root, "node_modules/.bin/bun")).catch(() => undefined)) throw new Error("Dependencies may not shadow the verifier runtime.");
  const binary = process.platform === "linux" ? `/proc/${process.pid}/exe` : process.execPath;
  const compiler = join(root, "node_modules/typescript/bin/tsc");
  if (!(await lstat(compiler)).isFile()) throw new Error("The compiler must be a regular file.");
  const environment = { ...process.env };
  for (const key of Object.keys(environment)) if (/(?:TOKEN|SECRET|CREDENTIAL|PASSWORD|PRIVATE_KEY)/i.test(key) || key.startsWith("ACTIONS_ID_TOKEN_")) delete environment[key];
  const steps = [
    ["audit", "--audit-level=high"], [compiler, "--noEmit"], [join(root, "tools/format.ts"), "--check"],
    ...((await lstat(join(root, "tools/lint.ts")).catch(() => undefined))?.isFile() ? [[join(root, "tools/lint.ts")]] : []), ["test"], [join(root, "tools/build.ts")],
  ];
  for (const step of steps) {
    const result = Bun.spawn([binary, "--no-env-file", ...step], { cwd: root, env: environment, stdin: "ignore", stdout: "inherit", stderr: "inherit" });
    if (await result.exited !== 0) throw new Error("Application verification failed.");
  }
}
