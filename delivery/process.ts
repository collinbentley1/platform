import { mkdtemp, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

export async function command(args: readonly string[], options: { cwd?: string; stdin?: string; quiet?: boolean; env?: Record<string, string | undefined> } = {}): Promise<string> {
  const process = Bun.spawn([...args], { ...(options.cwd ? { cwd: options.cwd } : {}), ...(options.env ? { env: options.env } : {}), stdin: options.stdin === undefined ? "ignore" : new Blob([options.stdin]), stdout: "pipe", stderr: "pipe" });
  const [status, output, error] = await Promise.all([process.exited, new Response(process.stdout).text(), new Response(process.stderr).text()]);
  if (output.length > 8_388_608 || error.length > 262_144) throw new Error("Command output exceeded its bound.");
  if (status !== 0) {
    // Arguments can contain tokens or configuration. Never echo them on failure.
    if (!options.quiet) {
      const directory = await mkdtemp(join(tmpdir(), "platform-command-"));
      await writeFile(join(directory, "diagnostic.log"), output + "\n" + error, { mode: 0o600 });
      console.error(`${args[0]} failed (exit ${status}); private diagnostic: ${directory}/diagnostic.log`);
    }
    throw new Error("External command failed.");
  }
  return output.trim();
}
export async function gcloud<T>(args: readonly string[]): Promise<T> { return JSON.parse(await command(["gcloud", ...args, "--format=json", "--quiet"])) as T; }
export async function github<T>(endpoint: string, args: readonly string[] = []): Promise<T> { return JSON.parse(await command(["gh", "api", endpoint, ...args])) as T; }
