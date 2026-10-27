export async function command(args: readonly string[], options: { cwd?: string; stdin?: string; quiet?: boolean } = {}): Promise<string> {
  const process = Bun.spawn([...args], { ...(options.cwd ? { cwd: options.cwd } : {}), stdin: options.stdin === undefined ? "ignore" : new Blob([options.stdin]), stdout: "pipe", stderr: "pipe" });
  const [status, output, error] = await Promise.all([process.exited, new Response(process.stdout).text(), new Response(process.stderr).text()]);
  if (output.length > 8_388_608 || error.length > 262_144) throw new Error("Command output exceeded its bound.");
  if (status !== 0) {
    // Arguments can contain tokens or configuration. Never echo them on failure.
    if (!options.quiet) console.error(`${args[0]} ${args[1]} failed (exit ${status}).`);
    throw new Error("External command failed.");
  }
  return output.trim();
}
export async function gcloud<T>(args: readonly string[]): Promise<T> { return JSON.parse(await command(["gcloud", ...args, "--format=json", "--quiet"])) as T; }
export async function github<T>(endpoint: string, args: readonly string[] = []): Promise<T> { return JSON.parse(await command(["gh", "api", endpoint, ...args])) as T; }
