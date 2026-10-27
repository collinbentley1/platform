import { projects } from "./catalog.ts";
import { command, gcloud } from "./process.ts";
import { catalogChange, deliver } from "./create.ts";

// Owner supplies a replacement through stdin. Secret bytes never enter Git,
// arguments, logs, or the catalog; only Google's exact numeric version does.
export async function rotate(name: string, key: string): Promise<void> {
  if (Bun.env.GITHUB_ACTIONS) throw new Error("Credential rotation requires the owner's session.");
  const app = projects.find(app => app.name === name); const current = app?.secrets[key];
  if (!app || !current) throw new Error("Select an enrolled application and an existing secret environment key.");
  const reader = Bun.stdin.stream().getReader(); const chunks: Uint8Array[] = []; let size = 0;
  for (;;) { const { done, value } = await reader.read(); if (done) break; size += value.byteLength; if (size > 65_536) { await reader.cancel(); throw new Error("Secret is too large."); } chunks.push(value); }
  if (!size) throw new Error("Supply the replacement secret on stdin.");
  const payload = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
  const id = current.split(":")[0]!;
  const version = JSON.parse(await command(["gcloud", "secrets", "versions", "add", id, `--project=${app.project}`, "--data-file=-", "--format=json", "--quiet"], { stdin: payload, quiet: true })) as { name: string };
  const number = version.name.split("/").at(-1); if (!number || !/^[1-9][0-9]*$/.test(number)) throw new Error("Secret version is not numeric.");
  const metadata = await gcloud<{ state: string }>(["secrets", "versions", "describe", number, `--secret=${id}`, `--project=${app.project}`]);
  if (metadata.state !== "ENABLED") throw new Error("The replacement version is not enabled.");
  await catalogChange(`rotate-${name}-${Bun.CryptoHasher.hash("sha256",key+":"+number,"hex").slice(0,12)}`, `Rotate ${name} ${key}`, catalog => {
    const target=catalog.projects.find(item=>item.name===name);
    if(!target || target.project!==app.project || target.secrets[key]!==current)throw new Error("Secret configuration changed; review before retrying.");
    target.secrets[key]=`${id}:${number}`;return true;
  });
  await deliver(name);
  console.log(JSON.stringify({event:"secret-rotation-deployed",app:name,key,version:number,previousVersion:current.split(":")[1],note:"The prior version remains available for rollback. Disable it with gcloud after any application-specific overlap window."}));
}
