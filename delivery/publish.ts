import { mkdtemp, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { projects, imageName } from "./catalog.ts";
import { command } from "./process.ts";
import { verifyImage } from "./oci.ts";
import { requireSha } from "./consumer.ts";
import { output } from "./github.ts";

export async function publish(archive: string) {
  const app = projects.find(app => app.name === Bun.env.PLATFORM_APP); if (!app) throw new Error("Unknown application.");
  const source = requireSha(Bun.env.SOURCE_SHA ?? ""); const release = requireSha(Bun.env.RELEASE_SHA ?? "");
  const token = Bun.env.GOOGLE_OAUTH_ACCESS_TOKEN; if (!token) throw new Error("Publisher credential is missing.");
  const directory = await mkdtemp(join(tmpdir(), "platform-publish-"));
  try {
    const layout = join(directory, "layout");
    await command(["python3", resolve(import.meta.dir, "extract-oci.py"), archive, layout]);
    const evidence = await verifyImage(layout, source, release);
    const env = { ...process.env, REGCTL_CONFIG: join(directory, "registry.json") };
    await command(["regctl", "registry", "login", `${app.region}-docker.pkg.dev`, "--user", "oauth2accesstoken", "--pass-stdin"], { stdin: token, env, quiet: true });
    // Publish by digest: reruns cannot replace a tag or an existing release.
    await command(["regctl", "image", "import", `${imageName(app)}@${evidence.digest}`, archive], { env });
    const actual = await command(["regctl", "image", "digest", `${imageName(app)}@${evidence.digest}`], { env });
    if (actual !== evidence.digest) throw new Error("Published image differs from the verified OCI graph.");
    await output({ evidence: JSON.stringify(evidence) });
    return evidence;
  } finally { await rm(directory, { recursive: true, force: true }); }
}
if (import.meta.main) await publish(resolve(Bun.argv[2] ?? "image.oci.tar"));
